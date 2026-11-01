#!/usr/bin/env node
// Copies the BI Agent Harness into a repository, or updates an earlier installation.
//   node hardening/scripts/install-into.mjs <target-repo> [--dry-run] [--keep-existing] [--hardening] [--update] [--enable-hooks [--shared]] [--allow-older] [--domain <list>]
// Domains: --domain takes a comma-separated list of the knowledge domains to install. This version has one, bi (Microsoft
// BI: Power BI, Analysis Services, paginated reports, SSIS), which is the default and whose files are the ones listed
// below; any other name is refused (exit 2) with the list of available domains. The manifest records the list
// ("domains": ["bi"]); --update reads it (a manifest written before the field existed counts as ["bi"]: the update
// changes no file and adds the field). The plan for v2: further domains live under domains/<name>/ in the
// harness repository and add their own files; no path a v1 install wrote changes (the manifest name, the bi skills,
// agents, rules, hooks and this installer's path stay as they are).
// Install: copies the core harness (no code) and, with --hardening, the optional Node pack. Nothing that exists is
// overwritten; an integration file that differs stops the install unless --keep-existing (with --dry-run: listed, exit
// 0). A file still as an earlier install left it (the manifest's digest) is no conflict: it is listed as "installed"
// and --update refreshes it, so the same install command runs twice. A .claude/settings.json kept
// that way still receives the harness's permission rules (added when missing, yours stay first) and "agent": "bi-expert"
// when it names no agent ("merged   : ..."); the rest of it stays yours, and every update lists it as kept.
// Update: refreshes the files you have not changed since they were installed, adds new ones and removes the ones the
// harness dropped. Files you changed are kept and listed. The manifest .claude/bi-agent-harness.json records what
// was installed; commit it so every clone can update. A manifest entry outside what the harness installs (outside the
// repository, in .git, a project file, local state such as settings.local.json) is never read or removed: the output
// lists it ("refused  : ...") and the new manifest drops it.
// A kept hardening/harness.config.json never receives new keys: the output lists the keys of the shipped config it
// lacks, with the default that applies, and the keys the pack does not know ("config: missing <key> (default <value>)",
// "config: unknown <key>").
// Both modes preflight before writing (paths, conflicts, the settings file the hooks go into) and append the missing
// .gitignore lines; installed files the target's own .gitignore excludes are listed ("ignored  : ..."), never re-ruled.
// A symbolic link or a junction (a dangling one too) at any path the installer reads or writes, or at a folder on the way
// to one, stops the run before the first read (exit 2, "Linked installation paths"), with nothing written.
// F2-63: --update needs the manifest; without one it stops (exit 2) and names the install.
// F2-48: the manifest records the harness commit the files came from ("commit", when the source is a Git checkout). An
// --update from a source that does not contain that commit (an older or unrelated clone, or a harness whose history was
// rewritten) would downgrade the files and remove the newer ones: it stops (exit 2, nothing changed) unless --allow-older.
// Where the commits cannot be compared (a source that is no Git checkout, a manifest without a commit), the pack version is
// compared with the recorded "version" and a lower one stops the same way. An install rerun from such a source keeps the
// recorded commit and version, so the manifest never moves back without that flag.

import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const SOURCE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const MANIFEST = '.claude/bi-agent-harness.json';
const CORE = [
  'AGENTS.md', 'TASKS.md', '.mcp.example.json', '.gitattributes', 'THIRD_PARTY_NOTICES.md',
  '.claude', 'docs', 'templates', '.vscode/extensions.json',
  '.github/instructions', '.github/agents', // GitHub Copilot: rule pointers, the bi-expert agent and the editors' agent files (VS Code, CLI, cloud agent)
];
// Local state no version of the harness ships: never copied, and never removed by an update whatever the manifest lists
// (case-insensitive: Windows and macOS find `.claude/Settings.Local.json` under that name too).
const LOCAL_STATE = [
  /^\.claude\/logs\//i, /^\.claude\/settings\.local\.json$/i, /^\.claude\/bi-agent-harness\.json$/i, /^hardening\/node_modules\//i,
  /^\.claude\/(?:scheduled_tasks\.|worktrees\/|checkpoints\/|agent-memory)/i, // Claude Code runtime files
];
const SKIP = [
  ...LOCAL_STATE, /(?:^|\/)\.DS_Store$/,
  /^hardening\/tests\/(?!run-all\.mjs$)/, // the runner ships so `npm test` works
  /^\.claude\/skills\/harness-audit\//, // for maintainers of the harness, not for its users
  /^hardening\/scripts\/release-check\.mjs$/, // the release scan runs on the harness repository itself
];
// The Copilot hook registrations --enable-hooks writes (below): harness files, though outside CORE. GitHub Copilot reads
// agent hooks from .github/hooks/*.json: the same scripts, registered for VS Code Copilot and for Copilot CLI and the
// cloud agent. [source in hardening/, destination, label, note]
const COPILOT_HOOKS = [
  ['vscode.hooks.json', '.github/hooks/bi-harness.json', 'VS Code Copilot', 'needs chat.useHooks on and a trusted workspace'],
  ['copilot-cli.hooks.json', '.github/hooks/bi-harness.copilot-cli.json', 'Copilot CLI and cloud agent', 'the CLI also runs the Claude registration above; watch .claude/logs/tool-audit.jsonl for "unmapped"'],
];
const COPILOT_HOOK_FILES = COPILOT_HOOKS.map(([, rel]) => rel);
// Claude Code reads CLAUDE.md instead of AGENTS.md when a CLAUDE.md or CLAUDE.local.md exists in the folder or above it
// (Claude Code docs, Memory). An import line in CLAUDE.md loads the harness in that case; the installer adds it once.
// F2-64: Claude Code evaluates no import inside a code block or a code span (Claude Code docs, Memory; an HTML comment is
// treated the same here), and an import may stand anywhere in a line (its path runs to the next white space). So the
// check skips fenced blocks (``` or ~~~) and HTML comments, each open to the end when unclosed, then looks for an
// `@AGENTS.md` or `@./AGENTS.md` token outside code spans. (An indented code block is not recognised.)
const AGENTS_IMPORT_TOKEN_RE = /(?:^|\s)@(?:\.\/)?AGENTS\.md(?=\s|$)/;
function hasAgentsImport(text) {
  let fence = null;
  let comment = false;
  for (let line of String(text).split(/\r?\n/)) {
    if (comment) {
      const end = line.indexOf('-->');
      if (end < 0) continue;
      comment = false;
      line = line.slice(end + 3);
    } else if (fence) {
      const close = /^ {0,3}(`{3,}|~{3,})\s*$/.exec(line);
      if (close && close[1][0] === fence[0] && close[1].length >= fence.length) fence = null;
      continue;
    } else {
      const open = /^ {0,3}(`{3,}|~{3,})(.*)$/.exec(line);
      if (open && !(open[1][0] === '`' && open[2].includes('`'))) { fence = open[1]; continue; }
    }
    line = line.replace(/(`+)[\s\S]*?\1/g, ' ').replace(/<!--[\s\S]*?-->/g, ' ');
    const start = line.indexOf('<!--');
    if (start >= 0) {
      comment = true;
      line = line.slice(0, start);
    }
    if (AGENTS_IMPORT_TOKEN_RE.test(line)) return true;
  }
  return false;
}
const AGENTS_IMPORT = ['', '<!-- BI Agent Harness: Claude Code reads CLAUDE.md instead of AGENTS.md when both exist; this import loads the harness. -->', '@AGENTS.md', ''].join('\n');
// --enable-hooks (with --hardening, or with --update on a repository whose manifest records the pack; any other run is
// refused with the command that works): also registers the hooks and permission rules of
// hardening/settings.hooks.json in .claude/settings.local.json (this machine only; merged, nothing added twice), writes
// the Copilot registrations hardening/vscode.hooks.json and copilot-cli.hooks.json to .github/hooks/ (recorded in the
// manifest: refreshed while you have not changed them) and sets core.hooksPath. --shared registers them in
// .claude/settings.json instead, the file a team commits, so every clone has the hooks; the manifest records the choice
// and --update re-applies it after refreshing the file. Once the manifest
// records "shared", --enable-hooks alone keeps the team registration (a teammate's per-machine step must not remove it
// from the committed file); moving it back to settings.local.json is a hand edit the output names.
// A shared settings.json you changed is kept and listed on every update, and its manifest digest never moves to its new
// content (the next update would take it for the installed state and overwrite it). The re-application still reaches
// it, by design: the harness's own hook groups (same matcher, same scripts) go back to the shipped form (a changed
// timeout is restored, a removed group is added again) and the pack's permission rules are added when missing; your own
// hook groups, rules and settings stay.
// F2-43: the manifest records the permission rules the registration merged, per settings file ("mergedRules"); a later
// registration removes the recorded ones hardening/settings.hooks.json no longer ships (never a rule the shipped
// .claude/settings.json has, in that file) and lists them; rules you added stay.
// F2-44: an --update without --enable-hooks re-applies the recorded registration only while the settings file still
// holds a harness hook (`node hardening/hooks/...`): after the documented disable it says the hooks stay disabled and
// names the flag that registers them again. It never sets core.hooksPath; F2-46: --enable-hooks sets it only when it is
// unset or already hardening/githooks and the target is the top of its Git work tree, and otherwise keeps it and says so.
const FLAGS = ['--dry-run', '--keep-existing', '--hardening', '--update', '--enable-hooks', '--shared', '--allow-older'];
// The GPL travels with every copy: the license and the attribution notice go next to the manifest, not over the
// target's own LICENSE or NOTICE. F2-47: so does the MIT notice of the vendored Microsoft references (the NOTICE next to
// it names it); the root THIRD_PARTY_NOTICES.md is still installed when the target has none of its own.
const LEGAL = [['LICENSE', '.claude/bi-agent-harness/LICENSE'], ['NOTICE', '.claude/bi-agent-harness/NOTICE'],
  ['THIRD_PARTY_NOTICES.md', '.claude/bi-agent-harness/THIRD_PARTY_NOTICES.md']];

// The knowledge domains this harness ships (--domain, header). One today; v2 adds domains/<name>/ in the harness
// repository without changing an installed path.
const DOMAINS = ['bi'];
const DEFAULT_DOMAINS = ['bi'];

const [targetArg, ...args] = process.argv.slice(2);
// --domain takes a value (the next argument); every other flag stands alone.
const flags = [];
const domainArgs = [];
let usage = !targetArg || targetArg.startsWith('--');
for (let i = 0; i < args.length; i++) {
  if (args[i] !== '--domain') { flags.push(args[i]); continue; }
  const value = args[++i];
  if (value === undefined || value.startsWith('--')) usage = true;
  else domainArgs.push(value);
}
if (usage || flags.some((flag) => !FLAGS.includes(flag))) {
  console.error(`usage: node hardening/scripts/install-into.mjs <target-repo> [${FLAGS.join('] [')}] [--domain <list>]`);
  process.exit(2);
}
// The --domain list: comma-separated names, trimmed, each once. Checked before any file is read.
const requestedDomains = domainArgs.length
  ? [...new Set(domainArgs.flatMap((value) => value.split(',')).map((name) => name.trim()).filter(Boolean))]
  : null;
if (requestedDomains) {
  const unknown = requestedDomains.filter((name) => !DOMAINS.includes(name));
  if (!requestedDomains.length || unknown.length) {
    console.error(`${unknown.length ? `Unknown domain${unknown.length === 1 ? '' : 's'}: ${unknown.join(', ')}` : '--domain names no domain'}. Available domains: ${DOMAINS.join(', ')}. No files changed.`);
    process.exit(2);
  }
}
const dryRun = flags.includes('--dry-run');
const keepExisting = flags.includes('--keep-existing');
const update = flags.includes('--update');
const target = path.resolve(targetArg);
if (!fs.existsSync(target) || !fs.statSync(target).isDirectory()) {
  console.error(`Target must be an existing directory: ${target}`);
  process.exit(2);
}
if (fs.realpathSync(target) === fs.realpathSync(SOURCE)) {
  console.error('Target is the harness itself; install into another repository.');
  process.exit(2);
}

const toPosix = (p) => p.replace(/\\/g, '/');
const blockers = [];

function stat(file) {
  try { return fs.lstatSync(file); }
  catch (err) { if (err.code === 'ENOENT') return null; throw err; }
}

// Audit 2026-10-31, second round (A2): every path the installer reads or writes must be a plain file or folder of the
// target, reached through plain folders. A symbolic link or a junction at it (a dangling one too: lstat sees the link, not
// what it names) or at a folder on the way could lead the read or the write outside the repository: the manifest
// overwrote an outside file, the @AGENTS.md import was appended to one, --enable-hooks merged into one. Such a path stops
// the run (exit 2) before the first read, with nothing written; so does a link that stays inside the target (third round,
// R6: CLAUDE.md -> AGENTS.md, .claude/skills -> ../skills), at a path the installer manages.
const linked = [];
const targetReal = (() => {
  try { return fs.realpathSync.native(target); } catch { return target; }
})();
/** The first part of `rel` (a POSIX path in the target) that is a link or a folder resolving outside the target; null when none. */
function linkedPart(rel) {
  const parts = rel.split('/');
  for (let i = 1; i <= parts.length; i++) {
    const partial = parts.slice(0, i).join('/');
    const full = path.join(target, ...parts.slice(0, i));
    const entry = stat(full);
    if (!entry) return null; // a missing part is created as a plain folder or file inside the target
    if (entry.isSymbolicLink()) return partial;
    if (i === parts.length) return null;
    if (!entry.isDirectory()) return null; // a file where a folder goes: destinationIsSafe reports it
    // The folder resolved: a reparse point that lstat does not report as a link still shows here.
    let real;
    try { real = fs.realpathSync.native(full); } catch { return partial; }
    const inside = path.relative(targetReal, real);
    if (!inside || inside.startsWith('..') || path.isAbsolute(inside)) return partial;
  }
  return null;
}
/** Adds the linked part of each path to `linked`; with any found, prints them all and stops the run (exit 2). */
function stopOnLinks(rels) {
  for (const rel of rels) {
    const part = linkedPart(rel);
    if (part && !linked.includes(part)) linked.push(part);
  }
  if (!linked.length) return;
  // Any link at a path the installer manages stops it, one that stays inside the target too (R6): the installer reads and
  // writes those paths itself and does not decide whether a read or a write through a link is meant.
  console.error(`Linked installation paths (no files changed): a symbolic link or a junction at a path the installer manages, inside or outside ${target}, is never read or written through:\n  ${linked.join('\n  ')}\nReplace each link with the file or folder itself, or install into another folder, then run again.`);
  process.exit(2);
}
// The files the installer generates, merges or reads besides the ones it copies (those are checked as they are listed:
// destinationIsSafe), all of them before the manifest is read.
stopOnLinks([MANIFEST, 'CLAUDE.md', 'AGENTS.md', '.gitignore', '.claude/settings.json', '.claude/settings.local.json', ...COPILOT_HOOK_FILES]);

/** SHA-256 of a file; text is hashed with LF line endings so a Windows (CRLF) checkout matches a macOS one. */
function digest(file) {
  const buf = fs.readFileSync(file);
  const data = buf.includes(0) ? buf : Buffer.from(buf.toString('latin1').replace(/\r\n/g, '\n'), 'latin1');
  return crypto.createHash('sha256').update(data).digest('hex');
}

/**
 * Whether a manifest key may reach the file system (a digest read, an unlink). The manifest is committed text that a
 * teammate or a pull request can change, so a key counts only when it is a plain relative POSIX path inside the target
 * (no absolute path, drive, backslash, colon, empty, `.` or `..` segment, no segment Windows would trim, nothing in a
 * `.git` folder) under what the harness installs: a CORE entry, the pack, the LICENSE and NOTICE copies or the Copilot
 * hook files, and not local state.
 */
function harnessPath(rel) {
  if (typeof rel !== 'string' || !rel || /[\\:\0]/.test(rel) || rel.startsWith('/')) return false;
  const parts = rel.split('/');
  if (parts.some((p) => p === '' || p === '.' || p === '..' || /[. ]$/.test(p) || p.toLowerCase() === '.git')) return false;
  if (!path.resolve(target, rel).startsWith(target + path.sep)) return false;
  if (LOCAL_STATE.some((re) => re.test(rel))) return false;
  return [...CORE, 'hardening'].some((entry) => rel === entry || rel.startsWith(`${entry}/`))
    || LEGAL.some(([, dest]) => dest === rel) || COPILOT_HOOK_FILES.includes(rel);
}

/** 'link' when a folder on the way to rel (inside the target) is a link, 'missing' when one is absent or not a folder. */
function parentState(rel) {
  const parts = rel.split('/');
  for (let i = 1; i < parts.length; i++) {
    const entry = stat(path.join(target, ...parts.slice(0, i)));
    if (entry?.isSymbolicLink()) return 'link';
    if (!entry?.isDirectory()) return 'missing';
  }
  return 'ok';
}

/** Whether two paths name the same file (a key in other case than a shipped file does on Windows and macOS). */
function sameFile(a, b) {
  try {
    const x = fs.statSync(a, { bigint: true });
    const y = fs.statSync(b, { bigint: true });
    return x.dev === y.dev && x.ino === y.ino;
  } catch {
    return false;
  }
}

function readManifest() {
  const file = path.join(target, MANIFEST);
  if (!fs.existsSync(file)) return null;
  try {
    const data = JSON.parse(fs.readFileSync(file, 'utf8'));
    return data && typeof data.files === 'object' ? data : { files: {} };
  } catch (err) {
    console.error(`${MANIFEST} is not valid JSON (${err.message}); fix or delete it, then run again. No files changed.`);
    process.exit(1);
  }
}

// Check parents too: .vscode/extensions.json is an individual entry, not a traversed directory. A link on the way is the
// linked-path stop (linkedPart, exit 2); a file where a folder goes, or the reverse, is a blocker (exit 1).
function destinationIsSafe(rel, directory) {
  const part = linkedPart(toPosix(rel));
  if (part) {
    if (!linked.includes(part)) linked.push(part);
    return false;
  }
  const parts = rel.split(/[\\/]/);
  for (let i = 0; i < parts.length; i++) {
    const partial = parts.slice(0, i + 1).join(path.sep);
    const entry = stat(path.join(target, partial));
    if (!entry) continue;
    if (entry.isSymbolicLink() || ((i < parts.length - 1 || directory) ? !entry.isDirectory() : !entry.isFile())) {
      blockers.push(`${partial}: symlink or incompatible file/directory type`);
      return false;
    }
  }
  return true;
}

/** Where each installed file comes from in the harness, keyed by its POSIX path in the target. */
const sourceOf = new Map();

/** The harness files to install, as POSIX paths relative to the target root. */
function sourceFiles(entries) {
  const out = [];
  const walk = (rel) => {
    if (SKIP.some((re) => re.test(toPosix(rel)))) return;
    const entry = stat(path.join(SOURCE, rel));
    if (!entry) return;
    if (entry.isSymbolicLink()) {
      blockers.push(`${rel}: source symlink is not a portable harness file`);
      return;
    }
    if (!destinationIsSafe(rel, entry.isDirectory())) return;
    if (entry.isDirectory()) {
      for (const name of fs.readdirSync(path.join(SOURCE, rel))) walk(path.join(rel, name));
      return;
    }
    out.push(toPosix(rel));
    sourceOf.set(toPosix(rel), toPosix(rel));
  };
  entries.forEach(walk);
  for (const [src, dest] of LEGAL) {
    if (!fs.existsSync(path.join(SOURCE, src))) {
      blockers.push(`${src}: missing in the harness source. Install from a clone of the harness repository, not from an installed copy.`);
      continue;
    }
    if (destinationIsSafe(dest, false)) {
      out.push(dest);
      sourceOf.set(dest, src);
    }
  }
  return out;
}

const manifest = readManifest();
// F2-3: a key outside what the harness installs is never read or removed: it is refused, listed in the output and
// dropped from the manifest this run writes. Everything below sees only the keys that passed.
const refusedKeys = Object.keys(manifest?.files ?? {}).filter((rel) => !harnessPath(rel));
const recorded = Object.fromEntries(Object.entries(manifest?.files ?? {}).filter(([rel]) => harnessPath(rel)));
const packRecorded = Object.keys(recorded).some((f) => f.startsWith('hardening/'));
const withHardening = flags.includes('--hardening') || (update && packRecorded);
const SETTINGS = '.claude/settings.json';
/** The settings file a hook registration goes into: the team's (shared) or this machine's (local). */
const settingsFileOf = (mode) => (mode === 'shared' ? SETTINGS : '.claude/settings.local.json');
const HARNESS_HOOK_RE = /hardening\/hooks\/[\w-]+\.mjs/;
/**
 * F2-44: whether a settings file still holds a harness hook registration (a hook that runs hardening/hooks/<script>.mjs,
 * in the shell string or the older exec form). A missing file holds none; one that cannot be read or parsed counts as
 * holding one, so the registration's own preflight below names the problem instead of a silent skip.
 */
function holdsHarnessHooks(rel) {
  let data;
  try {
    data = JSON.parse(fs.readFileSync(path.join(target, rel), 'utf8').replace(/^﻿/, ''));
  } catch (err) {
    return err.code !== 'ENOENT';
  }
  return HARNESS_HOOK_RE.test(JSON.stringify(data?.hooks ?? null));
}
// Where the hooks go: --shared → .claude/settings.json (committed, the team's); --enable-hooks → .claude/settings.local.json
// (this machine). An update without either flag re-applies what the manifest recorded, so a refreshed settings.json
// keeps the shared hooks. F2-13: --enable-hooks alone on a repository whose manifest records "shared" keeps the team
// registration (the teammate's per-machine step must not take the hooks out of the committed file).
const keptShared = manifest?.hooks === 'shared' && flags.includes('--enable-hooks') && !flags.includes('--shared');
const explicitHooks = flags.includes('--enable-hooks') || flags.includes('--shared');
const recordedHooks = manifest?.hooks === 'shared' || manifest?.hooks === 'local' ? manifest.hooks : null;
// F2-44: the documented disable (remove the hooks block, unset core.hooksPath) leaves the manifest's choice in place. An
// update without a hooks flag re-applies it only while the settings file still holds a harness hook; otherwise the hooks
// stay disabled and the output names the flag that registers them again.
const hooksDisabled = update && !explicitHooks && withHardening && recordedHooks !== null && !holdsHarnessHooks(settingsFileOf(recordedHooks));
const hooksMode = flags.includes('--shared') || keptShared ? 'shared' : flags.includes('--enable-hooks') ? 'local'
  : update && recordedHooks && !hooksDisabled ? recordedHooks : null;
// The hooks belong to the pack, so the pack must be part of this run: --hardening installs it, --update reads it from the
// manifest. Any other run would register nothing, exit 0 and rewrite the manifest as if the pack were not there: refuse
// before touching a file, and name the command that works. (Reading the pack from the manifest in an install-mode run
// would not do: that run stops on every integration file you changed, the shared settings.json included.)
if ((flags.includes('--enable-hooks') || flags.includes('--shared')) && !withHardening) {
  console.error(packRecorded
    ? `The hardening pack is already installed in this repository (${MANIFEST} lists it): register its hooks with --update --enable-hooks${flags.includes('--shared') ? ' --shared' : ''}. No files changed.`
    : 'The hooks belong to the hardening pack, and this run does not install it: add --hardening. No files changed.');
  process.exit(1);
}
// F2-63: --update decides from the manifest what is the harness's and what is yours. Without one it would install the
// pack past the integration-conflict stop of an install (a differing AGENTS.md or settings.json listed as "kept").
if (update && !manifest) {
  console.error(`No manifest: run the install first (without --update). ${target} has no ${MANIFEST}, which --update reads. No files changed.`);
  process.exit(2);
}
// The domains of this installation: the manifest's on a repository that has one (a manifest written before the field
// existed counts as bi, so an older install updates with no change), otherwise the --domain list (default bi). The
// manifest is committed text: a field that is no list of names stops the run, and so does a domain this source does not
// ship (an older clone). With one domain a valid --domain list always equals the recorded one; v2 decides how a run adds
// a domain to an installation.
const recordedDomains = (() => {
  if (!manifest) return null;
  if (!Object.hasOwn(manifest, 'domains')) return DEFAULT_DOMAINS;
  const listed = manifest.domains;
  if (!Array.isArray(listed) || !listed.length || listed.some((name) => typeof name !== 'string' || !name.trim())) {
    console.error(`${MANIFEST}: "domains" is not a list of domain names (available: ${DOMAINS.join(', ')}); fix or delete the field, then run again. No files changed.`);
    process.exit(1);
  }
  return [...new Set(listed.map((name) => name.trim()))];
})();
const unshipped = (recordedDomains ?? []).filter((name) => !DOMAINS.includes(name));
if (unshipped.length) {
  console.error(`${MANIFEST} records the domain${unshipped.length === 1 ? '' : 's'} ${unshipped.join(', ')}, which this harness source does not ship (available domains: ${DOMAINS.join(', ')}): it is older than the one installed. Update the harness clone and run again. No files changed.`);
  process.exit(2);
}
const domains = DOMAINS.filter((name) => (recordedDomains ?? requestedDomains ?? DEFAULT_DOMAINS).includes(name));

/**
 * Whether the source is a Git checkout of its own (not a harness folder nested in another repository: a zip unpacked
 * into a project, a release built under a lab, would otherwise take that repository's ignore rules and commit).
 */
const sourceRepo = (() => {
  const top = spawnSync('git', ['-C', SOURCE, 'rev-parse', '--show-toplevel'], { encoding: 'utf8' });
  if (top.error || top.status !== 0) return false;
  const dir = String(top.stdout).trim();
  try {
    return fs.realpathSync(dir) === fs.realpathSync(SOURCE) || sameFile(dir, SOURCE);
  } catch {
    return false;
  }
})();
// F2-48: the commit the files come from, recorded in the manifest; an update from a source that does not contain the
// recorded commit (an older clone, another branch, a commit the clone never fetched) would put back older files and
// remove newer ones as "no longer shipped". The manifest is committed text: only a full hexadecimal object name counts.
const COMMIT_RE = /^[0-9a-f]{40}(?:[0-9a-f]{24})?$/;
const sourceCommit = (() => {
  if (!sourceRepo) return null;
  const r = spawnSync('git', ['-C', SOURCE, 'rev-parse', '--verify', '--quiet', 'HEAD'], { encoding: 'utf8' });
  const sha = String(r.stdout ?? '').trim();
  return !r.error && r.status === 0 && COMMIT_RE.test(sha) ? sha : null;
})();
const recordedCommit = typeof manifest?.commit === 'string' && COMMIT_RE.test(manifest.commit) ? manifest.commit : null;
const allowOlder = flags.includes('--allow-older');
const olderSource = Boolean(recordedCommit && sourceCommit && recordedCommit !== sourceCommit) && (() => {
  const r = spawnSync('git', ['-C', SOURCE, 'merge-base', '--is-ancestor', recordedCommit, sourceCommit], { encoding: 'utf8' });
  return Boolean(r.error) || r.status !== 0;
})();
const shortSha = (sha) => sha.slice(0, 12);
// The remedy of both refusals below (the commit and, for a source that is no Git checkout, the version).
const OLDER_REMEDY = 'If this source is the one you want, run once with --update --allow-older to update from this source anyway; the manifest then records it. No files changed.';
if (olderSource && update && !allowOlder) {
  console.error(`The harness source ${SOURCE} (commit ${shortSha(sourceCommit)}) does not contain commit ${shortSha(recordedCommit)}, which ${MANIFEST} records for the last install or update: the source is older, on another branch, or from a harness whose history was rewritten since (git pull cannot bring that commit back then), and --update would put back older harness files and remove newer ones. An older clone or another branch: update it (git -C "${SOURCE}" pull) and run again. ${OLDER_REMEDY}`);
  process.exit(2);
}
if (olderSource && !update && !allowOlder) {
  console.warn(`Warning: the harness source ${SOURCE} (commit ${shortSha(sourceCommit)}) does not contain commit ${shortSha(recordedCommit)}, which ${MANIFEST} records: it is older, on another branch, or from a rewritten history. Files missing here come from this source; the manifest keeps commit ${shortSha(recordedCommit)}.`);
}

const packVersion = (() => {
  try { return JSON.parse(fs.readFileSync(path.join(SOURCE, 'hardening', 'package.json'), 'utf8')).version ?? null; } catch { return null; }
})();
/** -1, 0 or 1 for two dotted numeric versions (1.10.0 is above 1.9.2); null when either is missing or not one. */
function compareVersions(a, b) {
  const parse = (v) => (typeof v === 'string' && /^\d+(?:\.\d+)*$/.test(v.trim()) ? v.trim().split('.').map(Number) : null);
  const [x, y] = [parse(a), parse(b)];
  if (!x || !y) return null;
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    if ((x[i] ?? 0) !== (y[i] ?? 0)) return (x[i] ?? 0) < (y[i] ?? 0) ? -1 : 1;
  }
  return 0;
}
// Where the commits cannot be compared (olderSource) — a source that is no Git checkout (a zip, a copy), or a manifest that
// records no commit (an install from such a copy, later updated from a clone) — the pack version is compared with the
// version the manifest records instead, with the same stop and the same flag. With both commits the commit comparison
// decides alone. No opinion without both versions.
const recordedVersion = typeof manifest?.version === 'string' ? manifest.version : null;
const olderVersion = !(recordedCommit && sourceCommit) && compareVersions(packVersion, recordedVersion) === -1;
const noCommitWhy = sourceCommit ? `${MANIFEST} records no commit to compare it with` : 'it is not a Git checkout';
if (olderVersion && update && !allowOlder) {
  console.error(`The harness source ${SOURCE} cannot be compared by commit (${noCommitWhy}), and its pack version ${packVersion} is lower than version ${recordedVersion}, which ${MANIFEST} records for the last install or update: it is an older copy, and --update would put back older harness files and remove newer ones. Use a newer copy of the harness and run again. ${OLDER_REMEDY}`);
  process.exit(2);
}
if (olderVersion && !update && !allowOlder) {
  console.warn(`Warning: the harness source ${SOURCE} cannot be compared by commit (${noCommitWhy}), and its pack version ${packVersion} is lower than version ${recordedVersion}, which ${MANIFEST} records. Files missing here come from this source; the manifest keeps version ${recordedVersion}.`);
}
// The commit and version this run records. They describe one installed state and move together: an install rerun from an
// older source (by commit, or by version where the commits cannot be compared) overwrites no file, so the installed files
// are still the newer ones and the manifest keeps both recorded values unless --allow-older. Writing the older source's
// commit next to the kept version would make the next --update compare equal commits and downgrade with no stop. A source
// that is no Git checkout records no commit.
const keepRecorded = (olderSource || olderVersion) && !allowOlder;
const manifestCommit = keepRecorded ? recordedCommit : sourceCommit;
const manifestVersion = keepRecorded ? recordedVersion : packVersion;
// The hooks run `node` from PATH (settings.hooks.json). A hook that cannot start (no node there) or cannot parse (an old
// Node) lets every tool call through (Claude Code docs, Hooks), so the pack goes in only with Node 18.17+ on PATH.
if (withHardening) {
  const probe = spawnSync('node', ['--version'], { encoding: 'utf8' });
  const version = String(probe.stdout ?? '').trim();
  const m = /^v(\d+)\.(\d+)/.exec(version);
  if (!m || Number(m[1]) < 18 || (Number(m[1]) === 18 && Number(m[2]) < 17)) {
    console.error(`The hardening hooks run \`node\` from PATH, which is ${m ? version : 'missing'} there. A hook that cannot start or parse lets every tool call through. Put Node.js 18.17 or later on PATH, then run again. No files changed.`);
    process.exit(1);
  }
}
/**
 * Drops the files Git ignores in the source (local caches, credentials stubs, lab data); without Git nothing is dropped.
 * Only the source's own repository counts: a harness folder nested inside another repository (a zip unpacked into a
 * project, a release built under a lab) would otherwise inherit that repository's ignore rules and ship nothing.
 */
function dropIgnored(list) {
  if (!sourceRepo) return list;
  const r = spawnSync('git', ['-C', SOURCE, 'check-ignore', '--stdin'], { input: list.map((rel) => sourceOf.get(rel)).join('\n'), encoding: 'utf8' });
  if (r.error || (r.status !== 0 && r.status !== 1)) return list;
  const ignored = new Set(String(r.stdout).split(/\r?\n/).filter(Boolean).map(toPosix));
  return list.filter((rel) => !ignored.has(sourceOf.get(rel)));
}
const files = dropIgnored(sourceFiles(withHardening ? [...CORE, 'hardening'] : CORE));
// A release installs from a clean clone: uncommitted source changes would travel with it unnoticed.
const dirtySource = spawnSync('git', ['-C', SOURCE, 'status', '--porcelain', '--', ...CORE, ...(withHardening ? ['hardening'] : [])], { encoding: 'utf8' });
if (!dirtySource.error && String(dirtySource.stdout).trim()) {
  console.warn('Warning: the harness source has uncommitted or untracked files in what it ships; they are installed as they are. Install a release from a clean clone.');
}
destinationIsSafe('.gitignore', false);
if (hooksMode && withHardening) for (const rel of COPILOT_HOOK_FILES) destinationIsSafe(rel, false);
stopOnLinks([]);
if (blockers.length) {
  console.error(`Unsafe installation paths (no files changed):\n  ${[...new Set(blockers)].join('\n  ')}`);
  process.exit(1);
}

const integrationFile = (rel) => /^(?:AGENTS\.md|\.mcp\.example\.json|\.gitattributes|\.claude\/|hardening\/)/.test(rel);
// installed: in an install run, a file still as an earlier install left it (its recorded digest) that differs from the
// harness's copy: an older harness file, or the shared settings.json with the hooks merged in. It is not the user's, so
// it is no conflict (F1-121); an install never overwrites it, and --update refreshes it.
const plan = { add: [], update: [], same: [], installed: [], kept: [], conflicts: [], userDeleted: [], remove: [], keptRemoved: [], refused: [...refusedKeys] };
const hashes = {};
for (const rel of files) {
  const dest = path.join(target, rel);
  hashes[rel] = digest(path.join(SOURCE, sourceOf.get(rel)));
  if (!fs.existsSync(dest)) {
    if (update && recorded[rel]) plan.userDeleted.push(rel);
    else plan.add.push(rel);
    continue;
  }
  const current = fs.statSync(dest).isFile() ? digest(dest) : null;
  if (current === hashes[rel]) plan.same.push(rel);
  else if (current && recorded[rel] === current) (update ? plan.update : plan.installed).push(rel);
  else {
    plan.kept.push(rel);
    if (!update && integrationFile(rel)) plan.conflicts.push(rel);
  }
}
if (update) {
  const shipped = new Set(files);
  const shippedFolded = new Map([...files, ...COPILOT_HOOK_FILES].map((rel) => [rel.toLowerCase(), rel]));
  // The Copilot hook files are the hook registration's (below), not files the harness dropped.
  for (const rel of Object.keys(recorded).filter((f) => !shipped.has(f) && !COPILOT_HOOK_FILES.includes(f))) {
    // F2-3: a folder link on the way could lead outside the target or onto a file the harness never shipped.
    const parent = parentState(rel);
    if (parent === 'link') { plan.refused.push(rel); continue; }
    if (parent === 'missing') continue;
    const dest = path.join(target, rel);
    // A key in other case than a shipped file is that file on Windows and macOS: removing it would delete the shipped one.
    const twin = shippedFolded.get(rel.toLowerCase());
    if (twin && sameFile(dest, path.join(target, twin))) continue;
    const entry = stat(dest);
    if (!entry) continue;
    if (entry.isFile() && digest(dest) === recorded[rel]) plan.remove.push(rel);
    else plan.keptRemoved.push(rel);
  }
}
// F2-13: a shared settings.json is recorded as the shipped file with the hooks merged in. A run that does not merge them
// back (the manifest no longer lists the pack) must not refresh it to the shipped file, or the team's hooks and the pack
// rules go with the next commit: it is kept instead. (So does a run that leaves the hooks disabled, F2-44.)
if (manifest?.hooks === 'shared' && !(hooksMode === 'shared' && withHardening) && plan.update.includes(SETTINGS)) {
  plan.update.splice(plan.update.indexOf(SETTINGS), 1);
  plan.kept.push(SETTINGS);
}

/**
 * A kept hardening/harness.config.json against this source: the top-level and second-level keys of the shipped
 * hardening/harness.config.json it lacks, with the default that applies (DEFAULT_CONFIG of hooks/lib/common.mjs), and the
 * keys the pack does not know (not in DEFAULT_CONFIG: a typo or a removed key). A key only DEFAULT_CONFIG has is not
 * missing: a fresh install lacks it too, and the default applies (F1-117). Reads only; the user merges. Entries of
 * agentScopes the pack does not ship are the user's own subagents, not unknown keys.
 */
async function configDrift(rel) {
  let defaults;
  try {
    ({ DEFAULT_CONFIG: defaults } = await import(pathToFileURL(path.join(SOURCE, 'hardening', 'hooks', 'lib', 'common.mjs')).href));
  } catch {
    return [];
  }
  let shipped;
  try {
    shipped = JSON.parse(fs.readFileSync(path.join(SOURCE, CONFIG_FILE), 'utf8').replace(/^﻿/, ''));
  } catch {
    shipped = defaults;
  }
  let user;
  try {
    user = JSON.parse(fs.readFileSync(path.join(target, rel), 'utf8').replace(/^﻿/, ''));
  } catch (err) {
    return [`config: not valid JSON (${err.message}); the hooks use the defaults with approvals "ask"`];
  }
  const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
  if (!isObject(user)) return ['config: not a JSON object; the hooks use the defaults'];
  const show = (value) => {
    const text = JSON.stringify(value);
    return text.length <= 100 ? text : 'in DEFAULT_CONFIG of hardening/hooks/lib/common.mjs';
  };
  const out = [];
  const defaultOf = (key, sub) => {
    const def = Object.hasOwn(defaults, key) ? defaults[key] : shipped[key];
    if (sub === undefined) return def;
    return isObject(def) && Object.hasOwn(def, sub) ? def[sub] : shipped[key][sub];
  };
  for (const [key, ship] of Object.entries(isObject(shipped) ? shipped : {})) {
    if (!Object.hasOwn(user, key)) { out.push(`config: missing ${key} (default ${show(defaultOf(key))})`); continue; }
    if (!isObject(ship) || !isObject(user[key])) continue;
    for (const sub of Object.keys(ship)) {
      if (!Object.hasOwn(user[key], sub)) out.push(`config: missing ${key}.${sub} (default ${show(defaultOf(key, sub))})`);
    }
  }
  const known = (key, sub) => [defaults, shipped].some((source) => isObject(source) && Object.hasOwn(source, key)
    && (sub === undefined || (isObject(source[key]) && Object.hasOwn(source[key], sub))));
  for (const [key, value] of Object.entries(user)) {
    if (!known(key)) { out.push(`config: unknown ${key}`); continue; }
    if (key === 'agentScopes' || !isObject(value)) continue;
    for (const sub of Object.keys(value)) if (!known(key, sub) && [defaults, shipped].some((source) => isObject(source?.[key]))) out.push(`config: unknown ${key}.${sub}`);
  }
  return out;
}
const CONFIG_FILE = 'hardening/harness.config.json';
const configLines = plan.kept.includes(CONFIG_FILE) ? await configDrift(CONFIG_FILE) : [];

if (plan.conflicts.length && !keepExisting) {
  console.error(`Integration conflicts (no files changed):\n  ${plan.conflicts.join('\n  ')}`);
  console.error('Review/merge these files, then use --keep-existing to preserve the reviewed versions, or --update after a manifest exists. Task/docs files are always preserved.');
  process.exit(dryRun ? 0 : 1);
}

/**
 * F1-51: the harness's permission rules and agent merged into a .claude/settings.json the user keeps: a union per list
 * (allow, ask, deny) that keeps the user's rules first and in order, appends each missing rule once (exact text), and
 * sets "agent" only when the file names none. Returns the merged settings and what was added, or { error }.
 */
function mergeHarnessSettings(file) {
  const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
  let data;
  try {
    data = JSON.parse(fs.readFileSync(file, 'utf8').replace(/^﻿/, ''));
  } catch (err) {
    return { error: `not valid JSON: ${err.message}` };
  }
  if (!isObject(data) || (data.permissions !== undefined && !isObject(data.permissions))) return { error: 'not a settings object' };
  const shipped = JSON.parse(fs.readFileSync(path.join(SOURCE, SETTINGS), 'utf8'));
  data.permissions ??= {};
  let added = 0;
  for (const kind of ['allow', 'ask', 'deny']) {
    const rules = Array.isArray(shipped.permissions?.[kind]) ? shipped.permissions[kind] : [];
    if (data.permissions[kind] !== undefined && !Array.isArray(data.permissions[kind])) return { error: `permissions.${kind} is not a list` };
    for (const rule of rules) {
      if (data.permissions[kind]?.includes(rule)) continue;
      (data.permissions[kind] ??= []).push(rule);
      added++;
    }
  }
  const agentSet = !Object.hasOwn(data, 'agent') && typeof shipped.agent === 'string';
  if (agentSet) data.agent = shipped.agent;
  return { data, added, agentSet, agent: shipped.agent };
}
// Only a kept file the user owns qualifies: one still in the installed state (a shared settings.json with the hooks merged
// in) is in plan.installed, --update's to refresh. The merged file is not the installed state either: the manifest keeps
// what it recorded for it (nothing, for a file the harness never installed), so every update lists it as kept and none
// overwrites it.
const settingsMerge = !update && keepExisting && plan.kept.includes(SETTINGS) ? mergeHarnessSettings(path.join(target, SETTINGS)) : null;

// F1-120: the hook registration's inputs are read before the first write, so a settings file that is not valid JSON
// stops the run with nothing changed instead of leaving the files installed without hooks, core.hooksPath or the
// Copilot registrations. A settings.json this run replaces with the harness's copy is read after the copy, as before.
let hookSource = null;
if (hooksMode && withHardening) {
  try {
    hookSource = JSON.parse(fs.readFileSync(path.join(SOURCE, 'hardening', 'settings.hooks.json'), 'utf8'));
    for (const [srcName] of COPILOT_HOOKS) JSON.parse(fs.readFileSync(path.join(SOURCE, 'hardening', srcName), 'utf8'));
  } catch (err) {
    console.error(`The harness source's hook registrations cannot be read (${err.message}): install from a clean clone of the harness. No files changed.`);
    process.exit(1);
  }
  const rel = settingsFileOf(hooksMode);
  const file = path.join(target, rel);
  if (fs.existsSync(file) && !plan.add.includes(rel) && !plan.update.includes(rel)) {
    try {
      JSON.parse(fs.readFileSync(file, 'utf8').replace(/^﻿/, ''));
    } catch (err) {
      console.error(`${rel} is not valid JSON (${err.message}): fix it, then run again with ${flags.join(' ')}. No files changed.`);
      process.exit(1);
    }
  }
}

// Read merge inputs before mutation, so an invalid .gitignore cannot leave a partial install.
const gitignoreSrc = fs.readFileSync(path.join(SOURCE, '.gitignore'), 'utf8').split(/\r?\n/);
const gitignoreDest = path.join(target, '.gitignore');
const existing = fs.existsSync(gitignoreDest) ? fs.readFileSync(gitignoreDest, 'utf8') : '';
const missing = gitignoreSrc.filter((l) => l.trim() && !l.startsWith('#') && !existing.split(/\r?\n/).includes(l));
// CLAUDE.md next to AGENTS.md: add the import once. Only CLAUDE.local.md: create CLAUDE.md with the import, so every
// clone loads the harness. A CLAUDE.md in a parent folder cannot be fixed from here: warn.
const claudeMd = path.join(target, 'CLAUDE.md');
let claudeReport = null;
if (fs.existsSync(claudeMd)) {
  if (!hasAgentsImport(fs.readFileSync(claudeMd, 'utf8'))) claudeReport = { action: 'append', text: `CLAUDE.md: \`@AGENTS.md\` import ${dryRun ? 'would be ' : ''}appended (Claude Code reads CLAUDE.md instead of AGENTS.md when both exist)` };
} else if (fs.existsSync(path.join(target, 'CLAUDE.local.md'))) {
  claudeReport = { action: 'create', text: `CLAUDE.md: ${dryRun ? 'would be ' : ''}created with the \`@AGENTS.md\` import (a CLAUDE.local.md alone stops Claude Code from reading AGENTS.md)` };
}
for (let dir = path.dirname(target); dir !== path.dirname(dir); dir = path.dirname(dir)) {
  if (fs.existsSync(path.join(dir, 'CLAUDE.md')) || fs.existsSync(path.join(dir, 'CLAUDE.local.md'))) {
    console.warn(`Warning: ${dir} holds a CLAUDE.md or CLAUDE.local.md. Claude Code then reads that file instead of this repository's AGENTS.md: add the line \`@AGENTS.md\` to a CLAUDE.md in this repository (the installer does not change files outside it).`);
    break;
  }
}

const RULE_KINDS = ['allow', 'ask', 'deny'];
/** Sorted, distinct strings of a list (anything else in it is dropped). */
const ruleList = (value) => (Array.isArray(value) ? [...new Set(value.filter((r) => typeof r === 'string'))].sort() : []);
/**
 * F2-43: the permission rules the hook registration merged, per settings file, as the manifest records them
 * ("mergedRules"). The manifest is committed text: only the two settings files and the three rule lists count. A
 * registration replaces the record of its file; the other file's record is carried over unchanged.
 */
const mergedRules = (() => {
  const out = {};
  const data = manifest?.mergedRules;
  if (!data || typeof data !== 'object' || Array.isArray(data)) return out;
  for (const rel of [SETTINGS, settingsFileOf('local')]) {
    const entry = Object.hasOwn(data, rel) ? data[rel] : null;
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) continue;
    const kinds = Object.fromEntries(RULE_KINDS.map((kind) => [kind, ruleList(entry[kind])]).filter(([, rules]) => rules.length));
    if (Object.keys(kinds).length) out[rel] = kinds;
  }
  return out;
})();

const manifestFiles = {};
let hooksApplied = false;
/**
 * The manifest: what was installed (hashes), the domains, the harness version, the source commit (F2-48), where the hooks were
 * registered and the permission rules that registration merged (F2-43).
 */
function writeManifest() {
  const sorted = Object.fromEntries(Object.entries(manifestFiles).sort(([a], [b]) => a.localeCompare(b)));
  const rules = Object.fromEntries(Object.entries(mergedRules).sort(([a], [b]) => a.localeCompare(b)));
  // A run that registers no hooks keeps the recorded choice, or the next --update would not re-apply the registration
  // (and would refresh a shared settings.json without the hooks).
  const hooks = hooksApplied ? hooksMode : manifest?.hooks;
  const data = {
    harness: 'bi-agent-harness', domains, ...(manifestVersion ? { version: manifestVersion } : {}), ...(manifestCommit ? { commit: manifestCommit } : {}),
    ...(hooks === 'shared' || hooks === 'local' ? { hooks } : {}), ...(Object.keys(rules).length ? { mergedRules: rules } : {}), files: sorted,
  };
  fs.mkdirSync(path.join(target, '.claude'), { recursive: true });
  fs.writeFileSync(path.join(target, MANIFEST), `${JSON.stringify(data, null, 2)}\n`);
}

if (!dryRun) {
  for (const rel of [...plan.add, ...plan.update]) {
    const src = path.join(SOURCE, sourceOf.get(rel));
    const dest = path.join(target, rel);
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.copyFileSync(src, dest);
    // Git runs a hook only when it is executable; a zip or a plain copy of the source can drop the bit.
    const executable = rel.startsWith('hardening/githooks/') ? 0o755 : 0;
    fs.chmodSync(dest, fs.statSync(src).mode | executable);
  }
  for (const rel of plan.remove) {
    fs.unlinkSync(path.join(target, rel));
    // Drop the folders the removal emptied (a renamed skill leaves its old folder behind).
    for (let dir = path.dirname(path.join(target, rel)); dir.startsWith(target + path.sep); dir = path.dirname(dir)) {
      try { fs.rmdirSync(dir); } catch { break; }
    }
  }
  // Before the hook registration below, which reads the same file under --shared.
  if (settingsMerge?.data && (settingsMerge.added || settingsMerge.agentSet)) {
    fs.writeFileSync(path.join(target, SETTINGS), `${JSON.stringify(settingsMerge.data, null, 2)}\n`);
  }
  if (missing.length) {
    fs.appendFileSync(gitignoreDest, `${existing && !existing.endsWith('\n') ? '\n' : ''}\n# BI Agent Harness\n${missing.join('\n')}\n`);
  }
  if (claudeReport?.action === 'append') {
    const current = fs.readFileSync(claudeMd, 'utf8');
    fs.appendFileSync(claudeMd, `${current && !current.endsWith('\n') ? '\n' : ''}${AGENTS_IMPORT}`);
  } else if (claudeReport?.action === 'create') {
    fs.writeFileSync(claudeMd, `# Project instructions\n${AGENTS_IMPORT}`);
  }
  for (const rel of [...plan.add, ...plan.update, ...plan.same]) manifestFiles[rel] = hashes[rel];
  for (const rel of [...plan.kept, ...plan.userDeleted, ...plan.installed]) if (recorded[rel]) manifestFiles[rel] = recorded[rel];
  // An install that leaves the pack out (a rerun of the core) does not touch its files: they stay recorded as they were,
  // or no later --update would refresh the pack. An update decides by itself what the harness dropped; the Copilot hook
  // files stay recorded until the hook registration below records them again.
  const planned = new Set(files);
  if (!update) for (const rel of Object.keys(recorded)) if (!planned.has(rel)) manifestFiles[rel] = recorded[rel];
  if (update) for (const rel of COPILOT_HOOK_FILES) if (recorded[rel]) manifestFiles[rel] = recorded[rel];
  writeManifest();
}

const HOOKS_PATH = 'hardening/githooks';
/**
 * Points Git at hardening/githooks where that is safe, and returns what the hooks line says about it. F2-46: a
 * core.hooksPath already set to something else (.husky, a global hooks folder) is the team's or yours: it is kept, and the
 * line names it with the command that switches it. Git resolves the path from the top of the work tree, so in a target
 * below the top it would point the enclosing repository at a folder it does not have: nothing is set there. F2-44: an
 * update without --enable-hooks never sets it (an unset value may be the documented disable).
 */
function gitHooksPath() {
  const git = (...args) => spawnSync('git', ['-C', target, ...args], { encoding: 'utf8' });
  const repo = git('rev-parse', '--is-inside-work-tree');
  if (repo.error || String(repo.stdout).trim() !== 'true') return 'not a Git repository, so no Git hooks';
  const got = git('config', '--get', 'core.hooksPath');
  if (got.error || (got.status !== 0 && got.status !== 1)) return `core.hooksPath could not be read, so it is left as it is; to use the harness's Git hooks: git config core.hooksPath ${HOOKS_PATH}`;
  const current = got.status === 0 ? String(got.stdout).trim() : '';
  if (String(git('rev-parse', '--show-prefix').stdout ?? '').trim()) {
    const top = String(git('rev-parse', '--show-toplevel').stdout ?? '').trim();
    return `core.hooksPath ${current ? `kept as "${current}"` : 'not set'}: ${target} is not the top of its Git work tree (${top}), where Git would look for ${HOOKS_PATH}; install the harness at the top of the repository to use its Git hooks`;
  }
  if (current === HOOKS_PATH) return `core.hooksPath = ${HOOKS_PATH}`;
  if (current) return `core.hooksPath kept as "${current}" (not replaced), so the harness's Git hooks do not run; to use them instead: git config core.hooksPath ${HOOKS_PATH}`;
  if (!explicitHooks) return `core.hooksPath is unset and stays so (only --enable-hooks sets it); to use the harness's Git hooks: git config core.hooksPath ${HOOKS_PATH}`;
  if (!dryRun) git('config', 'core.hooksPath', HOOKS_PATH);
  return `core.hooksPath = ${HOOKS_PATH}`;
}

// --enable-hooks: merge the pack's hooks and permission rules into .claude/settings.local.json (never overwrite, never
// add an entry twice) and point Git at hardening/githooks, so the pack is active after a restart with no hand edits.
let hooksReport = hooksDisabled
  ? `  hooks    : the hooks stay disabled: ${settingsFileOf(recordedHooks)} holds no harness hook registration (${MANIFEST} records "${recordedHooks}"); --update --enable-hooks${recordedHooks === 'shared' ? ' --shared' : ''} registers them again`
  : null;
if (hooksMode && withHardening) {
  const src = hookSource;
  const settingsRel = settingsFileOf(hooksMode);
  const localFile = path.join(target, settingsRel);
  let local = {};
  if (fs.existsSync(localFile)) {
    try {
      local = JSON.parse(fs.readFileSync(localFile, 'utf8').replace(/^﻿/, ''));
    } catch (err) {
      console.error(`${settingsRel} is not valid JSON (${err.message}): fix it, then run again with --update --enable-hooks${hooksMode === 'shared' ? ' --shared' : ''}. The harness files are installed.`);
      process.exit(1);
    }
  }
  let merged = 0;
  if (!local.permissions || typeof local.permissions !== 'object') local.permissions = {};
  // F2-43: the merge only adds, so a rule the harness drops (a pre-approval narrowed by a fix) stayed in every install.
  // The rules an earlier registration merged into this file (the manifest's record) that the shipped
  // settings.hooks.json no longer has are removed first; a rule you added is not in the record and stays. In the shared
  // settings.json a rule the shipped .claude/settings.json has is the core's, not the pack's, and stays too.
  const shippedRules = Object.fromEntries(RULE_KINDS.map((kind) => [kind, ruleList(src.permissions?.[kind])]));
  const coreRules = settingsRel !== SETTINGS ? {} : (() => {
    try {
      const p = JSON.parse(fs.readFileSync(path.join(SOURCE, SETTINGS), 'utf8').replace(/^﻿/, '')).permissions;
      return Object.fromEntries(RULE_KINDS.map((kind) => [kind, ruleList(p?.[kind])]));
    } catch {
      return null; // unknown: nothing is removed from the shared file
    }
  })();
  const pruned = [];
  for (const kind of coreRules ? RULE_KINDS : []) {
    const stale = (mergedRules[settingsRel]?.[kind] ?? []).filter((rule) => !shippedRules[kind].includes(rule) && !coreRules[kind]?.includes(rule));
    if (!stale.length || !Array.isArray(local.permissions[kind])) continue;
    for (const rule of stale) if (local.permissions[kind].includes(rule)) pruned.push(`${kind}: ${rule}`);
    local.permissions[kind] = local.permissions[kind].filter((rule) => !stale.includes(rule));
  }
  const unrecorded = recordedHooks === hooksMode && !mergedRules[settingsRel];
  if (!dryRun) {
    const record = Object.fromEntries(RULE_KINDS.map((kind) => [kind, shippedRules[kind]]).filter(([, rules]) => rules.length));
    if (Object.keys(record).length) mergedRules[settingsRel] = record;
    else delete mergedRules[settingsRel];
  }
  for (const [kind, rules] of Object.entries(src.permissions ?? {})) {
    if (!Array.isArray(local.permissions[kind])) local.permissions[kind] = [];
    for (const rule of rules) if (!local.permissions[kind].includes(rule)) { local.permissions[kind].push(rule); merged++; }
  }
  if (!local.hooks || typeof local.hooks !== 'object') local.hooks = {};
  // The harness scripts a hook group registers, whatever its form (the shell string shipped since 2026-10-08, or the
  // exec form with `args` shipped before): a group that registers the same scripts for the same matcher is the same
  // registration and is replaced, so a hook never runs twice after an update.
  const scriptsOf = (group) => [...new Set(JSON.stringify(group).match(/hardening\/hooks\/[\w-]+\.mjs/g) ?? [])].sort().join(',');
  let replaced = 0;
  for (const [event, groups] of Object.entries(src.hooks ?? {})) {
    if (!Array.isArray(local.hooks[event])) local.hooks[event] = [];
    for (const group of groups) {
      if (local.hooks[event].some((g) => JSON.stringify(g) === JSON.stringify(group))) continue;
      const i = local.hooks[event].findIndex((g) => g && typeof g === 'object' && (g.matcher ?? '') === (group.matcher ?? '') && scriptsOf(g) !== '' && scriptsOf(g) === scriptsOf(group));
      if (i >= 0) { local.hooks[event][i] = group; replaced++; } else { local.hooks[event].push(group); merged++; }
    }
  }
  // The exec form (`command: node`, `args` naming a harness script) is no longer shipped: an entry still in that form
  // is the old registration under a matcher that changed since (the MCP matchers of 2026-10-08) and goes too.
  const harnessExec = (h) => h && typeof h === 'object' && Array.isArray(h.args) && h.args.some((a) => /hardening\/hooks\/[\w-]+\.mjs/.test(String(a)));
  for (const [event, groups] of Object.entries(local.hooks)) {
    if (!Array.isArray(groups)) continue;
    local.hooks[event] = groups.flatMap((g) => {
      if (!g || typeof g !== 'object' || !Array.isArray(g.hooks) || !g.hooks.some(harnessExec)) return [g];
      replaced++;
      const hooks = g.hooks.filter((h) => !harnessExec(h));
      return hooks.length ? [{ ...g, hooks }] : [];
    });
  }
  if (!dryRun && (merged || replaced || pruned.length)) {
    fs.mkdirSync(path.dirname(localFile), { recursive: true });
    fs.writeFileSync(localFile, `${JSON.stringify(local, null, 2)}\n`);
  }
  // The shared file is one the manifest tracks: record the merged content as the installed state, so an update
  // refreshes it and re-applies the hooks instead of listing it as a file the user changed. Only a file that was in the
  // installed state when this run began qualifies (copied from the harness now, unchanged since, or as an earlier install
  // left it). A file you changed or deleted keeps the digest it was recorded with: every update lists it as kept and none
  // overwrites it. (The manifest is written after the Copilot files below.)
  if (!dryRun && hooksMode === 'shared' && [...plan.add, ...plan.update, ...plan.same, ...plan.installed].includes(settingsRel)) {
    manifestFiles[settingsRel] = digest(localFile);
  }
  const gitHooks = gitHooksPath();
  const yours = hooksMode === 'shared' && plan.kept.includes(settingsRel) ? ' (a file you changed: only the harness hook groups and the pack permission rules are re-applied, the rest stays yours)' : '';
  hooksReport = keptShared ? `  hooks    : the team registration in ${SETTINGS} is kept (the manifest records "shared"); to register the hooks on this machine only, remove them from ${SETTINGS} and "hooks" from ${MANIFEST} by hand, then run --update --enable-hooks\n` : '';
  hooksReport += `  hooks    : ${merged} entr${merged === 1 ? 'y' : 'ies'} ${dryRun ? 'would be ' : ''}merged into ${settingsRel}${hooksMode === 'shared' ? ' (shared: commit it; teammates only run `git config core.hooksPath hardening/githooks`)' : ''}${replaced ? `, ${replaced} earlier registration${replaced === 1 ? '' : 's'} of the same hooks ${dryRun ? 'would be ' : ''}replaced` : ''}${yours}; ${gitHooks}`;
  if (pruned.length) hooksReport += `\n  hooks    : ${pruned.length} permission rule${pruned.length === 1 ? '' : 's'} the harness no longer ships ${dryRun ? 'would be ' : ''}removed from ${settingsRel}:${pruned.map((rule) => `\n    ${rule}`).join('')}`;
  if (unrecorded) hooksReport += `\n  hooks    : ${MANIFEST} had no record of the permission rules merged into ${settingsRel}: ${dryRun ? 'would be ' : ''}recorded from now on, so a later update removes the ones the harness drops`;
  // The Copilot registrations (COPILOT_HOOKS). F1-89: recorded in the manifest like the harness files, so deleting the
  // files the manifest lists removes them too. Written when absent; refreshed when unchanged since they were recorded
  // (a newer pack's registration reaches them); a file the user changed is kept, keeps its recorded digest, and is
  // reported. A copy from before this record (no digest) that differs from the harness's is kept once, like any other.
  for (const [srcName, rel, label, note] of COPILOT_HOOKS) {
    const srcFile = path.join(SOURCE, 'hardening', srcName);
    const dest = path.join(target, rel);
    const shippedDigest = digest(srcFile);
    const entry = stat(dest);
    const current = entry?.isFile() ? digest(dest) : null;
    let state;
    if (!entry || (current && current !== shippedDigest && current === recorded[rel])) {
      if (!dryRun) {
        fs.mkdirSync(path.dirname(dest), { recursive: true });
        fs.copyFileSync(srcFile, dest);
      }
      state = `${dryRun ? 'would be ' : ''}${entry ? 'updated' : 'written'}`;
      manifestFiles[rel] = shippedDigest;
    } else if (current === shippedDigest) {
      state = 'unchanged';
      manifestFiles[rel] = shippedDigest;
    } else {
      state = `kept (differs from hardening/${srcName}: merge by hand)`;
      if (recorded[rel]) manifestFiles[rel] = recorded[rel];
    }
    hooksReport += `\n  hooks (${label}): ${rel} ${state}; ${note}`;
  }
  if (!dryRun) {
    hooksApplied = true;
    writeManifest();
  }
}

/**
 * F1-118: the files this run installs or records that the target's own ignore rules exclude, so `git add` leaves them out
 * of every commit and a teammate's clone has no harness, manifest or shared hooks. Git decides (check-ignore, as for the
 * source); a tracked file is never listed, and without Git nothing is. Reads only: the rules are the user's to change.
 * The manifest and the shallow paths come first, so the list (50 lines) names the ones that matter most.
 */
function ignoredInTarget() {
  const repo = spawnSync('git', ['-C', target, 'rev-parse', '--is-inside-work-tree'], { encoding: 'utf8' });
  if (repo.error || String(repo.stdout).trim() !== 'true') return [];
  const depth = (rel) => rel.split('/').length;
  const candidates = [MANIFEST, ...(hooksMode && withHardening ? COPILOT_HOOK_FILES : []), ...(claudeReport ? ['CLAUDE.md'] : []),
    ...[...files].sort((a, b) => depth(a) - depth(b) || a.localeCompare(b))];
  const r = spawnSync('git', ['-C', target, 'check-ignore', '-z', '--stdin'], { input: `${candidates.join('\0')}\0`, encoding: 'utf8' });
  if (r.error || (r.status !== 0 && r.status !== 1)) return [];
  return String(r.stdout).split('\0').filter(Boolean).map(toPosix);
}

const list = (items) => (items.length ? `:\n    ${items.slice(0, 50).join('\n    ')}${items.length > 50 ? `\n    … ${items.length - 50} more` : ''}` : '');
// The kept config's drift, under the kept files: what to merge by hand (no key is added for the user).
const configNotes = () => { for (const line of configLines) console.log(`    ${line}`); };
// F2-3: keys the manifest lists outside what the harness installs. Never touched; the exit code stays 0, the line shows them.
const refusedNote = () => {
  if (plan.refused.length) console.log(`  refused  : ${plan.refused.length} manifest key(s) outside what the harness installs (not removed${dryRun ? '' : '; dropped from the manifest'})${list(plan.refused)}`);
};
const would = dryRun ? 'would be ' : '';
const settingsNote = () => {
  if (!settingsMerge) return;
  if (settingsMerge.error) {
    console.log(`  merged   : ${SETTINGS} left as it is (${settingsMerge.error}): fix it, then run again with --keep-existing to merge the harness's permission rules into it`);
    return;
  }
  const { added, agentSet, agent } = settingsMerge;
  console.log(`  merged   : ${SETTINGS} (${added} permission rule${added === 1 ? '' : 's'} ${would}added, agent ${agentSet ? `${would}set to ${JSON.stringify(agent)}` : 'kept'}); your own rules and settings stay`);
};
console.log(`${dryRun ? '[dry-run] ' : ''}Harness ${update ? 'update' : 'install'} → ${target}`);
console.log(`  domains  : ${domains.join(', ')}`);
console.log(`  added    : ${plan.add.length} file(s)`);
if (update) {
  console.log(`  updated  : ${plan.update.length} file(s)${list(plan.update)}`);
  console.log(`  removed  : ${plan.remove.length} file(s) the harness no longer ships${list(plan.remove)}`);
  refusedNote();
  console.log(`  unchanged: ${plan.same.length} file(s)`);
  console.log(`  kept     : ${plan.kept.length} file(s) you changed - compare with the harness and merge by hand${list(plan.kept)}`);
  configNotes();
  if (plan.keptRemoved.length) console.log(`  kept     : ${plan.keptRemoved.length} file(s) the harness dropped but you changed${list(plan.keptRemoved)}`);
  if (plan.userDeleted.length) console.log(`  skipped  : ${plan.userDeleted.length} file(s) you deleted (not restored)${list(plan.userDeleted)}`);
} else {
  console.log(`  skipped  : ${plan.kept.length + plan.same.length} existing file(s)${plan.kept.length ? ` - merge by hand${list(plan.kept)}` : ''}`);
  configNotes();
  if (plan.installed.length) console.log(`  installed: ${plan.installed.length} file(s) as an earlier install left them (not overwritten; --update refreshes them)${list(plan.installed)}`);
  settingsNote();
  refusedNote();
}
console.log(`  .gitignore: ${missing.length} line(s) ${dryRun ? 'would be ' : ''}appended`);
const ignored = ignoredInTarget();
if (ignored.length) console.log(`  ignored  : ${ignored.length} file(s) the harness installs match your .gitignore and would not be committed; the installer does not change your rules: narrow the rule \`git check-ignore -v <file>\` names, or \`git add -f\` the files${list(ignored)}`);
if (claudeReport) console.log(`  ${claudeReport.text}`);
if (!dryRun) console.log(`  manifest : ${MANIFEST} (commit it; --update uses it)`);
if (hooksReport) console.log(hooksReport);
console.log(update
  ? '\nNext: review `git diff`, merge the kept files by hand, commit the result with the manifest, then restart Claude Code.'
  : hooksReport
  ? '\nNext: restart Claude Code in the repository; /hooks lists the hooks, /bi-doctor checks the setup, /bi-onboard describes your projects and sources. See docs/harness/getting-started.md.'
  : withHardening
  ? '\nNext: run again with --update --enable-hooks (this machine) or --update --enable-hooks --shared (committed for the whole team), or merge hardening/settings.hooks.json by hand; run `git config core.hooksPath hardening/githooks`, then restart Claude Code. See hardening/README.md.'
  : '\nNext: restart Claude Code in the repository. Optional: rerun with --hardening to add the Node hardening pack.');
