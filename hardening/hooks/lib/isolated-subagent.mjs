// A subagent with worktree isolation (2026-11-18): Claude Code runs its hooks with the worktree as process folder, so the
// registered `node hardening/hooks/<script>.mjs` runs the worktree's own copy, and a hook whose file is not in the worktree does
// not run at all (a hook that cannot start is a non-blocking error). Measured live with the Claude desktop app 5.11492.5
// (2026-11-17, hardening/REFERENCE.md, Registration): with a pack that is not committed, such a subagent had no guard. The main
// session's PreToolUse guard sees the call that starts it (tool `Agent`, `tool_input.isolation: "worktree"`), so it checks that
// the guard's files are in the commit Claude Code cuts the worktree from. Claude Code's documentation ("Run parallel sessions
// with worktrees"): from the default branch on the remote (origin/HEAD), with no remote or no cached origin/HEAD from the local
// HEAD, and with `"worktree": { "baseRef": "head" }` in the settings from the local HEAD; a custom subagent may carry
// `isolation: worktree` in its frontmatter; git-ignored files that .worktreeinclude names are copied into new worktrees; a
// WorktreeCreate hook replaces git worktree creation. Node built-ins and the pack's own modules only; never throws for a
// file it cannot read, and a git that fails or times out (null from git()) never counts as a pass.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { HOME_DIR, PROJECT_DIR, git, globToRegExp, toPosix } from './common.mjs';
import { settingsFiles } from './permissions.mjs';

/** The files a subagent's worktree must hold for its guard to run: the PreToolUse guard and the subagent scope guard. */
export const ISOLATED_GUARD_FILES = ['hardening/hooks/pre-tool-use.mjs', 'hardening/hooks/agent-scope.mjs'];
const ORIGIN_HEAD = 'refs/remotes/origin/HEAD';

const deny = (reason) => ({ decision: 'deny', reason });
/** The floor (guard-pre-tool-use.mjs): an ask that auto and lab mode leave to the user. */
const askFloor = (reason) => ({ decision: 'ask', reason, autoApprovable: false, floor: true });

/** The keys of a Markdown file's YAML frontmatter as plain strings (quotes and a trailing comment dropped), or null without one. */
function frontmatter(text) {
  const m = /^﻿?---[ \t]*\r?\n([\s\S]*?)\r?\n---[ \t]*(?:\r?\n|$)/.exec(String(text));
  if (!m) return null;
  const out = {};
  for (const line of m[1].split(/\r?\n/)) {
    const kv = /^([A-Za-z_][\w-]*)[ \t]*:[ \t]*(.*?)[ \t]*$/.exec(line);
    if (!kv) continue;
    const quoted = /^(["'])(.*?)\1(?:[ \t]+#.*)?$/.exec(kv[2]);
    out[kv[1]] = quoted ? quoted[2] : kv[2].replace(/[ \t]+#.*$/, '');
  }
  return out;
}

/**
 * True when the custom subagent `type` (its frontmatter `name:`) is defined with `isolation: worktree` in the agents folder of
 * the main checkout, of a worktree session's project or of the user. A folder or file that cannot be read defines nothing.
 */
function definedWithIsolation(type) {
  if (typeof type !== 'string' || !type.trim()) return false;
  const dirs = [...new Set([path.join(HOME_DIR, '.claude', 'agents'), path.join(PROJECT_DIR, '.claude', 'agents'), path.join(os.homedir(), '.claude', 'agents')])];
  for (const dir of dirs) {
    let names = [];
    try {
      names = fs.readdirSync(dir).filter((n) => /\.md$/i.test(n));
    } catch {
      continue;
    }
    for (const name of names) {
      let fm = null;
      try {
        fm = frontmatter(fs.readFileSync(path.join(dir, name), 'utf8'));
      } catch {
        continue;
      }
      if (fm && fm.name === type.trim() && /^worktree$/i.test(fm.isolation ?? '')) return true;
    }
  }
  return false;
}

/** True when a call of the Agent tool asks for worktree isolation: the `isolation` argument, or the custom subagent's definition. */
export function asksWorktreeIsolation(toolInput) {
  const ti = toolInput && typeof toolInput === 'object' && !Array.isArray(toolInput) ? toolInput : {};
  return String(ti.isolation ?? '').toLowerCase() === 'worktree' || definedWithIsolation(ti.subagent_type);
}

/** A settings file as { parsed } (null when it does not exist) or { broken: true } when it exists and cannot be read as JSON. */
function readSettings(file) {
  try {
    return { parsed: JSON.parse(fs.readFileSync(file, 'utf8').replace(/^﻿/, '')) };
  } catch (err) {
    return err?.code === 'ENOENT' || err?.code === 'ENOTDIR' ? { parsed: null } : { broken: true };
  }
}

/**
 * The effective `worktree.baseRef` of the settings files that apply (settingsFiles: managed and its drop-ins win over local,
 * local over project, project over user; in a worktree session the files of both checkouts, a disagreement counting as
 * unknown): 'head', 'fresh' (the default) or null when a file cannot be parsed or the value is neither. `worktreeCreate`:
 * some file registers a WorktreeCreate hook.
 */
function worktreeSettings() {
  const lists = [...new Set([PROJECT_DIR, HOME_DIR])].map((root) => settingsFiles(root));
  const own = lists[0];
  const groups = [own.slice(0, -3), lists.map((l) => l[l.length - 1]), lists.map((l) => l[l.length - 2]), [own[own.length - 3]]];
  let broken = false;
  let worktreeCreate = false;
  let value;
  for (const group of groups) {
    const values = new Set();
    for (const file of new Set(group)) {
      const s = readSettings(file);
      if (s.broken || (s.parsed !== null && (typeof s.parsed !== 'object' || Array.isArray(s.parsed)))) {
        broken = true;
        continue;
      }
      if (!s.parsed) continue;
      const hooks = s.parsed.hooks;
      const create = hooks && typeof hooks === 'object' ? hooks.WorktreeCreate : undefined;
      if (create !== undefined && create !== null && !(Array.isArray(create) && create.length === 0)) worktreeCreate = true;
      const wt = s.parsed.worktree;
      if (wt !== undefined && (wt === null || typeof wt !== 'object' || Array.isArray(wt))) values.add(null);
      else if (wt && wt.baseRef !== undefined) values.add(wt.baseRef);
    }
    if (value === undefined && values.size) value = values.size === 1 ? [...values][0] : null;
  }
  const baseRef = broken ? null : value === undefined ? 'fresh' : value === 'head' || value === 'fresh' ? value : null;
  return { baseRef, worktreeCreate };
}

/** The non-comment patterns of <HOME_DIR>/.worktreeinclude, or null when the file cannot be read. */
function worktreeIncludePatterns() {
  let text;
  try {
    text = fs.readFileSync(path.join(HOME_DIR, '.worktreeinclude'), 'utf8');
  } catch {
    return null;
  }
  const out = [];
  for (const raw of text.replace(/^﻿/, '').split(/\r?\n/)) {
    let p = raw.replace(/[ \t]+$/, '');
    if (!p || p.startsWith('#')) continue;
    const negate = p.startsWith('!');
    if (negate) p = p.slice(1);
    // A pattern this small matcher cannot read (a character class, an escape) matches nothing.
    if (/[[\]\\]/.test(p)) continue;
    const dirOnly = p.endsWith('/');
    p = p.replace(/\/+$/, '');
    const anchored = p.includes('/');
    p = p.replace(/^\/+/, '');
    if (!p) continue;
    out.push({ negate, dirOnly, anchored, re: new RegExp(globToRegExp(p).source) });
  }
  return out;
}

/**
 * True when the patterns of .worktreeinclude take the project-relative `file`, as gitignore reads them: the last pattern that
 * matches decides (`!` takes it out again); a pattern with a slash is anchored at the root, one without matches any path
 * segment, a trailing slash names a folder; a matched folder takes every file below it; `*` and `**` as in globToRegExp,
 * letter case as written.
 */
function includedBy(patterns, file) {
  const parts = file.split('/');
  let included = false;
  for (const pat of patterns) {
    let hit = false;
    for (let k = 1; k <= parts.length && !hit; k++) {
      if (pat.dirOnly && k === parts.length) continue;
      hit = pat.re.test(pat.anchored ? parts.slice(0, k).join('/') : parts[k - 1]);
    }
    if (hit) included = !pat.negate;
  }
  return included;
}

/**
 * True when every one of `files` exists in the project, git ignores it and .worktreeinclude names it: Claude Code's
 * documentation has such files copied into every worktree it creates with git. A git that gives no answer counts as not ignored.
 */
function copiedIntoWorktrees(files) {
  if (!files.every((f) => fs.existsSync(path.join(PROJECT_DIR, f)))) return false;
  const out = git(['check-ignore', '--', ...files]);
  if (out === null) return false;
  const ignored = new Set(out.split(/\r?\n/).map((l) => toPosix(l.trim())).filter(Boolean));
  const patterns = worktreeIncludePatterns();
  return patterns !== null && files.every((f) => ignored.has(f) && includedBy(patterns, f));
}

/**
 * Whether the commit Claude Code cuts a subagent's worktree from holds the guard's files (ISOLATED_GUARD_FILES), as
 * { state, refs, missing }: 'no-repo' (no .git entry in the project), 'custom' (a WorktreeCreate hook creates worktrees),
 * 'ok', 'uncached' (a remote named origin and no cached origin/HEAD: Claude Code fetches the default branch, the guard cannot
 * know its commit), 'unknown' (git gave no answer for a ref that counts, listed in `refs`), 'missing' (`missing`: the files a ref that
 * counts lacks, `refs`: those refs) or 'included' (missing, but all of them copied by .worktreeinclude).
 */
export function worktreeBaseCheck() {
  try {
    fs.lstatSync(path.join(PROJECT_DIR, '.git'));
  } catch {
    return { state: 'no-repo', refs: [], missing: [] };
  }
  const { baseRef, worktreeCreate } = worktreeSettings();
  if (worktreeCreate) return { state: 'custom', refs: [], missing: [] };
  const refs = [];
  const unknown = [];
  if (baseRef !== 'head') {
    // Exits 0 with no output when the ref does not exist; null only when git gives no answer.
    const origin = git(['for-each-ref', '--format=%(refname)', ORIGIN_HEAD]);
    if (origin === null) unknown.push(ORIGIN_HEAD);
    else if (origin.trim()) refs.push(ORIGIN_HEAD);
    else {
      // Not cached. With a remote named origin Claude Code fetches the default branch before it cuts the worktree and falls
      // back to HEAD only when that fails, so the guard cannot know the commit: the floor, never a pass by HEAD alone.
      const remotes = git(['remote']);
      if (remotes === null) unknown.push(ORIGIN_HEAD);
      else if (remotes.split(/\r?\n/).some((l) => l.trim() === 'origin')) return { state: 'uncached', refs: [ORIGIN_HEAD], missing: [] };
    }
  }
  // HEAD counts with baseRef "head", when origin/HEAD is not cached, and when the setting cannot be read.
  if (baseRef === 'head' || baseRef === null || (refs.length === 0 && unknown.length === 0)) refs.push('HEAD');
  const lacking = [];
  const missing = new Set();
  for (const ref of refs) {
    const out = git(['ls-tree', '--name-only', ref, '--', ...ISOLATED_GUARD_FILES]);
    if (out === null) {
      unknown.push(ref);
      continue;
    }
    const present = new Set(out.split(/\r?\n/).map((l) => l.trim()).filter(Boolean));
    const absent = ISOLATED_GUARD_FILES.filter((f) => !present.has(f));
    if (absent.length) {
      lacking.push(ref);
      absent.forEach((f) => missing.add(f));
    }
  }
  if (lacking.length) return { state: copiedIntoWorktrees([...missing]) ? 'included' : 'missing', refs: lacking, missing: [...missing] };
  if (unknown.length) return { state: 'unknown', refs: unknown, missing: [] };
  return { state: 'ok', refs, missing: [] };
}

const refLabel = (ref) => (ref === ORIGIN_HEAD ? 'origin/HEAD (the default branch on the remote)' : 'HEAD (the current commit of this checkout)');
const refsLabel = (refs) => refs.map(refLabel).join(' and ');
const filesLabel = (files) => `${files.join(' and ')} ${files.length === 1 ? 'is' : 'are'}`;
const WAYS_OUT = 'Commit hardening/ to the branch new worktrees are cut from (the default branch on the remote, or the current branch with "worktree": { "baseRef": "head" } in the settings), or start the subagent without worktree isolation.';

/**
 * The guard's verdict for a call of the Agent tool under Claude Code (guard-pre-tool-use.mjs): null unless it asks for worktree
 * isolation (asksWorktreeIsolation) in a git repository; a deny when the commit its worktree is cut from lacks a guard file; the
 * floor when git gave no answer, when the files are only copied by .worktreeinclude, or when a WorktreeCreate hook creates the
 * worktree; null when the files are there.
 */
export function isolatedSubagentVerdict(input) {
  if (!asksWorktreeIsolation(input?.tool_input)) return null;
  const check = worktreeBaseCheck();
  switch (check.state) {
    case 'missing':
      return deny(`This starts a subagent with worktree isolation. Its hooks run from its own worktree, which Claude Code cuts from ${refsLabel(check.refs)}, and ${filesLabel(check.missing)} not in that commit: the subagent would run with no guard. ${WAYS_OUT}`);
    case 'included':
      return askFloor(`This starts a subagent with worktree isolation. Its hooks run from its own worktree, which Claude Code cuts from ${refsLabel(check.refs)}, and ${filesLabel(check.missing)} not in that commit. They exist here, git ignores them and .worktreeinclude names them, so Claude Code's documentation has them copied into new worktrees, but the guard cannot verify the copy; without them the subagent runs with no guard. Approve only if you accept that, or: ${WAYS_OUT}`);
    case 'custom':
      return askFloor(`This starts a subagent with worktree isolation, and a WorktreeCreate hook in the settings creates its worktree instead of git, so the guard cannot know whether that worktree holds ${ISOLATED_GUARD_FILES.join(' and ')}. The subagent's hooks run from its own worktree; without those files it runs with no guard. Approve only if you know the hook puts them there, or start the subagent without worktree isolation.`);
    case 'uncached':
      return askFloor(`This starts a subagent with worktree isolation. Claude Code cuts its worktree from the default branch on the remote, which it fetches first, and this checkout has no cached refs/remotes/origin/HEAD, so the guard cannot know which commit that is or whether it holds ${ISOLATED_GUARD_FILES.join(' and ')}. The subagent's hooks run from its own worktree; without those files it runs with no guard. Run \`git remote set-head origin -a\` so the guard can check, set "worktree": { "baseRef": "head" } in the settings, or start the subagent without worktree isolation.`);
    case 'unknown':
      return askFloor(`This starts a subagent with worktree isolation, and the guard could not check whether ${refsLabel(check.refs)}, the commit Claude Code cuts its worktree from, holds ${ISOLATED_GUARD_FILES.join(' and ')}: git gave no answer. The subagent's hooks run from its own worktree; without those files it runs with no guard. Approve only if hardening/ is committed there, or start the subagent without worktree isolation.`);
    default:
      return null;
  }
}

/** The session banner's line (session-start.mjs) when a guard file is missing from the commit new worktrees are cut from, else null. */
export function isolatedSubagentBanner() {
  const check = worktreeBaseCheck();
  if (check.state !== 'missing') return null;
  return `- Subagents with worktree isolation: ${filesLabel(check.missing)} not in ${refsLabel(check.refs)}, the commit Claude Code cuts their worktrees from. Such a subagent would run its hooks from that worktree and get no guard, so the guard denies starting one. Commit hardening/ there (or set "worktree": { "baseRef": "head" } in the settings and commit it to the current branch), or start subagents without worktree isolation.`;
}
