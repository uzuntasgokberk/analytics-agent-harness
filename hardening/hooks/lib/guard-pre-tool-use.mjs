// PreToolUse guard for Bash/PowerShell/Monitor, Read/Grep/Glob, Edit/Write/NotebookEdit and MCP calls, loaded by
// hooks/pre-tool-use.mjs. Decides deny / ask / allow before the permission prompt. Fails closed: a crash blocks the call.

import fs from 'node:fs';
import path from 'node:path';
import {
  PROJECT_DIR, appendJsonl, approvalsWidened, autoApprovalActive, canonicalPathOf, currentBranch, firstTimeInSession,
  isReferenceRel, labModeActive, loadConfig, matchesAny, opaquePath, projectRel, projectRelForms, runHook, screenshotsOf,
  screenshotsWidened, toPosix, withoutTrailingDots,
} from './common.mjs';
import { isCopilotClaudeDialect, isCopilotHost, unmappedToolReason } from './host-vscode.mjs';
import { TMDL_ONLY_REASON, analyzeMcpCall, analyzeShellCommand, classifyPath, describePathBlock, findSecrets, routineShell } from './policy.mjs';
import { withConfirmedTarget } from './mcp-state.mjs';
import { askOnce, markAsksEmitted } from './ask-once.mjs';
import { matchingRule } from './permissions.mjs';
import { sqlReadWidened } from './sql-read.mjs';
import {
  RDL_DATASET_ROUTES, countLines, fabricItemOf, isValidPbirName, itemFolderProblem, paginatedRdls, pbirNameSegments,
  removedDeclarations, rdlSourceFacts, roleMembersChanged, simulateEdit, ssisBinaryItems, ssisConnectionFacts, ssisIds,
  tmdlRelationshipFacts, tmdlSourceFacts, xmlProblem,
} from './validators.mjs';

// Files whose change is critical even in auto mode: the agent's own rules and safety net, row-level security, where
// data comes from and the model's database settings. Their edits always reach the user.
// Agent instruction files count in any folder (Claude Code also loads CLAUDE.md from subfolders), and a live
// connection's modelReference.json holds a connection string like dataSources.tmdl.
const CRITICAL_WRITE_RE =
  /^(?:\.claude\/|\.git\/|hardening\/|\.githooks\/|\.github\/|\.cursor\/|\.vscode\/|\.mcp(?:\.example)?\.json$|\.gitignore$|\.gitattributes$|package(?:-lock)?\.json$|docs\/harness\/|docs\/(?:conventions|static-checks|test-packs)\.md$|docs\/sources\/README\.md$|docs\/tests\/expected-values\.md$)|(?:^|\/)(?:AGENTS|CLAUDE|GEMINI)(?:\.local)?\.md$|(?:^|\/)roles\/[^/]+\.tmdl$|(?:^|\/)(?:dataSources|expressions|database)\.tmdl$|(?:^|\/)modelReference\.json$|\.(?:dtproj|conmgr|params|dtsconfig)$/i;
// References and evidence (AGENTS.md): read and copy, never edit.
// Reference folders (templates/, reports/*/source/ and the config's `references`): isReferenceRel in common.mjs.
// Project files that auto approval writes without a prompt: model, report, paginated report and the docs around them.
const ROUTINE_WRITE_RE = /\.(?:tmdl|md|dax|sql|rdl|rds|rsd|rptproj|pbip|pbir|pbism|dtsx)$|(?:^|\/)\.platform$|\.(?:report|semanticmodel)\/.+\.json$/i;

/** True for a path inside the bin/ or obj/ folder of an SSIS project (a folder whose parent holds a .dtproj). */
function ssisBuildFolder(rel) {
  const m = /^(?:(.*)\/)?(?:bin|obj)\//i.exec(rel);
  if (!m) return false;
  try {
    return fs.readdirSync(path.join(PROJECT_DIR, m[1] ?? '.')).some((n) => /\.dtproj$/i.test(n));
  } catch {
    return false;
  }
}

/** Whether auto approval may answer "allow" for a write to these project-relative forms. */
const routineWrite = (relForms, cfg) =>
  relForms.length > 0 && relForms.every((rel) => ROUTINE_WRITE_RE.test(rel) && !CRITICAL_WRITE_RE.test(rel) && !isReferenceRel(rel, cfg));
const criticalWrite = (relForms) => relForms.some((rel) => CRITICAL_WRITE_RE.test(rel));
// The hooks' own logs and session state: the guards read the state back (lib/ask-once.mjs, lib/mcp-state.mjs), so only the
// hooks write there. The shell guard denies the same (GUARD_PATH_RE in policy.mjs); reads stay open.
const HOOK_LOGS_RE = /^\.claude\/logs(?:\/|$)/i;

const SHELL_TOOLS = new Set(['Bash', 'PowerShell', 'Monitor']);
const READ_TOOLS = new Set(['Read', 'Grep', 'Glob', 'LSP']);
const WRITE_TOOLS = new Set(['Edit', 'Write', 'NotebookEdit', 'MultiEdit']);

const deny = (reason) => ({ decision: 'deny', reason });
/**
 * A Tier 2 change (AGENTS.md, Editing boundaries): auto approval never passes it, lab mode does. An explicit hook ask,
 * so it also prompts in permission modes that would accept edits on their own.
 */
const askUser = (reason) => ({ decision: 'ask', reason, autoApprovable: false });
/**
 * An ask lab mode leaves to the user too (the floor, like a command too deeply nested to analyse): what the guard
 * cannot read or judge is never turned into an allow, and its own harness files keep Claude Code's prompt (README, Approvals).
 */
const askFloor = (reason) => ({ decision: 'ask', reason, autoApprovable: false, floor: true });
/** An edit whose result the guard cannot work out: it cannot say which Tier 2 change it makes (data source, storage mode, relationship, rename, binding). */
const unevaluableAsk = (rel) =>
  askFloor(`The guard could not work out the edited text of ${rel} (the old text was not found as written, the call names no place to edit, or the tool inserts text where only it knows), so it cannot check what the edit changes: data sources, storage modes, relationships, renames, report bindings. Approve only if you can see exactly what it does; otherwise have the agent send the exact current text (old_string and new_string) or write the whole file.`);
/** A file that steers the agent or holds the project's evidence and security settings (CRITICAL_WRITE_RE): its edits always reach the user. */
const criticalAsk = (rel) =>
  askFloor(`${rel} steers the agent or holds the project's rules, evidence, security roles or data sources (AGENTS.md and CLAUDE.md, .claude/, hardening/, .github/, .vscode/, .cursor/, docs/harness/, the source registry and the expected values, row-level security roles, data sources, expressions, the database settings, SSIS connection files). Its edits always reach you, in every permission mode.`);
const RELATIONSHIPS_RE = /(?:^|\/)relationships\.tmdl$/i;
const DEFINITION_PBIR_RE = /(?:^|\/)definition\.pbir$/i;
const PLATFORM_RE = /(?:^|\/)\.platform$/i;
// Where a model's data comes from (tmdlSourceFacts in validators.mjs), in any TMDL file: each category is Tier 2.
const TMDL_SOURCE_LABELS = { dataSource: 'a data source', storageMode: 'a storage mode', refreshPolicy: 'a refresh policy', expression: 'a Power Query expression' };
/** "a", "a and b", "a, b and c". */
const listed = (items) => (items.length < 2 ? items.join('') : `${items.slice(0, -1).join(', ')} and ${items[items.length - 1]}`);
const DATASET_ROUTE_RE = new RegExp(`^(?:${RDL_DATASET_ROUTES.join('|')}): `);
/**
 * One sentence per changed `dataset "<Name>"` label of rdlSourceFacts, naming the source it reads now and read before:
 * 'Dataset "Invoices" now reads Prod instead of Dev.'
 */
function datasetRoutes(before, after, changed) {
  const sourceOf = (facts) => (facts === undefined ? null : facts.split('\n').map((l) => l.replace(DATASET_ROUTE_RE, '')).join(', '));
  return changed.filter((k) => k.startsWith('dataset "')).map((k) => {
    const [was, now] = [sourceOf(before.get(k)), sourceOf(after.get(k))];
    const name = `Dataset ${k.slice('dataset '.length)}`;
    if (was === null) return `${name} is new and reads ${now}.`;
    if (now === null) return `${name} is removed (it read ${was}).`;
    return `${name} now reads ${now} instead of ${was}.`;
  });
}

/** The report's binding (datasetReference of definition.pbir) as canonical JSON; undefined when the text is not JSON. */
function bindingOf(text) {
  try {
    return canonicalJson(JSON.parse(String(text).replace(/^﻿/, ''))?.datasetReference ?? null);
  } catch {
    return undefined;
  }
}
/** The identity of a Fabric item in its `.platform` text (config.logicalId, metadata.type); null when the text is not JSON. */
function platformIdentity(text) {
  try {
    const parsed = JSON.parse(String(text).replace(/^﻿/, ''));
    return { logicalId: parsed?.config?.logicalId, type: parsed?.metadata?.type };
  } catch {
    return null;
  }
}
const OPAQUE_REASON =
  'Alternate data streams (file::$DATA, file:stream), device paths (\\\\?\\, \\\\.\\) and administrative shares (\\\\localhost\\C$\\...) are blocked: they hide which file is meant. Use the plain path.';
const SETTINGS_RE = /(?:^|\/)\.claude\/settings(?:\.local)?\.json$/i;
const CONFIG_RE = /^hardening\/harness\.config\.json$/i;
const HOOK_REF_RE = /hardening\/hooks\/[\w-]+\.mjs/g;
// GitHub Copilot's hook files (VS Code and Copilot CLI run every .github/hooks/*.json): the pack's entries there are
// protected like its entries in the settings.
const COPILOT_HOOKS_RE = /^\.github\/hooks\/[^/]+\.json$/i;
// Settings variables that decide whether `node` starts for a hook at all: PATH and PATHEXT find it (Windows spells the
// first `Path`), NODE_OPTIONS can stop it (an unknown flag) or run other code first (--require). A hook command that cannot
// start is a non-blocking error in Claude Code, so the call runs unguarded.
const HOOK_START_ENV_RE = /^(?:PATH|PATHEXT|NODE_OPTIONS)$/i;

/** JSON with object keys sorted at every level and undefined values dropped, for comparing two configs. */
function canonicalJson(value) {
  const sort = (v) => (Array.isArray(v) ? v.map(sort)
    : v && typeof v === 'object' ? Object.fromEntries(Object.keys(v).filter((k) => v[k] !== undefined).sort().map((k) => [k, sort(v[k])]))
    : v);
  return JSON.stringify(sort(value));
}
const edits = (ti) => (Array.isArray(ti.edits) ? ti.edits.map((e) => (e && typeof e === 'object' ? e : {})) : []);
/** Every text a write tool would put into the file (Write content, Edit/MultiEdit replacements). */
const writtenText = (tool, ti) =>
  tool === 'MultiEdit' ? edits(ti).map((e) => String(e.new_string ?? '')).join('\n') : String(ti.content ?? ti.new_string ?? ti.new_source ?? ti.file_text ?? ti.new_str ?? '');

/**
 * Absolute paths (POSIX) of a target as written and as resolved: 8.3 short names, junctions and symlinks resolved, a `..`
 * after a link walked from where the link points (canonicalPathOf is given the written path, not path.resolve's).
 */
function absoluteForms(target) {
  const written = path.resolve(PROJECT_DIR, withoutTrailingDots(target));
  return [...new Set([toPosix(written), toPosix(canonicalPathOf(withoutTrailingDots(target), PROJECT_DIR))])];
}

/**
 * The project-relative forms of a target plus every absolute form that lies outside the project (a symlink or junction
 * out of it, or a target outside it). Parent folders of the project itself are never classified.
 */
function allForms(target) {
  const outside = absoluteForms(target).filter((a) => projectRel(a) === null);
  return [...new Set([...projectRelForms(target), ...outside])];
}

// A Grep glob reaches the files it names even where ripgrep would skip them as hidden or ignored (--glob overrides both),
// so it is judged by what it can match, like a Read of the file: a literal name or folder (classifyPath), a wildcard in
// the extension that can stand for a secret or data extension, and a wildcard that can match a hidden password file
// (`*`, `.*`, `**/*`, `*rc`). The lists mirror the secret and data names of classifyPath (policy.mjs): every secret and
// data extension (a data one may span two dots, `.rdl.data`) and every hidden secret file name. A name added there needs
// its entry here; tests/round2-file-guard.test.mjs reads both lists and fails when they drift. A wildcard in the name
// part of a visible file stays open: `*.json` must keep working for PBIR.
const GLOB_SECRET_EXTS = ['.pem', '.key', '.pfx', '.p12', '.publishsettings', '.kdbx', '.ppk', '.abf', '.pbix', '.rdl.data'];
const GLOB_HIDDEN_SECRETS = ['.env', '.env.local', '.env.production', '.npmrc', '.netrc', '.pypirc', '.pgpass', '.pg_service.conf', '.my.cnf', '.mylogin.cnf', '.git-credentials'];

/**
 * The part of a glob segment that stands where an extension of `dots` dots would be: from its `dots`-th last dot, or the
 * whole segment when it has fewer (a `*` can stand for the dots too: `*.data` can end in `.rdl.data`, `*m` in `.pem`).
 */
function extensionPart(segment, dots) {
  let at = segment.length;
  for (let n = 0; n < dots; n++) {
    at = segment.lastIndexOf('.', at - 1);
    if (at < 0) return segment;
  }
  return segment.slice(at);
}

/** `*.{pbix,abf}` -> `*.pbix`, `*.abf` (nested groups too); null when the groups multiply past 256 alternatives. */
function braceAlternatives(glob) {
  let list = [glob];
  for (let round = 0; round < 8 && list.some((g) => /\{[^{}]*\}/.test(g)); round++) {
    list = list.flatMap((g) => {
      const m = /\{([^{}]*)\}/.exec(g);
      return m ? m[1].split(',').map((part) => g.slice(0, m.index) + part + g.slice(m.index + m[0].length)) : [g];
    });
    if (list.length > 256) return null;
  }
  return list;
}

/**
 * Whether one glob segment (`*` and `?` stay inside the segment; `[a-c]` and `[!a]` are classes) matches a name, ignoring
 * case. Not a regular expression: a pattern full of stars must not make the hook run past its timeout (which lets the call through).
 */
function segmentMatches(segment, name) {
  const tokens = [];
  for (let i = 0; i < segment.length; i++) {
    const end = segment[i] === '[' ? segment.indexOf(']', i + 2) : -1;
    if (end > 0) {
      const negate = /^[!^]/.test(segment.slice(i + 1, end));
      tokens.push({ negate, set: segment.slice(i + 1 + (negate ? 1 : 0), end).toLowerCase() });
      i = end;
    } else if (segment[i] !== '*' || tokens[tokens.length - 1] !== '*') tokens.push(segment[i].toLowerCase());
  }
  const inSet = ({ negate, set }, c) => {
    let hit = false;
    for (let k = 0; k < set.length; k++) {
      if (set[k + 1] === '-' && k + 2 < set.length) {
        if (c >= set[k] && c <= set[k + 2]) hit = true;
        k += 2;
      } else if (set[k] === c) hit = true;
    }
    return hit !== negate;
  };
  const text = name.toLowerCase();
  let p = 0;
  let t = 0;
  let star = -1;
  let mark = 0;
  while (t < text.length) {
    const tok = tokens[p];
    if (tok === '*') {
      star = p++;
      mark = t;
    } else if (tok !== undefined && (tok === '?' || (typeof tok === 'string' ? tok === text[t] : inSet(tok, text[t])))) {
      p++;
      t++;
    } else if (star >= 0) {
      p = star + 1;
      t = ++mark;
    } else return false;
  }
  while (tokens[p] === '*') p++;
  return p === tokens.length;
}

/** True when a Grep `glob` can match a secret or data file. Judged as written, split at spaces and at commas, braces expanded. */
function globReachesSecrets(glob) {
  const text = String(glob).trim();
  if (text.length > 4096) return true; // no real glob is that long: too long to judge
  const reaches = (p) => {
    const cls = classifyPath(p);
    return cls.secret || cls.data;
  };
  for (const candidate of new Set([text, ...text.split(/\s+/), ...text.split(/[\s,]+/)])) {
    const alternatives = braceAlternatives(candidate);
    if (alternatives === null) return true;
    for (const alternative of alternatives) {
      const g = toPosix(alternative).replace(/^(?:\.?\/)+/, '');
      if (!g || g.startsWith('!')) continue; // an exclusion only removes files
      const last = g.slice(g.lastIndexOf('/') + 1);
      if (reaches(g) || reaches(last.replace(/[*?]+/g, 'a').replace(/\[[^\]]*\]/g, 'a'))) return true;
      const wildExt = (e) => {
        const part = extensionPart(last, e.split('.').length - 1);
        return /[*?[]/.test(part) && segmentMatches(part, e);
      };
      if (GLOB_SECRET_EXTS.some(wildExt)) return true;
      if (GLOB_HIDDEN_SECRETS.some((name) => segmentMatches(last, name))) return true;
    }
  }
  return false;
}

function checkRead(input) {
  const ti = input.tool_input ?? {};
  for (const target of [ti.file_path, ti.path].filter(Boolean)) {
    if (opaquePath(target)) return deny(OPAQUE_REASON);
    for (const form of allForms(target)) {
      const cls = classifyPath(form);
      if (cls.secret || cls.data) return deny(describePathBlock(form, cls));
    }
  }
  // globReachesSecrets first: it refuses an absurdly long glob before any pattern runs over it.
  if (input.tool_name === 'Grep' && ti.glob && (globReachesSecrets(ti.glob) || /(?:^|[/*{,])\.env(?![.\w]*example)|\.(?:pem|key|pfx|p12|ppk|abf|pbix|rdl\.data)\b/i.test(ti.glob))) {
    return deny('Searching inside secret or data files (.env, keys, the password files of SQL clients, cache.abf, .pbix, *.rdl.data, a workspace database) is blocked, and so is a glob that can match one of them (ripgrep reads a file an explicit glob names even when it is hidden or ignored). Name the file type instead, for example *.tmdl or *.md.');
  }
  return null;
}

/**
 * What the file holds after the call, or `next: null` when the guard cannot work that out (an old_string that is not in
 * the file as written, an Edit that names no place, a Write without text), and the text the call adds (scanned for
 * credentials). Copilot CLI's plain spellings (`old_str`, `new_str`, `file_text`) mean the same replace and whole-file
 * write as Claude's fields and are read as such. A NotebookEdit has no file text to simulate: next is null, added is the cell.
 */
function resultingContent(tool, ti, current) {
  const oldString = ti.old_string ?? ti.old_str;
  const newString = ti.new_string ?? ti.new_str;
  const content = ti.content ?? ti.file_text;
  if (tool === 'Write') return { next: typeof content === 'string' ? content : null, added: writtenText(tool, ti) };
  if (tool === 'Edit') {
    const added = String(newString ?? '');
    // An empty old_string makes Claude Code's Edit create a file that is missing or empty; in a file with text it names no place.
    if (oldString === '' && (current === null || current === '') && added !== '') return { next: added, added };
    return { next: simulateEdit(current, oldString, newString, ti.replace_all), added };
  }
  if (tool === 'MultiEdit') {
    let next = Array.isArray(ti.edits) ? current : null;
    for (const e of edits(ti)) next = next === null ? null : simulateEdit(next, e.old_string, e.new_string, e.replace_all);
    return { next, added: writtenText(tool, ti) };
  }
  return { next: null, added: writtenText(tool, ti) };
}

/**
 * True when parsed settings turn off prompts or hooks, wherever the key sits and however the text was escaped
 * (`"bypassPermissions"`). Semantic, so a protective deny rule that names the flag is not refused.
 */
function bypassInSettings(value, depth = 0) {
  if (depth > 8 || value === null || typeof value !== 'object') return false;
  return Object.entries(value).some(
    ([k, v]) => (k === 'disableAllHooks' && Boolean(v)) || (k === 'defaultMode' && v === 'bypassPermissions') || bypassInSettings(v, depth + 1),
  );
}

// A hook that runs a script of the pack, in either slash and any case (the paths of a Windows machine).
const PACK_HOOK_RE = /hardening[\\/]+hooks[\\/]+[\w-]+\.mjs/i;

/**
 * The pack's hook entries in parsed settings or a parsed Copilot hook file: every hook that runs a script of hardening/hooks/, as one canonical string of
 * its event, the matcher group around it (without the hook list) and the hook itself, mapped to its script. Whatever
 * differs in those (a matcher that matches nothing, another event, a timeout that always expires, another type, a word in
 * front of the command, an argument) is another entry, so a changed entry counts as a removed one (F1-45).
 */
function packHookEntries(settings) {
  const entries = new Map();
  const events = settings && typeof settings === 'object' ? settings.hooks : null;
  if (!events || typeof events !== 'object') return entries;
  for (const [event, groups] of Object.entries(events)) {
    for (const group of Array.isArray(groups) ? groups : []) {
      if (!group || typeof group !== 'object') continue;
      // Claude Code nests the hooks in a matcher group; GitHub Copilot's hook files list each hook on its own.
      const { hooks, ...rest } = group.hooks === undefined ? { hooks: [group] } : group;
      for (const hook of Array.isArray(hooks) ? hooks : []) {
        const script = PACK_HOOK_RE.exec(JSON.stringify(hook))?.[0];
        if (script) entries.set(canonicalJson({ event, rest, hook }), script.replace(/[\\/]+/g, '/'));
      }
    }
  }
  return entries;
}

/**
 * Why an edit of a file that registers hooks (`where`: "the settings", a Copilot hook file) removes, repoints or changes a
 * hook of the pack, or null. Every hook script stays referenced as often as before, and every pack entry of the current
 * text is still there exactly as it is (packHookEntries); additions are fine.
 */
function hookRegistrationChange(current, next, parsedNext, where) {
  const refs = (text) => {
    const counts = new Map();
    for (const ref of String(text ?? '').match(HOOK_REF_RE) ?? []) counts.set(ref, (counts.get(ref) ?? 0) + 1);
    return counts;
  };
  const after = refs(next);
  for (const [ref, n] of refs(current)) {
    if ((after.get(ref) ?? 0) < n) return `This edit removes or repoints a harness hook (${ref}) in ${where}. Only the user disables hooks (hardening/README.md, Disable).`;
  }
  let parsedCurrent = null;
  try {
    parsedCurrent = current === null ? null : JSON.parse(String(current).replace(/^﻿/, ''));
  } catch {
    // The names counted above are all there is to compare in a file that is not valid JSON.
  }
  const kept = packHookEntries(parsedNext);
  for (const [entry, script] of packHookEntries(parsedCurrent)) {
    if (!kept.has(entry)) {
      return `This edit removes or repoints a harness hook (${script}) in ${where}, or changes how it runs (event, matcher, command, type, timeout, flags). Only the user disables hooks (hardening/README.md, Disable).`;
    }
  }
  return null;
}

/** The settings' PATH, PATHEXT and NODE_OPTIONS (HOOK_START_ENV_RE, any letter case) as one comparable text. */
function hookStartEnv(settings) {
  const env = settings && typeof settings === 'object' && settings.env && typeof settings.env === 'object' && !Array.isArray(settings.env) ? settings.env : {};
  const pairs = Object.entries(env).filter(([k]) => HOOK_START_ENV_RE.test(k)).map(([k, v]) => [k.toUpperCase(), v]);
  return JSON.stringify(pairs.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0)));
}

/**
 * A GitHub Copilot hook file (.github/hooks/*.json) that holds a hook of the pack: deleting it, or an edit that removes or
 * changes one of those hooks, is denied like the same edit of the settings. A hook file without one is an ordinary critical
 * file (criticalAsk).
 */
function checkCopilotHooks(tool, rel, current, next, deletion) {
  if (current === null || !PACK_HOOK_RE.test(String(current))) return null;
  if (tool === 'NotebookEdit') return deny(`${rel} registers the harness hooks for GitHub Copilot; it is not a notebook.`);
  if (deletion) return deny(`This deletes ${rel}, which registers the harness hooks for GitHub Copilot. Only the user disables hooks (hardening/README.md, Disable).`);
  if (next === null) {
    return deny(`The guard cannot work out the result of this edit of ${rel}, which registers the harness hooks for GitHub Copilot (the old text was not found as written). Send the exact current text, or write the whole file.`);
  }
  let parsed;
  try {
    parsed = JSON.parse(next.replace(/^﻿/, ''));
  } catch (err) {
    return deny(`This change would leave ${rel}, which registers the harness hooks for GitHub Copilot, as invalid JSON (${err.message}).`);
  }
  const change = hookRegistrationChange(current, next, parsed, rel);
  return change ? deny(change) : null;
}

/** Checks for the files that steer the guards themselves: Claude Code settings, the harness config and Copilot's hook files. */
function checkGuardConfig(tool, ti, forms, current, next, deletion = false) {
  const settingsRel = forms.find((f) => SETTINGS_RE.test(f));
  const isSettings = settingsRel !== undefined;
  const isConfig = forms.some((f) => CONFIG_RE.test(f));
  const hooksRel = forms.find((f) => COPILOT_HOOKS_RE.test(f));
  if (!isSettings && !isConfig) return hooksRel === undefined ? null : checkCopilotHooks(tool, hooksRel, current, next, deletion);
  if (tool === 'NotebookEdit') return deny('Settings and the harness config are not notebooks.');
  // An apply_patch Delete File (deletion): what the file would hold is not the question, the file goes away.
  if (deletion && isSettings) {
    return deny(`This deletes ${settingsRel}, the Claude Code settings that register the harness hooks and hold the permission rules. Only the user removes them (hardening/README.md, Disable).`);
  }
  if (deletion) {
    return deny('This deletes hardening/harness.config.json, which steers the guards (approvals, agent scopes, reference folders, protected branches, the SQL read switch); without it the defaults apply, auto approval included. Only the user removes it (hardening/README.md, Approvals).');
  }
  if (next === null) {
    return deny('The guard cannot work out the result of this edit of a settings or harness config file (the old text was not found as written). Send the exact current text, or write the whole file.');
  }
  let parsed;
  try {
    parsed = JSON.parse(next.replace(/^﻿/, ''));
  } catch (err) {
    return deny(`This change would leave the file as invalid JSON (${err.message}).`);
  }
  if (isSettings) {
    if (bypassInSettings(parsed)) {
      return deny('The agent never turns off permission prompts or hooks (bypassPermissions, disableAllHooks, skipping permissions). The user starts such a session.');
    }
    // Every hook script stays referenced as often as before (repointing one hook to another script removes it too), and,
    // since the names alone do not tell whether a hook still runs (a matcher that matches nothing, a move to another
    // event, a timeout that always expires, another type, an `echo` in front or an argument keep every name), each hook
    // entry of the pack in the current settings is still there exactly as it is; additions are fine (F1-45).
    const change = hookRegistrationChange(current, next, parsed, 'the settings');
    if (change) return deny(change);
    let currentSettings = null;
    try {
      currentSettings = current === null ? null : JSON.parse(String(current).replace(/^﻿/, ''));
    } catch {
      // A file that is not valid JSON sets no variable.
    }
    if (hookStartEnv(currentSettings) !== hookStartEnv(parsed)) {
      return deny('This edit sets, changes or removes env.NODE_OPTIONS, env.PATH or env.PATHEXT in the settings. They decide whether node starts for the harness hooks at all: an unknown NODE_OPTIONS flag or a PATH without node stops every hook, and a hook that cannot start lets the call run unguarded. Only the user changes them (hardening/README.md, Disable).');
    }
  }
  if (isConfig && approvalsWidened(current, next)) {
    return deny('Only the user turns auto approval on or moves its end later (hardening/README.md, Approvals). The agent may set "mode": "ask" or end an active window earlier.');
  }
  // Everything else in the harness config steers the guards themselves (redaction, reference folders, protected
  // branches, reference copies, agent scopes, scan exclusions): the agent changes none of it.
  if (isConfig) {
    let before = {};
    try { before = current === null ? {} : JSON.parse(String(current).replace(/^﻿/, '')); } catch { before = null; }
    // The SQL read switch, like approvals: the agent may only make it stricter (off, fewer servers, a lower row cap,
    // more personal columns); only the user opens it.
    if (before !== null && sqlReadWidened(before, parsed)) {
      return deny('Only the user turns on or widens the SQL read switch (sources.sqlRead: mode "on", servers, mcpServers, maxRows, personalColumns). The agent may only make it stricter (README, Defaults you should know).');
    }
    // Desktop screenshots, likewise: off < ask < on, and only the user moves it up.
    if (before !== null && screenshotsWidened(before, parsed)) {
      return deny('Only the user turns Desktop screenshots on or from off to ask (desktop.screenshots in hardening/harness.config.json). The agent may only make it stricter (hardening/README.md, Approvals).');
    }
    const withoutStricterParts = (o) => {
      const obj = o && typeof o === 'object' ? o : {};
      const sources = obj.sources && typeof obj.sources === 'object' ? { ...obj.sources, sqlRead: undefined } : obj.sources;
      // Other keys of `desktop` stay compared; a `desktop` holding only the switch counts as absent, so adding
      // `"desktop": { "screenshots": "off" }` to a config without it is a narrowing, not another change.
      let desktop = obj.desktop && typeof obj.desktop === 'object' && !Array.isArray(obj.desktop) ? { ...obj.desktop, screenshots: undefined } : obj.desktop;
      if (desktop && typeof desktop === 'object' && !Array.isArray(desktop) && Object.values(desktop).every((v) => v === undefined)) desktop = undefined;
      return canonicalJson({ ...obj, approvals: undefined, sources, desktop });
    };
    if (before === null || withoutStricterParts(before) !== withoutStricterParts(parsed)) {
      return deny('The harness config steers the guards (redaction, reference folders, protected branches, agent scopes): only the user changes it. The agent may only make approvals, the SQL read switch and desktop.screenshots stricter (hardening/README.md, Approvals).');
    }
  }
  return null;
}

function checkWrite(input, cfg) {
  const tool = input.tool_name;
  const ti = input.tool_input ?? {};
  // The same keys as the verdict code below the call (`path` is the Copilot CLI's spelling): a file named by another key must not escape the checks.
  const target = ti.file_path ?? ti.notebook_path ?? ti.path;
  if (!target) return null;
  if (opaquePath(target)) return deny(OPAQUE_REASON);
  const relForms = projectRelForms(target);
  const forms = allForms(target);

  for (const form of forms) {
    const cls = classifyPath(form);
    if (cls.secret || cls.data) return deny(describePathBlock(form, cls));
    if (cls.desktopOwned) {
      return deny(`${form} is owned by Power BI Desktop (local settings, data cache, PBIR-Legacy report.json, mobileState or diagram layouts) and is not supported for external editing.`);
    }
    if (cls.autoDateTable) return deny(`${form} is an auto date/time table generated by Power BI Desktop; Microsoft does not support editing it with external tools.`);
    if (cls.kind === 'bim') return deny(`${form}: ${TMDL_ONLY_REASON}`);
  }
  if (relForms.some((f) => HOOK_LOGS_RE.test(f))) {
    return deny(`${relForms[0]} is in .claude/logs/, the hooks' own logs and session state, which the guards read back. Only the hooks write there; reading the logs stays open.`);
  }

  let current = null;
  try {
    current = fs.readFileSync(canonicalPathOf(withoutTrailingDots(target), PROJECT_DIR), 'utf8');
  } catch {
    // new file
  }
  // An apply_patch "Delete File" (flagged by host-vscode.mjs, never by a payload): nothing is written and the file goes
  // away, so the Tier 2 checks below judge it as emptied and the checks of what the file would hold are skipped.
  const deletion = input.host_delete === true;
  const { next, added } = deletion ? { next: '', added: '' } : resultingContent(tool, ti, current);
  // Project and user settings alike, the harness config and Copilot's hook files: before the outside-the-project exit below.
  const guardConfig = checkGuardConfig(tool, ti, forms, current, next, deletion);
  if (guardConfig) return guardConfig;

  const rel = relForms[0] ?? null;
  if (rel === null) return null; // outside the project: normal permission flow
  // Classify by the first form with a known kind: an 8.3 short name ("LOADEX~1.DTS") hides the real extension, the
  // resolved long form shows it, so content checks never depend on how the path was spelled.
  const clsRel = relForms.find((f) => classifyPath(f).kind !== 'other') ?? rel;
  const cls = classifyPath(clsRel);
  if (relForms.some((f) => isReferenceRel(f, cfg))) {
    return deny(`${rel} is a reference (templates/, a report's source/ folder, or a folder in the harness config's "references"): read it and copy from it, never edit it (AGENTS.md).`);
  }
  if (relForms.some((f) => /\.(?:ispac|dtproj\.user)$/i.test(f) || ssisBuildFolder(f))) {
    return deny(`${rel} is a build output or per-user file of an SSIS project (Visual Studio writes it). Edit the project's .dtsx, .params or .conmgr files instead.`);
  }
  // Fabric Git (docs/harness/fabric-git.md): a service commit deletes every file inside an item folder that is not part
  // of the item definition. A new such file is refused; an edit of one that already exists passes, and the validator
  // warns about it. A paginated report item holds one .rdl, so a second one is refused too.
  if (current === null) {
    for (const item of relForms.map(fabricItemOf).filter(Boolean)) {
      const problem = itemFolderProblem(item);
      if (problem) return deny(`${rel}: ${problem}`);
      if (item.kind === 'paginatedreport' && /\.rdl$/i.test(item.inner)) {
        const others = paginatedRdls(PROJECT_DIR, item.folder).filter((f) => f.toLowerCase() !== `${item.folder}/${item.inner}`.toLowerCase());
        if (others.length) return deny(`${rel}: ${item.folder}/ already holds ${others[0]}; a paginated report item folder holds one .rdl, and a Fabric Git commit from the service keeps only that one. Give the new report its own <Name>.PaginatedReport/ folder (docs/harness/fabric-git.md).`);
      }
    }
  }

  const badName = relForms.flatMap(pbirNameSegments).find((n) => !isValidPbirName(n));
  if (badName) return deny(`PBIR object name "${badName}" is invalid: use only letters, digits, "_" or "-", otherwise Power BI Desktop ignores the page/visual/bookmark.`);

  const secrets = findSecrets(added);
  if (secrets.length) {
    return deny(`Refusing to write a credential into ${rel} (${[...new Set(secrets.map((s) => s.id))].join(', ')}). Use a parameter or env var; data source credentials belong in Power BI Desktop/Service, not in files.`);
  }
  if (tool === 'NotebookEdit') return criticalWrite(relForms) ? criticalAsk(rel) : null; // a cell, not file text: judged by its path and its credentials
  // The edited text cannot be worked out (the old text is not in the file as written, the call names no place to edit, an
  // editor inserts text where only it knows): nothing below can run (F1-30). Where the guard compares Tier 2 facts of the
  // text (a model, a report's data sources, an SSIS package, a report's binding, a Fabric item's identity) the call asks;
  // a critical file asks as always. For any other file there is nothing to compare: no verdict, and the call is not
  // recognised as routine either, so the host's own flow decides and the PostToolUse check validates what was written.
  if (next === null) {
    const compared = cls.kind === 'tmdl' || cls.kind === 'bim' || cls.kind === 'rdl' || cls.kind === 'ssis' || relForms.some((f) => DEFINITION_PBIR_RE.test(f) || PLATFORM_RE.test(f));
    if (compared) return unevaluableAsk(rel);
    return criticalWrite(relForms) ? criticalAsk(rel) : { unevaluated: true };
  }

  if (cls.pbipText && next.charCodeAt(0) === 0xfeff) return deny(`${rel}: PBIP files must be UTF-8 without BOM.`);
  if (cls.kind === 'rdl') {
    const problem = deletion ? null : xmlProblem(next);
    if (problem) return deny(`This change would leave ${rel} as malformed XML (${problem.message}${problem.line ? `, line ${problem.line}` : ''}). Report Builder and the report server cannot open it.`);
    // Where the report reads data (rdlSourceFacts); a new file counts from nothing.
    const before = rdlSourceFacts(current ?? '');
    const after = rdlSourceFacts(next);
    const changed = [...new Set([...before.keys(), ...after.keys()])].filter((k) => before.get(k) !== after.get(k));
    if (changed.length) {
      const names = changed.length > 3 ? [...changed.slice(0, 3), `${changed.length - 3} more`] : changed;
      const routes = datasetRoutes(before, after, changed).slice(0, 3).map((r) => ` ${r}`).join('');
      return askUser(`This edit changes ${listed(names)} in ${rel}: the server, database, provider or shared item it reads, the data source a dataset reads, or a data source or dataset added or removed (Tier 2, .claude/rules/bi/rdl.md).${routes} Show the impact (which datasets, which server), then confirm.`);
    }
  }
  if (cls.kind === 'ssis') {
    const problem = deletion ? null : xmlProblem(next);
    if (problem) return deny(`This change would leave ${rel} as malformed XML (${problem.message}${problem.line ? `, line ${problem.line}` : ''}). Visual Studio (SSIS) and dtexec cannot load it.`);
    // Project, parameter, connection manager and configuration files always ask (.claude/rules/bi/ssis.md): they hold
    // the connections, the protection level and TargetServerVersion. Explicit here, so the ask also holds in permission
    // modes that would otherwise accept edits without a prompt.
    if (!/\.dtsx$/i.test(clsRel)) {
      return { decision: 'ask', autoApprovable: false, reason: `${rel} is an SSIS project, parameter, connection manager or configuration file: it sets connections, the protection level or TargetServerVersion (Tier 2). Confirm the change; secrets stay out of the file (DontSaveSensitive with parameters).` };
    }
    if (current !== null && !deletion && ssisBinaryItems(current) !== ssisBinaryItems(next)) {
      return deny('Script Task and Script Component code is stored as compiled binaries (<BinaryItem>) that Visual Studio rebuilds. Change the script in Visual Studio (SSDT), not the package text.');
    }
    if (current !== null) {
      const after = ssisIds(next);
      const lost = [...ssisIds(current)].filter((id) => !after.has(id));
      if (lost.length) {
        return { decision: 'ask', autoApprovable: false, reason: `This edit changes or removes existing object identities in ${rel} (${lost.slice(0, 3).join('; ')}${lost.length > 3 ? `; ${lost.length - 3} more` : ''}). Visual Studio, package logging and SSISDB reports identify objects by DTSID and refId: keep them, and give only new objects new GUIDs (.claude/rules/bi/ssis.md). Deleting or re-pathing an object is the user's call.` };
      }
    }
    if (ssisConnectionFacts(current ?? '') !== ssisConnectionFacts(next)) {
      return { decision: 'ask', autoApprovable: false, reason: `This edit sets or changes a connection string, server, password or protection level in ${rel}: where the package reads and writes data (Tier 2). Confirm it points at a local or test database; secrets stay out of the file (DontSaveSensitive with parameters).` };
    }
  }
  if (cls.kind === 'json' && !cls.jsonc && !deletion) {
    try {
      JSON.parse(next.replace(/^﻿/, '')); // a BOM is refused above for PBIP files
    } catch (err) {
      return deny(`This change would leave ${rel} as invalid JSON (${err.message}). Power BI Desktop refuses to open invalid PBIR/PBIP files.`);
    }
  }
  if (cls.kind === 'markdown') {
    const max = cfg.markdown.maxLines;
    const after = countLines(next);
    const before = current === null ? 0 : countLines(current);
    if (after > max && after > before) {
      return deny(`${rel} would have ${after} lines; the harness limit is ${max}. Split it: keep a short index file and move sections into linked sub-files (e.g. docs/<topic>/*.md or a skill's reference files).`);
    }
  }
  if (cls.kind === 'tmdl' && roleMembersChanged(current, next)) {
    return deny(`This edit changes the members of a role in ${rel}. Role membership is managed by the user (Power BI service, SSMS or Tabular Editor), never by the agent.`);
  }
  if (relForms.some((f) => matchesAny(f, cfg.sources?.referenceCopies ?? []))) {
    return askUser(`${rel} belongs to a reference copy of a model owned elsewhere (a cube or published model). Editing it changes nothing in that model and can mislead (Tier 2). Deliver the change as a request in docs/sources/<model>/requests/; edit the copy only after the user approves, to mirror the request or the owner's published version.`);
  }
  // Any edit of relationships.tmdl; in another TMDL file, a relationship added, removed, renamed or edited (a retargeted
  // column, a direction, an active flag), found by comparing the relationship blocks before and after (a new file counts from nothing).
  if (relForms.some((f) => RELATIONSHIPS_RE.test(f)) || (cls.kind === 'tmdl' && tmdlRelationshipFacts(current ?? '') !== tmdlRelationshipFacts(next))) {
    return askUser(`This edit of ${rel} adds, changes or removes a relationship: it changes how every visual and measure filters across tables (Tier 2, AGENTS.md). Show the impact (cardinality, direction, active path), then confirm.`);
  }
  if (cls.kind === 'tmdl' && current !== null) {
    const removed = removedDeclarations(current, next);
    if (removed.length) {
      return askUser(`This edit renames or removes model object(s): ${removed.join(', ')}. Visuals, measures and downstream reports that reference them will break (Tier 2). Approve only if intended.`);
    }
  }
  // A new file counts from nothing: a new table with an M partition adds a data source.
  if (cls.kind === 'tmdl') {
    const before = tmdlSourceFacts(current ?? '');
    const after = tmdlSourceFacts(next);
    const changed = Object.keys(TMDL_SOURCE_LABELS).filter((k) => before[k] !== after[k]);
    if (changed.length) {
      return askUser(`This edit changes ${listed(changed.map((k) => TMDL_SOURCE_LABELS[k]))} in ${rel} (Tier 2, AGENTS.md): show the impact (which tables, which server or path, refresh), then confirm.`);
    }
  }
  if (relForms.some((f) => DEFINITION_PBIR_RE.test(f)) && current !== null) {
    const before = bindingOf(current);
    if (before === undefined || before !== bindingOf(next)) {
      return askUser(`This edit changes the report's binding in ${rel} (datasetReference: byPath or byConnection): the report would read another model, and visuals bound to fields it lacks break (Tier 2, report bindings). Confirm the target model.`);
    }
  }
  // A Fabric item's identity: logicalId links the item across workspaces and branches, metadata.type says what it is. The
  // agent never changes either (docs/harness/fabric-git.md); a new file, a displayName or a version stay routine.
  if (current !== null && relForms.some((f) => PLATFORM_RE.test(f))) {
    const was = platformIdentity(current);
    const now = platformIdentity(next);
    if (was && ((was.logicalId !== undefined && was.logicalId !== now?.logicalId) || (was.type !== undefined && was.type !== now?.type))) {
      return askUser(`This edit changes the identity of the Fabric item in ${rel} (config.logicalId or metadata.type). logicalId links the item across workspaces and Git branches: a changed one makes Fabric Git treat the folder as another item (a duplicate, or a deleted and re-created item). The agent never changes it (docs/harness/fabric-git.md); approve only if you asked for exactly this.`);
    }
  }

  // What steers the agent or holds evidence and security settings (CRITICAL_WRITE_RE) always reaches the user. Claude Code's
  // settings ask rules cover only some of these files and Copilot never reads them, so the ask is the hook's own: it
  // also prompts in permission modes that accept edits (acceptEdits) and in every host. A floor ask: lab mode leaves the
  // harness's own files to the user, as it always did through the settings rules (F1-31).
  if (criticalWrite(relForms)) return criticalAsk(rel);

  const notes = [];
  if (cls.kind === 'tmdl' && /^ +\S/m.test(added)) notes.push('TMDL indentation uses tabs; the new text has lines indented with spaces.');
  if (cls.inPbip) {
    const branch = currentBranch();
    if (branch && cfg.git.protectedBranches.includes(branch) && firstTimeInSession(input.session_id, 'protected-branch-edit')) {
      notes.push(`You are editing PBIP files on protected branch '${branch}'. Create a feature branch before committing: git switch -c feature/<topic>.`);
    }
  }
  return notes.length ? { context: `[bi-harness] ${notes.join(' ')}` } : null;
}

await runHook(
  'PreToolUse',
  async (input, hostInput) => {
    const cfg = loadConfig();
    const tool = String(input.tool_name ?? '');
    let verdict = null;
    if (SHELL_TOOLS.has(tool)) {
      verdict = analyzeShellCommand(input.tool_input?.command, {
        protectedBranches: cfg.git.protectedBranches,
        getBranch: () => currentBranch(),
        baseDir: typeof input.cwd === 'string' ? input.cwd : undefined, // the shell's directory after earlier `cd`s
        references: cfg.references, // the config's read-only folders, besides templates/ and reports/*/source/
        sqlRead: cfg.sources?.sqlRead, // the SQL read switch (sql-read.mjs)
        screenshots: screenshotsOf(cfg).mode, // desktop.screenshots: off, ask (default) or on
      });
    } else if (READ_TOOLS.has(tool)) verdict = checkRead(input);
    else if (WRITE_TOOLS.has(tool)) verdict = checkWrite(input, cfg);
    // A Power BI DAX query or write whose connection this session has not confirmed asks (lib/mcp-state.mjs).
    else if (tool.startsWith('mcp__')) verdict = withConfirmedTarget(analyzeMcpCall(tool, input.tool_input, cfg), input, cfg);
    // A Copilot tool the translation does not know, whose text argument names a command or a local file (host-vscode.mjs):
    // the guard cannot judge it, so it asks. A floor ask (auto and lab mode leave it to the user, as when the merge added
    // it), put through the ask-once gate and the event log below like every other ask.
    const unmapped = unmappedToolReason(input);
    if (unmapped && verdict?.decision !== 'deny') verdict = { decision: 'ask', reason: unmapped, autoApprovable: false, floor: true };

    const ti = input.tool_input ?? {};
    const target = ti.file_path ?? ti.notebook_path ?? ti.path;
    const relForms = target && !opaquePath(target) ? projectRelForms(target) : [];
    // Never answer "allow" where a Claude Code deny rule applies (Claude Code blocks it anyway; the answer would mislead).
    const call = { command: ti.command, targets: target && !opaquePath(target) ? absoluteForms(target) : [] };
    const settingsDenied = Boolean(matchingRule('deny', tool, call));
    // GitHub Copilot (VS Code, the CLI, its Claude dialect) never evaluates Claude Code's permission rules (F1-12 below
    // for the ask rules): where a deny rule of the settings matches, the guard denies in its place, whatever its own
    // verdict and in every approvals mode. A terminal command is mapped to Bash whichever shell it runs in, so the rules
    // of both shell tools apply.
    if (verdict?.decision !== 'deny' && (isCopilotHost() || isCopilotClaudeDialect(input))) {
      const rule = (SHELL_TOOLS.has(tool) ? ['Bash', 'PowerShell'] : [tool]).map((name) => matchingRule('deny', name, call)).find(Boolean);
      if (rule) {
        verdict = deny(`This call matches the deny rule ${rule} of the Claude Code settings${target && !SHELL_TOOLS.has(tool) ? ` (${tool} ${relForms[0] ?? target})` : ''}. GitHub Copilot does not evaluate those rules, so the guard denies in their place.`);
      }
    }
    // Plan mode: auto and lab approvals are off; Claude Code honours a hook's allow there only for a read-only call.
    const autoOn = autoApprovalActive(cfg) && input.permission_mode !== 'plan';
    const allow = (reason, context) => ({
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision: 'allow',
        permissionDecisionReason: `[bi-harness] ${reason}`,
        ...(context ? { additionalContext: context } : {}),
      },
    });

    // An ask on a critical file stays with the user in every mode.
    if (verdict?.decision === 'ask' && WRITE_TOOLS.has(tool) && criticalWrite(relForms)) verdict.autoApprovable = false;

    // Positively recognised routine work: the only calls auto mode may answer "allow" when a Claude Code ask rule
    // would otherwise prompt (tests/settings-rules.test.mjs lists each such rule).
    // Computed only when needed: a denied command is never analysed twice. An edit whose result the guard could not work
    // out (`unevaluated`) is never positively recognised: no allow, whatever the file.
    const routineCall = verdict?.decision === 'deny' || verdict?.unevaluated ? false :
      (WRITE_TOOLS.has(tool) && routineWrite(relForms, cfg)) ||
      (SHELL_TOOLS.has(tool) && routineShell(ti.command, typeof input.cwd === 'string' ? input.cwd : undefined));
    // Lab mode (the user's switch; README.md, Approvals): no prompt for what the guard recognised (an ask other than
    // the floor, an allow, or routine work); every deny and floor ask stays. A call the guard did not recognise (no
    // verdict, not routine) keeps Claude Code's own flow: unknown is never turned into allow.
    const labOn = labModeActive(cfg) && input.permission_mode !== 'plan';
    const recognised = verdict?.decision === 'ask' || verdict?.decision === 'allow' || routineCall;
    if (labOn && recognised && !settingsDenied && verdict?.decision !== 'deny' && !verdict?.floor && (!WRITE_TOOLS.has(tool) || relForms.length > 0)) {
      if (verdict?.decision === 'ask') {
        appendJsonl('security-events.jsonl', {
          event: 'lab-approve',
          tool,
          agent: input.agent_type,
          ...(input.agent_id ? { agentId: String(input.agent_id) } : {}),
          session: String(input.session_id ?? '').slice(0, 8),
          reason: String(verdict.reason ?? '').slice(0, 300),
        });
      }
      return allow(`lab mode: ${verdict?.reason ?? 'no restriction applies'}`, verdict?.context);
    }
    // GitHub Copilot (VS Code, the CLI, its Claude dialect) never evaluates Claude Code's permission rules, so a call the
    // guard left to them runs unprompted with --allow-all-tools: rm or Remove-Item of a model file, an install, gh, az.
    // Where no verdict exists and the call is not routine, the guard asks in their place for every call an ask rule of
    // the settings matches (F1-12). The harness's own files and the critical files already ask in checkWrite, on every host.
    if ((!verdict || !verdict.decision) && !(autoOn && !settingsDenied && routineCall) && (isCopilotHost() || isCopilotClaudeDialect(input))) {
      // A terminal command is mapped to Bash whichever shell it runs in, so the rules of both shell tools apply.
      const rule = (SHELL_TOOLS.has(tool) ? ['Bash', 'PowerShell'] : [tool]).map((name) => matchingRule('ask', name, call)).find(Boolean);
      if (rule) {
        verdict = askUser(`This call matches the ask rule ${rule} of the project's Claude Code settings${target && !SHELL_TOOLS.has(tool) ? ` (${tool} ${relForms[0] ?? target})` : ''}. GitHub Copilot does not evaluate those rules, so the guard asks in their place.`);
      }
    }
    if (!verdict || !verdict.decision) {
      const context = verdict?.context;
      // Auto mode: routine work runs without a prompt; anything else follows Claude Code's own permission rules.
      if (autoOn && !settingsDenied && routineCall) {
        return allow(`auto mode: routine ${WRITE_TOOLS.has(tool) ? 'project file edit' : 'command'}`, context);
      }
      return context ? { hookSpecificOutput: { hookEventName: 'PreToolUse', additionalContext: context } } : null;
    }
    if (verdict.decision === 'allow' && settingsDenied) return null; // let the deny rule speak
    const auto = verdict.decision === 'ask' && autoOn;
    // A Claude Code ask rule that matches keeps its prompt unless the call is routine.
    if (auto && matchingRule('ask', tool, call) && !routineCall) verdict.autoApprovable = false;
    // Code the guard cannot see into (a script file, inline code with file or process calls): auto mode leaves it to
    // Claude Code's own permission flow instead of approving it.
    if (auto && verdict.autoDefer && verdict.autoApprovable !== false) return null;
    if (auto && verdict.autoApprovable !== false && !settingsDenied) {
      // Auto mode (README.md, Approvals): routine asks pass and are logged. Outward-facing, server, data-exposure and
      // critical-file asks are marked autoApprovable: false and still reach the user.
      appendJsonl('security-events.jsonl', {
        event: 'auto-approve',
        tool,
        agent: input.agent_type,
        ...(input.agent_id ? { agentId: String(input.agent_id) } : {}),
        session: String(input.session_id ?? '').slice(0, 8),
        until: cfg.approvals.until,
        reason: verdict.reason.slice(0, 300),
      });
      return {
        hookSpecificOutput: {
          hookEventName: 'PreToolUse',
          permissionDecision: 'allow',
          permissionDecisionReason: `[bi-harness] auto-approved (approvals.mode=auto${cfg.approvals.until ? ` until ${cfg.approvals.until}` : ''}): ${verdict.reason}`,
        },
      };
    }
    if (verdict.decision !== 'allow') {
      // GitHub Copilot runs this guard once per registration it finds (two or three copies of one call, one after another):
      // a later copy of an ask already put to the user for the same call and reason answers nothing and is logged as
      // `repeat` (lib/ask-once.mjs). A payload without a timestamp (Claude Code) and any failure here ask as before.
      let once = null;
      try {
        if (verdict.decision === 'ask') once = askOnce(input, verdict.reason, hostInput ?? input);
      } catch {
        once = null;
      }
      if (once?.decision === 'repeat') return null;
      appendJsonl('security-events.jsonl', {
        event: 'pre-tool-use',
        decision: verdict.decision,
        tool,
        ...(once ? { copy: once.copy } : {}),
        agent: input.agent_type,
        ...(input.agent_id ? { agentId: String(input.agent_id) } : {}),
        session: String(input.session_id ?? '').slice(0, 8),
        reason: verdict.reason.slice(0, 300),
      });
    }
    return {
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision: verdict.decision,
        permissionDecisionReason: `[bi-harness] ${verdict.reason}${auto && verdict.decision === 'ask' ? ' (Critical: auto mode always asks for this.)' : ''}`,
      },
    };
  },
  // An ask counts for the later copies only once it was written (lib/ask-once.mjs).
  { failClosed: true, afterOutput: (decision) => decision === 'ask' && markAsksEmitted() },
);
