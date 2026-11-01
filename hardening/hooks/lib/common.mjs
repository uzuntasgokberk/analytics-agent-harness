// Shared runtime for the BI harness: hook stdin/stdout protocol, paths, config, git, logs.
// Zero dependencies (Node.js >= 18). Every hook, the validator CLI and the git hooks import it.

import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  fromCopilotCli, isCopilotClaudeDialect, isCopilotCliHost, isCopilotHost, isVsCodeHost, mergeVerdicts, toClaudeCalls, toClaudeDialectOutput,
  toCopilotCliOutput, toHostOutput, VSCODE_HOST,
} from './host-vscode.mjs';

const HARNESS_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');

/** Project root: the session's project dir when running as a hook, else this harness checkout. */
export const PROJECT_DIR = path.resolve(process.env.CLAUDE_PROJECT_DIR || HARNESS_ROOT);

export const DEFAULT_CONFIG = Object.freeze({
  markdown: { maxLines: 500 },
  git: { protectedBranches: ['main', 'master'] },
  redaction: { secrets: true, piiInMcpOutput: true, piiInAllTools: false },
  // Names of the Power BI modeling MCP server: this harness's .mcp.example.json and Microsoft's sample registration.
  // Both lists count (powerbiServer is the older single setting); the policy also knows the server by its tool names.
  mcp: { powerbiServer: 'powerbi-modeling', powerbiServers: ['powerbi-modeling', 'powerbi-authoring-local'] },
  // Words that also add the Tier 2 deploy reminder to a prompt (English ones are built in), e.g. the team's language.
  deployReminder: { extraWords: [] },
  // TMDL copies of models owned elsewhere (cubes, published models): edits ask (Tier 2).
  // sqlRead: the SQL read switch (hooks/lib/sql-read.mjs). "off" (default): every query of a SQL client or SQL MCP
  // server asks the user, in every approvals mode. "on": a read-only, bounded query without personal columns against a
  // listed server passes in auto and lab mode. DML and DDL are denied either way; only the user widens the switch.
  sources: {
    referenceCopies: ['docs/sources/*/definition/**'],
    sqlRead: { mode: 'off', servers: [], mcpServers: [], maxRows: 50, personalColumns: [] },
  },
  // Extra read-only folders (project-relative prefixes ending in "/") besides templates/ and reports/*/source/: the
  // guard denies writes there, as for those two (AGENTS.md: references are read and copied, never edited). Example: a
  // lab's stand-in for the outside world ("setup/").
  references: [],
  // "auto" (default): routine work inside the repository runs without a prompt; critical actions (publish, deploy,
  // push, servers, data exposure, installs, harness files) still ask and "deny" never changes. `until` (optional, ISO
  // date and time with a time zone) ends auto at that time. "ask": every hook "ask" and Claude Code's own rules
  // prompt, for a developer who wants to see each step (README.md, Approvals).
  approvals: { mode: 'auto', until: null },
  // screenshots: what the guard does with `powerbi-desktop screenshot` and `screenshot-all`, which show the data on the
  // page. "ask" (default; also a missing or unknown value): asks in every approvals mode, lab included. "off": denied.
  // "on": approved and logged in auto and lab. Only the user widens it (docs/harness/desktop.md).
  desktop: { screenshots: 'ask' },
  // directories: the project-relative directories a Fabric workspace syncs (docs/harness/fabric-git.md), recorded by the
  // user; the Fabric Git warnings and the session banner check only those. null (default): not recorded, so an item
  // folder that holds .platform counts, which Desktop writes too. []: no directory is synced.
  fabric: { directories: null },
  scan: {
    exclude: [
      '.git/**',
      'node_modules/**',
      '.claude/logs/**',
      'hardening/tests/fixtures/**',
      '.claude/skills/bi-semantic-model/references/**',
      // The Claude desktop app's git worktrees: other checkouts of this repository, each scanned when run inside it.
      '.claude/worktrees/**',
    ],
  },
  // Per-subagent limits, enforced by hooks/agent-scope.mjs from the hook payload's agent_type.
  agentScopes: {
    'bi-dax-reviewer': { readOnly: true },
    'bi-report-reviewer': { readOnly: true },
    'bi-security-auditor': { readOnly: true },
    'bi-validator': { readOnly: true },
    'bi-source-analyst': { readOnly: true },
    'bi-tmdl-modeler': { mcpReadOnly: true, write: ['**/*.SemanticModel/**', '**/*.tmdl', 'docs/sources/**', 'docs/tests/**', 'reports/*/tests/**', 'reports/*/sql/**', 'TASKS.md'] },
    // StaticResources/: the theme files a report's resourcePackages name (a registered theme, a missing base theme).
    'bi-pbir-editor': { mcpReadOnly: true, write: ['**/*.Report/definition/**', '**/*.Report/StaticResources/**', 'TASKS.md'] },
    'bi-doc-generator': { mcpReadOnly: true, write: ['docs/**', 'reports/*/docs/**'] },
    'bi-rdl-analyst': { readOnly: true },
    'bi-rdl-editor': { mcpReadOnly: true, write: ['**/*.rdl', '**/*.rds', '**/*.rsd', '**/*.rptproj', 'docs/tests/**', 'reports/*/tests/**', 'TASKS.md'] },
    // etl/<project>/: packages, project files, DDL proposals (sql/) and job scripts (jobs/), as the registry names them.
    'bi-ssis-editor': { mcpReadOnly: true, write: ['etl/*/**', 'docs/tests/**', 'TASKS.md'] },
  },
});

const isPlainObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

/** A user value replaces a default only when it has the default's shape (object, array, or a scalar for a scalar). */
const sameShape = (def, value) =>
  def === undefined || def === null
    ? true
    : isPlainObject(def) ? isPlainObject(value)
    : Array.isArray(def) ? Array.isArray(value) && value.every((v) => typeof v === typeof (def[0] ?? v))
    : typeof def === typeof value;

function merge(base, override) {
  if (!isPlainObject(override)) return base;
  const out = { ...base };
  for (const [key, value] of Object.entries(override)) {
    // A broken value (null, a string for a list) keeps the safe default instead of crashing every hook call.
    if (!sameShape(base[key], value)) continue;
    out[key] = isPlainObject(value) && isPlainObject(base[key]) ? merge(base[key], value) : value;
  }
  return out;
}

const configCache = new Map();

/**
 * hardening/harness.config.json merged over defaults. A missing file yields the defaults; a broken one the defaults
 * with approvals "ask", and so does an approvals.mode that is not a string or an approvals that is not an object.
 */
export function loadConfig(root = PROJECT_DIR) {
  if (configCache.has(root)) return configCache.get(root);
  let user = {};
  try {
    // A byte order mark is read past, as the config guard reads it: both must see the same settings.
    user = JSON.parse(fs.readFileSync(path.join(root, 'hardening', 'harness.config.json'), 'utf8').replace(/^﻿/, ''));
  } catch (err) {
    // A file that cannot be read or parsed never widens anything: approvals fall back to "ask" (the validator reports
    // the broken file).
    if (err?.code !== 'ENOENT') user = { approvals: { mode: 'ask', until: null } };
  }
  const cfg = merge(structuredClone(DEFAULT_CONFIG), user);
  // merge drops a value of the wrong shape and keeps the default, and the default mode is "auto": a mode that is not a
  // string (null, 0, false, [], {}) would run in auto here while approvalsOf and approvalsWidened read it as "ask", so an
  // edit from "ask" to null passed the widening check and switched prompts off. It is "ask" in every reader (F1-44).
  if (isPlainObject(user?.approvals) && Object.hasOwn(user.approvals, 'mode') && typeof user.approvals.mode !== 'string') cfg.approvals.mode = 'ask';
  // Likewise an `approvals` that is not an object (`"approvals": "auto"`, null, a list): merge keeps the default "auto",
  // so it is "ask" here, as in approvalsOf.
  if (isPlainObject(user) && Object.hasOwn(user, 'approvals') && !isPlainObject(user.approvals)) cfg.approvals = { ...cfg.approvals, mode: 'ask' };
  configCache.set(root, cfg);
  return cfg;
}

const UNTIL_RE = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2})(?:\.\d{1,3})?)?(?:Z|[+-](\d{2}):(\d{2}))$/;

/**
 * Milliseconds of a strict ISO 8601 date and time with a time zone ("2026-10-07T00:00:00+03:00"), else NaN.
 * Date-only values, local times, other formats and impossible dates (30 February) are refused, not guessed.
 */
export function parseUntil(value) {
  const m = typeof value === 'string' ? UNTIL_RE.exec(value) : null;
  if (!m) return NaN;
  const [y, mo, d, h, mi, s = 0, oh = 0, om = 0] = m.slice(1).map((v) => (v === undefined ? 0 : Number(v)));
  const day = new Date(Date.UTC(y, mo - 1, d));
  if (day.getUTCFullYear() !== y || day.getUTCMonth() !== mo - 1 || day.getUTCDate() !== d) return NaN;
  if (h > 23 || mi > 59 || s > 59 || oh > 14 || om > 59) return NaN;
  return Date.parse(value);
}

const MODES = new Set(['auto', 'ask', 'lab']);
/**
 * The approvals settings with the defaults filled in (a missing mode is the default "auto"). The mode is trimmed and
 * lower-cased, so `" lab"` or `"Auto"` count; any other spelling is "ask" and `unknownMode` keeps the text for the
 * message (a typo must not switch prompts off silently, nor stay silent). An `approvals` that is there but is not an
 * object (`"approvals": "auto"`, null, a list) is "ask" too, with `rawApprovals` for the message.
 */
function approvalsOf(cfg) {
  const raw = cfg?.approvals;
  const approvals = { ...DEFAULT_CONFIG.approvals, ...(isPlainObject(raw) ? raw : {}) };
  if (raw !== undefined && !isPlainObject(raw)) return { ...approvals, mode: 'ask', modeKnown: false, rawMode: undefined, rawApprovals: raw };
  const mode = typeof approvals.mode === 'string' ? approvals.mode.trim().toLowerCase() : '';
  const known = MODES.has(mode);
  return { ...approvals, mode: known ? mode : 'ask', modeKnown: known, rawMode: approvals.mode };
}

/**
 * When auto approval ends, as milliseconds: Infinity for "auto" without `until`, the `until` time for "auto" with a
 * valid one, -Infinity for "ask", any other mode, or an `until` that is not an ISO date and time with a time zone.
 */
function autoEnd(approvals) {
  // "lab" is "auto" and more: every ask the guard can judge passes, only the floor (outward-facing actions) still asks.
  if (approvals.mode !== 'auto' && approvals.mode !== 'lab') return -Infinity;
  if (approvals.until === null || approvals.until === undefined || approvals.until === '') return Infinity;
  const until = parseUntil(approvals.until);
  return Number.isFinite(until) ? until : -Infinity;
}
/** When lab mode ends, as milliseconds; -Infinity when the mode is not "lab". */
const labEnd = (approvals) => (approvals.mode === 'lab' ? autoEnd(approvals) : -Infinity);

/** Auto approval state: on in "auto" or "lab" mode until `until` (if set). `reason` says why it is off. */
export function autoApprovalState(cfg, now = new Date()) {
  const approvals = approvalsOf(cfg);
  if (Object.hasOwn(approvals, 'rawApprovals')) {
    return { active: false, reason: `approvals ${JSON.stringify(approvals.rawApprovals)} is not an object such as { "mode": "auto" }: treated as "ask"` };
  }
  if (!approvals.modeKnown) {
    return { active: false, reason: `approvals.mode ${JSON.stringify(approvals.rawMode ?? null)} is not "auto", "ask" or "lab": treated as "ask"` };
  }
  if (approvals.mode !== 'auto' && approvals.mode !== 'lab') return { active: false, reason: null };
  const end = autoEnd(approvals);
  if (end === -Infinity) {
    return { active: false, reason: `${approvals.mode} is set but \`until\` is not an ISO date and time with a time zone (2026-10-07T18:00:00+03:00)` };
  }
  if (now.getTime() >= end) return { active: false, reason: `${approvals.mode} is set but \`until\` has passed` };
  return { active: true, reason: null };
}

export const autoApprovalActive = (cfg, now = new Date()) => autoApprovalState(cfg, now).active;
/** Lab mode: the user's switch for test sessions without prompts (README.md, Approvals). Only the user turns it on. */
export const labModeActive = (cfg, now = new Date()) => approvalsOf(cfg).mode === 'lab' && autoApprovalState(cfg, now).active;

/**
 * True when an edit of harness.config.json would let auto approval run longer than it does now: "ask" to "auto",
 * deleting an "ask" setting (the default is "auto"), removing `until` or moving it later. Only the user may do that;
 * the agent may switch to "ask" or end auto earlier.
 */
export function approvalsWidened(currentText, nextText) {
  const read = (text) => {
    if (text === null || text === undefined) return approvalsOf({});
    try {
      return approvalsOf(JSON.parse(String(text).replace(/^﻿/, '')));
    } catch {
      return approvalsOf({});
    }
  };
  const before = read(currentText);
  const after = read(nextText);
  return autoEnd(after) > autoEnd(before) || labEnd(after) > labEnd(before);
}

// From strictest to widest: only the user moves `desktop.screenshots` up this list.
const SCREENSHOT_RANK = Object.freeze({ off: 0, ask: 1, on: 2 });
/**
 * The Desktop screenshot switch (`desktop.screenshots`): trimmed and lower-cased like approvals.mode. A missing value
 * is the default "ask" (known); any other spelling is "ask" too, with `known` false so the session start can say so.
 */
export function screenshotsOf(cfg) {
  const raw = isPlainObject(cfg?.desktop) ? cfg.desktop.screenshots : undefined;
  if (raw === undefined) return { mode: 'ask', known: true, raw };
  const value = typeof raw === 'string' ? raw.trim().toLowerCase() : '';
  const known = Object.hasOwn(SCREENSHOT_RANK, value);
  return { mode: known ? value : 'ask', known, raw };
}

/** True when parsed config `after` opens Desktop screenshots further than `before` (off < ask < on; missing is ask). */
export const screenshotsWidened = (before, after) => SCREENSHOT_RANK[screenshotsOf(after).mode] > SCREENSHOT_RANK[screenshotsOf(before).mode];

// ---------------------------------------------------------------- hook protocol

/** Reads all of stdin. Resolves early if nothing arrives, so a hook can never hang the session. */
export function readStdin(timeoutMs = 5000) {
  return new Promise((resolve) => {
    if (process.stdin.isTTY) return resolve('');
    const chunks = [];
    const finish = () => {
      clearTimeout(timer);
      resolve(Buffer.concat(chunks).toString('utf8'));
    };
    const timer = setTimeout(() => {
      process.stdin.destroy();
      finish();
    }, timeoutMs);
    process.stdin.on('data', (chunk) => chunks.push(chunk));
    process.stdin.on('end', finish);
    process.stdin.on('error', finish);
  });
}

/**
 * True for a snake_case payload (`hook_event_name`, no camelCase `sessionId`). Copilot CLI sends its native hook file a
 * camelCase payload (sessionId, an epoch-millisecond timestamp; hooks/lib/host-vscode.mjs), so under
 * BI_HARNESS_HOST=copilot-cli such a payload comes from VS Code, which runs every .github/hooks/*.json file, the CLI's
 * included, with its own payload, and reads a Stop block only from hookSpecificOutput (F2-11).
 */
const isSnakeCasePayload = (parsed) =>
  Boolean(parsed) && typeof parsed === 'object' && typeof parsed.hook_event_name === 'string' && parsed.sessionId === undefined;

/**
 * VS Code's output (VS Code hooks reference, 2026-10-14): a Stop block nested in hookSpecificOutput (toHostOutput), a
 * SubagentStop block as top-level `decision` and `reason` only, with no hookSpecificOutput (F1-138).
 */
const toVsCodeOutput = (event, result) => (event === 'SubagentStop' ? result : toHostOutput(event, result));

/**
 * Runs a hook handler. The handler returns the JSON object to print on stdout (or null). A Copilot tool call reaches it as
 * the Claude-shaped calls of toClaudeCalls, each with the payload before translation as the second argument.
 * failClosed: a crash blocks the action (exit 2) instead of silently allowing it.
 * afterOutput: called with the printed permissionDecision (flat or nested; null when there is none) once the output was
 * written; not when nothing was printed or the write failed, and its errors change nothing.
 */
export async function runHook(event, handler, { failClosed = false, afterOutput } = {}) {
  // Every git call of this hook shares one budget below the hook's own timeout (gitBudgetMs, R2).
  startGitBudget(gitBudgetMs(event));
  try {
    const raw = await readStdin();
    if (failClosed && !raw.trim()) {
      // A guard that got no payload cannot decide, so it blocks.
      process.stderr.write(`[bi-harness] ${event} hook received no payload. Guard hooks fail closed, so this action was blocked.\n`);
      process.exitCode = 2;
      return;
    }
    const parsed = raw.trim() ? JSON.parse(raw) : {};
    // GitHub Copilot payloads come in camelCase from the native hook files (sessionId, toolName, toolArgs, toolResult)
    // or, through the Claude registration of .claude/settings*.json, with Claude's field names, the CLI's own argument
    // shapes and a `timestamp`; both are normalised here, host variable or not. A Claude Code payload is left as it is.
    const input = fromCopilotCli(parsed);
    const copilot = isCopilotHost() || isCopilotClaudeDialect(parsed);
    // A Copilot payload without a session id (VS Code's reference marks it optional): every event files its state under
    // the same fallback id the tool calls use (toClaudeCalls), so the Stop gate and the banner see what the tool hooks
    // recorded (F2-18). Claude Code always sends one.
    if (copilot && input && typeof input === 'object' && (input.session_id === undefined || input.session_id === null || input.session_id === '')) {
      input.session_id = VSCODE_HOST;
    }
    let result;
    if (copilot && input.tool_name !== undefined && (event === 'PreToolUse' || event === 'PostToolUse')) {
      // Copilot's tool names and input shapes become the Claude-shaped calls the policy knows
      // (hooks/lib/host-vscode.mjs); several files in one call give several verdicts, the strictest wins.
      const calls = toClaudeCalls(input, { cfg: loadConfig(), projectDir: PROJECT_DIR, event });
      const results = [];
      for (const call of calls) results.push(await handler(call, input));
      result = mergeVerdicts(event, results, calls);
      const unmapped = calls.find((c) => c.unmapped);
      if (unmapped) appendJsonl('tool-audit.jsonl', { event: 'unmapped', host: process.env.BI_HARNESS_HOST ?? 'copilot-claude', hook: event, tool: input.tool_name, inputKeys: Object.keys(input.tool_input ?? {}) });
    } else {
      result = await handler(input);
    }
    // VS Code nests a Stop block, the CLI's native hooks want a flat decision; the Claude registration run by the CLI
    // takes Claude's own shape plus `modifiedResult` for a masked output (probed with Copilot CLI 1.0.94, 2026-10-08).
    // stop-gate.mjs answers Stop and SubagentStop: the output takes the event the host sent. A Stop that VS Code sends to
    // the CLI's file (a snake_case payload) gets VS Code's nested block too, which keeps the CLI's flat decision and reason.
    const outEvent = event === 'Stop' && input?.hook_event_name === 'SubagentStop' ? 'SubagentStop' : event;
    const shaped = isVsCodeHost() || (isCopilotCliHost() && outEvent === 'Stop' && isSnakeCasePayload(parsed))
      ? toVsCodeOutput(outEvent, result)
      : isCopilotCliHost() ? toCopilotCliOutput(outEvent, result) : copilot ? toClaudeDialectOutput(result) : result;
    if (shaped && typeof afterOutput === 'function') {
      const decision = shaped.hookSpecificOutput?.permissionDecision ?? shaped.permissionDecision ?? null;
      process.stdout.write(JSON.stringify(shaped), (err) => {
        if (err) return;
        try {
          afterOutput(decision);
        } catch {
          // What was printed stands.
        }
      });
    } else if (shaped) process.stdout.write(JSON.stringify(shaped));
  } catch (err) {
    const message = `[bi-harness] ${event} hook error: ${err && err.message ? err.message : String(err)}`;
    if (failClosed) {
      process.stderr.write(
        `${message}\nGuard hooks fail closed, so this action was blocked. ` +
          'Diagnose with `claude --debug` (hook errors) and `node hardening/scripts/validate.mjs`; in a clone of the harness, `npm --prefix hardening test`.\n',
      );
      process.exitCode = 2;
      return;
    }
    process.stderr.write(`${message}\n`);
  }
}

// ---------------------------------------------------------------- paths

export const toPosix = (p) => String(p ?? '').replace(/\\/g, '/');

/** Built-in read-only reference folders (AGENTS.md): `templates/` and a report's `source/` folder. */
export const REFERENCE_RE = /^(?:templates\/|reports\/[^/]+\/source\/)/i;

/**
 * The config's `references` as lower-case POSIX prefixes ending in "/" ("setup", "setup\", "/setup/" and "./setup/"
 * all become "setup/"). Non-strings and entries that would match everything ("", "/", ".") are dropped.
 */
export function referencePrefixes(cfg) {
  const out = [];
  for (const p of Array.isArray(cfg?.references) ? cfg.references : []) {
    if (typeof p !== 'string') continue;
    let q = toPosix(p.trim()).replace(/^(?:\.\/)+/, '').replace(/^\/+/, '');
    if (!q || q === '.') continue;
    if (!q.endsWith('/')) q += '/';
    if (/^\.?\/$/.test(q)) continue;
    out.push(q.toLowerCase());
  }
  return out;
}

/** True when a project-relative POSIX path lies in a reference folder: built-in or the config's `references`. */
export const isReferenceRel = (rel, cfg) =>
  Boolean(rel) && (REFERENCE_RE.test(rel) || referencePrefixes(cfg).some((q) => String(rel).toLowerCase().startsWith(q)));

const SHARE_RE = /^[\\/]{2}(?:[?.][\\/]UNC[\\/])?(?![?.][\\/])[^\\/]/i;
/**
 * True on Windows for a share path (\\host\share, //host/share, \\?\UNC\host\share) while the project itself is not on a
 * share: such a path is never inside the project, and resolving it would make a guard connect to a host the command names
 * (seconds per unknown host, and a Windows sign-in attempt to it). Device paths (\\?\C:\..., \\.\...) name local files.
 */
export const foreignShare = (p) => process.platform === 'win32' && SHARE_RE.test(String(p ?? '')) && !SHARE_RE.test(PROJECT_DIR);

/**
 * The one spelling of an existing path: resolves symlinks, directory junctions, letter case and Windows
 * 8.3 short names (C:\Users\FIRSTN~1.LAS). Git reports this form, so compare git paths only against it.
 * A share outside a project that is not on one (foreignShare) is returned as written, without touching the network.
 */
export function canonicalPath(p) {
  const resolved = path.resolve(String(p));
  if (foreignShare(resolved)) return resolved;
  try {
    return fs.realpathSync.native(resolved);
  } catch {
    return resolved;
  }
}

/**
 * A written path with a `..` segment walked the way bash opens it: from the base (or the path's own root), `.` stays,
 * `..` goes to the parent of the PHYSICAL folder reached so far (a link resolved first: `c/..` with c -> .claude/logs is
 * .claude), any other segment is joined and resolved while it exists; from the first segment that does not exist on, the
 * rest is joined as text. Null for a Windows drive-relative path (`C:x`), which path.resolve places.
 */
function physicalWalk(written, base) {
  const win = process.platform === 'win32';
  let rest = written;
  let start;
  if (path.isAbsolute(written)) {
    const root = path.parse(written).root;
    rest = written.slice(root.length);
    start = path.resolve(root); // Windows: `/` is the current drive's root
  } else {
    if (win && /^[A-Za-z]:/.test(written)) return null;
    start = base === undefined ? process.cwd() : path.resolve(base);
  }
  let cur = start;
  try {
    cur = fs.realpathSync.native(start);
  } catch {
    // a base that does not exist: its segments below are joined as text
  }
  let missing = false;
  const tail = [];
  for (const seg of rest.split(win ? /[\\/]+/ : /\/+/)) {
    if (!seg || seg === '.') continue;
    if (missing) tail.push(seg);
    else if (seg === '..') cur = path.dirname(cur);
    else {
      try {
        cur = fs.realpathSync.native(path.join(cur, seg));
      } catch {
        missing = true;
        tail.push(seg);
      }
    }
  }
  return path.join(cur, ...tail);
}

/**
 * canonicalPath for a path that may not exist yet (a new file): canonicalizes its nearest existing parent. `base` places a
 * relative path (default: the working folder). A written path with a `..` segment is walked physically first
 * (physicalWalk), so a `..` after a link goes up from where the link points; any other path gives the result it always did.
 */
export function canonicalPathOf(p, base) {
  const written = String(p);
  let head = base === undefined ? path.resolve(written) : path.resolve(base, written);
  if (foreignShare(head)) return head;
  if (/(?:^|[\\/])\.\.(?:[\\/]|$)/.test(written)) head = physicalWalk(written, base) ?? head;
  const whole = head;
  const tail = [];
  for (;;) {
    try {
      return path.join(fs.realpathSync.native(head), ...tail);
    } catch {
      const parent = path.dirname(head);
      if (parent === head) return whole;
      tail.unshift(path.basename(head));
      head = parent;
    }
  }
}

const escapes = (rel) => rel === '..' || rel.startsWith(`..${path.sep}`) || path.isAbsolute(rel);

/** Windows drops trailing dots and spaces from each path segment: `.env.` opens `.env`. */
export const withoutTrailingDots = (p) =>
  toPosix(p).split('/').map((s) => (s === '.' || s === '..' ? s : s.replace(/[. ]+$/, ''))).join('/');

/**
 * True for spellings the guards cannot classify by name: an alternate data stream (`.env::$DATA`, `file:stream`), a
 * device path (`\\?\C:\...`, `\\.\...`) or an administrative share (`\\localhost\C$\...`, `\\<host>\D$\...`), which
 * names a local drive under a network path, outside every project-relative check. The tools never need them for
 * project files; an ordinary share (`\\server\share\...`) is a normal path outside the project.
 */
export function opaquePath(p) {
  const s = toPosix(p);
  if (/^\/\/[?.]\//.test(s)) return true;
  if (/^\/\/[^/]+\/[A-Za-z]\$(?:\/|$)/.test(s)) return true;
  return s.replace(/^[A-Za-z]:/, '').includes(':');
}

/**
 * Every project-relative spelling of a path: as written (trailing dots dropped, `..` collapsed as text, as Node and
 * PowerShell on Windows open it) and resolved (Windows 8.3 short names such as HARDEN~1, junctions, symlinks, a `..` after
 * a link walked from where the link points, as bash opens it). Guards check each, so another spelling of a protected file
 * is still caught.
 */
export function projectRelForms(p, root = PROJECT_DIR) {
  if (!p) return [];
  const forms = new Set();
  const written = withoutTrailingDots(p);
  const lexical = projectRel(written, root);
  if (lexical) forms.add(lexical);
  // The written path, not path.resolve's text-collapsed one: a `..` after a link is walked from where the link points.
  const resolved = path.relative(canonicalPath(root), canonicalPathOf(written, root));
  if (!escapes(resolved)) forms.add(resolved === '' ? '.' : toPosix(resolved));
  return [...forms];
}

/**
 * Project-relative POSIX path, or null when the path lies outside the project. A path that only looks
 * outside because project and file use different spellings of one directory is compared canonically,
 * so guards never skip a project file.
 */
export function projectRel(p, root = PROJECT_DIR) {
  if (!p) return null;
  const absolute = path.resolve(root, String(p));
  let rel = path.relative(root, absolute);
  if (escapes(rel)) rel = path.relative(canonicalPath(root), canonicalPathOf(absolute));
  if (rel === '') return '.';
  if (escapes(rel)) return null;
  return toPosix(rel);
}

const globCache = new Map();

/** Minimal glob: `**` spans directories, `*` and `?` stay inside one segment. Case-insensitive. */
export function globToRegExp(glob) {
  if (globCache.has(glob)) return globCache.get(glob);
  let re = '';
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === '*' && glob[i + 1] === '*') {
      const slash = glob[i + 2] === '/';
      re += slash ? '(?:.*/)?' : '.*';
      i += slash ? 2 : 1;
    } else if (c === '*') re += '[^/]*';
    else if (c === '?') re += '[^/]';
    else re += c.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  }
  const compiled = new RegExp(`^${re}$`, 'i');
  globCache.set(glob, compiled);
  return compiled;
}

export const matchesAny = (relPosix, globs = []) => globs.some((g) => globToRegExp(g).test(relPosix));

// ---------------------------------------------------------------- git

// The time one git call of a hook may take (git below): 3 s, or BI_HARNESS_GIT_TIMEOUT_MS where a slow machine needs more
// (a CI runner; tests/run-all.mjs sets it). It only raises the default, to at most 10 s: a hung git holds each call that
// long, and a hook past its own timeout lets the call through (hardening/README.md, Limits).
export const GIT_TIMEOUT_MS = 3000;
const GIT_TIMEOUT_MAX_MS = 10000;
/** The timeout of one git call, from BI_HARNESS_GIT_TIMEOUT_MS in `env` (default process.env) within GIT_TIMEOUT_MS..10 s. */
export function gitTimeoutMs(env = process.env) {
  const wanted = Number(env?.BI_HARNESS_GIT_TIMEOUT_MS);
  return Number.isFinite(wanted) && wanted > GIT_TIMEOUT_MS ? Math.min(Math.trunc(wanted), GIT_TIMEOUT_MAX_MS) : GIT_TIMEOUT_MS;
}

// All git calls of one hook process share one budget (audit 2026-10-31, third round, R2): a hook makes several in a row
// (four for `git switch other`, eight or more in the Stop gate), so the per-call timeout alone did not keep a hung git below
// the hook's own timeout. Each budget stays at least a third below the timeout its host registers (the three registration
// files; tests/self-protection.test.mjs reads them): 12 s of the 20 s the PreToolUse guard, the session start and the
// masking hook get everywhere; for the Stop gate 60 s of Claude Code's 90 s, and 20 s of the 30 s of Copilot CLI and VS Code
// (BI_HARNESS_HOST), where a Stop hook past its timeout fails open. runHook starts the budget; a script outside a hook (the
// validator, the pre-commit check) has none, since nothing times it out and a git that answers null there fails its check.
export const GIT_BUDGET_MS = 12000;
const STOP_GIT_BUDGET_MS = 60000;
const COPILOT_STOP_GIT_BUDGET_MS = 20000;
/**
 * The git time one hook process of `event` may spend in all under `host` (BI_HARNESS_HOST by default; '' is Claude Code):
 * GIT_BUDGET_MS, and for the Stop gate 60 s under Claude Code and 20 s under any host that sets BI_HARNESS_HOST.
 */
export const gitBudgetMs = (event, host = process.env.BI_HARNESS_HOST) => {
  if (event !== 'Stop' && event !== 'SubagentStop') return GIT_BUDGET_MS;
  return host ? COPILOT_STOP_GIT_BUDGET_MS : STOP_GIT_BUDGET_MS;
};
/** The timeout of the next git call: `perCallMs`, or what `spentMs` left of `totalMs` when that is less; 0 when nothing is left. */
export function gitCallTimeout(spentMs, perCallMs, totalMs) {
  const left = totalMs - spentMs;
  return left > 0 ? Math.min(perCallMs, left) : 0;
}
const gitClock = { totalMs: Infinity, spentMs: 0 };
/** Starts the git budget of this process (runHook): `totalMs` from now on, nothing spent yet. */
export function startGitBudget(totalMs) {
  gitClock.totalMs = Number.isFinite(totalMs) && totalMs > 0 ? totalMs : Infinity;
  gitClock.spentMs = 0;
}

/**
 * Runs git without a shell; returns stdout or null on any failure (not a repo, git missing, a timeout, the hook's git
 * budget used up: gitCallTimeout).
 */
export function git(args, { cwd = PROJECT_DIR } = {}) {
  // A hung git (an index.lock held by Desktop or Visual Studio, an antivirus scan, a network share) must not eat the hook's
  // own timeout: past it the call runs unguarded. Each call gets the per-call timeout or what is left of the hook's budget,
  // and none once it is spent; a failed git answers null, and the callers stay strict.
  const timeout = gitCallTimeout(gitClock.spentMs, gitTimeoutMs(), gitClock.totalMs);
  if (timeout <= 0) return null;
  const started = Date.now();
  try {
    return execFileSync('git', args, {
      cwd,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout,
      maxBuffer: 64 * 1024 * 1024,
      windowsHide: true,
    });
  } catch {
    return null;
  } finally {
    gitClock.spentMs += Date.now() - started;
  }
}

/** Current branch name (also on a fresh repo without commits); 'HEAD' when detached; null outside git. */
export function currentBranch(cwd = PROJECT_DIR) {
  const out = git(['symbolic-ref', '--short', '-q', 'HEAD'], { cwd }) ?? git(['rev-parse', '--abbrev-ref', 'HEAD'], { cwd });
  return out ? out.trim() || null : null;
}

export const isGitRepo = (cwd = PROJECT_DIR) => git(['rev-parse', '--is-inside-work-tree'], { cwd })?.trim() === 'true';

/** Uncommitted (modified, added, untracked, renamed) files as project-relative paths. */
export function gitChangedFiles(root = PROJECT_DIR) {
  const top = git(['rev-parse', '--show-toplevel'], { cwd: root })?.trim();
  const out = git(['status', '--porcelain=v1', '-z', '-uall'], { cwd: root });
  if (!top || out === null) return null;
  // Git prints the canonical path; compare it with the canonical project root, once.
  const base = canonicalPath(root);
  const repoTop = canonicalPath(top);
  const parts = out.split('\0');
  const files = [];
  for (let i = 0; i < parts.length; i++) {
    const entry = parts[i];
    if (!entry) continue;
    const xy = entry.slice(0, 2);
    if (xy[0] === 'R' || xy[0] === 'C') i++; // next part is the original path
    // Deleted paths still identify artifacts whose required files/references need checking.
    const rel = path.relative(base, path.join(repoTop, entry.slice(3)));
    if (rel && !escapes(rel)) files.push(toPosix(rel));
  }
  return files;
}

// ---------------------------------------------------------------- logs and per-session state

const LOG_DIR = () => path.join(PROJECT_DIR, '.claude', 'logs');

/** Appends one JSON line to .claude/logs/<fileName>; rotates at 5 MB. Never throws. */
export function appendJsonl(fileName, record) {
  try {
    fs.mkdirSync(LOG_DIR(), { recursive: true });
    const file = path.join(LOG_DIR(), fileName);
    try {
      if (fs.statSync(file).size > 5 * 1024 * 1024) fs.renameSync(file, `${file}.1`);
    } catch {
      // first write
    }
    fs.appendFileSync(file, `${JSON.stringify({ ts: new Date().toISOString(), ...record })}\n`);
  } catch {
    // Logging must never break a hook.
  }
}

const stateFile = (sessionId) =>
  path.join(LOG_DIR(), '.state', `${String(sessionId || 'no-session').replace(/[^\w-]/g, '_').slice(0, 80)}.json`);

/**
 * The instant of a hook payload's `timestamp` in epoch milliseconds, or null without one. Copilot stamps every payload:
 * epoch milliseconds in its camelCase dialect, ISO text in the snake_case one (hooks/lib/host-vscode.mjs), the same
 * instant either way; Claude Code sends none.
 */
export function eventTime(value) {
  const ms = typeof value === 'number' ? value : typeof value === 'string' && value.trim() ? Date.parse(value) : NaN;
  return Number.isFinite(ms) ? Math.trunc(ms) : null;
}

// One state file per session, shared by every hook of it, and a host runs several hooks at once (the PostToolUse hooks of
// parallel tool calls, two registrations of one hook). updateState reads, changes and writes it while it holds a lock
// file, and writes a temporary file that is renamed into place, so a reader never sees half a file and no writer loses
// another's change (F1-68). Neither throws: a lock not taken within LOCK_WAIT_MS is gone without, and a lock older than
// LOCK_STALE_MS was left by a hook that died, so it is removed. The state is also a control: the MCP connections a session
// confirmed (lib/mcp-state.mjs) and the asks a Copilot CLI copy already put to the user (lib/ask-once.mjs). Both read a
// change that was lost as not made and ask again, and only the hooks write the state: the shell and file guards deny
// every write under .claude/logs/ (GUARD_PATH_RE in policy.mjs, HOOK_LOGS_RE in guard-pre-tool-use.mjs).
const LOCK_WAIT_MS = 2000;
const LOCK_STALE_MS = 5000;
// Windows refuses to open or replace a file for a moment while another process opens, renames or scans it.
const BUSY_CODES = new Set(['EPERM', 'EBUSY', 'EACCES']);
/** Waits `ms` milliseconds without giving up the thread (the state helpers are synchronous). */
const pause = (ms) => {
  try {
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
  } catch {
    // no wait
  }
};

/** Takes the lock file `lock` (created exclusively); true when taken, false when it could not be within LOCK_WAIT_MS. */
function takeLock(lock) {
  const until = Date.now() + LOCK_WAIT_MS;
  for (;;) {
    try {
      fs.closeSync(fs.openSync(lock, 'wx'));
      return true;
    } catch (err) {
      if (err?.code === 'ENOENT') {
        try {
          fs.mkdirSync(path.dirname(lock), { recursive: true });
        } catch {
          return false;
        }
      } else if (err?.code === 'EEXIST') {
        try {
          if (Date.now() - fs.statSync(lock).mtimeMs > LOCK_STALE_MS) fs.rmSync(lock, { force: true });
        } catch {
          // released meanwhile
        }
      } else if (!BUSY_CODES.has(err?.code)) return false;
    }
    if (Date.now() >= until) return false;
    pause(5 + Math.floor(Math.random() * 20));
  }
}

/** Writes `text` to `file` through a temporary file in the same folder, renamed into place. Never throws. */
function writeAtomic(file, text) {
  const tmp = `${file}.${process.pid}.${Math.random().toString(36).slice(2, 10)}.tmp`;
  try {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(tmp, text);
    for (let attempt = 1; ; attempt += 1) {
      try {
        fs.renameSync(tmp, file);
        return;
      } catch (err) {
        if (!BUSY_CODES.has(err?.code) || attempt >= 10) throw err;
        pause(10 * attempt);
      }
    }
  } catch {
    try {
      fs.rmSync(tmp, { force: true });
      // The rename kept failing: a plain write still keeps the change (other writers wait for the lock).
      fs.writeFileSync(file, text);
    } catch {
      // The change is lost: its readers take it as not made (the controls among them ask again).
    }
  }
}

/** The session's state object; {} when there is none or it cannot be read (a busy or half-written file is read again first). */
export function readState(sessionId) {
  const file = stateFile(sessionId);
  for (let attempt = 1; ; attempt += 1) {
    try {
      const state = JSON.parse(fs.readFileSync(file, 'utf8'));
      return state && typeof state === 'object' && !Array.isArray(state) ? state : {};
    } catch (err) {
      if (err?.code === 'ENOENT' || attempt >= 4) return {};
      pause(10 * attempt);
    }
  }
}

/** Changes the session's state with `mutate(state)` under the session's lock, saves it and returns it. */
export function updateState(sessionId, mutate) {
  const file = stateFile(sessionId);
  const lock = `${file}.lock`;
  const locked = takeLock(lock);
  try {
    const state = readState(sessionId);
    mutate(state);
    writeAtomic(file, JSON.stringify(state));
    return state;
  } finally {
    if (locked) {
      try {
        fs.rmSync(lock, { force: true });
      } catch {
        // a stale lock is removed by the next writer
      }
    }
  }
}

/** True the first time `key` is seen in this session. */
export function firstTimeInSession(sessionId, key) {
  let first = false;
  updateState(sessionId, (s) => {
    s.seen ??= {};
    if (!s.seen[key]) {
      s.seen[key] = true;
      first = true;
    }
  });
  return first;
}

/** Deletes session state files older than `days`. */
export function pruneState(days = 7) {
  const dir = path.join(LOG_DIR(), '.state');
  let names = [];
  try {
    names = fs.readdirSync(dir);
  } catch {
    return;
  }
  const cutoff = Date.now() - days * 86400000;
  for (const name of names) {
    try {
      const file = path.join(dir, name);
      if (fs.statSync(file).mtimeMs < cutoff) fs.unlinkSync(file);
    } catch {
      // ignore
    }
  }
}
