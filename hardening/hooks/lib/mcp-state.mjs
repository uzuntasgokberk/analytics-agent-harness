// Session state of the Power BI modeling MCP server (docs/harness/MCP.md, sections 2 and 4), kept per MCP server: the
// connections that a connection_operations answer confirmed with a success signal, a connect that confirmed nothing
// (pending), and the model writes that ran and are not persisted yet (each call once). post-tool-redact.mjs records them
// (fail-open: recording never breaks the masking); the PreToolUse guard asks before a query or write on an unconfirmed
// target; stop-gate.mjs blocks finishing once with pending writes and no diff in a model folder (the connection's own
// when known) that declares every object the writes named, and marks the writes persisted once the diff does;
// session-start.mjs names pending writes. The state file is the per-session JSON of hooks/lib/common.mjs; it holds
// connection and object names, folder paths and hashed call identities only, never a connection string, a credential, a
// definition or query text.

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { PROJECT_DIR, eventTime, git, matchesAny, opaquePath, projectRel, readState, toPosix, updateState } from './common.mjs';
import { findSecrets, powerBiMcpCall } from './policy.mjs';
import { findPbipItems } from './validators.mjs';

const MAX_CONNECTIONS = 20;
const MAX_WRITES = 200;
const MAX_PENDING_CONNECTS = 10;
// Staging folders of the repository kept per write (the newest): each is a copy the Stop gate must not read as the model.
const MAX_STAGING = 10;

// database_operations operations that save the connected model as files (MCP.md, section 4: export to a fresh staging
// folder, compare, merge). ExportToTmdlFolder is the one the harness documents (bi-data-sources); "exportto", "saveas"
// and "saveto" also cover the same step under another spelling (ExportToFolder, SaveAsTmdl, SaveToFolder). Not counted:
// ExportTMDL and ExportTMSL (READ_OPERATIONS: they return the script as text and write no file; once the agent writes
// the files, git shows the model diff and the stop gate passes on that), SaveChanges (TOM's commit to the engine, still
// in memory) and ImportFromTmdlFolder (it loads files into the model: a write).
export const PERSIST_OPERATION_PREFIXES = Object.freeze(['exportto', 'saveas', 'saveto']);

/** True for a call that saves the model as files (PERSIST_OPERATION_PREFIXES on database_operations). */
const isPersist = (call) => call.tool === 'database_operations' && call.ops.some((op) => PERSIST_OPERATION_PREFIXES.some((p) => op.startsWith(p)));
const isDisconnect = (call) => call.tool === 'connection_operations' && call.ops.some((op) => op.startsWith('disconnect'));
/** connection_operations calls whose answer names connections: connect, and the list/get reads (not local instances). */
const namesConnections = (call) =>
  call.tool === 'connection_operations' && call.ops.length > 0 && call.ops.every((op) => !/instances$/.test(op)) &&
  (call.read || call.ops.some((op) => op.startsWith('connect')));

export const sameName = (a, b) => String(a ?? '').trim().toLowerCase() === String(b ?? '').trim().toLowerCase();

/** The MCP server of a tool name (`mcp__<server>__<tool>`), as the policy splits it; '' for any other name. */
export const mcpServerOf = (toolName) => /^mcp__(.+?)__/.exec(String(toolName ?? ''))?.[1] ?? '';

/** The connections recorded on one MCP server (live and disconnected), at most one per name. */
const connectionsOn = (state, mcpServer) =>
  (Array.isArray(state?.mcpConnections) ? state.mcpConnections : []).filter((c) => c && typeof c.name === 'string' && c.name && sameName(c.mcpServer, mcpServer));

/**
 * The pending connect of one MCP server, or undefined (F1-39): a connect whose answer reported no failure (failed(),
 * connectFailed) and confirmed no connection. It may have connected, and the server then sends a call without a name to that connection,
 * so the target rule asks for such a call and an unnamed write is put on no connection until a connect with a readable
 * success, a list of the connections or a get of the current one (clearsPendingConnect) shows the server's connections.
 */
const pendingConnectOn = (state, mcpServer) =>
  (Array.isArray(state?.mcpPendingConnects) ? state.mcpPendingConnects : []).filter((p) => p && typeof p === 'object' && sameName(p.mcpServer, mcpServer)).at(-1);
/** A confirming connection_operations call that shows which connection the server uses: a connect, a list, a get of the current connection. A get of one named connection does not. */
const clearsPendingConnect = (call) =>
  call.ops.some((op) => op.startsWith('connect') || op.startsWith('list') || op === 'getcurrentconnection' || op === 'getlastused') ||
  (!call.connectionName && call.ops.some((op) => op.startsWith('get')));

export const shortHash = (text) => crypto.createHash('sha256').update(String(text)).digest('hex').slice(0, 16);
/** A value with the keys of every object sorted, so two spellings of one request serialize alike. */
export const canonical = (v, depth = 0) =>
  depth > 16 || v === null || typeof v !== 'object' ? v
    : Array.isArray(v) ? v.map((x) => canonical(x, depth + 1))
    : Object.fromEntries(Object.keys(v).sort().map((k) => [k, canonical(v[k], depth + 1)]));

/**
 * The identities of one tool call (F2-11), hashed: its `tool_use_id` when the payload has one (Claude Code, VS Code), and,
 * when the payload has a timestamp (every Copilot payload; the CLI's native payload carries no call id), the tool name
 * (the policy's `mcp__<server>__<tool>`), the request with its keys sorted and the timestamp in epoch milliseconds
 * (eventTime). A host that runs two registrations of the hooks sends one call to both copies: the second copy's write
 * shares an identity with the first and is not recorded again. A payload with neither (no id, no timestamp) has no
 * identity, and its writes are never merged: two identical writes are two writes.
 */
function callIdentities(input, call) {
  const ids = [];
  if (typeof input?.tool_use_id === 'string' && input.tool_use_id) ids.push(`u:${shortHash(input.tool_use_id)}`);
  const ms = eventTime(input?.timestamp);
  if (ms !== null) ids.push(`t:${shortHash(JSON.stringify([String(input.tool_name ?? ''), canonical(call.request), ms]))}`);
  return ids;
}

/** The project-relative form of a path inside the repository; null outside it, and for a stream or device path. */
const insideRepo = (p, root = PROJECT_DIR) => (p && !opaquePath(p) ? projectRel(p, root) : null);
const underFolder = (file, folder) => folder === '.' || String(file).toLowerCase().startsWith(`${String(folder).toLowerCase().replace(/\/+$/, '')}/`);

// ---------------------------------------------------------------- reading a tool response

const ENVELOPE_KEYS = new Set(['content', 'isError', 'structuredContent', '_meta']);
/** The MCP transport's result object ({content: [...], isError}): its flags are the host's, its text is the answer. */
const isEnvelope = (o) => Array.isArray(o?.content) && Object.keys(o).every((k) => ENVELOPE_KEYS.has(k));
const BLOCK_TYPES = new Set(['text', 'image', 'audio', 'resource', 'resource_link']);
const BLOCK_KEYS = new Set(['type', 'text', 'data', 'mimeType', 'resource', 'uri', 'name', 'title', 'description', 'size', 'annotations', '_meta']);
/** An MCP content block ({type: 'text', text}, an image, a resource): its text is an answer; the other kinds hold none. */
const isContentBlock = (o) => BLOCK_TYPES.has(o?.type) && Object.keys(o).every((k) => BLOCK_KEYS.has(k));
const parseJson = (t) => {
  if (!/^[[{]/.test(t)) return undefined;
  try {
    const v = JSON.parse(t);
    return v !== null && typeof v === 'object' ? v : undefined;
  } catch {
    return undefined;
  }
};

/**
 * The parsed parts of a tool response. The shape varies by host and server version: a string, `[{type:'text', text}]`,
 * an envelope `{content, isError, structuredContent}`, an object. `roots`: the answers that are objects (the response
 * object, an envelope's structuredContent, each JSON text); `objects`: every object of an answer with its depth below
 * its root (0 for the root; a list adds no level) and whether it sits in a list; `texts`: the answers that are plain
 * text (a string response, a text block); `strings`: every string that is not JSON, the values of answer fields
 * included; `transportError`: the envelope's `isError: true`.
 */
function responseParts(response) {
  const roots = [];
  const objects = [];
  const texts = [];
  const strings = [];
  let transportError = false;
  const within = (value, depth, listed, steps) => {
    if (steps > 16 || value === null || value === undefined) return;
    if (typeof value === 'string') {
      const t = value.trim();
      const parsed = parseJson(t);
      if (parsed) within(parsed, depth, listed, steps + 1);
      else if (t) strings.push(t);
      return;
    }
    if (typeof value !== 'object') return;
    if (Array.isArray(value)) {
      for (const v of value) within(v, depth, true, steps + 1);
      return;
    }
    objects.push({ o: value, depth, listed });
    for (const v of Object.values(value)) within(v, depth + 1, false, steps + 1);
  };
  const answer = (value, steps) => {
    if (steps > 8 || value === null || value === undefined) return;
    if (typeof value === 'string') {
      const t = value.trim();
      const parsed = parseJson(t);
      if (parsed) answer(parsed, steps + 1);
      else if (t) {
        texts.push(t);
        strings.push(t);
      }
      return;
    }
    if (typeof value !== 'object') return;
    if (Array.isArray(value)) {
      for (const v of value) answer(v, steps + 1);
      return;
    }
    if (isEnvelope(value)) {
      if (value.isError === true) transportError = true;
      answer(value.content, steps + 1);
      answer(value.structuredContent, steps + 1);
      return;
    }
    if (isContentBlock(value)) {
      answer(value.text, steps + 1);
      return;
    }
    roots.push(value);
    within(value, 0, false, steps);
  };
  answer(response, 0);
  return { roots, objects, texts, strings, transportError };
}

const field = (o, re) => Object.entries(o).find(([k]) => re.test(k))?.[1];

const FAILED_STATUS_RE = /^(?:error|errors|failed|failure|fail)$/i;
/**
 * True when the call failed outright: the envelope's `isError`, or a root with `isError`, `success: false`, an error
 * status, or an `error` field without `success: true`. One failed item inside a batch answer, a pending status or an
 * unknown shape do not make a call a failure here: writes count unless this says they failed (a write without an answer,
 * or one still pending, may have run), so the Stop gate keeps them. Confirmations and exports use succeeded() instead.
 */
function failed(parts) {
  return parts.transportError || parts.roots.some((o) => {
    if (field(o, /^is_?error$/i) === true || field(o, /^success(?:ful)?$/i) === false) return true;
    const status = field(o, /^(?:status|result_?type|outcome)$/i);
    if (typeof status === 'string' && FAILED_STATUS_RE.test(status.trim())) return true;
    const error = field(o, /^error$/i);
    return Boolean(error) && field(o, /^success(?:ful)?$/i) !== true;
  });
}

const STATUS_KEY_RE = /^(?:status|state|result)$/i;
const DONE_STATUSES = new Set(['ok', 'success', 'succeeded', 'completed', 'complete', 'done']);
const NOT_DONE_STATUSES = new Set(['failed', 'failure', 'error', 'pending', 'inprogress', 'running', 'queued', 'cancelled', 'canceled']);
/** A status value without case, spaces, hyphens or underscores ("In Progress" is "inprogress"). */
const statusWord = (v) => (typeof v === 'string' ? v.trim().toLowerCase().replace(/[\s_-]+/g, '') : '');
const nonEmpty = (v) =>
  v === true || (typeof v === 'string' ? v.trim() !== '' : Array.isArray(v) ? v.length > 0 : v && typeof v === 'object' ? Object.keys(v).length > 0 : typeof v === 'number' && v !== 0);

/** An object that reports a failure or an unfinished call: `success: false`, `ok: false`, `isError: true`, a non-empty `error`/`errors`, a failed or unfinished status. */
function reportsNotDone(o) {
  return Object.entries(o).some(([k, v]) =>
    ((/^success(?:ful)?$/i.test(k) || /^ok$/i.test(k)) && v === false) ||
    (/^is_?error$/i.test(k) && v === true) ||
    (/^errors?$/i.test(k) && nonEmpty(v)) ||
    (STATUS_KEY_RE.test(k) && NOT_DONE_STATUSES.has(statusWord(v))));
}

/** An object that reports success explicitly: `success: true`, `ok: true`, `isError: false`, a done status. */
function reportsDone(o) {
  return Object.entries(o).some(([k, v]) =>
    ((/^success(?:ful)?$/i.test(k) || /^ok$/i.test(k)) && v === true) ||
    (/^is_?error$/i.test(k) && v === false) ||
    (STATUS_KEY_RE.test(k) && DONE_STATUSES.has(statusWord(v))));
}

// Words that make an answer, or the text next to a connection name, a failure: it never confirms or persists.
const FAILURE_TEXT_RE =
  /\b(?:fail(?:s|ed|ure|ing)?|errors?|unable|could ?n[o']t|cannot|can[’']t|not (?:connected|found|available|reachable)|no (?:such )?connection|unavailable|unreachable|denied|refused|timed? ?out|invalid|disconnected|lost)\b/i;
// A state or status value of a connection that is not live.
const FAILED_STATE_RE = /fail|error|disconnect|closed|broken|lost|unavailable|invalid|denied|refused|time ?out/i;
// Words that make a text answer unfinished: it reports no success yet.
const INCOMPLETE_TEXT_RE = /\b(?:pending|queued|in[ _-]?progress|cancell?ed|aborted|still running|not (?:yet )?(?:complete|completed|finished|done))\b/i;
// "not connected", "nothing was exported" and the like say the opposite of the positive words below; they are removed
// before those are tested.
const NEGATED_RE = /\b(?:not|never|no longer|isn['’]t|wasn['’]t|weren['’]t|nothing (?:was|were|has been))\s+(?:been\s+|yet\s+)?(?:connected|exported|saved|written)\b/gi;
// A text answer that reports a live connection: "Connected to ...", "Connection established", "Current connection: ...".
const POSITIVE_CONNECT_RE = /\b(?:connected|connection (?:established|opened|succeeded|successful)|(?:current|active|open) connections?)\b/i;
// A text answer that reports a written export or save: "Exported 42 files to ...", "Saved", "written".
const POSITIVE_PERSIST_RE = /\b(?:exported|saved|written|wrote)\b/i;
const withoutNegations = (text) => String(text).replace(NEGATED_RE, ' ');

/**
 * The success signal of an answer (a connection confirmation, an export or save), explicit only (third audit,
 * 2026-10-16). Not success: the envelope's `isError`, an object at most two levels below a root that reports a failure
 * or an unfinished call (reportsNotDone: `{result: {success: false}}`, `{status: 'Pending'}`), a plain-text answer with a
 * failure or unfinished word. Success: a root or a direct child of one (not a list item) that reports success
 * explicitly (reportsDone), or a plain-text answer with a `positive` word. Anything else is an unknown shape: no
 * success. The envelope's `isError: false` is the transport's flag, not the server's answer: it never counts as one.
 */
function succeeded(parts, positive) {
  if (parts.transportError) return false;
  if (parts.objects.some(({ o, depth }) => depth <= 2 && reportsNotDone(o))) return false;
  if (parts.texts.some((t) => FAILURE_TEXT_RE.test(t) || INCOMPLETE_TEXT_RE.test(t))) return false;
  if (parts.objects.some(({ o, depth, listed }) => depth <= 1 && !listed && reportsDone(o))) return true;
  return parts.texts.some((t) => positive.test(withoutNegations(t)));
}

/** succeeded() for a raw tool response: `kind` 'connect' (a connection confirmation) or 'persist' (an export or save). */
export const answerSucceeded = (response, kind = 'persist') =>
  succeeded(responseParts(response), kind === 'connect' ? POSITIVE_CONNECT_RE : POSITIVE_PERSIST_RE);

/**
 * True when one object (a root, or an item that names a connection) reports a failure: `isError`, `success: false`, a
 * status or state that is not live, an `errors`/`error` field, or a message with a failure word, unless it says
 * `success: true` explicitly.
 */
function objectFailed(o) {
  if (field(o, /^is_?error$/i) === true || field(o, /^success(?:ful)?$/i) === false) return true;
  const status = field(o, /^(?:status|state|result_?type|outcome|connection_?state)$/i);
  if (typeof status === 'string' && FAILED_STATE_RE.test(status)) return true;
  if (field(o, /^success(?:ful)?$/i) === true) return false;
  const error = field(o, /^errors?$/i);
  if (Array.isArray(error) ? error.length > 0 : Boolean(error)) return true;
  const message = field(o, /^(?:message|detail|details|reason|summary)$/i);
  return typeof message === 'string' && FAILURE_TEXT_RE.test(message);
}

/**
 * True when a connect's answer reports a failure in words or fields although failed() does not count it as one: a
 * plain-text answer with a failure word and no word of a live connection ("Connection failed: ...", "Could not connect
 * to ..."), or a root or a direct child of one that reports a failure (objectFailed: a failed state, a message with a
 * failure word). Such a connect leaves no trace; any other connect that confirms nothing is pending (F1-39).
 */
const connectFailed = (parts) =>
  parts.texts.some((t) => FAILURE_TEXT_RE.test(t) && !POSITIVE_CONNECT_RE.test(withoutNegations(t))) ||
  parts.objects.some(({ o, depth, listed }) => depth <= 1 && !listed && objectFailed(o));

/**
 * The names (lower case) a text mentions next to a failure word: in the same line, between the neighbouring names, at
 * most 80 characters before or after ("Connection failed: PBIDesktop-Sales-1", "TMDL-Finance (error: ...)").
 */
function namesNearFailure(text, names) {
  const lower = text.toLowerCase();
  const spans = [];
  for (const n of new Set(names.map((x) => String(x).toLowerCase()).filter(Boolean))) {
    for (let i = lower.indexOf(n); i >= 0; i = lower.indexOf(n, i + 1)) spans.push([i, i + n.length, n]);
  }
  spans.sort((a, b) => a[0] - b[0]);
  const out = new Set();
  spans.forEach(([start, end, n], i) => {
    const lineStart = text.lastIndexOf('\n', start - 1) + 1;
    const newline = text.indexOf('\n', end);
    const lineEnd = newline < 0 ? text.length : newline;
    const from = Math.max(lineStart, start - 80, i > 0 ? spans[i - 1][1] : 0);
    const to = Math.min(lineEnd, end + 80, i + 1 < spans.length ? spans[i + 1][0] : text.length);
    if (FAILURE_TEXT_RE.test(text.slice(Math.min(from, start), start)) || FAILURE_TEXT_RE.test(text.slice(end, Math.max(end, to)))) out.add(n);
  });
  return out;
}

const NAME_KEY_RE = /^connection_?name$/i;
const SERVER_KEY_RE = /^(?:data_?source|server(?:_?name)?|host(?:_?name)?|address|endpoint)$/i;
const DATABASE_KEY_RE = /^(?:database(?:_?name)?|initial_?catalog|catalog|model(?:_?name)?|dataset(?:_?name)?|semantic_?model(?:_?name)?)$/i;
const PATH_KEY_RE = /^(?:(?:folder|file|project|tmdl|pbip|definition)_?path|path|folder)$/i;
const CONNECTION_STRING_KEY_RE = /^connection_?string$/i;
// Names the modeling server gives local targets in free text (policy.mjs, LOCAL_CONNECTION_NAME_RE).
const LOCAL_NAME_TOKEN_RE = /\b(?:PBIDesktop|TMDL|BIM)-[^\s"',;()]+|\bLocal-(?:localhost|127\.0\.0\.1)[^\s"',;()]*/gi;

/** A short name or path: no connection string (`;`, `=`), no credential, at most 200 characters. */
function cleanValue(v, { allowAssign = false } = {}) {
  if (typeof v !== 'string' && typeof v !== 'number') return undefined;
  const s = String(v).trim();
  if (!s || s.length > 200 || /[\u0000-\u001f]/.test(s)) return undefined;
  if (!allowAssign && /[;=]/.test(s)) return undefined;
  if (/password|pwd|secret|token/i.test(s) || findSecrets(s).length) return undefined;
  return s;
}

/** Server and database named by a connection string, never the string itself (its credentials stay out). */
function fromConnectionString(text) {
  const part = (re) => re.exec(String(text ?? ''))?.[1];
  return {
    server: cleanValue(part(/(?:^|;)\s*(?:data source|server|datasource|address)\s*=\s*([^;]+)/i)),
    database: cleanValue(part(/(?:^|;)\s*(?:initial catalog|database|catalog)\s*=\s*([^;]+)/i)),
  };
}

/** Server, database and path named by one object of a request or response. */
function targetFields(o) {
  const out = {};
  for (const [k, v] of Object.entries(o ?? {})) {
    if (SERVER_KEY_RE.test(k)) out.server ??= cleanValue(v);
    else if (DATABASE_KEY_RE.test(k)) out.database ??= cleanValue(v);
    else if (PATH_KEY_RE.test(k)) out.path ??= cleanValue(v);
    else if (CONNECTION_STRING_KEY_RE.test(k)) {
      const cs = fromConnectionString(v);
      out.server ??= cs.server;
      out.database ??= cs.database;
    }
  }
  return Object.fromEntries(Object.entries(out).filter(([, v]) => v !== undefined));
}

/**
 * The connections a connection_operations answer confirms, only when the answer reports success explicitly
 * (succeeded(); audits of 2026-10-16): an object with a connectionName (or a `name` inside a `connections` list), the
 * server, database and path next to it, that reports no failure; a local connection name in a text that reports a live
 * connection ("Connected to ...", "Current connection: ..."); for a connect, the name its request gave when the answer
 * names none. A failed, unfinished or unknown answer confirms nothing (a list text with one failed line included), and
 * a name with fail/error/unable/could not next to it in any text of the answer is never confirmed. A connect fills in
 * what its own request named (dataSource, a folder path).
 */
export function connectionsFromResponse(call, response) {
  const parts = responseParts(response);
  if (!succeeded(parts, POSITIVE_CONNECT_RE)) return [];
  const found = [];
  for (const { o } of parts.objects) {
    if (objectFailed(o)) continue;
    const nameKey = Object.keys(o).find((k) => NAME_KEY_RE.test(k));
    const name = nameKey ? cleanValue(o[nameKey], { allowAssign: true }) : undefined;
    if (name) found.push({ name, ...targetFields(o) });
    for (const [k, list] of Object.entries(o)) {
      if (!/connections$/i.test(k) || !Array.isArray(list)) continue;
      for (const item of list) {
        if (!item || typeof item !== 'object' || objectFailed(item) || Object.keys(item).some((key) => NAME_KEY_RE.test(key))) continue;
        const n = cleanValue(item.name ?? item.Name, { allowAssign: true });
        if (n) found.push({ name: n, ...targetFields(item) });
      }
    }
  }
  // The text of an object that reports a failure (a list item in state "Disconnected") confirms nothing either.
  const failedTexts = new Set(parts.objects.map(({ o }) => o).filter(objectFailed).flatMap((o) => Object.values(o).filter((v) => typeof v === 'string').map((v) => v.trim())));
  for (const t of parts.strings) {
    if (failedTexts.has(t) || !POSITIVE_CONNECT_RE.test(withoutNegations(t))) continue;
    for (const m of t.matchAll(LOCAL_NAME_TOKEN_RE)) found.push({ name: m[0].replace(/[.:]+$/, '') });
  }
  const connect = call.ops.some((op) => op.startsWith('connect'));
  if (connect && !found.length && call.connectionName) {
    const name = cleanValue(call.connectionName, { allowAssign: true });
    if (name) found.push({ name });
  }
  const vetoed = new Set();
  for (const t of parts.strings) for (const n of namesNearFailure(t, found.map((c) => c.name))) vetoed.add(n);
  const unique = [];
  for (const c of found) {
    if (vetoed.has(c.name.toLowerCase())) continue;
    const i = unique.findIndex((u) => sameName(u.name, c.name));
    if (i < 0) unique.push(c);
    else unique[i] = { ...c, ...unique[i] };
  }
  if (connect && unique.length === 1) unique[0] = { ...targetFields(call.request), ...unique[0] };
  return unique;
}

// ---------------------------------------------------------------- recording

// The argument naming where an export or save writes: path, folder, outputPath, tmdlFolderPath, destination.
const EXPORT_TARGET_KEY_RE = /^(?:\w*(?:path|folder|directory|dir)|output|destination|target)$/i;
const exportTarget = (request) =>
  Object.entries(request ?? {}).find(([k, v]) => EXPORT_TARGET_KEY_RE.test(k) && typeof v === 'string' && v.trim())?.[1].trim();

/**
 * The model folder recorded with a connection's writes, else modelFolderOf (the connection's confirmed path, its name):
 * `{ folder }` inside the repository, `{ outside }`, or null when unknown.
 */
function writesFolder(state, mcpServer, connection, writes, { root = PROJECT_DIR, cfg, items } = {}) {
  const folder = writes.find((w) => typeof w.folder === 'string')?.folder;
  if (folder) return { folder };
  const outside = writes.find((w) => typeof w.folderOutside === 'string')?.folderOutside;
  if (outside) return { outside };
  if (!connection) return null;
  const record = connectionsOn(state, mcpServer).find((c) => sameName(c.name, connection));
  return modelFolderOf({ name: connection, path: record?.path }, { root, cfg, items });
}

/**
 * True when an export or save into `rel` (project-relative) persists the writes of a connection whose model folder is
 * `known` (writesFolder): a model folder of the repository (isModelFolder) that Git does not ignore (an ignored folder is
 * staging wherever it is) and, when the connection's folder is known, exactly that one (its `definition/` subfolder
 * counts as the same folder). With the folder unknown, a `*.SemanticModel` or TMDL folder counts only when Git already
 * tracks files in it (`tracked`, trackedModel): the export itself writes the files (a database.tmdl, a definition/
 * folder) that make any fresh staging folder look like a model (F1-36).
 */
function persistsInto(rel, known, { root = PROJECT_DIR, cfg, items, tracked = false }) {
  if (rel === null || !isModelFolder(rel, items, cfg)) return false;
  if (known?.outside) return false;
  // `git check-ignore -q` answers by exit code: 0 (ignored) is an empty answer to git(), 1 (not ignored) and 128 (no
  // repository) are null. A path argument, not a pathspec: it takes no --literal-pathspecs.
  if (git(['check-ignore', '-q', '--', rel], { cwd: root }) !== null) return false;
  if (known?.folder) return sameModelFolder(rel, known.folder);
  return tracked;
}

/** True when Git tracks files in the model folder of `rel` (project-relative; for `X.SemanticModel/definition`, anywhere in `X.SemanticModel`, where `definition.pbism` lives). */
const trackedModel = (rel, root = PROJECT_DIR) => Boolean(git(['--literal-pathspecs', 'ls-files', '--', modelRootOf(rel)], { cwd: root })?.trim());

/**
 * The connection an export or save belongs to (third audit, 2026-10-16), as `{ name, via }`: the connectionName the
 * answer names in a root or in a direct child of one that is no list item, the scopes succeeded() reads its success
 * signal from (via 'answer'; naming different connections: none; F1-128), else the request's connectionName
 * ('request'), else the one live connection confirmed on its server ('live'); else null. A request and an answer that
 * name different connections: the answer wins, and the request's connection keeps its writes. Never decided by which
 * connections have pending writes.
 */
function exportConnection(call, parts, state, mcpServer) {
  const answered = [];
  for (const { o } of parts.objects.filter(({ depth, listed }) => depth <= 1 && !listed)) {
    for (const [k, v] of Object.entries(o)) {
      const n = NAME_KEY_RE.test(k) ? cleanValue(v, { allowAssign: true }) : undefined;
      if (n && !answered.some((a) => sameName(a, n))) answered.push(n);
    }
  }
  if (answered.length) return answered.length === 1 ? { name: answered[0], via: 'answer' } : null;
  const requested = cleanValue(call.connectionName, { allowAssign: true });
  if (requested) return { name: requested, via: 'request' };
  const live = connectionsOn(state, mcpServer).filter((c) => !c.disconnected);
  return live.length === 1 ? { name: live[0].name, via: 'live' } : null;
}

/**
 * An export or save (PERSIST_OPERATION_PREFIXES) with an explicit success signal. It covers the writes of the one
 * connection it belongs to on its server (exportConnection); none known, it covers nothing. Into that connection's
 * model folder (persistsInto) it clears them: git now shows the files. Into any other folder, inside the repository
 * (`exports/`, a staging folder, another model, a reference copy, an ignored folder) or outside it, it records
 * `exportedTo` on them (and, inside the repository, the folder in `stagedInside`, up to MAX_STAGING per write) and they
 * stay pending until the export is merged into the project's model folder (third audit, 2026-10-16). Without a
 * success signal or a target folder nothing changes.
 */
function recordPersist(input, call, parts, mcpServer, cfg) {
  if (!succeeded(parts, POSITIVE_PERSIST_RE)) return { action: 'persist-unconfirmed' };
  const target = exportTarget(call.request);
  if (!target) return { action: 'persist-no-target' };
  const rel = insideRepo(target);
  let items = null;
  try {
    items = findPbipItems(PROJECT_DIR, cfg);
  } catch {
    // no item list: only a *.SemanticModel folder can be recognized
  }
  let result = null;
  updateState(input.session_id, (s) => {
    const owner = exportConnection(call, parts, s, mcpServer);
    if (!owner) {
      result = { action: 'persist-unattributed' };
      return;
    }
    const writes = (Array.isArray(s.mcpWrites) ? s.mcpWrites : []).filter((w) => w && typeof w === 'object');
    const owned = writes.filter((w) => sameName(w.mcpServer, mcpServer) && sameName(w.connection, owner.name));
    const covered = owned.filter((w) => w.persisted !== true);
    const base = { connection: owner.name, via: owner.via };
    if (!covered.length) {
      result = { action: 'persist-nothing-pending', ...base };
      return;
    }
    // The connection's own folder is looked up in what the project held before this export (F1-36). findPbipItems runs
    // after it and lists the copy the export just wrote like any model folder, so a target Git does not track, and the
    // staging copies of the earlier exports of these writes, are left out of that list.
    const tracked = rel !== null && trackedModel(rel);
    const known = writesFolder(s, mcpServer, owner.name, covered, { cfg, items: withoutStaging(items, [...(tracked ? [] : [rel]), ...covered.flatMap(stagedFoldersOf)]) });
    if (persistsInto(rel, known, { cfg, items, tracked })) {
      s.mcpWrites = writes.filter((w) => !owned.includes(w));
      result = { action: 'persisted', ...base, folder: rel, cleared: covered.length };
      return;
    }
    const exportedTo = rel ?? cleanValue(target) ?? 'a folder outside the repository';
    for (const w of covered) {
      // Every staging copy of a write is kept (F1-37): the Stop gate must not read any of them as the model.
      if (rel !== null) w.stagedInside = [...stagedFoldersOf(w).filter((t) => !sameName(t, rel)), rel].slice(-MAX_STAGING);
      w.exportedTo = exportedTo;
      if (rel !== null) w.exportedInside = true;
      else delete w.exportedInside;
    }
    s.mcpWrites = writes;
    result = { action: 'exported-staging', ...base, exportedTo, inside: rel !== null };
  });
  return result;
}

const MAX_OBJECTS = 20;
/**
 * The object names a write request carries (third audit, 2026-10-16): `definitions[].name`, `names[]` and `name`, at
 * most 20, each a short name without a credential; never a definition or an expression.
 */
export function writtenObjects(request) {
  const out = [];
  const add = (v) => {
    const n = cleanValue(v, { allowAssign: true });
    if (n && n.length <= 128 && out.length < MAX_OBJECTS && !out.some((x) => sameName(x, n))) out.push(n);
  };
  const r = request && typeof request === 'object' ? request : {};
  const definitions = field(r, /^definitions$/i);
  for (const d of Array.isArray(definitions) ? definitions : []) if (d && typeof d === 'object') add(field(d, /^name$/i));
  const names = field(r, /^names$/i);
  for (const n of Array.isArray(names) ? names : []) add(n);
  add(field(r, /^name$/i));
  return out;
}

/**
 * Records one Power BI MCP call that ran (PostToolUse) in the session state, per MCP server (`mcpServer`). Connect,
 * list and get calls of connection_operations add or refresh the connections they confirm (name, server, database or
 * path, confirmedAt; at most 20, newest last); a disconnect marks the connection `disconnected` (all of that server's
 * when it names none) and never clears a write: Desktop or the server still holds the change in memory. A connect that
 * confirms nothing and did not fail is the server's pending connect (pendingConnectOn) until a connect, a list or a get of
 * the current connection confirms one (F1-39). A model write adds a `mcpWrites` entry (server, tool, operations, the
 * object names it carried, connection, the connection's model folder when known, the call's hashed identities, time),
 * once per call (callIdentities, F2-11); an unnamed write is put on the server's only live connection when there is
 * exactly one and no pending connect. An export or save handles the writes it covers (recordPersist). A failed call
 * changes nothing. Returns what it did, for tests and logs.
 */
export function recordMcpCall(input, cfg, now = new Date()) {
  const call = powerBiMcpCall(input?.tool_name, input?.tool_input, cfg);
  if (!call) return null;
  const mcpServer = mcpServerOf(input.tool_name);
  const response = input.tool_response;
  const parts = responseParts(response);
  const at = now.toISOString();
  if (failed(parts)) return { action: 'failed' };
  const onServer = (entry) => sameName(entry?.mcpServer, mcpServer);
  if (isDisconnect(call)) {
    const name = cleanValue(call.connectionName, { allowAssign: true }) ?? '';
    updateState(input.session_id, (s) => {
      s.mcpConnections = (s.mcpConnections ?? []).map((c) =>
        (onServer(c) && (!name || sameName(c.name, name)) ? { ...c, disconnected: true, disconnectedAt: at } : c));
    });
    return { action: 'disconnected', connection: name || null };
  }
  if (isPersist(call)) return recordPersist(input, call, parts, mcpServer, cfg);
  if (namesConnections(call)) {
    const via = call.ops.join(',').slice(0, 60);
    const found = connectionsFromResponse(call, response).map((c) => ({ mcpServer, ...c, via, confirmedAt: at }));
    if (!found.length) {
      if (!call.ops.some((op) => op.startsWith('connect')) || connectFailed(parts)) return { action: 'none' };
      // No failure (failed() above, connectFailed) and nothing confirmed: the connect may have run (pendingConnectOn, F1-39).
      const attempt = { mcpServer, ...targetFields(call.request), at };
      updateState(input.session_id, (s) => {
        s.mcpPendingConnects = [...(Array.isArray(s.mcpPendingConnects) ? s.mcpPendingConnects : []).filter((p) => !onServer(p)), attempt].slice(-MAX_PENDING_CONNECTS);
      });
      return { action: 'connect-pending', attempt };
    }
    const clears = clearsPendingConnect(call);
    updateState(input.session_id, (s) => {
      const kept = (s.mcpConnections ?? []).filter((c) => !(onServer(c) && found.some((f) => sameName(f.name, c.name))));
      s.mcpConnections = [...kept, ...found].slice(-MAX_CONNECTIONS);
      if (clears && Array.isArray(s.mcpPendingConnects)) {
        s.mcpPendingConnects = s.mcpPendingConnects.filter((p) => !onServer(p));
        if (!s.mcpPendingConnects.length) delete s.mcpPendingConnects;
      }
    });
    return { action: 'confirmed', connections: found.map((c) => c.name) };
  }
  if (call.modelWrite) {
    const named = cleanValue(call.connectionName, { allowAssign: true });
    const state = readState(input.session_id);
    const known = connectionsOn(state, mcpServer);
    const live = known.filter((c) => !c.disconnected);
    // An unnamed write goes to the server's last connection: the one live connection, unless a connect since may have
    // opened another (F1-39).
    const connection = named ?? (live.length === 1 && !pendingConnectOn(state, mcpServer) ? live[0].name : null);
    let where = null;
    try {
      where = connection ? modelFolderOf({ name: connection, path: known.find((c) => sameName(c.name, connection))?.path }, { cfg }) : null;
    } catch {
      // the folder is a hint for the Stop gate, which looks again
    }
    const objects = writtenObjects(call.request);
    const ids = callIdentities(input, call);
    const entry = {
      mcpServer,
      tool: call.tool.slice(0, 60),
      operations: call.ops.slice(0, 10).map((op) => op.slice(0, 40)),
      ...(objects.length ? { objects } : {}),
      connection,
      ...(connection && !named ? { inferred: true } : {}),
      ...(where?.folder ? { folder: where.folder } : where?.outside ? { folderOutside: cleanValue(where.outside) ?? 'a folder outside the repository' } : {}),
      ...(ids.length ? { ids } : {}),
      at,
    };
    let repeated = false;
    updateState(input.session_id, (s) => {
      const writes = Array.isArray(s.mcpWrites) ? s.mcpWrites : [];
      // The same call seen by a second copy of this hook (callIdentities): recorded once.
      repeated = ids.length > 0 && writes.some((w) => Array.isArray(w?.ids) && w.ids.some((id) => ids.includes(id)));
      if (!repeated) s.mcpWrites = [...writes, entry].slice(-MAX_WRITES);
    });
    return { action: repeated ? 'write-repeated' : 'write', write: entry };
  }
  return { action: 'none' };
}

// ---------------------------------------------------------------- the target rule (PreToolUse)

export const NO_TARGET_REASON = 'Name the connection (connectionName): no connection was confirmed on this MCP server in this session (docs/harness/MCP.md, confirm the target)';
const CONFIRM_STEP = 'Connect, or list or get the connection (connection_operations), and check that it holds the requested model first (docs/harness/MCP.md, confirm the target)';
const short = (s, n = 120) => String(s).slice(0, n);

/**
 * Why a DAX execute or a write may not reach its target yet (docs/harness/MCP.md, section 2), or null. Only the live
 * (not disconnected) connections confirmed on the call's own MCP server count: a name confirmed on another server is
 * another connection. A named call passes when its name is confirmed there. A call without a name goes to whichever
 * connection the server used last, so it passes only when exactly one is confirmed there and no connect since may have
 * opened another (pendingConnectOn, F1-39); with a pending connect, none or several it asks and says why. Metadata reads
 * and connection_operations are never held back.
 */
export function unconfirmedTarget(call, state, mcpServer = '') {
  if (!call?.needsTarget) return null;
  const all = (Array.isArray(state?.mcpConnections) ? state.mcpConnections : []).filter((c) => c && typeof c.name === 'string' && c.name);
  const here = all.filter((c) => sameName(c.mcpServer, mcpServer));
  const live = here.filter((c) => !c.disconnected);
  const where = `MCP server "${short(mcpServer, 60)}"`;
  const list = live.length ? live.map((c) => short(c.name)).join(', ') : 'none';
  if (!call.connectionName) {
    const pending = pendingConnectOn(state, mcpServer);
    if (pending) {
      const target = [pending.server, pending.database, pending.path].filter((v) => typeof v === 'string' && v).map((v) => short(v, 80)).join(', ');
      return `A connect on ${where}${target ? ` (${target})` : ''} answered without confirming a connection, so a call without a name may go to it: name the connection (connectionName), or list or get the current connection (connection_operations) first (docs/harness/MCP.md, confirm the target)`;
    }
    if (live.length === 1) return null;
    if (!live.length) return NO_TARGET_REASON;
    return `Name the connection (connectionName): ${live.length} connections are confirmed on ${where} (${list}), and a call without a name goes to whichever one the server used last (docs/harness/MCP.md, confirm the target)`;
  }
  if (live.some((c) => sameName(c.name, call.connectionName))) return null;
  const notes = [];
  if (here.some((c) => c.disconnected && sameName(c.name, call.connectionName))) notes.push('it was disconnected since');
  const elsewhere = [...new Set(all.filter((c) => !c.disconnected && !sameName(c.mcpServer, mcpServer) && sameName(c.name, call.connectionName)).map((c) => short(c.mcpServer ?? 'an unnamed server', 60)))];
  if (elsewhere.length) notes.push(`its confirmation on ${elsewhere.join(', ')} does not count for this server`);
  return `The connection "${short(call.connectionName)}" was not confirmed on ${where} in this session (confirmed there: ${list}${notes.length ? `; ${notes.join('; ')}` : ''}). ${CONFIRM_STEP}`;
}

/**
 * The guard's MCP verdict with the target rule applied, with or without a session state file: no file means no
 * confirmed connection, so a host without a SessionStart hook still gets the ask. It reads the state only (no
 * filesystem walk: the guard fails closed). An unconfirmed target asks the user (auto approval never passes it; lab
 * mode does). A deny stays a deny, a floor ask stays the floor and keeps its own reason after this one; a confirmed
 * target keeps the verdict as it is.
 */
export function withConfirmedTarget(verdict, input, cfg) {
  if (verdict?.decision === 'deny') return verdict;
  const call = powerBiMcpCall(input?.tool_name, input?.tool_input, cfg);
  if (!call?.needsTarget) return verdict;
  const reason = unconfirmedTarget(call, readState(input?.session_id), mcpServerOf(input?.tool_name));
  if (!reason) return verdict;
  if (verdict?.decision === 'ask') return { ...verdict, autoApprovable: false, reason: `${reason}. ${verdict.reason}` };
  return { decision: 'ask', reason: `${reason}.`, autoApprovable: false };
}

// ---------------------------------------------------------------- persistence (Stop gate, session start)

/**
 * True for a changed file (project-relative) that holds a model definition in a model folder: a file under
 * `*.SemanticModel/definition/`, a `definition.pbism` or `model.bim`, or a TMDL file of a folder findPbipItems lists
 * as tabular (`items.tabular`). Never a reference copy (`docs/sources/**`, `sources.referenceCopies`), a scan
 * exclusion (test fixtures, other worktrees) or a file under an `exports` folder: a .tmdl file elsewhere persists no MCP
 * write (second and third audits, 2026-10-16).
 */
export function isModelFile(rel, items, cfg) {
  const f = toPosix(rel).replace(/^(?:\.\/)+/, '');
  if (!f || STAGING_PATH_RE.test(f) || matchesAny(f, cfg?.sources?.referenceCopies ?? []) || matchesAny(f, cfg?.scan?.exclude ?? [])) return false;
  if (/(?:^|\/)[^/]+\.SemanticModel\/definition\//i.test(f) || /(?:^|\/)(?:definition\.pbism|model\.bim)$/i.test(f)) return true;
  return /\.tmdl$/i.test(f) && (Array.isArray(items?.tabular) ? items.tabular : []).some((t) => underFolder(f, t));
}

// Never a model folder: an `exports` folder at any level (the staging folder .gitignore ignores) and docs/sources/.
const STAGING_PATH_RE = /(?:^|\/)exports(?:\/|$)|^docs\/sources(?:\/|$)/i;
const SEMANTIC_MODEL_FOLDER_RE = /(?:^|\/)[^/]+\.SemanticModel(?:\/definition)?$/i;
const folderForm = (rel) => toPosix(rel).replace(/^(?:\.\/)+/, '').replace(/\/+$/, '') || '.';

/**
 * True for a model folder of the repository (project-relative): a `*.SemanticModel` folder or its `definition/`
 * subfolder, or a TMDL folder findPbipItems lists as tabular (`items.tabular`). Never under an `exports` folder,
 * `docs/sources/`, a reference copy (`sources.referenceCopies`) or a scan exclusion (third audit, 2026-10-16).
 */
export function isModelFolder(rel, items, cfg) {
  const f = folderForm(rel);
  if (f !== '.' && (STAGING_PATH_RE.test(f) || matchesAny(`${f}/`, cfg?.sources?.referenceCopies ?? []) || matchesAny(`${f}/`, cfg?.scan?.exclude ?? []))) return false;
  return SEMANTIC_MODEL_FOLDER_RE.test(f) || (Array.isArray(items?.tabular) ? items.tabular : []).some((t) => sameName(folderForm(t), f));
}

/** The folder of a model: `X.SemanticModel` for itself and for its `definition/`; any other folder as it is. */
const modelRootOf = (p) => folderForm(p).replace(/(\.SemanticModel)\/definition$/i, '$1');
/** True when two project-relative folders are one model folder: `X.SemanticModel` and `X.SemanticModel/definition` are. */
const sameModelFolder = (a, b) => sameName(modelRootOf(a), modelRootOf(b));

/** The staging folders inside the repository that exports recorded on a write: every one (`stagedInside`) and the last (`exportedTo`, which an older state holds alone). */
function stagedFoldersOf(w) {
  const all = [
    ...(Array.isArray(w?.stagedInside) ? w.stagedInside.filter((t) => typeof t === 'string' && t) : []),
    ...(w?.exportedInside === true && typeof w.exportedTo === 'string' && w.exportedTo ? [w.exportedTo] : []),
  ];
  return all.filter((t, i) => all.findIndex((u) => sameName(u, t)) === i);
}

/**
 * `items` (findPbipItems) without the model folders that an export wrote, `staged` being their project-relative targets.
 * findPbipItems runs after the export, so it lists a fresh staging copy (`staging/Unknown.SemanticModel`) like the
 * project's own folder; looking the connection's folder up in that list would make its own copy the model (F1-36).
 */
function withoutStaging(items, staged) {
  const targets = (Array.isArray(staged) ? staged : []).filter(Boolean);
  if (!items || !targets.length) return items;
  const written = (folder) => targets.some((t) => sameModelFolder(folder, t) || underFolder(folder, t));
  return { ...items, models: (items.models ?? []).filter((m) => !written(m)), tabular: (items.tabular ?? []).filter((m) => !written(m)) };
}

/**
 * The model folder of a connection, when known: the path its connect, list or get answer (or the connect request)
 * named; the path of a `TMDL-<path>` or `BIM-<path>` name; for `PBIDesktop-<name>[-<port>]`, the one
 * `<name>.SemanticModel` folder of the repository (none or several: unknown). `{ folder }` is project-relative,
 * `{ outside }` a folder outside the repository; null when unknown. A .pbip file stands for its `.SemanticModel`
 * folder, a .bim or .tmdl file for its folder.
 */
export function modelFolderOf(connection, { root = PROJECT_DIR, cfg, items } = {}) {
  const fromPath = (p) => {
    let q = toPosix(String(p).trim()).replace(/\/+$/, '');
    if (!q) return null;
    if (/\.pbip$/i.test(q)) q = q.replace(/\.pbip$/i, '.SemanticModel');
    else if (/\.(?:bim|tmdl|pbism)$/i.test(q)) q = path.posix.dirname(q);
    const rel = insideRepo(q, root);
    return rel === null ? { outside: q } : { folder: rel };
  };
  if (typeof connection?.path === 'string' && connection.path.trim()) return fromPath(connection.path);
  const name = String(connection?.name ?? '').trim();
  const file = /^(?:TMDL|BIM)-(.+)$/i.exec(name)?.[1];
  if (file && (/[\\/]/.test(file) || path.isAbsolute(file) || fs.existsSync(path.resolve(root, file)))) return fromPath(file);
  const desktop = /^PBIDesktop-(.+?)(?:-\d+)?$/i.exec(name)?.[1];
  if (desktop) {
    const models = (items ?? findPbipItems(root, cfg)).models.filter((rel) => sameName(path.posix.basename(rel), `${desktop}.SemanticModel`));
    if (models.length === 1) return { folder: models[0] };
  }
  return null;
}

// How a write is grouped (pendingMcpWrites) and found again (markMcpWritesPersisted): its MCP server and its connection.
const writeServer = (w) => (typeof w.mcpServer === 'string' ? w.mcpServer : '');
const writeConnection = (w) => (typeof w.connection === 'string' && w.connection ? w.connection : null);

/**
 * The MCP writes of a state not persisted yet (not marked `persisted`, markMcpWritesPersisted): how many, the connections
 * they went to (a label each), the time of the last one, and `groups`, one per MCP server and connection: count, the
 * model folder recorded with the writes, `exportedTo` (the last export into a folder that is not the model's own;
 * `exportedInside` when that folder is in the repository), `staging` (every such folder in the repository, the earlier
 * exports' included: none of them is the model, F1-37) and `disconnected` (the connection was disconnected since).
 */
export function pendingMcpWrites(state) {
  const writes = (Array.isArray(state?.mcpWrites) ? state.mcpWrites : []).filter((w) => w && typeof w === 'object' && w.persisted !== true);
  const groups = [];
  for (const w of writes) {
    const mcpServer = writeServer(w);
    const connection = writeConnection(w);
    let g = groups.find((x) => sameName(x.mcpServer, mcpServer) && sameName(x.connection, connection));
    if (!g) groups.push((g = { mcpServer, connection, count: 0, folder: null, folderOutside: null, exportedTo: null, exportedInside: false, staging: [], objects: [], tools: [] }));
    g.count += 1;
    for (const t of stagedFoldersOf(w)) if (!g.staging.some((x) => sameName(x, t))) g.staging.push(t);
    for (const o of Array.isArray(w.objects) ? w.objects : []) {
      if (typeof o === 'string' && o && g.objects.length < MAX_OBJECTS && !g.objects.some((x) => sameName(x, o))) g.objects.push(o);
    }
    if (typeof w.tool === 'string' && w.tool && !g.tools.includes(w.tool)) g.tools.push(w.tool);
    if (typeof w.folder === 'string') g.folder ??= w.folder;
    else if (typeof w.folderOutside === 'string') g.folderOutside ??= w.folderOutside;
    if (typeof w.exportedTo === 'string') {
      g.exportedTo = w.exportedTo;
      g.exportedInside = w.exportedInside === true;
    }
  }
  const servers = new Set(groups.map((g) => g.mcpServer.toLowerCase()));
  for (const g of groups) {
    const on = connectionsOn(state, g.mcpServer);
    g.disconnected = g.connection
      ? Boolean(on.find((c) => sameName(c.name, g.connection))?.disconnected)
      : on.length > 0 && on.every((c) => c.disconnected);
    g.label = `${g.connection ?? 'the last connection'}${servers.size > 1 && g.mcpServer ? ` (${g.mcpServer})` : ''}`;
  }
  return { count: writes.length, connections: groups.map((g) => g.label).join(', '), last: writes.at(-1)?.at ?? null, groups };
}

// ---------------------------------------------------------------- what the model diff mentions

const MAX_DIFF_FILE_BYTES = 8 * 1024 * 1024;
/** The lines of a working file (BOM and CR dropped); none when it is missing or larger than 8 MB. */
function fileLines(file) {
  try {
    if (fs.statSync(file).size > MAX_DIFF_FILE_BYTES) return [];
    return fs.readFileSync(file, 'utf8').replace(/^\uFEFF/, '').split(/\r?\n/);
  } catch {
    return [];
  }
}
const indentOf = (s) => /^[\t ]*/.exec(s)[0].length;

/**
 * The lines that enclose a line of indentation `indent`, walking back through `lines` from index `from`: each nearer
 * line with a smaller indentation (a TMDL object holds its properties and expression lines one level deeper:
 * `measure 'Net Margin' =` above an expression line, `table Sales` above that).
 */
function enclosing(lines, from, indent) {
  const out = [];
  let level = indent;
  for (let i = Math.min(from, lines.length - 1); i >= 0 && level > 0; i -= 1) {
    if (!lines[i].trim()) continue;
    const d = indentOf(lines[i]);
    if (d < level) {
      out.push(lines[i]);
      level = d;
    }
  }
  return { lines: out, level };
}

/** The first line after index `from` that is neither blank nor a `///` description: the object a description describes. */
function described(lines, from) {
  for (let i = Math.max(from, 0); i < lines.length; i += 1) {
    const t = lines[i].trim();
    if (t && !t.startsWith('///')) return lines[i];
  }
  return '';
}

// A TMDL line that declares an object: `measure 'Net Margin' =`, `measure Revenue = SUM ( ... )`, `column Amount`, `table Sales`,
// `ref table Sales`, `partition Sales = m`, `level Year` (any keyword, a bare or a quoted name with `''` for a quote).
// The words that open a DAX or M line inside an expression (`VAR r = [Revenue]`, `RETURN r`, `in Source`) are no keyword.
const EXPRESSION_WORDS = 'VAR|RETURN|let|in|each|if|then|else|and|or|not';
const DECLARATION_HEAD = `^[\\t ]*(?:ref[\\t ]+)?(?!(?:${EXPRESSION_WORDS})[\\t ])[A-Za-z]+[\\t ]+`;
const DECLARATION_END = '(?=[\\t \\r]|=|$)';
const ANY_DECLARATION_RE = new RegExp(`${DECLARATION_HEAD}(?:'(?:[^']|'')+'|[\\p{L}\\p{N}_][\\p{L}\\p{N}_.-]*)${DECLARATION_END}`, 'iu');
/** True for a TMDL line that declares an object (any keyword, any name). */
const isDeclaration = (line) => ANY_DECLARATION_RE.test(line);

// A `table` declaration (not `ref table`, not `tablePermission`): the object that holds a measure, a column, a partition.
const TABLE_LINE_RE = /^[\t ]*table[\t ]/i;

/**
 * The declaration that holds a changed TMDL line (a property such as `formatString: 0`, a line of an expression, a child
 * declaration such as `level Quarter`): the nearest enclosing line that declares an object, `removed` (the earlier deleted
 * lines of the same hunk) first, then the working file `lines` before index `from`; undefined when there is none. Only that
 * one: the table around a measure does not hold a changed property of a neighbour, so a neighbour's edit never persists a
 * write on an object that only shares the table's name.
 */
function holderOf(body, removed, lines, from) {
  const inHunk = removed.length ? enclosing(removed, removed.length - 1, indentOf(body)) : { lines: [], level: indentOf(body) };
  return [...inHunk.lines, ...enclosing(lines, from, inHunk.level).lines].find(isDeclaration);
}

/** A path of a `---`/`+++` line of a diff (`a/` or `b/` prefix; null for /dev/null). */
const diffPath = (s) => {
  let p = s.replace(/\t.*$/, '');
  if (/^".*"$/.test(p)) p = p.slice(1, -1).replace(/\\(["\\])/g, '$1').replace(/\\t/g, '\t');
  return /^[ab]\//.test(p) ? p.slice(2) : null;
};

/**
 * Reads a `git diff -U0` of the project (paths relative to `root`) into `add(file, text)`: per changed line its text
 * and, in a TMDL file, the object it stands for: for a `///` line the declaration it describes, for any other line the
 * nearest declaration that holds it (holderOf: earlier deleted lines of the same hunk first, then the working file),
 * unless the line is a declaration itself and that holder is a table.
 */
function readDiff(root, text, add) {
  let file = null;
  let header = false;
  let lines = null;
  let next = 1;
  let removed = [];
  for (const line of text.split(/\r?\n/)) {
    if (line.startsWith('diff --git ')) {
      file = null;
      header = true;
      lines = null;
      continue;
    }
    // `---`/`+++` name the file only in the header: in a hunk they are a removed or added line ("-- a comment").
    if (header && (line.startsWith('--- ') || line.startsWith('+++ '))) {
      const p = diffPath(line.slice(4));
      if (p) file = p;
      continue;
    }
    const hunk = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/.exec(line);
    if (hunk) {
      header = false;
      next = Number(hunk[1]) + (hunk[2] === '0' ? 1 : 0);
      removed = [];
      continue;
    }
    const sign = line[0];
    if (header || !file || (sign !== '+' && sign !== '-')) continue;
    const body = line.slice(1).replace(/\r$/, '');
    let piece = body;
    if (/\.tmdl$/i.test(file) && body.trim()) {
      lines ??= fileLines(path.join(root, file));
      // A description stands for the object it describes. Any other line stands for the declaration that holds it (the
      // measure of a property or of a line of its expression, the role of a new table permission, the hierarchy of a new
      // level) and, if it declares an object itself, for that object. Never for the table around a declaration: a
      // measure, a column or a partition added to a table does not change what a write on an object named like the
      // table meant (F1-40).
      if (body.trim().startsWith('///')) piece += `\n${described(lines, sign === '+' ? next : next - 1)}`;
      else {
        const holder = holderOf(body, sign === '-' ? removed : [], lines, next - 2);
        if (holder !== undefined && !(isDeclaration(body) && TABLE_LINE_RE.test(holder))) piece += `\n${holder}`;
      }
      if (sign === '-') removed.push(body);
    }
    add(file, piece);
    if (sign === '+') next += 1;
  }
}

/**
 * What the diff of each changed model file shows (third audit, 2026-10-16), as a Map of the project-relative path in
 * lower case to text; null when Git cannot tell (no repository, git missing or failing). A tracked file: its changed
 * lines (`git diff -U0` against HEAD; before the first commit, the index and the work tree), each with the one
 * declaration it stands for in a TMDL file (readDiff: the nearest declaration that holds it, the object a `///` line
 * describes; not the table around a declaration, and no further ancestor); context lines never count, so an edit next to
 * a measure does not touch it. An untracked file: its whole text.
 */
export function modelDiffTexts(root, files) {
  const list = [...new Set((Array.isArray(files) ? files : []).map((f) => toPosix(f)))];
  const out = new Map();
  const add = (rel, text) => {
    const k = toPosix(rel).toLowerCase();
    out.set(k, `${out.get(k) ?? ''}${text}\n`);
  };
  if (!list.length) return out;
  const head = git(['rev-parse', '--verify', '-q', 'HEAD'], { cwd: root }) !== null;
  const diff = ['--literal-pathspecs', '-c', 'core.quotePath=false', 'diff', '--no-color', '--no-ext-diff', '--no-textconv', '--no-renames', '-U0', '--src-prefix=a/', '--dst-prefix=b/', '--relative'];
  for (let i = 0; i < list.length; i += 50) {
    const chunk = list.slice(i, i + 50);
    for (const args of head ? [[...diff, 'HEAD', '--', ...chunk]] : [[...diff, '--', ...chunk], [...diff, '--cached', '--', ...chunk]]) {
      const text = git(args, { cwd: root });
      if (text === null) return null;
      readDiff(root, text, add);
    }
    const untracked = git(['--literal-pathspecs', 'ls-files', '--others', '--exclude-standard', '-z', '--', ...chunk], { cwd: root });
    if (untracked === null) return null;
    for (const rel of untracked.split('\0').filter(Boolean)) add(rel, fileLines(path.join(root, rel)).join('\n'));
  }
  return out;
}

const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
/**
 * True when a text mentions an object name, quoted or bare, without case: `'Net Margin'` (TMDL, `''` inside),
 * `[Net Margin]` (DAX, `]]` inside), `"Net Margin"` (JSON), or the bare name between characters that are neither part of
 * a name nor a quote.
 */
export function mentionsObject(text, name) {
  const n = String(name ?? '');
  if (!n || !text) return false;
  const quoted = [`'${n.replace(/'/g, "''")}'`, `[${n.replace(/]/g, ']]')}]`, JSON.stringify(n)].map(escapeRe);
  const bare = `(?<![\\p{L}\\p{N}_'"\\[])${escapeRe(n)}(?![\\p{L}\\p{N}_'"\\]])`;
  return new RegExp(`${quoted.join('|')}|${bare}`, 'iu').test(text);
}

/**
 * True when a text holds a TMDL line that declares the object, without case: `measure 'Net Margin' =` (`''` inside the
 * quotes), `measure Revenue = ...`, `column Amount`, `table Sales`, `ref table Sales`, a line of any keyword followed by
 * the name (isDeclaration). A reference such as `[Revenue]` or `Sales[Amount]` inside another object's expression, or the
 * name inside another declaration's DAX, is no declaration (audit 2026-10-18, F1-40).
 */
export function declaresObject(text, name) {
  const n = String(name ?? '');
  if (!n || !text) return false;
  const spelled = [`'${n.replace(/'/g, "''")}'`, n].map(escapeRe).join('|');
  return new RegExp(`${DECLARATION_HEAD}(?:${spelled})${DECLARATION_END}`, 'imu').test(text);
}

/**
 * The pending writes a stop may not pass yet (stop-gate.mjs): a group of writes passes with a changed model file
 * (isModelFile), under its connection's model folder when that is known (modelFolderOf, looked up again when the write
 * recorded none, without the staging copies its exports wrote); a model folder outside the repository never shows in the
 * diff, nor does the staging copy of any export of the group (F1-37). When the group's writes named objects
 * (writtenObjects), the diff of those files must also declare every one of them (modelDiffTexts; declaresObject in a TMDL
 * file, mentionsObject in any other; F1-40), else the group stays open with the names still `missing`; writes without
 * names, or no Git to ask, keep the folder rule alone. Same shape as pendingMcpWrites with only the open groups, `total`,
 * every pending write, and `persisted`, what the diff persisted (a group that passed, the objects a group that stays open
 * declared): markMcpWritesPersisted records it (F1-38). `diffTexts` replaces modelDiffTexts (tests).
 */
export function unpersistedMcpWrites(state, changedFiles, { root = PROJECT_DIR, cfg, diffTexts = modelDiffTexts } = {}) {
  const pending = pendingMcpWrites(state);
  if (!pending.count) return { ...pending, total: 0, persisted: [] };
  const items = findPbipItems(root, cfg);
  const changed = (Array.isArray(changedFiles) ? changedFiles : []).map((f) => toPosix(f)).filter((f) => isModelFile(f, items, cfg));
  let texts;
  const persisted = [];
  const open = pending.groups.filter((g) => {
    if (!g.folder && !g.folderOutside && g.connection) {
      const record = connectionsOn(state, g.mcpServer).find((c) => sameName(c.name, g.connection));
      // What the group's exports wrote is not where its connection's model was found (F1-36).
      const where = modelFolderOf({ name: g.connection, path: record?.path }, { root, cfg, items: withoutStaging(items, g.staging) });
      if (where?.folder) g.folder = where.folder;
      else if (where?.outside) g.folderOutside = cleanValue(where.outside) ?? 'a folder outside the repository';
    }
    if (g.folderOutside) return true;
    // The staging copies of the exports inside the repository are not the model folder, whatever their files look like.
    const mine = changed.filter((f) => !g.staging.some((t) => underFolder(f, t)) && (!g.folder || underFolder(f, g.folder)));
    if (!mine.length) return true;
    const group = { mcpServer: g.mcpServer, connection: g.connection };
    if (!g.objects.length) {
      persisted.push({ ...group, objects: [], all: true });
      return false;
    }
    if (texts === undefined) texts = diffTexts(root, changed);
    if (texts === null) return false;
    // A TMDL file persists an object with a line that declares it, any other model file (model.bim) with a mention.
    const declares = (f, o) => (/\.tmdl$/i.test(f) ? declaresObject : mentionsObject)(texts.get(f.toLowerCase()) ?? '', o);
    const declared = g.objects.filter((o) => mine.some((f) => declares(f, o)));
    g.missing = g.objects.filter((o) => !declared.includes(o));
    if (declared.length) persisted.push({ ...group, objects: declared, all: !g.missing.length });
    return g.missing.length > 0;
  });
  return {
    count: open.reduce((n, g) => n + g.count, 0),
    connections: open.map((g) => g.label).join(', '),
    last: pending.last,
    groups: open,
    total: pending.count,
    persisted,
  };
}

/**
 * Marks as `persisted` (and `persistedAt`) the pending writes that a diff persisted, `persisted` being what
 * unpersistedMcpWrites returned for them: every write of a group that passed, and, in a group that stays open, the
 * writes whose objects the diff all declared. A marked write is no longer pending (pendingMcpWrites), so committing the
 * diff, or resuming the session, does not bring the stop gate's block or the session start's reminder back (F1-38).
 * Changes `state`; the caller saves it.
 */
export function markMcpWritesPersisted(state, persisted, at = new Date().toISOString()) {
  const done = Array.isArray(persisted) ? persisted : [];
  for (const w of Array.isArray(state?.mcpWrites) ? state.mcpWrites : []) {
    if (!w || typeof w !== 'object' || w.persisted === true) continue;
    const p = done.find((x) => sameName(x.mcpServer, writeServer(w)) && sameName(x.connection, writeConnection(w)));
    const objects = Array.isArray(w.objects) ? w.objects : [];
    if (p && (p.all || (objects.length > 0 && objects.every((o) => p.objects.some((d) => sameName(d, o)))))) {
      w.persisted = true;
      w.persistedAt = at;
    }
  }
}

const sentence = (s) => `${s[0].toUpperCase()}${s.slice(1)}`;
/**
 * What the Stop gate and the session start say about pending writes, on one line: the writes, then per group a
 * disconnect (not a persist), an export outside the repository (merge it), the objects the diff does not declare
 * (`missing`) and the model folder the diff must touch.
 */
export function persistenceMessage(pending) {
  const notes = [];
  for (const g of Array.isArray(pending?.groups) ? pending.groups : []) {
    if (g.disconnected) notes.push(`${g.label} was disconnected, and disconnecting is not persisting: Desktop or the server still holds the change in memory`);
    if (g.exportedTo) notes.push(`${g.label} was exported to ${g.exportedTo}, which is not the project's model folder: merge the export into the project's model folder${g.folder ? ` (${g.folder})` : ''} and show the diff`);
    if (g.missing?.length) {
      const names = g.missing.slice(0, 10).map((o) => `'${o}'`).join(', ') + (g.missing.length > 10 ? ` and ${g.missing.length - 10} more` : '');
      notes.push(`the diff under ${g.folder ?? 'the model folders'} does not declare ${names}, which the writes on ${g.label} changed (${g.tools.join(', ') || 'MCP'}): another object's diff does not persist them`);
    }
    if (g.folderOutside) notes.push(`the model folder of ${g.label} (${g.folderOutside}) is outside the repository: merge it into the project and show the diff`);
    else if (g.folder) notes.push(`only a diff under ${g.folder} persists ${g.label}`);
  }
  return `${pending.count} MCP write(s) on ${pending.connections} are in the model's memory only; persist them (export/save to the PBIP, then \`git diff\`), or state that they were discarded, before finishing (docs/harness/MCP.md, Persistence).` +
    (notes.length ? ` ${notes.map(sentence).join('. ')}.` : '');
}
