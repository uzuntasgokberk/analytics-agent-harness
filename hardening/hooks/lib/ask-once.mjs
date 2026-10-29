// One prompt per call under GitHub Copilot. Copilot CLI runs every registration of the PreToolUse guard it finds, one
// after another: the VS Code file (.github/hooks/bi-harness.json), its own file (bi-harness.copilot-cli.json) and the
// Claude registration of .claude/settings*.json, and each copy that answers `ask` is a prompt of its own; a deny or a
// refused prompt ends the call, an approval or no answer lets the next copy run (Copilot CLI 1.0.103, probed 2026-10-28).
// The copies of one call share the session, the payload's `timestamp` (one instant for every call of a model message)
// and the raw arguments, and carry no call id. All this was probed under Copilot CLI only, so only a copy that carries a
// signal of it (copilotCliSignal) takes part; on any other host every copy asks as before.
//
// So each copy judges the call as before, and only its `ask` passes through here: per call key and reason, the session
// state counts the asks each copy (BI_HARNESS_HOST, or `claude` for the Claude registration) has handled. A copy whose
// count another copy's emitted asks exceed is a repeat of an ask the user already answered: it prints nothing (never an
// allow) and is logged as `repeat`. Counting, not a flag, keeps two identical calls of one message apart. A Claude Code
// payload carries no timestamp and is never touched. Every failure (no timestamp, unreadable arguments, a state that
// cannot be read or written, a record whose ask was never marked as written) ends in an ask.
import { appendJsonl, eventTime, readState, updateState } from './common.mjs';
import { canonical, shortHash } from './mcp-state.mjs';

/** The session state key of the records. */
export const ASK_ONCE_KEY = 'askCopies';
/** Records older than this are dropped: a person may take minutes to answer, a late answer costs one extra prompt. */
export const ASK_ONCE_MAX_AGE_MS = 3600000;
/** At most this many records per session, the newest kept. */
export const ASK_ONCE_MAX_RECORDS = 200;

const isPlainObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const count = (v) => (Number.isInteger(v) && v > 0 ? v : 0);

/** Which registration this process runs for: the shipped hook files set BI_HARNESS_HOST, the Claude registration none. */
export function copyIdentity(env = process.env) {
  const host = typeof env.BI_HARNESS_HOST === 'string' ? env.BI_HARNESS_HOST.trim() : '';
  return host ? host.slice(0, 40) : 'claude';
}

/**
 * The signal that this copy runs under Copilot CLI, where the copies and their prompts were probed, or null. Each one alone
 * is enough:
 * - `COPILOT_CLI` is 1 (true, yes, on): Copilot CLI 1.0.103 exported COPILOT_CLI=1 to every hook copy (observed
 *   2026-10-28, not documented). Returns 'COPILOT_CLI'.
 * - `BI_HARNESS_HOST` is copilot-cli: the CLI hook file (bi-harness.copilot-cli.json) sets it. Returns 'BI_HARNESS_HOST'.
 *   Alone it silences nothing: only copies with a signal record their asks, so a copy whose sibling copies carry none
 *   finds no other copy's ask and asks.
 * Nothing else counts, so an unknown host gets one prompt per copy, as before (fails toward asking): VS Code's Copilot
 * harness (not probed; it may run the CLI file first, whose answer to VS Code's payload has the CLI's flat shape) and the
 * GitHub Copilot app (it ran all three copies and prompted once per copy in the 2026-10-22 lab; whether it exports
 * COPILOT_CLI is not known).
 */
export function copilotCliSignal(env = process.env) {
  const cli = typeof env.COPILOT_CLI === 'string' ? env.COPILOT_CLI.trim().toLowerCase() : '';
  if (cli === '1' || cli === 'true' || cli === 'yes' || cli === 'on') return 'COPILOT_CLI';
  if (typeof env.BI_HARNESS_HOST === 'string' && env.BI_HARNESS_HOST.trim() === 'copilot-cli') return 'BI_HARNESS_HOST';
  return null;
}

/**
 * The key of one translated call, equal in every copy: session, event, instant (eventTime: epoch milliseconds in the
 * CLI's camelCase payload, ISO text in the others), the translated tool name, the target the translation found and the
 * raw arguments as the host sent them, keys sorted (`host` is the payload before translation, as fromCopilotCli read it:
 * the CLI copy's translation drops a shell call's `description`, so the translated input differs between copies). Null
 * without an instant or with arguments that could not be read.
 */
export function askKey(call, host = call) {
  const ms = eventTime(call?.timestamp);
  if (ms === null || call?.tool_input_unreadable === true || host?.tool_input_unreadable === true) return null;
  const ti = isPlainObject(call.tool_input) ? call.tool_input : {};
  const target = ti.file_path ?? ti.notebook_path ?? ti.path ?? '';
  return shortHash(JSON.stringify([String(call.session_id ?? ''), 'PreToolUse', ms, String(call.tool_name ?? ''), String(target), canonical(host?.tool_input)]));
}

/** Drops records older than an hour, or with no readable time. */
function expire(book, now) {
  for (const [id, rec] of Object.entries(book)) {
    const at = rec?.at;
    if (!isPlainObject(rec) || !Number.isFinite(at) || now - at > ASK_ONCE_MAX_AGE_MS || at - now > ASK_ONCE_MAX_AGE_MS) delete book[id];
  }
}

/** Keeps the newest ASK_ONCE_MAX_RECORDS records (after expire, every record has a time). */
function cap(book) {
  const ids = Object.keys(book);
  if (ids.length <= ASK_ONCE_MAX_RECORDS) return;
  ids.sort((a, b) => book[a].at - book[b].at);
  for (const id of ids.slice(0, ids.length - ASK_ONCE_MAX_RECORDS)) delete book[id];
}

// The asks this process claimed; markAsksEmitted marks them once the output that carries them was written.
const pending = [];

/**
 * Whether this copy puts the ask (`reason`) for `call` to the user: `{ decision: 'ask', copy }`, or `{ decision:
 * 'repeat', copy }` when another copy has already put the same ask for the same call to the user more often than this
 * copy has handled it (the repeat is logged here). Null without a Copilot CLI signal (copilotCliSignal) and for a call
 * without a key (no instant: Claude Code; unreadable arguments): the guard asks as before. Never throws; anything it
 * cannot read or write is an ask.
 */
export function askOnce(call, reason, host = call, { env = process.env, identity = copyIdentity(env), now = Date.now() } = {}) {
  if (!copilotCliSignal(env)) return null;
  let key = null;
  try {
    key = askKey(call, host);
  } catch {
    return null;
  }
  if (!key) return null;
  const copy = identity;
  const session = call.session_id;
  const id = `${key}.${shortHash(String(reason ?? ''))}`;
  let decision = 'ask';
  try {
    let mine = 0;
    updateState(session, (s) => {
      const book = isPlainObject(s[ASK_ONCE_KEY]) ? s[ASK_ONCE_KEY] : {};
      expire(book, now);
      const copies = isPlainObject(book[id]?.copies) ? book[id].copies : {};
      const own = isPlainObject(copies[copy]) ? copies[copy] : {};
      mine = count(own.n);
      const asked = Object.entries(copies).filter(([who, c]) => who !== copy && isPlainObject(c)).map(([, c]) => Math.min(count(c.e), count(c.n)));
      decision = Math.max(0, ...asked) > mine ? 'repeat' : 'ask';
      // A repeat counts as handled; only a written ask raises `e` (markAsksEmitted).
      copies[copy] = { n: mine + 1, e: Math.min(count(own.e), mine + 1) };
      book[id] = { at: now, copies };
      cap(book);
      s[ASK_ONCE_KEY] = book;
    });
    // The lock is best effort and the write never throws: a count that did not land is no repeat.
    const saved = readState(session)?.[ASK_ONCE_KEY]?.[id]?.copies?.[copy];
    if (!isPlainObject(saved) || saved.n !== mine + 1) decision = 'ask';
  } catch {
    decision = 'ask';
  }
  if (decision === 'repeat') {
    appendJsonl('security-events.jsonl', {
      event: 'pre-tool-use',
      decision: 'repeat',
      tool: call.tool_name,
      copy,
      agent: call.agent_type,
      session: String(session ?? '').slice(0, 8),
      reason: String(reason ?? '').slice(0, 300),
    });
  } else {
    pending.push({ session, id, copy });
  }
  return { decision, copy };
}

/** Marks this process's asks as put to the user: called once the hook's output was written. Never throws. */
export function markAsksEmitted() {
  for (const { session, id, copy } of pending.splice(0)) {
    try {
      updateState(session, (s) => {
        const own = s?.[ASK_ONCE_KEY]?.[id]?.copies?.[copy];
        if (isPlainObject(own)) own.e = Math.min(count(own.e) + 1, count(own.n));
      });
    } catch {
      // An unmarked record makes the next copy ask.
    }
  }
}
