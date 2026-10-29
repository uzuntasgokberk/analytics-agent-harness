// Stop / SubagentStop quality gate: before Claude (or an editor subagent) finishes, validate every
// uncommitted file. Errors send it back to fix them - at most twice in a row, then the user is warned.
// MCP writes that live only in the connected model's memory (no model diff that declares them) send the main agent back
// once; that block is one of the two the errors get. A second copy of the hook on the same Stop event (a host that runs
// two registrations) repeats the first copy's verdict instead of counting a second stop (the identity rule below).

import { eventTime, gitChangedFiles, loadConfig, PROJECT_DIR, readState, runHook, updateState } from './lib/common.mjs';
import { markMcpWritesPersisted, persistenceMessage, unpersistedMcpWrites } from './lib/mcp-state.mjs';
import { formatIssues, validateFiles } from './lib/validators.mjs';
import { runValidation } from '../scripts/validate.mjs';

// Stops with validation errors that block, in a row (a clean stop starts over). The counter is the loop guard, not
// Claude Code's `stop_hook_active`: that is true on every stop that follows a block, so reading it would end the second
// block before it came (F1-35).
const MAX_CONSECUTIVE_BLOCKS = 2;
// Unpersisted MCP writes block once per set of writes; the next stop warns the user instead (the agent may have stated
// that they were discarded). A new write after that blocks once again.
const MAX_MCP_BLOCKS = 1;
const MCP_KEY = 'mcpStopBlocks';

/**
 * True when Claude Code is already continuing because of a stop hook and the state file does not hold the counter just
 * written (it cannot be written): then no counter ends a block, and only `stop_hook_active` can keep the block from
 * repeating forever. With a state file that works this is always false.
 */
const unsaved = (input, key, expected) =>
  input.stop_hook_active === true && JSON.stringify(readState(input.session_id)[key]) !== JSON.stringify(expected);

/**
 * docs/harness/MCP.md, Persistence: an MCP write is not in the repository until it is exported or saved to the PBIP
 * and its diff exists. Pending writes (lib/mcp-state.mjs) block, then warn, unless a model file changed in a model
 * folder (never under docs/sources), under the connection's own model folder when that is known, and its diff declares
 * every object the writes named (another object's diff does not persist them). Only the main agent: subagents have
 * read-only MCP access and cannot persist the main agent's writes. An export or save into the connection's model folder
 * (recorded by post-tool-redact.mjs) clears the writes; a disconnect never does, and an export into a staging folder
 * (`exports/`, outside the repository) leaves them pending and its copy is no model diff. A diff that declares them
 * marks them persisted (F1-38), so committing it brings no second block. The block counts every pending write, so a
 * disconnect or a staging export after the block brings no second one.
 */
function mcpPersistence(input, changed, cfg) {
  if (input.agent_id || input.hook_event_name === 'SubagentStop') return null;
  const context = { root: PROJECT_DIR, cfg };
  let state = readState(input.session_id);
  let open = unpersistedMcpWrites(state, changed, context);
  if (open.persisted?.length) {
    // The writes the diff declares are persisted from now on, even once the diff is committed; what is left is judged again.
    state = updateState(input.session_id, (s) => markMcpWritesPersisted(s, open.persisted));
    open = unpersistedMcpWrites(state, changed, context);
  }
  if (!open.count) {
    if (state[MCP_KEY]) {
      updateState(input.session_id, (s) => {
        delete s[MCP_KEY];
      });
    }
    return null;
  }
  const signature = `${open.total}@${open.last}`;
  const next = updateState(input.session_id, (s) => {
    if (s[MCP_KEY]?.signature !== signature) s[MCP_KEY] = { signature, blocks: 0 };
    s[MCP_KEY].blocks += 1;
  });
  const text = persistenceMessage(open);
  if (next[MCP_KEY].blocks > MAX_MCP_BLOCKS || unsaved(input, MCP_KEY, next[MCP_KEY])) return { systemMessage: `[bi-harness] ${text}` };
  return { decision: 'block', reason: `[bi-harness] Before finishing: ${text}` };
}

// One Stop event, two copies of this hook (F2-11): Copilot CLI runs its native file and the Claude registration, VS Code
// both .github/hooks files, each with the same event. Counting it twice would let the first copy use up the MCP block and
// leave the copy the host reads a warning. The identity rule: a Stop event is its payload timestamp in epoch
// milliseconds (eventTime: the same instant in the camelCase and the snake_case dialect) and the agent it ends
// (`agent_id`); a copy that meets the identity of the last Stop answered repeats that verdict (the handler's result,
// shaped for its own host by runHook) and changes no counter. A payload without a timestamp is never matched: Claude
// Code sends none and runs identical hook commands once. A copy that comes while the other still judges waits for its
// verdict, at most REPEAT_WAIT_MS, and judges itself when the other is gone.
const ANSWER_KEY = 'stopAnswer';
const REPEAT_WAIT_MS = 15000;

/** True while process `pid` runs. */
function alive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return err?.code === 'EPERM';
  }
}

/** The verdict another copy gives the Stop event `id` (key `key` of the state), once it has one; undefined if none comes. */
async function verdictOfOtherCopy(sessionId, key, id) {
  const until = Date.now() + REPEAT_WAIT_MS;
  for (;;) {
    const answer = readState(sessionId)[key];
    if (answer?.id !== id) return undefined;
    if (Object.hasOwn(answer, 'verdict')) return answer.verdict;
    if (!alive(answer.pid) || Date.now() >= until) return undefined;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
}

/** The verdict of one Stop or SubagentStop event: the MCP persistence block, then the validation of uncommitted files. */
async function stopGate(input) {
  const cfg = loadConfig();
  const gitChanges = gitChangedFiles(PROJECT_DIR);
  const changed = gitChanges ?? readState(input.session_id).changedFiles ?? [];
  let mcp = null;
  try {
    mcp = mcpPersistence(input, changed, cfg);
  } catch {
    // The persistence reminder never stops the validation below.
  }
  const key = input.agent_id ? `stopBlocks:${input.agent_id}` : 'stopBlocks';
  if (!changed.length) {
    // Nothing is left to validate (the files were committed or reverted): the series of blocks is over too.
    if (readState(input.session_id)[key] !== undefined) {
      updateState(input.session_id, (s) => {
        delete s[key];
      });
    }
    return mcp;
  }

  let issues;
  try {
    ({ issues } = gitChanges === null
      ? validateFiles(PROJECT_DIR, cfg, changed)
      : runValidation({ mode: 'changed' }));
  } catch (err) {
    // The MCP block does not depend on the validation.
    if (mcp?.decision === 'block') return mcp;
    throw err;
  }
  const errors = issues.filter((i) => i.level === 'error');

  if (!errors.length) {
    updateState(input.session_id, (s) => {
      delete s[key];
    });
    return mcp;
  }

  const summary = formatIssues(errors, 15);
  const state = updateState(input.session_id, (s) => {
    s[key] = (s[key] ?? 0) + 1;
  });
  // The MCP block comes first and uses one of the blocks these errors get: MCP block, validation block, then the warning.
  if (mcp?.decision === 'block') return mcp;
  // The MCP warning (if any) travels with the validation answer, so neither hides the other.
  const mcpWarning = mcp?.systemMessage ? { systemMessage: mcp.systemMessage } : {};
  if (state[key] > MAX_CONSECUTIVE_BLOCKS || unsaved(input, key, state[key])) {
    const message = `[bi-harness] ${errors.length} validation error(s) remain in uncommitted files:\n${summary}\nRun \`node hardening/scripts/validate.mjs --changed\` for details.`;
    return { systemMessage: [message, mcp?.systemMessage].filter(Boolean).join('\n') };
  }
  return {
    decision: 'block',
    reason:
      `[bi-harness] Before finishing: ${errors.length} validation error(s) in uncommitted files. ` +
      'Fix them, re-run `node hardening/scripts/validate.mjs --changed` and show its output. If an error cannot be fixed, stop and explain it to the user instead of weakening any check.\n' +
      summary,
    ...mcpWarning,
  };
}

// The subagents this gate judges on SubagentStop: the editors the Claude registration names in its SubagentStop matcher
// (hardening/settings.hooks.json; a test keeps the two equal). VS Code ignores matchers and runs this hook for every
// subagent (F2-17), so the script filters itself: a read-only reviewer is never sent back to fix files it may not edit.
// A payload without `agent_type` is judged as before.
const STOP_GATED_SUBAGENTS = ['bi-tmdl-modeler', 'bi-pbir-editor'];

await runHook('Stop', async (input) => {
  if (input.hook_event_name === 'SubagentStop' && typeof input.agent_type === 'string' && input.agent_type && !STOP_GATED_SUBAGENTS.includes(input.agent_type)) {
    return null;
  }
  const ms = eventTime(input.timestamp);
  if (ms === null) return stopGate(input);
  const id = `${input.agent_id ?? ''}@${ms}`;
  const key = input.agent_id ? `${ANSWER_KEY}:${input.agent_id}` : ANSWER_KEY;
  let seen = false;
  updateState(input.session_id, (s) => {
    if (s[key]?.id === id) seen = true;
    else s[key] = { id, pid: process.pid };
  });
  if (seen) {
    const verdict = await verdictOfOtherCopy(input.session_id, key, id);
    if (verdict !== undefined) return verdict;
  }
  const verdict = await stopGate(input);
  updateState(input.session_id, (s) => {
    s[key] = { id, verdict: verdict ?? null };
  });
  return verdict;
});
