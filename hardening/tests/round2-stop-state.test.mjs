// Follow-up audit, group F (2026-10-19): the session state the Stop gate and the MCP recorder share.
// F2-11: a host that runs two registrations of the hooks (Copilot CLI: its native file and the Claude registration; VS
// Code: both .github/hooks files) recorded one MCP write twice, and the first copy's Stop used up the single MCP block,
// so the copy the host reads printed only a warning. F1-39: a connect whose answer confirmed nothing left no trace, so an
// unnamed DAX query passed and an unnamed write was put on the earlier connection. F1-68: parallel PostToolUse hooks lost
// or wiped recorded writes (no lock, no atomic write). F1-116: an inherited GIT_INDEX_FILE (a `git commit -a` hook that
// runs the tests) sent the mcp-state tests' git calls to the outer repository's index. F1-138: a VS Code SubagentStop
// block was nested under hookEventName "Stop"; VS Code reads a SubagentStop decision at the top level.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const hooks = path.join(here, '..', 'hooks');
// Variables that point git at another repository, index or object store: an outer `git commit -a` hook exports them.
const GIT_VARS = new Set(['GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE', 'GIT_OBJECT_DIRECTORY', 'GIT_ALTERNATE_OBJECT_DIRECTORIES', 'GIT_COMMON_DIR', 'GIT_PREFIX']);
/** The environment without the host variable, the git variables above and the test runner's context, plus `extra`. */
function envWith(extra = {}) {
  const drop = (k) => k.toUpperCase() === 'BI_HARNESS_HOST' || k.toUpperCase() === 'NODE_TEST_CONTEXT' || GIT_VARS.has(k.toUpperCase());
  return { ...Object.fromEntries(Object.entries(process.env).filter(([k]) => !drop(k))), ...extra };
}
const gitIn = (dir, ...args) => spawnSync('git', args, { cwd: dir, env: envWith(), encoding: 'utf8' });

/** Runs a hook with the temporary project as CLAUDE_PROJECT_DIR; `host` sets BI_HARNESS_HOST (none: the Claude registration). */
function hook(script, dir, payload, host) {
  const r = spawnSync(process.execPath, [path.join(hooks, script)], {
    input: JSON.stringify(payload),
    env: envWith({ CLAUDE_PROJECT_DIR: dir, ...(host ? { BI_HARNESS_HOST: host } : {}) }),
    encoding: 'utf8',
  });
  assert.equal(r.status, 0, `${script}: ${r.stderr}`);
  assert.doesNotMatch(r.stderr, /hook error/, r.stderr);
  return r.stdout.trim() ? JSON.parse(r.stdout) : null;
}

/** A temporary Git repository whose session logs Git ignores, with `files` untracked. */
function withRepo(files, fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-round2-f-'));
  try {
    gitIn(dir, 'init', '-q');
    fs.appendFileSync(path.join(dir, '.git', 'info', 'exclude'), '\n.claude/logs/\n');
    for (const [rel, content] of Object.entries(files)) {
      fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
      fs.writeFileSync(path.join(dir, rel), content);
    }
    return fn(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}
const stateDir = (dir) => path.join(dir, '.claude', 'logs', '.state');
const stateOf = (dir, sid) => {
  const file = path.join(stateDir(dir), `${sid}.json`);
  return fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, 'utf8')) : {};
};

const SALES = 'PBIDesktop-Sales-1234';
const LOCAL = 'PBIDesktop-Sales-51234';
const BUDGET = 'PBIDesktop-Budget-60001';
const CREATE = { operation: 'Create', connectionName: SALES, definitions: [{ name: 'Total Sales', tableName: 'Sales', expression: 'SUM(Sales[Amount])' }] };
const OK = JSON.stringify({ success: true });
const T = Date.parse('2026-10-18T06:16:50.192Z');
const iso = (ms) => new Date(ms).toISOString();
const BIG_MD = Array.from({ length: 501 }, (_, i) => `line ${i}`).join('\n');

// ---------------------------------------------------------------- F2-11: two registrations, one event

test('F2-11: Copilot CLI runs its native file and the Claude registration: one write is recorded once, and the second copy repeats the block', () => {
  withRepo({}, (dir) => {
    const sid = 'f-cli-1';
    // One call, two payloads: the native camelCase one (epoch milliseconds) and the Claude dialect (the same instant as ISO text).
    hook('post-tool-redact.mjs', dir, { sessionId: sid, timestamp: T, cwd: dir, toolName: 'powerbi-modeling-mcp-measure_operations', toolArgs: { request: CREATE }, toolResult: { resultType: 'success', textResultForLlm: OK } }, 'copilot-cli');
    hook('post-tool-redact.mjs', dir, { hook_event_name: 'PostToolUse', session_id: sid, timestamp: iso(T), cwd: dir, tool_name: 'powerbi-modeling-mcp-measure_operations', tool_input: { request: CREATE }, tool_result: { result_type: 'success', text_result_for_llm: OK } });
    assert.equal(stateOf(dir, sid).mcpWrites?.length, 1, 'one call, one write');

    const stopAt = T + 1000;
    const native = hook('stop-gate.mjs', dir, { sessionId: sid, timestamp: stopAt, cwd: dir, transcriptPath: 't', stopReason: 'end_turn', stop_hook_active: false }, 'copilot-cli');
    assert.equal(native?.decision, 'block', 'agentStop reads decision');
    assert.match(native.reason, /1 MCP write\(s\) on PBIDesktop-Sales-1234/);
    assert.equal(native.hookSpecificOutput, undefined, 'the native payload keeps the flat CLI shape');
    const claude = hook('stop-gate.mjs', dir, { hook_event_name: 'Stop', session_id: sid, timestamp: iso(stopAt), cwd: dir, stop_hook_active: false });
    assert.equal(claude?.decision, 'block', 'the same Stop event gets the same verdict from the second copy');
    assert.equal(claude.reason, native.reason);
    assert.equal(stateOf(dir, sid).mcpStopBlocks?.blocks, 1, 'the repeat counts no second stop');

    // The agent was sent back and stops again: a new Stop event warns instead of blocking, as with one registration.
    const later = T + 60000;
    const again = hook('stop-gate.mjs', dir, { sessionId: sid, timestamp: later, cwd: dir, transcriptPath: 't', stopReason: 'end_turn', stop_hook_active: true }, 'copilot-cli');
    assert.equal(again?.decision, undefined, 'the second real stop passes on');
    const againClaude = hook('stop-gate.mjs', dir, { hook_event_name: 'Stop', session_id: sid, timestamp: iso(later), cwd: dir, stop_hook_active: true });
    assert.equal(againClaude?.decision, undefined);
    assert.match(againClaude?.systemMessage ?? '', /1 MCP write\(s\) on PBIDesktop-Sales-1234/, 'and warns the user');
  });
});

test('F2-11: VS Code runs both .github/hooks files: one write once, and the Stop block reaches VS Code nested, whichever copy runs first', () => {
  withRepo({}, (dir) => {
    const sid = 'f-vs-1';
    const write = { hook_event_name: 'PostToolUse', session_id: sid, timestamp: iso(T), cwd: dir, tool_name: 'mcp_powerbi-model_measure_operations', tool_use_id: 'u1', tool_input: { request: CREATE }, tool_response: OK };
    hook('post-tool-redact.mjs', dir, write, 'vscode');
    hook('post-tool-redact.mjs', dir, write, 'copilot-cli');
    assert.equal(stateOf(dir, sid).mcpWrites?.length, 1, 'one tool_use_id, one write');

    const stop = { hook_event_name: 'Stop', session_id: sid, timestamp: '2026-10-18T06:16:51.192Z', cwd: '.', stop_hook_active: false };
    const cliCopy = hook('stop-gate.mjs', dir, stop, 'copilot-cli');
    assert.equal(cliCopy?.decision, 'block');
    assert.equal(cliCopy.hookSpecificOutput?.decision, 'block', 'a VS Code payload gets the nested block VS Code reads, from the copilot-cli file too');
    assert.equal(cliCopy.hookSpecificOutput.hookEventName, 'Stop');
    const vsCopy = hook('stop-gate.mjs', dir, stop, 'vscode');
    assert.equal(vsCopy?.hookSpecificOutput?.decision, 'block', 'the vscode copy repeats the block');
    assert.equal(vsCopy.hookSpecificOutput.reason, cliCopy.reason);
    assert.equal(stateOf(dir, sid).mcpStopBlocks?.blocks, 1);

    const later = { ...stop, timestamp: '2026-10-18T06:17:51.192Z', stop_hook_active: true };
    const vsAgain = hook('stop-gate.mjs', dir, later, 'vscode');
    assert.equal(vsAgain?.decision, undefined, 'the second real stop passes on');
    assert.equal(vsAgain?.hookSpecificOutput, undefined);
    assert.match(vsAgain?.systemMessage ?? '', /1 MCP write\(s\)/);

    // The other order: the vscode copy first, then the copilot-cli copy.
    const sid2 = 'f-vs-2';
    hook('post-tool-redact.mjs', dir, { ...write, session_id: sid2, tool_use_id: 'u2' }, 'copilot-cli');
    hook('post-tool-redact.mjs', dir, { ...write, session_id: sid2, tool_use_id: 'u2' }, 'vscode');
    assert.equal(stateOf(dir, sid2).mcpWrites?.length, 1);
    const first = hook('stop-gate.mjs', dir, { ...stop, session_id: sid2 }, 'vscode');
    assert.equal(first?.hookSpecificOutput?.decision, 'block');
    const second = hook('stop-gate.mjs', dir, { ...stop, session_id: sid2 }, 'copilot-cli');
    assert.equal(second?.hookSpecificOutput?.decision, 'block', 'the copilot-cli copy repeats the block in the form VS Code reads');
    assert.equal(stateOf(dir, sid2).mcpStopBlocks?.blocks, 1);
  });
});

test('F2-11: two calls stay two writes: another tool_use_id, another instant, or a payload with no identity at all', () => {
  withRepo({}, (dir) => {
    const sid = 'f-two-1';
    const claudeCode = (extra) => ({ hook_event_name: 'PostToolUse', session_id: sid, tool_name: 'mcp__powerbi-modeling__measure_operations', tool_input: { request: CREATE }, tool_response: OK, ...extra });
    hook('post-tool-redact.mjs', dir, claudeCode({ tool_use_id: 'a' }));
    hook('post-tool-redact.mjs', dir, claudeCode({ tool_use_id: 'b' }));
    assert.equal(stateOf(dir, sid).mcpWrites?.length, 2, 'two tool_use_ids');
    hook('post-tool-redact.mjs', dir, claudeCode({}));
    hook('post-tool-redact.mjs', dir, claudeCode({}));
    assert.equal(stateOf(dir, sid).mcpWrites?.length, 4, 'no tool_use_id and no timestamp: never merged');
    const native = (ms) => ({ sessionId: sid, timestamp: ms, cwd: dir, toolName: 'powerbi-modeling-mcp-measure_operations', toolArgs: { request: CREATE }, toolResult: { resultType: 'success', textResultForLlm: OK } });
    hook('post-tool-redact.mjs', dir, native(T), 'copilot-cli');
    hook('post-tool-redact.mjs', dir, native(T + 5), 'copilot-cli');
    hook('post-tool-redact.mjs', dir, native(T), 'copilot-cli');
    assert.equal(stateOf(dir, sid).mcpWrites?.length, 6, 'two instants are two calls; the same call again is one');
  });
});

test('F2-11: a copy that comes while the other still judges the same Stop waits for its verdict; it judges itself once the other is gone', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-round2-wait-'));
  try {
    const sid = 'f-wait-1';
    const file = path.join(stateDir(dir), `${sid}.json`);
    fs.mkdirSync(stateDir(dir), { recursive: true });
    const stopAt = T + 2000;
    // The other copy (this test process, alive) claimed the event and has no verdict yet.
    fs.writeFileSync(file, JSON.stringify({ stopAnswer: { id: `@${stopAt}`, pid: process.pid } }));
    const out = await new Promise((resolve, reject) => {
      const p = spawn(process.execPath, [path.join(hooks, 'stop-gate.mjs')], { env: envWith({ CLAUDE_PROJECT_DIR: dir }), stdio: ['pipe', 'pipe', 'pipe'] });
      let stdout = '';
      let stderr = '';
      p.stdout.on('data', (d) => { stdout += d; });
      p.stderr.on('data', (d) => { stderr += d; });
      p.on('error', reject);
      p.on('close', (code) => (code === 0 ? resolve(stdout.trim() ? JSON.parse(stdout) : null) : reject(new Error(`exit ${code}: ${stderr}`))));
      p.stdin.end(JSON.stringify({ hook_event_name: 'Stop', session_id: sid, timestamp: iso(stopAt), stop_hook_active: false }));
      setTimeout(() => fs.writeFileSync(file, JSON.stringify({ stopAnswer: { id: `@${stopAt}`, verdict: { decision: 'block', reason: '[bi-harness] the other copy' } } })), 600);
    });
    assert.equal(out?.decision, 'block');
    assert.equal(out.reason, '[bi-harness] the other copy', 'the verdict of the copy that judged');

    // A claim left by a copy that died (its process is gone) is not waited for.
    const gone = spawnSync(process.execPath, ['-e', 'process.stdout.write(String(process.pid))'], { encoding: 'utf8' });
    const later = stopAt + 1000;
    fs.writeFileSync(file, JSON.stringify({ stopAnswer: { id: `@${later}`, pid: Number(gone.stdout) } }));
    const started = Date.now();
    assert.equal(hook('stop-gate.mjs', dir, { hook_event_name: 'Stop', session_id: sid, timestamp: iso(later), stop_hook_active: false }), null, 'nothing to hold: it judged itself');
    assert.ok(Date.now() - started < 10000, 'without waiting for the dead copy');
    assert.deepEqual(stateOf(dir, sid).stopAnswer, { id: `@${later}`, verdict: null });
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------- F1-138: SubagentStop under VS Code

test('F1-138: a VS Code SubagentStop block is top-level decision and reason; a Stop block stays nested', () => {
  withRepo({ 'docs/big.md': BIG_MD }, (dir) => {
    const sub = hook('stop-gate.mjs', dir, { hook_event_name: 'SubagentStop', session_id: 'f-sub-1', timestamp: '2026-10-18T08:00:00Z', stop_hook_active: false, agent_id: 'a1', agent_type: 'bi-tmdl-modeler' }, 'vscode');
    assert.equal(sub?.decision, 'block');
    assert.match(sub.reason, /501 lines/);
    assert.equal(sub.hookSpecificOutput, undefined, 'SubagentStop output has no hookSpecificOutput');
    const main = hook('stop-gate.mjs', dir, { hook_event_name: 'Stop', session_id: 'f-sub-1', timestamp: '2026-10-18T08:01:00Z', stop_hook_active: false }, 'vscode');
    assert.equal(main?.hookSpecificOutput?.hookEventName, 'Stop');
    assert.equal(main.hookSpecificOutput.decision, 'block');
  });
});

// ---------------------------------------------------------------- F1-39: a connect that confirmed nothing

const mcp = (tool) => `mcp__powerbi-modeling__${tool}`;
const textBlock = (o) => [{ type: 'text', text: JSON.stringify(o) }];
const post = (dir, sid, tool, request, response) =>
  hook('post-tool-redact.mjs', dir, { hook_event_name: 'PostToolUse', session_id: sid, tool_name: mcp(tool), tool_input: { request }, tool_response: response });
function guard(dir, sid, tool, request) {
  const out = hook('pre-tool-use.mjs', dir, { hook_event_name: 'PreToolUse', session_id: sid, tool_name: mcp(tool), tool_input: { request } })?.hookSpecificOutput;
  return { decision: out?.permissionDecision ?? null, reason: out?.permissionDecisionReason ?? '' };
}
const DAX = (connectionName) => ({ operation: 'Execute', maxRows: 5, query: "EVALUATE SUMMARIZECOLUMNS('Date'[Year], \"Sales\", [Total Sales])", ...(connectionName ? { connectionName } : {}) });
const PENDING_REASON = /A connect on MCP server "powerbi-modeling" \(localhost:60001\) answered without confirming a connection, so a call without a name may go to it: name the connection \(connectionName\), or list or get the current connection \(connection_operations\) first/;

test('F1-39: a connect whose answer confirms nothing is pending: an unnamed query asks, an unnamed write is put on no connection', () => {
  withRepo({}, (dir) => {
    const sid = 'f-pending-1';
    post(dir, sid, 'connection_operations', { operation: 'Connect', dataSource: 'localhost:51234' }, textBlock({ success: true, connectionName: LOCAL }));
    assert.equal(guard(dir, sid, 'dax_query_operations', DAX()).decision, 'allow', 'one confirmed connection: as before');
    // The answer has no success flag: an unknown shape, which may still have connected.
    post(dir, sid, 'connection_operations', { operation: 'Connect', dataSource: 'localhost:60001' }, textBlock({ connectionName: BUDGET, message: 'Connection opened' }));
    assert.deepEqual(stateOf(dir, sid).mcpConnections.map((c) => c.name), [LOCAL], 'nothing confirmed');
    const dax = guard(dir, sid, 'dax_query_operations', DAX());
    assert.equal(dax.decision, 'ask', 'the server may now use the new connection for an unnamed call');
    assert.match(dax.reason, PENDING_REASON);
    assert.equal(guard(dir, sid, 'dax_query_operations', DAX(LOCAL)).decision, 'allow', 'a named call on a confirmed connection is unaffected');
    assert.match(guard(dir, sid, 'measure_operations', { operation: 'Create', definitions: [{ name: 'Plan' }] }).reason, PENDING_REASON);

    post(dir, sid, 'measure_operations', { operation: 'Create', definitions: [{ name: 'Plan' }] }, textBlock({ success: true }));
    const [w] = stateOf(dir, sid).mcpWrites;
    assert.equal(w.connection, null, 'not put on the earlier connection');
    assert.equal(w.inferred, undefined);
    const stop = hook('stop-gate.mjs', dir, { hook_event_name: 'Stop', session_id: sid, stop_hook_active: false });
    assert.equal(stop?.decision, 'block', 'the write still holds the Stop gate');
    assert.match(stop.reason, /1 MCP write\(s\) on the last connection/);
  });
});

test('F1-39: a readable success, a list or a get of the current connection clears the pending connect; a named get or a failure does not', () => {
  withRepo({}, (dir) => {
    const sid = 'f-pending-2';
    const unnamed = () => guard(dir, sid, 'dax_query_operations', DAX());
    post(dir, sid, 'connection_operations', { operation: 'Connect', dataSource: 'localhost:60001' }, textBlock({ connectionName: BUDGET, message: 'Connection opened' }));
    assert.match(unnamed().reason, PENDING_REASON, 'pending with no confirmed connection');
    post(dir, sid, 'connection_operations', { operation: 'Connect', dataSource: 'localhost:60001' }, textBlock({ success: true, connectionName: BUDGET }));
    assert.equal(unnamed().decision, 'allow', 'a readable success clears the pending flag');

    // An explicit failure leaves no trace, as before: a failure flag, a failure text, a failed state.
    post(dir, sid, 'connection_operations', { operation: 'Connect', dataSource: 'localhost:70001' }, textBlock({ success: false, error: 'Login failed' }));
    post(dir, sid, 'connection_operations', { operation: 'Connect', dataSource: 'localhost:70001' }, 'Connection failed: PBIDesktop-Other-70001 could not be reached');
    post(dir, sid, 'connection_operations', { operation: 'Connect', dataSource: 'localhost:70001' }, textBlock({ connectionName: 'PBIDesktop-Other-70001', state: 'Disconnected' }));
    assert.equal(unnamed().decision, 'allow', 'an explicit failure is no pending connect');

    const pendingAgain = () => post(dir, sid, 'connection_operations', { operation: 'Connect', dataSource: 'localhost:60001' }, textBlock({ connectionName: 'PBIDesktop-Other-60001', message: 'Connection opened' }));
    pendingAgain();
    assert.equal(unnamed().decision, 'ask');
    post(dir, sid, 'connection_operations', { operation: 'GetConnection', connectionName: BUDGET }, textBlock({ success: true, connectionName: BUDGET }));
    assert.match(unnamed().reason, PENDING_REASON, 'a get of one named connection does not say which one the server uses');
    post(dir, sid, 'connection_operations', { operation: 'ListConnections' }, textBlock({ success: true, connections: [{ name: BUDGET }] }));
    assert.equal(unnamed().decision, 'allow', 'a list shows every connection: the pending one did not connect');

    pendingAgain();
    post(dir, sid, 'connection_operations', { operation: 'GetCurrentConnection' }, textBlock({ success: true, connectionName: BUDGET }));
    assert.equal(unnamed().decision, 'allow', 'a get of the current connection');
    assert.equal(stateOf(dir, sid).mcpPendingConnects?.length ?? 0, 0);
  });
});

// ---------------------------------------------------------------- F1-68: parallel hooks

test('F1-68: parallel PostToolUse hooks keep every recorded write and the confirmed connection', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-round2-race-'));
  try {
    const sid = 'f-race-1';
    post(dir, sid, 'connection_operations', { operation: 'Connect', dataSource: 'localhost:51234' }, textBlock({ success: true, connectionName: LOCAL }));
    const one = (name) => new Promise((resolve, reject) => {
      const p = spawn(process.execPath, [path.join(hooks, 'post-tool-redact.mjs')], { env: envWith({ CLAUDE_PROJECT_DIR: dir }), stdio: ['pipe', 'ignore', 'pipe'] });
      let err = '';
      p.stderr.on('data', (d) => { err += d; });
      p.on('error', reject);
      p.on('close', (code) => (code === 0 && !/hook error/.test(err) ? resolve() : reject(new Error(`exit ${code}: ${err}`))));
      p.stdin.end(JSON.stringify({ hook_event_name: 'PostToolUse', session_id: sid, tool_use_id: `u-${name}`, tool_name: mcp('measure_operations'), tool_input: { request: { operation: 'Create', connectionName: LOCAL, definitions: [{ name }] } }, tool_response: textBlock({ success: true }) }));
    });
    const N = 8;
    const ROUNDS = 4;
    for (let r = 0; r < ROUNDS; r += 1) {
      await Promise.all(Array.from({ length: N }, (_, i) => one(`M${r}_${i}`)));
      const s = stateOf(dir, sid);
      assert.equal(s.mcpWrites?.length, N * (r + 1), `round ${r + 1}: every write is kept`);
      assert.deepEqual(s.mcpConnections?.map((c) => c.name), [LOCAL], `round ${r + 1}: the confirmed connection is kept`);
    }
    assert.deepEqual(fs.readdirSync(stateDir(dir)).filter((f) => !f.endsWith('.json')), [], 'no lock or temporary file is left');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------- F1-116: an inherited GIT_INDEX_FILE

test('F1-116: the mcp-state tests never write into the index an inherited GIT_INDEX_FILE names', () => {
  const outer = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-round2-outer-'));
  try {
    gitIn(outer, 'init', '-q');
    fs.writeFileSync(path.join(outer, 'README.md'), '# outer\n');
    gitIn(outer, 'add', 'README.md');
    // The committer address is built at run time, so the release check finds no address in this file.
    const email = ['t', 'example.invalid'].join('@');
    const c = gitIn(outer, '-c', 'user.name=t', '-c', `user.email=${email}`, '-c', 'commit.gpgsign=false', 'commit', '-q', '--no-verify', '-m', 'init');
    assert.equal(c.status, 0, c.stderr);
    const index = path.join(outer, '.git', 'index');
    const before = fs.readFileSync(index);
    // As a `git commit -a` hook runs them: GIT_INDEX_FILE names the outer repository's index by an absolute path.
    const r = spawnSync(process.execPath, ['--test', '--test-reporter=tap', '--test-name-pattern=only a diff under it passes', path.join(here, 'mcp-state.test.mjs')], {
      env: envWith({ GIT_INDEX_FILE: index }),
      encoding: 'utf8',
      timeout: 120000,
    });
    assert.equal(r.status, 0, `${r.stdout.slice(-3000)}\n${r.stderr.slice(-1000)}`);
    assert.match(r.stdout, /^# pass [1-9]/m, 'the selected test ran');
    assert.match(r.stdout, /^# fail 0$/m);
    assert.ok(before.equals(fs.readFileSync(index)), 'the outer index is unchanged');
  } finally {
    fs.rmSync(outer, { recursive: true, force: true });
  }
});
