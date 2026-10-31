// Audit 2026-10-16 (Path A): the hooks judged each MCP call alone. Nothing checked that a connection_operations call
// had confirmed the target a DAX query or a write names (docs/harness/MCP.md, section 2), and a session could end with
// MCP writes that live only in the connected model's memory (section 4, persistence). The session state now records
// confirmed connections and in-memory writes (post-tool-redact.mjs, lib/mcp-state.mjs). A second audit the same day
// found a failed connect text confirming its name, one state shared by every MCP server, the target rule off without a
// state file, and pending writes cleared or passed by a disconnect, an export outside the repository or another model's
// diff; each rule below has a success and a failure case. A third audit the same day (the real hooks in a temporary
// project) found an export into an ignored folder of the repository clearing the write, an unnamed export whose answer
// named another connection clearing it, `{result: {success: false}}` and `{status: 'Pending'}` counting as success, and
// an unrelated TMDL change in the same model folder passing the Stop gate; the tests marked "third audit" replay them.
// A fourth audit (2026-10-18) found the Stop gate too loose in places and too strict in others: a name mentioned inside
// another object counted as persisting it, and one name of several was enough (F1-40, E1); an export into a fresh or an
// ignored *.SemanticModel folder cleared the writes (F1-36, E2) and only the last of two staging copies was left out
// (F1-37); a diff that was persisted and then committed made the gate block again (F1-38); a nested connectionName of an
// export answer was not read (F1-128, E10); validation errors never blocked twice (F1-35). The tests that name these ids
// replay them.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  NO_TARGET_REASON as NO_TARGET, PERSIST_OPERATION_PREFIXES, answerSucceeded, connectionsFromResponse, declaresObject, isModelFolder, markMcpWritesPersisted,
  mentionsObject, unpersistedMcpWrites,
} from '../hooks/lib/mcp-state.mjs';
import { powerBiMcpCall } from '../hooks/lib/policy.mjs';

const hooks = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'hooks');
const cfg = { mcp: { powerbiServer: 'powerbi-modeling' } };
const SESSION = 'mcp-state';
const LOCAL = 'PBIDesktop-Sales-51234';
const SERVER = 'powerbi-modeling';
// Microsoft's sample registration: a second MCP server name the harness knows (DEFAULT_CONFIG.mcp.powerbiServers).
const OTHER_SERVER = 'powerbi-authoring-local';
const mcpTool = (name, server = SERVER) => `mcp__${server}__${name}`;
/** An MCP answer as Claude Code passes it: content blocks holding the server's JSON as text. */
const textBlock = (obj) => [{ type: 'text', text: JSON.stringify(obj) }];

function project(files = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-mcpstate-'));
  for (const [rel, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), content);
  }
  return dir;
}
const statePath = (dir) => path.join(dir, '.claude', 'logs', '.state', `${SESSION}.json`);
const readStateFile = (dir) => (fs.existsSync(statePath(dir)) ? JSON.parse(fs.readFileSync(statePath(dir), 'utf8')) : null);
function writeStateFile(dir, state) {
  fs.mkdirSync(path.dirname(statePath(dir)), { recursive: true });
  fs.writeFileSync(statePath(dir), JSON.stringify(state));
}

// F1-116: variables that point git at another repository, index or object store. A `git commit -a` hook that runs these
// tests exports GIT_INDEX_FILE, and the temporary repositories' git calls (the tests' own and the hooks') wrote into the
// outer repository's index; every git call here runs without them.
const GIT_REPO_VARS = new Set(['GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE', 'GIT_OBJECT_DIRECTORY', 'GIT_ALTERNATE_OBJECT_DIRECTORIES', 'GIT_COMMON_DIR', 'GIT_PREFIX']);
const gitEnv = () => Object.fromEntries(Object.entries(process.env).filter(([k]) => !GIT_REPO_VARS.has(k.toUpperCase())));

/** Runs a hook as Claude Code does (stdin JSON) with the temporary project as CLAUDE_PROJECT_DIR. */
function run(dir, script, payload) {
  const env = { ...gitEnv(), CLAUDE_PROJECT_DIR: dir };
  delete env.BI_HARNESS_HOST;
  const r = spawnSync(process.execPath, [path.join(hooks, script)], { input: JSON.stringify({ session_id: SESSION, ...payload }), env, encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
  assert.doesNotMatch(r.stderr, /hook error/);
  return r.stdout.trim() ? JSON.parse(r.stdout) : null;
}
const post = (dir, tool, request, tool_response, server = SERVER) =>
  run(dir, 'post-tool-redact.mjs', { hook_event_name: 'PostToolUse', tool_name: mcpTool(tool, server), tool_input: { request }, tool_response });
/** The connections a connection_operations answer confirms (the recorder's reading, without a hook run). */
const confirms = (request, response) => connectionsFromResponse(powerBiMcpCall(mcpTool('connection_operations'), { request }, cfg), response).map((c) => c.name);

function withProject(files, fn) {
  const dir = project(files);
  try {
    return fn(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

// ---------------------------------------------------------------- 1. recording (PostToolUse)

test('classify: DAX execute and non-read operations need a confirmed target; only definition changes are writes', () => {
  const call = (tool, request) => powerBiMcpCall(mcpTool(tool), { request }, cfg);
  const dax = call('dax_query_operations', { operation: 'Execute', query: 'EVALUATE ROW("a", 1)', maxRows: 1 });
  assert.deepEqual([dax.needsTarget, dax.modelWrite], [true, false]);
  const create = call('measure_operations', { operation: 'Create', connectionName: ` ${LOCAL} ` });
  assert.deepEqual([create.needsTarget, create.modelWrite, create.connectionName], [true, true, LOCAL]);
  assert.deepEqual([call('measure_operations', { operation: 'List' }).needsTarget, call('dax_query_operations', { operation: 'Validate' }).needsTarget], [false, false]);
  assert.equal(call('connection_operations', { operation: 'Connect' }).needsTarget, false, 'connection_operations is never held back');
  for (const tool of ['transaction_operations', 'trace_operations', 'dax_query_operations']) {
    assert.equal(call(tool, { operation: 'Begin' }).modelWrite, false, tool);
  }
  assert.equal(powerBiMcpCall('mcp__github__create_issue', {}, cfg), null);
  assert.deepEqual([...PERSIST_OPERATION_PREFIXES], ['exportto', 'saveas', 'saveto']);
});

test('state: a connect answer records the connection with its server and database, never the connection string', () => {
  withProject({}, (dir) => {
    const secret = ['Tr0ub', '4dor', 'Zx'].join('');
    const request = { operation: 'Connect', connectionString: `Data Source=localhost:51234;Initial Catalog=sales-db;${['Pass', 'word'].join('')}=${secret}` };
    assert.equal(post(dir, 'connection_operations', request, textBlock({ success: true, message: `Connected to ${LOCAL}`, connectionName: LOCAL })), null);
    const state = readStateFile(dir);
    assert.deepEqual(state.mcpConnections.map((c) => [c.name, c.server, c.database]), [[LOCAL, 'localhost:51234', 'sales-db']]);
    const text = fs.readFileSync(statePath(dir), 'utf8');
    assert.ok(!text.includes(secret) && !/password|Data Source/i.test(text), 'names only');
  });
});

test('state: list and get answers record every connection they name; local instances and failed calls record nothing', () => {
  withProject({}, (dir) => {
    post(dir, 'connection_operations', { operation: 'ListLocalInstances' }, textBlock({ success: true, data: [{ port: 51234, connectionString: 'Data Source=localhost:51234' }] }));
    post(dir, 'connection_operations', { operation: 'GetConnection', connectionName: 'PBIDesktop-Gone-1' }, textBlock({ success: false, error: 'not found' }));
    assert.equal(readStateFile(dir), null, 'nothing confirmed, no state written');
    post(dir, 'connection_operations', { operation: 'ListConnections' }, textBlock({
      success: true,
      connections: [{ name: LOCAL, dataSource: 'localhost:51234', databaseName: 'sales-db' }, { connectionName: 'TMDL-Finance', folderPath: 'C:/work/Finance.SemanticModel/definition' }],
    }));
    const names = readStateFile(dir).mcpConnections.map((c) => c.name);
    assert.deepEqual(names, [LOCAL, 'TMDL-Finance']);
    assert.equal(readStateFile(dir).mcpConnections[1].path, 'C:/work/Finance.SemanticModel/definition');
    // A plain-text answer still names a local connection.
    post(dir, 'connection_operations', { operation: 'GetConnection' }, 'Current connection: PBIDesktop-Budget-60001.');
    assert.ok(readStateFile(dir).mcpConnections.some((c) => c.name === 'PBIDesktop-Budget-60001'));
  });
  assert.deepEqual(connectionsFromResponse({ ops: ['connect'], connectionName: '', request: {} }, { isError: true, content: [{ type: 'text', text: LOCAL }] }), []);
});

// Second audit (2026-10-16): a plain-text failure without a structured error flag confirmed the name it mentioned.
test('confirm: a failed connect never confirms, in any shape; an unknown shape confirms nothing', () => {
  const connect = { operation: 'Connect', connectionName: LOCAL, dataSource: 'localhost:51234' };
  for (const [label, response] of [
    ['plain text', `Connection failed: ${LOCAL} could not be reached`],
    ['an envelope without isError', { content: [{ type: 'text', text: `Could not connect to ${LOCAL}` }] }],
    ['a text block', [{ type: 'text', text: `Unable to open ${LOCAL}: the port is closed` }]],
    ['JSON naming it with a failure message', textBlock({ connectionName: LOCAL, message: 'Connection failed: timeout' })],
    ['JSON naming it with a failed state', textBlock({ connectionName: LOCAL, state: 'Disconnected' })],
    ['a negated positive word', `Not connected. Last target: ${LOCAL}`],
    ['no answer', undefined],
    ['an empty answer', ''],
    ['a bare OK', [{ type: 'text', text: 'OK' }]],
    ['an envelope without a positive word', { content: [{ type: 'text', text: 'Done' }] }],
  ]) assert.deepEqual(confirms(connect, response), [], label);
  withProject({}, (dir) => {
    post(dir, 'connection_operations', connect, `Connection failed: ${LOCAL} error 10061`);
    assert.equal(readStateFile(dir), null, 'a failed connect writes no state');
  });
});

test('confirm: a success signal confirms: JSON naming the connection, an explicit success, a positive text', () => {
  const connect = { operation: 'Connect', connectionName: LOCAL };
  assert.deepEqual(confirms(connect, `Connected to ${LOCAL}.`), [LOCAL]);
  assert.deepEqual(confirms(connect, textBlock({ success: true })), [LOCAL], 'an explicit success confirms the requested name');
  assert.deepEqual(confirms(connect, { content: [{ type: 'text', text: 'Connection established.' }] }), [LOCAL]);
  assert.deepEqual(confirms({ operation: 'Connect' }, textBlock({ success: true })), [], 'no name anywhere, nothing to confirm');
  assert.deepEqual(confirms({ operation: 'ListConnections' }, `Active connections: ${LOCAL}, TMDL-Finance`), [LOCAL, 'TMDL-Finance']);
  // Third audit: a text with a failure word is no success signal, so a list text with one failed line confirms nothing.
  const list = `Connections:\n${LOCAL} (connected)\nTMDL-Finance (error: folder missing)`;
  assert.deepEqual(confirms({ operation: 'ListConnections' }, list), []);
  assert.deepEqual(confirms({ operation: 'ListConnections' }, `Active connections: ${LOCAL}, TMDL-Finance (failed)`), []);
  const items = textBlock({ success: true, connections: [{ name: LOCAL, state: 'Connected' }, { name: 'PBIDesktop-Old-1', state: 'Disconnected', note: 'connected earlier to PBIDesktop-Old-1' }] });
  assert.deepEqual(confirms({ operation: 'ListConnections' }, items), [LOCAL], 'an item in a failed state confirms nothing, not even through its text');
  assert.deepEqual(confirms({ operation: 'ListConnections' }, textBlock({ connections: [{ name: LOCAL }] })), [], 'a list without a success flag is an unknown shape');
  assert.deepEqual(confirms({ operation: 'ListConnections' }, textBlock({ success: true, connections: [{ name: LOCAL }, { name: 'TMDL-Finance', status: 'Error' }] })), [], 'an item in status error makes the answer no success');
});

// Third audit: the success check took any non-empty object without a known failure marker for success.
test('success signal: explicit only; a failed, unfinished or unknown answer is no success', () => {
  for (const [label, response] of [
    ['success: true', textBlock({ success: true })],
    ['Success: true (any case)', textBlock({ Success: true, Message: 'done' })],
    ['ok: true', { ok: true }],
    ['isError: false in the server\'s JSON', textBlock({ isError: false, files: 42 })],
    ['a done status', textBlock({ status: 'Succeeded' })],
    ['a result string', textBlock({ result: 'completed' })],
    ['a state string', textBlock({ state: 'Done', requestId: '7' })],
    ['a direct child', textBlock({ result: { success: true } })],
    ['structuredContent', { content: [{ type: 'text', text: 'see structured content' }], structuredContent: { success: true } }],
    ['a text answer', [{ type: 'text', text: 'Exported 42 files to C:/work/Sales.SemanticModel/definition' }]],
    ['a plain string', 'Saved the model.'],
  ]) assert.equal(answerSucceeded(response), true, label);
  for (const [label, response] of [
    ['a nested failure', textBlock({ result: { success: false, error: 'E_EXPORT' } })],
    ['a pending status', textBlock({ status: 'Pending', requestId: '42' })],
    ['in progress', textBlock({ success: true, state: 'In Progress' })],
    ['queued below a root', textBlock({ success: true, job: { status: 'queued' } })],
    ['running two levels down', textBlock({ success: true, job: { steps: { status: 'running' } } })],
    ['cancelled', textBlock({ status: 'Cancelled' })],
    ['a non-empty errors list', textBlock({ success: true, data: { errors: ['partition Sales'] } })],
    ['an error text', textBlock({ ok: true, error: 'disk full' })],
    ['ok: false', textBlock({ ok: false })],
    ['the envelope\'s isError', { content: [{ type: 'text', text: '{"success":true}' }], isError: true }],
    ['the envelope\'s isError: false alone', { content: [{ type: 'text', text: 'Done' }], isError: false }],
    ['an object without a flag', textBlock({ requestId: '42', files: 42 })],
    ['a done status in a list item only', textBlock({ items: [{ status: 'done' }] })],
    ['a done status three levels down', textBlock({ job: { step: { status: 'done' } } })],
    ['a text with a failure word', 'Exported 40 of 42 files; 2 failed'],
    ['an unfinished text', 'Export queued: files will be written when the job ends'],
    ['a negated text', 'Nothing was exported.'],
    ['a bare success word', 'Success'],
    ['no answer', undefined],
    ['an empty answer', ''],
  ]) assert.equal(answerSucceeded(response), false, label);
  assert.equal(answerSucceeded('Connection established.', 'connect'), true);
  assert.equal(answerSucceeded('Connection established.', 'persist'), false, 'each kind has its own positive words');
});

test('state: connections are kept per MCP server with confirmedAt; a disconnect marks them on that server only', () => {
  withProject({}, (dir) => {
    post(dir, 'connection_operations', { operation: 'Connect', dataSource: 'localhost:51234' }, textBlock({ success: true, connectionName: LOCAL }));
    post(dir, 'connection_operations', { operation: 'Connect', dataSource: 'localhost:51234' }, textBlock({ success: true, connectionName: LOCAL }), OTHER_SERVER);
    const records = () => readStateFile(dir).mcpConnections.map((c) => [c.mcpServer, c.name, Boolean(c.disconnected)]);
    assert.deepEqual(records(), [[SERVER, LOCAL, false], [OTHER_SERVER, LOCAL, false]], 'one record per server');
    assert.ok(readStateFile(dir).mcpConnections.every((c) => !Number.isNaN(Date.parse(c.confirmedAt))));
    post(dir, 'connection_operations', { operation: 'Disconnect', connectionName: LOCAL }, textBlock({ success: true }), OTHER_SERVER);
    assert.deepEqual(records(), [[SERVER, LOCAL, false], [OTHER_SERVER, LOCAL, true]]);
    post(dir, 'connection_operations', { operation: 'GetConnection', connectionName: LOCAL }, textBlock({ success: true, connectionName: LOCAL }), OTHER_SERVER);
    assert.deepEqual(records(), [[SERVER, LOCAL, false], [OTHER_SERVER, LOCAL, false]], 'a new confirmation makes it live again');
  });
});

test('state: model writes are recorded (tool, operations, connection, time); reads, DAX and failed writes are not', () => {
  withProject({}, (dir) => {
    post(dir, 'measure_operations', { operation: 'List', connectionName: LOCAL }, textBlock({ success: true, data: [] }));
    post(dir, 'dax_query_operations', { operation: 'Execute', connectionName: LOCAL, maxRows: 1, query: 'EVALUATE ROW("a", 1)' }, textBlock({ success: true }));
    post(dir, 'measure_operations', { operation: 'Create', connectionName: LOCAL, definitions: [{ name: 'X' }] }, textBlock({ success: false, error: 'syntax' }));
    assert.equal(readStateFile(dir), null);
    post(dir, 'measure_operations', { operation: 'Create', connectionName: LOCAL, definitions: [{ name: 'Net', expression: '1' }] }, textBlock({ success: true }));
    post(dir, 'table_operations', { operation: 'Update', connectionName: LOCAL, definitions: [{ name: 'Sales', description: 'x' }] }, undefined);
    post(dir, 'measure_operations', { operation: 'Delete', connectionName: LOCAL, names: ['Old', 'Older'] }, textBlock({ success: true }));
    post(dir, 'table_operations', { operation: 'Refresh', connectionName: LOCAL }, textBlock({ success: true }));
    // Third audit: the explicit success signal is for confirmations and exports only. A write still pending, or a batch
    // with one failed item, may have changed the model, so it stays recorded for the Stop gate.
    post(dir, 'measure_operations', { operation: 'Create', connectionName: LOCAL, definitions: [{ name: 'Queued' }] }, textBlock({ status: 'Pending', requestId: '42' }));
    post(dir, 'measure_operations', { operation: 'Create', connectionName: LOCAL, definitions: [{ name: 'A' }, { name: 'B' }] }, textBlock({ success: true, results: [{ name: 'A', success: true }, { name: 'B', success: false }] }));
    const writes = readStateFile(dir).mcpWrites;
    assert.deepEqual(writes.map((w) => [w.tool, w.operations.join(), w.connection]), [
      ['measure_operations', 'create', LOCAL], ['table_operations', 'update', LOCAL], ['measure_operations', 'delete', LOCAL], ['table_operations', 'refresh', LOCAL],
      ['measure_operations', 'create', LOCAL], ['measure_operations', 'create', LOCAL],
    ]);
    assert.deepEqual(writes.map((w) => w.objects ?? null), [['Net'], ['Sales'], ['Old', 'Older'], null, ['Queued'], ['A', 'B']], 'the object names each write carried (definitions[].name, names[])');
    assert.ok(writes.every((w) => !Number.isNaN(Date.parse(w.at))));
    assert.ok(!JSON.stringify(writes).includes('expression'), 'no definitions in the state');
  });
});

test('state: masking off does not turn the record off, and masking still runs next to it', () => {
  withProject({ 'hardening/harness.config.json': JSON.stringify({ redaction: { secrets: false, piiInMcpOutput: false } }) }, (dir) => {
    assert.equal(post(dir, 'measure_operations', { operation: 'Create', connectionName: LOCAL }, textBlock({ success: true })), null);
    assert.equal(readStateFile(dir).mcpWrites.length, 1);
  });
  withProject({}, (dir) => {
    const email = ['someone', 'example.com'].join('@');
    const out = post(dir, 'connection_operations', { operation: 'Connect', dataSource: 'localhost:51234' }, { success: true, connectionName: LOCAL, owner: email });
    assert.match(JSON.stringify(out.hookSpecificOutput.updatedToolOutput), /\[PII:/);
    assert.equal(readStateFile(dir).mcpConnections[0].server, 'localhost:51234');
  });
});

/** A folder beside the temporary project: outside the repository on every platform (a drive path is not, on POSIX). */
const outsideFolder = (dir, name) => path.join(path.dirname(dir), `${path.basename(dir)}-staging-${name}`);
const exportCall = (dir, folderPath, { connectionName = LOCAL, response = textBlock({ success: true }), server = SERVER } = {}) =>
  post(dir, 'database_operations', { operation: 'ExportToTmdlFolder', ...(connectionName ? { connectionName } : {}), ...(folderPath ? { folderPath } : {}) }, response, server);
const pendingOf = (dir) => (readStateFile(dir)?.mcpWrites ?? []).map((w) => [w.connection, w.exportedTo ?? null]);

// Second audit: a disconnect cleared the writes Desktop still holds, and an export to a staging folder outside the
// repository cleared them although nothing reached the project. Third audit: a staging folder inside it did too.
test('state: an export into the model\'s own folder clears the writes it covers; any other folder records exportedTo; a disconnect clears nothing', () => {
  withProject({ 'Sales.SemanticModel/definition.pbism': '{}' }, (dir) => {
    const write = (connectionName) => post(dir, 'measure_operations', { operation: 'Create', connectionName }, textBlock({ success: true }));
    post(dir, 'connection_operations', { operation: 'Connect', dataSource: 'localhost:51234' }, textBlock({ success: true, connectionName: LOCAL }));
    write(LOCAL);
    write('TMDL-Finance');
    post(dir, 'database_operations', { operation: 'ExportTMDL', connectionName: LOCAL }, textBlock({ success: true, tmdl: 'model Model' }));
    post(dir, 'model_operations', { operation: 'ExportTMDL', connectionName: LOCAL }, textBlock({ success: true }));
    assert.equal(pendingOf(dir).length, 2, 'a script returned as text persists nothing');
    const model = path.join(dir, 'Sales.SemanticModel', 'definition');
    exportCall(dir, model, { response: textBlock({ success: false, error: 'denied' }) });
    exportCall(dir, model, { response: `Export failed: access to ${model} is denied` });
    exportCall(dir, model, { response: null });
    exportCall(dir, undefined);
    assert.deepEqual(pendingOf(dir), [[LOCAL, null], ['TMDL-Finance', null]], 'no success signal, or no folder named: nothing persisted');
    const staging = outsideFolder(dir, 'Sales');
    exportCall(dir, staging);
    assert.deepEqual(pendingOf(dir), [[LOCAL, staging], ['TMDL-Finance', null]], 'outside the repository: still pending, with exportedTo');
    post(dir, 'connection_operations', { operation: 'Disconnect', connectionName: LOCAL }, textBlock({ success: true }));
    assert.equal(pendingOf(dir).length, 2, 'a disconnect never clears a write');
    assert.deepEqual(readStateFile(dir).mcpConnections.map((c) => [c.name, Boolean(c.disconnected)]), [[LOCAL, true]]);
    exportCall(dir, model);
    assert.deepEqual(pendingOf(dir), [['TMDL-Finance', null]], 'into the model\'s definition folder: that connection\'s writes are cleared');
    exportCall(dir, 'staging/Finance', { connectionName: 'TMDL-Finance', response: 'Exported the model to staging/Finance.' });
    assert.deepEqual(pendingOf(dir), [['TMDL-Finance', 'staging/Finance']], 'a relative folder resolves inside the project; not a model folder: staging');
    assert.equal(readStateFile(dir).mcpWrites[0].exportedInside, true);
  });
});

// Third audit: an unnamed export went to whichever connection had pending writes, whatever its answer named.
test('state: an unnamed export belongs to the one live connection of its server, never to a count of pending writes', () => {
  withProject({ 'Sales.SemanticModel/definition.pbism': '{}' }, (dir) => {
    const model = path.join(dir, 'Sales.SemanticModel', 'definition');
    const connect = (connectionName) => post(dir, 'connection_operations', { operation: 'Connect' }, textBlock({ success: true, connectionName }));
    post(dir, 'measure_operations', { operation: 'Create', connectionName: LOCAL }, textBlock({ success: true }));
    post(dir, 'measure_operations', { operation: 'Create', connectionName: LOCAL }, textBlock({ success: true }), OTHER_SERVER);
    exportCall(dir, model, { connectionName: '' });
    assert.equal(pendingOf(dir).length, 2, 'no live connection on this server: the export belongs to none, though one connection has writes');
    connect(LOCAL);
    connect('TMDL-Finance');
    exportCall(dir, model, { connectionName: '' });
    assert.equal(pendingOf(dir).length, 2, 'two live connections: none');
    post(dir, 'connection_operations', { operation: 'Disconnect', connectionName: 'TMDL-Finance' }, textBlock({ success: true }));
    exportCall(dir, model, { connectionName: '' });
    assert.deepEqual(readStateFile(dir).mcpWrites.map((w) => [w.mcpServer, w.connection]), [[OTHER_SERVER, LOCAL]], 'one live connection: that one; the other server\'s writes stay');
  });
});

test('state: an unnamed write goes on the one live connection of its server; the model folder is recorded when known', () => {
  withProject({ 'Sales.SemanticModel/definition.pbism': '{}' }, (dir) => {
    const unnamed = () => post(dir, 'measure_operations', { operation: 'Create' }, textBlock({ success: true }));
    unnamed();
    post(dir, 'connection_operations', { operation: 'Connect' }, textBlock({ success: true, connectionName: LOCAL }));
    unnamed();
    post(dir, 'connection_operations', { operation: 'Connect' }, textBlock({ success: true, connectionName: 'TMDL-Finance' }));
    unnamed();
    const writes = readStateFile(dir).mcpWrites;
    assert.deepEqual(writes.map((w) => [w.connection, Boolean(w.inferred)]), [[null, false], [LOCAL, true], [null, false]], '0, 1 and 2 live connections');
    assert.equal(writes[1].folder, 'Sales.SemanticModel', 'PBIDesktop-Sales-<port> is the one Sales.SemanticModel folder');
    assert.equal(writes[1].mcpServer, SERVER);
  });
});

// ---------------------------------------------------------------- 2. the target rule (PreToolUse)

/** The PreToolUse guard's answer and the security events it logged. */
function guard(dir, tool, request, server = SERVER) {
  const out = run(dir, 'pre-tool-use.mjs', { hook_event_name: 'PreToolUse', tool_name: mcpTool(tool, server), tool_input: { request } })?.hookSpecificOutput;
  const log = path.join(dir, '.claude', 'logs', 'security-events.jsonl');
  const events = fs.existsSync(log) ? fs.readFileSync(log, 'utf8').trim().split('\n').map((l) => JSON.parse(l)) : [];
  return { decision: out?.permissionDecision ?? null, reason: out?.permissionDecisionReason ?? '', events };
}
const DAX = (connectionName) => ({ operation: 'Execute', maxRows: 5, query: "EVALUATE SUMMARIZECOLUMNS('Date'[Year], \"Sales\", [Total Sales])", ...(connectionName ? { connectionName } : {}) });
/** Connections confirmed on one MCP server, as the recorder writes them. */
const confirmedOn = (mcpServer, ...names) => names.map((name) => ({ mcpServer, name, server: 'localhost:51234', confirmedAt: '2026-10-16T09:00:00.000Z' }));
const confirmed = (...names) => ({ mcpConnections: confirmedOn(SERVER, ...names) });

// Second audit: without a state file (a host without a SessionStart hook) the rule did not apply at all.
test('target: without a state file there is no confirmed connection, so a query or write asks', () => {
  withProject({}, (dir) => {
    const dax = guard(dir, 'dax_query_operations', DAX());
    assert.equal(dax.decision, 'ask');
    assert.ok(dax.reason.includes(NO_TARGET), dax.reason);
    assert.equal(guard(dir, 'dax_query_operations', DAX(LOCAL)).decision, 'ask');
    assert.equal(guard(dir, 'measure_operations', { operation: 'Create', connectionName: LOCAL }).decision, 'ask');
    assert.equal(guard(dir, 'table_operations', { operation: 'List' }).decision, 'allow', 'a metadata read is never held back');
    assert.equal(guard(dir, 'connection_operations', { operation: 'Connect', connectionString: 'Data Source=localhost:51234' }).decision, 'allow');
    assert.equal(readStateFile(dir), null, 'the guard writes no state');
  });
});

test('target: an unnamed query or write passes with exactly one live connection on its server; with none or two it asks', () => {
  withProject({}, (dir) => {
    writeStateFile(dir, confirmed());
    assert.ok(guard(dir, 'dax_query_operations', DAX()).reason.includes(NO_TARGET), '0 confirmed');
    writeStateFile(dir, confirmed(LOCAL));
    assert.equal(guard(dir, 'dax_query_operations', DAX()).decision, 'allow', '1 confirmed: the server\'s last connection is that one');
    assert.equal(guard(dir, 'measure_operations', { operation: 'Create', definitions: [{ name: 'X' }] }).decision, 'ask', 'an unnamed write keeps the policy\'s own ask (not a local name)');
    writeStateFile(dir, confirmed(LOCAL, 'TMDL-Finance'));
    const two = guard(dir, 'dax_query_operations', DAX());
    assert.equal(two.decision, 'ask', '2 confirmed');
    assert.match(two.reason, /Name the connection \(connectionName\): 2 connections are confirmed on MCP server "powerbi-modeling" \(PBIDesktop-Sales-51234, TMDL-Finance\)/);
    assert.match(guard(dir, 'measure_operations', { operation: 'Update', definitions: [{ name: 'X' }] }).reason, /2 connections are confirmed/);
    writeStateFile(dir, { mcpConnections: [...confirmedOn(SERVER, LOCAL), { ...confirmedOn(SERVER, 'TMDL-Finance')[0], disconnected: true }] });
    assert.equal(guard(dir, 'dax_query_operations', DAX()).decision, 'allow', 'a disconnected connection does not count: one live is left');
  });
});

test('target: a name confirmed on one MCP server does not count on another', () => {
  withProject({}, (dir) => {
    writeStateFile(dir, { mcpConnections: confirmedOn(OTHER_SERVER, LOCAL) });
    const here = guard(dir, 'dax_query_operations', DAX(LOCAL));
    assert.equal(here.decision, 'ask');
    assert.match(here.reason, /"PBIDesktop-Sales-51234" was not confirmed on MCP server "powerbi-modeling" in this session \(confirmed there: none; its confirmation on powerbi-authoring-local does not count for this server\)/);
    assert.ok(guard(dir, 'dax_query_operations', DAX()).reason.includes(NO_TARGET), 'an unnamed call on the other server');
    assert.equal(guard(dir, 'dax_query_operations', DAX(LOCAL), OTHER_SERVER).decision, 'allow', 'on its own server it is confirmed');
    assert.equal(guard(dir, 'dax_query_operations', DAX(), OTHER_SERVER).decision, 'allow');
  });
});

test('target: no connectionName and no confirmed connection asks the user, in auto mode too; reads and connects do not', () => {
  withProject({}, (dir) => {
    writeStateFile(dir, {});
    const dax = guard(dir, 'dax_query_operations', DAX());
    assert.equal(dax.decision, 'ask');
    assert.ok(dax.reason.includes(NO_TARGET), dax.reason);
    assert.match(dax.reason, /Critical: auto mode always asks/);
    assert.ok(!dax.events.some((e) => e.event === 'auto-approve'));
    assert.equal(guard(dir, 'measure_operations', { operation: 'Create', definitions: [{ name: 'X' }] }).decision, 'ask');
    assert.equal(guard(dir, 'dax_query_operations', { operation: 'ClearCache' }).decision, 'ask');
    assert.equal(guard(dir, 'table_operations', { operation: 'List' }).decision, 'allow', 'a metadata read stays as today');
    assert.equal(guard(dir, 'dax_query_operations', { operation: 'Validate', query: 'EVALUATE ROW("a", 1)' }).decision, 'allow');
    assert.equal(guard(dir, 'connection_operations', { operation: 'Connect', connectionString: 'Data Source=localhost:51234' }).decision, 'allow', 'connection_operations is never held back');
    assert.equal(guard(dir, 'connection_operations', { operation: 'ListConnections' }).decision, 'allow');
  });
});

test('target: a confirmed name keeps today\'s verdict; an unknown name asks and lists the confirmed ones', () => {
  withProject({}, (dir) => {
    writeStateFile(dir, confirmed(LOCAL, 'TMDL-Finance'));
    assert.equal(guard(dir, 'dax_query_operations', DAX(LOCAL)).decision, 'allow');
    assert.equal(guard(dir, 'dax_query_operations', DAX(LOCAL.toLowerCase())).decision, 'allow', 'names compare without case');
    const create = guard(dir, 'measure_operations', { operation: 'Create', connectionName: LOCAL, definitions: [{ name: 'Net', expression: '1' }] });
    assert.equal(create.decision, 'allow', 'ordinary model work on a confirmed local connection is auto-approved');
    assert.ok(create.events.some((e) => e.event === 'auto-approve'));
    const other = guard(dir, 'dax_query_operations', DAX('PBIDesktop-Budget-60001'));
    assert.equal(other.decision, 'ask');
    assert.match(other.reason, /"PBIDesktop-Budget-60001" was not confirmed on MCP server "powerbi-modeling" in this session \(confirmed there: PBIDesktop-Sales-51234, TMDL-Finance\)/);
    assert.equal(guard(dir, 'measure_operations', { operation: 'Create', connectionName: 'PBIDesktop-Budget-60001' }).decision, 'ask');
    writeStateFile(dir, { mcpConnections: [{ ...confirmedOn(SERVER, LOCAL)[0], disconnected: true }] });
    assert.match(guard(dir, 'dax_query_operations', DAX(LOCAL)).reason, /\(confirmed there: none; it was disconnected since\)/);
  });
});

test('target: a deny stays a deny, the floor stays the floor, and lab mode runs an unconfirmed local query', () => {
  withProject({}, (dir) => {
    writeStateFile(dir, {});
    assert.equal(guard(dir, 'database_operations', { operation: 'DeployToFabric', connectionName: LOCAL }).decision, 'deny');
    const remote = guard(dir, 'measure_operations', { operation: 'Delete', connectionName: 'Fabric-WS-Model' });
    assert.equal(remote.decision, 'ask');
    assert.match(remote.reason, /was not confirmed on MCP server "powerbi-modeling" in this session \(confirmed there: none\)/);
    assert.match(remote.reason, /Destructive or bulk model operation/, 'the floor\'s own reason stays');
  });
  withProject({ 'hardening/harness.config.json': JSON.stringify({ approvals: { mode: 'lab' } }) }, (dir) => {
    writeStateFile(dir, {});
    assert.equal(guard(dir, 'dax_query_operations', DAX()).decision, 'allow');
    assert.equal(guard(dir, 'measure_operations', { operation: 'Delete', connectionName: 'Fabric-WS-Model' }).decision, 'ask', 'the floor asks in lab mode');
  });
});

test('target: end to end, a connect answer confirms the name and a disconnect takes it back', () => {
  withProject({}, (dir) => {
    run(dir, 'session-start.mjs', { hook_event_name: 'SessionStart', source: 'startup' });
    assert.ok(fs.existsSync(statePath(dir)), 'the session start writes the state file');
    assert.equal(guard(dir, 'dax_query_operations', DAX()).decision, 'ask');
    assert.equal(guard(dir, 'dax_query_operations', DAX(LOCAL)).decision, 'ask');
    post(dir, 'connection_operations', { operation: 'Connect', dataSource: 'localhost:51234' }, textBlock({ success: true, connectionName: LOCAL }));
    assert.equal(guard(dir, 'dax_query_operations', DAX(LOCAL)).decision, 'allow');
    post(dir, 'connection_operations', { operation: 'Disconnect', connectionName: LOCAL }, textBlock({ success: true }));
    assert.equal(guard(dir, 'dax_query_operations', DAX(LOCAL)).decision, 'ask', 'reconfirm after a disconnect');
  });
});

// ---------------------------------------------------------------- 3. the Stop gate

// An Analysis Services TMDL folder that validates cleanly (as in session-start.test.mjs).
const MODEL = {
  'models/Finance/database.tmdl': 'database Finance\n\tcompatibilityLevel: 1600\n',
  'models/Finance/model.tmdl': 'model Model\n\tculture: en-US\n\nref table Sales\n',
  'models/Finance/tables/Sales.tmdl': 'table Sales\n\n\tmeasure Revenue = SUM ( Sales[Amount] )\n\t\tformatString: 0\n\n\tcolumn Amount\n\t\tdataType: decimal\n\t\tsourceColumn: Amount\n',
};
const write = (connection, at, extra = {}) => ({ mcpServer: SERVER, tool: 'measure_operations', operations: ['create'], connection, at, ...extra });
const PENDING = { mcpWrites: [write(LOCAL, '2026-10-16T10:00:00.000Z'), write(LOCAL, '2026-10-16T10:01:00.000Z')] };

/** A temporary Git repository (no commit needed: untracked files count) whose session logs Git ignores. */
function withRepo(files, fn) {
  return withProject(files, (dir) => {
    spawnSync('git', ['init', '-q'], { cwd: dir, env: gitEnv() });
    fs.appendFileSync(path.join(dir, '.git', 'info', 'exclude'), '\n.claude/logs/\n');
    return fn(dir);
  });
}
const stop = (dir, extra = {}) => run(dir, 'stop-gate.mjs', { hook_event_name: 'Stop', stop_hook_active: false, ...extra });
const PERSIST_TEXT = /2 MCP write\(s\) on PBIDesktop-Sales-51234 are in the model's memory only; persist them \(export\/save to the PBIP, then `git diff`\), or state that they were discarded, before finishing \(docs\/harness\/MCP\.md, Persistence\)/;

test('stop gate: pending MCP writes without a model diff block once, then warn the user; a new write blocks again', () => {
  withRepo({}, (dir) => {
    writeStateFile(dir, PENDING);
    const first = stop(dir);
    assert.equal(first.decision, 'block');
    assert.match(first.reason, PERSIST_TEXT);
    const again = stop(dir, { stop_hook_active: true });
    assert.equal(again.decision, undefined);
    assert.match(again.systemMessage, PERSIST_TEXT);
    assert.equal(stop(dir).decision, undefined, 'no second block for the same writes');
    post(dir, 'measure_operations', { operation: 'Update', connectionName: LOCAL }, textBlock({ success: true }));
    const more = stop(dir);
    assert.equal(more.decision, 'block');
    assert.match(more.reason, /3 MCP write\(s\) on PBIDesktop-Sales-51234/);
  });
});

test('stop gate: a TMDL change in the repository lets the stop pass; an unrelated file does not', () => {
  withRepo({ 'notes.txt': 'x\n' }, (dir) => {
    writeStateFile(dir, PENDING);
    assert.equal(stop(dir).decision, 'block', 'a changed file that is not a model file');
    for (const [rel, content] of Object.entries(MODEL)) {
      fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
      fs.writeFileSync(path.join(dir, rel), content);
    }
    assert.equal(stop(dir), null);
    // F1-38: the diff that let the stop pass marks the writes persisted (they stay in the state, no longer pending).
    assert.deepEqual(readStateFile(dir).mcpWrites.map((w) => w.persisted), [true, true], 'a diff that lets the stop pass marks the writes persisted');
    assert.equal(readStateFile(dir).mcpStopBlocks, undefined, 'the block counter is reset');
    commitAll(dir);
    assert.equal(stop(dir), null, 'committing that diff brings no block back');
  });
});

test('stop gate: once the MCP block was given, validation errors still block and carry the MCP warning, then the user is warned', () => {
  withRepo({ 'docs/long.md': `${'line\n'.repeat(501)}` }, (dir) => {
    writeStateFile(dir, PENDING);
    assert.match(stop(dir).reason, PERSIST_TEXT, 'the MCP block comes first');
    // F1-35: Claude Code sends stop_hook_active: true on the stop that follows a block; the counters decide, not that flag.
    const next = stop(dir, { stop_hook_active: true });
    assert.equal(next.decision, 'block');
    assert.match(next.reason, /validation error\(s\) in uncommitted files/);
    assert.match(next.systemMessage, PERSIST_TEXT);
    // The MCP block was the first of the two blocks the errors get: MCP block, validation block, then the warning.
    const third = stop(dir, { stop_hook_active: true });
    assert.equal(third.decision, undefined);
    assert.match(third.systemMessage, /1 validation error\(s\) remain in uncommitted files:/);
    assert.match(third.systemMessage, PERSIST_TEXT);
  });
});

// F1-35: the gate read stop_hook_active, which Claude Code sets on the stop after a block, so the second block never came.
test('stop gate: validation errors block twice in a row whatever stop_hook_active says, then warn; a clean stop starts over (F1-35)', () => {
  withRepo({ 'docs/long.md': `${'line\n'.repeat(501)}` }, (dir) => {
    const first = stop(dir);
    assert.equal(first.decision, 'block');
    assert.match(first.reason, /Before finishing: 1 validation error\(s\) in uncommitted files/);
    assert.equal(readStateFile(dir).stopBlocks, 1);
    const second = stop(dir, { stop_hook_active: true });
    assert.equal(second.decision, 'block', 'the second block comes although a stop hook was already active');
    const third = stop(dir, { stop_hook_active: true });
    assert.equal(third.decision, undefined, 'the third stop only warns');
    assert.match(third.systemMessage, /1 validation error\(s\) remain in uncommitted files:/);
    assert.equal(readStateFile(dir).stopBlocks, 3);
    // A subagent has its own count (stopBlocks:<agent_id>).
    const sub = { agent_id: 'agent-1', agent_type: 'bi-tmdl-modeler', hook_event_name: 'SubagentStop', stop_hook_active: true };
    assert.equal(stop(dir, sub).decision, 'block');
    assert.equal(readStateFile(dir)['stopBlocks:agent-1'], 1);
    // Fixing the files ends the series: the count is gone, and new errors block twice again.
    addFiles(dir, { 'docs/long.md': 'short\n' });
    assert.equal(stop(dir), null);
    assert.equal(readStateFile(dir).stopBlocks, undefined, 'a clean stop resets the count');
    addFiles(dir, { 'docs/long.md': `${'line\n'.repeat(501)}` });
    assert.equal(stop(dir, { stop_hook_active: true }).decision, 'block');
    assert.equal(stop(dir, { stop_hook_active: true }).decision, 'block');
    assert.equal(stop(dir, { stop_hook_active: true }).decision, undefined);
    // The series also ends when nothing is left to validate (the file is reverted, or committed): later errors block twice again.
    fs.rmSync(path.join(dir, 'docs', 'long.md'));
    assert.equal(stop(dir), null);
    assert.equal(readStateFile(dir).stopBlocks, undefined, 'a clean tree resets the count too');
    addFiles(dir, { 'docs/long.md': `${'line\n'.repeat(501)}` });
    assert.equal(stop(dir, { stop_hook_active: true }).decision, 'block');
    assert.equal(readStateFile(dir).stopBlocks, 1);
  });
});

test('stop gate: a state file that cannot hold the count leaves the end of the block loop to stop_hook_active (F1-35)', () => {
  withRepo({ 'docs/long.md': `${'line\n'.repeat(501)}` }, (dir) => {
    fs.mkdirSync(statePath(dir), { recursive: true }); // a folder where the state file belongs: nothing can be saved there
    assert.equal(stop(dir).decision, 'block');
    assert.equal(stop(dir, { stop_hook_active: true }).decision, undefined, 'no counter can end the loop, so the flag does');
    assert.equal(fs.statSync(statePath(dir)).isDirectory(), true);
  });
});

test('stop gate: an export into the model\'s folder lets the stop pass; subagents are never held for MCP writes', () => {
  withRepo({ 'Sales.SemanticModel/definition.pbism': '{}' }, (dir) => {
    commitAll(dir);
    writeStateFile(dir, PENDING);
    assert.equal(stop(dir, { agent_id: 'agent-1', agent_type: 'bi-tmdl-modeler', hook_event_name: 'SubagentStop' }), null);
    exportCall(dir, path.join(dir, 'Sales.SemanticModel', 'definition'));
    assert.deepEqual(pendingOf(dir), []);
    assert.equal(stop(dir), null);
  });
});

const DISCONNECTED = /PBIDesktop-Sales-51234 was disconnected, and disconnecting is not persisting/;
test('stop gate: a disconnect is not a persist, so the stop still blocks once and says so', () => {
  withRepo({}, (dir) => {
    writeStateFile(dir, { ...confirmed(LOCAL), ...PENDING });
    post(dir, 'connection_operations', { operation: 'Disconnect', connectionName: LOCAL }, textBlock({ success: true }));
    const first = stop(dir);
    assert.equal(first.decision, 'block');
    assert.match(first.reason, PERSIST_TEXT);
    assert.match(first.reason, DISCONNECTED);
    const again = stop(dir);
    assert.equal(again.decision, undefined, 'blocked once');
    assert.match(again.systemMessage, DISCONNECTED);
  });
  withRepo({}, (dir) => {
    writeStateFile(dir, { ...confirmed(LOCAL), mcpWrites: [write(null, '2026-10-16T10:00:00.000Z')] });
    post(dir, 'connection_operations', { operation: 'Disconnect' }, textBlock({ success: true }));
    assert.match(stop(dir).reason, /1 MCP write\(s\) on the last connection .*The last connection was disconnected, and disconnecting is not persisting/);
  });
});

/** The Stop gate's note for an export into a folder that is not the model's own. */
const stagingNote = (to, folder = '') =>
  `PBIDesktop-Sales-51234 was exported to ${to}, which is not the project's model folder: merge the export into the project's model folder${folder ? ` (${folder})` : ''} and show the diff`;

test('stop gate: an export outside the repository keeps the block and asks to merge the export into the model folder', () => {
  withRepo({}, (dir) => {
    writeStateFile(dir, PENDING);
    const staging = outsideFolder(dir, 'Sales');
    exportCall(dir, staging);
    const first = stop(dir);
    assert.equal(first.decision, 'block');
    assert.ok(first.reason.includes(stagingNote(staging)), first.reason);
  });
});

/** Writes files into the repository (untracked files are changes for git). */
function addFiles(dir, files) {
  for (const [rel, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), content);
  }
}
/** Commits everything, so only later files are changes. */
function commitAll(dir) {
  spawnSync('git', ['add', '-A'], { cwd: dir, env: gitEnv() });
  // The committer address is built at run time, so the release check finds no address in this file.
  const email = ['t', 'example.invalid'].join('@');
  const r = spawnSync('git', ['-c', 'user.name=t', '-c', `user.email=${email}`, '-c', 'commit.gpgsign=false', 'commit', '-q', '--no-verify', '-m', 'base'], { cwd: dir, env: gitEnv(), encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
}
/** True when a stop answer carries the MCP persistence text (as a block or a warning). */
const mcpHeld = (answer) => /MCP write\(s\)/.test(JSON.stringify(answer ?? {}));
const TABLE = MODEL['models/Finance/tables/Sales.tmdl'];

// Second audit: any .tmdl anywhere passed the gate, a reference copy under docs/sources included.
test('stop gate: a .tmdl change under docs/sources or outside a model folder does not pass; one in a model folder does', () => {
  withRepo({}, (dir) => {
    writeStateFile(dir, PENDING);
    addFiles(dir, Object.fromEntries(Object.entries(MODEL).map(([rel, content]) => [rel.replace('models/Finance', 'docs/sources/Cube/definition'), content])));
    addFiles(dir, { 'scratch/Sales.tmdl': TABLE, 'Other.SemanticModel/notes/Sales.tmdl': TABLE });
    const held = stop(dir);
    assert.equal(held.decision, 'block', 'a reference copy, a loose .tmdl and a file outside definition/ persist nothing');
    assert.match(held.reason, PERSIST_TEXT);
    addFiles(dir, MODEL);
    assert.ok(!mcpHeld(stop(dir)), 'an Analysis Services TMDL folder (findPbipItems: tabular) passes');
  });
  withRepo({}, (dir) => {
    writeStateFile(dir, PENDING);
    addFiles(dir, { 'Sales.SemanticModel/definition/tables/Sales.tmdl': TABLE });
    assert.ok(!mcpHeld(stop(dir)), 'a *.SemanticModel/definition file passes');
  });
});

test('stop gate: when the connection\'s model folder is known, only a diff under it passes', () => {
  // PBIDesktop-Sales-<port>: the repository's one Sales.SemanticModel folder.
  withRepo({ 'Sales.SemanticModel/definition.pbism': '{}', 'Budget.SemanticModel/definition.pbism': '{}' }, (dir) => {
    commitAll(dir);
    writeStateFile(dir, PENDING);
    addFiles(dir, { 'Budget.SemanticModel/definition/tables/Budget.tmdl': TABLE });
    const held = stop(dir);
    assert.equal(held.decision, 'block', 'another model\'s diff');
    assert.match(held.reason, /Only a diff under Sales\.SemanticModel persists PBIDesktop-Sales-51234/);
    addFiles(dir, { 'Sales.SemanticModel/definition/tables/Sales.tmdl': TABLE });
    assert.ok(!mcpHeld(stop(dir)));
  });
  // TMDL-<path>: an Analysis Services TMDL folder named by its path.
  withRepo({ ...MODEL, ...Object.fromEntries(Object.entries(MODEL).map(([rel, c]) => [rel.replace('Finance', 'Budget'), c])) }, (dir) => {
    commitAll(dir);
    const name = `TMDL-${path.join(dir, 'models', 'Finance')}`;
    writeStateFile(dir, { mcpWrites: [write(name, '2026-10-16T10:00:00.000Z')] });
    addFiles(dir, { 'models/Budget/tables/Sales.tmdl': `${TABLE}\n` });
    assert.equal(stop(dir).decision, 'block', 'the other TMDL folder');
    addFiles(dir, { 'models/Finance/tables/Sales.tmdl': `${TABLE}\n` });
    assert.ok(!mcpHeld(stop(dir)));
  });
  // A path from the connect answer that lies outside the repository: no diff in the repository persists it.
  withRepo(MODEL, (dir) => {
    const elsewhere = outsideFolder(dir, 'Model').replace(/\\/g, '/');
    writeStateFile(dir, { mcpConnections: [{ ...confirmedOn(SERVER, 'TMDL-Elsewhere')[0], path: elsewhere }], mcpWrites: [write('TMDL-Elsewhere', '2026-10-16T10:00:00.000Z')] });
    const held = stop(dir);
    assert.equal(held.decision, 'block', 'a model diff of the repository is not that model');
    assert.ok(held.reason.includes(`The model folder of TMDL-Elsewhere (${elsewhere}) is outside the repository: merge it into the project and show the diff`), held.reason);
  });
});

// ---------------------------------------------------------------- 3b. third audit: export target and success signal

/** A committed PBIP model folder for PBIDesktop-Sales-<port> (the one Sales.SemanticModel of the repository). */
const SALES_MODEL = {
  'Sales.SemanticModel/definition.pbism': '{}',
  'Sales.SemanticModel/definition/database.tmdl': MODEL['models/Finance/database.tmdl'],
  'Sales.SemanticModel/definition/model.tmdl': MODEL['models/Finance/model.tmdl'],
  'Sales.SemanticModel/definition/tables/Sales.tmdl': TABLE,
};
/** Session start, a confirmed connect to PBIDesktop-Sales-<port> and one write that creates the measure Net Margin. */
function connectAndWrite(dir) {
  run(dir, 'session-start.mjs', { hook_event_name: 'SessionStart', source: 'startup' });
  post(dir, 'connection_operations', { operation: 'Connect', connectionName: LOCAL, dataSource: 'localhost:51234' }, textBlock({ success: true, connectionName: LOCAL }));
  post(dir, 'measure_operations', { operation: 'Create', connectionName: LOCAL, definitions: [{ name: 'Net Margin', tableName: 'Sales', expression: '1' }] }, textBlock({ success: true }));
}

test('third audit: an export into exports/staging/Sales (ignored, inside the repository) keeps the write pending, and the stop gate blocks', () => {
  withRepo({ '.gitignore': 'exports/\n', ...SALES_MODEL }, (dir) => {
    commitAll(dir);
    connectAndWrite(dir);
    exportCall(dir, path.join(dir, 'exports', 'staging', 'Sales'));
    // What the export wrote there: a complete TMDL folder, which Git ignores.
    addFiles(dir, Object.fromEntries(Object.entries(SALES_MODEL).filter(([rel]) => rel.endsWith('.tmdl')).map(([rel, c]) => [rel.replace('Sales.SemanticModel/definition', 'exports/staging/Sales'), c])));
    assert.deepEqual(pendingOf(dir), [[LOCAL, 'exports/staging/Sales']]);
    const held = stop(dir);
    assert.equal(held.decision, 'block');
    assert.ok(held.reason.includes(stagingNote('exports/staging/Sales', 'Sales.SemanticModel')), held.reason);
    exportCall(dir, path.join(dir, 'Sales.SemanticModel', 'definition'), { response: [{ type: 'text', text: `Exported 42 files to ${path.join(dir, 'Sales.SemanticModel', 'definition')}` }] });
    assert.deepEqual(pendingOf(dir), [], 'the text answer "Exported 42 files to <folder>" into the model\'s own definition folder clears it');
  });
});

test('third audit: an unnamed export whose answer names PBIDesktop-Other leaves PBIDesktop-Sales pending; the answer\'s name wins over the request\'s', () => {
  withRepo(SALES_MODEL, (dir) => {
    commitAll(dir);
    connectAndWrite(dir);
    const model = path.join(dir, 'Sales.SemanticModel', 'definition');
    exportCall(dir, model, { connectionName: '', response: textBlock({ success: true, connectionName: 'PBIDesktop-Other' }) });
    assert.deepEqual(pendingOf(dir), [[LOCAL, null]], 'Sales stays pending; Other has nothing to clear');
    assert.equal(stop(dir).decision, 'block');
    exportCall(dir, model, { connectionName: LOCAL, response: textBlock({ success: true, connectionName: 'PBIDesktop-Other' }) });
    assert.deepEqual(pendingOf(dir), [[LOCAL, null]], 'request Sales, answer Other: the answer wins and Sales stays pending');
    exportCall(dir, model, { connectionName: 'PBIDesktop-Other', response: textBlock({ success: true, connectionName: LOCAL }) });
    assert.deepEqual(pendingOf(dir), [], 'request Other, answer Sales: the answer wins and clears Sales');
  });
  withRepo(SALES_MODEL, (dir) => {
    commitAll(dir);
    connectAndWrite(dir);
    const roots = [{ type: 'text', text: JSON.stringify({ success: true, connectionName: LOCAL }) }, { type: 'text', text: JSON.stringify({ success: true, connectionName: 'PBIDesktop-Other' }) }];
    exportCall(dir, path.join(dir, 'Sales.SemanticModel', 'definition'), { connectionName: LOCAL, response: roots });
    assert.deepEqual(pendingOf(dir), [[LOCAL, null]], 'an answer naming two connections belongs to none');
    exportCall(dir, path.join(dir, 'Sales.SemanticModel', 'definition'), { connectionName: '' });
    assert.deepEqual(pendingOf(dir), [], 'no name anywhere: the one live connection');
  });
});

// F1-128 / E10: an answer's success counts on a root or a direct child, but its connectionName was read from the roots only,
// so {result: {success: true, connectionName: Other}} cleared the writes of the connection the request named.
test('F1-128: an export answer names its connection in a root or a direct child of one; two names belong to none', () => {
  withRepo(SALES_MODEL, (dir) => {
    commitAll(dir);
    connectAndWrite(dir);
    const model = path.join(dir, 'Sales.SemanticModel', 'definition');
    const rewrite = () => post(dir, 'measure_operations', { operation: 'Create', connectionName: LOCAL, definitions: [{ name: 'Gross Margin', tableName: 'Sales', expression: '2' }] }, textBlock({ success: true }));
    const answer = (connectionName, request) => exportCall(dir, model, { connectionName: request, response: textBlock({ result: { success: true, connectionName } }) });
    answer('PBIDesktop-Other', LOCAL);
    assert.deepEqual(pendingOf(dir), [[LOCAL, null]], 'request Sales, the child of the answer names Other: the answer wins, Sales stays pending');
    answer('PBIDesktop-Other', '');
    assert.deepEqual(pendingOf(dir), [[LOCAL, null]], 'an unnamed request: the same');
    exportCall(dir, model, { connectionName: LOCAL, response: textBlock({ success: true, connectionName: LOCAL, result: { connectionName: 'PBIDesktop-Other' } }) });
    assert.deepEqual(pendingOf(dir), [[LOCAL, null]], 'the root names Sales, its child names Other: two connections, none');
    answer(LOCAL, 'PBIDesktop-Other');
    assert.deepEqual(pendingOf(dir), [], 'request Other, the child of the answer names Sales: the answer wins and clears Sales');
    // The scopes are those of the success signal: a root and its direct children, not a list item and not deeper.
    rewrite();
    exportCall(dir, model, { connectionName: LOCAL, response: textBlock({ success: true, items: [{ connectionName: 'PBIDesktop-Other' }] }) });
    assert.deepEqual(pendingOf(dir), [], 'a name in a list item is not read: the request\'s name decides');
    rewrite();
    exportCall(dir, model, { connectionName: LOCAL, response: textBlock({ success: true, data: { info: { connectionName: 'PBIDesktop-Other' } } }) });
    assert.deepEqual(pendingOf(dir), [], 'nor is a name two levels down');
  });
});

test('export target: only the connection\'s own model folder clears; another model, a reference copy, an exclusion or exports/ is staging', () => {
  withProject({ 'Sales.SemanticModel/definition.pbism': '{}', 'Budget.SemanticModel/definition.pbism': '{}' }, (dir) => {
    connectAndWrite(dir);
    for (const rel of ['Budget.SemanticModel/definition', 'docs/sources/Sales.SemanticModel/definition', 'hardening/tests/fixtures/Sales.SemanticModel/definition', 'exports/Sales.SemanticModel/definition', 'Sales.SemanticModel/definition/tables']) {
      exportCall(dir, path.join(dir, rel));
      assert.deepEqual(pendingOf(dir), [[LOCAL, rel]], rel);
    }
    exportCall(dir, path.join(dir, 'Sales.SemanticModel'));
    assert.deepEqual(pendingOf(dir), [], 'the model folder root counts as the model folder');
  });
});

test('export target: with the connection\'s folder unknown, a TMDL folder counts only when Git tracks it, and a staging copy never passes the gate', () => {
  withRepo(MODEL, (dir) => {
    commitAll(dir);
    const unknown = 'PBIDesktop-Unknown-1';
    run(dir, 'session-start.mjs', { hook_event_name: 'SessionStart', source: 'startup' });
    post(dir, 'measure_operations', { operation: 'Create', connectionName: unknown }, textBlock({ success: true }));
    // A fresh staging folder the export fills: findPbipItems now lists it as tabular, but Git does not track it.
    addFiles(dir, Object.fromEntries(Object.entries(MODEL).map(([rel, c]) => [rel.replace('models/Finance', 'staging/Finance'), c])));
    exportCall(dir, path.join(dir, 'staging', 'Finance'), { connectionName: unknown });
    assert.deepEqual(pendingOf(dir), [[unknown, 'staging/Finance']]);
    assert.equal(stop(dir).decision, 'block', 'the staging copy\'s files are not the model\'s diff');
    exportCall(dir, path.join(dir, 'models', 'Finance'), { connectionName: unknown });
    assert.deepEqual(pendingOf(dir), [], 'a tracked TMDL folder of the repository');
  });
});

/** The files of SALES_MODEL under another folder name. */
const salesModelAt = (folder) => Object.fromEntries(Object.entries(SALES_MODEL).map(([rel, c]) => [rel.replace('Sales.SemanticModel', folder), c]));

// F1-36 / E2: with the connection's folder unknown, any folder named *.SemanticModel[/definition] cleared the writes: the copy the
// export had just written (once it exists it is the one Sales.SemanticModel of the repository), an ignored one, one not made yet.
test('export target (F1-36): with the connection\'s folder unknown, a fresh or an ignored *.SemanticModel copy is staging; a tracked model folder clears', () => {
  // PBIDesktop-Sales-51234 finds no Sales.SemanticModel in a repository that holds models/Finance only: its folder is unknown.
  const staged = (dir, staging) => {
    assert.deepEqual(pendingOf(dir), [[LOCAL, staging]], 'the write stays pending, with exportedTo');
    const held = stop(dir);
    assert.equal(held.decision, 'block');
    assert.match(held.reason, /^\[bi-harness\] Before finishing: 1 MCP write\(s\) on PBIDesktop-Sales-51234 are in the model's memory only/);
    assert.ok(held.reason.includes(stagingNote(staging)), held.reason);
  };
  withRepo(MODEL, (dir) => {
    commitAll(dir);
    connectAndWrite(dir);
    exportCall(dir, path.join(dir, 'staging', 'Sales.SemanticModel', 'definition'));
    staged(dir, 'staging/Sales.SemanticModel/definition'); // a folder that does not exist yet
  });
  withRepo(MODEL, (dir) => {
    commitAll(dir);
    connectAndWrite(dir);
    addFiles(dir, salesModelAt('staging/Sales.SemanticModel')); // what the export wrote: now the one Sales.SemanticModel of the repository
    exportCall(dir, path.join(dir, 'staging', 'Sales.SemanticModel', 'definition'));
    staged(dir, 'staging/Sales.SemanticModel/definition');
  });
  withRepo({ ...MODEL, '.gitignore': 'tmp/\n' }, (dir) => {
    commitAll(dir);
    connectAndWrite(dir);
    addFiles(dir, salesModelAt('tmp/Sales.SemanticModel'));
    assert.equal(spawnSync('git', ['check-ignore', '-q', '--', 'tmp/Sales.SemanticModel/definition'], { cwd: dir, env: gitEnv() }).status, 0, 'the target is ignored');
    exportCall(dir, path.join(dir, 'tmp', 'Sales.SemanticModel', 'definition'));
    staged(dir, 'tmp/Sales.SemanticModel/definition');
  });
  // Two Sales.SemanticModel folders: the name does not tell which is the connection's, so Git's tracking decides.
  withRepo({ ...salesModelAt('projA/Sales.SemanticModel'), ...salesModelAt('projB/Sales.SemanticModel') }, (dir) => {
    commitAll(dir);
    connectAndWrite(dir);
    addFiles(dir, salesModelAt('projA/staging/Sales.SemanticModel'));
    exportCall(dir, path.join(dir, 'projA', 'staging', 'Sales.SemanticModel', 'definition'));
    staged(dir, 'projA/staging/Sales.SemanticModel/definition');
    exportCall(dir, path.join(dir, 'projA', 'Sales.SemanticModel', 'definition'));
    assert.deepEqual(pendingOf(dir), [], 'the tracked folder of the project clears them');
    assert.equal(stop(dir), null);
  });
  // The tracked model folder has another name than the connection's: still the project's own.
  withRepo(salesModelAt('Budget.SemanticModel'), (dir) => {
    commitAll(dir);
    connectAndWrite(dir);
    exportCall(dir, path.join(dir, 'Budget.SemanticModel', 'definition'));
    assert.deepEqual(pendingOf(dir), []);
    assert.equal(stop(dir), null);
  });
  // The write recorded the project's folder (findPbipItems listed it before the export), committed or not: the export into it clears.
  withRepo(SALES_MODEL, (dir) => {
    connectAndWrite(dir);
    assert.equal(readStateFile(dir).mcpWrites[0].folder, 'Sales.SemanticModel');
    exportCall(dir, path.join(dir, 'Sales.SemanticModel', 'definition'));
    assert.deepEqual(pendingOf(dir), []);
  });
  // A target Git ignores is staging everywhere, the connection's own folder included.
  withRepo({ 'Sales.SemanticModel/definition.pbism': '{}', '.gitignore': 'Sales.SemanticModel/definition/\n' }, (dir) => {
    commitAll(dir);
    addFiles(dir, { 'Sales.SemanticModel/definition/database.tmdl': MODEL['models/Finance/database.tmdl'] });
    connectAndWrite(dir);
    assert.equal(readStateFile(dir).mcpWrites[0].folder, 'Sales.SemanticModel');
    exportCall(dir, path.join(dir, 'Sales.SemanticModel', 'definition'));
    assert.deepEqual(pendingOf(dir), [[LOCAL, 'Sales.SemanticModel/definition']], 'the folder is the connection\'s own, but ignored: nothing can show in git');
  });
  // The audit's own names: PBIDesktop-Unknown-1 exported into Unknown.SemanticModel copies, a fresh and an ignored one.
  withRepo({ ...MODEL, '.gitignore': 'tmp/\n' }, (dir) => {
    commitAll(dir);
    const unknown = 'PBIDesktop-Unknown-1';
    run(dir, 'session-start.mjs', { hook_event_name: 'SessionStart', source: 'startup' });
    post(dir, 'measure_operations', { operation: 'Create', connectionName: unknown, definitions: [{ name: 'Net Margin', tableName: 'Sales', expression: '1' }] }, textBlock({ success: true }));
    for (const to of ['staging/Unknown.SemanticModel', 'tmp/Unknown.SemanticModel']) {
      addFiles(dir, salesModelAt(to));
      exportCall(dir, path.join(dir, ...to.split('/'), 'definition'), { connectionName: unknown });
      assert.deepEqual(pendingOf(dir), [[unknown, `${to}/definition`]], to);
    }
    const held = stop(dir);
    assert.equal(held.decision, 'block');
    assert.ok(held.reason.includes('PBIDesktop-Unknown-1 was exported to tmp/Unknown.SemanticModel/definition, which is not the project\'s model folder: merge the export'), held.reason);
  });
});

// F1-37: pendingMcpWrites kept the last exportedTo only, so after a second staging export the first copy (which mentions the
// written object) passed the gate as a model diff.
test('stop gate: every staging copy of a write is left out of the diff, not only the last one (F1-37)', () => {
  withRepo(MODEL, (dir) => {
    commitAll(dir);
    connectAndWrite(dir);
    const copy = (to) => addFiles(dir, Object.fromEntries(Object.entries(MODEL).map(([rel, c]) => [rel.replace('models/Finance', to), rel.endsWith('Sales.tmdl') ? `${c}\n\tmeasure 'Net Margin' = 1\n` : c])));
    copy('staging/Finance1');
    exportCall(dir, path.join(dir, 'staging', 'Finance1'));
    copy('staging/Finance2');
    exportCall(dir, path.join(dir, 'staging', 'Finance2'));
    assert.deepEqual(readStateFile(dir).mcpWrites[0].stagedInside, ['staging/Finance1', 'staging/Finance2']);
    assert.equal(readStateFile(dir).mcpWrites[0].exportedTo, 'staging/Finance2', 'the last export stays the one the message names');
    const held = stop(dir);
    assert.equal(held.decision, 'block', 'both copies declare the measure, and neither is the model');
    assert.ok(held.reason.includes(stagingNote('staging/Finance2')), held.reason);
    // The merge into the model folder is what persists it.
    addFiles(dir, { 'models/Finance/tables/Sales.tmdl': `${TABLE}\n\tmeasure 'Net Margin' = 1\n` });
    assert.equal(stop(dir), null);
  });
});

test('state: the staging copies of a write are kept, the newest ten, an older state\'s one included (F1-37)', () => {
  withRepo(MODEL, (dir) => {
    commitAll(dir);
    const old = Array.from({ length: 10 }, (_, i) => `staging/F${i + 1}`);
    writeStateFile(dir, { mcpWrites: [write(LOCAL, '2026-10-16T10:00:00.000Z', { objects: ['Net Margin'], stagedInside: old, exportedTo: old[9], exportedInside: true })] });
    exportCall(dir, path.join(dir, 'staging', 'F11'));
    assert.deepEqual(readStateFile(dir).mcpWrites[0].stagedInside, [...old.slice(1), 'staging/F11'], 'ten kept, the oldest dropped');
    assert.equal(readStateFile(dir).mcpWrites[0].exportedTo, 'staging/F11');
    // A state written before the list existed holds the last staging copy as exportedTo alone.
    writeStateFile(dir, { mcpWrites: [write(LOCAL, '2026-10-16T10:00:00.000Z', { objects: ['Net Margin'], exportedTo: 'staging/Old', exportedInside: true })] });
    exportCall(dir, path.join(dir, 'staging', 'New'));
    assert.deepEqual(readStateFile(dir).mcpWrites[0].stagedInside, ['staging/Old', 'staging/New']);
    exportCall(dir, path.join(dir, 'staging', 'Old'));
    assert.deepEqual(readStateFile(dir).mcpWrites[0].stagedInside, ['staging/New', 'staging/Old'], 'a folder exported to again moves last, once');
  });
});

test('model folder: a *.SemanticModel folder or its definition/, a tabular folder; never exports/, docs/sources, a reference copy or an exclusion', () => {
  const items = { tabular: ['models/Finance', '.'] };
  const c = { sources: { referenceCopies: ['shared/**'] }, scan: { exclude: ['hardening/tests/fixtures/**'] } };
  for (const rel of ['Sales.SemanticModel', 'Sales.SemanticModel/definition/', 'reports/Sales.SemanticModel/definition', 'models/Finance', 'models/finance', '.']) {
    assert.equal(isModelFolder(rel, items, c), true, rel);
  }
  for (const rel of ['exports/staging/Sales', 'exports/Sales.SemanticModel/definition', 'sub/exports/Sales.SemanticModel', 'docs/sources/Cube.SemanticModel/definition', 'shared/Cube.SemanticModel/definition', 'hardening/tests/fixtures/Sales.SemanticModel', 'Sales.SemanticModel/definition/tables', 'staging/Finance', 'Sales.Report']) {
    assert.equal(isModelFolder(rel, items, c), false, rel);
  }
});

test('third audit: {result: {success: false}} and {status: Pending} neither clear a write nor confirm a connection', () => {
  withRepo({ 'Sales.SemanticModel/definition.pbism': '{}' }, (dir) => {
    commitAll(dir);
    const target = path.join(dir, 'Sales.SemanticModel', 'definition');
    const shapes = [textBlock({ result: { success: false, error: 'E_EXPORT' } }), textBlock({ status: 'Pending', requestId: '42' })];
    run(dir, 'session-start.mjs', { hook_event_name: 'SessionStart', source: 'startup' });
    for (const [i, response] of shapes.entries()) {
      const name = `PBIDesktop-Probe-${i + 1}`;
      post(dir, 'connection_operations', { operation: 'Connect', connectionName: name, dataSource: 'localhost:51234' }, response);
      assert.equal(guard(dir, 'dax_query_operations', DAX(name)).decision, 'ask', `shape ${i + 1} confirms no connection`);
    }
    assert.deepEqual(readStateFile(dir).mcpConnections ?? [], []);
    post(dir, 'connection_operations', { operation: 'Connect', connectionName: LOCAL, dataSource: 'localhost:51234' }, textBlock({ success: true, connectionName: LOCAL }));
    post(dir, 'measure_operations', { operation: 'Create', connectionName: LOCAL, definitions: [{ name: 'Net Margin', expression: '1' }] }, textBlock({ success: true }));
    for (const response of shapes) exportCall(dir, target, { response });
    assert.deepEqual(pendingOf(dir), [[LOCAL, null]], 'both answers leave the write pending');
    assert.equal(stop(dir).decision, 'block');
    exportCall(dir, target);
    assert.deepEqual(pendingOf(dir), [], 'an explicit success into the model folder clears it');
  });
});

// ---------------------------------------------------------------- 3c. third audit: the objects a write named

// F1-40: the gate says what the diff does not declare (it said "does not mention" while a mention counted).
const undeclared = (name) => new RegExp(`The diff under Sales\\.SemanticModel does not declare '${name}', which the writes on PBIDesktop-Sales-51234 changed \\(measure_operations\\)`);

test('third audit: a diff touching only an unrelated object in the same model folder blocks; one declaring the written measure passes', () => {
  const budget = 'table Budget\n\n\tmeasure Plan = 1\n\t\tformatString: 0\n';
  withRepo({ ...SALES_MODEL, 'Sales.SemanticModel/definition/model.tmdl': `${MODEL['models/Finance/model.tmdl']}ref table Budget\n`, 'Sales.SemanticModel/definition/tables/Budget.tmdl': budget }, (dir) => {
    commitAll(dir);
    connectAndWrite(dir);
    addFiles(dir, { 'Sales.SemanticModel/definition/tables/Budget.tmdl': budget.replace('Plan = 1', 'Plan = 2') });
    const held = stop(dir);
    assert.equal(held.decision, 'block', 'another object\'s diff in the same folder');
    assert.match(held.reason, undeclared('Net Margin'));
    addFiles(dir, { 'Sales.SemanticModel/definition/tables/Sales.tmdl': `${TABLE}\n\tmeasure 'Net Margin' = 1\n\t\tformatString: 0\n` });
    assert.ok(!mcpHeld(stop(dir)), 'the diff declares the written measure');
  });
});

// One table file: Revenue, then 'Net Margin' (a description and a five-line expression), then Cost.
const MARGIN = [
  'table Sales', '',
  '\tmeasure Revenue = SUM ( Sales[Amount] )', '\t\tformatString: 0', '',
  '\t/// Margin after all costs',
  "\tmeasure 'Net Margin' =", '\t\t\tVAR r = [Revenue]', '\t\t\tVAR c = [Cost]', '\t\t\tVAR m = r - c', '\t\t\tRETURN', '\t\t\t\tDIVIDE ( m, r )', '\t\tformatString: 0.0%', '',
  '\tmeasure Cost = SUM ( Sales[Amount] )', '\t\tformatString: 0', '',
  '\tcolumn Amount', '\t\tdataType: decimal', '\t\tsourceColumn: Amount', '',
].join('\n');

/** Puts the writes of a session back to pending (no persisted mark, no block count): one repository can then try several diffs. */
function repend(dir) {
  const state = readStateFile(dir);
  for (const w of state.mcpWrites ?? []) {
    delete w.persisted;
    delete w.persistedAt;
  }
  delete state.mcpStopBlocks;
  writeStateFile(dir, state);
}

test('stop gate: only changed lines and the objects that enclose them count, not the context next to them', () => {
  const file = 'Sales.SemanticModel/definition/tables/Sales.tmdl';
  withRepo({ ...SALES_MODEL, [file]: MARGIN }, (dir) => {
    commitAll(dir);
    connectAndWrite(dir);
    post(dir, 'measure_operations', { operation: 'Update', connectionName: LOCAL, definitions: [{ name: 'Net Margin', expression: 'x' }] }, textBlock({ success: true }));
    const check = (label, content, held) => {
      repend(dir); // a diff that persists the writes marks them (F1-38): every case starts from pending writes
      addFiles(dir, { [file]: content });
      const answer = stop(dir);
      assert.equal(mcpHeld(answer), held, `${label}: ${JSON.stringify(answer)}`);
      if (held) assert.match(JSON.stringify(answer), /does not declare 'Net Margin'/, label);
    };
    check('the next measure, within three lines of Net Margin', MARGIN.replace('Cost = SUM ( Sales[Amount] )\n\t\tformatString: 0', 'Cost = SUM ( Sales[Amount] )\n\t\tformatString: #,0'), true);
    check('the measure before it', MARGIN.replace('Revenue = SUM ( Sales[Amount] )\n\t\tformatString: 0', 'Revenue = SUM ( Sales[Amount] )\n\t\tformatString: #,0'), true);
    check('a line deep in its expression', MARGIN.replace('DIVIDE ( m, r )', 'DIVIDE ( m, r, 0 )'), false);
    check('a VAR line of its expression (no declaration, but the measure holds it)', MARGIN.replace('VAR m = r - c', 'VAR m = r - c - 1'), false);
    check('its format string', MARGIN.replace('0.0%', '0.00%'), false);
    check('its description', MARGIN.replace('Margin after all costs', 'Margin after every cost'), false);
    check('its removal', MARGIN.replace(/\t\/\/\/ Margin[^]*?0\.0%\n\n/, ''), false);
    check('an expression line of Cost added after it', MARGIN.replace('Cost = SUM ( Sales[Amount] )', 'Cost =\n\t\t\tSUM ( Sales[Amount] )'), true);
    // F1-40: another measure's definition that only refers to it ([Net Margin]) is not a change of the measure.
    check('a reference to it inside Cost', MARGIN.replace('Cost = SUM ( Sales[Amount] )', 'Cost = SUM ( Sales[Amount] ) + [Net Margin]'), true);
  });
});

test('stop gate: a new untracked file counts with its whole text; writes without names keep the folder rule', () => {
  withRepo(SALES_MODEL, (dir) => {
    commitAll(dir);
    connectAndWrite(dir);
    addFiles(dir, { 'Sales.SemanticModel/definition/tables/Notes.tmdl': 'table Notes\n\n\tcolumn Text\n\t\tdataType: string\n\t\tsourceColumn: Text\n' });
    assert.match(stop(dir).reason, undeclared('Net Margin'));
    addFiles(dir, { 'Sales.SemanticModel/definition/tables/Margin.tmdl': "table Margin\n\n\tmeasure 'Net Margin' = 1\n\t\tformatString: 0\n" });
    assert.ok(!mcpHeld(stop(dir)), 'an untracked file declaring the measure');
  });
  withRepo(SALES_MODEL, (dir) => {
    commitAll(dir);
    run(dir, 'session-start.mjs', { hook_event_name: 'SessionStart', source: 'startup' });
    post(dir, 'connection_operations', { operation: 'Connect', connectionName: LOCAL }, textBlock({ success: true, connectionName: LOCAL }));
    post(dir, 'model_operations', { operation: 'Update', connectionName: LOCAL, definition: { culture: 'en-GB' } }, textBlock({ success: true }));
    assert.equal(stop(dir).decision, 'block');
    addFiles(dir, { 'Sales.SemanticModel/definition/model.tmdl': MODEL['models/Finance/model.tmdl'].replace('en-US', 'en-GB') });
    assert.ok(!mcpHeld(stop(dir)), 'a write without object names: any diff under the model folder');
  });
});

/** Session start, a confirmed connect to PBIDesktop-Sales-<port> and one measure_operations write per name (`op`) on it. */
function connectAndWriteNames(dir, op, ...names) {
  run(dir, 'session-start.mjs', { hook_event_name: 'SessionStart', source: 'startup' });
  post(dir, 'connection_operations', { operation: 'Connect', connectionName: LOCAL, dataSource: 'localhost:51234' }, textBlock({ success: true, connectionName: LOCAL }));
  for (const name of names) post(dir, 'measure_operations', { operation: op, connectionName: LOCAL, definitions: [{ name, tableName: 'Sales', expression: '1' }] }, textBlock({ success: true }));
}
/** The table file Sales.tmdl with the given measures, `[name, expression, formatString]` each. */
const salesTable = (...measures) => ['table Sales', '', ...measures.flatMap(([name, expression, format]) => [`\tmeasure ${name} = ${expression}`, `\t\tformatString: ${format}`, '']), '\tcolumn Amount', '\t\tdataType: decimal', '\t\tsourceColumn: Amount', ''].join('\n');
const SALES_TABLE_FILE = 'Sales.SemanticModel/definition/tables/Sales.tmdl';
const SUM = 'SUM ( Sales[Amount] )';

// F1-40 / E1: a name inside another object's definition, a table that only holds the changed neighbour, and one name of several,
// each persisted a write the gate's own message calls unpersisted ("another object's diff does not persist them").
test('stop gate (F1-40): a reference, a neighbour\'s property or a table line declares nothing; every written object must be declared', () => {
  // Writes of Revenue and Cost on one connection, a diff that adds only the measure Revenue: Cost stays pending, and the reason names it.
  withRepo({ ...SALES_MODEL, [SALES_TABLE_FILE]: salesTable() }, (dir) => {
    commitAll(dir);
    connectAndWriteNames(dir, 'Create', 'Revenue', 'Cost');
    addFiles(dir, { [SALES_TABLE_FILE]: salesTable(['Revenue', SUM, '0']) });
    const held = stop(dir);
    assert.equal(held.decision, 'block');
    assert.match(held.reason, /^\[bi-harness\] Before finishing: 1 MCP write\(s\) on PBIDesktop-Sales-51234 are in the model's memory only/, 'Revenue is persisted and counts no more');
    assert.match(held.reason, /The diff under Sales\.SemanticModel does not declare 'Cost', which the writes on PBIDesktop-Sales-51234 changed \(measure_operations\)/);
    assert.doesNotMatch(held.reason, /does not declare[^.]*'Revenue'/);
    assert.deepEqual(readStateFile(dir).mcpWrites.map((w) => [w.objects[0], w.persisted === true]), [['Revenue', true], ['Cost', false]]);
    addFiles(dir, { [SALES_TABLE_FILE]: salesTable(['Revenue', SUM, '0'], ['Cost', SUM, '0']) });
    assert.equal(stop(dir), null, 'both are declared');
  });
  // A write on Revenue, a diff that adds a measure referring to [Revenue]: the reference persists nothing.
  withRepo({ ...SALES_MODEL, [SALES_TABLE_FILE]: salesTable(['Revenue', SUM, '0']) }, (dir) => {
    commitAll(dir);
    connectAndWriteNames(dir, 'Update', 'Revenue');
    addFiles(dir, { [SALES_TABLE_FILE]: salesTable(['Revenue', SUM, '0'], ['Unrelated', '[Revenue] + 1', '0']) });
    const held = stop(dir);
    assert.equal(held.decision, 'block');
    assert.match(held.reason, /does not declare 'Revenue'/);
    addFiles(dir, { [SALES_TABLE_FILE]: salesTable(['Revenue', 'SUM ( Sales[Amount] ) * 2', '0'], ['Unrelated', '[Revenue] + 1', '0']) });
    assert.equal(stop(dir), null, 'a changed line of the measure itself declares it');
  });
  // A write on the measure Sales, a diff that changes only Cost's format string: the table line `table Sales` and the Sales[Amount] in
  // Cost's definition are not the measure Sales.
  withRepo({ ...SALES_MODEL, [SALES_TABLE_FILE]: salesTable(['Sales', SUM, '0'], ['Cost', SUM, '0']) }, (dir) => {
    commitAll(dir);
    connectAndWriteNames(dir, 'Update', 'Sales');
    addFiles(dir, { [SALES_TABLE_FILE]: salesTable(['Sales', SUM, '0'], ['Cost', SUM, '#,0']) });
    const held = stop(dir);
    assert.equal(held.decision, 'block');
    assert.match(held.reason, /The diff under Sales\.SemanticModel does not declare 'Sales', which the writes on PBIDesktop-Sales-51234 changed/);
    addFiles(dir, { [SALES_TABLE_FILE]: salesTable(['Sales', SUM, '#,0'], ['Cost', SUM, '#,0']) });
    assert.equal(stop(dir), null, 'the measure Sales has a changed line of its own');
  });
  // A write on Revenue, a diff that changes only the format string of 'Revenue YTD' = TOTALYTD ( [Revenue], ... ).
  const ytd = (format) => ["'Revenue YTD'", "TOTALYTD ( [Revenue], 'Date'[Date] )", format];
  withRepo({ ...SALES_MODEL, [SALES_TABLE_FILE]: salesTable(['Revenue', SUM, '0'], ytd('0')) }, (dir) => {
    commitAll(dir);
    connectAndWriteNames(dir, 'Update', 'Revenue');
    addFiles(dir, { [SALES_TABLE_FILE]: salesTable(['Revenue', SUM, '0'], ytd('#,0')) });
    assert.match(stop(dir).reason, /does not declare 'Revenue'/);
  });
});

// F1-40: a changed line stands for the declaration that holds it. A new child declaration also stands for its parent object (a
// role for its new table permission, a hierarchy for its new level), but never for the table around a measure, a column or a partition.
test('stop gate (F1-40): a child declaration persists a write on its parent role or hierarchy, never one on the table around a new measure', () => {
  const role = 'role Admin\n\tmodelPermission: read\n\n\ttablePermission Sales = [Region] = "EU"\n';
  const date = 'table Date\n\n\tcolumn Year\n\t\tdataType: int64\n\t\tsourceColumn: Year\n\n\tcolumn Quarter\n\t\tdataType: int64\n\t\tsourceColumn: Quarter\n\n\thierarchy Calendar\n\t\tlevel Year\n\t\t\tcolumn: Year\n';
  const roleFile = 'Sales.SemanticModel/definition/roles/Admin.tmdl';
  const dateFile = 'Sales.SemanticModel/definition/tables/Date.tmdl';
  const model = `${MODEL['models/Finance/model.tmdl']}ref table Date\nref role Admin\n`;
  const base = { ...SALES_MODEL, 'Sales.SemanticModel/definition/model.tmdl': model, [roleFile]: role, [dateFile]: date, [SALES_TABLE_FILE]: salesTable(['Sales', SUM, '0']) };
  const seeded = (dir, name, tool) => writeStateFile(dir, { mcpWrites: [write(LOCAL, '2026-10-16T10:00:00.000Z', { tool, objects: [name], folder: 'Sales.SemanticModel' })] });
  withRepo(base, (dir) => {
    commitAll(dir);
    seeded(dir, 'Admin', 'security_role_operations');
    addFiles(dir, { [roleFile]: `${role}\ttablePermission Cost = [Region] = "EU"\n` });
    assert.equal(stop(dir), null, 'a new table permission is a change of the role');
  });
  withRepo(base, (dir) => {
    commitAll(dir);
    seeded(dir, 'Calendar', 'user_hierarchy_operations');
    addFiles(dir, { [dateFile]: `${date}\t\tlevel Quarter\n\t\t\tcolumn: Quarter\n` });
    assert.equal(stop(dir), null, 'a new level is a change of the hierarchy');
  });
  // The measure Sales shares its name with its table: a measure added beside it, or a column, is not a change of the measure Sales.
  withRepo(base, (dir) => {
    commitAll(dir);
    seeded(dir, 'Sales', 'measure_operations');
    addFiles(dir, { [SALES_TABLE_FILE]: salesTable(['Sales', SUM, '0'], ['Foo', '1', '0']) });
    const held = stop(dir);
    assert.equal(held.decision, 'block', 'a sibling measure was added');
    assert.match(held.reason, undeclared('Sales'));
    addFiles(dir, { [SALES_TABLE_FILE]: `${salesTable(['Sales', SUM, '0'])}\n\tcolumn Region\n\t\tdataType: string\n\t\tsourceColumn: Region\n` });
    assert.match(JSON.stringify(stop(dir)), /does not declare 'Sales'/, 'and so was a column');
  });
});

// F1-38: only a recorded export cleared a write, so the documented Save as PBIP (a diff that declares the object) let the stop pass
// once, and the gate blocked again, and the resumed session repeated it, as soon as that diff was committed.
test('stop gate: a diff that declares the written measure marks the write persisted: the commit, a resume and the next stop stay quiet (F1-38)', () => {
  withRepo(SALES_MODEL, (dir) => {
    commitAll(dir);
    connectAndWrite(dir);
    addFiles(dir, { [SALES_TABLE_FILE]: `${TABLE}\n\tmeasure 'Net Margin' = 1\n\t\tformatString: 0\n` });
    assert.equal(stop(dir), null, 'the uncommitted diff declares the measure');
    assert.equal(readStateFile(dir).mcpWrites[0].persisted, true);
    assert.ok(!Number.isNaN(Date.parse(readStateFile(dir).mcpWrites[0].persistedAt)));
    commitAll(dir);
    assert.equal(stop(dir), null, 'the diff is committed and gone; the write stays persisted');
    const banner = run(dir, 'session-start.mjs', { hook_event_name: 'SessionStart', source: 'resume' }).hookSpecificOutput.additionalContext;
    assert.doesNotMatch(banner, /MCP write\(s\)/, 'the resume banner is quiet too');
    // A later write is judged on its own.
    post(dir, 'measure_operations', { operation: 'Create', connectionName: LOCAL, definitions: [{ name: 'Gross Margin', tableName: 'Sales', expression: '2' }] }, textBlock({ success: true }));
    const again = stop(dir);
    assert.equal(again.decision, 'block');
    assert.match(again.reason, /^\[bi-harness\] Before finishing: 1 MCP write\(s\) on PBIDesktop-Sales-51234 /);
  });
  // Of two writes, the one the diff declares is marked at once: its diff may be committed before the other is persisted.
  withRepo(SALES_MODEL, (dir) => {
    commitAll(dir);
    connectAndWrite(dir);
    post(dir, 'measure_operations', { operation: 'Create', connectionName: LOCAL, definitions: [{ name: 'Gross Margin', tableName: 'Sales', expression: '2' }] }, textBlock({ success: true }));
    addFiles(dir, { [SALES_TABLE_FILE]: `${TABLE}\n\tmeasure 'Net Margin' = 1\n\t\tformatString: 0\n` });
    const held = stop(dir);
    assert.equal(held.decision, 'block');
    assert.match(held.reason, /^\[bi-harness\] Before finishing: 1 MCP write\(s\) on PBIDesktop-Sales-51234 /, 'only the unpersisted write is counted');
    assert.match(held.reason, undeclared('Gross Margin'));
    assert.doesNotMatch(held.reason, /does not declare[^.]*Net Margin/);
    assert.deepEqual(readStateFile(dir).mcpWrites.map((w) => [w.objects[0], w.persisted === true]), [['Net Margin', true], ['Gross Margin', false]]);
    commitAll(dir); // the Net Margin diff is gone
    addFiles(dir, { [SALES_TABLE_FILE]: `${TABLE}\n\tmeasure 'Net Margin' = 1\n\t\tformatString: 0\n\n\tmeasure 'Gross Margin' = 2\n\t\tformatString: 0\n` });
    assert.equal(stop(dir), null, 'the second diff declares the second write; the first needs none any more');
  });
});

test('markMcpWritesPersisted: the writes of a group that passed, or the writes whose objects were all declared; no other', () => {
  const at = '2026-10-16T10:00:00.000Z';
  const state = { mcpWrites: [write(LOCAL, at, { objects: ['A'] }), write(LOCAL, at, { objects: ['B'] }), write(LOCAL, at), write('TMDL-Other', at, { objects: ['A'] }), write(null, at)] };
  const marked = () => state.mcpWrites.map((w) => w.persisted === true);
  markMcpWritesPersisted(state, [], 'now');
  assert.deepEqual(marked(), [false, false, false, false, false], 'nothing persisted, nothing marked');
  markMcpWritesPersisted(state, [{ mcpServer: SERVER, connection: LOCAL, objects: ['A'], all: false }], 'now');
  assert.deepEqual(marked(), [true, false, false, false, false], 'the group stays open: only the write whose objects were all declared');
  assert.equal(state.mcpWrites[0].persistedAt, 'now');
  markMcpWritesPersisted(state, [{ mcpServer: SERVER, connection: LOCAL, objects: ['B'], all: true }], 'later');
  assert.deepEqual(marked(), [true, true, true, false, false], 'the group passed: every one of its writes, the unnamed one too');
  assert.equal(state.mcpWrites[0].persistedAt, 'now', 'a mark is not made again');
  markMcpWritesPersisted(state, [{ mcpServer: SERVER, connection: null, objects: [], all: true }], 'later');
  assert.deepEqual(marked(), [true, true, true, false, true], 'the writes without a connection are a group of their own');
  assert.doesNotThrow(() => markMcpWritesPersisted({}, [{ mcpServer: SERVER, connection: LOCAL, objects: [], all: true }]));
});

// Audit 2026-10-31, second round (A4): a write recorded at most 20 object names, and a group's list of names stopped at 20
// too. With 21 objects in one request, or 21 one-object writes on one connection, a diff that declared the first 20 passed
// the group, and `all: true` marked all 21 writes persisted: the 21st object was never checked.
const measureNames = (n) => Array.from({ length: n }, (_, i) => `Measure ${String(i + 1).padStart(2, '0')}`);
const declaring = (names) => salesTable(...names.map((name) => [`'${name}'`, '1', '0']));
/** Session start, a confirmed connect and one Create that carries every name. */
function connectAndWriteAll(dir, names) {
  run(dir, 'session-start.mjs', { hook_event_name: 'SessionStart', source: 'startup' });
  post(dir, 'connection_operations', { operation: 'Connect', connectionName: LOCAL, dataSource: 'localhost:51234' }, textBlock({ success: true, connectionName: LOCAL }));
  post(dir, 'measure_operations', { operation: 'Create', connectionName: LOCAL, definitions: names.map((name) => ({ name, tableName: 'Sales', expression: '1' })) }, textBlock({ success: true }));
}

test('audit 2026-10-31 A4: 21 objects in one write, or 21 one-object writes, and a diff of the first 20 leave a write pending', () => {
  const twenty = measureNames(20);
  withRepo({ ...SALES_MODEL, [SALES_TABLE_FILE]: salesTable() }, (dir) => {
    commitAll(dir);
    connectAndWriteAll(dir, measureNames(21));
    addFiles(dir, { [SALES_TABLE_FILE]: declaring(twenty) });
    const held = stop(dir);
    assert.equal(held?.decision, 'block', 'one request: the 21st object was not checked');
    assert.match(held.reason, /1 more not checked/);
    assert.notEqual(readStateFile(dir).mcpWrites[0].persisted, true, 'the write is not marked persisted');
    const banner = run(dir, 'session-start.mjs', { hook_event_name: 'SessionStart', source: 'resume' }).hookSpecificOutput.additionalContext;
    assert.match(banner, /- Earlier in this session: 1 MCP write\(s\) on PBIDesktop-Sales-51234 [^\n]*1 more not checked/, 'the session start says so too');
  });
  withRepo({ ...SALES_MODEL, [SALES_TABLE_FILE]: salesTable() }, (dir) => {
    commitAll(dir);
    connectAndWriteNames(dir, 'Create', ...measureNames(21));
    addFiles(dir, { [SALES_TABLE_FILE]: declaring(twenty) });
    const held = stop(dir);
    assert.equal(held?.decision, 'block', '21 writes: the 21st write is still pending');
    assert.match(held.reason, /^\[bi-harness\] Before finishing: 1 MCP write\(s\) on PBIDesktop-Sales-51234 /);
    assert.match(held.reason, undeclared('Measure 21'));
    assert.deepEqual(readStateFile(dir).mcpWrites.map((w) => w.persisted === true), [...Array(20).fill(true), false], 'the twenty declared writes are persisted, the 21st is not');
  });
});

test('audit 2026-10-31 A4: 20 objects in one write, or 20 one-object writes, all declared by the diff: every write persisted, as before', () => {
  const twenty = measureNames(20);
  withRepo({ ...SALES_MODEL, [SALES_TABLE_FILE]: salesTable() }, (dir) => {
    commitAll(dir);
    connectAndWriteAll(dir, twenty);
    addFiles(dir, { [SALES_TABLE_FILE]: declaring(twenty) });
    assert.equal(stop(dir), null);
    assert.deepEqual(readStateFile(dir).mcpWrites.map((w) => [w.objects.length, w.persisted === true]), [[20, true]]);
  });
  withRepo({ ...SALES_MODEL, [SALES_TABLE_FILE]: salesTable() }, (dir) => {
    commitAll(dir);
    connectAndWriteNames(dir, 'Create', ...twenty);
    addFiles(dir, { [SALES_TABLE_FILE]: declaring(twenty) });
    assert.equal(stop(dir), null);
    assert.ok(readStateFile(dir).mcpWrites.every((w) => w.persisted === true));
  });
});

// F1-40 / E1: it was "named writes need a diff that mentions one name": one of several names, and a mention inside another object, passed.
test('stop gate rule: named writes need a diff that declares every name; without Git the folder rule applies', () => {
  withProject(SALES_MODEL, (dir) => {
    const state = { mcpWrites: [write(LOCAL, '2026-10-16T10:00:00.000Z', { objects: ['Net Margin', 'Cost'], folder: 'Sales.SemanticModel' })] };
    const changed = ['Sales.SemanticModel/definition/tables/Sales.tmdl'];
    const texts = (text) => () => new Map([[changed[0].toLowerCase(), text]]);
    const open = (diffTexts) => unpersistedMcpWrites(state, changed, { root: dir, cfg, diffTexts });
    const neither = open(texts('\tmeasure Revenue = 2\ntable Sales'));
    assert.equal(neither.count, 1);
    assert.deepEqual(neither.groups[0].missing, ['Net Margin', 'Cost']);
    assert.deepEqual(neither.persisted, [], 'nothing of the group is persisted');
    const one = open(texts('\t\tformatString: 0\n\tmeasure Cost = SUM ( Sales[Amount] )'));
    assert.equal(one.count, 1, 'one of the two names is not enough');
    assert.deepEqual(one.groups[0].missing, ['Net Margin']);
    assert.deepEqual(one.persisted.map((p) => [p.objects, p.all]), [[['Cost'], false]], 'Cost is persisted, the group is not');
    const both = open(texts("\tmeasure Cost = 1\n\tmeasure 'Net Margin' = DIVIDE ( [Cost], 2 )"));
    assert.deepEqual([both.count, both.persisted.map((p) => [p.objects, p.all])], [0, [[['Net Margin', 'Cost'], true]]], 'both are declared');
    const refs = open(texts('\tmeasure Other = [Net Margin] + [Cost] + Sales[Cost]'));
    assert.deepEqual([refs.count, refs.groups[0].missing], [1, ['Net Margin', 'Cost']], 'a reference inside another object declares nothing');
    assert.equal(open(() => null).count, 0, 'Git cannot tell: the folder rule alone');
    assert.deepEqual(open(() => null).persisted, [], 'and nothing is marked persisted on that basis');
    // model.bim and definition.pbism are not TMDL: they keep the mention rule.
    const bim = ['Sales.SemanticModel/model.bim'];
    const json = (text) => () => new Map([[bim[0].toLowerCase(), text]]);
    const inBim = (text) => unpersistedMcpWrites(state, bim, { root: dir, cfg, diffTexts: json(text) });
    assert.equal(inBim('"name": "Net Margin", "expression": "SUM([Cost])"').count, 0, 'a mention of each name in a JSON file persists them');
    assert.equal(inBim('"name": "Net Margin"').count, 1, 'Cost is not mentioned');
  });
  for (const [text, hit] of [
    ["\tmeasure 'Net Margin' =", true], ['DIVIDE ( [Net Margin], 2 )', true], ['"name": "Net Margin"', true], ['net margin', true],
    ["\tmeasure 'Net Margin %' =", false], ['[Net Margins]', false], ['NetMargin', false],
  ]) assert.equal(mentionsObject(text, 'Net Margin'), hit, text);
  assert.equal(mentionsObject("\tmeasure 'O''Brien Sales' = 1", "O'Brien Sales"), true, 'a quote doubled inside TMDL quotes');
  assert.equal(mentionsObject('\tmeasure Net = 1', 'Net'), true, 'bare');
  assert.equal(mentionsObject("\tmeasure 'Net Margin' = 1", 'Net'), false, 'part of a quoted name');
});

// F1-40: a TMDL line declares an object when a keyword is followed by its name; a reference inside another object does not.
test('declaresObject: a declaration line of any keyword, quoted or bare, without case; never a reference or an expression word', () => {
  for (const [text, name, declares] of [
    ["\tmeasure 'Net Margin' =", 'Net Margin', true], ['\tmeasure Revenue = SUM ( Sales[Amount] )', 'Revenue', true], ['\tmeasure Revenue=1', 'Revenue', true],
    ['\tcolumn Amount', 'amount', true], ['table Sales', 'Sales', true], ['ref table Sales', 'Sales', true], ['\tpartition Sales = m', 'Sales', true],
    ['\t\tcalculationItem YTD =', 'YTD', true], ['\tlevel Year', 'Year', true], ['  measure Revenue = 1', 'Revenue', true],
    ["\tmeasure 'O''Brien Sales' = 1", "O'Brien Sales", true], ['\tmeasure Net Margin = 1', 'Net Margin', true],
    ['\tmeasure Unrelated = [Revenue] + 1', 'Revenue', false], ['\tmeasure Cost = SUM ( Sales[Amount] )', 'Sales', false],
    ['\t\tformatString: Revenue', 'Revenue', false], ['\tmeasure Revenue: 1', 'Revenue', false], ["\tmeasure 'Net Margin %' =", 'Net Margin', false],
    ['\tmeasure NetMargin = 1', 'Net Margin', false], ['measure Revenue', 'Revenu', false], ['"name": "Net Margin"', 'Net Margin', false],
    ['\t\t\tVAR Total = 1', 'Total', false], ['\t\t\tRETURN Total', 'Total', false], ['in\nSales', 'Sales', false], ['', 'Sales', false],
  ]) assert.equal(declaresObject(text, name), declares, `${JSON.stringify(text)} / ${name}`);
  assert.equal(declaresObject('anything', ''), false, 'no name, no declaration');
  assert.equal(declaresObject('\tmeasure Revenue = 1\n\tmeasure Cost = 2', 'Cost'), true, 'any line of the text');
});

test('end to end: a failed connect, two servers, a write, a disconnect and two exports through the hooks', () => {
  withRepo({ 'Sales.SemanticModel/definition.pbism': '{}' }, (dir) => {
    commitAll(dir);
    const connect = (response, server = SERVER) => post(dir, 'connection_operations', { operation: 'Connect', connectionName: LOCAL, dataSource: 'localhost:51234' }, response, server);
    // No session start ran: no state file, still no confirmed connection.
    assert.equal(guard(dir, 'dax_query_operations', DAX(LOCAL)).decision, 'ask');
    connect(`Connection failed: ${LOCAL} did not answer`);
    assert.equal(guard(dir, 'dax_query_operations', DAX(LOCAL)).decision, 'ask', 'a failed connect confirms nothing');
    connect(textBlock({ success: true, connectionName: LOCAL }), OTHER_SERVER);
    assert.equal(guard(dir, 'dax_query_operations', DAX(LOCAL)).decision, 'ask', 'confirmed on the other server only');
    connect(`Connected to ${LOCAL}.`);
    assert.equal(guard(dir, 'dax_query_operations', DAX(LOCAL)).decision, 'allow');
    assert.equal(guard(dir, 'dax_query_operations', DAX()).decision, 'allow', 'one live connection on this server');
    post(dir, 'measure_operations', { operation: 'Create', definitions: [{ name: 'Net' }] }, textBlock({ success: true }));
    assert.deepEqual(pendingOf(dir), [[LOCAL, null]], 'the unnamed write went on the one live connection');
    assert.equal(stop(dir).decision, 'block');
    post(dir, 'connection_operations', { operation: 'Disconnect', connectionName: LOCAL }, textBlock({ success: true }));
    assert.match(stop(dir).systemMessage, DISCONNECTED, 'blocked once; the warning says a disconnect is not a persist');
    const staging = outsideFolder(dir, 'Sales');
    exportCall(dir, staging);
    assert.ok(stop(dir).systemMessage.includes(stagingNote(staging, 'Sales.SemanticModel')));
    exportCall(dir, path.join(dir, 'Sales.SemanticModel', 'definition'));
    assert.deepEqual(pendingOf(dir), []);
    assert.equal(stop(dir), null, 'the export into the model\'s folder persisted the write');
  });
});

// ---------------------------------------------------------------- 4. the session start banner

test('session start: a resumed session with unpersisted MCP writes names their count and connection in one line', () => {
  withProject({}, (dir) => {
    const banner = () => run(dir, 'session-start.mjs', { hook_event_name: 'SessionStart', source: 'resume' }).hookSpecificOutput.additionalContext;
    assert.doesNotMatch(banner(), /MCP write\(s\)/, 'nothing pending, no line');
    writeStateFile(dir, { ...readStateFile(dir), mcpWrites: [write(LOCAL, '2026-10-16T10:00:00.000Z'), write('TMDL-Finance', '2026-10-16T10:05:00.000Z')] });
    const lines = banner().split('\n').filter((l) => /MCP write\(s\)/.test(l));
    assert.equal(lines.length, 1);
    assert.match(lines[0], /^- Earlier in this session: 2 MCP write\(s\) on PBIDesktop-Sales-51234, TMDL-Finance are in the model's memory only; persist them/);
    assert.equal(readStateFile(dir).mcpWrites.length, 2, 'the session start keeps the writes');
    const staging = outsideFolder(dir, 'Finance');
    writeStateFile(dir, { ...readStateFile(dir), mcpWrites: [write('TMDL-Finance', '2026-10-16T10:05:00.000Z', { exportedTo: staging })] });
    const exported = banner().split('\n').filter((l) => /MCP write\(s\)/.test(l));
    assert.equal(exported.length, 1, 'the notes stay on the same line');
    assert.ok(exported[0].includes(`TMDL-Finance was exported to ${staging}, which is not the project's model folder: merge the export into the project's model folder and show the diff`), exported[0]);
  });
});
