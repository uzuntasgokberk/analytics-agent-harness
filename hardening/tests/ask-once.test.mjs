// One prompt per call under GitHub Copilot (hooks/lib/ask-once.mjs), the functions called directly. Copilot CLI 1.0.103
// runs the PreToolUse guard once per registration (the VS Code file, the CLI file, the Claude registration), one after
// another, and each `ask` was a prompt of its own (probed 2026-10-28). The payloads below are the raw ones the three
// copies received in those runs: the same session, instant and arguments, another tool name and dialect per copy.
import { after, test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

// The state files live under the project of the hooks: a temporary one, set before the modules read it.
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-ask-once-'));
process.env.CLAUDE_PROJECT_DIR = dir;
delete process.env.BI_HARNESS_HOST;
// Copilot CLI exports COPILOT_CLI=1 to every hook copy: set here, never inherited (the gate has its own test below).
process.env.COPILOT_CLI = '1';
const { ASK_ONCE_KEY, ASK_ONCE_MAX_RECORDS, askKey, askOnce, copilotCliSignal, copyIdentity, markAsksEmitted } = await import('../hooks/lib/ask-once.mjs');
const { fromCopilotCli, toClaudeCalls } = await import('../hooks/lib/host-vscode.mjs');
const { loadConfig } = await import('../hooks/lib/common.mjs');
after(() => fs.rmSync(dir, { recursive: true, force: true }));

const stateFile = (sid) => path.join(dir, '.claude', 'logs', '.state', `${sid}.json`);
const stateOf = (sid) => (fs.existsSync(stateFile(sid)) ? JSON.parse(fs.readFileSync(stateFile(sid), 'utf8')) : {});
const securityRows = () => {
  const file = path.join(dir, '.claude', 'logs', 'security-events.jsonl');
  return fs.existsSync(file) ? fs.readFileSync(file, 'utf8').trim().split('\n').map((l) => JSON.parse(l)) : [];
};

/** As runHook does for a Copilot payload: fromCopilotCli, then the Claude-shaped calls; returns the untranslated payload too. */
function translate(raw) {
  const input = fromCopilotCli(raw);
  return { input, calls: toClaudeCalls(input, { cfg: loadConfig(), projectDir: dir, event: 'PreToolUse' }) };
}
const keysOf = (raw) => {
  const { input, calls } = translate(raw);
  return calls.map((c) => askKey(c, input));
};

// evidence.md step 4, run 1: `git status`, one payload per copy (cwd shortened as captured).
const SID = '4368943a-88c1-4093-b96c-2e58995246c3';
const STATUS = {
  vscode: { hook_event_name: 'PreToolUse', session_id: SID, timestamp: '2026-10-28T19:31:57.712Z', cwd: 'C:\\...\\install', tool_name: 'Bash', tool_input: { command: 'git status', description: 'Run git status' } },
  cli: { sessionId: SID, timestamp: 1793215917712, cwd: 'C:\\...\\install', toolName: 'powershell', toolArgs: { command: 'git status', description: 'Run git status' } },
  claude: { hook_event_name: 'PreToolUse', session_id: SID, timestamp: '2026-10-28T19:31:57.712Z', cwd: 'C:\\...\\install', tool_name: 'Bash', tool_input: { command: 'git status', description: 'Run git status' } },
};
// evidence.md step 3: `git push origin feature/x`, the CLI's arguments as a JSON string (GitHub's documented shape).
const PUSH_SID = '5e55a0b1-0000-4000-8000-000000000001';
const PUSH = {
  cli: { sessionId: PUSH_SID, timestamp: 1793181600123, cwd: 'C:/.../install', toolName: 'bash', toolArgs: '{"command":"git push origin feature/x","description":"probe"}' },
  vscode: { hook_event_name: 'PreToolUse', session_id: PUSH_SID, timestamp: '2026-10-28T10:00:00.123Z', cwd: 'C:/.../install', tool_name: 'Bash', tool_input: { command: 'git push origin feature/x', description: 'probe' } },
  claude: { hook_event_name: 'PreToolUse', session_id: PUSH_SID, timestamp: '2026-10-28T10:00:00.123Z', cwd: 'C:/.../install', tool_name: 'Bash', tool_input: { command: 'git push origin feature/x', description: 'probe' } },
};
// evidence.md step 4, run 4: a file tool, `view` in the CLI file and `Read` with the CLI's `path` in the other two.
const READ = {
  vscode: { hook_event_name: 'PreToolUse', session_id: SID, timestamp: '2026-10-28T19:37:24.439Z', cwd: 'C:\\...\\install', tool_name: 'Read', tool_input: { path: 'README.md' } },
  cli: { sessionId: SID, timestamp: 1793216244439, cwd: 'C:\\...\\install', toolName: 'view', toolArgs: { path: 'README.md' } },
  claude: { hook_event_name: 'PreToolUse', session_id: SID, timestamp: '2026-10-28T19:37:24.439Z', cwd: 'C:\\...\\install', tool_name: 'Read', tool_input: { path: 'README.md' } },
};

test('ask-once: one call has one key in the three dialects (toolArgs as an object and as a JSON string)', () => {
  for (const [what, copies] of [['git status', STATUS], ['git push', PUSH], ['view README.md', READ]]) {
    const keys = Object.values(copies).map(keysOf);
    for (const k of keys) assert.equal(k.length, 1, what);
    assert.ok(keys[0][0], `${what}: a key`);
    assert.equal(new Set(keys.map((k) => k[0])).size, 1, `${what}: ${JSON.stringify(keys)}`);
  }
  const asString = { ...STATUS.cli, toolArgs: JSON.stringify(STATUS.cli.toolArgs) };
  assert.equal(keysOf(asString)[0], keysOf(STATUS.vscode)[0], 'toolArgs as a JSON string');
  const reordered = { ...STATUS.claude, tool_input: { description: 'Run git status', command: 'git status' } };
  assert.equal(keysOf(reordered)[0], keysOf(STATUS.claude)[0], 'the order of the keys does not matter');
});

test('ask-once: another instant, session, argument or tool is another key; no instant or unreadable arguments is none', () => {
  const base = keysOf(STATUS.vscode)[0];
  assert.notEqual(keysOf({ ...STATUS.vscode, timestamp: '2026-10-28T19:31:57.713Z' })[0], base, 'instant');
  assert.notEqual(keysOf({ ...STATUS.cli, timestamp: 1793215917713 })[0], base, 'instant (epoch ms)');
  assert.notEqual(keysOf({ ...STATUS.vscode, session_id: 'other' })[0], base, 'session');
  assert.notEqual(keysOf({ ...STATUS.vscode, tool_input: { command: 'git status -s', description: 'Run git status' } })[0], base, 'command');
  assert.notEqual(keysOf({ ...STATUS.vscode, tool_input: { command: 'git status', description: 'another' } })[0], base, 'description');
  assert.notEqual(keysOf(READ.vscode)[0], keysOf({ ...READ.vscode, tool_input: { path: 'docs/a.md' } })[0], 'target');
  // Claude Code sends no timestamp (Claude Code 2.1.302): no key, so nothing changes there.
  const claudeCode = { hook_event_name: 'PreToolUse', session_id: SID, transcript_path: 't', tool_name: 'Bash', tool_input: { command: 'git status' }, tool_use_id: 'toolu_1' };
  assert.equal(askKey(claudeCode), null);
  assert.equal(askOnce(claudeCode, 'r', claudeCode, { identity: 'claude' }), null);
  assert.deepEqual(keysOf({ ...STATUS.cli, toolArgs: 'not json' }), [null], 'unreadable arguments');
  assert.equal(askKey({ ...STATUS.vscode, timestamp: 'not a time' }), null);
});

test('ask-once: the first copy asks, the later copies of the same ask are repeats, logged with their copy', () => {
  for (const order of [['vscode', 'copilot-cli', 'claude'], ['copilot-cli', 'vscode', 'claude'], ['claude', 'copilot-cli', 'vscode']]) {
    const sid = `order-${order.join('-')}`;
    const raw = { vscode: PUSH.vscode, 'copilot-cli': PUSH.cli, claude: PUSH.claude };
    const before = securityRows().length;
    const decisions = order.map((who) => {
      const { input, calls } = translate({ ...raw[who], ...(raw[who].sessionId ? { sessionId: sid } : { session_id: sid }) });
      const once = askOnce(calls[0], 'git push publishes commits', input, { identity: who });
      markAsksEmitted();
      return once;
    });
    assert.deepEqual(decisions.map((d) => d.decision), ['ask', 'repeat', 'repeat'], order.join(','));
    assert.deepEqual(decisions.map((d) => d.copy), order);
    const rows = securityRows().slice(before);
    assert.deepEqual(rows.map((r) => [r.decision, r.copy, r.tool]), [['repeat', order[1], 'Bash'], ['repeat', order[2], 'Bash']]);
    const [rec] = Object.values(stateOf(sid)[ASK_ONCE_KEY]);
    assert.deepEqual(rec.copies[order[0]], { n: 1, e: 1 }, 'the ask was marked as written');
    assert.deepEqual(rec.copies[order[1]], { n: 1, e: 0 }, 'a repeat is handled, not asked');
  }
});

test('ask-once: counting per copy keeps two identical calls of one message apart; another reason asks again', () => {
  const sid = 'twice-1';
  const call = { ...STATUS.claude, session_id: sid };
  const ask = (who, reason = 'r1') => {
    const once = askOnce(call, reason, call, { identity: who });
    markAsksEmitted();
    return once.decision;
  };
  assert.deepEqual([ask('vscode'), ask('vscode')], ['ask', 'ask'], 'the same copy twice: two calls, two asks');
  assert.deepEqual([ask('copilot-cli'), ask('copilot-cli'), ask('claude'), ask('claude')], ['repeat', 'repeat', 'repeat', 'repeat']);
  assert.equal(ask('copilot-cli'), 'ask', 'a third copy of the CLI file has no ask left to match');
  assert.equal(ask('claude', 'r2'), 'ask', 'the same call with another reason is another question');
});

test('ask-once: an ask never marked as written (the first copy killed by the host\'s timeout) does not silence the next copy', () => {
  const sid = 'killed-1';
  const call = { ...STATUS.vscode, session_id: sid };
  assert.equal(askOnce(call, 'r', call, { identity: 'vscode' }).decision, 'ask');
  // No markAsksEmitted: the process died before its output was written. The pending claim is dropped with it.
  const [rec] = Object.values(stateOf(sid)[ASK_ONCE_KEY]);
  assert.deepEqual(rec.copies.vscode, { n: 1, e: 0 });
  const record = JSON.stringify(stateOf(sid));
  const second = askOnce(call, 'r', call, { identity: 'copilot-cli' });
  assert.equal(second.decision, 'ask');
  markAsksEmitted();
  assert.notEqual(JSON.stringify(stateOf(sid)), record);
  assert.equal(askOnce(call, 'r', call, { identity: 'claude' }).decision, 'repeat', 'the copy that did ask counts');
});

test('ask-once: records older than an hour are dropped and at most the newest ASK_ONCE_MAX_RECORDS are kept', () => {
  const sid = 'expiry-1';
  const call = { ...STATUS.vscode, session_id: sid };
  const t0 = Date.now();
  askOnce(call, 'r', call, { identity: 'vscode', now: t0 });
  markAsksEmitted();
  assert.equal(askOnce(call, 'r', call, { identity: 'claude', now: t0 + 3600000 }).decision, 'repeat', 'an hour old: still there');
  assert.equal(askOnce(call, 'r', call, { identity: 'copilot-cli', now: t0 + 2 * 3600000 + 1 }).decision, 'ask', 'older: dropped');

  const many = 'expiry-2';
  for (let i = 0; i < ASK_ONCE_MAX_RECORDS + 5; i += 1) {
    const c = { ...STATUS.vscode, session_id: many, tool_input: { command: `git log -${i}` } };
    askOnce(c, 'r', c, { identity: 'vscode', now: t0 + i });
  }
  markAsksEmitted();
  const book = stateOf(many)[ASK_ONCE_KEY];
  assert.equal(Object.keys(book).length, ASK_ONCE_MAX_RECORDS);
  assert.equal(Math.min(...Object.values(book).map((r) => r.at)), t0 + 5, 'the oldest went first');
});

test('ask-once: a state that is missing, garbage or cannot be written means no earlier ask', () => {
  const run = (sid, damage) => {
    const call = { ...STATUS.vscode, session_id: sid };
    askOnce(call, 'r', call, { identity: 'vscode' });
    markAsksEmitted();
    damage(sid);
    const once = askOnce(call, 'r', call, { identity: 'copilot-cli' });
    markAsksEmitted();
    return once.decision;
  };
  assert.equal(run('missing-1', (sid) => fs.rmSync(stateFile(sid))), 'ask', 'missing');
  assert.equal(run('garbage-1', (sid) => fs.writeFileSync(stateFile(sid), '{"askCopies": {')), 'ask', 'garbage JSON');
  assert.equal(run('garbage-2', (sid) => fs.writeFileSync(stateFile(sid), JSON.stringify({ [ASK_ONCE_KEY]: 'x' }))), 'ask', 'records that are no object');
  assert.equal(run('garbage-3', (sid) => {
    const s = stateOf(sid);
    for (const rec of Object.values(s[ASK_ONCE_KEY])) rec.copies.vscode = { n: 'one', e: true };
    fs.writeFileSync(stateFile(sid), JSON.stringify(s));
  }), 'ask', 'counts that are no numbers');
  assert.equal(run('folder-1', (sid) => {
    fs.rmSync(stateFile(sid));
    fs.mkdirSync(stateFile(sid));
  }), 'ask', 'the state path is a folder: nothing can be read or written');
  assert.ok(fs.statSync(stateFile('folder-1')).isDirectory());
});

test('ask-once: a state that can be read but not written is a lost count: the copy asks instead of repeating', (t) => {
  if (typeof process.getuid === 'function' && process.getuid() === 0) return t.skip('root writes read-only files');
  const sid = 'readonly-1';
  const call = { ...STATUS.vscode, session_id: sid };
  askOnce(call, 'r', call, { identity: 'vscode' });
  markAsksEmitted();
  const file = stateFile(sid);
  const before = fs.readFileSync(file, 'utf8');
  // Windows refuses to replace or write a read-only file; elsewhere the folder must refuse the temporary file too.
  fs.chmodSync(file, 0o444);
  fs.chmodSync(path.dirname(file), 0o555);
  try {
    assert.equal(askOnce(call, 'r', call, { identity: 'copilot-cli' }).decision, 'ask', 'the record says repeat, but the count did not land');
    markAsksEmitted();
    assert.equal(fs.readFileSync(file, 'utf8'), before, 'nothing was written');
  } finally {
    fs.chmodSync(path.dirname(file), 0o755);
    fs.chmodSync(file, 0o644);
  }
});

test('ask-once: a state folder that cannot be created means an ask', () => {
  const sid = 'nofolder-1';
  const call = { ...STATUS.vscode, session_id: sid };
  askOnce(call, 'r', call, { identity: 'vscode' });
  markAsksEmitted();
  const stateDir = path.dirname(stateFile(sid));
  const moved = `${stateDir}.moved`;
  fs.renameSync(stateDir, moved);
  fs.writeFileSync(stateDir, 'a file where the folder was');
  try {
    assert.equal(askOnce(call, 'r', call, { identity: 'copilot-cli' }).decision, 'ask');
    markAsksEmitted();
  } finally {
    fs.rmSync(stateDir, { force: true });
    fs.renameSync(moved, stateDir);
  }
});

test('ask-once: the signals of Copilot CLI (copilotCliSignal); without one every copy asks as before and nothing is recorded', () => {
  for (const value of ['1', 'true', ' TRUE ', 'yes', 'on']) assert.equal(copilotCliSignal({ COPILOT_CLI: value }), 'COPILOT_CLI', value);
  assert.equal(copilotCliSignal({ COPILOT_CLI: '1', BI_HARNESS_HOST: 'vscode' }), 'COPILOT_CLI', 'every copy under the CLI');
  assert.equal(copilotCliSignal({ BI_HARNESS_HOST: 'copilot-cli' }), 'BI_HARNESS_HOST', 'the CLI hook file');
  assert.equal(copilotCliSignal({ BI_HARNESS_HOST: ' copilot-cli ' }), 'BI_HARNESS_HOST');
  for (const env of [{}, { COPILOT_CLI: '' }, { COPILOT_CLI: '0' }, { COPILOT_CLI: 'false' }, { COPILOT_CLI: 'no' }, { COPILOT_CLI: 'off' },
    { COPILOT_CLI: '2' }, { COPILOT_CLI: 'copilot' }, { BI_HARNESS_HOST: 'vscode' }, { BI_HARNESS_HOST: 'Copilot-CLI' }, { BI_HARNESS_HOST: 'copilot' }]) {
    assert.equal(copilotCliSignal(env), null, JSON.stringify(env));
  }
  const sid = 'gate-1';
  const call = { ...STATUS.vscode, session_id: sid };
  const before = securityRows().length;
  for (const identity of ['vscode', 'claude']) {
    assert.equal(askOnce(call, 'r', call, { identity, env: {} }), null, `${identity}: no signal`);
    assert.equal(askOnce(call, 'r', call, { identity, env: { COPILOT_CLI: '0' } }), null, `${identity}: COPILOT_CLI=0`);
  }
  markAsksEmitted();
  assert.equal(fs.existsSync(stateFile(sid)), false, 'no record');
  assert.equal(securityRows().length, before, 'no repeat row');

  // A host that sets no COPILOT_CLI (the Copilot app, if it does not; VS Code): only the CLI-file copy carries a signal,
  // records its asks, and still asks every time, because no copy with a signal asked before it.
  const app = 'gate-2';
  const appCall = { ...STATUS.vscode, session_id: app };
  const envs = { vscode: { BI_HARNESS_HOST: 'vscode' }, 'copilot-cli': { BI_HARNESS_HOST: 'copilot-cli' }, claude: {} };
  for (const round of [1, 2]) {
    const decisions = ['copilot-cli', 'vscode', 'claude', 'copilot-cli'].map((identity) => {
      const once = askOnce(appCall, 'r', appCall, { identity, env: envs[identity] });
      markAsksEmitted();
      return once?.decision ?? 'ask (no signal)';
    });
    assert.deepEqual(decisions, ['ask', 'ask (no signal)', 'ask (no signal)', 'ask'], `round ${round}`);
  }

  // The same calls under the CLI: one ask, two repeats.
  const cli = ['vscode', 'copilot-cli', 'claude'].map((identity) => {
    const once = askOnce(call, 'r', call, { identity, env: { COPILOT_CLI: '1', ...envs[identity] } });
    markAsksEmitted();
    return once.decision;
  });
  assert.deepEqual(cli, ['ask', 'repeat', 'repeat']);
});

test('ask-once: the copy identity is BI_HARNESS_HOST, or claude for the Claude registration', () => {
  assert.equal(copyIdentity({}), 'claude');
  assert.equal(copyIdentity({ BI_HARNESS_HOST: '' }), 'claude');
  assert.equal(copyIdentity({ BI_HARNESS_HOST: 'vscode' }), 'vscode');
  assert.equal(copyIdentity({ BI_HARNESS_HOST: ' copilot-cli ' }), 'copilot-cli');
  assert.equal(copyIdentity(), 'claude', 'this process has no host variable');
});
