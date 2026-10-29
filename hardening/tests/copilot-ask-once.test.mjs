// One prompt per call under GitHub Copilot: real hook processes, a temporary Git repository. Copilot CLI 1.0.103 runs the
// PreToolUse guard once per registration it finds (the VS Code file with BI_HARNESS_HOST=vscode, its own file with
// copilot-cli, the Claude registration with none), one after another, and each `ask` was a prompt of its own; a deny or a
// refused prompt ends the call, an approval or no output lets the next copy run (probed 2026-10-28). The payloads are the
// raw ones the copies received (the snake_case payload of the two PascalCase registrations, the CLI's camelCase one with
// `toolArgs` as an object, as 1.0.103 sent it, and as a JSON string, GitHub's documented shape): the first copy of an ask
// asks, the later copies print nothing and are logged as `repeat`; deny and allow never change; Claude Code is untouched.
// The CLI exports COPILOT_CLI=1 to every copy: each run below sets it (or leaves it out) explicitly, never inherited.
// Without it (VS Code's Copilot harness, not probed) every copy asks as before.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const hooks = path.join(here, '..', 'hooks');
const GIT_VARS = new Set(['GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE', 'GIT_OBJECT_DIRECTORY', 'GIT_ALTERNATE_OBJECT_DIRECTORIES', 'GIT_COMMON_DIR', 'GIT_PREFIX']);
/** The environment without the host variable, the git variables and the test runner's context, plus `extra`. */
function envWith(extra = {}) {
  const drop = (k) => ['BI_HARNESS_HOST', 'COPILOT_CLI', 'NODE_TEST_CONTEXT'].includes(k.toUpperCase()) || GIT_VARS.has(k.toUpperCase());
  return { ...Object.fromEntries(Object.entries(process.env).filter(([k]) => !drop(k))), ...extra };
}

/** A temporary Git repository with a .env file, removed afterwards. */
function withRepo(fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-ask-once-'));
  try {
    spawnSync('git', ['init', '-q'], { cwd: dir, env: envWith(), encoding: 'utf8' });
    fs.appendFileSync(path.join(dir, '.git', 'info', 'exclude'), '\n.claude/logs/\n');
    fs.writeFileSync(path.join(dir, '.env'), 'X=1\n');
    return fn(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

/**
 * Runs one copy of a hook: `copy` is the registration (vscode, copilot-cli, or claude: no host variable); `copilotCli`
 * sets COPILOT_CLI=1 as Copilot CLI does (default), false leaves it out.
 */
function runCopy(script, dir, copy, payload, { copilotCli = true } = {}) {
  const r = spawnSync(process.execPath, [path.join(hooks, script)], {
    input: JSON.stringify(payload),
    env: envWith({ CLAUDE_PROJECT_DIR: dir, ...(copy === 'claude' ? {} : { BI_HARNESS_HOST: copy }), ...(copilotCli ? { COPILOT_CLI: '1' } : {}) }),
    encoding: 'utf8',
  });
  assert.equal(r.status, 0, `${script} ${copy}: ${r.stderr}`);
  assert.doesNotMatch(r.stderr, /hook error/, r.stderr);
  return r.stdout;
}
/** The PreToolUse guard's answer in one copy: the decision (flat for the CLI file, nested otherwise) and the raw stdout. */
function guard(dir, copy, payload, options) {
  const stdout = runCopy('pre-tool-use.mjs', dir, copy, payload, options);
  const out = stdout.trim() ? JSON.parse(stdout) : null;
  const d = out?.hookSpecificOutput ?? out;
  return { decision: d?.permissionDecision ?? null, reason: d?.permissionDecisionReason ?? '', stdout };
}
const rows = (dir, file) => {
  const p = path.join(dir, '.claude', 'logs', file);
  return fs.existsSync(p) ? fs.readFileSync(p, 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l)) : [];
};
const stateFile = (dir, sid) => path.join(dir, '.claude', 'logs', '.state', `${sid}.json`);
const stateOf = (dir, sid) => (fs.existsSync(stateFile(dir, sid)) ? JSON.parse(fs.readFileSync(stateFile(dir, sid), 'utf8')) : {});

// The instant of evidence.md step 3 (epoch milliseconds in the CLI's payload, ISO text in the others).
const T = 1793181600123;
/** One call's payload per copy, as the three registrations received it (evidence.md, steps 3 and 4). */
function payloads(dir, sid, args, { cliTool = 'powershell', snakeTool = 'Bash', cliArgs = 'object', ms = T } = {}) {
  const snake = { hook_event_name: 'PreToolUse', session_id: sid, timestamp: new Date(ms).toISOString(), cwd: dir, tool_name: snakeTool, tool_input: args };
  return {
    vscode: snake,
    'copilot-cli': { sessionId: sid, timestamp: ms, cwd: dir, toolName: cliTool, toolArgs: cliArgs === 'string' ? JSON.stringify(args) : args },
    claude: snake,
  };
}
const PUSH = { command: 'git push origin feature/x', description: 'probe' };
const ORDERS = [['vscode', 'copilot-cli', 'claude'], ['copilot-cli', 'vscode', 'claude'], ['claude', 'copilot-cli', 'vscode'], ['claude', 'vscode', 'copilot-cli']];

test('Copilot: of the three copies of one ask, exactly one asks; the others print nothing and are logged as repeat, in every order', () => {
  withRepo((dir) => {
    for (const cliArgs of ['object', 'string']) {
      for (const order of ORDERS) {
        const sid = `order-${cliArgs}-${order.join('-')}`;
        const call = payloads(dir, sid, PUSH, { cliTool: cliArgs === 'string' ? 'bash' : 'powershell', cliArgs });
        const before = rows(dir, 'security-events.jsonl').length;
        const answers = order.map((copy) => guard(dir, copy, call[copy]));
        const label = `${cliArgs}: ${order.join(', ')}`;
        assert.equal(answers[0].decision, 'ask', label);
        assert.match(answers[0].reason, /git push publishes commits to the remote/, label);
        assert.deepEqual(answers.slice(1).map((a) => a.stdout), ['', ''], `${label}: the later copies print nothing, never an allow`);
        const events = rows(dir, 'security-events.jsonl').slice(before);
        assert.deepEqual(events.map((e) => [e.event, e.decision, e.copy, e.tool, e.session]), [
          ['pre-tool-use', 'ask', order[0], 'Bash', sid.slice(0, 8)],
          ['pre-tool-use', 'repeat', order[1], 'Bash', sid.slice(0, 8)],
          ['pre-tool-use', 'repeat', order[2], 'Bash', sid.slice(0, 8)],
        ], label);
        assert.equal(events[1].reason, events[0].reason, 'the repeat names the ask it repeats');
        const records = Object.values(stateOf(dir, sid).askCopies ?? {});
        assert.equal(records.length, 1, label);
        assert.deepEqual(records[0].copies[order[0]], { n: 1, e: 1 }, `${label}: the ask was marked once its output was written`);
      }
    }
    // The CLI file's answer stays flat, the others nested, as before.
    const sid = 'shape-1';
    const call = payloads(dir, sid, PUSH);
    assert.equal(JSON.parse(guard(dir, 'copilot-cli', call['copilot-cli']).stdout).permissionDecision, 'ask');
    assert.equal(JSON.parse(guard(dir, 'vscode', { ...call.vscode, session_id: 'shape-2' }).stdout).hookSpecificOutput.permissionDecision, 'ask');
  });
});

test('Copilot: deny and allow are never changed: every copy gives its own, and nothing is recorded or logged as repeat', () => {
  withRepo((dir) => {
    for (const [what, args, decision] of [['cat .env', { command: 'cat .env', description: 'probe' }, 'deny'], ['git status', { command: 'git status', description: 'Run git status' }, 'allow']]) {
      const sid = `same-${decision}`;
      const call = payloads(dir, sid, args);
      const before = rows(dir, 'security-events.jsonl').length;
      for (const copy of ['vscode', 'copilot-cli', 'claude']) assert.equal(guard(dir, copy, call[copy]).decision, decision, `${what}: ${copy}`);
      const events = rows(dir, 'security-events.jsonl').slice(before);
      assert.deepEqual(events.map((e) => e.decision), decision === 'deny' ? ['deny', 'deny', 'deny'] : [], what);
      assert.equal(stateOf(dir, sid).askCopies, undefined, `${what}: no ask, no record`);
    }
  });
});

test('Claude Code (no timestamp) is unchanged: the same ask three times is three asks, with no copy and no record', () => {
  withRepo((dir) => {
    const sid = 'claude-code-1';
    const payload = { hook_event_name: 'PreToolUse', session_id: sid, transcript_path: 't', cwd: dir, permission_mode: 'default', tool_name: 'Bash', tool_input: PUSH, tool_use_id: 'toolu_01' };
    // Claude Code sets no COPILOT_CLI; with it set, the missing timestamp alone keeps the dedupe off.
    for (const copilotCli of [false, true]) {
      const before = rows(dir, 'security-events.jsonl').length;
      assert.deepEqual([1, 2, 3].map(() => guard(dir, 'claude', payload, { copilotCli }).decision), ['ask', 'ask', 'ask'], `COPILOT_CLI ${copilotCli}`);
      const events = rows(dir, 'security-events.jsonl').slice(before);
      assert.deepEqual(events.map((e) => [e.decision, e.copy]), [['ask', undefined], ['ask', undefined], ['ask', undefined]]);
    }
    assert.equal(stateOf(dir, sid).askCopies, undefined);
  });
});

test('Without COPILOT_CLI (the Copilot app or VS Code, not probed) every copy asks as before, in any order', () => {
  withRepo((dir) => {
    // The reviewer's order (review.md, e6): VS Code runs the CLI file with its own snake_case payload, and that copy
    // answers in the CLI's flat shape, which VS Code may not read. The VS Code and Claude copies must still ask.
    const snake = payloads(dir, 'vs-flat-1', PUSH).vscode;
    const flat = guard(dir, 'copilot-cli', snake, { copilotCli: false });
    assert.equal(JSON.parse(flat.stdout).permissionDecision, 'ask', 'the flat shape, as before');
    assert.deepEqual(['vscode', 'claude'].map((copy) => guard(dir, copy, snake, { copilotCli: false }).decision), ['ask', 'ask']);
    for (const order of ORDERS) {
      const sid = `no-cli-${order.join('-')}`;
      const call = payloads(dir, sid, PUSH);
      assert.deepEqual(order.map((copy) => guard(dir, copy, call[copy], { copilotCli: false }).decision), ['ask', 'ask', 'ask'], order.join(', '));
      // Only the CLI-file copy carries a signal (its BI_HARNESS_HOST): it alone records, so it finds no other copy's ask.
      assert.deepEqual(Object.values(stateOf(dir, sid).askCopies).map((r) => Object.keys(r.copies)), [['copilot-cli']]);
    }
    const events = rows(dir, 'security-events.jsonl');
    assert.equal(events.length, 15);
    assert.deepEqual([...new Set(events.map((e) => e.decision))], ['ask'], 'asks only, no repeat');
    assert.deepEqual(events.filter((e) => e.copy).map((e) => e.copy), Array(5).fill('copilot-cli'), 'a copy field on the CLI-file copy\'s asks only');
    // The same call with COPILOT_CLI=1: one ask, two repeats.
    const call = payloads(dir, 'with-cli-1', PUSH);
    assert.deepEqual(['vscode', 'copilot-cli', 'claude'].map((copy) => guard(dir, copy, call[copy]).decision), ['ask', null, null]);
  });
});

test('Copilot: two identical calls of one message: one copy asks twice, the two others stay silent twice; a third copy asks', () => {
  withRepo((dir) => {
    const call = payloads(dir, 'twice-1', PUSH);
    // The CLI works through the entries across the calls of a message: entry 1 for each call, then entry 2, and so on.
    assert.deepEqual([guard(dir, 'vscode', call.vscode), guard(dir, 'vscode', call.vscode)].map((a) => a.decision), ['ask', 'ask']);
    for (const copy of ['copilot-cli', 'copilot-cli', 'claude', 'claude']) assert.equal(guard(dir, copy, call[copy]).stdout, '', copy);
    assert.equal(guard(dir, 'copilot-cli', call['copilot-cli']).decision, 'ask', 'no ask left to repeat');
  });
});

test('Copilot: another reason, instant, session or argument for the call asks again', () => {
  withRepo((dir) => {
    const sid = 'reason-1';
    const call = payloads(dir, sid, PUSH);
    assert.equal(guard(dir, 'vscode', call.vscode).decision, 'ask');
    // The record of an ask with another reason for the same call (its reason hash is the part after the dot).
    const state = stateOf(dir, sid);
    state.askCopies = Object.fromEntries(Object.entries(state.askCopies).map(([id, rec]) => [id.replace(/\.[0-9a-f]+$/, '.0000000000000000'), rec]));
    fs.writeFileSync(stateFile(dir, sid), JSON.stringify(state));
    assert.equal(guard(dir, 'copilot-cli', call['copilot-cli']).decision, 'ask', 'another reason');

    const base = payloads(dir, 'other-1', PUSH);
    assert.equal(guard(dir, 'vscode', base.vscode).decision, 'ask');
    assert.equal(guard(dir, 'claude', payloads(dir, 'other-1', PUSH, { ms: T + 1 }).claude).decision, 'ask', 'another instant');
    assert.equal(guard(dir, 'claude', payloads(dir, 'other-2', PUSH).claude).decision, 'ask', 'another session');
    assert.equal(guard(dir, 'claude', payloads(dir, 'other-1', { ...PUSH, description: 'other' }).claude).decision, 'ask', 'other arguments');
    assert.equal(guard(dir, 'claude', base.claude).stdout, '', 'the same call is still a repeat');
  });
});

test('Copilot: a state that is garbage, cannot be written, or holds an ask never marked as written: the later copy asks', () => {
  withRepo((dir) => {
    const cases = [
      ['garbage JSON', (sid) => fs.writeFileSync(stateFile(dir, sid), '{"askCopies": {')],
      ['the state file is a folder', (sid) => {
        fs.rmSync(stateFile(dir, sid));
        fs.mkdirSync(stateFile(dir, sid));
      }],
      ['an ask without the emitted mark (the first copy killed before its output)', (sid) => {
        const state = stateOf(dir, sid);
        for (const rec of Object.values(state.askCopies)) rec.copies.vscode.e = 0;
        fs.writeFileSync(stateFile(dir, sid), JSON.stringify(state));
      }],
    ];
    for (const [i, [what, damage]] of cases.entries()) {
      const sid = `fallback-${i}`;
      const call = payloads(dir, sid, PUSH);
      assert.equal(guard(dir, 'vscode', call.vscode).decision, 'ask', what);
      damage(sid);
      assert.equal(guard(dir, 'copilot-cli', call['copilot-cli']).decision, 'ask', what);
    }
    // The state folder itself cannot be created: a file stands where it would be.
    const stateDir = path.join(dir, '.claude', 'logs', '.state');
    fs.rmSync(stateDir, { recursive: true, force: true });
    fs.writeFileSync(stateDir, 'not a folder');
    const call = payloads(dir, 'nofolder-1', PUSH);
    assert.deepEqual(['vscode', 'copilot-cli', 'claude'].map((copy) => guard(dir, copy, call[copy]).decision), ['ask', 'ask', 'ask']);
  });
});

test('Copilot: one call with two asks of different reasons (an apply_patch over two files) is one prompt; both repeat later', () => {
  withRepo((dir) => {
    const sid = 'patch-1';
    const patch = ['*** Begin Patch', '*** Add File: docs/harness/a.md', '+# a', '*** Add File: .github/b.md', '+# b', '*** End Patch'].join('\n');
    const call = payloads(dir, sid, { input: patch }, { cliTool: 'apply_patch', snakeTool: 'apply_patch' });
    const before = rows(dir, 'security-events.jsonl').length;
    const first = guard(dir, 'claude', call.claude);
    assert.equal(first.decision, 'ask');
    assert.match(first.reason, /docs\/harness\/a\.md .* \| .*\.github\/b\.md /, 'both reasons in one prompt');
    assert.equal(guard(dir, 'vscode', call.vscode).stdout, '');
    assert.equal(guard(dir, 'copilot-cli', call['copilot-cli']).stdout, '');
    const events = rows(dir, 'security-events.jsonl').slice(before);
    assert.deepEqual(events.map((e) => `${e.decision}:${e.copy}`), ['ask:claude', 'ask:claude', 'repeat:vscode', 'repeat:vscode', 'repeat:copilot-cli', 'repeat:copilot-cli']);
  });
});

test('Copilot: an MCP write on a connection the session never confirmed asks once across the three copies', () => {
  withRepo((dir) => {
    const sid = 'mcp-1';
    // The CLI's name in its camelCase payload (logged 2026-10-07); the PascalCase payloads under the CLI were not captured
    // with MCP on, so they carry the same name, as tests/round2-stop-state.test.mjs assumes (F2-11).
    const request = { operation: 'Create', connectionName: 'PBIDesktop-Sales-1234', definitions: [{ name: 'Total Sales', tableName: 'Sales', expression: 'SUM(Sales[Amount])' }] };
    const call = payloads(dir, sid, { request }, { cliTool: 'powerbi-modeling-mcp-measure_operations', snakeTool: 'powerbi-modeling-mcp-measure_operations' });
    const answers = ['copilot-cli', 'vscode', 'claude'].map((copy) => guard(dir, copy, call[copy]));
    assert.equal(answers[0].decision, 'ask');
    assert.match(answers[0].reason, /confirm/i);
    assert.deepEqual(answers.slice(1).map((a) => a.stdout), ['', '']);
  });
});

test('Copilot: every audit row says which registration wrote it; a Claude Code row has no copy', () => {
  withRepo((dir) => {
    const sid = 'audit-1';
    const post = (copy) => (copy === 'copilot-cli'
      ? { sessionId: sid, timestamp: T, cwd: dir, toolName: 'powershell', toolArgs: { command: 'git status', description: 'd' }, toolResult: { resultType: 'success', textResultForLlm: 'ok' } }
      : { hook_event_name: 'PostToolUse', session_id: sid, timestamp: new Date(T).toISOString(), cwd: dir, tool_name: 'Bash', tool_input: { command: 'git status', description: 'd' }, tool_result: { result_type: 'success', text_result_for_llm: 'ok' } });
    for (const copy of ['vscode', 'copilot-cli', 'claude']) runCopy('audit-log.mjs', dir, copy, post(copy));
    runCopy('audit-log.mjs', dir, 'claude', { hook_event_name: 'PostToolUse', session_id: 'claude-c', tool_name: 'Bash', tool_input: { command: 'git status' }, tool_response: { stdout: 'ok' }, tool_use_id: 'u1' });
    assert.deepEqual(rows(dir, 'tool-audit.jsonl').map((r) => [r.session, r.tool, r.copy]), [
      [sid.slice(0, 8), 'Bash', 'vscode'],
      [sid.slice(0, 8), 'powershell', 'copilot-cli'],
      [sid.slice(0, 8), 'Bash', 'claude'],
      ['claude-c', 'Bash', undefined],
    ]);
  });
});
