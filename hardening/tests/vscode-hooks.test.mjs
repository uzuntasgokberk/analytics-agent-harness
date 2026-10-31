// VS Code Copilot hooks (hooks/lib/host-vscode.mjs, BI_HARNESS_HOST=vscode): VS Code's tool names and input shapes
// (Copilot Chat's published tool schemas, 2026-10-07) reach the same policy as Claude Code's tools; a multi-file call
// takes the strictest verdict; a Stop block is nested the way VS Code reads it. Built against the documented
// protocol, not executed inside VS Code: the first real session confirms it (hardening/README.md).
import { after, test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { claudeMcpName, fromCopilotCli, mergeVerdicts, patchFiles, toClaudeCalls, toCopilotCliOutput, toHostOutput, unmappedToolReason } from '../hooks/lib/host-vscode.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const hooks = path.join(here, '..', 'hooks');
const cfg = { mcp: { powerbiServer: 'powerbi-modeling' } };
const root = os.platform() === 'win32' ? 'C:\\repo' : '/repo';
const calls = (tool_name, tool_input) => toClaudeCalls({ hook_event_name: 'PreToolUse', tool_name, tool_input }, { cfg, projectDir: root });
// Variables that point git at another repository, index or object store. A `git commit` hook that runs these tests
// exports GIT_INDEX_FILE (and GIT_DIR in some setups); the temporary repositories' git calls, the tests' and the hooks',
// run without them (as mcp-state.test.mjs does since F1-116).
const GIT_REPO_VARS = new Set(['GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE', 'GIT_OBJECT_DIRECTORY', 'GIT_ALTERNATE_OBJECT_DIRECTORIES', 'GIT_COMMON_DIR', 'GIT_PREFIX']);
const gitEnv = () => Object.fromEntries(Object.entries(process.env).filter(([k]) => !GIT_REPO_VARS.has(k.toUpperCase())));

test('vscode: tool names and input shapes map to the Claude tools the policy knows', () => {
  const sh = calls('run_in_terminal', { command: 'git status', explanation: 'x', goal: 'y', mode: 'sync' });
  assert.deepEqual(sh.map((c) => [c.tool_name, c.tool_input]), [['Bash', { command: 'git status' }]]);
  assert.equal(sh[0].host_tool, 'run_in_terminal');
  assert.equal(sh[0].session_id, 'vscode', 'a missing session id gets a stable one');
  for (const name of ['read_file', 'copilot_readFile', 'readFile']) {
    assert.deepEqual(calls(name, { filePath: `${root}${path.sep}a.md`, startLine: 1, endLine: 5 }).map((c) => c.tool_name), ['Read'], name);
  }
  assert.deepEqual(calls('create_file', { filePath: `${root}${path.sep}docs${path.sep}x.md`, content: '# x' })[0], {
    hook_event_name: 'PreToolUse', tool_name: 'Write', tool_input: { file_path: path.join(root, 'docs', 'x.md'), content: '# x' }, session_id: 'vscode', host_tool: 'create_file',
  });
  const edit = calls('replace_string_in_file', { filePath: 'docs/x.md', oldString: 'a', newString: 'b' })[0];
  assert.deepEqual([edit.tool_name, edit.tool_input], ['Edit', { file_path: path.resolve(root, 'docs/x.md'), old_string: 'a', new_string: 'b' }], 'a relative path resolves against the project');
  const insert = calls('insert_edit_into_file', { filePath: 'docs/x.md', code: 'new', explanation: 'e' })[0];
  assert.deepEqual([insert.tool_name, insert.tool_input.new_string], ['Edit', 'new']);
  const multi = calls('multi_replace_string_in_file', { explanation: 'e', replacements: [{ filePath: 'a.md', oldString: '1', newString: '2' }, { filePath: 'b.md', oldString: '3', newString: '4' }] });
  assert.deepEqual(multi.map((c) => [c.tool_name, path.basename(c.tool_input.file_path)]), [['Edit', 'a.md'], ['Edit', 'b.md']]);
  const nb = calls('edit_notebook_file', { filePath: 'n.ipynb', cellId: 'c1', newCode: 'print(1)', editType: 'edit' })[0];
  assert.equal(nb.tool_name, 'NotebookEdit');
  assert.deepEqual(calls('grep_search', { query: 'Net Sales', isRegexp: false, includePattern: '**/*.tmdl' })[0].tool_input, { pattern: 'Net Sales', glob: '**/*.tmdl' });
  assert.equal(calls('grep_search', { query: 'x', isRegexp: false })[0].tool_name, 'Grep');
  assert.equal(calls('file_search', { query: '**/*.rdl' })[0].tool_name, 'Glob');
  assert.equal(calls('semantic_search', { query: 'where is freight' })[0].tool_name, 'Grep');
  assert.deepEqual(calls('list_dir', { path: 'docs' })[0].tool_input, { pattern: '*', path: path.resolve(root, 'docs') });
  assert.deepEqual(calls('fetch_webpage', { urls: ['https://example.com'], query: 'q' })[0].tool_input, { url: 'https://example.com', prompt: 'q' }, 'a web fetch gets the masking hook');
  const unknown = calls('get_errors', { filePaths: ['a.ts'] })[0];
  assert.equal(unknown.unmapped, true);
  assert.equal(unknown.tool_name, 'get_errors', 'an unknown tool passes through untouched');
});

test('vscode: MCP tool names (mcp_ + the label cut to 13 characters + _tool) become mcp__server__tool', () => {
  assert.equal(claudeMcpName('mcp_powerbi-model_measure_operations', cfg), 'mcp__powerbi-modeling__measure_operations');
  assert.equal(claudeMcpName('mcp_powerbi-model1_dax_query_operations', cfg), 'mcp__powerbi-modeling__dax_query_operations', 'a collision suffix is dropped');
  assert.equal(claudeMcpName('mcp_github_create_issue', cfg), 'mcp__github__create_issue');
  assert.equal(claudeMcpName('mcp_figma_use_figma', cfg), 'mcp__figma__use_figma');
  assert.equal(claudeMcpName('mcp_other_srv_do_it', cfg), 'mcp__other__srv_do_it', 'an unknown server splits at the first underscore');
  assert.equal(claudeMcpName('mcp__powerbi-modeling__measure_operations', cfg), 'mcp__powerbi-modeling__measure_operations', 'Claude names pass');
  const c = calls('mcp_powerbi-model_measure_operations', { request: { operation: 'Create' } })[0];
  assert.deepEqual([c.tool_name, c.tool_input], ['mcp__powerbi-modeling__measure_operations', { request: { operation: 'Create' } }]);
});

test('vscode: apply_patch names its files; Add is a Write, Update and Delete are Edits of that path', () => {
  const patch = ['*** Begin Patch', '*** Add File: docs/new.md', '+# New', '+line', '*** Update File: powerbi/X.Report/report.json', '@@ -1,2 +1,2 @@', '-old', '+new', ' ctx', '*** Delete File: templates/t.md', '*** End Patch'].join('\n');
  assert.deepEqual(patchFiles(patch).map((f) => [f.op, f.file, f.plus, f.minus]), [
    ['Add', 'docs/new.md', ['# New', 'line'], []], ['Update', 'powerbi/X.Report/report.json', ['new'], ['old']], ['Delete', 'templates/t.md', [], []],
  ]);
  const out = calls('apply_patch', { input: patch, explanation: 'e' });
  assert.deepEqual(out.map((c) => [c.tool_name, path.basename(c.tool_input.file_path)]), [['Write', 'new.md'], ['Edit', 'report.json'], ['Edit', 't.md']]);
  assert.equal(out[0].tool_input.content, '# New\nline');
});

test('vscode: several verdicts merge deny > ask > no opinion > allow; a Stop block is nested for VS Code', () => {
  const allow = { hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'allow', permissionDecisionReason: 'routine' } };
  const ask = { hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'ask', permissionDecisionReason: 'critical' } };
  const deny = { hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: 'no' } };
  assert.equal(mergeVerdicts('PreToolUse', [allow, null]), null, 'an unknown file never makes the whole call an allow');
  assert.equal(mergeVerdicts('PreToolUse', [allow, ask]).hookSpecificOutput.permissionDecision, 'ask');
  assert.equal(mergeVerdicts('PreToolUse', [ask, deny, null]).hookSpecificOutput.permissionDecision, 'deny');
  assert.equal(mergeVerdicts('PreToolUse', [allow, allow]).hookSpecificOutput.permissionDecision, 'allow');
  assert.equal(mergeVerdicts('PreToolUse', [deny]), deny, 'a single result passes through');
  const post = mergeVerdicts('PostToolUse', [null, { decision: 'block', reason: 'bad json' }, { hookSpecificOutput: { hookEventName: 'PostToolUse', additionalContext: 'warn' } }]);
  assert.deepEqual(post, { decision: 'block', reason: 'bad json', hookSpecificOutput: { hookEventName: 'PostToolUse', additionalContext: 'warn' } });
  assert.deepEqual(toHostOutput('Stop', { decision: 'block', reason: 'r' }), { decision: 'block', reason: 'r', hookSpecificOutput: { hookEventName: 'Stop', decision: 'block', reason: 'r' } });
  assert.deepEqual(toHostOutput('PreToolUse', deny), deny);
  assert.equal(toHostOutput('Stop', null), null);
});

/** Runs a hook as VS Code would: BI_HARNESS_HOST=vscode, VS Code payload, project = dir. */
function run(script, dir, payload) {
  const r = spawnSync(process.execPath, [path.join(hooks, script)], {
    input: JSON.stringify({ timestamp: '2026-10-07T12:00:00Z', cwd: dir, ...payload }),
    env: { ...gitEnv(), CLAUDE_PROJECT_DIR: dir, BI_HARNESS_HOST: 'vscode' },
    encoding: 'utf8',
  });
  const out = r.stdout.trim() ? JSON.parse(r.stdout) : null;
  return { status: r.status, out, decision: out?.hookSpecificOutput?.permissionDecision ?? null, stderr: r.stderr };
}

test('vscode: the guard judges VS Code payloads like Claude payloads, end to end', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-vscode-'));
  try {
    fs.mkdirSync(path.join(dir, 'docs'), { recursive: true });
    fs.mkdirSync(path.join(dir, 'templates'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'docs', 'notes.md'), '# notes\n');
    const pre = (tool_name, tool_input) => run('pre-tool-use.mjs', dir, { hook_event_name: 'PreToolUse', tool_name, tool_input, tool_use_id: 't1' });
    assert.equal(pre('run_in_terminal', { command: 'cat .env', explanation: 'x', goal: 'y', mode: 'sync' }).decision, 'deny');
    assert.equal(pre('run_in_terminal', { command: 'git status', explanation: 'x', goal: 'y', mode: 'sync' }).decision, 'allow', 'routine in auto mode');
    assert.equal(pre('read_file', { filePath: path.join(dir, '.env'), startLine: 1, endLine: 5 }).decision, 'deny');
    assert.equal(pre('create_file', { filePath: path.join(dir, 'powerbi', 'X.Report', 'report.json'), content: '{}' }).decision, 'deny', 'Desktop-owned file');
    assert.equal(pre('replace_string_in_file', { filePath: path.join(dir, 'docs', 'notes.md'), oldString: 'notes', newString: 'Notes' }).decision, 'allow', 'routine project edit');
    assert.equal(pre('multi_replace_string_in_file', { explanation: 'e', replacements: [
      { filePath: path.join(dir, 'docs', 'notes.md'), oldString: 'a', newString: 'b' },
      { filePath: path.join(dir, 'templates', 'house.md'), oldString: 'a', newString: 'b' },
    ] }).decision, 'deny', 'one reference-folder file denies the whole call');
    const patch = ['*** Begin Patch', '*** Update File: templates/house.md', '@@', '-a', '+b', '*** End Patch'].join('\n');
    assert.equal(pre('apply_patch', { input: patch, explanation: 'e' }).decision, 'deny');
    assert.equal(pre('grep_search', { query: 'pw', isRegexp: false, includePattern: '**/*.pbix' }).decision, 'deny', 'a data-file glob');
    // F1-100: create_and_run_task runs a shell command as a VS Code task; it reaches the shell policy like run_in_terminal.
    const task = (command, args) => ({ workspaceFolder: dir, task: { label: 't', type: 'shell', command, ...(args ? { args } : {}) } });
    assert.equal(pre('create_and_run_task', task('cat .env')).decision, 'deny', 'create_and_run_task: a shell read of a secret file');
    assert.equal(pre('create_and_run_task', task('cat', ['.env'])).decision, 'deny', 'the file named in task.args');
    assert.equal(pre('create_and_run_task', task('git status')).decision, 'allow', 'a routine task, like run_in_terminal');
    // F1-13: arguments sent as a JSON string get the verdict of the object form; text that is no JSON object asks.
    assert.equal(pre('run_in_terminal', JSON.stringify({ command: 'cat .env', explanation: 'x' })).decision, 'deny', 'tool_input as a JSON string');
    assert.equal(pre('run_in_terminal', 'cat .env').decision, 'ask', 'tool_input as text that is no JSON object');
    assert.equal(pre('mcp_powerbi-model_security_role_operations', { request: { operation: 'Update', members: ['a@example.com'] } }).decision, 'deny', 'role members through VS Code MCP naming');
    const unknown = pre('get_errors', { filePaths: ['a.ts'] });
    assert.equal(unknown.out, null, 'an unmapped tool gets no opinion');
    const audit = fs.readFileSync(path.join(dir, '.claude', 'logs', 'tool-audit.jsonl'), 'utf8');
    assert.match(audit, /"event":"unmapped".*"tool":"get_errors"/, 'and is logged for the first real session to review');
    // PostToolUse: a read never blocks; a write of a broken file does.
    fs.writeFileSync(path.join(dir, 'docs', 'big.md', ), Array.from({ length: 501 }, (_, i) => `line ${i}`).join('\n'));
    const read = run('post-tool-validate.mjs', dir, { hook_event_name: 'PostToolUse', tool_name: 'read_file', tool_input: { filePath: path.join(dir, 'docs', 'big.md'), startLine: 1, endLine: 2 }, tool_response: 'line 0' });
    assert.equal(read.out, null, 'a read of a file with issues is not a write');
    const wrote = run('post-tool-validate.mjs', dir, { hook_event_name: 'PostToolUse', tool_name: 'create_file', tool_input: { filePath: path.join(dir, 'docs', 'big.md'), content: 'x' }, tool_response: 'ok' });
    assert.equal(wrote.out?.decision, 'block');
    assert.match(wrote.out.reason, /501 lines/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('copilot cli: camelCase payloads become Claude fields, verdicts come back flat, and the guard judges them', () => {
  assert.deepEqual(fromCopilotCli({ sessionId: 's1', cwd: 'C:/x', toolName: 'bash', toolArgs: { command: 'git status' }, timestamp: 1 }),
    { sessionId: 's1', cwd: 'C:/x', toolName: 'bash', toolArgs: { command: 'git status' }, timestamp: 1, session_id: 's1', tool_name: 'bash', tool_input: { command: 'git status' } });
  assert.equal(fromCopilotCli({ toolName: 'view', toolArgs: { path: 'a' }, toolResult: { resultType: 'success', textResultForLlm: 'text' } }).tool_response, 'text');
  const deny = { hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: 'no' } };
  // The output shaping takes the event (F1-55): a PostToolUse block has no CLI equivalent and becomes context; a Stop block
  // stays {decision, reason}, which agentStop reads (see the Stop test below).
  assert.deepEqual(toCopilotCliOutput('PreToolUse', deny), { permissionDecision: 'deny', permissionDecisionReason: 'no' });
  assert.deepEqual(toCopilotCliOutput('PostToolUse', { decision: 'block', reason: 'bad', hookSpecificOutput: { hookEventName: 'PostToolUse', additionalContext: 'ctx' } }), { additionalContext: 'bad\n\nctx' });
  assert.deepEqual(toCopilotCliOutput('PostToolUse', { hookSpecificOutput: { hookEventName: 'PostToolUse', updatedToolOutput: 'masked', additionalContext: 'c' } }), { additionalContext: 'c', modifiedResult: { resultType: 'success', textResultForLlm: 'masked' } });
  assert.equal(toCopilotCliOutput('PostToolUse', null), null);
  assert.deepEqual(toCopilotCliOutput(deny), { permissionDecision: 'deny', permissionDecisionReason: 'no' }, 'a lone result (no event) still works');
  assert.equal(toCopilotCliOutput(null), null);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-cli-'));
  try {
    const cli = (script, payload) => {
      const r = spawnSync(process.execPath, [path.join(hooks, script)], {
        input: JSON.stringify({ sessionId: 'cli1', timestamp: 1, cwd: dir, ...payload }),
        env: { ...gitEnv(), CLAUDE_PROJECT_DIR: dir, BI_HARNESS_HOST: 'copilot-cli' },
        encoding: 'utf8',
      });
      return r.stdout.trim() ? JSON.parse(r.stdout) : null;
    };
    assert.deepEqual(cli('pre-tool-use.mjs', { toolName: 'bash', toolArgs: { command: 'cat .env' } })?.permissionDecision, 'deny');
    assert.equal(cli('pre-tool-use.mjs', { toolName: 'bash', toolArgs: { command: 'git status' } })?.permissionDecision, 'allow');
    assert.equal(cli('pre-tool-use.mjs', { toolName: 'create', toolArgs: { filePath: path.join(dir, 'powerbi', 'X.Report', 'report.json'), content: '{}' } })?.permissionDecision, 'deny');
    const fakeSecret = ['Pass', 'word=hunter2', 'fake', 'value;'].join(''); // built at run time: never a credential literal in a test
    const masked = cli('post-tool-redact.mjs', { toolName: 'bash', toolArgs: { command: 'cat x' }, toolResult: { resultType: 'success', textResultForLlm: fakeSecret } });
    assert.match(masked?.modifiedResult?.textResultForLlm ?? '', /REDACTED/, 'masking reaches the CLI as modifiedResult');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  const file = JSON.parse(fs.readFileSync(path.join(here, '..', 'copilot-cli.hooks.json'), 'utf8'));
  assert.equal(file.version, 1);
  for (const [event, list] of Object.entries(file.hooks)) {
    assert.match(event, /^[a-z][A-Za-z]+$/, `${event} is camelCase`);
    for (const h of list) {
      assert.match(h.bash, /^node hardening\/hooks\/[a-z-]+\.mjs$/, `${event}: ${h.bash}`);
      assert.equal(h.powershell, h.bash);
      assert.ok(fs.existsSync(path.join(here, '..', '..', h.bash.slice(5))), `${event}: ${h.bash} exists`);
      assert.equal(h.env?.BI_HARNESS_HOST, 'copilot-cli');
      assert.ok(Number.isInteger(h.timeoutSec) && h.timeoutSec > 0);
    }
  }
});

test('vscode: the shipped hook file registers every hook with a repo-relative node command and the host variable', () => {
  const file = JSON.parse(fs.readFileSync(path.join(here, '..', 'vscode.hooks.json'), 'utf8'));
  const events = Object.keys(file.hooks);
  for (const e of ['SessionStart', 'UserPromptSubmit', 'PreToolUse', 'PostToolUse', 'Stop', 'SubagentStop']) assert.ok(events.includes(e), e);
  for (const [event, list] of Object.entries(file.hooks)) {
    for (const h of list) {
      assert.equal(h.type, 'command', event);
      assert.match(h.command, /^node hardening\/hooks\/[a-z-]+\.mjs$/, `${event}: ${h.command}`);
      assert.ok(fs.existsSync(path.join(here, '..', '..', h.command.slice(5))), `${event}: ${h.command} exists`);
      assert.equal(h.env?.BI_HARNESS_HOST, 'vscode', `${event}: host variable`);
      assert.ok(Number.isInteger(h.timeout) && h.timeout > 0, `${event}: timeout`);
      assert.equal(h.matcher, undefined, 'VS Code ignores matchers: none written, the scripts filter by tool themselves');
    }
  }
  assert.ok(!file.hooks.PreToolUse.some((h) => /agent-scope/.test(h.command)), 'agent scopes need agent_type, which VS Code does not send on PreToolUse');
});

// Audit 2026-10-19, F2-35: the shape of every Copilot CLI entry was checked, but not that the events exist: without
// preToolUse (the only event whose verdict blocks under Copilot) or agentStop the suite stayed green. Inclusion, so an
// event added later does not break it; each script must run in both shells (the cloud agent runs only the bash variant).
test('copilot cli: the shipped hook file registers sessionStart, userPromptSubmitted, preToolUse, postToolUse and agentStop', () => {
  const file = JSON.parse(fs.readFileSync(path.join(here, '..', 'copilot-cli.hooks.json'), 'utf8'));
  const runs = (event, script) => (file.hooks[event] ?? []).some((h) => h.bash === `node hardening/hooks/${script}` && h.powershell === h.bash);
  for (const [event, script] of [
    ['sessionStart', 'session-start.mjs'],
    ['userPromptSubmitted', 'user-prompt-guard.mjs'],
    ['preToolUse', 'pre-tool-use.mjs'],
    ['postToolUse', 'post-tool-redact.mjs'],
    ['postToolUse', 'audit-log.mjs'],
    ['agentStop', 'stop-gate.mjs'],
  ]) {
    assert.ok(Object.hasOwn(file.hooks, event), `${event} is registered`);
    assert.ok(runs(event, script), `${event} runs ${script} in bash and powershell`);
  }
});

// ---------------------------------------------------------------- audit 2026-10-18: the Copilot translation layer (F1-11, F1-13, F1-55, F1-100)

const PATCH = ['*** Begin Patch', '*** Update File: templates/house.md', '@@', '-a', '+b', '*** End Patch'].join('\n');
const verdictOf = (permissionDecision) => ({ hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision, permissionDecisionReason: 'r' } });

/** Runs a hook as a Copilot host does: BI_HARNESS_HOST=<host>, a camelCase payload, project = dir; the parsed output or null. */
function runAs(host, script, dir, payload) {
  const env = { ...gitEnv(), CLAUDE_PROJECT_DIR: dir, BI_HARNESS_HOST: host };
  const r = spawnSync(process.execPath, [path.join(hooks, script)], { input: JSON.stringify({ timestamp: 1, cwd: dir, ...payload }), env, encoding: 'utf8' });
  assert.equal(r.status, 0, `${script}: ${r.stderr}`);
  return r.stdout.trim() ? JSON.parse(r.stdout) : null;
}

test('copilot: a search over several paths is judged path by path, and PostToolUse keeps one call (F1-11)', () => {
  const search = (name, input, extra = {}) => toClaudeCalls({ hook_event_name: 'PreToolUse', tool_name: name, tool_input: input }, { cfg, projectDir: root, ...extra });
  const two = { pattern: 'x', paths: ['docs', '.env'] };
  for (const name of ['grep', 'rg', 'Grep']) {
    assert.deepEqual(search(name, two).map((c) => [c.tool_name, c.tool_input.path, c.tool_input.pattern]),
      [['Grep', path.resolve(root, 'docs'), 'x'], ['Grep', path.resolve(root, '.env'), 'x']], name);
  }
  assert.deepEqual(search('rg', { pattern: 'x', paths: ['docs'] }).map((c) => c.tool_input.path), [path.resolve(root, 'docs')], 'one path, one call');
  assert.deepEqual(search('rg', { pattern: 'x', paths: 'docs' }).map((c) => c.tool_input.path), [path.resolve(root, 'docs')], 'a path as text');
  assert.deepEqual(search('rg', { pattern: 'x', paths: [] }).map((c) => c.tool_input), [{ pattern: 'x' }], 'no path: the call searches the project');
  assert.deepEqual(search('rg', { pattern: 'x', paths: ['docs', 'docs', ['.env']], path: 'a' }).map((c) => c.tool_input.path),
    [path.resolve(root, 'docs'), path.resolve(root, '.env'), path.resolve(root, 'a')], 'duplicates drop; nested lists and a lone path count');
  assert.deepEqual(search('rg', { ...two, glob: '*.md' }).map((c) => c.tool_input.glob), ['*.md', '*.md'], 'the glob travels with each call');
  assert.deepEqual(search('glob', { pattern: '**/*.tmdl', paths: ['a', 'b'] }).map((c) => [c.tool_name, path.basename(c.tool_input.path)]), [['Glob', 'a'], ['Glob', 'b']]);
  // The PostToolUse merge drops an updated (masked) output when there are several calls: a search stays one call there.
  assert.deepEqual(search('rg', two, { event: 'PostToolUse' }).map((c) => path.basename(c.tool_input.path)), ['docs'], 'event from the runtime: the first path, as before');
  assert.equal(toClaudeCalls({ hook_event_name: 'PostToolUse', tool_name: 'rg', tool_input: two }, { cfg, projectDir: root }).length, 1, 'event from the payload');
});

test('copilot: tool arguments sent as text are read, or flagged so the verdict asks, never dropped (F1-13)', () => {
  const read = (extra) => fromCopilotCli({ toolName: 'bash', ...extra });
  assert.deepEqual(read({ toolArgs: '{"command":"git status"}' }).tool_input, { command: 'git status' }, 'camelCase toolArgs as a JSON string');
  assert.deepEqual(read({ tool_input: ' {"command":"git status"} ' }).tool_input, { command: 'git status' }, 'snake_case tool_input as a JSON string');
  assert.deepEqual(read({ toolArgs: PATCH }).tool_input, { input: PATCH }, 'a bare apply_patch text');
  assert.deepEqual(read({ toolArgs: { command: 'git status' } }).tool_input, { command: 'git status' }, 'an object stays as it is');
  assert.equal(read({ toolArgs: { command: 'git status' }, tool_input_unreadable: true }).tool_input_unreadable, undefined, 'the flag is never taken from a payload');
  for (const nothing of [null, '', '  ', 'null']) {
    const r = read({ toolArgs: nothing });
    assert.deepEqual([r.tool_input, r.tool_input_unreadable], [{}, undefined], `no arguments: ${JSON.stringify(nothing)}`);
  }
  for (const bad of ['cat .env', '{"command":', '[1,2]', '"cat .env"', '7', [1], 7, true]) {
    const r = read({ toolArgs: bad });
    assert.deepEqual([r.tool_input, r.tool_input_unreadable], [{}, true], `unreadable: ${JSON.stringify(bad)}`);
  }
  const text = (name, tool_input) => toClaudeCalls({ hook_event_name: 'PreToolUse', tool_name: name, tool_input }, { cfg, projectDir: root });
  assert.deepEqual(text('bash', '{"command":"cat .env"}').map((c) => [c.tool_name, c.tool_input]), [['Bash', { command: 'cat .env' }]], 'a JSON string gets the calls of the object form');
  assert.deepEqual(text('view', JSON.stringify({ path: 'docs/a.md' })).map((c) => c.tool_name), ['Read']);
  assert.deepEqual(text('apply_patch', PATCH).map((c) => [c.tool_name, path.basename(c.tool_input.file_path)]), [['Edit', 'house.md']], 'a bare patch text names its files');
  const [flagged, ...rest] = text('bash', 'cat .env');
  assert.equal(rest.length, 0);
  assert.deepEqual([flagged.unmapped, flagged.tool_input_unreadable, flagged.tool_input, flagged.host_tool], [true, true, {}, 'bash']);
  assert.equal(text('mcp_powerbi-model_measure_operations', 'Create')[0].tool_input_unreadable, true, 'an MCP call whose arguments cannot be read');
  assert.equal(text('ask_user', 'not json')[0].tool_input_unreadable, undefined, 'a tool without a policy has no opinion by name, whatever it was sent');
  assert.equal(text('ask_user', 'not json')[0].unmapped, undefined);
  const viaCli = toClaudeCalls(fromCopilotCli({ toolName: 'bash', toolArgs: 'cat .env' }), { cfg, projectDir: root });
  assert.deepEqual([viaCli.length, viaCli[0].unmapped, viaCli[0].tool_input_unreadable], [1, true, true], 'the flag fromCopilotCli sets reaches the call');
  const viaCliNoPolicy = toClaudeCalls(fromCopilotCli({ toolName: 'ask_user', toolArgs: 'not json' }), { cfg, projectDir: root });
  assert.equal(viaCliNoPolicy[0].tool_input_unreadable, undefined, 'and only the flagged call carries it');
  // mergeVerdicts: a flagged call adds an ask to a PreToolUse verdict; a deny still wins; PostToolUse cannot ask.
  const calls1 = [flagged];
  const ask = mergeVerdicts('PreToolUse', [null], calls1);
  assert.equal(ask.hookSpecificOutput.permissionDecision, 'ask');
  assert.match(ask.hookSpecificOutput.permissionDecisionReason, /^\[bi-harness\] The guard could not read the arguments of bash /);
  assert.equal(mergeVerdicts('PreToolUse', [verdictOf('deny')], calls1).hookSpecificOutput.permissionDecision, 'deny');
  assert.equal(mergeVerdicts('PreToolUse', [verdictOf('allow')], calls1).hookSpecificOutput.permissionDecision, 'ask', 'an allow never hides the ask');
  assert.equal(mergeVerdicts('PostToolUse', [null], calls1), null);
  assert.equal(mergeVerdicts('PreToolUse', [null], []), null, 'no flagged call, no opinion');
  assert.equal(mergeVerdicts('PreToolUse', [null]), null, 'the calls are optional');
});

// Audit 2026-10-31 (S4): a Copilot tool the translation does not know ran with no verdict (an `unmapped` audit row only),
// also when its arguments named a command or a file. Such a call asks now; an unknown tool without one stays silent.
test('copilot audit 2026-10-31 S4: an unknown tool whose text argument names a command, a file or an address asks', () => {
  const risky = [[{ cmd: 'rm -rf x' }, 'cmd'], [{ script: 'Remove-Item x' }, 'script'], [{ commandLine: 'del x' }, 'commandLine'],
    [{ file: '.claude/settings.json' }, 'file'], [{ file_path: 'a.md' }, 'file_path'], [{ uri: 'file:///c/x' }, 'uri'],
    [{ url: 'https://example.com' }, 'url'], [{ content: '{}' }, 'content'], [{ command: 'view', filePath: 7 }, 'command']];
  for (const [input, field] of risky) {
    const out = calls('frobnicate', input);
    assert.deepEqual([out.length, out[0].tool_name, out[0].unmapped, out[0].tool_input_unmapped_risky], [1, 'frobnicate', true, field], JSON.stringify(input));
    assert.equal(unmappedToolReason(out[0]),
      `The guard does not know the tool frobnicate, so it cannot map its \`${field}\` argument to the files, commands or servers it checks. Allow it only if you can see what it does.`);
    // The guard raises the ask (ask-once gate, event log); the merge adds none of its own, so a later copy can stay silent.
    assert.equal(mergeVerdicts('PreToolUse', [null], out), null, JSON.stringify(input));
  }
  // A bare `command` is a terminal command: the shell policy judges it (rm -rf is denied there), not this ask.
  assert.deepEqual(calls('frobnicate', { command: 'rm -rf x' }).map((c) => [c.tool_name, c.tool_input]), [['Bash', { command: 'rm -rf x' }]]);
  // No such text argument, or a tool without a policy of its own: unmapped or passed through, and silent as before.
  for (const [name, input] of [['frobnicate', { query: 'x' }], ['frobnicate', { cmd: '  ' }], ['frobnicate', { file: ['a'] }], ['get_errors', { filePaths: ['a.ts'] }],
    ['task', { path: 'x', prompt: 'p' }], ['sql', { query: 'select 1', file: 'x.sql' }]]) {
    const out = calls(name, input);
    assert.equal(out[0].tool_input_unmapped_risky, undefined, `${name} ${JSON.stringify(input)}`);
    assert.equal(unmappedToolReason(out[0]), null, `${name} ${JSON.stringify(input)}`);
  }
  const forged = toClaudeCalls({ hook_event_name: 'PreToolUse', tool_name: 'frobnicate', tool_input: { query: 'x' }, tool_input_unmapped_risky: 'cmd' }, { cfg, projectDir: root });
  assert.equal(forged[0].tool_input_unmapped_risky, undefined, 'the flag is the translation\'s alone, never taken from a payload');
});

test('copilot audit 2026-10-31 S4: the ask reaches the CLI and VS Code end to end; the audit row still says unmapped', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-unmapped-'));
  try {
    const cli = (toolArgs) => runAs('copilot-cli', 'pre-tool-use.mjs', dir, { sessionId: 's4', toolName: 'frobnicate', toolArgs });
    const viaCli = cli({ cmd: 'rm -rf x' });
    assert.equal(viaCli?.permissionDecision, 'ask');
    assert.match(viaCli.permissionDecisionReason, /^\[bi-harness\] The guard does not know the tool frobnicate, so it cannot map its `cmd` argument/);
    assert.equal(cli({ query: 'x' }), null, 'an unknown tool without such an argument gets no opinion');
    const vs = runAs('vscode', 'pre-tool-use.mjs', dir, { hook_event_name: 'PreToolUse', session_id: 's4', tool_name: 'frobnicate', tool_input: { script: 'x' } });
    assert.equal(vs?.hookSpecificOutput?.permissionDecision, 'ask');
    const rows = fs.readFileSync(path.join(dir, '.claude', 'logs', 'tool-audit.jsonl'), 'utf8').trim().split('\n').map((l) => JSON.parse(l)).filter((r) => r.event === 'unmapped');
    assert.deepEqual(rows.map((r) => [r.tool, r.inputKeys]), [['frobnicate', ['cmd']], ['frobnicate', ['query']], ['frobnicate', ['script']]]);
    // The guard's own ask: logged like every other ask, and a floor ask that lab mode leaves to the user.
    const events = fs.readFileSync(path.join(dir, '.claude', 'logs', 'security-events.jsonl'), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    assert.deepEqual(events.map((e) => [e.event, e.decision, e.tool]), [['pre-tool-use', 'ask', 'frobnicate'], ['pre-tool-use', 'ask', 'frobnicate']]);
    fs.mkdirSync(path.join(dir, 'hardening'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'hardening', 'harness.config.json'), `${JSON.stringify({ approvals: { mode: 'lab' } })}\n`);
    assert.equal(cli({ commandLine: 'del x' })?.permissionDecision, 'ask', 'lab mode: the floor stays');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('copilot cli: a Stop or SubagentStop block stays {decision, reason}; only a PostToolUse block becomes context (F1-55)', () => {
  const block = { decision: 'block', reason: 'fix it' };
  assert.deepEqual(toCopilotCliOutput('Stop', block), { decision: 'block', reason: 'fix it' });
  assert.deepEqual(toCopilotCliOutput('SubagentStop', block), { decision: 'block', reason: 'fix it' });
  assert.deepEqual(toCopilotCliOutput('Stop', { ...block, systemMessage: 'warn' }), { decision: 'block', reason: 'fix it' }, 'agentStop takes decision and reason only');
  assert.deepEqual(toCopilotCliOutput('PostToolUse', block), { additionalContext: 'fix it' });
  assert.deepEqual(toCopilotCliOutput(block, 'Stop'), { decision: 'block', reason: 'fix it' }, '(result, event) works too');
  assert.equal(toCopilotCliOutput('Stop', null), null);
  assert.deepEqual(toHostOutput('Stop', block), { ...block, hookSpecificOutput: { hookEventName: 'Stop', decision: 'block', reason: 'fix it' } }, 'VS Code keeps its nested block');
});

test('vscode: create_and_run_task maps its task command and args to a shell command (F1-100)', () => {
  const task = (t) => calls('create_and_run_task', { workspaceFolder: root, task: { label: 't', type: 'shell', ...t } });
  assert.deepEqual(task({ command: 'cat .env' }).map((c) => [c.tool_name, c.tool_input]), [['Bash', { command: 'cat .env' }]]);
  assert.equal(task({ command: 'cat', args: ['.env', { value: 'a b', quoting: 'strong' }, 7] })[0].tool_input.command, 'cat .env a b', 'string and {value} arguments, in order');
  assert.equal(task({ command: 'cat', args: '.env' })[0].tool_input.command, 'cat .env', 'a single argument as text');
  assert.equal(task({ type: 'npm', script: 'build' })[0].unmapped, true, 'a task without a command is still unmapped');
  assert.equal(calls('create_and_run_task', { workspaceFolder: root, task: 'build' })[0].unmapped, true, 'so is a task that is no object');
});

test('copilot cli: arguments sent as a JSON string get the verdict of the object form, unreadable text asks, every searched path is judged (F1-13, F1-11)', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-cli-text-'));
  try {
    fs.mkdirSync(path.join(dir, 'docs'), { recursive: true });
    fs.mkdirSync(path.join(dir, 'templates'), { recursive: true });
    fs.writeFileSync(path.join(dir, '.env'), 'X=1\n');
    const pre = (toolName, toolArgs) => runAs('copilot-cli', 'pre-tool-use.mjs', dir, { sessionId: 'cli-text', toolName, toolArgs });
    const decision = (r) => r?.permissionDecision ?? null;
    for (const [toolName, args, expected] of [
      ['bash', { command: 'cat .env', description: 'x' }, 'deny'],
      ['bash', { command: 'git push --force origin main' }, 'deny'],
      ['bash', { command: 'git status' }, 'allow'],
      ['view', { path: '.env' }, 'deny'],
      ['view', { path: 'docs' }, null],
    ]) {
      assert.equal(decision(pre(toolName, args)), expected, `${toolName} ${JSON.stringify(args)}`);
      assert.equal(decision(pre(toolName, JSON.stringify(args))), expected, `${toolName} ${JSON.stringify(args)} as a JSON string`);
    }
    assert.equal(decision(pre('apply_patch', PATCH)), 'deny', 'a bare apply_patch text names a file in a reference folder');
    const unreadable = pre('bash', 'cat .env');
    assert.equal(decision(unreadable), 'ask', 'text that is no JSON object is never silence');
    assert.match(unreadable.permissionDecisionReason, /^\[bi-harness\] /);
    assert.equal(decision(pre('ask_user', 'not json')), null, 'a tool without a policy has no opinion, whatever it was sent');
    const rows = fs.readFileSync(path.join(dir, '.claude', 'logs', 'tool-audit.jsonl'), 'utf8').trim().split('\n').map((l) => JSON.parse(l)).filter((r) => r.event === 'unmapped');
    assert.deepEqual(rows.map((r) => [r.tool, r.inputKeys]), [['bash', []]], 'the unreadable call is logged without character indexes');
    // F1-11: a secret file anywhere in the list of searched paths
    const search = (paths) => decision(pre('rg', { pattern: 'x', paths }));
    assert.equal(search(['docs', '.env']), 'deny', 'a secret file as the second path');
    assert.equal(search(['.env', 'docs']), 'deny', 'as the first');
    assert.equal(search(['docs', 'templates']), null, 'plain folders');
    assert.equal(search(['docs']), null);
    assert.equal(decision(pre('grep', JSON.stringify({ pattern: 'x', paths: ['docs', '.env'] }))), 'deny', 'grep, arguments as a JSON string');
    // Masking survives a search over several paths: PostToolUse keeps one call, so the masked output is not merged away.
    const fakeSecret = ['Pass', 'word=hunter2', 'fake', 'value;'].join(''); // built at run time: never a credential literal in a test
    const masked = runAs('copilot-cli', 'post-tool-redact.mjs', dir, { sessionId: 'cli-text', toolName: 'rg', toolArgs: { pattern: 'x', paths: ['docs', 'templates'] }, toolResult: { resultType: 'success', textResultForLlm: fakeSecret } });
    assert.match(masked?.modifiedResult?.textResultForLlm ?? '', /REDACTED/, 'the masked output of a multi-path search reaches the CLI');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('copilot cli: a Stop gate block reaches agentStop as {decision, reason}; VS Code keeps its nested block, a PostToolUse block stays context (F1-55)', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-cli-stop-'));
  try {
    spawnSync('git', ['init', '-q'], { cwd: dir, env: gitEnv() });
    fs.appendFileSync(path.join(dir, '.git', 'info', 'exclude'), '\n.claude/logs/\n');
    fs.mkdirSync(path.join(dir, 'docs'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'docs', 'big.md'), Array.from({ length: 501 }, (_, i) => `line ${i}`).join('\n'));
    const native = runAs('copilot-cli', 'stop-gate.mjs', dir, { sessionId: 'stop-cli', transcriptPath: 't', stopReason: 'end_turn', stop_hook_active: false });
    assert.equal(native?.decision, 'block', 'agentStop reads decision');
    assert.match(native.reason, /501 lines/);
    assert.equal(native.additionalContext, undefined, 'agentStop takes no additionalContext');
    assert.equal(native.hookSpecificOutput, undefined, 'flat, not nested');
    const nested = runAs('vscode', 'stop-gate.mjs', dir, { hook_event_name: 'Stop', session_id: 'stop-vscode', stop_hook_active: false });
    assert.equal(nested?.hookSpecificOutput?.decision, 'block', 'VS Code reads the nested block');
    const wrote = runAs('copilot-cli', 'post-tool-validate.mjs', dir, { sessionId: 'post-cli', toolName: 'create', toolArgs: { path: path.join(dir, 'docs', 'big.md'), file_text: 'x' }, toolResult: { resultType: 'success', textResultForLlm: 'ok' } });
    assert.equal(wrote?.decision, undefined, 'a PostToolUse block has no CLI equivalent');
    assert.match(wrote?.additionalContext ?? '', /501 lines/, 'its reason reaches the model as context');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------- audit 2026-10-18 (G8): Copilot reads no settings ask rules (F1-12); edits the guard cannot read, deleted files (F1-30)

const emptyHome = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-copilot-home-'));
after(() => fs.rmSync(emptyHome, { recursive: true, force: true }));

const SALES_TMDL = 'table Sales\n\n\tmeasure Revenue = SUM(Sales[Amount])\n\n\tpartition Sales = m\n\t\tmode: import\n\t\tsource = Sql.Database("localhost", "Sales")\n';
const ASK_RULES = ['Bash(rm *)', 'Bash(npm install *)', 'PowerShell(Remove-Item *)'];

/** A temporary project with ask rules in its settings (the only ones in play: an empty home), a guard file, a script, a note and a table. */
function copilotProject(extra = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-copilot-g8-'));
  const files = {
    '.claude/settings.json': `${JSON.stringify({ permissions: { ask: ASK_RULES }, note: 1 }, null, 2)}\n`,
    'hardening/hooks/lib/policy.mjs': 'export const x = 1;\n',
    'scripts/helper.mjs': 'export const y = 1;\n',
    'docs/notes.md': '# notes\n',
    'templates/t.md': '# template\n',
    'M.SemanticModel/definition/tables/Sales.tmdl': SALES_TMDL,
    ...extra,
  };
  for (const [rel, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), content);
  }
  return dir;
}

/** Runs the PreToolUse hook as a Copilot host does (host null: Copilot CLI's Claude registration, recognised by `timestamp`, or Claude Code itself without one). */
function copilotPre(dir, host, payload) {
  const env = { ...gitEnv(), CLAUDE_PROJECT_DIR: dir, HOME: emptyHome, USERPROFILE: emptyHome };
  delete env.BI_HARNESS_HOST;
  if (host) env.BI_HARNESS_HOST = host;
  const r = spawnSync(process.execPath, [path.join(hooks, 'pre-tool-use.mjs')], { input: JSON.stringify(payload), env, encoding: 'utf8' });
  assert.equal(r.status, 0, `${JSON.stringify(payload)}: ${r.stderr}`);
  const out = r.stdout.trim() ? JSON.parse(r.stdout) : null;
  const decision = out?.hookSpecificOutput ?? out; // the CLI's native output is flat
  return { decision: decision?.permissionDecision ?? null, reason: decision?.permissionDecisionReason ?? '' };
}
const cliCall = (dir, toolName, toolArgs) => ({ sessionId: 'g8', timestamp: 1760000000000, cwd: dir, toolName, toolArgs });
const vsCall = (tool_name, tool_input, extra = {}) => ({ hook_event_name: 'PreToolUse', session_id: 'g8', timestamp: '2026-10-18T08:00:00Z', tool_name, tool_input, ...extra });
const dialectCall = (tool_name, tool_input) => ({ hook_event_name: 'PreToolUse', session_id: 'g8', timestamp: '2026-10-18T08:00:00.000Z', tool_name, tool_input });
const claudeCall = (tool_name, tool_input) => ({ hook_event_name: 'PreToolUse', session_id: 'g8', transcript_path: 't', tool_name, tool_input });

test('copilot (F1-12): the guard asks where Claude Code\'s ask rules would, because no Copilot host evaluates them', () => {
  const dir = copilotProject({ 'hardening/harness.config.json': JSON.stringify({ approvals: { mode: 'lab' } }) });
  try {
    const policy = 'hardening/hooks/lib/policy.mjs';
    const sales = 'M.SemanticModel/definition/tables/Sales.tmdl';
    // Copilot CLI, native hooks (camelCase), and the same calls through VS Code and CLI's Claude registration.
    for (const [what, call, host, reason] of [
      ['CLI: an edit of the guard policy', cliCall(dir, 'edit', { path: policy, old_str: 'x = 1', new_str: 'x = 2' }), 'copilot-cli', /steers the agent/],
      ['CLI: a new hook file under .github', cliCall(dir, 'create', { path: '.github/hooks/x.json', file_text: '{}' }), 'copilot-cli', /steers the agent/],
      ['CLI: a new RLS role file', cliCall(dir, 'create', { path: 'M.SemanticModel/definition/roles/Reader.tmdl', file_text: 'role Reader\n\tmodelPermission: read\n' }), 'copilot-cli', /steers the agent/],
      ['CLI: rm of a TMDL file', cliCall(dir, 'bash', { command: `rm ${sales}` }), 'copilot-cli', /ask rule Bash\(rm \*\) .*does not evaluate those rules/],
      ['CLI: an install', cliCall(dir, 'bash', { command: 'npm install left-pad' }), 'copilot-cli', /ask rule Bash\(npm install \*\)/],
      ['CLI Claude registration: an edit of the settings', dialectCall('Edit', { file_path: path.join(dir, '.claude', 'settings.json'), old_string: '"note": 1', new_string: '"note": 2' }), null, /steers the agent/],
      ['CLI Claude registration: a Bash install', dialectCall('Bash', { command: 'npm install left-pad' }), null, /ask rule Bash\(npm install \*\)/],
      ['VS Code: an edit of the guard policy', vsCall('replace_string_in_file', { filePath: policy, oldString: 'x = 1', newString: 'x = 2' }), 'vscode', /steers the agent/],
      ['VS Code: a new role file', vsCall('create_file', { filePath: 'M.SemanticModel/definition/roles/Reader.tmdl', content: 'role Reader\n\tmodelPermission: read\n' }), 'vscode', /steers the agent/],
      ['VS Code: Remove-Item in the terminal (a PowerShell rule)', vsCall('run_in_terminal', { command: `Remove-Item ${sales}`, explanation: 'x', goal: 'y', mode: 'sync' }), 'vscode', /ask rule PowerShell\(Remove-Item \*\)/],
    ]) {
      const r = copilotPre(dir, host, call);
      assert.equal(r.decision, 'ask', what);
      assert.match(r.reason, /^\[bi-harness\] /, what);
      assert.match(r.reason, reason, what);
    }
    // What the rules would not ask about passes as before, and Claude Code (no host, no timestamp) keeps its rules to itself.
    assert.equal(copilotPre(dir, 'copilot-cli', cliCall(dir, 'view', { path: 'docs' })).decision, null, 'a read');
    assert.equal(copilotPre(dir, 'copilot-cli', cliCall(dir, 'view', { path: policy })).decision, null, 'a read of a critical file');
    assert.equal(copilotPre(dir, 'copilot-cli', cliCall(dir, 'bash', { command: 'git status' })).decision, 'allow', 'routine');
    assert.equal(copilotPre(dir, 'copilot-cli', cliCall(dir, 'edit', { path: 'scripts/helper.mjs', old_str: 'y = 1', new_str: 'y = 2' })).decision, null, 'a script outside the harness');
    assert.equal(copilotPre(dir, 'copilot-cli', cliCall(dir, 'edit', { path: 'docs/notes.md', old_str: 'notes', new_str: 'Notes' })).decision, 'allow', 'a note');
    assert.equal(copilotPre(dir, null, claudeCall('Bash', { command: `rm ${sales}` })).decision, null, 'Claude Code: its own ask rule prompts, the hook has no opinion');
    assert.equal(copilotPre(dir, null, claudeCall('Bash', { command: 'npm install left-pad' })).decision, null);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('copilot (F1-12): in the default auto mode the same asks reach the user, marked as critical, and routine work still runs', () => {
  const dir = copilotProject();
  try {
    const sales = 'M.SemanticModel/definition/tables/Sales.tmdl';
    for (const [what, call, host] of [
      ['CLI: an edit of the guard policy', cliCall(dir, 'edit', { path: 'hardening/hooks/lib/policy.mjs', old_str: 'x = 1', new_str: 'x = 2' }), 'copilot-cli'],
      ['CLI: an edit of the settings that holds the ask rules', cliCall(dir, 'edit', { path: '.claude/settings.json', old_str: '"note": 1', new_str: '"note": 2' }), 'copilot-cli'],
      ['CLI: a new hook file under .github', cliCall(dir, 'create', { path: '.github/hooks/bi-harness.copilot-cli.json', file_text: '{}' }), 'copilot-cli'],
      ['CLI: rm of a TMDL file', cliCall(dir, 'bash', { command: `rm ${sales}` }), 'copilot-cli'],
      ['CLI: an install', cliCall(dir, 'bash', { command: 'npm install left-pad' }), 'copilot-cli'],
      ['VS Code: Remove-Item in the terminal', vsCall('run_in_terminal', { command: `Remove-Item ${sales}`, explanation: 'x', goal: 'y', mode: 'sync' }), 'vscode'],
      ['CLI Claude registration: an edit of the guard policy', dialectCall('Edit', { file_path: path.join(dir, 'hardening', 'hooks', 'lib', 'policy.mjs'), old_string: 'x = 1', new_string: 'x = 2' }), null],
    ]) {
      const r = copilotPre(dir, host, call);
      assert.equal(r.decision, 'ask', what);
      assert.match(r.reason, /\(Critical: auto mode always asks for this\.\)$/, what);
    }
    assert.equal(copilotPre(dir, 'copilot-cli', cliCall(dir, 'bash', { command: 'git status' })).decision, 'allow');
    assert.equal(copilotPre(dir, 'vscode', vsCall('replace_string_in_file', { filePath: 'docs/notes.md', oldString: 'notes', newString: 'Notes' })).decision, 'allow');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

const PATCH_OF = (op, file) => ['*** Begin Patch', `*** ${op} File: ${file}`, '*** End Patch'].join('\n');
const HOSTS = [
  ['VS Code', 'vscode', (dir, input) => vsCall('apply_patch', { input, explanation: 'e' })],
  ['Copilot CLI', 'copilot-cli', (dir, input) => cliCall(dir, 'apply_patch', { input })],
  ['the CLI\'s Claude registration', null, (dir, input) => dialectCall('apply_patch', { input })],
];

test('copilot (F1-30): insert_edit_into_file asks where the guard compares Tier 2 facts, and a Delete File is judged as the file emptied, in every Copilot host', () => {
  const pbir = `${JSON.stringify({ version: '4.0', datasetReference: { byPath: { path: '../M.SemanticModel' } } })}\n`;
  const platform = `${JSON.stringify({ metadata: { type: 'SemanticModel', displayName: 'Sales' }, config: { version: '2.0', logicalId: '4f1c2d3e-0000-4000-8000-0000000000ff' } })}\n`;
  const dir = copilotProject({
    'M.Report/definition.pbir': pbir,
    'M.Report/definition/pages/p1/visuals/v1/visual.json': '{"name":"v1"}\n',
    'M.SemanticModel/.platform': platform,
    'M.SemanticModel/definition/relationships.tmdl': 'relationship r1\n\tfromColumn: Sales.CustomerId\n\ttoColumn: Customer.CustomerId\n',
  });
  try {
    const sales = path.join(dir, 'M.SemanticModel', 'definition', 'tables', 'Sales.tmdl');
    const insert = copilotPre(dir, 'vscode', vsCall('insert_edit_into_file', {
      filePath: sales, code: '\tpartition Sales = m\n\t\tmode: directQuery\n\t\tsource = Sql.Database("prod-sql01", "Sales")\n', explanation: 'x',
    }));
    assert.equal(insert.decision, 'ask', 'a partition switched to directQuery by an editor that names no place');
    assert.match(insert.reason, /The guard could not work out the edited text of M\.SemanticModel\/definition\/tables\/Sales\.tmdl/);
    // The other kinds the guard compares Tier 2 facts of ask the same way: a report's binding and a Fabric item's identity.
    for (const rel of ['M.Report/definition.pbir', 'M.SemanticModel/.platform']) {
      const r = copilotPre(dir, 'vscode', vsCall('insert_edit_into_file', { filePath: path.join(dir, ...rel.split('/')), code: '{}', explanation: 'x' }));
      assert.equal(r.decision, 'ask', rel);
      assert.match(r.reason, /The guard could not work out the edited text of /, rel);
    }
    // Where it compares nothing (a note, a visual of a report) an insertion at an unknown place gets no verdict, not even
    // auto mode's routine allow: the host's own flow decides and the PostToolUse check validates what was written.
    for (const rel of ['docs/notes.md', 'M.Report/definition/pages/p1/visuals/v1/visual.json']) {
      const r = copilotPre(dir, 'vscode', vsCall('insert_edit_into_file', { filePath: path.join(dir, ...rel.split('/')), code: 'more', explanation: 'x' }));
      assert.equal(r.decision, null, `${rel}: no verdict`);
    }
    // The known text of a note is still routine; an old text that is not in it is not.
    assert.equal(copilotPre(dir, 'vscode', vsCall('replace_string_in_file', { filePath: path.join(dir, 'docs', 'notes.md'), oldString: 'notes', newString: 'Notes' })).decision, 'allow');
    assert.equal(copilotPre(dir, 'vscode', vsCall('replace_string_in_file', { filePath: path.join(dir, 'docs', 'notes.md'), oldString: 'absent', newString: 'x' })).decision, null);
    const control = copilotPre(dir, 'vscode', vsCall('replace_string_in_file', { filePath: sales, oldString: 'mode: import', newString: 'mode: directQuery' }));
    assert.equal(control.decision, 'ask');
    assert.match(control.reason, /changes a storage mode/);
    for (const [host, hostName, build] of HOSTS) {
      const pre = (op, file) => copilotPre(dir, hostName, build(dir, PATCH_OF(op, file)));
      const table = pre('Delete', 'M.SemanticModel/definition/tables/Sales.tmdl');
      assert.equal(table.decision, 'ask', `${host}: a deleted table file`);
      assert.match(table.reason, /renames or removes model object\(s\): table sales, measure revenue/, host);
      assert.equal(pre('Delete', 'M.SemanticModel/definition/relationships.tmdl').decision, 'ask', `${host}: relationships.tmdl`);
      assert.match(pre('Delete', 'M.Report/definition.pbir').reason, /binding/, `${host}: the report's binding`);
      assert.match(pre('Delete', 'M.SemanticModel/.platform').reason, /identity of the Fabric item/, `${host}: the item identity`);
      assert.match(pre('Delete', 'hardening/hooks/lib/policy.mjs').reason, /steers the agent/, `${host}: a guard file`);
      assert.equal(pre('Delete', 'templates/t.md').decision, 'deny', `${host}: a reference`);
      // Routine deletions keep working: a visual of a report and a note are not Tier 2.
      for (const file of ['M.Report/definition/pages/p1/visuals/v1/visual.json', 'docs/notes.md']) {
        const r = pre('Delete', file);
        assert.equal(r.decision, 'allow', `${host}: ${file}`);
        assert.match(r.reason, /routine project file edit/, `${host}: ${file}`);
      }
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('copilot (F1-30): only the translation of a Delete File marks a deletion; a payload field cannot turn an edit into one', () => {
  const patch = ['*** Begin Patch', '*** Add File: docs/new.md', '+# New', '*** Update File: docs/a.md', '@@', '-a', '+b', '*** Delete File: docs/old.md', '*** End Patch'].join('\n');
  const out = calls('apply_patch', { input: patch, explanation: 'e' });
  assert.deepEqual(out.map((c) => [c.tool_name, c.host_delete]), [['Write', undefined], ['Edit', undefined], ['Edit', true]]);
  assert.deepEqual([out[2].tool_input.old_string, out[2].tool_input.new_string], ['', ''], 'the guard reads the file itself');
  const smuggled = toClaudeCalls({ hook_event_name: 'PreToolUse', tool_name: 'replace_string_in_file', host_delete: true, tool_input: { filePath: 'docs/a.md', oldString: 'a', newString: 'b' } }, { cfg, projectDir: root });
  assert.equal(smuggled[0].host_delete, undefined, 'a host_delete in a payload is dropped');
  const dir = copilotProject();
  try {
    const sales = path.join(dir, 'M.SemanticModel', 'definition', 'tables', 'Sales.tmdl');
    // Were the field taken from the payload, this edit would be judged as an emptied file and ask for the wrong reason, or pass unjudged.
    const mode = copilotPre(dir, 'vscode', vsCall('replace_string_in_file', { filePath: sales, oldString: 'mode: import', newString: 'mode: directQuery' }, { host_delete: true }));
    assert.match(mode.reason, /changes a storage mode/);
    const measure = copilotPre(dir, 'vscode', vsCall('replace_string_in_file', { filePath: sales, oldString: 'SUM(Sales[Amount])', newString: 'SUM(Sales[Net])' }, { host_delete: true }));
    assert.equal(measure.decision, 'allow', 'an ordinary edit is judged as an ordinary edit');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
