// GitHub Copilot CLI through the Claude registration (hardening/settings.hooks.json merged into .claude/settings*.json):
// the CLI runs the same hooks as Claude Code with Claude's field and tool names, its own argument shapes (`path`,
// `paths`, `old_str`, `new_str`, `file_text`), a `tool_result` on PostToolUse, a `timestamp` on every payload and no
// BI_HARNESS_HOST. Probed with Copilot CLI 1.0.94 on 2026-10-08 (lab D-72): the command string runs in PowerShell on
// Windows from the repository root, `${CLAUDE_PROJECT_DIR}` is not substituted (a quoted or inline command fails and
// the CLI then refuses every tool), a Claude-shaped deny is honoured, a masked result reaches the model only through
// `modifiedResult`. Claude Code 2.1.293 sends no `timestamp` (same probe), so that field tells the hosts apart.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { fromCopilotCli, isCopilotClaudeDialect, toClaudeDialectOutput } from '../hooks/lib/host-vscode.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const pack = path.join(here, '..');
const hooks = path.join(pack, 'hooks');

// Variables that point git at another repository, index or object store. A `git commit` hook that runs these tests
// exports GIT_INDEX_FILE (and GIT_DIR in some setups); the temporary repositories' git calls, the tests' and the hooks',
// run without them (as mcp-state.test.mjs does since F1-116).
const GIT_REPO_VARS = ['GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE', 'GIT_OBJECT_DIRECTORY', 'GIT_ALTERNATE_OBJECT_DIRECTORIES', 'GIT_COMMON_DIR', 'GIT_PREFIX'];

/** The environment without the host variable, the git repository variables and, when asked, without CLAUDE_PROJECT_DIR (the CLI exports it; Claude Code too). */
function envWithout(...names) {
  const drop = new Set([...names, ...GIT_REPO_VARS].map((n) => n.toLowerCase()));
  return Object.fromEntries(Object.entries(process.env).filter(([k]) => !drop.has(k.toLowerCase())));
}

/** Runs a hook as the CLI does through the Claude registration: no host variable, a PascalCase payload with a timestamp. */
function cli(script, dir, payload) {
  const r = spawnSync(process.execPath, [path.join(hooks, script)], {
    input: JSON.stringify({ hook_event_name: 'PreToolUse', session_id: 'cli-claude', timestamp: '2026-10-08T06:16:50.192Z', cwd: dir, ...payload }),
    env: { ...envWithout('BI_HARNESS_HOST'), CLAUDE_PROJECT_DIR: dir },
    encoding: 'utf8',
  });
  if (r.error) throw r.error;
  const out = r.stdout.trim() ? JSON.parse(r.stdout) : null;
  return { status: r.status, out, decision: out?.hookSpecificOutput?.permissionDecision ?? null, stderr: r.stderr, detail: `exit ${r.status}, stderr ${JSON.stringify(String(r.stderr).slice(0, 400))}` };
}
/** Asserts a verdict (or none: null) and shows the hook's exit code and stderr when it differs. */
const expectDecision = (r, decision, label) => assert.equal(r.decision, decision, `${label}: ${r.detail}`);

function project() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-cli-claude-'));
  fs.mkdirSync(path.join(dir, 'docs'), { recursive: true });
  fs.mkdirSync(path.join(dir, 'templates'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'docs', 'notes.md'), '# notes\n');
  fs.writeFileSync(path.join(dir, 'templates', 'house.md'), '# house\n');
  fs.writeFileSync(path.join(dir, '.env'), 'X=1\n');
  return dir;
}
const auditRows = (dir) => {
  const file = path.join(dir, '.claude', 'logs', 'tool-audit.jsonl');
  return fs.existsSync(file) ? fs.readFileSync(file, 'utf8').trim().split('\n').map((l) => JSON.parse(l)) : [];
};

test('the Claude dialect of the CLI is told apart by its timestamp; its tool_result becomes tool_response', () => {
  assert.equal(isCopilotClaudeDialect({ hook_event_name: 'PreToolUse', session_id: 's', timestamp: '2026-10-08T06:16:50.192Z', cwd: 'C:/x', tool_name: 'Read', tool_input: { path: 'a' } }), true);
  assert.equal(isCopilotClaudeDialect({ session_id: 's', transcript_path: 't', cwd: 'C:/x', permission_mode: 'default', hook_event_name: 'PreToolUse', tool_name: 'Read', tool_input: { file_path: 'a' }, tool_use_id: 'u' }), false, 'a Claude Code payload');
  assert.equal(fromCopilotCli({ tool_name: 'Bash', tool_result: { result_type: 'success', text_result_for_llm: 'text' } }).tool_response, 'text');
  assert.equal(fromCopilotCli({ tool_name: 'Bash', tool_response: 'claude' }).tool_response, 'claude', 'a Claude field is never overwritten');
  const masked = { hookSpecificOutput: { hookEventName: 'PostToolUse', updatedToolOutput: 'm', additionalContext: 'c' } };
  assert.deepEqual(toClaudeDialectOutput(masked), { ...masked, modifiedResult: { resultType: 'success', textResultForLlm: 'm' } });
  const deny = { hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: 'r' } };
  assert.equal(toClaudeDialectOutput(deny), deny, 'a decision keeps its one Claude shape');
  assert.equal(toClaudeDialectOutput(null), null);
});

test('the guard judges the CLI\'s Claude-dialect payloads without a host variable: file tools by shape, MCP names, shell', () => {
  const dir = project();
  try {
    const pre = (tool_name, tool_input) => cli('pre-tool-use.mjs', dir, { tool_name, tool_input });
    expectDecision(pre('Read', { path: path.join(dir, '.env') }), 'deny', 'view of a secret file');
    expectDecision(pre('Read', { path: path.join(dir, 'docs', 'notes.md'), view_range: [1, 2] }), null, 'a plain view gets no opinion');
    expectDecision(pre('Edit', { path: path.join(dir, 'templates', 'house.md'), old_str: 'house', new_str: 'x' }), 'deny', 'a reference folder');
    expectDecision(pre('Write', { path: path.join(dir, 'powerbi', 'X.Report', 'report.json'), file_text: '{}' }), 'deny', 'a Desktop-owned file');
    expectDecision(pre('Write', { path: path.join(dir, 'docs', 'new.md'), file_text: '# new\n' }), 'allow', 'a routine project write in auto mode');
    expectDecision(pre('Edit', { path: path.join(dir, 'docs', 'notes.md'), old_str: 'notes', new_str: 'Notes' }), 'allow', 'a routine project edit');
    expectDecision(pre('Grep', { pattern: 'x', paths: path.join(dir, 'docs'), output_mode: 'content', '-n': true }), null, 'a search inside the project');
    expectDecision(pre('Grep', { pattern: 'x', paths: [dir], glob: '**/*.pbix' }), 'deny', 'a data-file glob');
    // F1-11: every path of the CLI's `paths` list is judged, not only the first.
    expectDecision(pre('Grep', { pattern: 'x', paths: [path.join(dir, 'docs'), path.join(dir, '.env')] }), 'deny', 'a secret file as the second searched path');
    expectDecision(pre('Grep', { pattern: 'x', paths: [path.join(dir, '.env'), path.join(dir, 'docs')] }), 'deny', 'a secret file as the first searched path');
    expectDecision(pre('Grep', { pattern: 'x', paths: [path.join(dir, 'docs'), path.join(dir, 'templates')] }), null, 'two plain folders');
    expectDecision(pre('Glob', { pattern: '**/*.md' }), null, 'a file listing');
    expectDecision(pre('Bash', { command: 'cat .env', description: 'read it' }), 'deny', 'a shell read of a secret file');
    expectDecision(pre('Bash', { command: 'git status', description: 'state' }), 'allow', 'routine git');
    expectDecision(pre('powerbi-modeling-mcp-database_operations', { request: { operation: 'Deploy' } }), 'deny', 'the CLI\'s MCP naming');
    expectDecision(pre('powerbi-modeling-mcp-security_role_operations', { request: { operation: 'Update', members: ['a@example.com'] } }), 'deny', 'role members through the CLI\'s MCP naming');
    expectDecision(pre('sql', { query: 'select 1', description: 'todo' }), null, 'a tool without a policy');
    expectDecision(pre('frobnicate', { x: 1 }), null, 'an unknown tool');
    const rows = auditRows(dir).filter((r) => r.event === 'unmapped');
    assert.deepEqual(rows.map((r) => [r.tool, r.host]), [['frobnicate', 'copilot-claude']], 'only the unknown tool is logged, with the dialect as host');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('the masking hook reads tool_result and answers in both shapes, so the CLI replaces the result', () => {
  const dir = project();
  try {
    const fakeSecret = ['Pass', 'word=hunter2', 'fake', 'value;'].join(''); // built at run time: never a credential literal in a test
    const r = cli('post-tool-redact.mjs', dir, { hook_event_name: 'PostToolUse', tool_name: 'Bash', tool_input: { command: 'cat x', description: 'd' }, tool_result: { result_type: 'success', text_result_for_llm: fakeSecret } });
    assert.match(r.out?.hookSpecificOutput?.updatedToolOutput ?? '', /REDACTED/, r.detail);
    assert.match(r.out?.modifiedResult?.textResultForLlm ?? '', /REDACTED/, 'the shape the CLI honours (probe of 2026-10-08)');
    assert.equal(r.out.modifiedResult.resultType, 'success');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('a Claude Code payload (no timestamp) passes through untouched and is never logged as unmapped', () => {
  const dir = project();
  try {
    const claude = (payload) => {
      const r = spawnSync(process.execPath, [path.join(hooks, 'pre-tool-use.mjs')], {
        input: JSON.stringify({ session_id: 's', transcript_path: 't', cwd: dir, permission_mode: 'default', hook_event_name: 'PreToolUse', tool_use_id: 'u', ...payload }),
        env: { ...envWithout('BI_HARNESS_HOST'), CLAUDE_PROJECT_DIR: dir },
        encoding: 'utf8',
      });
      return r.stdout.trim() ? JSON.parse(r.stdout) : null;
    };
    assert.equal(claude({ tool_name: 'Read', tool_input: { file_path: path.join(dir, 'docs', 'notes.md') } }), null);
    assert.equal(claude({ tool_name: 'Write', tool_input: { file_path: path.join(dir, 'docs', 'x.md'), content: '# x\n' } })?.hookSpecificOutput?.permissionDecision, 'allow');
    assert.equal(claude({ tool_name: 'Read', tool_input: { file_path: path.join(dir, '.env') } })?.hookSpecificOutput?.permissionDecision, 'deny');
    assert.equal(claude({ tool_name: 'WebFetch', tool_input: { url: 'https://example.com' } }), null);
    assert.deepEqual(auditRows(dir).filter((r) => r.event === 'unmapped'), []);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('settings.hooks.json registers every hook as the plain repo-relative shell string both hosts run', () => {
  const file = JSON.parse(fs.readFileSync(path.join(pack, 'settings.hooks.json'), 'utf8'));
  const commands = [];
  for (const [event, groups] of Object.entries(file.hooks)) {
    for (const group of groups) {
      for (const h of group.hooks) {
        assert.equal(h.type, 'command', event);
        assert.equal(h.args, undefined, `${event}: no exec form (Copilot CLI ignores args and runs the command as a shell string)`);
        assert.match(h.command, /^node hardening\/hooks\/[a-z-]+\.mjs$/, `${event}: ${h.command}`);
        assert.ok(fs.existsSync(path.join(pack, '..', h.command.slice(5))), `${event}: ${h.command} exists`);
        commands.push(h.command);
      }
    }
  }
  assert.ok(commands.includes('node hardening/hooks/pre-tool-use.mjs'));
  assert.ok(file.hooks.PreToolUse.some((g) => g.matcher === 'mcp__.*|.*-mcp-.*'), 'MCP tools in Claude\'s and the CLI\'s naming reach the guard');
  assert.ok(file.hooks.PostToolUse.some((g) => /-mcp-/.test(g.matcher ?? '')), 'and the masking hook');
});

/** Shells on this machine that can run the registered command string, each tried once with `true`/`exit 0`. */
function shells() {
  const found = [];
  for (const [name, args] of [['bash', ['-c', 'exit 0']], ['pwsh', ['-NoProfile', '-Command', 'exit 0']], ['powershell', ['-NoProfile', '-Command', 'exit 0']]]) {
    const r = spawnSync(name, args, { encoding: 'utf8', windowsHide: true });
    if (!r.error && r.status === 0) found.push(name);
  }
  return found;
}

test('the registered guard command runs from a project copy in bash and PowerShell, with and without CLAUDE_PROJECT_DIR', (t) => {
  const available = shells();
  if (!available.length) return t.skip('no bash, pwsh or powershell on PATH');
  const dir = project();
  try {
    // A project with the pack installed: the hook scripts and their imports, as the installer lays them out.
    for (const folder of ['hooks', 'scripts']) fs.cpSync(path.join(pack, folder), path.join(dir, 'hardening', folder), { recursive: true });
    const registration = JSON.parse(fs.readFileSync(path.join(pack, 'settings.hooks.json'), 'utf8'));
    const command = registration.hooks.PreToolUse[0].hooks[0].command;
    const payload = JSON.stringify({ hook_event_name: 'PreToolUse', session_id: 'x', timestamp: '2026-10-08T06:16:50.192Z', cwd: dir, tool_name: 'Bash', tool_input: { command: 'git push --force origin main', description: 'd' } });
    const problems = [];
    for (const shell of available) {
      const args = shell === 'bash' ? ['-c', command] : ['-NoProfile', '-Command', command];
      for (const [label, env] of [['without CLAUDE_PROJECT_DIR (Copilot CLI)', envWithout('BI_HARNESS_HOST', 'CLAUDE_PROJECT_DIR')], ['with CLAUDE_PROJECT_DIR (Claude Code)', { ...envWithout('BI_HARNESS_HOST'), CLAUDE_PROJECT_DIR: dir }]]) {
        const r = spawnSync(shell, args, { input: payload, cwd: dir, env, encoding: 'utf8', windowsHide: true, timeout: 60000 });
        let decision = null;
        try { decision = JSON.parse(r.stdout.trim()).hookSpecificOutput?.permissionDecision ?? null; } catch { decision = null; }
        if (decision !== 'deny') problems.push(`${shell} ${label}: exit ${r.status}, stdout ${JSON.stringify(r.stdout.slice(0, 200))}, stderr ${JSON.stringify(r.stderr.slice(0, 300))}`);
      }
    }
    assert.deepEqual(problems, []);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------- audit 2026-10-18: text arguments, the Stop block, masked searches

test('tool_input that arrives as text gets the verdict of the object form, and text that is no JSON object asks (F1-13)', () => {
  const dir = project();
  try {
    const pre = (tool_name, tool_input) => cli('pre-tool-use.mjs', dir, { tool_name, tool_input });
    const patch = ['*** Begin Patch', '*** Update File: templates/house.md', '@@', '-a', '+b', '*** End Patch'].join('\n');
    expectDecision(pre('Edit', { input: patch }), 'deny', 'the object form of an apply_patch call');
    expectDecision(pre('Edit', patch), 'deny', 'a bare apply_patch text names a file in a reference folder');
    expectDecision(pre('Bash', JSON.stringify({ command: 'cat .env', description: 'read it' })), 'deny', 'a shell read of a secret file as a JSON string');
    expectDecision(pre('Bash', JSON.stringify({ command: 'git status', description: 'state' })), 'allow', 'routine git as a JSON string');
    expectDecision(pre('powerbi-modeling-mcp-database_operations', JSON.stringify({ request: { operation: 'Deploy' } })), 'deny', 'an MCP call as a JSON string');
    const unreadable = pre('Bash', 'cat .env');
    expectDecision(unreadable, 'ask', 'text that is no JSON object is never silence');
    assert.match(unreadable.out.hookSpecificOutput.permissionDecisionReason, /^\[bi-harness\] The guard could not read the arguments of Bash /);
    expectDecision(pre('powerbi-modeling-mcp-database_operations', 'Deploy'), 'ask', 'an MCP call whose arguments cannot be read');
    expectDecision(pre('sql', 'select 1'), null, 'a tool without a policy has no opinion, whatever it was sent');
    const rows = auditRows(dir).filter((r) => r.event === 'unmapped');
    assert.deepEqual(rows.map((r) => [r.tool, r.host, r.inputKeys]), [['Bash', 'copilot-claude', []], ['powerbi-modeling-mcp-database_operations', 'copilot-claude', []]],
      'the unreadable calls are logged without the character indexes of the text');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('a Stop gate block and a PostToolUse block keep Claude\'s own shape under the Claude registration (F1-55)', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-cli-claude-stop-'));
  try {
    spawnSync('git', ['init', '-q'], { cwd: dir, env: envWithout() });
    fs.appendFileSync(path.join(dir, '.git', 'info', 'exclude'), '\n.claude/logs/\n');
    fs.mkdirSync(path.join(dir, 'docs'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'docs', 'big.md'), Array.from({ length: 501 }, (_, i) => `line ${i}`).join('\n'));
    const stop = cli('stop-gate.mjs', dir, { hook_event_name: 'Stop', session_id: 'stop-claude', stop_hook_active: false });
    assert.equal(stop.out?.decision, 'block', stop.detail);
    assert.match(stop.out.reason, /501 lines/);
    assert.equal(stop.out.hookSpecificOutput, undefined, 'top level, as the CLI reads the Claude dialect');
    assert.equal(stop.out.additionalContext, undefined);
    const wrote = cli('post-tool-validate.mjs', dir, { hook_event_name: 'PostToolUse', tool_name: 'Write', tool_input: { path: path.join(dir, 'docs', 'big.md'), file_text: 'x' }, tool_result: { result_type: 'success', text_result_for_llm: 'ok' } });
    assert.equal(wrote.out?.decision, 'block', wrote.detail);
    assert.match(wrote.out.reason, /501 lines/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('the masked output of a search over several paths reaches the CLI: PostToolUse keeps one call (F1-11)', () => {
  const dir = project();
  try {
    const fakeSecret = ['Pass', 'word=hunter2', 'fake', 'value;'].join(''); // built at run time: never a credential literal in a test
    const r = cli('post-tool-redact.mjs', dir, {
      hook_event_name: 'PostToolUse', tool_name: 'Grep', tool_input: { pattern: 'x', paths: [path.join(dir, 'docs'), path.join(dir, 'templates')] },
      tool_result: { result_type: 'success', text_result_for_llm: fakeSecret },
    });
    assert.match(r.out?.hookSpecificOutput?.updatedToolOutput ?? '', /REDACTED/, r.detail);
    assert.match(r.out?.modifiedResult?.textResultForLlm ?? '', /REDACTED/, 'the shape the CLI honours');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
