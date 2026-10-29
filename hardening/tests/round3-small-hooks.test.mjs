// The small hooks, follow-up audit round 3: the deploy reminder's wording (F2-16) and where it reaches under Copilot
// (F2-55), the Stop gate on a reviewer's SubagentStop under VS Code (F2-17), one session fallback for every Copilot event
// (F2-18), the banner and masking notice when VS Code runs the Copilot CLI hook file, and the warning for a failed call
// whose error holds a secret (PostToolUseFailure). Every hook runs in a temp project; fake secrets are built at run time.
// The Copilot payloads follow GitHub's hooks reference and VS Code's hooks reference (both read 2026-10-19); not run
// inside Copilot CLI, VS Code or Claude Code.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const hooks = path.join(here, '..', 'hooks');
const ISO = '2026-10-19T08:00:00.000Z';
const fakeToken = () => ['gh', 'p_'].join('') + 'B7'.repeat(18);

/** Environment without the repository variables an outer git (a hook, a worktree) may set. */
function cleanEnv(extra = {}) {
  const env = { ...process.env, ...extra };
  for (const k of Object.keys(env)) if (/^GIT_/.test(k)) delete env[k];
  delete env.BI_HARNESS_HOST;
  return env;
}

/** A temp project holding `files`; `git` makes it a repository with one empty commit. */
function project(files = {}, { git = false } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-r3s-'));
  if (git) {
    const g = (...args) => spawnSync('git', args, { cwd: dir, env: cleanEnv(), encoding: 'utf8' });
    g('init', '-q');
    g('-c', 'user.name=t', '-c', 'user.email=t@example.com', 'commit', '-q', '--allow-empty', '-m', 'init');
  }
  for (const [rel, text] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), text);
  }
  return dir;
}

/** Runs a hook in `dir` with `payload` on stdin; `host` sets BI_HARNESS_HOST. */
function run(script, dir, payload, { host } = {}) {
  const env = cleanEnv({ CLAUDE_PROJECT_DIR: dir });
  if (host) env.BI_HARNESS_HOST = host;
  const r = spawnSync(process.execPath, [path.join(hooks, script)], { cwd: dir, input: JSON.stringify(payload), env, encoding: 'utf8' });
  if (r.error) throw r.error;
  assert.doesNotMatch(r.stderr, /hook error/, `${script}: ${r.stderr}`);
  return { status: r.status, stdout: r.stdout, out: r.stdout.trim() ? JSON.parse(r.stdout) : null };
}

const rows = (dir, name) => {
  const file = path.join(dir, '.claude', 'logs', name);
  return fs.existsSync(file) ? fs.readFileSync(file, 'utf8').trim().split('\n').map((l) => JSON.parse(l)) : [];
};
const context = (out) => out?.hookSpecificOutput?.additionalContext ?? out?.additionalContext ?? '';

// ------------------------------------------------------------------------------------------------ deploy reminder

test('the deploy reminder says deployment and publishing are never the agent\'s, never that they are Tier 2 (F2-16)', () => {
  const dir = project();
  try {
    const r = run('user-prompt-guard.mjs', dir, { hook_event_name: 'UserPromptSubmit', session_id: 'r3s-1', prompt: 'publish this report to production' });
    const text = context(r.out);
    assert.match(text, /deployment and publishing are never the agent's/);
    assert.match(text, /hand the user the steps/);
    assert.doesNotMatch(text, /deploy\/publish[^.]*Tier 2/, 'deploy and publish are not called Tier 2');
    assert.equal(r.out.systemMessage, undefined, 'Claude Code: the model gets it, no message for the user');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('under VS Code the deploy reminder also goes out as a systemMessage, the field VS Code documents for the event (F2-55)', () => {
  const dir = project();
  try {
    const vscode = run('user-prompt-guard.mjs', dir, { hook_event_name: 'UserPromptSubmit', session_id: 'r3s-2', timestamp: ISO, cwd: '.', prompt: 'deploy the Sales model to production' }, { host: 'vscode' });
    assert.match(vscode.out.systemMessage, /deployment and publishing are never the agent's/);
    assert.match(vscode.out.systemMessage, /cannot add it to the model's context/);
    // The Claude registration run by a Copilot host (a timestamp, no host variable) says the same.
    const dialect = run('user-prompt-guard.mjs', dir, { hook_event_name: 'UserPromptSubmit', session_id: 'r3s-3', timestamp: ISO, prompt: 'deploy it' });
    assert.match(dialect.out.systemMessage, /never the agent's/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ------------------------------------------------------------------------------------------------ Stop gate

const subagentStop = (agentType, n) => ({
  hook_event_name: 'SubagentStop', session_id: `r3s-sub-${n}`, timestamp: `2026-10-19T08:00:0${n}.000Z`, cwd: '.', agent_id: `ag-${n}`, agent_type: agentType, stop_hook_active: false,
});

test('under VS Code a reviewer\'s SubagentStop is not gated; an editor\'s still is (F2-17)', () => {
  const dir = project({ '_probe/broken.json': '{ "a": 1,, }\n' }, { git: true });
  try {
    const reviewer = run('stop-gate.mjs', dir, subagentStop('bi-dax-reviewer', 1), { host: 'vscode' });
    assert.equal(reviewer.out, null, 'a read-only reviewer is never sent back to fix files it may not edit');
    const editor = run('stop-gate.mjs', dir, subagentStop('bi-tmdl-modeler', 2), { host: 'vscode' });
    assert.equal(editor.out.decision, 'block');
    assert.match(editor.out.reason, /broken\.json/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('the Stop gate\'s editor list is the SubagentStop matcher of the Claude registration (F2-17)', () => {
  const source = fs.readFileSync(path.join(hooks, 'stop-gate.mjs'), 'utf8');
  const list = /const STOP_GATED_SUBAGENTS = \[([^\]]*)\]/.exec(source);
  assert.ok(list, 'stop-gate.mjs names its list');
  const names = [...list[1].matchAll(/'([^']+)'/g)].map((m) => m[1]).sort();
  const settings = JSON.parse(fs.readFileSync(path.join(here, '..', 'settings.hooks.json'), 'utf8'));
  const gate = settings.hooks.SubagentStop.find((g) => g.hooks.some((h) => h.command === 'node hardening/hooks/stop-gate.mjs'));
  assert.deepEqual(gate.matcher.split('|').sort(), names);
});

test('a VS Code session without a session id: the Stop gate sees the MCP write the tool hook recorded (F2-18)', () => {
  const dir = project({}, { git: true });
  try {
    run('post-tool-redact.mjs', dir, {
      hook_event_name: 'PostToolUse', timestamp: ISO, cwd: '.', tool_name: 'mcp_powerbi-model_measure_operations', tool_use_id: 'u1',
      tool_input: { request: { operation: 'Create', connectionName: 'PBIDesktop-Sales-1234', definitions: [{ name: 'Total Sales', tableName: 'Sales', expression: 'SUM(Sales[Amount])' }] } },
      tool_response: '{"success":true}',
    }, { host: 'vscode' });
    const stop = run('stop-gate.mjs', dir, { hook_event_name: 'Stop', timestamp: '2026-10-19T08:00:05.000Z', cwd: '.', stop_hook_active: false }, { host: 'vscode' });
    const block = stop.out?.hookSpecificOutput ?? stop.out;
    assert.equal(block?.decision, 'block', JSON.stringify(stop.out));
    assert.match(block.reason, /MCP write/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ------------------------------------------------------------------------------------------------ VS Code runs the CLI's file

test('VS Code running the Copilot CLI hook file is named VS Code in the banner; the CLI\'s own payload stays the CLI', () => {
  const dir = project();
  try {
    const vscode = run('session-start.mjs', dir, { hook_event_name: 'SessionStart', session_id: 'r3s-ss-1', timestamp: ISO, cwd: '.', source: 'startup' }, { host: 'copilot-cli' });
    assert.match(context(vscode.out), /- Host: VS Code Copilot \(through the Copilot CLI hook file\) hooks\./);
    assert.match(context(vscode.out), /Output masking is a warning/);
    const cli = run('session-start.mjs', dir, { sessionId: 'r3s-ss-2', timestamp: 1760860800000, cwd: '.', source: 'startup' }, { host: 'copilot-cli' });
    assert.match(context(cli.out), /- Host: GitHub Copilot CLI hooks\./);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('the masking notice under the Copilot CLI hook file warns when VS Code sent the payload, and says redacted for the CLI', () => {
  const dir = project();
  try {
    const output = `token ${fakeToken()} found`;
    const vscode = run('post-tool-redact.mjs', dir, { hook_event_name: 'PostToolUse', session_id: 'r3s-m-1', timestamp: ISO, cwd: '.', tool_name: 'Bash', tool_input: { command: 'cat x' }, tool_response: { stdout: output } }, { host: 'copilot-cli' });
    assert.match(context(vscode.out), /may be visible to you unmasked/);
    const cli = run('post-tool-redact.mjs', dir, { sessionId: 'r3s-m-2', timestamp: 1760860800000, cwd: '.', toolName: 'bash', toolArgs: { command: 'cat x' }, toolResult: { textResultForLlm: output } }, { host: 'copilot-cli' });
    assert.match(context(cli.out), /were redacted/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ------------------------------------------------------------------------------------------------ PostToolUseFailure

test('a failed call whose error holds a secret gets a warning, never the value; a clean error gets nothing', () => {
  const dir = project();
  try {
    const token = fakeToken();
    const failed = run('post-tool-redact.mjs', dir, {
      hook_event_name: 'PostToolUseFailure', session_id: 'r3s-f-1', tool_name: 'Bash', tool_input: { command: 'gh api /user' }, tool_use_id: 't1',
      error: `HTTP 401: bad credentials for ${token}`,
    });
    assert.equal(failed.out.hookSpecificOutput.hookEventName, 'PostToolUseFailure');
    assert.match(failed.out.hookSpecificOutput.additionalContext, /error of this Bash call contained 1 sensitive value\(s\) \(github-token\)/);
    assert.match(failed.out.hookSpecificOutput.additionalContext, /may be visible to you unmasked/);
    assert.ok(!failed.stdout.includes(token), 'the hook never repeats the value');
    const events = rows(dir, 'security-events.jsonl');
    assert.deepEqual(events.map((e) => [e.event, e.tool, e.ids]), [['sensitive-error', 'Bash', ['github-token']]]);
    assert.ok(!JSON.stringify(events).includes(token));
    const clean = run('post-tool-redact.mjs', dir, { hook_event_name: 'PostToolUseFailure', session_id: 'r3s-f-2', tool_name: 'Bash', tool_input: { command: 'ls' }, error: 'exit code 2' });
    assert.equal(clean.out, null);
    // Copilot CLI's postToolUseFailure payload names no event: an error and no result.
    const cli = run('post-tool-redact.mjs', dir, { sessionId: 'r3s-f-3', timestamp: 1760860800000, cwd: '.', toolName: 'bash', toolArgs: { command: 'gh api /user' }, error: `401 for ${token}` }, { host: 'copilot-cli' });
    assert.match(cli.out.additionalContext, /sensitive value\(s\) \(github-token\)/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('the masking hook is registered for failed calls in the Claude registration and the Copilot CLI hook file', () => {
  const settings = JSON.parse(fs.readFileSync(path.join(here, '..', 'settings.hooks.json'), 'utf8'));
  const group = settings.hooks.PostToolUseFailure.find((g) => g.hooks.some((h) => h.command === 'node hardening/hooks/post-tool-redact.mjs'));
  assert.ok(group, 'PostToolUseFailure runs post-tool-redact.mjs');
  for (const tool of ['Read', 'Grep', 'Bash', 'PowerShell', 'WebFetch', 'mcp__sql__query', 'sql-mcp-query']) {
    assert.match(tool, new RegExp(`^(?:${group.matcher})$`), tool);
  }
  const cli = JSON.parse(fs.readFileSync(path.join(here, '..', 'copilot-cli.hooks.json'), 'utf8'));
  const commands = (cli.hooks.postToolUseFailure ?? []).map((h) => [h.bash, h.powershell]);
  assert.deepEqual(commands, [
    ['node hardening/hooks/post-tool-redact.mjs', 'node hardening/hooks/post-tool-redact.mjs'],
    ['node hardening/hooks/audit-log.mjs', 'node hardening/hooks/audit-log.mjs'],
  ]);
});
