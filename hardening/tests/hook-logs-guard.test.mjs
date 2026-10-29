// The hooks' own logs and session state (.claude/logs/) are written only by the hooks. The session state is a control
// since the ask-once record (hooks/lib/ask-once.mjs) and the confirmed MCP connections (hooks/lib/mcp-state.mjs) live
// there: an independent review (2026-10-28, review-work e1/e2) forged an ask-once record from the shell, which the guard
// gave no verdict on, and all three Copilot copies of the next ask stayed silent. Shell writes, in-place edits, copies,
// moves and deletes under .claude/logs/ are denied like the guardrail files (GUARD_PATH_RE in policy.mjs), and so are
// Edit, Write and NotebookEdit (HOOK_LOGS_RE in guard-pre-tool-use.mjs); reading the logs stays open.
import { after, test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyzeShellCommand } from '../hooks/lib/policy.mjs';

const preHook = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'hooks', 'pre-tool-use.mjs');
const GUARDRAIL = /Harness guardrail files \(.*\.claude\/logs\/.*cannot be changed from the shell|Deleting harness or git metadata/;
const temps = [];
after(() => temps.forEach((dir) => fs.rmSync(dir, { recursive: true, force: true })));
function project() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-logs-guard-'));
  temps.push(dir);
  spawnSync('git', ['init', '-q'], { cwd: dir, encoding: 'utf8' });
  fs.mkdirSync(path.join(dir, '.claude', 'logs', '.state'), { recursive: true });
  fs.writeFileSync(path.join(dir, '.claude', 'logs', 'tool-audit.jsonl'), '{"event":"PostToolUse"}\n');
  fs.writeFileSync(path.join(dir, '.claude', 'logs', '.state', 's1.json'), '{}');
  fs.mkdirSync(path.join(dir, 'docs'), { recursive: true });
  return dir;
}
/** The guard's verdict as a process: `copy` claude (a Claude Code payload) or copilot-cli (the CLI's camelCase payload). */
function hook(dir, copy, tool, input) {
  const env = { ...process.env, CLAUDE_PROJECT_DIR: dir };
  delete env.BI_HARNESS_HOST;
  delete env.COPILOT_CLI;
  const payload = copy === 'copilot-cli'
    ? { sessionId: 's1', timestamp: 1793181600123, cwd: dir, toolName: tool, toolArgs: input }
    : { hook_event_name: 'PreToolUse', session_id: 's1', cwd: dir, permission_mode: 'default', tool_name: tool, tool_input: input, tool_use_id: 'u1' };
  if (copy === 'copilot-cli') Object.assign(env, { BI_HARNESS_HOST: 'copilot-cli', COPILOT_CLI: '1' });
  const r = spawnSync(process.execPath, [preHook], { input: JSON.stringify(payload), env, encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
  const out = r.stdout.trim() ? JSON.parse(r.stdout) : null;
  const d = out?.hookSpecificOutput ?? out;
  return { decision: d?.permissionDecision ?? null, reason: d?.permissionDecisionReason ?? '' };
}

// The reviewer's forms (review-work e1) first, then the other writers the guardrail rule knows.
const WRITES = [
  `echo '{"askCopies":{}}' > .claude/logs/.state/abc.json`,
  `Set-Content -Path .claude/logs/.state/abc.json -Value '{}'`,
  `node -e "require('fs').writeFileSync('.claude/logs/.state/abc.json','{}')"`,
  `printf '{}' | tee .claude/logs/.state/abc.json`,
  'rm .claude/logs/.state/abc.json',
  'cp x.json .claude/logs/.state/abc.json',
  `python -c "open('.claude/logs/.state/abc.json','w').write('{}')"`,
  'echo x >> .claude/logs/security-events.jsonl',
  'echo x 2> .claude/logs/tool-audit.jsonl',
  'Add-Content .claude/logs/security-events.jsonl x',
  "'{}' | Out-File .claude\\logs\\.state\\abc.json",
  'Copy-Item x.json .claude\\logs\\.state\\abc.json',
  'mv x.json .claude/logs/.state/abc.json',
  'mv .claude/logs/security-events.jsonl old.jsonl',
  "sed -i 's/ask/allow/' .claude/logs/.state/s1.json",
  "perl -pi -e 's/ask/allow/' .claude/logs/.state/s1.json",
  'Remove-Item .claude/logs -Recurse',
  'rm -rf .claude/logs',
  'ls .claude/logs/.state | xargs rm',
  'Get-ChildItem .claude/logs | Remove-Item',
];

test('every shell write, in-place edit, copy, move and delete under .claude/logs/ is denied', () => {
  for (const cmd of WRITES) {
    const v = analyzeShellCommand(cmd);
    assert.equal(v?.decision, 'deny', cmd);
    assert.match(v.reason, GUARDRAIL, `${cmd}: ${v.reason}`);
  }
});

test('reading the logs stays open, and other folders named logs are not the hooks\' logs', () => {
  for (const cmd of ['cat .claude/logs/tool-audit.jsonl', 'tail -n 3 .claude/logs/security-events.jsonl', 'Get-Content .claude/logs/tool-audit.jsonl -Tail 3',
    `grep '"decision":"ask"' .claude/logs/security-events.jsonl`, 'Select-String -Path .claude/logs/security-events.jsonl -Pattern repeat', 'ls .claude/logs',
    'wc -l .claude/logs/tool-audit.jsonl', 'Get-ChildItem .claude/logs/.state']) {
    assert.notEqual(analyzeShellCommand(cmd)?.decision, 'deny', cmd);
  }
  for (const cmd of [`echo '{}' > .claude/logs2/x.json`, `echo '{}' > docs/logs/x.json`, 'cp x.json docs/logs/x.json', `node -e "require('fs').writeFileSync('docs/logs/x.json','{}')"`]) {
    const v = analyzeShellCommand(cmd);
    assert.doesNotMatch(v?.reason ?? '', GUARDRAIL, cmd);
    assert.notEqual(v?.decision, 'deny', cmd);
  }
});

test('the guard process denies the forged record in Claude Code and in the Copilot CLI copy; a read passes', () => {
  const dir = project();
  const forge = `echo '{"askCopies":{}}' > .claude/logs/.state/s1.json`;
  for (const [copy, tool] of [['claude', 'Bash'], ['copilot-cli', 'powershell'], ['copilot-cli', 'bash']]) {
    const r = hook(dir, copy, tool, { command: forge });
    assert.equal(r.decision, 'deny', `${copy} ${tool}`);
    assert.match(r.reason, GUARDRAIL);
    assert.notEqual(hook(dir, copy, tool, { command: 'cat .claude/logs/tool-audit.jsonl' }).decision, 'deny', `${copy}: a read`);
  }
  assert.equal(fs.readFileSync(path.join(dir, '.claude', 'logs', '.state', 's1.json'), 'utf8'), '{}', 'nothing was written');
});

test('Edit, Write and NotebookEdit under .claude/logs/ are denied in every dialect; elsewhere they keep their verdict', () => {
  const dir = project();
  const at = (...p) => path.join(dir, ...p);
  for (const [tool, input] of [
    ['Write', { file_path: at('.claude', 'logs', '.state', 'abc.json'), content: '{}' }],
    ['Write', { file_path: '.claude/logs/.state/abc.json', content: '{}' }],
    ['Edit', { file_path: at('.claude', 'logs', '.state', 's1.json'), old_string: '{}', new_string: '{"askCopies":{}}' }],
    ['Edit', { file_path: at('.claude', 'logs', 'tool-audit.jsonl'), old_string: 'PostToolUse', new_string: 'x' }],
    ['NotebookEdit', { notebook_path: at('.claude', 'logs', 'x.ipynb'), new_source: 'x' }],
  ]) {
    const r = hook(dir, 'claude', tool, input);
    assert.equal(r.decision, 'deny', `${tool} ${JSON.stringify(input).slice(0, 80)}`);
    assert.match(r.reason, /is in \.claude\/logs\/, the hooks' own logs and session state/);
  }
  // Copilot CLI's own file tools and a patch that deletes a log.
  for (const [tool, input] of [
    ['create', { path: '.claude/logs/.state/abc.json', file_text: '{}' }],
    ['edit', { path: '.claude/logs/.state/s1.json', old_str: '{}', new_str: '{"askCopies":{}}' }],
    ['apply_patch', { input: ['*** Begin Patch', '*** Delete File: .claude/logs/tool-audit.jsonl', '*** End Patch'].join('\n') }],
  ]) {
    assert.equal(hook(dir, 'copilot-cli', tool, input).decision, 'deny', tool);
  }
  // Reading the logs passes; a file elsewhere keeps its verdict (another .claude folder asks as a critical file, a note is routine).
  assert.notEqual(hook(dir, 'claude', 'Read', { file_path: at('.claude', 'logs', 'tool-audit.jsonl') }).decision, 'deny');
  assert.notEqual(hook(dir, 'copilot-cli', 'view', { path: '.claude/logs/tool-audit.jsonl' }).decision, 'deny');
  assert.equal(hook(dir, 'claude', 'Write', { file_path: at('.claude', 'logs2', 'x.json'), content: '{}' }).decision, 'ask');
  assert.equal(hook(dir, 'claude', 'Write', { file_path: at('docs', 'logs', 'x.md'), content: '# x\n' }).decision, 'allow');
});
