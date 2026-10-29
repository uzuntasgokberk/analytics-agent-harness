// GitHub Copilot CLI tools as GitHub documents them (hooks/lib/host-vscode.mjs). The tool NAMES come from GitHub's hooks
// reference (2026-10-17: the CLI's own runtime names and the names of its Claude-format table). The reference documents
// no argument schemas, so the shapes are the ones host-vscode.mjs recognises (`command`, `path`, `paths`, `old_str`,
// `new_str` and `file_text` from the logged CLI session of 2026-10-07, the rest the harness's own shape mapping), and the
// expected tools are the harness's shape-based verdicts (an Add-File patch or a `create` is a Write where GitHub's table
// says Edit). Every name the reference lists is locked to a Claude call or to a deliberate pass-through (no verdict, no
// `unmapped` row), so a renamed or new documented tool shows up here; the Claude-dialect names (`Bash`, `Edit`, ...) are
// covered by copilot-claude-dialect.test.mjs.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { fromCopilotCli, toClaudeCalls } from '../hooks/lib/host-vscode.mjs';

const cfg = { mcp: { powerbiServer: 'powerbi-modeling' } };
const root = os.platform() === 'win32' ? 'C:\\repo' : '/repo';
const file = path.join(root, 'docs', 'a.md');
const calls = (tool_name, tool_input) => toClaudeCalls({ hook_event_name: 'PreToolUse', tool_name, tool_input }, { cfg, projectDir: root });

test('copilot cli: every documented file, shell and web tool becomes the Claude call the policy knows', () => {
  const cases = [
    ['bash', { command: 'git status' }, 'Bash'],
    ['powershell', { command: 'git status' }, 'Bash'],
    ['view', { path: file }, 'Read'],
    ['create', { path: file, file_text: '# x' }, 'Write'],
    ['edit', { path: file, old_str: 'a', new_str: 'b' }, 'Edit'],
    ['grep', { pattern: 'x', paths: [root] }, 'Grep'],
    ['rg', { pattern: 'x', paths: [root] }, 'Grep'],
    ['glob', { pattern: '**/*.tmdl' }, 'Glob'],
    ['web_fetch', { url: 'https://example.com' }, 'WebFetch'],
    ['str_replace_editor', { command: 'view', path: file }, 'Read'],
    ['str_replace_editor', { command: 'str_replace', path: file, old_str: 'a', new_str: 'b' }, 'Edit'],
    ['str_replace_editor', { command: 'create', path: file, file_text: 'x' }, 'Write'],
    ['apply_patch', { input: '*** Begin Patch\n*** Add File: docs/a.md\n+x\n*** End Patch' }, 'Write'],
  ];
  for (const [name, input, expected] of cases) {
    const label = name === 'str_replace_editor' ? `${name} (${input.command})` : name;
    const out = calls(name, input);
    assert.deepEqual(out.map((c) => c.tool_name), [expected], label);
    // The guard decides by path: a mapping that kept the tool but dropped the file would still pass the line above.
    if ('path' in input || name === 'apply_patch') assert.equal(out[0].tool_input.file_path, file, `${label}: file_path`);
  }
  const camel = toClaudeCalls(fromCopilotCli({ toolName: 'view', toolArgs: { path: file } }), { cfg, projectDir: root });
  assert.deepEqual(camel.map((c) => c.tool_name), ['Read'], 'view (camelCase payload through fromCopilotCli)');
});

test('copilot cli: documented tools without a policy of their own pass through unchanged and are not logged as unmapped', () => {
  const cases = [
    ['ask_user', { question: 'q' }],
    ['task', { prompt: 'p' }],
    ['web_search', { query: 'q' }],
    ['update_todo', { todos: [] }],
  ];
  for (const [name, input] of cases) {
    const out = calls(name, input);
    assert.equal(out.length, 1, name);
    assert.equal(out[0].tool_name, name, name);
    assert.deepEqual(out[0].tool_input, input, name);
    assert.notEqual(out[0].unmapped, true, name);
  }
});
