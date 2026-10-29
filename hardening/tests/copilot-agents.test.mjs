// GitHub Copilot reads .claude/agents/*.md too, but it hands a subagent only the tools it can map from the file's `tools:`
// list. In the owner's lab (GitHub Copilot app, 2026-10-22) bi-pbir-editor answered twice that it had only view, grep and
// glob, although GitHub's alias table lists Edit, Write and Bash as compatible aliases of its edit and execute tools. Each
// editor therefore has a .github/agents/<name>.agent.md with the Copilot spellings (the CLI keeps that file when two files
// share a name). This test keeps the copies in step with the Claude files: every agent that can write has one, a read-only
// reviewer has none (it worked in the lab), and every tool name a copy lists is one GitHub or VS Code documents or one the
// hooks translate (copilot-documented-tools.test.mjs).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { toClaudeCalls } from '../hooks/lib/host-vscode.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const claudeDir = path.join(root, '.claude', 'agents');
const copilotDir = path.join(root, '.github', 'agents');

/** The frontmatter of an agent file: scalars by key, and `tools` as a list whether it is comma-separated, a flow list or a block list. */
function parse(file) {
  const text = fs.readFileSync(file, 'utf8');
  const m = /^---\r?\n([\s\S]*?)\r?\n---\r?\n?([\s\S]*)$/.exec(text);
  assert.ok(m, `${path.basename(file)} has a frontmatter`);
  const lines = m[1].split(/\r?\n/);
  const out = { body: m[2], scalars: {}, tools: null };
  for (let i = 0; i < lines.length; i++) {
    const kv = /^([A-Za-z][\w-]*):\s*(.*)$/.exec(lines[i]);
    if (!kv) continue;
    const [, key, value] = kv;
    if (key !== 'tools') {
      out.scalars[key] = value.trim();
      continue;
    }
    if (value.trim()) {
      out.tools = value.replace(/^\s*\[|\]\s*$/g, '').split(',').map((t) => t.trim().replace(/^["']|["']$/g, '')).filter(Boolean);
    } else {
      out.tools = [];
      while (/^\s+-\s+\S/.test(lines[i + 1] ?? '')) out.tools.push(lines[++i].replace(/^\s+-\s+/, '').trim().replace(/^["']|["']$/g, ''));
    }
  }
  return out;
}

const main = () => JSON.parse(fs.readFileSync(path.join(root, '.claude', 'settings.json'), 'utf8')).agent;
const claudeAgents = () =>
  fs.readdirSync(claudeDir).filter((f) => f.endsWith('.md')).map((f) => ({ id: f.slice(0, -3), ...parse(path.join(claudeDir, f)) }));
const canWrite = (a) => (a.tools ?? []).some((t) => ['Edit', 'Write', 'MultiEdit', 'NotebookEdit'].includes(t));

// What each Claude tool needs in the Copilot copy: GitHub's primary alias (custom agents configuration page), the Copilot CLI
// runtime names (hooks reference) and VS Code's Local harness names (tools reference, 2026-10-21). Unknown names are ignored by
// each host, so listing all three spellings is harmless.
const NEEDS = {
  Read: ['read', 'view', 'read/readFile'],
  Grep: ['search', 'grep', 'search/textSearch'],
  Glob: ['search', 'glob', 'search/fileSearch'],
  Edit: ['edit', 'str_replace_editor', 'edit/editFiles'],
  Write: ['edit', 'create', 'edit/createFile', 'edit/createDirectory'],
  Bash: ['execute', 'bash', 'powershell', 'execute/runInTerminal'],
  'powerbi-modeling/*': ['powerbi-modeling/*'],
  'microsoft-learn/*': ['microsoft-learn/*'],
};
// Claude Code tool names a Copilot host has no use for.
const CLAUDE_ONLY = new Set(['ToolSearch', 'ReadMcpResourceTool', 'ListMcpResourcesTool', 'mcp__powerbi-modeling', 'mcp__microsoft-learn']);

test('copilot agents: every Claude agent that can write has a .github/agents copy with the same name and the Copilot tools', (t) => {
  if (!fs.existsSync(claudeDir) || !fs.existsSync(copilotDir)) return t.skip('no .claude/agents or .github/agents next to this harness');
  const writers = claudeAgents().filter((a) => a.id !== main() && canWrite(a));
  assert.ok(writers.length >= 5, `writers found: ${writers.map((a) => a.id).join(', ')}`);
  for (const a of writers) {
    const file = path.join(copilotDir, `${a.id}.agent.md`);
    assert.ok(fs.existsSync(file), `${a.id} needs .github/agents/${a.id}.agent.md`);
    const c = parse(file);
    assert.equal(c.scalars.name, a.scalars.name, `${a.id}: name equals the Claude file's name`);
    assert.equal(a.scalars.name, a.id, `${a.id}: the Claude name is its file name`);
    assert.ok(c.scalars.description && c.scalars.description.length > 40, `${a.id}: a description that says what it edits and when to delegate`);
    assert.ok(Array.isArray(c.tools) && c.tools.length, `${a.id}: a tools list (without one, or with Claude's names alone, Copilot may hand the editor read tools only)`);
    // The documented edit and create tools: GitHub's `edit` alias and the CLI's `edit` and `create`.
    for (const name of ['edit', 'create']) assert.ok(c.tools.includes(name), `${a.id}: tools include ${name}`);
    for (const tool of a.tools) {
      if (CLAUDE_ONLY.has(tool)) continue;
      assert.ok(NEEDS[tool], `${a.id}: the Claude tool ${tool} has no entry in NEEDS (add the Copilot spellings)`);
      for (const name of NEEDS[tool]) assert.ok(c.tools.includes(name), `${a.id}: Claude ${tool} needs ${name} in the Copilot tools`);
    }
    // No more than the Claude file grants: a copy of a shell-less agent has no shell, and an agent without MCP none.
    if (!a.tools.includes('Bash')) for (const name of NEEDS.Bash) assert.ok(!c.tools.includes(name), `${a.id}: no shell in the Claude file, so none in the copy (${name})`);
    for (const server of ['powerbi-modeling/*', 'microsoft-learn/*']) {
      assert.equal(c.tools.includes(server), a.tools.includes(server), `${a.id}: ${server} matches the Claude file`);
    }
    // The main agent must be able to invoke an editor: GitHub's disable-model-invocation defaults to false, so the copy omits it.
    assert.ok(!('disable-model-invocation' in c.scalars), `${a.id}: no disable-model-invocation (the main agent invokes it)`);
    // A pointer, not a copy: it names the Claude file, says Copilot does not enforce the scope, and names the self-limit.
    assert.ok(c.body.includes(`.claude/agents/${a.id}.md`), `${a.id}: the body names .claude/agents/${a.id}.md`);
    assert.match(c.body, /Copilot does not enforce this scope/, `${a.id}: the body says the scope is not enforced`);
    assert.match(c.body, /never\s+from\s+the\s+shell|you\s+have\s+no\s+shell/, `${a.id}: the body forbids writing from the shell`);
    assert.match(c.body, /commit,\s+push,\s+deploy,\s+process,\s+publish/i, `${a.id}: the body forbids commit, push, deploy, process and publish`);
    assert.ok(c.body.split('\n').length < 25, `${a.id}: the body is a pointer, not a copy`);
  }
});

test('copilot agents: read-only agents have no copy, and no copy is left without its Claude writer', (t) => {
  if (!fs.existsSync(claudeDir) || !fs.existsSync(copilotDir)) return t.skip('no .claude/agents or .github/agents next to this harness');
  const claude = claudeAgents();
  // Reviewers, analysts and the validator never write; the lab showed they work from the Claude format file.
  for (const a of claude.filter((x) => x.id !== main() && !canWrite(x))) {
    assert.ok(!fs.existsSync(path.join(copilotDir, `${a.id}.agent.md`)), `${a.id} is read-only: no .github/agents copy`);
  }
  const writers = new Set(claude.filter((a) => canWrite(a) && a.id !== main()).map((a) => a.id));
  for (const f of fs.readdirSync(copilotDir).filter((x) => x.endsWith('.agent.md'))) {
    const id = f.replace(/\.agent\.md$/, '');
    assert.ok(id === main() || writers.has(id), `.github/agents/${f} has no Claude writer of that name`);
  }
});

test('copilot agents: the main agent is picked by the user, never invoked by another agent', (t) => {
  if (!fs.existsSync(copilotDir)) return t.skip('no .github/agents next to this harness');
  const c = parse(path.join(copilotDir, `${main()}.agent.md`));
  assert.equal(c.scalars['disable-model-invocation'], 'true');
  assert.equal(c.scalars.name, main());
});

// The runtime tool names a copy lists must be tools the hooks translate to a Claude call, or the guard would not judge them
// (they would be logged as `unmapped`). Every other name is a documented alias, a VS Code Local name or an MCP server.
test('copilot agents: every tool name in a copy is documented or translated by the hooks', (t) => {
  if (!fs.existsSync(copilotDir)) return t.skip('no .github/agents next to this harness');
  const cfg = { mcp: { powerbiServer: 'powerbi-modeling' } };
  const projectDir = os.platform() === 'win32' ? 'C:\\repo' : '/repo';
  const file = path.join(projectDir, 'docs', 'a.md');
  const runtime = {
    view: [{ path: file }, 'Read'], create: [{ path: file, file_text: 'x' }, 'Write'], edit: [{ path: file, old_str: 'a', new_str: 'b' }, 'Edit'],
    str_replace_editor: [{ command: 'create', path: file, file_text: 'x' }, 'Write'], grep: [{ pattern: 'x', paths: [projectDir] }, 'Grep'],
    glob: [{ pattern: '**/*.tmdl' }, 'Glob'], bash: [{ command: 'git status' }, 'Bash'], powershell: [{ command: 'git status' }, 'Bash'],
  };
  const aliases = new Set(['read', 'search', 'edit', 'execute']); // GitHub's primary aliases (custom agents configuration)
  const vscode = /^(?:read|search|edit|execute)\/[A-Za-z]+$/; // VS Code Local harness names (tools reference, 2026-10-21)
  const mcp = /^(?:powerbi-modeling|microsoft-learn)\/\*$/;
  for (const f of fs.readdirSync(copilotDir).filter((x) => x.endsWith('.agent.md'))) {
    const c = parse(path.join(copilotDir, f));
    for (const name of c.tools ?? []) {
      if (runtime[name]) {
        const [input, expected] = runtime[name];
        const out = toClaudeCalls({ hook_event_name: 'PreToolUse', tool_name: name, tool_input: input }, { cfg, projectDir });
        assert.deepEqual(out.map((x) => x.tool_name), [expected], `${f}: ${name} is judged as ${expected}`);
      } else {
        assert.ok(aliases.has(name) || vscode.test(name) || mcp.test(name), `${f}: ${name} is not a documented alias, a VS Code name or an MCP server`);
      }
    }
  }
});
