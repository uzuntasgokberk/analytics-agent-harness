// The shipped Claude Code registration (settings.hooks.json) routes every tool the guards handle to them. Audit
// 2026-10-19, F2-34: renaming the matchers Read|Grep|Glob, Edit|Write|NotebookEdit|MultiEdit or the subagent scope
// matcher to tools that do not exist left every test green, so a release could ship with reads, file writes and subagent
// scopes unguarded. The tests read the matchers as Claude Code does and assert inclusion, not the exact file: a group
// added later (another event, another hook) does not break them, a guard that stops running for a tool does.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const pack = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const settings = JSON.parse(fs.readFileSync(path.join(pack, 'settings.hooks.json'), 'utf8'));
const command = (script) => `node hardening/hooks/${script}`;

/** Claude Code's matcher: none, "" or "*" match every tool; any other value is a regular expression the whole name must match. */
function matches(matcher, tool) {
  if (matcher === undefined || matcher === '' || matcher === '*') return true;
  return new RegExp(`^(?:${matcher})$`).test(tool);
}

/** The commands the groups of `event` run for `tool`. */
const commandsFor = (event, tool) =>
  (settings.hooks[event] ?? []).filter((group) => matches(group.matcher, tool)).flatMap((group) => group.hooks.map((h) => h.command));

// Each tool the PreToolUse guard judges (lib/guard-pre-tool-use.mjs): the shell tools, the readers, the writers and MCP
// tools in Claude Code's naming (mcp__server__tool) and in Copilot CLI's (server-mcp-tool), which runs this registration too.
const GUARDED = ['Bash', 'PowerShell', 'Monitor', 'Read', 'Grep', 'Glob', 'Edit', 'Write', 'NotebookEdit', 'MultiEdit', 'mcp__x__y', 'x-mcp-y'];
// The subagent scopes (agent-scope.mjs) bound what a subagent writes or runs: the writers, the shell tools and MCP tools.
// Copilot sends no agent_type, so its MCP naming is not needed here.
const SCOPED = ['Edit', 'Write', 'NotebookEdit', 'MultiEdit', 'Bash', 'PowerShell', 'Monitor', 'mcp__x__y'];
// The tools whose output can hold a secret or personal data the masking hook replaces (post-tool-redact.mjs).
const MASKED = ['Read', 'Grep', 'Bash', 'PowerShell', 'WebFetch', 'mcp__x__y', 'x-mcp-y'];

test('registration: the matcher reading is anchored and "*" matches every tool', () => {
  assert.equal(matches('Read|Grep|Glob', 'Read'), true);
  assert.equal(matches('Read|Grep|Glob', 'MyRead'), false, 'a whole-name match: a tool whose name only contains Read is not matched');
  assert.equal(matches('Read|Grep|Glob', 'Reader'), false);
  assert.equal(matches('mcp__.*', 'mcp__x__y'), true);
  assert.equal(matches('mcp__.*', 'x-mcp-y'), false);
  assert.equal(matches('*', 'AnyTool'), true);
  assert.equal(matches(undefined, 'AnyTool'), true);
});

test('registration (F2-34): every tool the PreToolUse guard judges runs pre-tool-use.mjs', () => {
  for (const tool of GUARDED) {
    assert.ok(commandsFor('PreToolUse', tool).includes(command('pre-tool-use.mjs')), `${tool} reaches the PreToolUse guard`);
  }
});

test('registration (F2-34): the subagent scope guard runs for the write, shell and MCP tools', () => {
  for (const tool of SCOPED) {
    assert.ok(commandsFor('PreToolUse', tool).includes(command('agent-scope.mjs')), `${tool} reaches agent-scope.mjs`);
  }
});

test('registration (F2-34): the output of readers, shells, web fetches and MCP tools goes through the masking hook', () => {
  for (const tool of MASKED) {
    assert.ok(commandsFor('PostToolUse', tool).includes(command('post-tool-redact.mjs')), `${tool} output reaches post-tool-redact.mjs`);
  }
});
