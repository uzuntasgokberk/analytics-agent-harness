// Follow-up audit, round 2 (F2-12): VS Code's hooks reference (https://code.visualstudio.com/docs/agents/reference/hooks-reference,
// page dated 10/14/2026, read 2026-10-19) documents for PostToolUse only `decision`, `reason`,
// `hookSpecificOutput.hookEventName` and `hookSpecificOutput.additionalContext` (plus the common `continue`,
// `stopReason`, `systemMessage`): no field replaces the tool output. The masking hook still sends `updatedToolOutput`
// (harmless if ignored), but under BI_HARNESS_HOST=vscode it must not tell the model that values "were redacted": it says
// the output held sensitive values that may be visible and must not be used. Claude Code applies `updatedToolOutput`, and
// Copilot CLI documents `modifiedResult` ("Replacement tool result", GitHub's hooks configuration reference, read
// 2026-10-19), so their message stays. The session banner says the same for VS Code. Not run inside VS Code.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const hooks = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'hooks');

// Built at run time: never a credential or an address literal in a test.
const fakeSecret = () => ['Pass', 'word=hunter2', 'fake', 'value;'].join('');
const fakeMail = () => ['jane.doe', '@', 'example.com'].join('');

/** The environment without the host variable (the parent may run under a Copilot host). */
function baseEnv(dir) {
  const env = Object.fromEntries(Object.entries(process.env).filter(([k]) => k.toLowerCase() !== 'bi_harness_host'));
  return { ...env, CLAUDE_PROJECT_DIR: dir };
}

/** Runs a hook with a payload and an optional host; the parsed stdout (or null). */
function spawnHook(script, dir, payload, host) {
  const env = baseEnv(dir);
  if (host) env.BI_HARNESS_HOST = host;
  const r = spawnSync(process.execPath, [path.join(hooks, script)], { input: JSON.stringify(payload), env, encoding: 'utf8' });
  assert.equal(r.status, 0, `${script}: ${r.stderr}`);
  return r.stdout.trim() ? JSON.parse(r.stdout) : null;
}

function project() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-r2-vscode-'));
  fs.mkdirSync(path.join(dir, 'docs'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'docs', 'notes.md'), '# notes\n');
  return dir;
}

/** A VS Code PostToolUse payload (the shape of the lead's reproduction on 0268b55). */
const vsPost = (dir, tool_name, tool_input, tool_response) => ({
  hook_event_name: 'PostToolUse', session_id: 'r2-vscode-1', timestamp: '2026-10-18T06:16:50.192Z', cwd: dir, tool_name, tool_use_id: 'u', tool_input, tool_response,
});

const CLAIMS_REDACTED = /w(?:ere|as) redacted/i;

/** The VS Code notice: counts and kinds, may be visible, must not be used, tell the user; never "were redacted". */
function assertTruthfulVsCode(ctx, count, kind, label) {
  assert.doesNotMatch(ctx, CLAIMS_REDACTED, `${label}: VS Code documents no output replacement, so nothing may claim a redaction: ${ctx}`);
  assert.match(ctx, /^\[bi-harness\] /, label);
  assert.match(ctx, new RegExp(`${count} sensitive value\\(s\\)`), `${label}: the count`);
  assert.ok(ctx.includes(kind), `${label}: the kinds (${kind}): ${ctx}`);
  assert.match(ctx, /VS Code documents no way for a hook to replace tool output/, `${label}: why`);
  assert.match(ctx, /may be visible/, `${label}: the values may be visible`);
  assert.match(ctx, /Do not repeat, store, copy or use them/, `${label}: must not be used`);
  assert.match(ctx, /tell the user/, `${label}: tell the user`);
}

test('F2-12: under VS Code a masked Read still sends updatedToolOutput, and the model is told the values may be visible, not that they were redacted', () => {
  const dir = project();
  try {
    const secret = fakeSecret();
    const out = spawnHook('post-tool-redact.mjs', dir, vsPost(dir, 'read_file', { filePath: 'docs/notes.md', startLine: 1, endLine: 5 }, `Server=sql01;${secret}`), 'vscode');
    const h = out?.hookSpecificOutput;
    assert.equal(h?.hookEventName, 'PostToolUse');
    assert.equal(h?.updatedToolOutput, 'Server=sql01;Password=[REDACTED:password-assignment];', 'the masked output is still sent (works if VS Code applies it)');
    assert.ok(!JSON.stringify(out).includes('hunter2'), 'the value itself never appears in the hook output');
    assert.equal(out.decision, undefined, 'no block: it would stop BI work after the value was already shown');
    assertTruthfulVsCode(h.additionalContext ?? '', 1, 'password-assignment', 'read_file');
    assert.match(h.additionalContext, /This read_file output/, 'the tool is named as VS Code names it');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('F2-12: under VS Code the MCP output masking and a saved MCP answer read back carry the same truthful notice', () => {
  const dir = project();
  try {
    // Any MCP server's answer: a personal field is masked (redaction.piiInMcpOutput, on by default).
    const mcp = spawnHook('post-tool-redact.mjs', dir, vsPost(dir, 'mcp_github_search_users', { q: 'x' }, JSON.stringify({ rows: [{ Email: fakeMail(), Total: 12 }] })), 'vscode');
    assert.match(mcp?.hookSpecificOutput?.updatedToolOutput ?? '', /\[PII:personal-field\]/, 'masked as MCP output');
    assertTruthfulVsCode(mcp.hookSpecificOutput.additionalContext ?? '', 1, 'personal-field', 'MCP answer');
    // A read of an MCP answer saved to a file (any server's) is masked as MCP output.
    const saved = path.join(dir, 'session', 'tool-results', 'mcp-powerbi-modeling-dax_query_operations-1760000000000.txt');
    const read = spawnHook('post-tool-redact.mjs', dir, vsPost(dir, 'read_file', { filePath: saved, startLine: 1, endLine: 40 }, `{"Customer[Email]": "${fakeMail()}", "Total": 100}`), 'vscode');
    assert.match(read?.hookSpecificOutput?.updatedToolOutput ?? '', /\[PII:personal-field\]/, 'masked as a saved MCP answer');
    assertTruthfulVsCode(read.hookSpecificOutput.additionalContext ?? '', 1, 'personal-field', 'saved MCP answer');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('F2-12: Claude Code and Copilot CLI apply the replacement, so their notice is unchanged', () => {
  const dir = project();
  try {
    const text = `Server=sql01;${fakeSecret()}`;
    const today = '[bi-harness] 1 sensitive value(s) were redacted from this Read output (password-assignment). Do not try to recover them; tell the user if a real value is required.';
    // Claude Code: no host variable, no timestamp (Claude Code sends none).
    const claude = spawnHook('post-tool-redact.mjs', dir, {
      session_id: 's', transcript_path: 't', cwd: dir, permission_mode: 'default', hook_event_name: 'PostToolUse', tool_use_id: 'u',
      tool_name: 'Read', tool_input: { file_path: path.join(dir, 'docs', 'notes.md') }, tool_response: text,
    });
    assert.equal(claude?.hookSpecificOutput?.updatedToolOutput, 'Server=sql01;Password=[REDACTED:password-assignment];');
    assert.equal(claude.hookSpecificOutput.additionalContext, today, 'Claude Code keeps its notice');
    assert.equal(claude.modifiedResult, undefined, 'a Claude Code payload passes untouched');
    // Copilot CLI's native hooks: camelCase payload, flat output with modifiedResult (documented and probed).
    const cli = spawnHook('post-tool-redact.mjs', dir, { sessionId: 'cli1', timestamp: 1, cwd: dir, toolName: 'view', toolArgs: { path: 'docs/notes.md' }, toolResult: { resultType: 'success', textResultForLlm: text } }, 'copilot-cli');
    assert.match(cli?.modifiedResult?.textResultForLlm ?? '', /REDACTED:password-assignment/);
    assert.equal(cli.additionalContext, today, 'Copilot CLI keeps its notice');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('F2-12: the session banner says masking under VS Code is a warning, not a guarantee; the CLI line is unchanged', () => {
  const dir = project();
  try {
    // The CLI sends camelCase without an event name; a snake_case payload under the CLI's file is VS Code (copilotHostOf).
    const hostLine = (host) => {
      const payload = host === 'copilot-cli'
        ? { source: 'startup', sessionId: `r2-${host}`, timestamp: 1760860800000 }
        : { hook_event_name: 'SessionStart', source: 'startup', session_id: `r2-${host}` };
      const out = spawnHook('session-start.mjs', dir, payload, host);
      // VS Code reads hookSpecificOutput; the CLI's native hooks get the flat additionalContext (toCopilotCliOutput).
      const ctx = out?.hookSpecificOutput?.additionalContext ?? out?.additionalContext ?? '';
      return ctx.split('\n').find((l) => l.startsWith('- Host: ')) ?? '';
    };
    const vs = hostLine('vscode');
    assert.match(vs, /^- Host: VS Code Copilot hooks\./);
    assert.match(vs, /VS Code documents no way for a hook to replace tool output/, vs);
    assert.match(vs, /masking is a warning, not a guarantee/, vs);
    assert.doesNotMatch(vs, /validation, masking and audit log run/, 'VS Code is not told masking runs as in Claude Code');
    assert.match(vs, /subagent scopes do not/);
    const cli = hostLine('copilot-cli');
    assert.match(cli, /^- Host: GitHub Copilot CLI hooks\. The guard, validation, masking and audit log run; subagent scopes do not \(no agent_type here\)\./, cli);
    assert.doesNotMatch(cli, /warning, not a guarantee/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
