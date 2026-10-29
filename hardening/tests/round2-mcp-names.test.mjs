// MCP tool names of the GitHub Copilot hosts (hooks/lib/host-vscode.mjs, claudeMcpName and toClaudeCalls), follow-up
// audit round 2, group E. F2-8: a server whose own name holds "-mcp-" (Copilot CLI's built-in `github-mcp-server`, a
// plugin's `powerbi-modeling-mcp`) reached the policy with the wrong server and tool: GitHub writes got no verdict and a
// role-member write was asked in auto mode and allowed in lab mode. F2-10: VS Code cuts a server label to 13 characters,
// and a server named in sources.sqlRead.mcpServers was not restored, so a DELETE through it got no verdict.
// Built against the names the hosts are documented or were observed to send; not run inside Copilot CLI or VS Code.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { DEFAULT_CONFIG } from '../hooks/lib/common.mjs';
import { claudeMcpName, toClaudeCalls } from '../hooks/lib/host-vscode.mjs';
import { isPowerBiMcp, powerbiServersOf } from '../hooks/lib/policy.mjs';
import { sqlReadOf } from '../hooks/lib/sql-read.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const hooks = path.join(here, '..', 'hooks');
// As loadConfig merges a project's config over the defaults.
const cfg = structuredClone(DEFAULT_CONFIG);
const SQL_READ = { mode: 'off', servers: [], mcpServers: ['contoso-reporting'], maxRows: 50, personalColumns: [] };
const sqlCfg = { ...cfg, sources: { ...cfg.sources, sqlRead: SQL_READ } };
const root = os.platform() === 'win32' ? 'C:\\repo' : '/repo';
const mapped = (tool_name, config = cfg, tool_input = {}) =>
  toClaudeCalls({ hook_event_name: 'PreToolUse', tool_name, tool_input }, { cfg: config, projectDir: root });
const email = () => ['a', 'example.com'].join('@'); // built at run time: no personal data literal in a test
const GITHUB_WRITES = ['push_files', 'create_issue', 'delete_file', 'create_branch', 'merge_pull_request'];

test('F2-8: Copilot CLI\'s built-in GitHub server keeps its name and the bare tool, in both CLI spellings and VS Code\'s cut', () => {
  for (const tool of GITHUB_WRITES) {
    assert.equal(claudeMcpName(`github-mcp-server-${tool}`, cfg), `mcp__github-mcp-server__${tool}`, `<server>-<tool>: ${tool}`);
    assert.equal(claudeMcpName(`github-mcp-server-mcp-${tool}`, cfg), `mcp__github-mcp-server__${tool}`, `<server>-mcp-<tool>: ${tool}`);
    assert.equal(mapped(`github-mcp-server-${tool}`)[0].tool_name, `mcp__github-mcp-server__${tool}`, `toClaudeCalls: ${tool}`);
  }
  // VS Code: the label `github-mcp-server` cut to 13 characters, with or without a collision suffix.
  assert.equal(claudeMcpName('mcp_github-mcp-se_push_files', cfg), 'mcp__github-mcp-server__push_files');
  assert.equal(claudeMcpName('mcp_github-mcp-se2_push_files', cfg), 'mcp__github-mcp-server__push_files', 'a collision suffix is dropped');
  assert.equal(mapped('mcp_github-mcp-se_push_files', cfg, { owner: 'o', repo: 'r' })[0].tool_name, 'mcp__github-mcp-server__push_files');
  assert.equal(claudeMcpName('mcp_github_push_files', cfg), 'mcp__github__push_files', 'control: a server labelled github');
  assert.equal(claudeMcpName('mcp__github__push_files', cfg), 'mcp__github__push_files', 'control: a Claude Code name passes');
});

test('F2-8: a server whose own name ends in -mcp (the -mcp-mcp- case) keeps the bare Power BI tool name', () => {
  const name = 'powerbi-modeling-mcp-mcp-security_role_operations';
  assert.equal(claudeMcpName(name, cfg), 'mcp__powerbi-modeling-mcp__security_role_operations');
  assert.equal(isPowerBiMcp(claudeMcpName(name, cfg), cfg), true, 'the modeling server, known by its tool name');
  const named = { ...cfg, mcp: { ...cfg.mcp, powerbiServers: [...cfg.mcp.powerbiServers, 'powerbi-modeling-mcp'] } };
  assert.equal(claudeMcpName(name, named), 'mcp__powerbi-modeling-mcp__security_role_operations', 'configured: the same name');
  assert.equal(claudeMcpName('powerbi-modeling-mcp-measure_operations', named), 'mcp__powerbi-modeling-mcp__measure_operations',
    'a configured powerbi-modeling-mcp is matched before powerbi-modeling (longest first)');
  // Unknown servers: the split is at the last "-mcp-" that leaves a server and a tool.
  assert.equal(claudeMcpName('my-mcp-server-mcp-tool', cfg), 'mcp__my-mcp-server__tool');
  assert.equal(claudeMcpName('a-mcp-mcp-b', cfg), 'mcp__a-mcp__b');
  assert.equal(claudeMcpName('x-mcp-mcp-mcp-query_rows', cfg), 'mcp__x-mcp-mcp__query_rows');
  for (const raw of [name, 'github-mcp-server-mcp-push_files', 'my-mcp-server-mcp-tool', 'a-mcp-mcp-b', 'x-mcp-mcp-mcp-query_rows',
    'powerbi-modeling-mcp-mcp-mcp-dax_query_operations', 'figma-mcp-mcp-get_code', 'contoso-reporting-mcp-mcp-execute']) {
    const m = /^mcp__(.+?)__(.+)$/.exec(claudeMcpName(raw, sqlCfg));
    assert.ok(m, `${raw} maps to an MCP name`);
    assert.doesNotMatch(m[2], /^mcp-/i, `${raw}: the tool part never starts with mcp-`);
  }
});

test('F2-10: a server named in sources.sqlRead.mcpServers comes back from VS Code\'s 13-character label and both CLI spellings', () => {
  assert.equal(claudeMcpName('mcp_contoso-repor_execute', sqlCfg), 'mcp__contoso-reporting__execute');
  assert.equal(claudeMcpName('mcp_contoso-repor1_execute', sqlCfg), 'mcp__contoso-reporting__execute', 'a collision suffix is dropped');
  assert.equal(claudeMcpName('contoso-reporting-mcp-execute', sqlCfg), 'mcp__contoso-reporting__execute');
  assert.equal(claudeMcpName('contoso-reporting-execute', sqlCfg), 'mcp__contoso-reporting__execute', '<server>-<tool> of a listed server');
  assert.equal(claudeMcpName('Contoso-Reporting-execute', sqlCfg), 'mcp__contoso-reporting__execute', 'the CLI keeps the user\'s casing');
  const call = mapped('contoso-reporting-execute', sqlCfg, { statement: 'DELETE FROM dbo.Customer' });
  assert.deepEqual([call.length, call[0].tool_name, call[0].unmapped], [1, 'mcp__contoso-reporting__execute', undefined], 'routed as an MCP call');
  // Not listed: the old generic split, and a name without "-mcp-" is no MCP name.
  assert.equal(claudeMcpName('mcp_contoso-repor_execute', cfg), 'mcp__contoso-repor__execute');
  assert.equal(claudeMcpName('contoso-reporting-execute', cfg), 'contoso-reporting-execute');
  assert.equal(mapped('contoso-reporting-execute', cfg, { statement: 'x' })[0].unmapped, true);
  // The list claudeMcpName matches holds what the policy's own readers return.
  const both = { ...sqlCfg, mcp: { powerbiServer: 'my_pbi', powerbiServers: ['powerbi-modeling', 'pbi-long-server-name'] } };
  for (const server of [...powerbiServersOf(both), ...sqlReadOf(both).mcpServers]) {
    assert.equal(claudeMcpName(`${server}-mcp-table_operations`, both), `mcp__${server}__table_operations`, `${server}: CLI`);
    const label = server.toLowerCase().replace(/[^a-z0-9_.-]+/g, '_').slice(0, 13);
    assert.equal(claudeMcpName(`mcp_${label}_table_operations`, both), `mcp__${server}__table_operations`, `${server}: VS Code`);
  }
});

test('names the hosts sent before map exactly as before; a known server\'s <server>-<tool> is new', () => {
  const pins = [
    ['mcp__powerbi-modeling__measure_operations', 'mcp__powerbi-modeling__measure_operations'],
    ['powerbi-modeling-mcp-measure_operations', 'mcp__powerbi-modeling__measure_operations'],
    ['powerbi-modeling-mcp-database_operations', 'mcp__powerbi-modeling__database_operations'],
    ['powerbi-modeling-mcp-security_role_operations', 'mcp__powerbi-modeling__security_role_operations'],
    ['mcp_powerbi-model_measure_operations', 'mcp__powerbi-modeling__measure_operations'],
    ['mcp_powerbi-model1_dax_query_operations', 'mcp__powerbi-modeling__dax_query_operations'],
    ['mcp_powerbi-autho_database_operations', 'mcp__powerbi-authoring-local__database_operations'],
    ['mcp_github_create_issue', 'mcp__github__create_issue'],
    ['mcp_figma_use_figma', 'mcp__figma__use_figma'],
    ['mcp_other_srv_do_it', 'mcp__other__srv_do_it'],
    ['jira-mcp-get_issue', 'mcp__jira__get_issue'],
    ['read_file', 'read_file'],
    ['run_in_terminal', 'run_in_terminal'],
    ['view', 'view'],
    ['github_repo', 'github_repo'],
  ];
  for (const [raw, want] of pins) assert.equal(claudeMcpName(raw, cfg), want, raw);
  assert.equal(mapped('get_errors', cfg, { filePaths: ['a.ts'] })[0].unmapped, true, 'a tool that is no MCP tool stays unmapped');
  assert.equal(mapped('view', cfg, { path: 'docs/a.md' })[0].tool_name, 'Read', 'a CLI file tool keeps its shape mapping');
  // New: the CLI's <server>-<tool> spelling of a server the hooks know by name.
  assert.equal(claudeMcpName('powerbi-modeling-measure_operations', cfg), 'mcp__powerbi-modeling__measure_operations');
  assert.equal(claudeMcpName('microsoft-learn-microsoft_docs_search', cfg), 'mcp__microsoft-learn__microsoft_docs_search');
  assert.equal(mapped('powerbi-modeling-security_role_operations', cfg, { request: { operation: 'Update' } })[0].tool_name,
    'mcp__powerbi-modeling__security_role_operations');
});

/** A temp project with this harness.config.json (null: none, the defaults). */
function project(config) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-round2-mcp-'));
  if (config) {
    fs.mkdirSync(path.join(dir, 'hardening'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'hardening', 'harness.config.json'), JSON.stringify(config));
  }
  return dir;
}

/** Runs pre-tool-use.mjs in `dir`: host 'copilot-cli' (camelCase payload, flat output), 'vscode', or null (Claude Code). */
function pre(dir, host, tool, args) {
  const payload = host === 'copilot-cli'
    ? { sessionId: 'r2-mcp', timestamp: 1760770000000, cwd: dir, toolName: tool, toolArgs: args }
    : { hook_event_name: 'PreToolUse', session_id: 'r2-mcp', cwd: dir, tool_name: tool, tool_input: args, tool_use_id: 'u',
      ...(host === 'vscode' ? { timestamp: '2026-10-18T06:16:50.192Z' } : {}) };
  const env = { ...process.env, CLAUDE_PROJECT_DIR: dir };
  delete env.BI_HARNESS_HOST;
  if (host) env.BI_HARNESS_HOST = host;
  const r = spawnSync(process.execPath, [path.join(hooks, 'pre-tool-use.mjs')], { input: JSON.stringify(payload), env, encoding: 'utf8' });
  if (r.error) throw r.error;
  const out = r.stdout.trim() ? JSON.parse(r.stdout) : null;
  const verdict = host === 'copilot-cli' ? out : out?.hookSpecificOutput;
  return {
    decision: verdict?.permissionDecision ?? null,
    reason: String(verdict?.permissionDecisionReason ?? ''),
    detail: `exit ${r.status}, stdout ${r.stdout.slice(0, 300)}, stderr ${JSON.stringify(String(r.stderr).slice(0, 300))}`,
  };
}

test('F2-8: a role-member Update through powerbi-modeling-mcp-mcp-security_role_operations is denied in auto and lab mode', () => {
  const args = { request: { operation: 'Update', connectionName: 'PBIDesktop-Sales-1234', members: [email()] } };
  for (const mode of ['auto', 'lab']) {
    const dir = project({ approvals: { mode } });
    try {
      for (const tool of ['powerbi-modeling-mcp-mcp-security_role_operations', 'powerbi-modeling-mcp-security_role_operations']) {
        const r = pre(dir, 'copilot-cli', tool, args);
        assert.equal(r.decision, 'deny', `${mode}, ${tool}: ${r.detail}`);
        assert.match(r.reason, /Role membership is managed by the user/, `${mode}, ${tool}`);
      }
      const vscode = pre(dir, 'vscode', 'mcp_powerbi-model1_security_role_operations', args);
      assert.equal(vscode.decision, 'deny', `${mode}, VS Code label powerbi-modeling-mcp: ${vscode.detail}`);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }
});

test('F2-10: a DELETE through a listed SQL MCP server is denied under VS Code\'s cut label, as under the CLI and Claude Code names', () => {
  const dir = project({ sources: { sqlRead: SQL_READ } });
  try {
    const args = { statement: 'DELETE FROM dbo.Customer' };
    for (const [host, tool] of [['vscode', 'mcp_contoso-repor_execute'], ['copilot-cli', 'contoso-reporting-mcp-execute'],
      ['copilot-cli', 'contoso-reporting-execute'], [null, 'mcp__contoso-reporting__execute']]) {
      const r = pre(dir, host, tool, args);
      assert.equal(r.decision, 'deny', `${host ?? 'claude'}, ${tool}: ${r.detail}`);
      assert.match(r.reason, /SQL MCP contoso-reporting: the statement .* changes data/, `${host ?? 'claude'}, ${tool}`);
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
