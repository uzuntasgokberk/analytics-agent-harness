// Second review of the guards (2026-10-06): path spellings, fail-closed loading, settings and config protection,
// wrapped shell commands, MCP targets and row-exposing DAX. Each case was a confirmed bypass before the fix.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadConfig } from '../hooks/lib/common.mjs';
import { analyzeMcpCall, analyzeShellCommand } from '../hooks/lib/policy.mjs';
import { roleMembersChanged } from '../hooks/lib/validators.mjs';

const hooksDir = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'hooks');
const hook = path.join(hooksDir, 'pre-tool-use.mjs');

function project(files = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-guard-'));
  for (const [rel, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), content);
  }
  return dir;
}

function runGuard(dir, tool_name, tool_input, script = hook) {
  const r = spawnSync(process.execPath, [script], {
    input: JSON.stringify({ hook_event_name: 'PreToolUse', session_id: 'test', tool_name, tool_input }),
    env: { ...process.env, CLAUDE_PROJECT_DIR: dir },
    encoding: 'utf8',
  });
  const out = r.stdout.trim() ? JSON.parse(r.stdout).hookSpecificOutput : null;
  return { status: r.status, decision: out?.permissionDecision ?? null, reason: out?.permissionDecisionReason ?? '' };
}

const cfg = (mode, until) => JSON.stringify({ approvals: { mode, until } });
const soon = (hours) => new Date(Date.now() + hours * 3600000).toISOString();

// Audit 2026-10-19, F2-33: both PreToolUse entry scripts, each next to its own broken guard module (no check script in
// the copy, so the load error itself is printed). The subagent scope guard gets the payload it judges (an agent_type).
test('a guard that cannot load blocks the call (exit 2), it does not let it through (exit 1)', () => {
  for (const [entry, lib, who] of [
    ['pre-tool-use.mjs', 'guard-pre-tool-use.mjs', 'PreToolUse guard'],
    ['agent-scope.mjs', 'guard-agent-scope.mjs', 'subagent scope guard'],
  ]) {
    const dir = project({ [`hooks/lib/${lib}`]: 'export const x = ;\n' });
    try {
      fs.copyFileSync(path.join(hooksDir, entry), path.join(dir, 'hooks', entry));
      const r = spawnSync(process.execPath, [path.join(dir, 'hooks', entry)], {
        input: JSON.stringify({ hook_event_name: 'PreToolUse', session_id: 'test', agent_type: 'bi-dax-reviewer', tool_name: 'Write', tool_input: { file_path: 'docs/x.md', content: 'x' } }),
        env: { ...process.env, CLAUDE_PROJECT_DIR: dir },
        encoding: 'utf8',
      });
      assert.equal(r.status, 2, `${entry}: ${r.stderr}`);
      assert.match(r.stderr, new RegExp(`The ${who} could not load \\(Unexpected token`), entry);
      assert.equal(r.stdout, '', `${entry} prints no verdict`);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }
});

// Audit 2026-10-18, F1-62: REFERENCE.md says a guard that receives no payload blocks. Exit 2 blocks the call; an exit 0 or 1
// would let it through, and only a module that fails to load was tested. Both PreToolUse guards, an empty and an unreadable payload.
test('a guard that gets no payload, or one it cannot parse, blocks the call (exit 2)', () => {
  const dir = project();
  for (const script of [hook, path.join(hooksDir, 'agent-scope.mjs')]) {
    for (const [input, stderr] of [['', /received no payload/], ['not json', /hook error/]]) {
      const r = spawnSync(process.execPath, [script], { input, env: { ...process.env, CLAUDE_PROJECT_DIR: dir }, encoding: 'utf8' });
      const what = `${path.basename(script)} with ${JSON.stringify(input)}`;
      assert.equal(r.status, 2, what);
      assert.match(r.stderr, stderr, what);
      assert.equal(r.stdout, '', `${what} prints no verdict`);
    }
  }
  fs.rmSync(dir, { recursive: true, force: true });
});

test('alternate data streams, device paths and trailing dots cannot hide a secret file', () => {
  const dir = project({ '.env': 'X=1\n' });
  for (const file_path of ['.env::$DATA', '.env.', '.env:stream', '\\\\?\\C:\\x\\.env', path.join(dir, '.env. ')]) {
    assert.equal(runGuard(dir, 'Read', { file_path }).decision, 'deny', file_path);
  }
  fs.rmSync(dir, { recursive: true, force: true });
});

test('a short (8.3) name of the harness config is checked like the long name', (t) => {
  const dir = project({ 'hardening/harness.config.json': cfg('ask', null) });
  const shortDir = path.join(dir, 'HARDEN~1');
  if (!fs.existsSync(shortDir)) {
    fs.rmSync(dir, { recursive: true, force: true });
    return t.skip('this volume does not create 8.3 names');
  }
  const r = runGuard(dir, 'Write', { file_path: path.join(shortDir, 'harness.config.json'), content: cfg('auto', soon(2)) });
  fs.rmSync(dir, { recursive: true, force: true });
  assert.equal(r.decision, 'deny');
});

test('settings: escaped bypass values and removing the harness hooks are denied', () => {
  const hooks = JSON.stringify({ hooks: { PreToolUse: [{ hooks: [{ type: 'command', command: 'node', args: ['${CLAUDE_PROJECT_DIR}/hardening/hooks/pre-tool-use.mjs'] }] }] } });
  const dir = project({ '.claude/settings.local.json': hooks });
  const settings = path.join(dir, '.claude', 'settings.local.json');
  assert.equal(runGuard(dir, 'Write', { file_path: settings, content: '{"permissions":{"defaultMode":"bypass\\u0050ermissions"}}' }).decision, 'deny');
  assert.equal(runGuard(dir, 'Write', { file_path: settings, content: '{"disableAll\\u0048ooks":true}' }).decision, 'deny');
  assert.equal(runGuard(dir, 'Write', { file_path: settings, content: '{}' }).decision, 'deny');
  // A protective deny rule that names the flag is fine.
  const protective = JSON.parse(hooks);
  protective.permissions = { deny: ['Bash(claude --dangerously-skip-permissions*)'] };
  assert.notEqual(runGuard(dir, 'Edit', { file_path: settings, old_string: hooks, new_string: JSON.stringify(protective) }).decision, 'deny');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('config: an edit the guard cannot predict, and NotebookEdit, are denied', () => {
  const dir = project({ 'hardening/harness.config.json': cfg('ask', null) });
  const file_path = path.join(dir, 'hardening', 'harness.config.json');
  assert.equal(runGuard(dir, 'Edit', { file_path, old_string: 'not in the file', new_string: 'x' }).decision, 'deny');
  assert.equal(runGuard(dir, 'NotebookEdit', { notebook_path: file_path, new_source: 'x' }).decision, 'deny');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('malformed tool input and a broken config do not crash the guard', () => {
  const dir = project({ 'hardening/harness.config.json': JSON.stringify({ git: null, mcp: null, sources: { referenceCopies: 'x' } }), 'a.md': '# a\n' });
  assert.equal(runGuard(dir, 'MultiEdit', { file_path: path.join(dir, 'a.md'), edits: [null] }).status, 0);
  assert.equal(runGuard(dir, 'MultiEdit', { file_path: path.join(dir, 'a.md'), edits: 'x' }).status, 0);
  assert.equal(runGuard(dir, 'Bash', { command: 'git status' }).status, 0);
  assert.equal(runGuard(dir, 'mcp__powerbi-modeling__table_operations', { request: { operation: 'List' } }).status, 0);
  const loaded = loadConfig(dir);
  assert.ok(Array.isArray(loaded.git.protectedBranches));
  assert.ok(Array.isArray(loaded.sources.referenceCopies));
  fs.rmSync(dir, { recursive: true, force: true });
});

const ctx = { protectedBranches: ['main'], getBranch: () => 'feature/x' };
const verdict = (r) => (r ? `${r.decision}${r.autoApprovable === false ? '/user' : ''}` : 'none');

test('shell: writes to harness files from inline code or patches are stopped', () => {
  for (const [want, cmd] of [
    ['deny', `node -e "require('fs').writeFileSync('hardening/harness.config.json','{}')"`],
    ['deny', `[IO.File]::WriteAllText('.claude/settings.local.json', 'x')`],
    ['deny', `python -c "open('hardening/x.json','w').write('1')"`],
    ['deny', 'cp -r x /c/repo/hardening'],
    ['ask/user', 'git apply cfg.patch'],
    ['none', 'git apply --check cfg.patch'],
    ['ask', `node -e "require('child_process').execSync('dir')"`],
    ['none', 'node -e "console.log(1 + 1)"'],
  ]) assert.equal(verdict(analyzeShellCommand(cmd, ctx)), want, cmd);
});

test('shell: wrapped and nested commands are judged like the command inside', () => {
  const encoded = Buffer.from('git push origin f', 'utf16le').toString('base64');
  for (const [want, cmd] of [
    ['ask/user', 'sleep 1 & git push origin f'],
    ['deny', 'true & ssh host'],
    ['ask/user', 'pwsh -c git push origin f'],
    ['ask/user', 'powershell git push origin f'],
    ['deny', 'bash -lc "ssh host"'],
    ['deny', 'bash -lc "rm -rf build"'],
    ['ask/user', 'cmd /s /c "sqlcmd -Q 1"'],
    ['ask/user', '(git push origin f)'],
    ['ask/user', 'if true; then git push origin f; fi'],
    ['ask/user', 'Invoke-Command { sqlcmd -Q 1 }'],
    ['ask/user', '1 | % { sqlcmd -Q 1 }'],
    ['ask/user', 'start "" sqlcmd -Q 1'],
    ['ask/user', 'nice -n 5 sqlcmd -Q 1'],
    ['ask/user', 'env -i sqlcmd -Q 1'],
    ['ask/user', 'xargs sqlcmd -Q'],
    ['deny', 'find . -exec ssh host \\;'],
    ['ask/user', `pwsh -EncodedCommand ${encoded}`],
    ['deny', 'pwsh -EncodedCommand ////'],
    ['ask/user', 'Write-Output "[System.Data.SqlClient.SqlConnection]::new(1)" | Invoke-Expression'],
    ['deny', 'cat ".env::$DATA"'],
    ['deny', 'cat .env.'],
  ]) assert.equal(verdict(analyzeShellCommand(cmd, ctx)), want, cmd);
});

// Audit 2026-10-18, F1-61: shell denies that REFERENCE.md documents (environment dumps, also through process.env, os.environ
// and /proc/*/environ; no-verify; force branch deletion in any flag form) and that no test pinned. Each string below is data
// for the analyzer, never run as a command; the reason is checked too, so a deny for another cause does not pass.
test('shell: environment dumps, --no-verify and forced branch deletion are denied, each with its documented reason', () => {
  for (const [reason, commands] of [
    [/Dumping environment variables/, [
      'printenv', 'env', 'set', 'export -p', 'declare -p', 'cat /proc/self/environ',
      'node -e "console.log(process.env)"', 'python -c "import os; print(os.environ)"',
      'Get-ChildItem env:', 'dir env:', 'cmd /c set', '[Environment]::GetEnvironmentVariables()',
    ]],
    [/git commit --no-verify bypasses the PBIP pre-commit/, ['git commit -n -m "fix: x"', 'git commit --no-verify -m "fix: x"']],
    [/git push --no-verify bypasses the harness pre-push/, ['git push --no-verify origin feature/x']],
    [/Force-deleting branches is blocked/, ['git branch -D feature/x', 'git branch --delete --force feature/x', 'git branch -df feature/x']],
  ]) {
    for (const cmd of commands) {
      const r = analyzeShellCommand(cmd, ctx);
      assert.equal(r?.decision, 'deny', cmd);
      assert.match(r.reason, reason, cmd);
    }
  }
});

// F1-61: the PreToolUse matcher is Bash|PowerShell|Monitor; Monitor streams a command's output and is judged like the shell tools.
test('the Monitor tool is judged like Bash and PowerShell: a command that reads a secret file is denied', () => {
  const dir = project();
  for (const tool of ['Bash', 'PowerShell', 'Monitor']) {
    const r = runGuard(dir, tool, { command: 'cat .env' });
    assert.equal(r.status, 0, tool);
    assert.equal(r.decision, 'deny', tool);
    assert.match(r.reason, /secret or data file/, tool);
  }
  fs.rmSync(dir, { recursive: true, force: true });
});

test('shell: scripts outside the harness ask, whatever their extension; role members and backups are servers', () => {
  for (const [want, cmd] of [
    ['ask', 'node docs/hardening/x.mjs'],
    ['ask', 'node hardening/../x.mjs'],
    ['ask', 'node docs/x'],
    ['ask', 'python notes.txt'],
    ['ask', 'python -m http.server'],
    ['deny', 'Add-RoleMember -MemberName x -Database y -RoleName z'],
    ['ask/user', 'Backup-SqlDatabase -Database x'],
    ['ask/user', '[System.Data.OleDb.OleDbConnection]::new("Provider=MSOLAP")'],
  ]) assert.equal(verdict(analyzeShellCommand(cmd, ctx)), want, cmd);
});

test('shell: naming a web cmdlet in a search or a commit message is not a network call', () => {
  for (const cmd of ['grep -rn "Invoke-WebRequest" hardening', 'git commit -m "block Invoke-WebRequest and [System.Net.Sockets]"',
    'Select-String -Pattern "Invoke-RestMethod" -Path docs/x.md']) {
    assert.notEqual(analyzeShellCommand(cmd, ctx)?.decision, 'deny', cmd);
  }
  assert.equal(analyzeShellCommand('$r = Invoke-WebRequest https://x', ctx)?.decision, 'deny');
});

test('shell: ordinary commands stay quiet', () => {
  for (const cmd of [
    'node hardening/scripts/validate.mjs --changed', 'npm --prefix hardening test', 'git status', 'git diff HEAD~1 --stat',
    'git commit -m "fix a & b; cmd /c x"', 'ls -la docs', 'Get-Content TASKS.md', 'node --check hardening/hooks/lib/policy.mjs',
    'powerbi-desktop status', 'dtexec /Va /F x.dtsx', 'grep -r Microsoft.AnalysisServices docs',
  ]) assert.equal(analyzeShellCommand(cmd, ctx), null, cmd);
});

test('MCP: remote servers, service calls and writes on an unnamed or remote connection need the user', () => {
  const mcp = (tool, request) => verdict(analyzeMcpCall(`mcp__powerbi-modeling__${tool}`, { request }, { mcp: { powerbiServer: 'powerbi-modeling' } }));
  assert.equal(mcp('connection_operations', { operation: 'Connect', connectionString: 'Data Source=ssas-prod.contoso.com;Initial Catalog=X' }), 'ask/user');
  assert.equal(mcp('connection_operations', { operation: 'Connect', connectionString: 'Data Source=localhost:53342' }), 'ask');
  assert.equal(mcp('partition_operations', { operation: 'RefreshWithAPI', connectionName: 'PBIDesktop-Sales-1' }), 'ask/user');
  assert.equal(mcp('measure_operations', { operation: 'Create', connectionName: 'Fabric-WS-Model' }), 'ask/user');
  assert.equal(mcp('measure_operations', { operation: 'Create' }), 'ask/user');
  assert.equal(mcp('measure_operations', { operation: 'Create', connectionName: 'PBIDesktop-Sales-1' }), 'ask');
  assert.equal(mcp('dax_query_operations', { operation: '1', maxRows: 5, query: 'EVALUATE ROW("a",1)' }), 'ask/user');
  assert.equal(mcp('table_operations', { operation: 'List' }), 'allow');
});

test('MCP: DAX that packs rows into one value or groups by personal columns needs the user; counting them does not', () => {
  const dax = (query, maxRows) => verdict(analyzeMcpCall('mcp__powerbi-modeling__dax_query_operations', { request: { operation: 'Execute', maxRows, query } }, { mcp: { powerbiServer: 'powerbi-modeling' } }));
  assert.equal(dax("EVALUATE ROW(\"e\", CONCATENATEX('Customer','Customer'[Email],\";\"))", 1), 'ask/user');
  assert.equal(dax("EVALUATE SUMMARIZECOLUMNS('Customer'[Email],'Customer'[Customer Name])", 50), 'ask/user');
  assert.equal(dax("EVALUATE ROW(\"n\", DISTINCTCOUNT('Salesperson'[Salesperson Email]), \"b\", COUNTROWS(FILTER('Salesperson', ISBLANK('Salesperson'[Salesperson Email]))))", 1), 'allow');
  assert.equal(dax("EVALUATE SUMMARIZECOLUMNS('Customer'[Region], \"S\", [Net Sales])", 5), 'allow');
});

// Eval run 2: 17 prompts in one run came from aggregate queries the shape check did not recognise.
test('MCP: aggregate DAX in its common wrappers runs; a query that returns a table\'s rows still needs the user', () => {
  const dax = (query, maxRows = 20) => verdict(analyzeMcpCall('mcp__powerbi-modeling__dax_query_operations', { request: { operation: 'Execute', maxRows, query } }, { mcp: { powerbiServer: 'powerbi-modeling' } }));
  for (const query of [
    "EVALUATE CALCULATETABLE ( SUMMARIZECOLUMNS ( Customer[Region], \"Net\", SUM ( Sales[Line Amount] ) ), 'Date'[Year] = 2025 ) ORDER BY Customer[Region]",
    'EVALUATE VAR _Lines = ADDCOLUMNS ( Sales, "@CR", RELATED ( Customer[Region] ) ) RETURN ROW ( "Lines", COUNTROWS ( _Lines ) )',
    'EVALUATE VAR _Last = MAX ( Sales[Order Date Key] ) RETURN ADDCOLUMNS ( TOPN ( 15, SUMMARIZECOLUMNS ( \'Date\'[Year Month], "Net", [Net Sales] ), \'Date\'[Year Month], DESC ), "Last", _Last )',
    'EVALUATE VAR _T = CALCULATETABLE ( ADDCOLUMNS ( VALUES ( Customer[Region] ), "Net", [Net Sales] ), \'Date\'[Year] = 2025 ) VAR _Tot = ROW ( "Net", [Net Sales] ) RETURN UNION ( _T, SELECTCOLUMNS ( _Tot, "Region", "(Total)", "Net", [Net] ) )',
    "DEFINE MEASURE Sales[Test] = [Net Sales] * 2 EVALUATE SUMMARIZECOLUMNS ( 'Date'[Year], \"T\", [Test] )",
    'EVALUATE FILTER ( SUMMARIZECOLUMNS ( Product[Category], "N", [Net Sales] ), [N] > 0 )',
    'EVALUATE { COUNTROWS ( Sales ) }',
    "EVALUATE ( VALUES ( 'Date'[Fiscal Year] ) )",
    "EVALUATE SUMMARIZECOLUMNS ( 'Date'[Year], \"N\", [Net Sales] ) ORDER BY 'Date'[Year]\nEVALUATE ROW ( \"All\", [Net Sales] )",
    "EVALUATE SUMMARIZE ( 'Sales Metric', 'Sales Metric'[Sales Metric Order], 'Sales Metric'[Sales Metric] )",
    'EVALUATE ROW ( "s", "EVALUATE Customer" )',
    'EVALUATE DISTINCT ( UNION ( SELECTCOLUMNS ( DISTINCT ( Salesperson[Salesperson Region] ), "R", Salesperson[Salesperson Region] ), SELECTCOLUMNS ( DISTINCT ( Customer[Region] ), "R", Customer[Region] ) ) )',
  ]) assert.equal(dax(query), 'allow', query);
  for (const query of [
    "EVALUATE 'Customer'",
    'EVALUATE Sales',
    "EVALUATE FILTER ( Customer, Customer[Region] = \"North\" )",
    "EVALUATE CALCULATETABLE ( Sales, 'Date'[Year] = 2025 )",
    'EVALUATE ADDCOLUMNS ( Customer, "x", 1 )',
    'EVALUATE VAR t = Customer RETURN t',
    'EVALUATE TOPN ( 500, Sales )',
    'EVALUATE VALUES ( Customer )',
    'EVALUATE DISTINCT ( Customer )',
    'EVALUATE DISTINCT ( FILTER ( Sales, Sales[Quantity] > 1 ) )',
    'EVALUATE UNION ( ROW ( "a", 1 ), SELECTCOLUMNS ( Customer, "a", Customer[City] ) )',
    'EVALUATE SUMMARIZECOLUMNS ( Customer[Region] ) EVALUATE Customer',
    'EVALUATE UNKNOWNFUNC ( Customer )',
  ]) assert.equal(dax(query), 'ask/user', query);
});

// Fable's review of the run 2 fix: rows rebuilt from a key or name column, and multi-column ALL, passed as "grouped".
test('MCP: DAX grouped by a key, ID or self-named name column, or by several columns at once, returns rows and asks', () => {
  const dax = (query) => verdict(analyzeMcpCall('mcp__powerbi-modeling__dax_query_operations', { request: { operation: 'Execute', maxRows: 20, query } }, { mcp: { powerbiServer: 'powerbi-modeling' } }));
  for (const query of [
    'EVALUATE VALUES ( Customer[Customer Key] )',
    'EVALUATE ADDCOLUMNS ( VALUES ( Customer[Customer Key] ), "n", CALCULATE ( MAX ( Customer[Customer] ) ), "c", CALCULATE ( MAX ( Customer[City] ) ) )',
    'EVALUATE SELECTCOLUMNS ( VALUES ( Customer[Customer Key] ), "k", Customer[Customer Key] )',
    'EVALUATE GENERATE ( VALUES ( Customer[Customer Key] ), ROW ( "c", CALCULATE ( MAX ( Customer[City] ) ) ) )',
    'EVALUATE ALL ( Customer[Customer Key], Customer[Customer], Customer[City] )',
    'EVALUATE CROSSJOIN ( VALUES ( Customer[Customer Key] ), VALUES ( Customer[City] ) )',
    'EVALUATE SUMMARIZECOLUMNS ( Customer[Customer Key], Customer[City] )',
    "EVALUATE SUMMARIZE ( Sales, Sales[Customer Key], \"n\", SUM ( Sales[Line Amount] ) )",
    "EVALUATE SUMMARIZECOLUMNS ( 'Salesperson'[Salesperson], \"Net\", [Net Sales] )",
    'EVALUATE ADDCOLUMNS ( VALUES ( Customer[City] ), "who", CALCULATE ( MAX ( Customer[Customer] ) ) )',
  ]) assert.equal(dax(query), 'ask/user', query);
  for (const query of [
    "EVALUATE SUMMARIZECOLUMNS ( 'Date'[Date Key], \"Net\", [Net Sales] )",
    "EVALUATE SUMMARIZECOLUMNS ( 'Date'[Year Month Number], \"Net\", [Net Sales] )",
    'EVALUATE ADDCOLUMNS ( VALUES ( Customer[Region] ), "Last", CALCULATE ( MAX ( Sales[Order Date Key] ) ) )',
    "EVALUATE ROW ( \"Customers\", DISTINCTCOUNT ( Customer[Customer] ) )",
    "EVALUATE SUMMARIZECOLUMNS ( Product[Product Key], \"N\", [Net Sales] )",
    "EVALUATE SUMMARIZE ( Sales, Sales[Sales Order ID], \"n\", SUM ( Sales[Line Amount] ) )",
  ]) assert.equal(dax(query), 'allow', query);
});

test('MCP: an export with restricted information (connection strings) is never a plain read', () => {
  const call = (tool, request) => verdict(analyzeMcpCall(`mcp__powerbi-modeling__${tool}`, { request }, { mcp: { powerbiServer: 'powerbi-modeling' } }));
  assert.equal(call('database_operations', { operation: 'ExportTMDL', tmdlExportOptions: { serializationOptions: { includeRestrictedInformation: true } } }), 'ask/user');
  assert.equal(call('model_operations', { operation: 'ExportTMSL', tmslExportOptions: { includeRestricted: true } }), 'ask/user');
  assert.equal(call('database_operations', { operation: 'ExportTMDL', tmdlExportOptions: { serializationOptions: { includeRestrictedInformation: false } } }), 'allow');
});

test('MCP: reading roles (get, list, permissions, TMDL or TMSL export) runs; changing them still asks', () => {
  const role = (operation) => verdict(analyzeMcpCall('mcp__powerbi-modeling__security_role_operations', { request: { operation } }, { mcp: { powerbiServer: 'powerbi-modeling' } }));
  for (const op of ['List', 'Get', 'ExportTMDL', 'ExportTMSL', 'GetPermissions', 'ListPermissions', 'GetEffectivePermissions', 'Help']) assert.equal(role(op), 'allow', op);
  for (const op of ['Create', 'Update', 'Delete', 'Rename', 'CreatePermissions', 'UpdatePermissions', 'DeletePermissions']) assert.equal(role(op), 'ask/user', op);
});

// Audit 2026-10-18, F1-60: the deny of role-member edits in TMDL (README.md: role membership is managed by the user) had only
// the timing test below, no test of the verdict. Write and Edit, in a role that has members, in one that has none and in a
// new one. A change of the role's modelPermission or tablePermission is not this rule: it reaches the user as an ask (from
// the guard or from the roles/*.tmdl ask rule of .claude/settings.json), so it is never this deny, and the test does not pin
// which of the two asks. Every call must exit 0, or a crash would pass "not denied".
test('role files: adding, removing or renaming a member is denied; a modelPermission or tablePermission change is not', () => {
  const role = ({ name = 'Reader', permission = 'read', region = 'West', members = ['reader_one', 'reader_two'] } = {}) =>
    [`role ${name}`, `\tmodelPermission: ${permission}`, `\ttablePermission Customer = [Region] = "${region}"`,
      ...(members.length ? [''] : []), ...members.map((m) => `\tmember ${m}`), ''].join('\n');
  const folder = 'S.SemanticModel/definition/roles';
  const dir = project({ [`${folder}/Reader.tmdl`]: role(), [`${folder}/Auditor.tmdl`]: role({ name: 'Auditor', members: [] }) });
  const file = (name) => path.join(dir, ...folder.split('/'), `${name}.tmdl`);
  const write = (what, name, content) => [what, 'Write', { file_path: file(name), content }];
  const edit = (what, old_string, new_string) => {
    assert.ok(fs.readFileSync(file('Reader'), 'utf8').includes(old_string), `${what}: the fixture holds the text to replace`);
    return [what, 'Edit', { file_path: file('Reader'), old_string, new_string }];
  };
  const cases = {
    denied: [
      write('Write adds a member', 'Reader', role({ members: ['reader_one', 'reader_two', 'reader_three'] })),
      edit('Edit adds a member', '\tmember reader_two\n', '\tmember reader_two\n\tmember reader_three\n'),
      write('Write removes a member', 'Reader', role({ members: ['reader_one'] })),
      edit('Edit removes a member', '\tmember reader_two\n', ''),
      write('Write renames a member', 'Reader', role({ members: ['reader_one', 'reader_2'] })),
      edit('Edit renames a member', 'member reader_two', 'member reader_2'),
      write('Write adds the first member of a role', 'Auditor', role({ name: 'Auditor', members: ['reader_one'] })),
      write('Write creates a role that has a member', 'Viewer', role({ name: 'Viewer', members: ['reader_one'] })),
    ],
    permissionsOnly: [
      write('Write changes modelPermission', 'Reader', role({ permission: 'readRefresh' })),
      edit('Edit changes modelPermission', 'modelPermission: read\n', 'modelPermission: readRefresh\n'),
      write('Write changes the tablePermission filter', 'Reader', role({ region: 'East' })),
      edit('Edit changes the tablePermission filter', '"West"', '"East"'),
      write('Write changes a role that has no members', 'Auditor', role({ name: 'Auditor', permission: 'readRefresh', members: [] })),
    ],
  };
  for (const [what, tool, input] of cases.denied) {
    const r = runGuard(dir, tool, input);
    assert.equal(r.status, 0, what);
    assert.equal(r.decision, 'deny', what);
    assert.match(r.reason, /members of a role/, what);
  }
  for (const [what, tool, input] of cases.permissionsOnly) {
    const r = runGuard(dir, tool, input);
    assert.equal(r.status, 0, what);
    assert.notEqual(r.decision, 'deny', `${what}: ${r.reason}`);
    assert.doesNotMatch(r.reason, /members of a role/, what);
  }
  fs.rmSync(dir, { recursive: true, force: true });
});

test('the role member scan stays linear on long files', () => {
  const big = '\n'.repeat(200000);
  const started = Date.now();
  roleMembersChanged(big, `${big}x`);
  assert.ok(Date.now() - started < 2000);
});
