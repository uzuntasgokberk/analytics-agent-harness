// A `cd` that leaves the session in a project subfolder. Claude Code keeps the shell's folder for the next calls and runs
// the hook commands (`node hardening/hooks/<script>.mjs`, relative by design) from it: there the scripts cannot be found,
// every hook fails with a non-blocking "Cannot find module" error and the guards stop guarding. The PreToolUse guard runs
// while the shell is still at the root, so it denies the `cd` that would strand the session.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { strandedCd } from '../hooks/lib/policy.mjs';

const hook = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'hooks', 'pre-tool-use.mjs');
const STRANDED = /leaves the shell in/;

function withProject(fn) {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-stranded-cd-')));
  for (const rel of ['reports/Sales.Report', 'My Reports', 'models/Finance']) fs.mkdirSync(path.join(dir, rel), { recursive: true });
  try {
    return fn(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

/**
 * The hook with the shell at the project root: a Claude Code payload unless `payload` replaces it (a Copilot host's), no
 * host variable unless `env` sets one. A Copilot CLI answer is not nested in hookSpecificOutput.
 */
function runHook(dir, payload, env = {}) {
  const base = { ...process.env, CLAUDE_BASH_MAINTAIN_PROJECT_WORKING_DIR: '' };
  delete base.BI_HARNESS_HOST;
  delete base.COPILOT_CLI;
  const r = spawnSync(process.execPath, [hook], {
    input: JSON.stringify({ cwd: dir, ...payload }),
    env: { ...base, ...env, CLAUDE_PROJECT_DIR: dir },
    encoding: 'utf8',
  });
  assert.equal(r.status, 0, r.stderr);
  const out = r.stdout.trim() ? JSON.parse(r.stdout) : null;
  const d = out?.hookSpecificOutput ?? out;
  return { decision: d?.permissionDecision ?? null, reason: d?.permissionDecisionReason ?? '' };
}

/** The hook as Claude Code's main session runs it. */
const runGuard = (dir, toolName, command, env = {}, extra = {}) =>
  runHook(dir, { hook_event_name: 'PreToolUse', session_id: 'test', tool_name: toolName, tool_input: { command }, ...extra }, env);

test('stranded cd (bash): a top-level cd into a project subfolder is named; subshells, a return to the root and other folders are not', () => {
  withProject((dir) => {
    const at = (command) => strandedCd(command, dir, dir);
    assert.equal(at('cd reports && ls'), 'reports');
    assert.equal(at('cd "My Reports"; ls'), 'My Reports');
    assert.equal(at('cd reports/Sales.Report'), 'reports/Sales.Report');
    assert.equal(at('Set-Location models/Finance'), 'models/Finance');
    assert.equal(at('Set-Location -Path reports'), 'reports');
    assert.equal(at('cd reports && (cd Sales.Report && ls)'), 'reports', 'the subshell moves nothing after it');
    assert.equal(at('echo "(" && cd reports'), 'reports', 'a quoted parenthesis opens nothing');
    // A brace group and an if body run in the shell itself (bash 5.2: `{ cd sub; true; }; pwd` prints sub).
    assert.equal(at('{ cd reports; ls; }'), 'reports');
    assert.equal(at('if [ -d reports ]; then cd reports; fi'), 'reports');
    assert.equal(at('(cd reports && ls)'), null);
    assert.equal(at('(cd "reports" && ls)'), null);
    assert.equal(at('(Set-Location reports)'), null);
    assert.equal(at('Push-Location reports; ls; Pop-Location'), null);
    assert.equal(at('( cd reports; ls ) && git status'), null);
    assert.equal(at('$(cd reports; ls)'), null, 'a command substitution is a subshell');
    assert.equal(at('echo $(cd reports)'), null);
    assert.equal(at('cd reports; cd ..'), null);
    assert.equal(at(`cd reports && cd "${dir}"`), null);
    assert.equal(at('cd reports && cd -'), null, 'a folder the guard cannot place makes no claim');
    assert.equal(at('pushd reports; popd'), null);
    assert.equal(at('cd missing-folder && ls'), null, 'a cd that fails leaves the shell where it was');
    assert.equal(at(`cd "${os.tmpdir()}"`), null, 'outside the project');
    assert.equal(at('bash -c "cd reports; ls"'), null, 'a command string run by another process');
    assert.equal(at('git -C reports status'), null);
    assert.equal(at('ls reports'), null);
  });
});

test('stranded cd (PowerShell): ( ), $( ), { } and if bodies run in the session, so every cd there counts; Push/Pop-Location does not', () => {
  withProject((dir) => {
    const at = (command) => strandedCd(command, dir, dir, 'pwsh');
    // pwsh 7.6 and Windows PowerShell 5.1 (2026-11-10): after each of these the location is the subfolder.
    for (const command of ['(cd "reports" && ls)', '(Set-Location reports)', '$(cd reports; ls)', 'if (Test-Path reports) { cd reports }', '& { cd reports }', '. { cd reports }', 'Set-Location -Path reports', 'cd reports; Get-ChildItem', 'Get-ChildItem | ForEach-Object { Set-Location reports }']) {
      assert.equal(at(command), 'reports', command);
    }
    assert.equal(at('Write-Output "(" ; Set-Location reports'), 'reports', 'a quoted parenthesis changes nothing');
    assert.equal(at("Set-Location 'My Reports'"), 'My Reports');
    assert.equal(at('Push-Location reports; ls; Pop-Location'), null);
    assert.equal(at('Push-Location reports; try { ls } finally { Pop-Location }'), null);
    assert.equal(at('Set-Location reports; Set-Location ..'), null);
    assert.equal(at(`Set-Location reports; Set-Location "${dir}"`), null);
    assert.equal(at('Set-Location $env:USERPROFILE'), null, 'a folder the guard cannot place makes no claim');
    assert.equal(at('Set-Location (Join-Path $PWD reports)'), null, 'a computed folder is not placed');
    assert.equal(at('Set-Location missing-folder'), null);
    assert.equal(at(`Set-Location "${os.tmpdir()}"`), null, 'outside the project');
    assert.equal(at('pwsh -NoProfile -Command "cd reports; ls"'), null, 'a command string run by another process');
    assert.equal(at('Get-ChildItem reports'), null);
  });
});

test('stranded cd: the guard denies a cd that would strand the main session, with an alternative each tool passes', () => {
  withProject((dir) => {
    const bash = runGuard(dir, 'Bash', 'cd reports && ls');
    assert.equal(bash.decision, 'deny');
    assert.match(bash.reason, /leaves the shell in reports\. The session keeps that folder for the next calls/);
    assert.match(bash.reason, /\(cd "reports" && \.\.\.\)$/);
    for (const command of ['Set-Location reports', '(Set-Location reports)', '$(cd reports; ls)', 'if (Test-Path reports) { cd reports }', '(cd "reports" && ls)']) {
      const ps = runGuard(dir, 'PowerShell', command);
      assert.equal(ps.decision, 'deny', command);
      assert.match(ps.reason, STRANDED, command);
    }
    for (const command of ['{ cd reports; ls; }', 'if [ -d reports ]; then cd reports; fi']) {
      const group = runGuard(dir, 'Bash', command);
      assert.equal(group.decision, 'deny', command);
      assert.match(group.reason, STRANDED, command);
    }
    const ps = runGuard(dir, 'PowerShell', 'Set-Location reports').reason;
    assert.match(ps, /Push-Location "reports"; try \{ \.\.\. \} finally \{ Pop-Location \}$/);
    assert.doesNotMatch(ps, /&&|\(cd/, 'no && (a parse error in Windows PowerShell 5.1) and no subshell advice');
    for (const [tool, command] of [['Bash', '(cd reports && ls)'], ['Bash', 'ls reports'], ['PowerShell', 'Push-Location reports; ls; Pop-Location'], ['PowerShell', 'Get-ChildItem reports']]) {
      assert.doesNotMatch(runGuard(dir, tool, command).reason, STRANDED, `${tool}: ${command}`);
    }
  });
});

test('stranded cd: every form the deny text advises passes the guard of the same tool', () => {
  withProject((dir) => {
    for (const [tool, command, fromRoot] of [['Bash', 'cd reports && ls', 'ls reports'], ['PowerShell', 'Set-Location reports', 'Get-ChildItem reports']]) {
      const { reason } = runGuard(dir, tool, command);
      assert.match(reason, /Use paths from the repository root, or [^:]+: /, tool);
      const advised = reason.slice(reason.lastIndexOf(': ') + 2).replace('...', 'ls');
      for (const form of [advised, fromRoot]) {
        const r = runGuard(dir, tool, form);
        assert.notEqual(r.decision, 'deny', `${tool}: ${form}: ${r.reason}`);
      }
    }
  });
});

test('stranded cd: GitHub Copilot hosts and subagents get no cd claim; Claude Code\'s main session still does', () => {
  withProject((dir) => {
    const vscode = runHook(dir, { timestamp: '2026-10-07T12:00:00Z', hook_event_name: 'PreToolUse', tool_name: 'run_in_terminal', tool_input: { command: 'cd reports && ls', explanation: 'x', goal: 'y', mode: 'sync' }, tool_use_id: 't1' }, { BI_HARNESS_HOST: 'vscode' });
    assert.doesNotMatch(vscode.reason, STRANDED, 'VS Code run_in_terminal');
    const cli = runHook(dir, { sessionId: 'cli1', timestamp: 1, toolName: 'bash', toolArgs: { command: 'cd reports && ls' } }, { BI_HARNESS_HOST: 'copilot-cli' });
    assert.doesNotMatch(cli.reason, STRANDED, 'Copilot CLI bash');
    const dialect = runGuard(dir, 'Bash', 'cd reports && ls', {}, { timestamp: '2026-10-08T06:16:50.192Z' });
    assert.doesNotMatch(dialect.reason, STRANDED, 'the Claude registration run by a Copilot host');
    for (const [tool, command] of [['Bash', 'cd reports && ls'], ['PowerShell', 'Set-Location reports']]) {
      assert.doesNotMatch(runGuard(dir, tool, command, {}, { agent_id: 'a1', agent_type: 'general-purpose' }).reason, STRANDED, `${tool} in a subagent`);
      const main = runGuard(dir, tool, command);
      assert.equal(main.decision, 'deny', `${tool} in the main session`);
      assert.match(main.reason, STRANDED);
    }
  });
});

// Measured with Claude Code 2.1.322 on Windows 11 (2026-11-10): with the variable set to 1, a PowerShell `Set-Location sub`
// no longer carried to the next PowerShell call.
test('stranded cd: with CLAUDE_BASH_MAINTAIN_PROJECT_WORKING_DIR both shell tools return to the root, so neither is denied', () => {
  withProject((dir) => {
    const env = { CLAUDE_BASH_MAINTAIN_PROJECT_WORKING_DIR: '1' };
    assert.notEqual(runGuard(dir, 'Bash', 'cd reports && ls', env).decision, 'deny');
    assert.notEqual(runGuard(dir, 'PowerShell', 'Set-Location reports', env).decision, 'deny');
    assert.equal(runGuard(dir, 'PowerShell', 'Set-Location reports', { CLAUDE_BASH_MAINTAIN_PROJECT_WORKING_DIR: '0' }).decision, 'deny', 'only a true value counts');
  });
});
