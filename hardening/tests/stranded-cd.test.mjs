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

function withProject(fn) {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-stranded-cd-')));
  for (const rel of ['reports/Sales.Report', 'My Reports', 'models/Finance']) fs.mkdirSync(path.join(dir, rel), { recursive: true });
  try {
    return fn(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

/** The hook as Claude Code runs it, with the shell at the project root. */
function runGuard(dir, toolName, command, env = {}) {
  const r = spawnSync(process.execPath, [hook], {
    input: JSON.stringify({ hook_event_name: 'PreToolUse', session_id: 'test', tool_name: toolName, tool_input: { command }, cwd: dir }),
    env: { ...process.env, CLAUDE_BASH_MAINTAIN_PROJECT_WORKING_DIR: '', ...env, CLAUDE_PROJECT_DIR: dir },
    encoding: 'utf8',
  });
  const out = r.stdout.trim() ? JSON.parse(r.stdout).hookSpecificOutput : null;
  return { decision: out?.permissionDecision ?? null, reason: out?.permissionDecisionReason ?? '' };
}

test('stranded cd: a top-level cd into a project subfolder is named; subshells, a return to the root and other folders are not', () => {
  withProject((dir) => {
    const at = (command) => strandedCd(command, dir, dir);
    assert.equal(at('cd reports && ls'), 'reports');
    assert.equal(at('cd "My Reports"; ls'), 'My Reports');
    assert.equal(at('cd reports/Sales.Report'), 'reports/Sales.Report');
    assert.equal(at('Set-Location models/Finance'), 'models/Finance');
    assert.equal(at('cd reports && (cd Sales.Report && ls)'), 'reports', 'the subshell moves nothing after it');
    assert.equal(at('echo "(" && cd reports'), 'reports', 'a quoted parenthesis opens nothing');
    assert.equal(at('(cd reports && ls)'), null);
    assert.equal(at('( cd reports; ls ) && git status'), null);
    assert.equal(at('cd reports; cd ..'), null);
    assert.equal(at(`cd reports && cd "${dir}"`), null);
    assert.equal(at('cd reports && cd -'), null, 'a folder the guard cannot place makes no claim');
    assert.equal(at('pushd reports; popd'), null);
    assert.equal(at('cd missing-folder && ls'), null, 'a cd that fails leaves the shell where it was');
    assert.equal(at(`cd "${os.tmpdir()}"`), null, 'outside the project');
    assert.equal(at('git -C reports status'), null);
    assert.equal(at('ls reports'), null);
  });
});

test('stranded cd: the guard denies a Bash or PowerShell cd that would leave the session in a subfolder', () => {
  withProject((dir) => {
    const bash = runGuard(dir, 'Bash', 'cd reports && ls');
    assert.equal(bash.decision, 'deny');
    assert.match(bash.reason, /leaves the shell in reports\. The session keeps that folder for the next calls/);
    assert.match(bash.reason, /\(cd "reports" && \.\.\.\)/);
    assert.equal(runGuard(dir, 'PowerShell', 'Set-Location reports').decision, 'deny');
    assert.notEqual(runGuard(dir, 'Bash', '(cd reports && ls)').decision, 'deny');
    assert.notEqual(runGuard(dir, 'Bash', 'ls reports').decision, 'deny');
  });
});

test('stranded cd: with CLAUDE_BASH_MAINTAIN_PROJECT_WORKING_DIR the Bash tool returns to the root, so only PowerShell is denied', () => {
  withProject((dir) => {
    const env = { CLAUDE_BASH_MAINTAIN_PROJECT_WORKING_DIR: '1' };
    assert.notEqual(runGuard(dir, 'Bash', 'cd reports && ls', env).decision, 'deny');
    assert.equal(runGuard(dir, 'PowerShell', 'Set-Location reports', env).decision, 'deny');
  });
});
