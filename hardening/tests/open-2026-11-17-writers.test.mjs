// Open findings 2026-11-17, each measured before the fix on a fixture with templates/t.md, reports/r1/source/q.sql,
// reports/r1/docs/x.md and docs/a.md:
// A. A delete, move or rename of a folder that holds a reference folder (`rm -r reports`, `mv reports/r1 x`, `Remove-Item
//    reports -Recurse`, `git mv reports old`) had no verdict, and `git rm -r reports` only the ask auto mode passes, while the
//    reference folder itself is denied.
// B. A `cd` the cd guard could not see (inside eval or Invoke-Expression, in a bash function body, a .NET call that sets the
//    location) left the main session in a subfolder with no verdict; eval and Invoke-Expression of text the command does not
//    hold (`eval $x`, `iex (Get-Content x.ps1 -Raw)`) passed with none, also in lab mode.
// C. git worktree add -B onto a protected branch, `git -C <dir> checkout` / `restore` of a guardrail file, and a fetch refspec
//    into a protected branch set with -c or stored with git config had no verdict.
import { after, test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const preHook = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'hooks', 'pre-tool-use.mjs');

/** A temporary project with the given files (the real path: a Windows short name would not be the project's spelling). */
function project(files, prefix = 'bi-harness-open-1117-writers-') {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
  for (const [rel, text] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(root, rel)), { recursive: true });
    fs.writeFileSync(path.join(root, rel), text);
  }
  return root;
}

// The project of the guard: reference folders, a folder that holds one (reports/, reports/r1/), one that holds none
// (reports/r1/docs/, docs/), a guardrail file and a configured reference below setup/. Set before the modules read
// CLAUDE_PROJECT_DIR.
const dir = project({
  'templates/t.md': '# t\n', 'reports/r1/source/q.sql': 'SELECT 1\n', 'reports/r1/docs/x.md': '# x\n', 'docs/a.md': '# a\n', 'docs/b.txt': 'b\n',
  'hardening/hooks/x.mjs': '// x\n', 'setup/deep/ref/x.txt': 'x\n',
  'hardening/harness.config.json': `${JSON.stringify({ references: ['setup/deep/ref/'] }, null, 2)}\n`,
});
process.env.CLAUDE_PROJECT_DIR = dir;
const { analyzeShellCommand, routineShell, strandedCd } = await import('../hooks/lib/policy.mjs');
const made = [dir];
after(() => made.forEach((root) => fs.rmSync(root, { recursive: true, force: true })));

const references = ['setup/deep/ref/'];
const onFeature = { protectedBranches: ['main'], getBranch: () => 'feature/x', baseDir: dir, references };
const unprotected = { protectedBranches: [], getBranch: () => 'feature/x', baseDir: dir, references };
const shell = (cmd, ctx = onFeature) => analyzeShellCommand(cmd, ctx);
const REFERENCE = /reference folder/i;
const GUARDRAIL = /Harness guardrail files/;
const STRANDED = /leaves the shell in/;

/** Asserts a deny whose reason matches `reason`, and that auto mode never takes the command for routine. */
function assertDeny(cmd, reason, ctx = onFeature) {
  const v = shell(cmd, ctx);
  assert.equal(v?.decision, 'deny', `${cmd} (from ${path.relative(dir, ctx.baseDir) || 'the project'})`);
  assert.match(v.reason, reason, cmd);
  assert.equal(routineShell(cmd), false, cmd);
}
/** The floor ask: auto approval never passes it and lab mode leaves it to the user; never routine. */
function assertFloor(cmd) {
  const v = shell(cmd);
  assert.equal(v?.decision, 'ask', cmd);
  assert.equal(v.floor, true, cmd);
  assert.equal(v.autoApprovable, false, cmd);
  assert.equal(routineShell(cmd), false, cmd);
}

// The hook runs with the machine's global and system git configuration left out, no host variable and the shell tools' folder
// kept between calls (as Claude Code's main session runs it), as in open-2026-11-17-git.test.mjs and stranded-cd.test.mjs.
function hookEnv(root) {
  const env = Object.fromEntries(Object.entries(process.env).filter(([k]) => !/^GIT_(?:CONFIG|DIR$|WORK_TREE$|INDEX_FILE$|COMMON_DIR$|OBJECT_DIRECTORY$|ALTERNATE)/i.test(k)));
  delete env.BI_HARNESS_HOST;
  delete env.COPILOT_CLI;
  const globalConfig = path.join(root, 'empty.gitconfig');
  if (!fs.existsSync(globalConfig)) fs.writeFileSync(globalConfig, '');
  return { ...env, CLAUDE_PROJECT_DIR: root, CLAUDE_BASH_MAINTAIN_PROJECT_WORKING_DIR: '', GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: globalConfig, GIT_CEILING_DIRECTORIES: path.dirname(root) };
}

/** The PreToolUse guard's decision and reason for one shell command, run as a process like Claude Code's main session runs it. */
function hook(root, command, tool_name = 'Bash') {
  const r = spawnSync(process.execPath, [preHook], {
    input: JSON.stringify({ hook_event_name: 'PreToolUse', session_id: 'open-1117-writers', tool_name, tool_input: { command }, cwd: root }),
    env: hookEnv(root),
    encoding: 'utf8',
  });
  assert.equal(r.status, 0, r.stderr); // a guard that did not run prints no verdict, which "not allow" would read as a pass
  const out = r.stdout.trim() ? JSON.parse(r.stdout).hookSpecificOutput : null;
  return { decision: out?.permissionDecision ?? null, reason: out?.permissionDecisionReason ?? '' };
}

// ---------------------------------------------------------------- A: a folder that holds a reference folder

test('A: a delete, move or rename of a folder that holds a reference folder is denied like the reference folder', () => {
  for (const cmd of [
    'rm -r reports', 'rm -r reports/r1', 'rm -r reports/', 'rm -r ./reports/r1/', 'rm reports', 'rmdir reports', 'rm -r docs reports',
    'mv reports old', 'mv reports/r1 reports/r2', 'mv -t old reports', 'mv --target-directory=old reports/r1', 'mv -- reports old', 'mv -f reports old',
    // PowerShell, its aliases and cmd (forward slashes: a backslash is one name for the Linux path functions).
    'Remove-Item reports -Recurse', 'Remove-Item -Path reports/r1 -Recurse', 'ri reports -r', 'rd /s reports', 'rd reports', 'del reports',
    'Rename-Item reports old', 'rni reports old', 'ren reports old', 'Move-Item reports old', 'Move-Item -Path reports -Destination old',
    'Move-Item -LiteralPath reports/r1 -Destination x', 'Move-Item -Destination old -Path:reports', 'mi reports old', 'move reports old',
    'Remove-Item . -Recurse',
    // git rm and the sources of git mv.
    'git rm -r reports', 'git rm -r reports/r1', 'git rm -r -- reports', 'git -C reports rm -r r1', 'git mv reports old', 'git mv reports/r1 reports/r2',
    'git mv -f reports old', 'git mv -k reports/r1 docs',
    // After a cd of the same command line, and a literal handed to eval or Invoke-Expression.
    'cd reports && rm -r r1', '(cd reports && mv r1 r2)', "eval 'rm -r reports'", "iex 'Remove-Item reports -Recurse'",
    // A folder above a configured reference that exists.
    'rm -r setup', 'mv setup/deep s2', 'git rm -r setup/deep',
  ]) {
    assertDeny(cmd, REFERENCE);
  }
  // From the shell's folder of the payload.
  for (const cmd of ['rm -r r1', 'mv r1 r2', 'Remove-Item r1 -Recurse', 'git rm -r r1', 'rm -r .']) assertDeny(cmd, REFERENCE, { ...onFeature, baseDir: path.join(dir, 'reports') });
  // The reason is the reference deny's.
  assert.equal(shell('rm -r reports').reason, shell('rm -r reports/r1/source').reason);
});

test('A: must stay: folders that hold no reference folder, a move into such a folder, copies out, reads and the denies of today', () => {
  for (const cmd of ['rm -r docs', 'rm -r reports/r1/docs', 'mv docs docs2', 'rm -r nothere', 'mv nothere x', 'Remove-Item docs -Recurse', 'Rename-Item docs d2',
    'git mv docs d2', 'mv docs/b.txt reports', 'mv docs/b.txt reports/r1', 'Move-Item docs/b.txt reports', 'Move-Item -Destination reports docs/b.txt',
    'Move-Item -Path docs/b.txt -Destination reports/r1', 'move docs/b.txt reports', 'git mv docs/b.txt reports/r1', 'cp -r reports docs/backup',
    'ls reports', 'cat reports/r1/docs/x.md', 'git rm -r --cached reports', 'rm -r $dir', 'rm -r report*', 'git clean -n reports', 'rm -r setup/deep/other']) {
    assert.equal(shell(cmd), null, cmd);
  }
  // `rm -rf reports/r1` is denied by the rm -rf rule (checkSubcommand) before the new rule: kept, with its reason.
  assert.deepEqual(shell('rm -rf reports/r1'), { decision: 'deny', reason: 'rm -rf is blocked. Delete specific files, one step at a time, after confirming with the user.' });
  assert.deepEqual(shell('rmdir /s /q reports'), { decision: 'deny', reason: 'Recursive forced deletes are blocked.' });
  assert.deepEqual(shell('git clean -fd reports'), { decision: 'deny', reason: 'git clean -f permanently deletes untracked files.' });
  for (const cmd of ['rm -r reports/r1/source', 'rm -r templates', 'mv docs/a.md templates', 'git mv docs/a.md reports/r1/source']) assertDeny(cmd, REFERENCE);
  assert.match(shell('git rm -r docs')?.reason ?? '', /git rm deletes files/);
});

test('A: the walk below a folder is bounded: past the bound it denies nothing; under it the hook denies', () => {
  const folders = (n) => Object.fromEntries(Array.from({ length: n }, (_, k) => [`reports/a${String(k).padStart(4, '0')}/x.txt`, 'x\n']));
  // 510 folders sort before zz/: the walk reads 500 and stops without an answer.
  const wide = project({ ...folders(510), 'reports/zz/source/q.sql': 'SELECT 1\n' }, 'bi-harness-open-1117-wide-');
  const narrow = project({ ...folders(10), 'reports/zz/source/q.sql': 'SELECT 1\n' }, 'bi-harness-open-1117-narrow-');
  made.push(wide, narrow);
  assert.notEqual(hook(wide, 'rm -r reports').decision, 'deny');
  const out = hook(narrow, 'rm -r reports');
  assert.equal(out.decision, 'deny');
  assert.match(out.reason, REFERENCE);
});

test('A: the hook denies them end to end, the config\'s references included', () => {
  for (const [tool, command] of [['Bash', 'rm -r reports'], ['Bash', 'mv reports/r1 reports/r2'], ['Bash', 'git rm -r reports'], ['Bash', 'git mv reports old'],
    ['PowerShell', 'Remove-Item reports -Recurse'], ['PowerShell', 'Rename-Item reports old'], ['PowerShell', 'rd /s reports'], ['Bash', 'rm -r setup']]) {
    const out = hook(dir, command, tool);
    assert.equal(out.decision, 'deny', `${tool}: ${command}`);
    assert.match(out.reason, REFERENCE, command);
  }
  for (const command of ['rm -r docs', 'mv docs docs2', 'rm -r reports/r1/docs']) assert.notEqual(hook(dir, command).decision, 'deny', command);
});

// ---------------------------------------------------------------- B: eval, Invoke-Expression and a cd the guard could not see

test('B: a cd inside eval or a bash function body strands the session like the plain cd', () => {
  const at = (command) => strandedCd(command, dir, dir);
  assert.equal(at('cd docs'), 'docs');
  for (const command of ['eval cd docs', 'eval "cd docs"', "eval 'cd docs'", 'eval "cd docs && ls"', 'eval eval cd docs', 'ls; eval cd docs',
    'function f { cd docs; }; f', 'f() { cd docs; }; f', 'f () { cd docs; }; f', 'function f() { cd docs; }', 'function f { cd docs; }']) {
    assert.equal(at(command), at('cd docs'), command);
  }
  // A subshell, a return, a command string run by another process, a body in parentheses and text stay without a claim.
  for (const command of ['(eval cd docs)', 'eval cd docs; cd ..', 'bash -c "eval cd docs"', 'echo "eval cd docs"', 'f() ( cd docs ); f', 'eval $x', 'eval cd missing-folder']) {
    assert.equal(at(command), null, command);
  }
});

test('B: a cd inside Invoke-Expression, piped into iex, or set by a .NET call with a literal folder strands the session like Set-Location', () => {
  const at = (command) => strandedCd(command, dir, dir, 'pwsh');
  assert.equal(at('Set-Location reports'), 'reports');
  for (const command of ["Invoke-Expression 'cd reports'", "iex 'cd reports'", 'iex "cd reports"', "Invoke-Expression -Command 'cd reports'", "'cd reports' | iex",
    '"Set-Location reports" | Invoke-Expression', "$ExecutionContext.SessionState.Path.SetLocation('reports')", "[Environment]::CurrentDirectory = 'reports'",
    "[System.Environment]::CurrentDirectory='reports'", "[IO.Directory]::SetCurrentDirectory('reports')", '[System.IO.Directory]::SetCurrentDirectory("reports")',
    "ls; [IO.Directory]::SetCurrentDirectory('reports')", 'function f { cd reports }']) {
    assert.equal(at(command), at('Set-Location reports'), command);
  }
  for (const command of ["Push-Location reports; iex 'cd r1'; Pop-Location", "iex 'cd reports'; Set-Location ..", 'iex $cmd', '[IO.Directory]::SetCurrentDirectory($dir)',
    '$ExecutionContext.SessionState.Path.SetLocation("$x")', 'Write-Output "[IO.Directory]::SetCurrentDirectory(\'reports\')"', "pwsh -Command \"iex 'cd reports'\""]) {
    assert.equal(at(command), null, command);
  }
});

test('B: the hook denies those cds in the main session with the stranded-cd reason', () => {
  for (const [tool, command] of [['Bash', 'eval cd docs'], ['Bash', 'eval "cd docs"'], ['Bash', "eval 'cd docs'"], ['Bash', 'function f { cd reports; }; f'],
    ['Bash', 'f() { cd reports; }; f'], ['PowerShell', "Invoke-Expression 'cd reports'"], ['PowerShell', "iex 'cd reports'"], ['PowerShell', "'cd reports' | iex"],
    ['PowerShell', "$ExecutionContext.SessionState.Path.SetLocation('reports')"], ['PowerShell', "[Environment]::CurrentDirectory = 'reports'"],
    ['PowerShell', "[IO.Directory]::SetCurrentDirectory('reports')"]]) {
    const out = hook(dir, command, tool);
    assert.equal(out.decision, 'deny', `${tool}: ${command}`);
    assert.match(out.reason, STRANDED, command);
  }
});

test('B: a literal handed to eval or Invoke-Expression goes through every rule, not only the cd rule', () => {
  assert.deepEqual(shell("iex 'Remove-Item reports -Recurse'"), shell('Remove-Item reports -Recurse'));
  assert.deepEqual(shell("eval 'mv reports old'"), shell('mv reports old'));
  assert.equal(shell('mv reports old')?.decision, 'deny');
  // Kept: eval 'rm -rf docs' was denied before; iex of a command with no verdict has none.
  assert.deepEqual(shell("eval 'rm -rf docs'"), shell('rm -rf docs'));
  assert.equal(shell("eval 'rm -rf docs'")?.decision, 'deny');
  assert.deepEqual(shell('iex "Remove-Item docs -Recurse"'), shell('Remove-Item docs -Recurse'));
  // A single cd that eval or Invoke-Expression runs moves the folder the later words are placed from, like the plain cd.
  for (const [evaluated, plain, reason] of [['eval cd templates; rm t.md', 'cd templates; rm t.md', REFERENCE],
    ["iex 'cd templates'; Remove-Item t.md", 'cd templates; Remove-Item t.md', REFERENCE],
    ['eval cd .claude; rm settings.local.json; cd ..', 'cd .claude; rm settings.local.json; cd ..', GUARDRAIL]]) {
    assert.deepEqual(shell(evaluated), shell(plain), evaluated);
    assertDeny(evaluated, reason);
  }
});

test('B: eval and Invoke-Expression of text the command does not hold are the floor, never routine', () => {
  for (const cmd of ['eval "$(cat docs/a.md)"', 'eval $x', 'eval "cd $dir"', 'eval `cat x.sh`', 'iex $cmd', 'iex (Get-Content x.ps1 -Raw)',
    'Invoke-Expression -Command $x', 'Invoke-Expression "$a; $b"', 'ls && eval $x']) {
    assertFloor(cmd);
  }
  // A literal is judged as a command line of its own: no verdict where it has none.
  for (const cmd of ['eval echo hi', "eval 'ls docs'", 'eval', "iex 'Get-ChildItem docs'", "eval 'echo $HOME'"]) assert.equal(shell(cmd), null, cmd);
});

test('B: lab mode leaves eval and Invoke-Expression of unseen text to the user', () => {
  const lab = project({ 'hardening/harness.config.json': `${JSON.stringify({ approvals: { mode: 'lab' } }, null, 2)}\n` }, 'bi-harness-open-1117-lab-');
  made.push(lab);
  for (const [tool, command] of [['Bash', 'eval $x'], ['Bash', 'eval "$(cat notes.txt)"'], ['PowerShell', 'iex $cmd'], ['PowerShell', 'iex (Get-Content x.ps1 -Raw)']]) {
    assert.equal(hook(lab, command, tool).decision, 'ask', `${tool}: ${command}`);
  }
});

// ---------------------------------------------------------------- C: three git leftovers

test('C: git worktree add -B onto a protected branch is denied like git checkout -B', () => {
  assert.equal(shell('git checkout -B main')?.decision, 'deny');
  for (const cmd of ['git worktree add -B main ../wt', 'git worktree add -B MAIN ../wt HEAD~1', 'git worktree add -fB main ../wt', 'git worktree add -Bmain ../wt',
    'git worktree add ../wt -B main', 'git worktree add -qB main ../wt', "git worktree add -B 'main' ../wt", 'git -C docs worktree add -B main ../wt',
    'git worktree add -B main ../wt 2>&1']) {
    assertDeny(cmd, /git worktree add -B main moves the protected branch main/i);
  }
  for (const cmd of ['git worktree add -b feature/y ../wt', 'git worktree add ../wt', 'git worktree list', 'git worktree add -B feature/y ../wt', 'git worktree add -b main ../wt',
    'git worktree add -B mainline ../wt', 'git worktree remove ../wt', 'git worktree prune']) {
    assert.equal(shell(cmd), null, cmd);
  }
  assert.equal(shell('git worktree add -B main ../wt', unprotected), null);
});

test('C: git -C <dir> checkout and restore of a guardrail file get the verdict of the plain spelling', () => {
  const plainCheckout = shell('git checkout -- hardening/hooks/x.mjs');
  const plainRestore = shell('git restore hardening/hooks/x.mjs');
  assert.equal(plainCheckout?.decision, 'deny');
  for (const cmd of ['git -C hardening checkout -- hooks/x.mjs', 'git -C hardening/hooks checkout -- x.mjs', 'git -C hardening checkout HEAD~1 -- hooks/x.mjs']) {
    assert.deepEqual(shell(cmd), plainCheckout, cmd);
    assertDeny(cmd, GUARDRAIL);
  }
  for (const cmd of ['git -C hardening restore hooks/x.mjs', 'git -C hardening restore --source=HEAD~1 hooks/x.mjs', 'git -C hardening/hooks restore -- x.mjs']) {
    assert.deepEqual(shell(cmd), plainRestore, cmd);
    assertDeny(cmd, GUARDRAIL);
  }
  for (const cmd of ['git -C docs checkout -- a.md', 'git -C docs restore a.md', 'git -C hardening status', 'git -C hardening diff -- hooks/x.mjs', 'git -C hardening restore --staged hooks/x.mjs']) {
    assert.equal(shell(cmd), null, cmd);
  }
});

test('C: a fetch refspec into a protected branch set with -c or stored with git config is denied', () => {
  for (const cmd of ['git -c remote.origin.fetch=+refs/heads/x:refs/heads/main fetch origin', 'git config remote.origin.fetch +refs/heads/x:refs/heads/main',
    'git config --add remote.origin.fetch +refs/heads/x:refs/heads/main', 'git config --global --add remote.origin.fetch refs/heads/x:refs/heads/main',
    'git config --replace-all remote.origin.fetch +refs/heads/*:refs/heads/*', 'git config set --append remote.origin.fetch +x:main',
    'git -c remote.origin.fetch=+refs/heads/*:refs/heads/* pull origin', 'git config remote.origin.fetch +refs/heads/x:refs/heads/MAIN',
    'git config remote.upstream.fetch +refs/heads/x:heads/main', 'git -c remote.origin.fetch=x:main fetch', 'git --config-env=remote.origin.fetch=SPEC fetch origin']) {
    assertDeny(cmd, /fetch refspec into the protected branch main/);
  }
  // The usual refspec, reads, an unset and a refspec without a destination: as before.
  for (const cmd of ['git config remote.origin.fetch +refs/heads/*:refs/remotes/origin/*', 'git -c remote.origin.fetch=+refs/heads/*:refs/remotes/origin/* fetch origin',
    'git config remote.origin.fetch', 'git config --get-all remote.origin.fetch', 'git config --unset remote.origin.fetch refs/heads/main',
    'git config remote.origin.fetch refs/heads/main', 'git config --add remote.origin.fetch +refs/heads/main:refs/remotes/origin/main', 'git fetch origin']) {
    assert.equal(shell(cmd), null, cmd);
  }
  assert.equal(shell('git config remote.origin.fetch +refs/heads/x:refs/heads/main', unprotected), null);
});

test('C: the hook denies them end to end', () => {
  for (const command of ['git worktree add -B main ../wt', 'git -C hardening checkout -- hooks/x.mjs', 'git -C hardening restore hooks/x.mjs',
    'git -c remote.origin.fetch=+refs/heads/x:refs/heads/main fetch origin', 'git config remote.origin.fetch +refs/heads/x:refs/heads/main']) {
    assert.equal(hook(dir, command).decision, 'deny', command);
  }
  for (const command of ['git worktree add -b feature/y ../wt', 'git config remote.origin.fetch +refs/heads/*:refs/remotes/origin/*']) {
    assert.notEqual(hook(dir, command).decision, 'deny', command);
  }
});
