// Findings of the 2026-10-08 audit of the pack (an independent code review and a security audit), each kept as a test:
// redirects with a stream number or &, PowerShell separators behind a backslash, the harness-script exemption, git
// options that write or read any file, forced switches, secret names hidden by quotes or wildcards, interpreters fed
// from stdin, git config keys that run programs, administrative-share spellings of the project, and a lab mode that
// must never be committed. Each case was a silent pass before the fix: the guard said nothing, or answered "allow".
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyzeShellCommand, redirectTargets, routineShell } from '../hooks/lib/policy.mjs';
import { opaquePath } from '../hooks/lib/common.mjs';
import { validateFileText } from '../hooks/lib/validators.mjs';

const shell = (cmd) => analyzeShellCommand(cmd, {});
const decision = (cmd) => shell(cmd)?.decision ?? null;
const scopeHook = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'hooks', 'agent-scope.mjs');

/** The subagent scope guard's decision for one call, run as a process like Claude Code runs it. */
function scope(dir, agent, tool, tool_input) {
  const r = spawnSync(process.execPath, [scopeHook], {
    input: JSON.stringify({ hook_event_name: 'PreToolUse', session_id: 'gaps', agent_type: agent, tool_name: tool, tool_input }),
    env: { ...process.env, CLAUDE_PROJECT_DIR: dir },
    encoding: 'utf8',
  });
  assert.equal(r.status, 0, r.stderr);
  return r.stdout.trim() ? JSON.parse(r.stdout).hookSpecificOutput?.permissionDecision ?? null : null;
}

test('audit: a redirect with a stream number, & or | is a write like a plain >', () => {
  const tmdl = 'powerbi/Sales.SemanticModel/definition/tables/Sales.tmdl';
  for (const cmd of [`echo "measure X = 1" 1> ${tmdl}`, 'echo x 2> docs/x.md', 'echo x &> docs/x.md', 'echo x >| docs/x.md',
    'echo x >& docs/x.md', 'echo x 1>> docs/x.md', 'echo x *> docs/x.md']) {
    assert.equal(decision(cmd), 'deny', cmd);
    assert.equal(routineShell(cmd), false, cmd);
  }
  assert.deepEqual(redirectTargets('echo x 2>&1 >/dev/null'), ['/dev/null']);
  assert.deepEqual(redirectTargets('echo x >&1'), [], '>&1 duplicates a stream; it names no file');
  assert.deepEqual(redirectTargets('echo x 1> a.tmdl 2>> "b c.md" &> \'d.md\''), ['a.tmdl', 'b c.md', 'd.md']);
  for (const cmd of ['git status 2>&1', 'git status > /dev/null 2>&1', 'git log -1 >$null']) {
    assert.equal(decision(cmd), null, cmd);
    assert.equal(routineShell(cmd), true, cmd);
  }
});

test('audit: a backslash before ; & or | hides nothing (PowerShell gives a backslash no meaning)', () => {
  const push = shell('echo a\\;git push origin feature/x');
  assert.equal(push?.decision, 'ask');
  assert.equal(push?.floor, true, 'the push behind the backslash is the floor ask');
  assert.equal(decision('echo a\\&&git push --force origin main'), 'deny');
  assert.equal(shell('echo a\\|git push origin feature/x')?.floor, true);
  assert.equal(shell('echo a\\;node evil.mjs')?.decision, 'ask', 'the script behind the backslash asks');
  for (const cmd of ['echo a\\;git push origin feature/x', 'echo a\\&&git push --force origin main', 'echo a\\|git push origin feature/x', 'echo a\\;node evil.mjs']) {
    assert.equal(routineShell(cmd), false, cmd);
  }
  assert.equal(decision('echo "a\\;b"'), null, 'inside quotes nothing runs');
  assert.equal(decision('find . -name "*.tmp" -exec rm {} \\;'), 'ask', 'find -exec rm keeps its ask, no more');
});

test('audit: only the harness checks are routine scripts; the installer and the Copilot sync are ordinary script runs', () => {
  for (const cmd of ['node hardening/scripts/validate.mjs --changed', 'node hardening/scripts/rdl-compare.mjs a.rdl b.rdl', 'node hardening/tests/run-all.mjs']) {
    assert.equal(decision(cmd), null, cmd);
    assert.equal(routineShell(cmd), true, cmd);
  }
  for (const cmd of ['node hardening/scripts/install-into.mjs C:/elsewhere --hardening --enable-hooks', 'node hardening/scripts/sync-copilot-instructions.mjs',
    'node hardening/tests/eval/run-eval.mjs', 'node hardening/scripts/../scripts/install-into.mjs .']) {
    const v = shell(cmd);
    assert.equal(v?.decision, 'ask', cmd);
    assert.equal(v?.autoDefer, true, `${cmd}: Claude Code's own prompt decides in auto mode`);
    assert.equal(routineShell(cmd), false, cmd);
  }
});

test('audit: git options that write or read any file are denied; a forced switch is denied and never routine', () => {
  for (const cmd of ['git diff --output=.claude/settings.json HEAD~1', 'git diff --output hardening/hooks/pre-tool-use.mjs HEAD~1',
    'git log --output=AGENTS.md -1', 'git show --output=x.md HEAD', 'git diff --no-index ~/.aws/credentials /dev/null',
    'git diff --no-index a.md b.md', 'git diff --ext-diff', 'git log --textconv -p']) {
    assert.equal(decision(cmd), 'deny', cmd);
    assert.equal(routineShell(cmd), false, cmd);
  }
  for (const cmd of ['git switch -f main', 'git switch --force main', 'git switch --discard-changes main', 'git switch -C main',
    'git switch --force-create main', 'git switch -fc x']) {
    assert.equal(decision(cmd), 'deny', cmd);
    assert.equal(routineShell(cmd), false, cmd);
  }
  // A switch to another commit is judged by the harness files it holds (F2-2, tests/round2-git.test.mjs): HEAD here.
  for (const cmd of ['git switch -c feature/x', 'git switch --detach HEAD', 'git diff HEAD~1', 'git log -1 --stat', 'git show HEAD --stat']) {
    assert.equal(decision(cmd), null, cmd);
    assert.equal(routineShell(cmd), true, cmd);
  }
});

test('audit: a secret file name hidden by quotes or a wildcard is still a secret file; cloud credentials count too', () => {
  for (const cmd of ["cat .en''v", 'cat .e"n"v', 'type ".env"', 'cat *.env', 'cat *.pem', 'grep -n key *.key', 'cat .e*v', 'Get-Content *.pfx']) {
    assert.equal(decision(cmd), 'deny', cmd);
  }
  for (const cmd of ['cat ~/.aws/credentials', 'type %USERPROFILE%\\.git-credentials', 'cat ~/.config/gh/hosts.yml',
    'Get-Content $HOME/.azure/accessTokens.json', 'cat ~/.kube/config', 'cat ~/.docker/config.json', 'cat .pypirc']) {
    assert.equal(decision(cmd), 'deny', cmd);
  }
  for (const cmd of ['ls *.env', 'cat *.md', 'cat *.json', 'cat a*', "find . -name '*.pem'", 'cat .env.example', 'git ls-files *.env', 'Get-ChildItem *.pem']) {
    assert.equal(decision(cmd), null, cmd);
  }
});

test('audit: text piped into an interpreter without a script is code the guard cannot read: the floor', () => {
  for (const cmd of ['echo aGk= | base64 -d | bash', 'cat x | pwsh -', 'git show HEAD:x.ps1 | powershell -', 'cat x.py | python3 -',
    'type x.js | node', 'echo x | sh', 'Get-Content x.ps1 | iex', 'cat x | cmd']) {
    const v = shell(cmd);
    assert.equal(v?.decision, 'ask', cmd);
    assert.equal(v?.floor, true, cmd);
    assert.equal(routineShell(cmd), false, cmd);
  }
  for (const cmd of ['echo x | grep y', 'git log | head -3', 'cat a.json | node hardening/scripts/validate.mjs', 'echo "{}" | node hardening/hooks/pre-tool-use.mjs',
    'cat x | pwsh -NoProfile -Command "git status"']) {
    assert.ok(!shell(cmd)?.floor, cmd);
  }
});

// F1-21 (audit 2026-10-18): a command inside a block, a function body, a case arm or the -ArgumentList of Start-Process got no
// verdict, while the same command inside `& { }` or `if ...; then ...; fi` was denied.
test('audit: commands inside blocks, function bodies, case arms and Start-Process -ArgumentList are judged like bare ones', () => {
  for (const cmd of [
    "Start-Process git -ArgumentList 'push','-f','origin','feat'", "Start-Process -FilePath git -ArgumentList 'push -f origin feat' -NoNewWindow -Wait",
    "Start-Process git 'push -f origin feat'", 'saps git -Args push,-f,origin,feat', "Start-Process git -ArgumentList @('push','-f','origin','feat')",
    "Start-Process cmd -ArgumentList '/c','git push -f origin feat'",
    'if ($true) { git push -f origin feat }', 'try { git push -f origin feat } catch {}', 'while ($true) { git push -f origin feat }',
    'function f { git push -f origin feat }; f', '$sb = { git push -f origin feat }; & $sb',
    'Invoke-Command -ComputerName localhost -ScriptBlock { git push -f origin feat }',
    'foreach ($x in 1..2) { git push -f origin feat; if ($x) { echo hi } }', // a block that holds another block is judged with its own commands
    'f() { git push -f origin feat; }; f', 'function f { git push -f origin feat; }; f', 'f() { git push -f origin feat; if true; then echo hi; fi; }; f',
    'case x in x) git push -f origin feat;; esac', 'case x in a) echo a;; b) git push -f origin feat;; esac', 'case x in a|b) git push -f origin feat;; esac',
    '& { git push -f origin feat }', 'if true; then git push -f origin feat; fi', // the forms that were judged before
  ]) {
    assert.equal(decision(cmd), 'deny', cmd);
  }
  const main = analyzeShellCommand("Start-Process git -ArgumentList 'push','origin','main'", { protectedBranches: ['main'] });
  assert.equal(main?.decision, 'deny', 'a push to a protected branch through Start-Process');
  assert.equal(shell("Start-Process git -ArgumentList 'push','origin','feat'")?.floor, true, 'a plain push through Start-Process is the floor ask');
  // Braces that hold no command stay quiet: expansions, hashtables, format strings, awk programs; so does the rest of the syntax.
  for (const cmd of ['git stash show stash@{0}', 'echo ${HOME}', 'echo {a,b}.md', "awk '{print $1}' docs/a.md", '$x = @{ a = 1 }', "'{0} files' -f 3",
    'Get-ChildItem | ForEach-Object { $_.Name }', 'f() { echo hi; }; f', 'case $x in a) echo a;; b) echo b;; esac', 'Start-Process notepad',
    "Start-Process git -ArgumentList 'status'"]) {
    assert.equal(decision(cmd), null, cmd);
  }
  assert.equal(routineShell("Start-Process git -ArgumentList 'status' -WorkingDirectory docs"), true);
  assert.equal(routineShell("Start-Process git -ArgumentList 'push','-f'"), false);
  for (const cmd of ['f() { git status; }; f', 'case x in x) git status;; esac', 'try { git status } catch {}']) {
    assert.equal(routineShell(cmd), false, `${cmd}: code in a block is never routine`);
  }
  // Blocks nested deeper than the analysis goes are not skipped: the user decides.
  const started = Date.now();
  const deep = shell(`${'{ a '.repeat(10)}${'}'.repeat(10)}`);
  assert.equal(deep?.floor, true);
  assert.ok(Date.now() - started < 2000, `took ${Date.now() - started} ms`);
});

test('audit: shell writes to .github, .vscode, .gitignore and friends are guardrail writes; an administrative share is opaque', () => {
  for (const cmd of ['echo x > .gitignore', 'echo x > .github/workflows/ci.yml', 'echo x > .vscode/settings.json', 'echo x > .gitattributes',
    'echo x > .cursor/rules/x.mdc', 'Set-Content .claude/rules/bi/x.md y', 'cp a .claude/bi-agent-harness.json', 'tee .github/hooks/x.json']) {
    assert.equal(decision(cmd), 'deny', cmd);
  }
  for (const p of ['\\\\localhost\\C$\\repo\\hardening\\harness.config.json', '//127.0.0.1/c$/repo/x.tmdl', '\\\\MYPC\\D$\\x']) {
    assert.equal(opaquePath(p), true, p);
  }
  for (const p of ['\\\\server\\share\\x.md', 'C:\\repo\\x.md', '/c/repo/x.md', 'docs/x.md']) assert.equal(opaquePath(p), false, p);
});

test('audit: git config keys that run a program or redirect git are denied, on the command line and in the environment too', () => {
  for (const cmd of ['git config core.fsmonitor ./x.sh', 'git config core.pager x', 'git config --global core.editor x', "git config alias.x '!sh'",
    'git config diff.external x', 'git config diff.tmdl.textconv cat', 'git config include.path ../x', 'git config credential.helper x',
    'git config core.sshCommand x', 'git -c core.pager=x log', 'git -c diff.external=x diff', 'GIT_EXTERNAL_DIFF=x git diff', 'GIT_PAGER=x git log',
    'git config core.hooksPath .git/hooks']) {
    assert.equal(decision(cmd), 'deny', cmd);
  }
  for (const cmd of ['git config --get core.hooksPath', 'git config --list', 'git config user.name x', 'git config core.hooksPath hardening/githooks',
    'git log --grep alias.x', 'git commit -m "document core.pager"']) {
    assert.notEqual(decision(cmd), 'deny', cmd);
  }
});

test('audit: a harness config in lab mode is an error when staged or in a full scan, never in the Stop gate (changed files)', () => {
  const rel = 'hardening/harness.config.json';
  const lab = '{ "approvals": { "mode": "lab" } }';
  const auto = '{ "approvals": { "mode": "auto" } }';
  const labErrors = (text, opts) => validateFileText(rel, text, opts).filter((i) => i.level === 'error' && /lab/.test(i.message));
  for (const mode of ['staged', 'full']) {
    assert.equal(labErrors(lab, { mode }).length, 1, mode);
    assert.equal(labErrors(' { "approvals": { "mode": " Lab " } }', { mode }).length, 1, `${mode}: spelling variants count`);
    assert.equal(labErrors(auto, { mode }).length, 0, mode);
  }
  assert.equal(labErrors(lab, { mode: 'changed' }).length, 0, 'the user\'s own switch in a working tree is not an error');
  assert.equal(labErrors(lab, {}).length, 0);
  assert.equal(labErrors('{ not json', { mode: 'staged' }).length, 0, 'broken JSON is reported by the JSON check, once');
});

test('audit: the Stop gate finds a broken binding through git, not by walking the tree', () => {
  const validator = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'scripts', 'validate.mjs');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-gaps-'));
  const write = (rel, content) => { fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true }); fs.writeFileSync(path.join(dir, rel), content); };
  const git = (...args) => spawnSync('git', ['-C', dir, ...args], { encoding: 'utf8' });
  const run = () => {
    const r = spawnSync(process.execPath, [validator, '--changed', '--json'], { env: { ...process.env, CLAUDE_PROJECT_DIR: dir }, encoding: 'utf8' });
    assert.ok(r.stdout.trim(), r.stderr);
    return JSON.parse(r.stdout).issues.filter((i) => i.level === 'error' && /M\.SemanticModel|binding|byPath/i.test(`${i.file} ${i.message}`));
  };
  try {
    write('M.SemanticModel/definition.pbism', '{}');
    write('M.SemanticModel/definition/model.tmdl', 'model Model\n');
    write('M.SemanticModel/definition/tables/T.tmdl', 'table T\n\n\tcolumn A\n\t\tdataType: int64\n\t\tsourceColumn: A\n');
    write('R.Report/definition.pbir', JSON.stringify({ datasetReference: { byPath: { path: '../M.SemanticModel' } } }));
    write('R.Report/definition/report.json', '{}');
    git('init', '-q');
    git('add', '-A');
    git('-c', 'user.name=t', '-c', 'user.email=t@example.com', 'commit', '-q', '-m', 'init');
    const before = run().length;
    fs.rmSync(path.join(dir, 'M.SemanticModel'), { recursive: true, force: true });
    assert.ok(run().length > before, 'the surviving report, a candidate from git ls-files, reports its missing model');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('audit: a read-only subagent cannot write through 1> or &> either', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-gaps-'));
  try {
    for (const cmd of ['echo x 1> a.tmdl', 'echo x &> docs/x.md', 'echo x > docs/x.md', 'echo x 2>> log.md']) {
      assert.equal(scope(dir, 'bi-dax-reviewer', 'Bash', { command: cmd }), 'deny', cmd);
    }
    for (const cmd of ['git status 2>&1', 'git log -1 >$null 2>&1', 'node hardening/scripts/validate.mjs --changed']) {
      assert.equal(scope(dir, 'bi-dax-reviewer', 'Bash', { command: cmd }), null, cmd);
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// Audit 2026-10-18, git options (F1-4, F1-10, F1-14, F1-15). The abbreviations below were probed against git 2.52.
const preHook = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'hooks', 'pre-tool-use.mjs');

/** The PreToolUse guard's decision for one shell command, run as a process like Claude Code runs it (auto mode, the default). */
function hookDecision(dir, command, tool_name = 'Bash') {
  const r = spawnSync(process.execPath, [preHook], {
    input: JSON.stringify({ hook_event_name: 'PreToolUse', session_id: 'git-options', tool_name, tool_input: { command } }),
    env: { ...process.env, CLAUDE_PROJECT_DIR: dir },
    encoding: 'utf8',
  });
  assert.equal(r.status, 0, r.stderr); // a guard that did not run prints no verdict, which "not allow" would read as a pass
  return r.stdout.trim() ? JSON.parse(r.stdout).hookSpecificOutput?.permissionDecision ?? null : null;
}

// F1-4: git reads any unambiguous prefix of a long option as that option: `git commit --no-verif` skips the hooks, `git switch
// --discard` drops the changes, `git grep --no-ind` searches outside the repository. The checks compared full names only, so
// the abbreviation was routine while the full spelling was denied.
test('F1-4: an abbreviated long option is judged exactly like the option it abbreviates', () => {
  const pairs = [
    ['git switch --discard main', 'git switch --discard-changes main'], ['git switch --disc main', 'git switch --discard-changes main'],
    ['git switch --discard-change main', 'git switch --discard-changes main'], ['git switch --force-c main', 'git switch --force-create main'],
    ['git switch --force-c=feature/x', 'git switch --force-create=feature/x'],
    ['git commit -m x --no-verif', 'git commit -m x --no-verify'], ['git commit -m x --no-veri', 'git commit -m x --no-verify'],
    ['git commit --amen -m x', 'git commit --amend -m x'],
    ['git branch --delet --forc x', 'git branch --delete --force x'], ['git branch --delet --force x', 'git branch --delete --force x'],
    ['git add --forc .', 'git add --force .'], ['git add --f .', 'git add --force .'],
    ['git push --forc origin feature/x', 'git push --force origin feature/x'], ['git push --no-verif origin feature/x', 'git push --no-verify origin feature/x'],
    ['git push --force-w origin feature/x', 'git push --force-with-lease origin feature/x'],
    ['git push --force-with-lea=main origin feature/x', 'git push --force-with-lease=main origin feature/x'],
    ['git push --force-i origin feature/x', 'git push --force-if-includes origin feature/x'], ['git push --mirro origin', 'git push --mirror origin'],
    ['git push --dele origin feature/x', 'git push --delete origin feature/x'], ['git push --pru origin', 'git push --prune origin'],
    ['git reset --har HEAD~1', 'git reset --hard HEAD~1'], ['git clean --forc', 'git clean --force'], ['git checkout --forc t1', 'git checkout --force t1'],
    ['git restore --staged --worktr .', 'git restore --staged --worktree .'], ['git gc --prun=now', 'git gc --prune=now'],
    ['git grep --no-ind -e x ../other', 'git grep --no-index -e x ../other'], ['git grep --textc x', 'git grep --textconv x'],
    ['git cat-file --textc HEAD:README.md', 'git cat-file --textconv HEAD:README.md'], ['git cat-file --text HEAD:README.md', 'git cat-file --textconv HEAD:README.md'],
  ];
  for (const [abbreviated, full] of pairs) {
    const expected = shell(full);
    assert.ok(['deny', 'ask'].includes(expected?.decision), `${full} is judged`);
    assert.deepEqual(shell(abbreviated), expected, abbreviated);
    assert.equal(routineShell(abbreviated), routineShell(full), abbreviated);
  }
  // A prefix that several options share is an error in git; the guard never reads it as no option at all.
  for (const cmd of ['git push --f origin feature/x', 'git push --fo origin feature/x', 'git push --for origin feature/x', 'git switch --f main',
    'git switch --for main', 'git commit -m x --no-v', 'git commit -m x --no-ver', 'git commit -m x --no-', 'git add --fo .']) {
    assert.equal(decision(cmd), 'deny', cmd);
  }
  // Options that only begin like a judged one, and options of diff, log and show (full names only), stay as they were.
  const quiet = ['git commit -m x --allow-empty', 'git commit --all -m x', 'git add --all', 'git add --patch', 'git add --dry-run .', 'git add --intent-to-add x',
    'git switch --create feature/x', 'git switch --detach HEAD', 'git branch --list', 'git branch --show-current', 'git branch --contains HEAD',
    'git branch --merged', 'git diff --text', 'git diff --stat', 'git grep --text x', 'git grep --no-color x', 'git cat-file -p HEAD:README.md',
    'git cat-file --batch-check', 'git log --text -1'];
  for (const cmd of quiet) {
    assert.equal(decision(cmd), null, cmd);
    assert.equal(routineShell(cmd), true, cmd);
  }
  // A subcommand named like a property of Object.prototype has no options to spell out (and no crash).
  for (const name of ['constructor', 'toString', '__proto__', 'hasOwnProperty']) {
    assert.equal(decision(`git ${name} --force`), null, name);
    assert.equal(routineShell(`git ${name} --force`), false, name);
  }
});

test('F1-4: every prefix of every judged long option is read as that option', () => {
  const judged = [
    ['switch', 'discard-changes', (o) => `git switch ${o} main`], ['switch', 'force', (o) => `git switch ${o} main`],
    ['switch', 'force-create', (o) => `git switch ${o} main`], ['switch', 'orphan', (o) => `git switch ${o} tmp`],
    ['checkout', 'force', (o) => `git checkout ${o} t1`], ['checkout', 'orphan', (o) => `git checkout ${o} tmp`],
    ['branch', 'delete', (o) => `git branch ${o} --force x`], ['branch', 'force', (o) => `git branch --delete ${o} x`],
    ['branch', 'move', (o) => `git branch ${o} a b`], ['branch', 'copy', (o) => `git branch ${o} a b`],
    ['commit', 'no-verify', (o) => `git commit -m x ${o}`], ['commit', 'amend', (o) => `git commit ${o} -m x`],
    ['add', 'force', (o) => `git add ${o} .`], ['clean', 'force', (o) => `git clean ${o}`], ['reset', 'hard', (o) => `git reset ${o} HEAD~1`],
    ['restore', 'worktree', (o) => `git restore --staged ${o} .`], ['gc', 'prune', (o) => `git gc ${o}=now`],
    ['push', 'no-verify', (o) => `git push ${o} origin feature/x`], ['push', 'force', (o) => `git push ${o} origin feature/x`],
    ['push', 'force-with-lease', (o) => `git push ${o} origin feature/x`], ['push', 'force-if-includes', (o) => `git push ${o} origin feature/x`],
    ['push', 'mirror', (o) => `git push ${o} origin`], ['push', 'delete', (o) => `git push ${o} origin feature/x`],
    ['push', 'prune', (o) => `git push ${o} origin feature/x`],
    ['grep', 'no-index', (o) => `git grep ${o} -e x ../other`], ['grep', 'textconv', (o) => `git grep ${o} x`],
    ['cat-file', 'textconv', (o) => `git cat-file ${o} HEAD:README.md`],
  ];
  for (const [sub, option, command] of judged) {
    const full = command(`--${option}`);
    for (let n = 1; n < option.length; n++) {
      const prefix = option.slice(0, n);
      if (sub === 'grep' && prefix === 'text') continue; // git grep --text is an option of its own (-a), not --textconv
      const abbreviated = command(`--${prefix}`);
      assert.deepEqual(shell(abbreviated), shell(full), abbreviated);
      assert.equal(routineShell(abbreviated), routineShell(full), abbreviated);
    }
  }
});

// F1-10: `git switch --orphan` starts a branch with an empty tree and so removes every tracked file from the working tree,
// hardening/ and .claude/ included; the hooks then cannot start and the commands after it run unguarded.
test('F1-10: git switch --orphan and git checkout --orphan are denied, never routine; the other switches stay routine', () => {
  for (const cmd of ['git switch --orphan tmp', 'git switch --orphan=tmp', 'git switch --orph tmp', 'git switch --or tmp', 'git switch -q --orphan tmp',
    'git checkout --orphan tmp', 'git checkout --orph=tmp', 'git -C docs switch --orphan tmp']) {
    const v = shell(cmd);
    assert.equal(v?.decision, 'deny', cmd);
    assert.match(v.reason, /empty tree.*hardening\/.*\.claude\//, cmd);
    assert.equal(routineShell(cmd), false, cmd);
  }
  for (const cmd of ['git switch -c feature/x', 'git switch --create feature/x', 'git switch --detach HEAD', 'git switch --detach']) {
    assert.equal(decision(cmd), null, cmd);
    assert.equal(routineShell(cmd), true, cmd);
  }
});

// F1-14: --git-dir and --work-tree (with = or the value as the next word) point git at another repository, whose
// configuration it then runs (core.fsmonitor), or at files outside the project; GIT_DIR= was denied, the option was routine.
test('F1-14: --git-dir, --work-tree, --namespace and --exec-path are denied like the GIT_* variables', () => {
  assert.equal(shell('GIT_DIR=../x/.git git status')?.decision, 'deny');
  for (const cmd of ['git --git-dir=../x/.git --work-tree=. status', 'git --git-dir=../x/.git log', 'git --git-dir ../x/.git status', 'git --work-tree=/ status',
    'git --work-tree / status', 'git --work-tree=. --git-dir=../x/.git status', 'git --namespace=foo status', 'git --namespace foo status',
    'git --exec-path=./bin status', 'git --exec-path status', 'git --no-pager --git-dir=../x/.git log', 'git -C docs --git-dir=../x/.git status',
    'git -c core.quotepath=false --work-tree=/ status', 'env git --git-dir=../x/.git status', 'bash -c "git --git-dir=../x/.git status"',
    "Start-Process git -ArgumentList '--git-dir=../x/.git','status'"]) {
    const v = shell(cmd);
    assert.equal(v?.decision, 'deny', cmd);
    assert.match(v.reason, /GIT_\*/, cmd);
    assert.equal(routineShell(cmd), false, cmd);
  }
  // The word after a global option that takes a value is its value, not the subcommand: `git --attr-source status push -f`
  // runs push, which the guard read as `status` (routine, no verdict) while the full command line was a force push.
  for (const cmd of ['git --attr-source status push --force origin main', 'git --attr-source log push -f origin feature/x',
    'git --super-prefix x/ push --force origin feature/x', 'git --config-env core.quotepath=Q push --force origin feature/x',
    'git -c core.quotepath=false push --force origin feature/x']) {
    assert.equal(decision(cmd), 'deny', cmd);
  }
  assert.equal(shell('git --attr-source status push origin feature/x')?.floor, true, 'a plain push behind the same words is the floor ask');
  assert.equal(routineShell('git --attr-source status push origin feature/x'), false);
  // A harmless global option, or its value, changes nothing.
  for (const cmd of ['git --no-pager log -1', 'git --attr-source HEAD status', 'git --attr-source=HEAD status', 'git status']) {
    assert.equal(decision(cmd), null, cmd);
    assert.equal(routineShell(cmd), true, cmd);
  }
  assert.equal(decision('git -c core.quotepath=false status'), null);
});

// F1-15: checkSubcommand returned checkGit's verdict before the shell-write and reference-folder checks, so a redirect
// from a git command into a guarded file got no verdict while the same redirect from echo was denied.
test('F1-15: a git command that redirects into a guarded file, AGENTS.md or a reference folder is denied like echo', () => {
  const echo = shell('echo x > docs/notes.md');
  assert.equal(echo?.decision, 'deny');
  for (const cmd of ['git show HEAD:README.md > templates/x.json', 'git show HEAD:README.md > docs/notes.md', 'git diff > M.SemanticModel/definition/model.tmdl',
    'git show HEAD:README.md > AGENTS.md', 'git log -1 2> docs/notes.md', 'git show HEAD:README.md > reports/r/source/x.rdl',
    'git show HEAD:README.md >> docs/notes.md', 'git show HEAD:README.md &> docs/notes.md', 'git log -1 >| docs/notes.md',
    'git show HEAD:README.md > "docs/notes.md"', 'git diff 1> a.tmdl', 'env git show HEAD:README.md > docs/notes.md',
    'git show HEAD:README.md > docs/notes.md.']) { // Windows drops the trailing dot: docs/notes.md
    assert.deepEqual(shell(cmd), echo, cmd);
    assert.equal(routineShell(cmd), false, cmd);
  }
  // Reading, the null device and a file nothing guards are as before.
  for (const cmd of ['git show HEAD:README.md', 'git diff > /dev/null', 'git diff 2>&1', 'git log -1 >$null', 'git status > /dev/null 2>&1']) {
    assert.equal(decision(cmd), null, cmd);
    assert.equal(routineShell(cmd), true, cmd);
  }
  assert.equal(decision('git show HEAD:README.md > out.txt'), null);
  // A `>` inside a quoted commit message or search pattern is text, not a redirect (before F1-15 these commands had no verdict
  // at all, and the redirect pattern reads `-> b.md"` as a redirect into b.md) ...
  for (const cmd of ['git commit -m "rename a.md -> b.md"', "git commit -m 'rename a.tmdl -> b.tmdl'", 'git commit -m "x" -m "a -> b.md"',
    'git tag -a v1 -m "rename a.md -> b.md"', 'git log --grep "a > b.md" -1', 'git commit -m "it\'s a -> b.md"']) {
    assert.equal(decision(cmd), null, cmd);
  }
  // ... while a redirect of the same command is still one, also when the message names the same file or the target holds a space.
  for (const cmd of ['git commit -m x > docs/notes.md', 'git commit -m "rename a.md -> b.md" > docs/notes.md', 'git commit -m "docs/notes.md" > docs/notes.md',
    'git commit -m "docs/notes.md" > "docs/notes.md"', 'git commit -m "docs/notes.md" >"docs/notes.md"', 'git commit -m "docs/notes.md" 2>"docs/notes.md"',
    'git log --grep x > "docs/my notes.md"', 'git commit -m "x" ; echo y > docs/notes.md', 'git commit -m "a -> b.md" | tee docs/notes.md']) {
    assert.equal(decision(cmd), 'deny', cmd);
  }
  assert.equal(decision('echo "rename a.md -> b.md"'), 'deny', 'other programs are judged as before');
});

test('F1-4, F1-10, F1-14, F1-15: the PreToolUse hook answers deny where it once answered allow or nothing, and still allows routine git', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-git-options-'));
  try {
    for (const command of ['git switch --discard main', 'git switch --force-c main', 'git commit -m x --no-verif', 'git add --forc .', 'git branch --delet --forc x',
      'git push --forc origin feature/x', 'git grep --no-ind -e x ../other', 'git switch --orphan tmp', 'git checkout --orphan tmp',
      'git --git-dir=../x/.git --work-tree=. status', 'git --git-dir ../x/.git status', 'git --attr-source status push --force origin main',
      'git show HEAD:README.md > docs/notes.md', 'git show HEAD:README.md > templates/x.json']) {
      assert.equal(hookDecision(dir, command), 'deny', command);
    }
    assert.equal(hookDecision(dir, 'git commit -m x --no-verif', 'PowerShell'), 'deny');
    for (const command of ['git switch -c feature/x', 'git switch --detach', 'git status', 'git diff --text', 'git show HEAD:README.md', 'git diff > /dev/null',
      'git --no-pager log -1']) {
      assert.equal(hookDecision(dir, command), 'allow', command);
    }
    // In ask mode the settings allow rules (git switch *, git commit *, git add *) are what would run an abbreviation: the hook denies it there too.
    fs.mkdirSync(path.join(dir, 'hardening'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'hardening', 'harness.config.json'), JSON.stringify({ approvals: { mode: 'ask' } }));
    for (const command of ['git switch --discard main', 'git commit -m x --no-verif', 'git add --forc .', 'git switch --orphan tmp', 'git --git-dir ../x/.git status']) {
      assert.equal(hookDecision(dir, command), 'deny', `ask mode: ${command}`);
    }
    assert.equal(hookDecision(dir, 'git status'), null, 'ask mode leaves routine git to Claude Code');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
