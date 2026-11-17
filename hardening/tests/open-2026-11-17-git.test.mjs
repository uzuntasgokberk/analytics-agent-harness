// Open findings 2026-11-17, git spellings that moved a protected branch, rewrote the git configuration or discarded the
// working tree with no verdict (or only an ask), while the plain spelling of the same act was denied:
// 1. git fetch (and git pull) with a refspec into a protected branch: forced (`+`, --force) from any remote, or from a local
//    path (`git fetch . HEAD~1:main`), where a fast-forward moves main to any commit of that repository.
// 2. git checkout -B main <start> got the guard's "cannot tell" ask; git switch -C main is denied.
// 3. git subtree split -b/--branch main moves main to the split history of a folder (git update-ref).
// 4. A protected branch named in another case (MAIN, Main): on Windows and macOS refs/heads/MAIN is main's loose ref file.
// 5. git config --remove-section / --rename-section of a section that holds a protected key, and git config -e / --edit.
// 6. git checkout-index -f -a (the plumbing under git checkout -- .) and -f <path> in a reference or guardrail folder.
import { after, test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const preHook = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'hooks', 'pre-tool-use.mjs');

// A temporary project (the real path: a Windows short name would not be the project's spelling) with a reference folder, a
// guardrail file and an ordinary one. Set before the modules read CLAUDE_PROJECT_DIR.
const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-open-1117-git-')));
for (const [rel, text] of Object.entries({ 'templates/t.md': '# t\n', 'reports/r1/source/q.sql': 'SELECT 1\n', 'docs/a.md': '# a\n', 'hardening/hooks/x.mjs': '// x\n' })) {
  fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
  fs.writeFileSync(path.join(dir, rel), text);
}
process.env.CLAUDE_PROJECT_DIR = dir;
const { analyzeShellCommand, routineShell } = await import('../hooks/lib/policy.mjs');
after(() => fs.rmSync(dir, { recursive: true, force: true }));

const onFeature = { protectedBranches: ['main'], getBranch: () => 'feature/x', baseDir: dir };
const unprotected = { protectedBranches: [], getBranch: () => 'feature/x', baseDir: dir };
const shell = (cmd, ctx = onFeature) => analyzeShellCommand(cmd, ctx);
const decision = (cmd, ctx = onFeature) => shell(cmd, ctx)?.decision ?? null;
const REFERENCE = /reference folder/i;
const GUARDRAIL = /Harness guardrail files/;

/** Asserts a deny whose reason matches `reason`, and that auto mode never takes the command for routine. */
function assertDeny(cmd, reason, ctx = onFeature) {
  const v = shell(cmd, ctx);
  assert.equal(v?.decision, 'deny', cmd);
  assert.match(v.reason, reason, cmd);
  assert.equal(routineShell(cmd), false, cmd);
}

/** Every proper prefix of a long option from `from` letters on, longest last: prefixes('force', 2) gives fo, for, forc. */
const prefixes = (option, from = 1) => Array.from({ length: option.length - from }, (_, n) => option.slice(0, n + from));

// ---------------------------------------------------------------- 1: git fetch and git pull into a protected branch

test('1: git fetch or pull with a forced refspec, or from a local path, into a protected branch is denied', () => {
  const forms = ['git fetch . +HEAD~1:main', 'git fetch . HEAD~1:main', 'git fetch origin +feature/x:main', 'git fetch --force origin feature/x:main',
    'git fetch -f origin feature/x:main', 'git fetch . +HEAD~1:refs/heads/main', 'git fetch . +HEAD~1:heads/main', 'git fetch . HEAD:refs/heads/main',
    'git fetch . @:main', 'git fetch . +@:main', 'git fetch ./ feature/x:main', 'git fetch .git feature/x:main', 'git fetch ../other feature/x:main',
    'git fetch file:///srv/repo.git feature/x:main', 'git fetch -qf origin feature/x:main', 'git fetch origin feature/x:main --force', "git fetch . '+HEAD~1:main'",
    'git fetch -j 4 . feature/x:main', 'git fetch -j4 . feature/x:main', 'git fetch --depth 1 . feature/x:main', 'git fetch -o x . feature/x:main',
    'git fetch origin feature/x +feature/x:main', "git fetch origin '+refs/heads/*:refs/heads/*'", 'git fetch --refmap=+feature/x:refs/heads/main origin feature/x',
    'git fetch --refmap +feature/x:refs/heads/main origin feature/x', 'git -C docs fetch .. feature/x:main', 'git -C . fetch origin +feature/x:main',
    'git -c user.name=x fetch . +HEAD~1:main', 'git fetch . +HEAD~1:main 2>&1', 'git pull . +HEAD~1:main', 'git pull . feature/x:main',
    'git pull origin +feature/x:main', 'git pull --force origin feature/x:main', 'git pull -s ours . feature/x:main', 'git pull --rebase origin +feature/x:main',
    'git fetch -4f origin feature/x:main', 'git fetch -f4 origin feature/x:main', 'git fetch -fj4 origin feature/x:main', 'git fetch -6qf origin feature/x:main',
    'git pull -4f origin feature/x:main', 'git pull -fs ours origin feature/x:main', 'git pull -j4 . feature/x:main', 'git pull -X ours . feature/x:main'];
  for (const p of prefixes('force', 2)) forms.push(`git fetch --${p} origin feature/x:main`, `git pull --${p} origin feature/x:main`);
  for (const cmd of forms) assertDeny(cmd, /git (?:fetch|pull) with the refspec .* moves the protected branch main/);
  // No protected branch configured: nothing to protect.
  for (const cmd of ['git fetch . +HEAD~1:main', 'git fetch origin +feature/x:main', 'git pull . feature/x:main']) assert.equal(shell(cmd, unprotected), null, cmd);
  // --stdin reads more refspecs, which the guard cannot see: the user decides.
  for (const cmd of ['git fetch --stdin origin', 'git fetch --std origin', 'git fetch origin --stdin']) {
    const v = shell(cmd);
    assert.equal(v?.decision, 'ask', cmd);
    assert.equal(v?.autoApprovable, false, cmd);
  }
});

test('1: must stay: a plain fetch, a fetch into a remote-tracking branch or another branch, and a non-forced fetch from a named remote', () => {
  for (const cmd of ['git fetch origin main:main', 'git fetch origin', 'git fetch --all', 'git fetch origin feature/x', 'git fetch origin main', 'git fetch . main',
    'git fetch', 'git fetch --prune origin', 'git fetch -p', 'git fetch --force origin', 'git fetch -f origin main', 'git fetch origin main:refs/remotes/origin/main',
    "git fetch origin '+refs/heads/*:refs/remotes/origin/*'", 'git fetch origin +main:refs/tags/main', 'git fetch origin +feature/x:feature/y', 'git fetch origin +a:b',
    'git fetch origin :b', 'git fetch . feature/x:feature/y', 'git fetch origin feature/x:main', 'git fetch git@host:owner/repo.git main:main',
    'git fetch https://example.invalid/x.git main:main', 'git fetch origin heads/main:refs/heads/main', 'git pull', 'git pull origin main', 'git pull origin main:main',
    'git pull . main', 'git pull --rebase origin main', 'git pull origin +a:b', 'git pull -s ours origin main', 'git fetch -ofoo origin feature/x:main',
    'git fetch -j4 origin feature/x:main', 'git pull -Sfeed origin feature/x:main', 'git pull -sfoo origin feature/x:main']) {
    assert.equal(shell(cmd), null, cmd);
  }
});

// ---------------------------------------------------------------- 2: git checkout -B onto a protected branch

test('2: git checkout -B onto a protected branch is denied, with or without a start point, in a cluster or glued', () => {
  assert.equal(decision('git switch -C main HEAD~1'), 'deny');
  assert.equal(decision('git switch -C main'), 'deny');
  for (const cmd of ['git checkout -B main HEAD~1', 'git checkout -B main', 'git checkout -qB main HEAD~1', 'git checkout -qB main', 'git checkout -Bmain HEAD~1',
    'git checkout -qBmain', 'git checkout -B main --track origin/main', 'git checkout -B main HEAD~1 2>&1', 'git -C docs checkout -B main HEAD~1',
    "git checkout -B 'main' HEAD~1"]) {
    assertDeny(cmd, /git checkout -B main moves the protected branch main/);
  }
  // -b creates a branch only when it does not exist, and -B onto another branch keeps today's verdict.
  for (const cmd of ['git checkout -b feature/y', 'git checkout -B feature/y', 'git checkout -b main', 'git checkout -B mainline']) assert.equal(shell(cmd), null, cmd);
  assert.equal(shell('git checkout -B main', unprotected), null);
});

// ---------------------------------------------------------------- 3: git subtree -b / --branch

test('3: git subtree split (or push) with -b / --branch onto a protected branch is denied in every spelling', () => {
  const forms = ['git subtree split -b main --prefix=docs', 'git subtree split --prefix=docs --branch main', 'git subtree split --prefix=docs --branch=main',
    'git subtree split -P docs -bmain', 'git subtree split -P docs -qb main', 'git subtree -b main split -P docs', 'git subtree split --prefix docs -b main --rejoin',
    "git subtree split -P docs -b 'main'", 'git subtree push -P docs -b main origin feature/x'];
  for (const p of prefixes('branch')) forms.push(`git subtree split -P docs --${p} main`, `git subtree split -P docs --${p}=main`);
  for (const cmd of forms) assertDeny(cmd, /git subtree -b\/--branch main creates or moves main/);
  // Another branch, main as the prefix, the --onto commit or the message, and a name git takes as written: as before.
  for (const cmd of ['git subtree split -P docs', 'git subtree split --prefix=docs --onto main', 'git subtree split -P docs -b feature/split',
    'git subtree split -P main -b feature/split', 'git subtree split -P docs -m main', 'git subtree split -P docs -b refs/heads/main']) {
    assert.equal(shell(cmd), null, cmd);
  }
  assert.equal(shell('git subtree split -P docs -b main', unprotected), null);
});

// ---------------------------------------------------------------- 4: a protected branch in another case

test('4: a protected branch is compared without case on every platform', () => {
  for (const cmd of ['git branch -f MAIN HEAD~1', 'git branch -f Main HEAD~1', 'git branch -M feature/x MAIN', 'git update-ref refs/heads/MAIN HEAD~1',
    'git update-ref refs/HEADS/main HEAD~1', 'git switch -C MAIN x', 'git checkout -B Main x', 'git checkout -B MAIN', 'git fetch . +x:MAIN', 'git fetch . +x:refs/heads/Main',
    'git push origin HEAD:MAIN', 'git push origin HEAD:refs/heads/Main', 'git push origin HEAD:refs/HEADS/main', 'git push origin feature/x:Main',
    'git subtree split -P docs -b MAIN', 'git send-pack origin HEAD:refs/heads/MAIN', 'git subtree push -P docs origin MAIN']) {
    assert.equal(decision(cmd), 'deny', cmd);
    assert.equal(routineShell(cmd), false, cmd);
  }
  assert.deepEqual(shell('git push origin HEAD:MAIN'), shell('git push origin HEAD:main'));
  // A protected branch configured in another case protects main too.
  const upper = { protectedBranches: ['Main'], getBranch: () => 'feature/x', baseDir: dir };
  for (const cmd of ['git push origin HEAD:main', 'git branch -f main HEAD~1', 'git update-ref refs/heads/main HEAD~1']) assert.equal(decision(cmd, upper), 'deny', cmd);
  // MAIN checked out is main checked out.
  const onUpperMain = { protectedBranches: ['main'], getBranch: () => 'MAIN', baseDir: dir };
  assert.equal(decision('git push origin HEAD', onUpperMain), 'deny');
  assert.equal(decision('git update-ref HEAD HEAD~1', onUpperMain), 'deny');
  assert.equal(decision('git commit -m x', onUpperMain), 'ask');
  // Another name stays another branch; without a protected branch nothing is protected.
  assert.equal(decision('git branch -f mainline HEAD~1'), null);
  assert.equal(decision('git update-ref refs/heads/MAINLINE HEAD'), null);
  assert.equal(decision('git push origin HEAD:mainline'), 'ask');
  assert.equal(decision('git push origin HEAD:MAIN', unprotected), 'ask');
  assert.equal(decision('git branch -f MAIN HEAD~1', unprotected), null);
});

// ---------------------------------------------------------------- 5: git config sections and the editor

test('5: removing or renaming a section that holds a protected key is denied like unsetting the key', () => {
  // One key per section of PROTECTED_CONFIG_SECTIONS: unsetting it is denied today, so is removing or renaming its section.
  const keys = ['core.hooksPath', 'core.pager', 'diff.external', 'diff.x.textconv', 'merge.x.driver', 'alias.co', 'include.path', 'includeIf.gitdir:x/.path',
    'credential.helper', 'credential.https://example.invalid.helper', 'filter.lfs.clean', 'sequence.editor', 'gpg.program', 'ssh.variant', 'uploadpack.allowAnySHA1InWant',
    'receive.denyCurrentBranch', 'url.https://example.invalid/.insteadOf', 'protocol.file.allow', 'safe.directory', 'http.proxy', 'trace2.eventTarget',
    'push.default', 'remote.origin.push', 'remote.origin.mirror'];
  for (const key of keys) {
    const section = key.slice(0, key.lastIndexOf('.'));
    assert.equal(decision(`git config --unset ${key}`), 'deny', `--unset ${key}`);
    for (const cmd of [`git config --remove-section ${section}`, `git config --rename-section ${section} x`, `git config --rename-section x ${section}`,
      `git config remove-section ${section}`, `git config rename-section ${section} x`]) {
      assertDeny(cmd, /removes or renames a whole section/);
    }
  }
  for (const cmd of ['git config --rem core', 'git config --remove core', 'git config --ren core x', 'git config --rena core x', 'git config --global --remove-section alias',
    'git config --file x --remove-section core', 'git config -f x --remove-section core', 'git config --remove-section CORE', 'git config --remove-section Remote.origin',
    'git config core --remove-section', 'git -C docs config --remove-section core', 'git config --global remove-section alias']) {
    assertDeny(cmd, /removes or renames a whole section/);
  }
  // A section with no protected key keeps today's verdict (none).
  for (const cmd of ['git config --remove-section branch.feature', 'git config --rename-section branch.a branch.b', 'git config remove-section user',
    'git config --remove-section color.diff']) {
    assert.equal(shell(cmd), null, cmd);
  }
});

test('5: git config -e / --edit (git config edit) is denied in every scope', () => {
  const forms = ['git config -e', 'git config --edit', 'git config --global -e', 'git config --local --edit', 'git config --file x -e', 'git config --file=x --edit',
    'git config -f x -e', 'git config --system -e', 'git config --worktree --edit', 'git config -ze', 'git config -ef x', 'git config edit', 'git config --global edit',
    'git -C docs config -e'];
  for (const p of prefixes('edit', 2)) forms.push(`git config --${p}`);
  for (const cmd of forms) assertDeny(cmd, /git config -e \/ --edit \(git config edit\) opens the configuration in an editor/);
});

test('5: must stay: reading and ordinary keys', () => {
  for (const cmd of ['git config user.name x', 'git config --get core.hooksPath', 'git config --list', 'git config -l', 'git config list', 'git config get user.name',
    'git config -f edit.cfg user.name x', 'git config --file edit.cfg --list', 'git config -fedit.cfg --list', 'git config user.name edit', 'git config --global user.email x',
    'git config remote.origin.url git@host:owner/repo.git']) {
    assert.equal(shell(cmd), null, cmd);
  }
  assert.equal(decision('git config --unset core.hooksPath'), 'deny');
});

// ---------------------------------------------------------------- 6: git checkout-index

test('6: git checkout-index -f with -a / --all (or .) gets the deny of git checkout -- .', () => {
  const all = shell('git checkout -- .');
  assert.equal(all?.decision, 'deny');
  const forms = ['git checkout-index -a -f', 'git checkout-index -f --all', 'git checkout-index -f -a', 'git checkout-index --force --all', 'git checkout-index -fa',
    'git checkout-index -af', 'git checkout-index -qfa', 'git checkout-index -f -a -u', 'git checkout-index -f .', 'git checkout-index -f -a --prefix=./',
    'git checkout-index -f -a --prefix=out/', 'git -C docs checkout-index -fa', 'git checkout-index -fa 2>&1'];
  for (const p of prefixes('force')) forms.push(`git checkout-index --${p} -a`);
  for (const p of prefixes('all')) forms.push(`git checkout-index -f --${p}`);
  for (const cmd of forms) {
    assert.equal(decision(cmd), all.decision, cmd);
    assertDeny(cmd, /discards uncommitted changes/);
  }
});

test('6: git checkout-index -f <path> judges the path like git checkout -- <path>; without -f it overwrites nothing', () => {
  for (const p of ['docs/a.md', 'templates/t.md', 'reports/r1/source/q.sql', 'hardening/hooks/x.mjs']) {
    const like = shell(`git checkout -- ${p}`);
    for (const cmd of [`git checkout-index -f ${p}`, `git checkout-index -f -- ${p}`, `git checkout-index --force ${p}`, `git checkout-index -qf ${p}`]) {
      assert.deepEqual(shell(cmd), like, cmd);
    }
  }
  assert.equal(shell('git checkout-index -f docs/a.md'), null);
  for (const cmd of ['git checkout-index -f templates/t.md', 'git checkout-index -f -- reports/r1/source/q.sql', 'git -C templates checkout-index -f t.md']) assertDeny(cmd, REFERENCE);
  for (const cmd of ['git checkout-index -f hardening/hooks/x.mjs', 'git -C hardening checkout-index -f hooks/x.mjs']) assertDeny(cmd, GUARDRAIL);
  // The --prefix folder is a written path: a reference or guardrail folder is denied.
  for (const cmd of ['git checkout-index --prefix=templates/ -a', 'git checkout-index --prefix templates/x -a', 'git checkout-index -a --prefix=reports/r1/source/']) {
    assertDeny(cmd, REFERENCE);
  }
  assertDeny('git checkout-index -a --prefix=hardening/', GUARDRAIL);
  // Without -f git leaves the files that exist alone; --temp writes temporary files; --prefix=out/ writes copies elsewhere.
  for (const cmd of ['git checkout-index docs/a.md', 'git checkout-index templates/t.md', 'git checkout-index -a', 'git checkout-index --all', 'git checkout-index -u -a',
    'git checkout-index --prefix=out/ -a', 'git checkout-index -f -a --temp', 'git checkout-index --stdin']) {
    assert.equal(shell(cmd), null, cmd);
  }
  // -f with --stdin overwrites files the guard cannot see: the user decides.
  const v = shell('git checkout-index -f --stdin');
  assert.equal(v?.decision, 'ask');
  assert.equal(v?.autoApprovable, false);
});

// ---------------------------------------------------------------- end to end

// The hook runs with the machine's global and system git configuration left out and without repository variables a caller
// may export (as in audit-2026-11-16-git.test.mjs).
function hookEnv(root) {
  const env = Object.fromEntries(Object.entries(process.env).filter(([k]) => !/^GIT_(?:CONFIG|DIR$|WORK_TREE$|INDEX_FILE$|COMMON_DIR$|OBJECT_DIRECTORY$|ALTERNATE)/i.test(k)));
  delete env.BI_HARNESS_HOST;
  const globalConfig = path.join(root, 'empty.gitconfig');
  if (!fs.existsSync(globalConfig)) fs.writeFileSync(globalConfig, '');
  return { ...env, CLAUDE_PROJECT_DIR: root, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: globalConfig, GIT_CEILING_DIRECTORIES: path.dirname(root) };
}

/** The PreToolUse guard's decision for one shell command, run as a process like Claude Code runs it (auto mode, the default). */
function hookDecision(root, command, tool_name = 'Bash') {
  const r = spawnSync(process.execPath, [preHook], {
    input: JSON.stringify({ hook_event_name: 'PreToolUse', session_id: 'open-1117-git', tool_name, tool_input: { command } }),
    env: hookEnv(root),
    encoding: 'utf8',
  });
  assert.equal(r.status, 0, r.stderr); // a guard that did not run prints no verdict, which "not allow" would read as a pass
  return r.stdout.trim() ? JSON.parse(r.stdout).hookSpecificOutput?.permissionDecision ?? null : null;
}

test('1-6: the PreToolUse hook denies them end to end and leaves the ordinary spellings alone', () => {
  for (const command of ['git fetch . +HEAD~1:main', 'git fetch . HEAD~1:main', 'git fetch origin +feature/x:main', 'git pull . +HEAD~1:main', 'git checkout -B main HEAD~1',
    'git subtree split -b main --prefix=docs', 'git branch -f MAIN HEAD~1', 'git push origin HEAD:MAIN', 'git config --remove-section core', 'git config -e',
    'git checkout-index -a -f', 'git checkout-index -f templates/t.md']) {
    assert.equal(hookDecision(dir, command), 'deny', command);
  }
  assert.equal(hookDecision(dir, 'git fetch . +HEAD~1:main', 'PowerShell'), 'deny');
  for (const command of ['git fetch origin main:main', 'git checkout-index docs/a.md', 'git config --remove-section branch.feature']) {
    assert.notEqual(hookDecision(dir, command), 'deny', command);
  }
});
