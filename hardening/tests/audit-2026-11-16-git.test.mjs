// Audit 2026-11-16, git commands that publish or move a protected branch, or take the hooks out of the working tree. Each
// was reproduced through the spawned PreToolUse hook before the fix:
// 6. A push whose destination is spelled heads/main (`git push origin heads/main`, `HEAD:heads/main`) got the ordinary push
//    ask, while main and refs/heads/main were denied. git finds refs/heads/main for heads/main by its `refs/%s` rule: a
//    local bare repository took both pushes onto its main.
// 7. Plumbing that publishes or moves a protected branch had no verdict at all: git send-pack (the plumbing under git push,
//    without the pre-push hook; `--force origin +main` rewound a bare repository's main), git subtree push, git update-ref
//    refs/heads/main (or HEAD while main is checked out), git branch -f main and -M/-C onto main. In auto mode
//    `git branch -qf main HEAD~1` was even routine: the hook answered "allow".
// 8. git stash -a / --all stashes the ignored files too and removes them from the working tree: .claude/settings.local.json
//    (where a default install registers the hooks) and .claude/logs/ (the hooks' session state) were gone until git stash pop.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyzeShellCommand, routineShell } from '../hooks/lib/policy.mjs';

const preHook = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'hooks', 'pre-tool-use.mjs');
const onFeature = { protectedBranches: ['main'], getBranch: () => 'feature/x' };
const onMain = { protectedBranches: ['main'], getBranch: () => 'main' };
const unprotected = { protectedBranches: [], getBranch: () => 'feature/x' };
const shell = (cmd, ctx = onFeature) => analyzeShellCommand(cmd, ctx);
const decision = (cmd, ctx = onFeature) => shell(cmd, ctx)?.decision ?? null;

/** Asserts the floor ask of a push: the user decides, in every approvals mode. */
function assertFloor(cmd, ctx = onFeature) {
  const v = shell(cmd, ctx);
  assert.equal(v?.decision, 'ask', cmd);
  assert.equal(v?.floor, true, cmd);
  assert.equal(v?.autoApprovable, false, cmd);
}

/** Every proper prefix of a long option, longest last: `force` gives f, fo, for, forc. */
const prefixes = (option) => Array.from({ length: option.length - 1 }, (_, n) => option.slice(0, n + 1));

// ---------------------------------------------------------------- 6: the branch a push destination resolves to

test('6: a push destination X, heads/X and refs/heads/X give one verdict, with or without a source, quoted or not', () => {
  const direct = shell('git push origin main');
  assert.equal(direct?.decision, 'deny');
  assert.match(direct.reason, /Direct pushes to main are blocked/);
  const spellings = ['main', 'heads/main', 'refs/heads/main'];
  const refspecs = [];
  for (const dst of spellings) {
    refspecs.push(dst, `HEAD:${dst}`, `feature/x:${dst}`, `refs/heads/feature/x:${dst}`, `'HEAD:${dst}'`, `"${dst}"`, `"feature/x:${dst}"`);
    for (const src of spellings) refspecs.push(`${src}:${dst}`);
  }
  for (const refspec of refspecs) {
    for (const cmd of [`git push origin ${refspec}`, `git push -u origin ${refspec}`, `git push origin feature/x ${refspec}`, `git push -o ci.skip origin ${refspec}`]) {
      assert.deepEqual(shell(cmd), direct, cmd);
      assert.equal(routineShell(cmd), false, cmd);
    }
    // No protected branch configured: no protected push, the plain floor ask.
    assertFloor(`git push origin ${refspec}`, unprotected);
  }
  // A feature branch in every spelling, also pushed from main: the plain floor ask, as before.
  for (const refspec of ['feature/x', 'heads/feature/x', 'refs/heads/feature/x', 'HEAD:heads/feature/x', 'main:heads/feature/x', 'heads/main:feature/x',
    'refs/heads/main:refs/heads/feature/x', "'HEAD:heads/feature/x'"]) {
    assertFloor(`git push origin ${refspec}`);
  }
  // Only one prefix comes off: refs/heads/heads/main is the branch heads/main, not main.
  assertFloor('git push origin HEAD:refs/heads/heads/main');
});

// ---------------------------------------------------------------- 7a: git send-pack and git subtree push

test('7a: git send-pack gets the verdict of the equivalent git push', () => {
  const force = shell('git push --force origin feature/x');
  const direct = shell('git push origin main');
  assert.equal(force?.decision, 'deny');
  assert.equal(direct?.decision, 'deny');
  // Forced updates, a mirror and deletions: denied like a force push, whatever the destination.
  for (const cmd of ['git send-pack --force origin +main', 'git send-pack --force origin feature/x', 'git send-pack -f origin feature/x', 'git send-pack -vf origin feature/x',
    'git send-pack origin +feature/x', "git send-pack origin '+HEAD:refs/heads/feature/x'", 'git send-pack --mirror origin', 'git send-pack origin :feature/x',
    'git send-pack origin :refs/heads/old', 'git send-pack --force-with-lease origin feature/x', 'git send-pack --force-with-lease=feature/x origin feature/x',
    'git send-pack --force-if-includes origin feature/x', 'git send-pack --dry-run --force origin feature/x', 'git send-pack --force origin feature/x 2>&1']) {
    assert.deepEqual(shell(cmd), force, cmd);
    assert.deepEqual(shell(cmd, unprotected), force, `unprotected: ${cmd}`);
    assert.equal(routineShell(cmd), false, cmd);
  }
  // git reads any unambiguous prefix of a long option as that option; an ambiguous one is never read as no option.
  for (const option of ['force', 'mirror', 'force-with-lease', 'force-if-includes']) {
    for (const p of [...prefixes(option), option]) assert.deepEqual(shell(`git send-pack --${p} origin feature/x`), force, `--${p}`);
  }
  // A protected destination in any spelling, a pattern that reaches it, --all, and no ref at all (the heads that exist on
  // both sides, main among them): denied like a push to main.
  const protectedForms = ['git send-pack origin HEAD:refs/heads/main', 'git send-pack origin main', 'git send-pack origin heads/main', 'git send-pack origin refs/heads/main',
    'git send-pack origin HEAD:main', 'git send-pack origin HEAD:heads/main', 'git send-pack origin feature/x:refs/heads/main', "git send-pack origin 'HEAD:heads/main'",
    'git send-pack origin feature/x main', "git send-pack origin 'refs/heads/*:refs/heads/*'", 'git send-pack --all origin', 'git send-pack origin --all',
    'git send-pack origin', 'git send-pack --thin --atomic origin', 'git send-pack --receive-pack git-receive-pack origin', 'git send-pack --stdin origin main',
    'git send-pack example.com:repo.git main', 'git send-pack --dry-run origin main'];
  for (const p of prefixes('all')) protectedForms.push(`git send-pack --${p} origin`);
  for (const cmd of protectedForms) {
    assert.deepEqual(shell(cmd), direct, cmd);
    assert.equal(routineShell(cmd), false, cmd);
  }
  assert.deepEqual(shell('git send-pack origin HEAD', onMain), direct, 'HEAD while main is checked out');
  // Everything else publishes commits: the floor ask; refs read from standard input are unseen, so at least that.
  for (const cmd of ['git send-pack origin feature/x', 'git send-pack origin HEAD:refs/heads/feature/x', 'git send-pack origin heads/feature/x', 'git send-pack origin HEAD',
    'git send-pack --dry-run origin feature/x', 'git send-pack --receive-pack=git-receive-pack origin feature/x', 'git send-pack --stdin origin', 'git send-pack --std origin',
    'git send-pack --stdin origin feature/x', 'git send-pack --no-force origin feature/x']) {
    assertFloor(cmd);
    assert.equal(routineShell(cmd), false, cmd);
  }
  // No protected branch: nothing is a protected push.
  for (const cmd of ['git send-pack origin HEAD:refs/heads/main', 'git send-pack --all origin', 'git send-pack origin', 'git send-pack origin heads/main']) {
    assertFloor(cmd, unprotected);
  }
});

test('7a: git subtree push is judged by its last words, the repository and the remote ref', () => {
  const force = shell('git push --force origin feature/x');
  const direct = shell('git push origin main');
  for (const cmd of ['git subtree push --prefix=docs origin main', 'git subtree push -P docs origin main', 'git subtree push --prefix docs origin main',
    'git subtree -P docs push origin main', 'git subtree push -P docs origin HEAD:main', 'git subtree push -P docs origin feature/x:main', 'git subtree push -qP docs origin main',
    'git subtree push --pre docs origin main', 'git subtree push --prefix=docs origin heads/main', "git subtree push --prefix=docs origin 'main'",
    'git subtree push --rejoin -m x -P docs origin main', 'git subtree push origin main --prefix docs']) {
    assert.deepEqual(shell(cmd), direct, cmd);
    assert.equal(routineShell(cmd), false, cmd);
  }
  for (const cmd of ['git subtree push -P docs origin +feature/x', 'git subtree push -P docs origin :feature/x']) assert.deepEqual(shell(cmd), force, cmd);
  // A feature branch is the floor ask; the value of --prefix is no remote ref, wherever it stands.
  for (const cmd of ['git subtree push -P docs origin feature/x', 'git subtree push --prefix=docs origin HEAD:feature/x', 'git subtree push origin feature/x --prefix main',
    'git subtree push -P main origin feature/x']) {
    assertFloor(cmd);
    assert.equal(routineShell(cmd), false, cmd);
  }
  assertFloor('git subtree push -P docs origin main', unprotected);
  // The other subtree commands keep their verdict (none from this rule).
  for (const cmd of ['git subtree split -P docs', 'git subtree split --prefix=docs --onto main']) assert.equal(decision(cmd), null, cmd);
});

// ---------------------------------------------------------------- 7b: git update-ref

test('7b: git update-ref that sets a protected branch is denied; --stdin asks the user; -d stays denied', () => {
  for (const cmd of ['git update-ref refs/heads/main HEAD~1', 'git update-ref refs/heads/main HEAD~1 HEAD', "git update-ref 'refs/heads/main' HEAD~1",
    'git update-ref -m x refs/heads/main HEAD~1', 'git update-ref -m "rewind main" refs/heads/main HEAD~1', 'git update-ref -mx refs/heads/main HEAD~1',
    'git update-ref --create-reflog refs/heads/main HEAD~1', 'git update-ref --no-deref refs/heads/main HEAD~1', 'git update-ref -- refs/heads/main HEAD~1']) {
    const v = shell(cmd);
    assert.equal(v?.decision, 'deny', cmd);
    assert.match(v.reason, /main/, cmd);
    assert.equal(routineShell(cmd), false, cmd);
  }
  assert.equal(decision('git update-ref HEAD HEAD~1', onMain), 'deny', 'HEAD while main is checked out moves main');
  assert.equal(decision('git update-ref -m x HEAD HEAD~1', onMain), 'deny');
  // --stdin: the refs are unseen; auto approval never passes it.
  for (const cmd of ['git update-ref --stdin', 'git update-ref --stdin -z', 'git update-ref -z --stdin', 'git update-ref --std', 'git update-ref --s', 'git update-ref -m x --stdin']) {
    const v = shell(cmd);
    assert.equal(v?.decision, 'ask', cmd);
    assert.equal(v?.autoApprovable, false, cmd);
    assert.equal(routineShell(cmd), false, cmd);
  }
  for (const cmd of ['git update-ref -d refs/heads/x', 'git update-ref -d refs/heads/main', 'git update-ref --delete refs/heads/x', 'git update-ref -d refs/tags/v1']) {
    assert.deepEqual(shell(cmd), { decision: 'deny', reason: 'Deleting refs is blocked.' }, cmd);
  }
  // Other refs, HEAD on a feature branch and names git does not read as a branch keep today's verdict (none).
  for (const cmd of ['git update-ref refs/heads/feature/x HEAD~1', 'git update-ref refs/heads/mainline HEAD', 'git update-ref refs/tags/main HEAD',
    'git update-ref heads/main HEAD', 'git update-ref -m refs/heads/main refs/heads/feature/x HEAD', 'git update-ref HEAD HEAD~1']) {
    assert.equal(decision(cmd), null, cmd);
  }
  assert.equal(decision('git update-ref refs/heads/main HEAD~1', unprotected), null);
});

// ---------------------------------------------------------------- 7c: git branch -f, -M, -C

test('7c: git branch -f, -M and -C onto a protected branch are denied in every flag form', () => {
  const forced = ['git branch -f main HEAD~1', 'git branch --force main HEAD~1', 'git branch -f main', 'git branch --force main', 'git branch -qf main HEAD~1',
    'git branch -fq main', 'git branch -f -q main HEAD~1', 'git branch -q main HEAD~1 --force', "git branch -f 'main' HEAD~1", 'git branch -f --track main origin/main',
    'git branch -M feature/x main', 'git branch -M main', 'git branch -C feature/x main', 'git branch -qM feature/x main', 'git branch --move --force feature/x main',
    'git branch --copy --force feature/x main', 'git branch -mf feature/x main', 'git branch -cf feature/x main', 'git branch -m -f feature/x main', 'git branch -f -m feature/x main'];
  for (const p of prefixes('force')) forced.push(`git branch --${p} main HEAD~1`);
  for (const p of prefixes('move')) forced.push(`git branch --${p} --force feature/x main`);
  for (const p of prefixes('copy')) forced.push(`git branch --${p} --forc feature/x main`);
  for (const cmd of forced) {
    const v = shell(cmd);
    assert.equal(v?.decision, 'deny', cmd);
    assert.match(v.reason, /main/, cmd);
  }
  // Another branch, main as the start point or the old name, a move or copy without force: as before.
  for (const cmd of ['git branch -f feature/x HEAD~1', 'git branch -f feature/x main', 'git branch --force feature/x main', 'git branch -qf feature/x HEAD~1',
    'git branch -m feature/x main', 'git branch -c feature/x main', 'git branch -M main feature/x', 'git branch -C main feature/y', 'git branch feature/y main',
    'git branch --list', 'git branch -a', 'git branch --contains main', 'git branch -d feature/x']) {
    assert.equal(decision(cmd), null, cmd);
  }
  assert.equal(decision('git branch -f main HEAD~1', unprotected), null);
  assert.match(shell('git branch -D feature/x').reason, /Force-deleting branches is blocked/, 'a forced delete keeps its own reason');
  assert.match(shell('git branch -Df main').reason, /Force-deleting branches is blocked/);
});

// ---------------------------------------------------------------- 8: git stash with the ignored files

test('8: git stash that takes the ignored files is denied with what it removes, never routine', () => {
  const forms = ['git stash -a', 'git stash --all', 'git stash push -a', 'git stash push --all', 'git stash push --all -m x', 'git stash push -m x --all', 'git stash push -m x -a',
    'git stash push --message=x --all', 'git stash push --message x -a', 'git stash push --mes x -a', 'git stash push -ka', 'git stash -qa', 'git stash -am x', 'git stash -q --all',
    'git stash push -a -- docs', 'git stash save -a', 'git stash save --all wip', 'git stash save -qa wip', "git stash save -a 'work in progress'", 'git stash push -u --all',
    'git -C docs stash -a', 'git stash -a 2>&1'];
  for (const p of prefixes('all')) forms.push(`git stash --${p}`, `git stash push --${p}`, `git stash save --${p} wip`);
  for (const cmd of forms) {
    const v = shell(cmd);
    assert.equal(v?.decision, 'deny', cmd);
    assert.match(v.reason, /ignored/, cmd);
    assert.match(v.reason, /\.claude\/settings\.local\.json/, cmd);
    assert.match(v.reason, /hooks/, cmd);
    assert.match(v.reason, /logs/, cmd);
    assert.equal(routineShell(cmd), false, cmd);
  }
  // The value of -m and the words after -- are no option.
  for (const cmd of ['git stash push -m -a', 'git stash push -ma', 'git stash push --message -a', 'git stash push -- -a', 'git stash save -- -a']) {
    assert.equal(decision(cmd), null, cmd);
  }
});

// ---------------------------------------------------------------- what the fix leaves alone (passes before and after)

test('must stay: the stash, push, branch and update-ref verdicts the fix leaves alone', () => {
  for (const cmd of ['git stash', 'git stash -u', 'git stash --include-untracked', 'git stash push -m x', 'git stash list', 'git stash list --all', 'git stash show -p',
    'git stash pop', 'git stash apply']) {
    assert.equal(shell(cmd), null, cmd);
    assert.equal(routineShell(cmd), false, cmd);
  }
  for (const cmd of ['git stash drop', 'git stash clear']) assert.deepEqual(shell(cmd), { decision: 'deny', reason: 'git stash drop/clear loses stashed work.' }, cmd);
  const feature = shell('git push origin feature/x');
  assertFloor('git push origin feature/x');
  assert.deepEqual(shell('git push origin heads/feature/x'), feature);
  assert.deepEqual(shell('git push origin refs/heads/feature/x'), feature);
  assert.equal(decision('git branch --list'), null);
  assert.equal(routineShell('git branch --list'), true);
  assert.equal(decision('git branch -f feature/x HEAD~1'), null);
  assert.equal(routineShell('git branch -f feature/x HEAD~1'), false);
  assert.equal(decision('git update-ref refs/heads/feature/x HEAD~1'), null);
  assert.deepEqual(shell('git update-ref -d refs/heads/x'), { decision: 'deny', reason: 'Deleting refs is blocked.' });
  // No protected branch configured: no push is denied as a protected push.
  for (const cmd of ['git push origin main', 'git push origin HEAD:main', 'git push origin refs/heads/main', 'git push origin --all', "git push origin 'refs/heads/*:refs/heads/*'"]) {
    assertFloor(cmd, unprotected);
  }
  // A push to main in the spellings denied before the fix stays denied.
  for (const cmd of ['git push origin main', 'git push origin HEAD:main', 'git push origin refs/heads/main', 'git push origin feature/x:refs/heads/main']) {
    assert.equal(decision(cmd), 'deny', cmd);
  }
});

// ---------------------------------------------------------------- end to end

// The hook runs with the machine's global and system git configuration left out (a push.default there would change the
// verdict of a push without a refspec) and without repository variables a caller may export.
function hookEnv(dir) {
  const env = Object.fromEntries(Object.entries(process.env).filter(([k]) => !/^GIT_(?:CONFIG|DIR$|WORK_TREE$|INDEX_FILE$|COMMON_DIR$|OBJECT_DIRECTORY$|ALTERNATE)/i.test(k)));
  delete env.BI_HARNESS_HOST;
  const globalConfig = path.join(dir, 'empty.gitconfig');
  if (!fs.existsSync(globalConfig)) fs.writeFileSync(globalConfig, '');
  return { ...env, CLAUDE_PROJECT_DIR: dir, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: globalConfig, GIT_CEILING_DIRECTORIES: path.dirname(dir) };
}

/** The PreToolUse guard's decision for one shell command, run as a process like Claude Code runs it (auto mode, the default). */
function hookDecision(dir, command, tool_name = 'Bash') {
  const r = spawnSync(process.execPath, [preHook], {
    input: JSON.stringify({ hook_event_name: 'PreToolUse', session_id: 'audit-1116-git', tool_name, tool_input: { command } }),
    env: hookEnv(dir),
    encoding: 'utf8',
  });
  assert.equal(r.status, 0, r.stderr); // a guard that did not run prints no verdict, which "not allow" would read as a pass
  return r.stdout.trim() ? JSON.parse(r.stdout).hookSpecificOutput?.permissionDecision ?? null : null;
}

test('6-8: the PreToolUse hook denies them end to end, and keeps the floor ask of a feature push', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-audit-1116-git-'));
  try {
    for (const command of ['git push origin heads/main', 'git push origin HEAD:heads/main', 'git push origin heads/main:heads/main', 'git send-pack --force origin +main',
      'git send-pack origin HEAD:refs/heads/main', 'git subtree push --prefix=docs origin main', 'git update-ref refs/heads/main HEAD~1', 'git branch -f main HEAD~1',
      'git branch --force main HEAD~1', 'git branch -qf main HEAD~1', 'git branch -M feature/x main', 'git stash -a', 'git stash --all', 'git stash push --al',
      'git -c remote.origin.push=HEAD:heads/main push origin']) {
      assert.equal(hookDecision(dir, command), 'deny', command);
    }
    assert.equal(hookDecision(dir, 'git stash -a', 'PowerShell'), 'deny');
    for (const command of ['git push origin feature/x', 'git push origin heads/feature/x', 'git send-pack origin feature/x', 'git subtree push -P docs origin feature/x',
      'git update-ref --stdin']) {
      assert.equal(hookDecision(dir, command), 'ask', command);
    }
    assert.equal(hookDecision(dir, 'git branch --list'), 'allow');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------- follow-ups: @ for HEAD, short option clusters of git branch

// `@` is git's short name for HEAD: a source-only or destination `@` pushes the checked-out branch, like HEAD.
test('6: a refspec @ is judged like HEAD: denied while a protected branch is checked out, the floor ask on a feature branch', () => {
  for (const [cmd, like] of [['git push origin @', 'git push origin HEAD'], ['git push -u origin @', 'git push -u origin HEAD'], ["git push origin '@'", 'git push origin HEAD'],
    ['git push origin feature/x:@', 'git push origin feature/x:HEAD'], ['git send-pack origin @', 'git send-pack origin HEAD'],
    ['git subtree push -P docs origin @', 'git subtree push -P docs origin HEAD']]) {
    const head = shell(like, onMain);
    assert.equal(head?.decision, 'deny', `on main: ${like}`);
    assert.deepEqual(shell(cmd, onMain), head, `on main: ${cmd}`);
    assertFloor(cmd, onFeature);
    assert.deepEqual(shell(cmd, onFeature), shell(like, onFeature), `on feature/x: ${cmd}`);
    assertFloor(cmd, { protectedBranches: [], getBranch: () => 'main' });
    assert.equal(routineShell(cmd), false, cmd);
  }
  // A destination decides, not the source: @:main stays denied, @:feature/x keeps the floor ask on main too.
  for (const ctx of [onMain, onFeature]) {
    assert.equal(decision('git push origin @:main', ctx), 'deny');
    assert.equal(decision('git send-pack origin @:refs/heads/main', ctx), 'deny');
    assertFloor('git push origin @:feature/x', ctx);
    assertFloor('git push origin @:refs/heads/feature/x', ctx);
  }
});

test('7c: git branch with a short option cluster that deletes, moves, copies or forces is never routine', () => {
  for (const cmd of ['git branch -qf feature/x HEAD~1', 'git branch -fq feature/x HEAD~1', 'git branch -qd x', 'git branch -dq x', 'git branch -qm a b', 'git branch -qc a b',
    'git branch -qM a b', 'git branch -qC a b', 'git branch -qD x', 'git branch -vf feature/x HEAD~1', 'git branch -tf feature/x origin/feature/x', 'git -C docs branch -qd x',
    'git branch -f feature/x HEAD~1', 'git branch -d x', 'git branch -m a b', 'git branch -c a b', 'git branch -M a b', 'git branch -C a b', 'git branch --force feature/x HEAD~1',
    'git branch --delete x', 'git branch --move a b', 'git branch --copy a b', 'git branch --forc feature/x HEAD~1', 'git branch --del x']) {
    assert.equal(routineShell(cmd), false, cmd);
  }
  // Listing, the current branch, upstream and filters stay routine: their short options hold none of those letters.
  for (const cmd of ['git branch', 'git branch --list', 'git branch --show-current', 'git branch -a', 'git branch -vv', 'git branch -r', 'git branch -q --list', 'git branch -v',
    'git branch -av', 'git branch -l', 'git branch -i --list', 'git branch --contains HEAD', 'git branch --merged', 'git branch --no-merged', 'git branch --sort=-committerdate']) {
    assert.equal(routineShell(cmd), true, cmd);
    assert.equal(decision(cmd), null, cmd);
  }
  // End to end: auto mode answered "allow" for the clusters; now Claude Code's own rules decide.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-audit-1116-git-'));
  try {
    for (const command of ['git branch -qf feature/x HEAD~1', 'git branch -qd x', 'git branch -qm a b']) {
      assert.notEqual(hookDecision(dir, command), 'allow', command);
    }
    assert.equal(hookDecision(dir, 'git branch -vv'), 'allow');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
