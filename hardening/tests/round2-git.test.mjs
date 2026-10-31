// Follow-up audit 2026-10-18 (round 2), group A: the shell's git checks and the GitHub MCP gate.
// F2-2: a routine `git switch` to a branch or commit whose tree predates the harness install removed hardening/ and
//       .claude/settings.json; every later PreToolUse hook then failed to start (MODULE_NOT_FOUND) and ran unguarded.
// F2-5: `git push --all`, `--branches` and a `*` refspec pushed main from a feature branch with only the plain push ask.
// F2-6: `git diff /dev/null <file>` or a path outside the repository runs as an implicit `git diff --no-index`, which
//       prints any file on the machine; only the explicit --no-index was denied, the implicit form was routine.
// F2-9: only an MCP server named exactly `github` got the GitHub write floor; GitHub, github-enterprise and the like none.
import { after, test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { analyzeMcpCall, analyzeShellCommand, routineShell } from '../hooks/lib/policy.mjs';
import { DEFAULT_CONFIG } from '../hooks/lib/common.mjs';

const hooks = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'hooks');
const preHook = path.join(hooks, 'pre-tool-use.mjs');
const shell = (cmd, ctx = {}) => analyzeShellCommand(cmd, ctx);

/** The PreToolUse guard's verdict for one shell command, run as a process like Claude Code runs it (auto mode, the default). */
function hook(dir, command, tool_name = 'Bash') {
  const r = spawnSync(process.execPath, [preHook], {
    input: JSON.stringify({ hook_event_name: 'PreToolUse', session_id: 'round2-git', tool_name, tool_input: { command } }),
    env: { ...process.env, CLAUDE_PROJECT_DIR: dir },
    encoding: 'utf8',
  });
  assert.equal(r.status, 0, r.stderr); // a guard that did not run prints no verdict, which "not allow" would read as a pass
  const out = r.stdout.trim() ? JSON.parse(r.stdout).hookSpecificOutput ?? {} : {};
  return { decision: out.permissionDecision ?? null, reason: out.permissionDecisionReason ?? '' };
}

/**
 * The shell policy's verdict and routine flag for each command, with `dir` as the project (one process for many
 * commands: the project folder is read once, when the policy module loads). Each item: { decision, floor, reason, routine }.
 */
function policyIn(dir, commands) {
  const script = `import fs from 'node:fs';
    import { analyzeShellCommand, routineShell } from ${JSON.stringify(pathToFileURL(path.join(hooks, 'lib', 'policy.mjs')).href)};
    const verdicts = JSON.parse(fs.readFileSync(0, 'utf8')).map((c) => {
      const v = analyzeShellCommand(c, {});
      return { decision: v?.decision ?? null, floor: v?.floor === true, reason: v?.reason ?? '', routine: routineShell(c) };
    });
    process.stdout.write(JSON.stringify(verdicts));`;
  const r = spawnSync(process.execPath, ['--input-type=module', '-e', script], {
    input: JSON.stringify(commands),
    env: { ...process.env, CLAUDE_PROJECT_DIR: dir },
    encoding: 'utf8',
  });
  assert.equal(r.status, 0, r.stderr);
  return Object.fromEntries(JSON.parse(r.stdout).map((v, i) => [commands[i], v]));
}

/** Runs git in `dir` (test setup only); throws on failure. */
function git(dir, ...args) {
  const r = spawnSync('git', ['-c', 'user.email=t@example.com', '-c', 'user.name=t', '-c', 'core.autocrlf=false', ...args], { cwd: dir, encoding: 'utf8' });
  assert.equal(r.status, 0, `git ${args.join(' ')}: ${r.stderr}`);
  return r.stdout.trim();
}

const temps = [];
after(() => temps.forEach((dir) => fs.rmSync(dir, { recursive: true, force: true })));
const tempDir = (name) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `bi-harness-round2-${name}-`));
  temps.push(dir);
  return dir;
};

/**
 * A project whose `main` predates the harness install: main holds README.md only, feature/x adds stand-ins for the pack
 * (hardening/hooks/pre-tool-use.mjs) and its registration (.claude/settings.json), feature/z changes README.md only, and
 * two remote-tracking branches point at main (origin/old) and at feature/x (origin/twin). HEAD is feature/x, @{-1} main.
 */
let preInstall = null;
function preInstallRepo() {
  if (preInstall) return preInstall;
  const dir = tempDir('git');
  git(dir, 'init', '-q', '-b', 'main', '.');
  fs.writeFileSync(path.join(dir, 'README.md'), 'start\n');
  git(dir, 'add', 'README.md');
  git(dir, 'commit', '-qm', 'docs: start');
  const before = git(dir, 'rev-parse', 'HEAD');
  git(dir, 'switch', '-qc', 'feature/x');
  fs.mkdirSync(path.join(dir, 'hardening', 'hooks'), { recursive: true });
  fs.mkdirSync(path.join(dir, '.claude'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'hardening', 'hooks', 'pre-tool-use.mjs'), '// stand-in for the guard\n');
  fs.writeFileSync(path.join(dir, '.claude', 'settings.json'), '{}\n');
  git(dir, 'add', '-A');
  git(dir, 'commit', '-qm', 'chore: install harness');
  const installed = git(dir, 'rev-parse', 'HEAD');
  git(dir, 'switch', '-qc', 'feature/z');
  fs.writeFileSync(path.join(dir, 'README.md'), 'start\nmore\n');
  git(dir, 'commit', '-qam', 'docs: more');
  git(dir, 'update-ref', 'refs/remotes/origin/old', before);
  git(dir, 'update-ref', 'refs/remotes/origin/twin', installed);
  git(dir, 'switch', '-q', 'main');
  git(dir, 'switch', '-q', 'feature/x');
  preInstall = dir;
  return dir;
}

// ---------------------------------------------------------------- F2-2

test('F2-2: a switch or checkout to a tree without the harness files is a floor ask, never routine; the same tree stays routine', () => {
  const dir = preInstallRepo();
  const leaves = ['git switch main', 'git switch --detach HEAD~1', 'git switch -', 'git switch -d main', 'git switch --detach main', 'git switch --det main',
    'git checkout main', 'git checkout -', 'git checkout --detach HEAD~1', 'git switch -c y main', 'git switch -qc y main', 'git switch --create=y main',
    'git switch --cr y main', 'git checkout -b y main', 'git checkout -by HEAD~1', 'git switch old', 'git checkout old', 'git switch --track origin/old',
    'git switch -q main', 'git switch --no-guess main', 'git switch nope', 'git checkout nope', 'git -C docs switch main', 'git --no-pager switch main',
    'git status && git switch main', 'git switch main 2>&1', 'git switch -c y -- -x'];
  // A redirect is the shell's, not a target: `2>&1` and `> /dev/null` change nothing.
  const same = ['git switch -c y', 'git switch -c y HEAD', 'git switch --create y', 'git switch feature/z', 'git switch twin', 'git switch --detach',
    'git switch --detach feature/z', 'git switch -c y feature/z', 'git checkout -b y feature/z', 'git checkout feature/z', 'git switch -c y 2>&1',
    'git switch feature/z > /dev/null'];
  // checkout's file forms move nothing: judged as before (no verdict; Claude Code's ask rule for git checkout decides).
  const files = ['git checkout README.md', 'git checkout main -- README.md', 'git checkout -- README.md', 'git checkout main README.md', 'git checkout -p main'];
  const denied = ['git switch -f main', 'git switch --orphan tmp', 'git checkout -f main', 'git checkout --orphan tmp', 'git checkout hardening/hooks/pre-tool-use.mjs'];
  const got = policyIn(dir, [...leaves, ...same, ...files, ...denied]);
  for (const cmd of leaves) {
    assert.equal(got[cmd].decision, 'ask', cmd);
    assert.equal(got[cmd].floor, true, `${cmd}: lab mode never passes it`);
    assert.match(got[cmd].reason, /guard/, cmd);
    assert.equal(got[cmd].routine, false, cmd);
  }
  assert.match(got['git switch main'].reason, /hardening\/.*\.claude\/settings\.json.*stop working/);
  assert.match(got['git switch nope'].reason, /cannot tell/);
  for (const cmd of same) {
    assert.equal(got[cmd].decision, null, cmd);
    assert.equal(got[cmd].routine, !cmd.startsWith('git checkout'), cmd);
  }
  for (const cmd of files) assert.deepEqual([got[cmd].decision, got[cmd].routine], [null, false], cmd);
  for (const cmd of denied) assert.equal(got[cmd].decision, 'deny', cmd);
});

test('F2-2: the guard asks end to end, also in lab mode, and still allows the switch that keeps its files', () => {
  const dir = preInstallRepo();
  for (const [command, tool] of [['git switch main', 'Bash'], ['git switch --detach HEAD~1', 'Bash'], ['git switch -', 'Bash'], ['git checkout main', 'Bash'],
    ['git switch main', 'PowerShell']]) {
    assert.equal(hook(dir, command, tool).decision, 'ask', `${tool}: ${command}`);
  }
  for (const command of ['git switch -c y', 'git switch feature/z']) {
    const v = hook(dir, command);
    assert.equal(v.decision, 'allow', command);
    assert.match(v.reason, /routine command/, command);
  }
  // Lab mode (an untracked config, so both trees still match): the floor stays, routine still passes.
  const cfg = path.join(dir, 'hardening', 'harness.config.json');
  fs.writeFileSync(cfg, `${JSON.stringify({ approvals: { mode: 'lab' } })}\n`);
  try {
    for (const command of ['git switch main', 'git switch -', 'git switch old']) assert.equal(hook(dir, command).decision, 'ask', `lab: ${command}`);
    assert.equal(hook(dir, 'git switch feature/z').decision, 'allow', 'lab: the same tree');
  } finally {
    fs.rmSync(cfg);
  }
});

test('F2-2: when git cannot compare (no repository) a switch asks; a switch that names no other commit needs no git', () => {
  const got = policyIn(tempDir('nogit'), ['git switch main', 'git checkout main', 'git switch -c feature/y']);
  assert.deepEqual([got['git switch main'].decision, got['git switch main'].floor], ['ask', true]);
  assert.deepEqual([got['git checkout main'].decision, got['git checkout main'].floor], ['ask', true]);
  assert.deepEqual([got['git switch -c feature/y'].decision, got['git switch -c feature/y'].routine], [null, true]);
  // In this checkout: a new branch at HEAD and a detach at HEAD stay routine with no verdict.
  for (const cmd of ['git switch -c feature/y', 'git switch --create feature/y', 'git switch --detach', 'git switch -c feature/y HEAD', 'git switch --detach HEAD']) {
    assert.equal(shell(cmd), null, cmd);
    assert.equal(routineShell(cmd), true, cmd);
  }
});

test('F2-2: in a project that never tracked the harness files, a switch changes nothing for the guard', () => {
  const dir = tempDir('untracked');
  git(dir, 'init', '-q', '-b', 'main', '.');
  fs.writeFileSync(path.join(dir, 'README.md'), 'start\n');
  git(dir, 'add', 'README.md');
  git(dir, 'commit', '-qm', 'docs: start');
  git(dir, 'switch', '-qc', 'feature/x');
  fs.writeFileSync(path.join(dir, 'a.md'), 'a\n');
  git(dir, 'add', 'a.md');
  git(dir, 'commit', '-qm', 'docs: a');
  fs.mkdirSync(path.join(dir, 'hardening'), { recursive: true }); // installed, never committed: a switch leaves it in place
  fs.writeFileSync(path.join(dir, 'hardening', 'x.mjs'), '// untracked\n');
  const got = policyIn(dir, ['git switch main', 'git switch --detach HEAD~1']);
  for (const [cmd, v] of Object.entries(got)) assert.deepEqual([v.decision, v.routine], [null, true], cmd);
});

// Audit 2026-10-31 (S2): under a project path that is not its canonical spelling (a symlink, a junction, macOS
// /var -> /private/var, a Windows runner's RUNNER~1 profile), the 8.3 expansion turned `HEAD~1` into an absolute file
// path, so `git switch --detach HEAD~1` became a floor ask. The project is reached here through a link on every OS.
test('F2-2: under a linked (non-canonical) project folder, HEAD~1 stays a revision and the switch stays routine', () => {
  const dir = tempDir('linked');
  git(dir, 'init', '-q', '-b', 'main', '.');
  fs.writeFileSync(path.join(dir, 'README.md'), 'start\n');
  git(dir, 'add', 'README.md');
  git(dir, 'commit', '-qm', 'docs: start');
  git(dir, 'switch', '-qc', 'feature/x');
  fs.writeFileSync(path.join(dir, 'a.md'), 'a\n');
  git(dir, 'add', 'a.md');
  git(dir, 'commit', '-qm', 'docs: a');
  fs.mkdirSync(path.join(dir, 'hardening'), { recursive: true }); // installed, never committed, as in the test above
  fs.writeFileSync(path.join(dir, 'hardening', 'x.mjs'), '// untracked\n');
  const link = path.join(tempDir('link'), 'project');
  fs.symlinkSync(dir, link, process.platform === 'win32' ? 'junction' : 'dir'); // a junction needs no admin rights
  assert.notEqual(fs.realpathSync.native(link), link, 'the link is a spelling of its own');
  const got = policyIn(link, ['git switch --detach HEAD~1', 'git switch main']);
  for (const [cmd, v] of Object.entries(got)) assert.deepEqual([v.decision, v.routine], [null, true], cmd);
});

test('F2-2: a real 8.3 short name in a shell command still expands, also under a linked project folder', (t) => {
  const dir = tempDir('short');
  fs.mkdirSync(path.join(dir, 'hardening'));
  if (!fs.existsSync(path.join(dir, 'HARDEN~1'))) return t.skip('this volume does not create 8.3 names');
  const link = path.join(tempDir('short-link'), 'project');
  fs.symlinkSync(dir, link, 'junction');
  for (const root of [dir, link]) {
    const got = policyIn(root, ['Set-Content HARDEN~1/x.mjs y', `Set-Content ${path.join(root, 'HARDEN~1', 'x.mjs')} y`]);
    for (const [cmd, v] of Object.entries(got)) {
      assert.equal(v.decision, 'deny', `${root}: ${cmd}`);
      assert.match(v.reason, /Harness guardrail files/, `${root}: ${cmd}`);
    }
  }
});

test('F2-2: only the files the guard runs from count: a branch that changes the pack\'s docs or tests stays routine', () => {
  const dir = tempDir('runtime');
  git(dir, 'init', '-q', '-b', 'main', '.');
  const write = (rel, text) => {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), text);
  };
  for (const rel of ['hardening/hooks/pre-tool-use.mjs', 'hardening/scripts/check-hooks.mjs', 'hardening/githooks/pre-commit', 'hardening/README.md',
    'hardening/tests/a.test.mjs', 'hardening/harness.config.json', '.claude/settings.json']) write(rel, `${rel}\n`);
  git(dir, 'add', '-A');
  git(dir, 'commit', '-qm', 'chore: install harness');
  const branch = (name, rel) => {
    git(dir, 'switch', '-qc', name, 'main');
    write(rel, `${rel} changed\n`);
    git(dir, 'commit', '-qam', `docs: ${name}`);
  };
  branch('docs', 'hardening/README.md');
  branch('tests', 'hardening/tests/a.test.mjs');
  branch('mode', 'hardening/harness.config.json');
  branch('hook', 'hardening/hooks/pre-tool-use.mjs');
  branch('script', 'hardening/scripts/check-hooks.mjs');
  branch('githook', 'hardening/githooks/pre-commit');
  git(dir, 'switch', '-q', 'main');
  const got = policyIn(dir, ['git switch docs', 'git switch tests', 'git switch mode', 'git switch hook', 'git switch script', 'git switch githook']);
  for (const cmd of ['git switch docs', 'git switch tests']) assert.deepEqual([got[cmd].decision, got[cmd].routine], [null, true], cmd);
  for (const cmd of ['git switch mode', 'git switch hook', 'git switch script', 'git switch githook']) {
    assert.deepEqual([got[cmd].decision, got[cmd].floor, got[cmd].routine], ['ask', true, false], cmd);
  }
});

// ---------------------------------------------------------------- F2-5

const onFeature = { protectedBranches: ['main', 'master'], getBranch: () => 'feature/x' };
const onMain = { protectedBranches: ['main', 'master'], getBranch: () => 'main' };

test('F2-5: --all, --branches and a refspec pattern that reaches main are denied like a push to main', () => {
  const direct = shell('git push origin main', onFeature);
  assert.equal(direct?.decision, 'deny');
  for (const cmd of ['git push origin --all', 'git push origin --branches', "git push origin 'refs/heads/*:refs/heads/*'", 'git push origin refs/heads/*:refs/heads/*',
    'git push --all', 'git push --all origin', 'git push -u origin --all', 'git push --al origin', 'git push --bra origin', 'git push origin "refs/heads/*"',
    "git push origin '*:*'", "git push origin 'refs/remotes/origin/*:refs/heads/*'", "git push origin 'refs/heads/ma*:refs/heads/ma*'", "git push origin 'refs/*:refs/*'",
    'git push -o ci.skip origin --all']) {
    assert.deepEqual(shell(cmd, onFeature), direct, cmd);
    assert.equal(routineShell(cmd), false, cmd);
  }
  // Options with a value do not shift the repository and refspec words: on main, a push with no refspec is denied.
  for (const cmd of ['git push', 'git push origin', 'git push -o ci.skip origin', 'git push --push-option ci.skip origin', 'git push --repo origin',
    'git push --repo=origin', 'git push -u origin', 'git push --set-upstream origin', 'git push --receive-pack git-receive-pack origin',
    'git push --push-o x origin', 'git push -uo ci.skip origin', 'git push --recurse-submodules check origin', 'git push origin 2>&1']) {
    assert.equal(shell(cmd, onMain)?.decision, 'deny', `on main: ${cmd}`);
  }
  // A feature branch, also with options, a pattern that stays in another namespace, and tags: the plain push floor.
  for (const cmd of ['git push origin feature/x', 'git push -u origin feature/x', 'git push --set-upstream origin feature/x', 'git push -o ci.skip origin feature/x',
    'git push --push-option=ci.skip origin feature/x', "git push origin 'refs/heads/feature/*:refs/heads/feature/*'", 'git push origin --tags', 'git push origin',
    'git push --repo origin feature/x']) {
    const v = shell(cmd, onFeature);
    assert.equal(v?.decision, 'ask', cmd);
    assert.equal(v?.floor, true, cmd);
  }
});

test('F2-5: the guard denies git push --all on a feature branch end to end', () => {
  const dir = preInstallRepo();
  for (const command of ['git push origin --all', 'git push origin --branches', "git push origin 'refs/heads/*:refs/heads/*'"]) {
    assert.equal(hook(dir, command).decision, 'deny', command);
  }
  assert.equal(hook(dir, 'git push origin feature/x').decision, 'ask');
});

// ---------------------------------------------------------------- F2-6

test('F2-6: git diff with the null device or a path outside the project is denied like --no-index, never routine', () => {
  const outside = path.join(os.tmpdir(), 'bi-harness-round2-outside', 'appsettings.json').replace(/\\/g, '/');
  assert.equal(shell('git diff --no-index a.md b.md')?.decision, 'deny');
  for (const cmd of ['git diff /dev/null /c/Windows/win.ini', `git diff /dev/null ${outside}`, 'git diff ../a.txt ../b.txt', 'git diff NUL README.md',
    'git diff nul README.md', 'git diff README.md NUL:', 'git diff nul.txt README.md', 'git diff README.md ../outside.txt', 'git diff -- /dev/null ../x.txt',
    'git diff --stat /dev/null C:/Windows/win.ini', 'git diff /dev/null C:\\Windows\\win.ini', 'git diff ~/x.txt README.md', 'git diff README.md ~/x.txt',
    `git diff ${outside} README.md`, 'git diff /c/Windows/win.ini /c/Windows/system.ini', 'git diff /dev/stdin README.md', 'git -C .. diff a.md b.md',
    'git diff HEAD -- ../x.txt', 'git diff //server/share/x.txt README.md', 'git --no-pager diff /dev/null ../x.txt']) {
    const v = shell(cmd);
    assert.equal(v?.decision, 'deny', cmd);
    assert.match(v.reason, /--no-index/, cmd);
    assert.equal(routineShell(cmd), false, cmd);
  }
  // Revisions, ranges, blobs, pathspecs inside the project and search texts stay routine.
  for (const cmd of ['git diff', 'git diff --stat', 'git diff HEAD~1 -- README.md', 'git diff main feature/x', 'git diff origin/main', 'git diff HEAD~2..HEAD',
    'git diff main...feature/x --stat', 'git diff HEAD:README.md HEAD~1:README.md', "git diff -- '*.md'", 'git diff -S /api/v1', 'git diff -G /x/ HEAD~1',
    'git diff --cached', 'git diff refs/heads/main', 'git diff HEAD -- docs/a.md hardening/README.md', 'git diff HEAD^ HEAD', 'git diff :/fix',
    'git diff > /dev/null', 'git diff HEAD~1 2>&1', 'git diff HEAD~1 >$null']) {
    assert.equal(shell(cmd), null, cmd);
    assert.equal(routineShell(cmd), true, cmd);
  }
  // Two words the guard cannot place (variables) may be an outside file: the user decides, never auto mode.
  const vars = shell('git diff "$A" "$B"');
  assert.equal(vars?.decision, 'ask');
  assert.equal(vars?.autoApprovable, false);
  assert.equal(routineShell('git diff $A $B'), false);
  assert.equal(shell('git diff $REV'), null, 'one word is never compared as a file');
  assert.equal(routineShell('git diff $REV'), false);
});

test('F2-6: the guard denies the implicit --no-index end to end, in Bash and PowerShell', () => {
  const dir = preInstallRepo();
  for (const [command, tool] of [['git diff /dev/null /c/Windows/win.ini', 'Bash'], ['git diff /dev/null C:/Windows/win.ini', 'PowerShell'],
    ['git diff NUL README.md', 'PowerShell'], ['git diff README.md ../outside.txt', 'Bash']]) {
    assert.equal(hook(dir, command, tool).decision, 'deny', `${tool}: ${command}`);
  }
  assert.equal(hook(dir, 'git diff main feature/x').decision, 'allow');
});

// Adjacent claim of F2-6: `git commit -F <file outside>` reads that file into the commit. PR #15 (F1-57, gitFileRead) made it
// an ask auto mode never answers; pinned here.
test('F2-6: git commit -F with a file outside the project asks the user and is never routine', () => {
  for (const cmd of ['git commit --allow-empty -F ../x.txt', 'git commit --allow-empty -F /c/Windows/win.ini', 'git commit -aF ../x.txt', 'git commit --file=../x.txt']) {
    const v = shell(cmd);
    assert.equal(v?.decision, 'ask', cmd);
    assert.equal(v?.autoApprovable, false, cmd);
    assert.equal(routineShell(cmd), false, cmd);
  }
  assert.equal(shell('git commit --allow-empty -F docs/msg.txt'), null);
});

// ---------------------------------------------------------------- F2-9

test('F2-9: a GitHub MCP server under any name gets the GitHub write floor; its reads get no verdict', () => {
  for (const tool of ['mcp__github__create_pull_request', 'mcp__GitHub__create_pull_request', 'mcp__github-enterprise__merge_pull_request',
    'mcp__github_server__push_files', 'mcp__github-mcp-server__create_issue', 'mcp__GITHUB__delete_file']) {
    const v = analyzeMcpCall(tool, {}, DEFAULT_CONFIG);
    assert.equal(v?.decision, 'ask', tool);
    assert.equal(v?.floor, true, tool);
    assert.match(v.reason, /GitHub write action/, tool);
  }
  for (const tool of ['mcp__GitHub__get_file_contents', 'mcp__github-enterprise__search_code', 'mcp__github_server__list_issues']) {
    assert.equal(analyzeMcpCall(tool, {}, DEFAULT_CONFIG), null, tool);
  }
});
