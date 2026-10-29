// Follow-up audit 2026-10-19 (round 3): the shell guard's environment dumps, git trace targets and configured pushes.
// F2-15: bare `export`, `declare` and `typeset`, and `declare -x`/`typeset -x`/`typeset -p` without a NAME print every
//        variable with its value; only `export -p` and `declare -p` were denied.
// GIT_TRACE: `GIT_TRACE=/some/file git status` (and GIT_TRACE_PACKET, GIT_TRACE2_EVENT, af_unix: targets, the trace2.*Target
//        keys) makes git append its trace to any file; no form had a verdict. `export GIT_PAGER=x; git log` and PowerShell's
//        `$env:GIT_PAGER = 'x'` had none either: only the form in front of git was denied.
// Push configuration: a bare `git push` from a feature branch pushed main too when the configuration said so
//        (push.default=matching, a remote.<name>.push refspec, remote.<name>.mirror, -c of these); it got the plain push ask.
import { after, test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { analyzeShellCommand, routineShell } from '../hooks/lib/policy.mjs';

const preHook = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'hooks', 'pre-tool-use.mjs');
const decision = (cmd, ctx = {}) => analyzeShellCommand(cmd, ctx)?.decision ?? null;

const temps = [];
after(() => temps.forEach((dir) => fs.rmSync(dir, { recursive: true, force: true })));
const tempDir = (name) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `bi-harness-round3-${name}-`));
  temps.push(dir);
  return dir;
};

// git and the hook run with no inherited repository variables (a `git commit -a` hook exports GIT_INDEX_FILE, some setups
// GIT_DIR) and with the machine's global and system configuration left out: a push.default=matching there would change
// the verdicts the negative controls expect. The global file is an empty one of the test's own.
const GIT_REPO_VARS = new Set(['GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE', 'GIT_OBJECT_DIRECTORY', 'GIT_ALTERNATE_OBJECT_DIRECTORIES', 'GIT_COMMON_DIR', 'GIT_PREFIX']);
let globalConfig = null;
function cleanEnv(extra = {}) {
  if (!globalConfig) {
    globalConfig = path.join(tempDir('home'), 'gitconfig');
    fs.writeFileSync(globalConfig, '');
  }
  const env = Object.fromEntries(Object.entries(process.env).filter(([k]) => !GIT_REPO_VARS.has(k.toUpperCase()) && !/^GIT_CONFIG/i.test(k)));
  delete env.BI_HARNESS_HOST;
  return { ...env, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: globalConfig, ...extra };
}

/** Runs git in `dir` (test setup only); throws on failure. */
function git(dir, ...args) {
  const r = spawnSync('git', ['-c', 'user.email=t@example.com', '-c', 'user.name=t', '-c', 'core.autocrlf=false', ...args], { cwd: dir, encoding: 'utf8', env: cleanEnv() });
  assert.equal(r.status, 0, `git ${args.join(' ')}: ${r.stderr}`);
  return r.stdout.trim();
}

/** The PreToolUse guard's verdict for one shell command, run as a process like Claude Code runs it (auto mode, the default). */
function hook(dir, command, tool_name = 'Bash') {
  const r = spawnSync(process.execPath, [preHook], {
    input: JSON.stringify({ hook_event_name: 'PreToolUse', session_id: 'round3-policy', tool_name, cwd: dir, tool_input: { command } }),
    env: cleanEnv({ CLAUDE_PROJECT_DIR: dir }),
    encoding: 'utf8',
  });
  assert.equal(r.status, 0, r.stderr); // a guard that did not run prints no verdict, which "not allow" would read as a pass
  const out = r.stdout.trim() ? JSON.parse(r.stdout).hookSpecificOutput ?? {} : {};
  return { decision: out.permissionDecision ?? null, reason: out.permissionDecisionReason ?? '' };
}

/**
 * The shell policy's verdict for each command with `dir` as the project, as the guard calls it (the default protected
 * branches, the current branch read from `dir`), in one process for many commands: { decision, reason } per command.
 */
function policyIn(dir, commands) {
  const lib = (name) => JSON.stringify(pathToFileURL(path.join(path.dirname(preHook), 'lib', name)).href);
  const script = `import fs from 'node:fs';
    import { analyzeShellCommand } from ${lib('policy.mjs')};
    import { DEFAULT_CONFIG, currentBranch } from ${lib('common.mjs')};
    const ctx = { protectedBranches: DEFAULT_CONFIG.git.protectedBranches, getBranch: () => currentBranch() };
    const verdicts = JSON.parse(fs.readFileSync(0, 'utf8')).map((c) => {
      const v = analyzeShellCommand(c, ctx);
      return { decision: v?.decision ?? null, reason: v?.reason ?? '' };
    });
    process.stdout.write(JSON.stringify(verdicts));`;
  const r = spawnSync(process.execPath, ['--input-type=module', '-e', script], { input: JSON.stringify(commands), env: cleanEnv({ CLAUDE_PROJECT_DIR: dir }), encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
  return Object.fromEntries(JSON.parse(r.stdout).map((v, i) => [commands[i], v]));
}

/**
 * A project on branch feature/x with a local main, remotes that are never contacted (the guard only reads the
 * configuration: origin, and each name in `remotes`) and the given configuration entries (`git config --add key value`,
 * so a key may repeat).
 */
function repo(name, config = [], remotes = []) {
  const dir = tempDir(name);
  git(dir, 'init', '-q', '-b', 'main', '.');
  fs.writeFileSync(path.join(dir, 'README.md'), 'start\n');
  git(dir, 'add', 'README.md');
  git(dir, 'commit', '-qm', 'docs: start');
  git(dir, 'switch', '-qc', 'feature/x');
  for (const remote of ['origin', ...remotes]) git(dir, 'remote', 'add', remote, `https://example.invalid/${remote}.git`);
  for (const [key, value] of config) git(dir, 'config', '--add', key, value);
  return dir;
}

// ---------------------------------------------------------------- F2-15: variable listings

test('F2-15: export, declare and typeset without a NAME print every variable: denied like export -p', () => {
  const dumps = ['export', 'declare', 'typeset', 'declare -x', 'typeset -x', 'typeset -p', 'export -n', 'declare -r', 'declare --', 'declare +x',
    'declare -g', 'declare -i', 'export 2>&1', 'export > env-list.txt', 'echo hi && declare', 'builtin declare -x', 'command export',
    'typeset -p NAME', 'declare -Ap'];
  for (const cmd of dumps) {
    const v = analyzeShellCommand(cmd, {});
    assert.equal(v?.decision, 'deny', cmd);
    assert.match(v.reason, /Dumping environment variables/, cmd);
  }
  // Still denied as before.
  for (const cmd of ['export -p', 'declare -p', 'declare -px', 'declare -p NAME']) assert.equal(decision(cmd), 'deny', cmd);
});

test('F2-15: the guard denies a bare export end to end, in Bash and in a PowerShell call that hands it to bash', () => {
  const dir = repo('dump');
  assert.equal(hook(dir, 'export').decision, 'deny');
  assert.equal(hook(dir, 'typeset -x').decision, 'deny');
  assert.equal(hook(dir, "bash -c 'declare'", 'PowerShell').decision, 'deny');
});

test('F2-15: a NAME, a function listing and local stay as they were (no deny)', () => {
  for (const cmd of ['export NAME=value', 'declare -a arr', 'declare NAME=1', 'typeset -i n=1', 'declare -x NAME=1', 'export NAME', 'export -f',
    'declare -F', 'declare -f', 'declare -fx', 'local', 'local x=1', 'readonly', 'export A=1 B=2']) {
    assert.equal(decision(cmd), null, cmd);
  }
});

// ---------------------------------------------------------------- GIT_TRACE* targets

const TRACE_VARS = ['GIT_TRACE', 'GIT_TRACE_PACKET', 'GIT_TRACE_PACKFILE', 'GIT_TRACE_PERFORMANCE', 'GIT_TRACE_SETUP', 'GIT_TRACE_CURL',
  'GIT_TRACE_PACK_ACCESS', 'GIT_TRACE_SHALLOW', 'GIT_TRACE_REFS', 'GIT_TRACE_FSMONITOR', 'GIT_TRACE2', 'GIT_TRACE2_EVENT', 'GIT_TRACE2_PERF'];

test('GIT_TRACE*: a file, socket or name as the target is denied in every form that reaches git', () => {
  const forms = [
    ...TRACE_VARS.map((name) => `${name}=/tmp/trace.txt git status`),
    'GIT_TRACE=C:/Users/x/trace.txt git status', 'GIT_TRACE="/tmp/a b" git status', 'GIT_TRACE=trace.log git status', 'GIT_TRACE=$HOME/t git status',
    'GIT_TRACE2=af_unix:/tmp/sock git status', 'GIT_TRACE2_EVENT=af_unix:stream:/tmp/sock git status', 'git_trace=/tmp/x git status',
    'env GIT_TRACE=/tmp/x git status', 'env -u X GIT_TRACE_PACKET=/tmp/x git fetch',
    'export GIT_TRACE=/tmp/x; git status', 'export GIT_TRACE=/tmp/x && git status', 'export A=1 GIT_TRACE2_EVENT=/tmp/x; git status',
    'declare -x GIT_TRACE=/tmp/x; git status', 'GIT_TRACE=/tmp/x; export GIT_TRACE; git status', 'GIT_TRACE=/tmp/x bash -c "git status"',
    'setx GIT_TRACE C:/Users/x/trace.txt', 'setx GIT_TRACE /tmp/x /m', 'cmd /c "set GIT_TRACE=C:/x/t.txt&& git status"',
    "$env:GIT_TRACE='C:/x'; git status", '$env:GIT_TRACE = "C:/x"; git status', "${env:GIT_TRACE2_EVENT}='C:/x'; git status",
    "$env:GIT_TRACE += 'C:/x'; git status", '$env:GIT_TRACE=$p; git status',
    "[Environment]::SetEnvironmentVariable('GIT_TRACE', 'C:/x/t.txt', 'User')", 'Set-Item env:GIT_TRACE C:/x', 'Set-Item -Path Env:\\GIT_TRACE -Value C:/x',
    'git -c trace2.eventTarget=/tmp/x status', 'git -c trace2.normalTarget=/tmp/x status', 'git -c Trace2.PerfTarget=af_unix:/tmp/s status',
    'git --config-env=trace2.eventTarget=T status', 'git config trace2.eventTarget /tmp/x', 'git config --global trace2.normalTarget /tmp/x',
  ];
  for (const cmd of forms) {
    const v = analyzeShellCommand(cmd, {});
    assert.equal(v?.decision, 'deny', cmd);
    assert.match(v.reason, /GIT_TRACE|trace2 targets/, cmd);
  }
});

test('GIT_TRACE*: the guard denies the bash, env, export and PowerShell forms end to end', () => {
  const dir = repo('trace');
  for (const [command, tool] of [['GIT_TRACE=/tmp/x git status', 'Bash'], ['env GIT_TRACE2_EVENT=/tmp/x git status', 'Bash'],
    ['export GIT_TRACE=/tmp/x; git status', 'Bash'], ["$env:GIT_TRACE='C:\\x'; git status", 'PowerShell'], ['git -c trace2.eventTarget=/tmp/x status', 'Bash']]) {
    assert.equal(hook(dir, command, tool).decision, 'deny', `${tool}: ${command}`);
  }
});

test('GIT_* program and repository variables: the export, $env: and SetEnvironmentVariable forms are denied like the prefix form', () => {
  for (const cmd of ['export GIT_PAGER=./x.sh; git log', 'export GIT_DIR=../other/.git; git status', 'declare -x GIT_EXTERNAL_DIFF=./x.sh; git diff',
    "$env:GIT_PAGER='C:\\x.cmd'; git log", '$env:GIT_SSH_COMMAND = "x"; git fetch', "[Environment]::SetEnvironmentVariable('GIT_EDITOR', 'x')",
    'Set-Item env:GIT_ASKPASS x', 'setx GIT_PAGER x', 'GIT_PAGER=./x.sh bash -c "git log"', 'GIT_CONFIG_GLOBAL=/tmp/g; git status']) {
    const v = analyzeShellCommand(cmd, {});
    assert.equal(v?.decision, 'deny', cmd);
    assert.match(v.reason, /GIT_\* variable/, cmd);
  }
});

test('GIT_TRACE*: standard error, a descriptor, off and the trace2 settings without a target stay as they were', () => {
  const harmless = ['GIT_TRACE=1 git status', 'GIT_TRACE=true git status', 'GIT_TRACE=0 git status', 'GIT_TRACE= git status', 'GIT_TRACE=2 git status',
    'GIT_TRACE=10 git status', 'GIT_TRACE=off git status', 'GIT_TRACE_PACKET=yes git fetch', 'GIT_TRACE_REDACT=0 git status',
    'GIT_TRACE2_CONFIG_PARAMS=core.*,remote.* git status', 'GIT_TRACE2_ENV_VARS=PATH git status', 'GIT_TRACE2_EVENT_NESTING=5 git status',
    'export GIT_TRACE=1; git status', "$env:GIT_TRACE='1'; git status", '$env:GIT_TRACE = "true"; git status', 'setx GIT_TRACE 1',
    'git -c color.ui=never status', 'git config --get trace2.eventTarget', 'export NAME=/tmp/x; git status', 'Set-Item env:NAME C:/x',
    'git commit -m "deny export GIT_TRACE=/x and $env:GIT_TRACE=C:/x"'];
  for (const cmd of harmless) assert.equal(decision(cmd), null, cmd);
  assert.equal(routineShell('git status'), true);
});

// ---------------------------------------------------------------- a push without a refspec follows the configuration

test('push configuration: push.default=matching sends main with a bare git push; an explicit refspec does not read it', () => {
  const dir = repo('matching', [['push.default', 'matching']]);
  // End to end once, as Claude Code runs the guard.
  const e2e = hook(dir, 'git push');
  assert.equal(e2e.decision, 'deny');
  assert.match(e2e.reason, /push\.default is matching/);
  const bare = ['git push', 'git push origin', 'git push -u origin', 'git push --verbose', 'git push --repo=origin'];
  const got = policyIn(dir, [...bare, 'git push origin feature/x', 'git push origin HEAD']);
  for (const command of bare) {
    assert.equal(got[command].decision, 'deny', command);
    assert.match(got[command].reason, /push\.default is matching/, command);
  }
  assert.equal(got['git push origin feature/x'].decision, 'ask');
  assert.equal(got['git push origin HEAD'].decision, 'ask');
});

test('push configuration: remote.<name>.push refspecs that reach main, force, match or delete are judged like written ones', () => {
  const refspecs = ['refs/heads/*:refs/heads/*', 'HEAD:main', 'main', 'refs/heads/main:refs/heads/main', ':', '+refs/heads/feature/*:refs/heads/feature/*', ':refs/heads/old'];
  const remotes = refspecs.map((_, i) => `r${i}`);
  // Each remote holds a harmless refspec and then the one under test; origin holds the pattern, for a push that names no remote.
  const dir = repo('refspecs', [['remote.origin.push', 'refs/heads/*:refs/heads/*'],
    ...refspecs.flatMap((refspec, i) => [[`remote.r${i}.push`, 'refs/heads/feature/*:refs/heads/feature/*'], [`remote.r${i}.push`, refspec]])], remotes);
  assert.equal(hook(dir, 'git push').decision, 'deny', 'end to end');
  const got = policyIn(dir, ['git push', ...remotes.flatMap((r) => [`git push ${r}`, `git push ${r} feature/x`])]);
  assert.match(got['git push'].reason, /remote\.\w+\.push/);
  refspecs.forEach((refspec, i) => {
    assert.equal(got[`git push r${i}`].decision, 'deny', refspec);
    assert.match(got[`git push r${i}`].reason, new RegExp(`remote\\.r${i}\\.push`), refspec);
    assert.equal(got[`git push r${i} feature/x`].decision, 'ask', `${refspec}: an explicit refspec replaces the configured ones`);
  });
});

test('push configuration: remote.<name>.mirror makes a push to that remote a mirror push; push.default=upstream onto main', () => {
  const mirror = repo('mirror', [['remote.origin.mirror', 'true']]);
  const got = policyIn(mirror, ['git push origin', 'git push']);
  assert.equal(got['git push origin'].decision, 'deny');
  assert.match(got['git push origin'].reason, /mirror/);
  assert.equal(got['git push'].decision, 'deny');
  const upstream = repo('upstream', [['push.default', 'upstream'], ['branch.feature/x.remote', 'origin'], ['branch.feature/x.merge', 'refs/heads/main']]);
  const v = policyIn(upstream, ['git push'])['git push'];
  assert.equal(v.decision, 'deny');
  assert.match(v.reason, /upstream of feature\/x is main/);
});

test('push configuration: -c and --config-env before push count like the configuration', () => {
  const dir = repo('inline');
  const commands = ['git -c push.default=matching push', 'git -c remote.origin.push=refs/heads/*:refs/heads/* push', 'git -c remote.origin.push=HEAD:main push origin',
    'git -c remote.origin.mirror=true push origin', 'git -c remote.origin.mirror push', 'git --config-env=push.default=PUSHMODE push',
    'git --config-env remote.origin.push=SPEC push origin'];
  assert.equal(hook(dir, commands[0]).decision, 'deny', 'end to end');
  const got = policyIn(dir, commands);
  for (const command of commands) assert.equal(got[command].decision, 'deny', command);
});

test('push configuration: git config that changes what a bare push sends is denied; reading it is not', () => {
  for (const cmd of ['git config push.default matching', 'git config remote.origin.push refs/heads/*:refs/heads/*', 'git config --add remote.origin.push HEAD:main',
    'git config remote.origin.mirror true', 'git config --global push.default matching']) {
    assert.equal(decision(cmd), 'deny', cmd);
  }
  for (const cmd of ['git config --get push.default', 'git config --get-all remote.origin.push', 'git config push.default']) assert.equal(decision(cmd), null, cmd);
});

test('push configuration: a configuration that keeps to the feature branch keeps the plain push ask', () => {
  const cases = [
    ['none', []],
    ['simple', [['push.default', 'simple']]],
    ['current', [['push.default', 'current']]],
    ['feature-refspec', [['remote.origin.push', 'refs/heads/feature/*:refs/heads/feature/*']]],
    ['named-remote-wins', [['push.default', 'matching'], ['remote.origin.push', 'HEAD']]],
    ['upstream-feature', [['push.default', 'upstream'], ['branch.feature/x.remote', 'origin'], ['branch.feature/x.merge', 'refs/heads/feature/x']]],
    ['mirror-false', [['remote.origin.mirror', 'false']]],
  ];
  for (const [label, config] of cases) {
    const dir = repo(`keep-${label}`, config);
    const command = label === 'named-remote-wins' ? 'git push origin' : 'git push';
    const v = policyIn(dir, [command])[command];
    assert.equal(v.decision, 'ask', `${label}: ${command} (${v.reason})`);
    assert.match(v.reason, /publishes commits to the remote/, label);
  }
  const dir = repo('keep-inline');
  assert.equal(hook(dir, 'git push').decision, 'ask', 'end to end');
  const inline = ['git -c push.default=matching push origin feature/x', 'git -c push.default=simple push', 'git -c remote.other.push=main push origin'];
  const got = policyIn(dir, inline);
  for (const command of inline) assert.equal(got[command].decision, 'ask', command);
});
