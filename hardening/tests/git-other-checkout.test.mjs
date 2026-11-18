// git commands that act on another checkout (2026-11-18). Measured on 94dce45 with the hook as a process: `git -C <dir> ...`,
// `git worktree remove --force <path>` and `git worktree move <a> <b>` passed where their plain spellings (`cd <dir> && git ...`,
// `rm -rf <path>`, `mv <a> <b>`) were denied, most of all from a worktree session, whose project is the worktree: there a
// `git -C <main checkout> checkout -- x` rewrote a file of the main checkout unprompted. The policy (plainGitVerdict in
// lib/policy.mjs) now gives each the stricter of its own verdict and that of its plain spelling:
//   1. `git -C <dir>` into another checkout (a folder outside the project, or one inside it with its own .git entry), any number
//      of -C combined as git combines them: the verdict of `cd <dir> && git ...`; a -C the guard cannot place keeps its verdict;
//   2. `git worktree remove` with -f or --force (anywhere, clustered, abbreviated): the verdict of `rm -rf <path>` from git's folder;
//      without force unchanged (git refuses a worktree with changes);
//   3. `git worktree move <a> <b>`: the verdict of `mv <a> <b>` from git's folder;
//   4. git worktree prune, add, lock, unlock, repair and list: unchanged.
// A -C into a folder of the project itself keeps its verdict: `cd hardening && git restore --staged x` is denied as a write in
// a guardrail folder, while `git -C hardening restore --staged x` passes (open-2026-11-17-writers.test.mjs asserts it).
// Every row runs pre-tool-use.mjs as a process: from the repository root (the main session), from a project subfolder, and in a
// worktree session (CLAUDE_PROJECT_DIR the main checkout, payload `cwd` a verified worktree), with the main checkout's hook and as
// a subagent with the worktree's own copy. {O} is another repository outside the project, {OW} a linked worktree of the project
// outside it, {T} a folder outside both.
import { after, test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const pack = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const temps = [];
const tempDir = (name) => {
  const dir = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), `bi-harness-goc-${name}-`)));
  temps.push(dir);
  return dir;
};
after(() => temps.forEach((t) => fs.rmSync(t, { recursive: true, force: true, maxRetries: 3 })));
const posix = (p) => String(p).replace(/\\/g, '/');
const write = (root, files) => {
  for (const [rel, text] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(root, rel)), { recursive: true });
    fs.writeFileSync(path.join(root, rel), text);
  }
};

// ---------------------------------------------------------------- fixture

const emptyHome = tempDir('home');
const top = tempDir('fx');
const baseEnv = {
  ...Object.fromEntries(Object.entries(process.env).filter(([k]) => !/^(?:GIT_|CLAUDE_|BI_HARNESS_HOST$|COPILOT_CLI$)/i.test(k))),
  HOME: emptyHome, USERPROFILE: emptyHome, GIT_CONFIG_NOSYSTEM: '1', GIT_CEILING_DIRECTORIES: path.dirname(top),
  BI_HARNESS_GIT_TIMEOUT_MS: process.env.BI_HARNESS_GIT_TIMEOUT_MS ?? '10000',
};
function git(cwd, ...args) {
  const r = spawnSync('git', ['-c', 'user.name=Harness Test', '-c', 'user.email=t@example.com', '-c', 'commit.gpgsign=false',
    '-c', 'core.autocrlf=false', '-c', 'init.defaultBranch=main', ...args], { cwd, encoding: 'utf8', env: baseEnv, windowsHide: true });
  assert.equal(r.status, 0, `git ${args.join(' ')}: ${r.stderr}`);
  return r.stdout;
}

const repo = path.join(top, 'repo');
const wt = path.join(repo, '.claude', 'worktrees', 'wt');
const wt2 = path.join(repo, '.claude', 'worktrees', 'wt2');
const O = path.join(top, 'other');
const OW = path.join(top, 'ow');
const T = path.join(top, 'target');

fs.mkdirSync(repo, { recursive: true });
git(repo, 'init', '-q');
fs.cpSync(path.join(pack, 'hooks'), path.join(repo, 'hardening', 'hooks'), { recursive: true });
fs.cpSync(path.join(pack, 'scripts'), path.join(repo, 'hardening', 'scripts'), { recursive: true });
write(repo, { 'notes.txt': 'n\n', 'docs/a.md': '# a\n', '.claude/settings.json': '{}\n', 'hardening/harness.config.json': '{ "approvals": { "mode": "auto" } }\n' });
fs.appendFileSync(path.join(repo, '.git', 'info', 'exclude'), '\n.claude/worktrees/\n.claude/logs/\n.claude/settings.local.json\n');
git(repo, 'add', '-A');
git(repo, 'commit', '-q', '-m', 'fixture');
git(repo, 'checkout', '-q', '-b', 'feature');
git(repo, 'worktree', 'add', '-q', '-b', 'wt-branch', wt);
git(repo, 'worktree', 'add', '-q', '-b', 'wt2-branch', wt2);
git(repo, 'worktree', 'add', '-q', '-b', 'ow-branch', OW);
fs.mkdirSync(O, { recursive: true });
git(O, 'init', '-q');
write(O, { 'notes.txt': 'o\n' });
git(O, 'add', '-A');
git(O, 'commit', '-q', '-m', 'other');
git(O, 'checkout', '-q', '-b', 'feat');
fs.mkdirSync(T, { recursive: true });

// ---------------------------------------------------------------- running the guard

const SUB = { agent_id: 'b6e1d2c3f4a5', agent_type: 'general-purpose' };
/** A session: the payload's cwd, the checkout whose hook script runs, the process folder, the agent fields. */
const S = {
  root: { cwd: repo, hooks: repo, proc: repo, agent: {} },
  docs: { cwd: path.join(repo, 'docs'), hooks: repo, proc: repo, agent: {} },
  wtMain: { cwd: wt, hooks: repo, proc: repo, agent: {} },
  wtSub: { cwd: wt, hooks: wt, proc: wt, agent: SUB },
  wtDocs: { cwd: path.join(wt, 'docs'), hooks: repo, proc: repo, agent: {} },
};
let calls = 0;
function guard(s, command) {
  const [tool_name, text] = command.startsWith('PS> ') ? ['PowerShell', command.slice(4)] : ['Bash', command];
  const payload = { session_id: `goc${String(++calls).padStart(5, '0')}`, cwd: s.cwd, permission_mode: 'default', hook_event_name: 'PreToolUse',
    tool_name, tool_input: { command: fill(text) }, ...s.agent };
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [path.join(s.hooks, 'hardening', 'hooks', 'pre-tool-use.mjs')], {
      cwd: s.proc, env: { ...baseEnv, CLAUDE_PROJECT_DIR: repo, CLAUDE_BASH_MAINTAIN_PROJECT_WORKING_DIR: '1' }, windowsHide: true,
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (c) => { stdout += c; });
    child.stderr.on('data', (c) => { stderr += c; });
    child.on('close', (status) => {
      assert.equal(status, 0, `${command}: ${stderr}`); // a guard that did not run prints no verdict, which would read as a pass
      const out = stdout.trim() ? JSON.parse(stdout).hookSpecificOutput : null;
      resolve({ decision: out?.permissionDecision ?? null, reason: out?.permissionDecisionReason ?? '' });
    });
    child.stdin.end(JSON.stringify(payload));
  });
}
const fill = (cmd) => cmd.replaceAll('{O}', posix(O)).replaceAll('{OW}', posix(OW)).replaceAll('{T}', posix(T));
async function mapLimit(items, limit, fn) {
  const out = new Array(items.length);
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i], i);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return out;
}
// The guard answers allow for routine work in auto mode (the fixture's approvals): no verdict of its own.
const RANK = { deny: 3, ask: 2, null: 1, allow: 1 };
const rank = (v) => RANK[v.decision ?? 'null'];

// ---------------------------------------------------------------- the rows

// [session, git spelling, plain spelling, decision now, decision on 94dce45 when it had one]. The plain spelling is the brief's
// (`(cd <dir> && git ...)`), except for `git switch main` and `git checkout main` from the root and `git switch main` from a worktree session: there the subshell
// spelling asks only because its closing parenthesis is read as part of the branch name ("The guard cannot tell what main)
// holds"), and the bare `cd <dir> && git ...` and PowerShell's Push-Location spelling give no verdict, so those rows keep theirs.
const PAIRS = [
  // From the repository root.
  ['root', 'git -C {O} switch main', 'cd {O} && git switch main', null],
  ['root', 'git -c color.ui=never -C {O} switch main', 'cd {O} && git -c color.ui=never switch main', null],
  ['root', 'git -C {O} checkout main', 'cd {O} && git checkout main', null],
  ['root', 'git -C {O} checkout -- notes.txt', '(cd {O} && git checkout -- notes.txt)', null],
  ['root', 'git -C {O} restore notes.txt', '(cd {O} && git restore notes.txt)', null],
  // A word with a quote and separators stays one word in the plain spelling: nothing of it runs as a command of its own.
  ['root', 'git -C {O} commit -m "don\'t; rm -rf x | y"', 'cd {O} && git commit -m "don\'t; rm -rf x | y"', null],
  ['root', 'git worktree remove --force {OW}', 'rm -rf {OW}', 'deny'],
  ['root', 'git worktree remove --force .claude/worktrees/wt2', 'rm -rf .claude/worktrees/wt2', 'deny'],
  ['root', 'git worktree remove {OW} --force', 'rm -rf {OW}', 'deny'],
  ['root', 'git worktree remove -f -f .claude/worktrees/wt2', 'rm -rf .claude/worktrees/wt2', 'deny'],
  ['root', 'git worktree remove -ff {OW}', 'rm -rf {OW}', 'deny'],
  ['root', 'git worktree remove --forc {OW}', 'rm -rf {OW}', 'deny'],
  ['root', 'git -C docs worktree remove --force ../.claude/worktrees/wt2', 'rm -rf .claude/worktrees/wt2', 'deny'],
  ['root', 'PS> git worktree remove --force {OW}', 'PS> Remove-Item -Recurse -Force {OW}', 'deny'],
  ['root', 'PS> git worktree remove --force .claude/worktrees/wt2', 'PS> Remove-Item -Recurse -Force .claude/worktrees/wt2', 'deny'],
  ['root', 'git worktree move .claude/worktrees/wt2 {T}/moved', 'mv .claude/worktrees/wt2 {T}/moved', 'deny'],
  ['root', 'git worktree move {OW} {T}/moved2', 'mv {OW} {T}/moved2', null],
  // Another checkout inside the project: a worktree under .claude/worktrees/ holds its own .git.
  ['root', 'git -C .claude/worktrees/wt2 checkout main', '(cd .claude/worktrees/wt2 && git checkout main)', 'deny'],
  ['root', 'git -C .claude/worktrees/wt2 checkout -- notes.txt', '(cd .claude/worktrees/wt2 && git checkout -- notes.txt)', 'deny', 'deny'],
  // From a project subfolder: relative paths start there.
  ['docs', 'git worktree remove --force ../.claude/worktrees/wt2', 'rm -rf ../.claude/worktrees/wt2', 'deny'],
  ['docs', 'git worktree move ../.claude/worktrees/wt2 {T}/moved', 'mv ../.claude/worktrees/wt2 {T}/moved', 'deny'],
];
// The same from a worktree session, with the main checkout's hook and as a subagent with the worktree's own copy.
const WORKTREE_PAIRS = [
  ['git -C {O} checkout -- notes.txt', '(cd {O} && git checkout -- notes.txt)', 'deny'],
  ['git -C {O} restore notes.txt', '(cd {O} && git restore notes.txt)', 'deny'],
  ['git -C {O} checkout main', '(cd {O} && git checkout main)', 'deny'],
  ['git -C {OW} checkout -- notes.txt', '(cd {OW} && git checkout -- notes.txt)', 'deny'],
  ['git -C {O} switch main', 'cd {O} && git switch main', null],
  ['PS> git -C {O} checkout -- notes.txt', 'PS> Push-Location {O}; try { git checkout -- notes.txt } finally { Pop-Location }', 'deny'],
  ['git -C ../../.. checkout -- notes.txt', '(cd ../../.. && git checkout -- notes.txt)', 'deny'],
  ['git worktree remove --force {OW}', 'rm -rf {OW}', 'deny'],
  ['git worktree remove --force ../wt2', 'rm -rf ../wt2', 'deny'],
  ['PS> git worktree remove --force {OW}', 'PS> Remove-Item -Recurse -Force {OW}', 'deny'],
  ['git worktree move {OW} {T}/moved', 'mv {OW} {T}/moved', 'deny'],
  ['git worktree move ../wt2 {T}/moved', 'mv ../wt2 {T}/moved', 'deny'],
  // Spellings of -C: twice, after another global option, after --no-pager, quoted.
  ['git -C {T} -C ../other checkout -- notes.txt', '(cd {O} && git checkout -- notes.txt)', 'deny'],
  ['git -c color.ui=never -C {O} checkout -- notes.txt', '(cd {O} && git -c color.ui=never checkout -- notes.txt)', 'deny'],
  ['git --no-pager -C {O} checkout -- notes.txt', '(cd {O} && git --no-pager checkout -- notes.txt)', 'deny'],
  ['git -C "{O}" checkout -- notes.txt', '(cd "{O}" && git checkout -- notes.txt)', 'deny'],
  ["git -C '{O}' restore notes.txt", "(cd '{O}' && git restore notes.txt)", 'deny'],
  // Spellings of the program: git.exe, a path to it, behind env, command, an assignment or bash -c; PowerShell's call operator.
  ['git.exe -C {O} checkout -- notes.txt', '(cd {O} && git checkout -- notes.txt)', 'deny'],
  ['/usr/bin/git -C {O} checkout -- notes.txt', '(cd {O} && git checkout -- notes.txt)', 'deny'],
  ['env git -C {O} checkout -- notes.txt', '(cd {O} && git checkout -- notes.txt)', 'deny'],
  ['command git -C {O} checkout -- notes.txt', '(cd {O} && git checkout -- notes.txt)', 'deny'],
  ['FOO=1 git -C {O} checkout -- notes.txt', '(cd {O} && git checkout -- notes.txt)', 'deny'],
  ['bash -c "git -C {O} checkout -- notes.txt"', '(cd {O} && git checkout -- notes.txt)', 'deny'],
  ['PS> & git -C {O} checkout -- notes.txt', 'PS> Push-Location {O}; try { git checkout -- notes.txt } finally { Pop-Location }', 'deny'],
  ['git.exe worktree remove --force {OW}', 'rm -rf {OW}', 'deny'],
  ['env git worktree remove --force {OW}', 'rm -rf {OW}', 'deny'],
  ['echo y | xargs git worktree remove --force {OW}', 'rm -rf {OW}', 'deny'],
];
const ROWS = [
  ...PAIRS.map(([s, gitCmd, plain, now, was = null]) => ({ s, git: gitCmd, plain, now, was })),
  ...WORKTREE_PAIRS.flatMap(([gitCmd, plain, now]) => ['wtMain', 'wtSub'].map((s) => ({ s, git: gitCmd, plain, now, was: null }))),
  // A relative -C from a subfolder of the worktree: ../../../.. is the main checkout.
  { s: 'wtDocs', git: 'git -C ../../../.. checkout -- notes.txt', plain: '(cd ../../../.. && git checkout -- notes.txt)', now: 'deny', was: null },
];

// Denied or asked on 94dce45 already, and to stay so.
const ALREADY = [
  ['git -C {O} reset --hard', 'deny'], ['git -C {O} clean -fdx', 'deny'], ['git -C {O} config core.hooksPath x', 'deny'], ['git -C {O} checkout .', 'deny'],
  ['git --git-dir={O}/.git --work-tree={O} status', 'deny'], ['git --git-dir={O}/.git --work-tree={O} checkout -- notes.txt', 'deny'],
  ['GIT_DIR={O}/.git git status', 'deny'], ['GIT_WORK_TREE={O} git checkout -- notes.txt', 'deny'], ['git -C {O} push', 'ask'],
];
// Their verdicts on 94dce45, unchanged: a -C inside the project, reads and commits in another repository, the worktree verbs
// that delete nothing, remove without force, and the plain file restores.
const UNCHANGED = [
  ['root', 'git -C docs checkout -- a.md', null], ['root', 'git -C . checkout -- notes.txt', null], ['root', 'git -C {O} status', null],
  ['root', 'git -C {O} commit -am x', null], ['root', 'git worktree list', null], ['root', 'git worktree prune', null],
  ['root', 'git worktree add {T}/new', null], ['root', 'git worktree lock {OW}', null], ['root', 'git worktree unlock {OW}', null],
  ['root', 'git worktree repair', null], ['root', 'git worktree remove {OW}', null], ['root', 'git worktree remove .claude/worktrees/wt2', null],
  ['root', 'git checkout -- notes.txt', null], ['root', 'git restore notes.txt', null], ['root', 'git -C hardening restore --staged hooks/x.mjs', null],
  ['root', 'git -C {O} switch feat', 'ask'],
  // Reads and records in a worktree under .claude/worktrees/ (another checkout inside the project): routine as before.
  ['root', 'git -C .claude/worktrees/wt2 status', 'allow'], ['root', 'git -C .claude/worktrees/wt2 diff', 'allow'],
  ['root', 'git -C .claude/worktrees/wt2 log -1', 'allow'], ['root', 'git -C .claude/worktrees/wt2 add -A', 'allow'],
  ['root', 'git -C .claude/worktrees/wt2 commit -am x', 'allow'],
  ['wtMain', 'git -C {O} status', null], ['wtMain', 'git -C {O} commit -am x', null], ['wtMain', 'git worktree list', null],
  ['wtMain', 'git worktree remove {OW}', null], ['wtMain', 'git checkout -- notes.txt', null], ['wtMain', 'git restore notes.txt', null],
  ['wtSub', 'git -C {O} status', null], ['wtSub', 'git checkout -- notes.txt', null], ['wtSub', 'git -C docs checkout -- a.md', null],
];

const judged = (async () => {
  const jobs = [
    ...ROWS.flatMap((r) => [[r.s, r.git], [r.s, r.plain]]),
    ...ALREADY.flatMap(([cmd]) => [['root', cmd], ['wtMain', cmd]]),
    ...UNCHANGED.map(([s, cmd]) => [s, cmd]),
  ];
  const results = await mapLimit(jobs, 6, ([s, cmd]) => guard(S[s], cmd));
  return new Map(jobs.map(([s, cmd], i) => [`${s}|${cmd}`, results[i]]));
})();
const verdict = async (s, cmd) => (await judged).get(`${s}|${cmd}`);

// ---------------------------------------------------------------- tests

test('git spelling is never weaker than its plain spelling, from the root, a subfolder and a worktree session', async () => {
  for (const r of ROWS) {
    const [g, p] = [await verdict(r.s, r.git), await verdict(r.s, r.plain)];
    assert.ok(rank(g) >= rank(p), `${r.s}: ${r.git} (${g.decision}) is weaker than ${r.plain} (${p.decision}: ${p.reason})`);
  }
});

test('the rows that change get their exact decision, and a reason that names the plain spelling', async () => {
  for (const r of ROWS) {
    const g = await verdict(r.s, r.git);
    assert.equal(g.decision === 'allow' ? null : g.decision, r.now, `${r.s}: ${r.git}: ${g.reason}`);
    if (r.now === 'deny' && r.was !== 'deny') assert.match(g.reason, /runs git in another checkout|worktree remove --force deletes the worktree folder|worktree move moves the worktree folder/, `${r.s}: ${r.git}`);
  }
});

test('commands denied or asked on 94dce45 keep that verdict', async () => {
  for (const [cmd, decision] of ALREADY) {
    for (const s of ['root', 'wtMain']) assert.equal((await verdict(s, cmd)).decision, decision, `${s}: ${cmd}`);
  }
});

test('must not change: -C inside the project, reads and commits elsewhere, worktree prune/add/lock/unlock/repair/list, remove without force', async () => {
  for (const [s, cmd, decision] of UNCHANGED) assert.equal((await verdict(s, cmd)).decision, decision, `${s}: ${cmd}`);
});

test('a -C into another checkout, git worktree remove --force and git worktree move are never answered as routine work', async () => {
  // Auto mode (the fixture's approvals) answers allow for routine work.
  for (const r of ROWS) assert.notEqual((await verdict(r.s, r.git)).decision, 'allow', `${r.s}: ${r.git}`);
  for (const [cmd] of ALREADY) assert.notEqual((await verdict('root', cmd)).decision, 'allow', cmd);
});

test('routineShell reports none of the root rows as routine (rule 5 holds by construction: a -C outside the project and the worktree verbs are never routine)', () => {
  // routineShell itself, in a process whose project is the fixture (CLAUDE_PROJECT_DIR), with the controls it passes.
  const commands = ROWS.filter((r) => r.s === 'root').map((r) => fill(r.git));
  const controls = ['git -C docs status', 'git -C .claude/worktrees/wt2 status', 'git -C .claude/worktrees/wt2 commit -am x'];
  const policy = pathToFileURL(path.join(repo, 'hardening', 'hooks', 'lib', 'policy.mjs')).href;
  const script = `const { routineShell } = await import(${JSON.stringify(policy)}); const [cmds, cwd] = JSON.parse(process.argv[1]);`
    + ' process.stdout.write(JSON.stringify(cmds.map((c) => routineShell(c, cwd))));';
  const r = spawnSync(process.execPath, ['--input-type=module', '-e', script, JSON.stringify([[...commands, ...controls], repo])],
    { cwd: repo, env: { ...baseEnv, CLAUDE_PROJECT_DIR: repo }, encoding: 'utf8', windowsHide: true });
  assert.equal(r.status, 0, r.stderr);
  const routine = JSON.parse(r.stdout);
  commands.forEach((cmd, j) => assert.equal(routine[j], false, cmd));
  controls.forEach((cmd, j) => assert.equal(routine[commands.length + j], true, `control: ${cmd}`));
});
