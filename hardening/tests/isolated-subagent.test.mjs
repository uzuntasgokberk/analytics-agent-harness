// A subagent with worktree isolation and no pack in its worktree has no guard (2026-11-18). Measured live (Claude desktop app
// 5.11492.5, 2026-11-17): such a subagent runs its hooks with the worktree as process folder, so `node hardening/hooks/<script>.mjs`
// runs the worktree's own copy, and a hook whose file is not in the worktree did not run at all. The main session's PreToolUse
// guard sees the call that starts it (tool `Agent`, tool_input { description, isolation: "worktree", prompt, subagent_type },
// payload cwd the main session's folder). The guard (lib/isolated-subagent.mjs) now checks that hardening/hooks/pre-tool-use.mjs
// and hardening/hooks/agent-scope.mjs are in the commit Claude Code cuts the worktree from: origin/HEAD when it is cached, else
// HEAD; HEAD with "worktree": { "baseRef": "head" }; both when a settings file cannot be parsed or the value is neither.
// A missing file denies; a git that gives no answer, files copied only by .worktreeinclude and a WorktreeCreate hook are the
// floor ask; a project without .git, a Copilot payload and an Agent call without worktree isolation get no verdict. The banner
// names the gap. Every judgement runs the pack's hook as a process with CLAUDE_PROJECT_DIR the fixture; the fixture's own
// hardening/hooks/ files are stubs that git holds or not (git ls-tree reads names only).
import { after, test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const pack = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const temps = [];
const tempDir = (name) => {
  const dir = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), `bi-harness-iso-${name}-`)));
  temps.push(dir);
  return dir;
};
after(() => temps.forEach((t) => fs.rmSync(t, { recursive: true, force: true, maxRetries: 3 })));
const write = (root, files) => {
  for (const [rel, text] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(root, rel)), { recursive: true });
    fs.writeFileSync(path.join(root, rel), text);
  }
};

const emptyHome = tempDir('home');
const top = tempDir('fx');
const baseEnv = {
  ...Object.fromEntries(Object.entries(process.env).filter(([k]) => !/^(?:GIT_|CLAUDE_|BI_HARNESS_HOST$|COPILOT_CLI$)/i.test(k))),
  HOME: emptyHome, USERPROFILE: emptyHome, GIT_CONFIG_NOSYSTEM: '1', GIT_CEILING_DIRECTORIES: top,
  BI_HARNESS_GIT_TIMEOUT_MS: process.env.BI_HARNESS_GIT_TIMEOUT_MS ?? '10000',
};
function git(cwd, ...args) {
  const r = spawnSync('git', ['-c', 'user.name=Harness Test', '-c', 'user.email=t@example.com', '-c', 'commit.gpgsign=false',
    '-c', 'core.autocrlf=false', '-c', 'init.defaultBranch=main', ...args], { cwd, encoding: 'utf8', env: baseEnv, windowsHide: true });
  assert.equal(r.status, 0, `git ${args.join(' ')}: ${r.stderr}`);
  return r.stdout;
}

// ---------------------------------------------------------------- fixtures

const STUBS = { 'hardening/hooks/pre-tool-use.mjs': '// stub\n', 'hardening/hooks/agent-scope.mjs': '// stub\n' };
const AUTO = { 'hardening/harness.config.json': '{ "approvals": { "mode": "auto" } }\n' };
const LAB = { 'hardening/harness.config.json': '{ "approvals": { "mode": "lab" } }\n' };
const HEAD_REF = { '.claude/settings.local.json': '{ "worktree": { "baseRef": "head" } }\n' };
const commitAll = (repo, message) => {
  git(repo, 'add', '-A');
  git(repo, 'commit', '-q', '-m', message);
};
/** A repository: `committed` files in the first commit, `disk` files written after it (untracked unless ignored). */
function repoWith(name, { committed = {}, disk = {}, config = AUTO } = {}) {
  const repo = path.join(top, name);
  fs.mkdirSync(repo, { recursive: true });
  git(repo, 'init', '-q');
  write(repo, { 'README.md': '# r\n', ...committed });
  commitAll(repo, 'first');
  write(repo, { ...config, ...disk });
  return repo;
}
/** A bare remote that holds `branch` of `repo`, with refs/remotes/origin/HEAD cached and pointing at it. */
function withRemote(repo, branch = 'main') {
  const bare = path.join(top, `${path.basename(repo)}.git`);
  git(top, 'init', '-q', '--bare', bare);
  git(repo, 'remote', 'add', 'origin', bare);
  git(repo, 'push', '-q', 'origin', branch);
  git(repo, 'remote', 'set-head', 'origin', branch);
  return repo;
}

const IGNORED = { '.gitignore': 'hardening/\n' };
const AGENTS = {
  '.claude/agents/iso.md': '---\nname: iso-agent\ndescription: works in its own worktree\nisolation: worktree\n---\nDo the work.\n',
  '.claude/agents/quoted.md': '---\nname: "quoted-agent"\nisolation: "worktree" # its own checkout\n---\nDo the work.\n',
  '.claude/agents/plain.md': '---\nname: plain-agent\ndescription: works in the session folder\n---\nDo the work.\n',
};

const F = {};
// The pack committed on the default branch, which origin/HEAD names and HEAD is on.
F.committed = withRemote(repoWith('committed', { committed: STUBS }));
F.committedAgents = withRemote(repoWith('committed-agents', { committed: { ...STUBS, ...AGENTS } }));
// No remote: judged by HEAD.
F.noRemote = repoWith('no-remote', { committed: STUBS });
F.untracked = repoWith('untracked', { disk: STUBS });
F.untrackedLab = repoWith('untracked-lab', { disk: STUBS, config: LAB });
F.untrackedAgents = repoWith('untracked-agents', { disk: { ...STUBS, ...AGENTS } });
F.ignored = repoWith('ignored', { committed: IGNORED, disk: STUBS });
// Ignored, and .worktreeinclude at the project root: the files are copied into new worktrees only when every one is named.
const INCLUDE = {
  inclFolder: ['hardening/', 'ask'], inclAnchored: ['/hardening/hooks/', 'ask'], inclNames: ['# the guard\npre-tool-use.mjs\nagent-scope.mjs\n', 'ask'],
  inclGlob: ['**/*.mjs', 'ask'], inclStar: ['hardening/hooks/*.mjs', 'ask'],
  inclOther: ['docs/', 'deny'], inclOne: ['hardening/hooks/pre-tool-use.mjs', 'deny'], inclNegated: ['hardening/\n!hardening/hooks/agent-scope.mjs', 'deny'],
  inclComment: ['# hardening/\n\n', 'deny'], inclFileAsFolder: ['pre-tool-use.mjs/\nagent-scope.mjs/', 'deny'], inclClass: ['hardening/[h]ooks/', 'deny'],
  inclCase: ['HARDENING/', 'deny'],
};
for (const [key, [text]] of Object.entries(INCLUDE)) F[key] = repoWith(key, { committed: IGNORED, disk: { ...STUBS, '.worktreeinclude': text } });
// Tracked but not ignored is no copy: .worktreeinclude only copies ignored files.
F.inclUntracked = repoWith('incl-untracked', { disk: { ...STUBS, '.worktreeinclude': 'hardening/\n' } });
// The pack only on the feature branch: origin/HEAD (main) lacks it, HEAD holds it.
function featureOnly(name, extra = {}) {
  const repo = withRemote(repoWith(name));
  git(repo, 'checkout', '-q', '-b', 'feature');
  write(repo, STUBS);
  commitAll(repo, 'pack');
  write(repo, extra);
  return repo;
}
F.feature = featureOnly('feature');
F.featureHead = featureOnly('feature-head', HEAD_REF);
F.featureBroken = featureOnly('feature-broken', { ...HEAD_REF, '.claude/settings.json': '{ "worktree": ' });
// The pack on origin/HEAD, removed on HEAD.
function removedOnHead(name, extra = {}) {
  const repo = withRemote(repoWith(name, { committed: STUBS }));
  git(repo, 'checkout', '-q', '-b', 'feature');
  git(repo, 'rm', '-q', '-r', 'hardening/hooks');
  git(repo, 'commit', '-q', '-m', 'drop the pack');
  write(repo, extra);
  return repo;
}
F.removed = removedOnHead('removed');
F.removedHead = removedOnHead('removed-head', HEAD_REF);
F.removedBroken = removedOnHead('removed-broken', { '.claude/settings.json': '{ "worktree": ' });
F.removedWeird = removedOnHead('removed-weird', { '.claude/settings.json': '{ "worktree": { "baseRef": "main" } }\n' });
F.removedManyValues = removedOnHead('removed-many', { '.claude/settings.json': '{ "worktree": "head" }\n' });
// A remote named origin whose default branch is not cached (no refs/remotes/origin/HEAD): Claude Code fetches it before it
// cuts the worktree, so HEAD alone proves nothing. The pack is on HEAD in both; the second sets baseRef "head".
function uncachedOrigin(name, extra = {}) {
  const repo = repoWith(name, { committed: STUBS });
  const bare = path.join(top, `${name}.git`);
  git(top, 'init', '-q', '--bare', bare);
  git(repo, 'remote', 'add', 'origin', bare);
  git(repo, 'push', '-q', 'origin', 'HEAD');
  write(repo, extra);
  return repo;
}
F.uncached = uncachedOrigin('uncached');
F.uncachedHead = uncachedOrigin('uncached-head', HEAD_REF);
// A WorktreeCreate hook creates worktrees instead of git.
F.createHook = withRemote(repoWith('create-hook', { committed: STUBS }));
write(F.createHook, { '.claude/settings.json': JSON.stringify({ hooks: { WorktreeCreate: [{ hooks: [{ type: 'command', command: 'node make-worktree.mjs' }] }] } }) });
// No git repository at all.
F.noGit = path.join(top, 'no-git');
write(F.noGit, { ...STUBS, ...AUTO, 'README.md': '# r\n' });
// A git that cannot answer: HEAD corrupt (every git call fails), in auto and in lab mode.
F.badHead = repoWith('bad-head', { committed: STUBS });
F.badHeadLab = repoWith('bad-head-lab', { committed: STUBS, config: LAB });
for (const repo of [F.badHead, F.badHeadLab]) fs.writeFileSync(path.join(repo, '.git', 'HEAD'), 'not a ref\n');

// ---------------------------------------------------------------- running the hooks

const emptyBin = tempDir('nobin');
/** The environment without any spelling of PATH, and PATH an empty folder: git cannot start. */
const noGitEnv = () => ({ ...Object.fromEntries(Object.entries(baseEnv).filter(([k]) => !/^path$/i.test(k))), PATH: emptyBin });
let calls = 0;
function runHook(script, repo, payload, env = baseEnv) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [path.join(pack, 'hooks', script)], { cwd: repo, env: { ...env, CLAUDE_PROJECT_DIR: repo }, windowsHide: true });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (c) => { stdout += c; });
    child.stderr.on('data', (c) => { stderr += c; });
    child.on('close', (status) => resolve({ status, stdout, stderr }));
    child.stdin.end(JSON.stringify({ session_id: `iso${String(++calls).padStart(5, '0')}`, cwd: repo, permission_mode: 'default', ...payload }));
  });
}
const AGENT_INPUT = { description: 'Fix the thing', prompt: 'Fix the thing in its own worktree.', subagent_type: 'general-purpose' };
/** The guard's answer to a call of the Agent tool: decision, reason and the raw output. */
async function agent(repo, input = { ...AGENT_INPUT, isolation: 'worktree' }, { env, extra = {} } = {}) {
  const r = await runHook('pre-tool-use.mjs', repo, { hook_event_name: 'PreToolUse', tool_name: 'Agent', tool_input: input, ...extra }, env);
  assert.equal(r.status, 0, r.stderr); // a guard that did not run prints no verdict, which would read as a pass
  const out = r.stdout.trim() ? JSON.parse(r.stdout).hookSpecificOutput : null;
  return { decision: out?.permissionDecision ?? null, reason: out?.permissionDecisionReason ?? '', raw: r.stdout };
}
/** The session banner's text. */
async function banner(repo, extra = {}) {
  const r = await runHook('session-start.mjs', repo, { hook_event_name: 'SessionStart', source: 'startup', ...extra });
  assert.equal(r.status, 0, r.stderr);
  return r.stdout.trim() ? JSON.parse(r.stdout).hookSpecificOutput?.additionalContext ?? '' : '';
}
const DENY_REASON = /subagent with worktree isolation\. Its hooks run from its own worktree, which Claude Code cuts from .*not in that commit: the subagent would run with no guard\. Commit hardening\/ to the branch new worktrees are cut from .*"baseRef": "head".*or start the subagent without worktree isolation/;

// ---------------------------------------------------------------- tests

test('pack committed on the default branch and HEAD, or on HEAD without a remote: no verdict', async () => {
  for (const repo of [F.committed, F.noRemote, F.removed, F.featureHead]) {
    const v = await agent(repo);
    assert.equal(v.decision, null, `${path.basename(repo)}: ${v.reason}`);
    assert.equal(v.raw, '', `${path.basename(repo)}: no output at all`);
  }
});

test('pack untracked, ignored, or only on a branch other than the one worktrees are cut from: deny, with the ways out', async () => {
  const cases = [
    [F.untracked, /HEAD \(the current commit of this checkout\)/], [F.ignored, /HEAD \(the current commit/],
    [F.feature, /origin\/HEAD \(the default branch on the remote\)/], [F.removedHead, /HEAD \(the current commit/],
  ];
  for (const [repo, ref] of cases) {
    const v = await agent(repo);
    assert.equal(v.decision, 'deny', `${path.basename(repo)}: ${v.reason}`);
    assert.match(v.reason, DENY_REASON, path.basename(repo));
    assert.match(v.reason, ref, path.basename(repo));
    assert.match(v.reason, /hardening\/hooks\/pre-tool-use\.mjs and hardening\/hooks\/agent-scope\.mjs are not in that commit/, path.basename(repo));
  }
});

test('a settings file that cannot be parsed, or a baseRef that is neither value, makes both refs count', async () => {
  // origin/HEAD holds the pack and HEAD does not: the default reads origin/HEAD (no verdict, above), these read both.
  for (const repo of [F.removedBroken, F.removedWeird, F.removedManyValues]) {
    const v = await agent(repo);
    assert.equal(v.decision, 'deny', `${path.basename(repo)}: ${v.reason}`);
    assert.match(v.reason, /cuts from HEAD \(the current commit/, path.basename(repo));
  }
  // HEAD holds the pack and origin/HEAD does not: baseRef "head" alone would pass, the broken project file makes origin/HEAD count.
  const v = await agent(F.featureBroken);
  assert.equal(v.decision, 'deny', v.reason);
  assert.match(v.reason, /origin\/HEAD/);
});

test('ignored and named by .worktreeinclude: the floor ask; a pattern that does not take every file: deny', async () => {
  for (const [key, [text, expected]] of Object.entries(INCLUDE)) {
    const v = await agent(F[key]);
    assert.equal(v.decision, expected, `${key} (${JSON.stringify(text)}): ${v.reason}`);
    if (expected === 'ask') assert.match(v.reason, /git ignores them and \.worktreeinclude names them, so Claude Code's documentation has them copied into new worktrees, but the guard cannot verify the copy/, key);
  }
  const untracked = await agent(F.inclUntracked);
  assert.equal(untracked.decision, 'deny', `not ignored: .worktreeinclude copies ignored files only: ${untracked.reason}`);
});

test('a remote named origin without a cached origin/HEAD: the floor ask, never a pass by HEAD alone; baseRef "head" is judged by HEAD', async () => {
  const v = await agent(F.uncached);
  assert.equal(v.decision, 'ask', v.reason);
  assert.match(v.reason, /no cached refs\/remotes\/origin\/HEAD, so the guard cannot know which commit that is/);
  assert.match(v.reason, /git remote set-head origin -a/);
  const head = await agent(F.uncachedHead);
  assert.equal(head.raw, '', `baseRef "head" and the pack on HEAD: ${head.reason}`);
  assert.doesNotMatch(await banner(F.uncached), /Subagents with worktree isolation/, 'the banner names a missing file only');
});

test('a WorktreeCreate hook in the settings: the floor ask', async () => {
  const v = await agent(F.createHook);
  assert.equal(v.decision, 'ask', v.reason);
  assert.match(v.reason, /WorktreeCreate hook in the settings creates its worktree instead of git/);
});

test('a custom subagent with isolation: worktree in its frontmatter is judged like the argument', async () => {
  for (const type of ['iso-agent', 'quoted-agent']) {
    const v = await agent(F.untrackedAgents, { ...AGENT_INPUT, subagent_type: type });
    assert.equal(v.decision, 'deny', `${type}: ${v.reason}`);
    assert.match(v.reason, DENY_REASON);
    assert.equal((await agent(F.committedAgents, { ...AGENT_INPUT, subagent_type: type })).decision, null, `${type}: the pack is committed`);
  }
  const plain = await agent(F.untrackedAgents, { ...AGENT_INPUT, subagent_type: 'plain-agent' });
  assert.equal(plain.raw, '', 'a custom subagent without isolation: no output at all');
});

test('an Agent call without worktree isolation gets no output at all, in every fixture', async () => {
  const repos = [...new Set(Object.values(F))];
  for (const repo of repos) {
    for (const input of [AGENT_INPUT, { ...AGENT_INPUT, isolation: 'none' }, { description: 'x', prompt: 'y' }]) {
      const v = await agent(repo, input);
      assert.equal(v.raw, '', `${path.basename(repo)} ${JSON.stringify(input)}: ${v.raw}`);
    }
  }
});

test('a git that cannot answer is the floor ask, never a pass', async () => {
  const corrupt = await agent(F.badHead);
  assert.equal(corrupt.decision, 'ask', corrupt.reason);
  assert.match(corrupt.reason, /could not check whether .* holds hardening\/hooks\/pre-tool-use\.mjs and hardening\/hooks\/agent-scope\.mjs: git gave no answer/);
  for (const repo of [F.committed, F.untracked]) {
    const v = await agent(repo, undefined, { env: noGitEnv() });
    assert.equal(v.decision, 'ask', `${path.basename(repo)} without git on PATH: ${v.reason}`);
    assert.match(v.reason, /git gave no answer/);
  }
});

test('no git repository: no verdict', async () => {
  const v = await agent(F.noGit);
  assert.equal(v.raw, '', v.reason);
});

test('a GitHub Copilot payload: no verdict', async () => {
  const v = await agent(F.untracked, { ...AGENT_INPUT, isolation: 'worktree' }, { extra: { timestamp: Date.now() } });
  assert.notEqual(v.decision, 'deny', v.reason);
  assert.notEqual(v.decision, 'ask', v.reason);
});

test('lab mode: the deny stays a deny, the floor ask stays an ask', async () => {
  const denied = await agent(F.untrackedLab);
  assert.equal(denied.decision, 'deny', denied.reason);
  const floor = await agent(F.badHeadLab);
  assert.equal(floor.decision, 'ask', floor.reason);
  assert.doesNotMatch(floor.reason, /lab mode/);
});

test('the banner names a guard file missing from the commit worktrees are cut from, and only then', async () => {
  const LINE = /- Subagents with worktree isolation: hardening\/hooks\/pre-tool-use\.mjs and hardening\/hooks\/agent-scope\.mjs are not in .*the commit Claude Code cuts their worktrees from\. .*the guard denies starting one/;
  for (const repo of [F.untracked, F.feature, F.removedHead]) assert.match(await banner(repo), LINE, path.basename(repo));
  for (const repo of [F.committed, F.noRemote, F.removed, F.featureHead, F.badHead, F.inclFolder, F.createHook]) {
    assert.doesNotMatch(await banner(repo), /Subagents with worktree isolation/, path.basename(repo));
  }
  assert.doesNotMatch(await banner(F.untracked, { timestamp: Date.now() }), /Subagents with worktree isolation/, 'not under GitHub Copilot');
});

test('registration: a PreToolUse group with matcher Agent runs the guard; the shell group stays first', () => {
  const settings = JSON.parse(fs.readFileSync(path.join(pack, 'settings.hooks.json'), 'utf8'));
  const groups = settings.hooks.PreToolUse.filter((g) => g.matcher === 'Agent');
  assert.equal(groups.length, 1);
  assert.deepEqual(groups[0].hooks, [{ type: 'command', command: 'node hardening/hooks/pre-tool-use.mjs', timeout: 20 }]);
  assert.equal(settings.hooks.PreToolUse[0].matcher, 'Bash|PowerShell|Monitor');
  for (const file of ['vscode.hooks.json', 'copilot-cli.hooks.json']) {
    assert.doesNotMatch(fs.readFileSync(path.join(pack, file), 'utf8'), /"Agent"/, `${file} is unchanged`);
  }
});

const installer = path.join(pack, 'scripts', 'install-into.mjs');
const harnessClone = fs.existsSync(path.join(pack, '..', 'LICENSE'));
test('the installer merges the Agent group, on a fresh install and on an update of a registration without it', (t) => {
  if (!harnessClone) return t.skip('runs only in a clone of the harness (LICENSE at the root)');
  const shipped = JSON.parse(fs.readFileSync(path.join(pack, 'settings.hooks.json'), 'utf8'));
  const agentGroups = (dir) => JSON.parse(fs.readFileSync(path.join(dir, '.claude', 'settings.local.json'), 'utf8')).hooks.PreToolUse
    .filter((g) => g.matcher === 'Agent' && g.hooks.some((h) => h.command === 'node hardening/hooks/pre-tool-use.mjs'));
  const fresh = tempDir('install');
  git(fresh, 'init', '-q');
  const first = spawnSync(process.execPath, [installer, fresh, '--hardening', '--enable-hooks'], { encoding: 'utf8', env: baseEnv });
  assert.equal(first.status, 0, first.stderr);
  assert.equal(agentGroups(fresh).length, 1, 'a fresh install registers the Agent group once');
  // The installed guard imports the new module: it ships, and the installed hook answers a plain Agent call with nothing.
  assert.ok(fs.existsSync(path.join(fresh, 'hardening', 'hooks', 'lib', 'isolated-subagent.mjs')), 'the module ships');
  const installed = spawnSync(process.execPath, [path.join(fresh, 'hardening', 'hooks', 'pre-tool-use.mjs')], {
    cwd: fresh, env: { ...baseEnv, CLAUDE_PROJECT_DIR: fresh }, encoding: 'utf8', windowsHide: true,
    input: JSON.stringify({ session_id: 'iso-installed', cwd: fresh, permission_mode: 'default', hook_event_name: 'PreToolUse', tool_name: 'Agent', tool_input: AGENT_INPUT }),
  });
  assert.equal(installed.status, 0, installed.stderr);
  assert.equal(installed.stdout, '', 'the installed guard loads and gives a plain Agent call no output');
  // A registration from before: the shipped one without the Agent group.
  const older = structuredClone(shipped);
  older.hooks.PreToolUse = older.hooks.PreToolUse.filter((g) => g.matcher !== 'Agent');
  fs.writeFileSync(path.join(fresh, '.claude', 'settings.local.json'), `${JSON.stringify(older, null, 2)}\n`);
  const update = spawnSync(process.execPath, [installer, fresh, '--update', '--enable-hooks'], { encoding: 'utf8', env: baseEnv });
  assert.equal(update.status, 0, update.stderr);
  assert.equal(agentGroups(fresh).length, 1, 'an update adds the Agent group once');
});
