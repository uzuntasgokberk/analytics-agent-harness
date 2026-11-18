// Worktree sessions (2026-11-17): a Claude Code session or subagent whose hook payload `cwd` lies in a verified linked worktree
// <CLAUDE_PROJECT_DIR>/.claude/worktrees/<name> is judged with that worktree as its project for path rules, while the
// configuration, the logs and the session state stay with the main checkout. Nothing outside the worktree gets a more permissive
// verdict, and a folder under .claude/worktrees/ that is not a verified worktree keeps the behaviour it had.
// Every judgement runs a hook as a process, in the two shapes measured live (Claude desktop app 5.11492.5, Agent SDK 0.3.325,
// Windows 11, 2026-11-17), with CLAUDE_PROJECT_DIR the main checkout and the payload's `cwd` the worktree in both:
//   main: the main session; the repository's copy of the hook script, process folder = the repository root, no agent_id.
//   sub:  a subagent with worktree isolation; the worktree's own copy of the script, process folder = the worktree, agent_id and
//         agent_type set (strandedCd makes no claim for a subagent).
// The fixture copies this pack's hooks/ and scripts/ into the repository (committed, so each worktree holds its own copy) and into
// the plain project it is compared with. The hooks run with an empty home and without the machine's git configuration.
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
  const dir = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), `bi-harness-wts-${name}-`)));
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

// ---------------------------------------------------------------- environment and fixture

const emptyHome = tempDir('home');
const top = tempDir('fx');
// No host variable, no Claude Code variable (CLAUDE_PROJECT_DIR and CLAUDE_BASH_MAINTAIN_PROJECT_WORKING_DIR are set per call),
// no git variable of the machine.
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

// The files of over-denials-2026-11-17.test.mjs part 4, a harness config, and the pack's own hooks and scripts.
const FILES = { 'docs/a.md': '# a\n', 'docs/b.txt': 'b\n', 'notes.txt': 'n\n', 'hardening/hooks/x.mjs': '// x\n', '.claude/settings.json': '{}\n',
  'templates/t.md': '# t\n', '.githooks/pre-commit': '#!/bin/sh\n', 'sql/q.sql': 'select 1\n', 'hardening/harness.config.json': '{ "approvals": { "mode": "auto" } }\n',
  'docs/locked-home.md': '# l\n', 'docs/locked-wt.md': '# l\n' };
// Untracked in every checkout (git ignores them through the shared info/exclude): a secret, the local settings and the links.
const EXCLUDE = ['.env', '.claude/settings.local.json', '.claude/worktrees/', '.claude/logs/', 'link', 'hlink', 'dlink'];
const withPack = (root) => {
  fs.cpSync(path.join(pack, 'hooks'), path.join(root, 'hardening', 'hooks'), { recursive: true });
  fs.cpSync(path.join(pack, 'scripts'), path.join(root, 'hardening', 'scripts'), { recursive: true });
  write(root, FILES);
};
const links = (root) => {
  fs.symlinkSync(path.join(repo, '.claude'), path.join(root, 'link'), 'junction');
  fs.symlinkSync(path.join(repo, 'hardening'), path.join(root, 'hlink'), 'junction');
  fs.symlinkSync(path.join(repo, 'docs'), path.join(root, 'dlink'), 'junction');
};

const repo = path.join(top, 'repo');
const WT_BASE = path.join(repo, '.claude', 'worktrees');
const wt = path.join(WT_BASE, 'wt');
const wt2 = path.join(WT_BASE, 'wt2');
const plain = path.join(top, 'plain', 'proj');
const elsewhere = path.join(top, 'elsewhere');

fs.mkdirSync(repo, { recursive: true });
git(repo, 'init', '-q');
withPack(repo);
fs.appendFileSync(path.join(repo, '.git', 'info', 'exclude'), `\n${EXCLUDE.join('\n')}\n`);
git(repo, 'add', '-A');
git(repo, 'commit', '-q', '-m', 'fixture');
// The registered worktrees: the one under test, a sibling, one two segments deep and one outside .claude/worktrees/.
git(repo, 'worktree', 'add', '-q', '-b', 'wt-branch', wt);
git(repo, 'worktree', 'add', '-q', '-b', 'wt2-branch', wt2);
git(repo, 'worktree', 'add', '-q', '-b', 'deep-branch', path.join(WT_BASE, 'group', 'deep'));
git(repo, 'worktree', 'add', '-q', '-b', 'elsewhere-branch', elsewhere);
for (const root of [repo, wt, wt2]) write(root, { '.env': 'X=1\n' });
write(repo, { '.claude/settings.local.json': JSON.stringify({ permissions: { deny: ['Edit(/docs/locked-home.md)'] } }) });
write(wt, { '.claude/settings.local.json': JSON.stringify({ permissions: { deny: ['Edit(/docs/locked-wt.md)'] } }) });
links(wt);
// The worktree's folder spelled through a link outside the repository: verified by its canonical path, no .claude/ in the spelling.
const wtLink = path.join(top, 'wtj');
fs.symlinkSync(wt, wtLink, 'junction');

// Folders under .claude/worktrees/ that are no verified worktree. `fake` mirrors the worktree (files and links): the twin whose
// verdicts are those every folder there got before.
const fake = path.join(WT_BASE, 'fake');
write(fake, { ...FILES, '.env': 'X=1\n', '.claude/settings.local.json': '{}\n' });
links(fake);
const forged = path.join(WT_BASE, 'forged');
write(forged, { ...FILES, '.git': `gitdir: ${posix(path.join(repo, '.git', 'worktrees', 'wt'))}\n` });
const outsider = path.join(WT_BASE, 'outsider');
const admin = path.join(top, 'admin', 'outsider');
write(outsider, { ...FILES, '.git': `gitdir: ${posix(admin)}\n` });
write(admin, { gitdir: `${posix(path.join(outsider, '.git'))}\n`, HEAD: 'ref: refs/heads/main\n', commondir: `${posix(path.join(repo, '.git'))}\n` });
const clone = path.join(WT_BASE, 'clone');
fs.mkdirSync(clone, { recursive: true });
git(clone, 'init', '-q');
write(clone, FILES);
const jx = path.join(WT_BASE, 'jx');
fs.symlinkSync(elsewhere, jx, 'junction');
const deep = path.join(WT_BASE, 'group', 'deep');
const UNVERIFIED = { fake, forged, outsider, clone, jx, deep };

// The plain project: the same files and pack, its own repository, on a feature branch like the worktree.
fs.mkdirSync(plain, { recursive: true });
git(plain, 'init', '-q');
withPack(plain);
fs.appendFileSync(path.join(plain, '.git', 'info', 'exclude'), `\n${EXCLUDE.join('\n')}\n`);
git(plain, 'add', '-A');
git(plain, 'commit', '-q', '-m', 'fixture');
git(plain, 'checkout', '-q', '-b', 'feature');
write(plain, { '.env': 'X=1\n', '.claude/settings.local.json': '{}\n' });

/** The 8.3 short spelling of a folder where Windows gives one, else null. */
function shortName(p) {
  if (process.platform !== 'win32') return null;
  const r = spawnSync('cmd.exe', ['/d', '/s', '/c', `"for %I in ("${p}") do @echo %~sI"`], { encoding: 'utf8', windowsVerbatimArguments: true, windowsHide: true });
  const s = String(r.stdout ?? '').trim();
  return s && s.toLowerCase() !== p.toLowerCase() && fs.existsSync(s) ? s : null;
}
const repoShort = shortName(repo);
/** The repository's path in another letter case (Windows and macOS open it as the same folder). */
const repoCase = repo.replace(/[a-z]/gi, (c) => (c === c.toLowerCase() ? c.toUpperCase() : c.toLowerCase()));

// ---------------------------------------------------------------- running the hooks

const SUB = { agent_id: 'a5f0c1d2e3b4', agent_type: 'general-purpose' };
/** A session: CLAUDE_PROJECT_DIR, the payload's cwd, the checkout whose hook scripts run, the process folder, the agent fields. */
const session = (project, cwd, hooks, proc, agent = {}) => ({ project, cwd, hooks, proc, agent });
const S = {
  plainMain: session(plain, plain, plain, plain),
  plainSub: session(plain, plain, plain, plain, SUB),
  wtMain: session(repo, wt, repo, repo),
  wtSub: session(repo, wt, wt, wt, SUB),
  wtLink: session(repo, wtLink, repo, repo),
  wtDocs: session(repo, path.join(wt, 'docs'), repo, repo),
  home: session(repo, repo, repo, repo),
};
const unverified = (folder) => session(repo, folder, repo, repo);

function spawnHook(script, { proc, project, payload, env }) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [script], { cwd: proc, env: { ...baseEnv, CLAUDE_PROJECT_DIR: project, ...env }, windowsHide: true });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (c) => { stdout += c; });
    child.stderr.on('data', (c) => { stderr += c; });
    child.on('error', (err) => resolve({ status: null, stdout, stderr: String(err.message) }));
    child.on('close', (status) => resolve({ status, stdout, stderr }));
    child.stdin.end(JSON.stringify(payload));
  });
}
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
let calls = 0;
/**
 * One hook run in session `s`: its parsed output (null when it printed none), exit status and stderr. `maintain` sets
 * CLAUDE_BASH_MAINTAIN_PROJECT_WORKING_DIR as the default install does; `sessionId` names the session (8 characters reach the logs).
 */
async function run(s, hook, payload, { env = {}, maintain = true, sessionId } = {}) {
  const r = await spawnHook(path.join(s.hooks, 'hardening', 'hooks', hook), {
    proc: s.proc, project: s.project,
    payload: { session_id: sessionId ?? `wts${String(++calls).padStart(5, '0')}`, cwd: s.cwd, permission_mode: 'default', ...s.agent, ...payload },
    env: { ...(maintain ? { CLAUDE_BASH_MAINTAIN_PROJECT_WORKING_DIR: '1' } : {}), ...env },
  });
  return { status: r.status, stderr: r.stderr, out: r.stdout.trim() ? JSON.parse(r.stdout) : null };
}
/** The PreToolUse guard's decision and reason for one call in session `s`. */
async function pre(s, tool_name, tool_input, options) {
  const r = await run(s, 'pre-tool-use.mjs', { hook_event_name: 'PreToolUse', tool_name, tool_input }, options);
  assert.equal(r.status, 0, r.stderr); // a guard that did not run prints no verdict, which would read as a pass
  const out = r.out?.hookSpecificOutput;
  return { decision: out?.permissionDecision ?? null, reason: out?.permissionDecisionReason ?? '' };
}
/** A reason with the project's absolute path written as {ROOT}, in either slash. */
const normal = (reason, root) => [root, posix(root)].reduce((t, r) => t.split(r).join('{ROOT}'), String(reason));
const fill = (cmd, root) => cmd.replaceAll('{ROOT}', posix(root)).replaceAll('{REPO}', posix(repo));
const RANK = { deny: 3, ask: 2, null: 1, allow: 0 };
const rank = (v) => RANK[v.decision ?? 'null'];
const shellTool = (cmd) => (cmd.startsWith('PS> ') ? ['PowerShell', cmd.slice(4)] : ['Bash', cmd]);
const GUARD_REASON = /Harness guardrail files/;
const logRows = (root, file = 'security-events.jsonl') => {
  try {
    return fs.readFileSync(path.join(root, '.claude', 'logs', file), 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
  } catch {
    return [];
  }
};

// ---------------------------------------------------------------- 1: the worktree's own files get the plain project's verdicts

const IN_PROJECT = [
  // over-denials-2026-11-17.test.mjs part 4, IN_PROJECT.
  'touch notes.txt', 'echo hi > notes.txt', 'rm docs/b.txt', 'Set-Content notes.txt hi', 'mv docs/b.txt docs/c.txt', 'sed -i s/a/b/ notes.txt',
  'New-Item -ItemType File out.txt', 'git checkout -- notes.txt', 'git restore notes.txt', 'git rm docs/b.txt', 'touch docs/../notes.txt', 'echo x > $f', 'rm $f',
  'touch {ROOT}/notes.txt', 'rm {ROOT}/docs/b.txt', 'rm -r {ROOT}/docs', 'Remove-Item {ROOT}/docs/b.txt', 'mv {ROOT}/docs/b.txt {ROOT}/docs/c.txt',
  'cp {ROOT}/docs/b.txt {ROOT}/docs/c.txt', 'git rm {ROOT}/docs/b.txt', '(cd {ROOT}/docs && touch x.txt)', 'ls {ROOT}/docs | xargs rm',
  "[IO.File]::WriteAllText('notes.txt','x')", `node -e "require('fs').writeFileSync('notes.txt','x')"`, "'notes.txt' | Remove-Item",
  'cat docs/a.md', 'ls', 'git status', 'mkdir out', 'echo x > {ROOT}/notes.txt', 'cd {ROOT}/docs && ls', 'find {ROOT}/docs -name x -delete', 'cp docs/a.md docs/c.md',
  'cd docs && touch x.md', 'cat .env', 'cat {ROOT}/.env', 'echo x > hardening/hooks/x.mjs', 'echo x > .claude/settings.json', 'echo x > .claude/settings.local.json',
  'echo x > .githooks/pre-commit', 'echo x > templates/t.md', 'rm -r templates', 'rm -r .claude', 'cd .claude && touch x', '(cd hardening && echo x > y.mjs)',
  'echo x > {ROOT}/.claude/settings.json', 'echo x > {ROOT}/hardening/hooks/x.mjs', 'rm -r {ROOT}/.claude', 'rm -r {ROOT}/hardening', 'rm -r {ROOT}/templates',
  'cd {ROOT}/.claude && touch x',
  // PowerShell.
  'PS> Set-Content notes.txt hi', 'PS> Remove-Item docs/b.txt', 'PS> New-Item -ItemType File out.txt', 'PS> Add-Content docs/a.md x', 'PS> Copy-Item docs/a.md docs/c.md',
  'PS> Move-Item docs/b.txt docs/c.txt', 'PS> Get-Content .env', 'PS> Get-ChildItem docs', 'PS> Set-Content .claude/settings.json x',
  'PS> Set-Content .claude/settings.local.json x', 'PS> Remove-Item -Recurse templates', "PS> 'x' | Out-File {ROOT}/notes.txt", 'PS> Set-Content {ROOT}/hardening/hooks/x.mjs x',
  'PS> Push-Location docs; try { New-Item x.md } finally { Pop-Location }', "PS> [IO.File]::WriteAllText('.claude/settings.local.json','x')",
];
const FILE_ROWS = [
  ['Edit', (r) => ({ file_path: path.join(r, 'docs', 'a.md'), old_string: '# a', new_string: '# b' })],
  ['Write', (r) => ({ file_path: path.join(r, 'docs', 'new.md'), content: '# new\n' })],
  ['Write', (r) => ({ file_path: path.join(r, 'notes.txt'), content: 'x\n' })],
  ['Write', (r) => ({ file_path: path.join(r, 'sql', 'q.sql'), content: 'select 2\n' })],
  ['Write', (r) => ({ file_path: path.join(r, 'hardening', 'hooks', 'x.mjs'), content: '// y\n' })],
  ['Edit', (r) => ({ file_path: path.join(r, '.claude', 'settings.json'), old_string: '{}', new_string: '{ }' })],
  ['Write', (r) => ({ file_path: path.join(r, '.claude', 'settings.local.json'), content: '{}\n' })],
  ['Write', (r) => ({ file_path: path.join(r, 'templates', 't.md'), content: '# u\n' })],
  ['Write', (r) => ({ file_path: path.join(r, '.githooks', 'pre-commit'), content: '#!/bin/sh\n' })],
  ['Write', (r) => ({ file_path: path.join(r, '.env'), content: 'X=2\n' })],
  ['Write', (r) => ({ file_path: path.join(r, '.claude', 'logs', 'x.jsonl'), content: '{}\n' })],
  ['Write', (r) => ({ file_path: path.join(r, 'hardening', 'harness.config.json'), content: '{ "approvals": { "mode": "lab" } }\n' })],
  ['Read', (r) => ({ file_path: path.join(r, '.env') })],
  ['Read', (r) => ({ file_path: path.join(r, 'docs', 'a.md') })],
  ['Read', (r) => ({ file_path: path.join(r, '.claude', 'settings.local.json') })],
  ['Grep', (r) => ({ pattern: 'a', path: path.join(r, 'docs') })],
  ['Grep', (r) => ({ pattern: 'a', path: r, glob: '*.pem' })],
  ['Grep', (r) => ({ pattern: 'X', path: path.join(r, '.env') })],
  ['Glob', (r) => ({ pattern: '**/*.md', path: r })],
  ['Glob', (r) => ({ pattern: '*', path: path.join(r, 'templates') })],
];
/** Each row in a session, normalised: `row` is a shell command (PS> for PowerShell) or a FILE_ROWS entry. */
async function judgeRows(s, root, rows) {
  return mapLimit(rows, 8, async (row) => {
    const v = typeof row === 'string' ? await pre(s, ...(([tool, cmd]) => [tool, { command: fill(cmd, root) }])(shellTool(row))) : await pre(s, row[0], row[1](root));
    return { decision: v.decision, reason: normal(v.reason, root) };
  });
}
const label = (row) => (typeof row === 'string' ? row : `${row[0]} ${posix(path.relative('R', row[1]('R').file_path ?? row[1]('R').path ?? ''))}`);

test('1: in a worktree session every call on the worktree\'s own files gets the plain project\'s verdict and reason, in both measured shapes', async () => {
  const rows = [...IN_PROJECT, ...FILE_ROWS];
  const [plainMain, plainSub, wtMain, wtSub] = await Promise.all([
    judgeRows(S.plainMain, plain, rows), judgeRows(S.plainSub, plain, rows), judgeRows(S.wtMain, wt, rows), judgeRows(S.wtSub, wt, rows),
  ]);
  const differs = rows.map((row, i) => ({ row: label(row), plain: plainMain[i], main: wtMain[i], sub: wtSub[i], plainSub: plainSub[i] }))
    .filter((d) => JSON.stringify(d.main) !== JSON.stringify(d.plain) || JSON.stringify(d.sub) !== JSON.stringify(d.plainSub) || JSON.stringify(d.main) !== JSON.stringify(d.sub));
  assert.deepEqual(differs, []);
  // The rows the task names, and the worktree's own guardrail, reference and secret paths (settings.local.json among them).
  const at = (row) => wtMain[rows.indexOf(row)];
  for (const cmd of ['touch notes.txt', 'echo hi > notes.txt', 'rm docs/b.txt', 'Set-Content notes.txt hi']) assert.notEqual(at(cmd).decision, 'deny', cmd);
  for (const cmd of ['echo x > hardening/hooks/x.mjs', 'echo x > .claude/settings.json', 'echo x > .claude/settings.local.json', 'echo x > .githooks/pre-commit',
    'echo x > templates/t.md', 'rm -r templates', 'cat .env', 'PS> Set-Content .claude/settings.local.json x']) {
    assert.equal(at(cmd).decision, 'deny', cmd);
  }
  assert.equal(at(FILE_ROWS[0]).decision, 'allow', 'Edit of docs/a.md is routine');
  assert.equal(at(FILE_ROWS[6]).decision, 'ask', 'Write of .claude/settings.local.json asks');
  assert.equal(at(FILE_ROWS[12]).decision, 'deny', 'Read of .env is denied');
});

// ---------------------------------------------------------------- 2: what leaves the worktree stays denied

const OUTSIDE = [
  // over-denials-2026-11-17.test.mjs part 4, the "outside" list: the parent repository's guardrail files, relative and absolute.
  'echo x > ../../settings.json', 'echo x > ../../settings.local.json', 'echo x > ../../../hardening/hooks/pre-tool-use.mjs', 'rm -r ../../../.git',
  'echo x > ../../../.githooks/pre-commit', 'echo x > {REPO}/.claude/settings.json', 'echo x > {REPO}/.claude/settings.local.json',
  'echo x > {REPO}/hardening/hooks/pre-tool-use.mjs', 'rm -r {REPO}/.git', 'echo x > {REPO}/.githooks/pre-commit', 'rm ../../settings.json',
  'Set-Content ../../settings.json x', 'cp docs/b.txt ../../settings.json', '(cd ../.. && echo x > settings.json)', '(cd ../.. && rm settings.local.json)',
  'ls ../.. | xargs rm', 'ln -s ../.. lnk',
  "[IO.File]::WriteAllText('../../settings.json','x')", `node -e "require('fs').writeFileSync('../../settings.json','x')"`,
  `python -c "open('../../settings.json','w').write('x')"`, "'../../settings.json' | Remove-Item", "[IO.File]::WriteAllText('link/settings.json','x')",
  `node -e "require('fs').writeFileSync('link/settings.json','x')"`, "'link/settings.json' | Remove-Item",
  'echo x > ../wt2/hardening/hooks/x.mjs', 'echo x > ../wt2/.claude/settings.json', 'echo x > {REPO}/.claude/worktrees/wt2/hardening/hooks/x.mjs',
  'echo x > {REPO}/.claude/worktrees/wt2/.claude/settings.json',
  'echo x > ../../../notes.txt', 'echo x > ../wt2/notes.txt', 'touch ../../../notes.txt', 'echo x > ~/notes.txt',
  'echo x > link/settings.json', 'echo x > link/settings.local.json', 'echo x > {ROOT}/link/settings.json', 'echo x > hlink/hooks/pre-tool-use.mjs',
  'echo x > link/worktrees/wt2/notes.txt',
  // Ordinary files of the main checkout through a link, by an absolute spelling, and after a cd out of the worktree.
  'echo x > dlink/a.md', 'touch {ROOT}/dlink/new.md', 'touch {REPO}/docs/new.md', '(cd ../../.. && echo x > notes.txt)',
  'cd ../../.. && touch notes.txt', 'echo x > ../../../docs/a.md',
  // The worktree's own .git file and the main repository's administrative folder of the worktree.
  'echo x > .git', 'rm .git', 'echo x > ../../../.git/worktrees/wt/gitdir', 'rm -r {REPO}/.git/worktrees',
  // The parent's guardrail files in other letter case.
  'echo x > {REPO_CASE}/.claude/settings.json', 'echo x > {REPO_CASE}/hardening/hooks/pre-tool-use.mjs',
  // PowerShell.
  'PS> Set-Content ../../settings.json x', 'PS> Set-Content {REPO}/.claude/settings.local.json x', 'PS> Set-Content ../../../notes.txt x',
  "PS> [IO.File]::WriteAllText('{REPO}/notes.txt','x')", 'PS> Set-Location ../../..; Set-Content notes.txt x', 'PS> Set-Content .git x',
];
// A redirect to an absolute path is judged by its name in any project, so from the worktree's folder these had no verdict before
// (measured on 2f07e2b): an ordinary file of the main checkout or a sibling, and the worktree's administrative folder. In a
// worktree session a redirect into the main checkout leaves the project and is denied; one outside the repository is judged as before.
const OUTSIDE_ABSOLUTE = ['echo x > {REPO}/notes.txt', 'echo x > {REPO}/docs/a.md', 'echo x > {REPO}/.git/worktrees/wt/gitdir',
  'echo x > {REPO}/.claude/worktrees/wt2/notes.txt', 'PS> Set-Content -Path {REPO}/notes.txt -Value x',
  // Another letter case names the main checkout only where the file system ignores case (Windows, macOS; not the Ubuntu CI job).
  ...(fs.existsSync(repoCase) ? ['echo x > {REPO_CASE}/notes.txt'] : [])];
const OUTSIDE_REPOSITORY = ['echo x > {TOP}/outside.txt'];
// Git commands that act on the main checkout or a sibling: never more permissive than in the unverified twin.
const GIT_OUTSIDE = ['git -C ../../.. checkout -- notes.txt', 'git -C {REPO} rm notes.txt', 'git -C ../wt2 checkout -- notes.txt', 'git worktree remove ../wt2',
  'git worktree remove --force {REPO}/.claude/worktrees/wt2', 'git worktree prune', 'git --git-dir=../../../.git --work-tree=../../.. checkout -- notes.txt',
  'git -C ../../.. reset --hard', 'git -C ../wt2 clean -fdx'];
const fillOutside = (cmd, root) => fill(cmd, root).replaceAll('{REPO_CASE}', posix(repoCase)).replaceAll('{REPO_SHORT}', posix(repoShort ?? '')).replaceAll('{TOP}', posix(top));
const outsideRows = () => [...OUTSIDE, ...(repoShort ? ['echo x > {REPO_SHORT}/.claude/settings.json', 'echo x > {REPO_SHORT}/hardening/hooks/pre-tool-use.mjs'] : [])];
async function judgeShell(s, root, cmds, options) {
  return mapLimit(cmds, 8, async (cmd) => {
    const [tool, text] = shellTool(cmd);
    return pre(s, tool, { command: fillOutside(text, root) }, options);
  });
}

test('2: from a worktree session the main checkout, a sibling, links out, .git and the administrative folder stay denied, in both shapes', async () => {
  const rows = outsideRows();
  const [main, sub, twin] = await Promise.all([judgeShell(S.wtMain, wt, rows), judgeShell(S.wtSub, wt, rows), judgeShell(unverified(fake), fake, rows)]);
  const notDenied = rows.map((cmd, i) => ({ cmd, main: main[i].decision, sub: sub[i].decision })).filter((r) => r.main !== 'deny' || r.sub !== 'deny');
  assert.deepEqual(notDenied, []);
  // The unverified twin denies every one of them too (the verdict these calls had before).
  assert.deepEqual(rows.filter((cmd, i) => twin[i].decision !== 'deny'), []);
  // The worktree's .git file by Edit or Write: asked like a file under .git/ (no plain project has a .git file to compare).
  for (const s of [S.wtMain, S.wtSub]) {
    assert.equal((await pre(s, 'Write', { file_path: path.join(wt, '.git'), content: 'gitdir: ../../../.git\n' })).decision, 'ask');
    assert.equal((await pre(s, 'Edit', { file_path: path.join(wt, '.git'), old_string: 'gitdir', new_string: 'gitdir' })).decision, 'ask');
  }
});

test('2: a redirect by an absolute spelling into the main checkout is denied from a worktree session; one outside the repository keeps its verdict', async () => {
  const rows = [...OUTSIDE_ABSOLUTE, ...(repoShort ? ['echo x > {REPO_SHORT}/notes.txt'] : [])];
  const [main, sub] = await Promise.all([judgeShell(S.wtMain, wt, rows), judgeShell(S.wtSub, wt, rows)]);
  assert.deepEqual(rows.map((cmd, i) => ({ cmd, main: main[i].decision, sub: sub[i].decision })).filter((r) => r.main !== 'deny' || r.sub !== 'deny'), []);
  const [outMain, outPlain] = await Promise.all([judgeShell(S.wtMain, wt, OUTSIDE_REPOSITORY), judgeShell(S.plainMain, plain, OUTSIDE_REPOSITORY)]);
  assert.deepEqual(outMain, outPlain);
});

test('2: a worktree session whose folder is spelled through a link, or is a subfolder, keeps the denies and the plain verdicts', async () => {
  const leaving = ['touch {REPO}/docs/new.md', 'cp docs/b.txt {REPO}/notes.txt', 'echo x > {REPO}/notes.txt', 'echo x > {REPO}/.claude/settings.json',
    'PS> Set-Content {REPO}/notes.txt x', 'echo x > .git'];
  const fromDocs = ['touch {REPO}/docs/new.md', 'cp b.txt {REPO}/notes.txt', 'echo x > {REPO}/notes.txt', 'echo x > ../../../../notes.txt',
    'echo x > ../../../settings.json', 'echo x > ../.git'];
  const [viaLink, inDocs] = await Promise.all([judgeShell(S.wtLink, wt, leaving), judgeShell(S.wtDocs, wt, fromDocs)]);
  assert.deepEqual([...leaving.map((cmd, i) => ({ cmd, v: viaLink[i].decision })), ...fromDocs.map((cmd, i) => ({ cmd: `docs: ${cmd}`, v: inDocs[i].decision }))]
    .filter((r) => r.v !== 'deny'), []);
  const plainRows = ['touch notes.txt', 'rm docs/b.txt', 'PS> Set-Content notes.txt hi'];
  const [link, plainRun] = await Promise.all([judgeShell(S.wtLink, wt, plainRows), judgeShell(S.plainMain, plain, plainRows)]);
  assert.deepEqual(link, plainRun);
  const [docs, plainDocs] = await Promise.all([judgeShell(S.wtDocs, wt, ['touch b.txt']), judgeShell(session(plain, path.join(plain, 'docs'), plain, plain), plain, ['touch b.txt'])]);
  assert.deepEqual(docs, plainDocs);
  const id = 'lnkrow01';
  await pre(S.wtLink, 'Bash', { command: 'echo x > .claude/settings.json' }, { sessionId: id });
  assert.equal(logRows(repo).find((r) => r.session === id)?.worktree, 'wt');
});

test('2: git commands on the main checkout or a sibling are never more permissive than in the unverified twin', async () => {
  const [main, sub, twin] = await Promise.all([judgeShell(S.wtMain, wt, GIT_OUTSIDE), judgeShell(S.wtSub, wt, GIT_OUTSIDE), judgeShell(unverified(fake), fake, GIT_OUTSIDE)]);
  const weaker = GIT_OUTSIDE.map((cmd, i) => ({ cmd, main: main[i].decision, sub: sub[i].decision, twin: twin[i].decision }))
    .filter((r) => RANK[r.main ?? 'null'] < RANK[r.twin ?? 'null'] || RANK[r.sub ?? 'null'] < RANK[r.twin ?? 'null'] || r.main === 'allow' || r.sub === 'allow');
  assert.deepEqual(weaker, []);
});

// ---------------------------------------------------------------- 3: an unverified folder keeps the behaviour it had

test('3: a folder under .claude/worktrees/ that is no verified worktree is judged as before (unregistered, forged, outside admin folder, clone, junction, two deep)', async () => {
  for (const [name, folder] of Object.entries(UNVERIFIED)) {
    const s = unverified(folder);
    const write = await pre(s, 'Bash', { command: 'echo hi > notes.txt' });
    assert.equal(write.decision, 'deny', `${name}: echo hi > notes.txt`);
    assert.match(write.reason, GUARD_REASON, `${name}: echo hi > notes.txt`);
    const ps = await pre(s, 'PowerShell', { command: 'Set-Content notes.txt hi' });
    assert.equal(ps.decision, 'deny', `${name}: Set-Content notes.txt hi`);
    // The main session without CLAUDE_BASH_MAINTAIN_PROJECT_WORKING_DIR: the folder reads as a subfolder of the project.
    const ls = await pre(s, 'Bash', { command: 'ls' }, { maintain: false });
    assert.equal(ls.decision, 'deny', `${name}: ls`);
    assert.match(ls.reason, new RegExp(`leaves the shell in \\.claude/worktrees/${path.basename(folder) === 'deep' ? 'group/deep' : path.basename(folder)}`), `${name}: ls`);
    // File tools: the verdict of the same call from the repository root, which never depended on the shell's folder.
    for (const [tool, input] of [['Edit', { file_path: path.join(folder, 'docs', 'a.md'), old_string: '# a', new_string: '# b' }],
      ['Write', { file_path: path.join(folder, 'notes.txt'), content: 'x\n' }], ['Read', { file_path: path.join(folder, 'docs', 'a.md') }]]) {
      assert.deepEqual(await pre(s, tool, input), await pre(S.home, tool, input), `${name}: ${tool}`);
    }
    assert.equal((await pre(s, 'Edit', { file_path: path.join(folder, 'docs', 'a.md'), old_string: '# a', new_string: '# b' })).decision, 'ask', `${name}: Edit`);
    // Its log rows carry no worktree.
    const id = `uv${name.slice(0, 6).padEnd(6, '0')}`;
    await pre(s, 'Bash', { command: 'echo x > .claude/settings.json' }, { sessionId: id });
    const rows = logRows(repo).filter((r) => r.session === id);
    assert.ok(rows.length, `${name}: a log row`);
    assert.ok(rows.every((r) => !Object.hasOwn(r, 'worktree')), `${name}: no worktree in the row`);
  }
});

test('3: under GitHub Copilot the root never changes: a worktree folder is judged as before, through the Claude registration and the host files', async () => {
  const ISO = '2026-11-17T10:00:00.000Z';
  const decisionOf = (r) => r.out?.hookSpecificOutput?.permissionDecision ?? r.out?.permissionDecision ?? null;
  for (const [label, payload, env] of [
    ['Claude registration (timestamp)', { timestamp: ISO }, {}],
    ['VS Code', { timestamp: ISO }, { BI_HARNESS_HOST: 'vscode' }],
  ]) {
    for (const [command, expected] of [['echo hi > notes.txt', 'deny'], ['Set-Content notes.txt hi', 'deny']]) {
      const r = await run(S.wtMain, 'pre-tool-use.mjs', { hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command }, ...payload }, { env });
      assert.equal(r.status, 0, r.stderr);
      assert.equal(decisionOf(r), expected, `${label}: ${command}`);
    }
  }
});

test('3: a session root step that fails blocks the call in both guards (exit 2), like a guard that cannot load', () => {
  for (const [entry, who] of [['pre-tool-use.mjs', 'PreToolUse guard'], ['agent-scope.mjs', 'subagent scope guard']]) {
    const dir = tempDir('broken');
    for (const variant of ['missing', 'throws']) {
      fs.rmSync(path.join(dir, 'hooks'), { recursive: true, force: true });
      fs.mkdirSync(path.join(dir, 'hooks', 'lib'), { recursive: true });
      fs.copyFileSync(path.join(pack, 'hooks', entry), path.join(dir, 'hooks', entry));
      if (variant === 'throws') fs.writeFileSync(path.join(dir, 'hooks', 'lib', 'session-root.mjs'), 'export async function prepareSessionRoot() { throw new Error("broken"); }\n');
      const r = spawnSync(process.execPath, [path.join(dir, 'hooks', entry)], {
        input: JSON.stringify({ hook_event_name: 'PreToolUse', session_id: 'broken', cwd: wt, agent_type: 'bi-dax-reviewer', tool_name: 'Write', tool_input: { file_path: path.join(wt, 'docs', 'x.md'), content: 'x' } }),
        env: { ...baseEnv, CLAUDE_PROJECT_DIR: repo }, cwd: dir, encoding: 'utf8', windowsHide: true,
      });
      assert.equal(r.status, 2, `${entry} (${variant}): ${r.stderr}`);
      assert.match(r.stderr, new RegExp(`The ${who} could not load`), `${entry} (${variant})`);
      assert.equal(r.stdout, '', `${entry} (${variant}) prints no verdict`);
    }
  }
});

// ---------------------------------------------------------------- 4: a session in the repository root

// The verdicts measured on 2f07e2b: the cd into the worktree makes the write a guardrail write, the redirect by its path is
// judged by name (no verdict: Claude Code's own permission flow), and the Edit asks (a critical file under .claude/).
test('4: a session in the repository root keeps its verdicts for the worktree (deny, no verdict, ask)', async () => {
  const cd = await pre(S.home, 'Bash', { command: 'cd .claude/worktrees/wt && echo hi > notes.txt' });
  assert.equal(cd.decision, 'deny');
  assert.match(cd.reason, GUARD_REASON);
  assert.equal((await pre(S.home, 'Bash', { command: 'echo hi > .claude/worktrees/wt/notes.txt' })).decision, null);
  assert.equal((await pre(S.home, 'Edit', { file_path: path.join(wt, 'docs', 'a.md'), old_string: '# a', new_string: '# b' })).decision, 'ask');
  // strandedCd from the repository root (no CLAUDE_BASH_MAINTAIN_PROJECT_WORKING_DIR): a cd into the worktree strands the shell.
  const stranded = await pre(S.home, 'Bash', { command: 'cd .claude/worktrees/wt' }, { maintain: false });
  assert.equal(stranded.decision, 'deny');
  assert.match(stranded.reason, /leaves the shell in \.claude\/worktrees\/wt\./);
});

// ---------------------------------------------------------------- 5: file tools on targets outside the worktree

const OUTSIDE_FILES = [
  ['Write', { file_path: path.join(repo, '.claude', 'settings.json'), content: '{}\n' }],
  ['Edit', { file_path: path.join(repo, '.claude', 'settings.local.json'), old_string: '{"permissions"', new_string: '{ "permissions"' }],
  ['Write', { file_path: path.join(repo, 'hardening', 'harness.config.json'), content: '{ "approvals": { "mode": "lab" } }\n' }],
  ['Write', { file_path: path.join(repo, 'hardening', 'harness.config.json'), content: '{ "approvals": { "mode": "ask" } }\n' }],
  ['Write', { file_path: path.join(repo, 'hardening', 'harness.config.json'), content: '{ "approvals": { "mode": "auto" }, "references": ["setup/"] }\n' }],
  ['Write', { file_path: path.join(repo, '.claude', 'logs', 'x.jsonl'), content: '{}\n' }],
  ['Edit', { file_path: path.join(repo, 'hardening', 'hooks', 'x.mjs'), old_string: '// x', new_string: '// y' }],
  ['Read', { file_path: path.join(repo, '.env') }],
  ['Write', { file_path: path.join(repo, '.env'), content: 'X=2\n' }],
  ['Grep', { pattern: 'X', path: path.join(repo, '.env') }],
  ['Write', { file_path: path.join(repo, 'notes.txt'), content: 'x\n' }],
  ['Write', { file_path: path.join(repo, 'templates', 't.md'), content: '# u\n' }],
  ['Write', { file_path: path.join(repo, '.githooks', 'pre-commit'), content: '#!/bin/sh\n' }],
  ['Write', { file_path: path.join(wt2, 'notes.txt'), content: 'x\n' }],
  ['Write', { file_path: path.join(wt2, 'docs', 'new.md'), content: '# n\n' }],
  ['Write', { file_path: path.join(wt2, '.claude', 'settings.json'), content: '{}\n' }],
  ['Write', { file_path: path.join(repo, '.git', 'worktrees', 'wt', 'gitdir'), content: 'x\n' }],
  ['Edit', { file_path: path.join(wt, 'link', 'settings.json'), old_string: '{}', new_string: '{ }' }],
  ['Write', { file_path: path.join(wt, 'link', 'agents', 'x.md'), content: '# x\n' }],
  ['Write', { file_path: path.join(wt, 'hlink', 'hooks', 'y.mjs'), content: '// y\n' }],
  ['Write', { file_path: path.join(wt, 'dlink', 'new.md'), content: '# n\n' }],
  ['Write', { file_path: `${wt}${path.sep}..${path.sep}..${path.sep}..${path.sep}notes.txt`, content: 'x\n' }],
  ['Read', { file_path: path.join(repo, '.claude', 'logs', 'security-events.jsonl') }],
  // An MCP tool the guard does not know, writing into the main checkout.
  ['mcp__files__write_file', { path: path.join(repo, '.claude', 'logs', 'x.jsonl'), content: '{}' }],
  ['mcp__files__write_file', { path: path.join(repo, 'hardening', 'harness.config.json'), content: '{}' }],
  ['mcp__files__write_file', { path: path.join(repo, '.claude', 'agents', 'x.md'), content: '# x' }],
  ['mcp__files__write_file', { path: path.join(wt, 'link', 'logs', 'y.jsonl'), content: '{}' }],
  ['mcp__files__read_file', { path: path.join(repo, '.env') }],
];
// Routine files of the main checkout: auto mode allows them from the repository root, never from a worktree session.
const OUTSIDE_ROUTINE = [
  ['Edit', { file_path: path.join(repo, 'docs', 'a.md'), old_string: '# a', new_string: '# b' }],
  ['Write', { file_path: path.join(repo, 'docs', 'new.md'), content: '# n\n' }],
  ['Write', { file_path: path.join(repo, 'sql', 'q.sql'), content: 'select 2\n' }],
  ['Write', { file_path: `${wt}${path.sep}..${path.sep}..${path.sep}..${path.sep}docs${path.sep}new2.md`, content: '# n\n' }],
];
const fileLabel = ([tool, input]) => `${tool} ${posix(path.relative(top, input.file_path ?? input.path))}`;

test('5: Edit, Write and Read on targets outside the worktree are never more permissive than from the repository root', async () => {
  const rows = [...OUTSIDE_FILES, ...OUTSIDE_ROUTINE];
  const judge = (s) => mapLimit(rows, 8, ([tool, input]) => pre(s, tool, input));
  const [main, sub, home] = await Promise.all([judge(S.wtMain), judge(S.wtSub), judge(S.home)]);
  const weaker = rows.map((row, i) => ({ row: fileLabel(row), main: main[i].decision, sub: sub[i].decision, home: home[i].decision }))
    .filter((r) => RANK[r.main ?? 'null'] < RANK[r.home ?? 'null'] || RANK[r.sub ?? 'null'] < RANK[r.home ?? 'null']);
  assert.deepEqual(weaker, []);
  const allowed = OUTSIDE_FILES.map((row, i) => ({ row: fileLabel(row), main: main[i].decision, sub: sub[i].decision })).filter((r) => r.main === 'allow' || r.sub === 'allow');
  assert.deepEqual(allowed, []);
});

test('5: a routine file outside the worktree is never answered with an allow from a worktree session', async () => {
  const judge = (s) => mapLimit(OUTSIDE_ROUTINE, 4, ([tool, input]) => pre(s, tool, input));
  const [main, sub, home] = await Promise.all([judge(S.wtMain), judge(S.wtSub), judge(S.home)]);
  assert.ok(home.every((v) => v.decision === 'allow'), 'routine from the repository root');
  const allowed = OUTSIDE_ROUTINE.map((row, i) => ({ row: fileLabel(row), main: main[i].decision, sub: sub[i].decision })).filter((r) => r.main === 'allow' || r.sub === 'allow');
  assert.deepEqual(allowed, []);
});

// ---------------------------------------------------------------- 6: validator, Stop gate, agent scope, strandedCd, settings rules

const removeAll = (...files) => files.forEach((f) => fs.rmSync(f, { force: true, recursive: true }));

test('6: post-tool-validate validates a PBIR file of the worktree as the worktree\'s file and files it under the worktree', async () => {
  const rel = 'X.Report/definition/pages/p1/page.json';
  const file = path.join(wt, ...rel.split('/'));
  write(wt, { [rel]: '{ "name": "p1", ' });
  try {
    for (const [shape, s] of [['main', S.wtMain], ['sub', S.wtSub]]) {
      const id = `ptv${shape.padEnd(5, '0')}`;
      const r = await run(s, 'post-tool-validate.mjs', { hook_event_name: 'PostToolUse', tool_name: 'Write', tool_input: { file_path: file, content: '{ "name": "p1", ' }, tool_response: {} }, { sessionId: id });
      assert.equal(r.status, 0, r.stderr);
      assert.equal(r.out?.decision, 'block', shape);
      assert.match(r.out.reason, /^\[bi-harness\] X\.Report\/definition\/pages\/p1\/page\.json failed validation/, shape);
      assert.match(r.out.reason, /Invalid JSON/, shape);
      // The session state stays with the main checkout and keeps the worktree's path apart from the main checkout's.
      const state = JSON.parse(fs.readFileSync(path.join(repo, '.claude', 'logs', '.state', `${id}.json`), 'utf8'));
      assert.equal(state.changedFiles, undefined, `${shape}: the main checkout's list is untouched`);
      assert.ok(Object.entries(state).some(([k, v]) => k.startsWith('changedFiles') && Array.isArray(v) && v.includes(rel)), `${shape}: the worktree's list holds ${rel}`);
      assert.equal(fs.existsSync(path.join(wt, '.claude', 'logs')), false, `${shape}: nothing under the worktree's .claude/logs`);
    }
  } finally {
    removeAll(path.join(wt, 'X.Report'));
  }
});

test('6: post-tool-validate still validates a file of the main checkout written from a worktree session, as the main checkout\'s', async () => {
  const file = path.join(repo, 'docs', 'home-written.json');
  write(repo, { 'docs/home-written.json': '{ "a": ' });
  try {
    for (const [shape, s] of [['main', S.wtMain], ['sub', S.wtSub], ['home', S.home]]) {
      const id = `pth${shape.padEnd(5, '0')}`;
      const r = await run(s, 'post-tool-validate.mjs', { hook_event_name: 'PostToolUse', tool_name: 'Write', tool_input: { file_path: file, content: '{ "a": ' }, tool_response: {} }, { sessionId: id });
      assert.equal(r.status, 0, r.stderr);
      assert.equal(r.out?.decision, 'block', shape);
      assert.match(r.out.reason, /^\[bi-harness\] docs\/home-written\.json failed validation/, shape);
      const state = JSON.parse(fs.readFileSync(path.join(repo, '.claude', 'logs', '.state', `${id}.json`), 'utf8'));
      assert.deepEqual(state.changedFiles, ['docs/home-written.json'], shape);
    }
  } finally {
    removeAll(file);
  }
});

test('6: the Stop gate reads the worktree\'s uncommitted files, not the main checkout\'s, in both shapes', async () => {
  const stop = (s, id) => run(s, 'stop-gate.mjs', s.agent.agent_id
    ? { hook_event_name: 'SubagentStop', agent_type: 'bi-tmdl-modeler', stop_hook_active: false }
    : { hook_event_name: 'Stop', stop_hook_active: false }, { sessionId: id });
  write(repo, { 'docs/home-bad.json': '{ "a": ' });
  try {
    for (const [shape, s] of [['main', S.wtMain], ['sub', S.wtSub]]) {
      const clean = await stop(s, `sgc${shape.padEnd(5, '0')}`);
      assert.equal(clean.status, 0, clean.stderr);
      assert.notEqual(clean.out?.decision, 'block', `${shape}: an invalid file of the main checkout does not block a worktree session`);
    }
    write(wt, { 'docs/wt-bad.json': '{ "b": ' });
    for (const [shape, s] of [['main', S.wtMain], ['sub', S.wtSub]]) {
      const r = await stop(s, `sgb${shape.padEnd(5, '0')}`);
      assert.equal(r.status, 0, r.stderr);
      assert.equal(r.out?.decision, 'block', shape);
      assert.match(r.out.reason, /docs\/wt-bad\.json/, shape);
      assert.doesNotMatch(r.out.reason, /home-bad|\.claude\/worktrees/, shape);
    }
  } finally {
    removeAll(path.join(repo, 'docs', 'home-bad.json'), path.join(wt, 'docs', 'wt-bad.json'));
  }
});

test('6: an editor subagent\'s scope is read from the worktree: docs/x.md passes, notes.txt does not', async () => {
  const scoped = { agent_id: 'b6e1d2c3f4a5', agent_type: 'bi-doc-generator' };
  for (const [shape, s] of [['main', { ...S.wtMain, agent: scoped }], ['sub', { ...S.wtSub, agent: scoped }]]) {
    const scope = (file) => run(s, 'agent-scope.mjs', { hook_event_name: 'PreToolUse', tool_name: 'Write', tool_input: { file_path: path.join(wt, ...file.split('/')), content: '# x\n' } });
    const docs = await scope('docs/x.md');
    assert.equal(docs.status, 0, docs.stderr);
    assert.equal(docs.out?.hookSpecificOutput?.permissionDecision ?? null, null, `${shape}: docs/x.md`);
    const notes = await scope('notes.txt');
    assert.equal(notes.out?.hookSpecificOutput?.permissionDecision, 'deny', `${shape}: notes.txt`);
    assert.match(notes.out.hookSpecificOutput.permissionDecisionReason, /notes\.txt is out of scope/, `${shape}: notes.txt`);
  }
});

test('6: a scoped subagent in a worktree session is never passed outside the worktree where the repository root denies it', async () => {
  const decisionOf = (r) => r.out?.hookSpecificOutput?.permissionDecision ?? null;
  const W = (file) => ['Write', { file_path: file, content: '# x\n' }];
  const calls = [
    W(path.join(repo, 'docs', 'x.md')), W(path.join(repo, 'notes.txt')), W(path.join(repo, 'hardening', 'hooks', 'x.mjs')), W(path.join(repo, '.claude', 'settings.json')),
    W(path.join(wt2, 'docs', 'x.md')), W(path.join(wt2, 'notes.txt')), W(path.join(wt, 'dlink', 'x.md')), W(path.join(wt, 'link', 'agents', 'x.md')),
    W(`${wt}${path.sep}..${path.sep}..${path.sep}..${path.sep}docs${path.sep}y.md`), W(path.join(top, 'outside.md')),
    ['Edit', { file_path: path.join(repo, 'docs', 'a.md'), old_string: '# a', new_string: '# b' }],
    ['Bash', { command: 'echo x > ../../../docs/x.md' }], ['Bash', { command: `echo x > ${posix(repo)}/notes.txt` }], ['Bash', { command: 'rm ../../../docs/a.md' }],
    ['Bash', { command: 'echo x > docs/x.md' }],
  ];
  const label = ([tool, input]) => `${tool} ${posix(input.command ?? path.relative(top, input.file_path))}`;
  for (const agent_type of ['bi-doc-generator', 'bi-dax-reviewer', 'bi-tmdl-modeler']) {
    const scoped = { agent_id: 'c7f2e3d4a5b6', agent_type };
    const judge = (s) => mapLimit(calls, 8, async ([tool, input]) => {
      const r = await run({ ...s, agent: scoped }, 'agent-scope.mjs', { hook_event_name: 'PreToolUse', tool_name: tool, tool_input: input });
      assert.equal(r.status, 0, r.stderr);
      return decisionOf(r);
    });
    const [main, sub, home] = await Promise.all([judge(S.wtMain), judge(S.wtSub), judge(S.home)]);
    const weaker = calls.map((call, i) => ({ call: `${agent_type}: ${label(call)}`, main: main[i], sub: sub[i], home: home[i] }))
      .filter((r) => RANK[r.main ?? 'null'] < RANK[r.home ?? 'null'] || RANK[r.sub ?? 'null'] < RANK[r.home ?? 'null']);
    assert.deepEqual(weaker, []);
    // Nothing outside the worktree is in a scope read from the worktree: every write there is denied, the editor's docs/ too.
    const notDenied = calls.slice(0, -1).map((call, i) => ({ call: `${agent_type}: ${label(call)}`, main: main[i], sub: sub[i] })).filter((r) => r.main !== 'deny' || r.sub !== 'deny');
    assert.deepEqual(notDenied, []);
  }
});

test('6: strandedCd in a worktree main session: ls passes, cd docs is denied; a subagent gets no cd claim', async () => {
  const ls = await pre(S.wtMain, 'Bash', { command: 'ls' }, { maintain: false });
  assert.notEqual(ls.decision, 'deny', 'ls');
  const cd = await pre(S.wtMain, 'Bash', { command: 'cd docs' }, { maintain: false });
  assert.equal(cd.decision, 'deny', 'cd docs');
  assert.match(cd.reason, /leaves the shell in docs\./, 'cd docs');
  const ps = await pre(S.wtMain, 'PowerShell', { command: 'Set-Location docs' }, { maintain: false });
  assert.equal(ps.decision, 'deny', 'Set-Location docs');
  assert.deepEqual(await pre(S.wtMain, 'Bash', { command: 'cd docs' }, { maintain: false }), await pre(S.plainMain, 'Bash', { command: 'cd docs' }, { maintain: false }));
  assert.deepEqual(await pre(S.wtSub, 'Bash', { command: 'cd docs' }, { maintain: false }), await pre(S.plainSub, 'Bash', { command: 'cd docs' }, { maintain: false }));
  assert.notEqual((await pre(S.wtSub, 'Bash', { command: 'ls' }, { maintain: false })).decision, 'deny', 'ls in a subagent');
  // A cd that leaves the worktree for another folder of the main checkout keeps the claim it had there (the unverified twin):
  // a sibling worktree, the worktrees folder. The main checkout's root makes none, as before; no longer routine (it leaves
  // the project), it is never more permissive than there.
  for (const cmd of ['cd ../wt2', 'cd ..', 'PS> Set-Location ../wt2']) {
    const [tool, text] = shellTool(cmd);
    assert.deepEqual(await pre(S.wtMain, tool, { command: text }, { maintain: false }), await pre(unverified(fake), tool, { command: text }, { maintain: false }), cmd);
  }
  const [root, rootTwin] = [await pre(S.wtMain, 'Bash', { command: 'cd ../../..' }, { maintain: false }), await pre(unverified(fake), 'Bash', { command: 'cd ../../..' }, { maintain: false })];
  assert.notEqual(root.decision, 'deny', 'cd ../../..');
  assert.ok(rank(root) >= rank(rootTwin), 'cd ../../..');
  const sibling = await pre(S.wtMain, 'Bash', { command: 'cd ../wt2' }, { maintain: false });
  assert.equal(sibling.decision, 'deny');
  assert.match(sibling.reason, /leaves the shell in \.claude\/worktrees\/wt2\./);
});

test('6: the permission rules of the main checkout and of the worktree both hold back an allow in a worktree session', async () => {
  for (const s of [S.wtMain, S.wtSub]) {
    const edit = (name) => pre(s, 'Edit', { file_path: path.join(wt, 'docs', name), old_string: '# ', new_string: '## ' });
    assert.equal((await edit('a.md')).decision, 'allow', 'no rule: routine');
    assert.notEqual((await edit('locked-home.md')).decision, 'allow', 'a deny rule of the main checkout');
    assert.notEqual((await edit('locked-wt.md')).decision, 'allow', 'a deny rule of the worktree');
  }
});

test('6: the session banner of a worktree session reads the worktree\'s branch; its state and log row stay with the main checkout', async () => {
  for (const [shape, s] of [['main', S.wtMain], ['sub', S.wtSub]]) {
    const id = `ss${shape.padEnd(6, '0')}`;
    const r = await run(s, 'session-start.mjs', { hook_event_name: 'SessionStart', source: 'startup' }, { sessionId: id });
    assert.equal(r.status, 0, r.stderr);
    const banner = r.out?.hookSpecificOutput?.additionalContext ?? '';
    assert.match(banner, /- Git: branch wt-branch,/, shape);
    assert.match(banner, /- Approvals: auto\./, `${shape}: the main checkout's config`);
    assert.ok(fs.existsSync(path.join(repo, '.claude', 'logs', '.state', `${id}.json`)), `${shape}: state under the main checkout`);
    assert.equal(logRows(repo, 'sessions.jsonl').find((row) => row.session === id)?.worktree, 'wt', shape);
  }
  assert.equal(fs.existsSync(path.join(wt, '.claude', 'logs')), false, 'the worktree has no .claude/logs');
});

test('6: the main checkout\'s harness config governs a worktree session, not the worktree\'s copy', async () => {
  const CONFIG = 'hardening/harness.config.json';
  const edit = (s) => pre(s, 'Edit', { file_path: path.join(wt, 'docs', 'a.md'), old_string: '# a', new_string: '# b' });
  try {
    write(wt, { [CONFIG]: '{ "approvals": { "mode": "ask" } }\n' });
    for (const s of [S.wtMain, S.wtSub]) assert.equal((await edit(s)).decision, 'allow', 'auto in the main checkout, ask in the worktree');
    write(wt, { [CONFIG]: FILES[CONFIG] });
    write(repo, { [CONFIG]: '{ "approvals": { "mode": "ask" } }\n' });
    for (const s of [S.wtMain, S.wtSub]) assert.notEqual((await edit(s)).decision, 'allow', 'ask in the main checkout, auto in the worktree');
  } finally {
    write(wt, { [CONFIG]: FILES[CONFIG] });
    write(repo, { [CONFIG]: FILES[CONFIG] });
  }
});

// ---------------------------------------------------------------- 7: logs stay with the main checkout

test('7: a denied call from a worktree session logs under the main checkout with worktree "wt", and nothing under the worktree', async () => {
  for (const [shape, s] of [['main', S.wtMain], ['sub', S.wtSub]]) {
    const id = `log${shape.padEnd(5, '0')}`;
    const v = await pre(s, 'Bash', { command: 'echo x > .claude/settings.json' }, { sessionId: id });
    assert.equal(v.decision, 'deny', shape);
    const rows = logRows(repo).filter((r) => r.session === id);
    assert.equal(rows.length, 1, `${shape}: one row under the main checkout's .claude/logs`);
    assert.equal(rows[0].worktree, 'wt', shape);
    assert.equal(rows[0].decision, 'deny', shape);
    assert.equal(logRows(wt).filter((r) => r.session === id).length, 0, `${shape}: no row under the worktree`);
  }
  assert.equal(fs.existsSync(path.join(wt, '.claude', 'logs')), false, 'the worktree has no .claude/logs');
});

// ---------------------------------------------------------------- 8: no environment variable chooses the root

// Variables a launcher, a shell or a future version might use to name a folder. GIT_* are left out (they change what the git
// commands of a hook report, not the root, which no git process decides), and so are the host switches BI_HARNESS_HOST and
// COPILOT_CLI (a Copilot host keeps the main checkout by design), CLAUDE_PROJECT_DIR (the main checkout) and
// CLAUDE_BASH_MAINTAIN_PROJECT_WORKING_DIR (strandedCd's switch).
const DECOY_VARS = ['PWD', 'OLDPWD', 'INIT_CWD', 'CLAUDE_CWD', 'CLAUDE_WORKTREE', 'CLAUDE_WORKTREE_DIR', 'CLAUDE_CODE_WORKTREE', 'CLAUDE_WORKING_DIR',
  'CLAUDE_PROJECT_ROOT', 'BI_HARNESS_PROJECT_DIR', 'BI_HARNESS_WORKTREE', 'BI_HARNESS_ROOT', 'BI_HARNESS_HOME'];
const decoys = (folder) => Object.fromEntries(DECOY_VARS.map((k) => [k, folder]));

test('8: no environment variable changes the verdicts of a worktree session, of the repository root or of an unverified folder', async () => {
  const cases = [
    [S.wtMain, 'Bash', { command: 'touch notes.txt' }, {}], [S.wtMain, 'Bash', { command: 'echo x > ../../settings.json' }, {}],
    [S.wtMain, 'Write', { file_path: path.join(wt, 'docs', 'new.md'), content: '# n\n' }, {}], [S.wtMain, 'Bash', { command: 'cd docs' }, { maintain: false }],
    [S.wtMain, 'Write', { file_path: path.join(repo, 'docs', 'new.md'), content: '# n\n' }, {}], [S.wtSub, 'Bash', { command: 'rm docs/b.txt' }, {}],
    [S.home, 'Bash', { command: 'echo hi > .claude/worktrees/wt/notes.txt' }, {}], [S.home, 'Edit', { file_path: path.join(wt, 'docs', 'a.md'), old_string: '# a', new_string: '# b' }, {}],
    [unverified(fake), 'Bash', { command: 'echo hi > notes.txt' }, {}], [unverified(forged), 'Bash', { command: 'ls' }, { maintain: false }],
  ];
  for (const [s, tool, input, options] of cases) {
    const plainRun = await pre(s, tool, input, options);
    for (const folder of [wt, fake, repo, wt2]) {
      assert.deepEqual(await pre(s, tool, input, { ...options, env: decoys(folder) }), plainRun, `${tool} ${JSON.stringify(input)} with the variables at ${posix(path.relative(top, folder))}`);
    }
  }
  // The log row of a worktree session names the worktree whatever the variables say; an unverified folder's row names none.
  await pre(S.wtMain, 'Bash', { command: 'echo x > .claude/settings.json' }, { sessionId: 'envwt001', env: decoys(fake) });
  await pre(unverified(fake), 'Bash', { command: 'echo x > .claude/settings.json' }, { sessionId: 'envfk001', env: decoys(wt) });
  assert.equal(logRows(repo).find((r) => r.session === 'envwt001')?.worktree, 'wt');
  assert.equal(Object.hasOwn(logRows(repo).find((r) => r.session === 'envfk001') ?? {}, 'worktree'), false);
});
