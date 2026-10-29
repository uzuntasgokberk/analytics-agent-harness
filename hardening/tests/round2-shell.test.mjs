// Follow-up audit 2026-10-19 (round 2), group W2-A: the shell policy.
// F1-65:  `gh auth status --show-token` (or -t) prints the sign-in token like `gh auth token`, but got no verdict.
// F1-77:  deleting harness files through a pipeline (`find hardening | xargs rm`, `gci hardening | Remove-Item`) got no
//         verdict, while the direct `rm` or `Remove-Item` of the same files is denied.
// F1-133: the core.hooksPath deny exempted `.githooks`, a folder the harness does not ship.
// F1-135: `git config core.hooksPath` (a read: one key, no value) was denied as a change.
// Residual gaps of the PR #15 fix groups: bash ANSI-C quoting ($'\x2eenv'), `#` and `<# #>` comments that hide the next
// line from the splitter, `git -C <dir>` never routine, a commit message glued to its option read as a redirect,
// `git restore --staged -W .`, GIT_NAMESPACE, the text-word helper's own subcommand finder, and a share path the guard
// resolved through the network.
import { after, test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyzeShellCommand, routineShell } from '../hooks/lib/policy.mjs';
import { splitStatements, tokenize } from '../hooks/lib/shell-split.mjs';
import { PROJECT_DIR } from '../hooks/lib/common.mjs';

const shell = (cmd, ctx = {}) => analyzeShellCommand(cmd, ctx);
const decision = (cmd, ctx = {}) => shell(cmd, ctx)?.decision ?? null;
const preHook = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'hooks', 'pre-tool-use.mjs');

const temps = [];
after(() => temps.forEach((dir) => fs.rmSync(dir, { recursive: true, force: true })));
const tempDir = () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-round2-shell-'));
  temps.push(dir);
  return dir;
};

/** The PreToolUse guard's verdict for one shell command, run as a process like Claude Code runs it (auto mode, the default). */
function hook(dir, command, tool_name = 'Bash') {
  const r = spawnSync(process.execPath, [preHook], {
    input: JSON.stringify({ hook_event_name: 'PreToolUse', session_id: 'round2-shell', tool_name, tool_input: { command } }),
    env: { ...process.env, CLAUDE_PROJECT_DIR: dir },
    encoding: 'utf8',
  });
  assert.equal(r.status, 0, r.stderr); // a guard that did not run prints no verdict, which "not allow" would read as a pass
  const out = r.stdout.trim() ? JSON.parse(r.stdout).hookSpecificOutput ?? {} : {};
  return { decision: out.permissionDecision ?? null, reason: out.permissionDecisionReason ?? '' };
}

test('F1-65: gh auth status --show-token and -t print the sign-in token and are denied like gh auth token', () => {
  for (const cmd of ['gh auth status --show-token', 'gh auth status -t', 'gh auth status -h github.com -t', 'gh auth status --hostname github.com --show-token',
    'gh auth status -at', 'gh auth status --show-token=true', 'gh auth token']) {
    const v = shell(cmd);
    assert.equal(v?.decision, 'deny', cmd);
    assert.match(v.reason, /sign-in token/, cmd);
    assert.equal(routineShell(cmd), false, cmd);
  }
  for (const cmd of ['gh auth status', 'gh auth status -h github.com', 'gh auth status --active']) assert.notEqual(decision(cmd), 'deny', cmd);
  assert.equal(hook(tempDir(), 'gh auth status -t').decision, 'deny', 'the spawned guard denies it too');
});

test('F1-77: a pipeline that deletes, moves or edits the files an earlier stage names in a guardrail folder is denied like the direct form', () => {
  const guardrail = /Harness guardrail files|Deleting harness or git metadata/;
  for (const cmd of ['find hardening -type f | xargs rm', 'ls hardening/hooks/*.mjs | xargs rm', 'Get-ChildItem -Recurse hardening | Remove-Item',
    'gci hardening -r | ri', 'dir hardening\\hooks | del', 'echo hardening/x | xargs rm', 'git ls-files hardening | xargs rm',
    'find .claude -name x | xargs rm -f', 'gci .claude | Remove-Item', 'gci hardening | ForEach-Object { Remove-Item $_ }',
    'gci hardening | % { ri $_.FullName }', 'find hardening | xargs -I{} rm {}', 'find hardening | xargs -I {} rm {}',
    'gci hardening | Move-Item -Destination x', 'find hardening -name "*.mjs" | xargs sed -i s/deny/allow/', 'find .git -name "*.lock" | xargs rm',
    'gci hardening/hooks | Set-Content -Value x', 'ls .claude/settings.json | xargs rm', 'find hardening | xargs tee']) {
    const v = shell(cmd);
    assert.equal(v?.decision, 'deny', cmd);
    assert.match(v.reason, guardrail, cmd);
  }
  // The direct forms stay denied; Remove-Item of a guardrail folder now matches its bash twin `rm .claude`.
  for (const cmd of ['rm hardening/hooks/pre-tool-use.mjs', 'Remove-Item hardening\\hooks\\pre-tool-use.mjs', 'Remove-Item -Recurse hardening',
    'rm .claude', 'Remove-Item .claude', 'del .claude', 'ri hardening']) {
    assert.equal(decision(cmd), 'deny', cmd);
  }
  // Pipelines that only read guardrail files, write the listing into a file of their own, or delete files elsewhere.
  for (const cmd of ['gci docs | Remove-Item', 'ls docs | xargs rm', 'cat hardening/README.md | grep x', 'ls hardening | wc -l',
    'gci hardening | Select-String x', 'ls hardening | tee docs-list.txt', 'gci hardening | Out-File list.txt', 'grep -l hardening docs/a.txt | xargs rm',
    'find hardening -name "*.mjs" | xargs grep -n deny', 'git ls-files hardening | xargs wc -l']) {
    assert.notEqual(decision(cmd), 'deny', cmd);
  }
  assert.equal(hook(tempDir(), 'find hardening -type f | xargs rm').decision, 'deny');
  assert.equal(hook(tempDir(), 'gci hardening -r | ri', 'PowerShell').decision, 'deny');
});

test('F1-133: core.hooksPath pointed at .githooks (a folder the harness does not ship) is denied; hardening/githooks stays allowed', () => {
  for (const cmd of ['git config core.hooksPath .githooks', 'git config --local core.hooksPath .githooks', 'git -c core.hooksPath=.githooks commit -m x']) {
    const v = shell(cmd);
    assert.equal(v?.decision, 'deny', cmd);
    assert.match(v.reason, /core\.hooksPath/, cmd);
  }
  assert.notEqual(decision('git config core.hooksPath hardening/githooks'), 'deny');
});

test('F1-135: reading git configuration (one key, no value; get; --get) is not denied, setting and unsetting stay denied', () => {
  for (const cmd of ['git config core.hooksPath', 'git config --local core.hooksPath', 'git config --global core.hooksPath', 'git config get core.hooksPath',
    'git config --show-origin core.hooksPath', 'git config --get core.hooksPath', 'git config core.pager', 'git config --type=bool core.fsmonitor']) {
    assert.notEqual(decision(cmd), 'deny', cmd);
  }
  for (const cmd of ['git config core.hooksPath .git/hooks', 'git config --unset core.hooksPath', 'git config --unse core.hooksPath',
    'git config set core.hooksPath x', 'git config unset core.hooksPath', 'git config core.hooksPath ""', 'git config --add core.hooksPath x',
    'git config core.pager less', 'git config set core.pager less', 'git config --glob core.hooksPath',
    // Found with F1-135: a commit message that says "config --get" made the -c core.hooksPath of a commit read as a read.
    'git -c core.hooksPath=evil commit -m "config --get"', 'git -c core.hooksPath=evil commit -m "see git config --list"']) {
    assert.equal(decision(cmd), 'deny', cmd);
  }
});

test('residual 1: bash ANSI-C quoting ($\'\\x2eenv\') is decoded, so the secret name is seen; a quote-hidden name piped on is seen too', () => {
  assert.deepEqual(tokenize("cat $'\\x2eenv'"), ['cat', '.env']);
  assert.deepEqual(tokenize("cat $'\\056env' $'\\u002eenv' $'.e\\x6ev' $'\\U0000002eenv'"), ['cat', '.env', '.env', '.env', '.env']);
  // Bash keeps the backslash of an unknown escape, ends the quoted part at a NUL, and reads at most 2 hex and 3 octal digits.
  assert.deepEqual(tokenize("x $'a\\zb' $'a\\x00b'c $'\\x41B' $'\\1012' $'\\'' $'a\\tb'"), ['x', 'a\\zb', 'ac', 'AB', 'A2', "'", 'a\tb']);
  for (const cmd of ["cat $'\\x2eenv'", "gc $'\\x2eenv'", "cat $'\\056env'", "cat $'.e\\x6ev'", "ls $'\\x2eenv' | xargs cat", "ls .en''v | xargs cat",
    "cat $'\\x2essh/id_rsa'"]) {
    assert.equal(decision(cmd), 'deny', cmd);
    assert.equal(routineShell(cmd), false, cmd);
  }
  assert.equal(routineShell("cat $'README.md'"), true, 'an ANSI-C quoted project file stays routine');
});

test('residual 2: a # or <# #> comment never hides the next line or the rest of the command', () => {
  assert.deepEqual(splitStatements("echo hi # it's\nrm -rf /"), ["echo hi # it's", 'rm -rf /']);
  // Found with residual 2: PowerShell ends a statement at a carriage return alone (`a<CR>b` runs b), the splitter did not.
  assert.deepEqual(splitStatements('echo hi\rgit push'), ['echo hi', 'git push']);
  for (const cmd of ['echo hi\rgit push --force origin main', 'Write-Output a # x\rgit push --force origin main']) {
    assert.equal(decision(cmd), 'deny', cmd);
    assert.equal(routineShell(cmd), false, cmd);
  }
  assert.deepEqual(tokenize("echo hi # it's"), ['echo', 'hi', '#', "it's"]);
  for (const cmd of ["echo hi # it's\nrm -rf /", "Write-Output a <# it's\n#> ; git push --force origin main", 'git <# x #> push --force origin main',
    'git restore . # --staged', "bash -c \"echo hi # it's\nrm -rf /\"", 'pwsh -Command "git <# x #> push --force origin main"',
    "cat README.md # it's\ncat .env"]) {
    assert.equal(decision(cmd), 'deny', cmd);
    assert.equal(routineShell(cmd), false, cmd);
  }
  for (const cmd of ["gc README.md # it's\ngc ../outside.txt", "gc README.md <# it's #> ; gc ../outside.txt", "cat README.md # it's\ngit push origin main"]) {
    assert.equal(routineShell(cmd), false, cmd);
  }
  assert.equal(shell("cat README.md # it's\ngit push origin main")?.floor, true, 'the push behind the comment gets the floor ask');
  for (const cmd of ['git status # check it', 'echo a#b', 'git log --grep "#12" -1', 'cat README.md']) assert.equal(routineShell(cmd), true, cmd);
  // The spawned guard in auto mode allowed the force push behind the PowerShell block comment before the fix.
  assert.equal(hook(tempDir(), "Write-Output a <# it's\n#> ; git push --force origin main", 'PowerShell').decision, 'deny');
  assert.equal(hook(tempDir(), "echo hi # it's\nrm -rf x").decision, 'deny');
});

test('residual 3: git -C <folder inside the project> is routine; -C outside, a -C chain that leaves it, and -c are not', () => {
  for (const cmd of ['git -C docs status', 'git -C . log -1', 'git -C hardening log -1', 'git -C docs diff HEAD -- a.md']) assert.equal(routineShell(cmd), true, cmd);
  for (const cmd of ['git -C .. status', 'git -C docs -C ../.. status', 'git -c core.pager=x log', 'git --exec-path=x status', 'git -C $HOME status']) {
    assert.equal(routineShell(cmd), false, cmd);
  }
  const docs = path.join(PROJECT_DIR, 'docs');
  // From docs/, `-C ..` is the project root and `-C ../x` from there leaves it; `-F ../x` from the root names a file outside.
  assert.equal(routineShell('git -C .. -C ../x status', docs), false);
  assert.equal(routineShell('git -C .. commit -F ../outside.txt', docs), false);
  assert.equal(shell('git -C .. commit -F ../outside.txt', { baseDir: docs })?.decision, 'ask');
});

test('residual 4: a commit message glued to its option is text, not a redirect', () => {
  for (const cmd of ['git commit --message="rename a.md -> b.md"', 'git commit -m"rename a.md -> b.md"', 'git commit -am"rename a.md -> b.md"',
    "git commit --message='rename a.md -> b.md'", 'git log --grep="a.md -> b.md"']) {
    assert.notEqual(decision(cmd), 'deny', cmd);
  }
  for (const cmd of ['git commit -m"x" > docs/a.md', 'git commit --message="x" >docs/a.md', 'git log --grep=x > notes.md']) assert.equal(decision(cmd), 'deny', cmd);
});

test('residual 5: git restore --staged -W (and -W in a cluster) discards the working tree like --worktree', () => {
  for (const cmd of ['git restore --staged -W .', 'git restore --staged -W :/', 'git restore -W --staged .', 'git restore --staged -qW .', 'git restore --staged --worktree .']) {
    assert.equal(decision(cmd), 'deny', cmd);
  }
  assert.equal(decision('git restore --staged .'), null);
});

test('residual 6: GIT_NAMESPACE= is denied like --namespace', () => {
  for (const cmd of ['GIT_NAMESPACE=x git log', 'git --namespace x log', 'env GIT_NAMESPACE=x git status']) assert.equal(decision(cmd), 'deny', cmd);
});

test('residual 7: the value of a global git option is never read as the subcommand by the text-word scan', () => {
  // A branch named `commit` makes `git --attr-source commit show -m HEAD:.env` print .env (probed on git 2.52).
  for (const cmd of ['git --attr-source commit show -m HEAD:.env', 'git --attr-source commit log -m .env', 'git --super-prefix commit show -m HEAD:.env']) {
    assert.equal(decision(cmd), 'deny', cmd);
  }
  // The guard allowed it in auto mode before (the scan took HEAD:.env for a commit message, and git show is routine).
  assert.equal(hook(tempDir(), 'git --attr-source commit show -m HEAD:.env').decision, 'deny');
  for (const cmd of ['git --no-pager commit -m "mention .env"', 'git -C docs commit -m "x .env"', 'git -c core.quotepath=off commit -m "x .env"']) {
    assert.notEqual(decision(cmd), 'deny', cmd);
  }
});

test('residual 10: a share path (//host/share, \\\\host\\share) outside a project that is not on one is judged without touching the file system', () => {
  const touched = [];
  const share = (p) => typeof p === 'string' && /^[\\/]{2}w2a-/i.test(p);
  const fail = (name, p) => {
    touched.push(`${name} ${p}`);
    throw Object.assign(new Error(`ENOENT: ${p}`), { code: 'ENOENT' });
  };
  const original = { realpath: fs.realpathSync.native, stat: fs.statSync, exists: fs.existsSync, read: fs.readFileSync, readdir: fs.readdirSync, lstat: fs.lstatSync };
  fs.realpathSync.native = (p, ...rest) => (share(p) ? fail('realpath', p) : original.realpath(p, ...rest));
  fs.statSync = (p, ...rest) => (share(p) ? fail('stat', p) : original.stat(p, ...rest));
  fs.lstatSync = (p, ...rest) => (share(p) ? fail('lstat', p) : original.lstat(p, ...rest));
  fs.existsSync = (p) => (share(p) ? (touched.push(`exists ${p}`), false) : original.exists(p));
  fs.readFileSync = (p, ...rest) => (share(p) ? fail('read', p) : original.read(p, ...rest));
  fs.readdirSync = (p, ...rest) => (share(p) ? fail('readdir', p) : original.readdir(p, ...rest));
  const cmds = ['cat //w2a-h1/share/x', 'gc \\\\w2a-h2\\share\\x', 'cd //w2a-h3/share', 'find //w2a-h4/share -delete', 'dtexec /F //w2a-h5/share/p.dtsx /Validate',
    'git checkout //w2a-h6/share/x', 'node //w2a-h7/share/x.mjs', 'npm --prefix //w2a-h8/share test', 'rm //w2a-h9/share/x',
    'git commit -F //w2a-h10/share/x', 'Remove-Item //w2a-h11/share/x.md', 'ls //w2a-h12/share'];
  const verdicts = {};
  try {
    for (const cmd of cmds) verdicts[cmd] = { decision: decision(cmd), routine: routineShell(cmd) };
  } finally {
    Object.assign(fs, { statSync: original.stat, existsSync: original.exists, readFileSync: original.read, readdirSync: original.readdir, lstatSync: original.lstat });
    fs.realpathSync.native = original.realpath;
  }
  assert.deepEqual(touched, [], 'the guard touched a share path');
  for (const cmd of cmds) assert.equal(verdicts[cmd].routine, false, `${cmd}: a share is outside the project`);
  assert.equal(verdicts['find //w2a-h4/share -delete'].decision, 'deny', 'find -delete outside the project stays denied');
  assert.equal(verdicts['git commit -F //w2a-h10/share/x'].decision, 'ask', 'a commit message file outside the project still asks');
});
