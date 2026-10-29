// Audit 2026-10-18, group G4: the programs the guard approves as routine or answers with a plain ask, and the arguments it
// let through unread. F1-9: `find -delete` and `find -exec rm|mv|sed -i` were auto-approved, `.git` and hardening/ included.
// F1-57: a harness script and `git blame --contents` / `git commit -F` read any file on the machine without a prompt.
// F1-58: `npm --prefix hardening test --prefix <other>` and `--node-options` ran other code as a routine test, and the
// shipped allow rules accepted any trailing option. F2-1: `git grep -O<cmd>` runs a program. Also: check-hooks.mjs is one of
// the pack's own checks (routine as the whole command, no argument). Each case was a silent pass or an allow before the fix.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { PROJECT_DIR } from '../hooks/lib/common.mjs';
import { ruleMatches } from '../hooks/lib/permissions.mjs';
import { analyzeShellCommand, routineShell } from '../hooks/lib/policy.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const pack = path.join(here, '..');
const repo = path.join(pack, '..');
const preHook = path.join(pack, 'hooks', 'pre-tool-use.mjs');
const scopeHook = path.join(pack, 'hooks', 'agent-scope.mjs');
const posix = (p) => p.replace(/\\/g, '/');
const TMP = posix(os.tmpdir());

const shell = (cmd, ctx = {}) => analyzeShellCommand(cmd, ctx);
const decision = (cmd, ctx) => shell(cmd, ctx)?.decision ?? null;
/** 'deny', 'user' (an ask auto mode never answers), 'floor', 'pass' (a plain ask auto mode answers) or 'none'. */
function kind(cmd, ctx) {
  const v = shell(cmd, ctx);
  if (!v) return 'none';
  if (v.decision === 'deny') return 'deny';
  return v.floor ? 'floor' : v.autoApprovable === false ? 'user' : 'pass';
}

/** A temporary project with an optional harness config, project settings and folders. */
function project({ config, settings, dirs = [] } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-routine-'));
  fs.mkdirSync(path.join(dir, 'hardening'), { recursive: true });
  if (config) fs.writeFileSync(path.join(dir, 'hardening', 'harness.config.json'), JSON.stringify(config));
  if (settings) {
    fs.mkdirSync(path.join(dir, '.claude'), { recursive: true });
    fs.writeFileSync(path.join(dir, '.claude', 'settings.json'), JSON.stringify(settings));
  }
  for (const d of dirs) fs.mkdirSync(path.join(dir, d), { recursive: true });
  return dir;
}
const cleanup = (dir) => fs.rmSync(dir, { recursive: true, force: true });

/** The PreToolUse guard as Claude Code runs it, for one shell command. */
function hook(dir, command, { tool = 'Bash', cwd } = {}) {
  const r = spawnSync(process.execPath, [preHook], {
    input: JSON.stringify({ hook_event_name: 'PreToolUse', session_id: 'routine-programs', tool_name: tool, tool_input: { command }, ...(cwd ? { cwd } : {}) }),
    env: { ...process.env, CLAUDE_PROJECT_DIR: dir },
    encoding: 'utf8',
  });
  assert.equal(r.status, 0, r.stderr); // a guard that did not run prints no verdict, which "not allow" would read as a pass
  const out = r.stdout.trim() ? JSON.parse(r.stdout).hookSpecificOutput : {};
  return { decision: out.permissionDecision ?? null, reason: out.permissionDecisionReason ?? '' };
}

/** The subagent scope guard for one shell command of a read-only agent. */
function scope(dir, command, agent = 'bi-validator') {
  const r = spawnSync(process.execPath, [scopeHook], {
    input: JSON.stringify({ hook_event_name: 'PreToolUse', session_id: 'routine-programs', agent_type: agent, tool_name: 'Bash', tool_input: { command } }),
    env: { ...process.env, CLAUDE_PROJECT_DIR: dir },
    encoding: 'utf8',
  });
  assert.equal(r.status, 0, r.stderr);
  return r.stdout.trim() ? JSON.parse(r.stdout).hookSpecificOutput?.permissionDecision ?? null : null;
}

// What the pack ships as permission rules, and what the harness documents (README.md, hardening/README.md, hardening/REFERENCE.md,
// .claude/rules/bi/harness.md, the bi-map security review): `npm --prefix hardening test`. The package scripts are validate,
// validate:changed, validate:staged, test and hooks:install; only the first four are checks.
const shipped = JSON.parse(fs.readFileSync(path.join(pack, 'settings.hooks.json'), 'utf8'));
const ownSettingsFile = path.join(repo, '.claude', 'settings.json');
const own = fs.existsSync(ownSettingsFile) ? JSON.parse(fs.readFileSync(ownSettingsFile, 'utf8')) : null;
const DOCUMENTED = ['npm --prefix hardening test', 'npm --prefix hardening test -- tests/guard.test.mjs', 'npm --prefix hardening run validate',
  'npm --prefix hardening run validate -- --changed', 'node hardening/scripts/validate.mjs --changed', 'node hardening/scripts/rdl-compare.mjs a.rdl b.rdl',
  'node hardening/scripts/check-hooks.mjs', 'node --version'];

/** What the permission rules alone decide, ordered as Claude Code orders them: deny, then ask, then allow. */
function rulesVerdict(permissions, tool, command) {
  for (const kindOfRule of ['deny', 'ask', 'allow']) {
    if ((permissions?.[kindOfRule] ?? []).some((rule) => ruleMatches(rule, tool, { command }))) return kindOfRule;
  }
  return null;
}

// ---------------------------------------------------------------- F1-9: find

// A find that changes files and aims at the repository history, the harness, or a folder outside the project is denied.
const FIND_DENIED = [
  'find hardening -delete', 'find hardening -type f -exec rm {} +', 'find .git -delete', 'find .git -exec rm -f {} +', 'find .claude -name settings.json -delete',
  'find .githooks -delete', 'find .github -type f -delete', 'find ./hardening/hooks -name "*.mjs" -delete', 'find docs/../hardening -delete',
  'find /c/Users -delete', 'find .. -delete', 'find ../x -exec rm {} +', `find "${TMP}" -delete`, 'find ~ -delete', 'find -L /c/Windows -exec rm {} +',
  'find . -fprint .claude/settings.json', 'find . -fls hardening/x.txt', 'find . -fprintf ../out.txt %p',
  // in-place editors write every matched file outside the Edit/Write checks
  "find . -name '*.tmdl' -exec sed -i s/Revenue/Rev/ {} +", 'find docs -type f -execdir sed -i.bak s/a/b/ {} \\;', 'find . -exec perl -pi -e s/a/b/ {} +',
  'find . -exec sed --in-place s/a/b/ {} +', 'find . -exec gawk -i inplace 1 {} +', 'find . -name x -exec echo {} \\; -exec sed -i s/a/b/ {} \\;',
  // a reference folder is read-only, and so is a guarded file named by -fprint
  'find templates -delete', 'find . -fprint docs/notes.md',
];
// Anything else that changes files is the user's call: an ask that auto mode never answers.
const FIND_ASKED = [
  'find . -delete', 'find -delete', 'find docs -name "*.tmp" -delete', 'find docs -depth -delete', 'find . -exec rm -f {} +', 'find . -name "*.tmp" -exec rm {} \\;',
  'find . -exec mv {} /tmp \\;', 'find . -exec cp {} /tmp \\;', 'find . -execdir rm {} +', 'find . -ok rm {} \\;', 'find . -okdir rm {} \\;',
  'find . -exec echo {} \\; -exec rm {} \\;', // every -exec counts, not only the first
  'find . -exec bash -c "echo $0" {} \\;', 'find . -exec chmod 600 {} +', 'find . -exec truncate -s 0 {} +', 'find . -exec rg --pre rm x {} +',
  'find . -name x -fprint out.txt', 'find . -fprint0 out.txt', 'find . -fprintf out.txt %p', 'find . -fls out.txt',
  'find -H . -delete', 'find -L docs -delete', 'find $DIR -delete', 'find * -delete', 'find . -exec',
];
// A find that only looks, or whose -exec only reads or prints, has no verdict.
const FIND_QUIET = [
  "find . -name '*.tmdl'", 'find docs -type f', "find . -name '*.rdl' -exec grep -l Foo {} +", 'find docs -name "*.md" -exec cat {} \\;', 'find . -exec wc -l {} +',
  'find . -exec ls -l {} \\;', 'find . -exec echo {} \\;', 'find hardening -name "*.mjs" -exec grep -l x {} +', 'find .git -name HEAD', 'find .. -name x -print',
  'find . -exec rg x {} +', 'find . -type f -print0',
];

test('F1-9: find -delete, -fprint and -exec with a program that changes files: denied on .git, .claude, .githooks, .github, hardening and outside the project; asked otherwise', () => {
  for (const cmd of FIND_DENIED) {
    const v = shell(cmd);
    assert.equal(v?.decision, 'deny', cmd);
    assert.equal(routineShell(cmd), false, cmd);
  }
  assert.match(shell('find hardening -delete').reason, /\.git, \.claude, \.githooks, \.github or hardening are blocked/);
  assert.match(shell('find /c/Users -delete').reason, /outside the project/);
  assert.match(shell("find . -name '*.tmdl' -exec sed -i s/Revenue/Rev/ {} +").reason, /Edit tool/);
  assert.match(shell('find templates -delete').reason, /reference folder/);
  for (const cmd of FIND_ASKED) {
    const v = shell(cmd);
    assert.equal(v?.decision, 'ask', cmd);
    assert.equal(v.autoApprovable, false, `${cmd}: auto mode never answers it`);
    assert.equal(routineShell(cmd), false, cmd);
  }
  for (const cmd of FIND_QUIET) assert.equal(shell(cmd), null, cmd);
  for (const cmd of ["find . -name '*.tmdl'", 'find docs -type f', 'find . -type f -print0']) assert.equal(routineShell(cmd), true, cmd);
});

test('F1-9: the shell folder counts: a cd into hardening makes a bare `find .` a find on hardening; a folder the guard lost is asked, not denied', () => {
  const inHardening = path.join(PROJECT_DIR, 'hardening');
  assert.equal(decision('cd hardening && find . -delete'), 'deny');
  assert.equal(decision('Set-Location hardening; find . -exec rm {} +'), 'deny');
  assert.equal(decision('cd docs && find ../hardening -delete'), 'deny');
  assert.equal(decision('find . -delete', { baseDir: inHardening }), 'deny', 'the payload\'s own folder is hardening');
  assert.equal(decision('find ../docs -delete', { baseDir: inHardening }), 'ask');
  assert.equal(decision('cd .. && find . -delete', { baseDir: inHardening }), 'ask', 'back at the project root');
  assert.equal(kind('cd docs && find . -delete'), 'user');
  assert.equal(kind('cd $X && find . -delete'), 'user', 'a folder the guard cannot place is the user\'s call');
  assert.equal(kind('cd nothing-there && find . -delete'), 'user', 'a failing cd leaves the next command where it was');
  assert.equal(kind('cd docs; popd; find . -delete'), 'user', 'popd goes back to a folder the command line does not name');
  assert.equal(decision('cd docs && find .. -delete'), 'ask', 'the project root itself is not a guardrail folder');
});

test('F1-9: find -exec still judges the program it runs as a command of its own', () => {
  assert.equal(decision('find . -exec ssh host \\;'), 'deny');
  assert.equal(decision('find . -exec git push --force origin main \\;'), 'deny');
  assert.equal(decision('find . -exec echo {} \\; -exec ssh host \\;'), 'deny', 'a later -exec counts too');
  assert.equal(shell('find . -exec git push origin feature/x \\;').floor, true);
  assert.equal(decision('find . -exec rm -rf {} +'), 'deny');
  assert.equal(decision('find . -exec sh -c "rm -rf hardening" \\;'), 'deny');
});

test('F1-9: through the PreToolUse hook no find that changes files is answered allow, in auto, ask or lab mode', () => {
  const dir = project();
  const askDir = project({ config: { approvals: { mode: 'ask' } } });
  const labDir = project({ config: { approvals: { mode: 'lab' } } });
  try {
    // The record's reproduction: all of these were `allow` ("auto-approved: find -delete / -exec rm|mv|sed can modify many files at once").
    for (const cmd of ['find hardening -delete', 'find . -delete', 'find .git -delete', 'find /c/Users -delete', 'find .claude -name settings.json -delete',
      'find hardening -type f -exec rm {} +', 'find . -exec rm -f {} +', "find . -name '*.tmdl' -exec sed -i s/Revenue/Rev/ {} +"]) {
      for (const tool of ['Bash', 'PowerShell']) {
        const auto = hook(dir, cmd, { tool });
        assert.notEqual(auto.decision, 'allow', `auto: ${tool} ${cmd}`);
        assert.equal(auto.decision, kind(cmd) === 'deny' ? 'deny' : 'ask', `auto: ${tool} ${cmd}`);
        assert.notEqual(hook(askDir, cmd, { tool }).decision, 'allow', `ask: ${tool} ${cmd}`);
      }
      if (kind(cmd) === 'deny') assert.equal(hook(labDir, cmd).decision, 'deny', `lab: ${cmd}`);
    }
    assert.match(hook(dir, 'find . -delete').reason, /Critical: auto mode always asks/);
    // The controls of the record stay denied, and a find that looks stays routine.
    for (const cmd of ['rm -rf hardening', 'rm hardening/hooks/pre-tool-use.mjs']) assert.equal(hook(dir, cmd).decision, 'deny', cmd);
    assert.equal(hook(dir, "find . -name '*.tmdl'").decision, 'allow');
    assert.equal(hook(dir, 'find . -name x -exec grep -l y {} +').decision, null);
  } finally {
    cleanup(dir);
    cleanup(askDir);
    cleanup(labDir);
  }
});

// ---------------------------------------------------------------- F1-57: harness scripts and git file options

const OUTSIDE = ['~/.gitconfig', '../outside/appsettings.json', 'C:/Windows/win.ini', '$HOME/x.txt', '%USERPROFILE%/x.txt', `${TMP}/notes.txt`];

test('F1-57: every argument of a harness script must stay inside the project: not routine, and an ask the shipped allow rules cannot answer', () => {
  for (const f of OUTSIDE) {
    for (const cmd of [`node hardening/scripts/rdl-compare.mjs docs/handoff.md ${f}`, `node hardening/scripts/rdl-compare.mjs ${f} a.rdl`,
      `node hardening/scripts/validate.mjs --files ${f}`, `node hardening/scripts/validate.mjs --files docs/handoff.md ${f}`,
      `node hardening/scripts/githook.mjs commit-msg ${f}`]) {
      assert.equal(routineShell(cmd), false, cmd);
      const v = shell(cmd);
      assert.equal(v?.decision, 'ask', cmd);
      assert.equal(v.autoApprovable, false, cmd);
      assert.match(v.reason, /reads the files named on its command line/, cmd);
    }
  }
  // The record's commands, as the PreToolUse hook sees them: they were `allow` ("auto mode: routine command").
  const dir = project();
  try {
    for (const cmd of ['node hardening/scripts/rdl-compare.mjs docs/handoff.md ~/.gitconfig', 'node hardening/scripts/validate.mjs --files ~/.claude.json']) {
      assert.equal(hook(dir, cmd).decision, 'ask', cmd);
      assert.equal(hook(dir, cmd, { tool: 'PowerShell' }).decision, 'ask', `PowerShell: ${cmd}`);
    }
  } finally {
    cleanup(dir);
  }
  // A secret file is denied, as before.
  for (const cmd of ['node hardening/scripts/rdl-compare.mjs .env a.rdl', 'node hardening/scripts/validate.mjs --files ~/.aws/credentials']) assert.equal(decision(cmd), 'deny', cmd);
});

test('F1-57: the harness checks with files inside the project stay routine and quiet', () => {
  for (const cmd of ['node hardening/scripts/rdl-compare.mjs a.rdl b.rdl', 'node hardening/scripts/rdl-compare.mjs reports/Sales/source/Sales.rdl reports/Sales/Sales.rdl --ignore Body',
    'node hardening/scripts/validate.mjs', 'node hardening/scripts/validate.mjs --changed', 'node hardening/scripts/validate.mjs --staged --json',
    'node hardening/scripts/validate.mjs --files docs/handoff.md docs/decisions.md', `node hardening/scripts/validate.mjs --files "${posix(PROJECT_DIR)}/docs/handoff.md"`,
    'node hardening/scripts/githook.mjs pre-commit', 'node hardening/tests/run-all.mjs', 'node hardening/hooks/pre-tool-use.mjs',
    // a redirection is the shell's, not an argument of the script
    'node hardening/scripts/validate.mjs --changed 2>&1', 'node hardening/scripts/validate.mjs --changed > /dev/null', 'node hardening/scripts/check-hooks.mjs 2>&1']) {
    assert.equal(decision(cmd), null, cmd);
    assert.equal(routineShell(cmd), true, cmd);
  }
  // A wildcard inside the project is no ask (the script reads what it matches) but is not routine either.
  assert.equal(decision('node hardening/scripts/validate.mjs --files docs/*.md'), null);
  assert.equal(routineShell('node hardening/scripts/validate.mjs --files docs/*.md'), false);
  // The script is still the first word: a node option in front of it keeps the old "not routine".
  assert.equal(routineShell('node --max-old-space-size=4096 hardening/scripts/validate.mjs'), false);
});

const GIT_READS = [
  (f) => `git blame --contents ${f} -- TASKS.md`, (f) => `git blame --contents=${f} TASKS.md`, (f) => `git blame --cont ${f} TASKS.md`,
  (f) => `git blame --ignore-revs-file ${f} TASKS.md`, (f) => `git blame --ignore-revs=${f} TASKS.md`, (f) => `git blame -S ${f} TASKS.md`,
  (f) => `git commit --allow-empty -F ${f}`, (f) => `git commit -F${f}`, (f) => `git commit -aF ${f}`, (f) => `git commit -qF ${f} --allow-empty`,
  (f) => `git commit --file ${f}`, (f) => `git commit --file=${f}`, (f) => `git commit --fil=${f}`, (f) => `git commit -t ${f}`,
  (f) => `git commit --template=${f}`, (f) => `git commit --templ ${f}`, (f) => `git commit --pathspec-from-file=${f}`,
  (f) => `git add --pathspec-from-file ${f}`, (f) => `git add --pathspec-from=${f}`, (f) => `git -C docs commit -F ${f}`, (f) => `git -c core.quotepath=off commit -F ${f}`,
];

test('F1-57: a git file option (blame --contents, commit -F/--file/-t/--template, --pathspec-from-file) that reads outside the project is an ask, never routine', () => {
  for (const f of OUTSIDE) {
    for (const make of GIT_READS) {
      const cmd = make(f);
      const v = shell(cmd);
      assert.equal(v?.decision, 'ask', cmd);
      assert.equal(v.autoApprovable, false, cmd);
      assert.match(v.reason, /reads a file named on its command line/, cmd);
      assert.equal(routineShell(cmd), false, cmd);
    }
  }
  // The deny of a forced or hook-skipping commit is not turned into an ask by the file option.
  assert.equal(decision('git commit --no-verify -F ../x'), 'deny');
  assert.equal(decision('git add --force --pathspec-from-file ../x'), 'deny');
  // A secret file is denied, by the name scan.
  for (const cmd of ['git commit -F .env', 'git blame --contents ~/.aws/credentials -- TASKS.md', 'git commit -F ~/.ssh/id_rsa', 'git commit --file=secrets/x.txt']) {
    assert.equal(decision(cmd), 'deny', cmd);
  }
});

test('F1-57: the same git file options with a file inside the project, a message or stdin stay routine', () => {
  for (const cmd of ['git commit --allow-empty -F docs/handoff.md', 'git commit -F docs/handoff.md', 'git commit --file=docs/handoff.md', 'git commit -t docs/template.txt -m x',
    'git blame --contents docs/handoff.md -- TASKS.md', 'git blame TASKS.md', 'git blame -L 1,5 TASKS.md', 'git blame --ignore-rev abc123 TASKS.md', 'git blame -S docs/revs.txt TASKS.md',
    'git commit -F -', 'git commit -m "~ and $ in a message" --allow-empty', 'git commit -am "x"', 'git commit -m x -m "-F ../outside"', 'git commit --allow-empty-message -m ""',
    'git add docs/a.md', 'git add --pathspec-from-file=docs/paths.txt', 'git commit --pathspec-from-file=docs/paths.txt',
    'git add -- ../outside.md', 'git log --template=../x']) {
    assert.equal(decision(cmd), null, cmd);
    assert.equal(routineShell(cmd), true, cmd);
  }
});

test('F1-57: through the PreToolUse hook the record\'s git commands ask in auto mode, and a file inside the project is still routine', () => {
  const dir = project();
  try {
    for (const cmd of ['git blame --contents ~/.gitconfig -- TASKS.md', 'git commit --allow-empty -F ../sec5-outside/appsettings.json']) {
      assert.equal(hook(dir, cmd).decision, 'ask', cmd);
    }
    assert.equal(hook(dir, 'git blame --contents docs/handoff.md -- TASKS.md').decision, 'allow');
    assert.equal(hook(dir, 'git commit --allow-empty -F docs/handoff.md').decision, 'allow');
    assert.equal(hook(dir, 'git commit -F .env').decision, 'deny');
  } finally {
    cleanup(dir);
  }
});

// ---------------------------------------------------------------- F1-58: npm

const NPM_ROUTINE = [
  'npm --prefix hardening test', 'npm --prefix hardening run validate', 'npm --prefix hardening run validate:changed', 'npm --prefix hardening run validate:staged',
  'npm --prefix hardening test -- tests/guard.test.mjs', 'npm --prefix hardening test --', 'npm --prefix hardening run validate -- --changed',
  'npm --prefix hardening run validate -- --files docs/handoff.md', 'npm --prefix=hardening test', 'npm --prefix ./hardening test', 'npm --prefix hardening/ test',
  'npm.cmd --prefix hardening test', 'npm --version',
  // a redirection is the shell's, not an argument: `2>&1` and the null device stay routine, as they were
  'npm --prefix hardening test 2>&1', 'npm --prefix hardening test > /dev/null', 'npm --prefix hardening test -- tests/guard.test.mjs 2>&1', 'npm --prefix hardening run validate >$null',
];
// The record's forms and their relatives: an option after the script name, another prefix, a bare script, a paths outside.
const NPM_LOOKALIKES = [
  'npm --prefix hardening test --prefix _probe-sec5/evil', 'npm --prefix hardening run validate --prefix _probe-sec5/evil',
  'npm --prefix hardening run validate --node-options="--require ../_probe-sec5/x.cjs"', 'npm --prefix hardening run validate --node-options=--require=x.cjs',
  'npm --prefix hardening test --script-shell=x', 'npm --prefix hardening test --userconfig=x', 'npm --prefix hardening test -w x',
  'npm --prefix hardening test --workspace x', 'npm --prefix hardening test --ignore-scripts=false', 'npm --prefix hardening test x',
  'npm --prefix hardening run validate:changed --prefix x', 'npm --prefix=hardening test --prefix=x',
];
const NPM_NOT_ROUTINE = [
  ...NPM_LOOKALIKES, 'npm test --prefix _probe-sec5/evil', 'npm test', 'npm run validate', 'npm --prefix other test', 'npm --prefix hardening/tests test',
  'npm --prefix hardening run test', 'npm --prefix hardening run hooks:install', 'npm --prefix hardening run build', 'npm --prefix hardening install',
  'npm --prefix hardening test -- ~/x', 'npm --prefix hardening run validate -- --files $HOME/x', 'npm --prefix hardening run validate -- --files ../outside.md',
  'npm --prefix $X test', 'npm --prefix hardening test && npm test', 'cd docs && npm --prefix hardening test', 'npm --prefix hardening test > out.txt',
];

test('F1-58: npm is routine only as `--prefix hardening test` or `run validate[:name]`, with script arguments after "--" that stay inside the project', () => {
  for (const cmd of NPM_ROUTINE) {
    assert.equal(routineShell(cmd), true, cmd);
    assert.equal(decision(cmd), null, cmd);
  }
  for (const cmd of NPM_NOT_ROUTINE) assert.equal(routineShell(cmd), false, cmd);
  // The output of a test run kept in a file is not routine (a redirect into a file), and it is no ask either (tests/redteam.test.mjs).
  assert.equal(routineShell('npm --prefix hardening test > test-output.log'), false);
  assert.equal(decision('npm --prefix hardening test > test-output.log'), null);
  assert.equal(decision('node hardening/scripts/validate.mjs --changed > validation.log'), null);
});

test('F1-58: an npm command that starts like the harness\'s own but carries more is an ask; a path outside the project after "--" is one too', () => {
  for (const cmd of NPM_LOOKALIKES) {
    const v = shell(cmd);
    assert.equal(v?.decision, 'ask', cmd);
    assert.equal(v.autoApprovable, false, cmd);
    assert.match(v.reason, /changes the package or the program npm runs/, cmd);
  }
  for (const cmd of ['npm --prefix hardening test -- ~/x', 'npm --prefix hardening run validate -- --files $HOME/x', 'npm --prefix hardening run validate -- --files ../outside.md']) {
    const v = shell(cmd);
    assert.equal(v?.decision, 'ask', cmd);
    assert.equal(v.autoApprovable, false, cmd);
    assert.match(v.reason, /reads the files named on its command line/, cmd);
  }
  // Other npm commands keep their own rules (Claude Code's ask rules): no verdict of the guard.
  for (const cmd of ['npm test', 'npm --prefix other test', 'npm install', 'npm ls']) assert.equal(decision(cmd), null, cmd);
});

test('F1-58: through the hook the record\'s forms are not allowed, even where an install still carries the old broad allow rules', () => {
  // The rules an install made before the fix carries (`--update` adds new rules and keeps the user's): they run the record's forms.
  const old = { permissions: { allow: ['Bash(npm --prefix hardening test *)', 'Bash(npm --prefix hardening run validate *)', 'PowerShell(npm --prefix hardening test *)',
    'PowerShell(npm --prefix hardening run validate *)'] } };
  const dir = project({ settings: old });
  // The pack's own rules: their `-- *` forms and `node hardening/scripts/validate.mjs *` cannot judge a path, so the guard asks.
  const fresh = project({ settings: { permissions: shipped.permissions } });
  try {
    for (const cmd of ['npm --prefix hardening test --prefix _probe-sec5/evil', 'npm --prefix hardening run validate --node-options="--require ../_probe-sec5/x.cjs"']) {
      for (const tool of ['Bash', 'PowerShell']) assert.equal(hook(dir, cmd, { tool }).decision, 'ask', `${tool}: ${cmd}`);
    }
    for (const cmd of ['npm test --prefix _probe-sec5/evil', 'node _probe-sec5/x.cjs']) assert.notEqual(hook(dir, cmd).decision, 'allow', cmd);
    for (const cmd of ['npm --prefix hardening test', 'npm --prefix hardening run validate', 'npm --prefix hardening test -- tests/guard.test.mjs']) {
      assert.equal(hook(dir, cmd).decision, 'allow', cmd);
    }
    for (const cmd of ['npm --prefix hardening test -- ~/x', 'npm --prefix hardening run validate -- --files ../outside.md', 'node hardening/scripts/validate.mjs --files ~/.claude.json',
      'node hardening/scripts/rdl-compare.mjs a.rdl ../outside.rdl', 'npm --prefix hardening test --prefix _probe-sec5/evil']) {
      for (const tool of ['Bash', 'PowerShell']) assert.equal(hook(fresh, cmd, { tool }).decision, 'ask', `shipped rules, ${tool}: ${cmd}`);
    }
  } finally {
    cleanup(dir);
    cleanup(fresh);
  }
});

test('F1-58: the shipped allow rules cover exactly the documented npm forms and answer none of the record\'s', () => {
  for (const tool of ['Bash', 'PowerShell']) {
    for (const cmd of DOCUMENTED) assert.equal(rulesVerdict(shipped.permissions, tool, cmd), 'allow', `${tool}: ${cmd}`);
    // The rules read text: a path after "--" is the one thing they cannot judge (the guard asks for one outside the project, F1-57).
    for (const cmd of NPM_NOT_ROUTINE.filter((c) => /^npm/.test(c) && !/&&|>| -- /.test(c))) {
      for (const permissions of [shipped.permissions, own?.permissions]) {
        assert.notEqual(rulesVerdict(permissions, tool, cmd), 'allow', `${tool}: ${cmd}`);
      }
    }
    // Every allow rule of the pack, expanded with the options of the record, is no longer answered allow.
    for (const rule of shipped.permissions.allow.filter((r) => r.startsWith(`${tool}(npm `))) {
      const base = /^\w+\((.*?)(?: \*)?\)$/.exec(rule)[1].replace(/ --$/, '');
      for (const extra of ['--prefix x', '--node-options=--require=x.cjs', '--script-shell=x', '-w x']) {
        assert.notEqual(rulesVerdict(shipped.permissions, tool, `${base} ${extra}`), 'allow', `${tool}: ${base} ${extra}`);
      }
    }
  }
  // Every form of the pack's rules is routine for the guard too: the rules and the guard say the same.
  for (const rule of shipped.permissions.allow.filter((r) => /^Bash\(npm /.test(r))) {
    const cmd = /^Bash\((.*)\)$/.exec(rule)[1].replace(/ \*$/, ' x');
    assert.equal(routineShell(cmd), true, `${rule} -> ${cmd}`);
  }
});

test('F1-58: every `npm --prefix hardening ...` form the docs and agent files name is routine and allowed by the shipped rules', (t) => {
  const files = [];
  const walk = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (entry.name === 'node_modules' || entry.name === '.git' || entry.name === 'worktrees') continue;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.name.endsWith('.md')) files.push(full);
    }
  };
  for (const rel of ['docs', '.claude', '.github']) if (fs.existsSync(path.join(repo, rel))) walk(path.join(repo, rel));
  for (const rel of ['README.md', 'AGENTS.md', 'hardening/README.md', 'hardening/REFERENCE.md']) if (fs.existsSync(path.join(repo, rel))) files.push(path.join(repo, rel));
  const found = new Set();
  for (const file of files) {
    for (const m of fs.readFileSync(file, 'utf8').matchAll(/npm --prefix hardening (test|run validate(?::[\w-]+)?)(?![\w:-])/g)) found.add(`npm --prefix hardening ${m[1]}`);
  }
  if (!found.size) return t.skip('no document of this checkout names an npm form');
  for (const cmd of found) {
    assert.equal(routineShell(cmd), true, cmd);
    for (const tool of ['Bash', 'PowerShell']) {
      // run validate:changed and the like are covered by the guard's routine rule; the rules carry the two documented bare forms.
      if (!/validate:/.test(cmd)) assert.equal(rulesVerdict(shipped.permissions, tool, cmd), 'allow', `${tool}: ${cmd}`);
    }
  }
});

test('F1-58: a read-only subagent may run the exact npm checks, and no npm option in front of the script', () => {
  const dir = project();
  try {
    for (const cmd of ['npm --prefix hardening test', 'npm --prefix hardening run validate', 'npm --prefix hardening run validate:changed', 'npm test',
      'npm --prefix hardening test -- tests/guard.test.mjs', 'npm --prefix hardening run validate -- --changed', 'node hardening/scripts/validate.mjs --changed']) {
      assert.equal(scope(dir, cmd), null, cmd);
    }
    for (const cmd of ['npm --prefix hardening test --prefix evil', 'npm --prefix hardening run validate --node-options=--require=x.cjs', 'npm test --script-shell=x',
      'npm --prefix hardening test -w x', 'npm --prefix hardening test x']) {
      assert.equal(scope(dir, cmd), 'deny', cmd);
    }
  } finally {
    cleanup(dir);
  }
});

// ---------------------------------------------------------------- F2-1: git grep -O

const PAGER_DENIED = [
  'git grep -O"echo PAGER-RAN" one', 'git grep -Oecho one', 'git grep -O one', 'git grep -nO"echo x" one', 'git grep -inOcmd x', 'git grep -n -O"echo x" one',
  'git grep --open-files-in-pager="echo x" one', 'git grep --open-files-in-pager=x one', 'git grep --open-files-in-pager one', 'git grep --open-f="echo x" one',
  'git grep --open one', 'git grep --op=x one', 'git grep --o x one', 'git grep -e x -O one', 'git -C docs grep -Oecho x', 'git --no-pager grep -O x',
  'git grep -O"fab deploy x" foo', 'git grep -O"curl -s x" foo', 'GIT_PAGER=x git grep -O y',
];
const PAGER_QUIET = [
  'git grep -e Order TASKS.md', 'git grep -n Order TASKS.md', 'git grep -eOrder TASKS.md', 'git grep --only-matching Order TASKS.md', 'git grep -on Order TASKS.md',
  'git grep -e x --or -e y', 'git grep --no-open-files-in-pager x', 'git grep x -- -Ofile', 'git grep -m1 Ox', 'git grep -C3 Ordered', 'git grep -An1 O', 'git grep -l Order',
  'git log --grep=-O', 'git commit -m "git grep -O x"',
];

test('F2-1: git grep -O<cmd> and --open-files-in-pager[=<cmd>] run a program: denied under every spelling, never routine', () => {
  for (const cmd of PAGER_DENIED) {
    const v = shell(cmd);
    assert.equal(v?.decision, 'deny', cmd);
    assert.equal(routineShell(cmd), false, cmd);
  }
  assert.match(shell('git grep --open-files-in-pager="echo x" one').reason, /run a program/);
  for (const cmd of PAGER_QUIET) {
    assert.equal(decision(cmd), null, cmd);
    assert.equal(routineShell(cmd), true, cmd);
  }
});

test('F2-1: through the hook the record\'s command is denied in auto, ask and lab mode, and a plain git grep stays routine', () => {
  const dirs = ['auto', 'ask', 'lab'].map((mode) => [mode, project({ config: { approvals: { mode } } })]);
  try {
    for (const [mode, dir] of dirs) {
      for (const tool of ['Bash', 'PowerShell']) {
        assert.equal(hook(dir, 'git grep -O"echo PAGER-RAN" one', { tool }).decision, 'deny', `${mode} ${tool}`);
        assert.equal(hook(dir, 'git grep --open-files-in-pager="echo x" one', { tool }).decision, 'deny', `${mode} ${tool}`);
      }
    }
    assert.equal(hook(dirs[0][1], 'git grep -n Order TASKS.md').decision, 'allow');
  } finally {
    for (const [, dir] of dirs) cleanup(dir);
  }
});

// ---------------------------------------------------------------- check-hooks.mjs

test('check-hooks.mjs is one of the pack\'s own checks: routine as the whole command, with no argument and no redirect', () => {
  for (const cmd of ['node hardening/scripts/check-hooks.mjs', 'node ./hardening/scripts/check-hooks.mjs', 'node hardening/scripts/check-hooks.mjs; git status']) {
    assert.equal(decision(cmd), null, cmd);
    assert.equal(routineShell(cmd), true, cmd);
  }
  for (const cmd of ['node hardening/scripts/check-hooks.mjs --x', 'node hardening/scripts/check-hooks.mjs docs', 'node hardening/scripts/check-hooks.mjs > out.txt',
    'node hardening/scripts/check-hooks.mjs | node', 'node hardening/scripts/check-hooks.mjs && git push', 'node hardening/scripts/check-hooks.mjs ~/x',
    'node hardening/scripts/../scripts/check-hooks.mjs --x', 'node hardening/scripts/check-hook.mjs', 'node hardening/scripts/check-hooks.mjs.bak']) {
    assert.equal(routineShell(cmd), false, cmd);
  }
  assert.equal(decision('node hardening/scripts/check-hooks.mjs ~/x'), 'ask', 'a path outside the project after any harness script asks');
  assert.equal(decision('node hardening/scripts/check-hooks.mjs.bak')?.length > 0, true, 'another file is an ordinary script run: it asks');
  const dir = project();
  try {
    for (const tool of ['Bash', 'PowerShell']) {
      const v = hook(dir, 'node hardening/scripts/check-hooks.mjs', { tool });
      assert.equal(v.decision, 'allow', tool);
      assert.match(v.reason, /routine command/, tool);
      assert.notEqual(hook(dir, 'node hardening/scripts/check-hooks.mjs --x', { tool }).decision, 'allow', tool);
      assert.notEqual(hook(dir, 'node hardening/scripts/check-hooks.mjs > out.txt', { tool }).decision, 'allow', tool);
    }
  } finally {
    cleanup(dir);
  }
});

test('check-hooks.mjs: a read-only subagent may run it alone; with an argument, a redirect or a second command it is neither a check nor allowed', () => {
  const dir = project();
  try {
    for (const agent of ['bi-validator', 'bi-dax-reviewer', 'bi-security-auditor']) {
      assert.equal(scope(dir, 'node hardening/scripts/check-hooks.mjs', agent), null, agent);
      assert.equal(scope(dir, 'node hardening\\scripts\\check-hooks.mjs', agent), null, `${agent}: backslashes`);
      assert.equal(scope(dir, 'node ./hardening/scripts/check-hooks.mjs', agent), null, `${agent}: ./`);
      for (const cmd of ['node hardening/scripts/check-hooks.mjs --x', 'node hardening/scripts/check-hooks.mjs > out.txt', 'node hardening/scripts/check-hooks.mjs && git commit -m x',
        'node hardening/scripts/check-hooks.mjs\nrm notes.txt', 'node hardening/scripts/check-hooks.mjs | tee out.txt', 'node ../hardening/scripts/check-hooks.mjs', 'node hardening/scripts/check-hooks.mjs.bak']) {
        assert.equal(scope(dir, cmd, agent), 'deny', `${agent}: ${JSON.stringify(cmd)}`);
      }
    }
    assert.equal(scope(dir, 'node hardening/scripts/check-hooks.mjs', 'general-purpose'), null, 'an agent without a scope is not limited here');
  } finally {
    cleanup(dir);
  }
});

test('check-hooks.mjs: the shipped allow rules name the exact command for both shell tools and no argument form', () => {
  for (const tool of ['Bash', 'PowerShell']) {
    assert.ok(shipped.permissions.allow.includes(`${tool}(node hardening/scripts/check-hooks.mjs)`), `${tool}: the exact rule`);
    assert.equal(rulesVerdict(shipped.permissions, tool, 'node hardening/scripts/check-hooks.mjs'), 'allow', tool);
    for (const cmd of ['node hardening/scripts/check-hooks.mjs --x', 'node hardening/scripts/check-hooks.mjs ~/x']) {
      assert.notEqual(rulesVerdict(shipped.permissions, tool, cmd), 'allow', `${tool}: ${cmd}`);
    }
  }
});
