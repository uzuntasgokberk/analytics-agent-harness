// Open findings 2026-11-17, two rules outside the guard's own file checks.
// D. The deny rules of .claude/settings.json named Read(.env) and Read(.env.*), which match no .envrc, and nothing for
//    .credentials.json: Claude Code without the pack (and the Copilot mirror of the deny rules) let a Read of either pass.
// E. The protected-branch note of the guard (an edit of PBIP files) and the session banner compared the checked-out branch
//    with the protected branches in exact case. On Windows and macOS a checkout of MAIN is main (one loose ref file), and
//    the shell policy compares without case (policy.mjs, isProtectedBranch); both notes now do too, on every platform.
// The fixtures set HEAD with `git symbolic-ref` on an unborn branch, so no test depends on the case of the file system.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ruleMatches } from '../hooks/lib/permissions.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const hooks = path.join(here, '..', 'hooks');
const settingsFile = path.join(here, '..', '..', '.claude', 'settings.json');

// Variables that point git at another repository (a commit hook that runs the tests exports GIT_INDEX_FILE), and the
// developer's global and system configuration: the temporary repositories' git calls stay in them.
const GIT_REPO_VARS = new Set(['GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE', 'GIT_OBJECT_DIRECTORY', 'GIT_ALTERNATE_OBJECT_DIRECTORIES', 'GIT_COMMON_DIR', 'GIT_PREFIX']);
const gitEnv = () => ({
  ...Object.fromEntries(Object.entries(process.env).filter(([k]) => !GIT_REPO_VARS.has(k.toUpperCase()))),
  GIT_CONFIG_GLOBAL: path.join(os.tmpdir(), 'bi-harness-open-rules-no-global-gitconfig'),
  GIT_CONFIG_NOSYSTEM: '1',
});
const gitIn = (dir, ...args) => {
  const r = spawnSync('git', args, { cwd: dir, env: gitEnv(), encoding: 'utf8' });
  assert.equal(r.status, 0, `git ${args.join(' ')}: ${r.stderr}`);
};

// ---------------------------------------------------------------- D. the Read deny rules of .claude/settings.json

test('D: the deny rules of .claude/settings.json match a Read of .envrc in any folder and of .credentials.json', (t) => {
  if (!fs.existsSync(settingsFile)) return t.skip('no .claude/settings.json next to this harness');
  const deny = JSON.parse(fs.readFileSync(settingsFile, 'utf8')).permissions.deny;
  const root = path.join(os.tmpdir(), 'bi-harness-open-rules-project');
  const denied = (rel) => deny.some((rule) => ruleMatches(rule, 'Read', { targets: [`${root.replace(/\\/g, '/')}/${rel}`] }, root));
  for (const rel of ['.envrc', 'app/.envrc', '.claude/.credentials.json', 'x/y/.credentials.json']) assert.ok(denied(rel), `Read ${rel} is denied`);
  // The new rules stand next to Read(.env) and Read(.env.*), in the style of their neighbours.
  const at = deny.indexOf('Read(.env.*)');
  assert.ok(at >= 0, 'Read(.env.*) is there');
  for (const rule of ['Read(.envrc)', 'Read(**/.envrc)', 'Read(**/.credentials.json)']) {
    assert.ok(deny.includes(rule), rule);
    assert.ok(Math.abs(deny.indexOf(rule) - at) <= 4, `${rule} stands next to Read(.env.*)`);
  }
  // What must stay: files that only look alike are not denied by these rules.
  for (const rel of ['docs/envrc.md', 'app/.envrc.md', 'credentials.json.md', 'docs/a.md']) assert.ok(!denied(rel), `Read ${rel} is not denied`);
});

// ---------------------------------------------------------------- E. the protected branch in another case

/** A temporary Git repository with an existing PBIP report page (HEAD set by the test, unborn) and an empty home folder. */
function withRepo(fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-open-rules-'));
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-open-rules-home-'));
  try {
    const page = path.join(dir, 'Sales.Report', 'definition', 'pages', 'p1', 'page.json');
    fs.mkdirSync(path.dirname(page), { recursive: true });
    fs.writeFileSync(page, '{"name":"p1","displayName":"Page 1"}\n');
    gitIn(dir, 'init', '-q');
    homes.set(dir, home);
    return fn(dir, page);
  } finally {
    homes.delete(dir);
    fs.rmSync(dir, { recursive: true, force: true });
    fs.rmSync(home, { recursive: true, force: true });
  }
}
const homes = new Map();
let sessions = 0;
/** Runs a hook in `dir` as Claude Code does, with no user settings; returns hookSpecificOutput.additionalContext ('' when there is none). */
function contextOf(dir, script, payload) {
  const env = { ...gitEnv(), CLAUDE_PROJECT_DIR: dir, HOME: homes.get(dir), USERPROFILE: homes.get(dir) };
  delete env.BI_HARNESS_HOST;
  delete env.COPILOT_CLI;
  const r = spawnSync(process.execPath, [path.join(hooks, script)], {
    input: JSON.stringify({ session_id: `open-rules-${process.pid}-${++sessions}`, cwd: dir, ...payload }),
    env,
    encoding: 'utf8',
  });
  assert.equal(r.status, 0, r.stderr);
  return r.stdout.trim() ? JSON.parse(r.stdout).hookSpecificOutput?.additionalContext ?? '' : '';
}
const banner = (dir) => contextOf(dir, 'session-start.mjs', { hook_event_name: 'SessionStart', source: 'startup' });
const pageEdit = (dir, page) => contextOf(dir, 'pre-tool-use.mjs', {
  hook_event_name: 'PreToolUse', tool_name: 'Write', tool_input: { file_path: page, content: '{"name":"p1","displayName":"Sales"}\n' },
});
const NOTE = (branch) => new RegExp(`You are editing PBIP files on protected branch '${branch}'\\. Create a feature branch before committing`);
const BANNER = (branch) => new RegExp(`- On protected branch '${branch}': create a feature branch before editing`);

test('E: on a protected branch checked out in another case the banner and the PBIP edit note warn, naming the branch as checked out', () => {
  withRepo((dir, page) => {
    for (const branch of ['MAIN', 'Main', 'Master']) {
      gitIn(dir, 'symbolic-ref', 'HEAD', `refs/heads/${branch}`);
      assert.match(banner(dir), BANNER(branch), `banner on ${branch}`);
      assert.match(pageEdit(dir, page), NOTE(branch), `PBIP edit note on ${branch}`);
    }
  });
});

test('must stay: main warns in both places, a feature branch in neither (passes before and after the fix)', () => {
  withRepo((dir, page) => {
    gitIn(dir, 'symbolic-ref', 'HEAD', 'refs/heads/main');
    assert.match(banner(dir), BANNER('main'));
    assert.match(pageEdit(dir, page), NOTE('main'));
    for (const branch of ['feature/x', 'mainline', 'feature/main']) {
      gitIn(dir, 'symbolic-ref', 'HEAD', `refs/heads/${branch}`);
      assert.doesNotMatch(banner(dir), /On protected branch/, `banner on ${branch}`);
      assert.doesNotMatch(pageEdit(dir, page), /protected branch/, `PBIP edit note on ${branch}`);
    }
  });
});
