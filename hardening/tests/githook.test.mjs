// Git hook runner (scripts/githook.mjs, called by the shims in hardening/githooks/), audit F1-109: pre-commit validates
// the staged content, commit-msg enforces Conventional Commits, pre-push blocks direct pushes to protected branches.
// Each case runs in a temporary repository; the last test goes through the shims with a real `git commit` and
// `git push`. Fake credentials are joined at run time, so this file holds none.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const pack = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const runner = path.join(pack, 'scripts', 'githook.mjs');

// Variables that point git at another repository, index or object store: a `git commit` hook that runs these tests
// exports GIT_INDEX_FILE (and GIT_DIR in some setups), which would send the temporary repositories' git calls elsewhere.
const GIT_REPO_VARS = new Set(['GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE', 'GIT_OBJECT_DIRECTORY', 'GIT_ALTERNATE_OBJECT_DIRECTORIES', 'GIT_COMMON_DIR', 'GIT_PREFIX']);
const gitEnv = () => Object.fromEntries(Object.entries(process.env).filter(([k]) => !GIT_REPO_VARS.has(k.toUpperCase())));
const email = ['t', 'example.invalid'].join('@');
const fakeCredential = () => ['Pass', 'word=', 'Hunt', 'er2', 'Xyz'].join('');

const git = (dir, ...args) => spawnSync('git', ['-c', 'user.name=t', '-c', `user.email=${email}`, '-c', 'commit.gpgsign=false', ...args], { cwd: dir, env: gitEnv(), encoding: 'utf8' });
const write = (dir, rel, text) => {
  fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
  fs.writeFileSync(path.join(dir, rel), text);
};
/** Runs the hook runner as the shims do, from the repository root, with the repository as the project. */
const hook = (dir, args, input = '') => spawnSync(process.execPath, [runner, ...args], { cwd: dir, env: { ...gitEnv(), CLAUDE_PROJECT_DIR: dir }, input, encoding: 'utf8' });

function withRepo(fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-githook-'));
  try {
    assert.equal(git(dir, 'init', '-q').status, 0);
    return fn(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

test('githook commit-msg: Conventional Commits pass, other subjects fail; comment lines are skipped; a missing file fails closed', () => {
  withRepo((dir) => {
    const msg = path.join(dir, '.git', 'COMMIT_EDITMSG');
    const cases = [
      ['fix stuff\n', 1],
      ['feat(model): add Sales YoY % measure\n', 0],
      ['fix(harness)!: drop the old switch\n', 0],
      ['docs: explain the release check\n\nA body line that is free text.\n', 0],
      ["Merge branch 'feature/x'\n", 0],
      ['Revert "feat(model): add x"\n', 0],
      ['fixup! feat(model): add x\n', 0],
      ['squash! feat(model): add x\n', 0],
      ['# Please enter the commit message.\n# Lines starting with # are ignored.\nfeat(report): add a page\n', 0],
      ['# only comments\n', 1],
      ['\n\n', 1],
      ['Feat: capitalised type\n', 1],
      ['feat(Model): upper-case scope\n', 1],
      ['feat:no space\n', 1],
      ['feat: ab\n', 1], // the summary needs three characters
      ['wip(model): add x\n', 1], // an unknown type
    ];
    for (const [text, expected] of cases) {
      fs.writeFileSync(msg, text);
      const r = hook(dir, ['commit-msg', msg]);
      assert.equal(r.status, expected, `${JSON.stringify(text)}: ${r.stderr}`);
      if (expected) assert.match(r.stderr, /is not a Conventional Commit/);
    }
    const missing = hook(dir, ['commit-msg', path.join(dir, '.git', 'NO_SUCH_FILE')]);
    assert.equal(missing.status, 1, 'a hook that cannot read the message lets nothing through');
    assert.match(missing.stderr, /^githook commit-msg: /m);
  });
});

test('githook pre-commit: a staged credential, invalid JSON or secret file blocks the commit; the staged content counts, not the working copy', () => {
  withRepo((dir) => {
    const secret = fakeCredential();
    write(dir, 'docs/a.md', '# A\n');
    git(dir, 'add', 'docs/a.md');
    let r = hook(dir, ['pre-commit']);
    assert.equal(r.status, 0, r.stdout + r.stderr);

    // The working copy gets a credential after staging: the commit takes the staged text, so it passes.
    write(dir, 'docs/a.md', `# A\nServer=x;${secret};\n`);
    r = hook(dir, ['pre-commit']);
    assert.equal(r.status, 0, `only the staged content is checked: ${r.stdout}${r.stderr}`);
    git(dir, 'add', 'docs/a.md');
    write(dir, 'docs/a.md', '# A\n'); // and the reverse: a clean working copy does not hide a staged credential
    r = hook(dir, ['pre-commit']);
    assert.equal(r.status, 1, r.stdout + r.stderr);
    assert.match(r.stdout, /^ERROR docs\/a\.md:2 — Possible credential \(password-assignment/m);
    assert.match(r.stderr, /The BI harness blocks this commit/);
    assert.ok(!`${r.stdout}${r.stderr}`.includes(secret), 'the credential is masked in the report');
    git(dir, 'reset', '-q', 'docs/a.md');

    write(dir, 'docs/x.json', '{"a": ');
    git(dir, 'add', 'docs/x.json');
    r = hook(dir, ['pre-commit']);
    assert.equal(r.status, 1, r.stdout + r.stderr);
    assert.match(r.stdout, /^ERROR docs\/x\.json — Invalid JSON/m);
    git(dir, 'reset', '-q', 'docs/x.json');

    write(dir, '.env', 'X=1\n');
    git(dir, 'add', '-f', '.env');
    r = hook(dir, ['pre-commit']);
    assert.equal(r.status, 1, r.stdout + r.stderr);
    assert.match(r.stdout, /^ERROR \.env — Staged file must never be committed/m);
  });
});

// F1-107: scan.exclude keeps the vendored references, the test fixtures and the worktrees out of the full scan's
// structure checks; a staged file in those folders is still checked for credentials before it is committed.
test('githook pre-commit: a credential staged in a scan.exclude folder blocks the commit; its structure is still not checked', () => {
  withRepo((dir) => {
    const secret = fakeCredential();
    for (const rel of ['hardening/tests/fixtures/conn.md', '.claude/skills/bi-semantic-model/references/conn.md']) {
      write(dir, rel, `Server=prod-sql;User Id=svc;${secret};\n`);
      git(dir, 'add', rel);
      const r = hook(dir, ['pre-commit']);
      assert.equal(r.status, 1, `${rel}: ${r.stdout}${r.stderr}`);
      assert.match(r.stdout, new RegExp(`^ERROR ${rel.replace(/[.]/g, '\\.')}:1 — Possible credential \\(password-assignment`, 'm'));
      assert.ok(!r.stdout.includes(secret), 'masked');
      git(dir, 'reset', '-q', rel);
    }
    // Structure checks stay off there: invalid JSON and a long Markdown file in a fixture folder pass.
    write(dir, 'hardening/tests/fixtures/broken.json', '{"a": ');
    write(dir, 'hardening/tests/fixtures/long.md', Array.from({ length: 600 }, (_, i) => `line ${i}\n`).join(''));
    git(dir, 'add', 'hardening/tests/fixtures/broken.json', 'hardening/tests/fixtures/long.md');
    const r = hook(dir, ['pre-commit']);
    assert.equal(r.status, 0, r.stdout + r.stderr);
  });
});

test('githook pre-push: main and master are blocked, a feature branch passes, and the configured list replaces the default', () => {
  withRepo((dir) => {
    const sha = 'a'.repeat(40);
    const zero = '0'.repeat(40);
    const line = (remote) => `refs/heads/feature ${sha} ${remote} ${zero}\n`;
    for (const [input, expected] of [
      [line('refs/heads/main'), 1],
      [line('refs/heads/master'), 1],
      [line('refs/heads/feature'), 0],
      [`${line('refs/heads/feature')}${line('refs/heads/main')}`, 1], // any line counts
      [line('refs/tags/v1'), 0],
      ['', 0], // nothing to push
    ]) {
      const r = hook(dir, ['pre-push', 'origin', 'https://example.com/r.git'], input);
      assert.equal(r.status, expected, `${JSON.stringify(input)}: ${r.stderr}`);
      if (expected) assert.match(r.stderr, /^pre-push: direct push to 'ma(?:in|ster)' is blocked by the BI harness/m);
    }
    write(dir, 'hardening/harness.config.json', JSON.stringify({ git: { protectedBranches: ['release'] } }));
    assert.equal(hook(dir, ['pre-push', 'origin', 'x'], line('refs/heads/release')).status, 1, 'a configured branch is protected');
    assert.equal(hook(dir, ['pre-push', 'origin', 'x'], line('refs/heads/main')).status, 0, 'the configured list replaces main and master');
  });
});

test('githook: an unknown or missing command exits 2', () => {
  withRepo((dir) => {
    for (const args of [['bogus'], []]) {
      const r = hook(dir, args);
      assert.equal(r.status, 2, JSON.stringify(args));
      assert.match(r.stderr, /^githook: unknown command/m);
    }
  });
});

// The shims as Git runs them: core.hooksPath set, the pack laid out as the installer does, no CLAUDE_PROJECT_DIR (a
// person committing in a terminal), the project found from the pack's own location.
test('githook: through the shims, git refuses a non-conventional message, a staged credential and a push to main', () => {
  withRepo((dir) => {
    for (const folder of ['githooks', 'scripts', 'hooks']) fs.cpSync(path.join(pack, folder), path.join(dir, 'hardening', folder), { recursive: true });
    for (const shim of ['pre-commit', 'commit-msg', 'pre-push']) fs.chmodSync(path.join(dir, 'hardening', 'githooks', shim), 0o755);
    fs.appendFileSync(path.join(dir, '.git', 'info', 'exclude'), '\nhardening/\n');
    const env = gitEnv();
    delete env.CLAUDE_PROJECT_DIR;
    const g = (...args) => spawnSync('git', ['-c', 'user.name=t', '-c', `user.email=${email}`, '-c', 'commit.gpgsign=false', '-c', 'core.hooksPath=hardening/githooks', ...args], { cwd: dir, env, encoding: 'utf8' });
    const count = () => Number(g('rev-list', '--count', '--all').stdout.trim() || 0);

    write(dir, 'docs/a.md', '# A\n');
    g('add', 'docs/a.md');
    let r = g('commit', '-q', '-m', 'fix stuff');
    assert.notEqual(r.status, 0, 'commit-msg refuses the subject');
    assert.match(r.stderr, /commit-msg: "fix stuff" is not a Conventional Commit/);
    assert.equal(count(), 0);
    r = g('commit', '-q', '-m', 'docs(harness): add a note');
    assert.equal(r.status, 0, r.stderr);
    assert.equal(count(), 1);

    write(dir, 'docs/conn.md', `Server=x;${fakeCredential()};\n`);
    g('add', 'docs/conn.md');
    r = g('commit', '-q', '-m', 'docs(harness): add a connection');
    assert.notEqual(r.status, 0, 'pre-commit refuses the staged credential');
    assert.match(`${r.stdout}${r.stderr}`, /Possible credential/);
    assert.equal(count(), 1);
    g('reset', '-q', 'docs/conn.md');

    const remote = `${dir}-remote.git`;
    try {
      assert.equal(spawnSync('git', ['init', '-q', '--bare', remote], { env, encoding: 'utf8' }).status, 0);
      r = g('push', '-q', remote, 'HEAD:refs/heads/main');
      assert.notEqual(r.status, 0, 'pre-push refuses main');
      assert.match(r.stderr, /pre-push: direct push to 'main' is blocked/);
      r = g('push', '-q', remote, 'HEAD:refs/heads/feature/x');
      assert.equal(r.status, 0, r.stderr);
    } finally {
      fs.rmSync(remote, { recursive: true, force: true });
    }
  });
});
