// Audit 2026-11-16, finding 5, the validator's side. direnv's .envrc and Claude Code's .credentials.json joined the secret
// names so that the guards keep the agent out of them. classifyPath's `secret` is also the validator's "must never be
// committed" (tracked files in a full scan, staged files in --staged: the pre-commit hook, the Stop gate's full scan, CI),
// and projects commit a .envrc on purpose (`use flake`, `layout python`, `dotenv`, no credential): those two checks keep the
// verdict they gave it before, none. A .credentials.json is a credential store by name and is reported there like .env.
// The validator runs as a process against temporary Git repositories; every value is a fake built at run time.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const cli = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'scripts', 'validate.mjs');

// Variables that point git at another repository, index or object store (a `git commit` hook that runs these tests exports
// GIT_INDEX_FILE): stripped, so the temporary repositories' git calls stay in them.
const GIT_REPO_VARS = new Set(['GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE', 'GIT_OBJECT_DIRECTORY', 'GIT_ALTERNATE_OBJECT_DIRECTORIES', 'GIT_COMMON_DIR', 'GIT_PREFIX']);
const gitEnv = () => Object.fromEntries(Object.entries(process.env).filter(([k]) => !GIT_REPO_VARS.has(k.toUpperCase())));
const email = ['t', 'example.com'].join('@');
const SECRET = ['S3cr3t', 'Pa55w0rd'].join('');

const git = (dir, ...args) => {
  const r = spawnSync('git', ['-c', 'user.name=t', '-c', `user.email=${email}`, '-c', 'commit.gpgsign=false', '-c', 'core.autocrlf=false', ...args], { cwd: dir, env: gitEnv(), encoding: 'utf8' });
  assert.equal(r.status, 0, `git ${args.join(' ')}: ${r.stderr}`);
  return r;
};
const write = (dir, rel, text) => {
  fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
  fs.writeFileSync(path.join(dir, rel), text);
};
/** The validator's JSON report for one run, as the pre-commit hook and CI run it: the repository is the project. */
function validate(dir, ...args) {
  const r = spawnSync(process.execPath, [cli, ...args, '--json'], { cwd: dir, env: { ...gitEnv(), CLAUDE_PROJECT_DIR: dir }, encoding: 'utf8' });
  assert.ok(r.status === 0 || r.status === 1, `validate ${args.join(' ')} did not run: ${r.stdout}${r.stderr}`);
  return { status: r.status, issues: JSON.parse(r.stdout).issues, out: r.stdout + r.stderr };
}
function withRepo(fn) {
  // The real path: index-view compares Git's top-level with the project path, which must not be an 8.3 short name.
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-1116v-')));
  try {
    git(dir, 'init', '-q');
    return fn(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}
const issuesOf = (report, file) => report.issues.filter((i) => i.file === file);
const filesWith = (report, re) => report.issues.filter((i) => i.level === 'error' && re.test(i.message)).map((i) => i.file).sort();
const STAGED = /^Staged file must never be committed/;
const TRACKED = /^Tracked in git but must never be committed/;
// Credential stores by name or by place: refused when staged, reported when tracked. secrets/.envrc is a secret by its folder.
const FORBIDDEN = ['.credentials.json', '.env', 'sub/credentials.json', 'secrets/.envrc'];

test('finding 5: a project that commits .envrc passes --staged and the full scan, with no issue for the file', () => {
  withRepo((dir) => {
    write(dir, '.envrc', 'use flake\n');
    write(dir, 'app/.envrc', 'layout python\n');
    write(dir, 'docs/a.md', '# A\n');
    git(dir, 'add', '-f', '.envrc', 'app/.envrc', 'docs/a.md');
    const staged = validate(dir, '--staged');
    for (const rel of ['.envrc', 'app/.envrc']) assert.deepEqual(issuesOf(staged, rel), [], `--staged ${rel}: ${staged.out}`);
    assert.equal(staged.status, 0, staged.out);

    git(dir, 'commit', '-q', '--no-verify', '-m', 'chore: direnv');
    const full = validate(dir);
    for (const rel of ['.envrc', 'app/.envrc']) assert.deepEqual(issuesOf(full, rel), [], `full scan ${rel}: ${full.out}`);
    assert.equal(full.status, 0, full.out);
  });
});

test('finding 5: a staged or tracked .credentials.json is refused like .env and credentials.json; .envrc beside them is not', () => {
  withRepo((dir) => {
    write(dir, '.envrc', 'use flake\n');
    write(dir, '.credentials.json', '{}\n');
    write(dir, '.env', 'FAKE=not-a-secret\n');
    write(dir, 'sub/credentials.json', '{}\n');
    write(dir, 'secrets/.envrc', 'use flake\n');
    git(dir, 'add', '-f', '.envrc', ...FORBIDDEN);
    const staged = validate(dir, '--staged');
    assert.equal(staged.status, 1, staged.out);
    assert.deepEqual(filesWith(staged, STAGED), [...FORBIDDEN].sort(), staged.out);
    assert.deepEqual(issuesOf(staged, '.envrc'), [], staged.out);

    git(dir, 'commit', '-q', '--no-verify', '-m', 'chore: track by mistake');
    const full = validate(dir);
    assert.equal(full.status, 1, full.out);
    assert.deepEqual(filesWith(full, TRACKED), [...FORBIDDEN].sort(), full.out);
    assert.deepEqual(issuesOf(full, '.envrc'), [], full.out);
  });
});

test('finding 5: a staged .envrc that holds a credential-shaped value is reported like the same line in another text file (since 2026-11-17 the text of a .envrc git tracks, stages or would add is scanned)', () => {
  withRepo((dir) => {
    const text = `export API_KEY=${SECRET}\n`;
    write(dir, '.envrc', text);
    // The same line in a text file the validator reads: the value is one the credential scan reports.
    write(dir, 'docs/setup.sh', text);
    git(dir, 'add', '-f', '.envrc', 'docs/setup.sh');
    const staged = validate(dir, '--staged');
    const control = issuesOf(staged, 'docs/setup.sh');
    assert.equal(control.length, 1, staged.out);
    assert.match(control[0].message, /^Possible credential \(credential-assignment: /);
    assert.deepEqual(issuesOf(staged, '.envrc').map((i) => i.message), control.map((i) => i.message), staged.out);
    assert.ok(!staged.out.includes(SECRET), 'the report masks the value');
  });
});
