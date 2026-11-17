// Open findings 2026-11-17, the validator's side of direnv's .envrc. Since audit 2026-11-16 a tracked or staged .envrc is
// allowed as a file (classifyPath's committedSecret), but its text was never read: it has no extension the validator scans,
// so a credential written into a committed .envrc was not found by the full scan, --changed or --staged. Its text now gets
// the credential scan every other text file gets when git tracks it, has it staged or would add it (untracked and not
// ignored). A .envrc git ignores is where direnv keeps real local secrets: it is never read, nor is any .envrc when git
// cannot answer. A .envrc without a credential stays clean, and .env and .credentials.json stay errors as files. The
// validator runs as a process against temporary folders; every value is a fake built at run time, and no finding may print it.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const cli = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'scripts', 'validate.mjs');

// Variables that point git at another repository, index or object store (a `git commit` hook that runs these tests exports
// GIT_INDEX_FILE): stripped, so the temporary repositories' git calls stay in them. Nor do they read the developer's global
// or system configuration, whose excludes file may ignore .envrc (common with direnv) and hide it from git status.
const GIT_REPO_VARS = new Set(['GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE', 'GIT_OBJECT_DIRECTORY', 'GIT_ALTERNATE_OBJECT_DIRECTORIES', 'GIT_COMMON_DIR', 'GIT_PREFIX']);
const gitEnv = () => ({
  ...Object.fromEntries(Object.entries(process.env).filter(([k]) => !GIT_REPO_VARS.has(k.toUpperCase()))),
  GIT_CONFIG_GLOBAL: path.join(os.tmpdir(), 'bi-harness-1117v-no-global-gitconfig'),
  GIT_CONFIG_NOSYSTEM: '1',
});
const email = ['t', 'example.com'].join('@');
// A value the credential scan reports after API_KEY= and a GitHub token shape, both fakes built from parts.
const SECRET = ['S3cr3t', 'Pa55w0rd', 'Xy'].join('');
const TOKEN = ['gh', 'p_', 'A1b2C3d4'.repeat(5)].join('');
// The value of an ignored .envrc: its own first characters, so a finding's masked preview of it would show in the output.
const LOCAL = ['Qz9w', 'Lm4kPx7rTt2v'].join('');
const CLEAN = 'export FAKE=not-a-secret\nuse flake\nPATH_add bin\n';

const git = (dir, ...args) => {
  const r = spawnSync('git', ['-c', 'user.name=t', '-c', `user.email=${email}`, '-c', 'commit.gpgsign=false', '-c', 'core.autocrlf=false', ...args], { cwd: dir, env: gitEnv(), encoding: 'utf8' });
  assert.equal(r.status, 0, `git ${args.join(' ')}: ${r.stderr}`);
  return r;
};
const write = (dir, rel, text) => {
  fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
  fs.writeFileSync(path.join(dir, rel), text);
};
/**
 * The validator's JSON report for one run, as the pre-commit hook, the Stop gate and CI run it: the folder is the project.
 * Git looks for no repository above the folder (GIT_CEILING_DIRECTORIES), so a folder without one is outside any repository.
 */
function validate(dir, ...args) {
  const env = { ...gitEnv(), CLAUDE_PROJECT_DIR: dir, GIT_CEILING_DIRECTORIES: path.dirname(dir) };
  const r = spawnSync(process.execPath, [cli, ...args, '--json'], { cwd: dir, env, encoding: 'utf8' });
  assert.ok(r.status === 0 || r.status === 1, `validate ${args.join(' ')} did not run: ${r.stdout}${r.stderr}`);
  return { status: r.status, issues: JSON.parse(r.stdout).issues, out: r.stdout + r.stderr };
}
/** A temporary folder, a Git repository unless `repo` is false, removed afterwards. */
function withDir(fn, { repo = true } = {}) {
  // The real path: index-view compares Git's top-level with the project path, which must not be an 8.3 short name.
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-1117v-')));
  try {
    if (repo) git(dir, 'init', '-q');
    return fn(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}
const withRepo = (fn) => withDir(fn);
const issuesOf = (report, file) => report.issues.filter((i) => i.file === file);
const credentialIds = (report, file) => issuesOf(report, file).map((i) => /^Possible credential \(([\w-]+): /.exec(i.message)?.[1] ?? i.message);
const commit = (dir, ...files) => {
  git(dir, 'add', '-f', ...files);
  git(dir, 'commit', '-q', '--no-verify', '-m', 'chore: fixture');
};

/** Writes each file, stages it for --staged, commits it for the full scan; --changed sees the staged, uncommitted files. */
function reports(dir, files) {
  for (const [rel, text] of Object.entries(files)) write(dir, rel, text);
  git(dir, 'add', '-f', ...Object.keys(files));
  const staged = validate(dir, '--staged');
  const changed = validate(dir, '--changed');
  git(dir, 'commit', '-q', '--no-verify', '-m', 'chore: fixture');
  return { '--staged': staged, '--changed': changed, full: validate(dir) };
}

test('a credential in a staged or tracked .envrc is found like the same line in another text file, in --staged, --changed and the full scan', () => {
  withRepo((dir) => {
    const text = `export API_KEY=${SECRET}\nexport API_TOKEN=${TOKEN}\nuse flake\n`;
    const all = reports(dir, { '.envrc': text, 'app/.envrc': text, 'docs/setup.sh': text });
    for (const [mode, report] of Object.entries(all)) {
      const control = credentialIds(report, 'docs/setup.sh');
      assert.deepEqual(control, ['github-token', 'credential-assignment'], `${mode}: the control file's findings: ${report.out}`);
      for (const rel of ['.envrc', 'app/.envrc']) {
        assert.deepEqual(credentialIds(report, rel), control, `${mode} ${rel}: the same findings as the control: ${report.out}`);
        assert.deepEqual(issuesOf(report, rel).map((i) => i.line), [2, 1], `${mode} ${rel}: the lines`);
      }
      assert.equal(report.status, 1, `${mode}: the run fails`);
      assert.ok(!report.out.includes(SECRET) && !report.out.includes(TOKEN), `${mode}: the report never prints a value`);
    }
  });
});

test('a credential in a tracked .envrc is found by the full scan, also when .gitignore names it (added with -f)', () => {
  withRepo((dir) => {
    write(dir, '.gitignore', '.envrc\n');
    write(dir, '.envrc', `export API_KEY=${SECRET}\n`);
    write(dir, 'app/.envrc', `export API_KEY=${SECRET}\n`);
    commit(dir, '.gitignore', '.envrc', 'app/.envrc');
    const full = validate(dir);
    for (const rel of ['.envrc', 'app/.envrc']) assert.deepEqual(credentialIds(full, rel), ['credential-assignment'], `${rel}: ${full.out}`);
    assert.ok(!full.out.includes(SECRET), 'the value is masked');
  });
});

test('a credential in an untracked .envrc that git does not ignore is found by --changed and the full scan', () => {
  withRepo((dir) => {
    write(dir, 'docs/a.md', '# A\n');
    commit(dir, 'docs/a.md');
    write(dir, 'tools/.envrc', `export API_KEY=${SECRET}\n`);
    for (const args of [['--changed'], []]) {
      const report = validate(dir, ...args);
      assert.deepEqual(credentialIds(report, 'tools/.envrc'), ['credential-assignment'], `${args[0] ?? 'full scan'}: ${report.out}`);
      assert.ok(!report.out.includes(SECRET), 'the value is masked');
    }
  });
});

test('a .envrc that git ignores is never read: no finding in --staged, --changed or the full scan, and no part of its value', () => {
  withRepo((dir) => {
    write(dir, '.gitignore', '.envrc\nlocal/\n');
    write(dir, 'docs/setup.sh', `export API_KEY=${SECRET}\n`);
    commit(dir, '.gitignore', 'docs/setup.sh');
    for (const rel of ['.envrc', 'app/.envrc', 'local/.envrc']) write(dir, rel, `export API_KEY=${LOCAL}\nexport API_TOKEN=${TOKEN}\n`);
    // The control file, committed, and one staged for --staged: the scan runs in every mode.
    write(dir, 'docs/next.sh', `export API_KEY=${SECRET}\n`);
    git(dir, 'add', 'docs/next.sh');
    for (const args of [['--staged'], ['--changed'], []]) {
      const report = validate(dir, ...args);
      const mode = args[0] ?? 'full scan';
      assert.deepEqual(report.issues.filter((i) => /\.envrc$/.test(i.file)), [], `${mode}: nothing for an ignored .envrc: ${report.out}`);
      // A finding shows the first four characters of a value (policy.mjs, mask); the control files hold neither value.
      assert.ok(!report.out.includes(LOCAL.slice(0, 4)) && !report.out.includes(TOKEN.slice(0, 4)), `${mode}: no part of its values`);
      assert.deepEqual(credentialIds(report, 'docs/next.sh'), ['credential-assignment'], `${mode}: the control file is reported: ${report.out}`);
    }
  });
});

test('in a folder that is no Git repository a .envrc is not read, while the same text in another file is reported', () => {
  withDir((dir) => {
    const text = `export API_KEY=${SECRET}\n`;
    write(dir, '.envrc', text);
    write(dir, 'docs/setup.sh', text);
    const full = validate(dir);
    assert.deepEqual(issuesOf(full, '.envrc'), [], full.out);
    assert.deepEqual(credentialIds(full, 'docs/setup.sh'), ['credential-assignment'], full.out);
    assert.ok(!full.out.includes(SECRET), 'the value is masked');
  }, { repo: false });
});

// ---------------------------------------------------------------- what must stay (passes before and after the fix)

test('must stay: a .envrc without a credential is clean in every mode, and .env and .credentials.json stay errors as files', () => {
  withRepo((dir) => {
    const all = reports(dir, { '.envrc': CLEAN, 'app/.envrc': 'layout python\ndotenv\n', 'docs/a.md': '# A\n' });
    for (const [mode, report] of Object.entries(all)) {
      for (const rel of ['.envrc', 'app/.envrc']) assert.deepEqual(issuesOf(report, rel), [], `${mode} ${rel}: ${report.out}`);
      assert.equal(report.status, 0, `${mode}: ${report.out}`);
    }
  });
  withRepo((dir) => {
    const all = reports(dir, { '.env': 'FAKE=not-a-secret\n', '.credentials.json': '{}\n', '.envrc': CLEAN });
    assert.match(issuesOf(all['--staged'], '.env')[0]?.message ?? '', /^Staged file must never be committed/);
    assert.match(issuesOf(all['--staged'], '.credentials.json')[0]?.message ?? '', /^Staged file must never be committed/);
    assert.match(issuesOf(all.full, '.env')[0]?.message ?? '', /^Tracked in git but must never be committed/);
    assert.match(issuesOf(all.full, '.credentials.json')[0]?.message ?? '', /^Tracked in git but must never be committed/);
    for (const report of Object.values(all)) assert.deepEqual(issuesOf(report, '.envrc'), [], report.out);
  });
});
