// The validator CLI against temporary Git repositories (follow-up audit, round 2, F2-31): per-user, secret and data files
// are refused when staged and reported when tracked, a PBIP without the .gitignore rules is an error, and --staged checks
// the index (index-view.mjs), not the working tree. The cases of validator-and-git.test.mjs that bfe8af5 deleted, without
// what githook.test.mjs covers now (a staged .env through the hook runner; staged text, not the working copy).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const cli = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'scripts', 'validate.mjs');

// Variables that point git at another repository, index or object store: a `git commit` hook that runs these tests
// exports GIT_INDEX_FILE (and GIT_DIR in some setups), which would send the temporary repositories' git calls elsewhere.
const GIT_REPO_VARS = new Set(['GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE', 'GIT_OBJECT_DIRECTORY', 'GIT_ALTERNATE_OBJECT_DIRECTORIES', 'GIT_COMMON_DIR', 'GIT_PREFIX']);
const gitEnv = () => Object.fromEntries(Object.entries(process.env).filter(([k]) => !GIT_REPO_VARS.has(k.toUpperCase())));
const email = ['t', 'example.invalid'].join('@');

const git = (dir, ...args) => {
  const r = spawnSync('git', ['-c', 'user.name=t', '-c', `user.email=${email}`, '-c', 'commit.gpgsign=false', '-c', 'core.autocrlf=false', ...args], { cwd: dir, env: gitEnv(), encoding: 'utf8' });
  assert.equal(r.status, 0, `git ${args.join(' ')}: ${r.stderr}`);
  return r;
};
const write = (dir, rel, text) => {
  fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
  fs.writeFileSync(path.join(dir, rel), text);
};
/** Runs the CLI as the pre-commit hook and CI do: the repository is the project, git sees only that repository. */
function validate(dir, ...args) {
  const r = spawnSync(process.execPath, [cli, ...args], { cwd: dir, env: { ...gitEnv(), CLAUDE_PROJECT_DIR: dir }, encoding: 'utf8' });
  const json = args.includes('--json') && r.stdout.trim() ? JSON.parse(r.stdout) : null;
  return { status: r.status, stdout: r.stdout, stderr: r.stderr, json, out: r.stdout + r.stderr };
}

function withRepo(fn) {
  // The real path: index-view compares Git's top-level with the project path, which must not be an 8.3 short name.
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-validate-cli-')));
  try {
    git(dir, 'init', '-q');
    return fn(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

const GITIGNORE = '**/.pbi/localSettings.json\n**/.pbi/cache.abf\n';
/** A semantic model with two tables; `copy` is the measure of table Copy. */
const model = (copy = 'Other') => ({
  'M.SemanticModel/definition.pbism': '{}\n',
  'M.SemanticModel/definition/model.tmdl': 'model Model\n',
  'M.SemanticModel/definition/tables/Sales.tmdl': 'table Sales\n\n\tmeasure Total = 1\n\t\tformatString: 0\n',
  'M.SemanticModel/definition/tables/Copy.tmdl': `table Copy\n\n\tmeasure ${copy} = 2\n\t\tformatString: 0\n`,
});
const COPY = 'M.SemanticModel/definition/tables/Copy.tmdl';

// Files that must never be committed, one per class of classifyPath: a secret, a data cache, per-user settings.
const FORBIDDEN = ['.env', 'reports/Orders.rdl.data', 'docs/sources/Sales/model.user.tmuo', 'M.SemanticModel/.pbi/localSettings.json'];
const issuesOf = (report, re) => report.json.issues.filter((i) => i.level === 'error' && re.test(i.message));

test('validate --staged refuses a staged secret, data cache or per-user settings file; a full scan reports it once tracked', () => {
  withRepo((dir) => {
    for (const [rel, text] of Object.entries({ ...model(), '.gitignore': GITIGNORE, 'docs/a.md': '# A\n' })) write(dir, rel, text);
    git(dir, 'add', '-A');
    const clean = validate(dir, '--staged', '--json');
    assert.equal(clean.status, 0, clean.out);
    assert.deepEqual(clean.json.issues.filter((i) => i.level === 'error'), []);

    write(dir, '.env', 'X=1\n');
    write(dir, 'reports/Orders.rdl.data', 'cached query rows\n');
    write(dir, 'docs/sources/Sales/model.user.tmuo', JSON.stringify({ Deployment: { TargetDatabase: 'Sales' } }));
    write(dir, 'M.SemanticModel/.pbi/localSettings.json', '{}\n');
    git(dir, 'add', '-f', ...FORBIDDEN);
    const staged = validate(dir, '--staged', '--json');
    assert.equal(staged.status, 1, staged.out);
    assert.deepEqual(issuesOf(staged, /^Staged file must never be committed/).map((i) => i.file).sort(), [...FORBIDDEN].sort(), staged.stdout);
    const text = validate(dir, '--staged');
    assert.equal(text.status, 1, text.out);
    assert.match(text.stdout, /^ERROR docs\/sources\/Sales\/model\.user\.tmuo — Staged file must never be committed/m);

    // Unstaged again, the files stay in the working tree and are no longer the commit's.
    git(dir, 'reset', '-q', '--', ...FORBIDDEN);
    assert.equal(validate(dir, '--staged').status, 0);

    git(dir, 'add', '-f', ...FORBIDDEN);
    git(dir, 'commit', '-q', '--no-verify', '-m', 'chore: track by mistake');
    const full = validate(dir, '--json');
    assert.equal(full.status, 1, full.out);
    assert.deepEqual(issuesOf(full, /^Tracked in git but must never be committed/).map((i) => i.file).sort(), [...FORBIDDEN].sort(), full.stdout);
    assert.deepEqual(issuesOf(full, /^Staged file/), [], 'a full scan does not judge the index');
  });
});

test('a full scan of a repository with a PBIP item reports each .gitignore rule it lacks; without an item it does not ask for them', () => {
  withRepo((dir) => {
    write(dir, 'docs/a.md', '# A\n');
    const missing = (r) => issuesOf(r, /^Missing "/).filter((i) => i.file === '.gitignore').map((i) => /^Missing "([^"]+)"/.exec(i.message)[1]);
    assert.deepEqual(missing(validate(dir, '--json')), [], 'no PBIP item, no .gitignore rule required');

    for (const [rel, text] of Object.entries(model())) write(dir, rel, text);
    const none = validate(dir, '--json');
    assert.equal(none.status, 1, none.out);
    assert.deepEqual(missing(none), ['**/.pbi/localSettings.json', '**/.pbi/cache.abf']);
    write(dir, '.gitignore', 'node_modules/\n**/.pbi/localSettings.json\n');
    assert.deepEqual(missing(validate(dir, '--json')), ['**/.pbi/cache.abf']);
    write(dir, '.gitignore', GITIGNORE);
    const complete = validate(dir, '--json');
    assert.equal(complete.status, 0, complete.out);
    assert.deepEqual(missing(complete), []);
  });
});

test('validate --staged checks the artifacts in the index: an unstaged repair does not fix the commit, unstaged damage does not break it', () => {
  withRepo((dir) => {
    for (const [rel, text] of Object.entries({ ...model(), '.gitignore': GITIGNORE })) write(dir, rel, text);
    git(dir, 'add', '-A');
    git(dir, 'commit', '-q', '--no-verify', '-m', 'chore: baseline');

    // A duplicate measure name is a model-wide check: it reads the other table through the index view.
    write(dir, COPY, model('Total')[COPY]);
    git(dir, 'add', COPY);
    write(dir, COPY, model('Repaired')[COPY]);
    const broken = validate(dir, '--staged');
    assert.equal(broken.status, 1, `unstaged repair cannot fix the commit: ${broken.out}`);
    assert.match(broken.stdout, /Measure "total" is also defined in/);
    assert.equal(validate(dir, '--changed').status, 0, 'the working tree itself is fine');

    git(dir, 'add', COPY);
    write(dir, COPY, model('Total')[COPY]);
    const fixed = validate(dir, '--staged');
    assert.equal(fixed.status, 0, `unstaged damage cannot break a valid index: ${fixed.out}`);
    assert.equal(validate(dir, '--changed').status, 1, 'the working tree itself is broken');
  });
});

test('validate --staged: a required file deleted in the index is missing, even when the working tree still has it', () => {
  withRepo((dir) => {
    for (const [rel, text] of Object.entries({ ...model(), '.gitignore': GITIGNORE })) write(dir, rel, text);
    git(dir, 'add', '-A');
    git(dir, 'commit', '-q', '--no-verify', '-m', 'chore: baseline');
    git(dir, 'rm', '-q', '--cached', 'M.SemanticModel/definition.pbism');
    assert.ok(fs.existsSync(path.join(dir, 'M.SemanticModel/definition.pbism')));
    const staged = validate(dir, '--staged');
    assert.equal(staged.status, 1, staged.out);
    assert.match(staged.stdout, /^ERROR M\.SemanticModel — Missing definition\.pbism/m);
  });
});

test('validate --files: a path that does not exist is an error and is not counted as checked', () => {
  withRepo((dir) => {
    const r = validate(dir, '--files', 'missing.json', '--json');
    assert.equal(r.status, 1, r.out);
    assert.equal(r.json.checked, 0);
    assert.deepEqual(r.json.issues.map((i) => [i.level, i.file]), [['error', 'missing.json']]);
    assert.match(r.json.issues[0].message, /^Cannot read file/);
  });
});
