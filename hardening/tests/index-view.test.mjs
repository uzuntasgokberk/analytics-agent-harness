// The index view reads an unchanged file from disk only when lstat says it is a regular file (review finding 5): a symlink,
// a directory or a missing path comes from the index. The view is taken first and the disk changed afterwards, so the read
// reaches the disk path that `git diff` would otherwise route to the index.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { indexView } from '../hooks/lib/index-view.mjs';

// indexView runs git with this process's environment: a `git commit` hook that runs these tests exports GIT_INDEX_FILE
// (and GIT_DIR in some setups), which would send its calls to the outer repository.
const GIT_REPO_VARS = new Set(['GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE', 'GIT_OBJECT_DIRECTORY', 'GIT_ALTERNATE_OBJECT_DIRECTORIES', 'GIT_COMMON_DIR', 'GIT_PREFIX']);
for (const key of Object.keys(process.env)) if (GIT_REPO_VARS.has(key.toUpperCase())) delete process.env[key];

const git = (dir, ...args) => {
  const r = spawnSync('git', ['-c', 'core.autocrlf=false', ...args], { cwd: dir, encoding: 'utf8' });
  assert.equal(r.status, 0, `git ${args.join(' ')}: ${r.stderr}`);
};

function withStaged(files, fn) {
  // The real path: index-view compares Git's top-level with the project path, which must not be an 8.3 short name.
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-index-view-')));
  try {
    git(dir, 'init', '-q');
    for (const [rel, text] of Object.entries(files)) fs.writeFileSync(path.join(dir, rel), text);
    git(dir, 'add', '-A');
    return fn(dir, indexView(dir));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

test('index view: a regular unchanged file is read from disk; a directory or a missing path comes from the index', () => {
  withStaged({ 'disk.tmdl': 'staged\n', 'dir.tmdl': 'staged dir\n', 'gone.tmdl': 'staged gone\n' }, (dir, view) => {
    fs.writeFileSync(path.join(dir, 'disk.tmdl'), 'on disk\n');
    fs.rmSync(path.join(dir, 'dir.tmdl'));
    fs.mkdirSync(path.join(dir, 'dir.tmdl'));
    fs.rmSync(path.join(dir, 'gone.tmdl'));
    assert.equal(view.readFileSync(path.join(dir, 'disk.tmdl')), 'on disk\n', 'the disk path still serves regular files');
    assert.equal(view.readFileSync(path.join(dir, 'dir.tmdl')), 'staged dir\n');
    assert.equal(view.readFileSync(path.join(dir, 'gone.tmdl')), 'staged gone\n');
  });
});

// A directory or a missing path made readFileSync throw before the lstat guard too; this case fails without the guard and
// runs where no symlink can be created: lstat reports a link, readFileSync would follow it to a regular file's text.
test('index view: a path lstat reports as a symlink comes from the index, even where readFileSync could read it', (t) => {
  withStaged({ 'link.tmdl': 'staged link\n' }, (dir, view) => {
    const link = path.join(dir, 'link.tmdl');
    fs.writeFileSync(link, 'the target, followed\n');
    const lstat = fs.lstatSync;
    t.mock.method(fs, 'lstatSync', (p, ...rest) => (path.resolve(p) === link ? { isFile: () => false, isSymbolicLink: () => true } : lstat(p, ...rest)));
    assert.equal(view.readFileSync(link), 'staged link\n');
  });
});

test('index view: a symlink is not followed; its path comes from the index', (t) => {
  const outside = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-index-view-outside-')));
  try {
    fs.writeFileSync(path.join(outside, 'target.tmdl'), 'outside the repository\n');
    withStaged({ 'link.tmdl': 'staged link\n' }, (dir, view) => {
      fs.rmSync(path.join(dir, 'link.tmdl'));
      try {
        fs.symlinkSync(path.join(outside, 'target.tmdl'), path.join(dir, 'link.tmdl'), 'file');
      } catch (err) {
        t.skip(`cannot create a symlink here (${err.code}): Windows needs Developer Mode or the privilege; CI on Ubuntu runs it`);
        return;
      }
      assert.equal(view.readFileSync(path.join(dir, 'link.tmdl')), 'staged link\n');
    });
  } finally {
    fs.rmSync(outside, { recursive: true, force: true });
  }
});
