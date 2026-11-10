// A read-only filesystem view of the Git index. Artifact checks must inspect the same
// snapshot as per-file checks, including staged deletions and unstaged repairs.
import fs from 'node:fs';
import path from 'node:path';
import { canonicalPath, git, toPosix } from './common.mjs';

export function indexView(root) {
  // -v tags each entry: H is a normal entry; S (skip-worktree) and lowercase tags (assume-unchanged) mean Git does not
  // compare the working copy, so their content comes from the index.
  const listed = git(['ls-files', '--cached', '-z', '-v', '--full-name'], { cwd: root });
  const top = git(['rev-parse', '--show-toplevel'], { cwd: root })?.trim();
  if (listed === null || !top) throw new Error('Cannot read Git index.');
  // Entries whose working copy differs from the index: unstaged edits and deletions. Every other normal entry is read
  // from disk, which holds the blob's content after checkout (line endings may differ, as in --changed and the full
  // scan): one `git show` per file made a pre-commit run take minutes in a repository with thousands of PBIP files.
  // When the list cannot be read, every file comes from the index as before.
  const diff = git(['diff', '--name-only', '--no-renames', '-z'], { cwd: root });
  const changed = diff === null ? null : new Set(diff.split('\0').filter(Boolean));
  // Git names are relative to its canonical top; callers address files under their own spelling of root.
  const base = path.resolve(root);
  const canonicalRoot = canonicalPath(base);
  const repoTop = canonicalPath(top);
  const entries = new Map();
  // Directory -> its children (name -> entry) in first-seen order, so a listing does not scan every entry.
  const children = new Map();
  const addChild = (absolute, entry) => {
    const dir = path.dirname(absolute);
    if (!children.has(dir)) children.set(dir, new Map());
    const list = children.get(dir);
    if (!list.has(path.basename(absolute))) list.set(path.basename(absolute), entry);
  };
  for (const record of listed.split('\0').filter(Boolean)) {
    const tag = record[0];
    const name = record.slice(2);
    const relative = path.relative(canonicalRoot, path.resolve(repoTop, name));
    if (relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) continue;
    const absolute = path.join(base, relative);
    const entry = { file: true, gitPath: name, onDisk: changed !== null && tag === 'H' && !changed.has(name) };
    entries.set(absolute, entry);
    addChild(absolute, entry);
    let parent = path.dirname(absolute);
    while (parent !== base && parent !== path.dirname(parent)) {
      if (!entries.has(parent)) entries.set(parent, { file: false });
      addChild(parent, entries.get(parent));
      parent = path.dirname(parent);
    }
  }
  const cache = new Map();
  return {
    existsSync: (file) => entries.has(path.resolve(file)),
    readFileSync(file) {
      const key = path.resolve(file);
      if (cache.has(key)) return cache.get(key);
      const entry = entries.get(key);
      if (!entry?.file) throw new Error(`Not an index file: ${toPosix(path.relative(root, key))}`);
      let text = null;
      if (entry.onDisk) {
        try {
          // Only a regular file: readFileSync follows a symlink to content the commit does not hold (the index has the
          // link's text), possibly outside the repository. A link, a directory or a missing path comes from the index.
          if (fs.lstatSync(key).isFile()) text = fs.readFileSync(key, 'utf8');
        } catch {
          text = null; // gone since the listing: fall back to the index
        }
      }
      if (text === null) text = git(['show', `:${entry.gitPath}`], { cwd: root });
      if (text === null) throw new Error(`Cannot read index blob: ${entry.gitPath}`);
      cache.set(key, text);
      return text;
    },
    readdirSync(dir, { withFileTypes = false } = {}) {
      const list = [...(children.get(path.resolve(dir)) ?? new Map())];
      return list.map(([name, entry]) => withFileTypes
        ? { name, isDirectory: () => !entry.file, isFile: () => entry.file }
        : name);
    },
  };
}
