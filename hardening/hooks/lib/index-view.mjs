// A read-only filesystem view of the Git index. Artifact checks must inspect the same
// snapshot as per-file checks, including staged deletions and unstaged repairs.
import path from 'node:path';
import { canonicalPath, git, toPosix } from './common.mjs';

export function indexView(root) {
  const listed = git(['ls-files', '--cached', '-z', '--full-name'], { cwd: root });
  const top = git(['rev-parse', '--show-toplevel'], { cwd: root })?.trim();
  if (listed === null || !top) throw new Error('Cannot read Git index.');
  // Git names are relative to its canonical top; callers address files under their own spelling of root.
  const base = path.resolve(root);
  const canonicalRoot = canonicalPath(base);
  const repoTop = canonicalPath(top);
  const entries = new Map();
  for (const name of listed.split('\0').filter(Boolean)) {
    const relative = path.relative(canonicalRoot, path.resolve(repoTop, name));
    if (relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) continue;
    const absolute = path.join(base, relative);
    entries.set(absolute, { file: true, gitPath: name });
    let parent = path.dirname(absolute);
    while (parent !== base && parent !== path.dirname(parent)) {
      entries.set(parent, { file: false });
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
      const text = git(['show', `:${entry.gitPath}`], { cwd: root });
      if (text === null) throw new Error(`Cannot read index blob: ${entry.gitPath}`);
      cache.set(key, text);
      return text;
    },
    readdirSync(dir, { withFileTypes = false } = {}) {
      const absolute = path.resolve(dir);
      const children = [...entries].filter(([file]) => path.dirname(file) === absolute);
      return children.map(([file, entry]) => withFileTypes
        ? { name: path.basename(file), isDirectory: () => !entry.file, isFile: () => entry.file }
        : path.basename(file));
    },
  };
}
