#!/usr/bin/env node
// Finds the broken file of the hook pack. The same command works in Git Bash and in PowerShell:
//   node hardening/scripts/check-hooks.mjs
// Run it when every tool call is blocked with "The PreToolUse guard could not load" (hardening/README.md, Limits). It runs
// `node --check` on every hardening/hooks/**/*.mjs file, one file at a time (`node --check hardening/hooks/lib/*.mjs`
// checks only its first file, and PowerShell does not expand the pattern), looks for a relative import of a hook file whose
// target is missing (an entry script's imports are not loaded below), then loads each module of hardening/hooks/lib in a
// process of its own, as the guard does, which also finds a missing export and an error at load time, and last checks
// that every name an entry script imports (statically or by a dynamic import) is exported by its module, which it loads
// on its own for that.
// Prints the first failure as `file:line: message`. Exit 0: the pack is clean. Exit 1: a broken file. Exit 2: the check
// could not run or finish. The two guard entry scripts import describeFirstFailure to name the file in their message.
// Never run an entry script from here: a broken one would start this check again.

import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
// The same folder as Node prints it in an error (symlinks and Windows short names resolved).
const ROOT_REAL = (() => {
  try {
    return fs.realpathSync.native(ROOT);
  } catch {
    return ROOT;
  }
})();
const HOOKS = path.join(ROOT, 'hardening', 'hooks');
const LIB = path.join(HOOKS, 'lib');
const FILE_MS = 30000; // one Node process may take this long, whatever the budget
// Loads one module and exits 0 once it has loaded; a guard module reads its payload at load time and finds none (stdin is
// closed), which is the healthy state. A failure prints the stack, whose first line names the file and line of a link error.
const LOAD_CODE = 'import(process.argv[1]).then(() => process.exit(0), (e) => { process.stderr.write(String(e && e.stack ? e.stack : e) + "\\n"); process.exit(1); });';
// Loads one module and prints the names it exports after a marker line (a module may print on its own while it loads).
const EXPORTS_MARK = '@@bi-harness-exports@@';
const EXPORTS_CODE = `import(process.argv[1]).then((m) => process.stdout.write("\\n${EXPORTS_MARK}" + JSON.stringify(Object.keys(m)) + "\\n", () => process.exit(0)), (e) => { process.stderr.write(String(e && e.stack ? e.stack : e) + "\\n"); process.exit(1); });`;

const toPosix = (p) => String(p).replace(/\\/g, '/');
const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
/** A path relative to the pack's root as POSIX text; one outside the root keeps its ".." and is not "in the pack". */
const relOf = (file) => toPosix(path.relative(ROOT, file));
/** The path of a file below the pack's root (hardening/hooks/lib/x.mjs), or null when it lies elsewhere. */
function inPack(abs) {
  for (const base of new Set([ROOT, ROOT_REAL])) {
    const rel = path.relative(base, abs);
    if (rel && !rel.startsWith('..') && !path.isAbsolute(rel)) return toPosix(rel);
  }
  return null;
}

/** Every .mjs file below hardening/hooks: the modules of lib/ first, then the entry scripts, each group by name. */
function hookFiles(dir = HOOKS) {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...hookFiles(full));
    else if (entry.name.endsWith('.mjs')) out.push(full);
  }
  const inLib = (f) => (path.dirname(f) === LIB ? 0 : 1);
  return out.sort((a, b) => inLib(a) - inLib(b) || (a < b ? -1 : a > b ? 1 : 0));
}

/** Runs node with these arguments and never rejects: { status, stdout, stderr, timedOut } (stdout only when asked). Stdin is closed. */
function runNode(args, timeoutMs, { captureStdout = false } = {}) {
  return new Promise((resolve) => {
    let stdout = '';
    let stderr = '';
    let timedOut = false;
    let child;
    try {
      child = spawn(process.execPath, args, { stdio: ['ignore', captureStdout ? 'pipe' : 'ignore', 'pipe'], windowsHide: true, env: { ...process.env, CLAUDE_PROJECT_DIR: ROOT } });
    } catch (err) {
      resolve({ status: null, stdout, stderr: String(err.message), timedOut });
      return;
    }
    const timer = setTimeout(() => { timedOut = true; child.kill(); }, timeoutMs);
    child.stdout?.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('error', (err) => { clearTimeout(timer); resolve({ status: null, stdout, stderr: stderr || String(err.message), timedOut }); });
    child.on('close', (status) => { clearTimeout(timer); resolve({ status, stdout, stderr, timedOut }); });
  });
}

/** Maps with at most `limit` calls running at once; the results keep the order of the items. */
async function mapLimit(items, limit, fn) {
  const out = new Array(items.length);
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i]);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return out;
}

const ROOT_FORMS = [...new Set([ROOT, ROOT_REAL])].flatMap((r) => [pathToFileURL(r).href, toPosix(r), r]).sort((a, b) => b.length - a.length);
const ROOT_RE = new RegExp(`(?:${ROOT_FORMS.map(escapeRe).join('|')})[\\\\/]*`, 'gi');
/** The text without the absolute folder of the pack: paths read as hardening/hooks/..., never as a user folder. */
const scrub = (text) => toPosix(String(text).replace(ROOT_RE, ''));

/** A path or file URL as an absolute path, or null when it is neither. */
function toAbsolute(location) {
  try {
    return location.startsWith('file:') ? fileURLToPath(location) : path.resolve(location);
  } catch {
    return null;
  }
}

const PATH_START = '(?:file:\\/\\/\\/?|[A-Za-z]:[\\\\/]|\\/)';
const HEADER_RE = new RegExp(`^(${PATH_START}.+?):(\\d+)$`);
const FRAME_RE = new RegExp(`^\\s*at (?:.+? \\()?(${PATH_START}[^\\s)]+?):(\\d+):\\d+\\)?\\s*$`);

/**
 * Where a failed `node --check` or load says the fault is: { file, line, message }, the file relative to the pack's root.
 * Node's first line is "<file>:<line>" for a syntax error and for a link error (a missing export); an error thrown while a
 * module runs names its file in the first frame; a missing file names the module that imports it in the message.
 */
function failureOf(file, stderr) {
  const lines = String(stderr).replace(/\r\n?/g, '\n').split('\n');
  const first = (lines.find((l) => l.trim()) ?? '').trim();
  const message = scrub((lines.find((l) => /^[A-Za-z]*Error(?: \[\w+\])?: /.test(l.trim())) ?? first).trim()).slice(0, 300) || 'it did not load';
  const inside = (m) => (m ? (toAbsolute(m[1]) ? inPack(toAbsolute(m[1])) : null) : null);
  let located = HEADER_RE.exec(first);
  if (!inside(located)) located = lines.map((l) => FRAME_RE.exec(l)).find(inside) ?? null;
  if (located) return { file: inside(located), line: Number(located[2]), message };
  const importer = /imported from (.+)$/m.exec(String(stderr));
  const from = importer && toAbsolute(importer[1].trim()) ? inPack(toAbsolute(importer[1].trim())) : null;
  return { file: from ?? inPack(file) ?? relOf(file), line: null, message };
}

/** `file:line: message` (no line when none is known). */
export const formatFailure = (f) => `${f.file}${f.line ? `:${f.line}` : ''}: ${f.message}`;

// A relative module a hook file names: `from './x.mjs'`, `import('./x.mjs')` or `import './x.mjs'`.
const IMPORT_RE = /(?:\bfrom\s*|\bimport\s*\(\s*|\bimport\s+)(['"])(\.{1,2}\/[^'"\r\n]+)\1/g;

/**
 * The files below hardening/hooks that a hook file names and that are not there, as failures. Nothing loads an entry
 * script's own imports, and a deleted module that only an entry script names (the guard itself) is in no list of files,
 * so only the names reveal it; the line is that of the import.
 */
function missingImports(files) {
  const out = [];
  for (const file of files) {
    let text;
    try {
      text = fs.readFileSync(file, 'utf8');
    } catch {
      continue;
    }
    for (const m of text.matchAll(IMPORT_RE)) {
      const target = path.resolve(path.dirname(file), m[2]);
      const rel = path.relative(HOOKS, target);
      if (rel.startsWith('..') || path.isAbsolute(rel) || fs.existsSync(target)) continue;
      out.push({ file: inPack(file) ?? relOf(file), line: text.slice(0, m.index).split('\n').length, message: `it imports ${m[2]}, which does not exist` });
    }
  }
  return out;
}

// The names a file takes from a relative module: `import { a, b as c } from './x.mjs'` (also with a default import in
// front and over several lines), `const { a, b: c } = await import('./x.mjs')` and `(await import('./x.mjs')).a`.
const STATIC_NAMED_RE = /\bimport\s*(?:[A-Za-z_$][\w$]*\s*,\s*)?\{([^}]*)\}\s*from\s*(['"])(\.{1,2}\/[^'"\r\n]+)\2/g;
const DYNAMIC_DESTRUCTURE_RE = /\{([^{}]*)\}\s*=\s*await\s+import\s*\(\s*(['"])(\.{1,2}\/[^'"\r\n]+)\2\s*\)/g;
const DYNAMIC_MEMBER_RE = /\(\s*await\s+import\s*\(\s*(['"])(\.{1,2}\/[^'"\r\n]+)\1\s*\)\s*\)\s*\.\s*([A-Za-z_$][\w$]*)/g;

/**
 * The names a module's text imports from relative modules, in the order of their lines: [{ specifier, names, line }],
 * each name as the module exports it (`b as c` and `b: c` are b). A namespace or side-effect import names nothing.
 */
export function importedNames(text) {
  const source = String(text ?? '');
  const lineAt = (index) => source.slice(0, index).split('\n').length;
  const namesIn = (list) => list.split(',').map((item) => /^\s*([A-Za-z_$][\w$]*)/.exec(item)?.[1]).filter(Boolean);
  const out = [];
  for (const m of source.matchAll(STATIC_NAMED_RE)) out.push({ specifier: m[3], names: namesIn(m[1]), line: lineAt(m.index) });
  for (const m of source.matchAll(DYNAMIC_DESTRUCTURE_RE)) out.push({ specifier: m[3], names: namesIn(m[1]), line: lineAt(m.index) });
  for (const m of source.matchAll(DYNAMIC_MEMBER_RE)) out.push({ specifier: m[2], names: [m[3]], line: lineAt(m.index) });
  return out.filter((i) => i.names.length).sort((a, b) => a.line - b.line);
}

/**
 * The names the entry scripts (the hook files outside lib/) import from a module of the pack that the module does not
 * export, as failures at the line of the import; a module that does not load is a failure of its own. Nothing loads an
 * entry script here, so a renamed export breaks it unseen (its static imports fail at link time, a dynamic one at run
 * time). Each module is loaded once, on its own; `judge(file, args)` runs it as the other checks do.
 */
async function missingNames(entries, judge) {
  const wanted = [];
  for (const file of entries) {
    let text;
    try {
      text = fs.readFileSync(file, 'utf8');
    } catch {
      continue;
    }
    for (const imp of importedNames(text)) {
      const target = path.resolve(path.dirname(file), imp.specifier);
      if (inPack(target) && fs.existsSync(target)) wanted.push({ file, target, ...imp }); // a missing one is missingImports' or not the pack's
    }
  }
  const targets = [...new Set(wanted.map((w) => w.target))];
  const listed = await mapLimit(targets, 6, (target) => judge(target, ['--input-type=module', '-e', EXPORTS_CODE, pathToFileURL(target).href]));
  const exportsOf = new Map(targets.map((t, i) => [t, listed[i]]));
  const out = listed.filter((r) => r?.failure).map((r) => r.failure);
  for (const w of wanted) {
    const names = exportsOf.get(w.target)?.names;
    if (!names) continue; // did not load (reported above) or was cut off
    for (const name of w.names.filter((n) => !names.includes(n))) {
      out.push({ file: inPack(w.file) ?? relOf(w.file), line: w.line, message: `it imports ${name} from ${w.specifier}, which does not export it` });
    }
  }
  return out;
}

/**
 * Checks every hook file for syntax, then the files they import, then every module of hardening/hooks/lib for loading,
 * then the names the entry scripts import (missingNames).
 * Resolves { files, libs, failures, incomplete }: `failures` holds the files that fail `node --check` (all of them), or,
 * when all parse, the imports of missing files (all of them), or, when none is missing, the first module that does not
 * load (the modules that import it fail for the same reason), or, when all load, every imported name that is not
 * exported. `incomplete`: `budgetMs` ran out before every file was judged; a file that was cut off is not counted as failed.
 */
export async function checkHooks({ budgetMs = 120000 } = {}) {
  const deadline = Date.now() + budgetMs;
  let incomplete = false;
  const judge = async (file, args) => {
    if (Date.now() >= deadline) { incomplete = true; return null; }
    const r = await runNode(args, Math.min(FILE_MS, Math.max(1000, deadline - Date.now())));
    // A process that timed out, could not start or was killed says nothing about the file.
    if (r.timedOut || r.status === null) { incomplete = true; return null; }
    return r.status === 0 ? null : failureOf(file, r.stderr);
  };
  const files = hookFiles();
  const libs = files.filter((f) => path.dirname(f) === LIB);
  const syntax = (await mapLimit(files, 8, (file) => judge(file, ['--check', file]))).filter(Boolean);
  if (syntax.length) return { files: files.length, libs: libs.length, failures: syntax, incomplete };
  const missing = missingImports(files);
  if (missing.length) return { files: files.length, libs: libs.length, failures: missing, incomplete };
  const loads = (await mapLimit(libs, 6, (file) => judge(file, ['--input-type=module', '-e', LOAD_CODE, pathToFileURL(file).href]))).filter(Boolean);
  if (loads.length) return { files: files.length, libs: libs.length, failures: loads.slice(0, 1), incomplete };
  // A module's export list: { names }, { failure } when it does not load, null when cut off.
  const listExports = async (file, args) => {
    if (Date.now() >= deadline) { incomplete = true; return null; }
    const r = await runNode(args, Math.min(FILE_MS, Math.max(1000, deadline - Date.now())), { captureStdout: true });
    if (r.timedOut || r.status === null) { incomplete = true; return null; }
    if (r.status !== 0) return { failure: failureOf(file, r.stderr) };
    const marked = r.stdout.split(/\r?\n/).reverse().find((l) => l.startsWith(EXPORTS_MARK));
    try {
      return { names: JSON.parse(marked.slice(EXPORTS_MARK.length)) };
    } catch {
      incomplete = true; // no list printed: nothing is known about the names
      return null;
    }
  };
  const unlinked = await missingNames(files.filter((f) => path.dirname(f) !== LIB), listExports);
  return { files: files.length, libs: libs.length, failures: unlinked, incomplete };
}

/** The first failure as `file:line: message` for a hook's own message; '' when nothing fails or the check cannot run. */
export async function describeFirstFailure(options) {
  try {
    const { failures } = await checkHooks(options);
    return failures.length ? formatFailure(failures[0]) : '';
  } catch {
    return '';
  }
}

async function main() {
  if (!fs.existsSync(HOOKS)) {
    console.error(`check-hooks: ${relOf(HOOKS)} does not exist; run this from a repository that holds the hardening pack.`);
    return 2;
  }
  const { files, libs, failures, incomplete } = await checkHooks();
  if (!files) {
    console.error(`check-hooks: no .mjs file below ${relOf(HOOKS)}; restore the pack (git checkout -- hardening/hooks).`);
    return 2;
  }
  if (failures.length) {
    for (const f of failures) console.log(formatFailure(f));
    console.log(`check-hooks: ${failures.length} broken file(s), first above. Fix it (or restore the pack: git checkout -- hardening/hooks), then run this check again.`);
    return 1;
  }
  if (incomplete) {
    console.error('check-hooks: the check did not finish (a Node process timed out); no broken file was found in the rest. Run it again.');
    return 2;
  }
  console.log(`check-hooks: ${files} hook files parse and the ${libs} modules of hardening/hooks/lib load, and every name the entry scripts import is exported.`);
  return 0;
}

const direct = (() => {
  try {
    return Boolean(process.argv[1]) && fs.realpathSync.native(process.argv[1]) === fs.realpathSync.native(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
})();
if (direct) {
  try {
    process.exitCode = await main();
  } catch (err) {
    console.error(`check-hooks: ${err.message}`);
    process.exitCode = 2;
  }
}
