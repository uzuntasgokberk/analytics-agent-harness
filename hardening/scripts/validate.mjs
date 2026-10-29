#!/usr/bin/env node
// PBIP validator CLI - the same checks the hooks run, for humans, git hooks and CI.
//
//   node hardening/scripts/validate.mjs              full scan (files + PBIP artifacts + repo hygiene)
//   node hardening/scripts/validate.mjs --changed    only uncommitted files (git status)
//   node hardening/scripts/validate.mjs --staged     only staged content (used by the pre-commit hook)
//   node hardening/scripts/validate.mjs --files a b  only the given files
//   flags: --json (machine output)  --verbose (also print info)

import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { PROJECT_DIR, git, gitChangedFiles, loadConfig, toPosix } from '../hooks/lib/common.mjs';
import { classifyPath } from '../hooks/lib/policy.mjs';
import { indexView } from '../hooks/lib/index-view.mjs';
import {
  checkRepoHygiene, findPbipItems, formatIssues, validateArtifacts, validateFiles, walkFiles,
} from '../hooks/lib/validators.mjs';

const ROOT = PROJECT_DIR;

function stagedFiles() {
  const out = git(['diff', '--cached', '--name-only', '--no-renames', '--diff-filter=ACMRD', '-z', '--relative'], { cwd: ROOT });
  if (out === null) throw new Error('Not a git repository (needed for --staged).');
  return out.split('\0').filter(Boolean).map(toPosix);
}

/** Runs the validation and returns { mode, files, issues }. Never exits the process. */
export function runValidation({ mode = 'full', files = [] } = {}) {
  const cfg = loadConfig(ROOT);
  const issues = [];
  let targets;
  let readText;
  let io;

  if (mode === 'staged') {
    targets = stagedFiles();
    io = indexView(ROOT);
    readText = (rel) => io.readFileSync(path.join(ROOT, rel));
    for (const rel of targets) {
      if (!io.existsSync(path.join(ROOT, rel))) continue;
      const cls = classifyPath(rel);
      if (cls.secret || cls.data || cls.localOnly) {
        issues.push({ level: 'error', file: rel, message: 'Staged file must never be committed (secret, data cache, .pbix or per-user settings such as .pbi/localSettings.json or *.tmuo). Unstage it: git restore --staged <file>.' });
      }
    }
  } else if (mode === 'changed') {
    targets = gitChangedFiles(ROOT);
    if (targets === null) throw new Error('Not a git repository (needed for --changed).');
  } else if (mode === 'files') {
    targets = files.map((f) => toPosix(path.relative(ROOT, path.resolve(f))));
  } else {
    targets = walkFiles(ROOT, cfg);
  }

  // Check every surviving binding even when the removed model/report was the only change. The candidates come from git
  // (tracked files, plus the untracked ones git does not ignore), not from a walk of the tree: the Stop gate runs this
  // at every stop, and a walk of a large repository would exceed its limit and skip silently. Without git, the walk stays.
  if (mode !== 'full') {
    const listed = git(io ? ['ls-files', '-z', '--cached'] : ['ls-files', '-z', '--cached', '--others', '--exclude-standard'], { cwd: ROOT });
    const candidates = listed === null ? walkFiles(ROOT, cfg) : listed.split('\0').map(toPosix);
    targets = [...new Set([...targets, ...candidates.filter((f) => /(?:\.pbip|\/definition\.pbir)$/i.test(f))])];
  }
  const result = validateFiles(ROOT, cfg, targets, {
    readText, io, projectChecks: mode !== 'full', allowMissing: mode === 'changed' || mode === 'staged', mode,
  });
  issues.push(...result.issues);

  if (mode === 'full') {
    const items = findPbipItems(ROOT, cfg, Infinity);
    issues.push(...validateArtifacts(ROOT, items));
    issues.push(...checkRepoHygiene(ROOT, items.models.length + items.reports.length > 0));
  }
  return { mode, files: result.files, issues };
}

// AGENTS.md and docs/static-checks.md report engine, reconciliation and Desktop checks separately; the summary says so.
const STATIC_ONLY_NOTE ='Static check only: it does not compile DAX, run a query, test RLS or render a report; engine, reconciliation and Desktop checks are reported separately (docs/static-checks.md).';

export function printReport({ mode, files, issues }, { json = false, verbose = false } = {}) {
  if (json) {
    process.stdout.write(`${JSON.stringify({ mode, checked: files.length, issues }, null, 2)}\n`);
    return;
  }
  const shown = verbose ? issues : issues.filter((i) => i.level !== 'info');
  const count = (level) => issues.filter((i) => i.level === level).length;
  console.log(`PBIP validation (${mode}): ${files.length} file(s) checked`);
  if (shown.length) console.log(formatIssues(shown, 200));
  console.log(`Summary: ${count('error')} error(s), ${count('warn')} warning(s), ${count('info')} info`);
  console.log(STATIC_ONLY_NOTE);
}

const USAGE = `Usage: node hardening/scripts/validate.mjs [--changed | --staged | --files <file>...] [--json] [--verbose]
  (no option)  full scan: files, PBIP artifacts and repository hygiene
  --changed    only uncommitted files (git status)
  --staged     only staged content (the pre-commit hook)
  --files      only the given files
  --json       machine-readable output
  --verbose    also print info lines`;
const KNOWN_FLAGS = new Set(['--changed', '--staged', '--files', '--json', '--verbose', '--help', '-h']);

function main(argv) {
  const has = (flag) => argv.includes(flag);
  if (has('--help') || has('-h')) {
    console.log(USAGE);
    return;
  }
  const unknown = argv.find((a) => a.startsWith('-') && !KNOWN_FLAGS.has(a));
  if (unknown) {
    console.error(`validate: unknown option ${unknown}\n${USAGE}`);
    process.exitCode = 2;
    return;
  }
  const mode = has('--staged') ? 'staged' : has('--changed') ? 'changed' : has('--files') ? 'files' : 'full';
  const files = has('--files') ? argv.slice(argv.indexOf('--files') + 1).filter((a) => !a.startsWith('--')) : [];
  try {
    const report = runValidation({ mode, files });
    printReport(report, { json: has('--json'), verbose: has('--verbose') });
    process.exitCode = report.issues.some((i) => i.level === 'error') ? 1 : 0;
  } catch (err) {
    console.error(`validate: ${err.message}`);
    process.exitCode = 2;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main(process.argv.slice(2));
}

export const SCRIPT_PATH = fileURLToPath(import.meta.url);
