#!/usr/bin/env node
// Git hook runner (called by the shims in hardening/githooks/). Guards human and agent commits alike.
//   pre-commit          validate staged content (JSON/TMDL/PBIR, secrets, forbidden files, md <= 500 lines)
//   commit-msg <file>   enforce Conventional Commits
//   pre-push            block direct pushes to protected branches

import fs from 'node:fs';
import { loadConfig, readStdin } from '../hooks/lib/common.mjs';
import { printReport, runValidation } from './validate.mjs';

const COMMIT_RE = /^(?:feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert)(?:\([a-z0-9._-]+\))?!?: \S.{2,}$/;
const EXEMPT_RE = /^(?:Merge |Revert "|fixup! |squash! |amend! )/;

function preCommit() {
  const report = runValidation({ mode: 'staged' });
  const errors = report.issues.filter((i) => i.level === 'error');
  if (!errors.length) return 0;
  printReport(report);
  console.error('\npre-commit: fix the errors above (or unstage the files). The BI harness blocks this commit.');
  return 1;
}

function commitMsg(file) {
  const first = (fs.readFileSync(file, 'utf8').split(/\r?\n/).find((l) => l.trim() && !l.startsWith('#')) ?? '').trim();
  if (EXEMPT_RE.test(first) || COMMIT_RE.test(first)) return 0;
  console.error(`commit-msg: "${first}" is not a Conventional Commit.`);
  console.error('  format: <type>(<scope>)?: <summary>   e.g. feat(model): add Sales YoY % measure');
  console.error('  types : feat fix docs style refactor perf test build ci chore revert');
  console.error('  PBIP scopes: model, dax, pq, rls, report, visuals, harness, docs');
  return 1;
}

async function prePush() {
  const protectedBranches = loadConfig().git.protectedBranches;
  const lines = (await readStdin(10000)).split(/\r?\n/).filter(Boolean);
  for (const line of lines) {
    const remoteRef = line.split(/\s+/)[2] ?? '';
    const branch = remoteRef.replace(/^refs\/heads\//, '');
    if (protectedBranches.includes(branch)) {
      console.error(`pre-push: direct push to '${branch}' is blocked by the BI harness. Push a feature branch and open a pull request.`);
      return 1;
    }
  }
  return 0;
}

const [command, arg] = process.argv.slice(2);
try {
  if (command === 'pre-commit') process.exitCode = preCommit();
  else if (command === 'commit-msg') process.exitCode = commitMsg(arg);
  else if (command === 'pre-push') process.exitCode = await prePush();
  else {
    console.error(`githook: unknown command "${command}"`);
    process.exitCode = 2;
  }
} catch (err) {
  console.error(`githook ${command}: ${err.message}`);
  process.exitCode = 1; // fail closed: a broken hook must not let a commit through silently
}
