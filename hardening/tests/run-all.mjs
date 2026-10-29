// Runs every *.test.mjs in this folder with Node's built-in test runner (no dependencies).
// The harness installer leaves tests out of installed copies; this folder holds the tests of local changes.
// Exit codes: the test runner's own (0 all passed, 1 a failure); 3 when there are no tests at all, so a CI step or an
// agent that reads only the exit code never takes "no tests" for "tests passed".
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const NO_TESTS_EXIT = 3;
const here = path.dirname(fileURLToPath(import.meta.url));
const files = fs.readdirSync(here).filter((f) => f.endsWith('.test.mjs')).map((f) => path.join(here, f));
if (!files.length) {
  console.log('No harness tests in this copy: the installer leaves them out. This is not a validation of your project; run `node hardening/scripts/validate.mjs`.');
  process.exit(NO_TESTS_EXIT);
}
// The tests run with a home folder of their own, empty and removed afterwards: the hooks read the user's Claude Code
// settings (~/.claude/settings.json, hooks/lib/permissions.mjs), so a permission rule of the developer changed their
// verdicts and failed the suite (F1-79). Managed settings (Program Files, /etc) are not redirected.
const home = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-tests-home-'));
let result;
try {
  result = spawnSync(process.execPath, ['--test', ...files], { stdio: 'inherit', env: { ...process.env, HOME: home, USERPROFILE: home } });
} finally {
  fs.rmSync(home, { recursive: true, force: true });
}
process.exit(result.status ?? 1);
