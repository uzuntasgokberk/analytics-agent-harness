// 2026-10-16 audit of fe1dd6f: in an installed copy (the installer leaves the tests out) run-all.mjs printed
// "No tests found." and exited 0, so a CI step or an agent reading only the exit code took it for a pass.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const runner = path.join(path.dirname(fileURLToPath(import.meta.url)), 'run-all.mjs');

test('run-all: no *.test.mjs exits 3 with a notice; with tests it returns the runner\'s result', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-runall-'));
  const env = { ...process.env };
  delete env.NODE_TEST_CONTEXT; // the copy must run as a top-level runner, not as a child of this one
  const run = () => spawnSync(process.execPath, [path.join(dir, 'run-all.mjs')], { encoding: 'utf8', env, cwd: dir });
  try {
    fs.copyFileSync(runner, path.join(dir, 'run-all.mjs'));
    const empty = run();
    assert.equal(empty.status, 3, empty.stdout + empty.stderr);
    // The notice's opening and the command it names, not its whole sentence (follow-up audit, F2-62).
    assert.match(empty.stdout, /^No harness tests in this copy\b/);
    assert.match(empty.stdout, /`node hardening\/scripts\/validate\.mjs`/);

    fs.writeFileSync(path.join(dir, 'ok.test.mjs'), "import { test } from 'node:test';\ntest('ok', () => {});\n");
    const passing = run();
    assert.equal(passing.status, 0, passing.stdout + passing.stderr);
    assert.doesNotMatch(passing.stdout, /No harness tests/);

    fs.writeFileSync(path.join(dir, 'bad.test.mjs'), "import { test } from 'node:test';\ntest('bad', () => { throw new Error('x'); });\n");
    assert.equal(run().status, 1);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// Audit 2026-10-31, second round (A5): two tests flaked on a slow Windows runner, one git call past the hooks' 3 s (F1-38)
// and a broken guard's diagnosis past its 5 s (F1-47). The runner gives the hooks the larger budgets of their knobs.
test('run-all: the tests get the larger git and diagnosis budgets; a value the caller set stays', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-runall-'));
  const base = { ...process.env };
  delete base.NODE_TEST_CONTEXT;
  delete base.BI_HARNESS_GIT_TIMEOUT_MS;
  delete base.BI_HARNESS_CHECK_BUDGET_MS;
  const run = (env) => spawnSync(process.execPath, [path.join(dir, 'run-all.mjs')], { encoding: 'utf8', env: { ...base, ...env }, cwd: dir });
  try {
    fs.copyFileSync(runner, path.join(dir, 'run-all.mjs'));
    fs.writeFileSync(path.join(dir, 'env.test.mjs'), [
      "import { test } from 'node:test';",
      "import assert from 'node:assert/strict';",
      "test('env', () => assert.deepEqual([process.env.BI_HARNESS_GIT_TIMEOUT_MS, process.env.BI_HARNESS_CHECK_BUDGET_MS], [process.env.WANT_GIT, process.env.WANT_CHECK]));",
      '',
    ].join('\n'));
    const defaults = run({ WANT_GIT: '10000', WANT_CHECK: '12000' });
    assert.equal(defaults.status, 0, defaults.stdout + defaults.stderr);
    const own = run({ BI_HARNESS_GIT_TIMEOUT_MS: '7000', BI_HARNESS_CHECK_BUDGET_MS: '4000', WANT_GIT: '7000', WANT_CHECK: '4000' });
    assert.equal(own.status, 0, own.stdout + own.stderr);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
