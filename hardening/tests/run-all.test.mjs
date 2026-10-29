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
