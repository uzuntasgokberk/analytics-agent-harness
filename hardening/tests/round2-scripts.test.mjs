// Follow-up audit, scripts: the vendored references stay byte-identical to their checksums (F1-108), and the Copilot
// instruction pointers read every YAML form of a rule's `paths:` (F1-137).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const repo = path.resolve(here, '..', '..');

// ---------------------------------------------------------------- F1-108: vendored references

// .claude/skills/bi-semantic-model/references/ is Microsoft's text, copied unmodified (UPSTREAM.md); .gitattributes keeps
// its line ends. A changed byte, a converted line end or an unlisted file fails here. Refresh: re-copy from upstream
// and rewrite SHA256SUMS (`sha256sum *.md > SHA256SUMS`), never edit a file in place.
test('vendored references: every file matches SHA256SUMS and every file but UPSTREAM.md is listed (F1-108)', (t) => {
  const refs = path.join(repo, '.claude', 'skills', 'bi-semantic-model', 'references');
  if (!fs.existsSync(path.join(refs, 'SHA256SUMS'))) return t.skip('no vendored references with SHA256SUMS next to this harness');
  const listed = new Map();
  for (const line of fs.readFileSync(path.join(refs, 'SHA256SUMS'), 'utf8').split(/\r?\n/).filter((l) => l.trim())) {
    const m = /^([0-9a-f]{64}) [ *](.+)$/.exec(line);
    assert.ok(m, `SHA256SUMS line in sha256sum format: ${JSON.stringify(line)}`);
    listed.set(m[2], m[1]);
  }
  assert.ok(listed.size > 0, 'SHA256SUMS lists the vendored files');
  const problems = [];
  for (const [name, sum] of listed) {
    const file = path.join(refs, name);
    if (!fs.existsSync(file)) problems.push(`${name}: listed but missing`);
    else if (createHash('sha256').update(fs.readFileSync(file)).digest('hex') !== sum) problems.push(`${name}: content differs from SHA256SUMS`);
  }
  for (const name of fs.readdirSync(refs)) {
    if (!['SHA256SUMS', 'UPSTREAM.md'].includes(name) && !listed.has(name)) problems.push(`${name}: not in SHA256SUMS`);
  }
  assert.deepEqual(problems, [], 'Re-copy the file from upstream (UPSTREAM.md) and refresh SHA256SUMS; never edit vendored text.');
});

// ---------------------------------------------------------------- F1-137: Copilot instruction pointers

const syncScript = path.join(here, '..', 'scripts', 'sync-copilot-instructions.mjs');

/** A temporary repository with the generator and the given rules; runs it there. */
function withRules(rules, fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-copilot-sync-'));
  try {
    fs.mkdirSync(path.join(dir, 'hardening', 'scripts'), { recursive: true });
    fs.copyFileSync(syncScript, path.join(dir, 'hardening', 'scripts', 'sync-copilot-instructions.mjs'));
    fs.mkdirSync(path.join(dir, '.claude', 'rules', 'bi'), { recursive: true });
    for (const [name, text] of Object.entries(rules)) fs.writeFileSync(path.join(dir, '.claude', 'rules', 'bi', `${name}.md`), text);
    const run = (...args) => spawnSync(process.execPath, [path.join(dir, 'hardening', 'scripts', 'sync-copilot-instructions.mjs'), ...args], { encoding: 'utf8' });
    const applyTo = (rule) => {
      const file = path.join(dir, '.github', 'instructions', `bi-${rule}.instructions.md`);
      return fs.existsSync(file) ? /^applyTo: "(.*)"$/m.exec(fs.readFileSync(file, 'utf8'))?.[1] ?? '(no applyTo)' : null;
    };
    return fn({ dir, run, applyTo });
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

const RULES = {
  double: '---\npaths:\n  - "**/*.tmdl"\n  - "docs/sources/**"\n---\n\n# Double\n',
  single: "---\npaths:\n  - '**/*.bim'\n  - 'it''s/*.md'\n---\n\n# Single\n",
  bare: '---\npaths:\n  - docs/models/*.md   # the model notes\n  - reports/x/**\n---\n\n# Bare\n',
  flow: `---\npaths: ["**/*.rdl", '**/*.rds', docs/rdl/*.md]\n---\n\n# Flow\n`,
  scalar: '---\npaths: "**/*.dtsx"\n---\n\n# Scalar\n',
  crlf: '---\r\npaths:\r\n  - "**/*.json"\r\n---\r\n\r\n# CRLF\r\n',
  others: '---\ndescription: a rule with other lists\ntags:\n  - "not-a-path"\npaths:\n  - "**/*.pq"\n\n  # a comment inside the list\n  - "**/*.m"\nrelated:\n  - "not-a-path-either"\n---\n\n# Others\n',
  none: '---\ndescription: applies everywhere\n---\n\n# None\n',
};

test('copilot sync: double-quoted, single-quoted, bare, flow and single-value paths all get a pointer with the same globs (F1-137)', () => {
  withRules(RULES, ({ run, applyTo }) => {
    const r = run();
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.deepEqual(Object.fromEntries(Object.keys(RULES).map((k) => [k, applyTo(k)])), {
      double: '**/*.tmdl,docs/sources/**',
      single: "**/*.bim,it's/*.md",
      bare: 'docs/models/*.md,reports/x/**',
      flow: '**/*.rdl,**/*.rds,docs/rdl/*.md',
      scalar: '**/*.dtsx',
      crlf: '**/*.json',
      others: '**/*.pq,**/*.m',
      none: null,
    });
    const check = run('--check');
    assert.equal(check.status, 0, check.stdout + check.stderr);
    assert.match(check.stdout, /7 instruction file\(s\) checked; 0 out of date/);
  });
});

test('copilot sync: a rule whose paths: key reads as no glob fails --check and the sync instead of passing silently (F1-137)', () => {
  withRules({ ok: RULES.double, empty: '---\npaths:\n---\n\n# Empty\n', list: '---\npaths: []\n---\n\n# Empty list\n' }, ({ run, applyTo }) => {
    for (const args of [['--check'], []]) {
      const r = run(...args);
      assert.equal(r.status, 1, `${args.join(' ') || 'sync'}: ${r.stdout}${r.stderr}`);
      assert.match(r.stdout, /^unreadable: \.claude\/rules\/bi\/empty\.md has a paths: key but no glob the generator can read$/m);
      assert.match(r.stdout, /^unreadable: \.claude\/rules\/bi\/list\.md /m);
    }
    assert.equal(applyTo('ok'), '**/*.tmdl,docs/sources/**', 'the readable rules are still written');
    assert.equal(applyTo('empty'), null);
  });
});
