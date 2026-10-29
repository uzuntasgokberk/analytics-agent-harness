// scan.exclude and the Claude desktop app's git worktrees (2026-10-16). The app creates each worktree under
// .claude/worktrees/<name>/ inside the repository: a full checkout with its own copy of Microsoft's vendored references,
// which are over the Markdown limit and excluded only under their own path. The full validator scan, its project
// inventory (findPbipItems) and the release check skip .claude/worktrees/**; each worktree is checked when run inside it.
// A user's scan.exclude replaces the default list, so the shipped harness.config.json carries the entry as well.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { DEFAULT_CONFIG } from '../hooks/lib/common.mjs';
import { findPbipItems } from '../hooks/lib/validators.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const validateCli = path.join(here, '..', 'scripts', 'validate.mjs');
const releaseCheck = path.join(here, '..', 'scripts', 'release-check.mjs');
const shippedConfig = fs.readFileSync(path.join(here, '..', 'harness.config.json'), 'utf8');

/** 501 lines, no trailing newline: one over the limit for the validator and the release check alike. */
const LONG = Array.from({ length: 501 }, (_, i) => `line ${i + 1}`).join('\n');
const WT = '.claude/worktrees/x';

function repo(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-scan-exclude-'));
  for (const [rel, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), content);
  }
  return dir;
}

const fixture = (extra = {}) => repo({
  'long.md': LONG,
  [`${WT}/long.md`]: LONG,
  [`${WT}/paginated/Orders.rdl`]: '<Report/>',
  ...extra,
});

test('scan.exclude: the default and the shipped config both list .claude/worktrees/**', () => {
  assert.ok(DEFAULT_CONFIG.scan.exclude.includes('.claude/worktrees/**'));
  assert.ok(JSON.parse(shippedConfig).scan.exclude.includes('.claude/worktrees/**'));
});

test('findPbipItems skips a worktree under .claude/worktrees/ (without the exclusion it is found)', () => {
  const dir = fixture();
  try {
    assert.deepEqual(findPbipItems(dir, {}, Infinity).rdl, [`${WT}/paginated/Orders.rdl`]);
    assert.deepEqual(findPbipItems(dir, DEFAULT_CONFIG, Infinity).rdl, []);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('the full validator scan reports a long root Markdown file, never one inside .claude/worktrees/', () => {
  for (const [label, extra] of [['default config', {}], ['shipped config', { 'hardening/harness.config.json': shippedConfig }]]) {
    const dir = fixture(extra);
    try {
      const r = spawnSync(process.execPath, [validateCli, '--json'], { env: { ...process.env, CLAUDE_PROJECT_DIR: dir }, encoding: 'utf8' });
      const { issues } = JSON.parse(r.stdout);
      assert.ok(issues.some((i) => i.file === 'long.md' && /Markdown has \d+ lines/.test(i.message)), `${label}: ${r.stdout}`);
      assert.ok(!issues.some((i) => i.file.startsWith('.claude/worktrees/')), `${label}: ${r.stdout}`);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }
});

test('the release check reports a long root Markdown file, never one inside .claude/worktrees/', () => {
  const dir = fixture({ 'hardening/harness.config.json': shippedConfig });
  try {
    const r = spawnSync(process.execPath, [releaseCheck, dir, '--json'], { encoding: 'utf8' });
    const { findings } = JSON.parse(r.stdout);
    assert.ok(findings.some((f) => f.file === 'long.md' && f.rule === 'markdown-limit'), r.stdout);
    assert.ok(!findings.some((f) => f.file.startsWith('.claude/worktrees/')), r.stdout);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
