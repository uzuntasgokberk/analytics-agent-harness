// GitHub Copilot does not load Claude's path-scoped rules; .github/instructions/bi-*.instructions.md are generated
// pointers with the same globs (hardening/scripts/sync-copilot-instructions.mjs). They must stay in sync with
// .claude/rules/bi/*.md: this test fails when a rule's paths changed and the generator was not re-run.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '..', '..');
const script = path.join(root, 'hardening', 'scripts', 'sync-copilot-instructions.mjs');

test('copilot: every rule with paths has an in-sync instructions pointer, and no orphan exists', (t) => {
  if (!fs.existsSync(path.join(root, '.claude', 'rules', 'bi'))) return t.skip('no .claude/rules/bi next to this harness');
  const r = spawnSync(process.execPath, [script, '--check'], { encoding: 'utf8' });
  assert.equal(r.status, 0, `${r.stdout}${r.stderr}\nRun: node hardening/scripts/sync-copilot-instructions.mjs`);
  const files = fs.readdirSync(path.join(root, '.github', 'instructions')).filter((f) => /^bi-.*\.instructions\.md$/.test(f));
  assert.ok(files.length >= 8, `pointers present: ${files.length}`);
  for (const f of files) {
    const text = fs.readFileSync(path.join(root, '.github', 'instructions', f), 'utf8');
    // A clone with core.autocrlf=true (Git for Windows' default) checks the files out with CRLF line ends.
    assert.match(text, /^---\r?\napplyTo: ".+"\r?\n/, `${f} has an applyTo frontmatter`);
    const rule = f.replace(/^bi-|\.instructions\.md$/g, '');
    assert.match(text, new RegExp(`\\.claude/rules/bi/${rule.replace(/[-]/g, '\\-')}\\.md`), `${f} points at its rule`);
    assert.ok(text.split('\n').length < 20, `${f} is a pointer, not a copy`);
  }
});
