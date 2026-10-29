// Follow-up audit round 3 (2026-10-19): the agent's own instructions under .claude/ agree with AGENTS.md and the guard,
// and the core deny rules cover every push the pack blocks as destroying shared history.
// - F2-28: remote branch deletion, mirror and prune pushes meet a deny rule in both shell tools.
// - F2-19, F2-20: a new Power Query parameter and a relationship are Tier 2, never listed as normal work.
// - F2-23: opening Desktop runs in approvals mode auto; the router and the main-session prompt point to desktop.md.
// - F2-29: a skill pre-approves edits only of the files it says it writes.
// - F2-30, F2-60: harness.md names files that exist and the whole update procedure of the vendored references.
// - F2-56: a state list that names TASKS.md uses its headings. F2-57: which rules a TMDL file loads.
// - F2-61: the main-session layers and /bi-plan's editors include paginated reports. F2-21: one theme recipe.
// The checks read the repository next to this folder (an installed copy has no tests) and skip a file that is absent.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ruleMatches } from '../hooks/lib/permissions.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const has = (rel) => fs.existsSync(path.join(root, rel));
const read = (rel) => fs.readFileSync(path.join(root, rel), 'utf8');
/** One line of text, so a phrase the Markdown wraps is still found. */
const flat = (text) => text.replace(/\s+/g, ' ');
const VENDORED = '.claude/skills/bi-semantic-model/references/';

/** Environment without the repository variables an outer git (a hook, a worktree) may set. */
function cleanEnv() {
  const env = { ...process.env };
  for (const k of Object.keys(env)) if (/^GIT_/.test(k)) delete env[k];
  return env;
}

/** The Markdown files this repository authors (tracked or not yet added), without Microsoft's vendored references. */
function markdownFiles() {
  const git = spawnSync('git', ['ls-files', '-z', '--cached', '--others', '--exclude-standard', '--', '*.md'], { cwd: root, encoding: 'utf8', env: cleanEnv() });
  const files = git.status === 0 ? git.stdout.split('\0').filter(Boolean) : [];
  return files.filter((rel) => !rel.startsWith(VENDORED) && has(rel));
}

/** The agent's own instructions: the rules and every skill file, without the vendored references. */
function instructionFiles() {
  return markdownFiles().filter((rel) => rel.startsWith('.claude/rules/bi/') || rel.startsWith('.claude/skills/'));
}

// ---------------------------------------------------------------- F2-28: destructive pushes

const settingsFile = path.join(root, '.claude', 'settings.json');
const DESTRUCTIVE_PUSHES = ['git push origin --delete feature/x', 'git push origin :feature/x', 'git push -d origin feature/x',
  'git push --mirror origin', 'git push --prune origin'];
const PLAIN_PUSHES = ['git push origin feature/x', 'git push -u origin feature/x', 'git push --dry-run origin feature/x',
  'git push origin HEAD:refs/heads/feature/x'];

test('F2-28: a deny rule meets every remote branch deletion, mirror and prune push in both shell tools; a plain push meets none', (t) => {
  if (!fs.existsSync(settingsFile)) return t.skip('no .claude/settings.json next to this harness');
  const deny = JSON.parse(fs.readFileSync(settingsFile, 'utf8')).permissions?.deny ?? [];
  const problems = [];
  for (const tool of ['Bash', 'PowerShell']) {
    for (const command of DESTRUCTIVE_PUSHES) {
      if (!deny.some((rule) => ruleMatches(rule, tool, { command }, root))) problems.push(`${tool}: ${command} meets no deny rule`);
    }
    for (const command of PLAIN_PUSHES) {
      const hit = deny.filter((rule) => ruleMatches(rule, tool, { command }, root));
      if (hit.length) problems.push(`${tool}: ${command} is denied by ${hit.join(', ')}`);
    }
  }
  assert.deepEqual(problems, []);
});

// ---------------------------------------------------------------- F2-19, F2-20: Tier 2 is never "normal"

// The two passages the audit found: a "not Tier 2" list naming a parameter (power-query-m.md) and a table row that marks
// a relationship "normal" (incremental-refresh.md). A paginated report's parameter default is not Tier 2 (AGENTS.md), and
// rdl.md says so in other words; these patterns leave it alone.
const NOT_TIER2 = [
  { re: /\bis not:[^.]*?\b(?:parameter|relationship)s?\b/i, what: 'a "not Tier 2" list names a parameter or a relationship' },
  { re: /^\|[^\n]*\b(?:parameter|relationship)s?\b[^\n]*\|\s*(?:normal|ordinary|not Tier 2)\s*\|\s*$/im, what: 'a table row marks a parameter or a relationship normal' },
];

test('F2-19, F2-20: no rule or skill lists a Power Query parameter or a relationship as normal, not Tier 2 work', () => {
  const problems = [];
  for (const rel of instructionFiles()) {
    const text = read(rel);
    for (const { re, what } of NOT_TIER2) {
      const m = re.exec(re.flags.includes('m') ? text : flat(text));
      if (m) problems.push(`${rel}: ${what}: ${m[0].slice(0, 160)}`);
    }
  }
  assert.deepEqual(problems, []);
});

test('F2-19: the Power Query rule names a new parameter, also one replacing a hard-coded value, as Tier 2', (t) => {
  if (!has('.claude/rules/bi/power-query-m.md')) return t.skip('no power-query-m rule');
  const text = flat(read('.claude/rules/bi/power-query-m.md'));
  assert.match(text, /a new parameter \(also one replacing a hard-coded value\)[^.]*is Tier 2/);
});

test('F2-20: the incremental refresh table has a Tier 2 row for a relationship of the table', (t) => {
  if (!has('.claude/skills/bi-data-sources/incremental-refresh.md')) return t.skip('no incremental refresh guide');
  assert.match(read('.claude/skills/bi-data-sources/incremental-refresh.md'), /^\| a relationship of the table[^|\n]*\| Tier 2[^|\n]*\|\s*$/m);
});

// ---------------------------------------------------------------- F2-23: Desktop approvals

test('F2-23: bi-map and bi-expert point to desktop.md and never say that every Desktop action needs approval', () => {
  const problems = [];
  for (const rel of ['.claude/skills/bi-map/SKILL.md', '.claude/agents/bi-expert.md']) {
    if (!has(rel)) continue;
    const text = flat(read(rel));
    if (/Desktop actions? (?:needs?|requires?) (?:the user's )?approval/i.test(text)) problems.push(`${rel}: says Desktop actions need approval`);
    if (/\bopen(?:ing)?\b[^;]{0,140}\bwithout the user's approval/i.test(text)) problems.push(`${rel}: says opening Desktop needs approval`);
    if (!text.includes('docs/harness/desktop.md')) problems.push(`${rel}: does not name docs/harness/desktop.md`);
    if (!/`?open`? runs in approvals mode `?auto`?/.test(text)) problems.push(`${rel}: does not say open runs in approvals mode auto`);
  }
  assert.deepEqual(problems, []);
});

// ---------------------------------------------------------------- F2-29: skill allowed-tools

/** The allowed-tools entries of every SKILL.md: `Bash(git status *)` is one entry. */
function allowedTools() {
  const found = [];
  const dir = path.join(root, '.claude', 'skills');
  if (!fs.existsSync(dir)) return found;
  for (const name of fs.readdirSync(dir)) {
    const rel = `.claude/skills/${name}/SKILL.md`;
    if (!has(rel)) continue;
    const front = /^---\r?\n([\s\S]*?)\r?\n---/.exec(read(rel))?.[1] ?? '';
    const line = /^allowed-tools:[ \t]*(.*)$/m.exec(front)?.[1] ?? '';
    found.push({ rel, entries: line.match(/[A-Za-z_][\w-]*(?:\([^)]*\))?/g) ?? [] });
  }
  return found;
}

test('F2-29: no skill pre-approves a bare Edit or Write; /bi-onboard only the three drafts it writes', () => {
  const problems = [];
  const drafts = new Set(['/docs/sources/README.md', '/docs/conventions.md', '/TASKS.md']);
  for (const { rel, entries } of allowedTools()) {
    for (const entry of entries) {
      const m = /^(Edit|Write|MultiEdit|NotebookEdit)(?:\(([^)]*)\))?$/.exec(entry);
      if (!m) continue;
      const spec = (m[2] ?? '').trim();
      if (!spec || spec === '*' || spec === '**' || spec === '/**') problems.push(`${rel}: ${entry} pre-approves every file edit`);
      else if (rel === '.claude/skills/bi-onboard/SKILL.md' && !drafts.has(spec)) problems.push(`${rel}: ${entry} is not one of its drafts`);
    }
  }
  assert.deepEqual(problems, []);
});

// ---------------------------------------------------------------- F2-30, F2-60: harness.md

test('F2-30: every backticked hardening path in harness.md exists; the fake-value rule names a test that joins its values', (t) => {
  if (!has('.claude/rules/bi/harness.md')) return t.skip('no harness rule');
  const text = read('.claude/rules/bi/harness.md');
  const named = [...text.matchAll(/`([^`]+)`/g)].flatMap((m) => m[1].split(/\s+/)).filter((p) => p.startsWith('hardening/') && !/[<*]/.test(p));
  assert.deepEqual(named.filter((p) => !has(p)), [], 'named in harness.md but missing');
  const rule = text.split(/\r?\n(?=- )/).find((item) => /real credential/.test(item)) ?? '';
  const examples = [...rule.matchAll(/`(hardening\/tests\/[\w.-]+\.test\.mjs)`/g)].map((m) => m[1]);
  assert.ok(examples.length > 0, `the credential rule names no test file: ${flat(rule)}`);
  for (const ex of examples) assert.match(read(ex), /\]\.join\(''\)/, `${ex} builds no value at run time`);
});

test('F2-60: harness.md gives the whole update of the vendored references: SHA256SUMS and the commit in both notices', (t) => {
  if (!has('.claude/rules/bi/harness.md')) return t.skip('no harness rule');
  const item = flat(read('.claude/rules/bi/harness.md').split(/\r?\n(?=- )/).find((i) => i.includes(VENDORED)) ?? '');
  for (const name of ['UPSTREAM.md', 'THIRD_PARTY_NOTICES.md', 'SHA256SUMS']) assert.ok(item.includes(`\`${name}\``), `${name} missing from: ${item}`);
});

// ---------------------------------------------------------------- F2-56: TASKS.md states

test('F2-56: every state list that names TASKS.md uses the headings of TASKS.md', (t) => {
  if (!has('TASKS.md')) return t.skip('no TASKS.md');
  const states = [...read('TASKS.md').matchAll(/^## (.+?)\s*$/gm)].map((m) => m[1]);
  assert.ok(states.includes('Todo') && states.includes('Done'), `TASKS.md headings: ${states.join(', ')}`);
  const problems = [];
  for (const rel of markdownFiles()) {
    for (const sentence of flat(read(rel)).split(/(?<=[.!?])\s+(?=[A-Z0-9`*[(])/)) {
      if (!sentence.includes('TASKS.md') && rel !== 'TASKS.md') continue;
      const parts = sentence.replace(/\([^)]*\)/g, '').split('→').map((s) => s.replace(/\s+/g, ' ').trim());
      if (parts.length < 3) continue;
      const ok = states.some((s) => parts[0].endsWith(s)) && states.some((s) => parts.at(-1).startsWith(s))
        && parts.slice(1, -1).every((p) => p.split(/\s+or\s+/).every((s) => states.includes(s)));
      if (!ok) problems.push(`${rel}: ${sentence.slice(0, 160)}`);
    }
  }
  assert.deepEqual(problems, []);
});

// ---------------------------------------------------------------- F2-57: which rules a TMDL file loads

/** The `paths` globs of a rule's frontmatter (block list, quoted or not). */
function rulePaths(text) {
  const front = /^---\r?\n([\s\S]*?)\r?\n---/.exec(text)?.[1] ?? '';
  const block = /^paths:[ \t]*\r?\n((?:[ \t]+-[^\n]*\n?)+)/m.exec(front)?.[1] ?? '';
  return [...block.matchAll(/^[ \t]+-[ \t]*["']?([^"'\r\n]+?)["']?[ \t]*$/gm)].map((m) => m[1]);
}

test('F2-57: each TMDL file loads exactly the rules its content needs (functions.tmdl holds DAX)', (t) => {
  const dir = path.join(root, '.claude', 'rules', 'bi');
  if (!fs.existsSync(dir)) return t.skip('no rules');
  // path.matchesGlob arrived in Node 22.5; the pack supports Node 18.17 and later.
  if (typeof path.posix.matchesGlob !== 'function') return t.skip(`path.matchesGlob is missing in Node ${process.version}`);
  const rules = fs.readdirSync(dir).filter((f) => f.endsWith('.md')).map((f) => ({ name: f.slice(0, -3), globs: rulePaths(fs.readFileSync(path.join(dir, f), 'utf8')) }));
  const def = 'powerbi/Sales.SemanticModel/definition';
  const expected = {
    [`${def}/tables/Sales.tmdl`]: ['dax', 'power-query-m', 'tmdl'],
    [`${def}/expressions.tmdl`]: ['power-query-m', 'tmdl'],
    [`${def}/functions.tmdl`]: ['dax', 'tmdl'],
    [`${def}/roles/Reader.tmdl`]: ['rls-security', 'tmdl'],
    [`${def}/model.tmdl`]: ['tmdl'],
    [`${def}/relationships.tmdl`]: ['tmdl'],
    'models/Finance/database.tmdl': ['tmdl'],
  };
  for (const [file, want] of Object.entries(expected)) {
    const got = rules.filter((r) => r.globs.some((g) => path.posix.matchesGlob(file, g))).map((r) => r.name).sort();
    assert.deepEqual(got, want, file);
  }
});

// ---------------------------------------------------------------- F2-61: paginated reports in the loop

test('F2-61: the main-session loop names every layer and /bi-plan names the RDL editor', () => {
  if (has('.claude/agents/bi-expert.md')) {
    const classify = flat(read('.claude/agents/bi-expert.md')).match(/\*\*Classify:\*\*[^.]*/)?.[0] ?? '';
    for (const layer of ['model', 'report', 'paginated report', 'SSIS', 'project']) assert.ok(classify.includes(layer), `bi-expert Classify lacks ${layer}: ${classify}`);
  }
  if (has('.claude/skills/bi-plan/SKILL.md')) assert.match(read('.claude/skills/bi-plan/SKILL.md'), /`bi-rdl-editor`/);
});

// ---------------------------------------------------------------- F2-21: one theme recipe

test('F2-21: only THEME.md gives the theme recipe; no other Markdown forbids writing customTheme by hand', () => {
  const problems = [];
  for (const rel of markdownFiles()) {
    if (rel === '.claude/skills/bi-report-design/THEME.md') continue;
    const m = /\bnever\b[^.]{0,80}customTheme|customTheme[^.]{0,120}\bby hand\b/i.exec(flat(read(rel)));
    if (m) problems.push(`${rel}: ${m[0]}`);
  }
  assert.deepEqual(problems, []);
});
