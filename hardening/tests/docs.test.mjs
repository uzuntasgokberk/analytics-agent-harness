// What the Markdown and the CI template say must match what the code does (audit 2026-10-18, documentation group):
// - F1-56: a ```powershell fence also runs in Windows PowerShell 5.1, which cannot parse `&&` or `||`.
// - F1-86: a TMDL rename or delete and a relationship edit ask in `auto` and `ask` mode and are never auto-approved
//   (tier2.test.mjs); the README and how-it-works.md said the guard logs a rename and passes a relationship edit.
// - F1-52: the git commands the security auditor's procedure names must not be denied by the guards it runs under.
// - F1-125, F1-126, F1-121: the CI push trigger, the eval scenario E3 and the FAQ's hook command.
// The checks read the repository next to this folder (an installed copy has no tests); the guard checks run the hook
// files as processes, in a temporary project, like the other guard tests.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const hooks = path.join(root, 'hardening', 'hooks');
const has = (rel) => fs.existsSync(path.join(root, rel));
const read = (rel) => fs.readFileSync(path.join(root, rel), 'utf8');
/** One line of text, so a phrase the Markdown wraps is still found. */
const flat = (text) => text.replace(/\s+/g, ' ');

/**
 * The Markdown files this repository authors: tracked or not yet added (Git skips what it ignores, such as
 * .claude/worktrees), without the vendored folders. Those hold Microsoft's files unmodified and nobody edits them here:
 * the semantic model references, and any folder that carries an UPSTREAM.md.
 */
function markdownFiles() {
  const git = spawnSync('git', ['ls-files', '-z', '--cached', '--others', '--exclude-standard', '--', '*.md'], { cwd: root, encoding: 'utf8' });
  const files = git.status === 0 ? git.stdout.split('\0').filter(Boolean) : [];
  const vendored = ['.claude/skills/bi-semantic-model/references/', ...files.filter((rel) => path.posix.basename(rel) === 'UPSTREAM.md').map((rel) => `${path.posix.dirname(rel)}/`)];
  return files.filter((rel) => !vendored.some((dir) => rel.startsWith(dir)));
}

/** The lines of every ```powershell fence of a Markdown text (an indented fence inside a list too), with their line numbers. */
function powershellLines(text) {
  const found = [];
  let fence = null;
  text.split(/\r?\n/).forEach((line, i) => {
    const m = /^\s*(`{3,}|~{3,})(.*)$/.exec(line);
    if (!fence) {
      if (m) fence = { marker: m[1], powershell: /^(?:powershell|ps1)$/i.test(m[2].trim().split(/\s+/)[0]) };
    } else if (m && m[1].startsWith(fence.marker) && !m[2].trim()) {
      fence = null;
    } else if (fence.powershell) {
      found.push({ line: i + 1, text: line });
    }
  });
  return found;
}

/** The code of a PowerShell line: quoted strings dropped, a `#` comment cut off. */
function codeOf(line) {
  let out = '';
  let quote = null;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (quote) {
      if (c === '`' && quote === '"') i++; // a backtick escapes the next character inside double quotes
      else if (c === quote) quote = null;
    } else if (c === '"' || c === "'") quote = c;
    else if (c === '#' && (i === 0 || /\s/.test(line[i - 1]))) break;
    else out += c;
  }
  return out;
}

const chained = (text) => powershellLines(text).filter((l) => /&&|\|\|/.test(codeOf(l.text)));

test('docs: the PowerShell fence check finds && and || in code, not in a comment, a string or another language', () => {
  const md = [
    '```powershell', 'git add -A && git commit -m "x"', 'a || b', '```',
    '```powershell', 'git add -A   # then commit && push', "Write-Output 'a && b' \"c || d\"", '# && alone', '```',
    '   ```powershell', '   git add -A && git status', '   ```',
    '```bash', 'git add -A && git commit -m "x"', '```',
    '```text', 'a && b', '```',
  ].join('\n');
  assert.deepEqual(chained(md).map((l) => l.line), [2, 3, 11]);
});

test('docs: no ```powershell fence in the Markdown of this repository chains commands with && or || (F1-56)', (t) => {
  const files = markdownFiles();
  if (!files.length) return t.skip('not a Git checkout of the harness');
  const bad = [];
  for (const rel of files) for (const l of chained(read(rel))) bad.push(`${rel}:${l.line}: ${l.text.trim()}`);
  assert.deepEqual(bad, [], 'Windows PowerShell 5.1 cannot parse && or ||: put each command on its own line');
  assert.ok(files.some((rel) => powershellLines(read(rel)).length), 'the check found at least one PowerShell fence to read');
});

test('docs: README and how-it-works do not say a TMDL rename is auto-approved or a relationship edit is routine for the guard (F1-86)', (t) => {
  const files = ['README.md', 'docs/harness/how-it-works.md'];
  if (!files.every(has)) return t.skip('no README.md next to this harness');
  for (const rel of files) {
    const text = flat(read(rel));
    for (const old of ['relationship edit is routine', 'relationship edit is a routine', 'rename is logged in `auto`', 'that `auto` approves']) {
      assert.ok(!text.includes(old), `${rel} still says "${old}": the guard asks for both in auto and ask mode and never auto-approves them (tier2.test.mjs)`);
    }
  }
});

/** The permission decision of each PreToolUse guard for one shell command run by a subagent, in a temporary project. */
function verdicts(dir, agent, command) {
  return ['pre-tool-use.mjs', 'agent-scope.mjs'].map((script) => {
    const r = spawnSync(process.execPath, [path.join(hooks, script)], {
      input: JSON.stringify({ hook_event_name: 'PreToolUse', session_id: 'docs', cwd: dir, agent_type: agent, tool_name: 'Bash', tool_input: { command } }),
      env: { ...process.env, CLAUDE_PROJECT_DIR: dir },
      encoding: 'utf8',
    });
    assert.equal(r.status, 0, `${script}: ${r.stderr}`);
    return r.stdout.trim() ? JSON.parse(r.stdout).hookSpecificOutput?.permissionDecision ?? null : null;
  });
}
const gitSpans = (text) => [...text.matchAll(/`(git [^`\n]+)`/g)].map((m) => m[1]);

test('docs: the git commands the security auditor is told to run are not denied by the guards it runs under; the secret-file forms stay denied (F1-52)', (t) => {
  const agentFile = '.claude/agents/bi-security-auditor.md';
  const checklist = '.claude/skills/bi-map/references/security-review.md';
  if (!has(agentFile) || !has(checklist)) return t.skip('no .claude/agents next to this harness');
  const procedure = read(agentFile).split(/^## /m).find((section) => section.startsWith('Procedure'));
  assert.ok(procedure, 'the agent file has a Procedure section');
  const commands = [...new Set([
    ...gitSpans(procedure),
    ...gitSpans(read(checklist)).filter((c) => /^git (?:ls-files|log|show)\b/.test(c)),
  ])];
  assert.ok(commands.some((c) => c.startsWith('git ls-files')) && commands.some((c) => c.startsWith('git log')), `the procedure names a listing and a history command: ${commands.join(' | ')}`);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-docs-'));
  try {
    for (const command of commands) {
      assert.ok(!command.includes('<'), `${command}: a placeholder is a redirect to the shell parser; write a concrete command`);
      assert.ok(!verdicts(dir, 'bi-security-auditor', command).includes('deny'), `denied for the auditor: ${command}`);
    }
    // The documented reason for the allowed forms: the file itself stays out of reach.
    for (const command of ['git log -p -- .env', 'git show HEAD:.env']) {
      assert.equal(verdicts(dir, 'bi-security-auditor', command)[0], 'deny', command);
    }
    assert.match(flat(procedure), /`git log` or `git show` of the secret file itself is denied/, 'the procedure says so');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('docs: the CI push trigger tells the reader to list every connected branch, and the Fabric guide says the check needs it (F1-125)', (t) => {
  if (!has('hardening/ci/bi-validate.yml') || !has('docs/harness/fabric-git.md')) return t.skip('no CI template next to this harness');
  const branchesLine = read('hardening/ci/bi-validate.yml').split(/\r?\n/).find((l) => /^\s*branches:/.test(l));
  assert.ok(branchesLine, 'the push trigger lists branches');
  const comment = branchesLine.slice(branchesLine.indexOf('#') + 1);
  assert.ok(branchesLine.includes('#') && /Fabric/i.test(comment) && /branch/i.test(comment), 'the comment on the branches line says to add the branches a Fabric workspace is connected to');
  assert.match(flat(read('docs/harness/fabric-git.md')), /push trigger/, 'fabric-git.md says the branch must be in the workflow\'s push trigger');
});

test('docs: eval scenario E3 does not ask rdl-compare to prove the data layer unchanged (F1-126)', (t) => {
  if (!has('hardening/tests/eval/README.md')) return t.skip('no eval README next to this harness');
  const row = read('hardening/tests/eval/README.md').split(/\r?\n/).find((l) => l.startsWith('| E3 |'));
  assert.ok(row, 'the eval has a scenario E3');
  // rdl-compare removes <DataSources> and <DataSets> from both files and compares the rest: it is blind to the data layer.
  assert.doesNotMatch(flat(row), /rdl-compare[^|;]*data layer unchanged/);
  assert.match(row, /\bdiff\b.*<DataSources>.*<DataSets>/, 'E3 names a check that does see the data layer');
});

test('docs: the FAQ tells a repository that has the pack to register the hooks with --update --enable-hooks (F1-121)', (t) => {
  if (!has('docs/harness/faq.md')) return t.skip('no docs next to this harness');
  const row = read('docs/harness/faq.md').split(/\r?\n/).find((l) => l.startsWith('| Claude Code hooks not registered'));
  assert.ok(row, 'the FAQ has the /bi-doctor row for unregistered hooks');
  assert.match(row, /--update --enable-hooks/);
  assert.match(row, /--update --enable-hooks --shared/);
  assert.doesNotMatch(row, /install again with/, 'the installer refuses --enable-hooks without --hardening or --update');
});
