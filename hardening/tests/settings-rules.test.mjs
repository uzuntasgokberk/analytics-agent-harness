// The guard against every permission rule of .claude/settings.json, in auto mode (the default). A hook's "allow" does
// not skip Claude Code's ask or deny rules (Claude Code docs, Permissions, checked 2026-10-19), but an "allow" where a
// rule denies would mislead, so: no deny rule may come back "allow", and an ask rule may come back "allow" only where
// auto mode deliberately treats it as routine (ROUTINE below).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ruleMatches } from '../hooks/lib/permissions.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const hook = path.join(here, '..', 'hooks', 'pre-tool-use.mjs');
const settingsFile = path.join(here, '..', '..', '.claude', 'settings.json');

// Ask rules the guard approves in auto mode, each with the reason; Claude Code still prompts for them.
const ROUTINE = new Map([
  ['Bash(powerbi-desktop open *)', 'local Desktop; opening it is routine in auto mode'],
  // reload is not here: it discards unsaved Desktop work the guard cannot see, so its ask rule keeps prompting.
  // Neither are screenshot and screenshot-all (2026-10-15): desktop.screenshots defaults to "ask", so their ask rules
  // keep prompting; only the user's "on" makes them routine (tests/desktop-screenshots.test.mjs).
  ['PowerShell(powerbi-desktop open *)', 'local Desktop'],
  ['Edit(**/.platform)', 'project file in git; Tier 2 binding changes are reviewed in the diff'],
  // A new definition.pbir; changing an existing report's datasetReference is Tier 2 and asks (tests/tier2.test.mjs).
  ['Edit(**/definition.pbir)', 'project file in git'],
  ['Edit(**/definition.pbism)', 'project file in git'],
  ['Edit(**/*.pbip)', 'project file in git'],
  // relationships.tmdl is not here (2026-10-16): relationships are Tier 2 (AGENTS.md), so auto mode asks.
]);

/** One representative call for a rule: `*` becomes a word, a path pattern becomes a file inside a temp project. */
function callFor(rule, dir) {
  const m = /^(\w+)\(([\s\S]*)\)$/.exec(rule);
  if (!m) return null;
  const [, tool, spec] = m;
  if (tool === 'Bash' || tool === 'PowerShell') {
    // A `*` standing alone is an argument ("x"); one attached to text (`*--force*`, `-f*`) stands for nothing, so the call
    // carries the option itself: `git add *--force*` is `git add --force`, not `git add x--forcex`, an ordinary add (F1-53).
    const command = spec.replace(/(?<=^|\s)\*(?=\s|$)/g, 'x').replace(/\*/g, '').replace(/\s+/g, ' ').trim();
    return { tool_name: tool, tool_input: { command } };
  }
  if (tool !== 'Read' && tool !== 'Edit') return null;
  if (spec.startsWith('!')) return null;
  let p = spec.replace(/\*\*\//g, 'a/').replace(/\/\*\*$/, '/x.txt').replace(/\*/g, 'x');
  if (p.startsWith('~/')) p = path.join(os.homedir(), p.slice(2));
  else if (p.startsWith('/')) p = path.join(dir, p.slice(1));
  else p = path.join(dir, 'sub', p);
  const content = /\.(?:json|platform|pbir|pbism|pbip)$|\.platform$/.test(p) ? '{}' : 'x';
  return tool === 'Read' ? { tool_name: 'Read', tool_input: { file_path: p } } : { tool_name: 'Write', tool_input: { file_path: p, content } };
}

function decide(dir, call) {
  const r = spawnSync(process.execPath, [hook], {
    input: JSON.stringify({ hook_event_name: 'PreToolUse', session_id: 'rules', ...call }),
    env: { ...process.env, CLAUDE_PROJECT_DIR: dir },
    encoding: 'utf8',
  });
  // F1-64: a guard that did not run (exit 1 does not start, exit 2 does not load) prints no verdict, which every check
  // below reads as "not allow". A crash on one variant is a failure here, not a pass.
  assert.equal(r.status, 0, `${call.tool_name} ${JSON.stringify(call.tool_input)}: ${r.stderr}`);
  return r.stdout.trim() ? JSON.parse(r.stdout).hookSpecificOutput?.permissionDecision ?? null : null;
}

test('every deny rule stays denied and every ask rule stays critical unless it is deliberately routine', (t) => {
  if (!fs.existsSync(settingsFile)) return t.skip('no .claude/settings.json next to this harness');
  const settings = JSON.parse(fs.readFileSync(settingsFile, 'utf8'));
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-rules-'));
  fs.mkdirSync(path.join(dir, '.claude'), { recursive: true });
  fs.writeFileSync(path.join(dir, '.claude', 'settings.json'), JSON.stringify(settings));
  const problems = [];
  for (const rule of settings.permissions?.deny ?? []) {
    const call = callFor(rule, dir);
    if (!call) continue;
    // The rule's own call, and the same thing hidden in a routine-looking command.
    const variants = [call];
    if (call.tool_input.command) {
      const x = call.tool_input.command;
      for (const wrapped of [`echo $(${x})`, `echo \`${x}\``, `Get-ChildItem | Where-Object { ${x} }`]) {
        variants.push({ tool_name: 'Bash', tool_input: { command: wrapped } }, { tool_name: 'PowerShell', tool_input: { command: wrapped } });
      }
    }
    if (call.tool_name === 'Read') {
      const file = call.tool_input.file_path;
      variants.push({ tool_name: 'Bash', tool_input: { command: `cat "${file}"` } }, { tool_name: 'PowerShell', tool_input: { command: `Get-Content "${file}"` } });
    }
    for (const v of variants) {
      if (decide(dir, v) === 'allow') problems.push(`deny rule answered allow: ${rule} via ${JSON.stringify(v.tool_input)}`);
    }
  }
  for (const rule of settings.permissions?.ask ?? []) {
    const call = callFor(rule, dir);
    if (!call) continue;
    const got = decide(dir, call);
    if (ROUTINE.has(rule) && got !== 'allow') problems.push(`routine ask rule not answered by auto mode: ${rule} (got ${got})`);
    if (!ROUTINE.has(rule) && got === 'allow') problems.push(`critical ask rule answered allow: ${rule}`);
  }
  fs.rmSync(dir, { recursive: true, force: true });
  assert.deepEqual(problems, []);
});

// Programs that run the same way from both shell tools: a Bash rule for them needs the identical PowerShell rule, or
// the PowerShell tool is the way around the prompt (a `del` or `gh` typed there met no rule before 2026-10-07).
const MIRRORED = new Set(['git', 'gh', 'az', 'fab', 'npm', 'npx', 'pip', 'pip3', 'winget', 'rm', 'sudo', 'curl', 'wget', 'nc',
  'ncat', 'scp', 'sftp', 'ftp', 'ssh', 'pwsh', 'powershell', 'powerbi-desktop', 'powerbi-report-author']);
// PowerShell aliases of the cmdlets the rules name; each needs its own rule, because the rules match the typed text.
const ALIASES = {
  ask: { 'Remove-Item': ['del', 'ri', 'erase', 'rd', 'rmdir', 'rm'] },
  deny: { 'Invoke-WebRequest': ['iwr', 'curl', 'wget'], 'Invoke-RestMethod': ['irm'] },
};

test('the PowerShell rules mirror the Bash rules of shared programs and cover the cmdlet aliases', (t) => {
  if (!fs.existsSync(settingsFile)) return t.skip('no .claude/settings.json next to this harness');
  const settings = JSON.parse(fs.readFileSync(settingsFile, 'utf8'));
  const problems = [];
  for (const list of ['allow', 'ask', 'deny']) {
    const rules = new Set(settings.permissions?.[list] ?? []);
    for (const rule of rules) {
      const m = /^Bash\((\S+)(.*)\)$/.exec(rule);
      if (m && MIRRORED.has(m[1]) && !rules.has(`PowerShell(${m[1]}${m[2]})`)) problems.push(`${list}: ${rule} has no PowerShell twin`);
    }
    for (const [cmdlet, aliases] of Object.entries(ALIASES[list] ?? {})) {
      if (!rules.has(`PowerShell(${cmdlet} *)`)) problems.push(`${list}: PowerShell(${cmdlet} *) missing`);
      for (const a of aliases) if (!rules.has(`PowerShell(${a} *)`)) problems.push(`${list}: alias PowerShell(${a} *) of ${cmdlet} missing`);
    }
  }
  assert.deepEqual(problems, []);
});

// Audit 2026-10-18, F1-53: the allow rules for routine git (switch, add, commit) pre-approved their forced forms.
// Claude Code applies a deny rule before an allow rule, so each forced form has a deny rule of its own, one per shell
// tool. Without the pack they are all that stops `git add -f` of a cache file, `git commit --no-verify` and a switch
// that throws uncommitted work away (`git checkout -f`, which does the same, asks). The matcher is the guard's own
// model of the rule syntax (hooks/lib/permissions.mjs): `*` is any text, and the match ignores case. They are text rules:
// a commit message that spells a flag out (`-m "... --no-verify ..."`) is denied too; reword it or pass it with `-F`.
const FORCED_GIT = [
  'git switch -f main', 'git switch -fc feature/x', 'git switch main -f', 'git switch -c feature/x -f',
  'git switch --force main', 'git switch main --force', 'git switch --force-create feature/x',
  'git switch --discard-changes main', 'git switch main --discard-changes',
  'git add -f Sales.SemanticModel/.pbi/cache.abf', 'git add Sales.SemanticModel/.pbi/cache.abf -f', 'git add -fA',
  'git add --force .', 'git add . --force',
  'git commit --no-verify -m x', 'git commit -m x --no-verify', 'git commit -n -m x', 'git commit -m x -n', 'git commit -nm x',
  'git add -A && git commit --no-verify -m x', 'git status; git switch --discard-changes main',
];
// The routine forms that stay allowed. `git switch -c` is here on purpose: the match ignores case, so a deny rule for
// the forced `-C` (reset a branch to HEAD) would also deny the one switch AGENTS.md pre-approves. Only the pack tells
// them apart, and it alone sees a forced letter inside combined short flags (`git add -Af`, `git commit -anm`).
const ROUTINE_GIT = [
  'git switch -c feature/x', 'git switch -c fix-foo', 'git switch --create feature/x', 'git switch fix-foo', 'git switch feature/x', 'git switch main',
  'git add -A', 'git add -p', 'git add .', 'git add docs/fix-foo.md', 'git add -u',
  'git commit -m "fix: x"', 'git commit --amend', 'git commit --amend --no-edit', 'git commit -am "fix: foo-bar"',
];

/** What the rules alone decide, ordered as Claude Code orders them: a matching deny wins over ask, and ask over allow. */
function rulesVerdict(permissions, tool, command) {
  for (const kind of ['deny', 'ask', 'allow']) {
    if ((permissions?.[kind] ?? []).some((rule) => ruleMatches(rule, tool, { command }))) return kind;
  }
  return null;
}

test('the allow rules of git switch, add and commit do not pre-approve their forced forms, in either shell tool', (t) => {
  if (!fs.existsSync(settingsFile)) return t.skip('no .claude/settings.json next to this harness');
  const { permissions } = JSON.parse(fs.readFileSync(settingsFile, 'utf8'));
  const problems = [];
  for (const tool of ['Bash', 'PowerShell']) {
    for (const command of FORCED_GIT) {
      const got = rulesVerdict(permissions, tool, command);
      if (got !== 'deny') problems.push(`${tool}: ${command} is ${got}, not denied`);
    }
    for (const command of ROUTINE_GIT) {
      const got = rulesVerdict(permissions, tool, command);
      if (got !== 'allow') problems.push(`${tool}: ${command} is ${got}, not allowed`);
    }
  }
  assert.deepEqual(problems, []);
});

// Audit 2026-10-19, F2-4: without the pack, the allow rules Bash/PowerShell(git diff|log|show *) also pre-approved the
// forms that write a file (--output, which overwrote templates/README.md in the audit) or run a configured program
// (--ext-diff, --textconv), and the comparison of any two files on the machine: --no-index, and its implicit form, a
// path outside the repository or /dev/null (git compares files outside the work tree as if --no-index were given).
// Text rules cannot resolve a path, so they deny the spellings of one: absolute (/x, C:/x, C:\x), home (~/x) and
// parent (../x, ..\x). Inside the repository, revisions and ranges (main..feature/x, HEAD~1) stay allowed.
const GIT_READ_ESCAPES = [
  'git diff --output=.claude/settings.json', 'git diff --output .claude/settings.json HEAD~1', 'git log -1 --output=templates/README.md',
  'git show --output=AGENTS.md HEAD', 'git log --format=%s -1 --output=x.md',
  'git diff --no-index a.md b.md', 'git diff --no-index ~/.git-credentials /dev/null',
  'git diff --ext-diff', 'git log -p --ext-diff', 'git log --textconv -p', 'git show --textconv HEAD',
  'git diff /dev/null /c/Windows/win.ini', 'git diff /c/Windows/win.ini /c/Windows/system.ini', 'git diff README.md /dev/null',
  'git diff C:/Windows/win.ini C:/Windows/system.ini', 'git diff C:\\Windows\\win.ini README.md', 'git diff -- /etc/hosts README.md',
  'git diff ~/.git-credentials README.md', 'git diff README.md ~/.git-credentials', 'git diff ../other/appsettings.json README.md',
  'git diff ..\\other\\appsettings.json README.md', 'git diff README.md ../other/web.config',
];
const GIT_READS = [
  'git diff --stat', 'git diff --cached', 'git diff HEAD~1 -- README.md', 'git diff main...feature/x', 'git diff main..feature/x -- docs/a.md',
  'git diff origin/main', 'git diff HEAD~1..HEAD', 'git diff --no-ext-diff', 'git log --oneline -5', 'git log -p --no-textconv -1',
  'git log --format=%h -1', 'git show HEAD --stat', 'git show HEAD~2:README.md',
];

test('F2-4: the git read allow rules do not pre-approve a write, a configured program or a file outside the repository', (t) => {
  if (!fs.existsSync(settingsFile)) return t.skip('no .claude/settings.json next to this harness');
  const { permissions } = JSON.parse(fs.readFileSync(settingsFile, 'utf8'));
  const problems = [];
  for (const tool of ['Bash', 'PowerShell']) {
    for (const command of GIT_READ_ESCAPES) {
      const got = rulesVerdict(permissions, tool, command);
      if (got !== 'deny') problems.push(`${tool}: ${command} is ${got}, not denied`);
    }
    for (const command of GIT_READS) {
      const got = rulesVerdict(permissions, tool, command);
      if (got !== 'allow') problems.push(`${tool}: ${command} is ${got}, not allowed`);
    }
  }
  assert.deepEqual(problems, []);
});
