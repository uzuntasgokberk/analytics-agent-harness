// Follow-up audit 2026-10-18 (round 2), group W2-F: the file guard, the pack's self-protection and the subagent scopes.
// F1-110: the hook-level write denies (Model.bim, an auto date/time table, invalid JSON, a BOM, a PBIR name, a Markdown
//         file over 500 lines) had no test of their own.
// F1-79:  the spawned-hook tests read the developer's own ~/.claude/settings.json, so a user rule failed the suite.
// F1-91:  theme work is routed to bi-pbir-editor, whose scope denied the theme file under StaticResources/.
// F1-92:  quoted and backslash spellings of the validator for scoped subagents (already passing: pinned).
// Residual gaps of PR #15: settings deny rules under Copilot (R1), the reason of a deleted settings file (R2), Grep globs
// that reach *.rdl.data, .ppk and .git-credentials (R3, R5), same-named objects in two tables (R4), the settings `env` and
// the Copilot hook files (R6), the named imports of the entry scripts (R7), a non-object `approvals` (R8) and the scope
// guard's reading of abbreviated git options (R9).
// Fixtures are temporary projects; every hook runs with an empty home folder (no user-level settings rules), and fake
// values only.
import { after, test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { approvalsWidened, autoApprovalActive, autoApprovalState, labModeActive, loadConfig } from '../hooks/lib/common.mjs';
import { classifyPath } from '../hooks/lib/policy.mjs';
import { removedDeclarations } from '../hooks/lib/validators.mjs';

const pack = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const hooksDir = path.join(pack, 'hooks');
const preHook = path.join(hooksDir, 'pre-tool-use.mjs');
const scopeHook = path.join(hooksDir, 'agent-scope.mjs');
const checker = path.join(pack, 'scripts', 'check-hooks.mjs');

const temps = [];
after(() => temps.forEach((dir) => fs.rmSync(dir, { recursive: true, force: true })));
const tempDir = (name) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `bi-harness-w2f-${name}-`));
  temps.push(dir);
  return dir;
};
const emptyHome = tempDir('home');

/** A temporary project holding `files` (text, or an object written as JSON). */
function project(files = {}) {
  const dir = tempDir('project');
  for (const [rel, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), typeof content === 'string' ? content : `${JSON.stringify(content, null, 2)}\n`);
  }
  return dir;
}

/**
 * Runs a hook in `dir` with an isolated home; `host` sets BI_HARNESS_HOST (none: Claude Code, or Copilot's Claude dialect when
 * the payload has a timestamp). Returns the decision and its reason (the CLI's native output is flat).
 */
function run(dir, payload, { script = preHook, host = null, home = emptyHome } = {}) {
  const env = { ...process.env, CLAUDE_PROJECT_DIR: dir, HOME: home, USERPROFILE: home };
  delete env.BI_HARNESS_HOST;
  if (host) env.BI_HARNESS_HOST = host;
  const r = spawnSync(process.execPath, [script], { input: JSON.stringify(payload), env, encoding: 'utf8' });
  assert.equal(r.status, 0, `${JSON.stringify(payload).slice(0, 200)}: ${r.stderr}`);
  const out = r.stdout.trim() ? JSON.parse(r.stdout) : null;
  const d = out?.hookSpecificOutput ?? out;
  return { decision: d?.permissionDecision ?? null, reason: d?.permissionDecisionReason ?? '' };
}
const claude = (tool_name, tool_input, extra = {}) => ({ hook_event_name: 'PreToolUse', session_id: 'w2f', tool_name, tool_input, ...extra });
const guard = (dir, tool_name, tool_input, options) => run(dir, claude(tool_name, tool_input), options);
const scope = (dir, agent, tool_name, tool_input) => run(dir, claude(tool_name, tool_input, { agent_type: agent }), { script: scopeHook }).decision;
const cliCall = (dir, toolName, toolArgs) => ({ sessionId: 'w2f', timestamp: 1760000000000, cwd: dir, toolName, toolArgs });
const vsCall = (tool_name, tool_input) => ({ hook_event_name: 'PreToolUse', session_id: 'w2f', timestamp: '2026-10-19T08:00:00Z', tool_name, tool_input });
const dialectCall = (tool_name, tool_input) => ({ hook_event_name: 'PreToolUse', session_id: 'w2f', timestamp: '2026-10-19T08:00:00.000Z', tool_name, tool_input });
const PATCH_OF = (op, file) => ['*** Begin Patch', `*** ${op} File: ${file}`, '*** End Patch'].join('\n');
const HOSTS = [
  ['VS Code', 'vscode', (dir, input) => vsCall('apply_patch', { input, explanation: 'e' })],
  ['Copilot CLI', 'copilot-cli', (dir, input) => cliCall(dir, 'apply_patch', { input })],
  ['the CLI\'s Claude registration', null, (dir, input) => dialectCall('apply_patch', { input })],
];
const lines = (n) => `${Array.from({ length: n }, (_, i) => `line ${i + 1}`).join('\n')}\n`;

// ---------------------------------------------------------------- F1-110: the write denies of the file guard

test('F1-110: Model.bim, an auto date/time table, invalid JSON, a BOM, a bad PBIR name and a Markdown file over 500 lines are denied by the hook', () => {
  const page = 'R.Report/definition/pages/p1/page.json';
  const dir = project({ [page]: '{"name":"p1"}\n', 'docs/long.md': lines(600), 'S.SemanticModel/model.bim': '{}\n' });
  const write = (rel, content) => guard(dir, 'Write', { file_path: path.join(dir, rel), content });
  for (const [label, r, reason] of [
    ['a new model.bim', write('S.SemanticModel/model.bim', '{}'), /This harness works on TMDL only and never edits Model\.bim/],
    ['an edit of model.bim', guard(dir, 'Edit', { file_path: path.join(dir, 'S.SemanticModel', 'model.bim'), old_string: '{}', new_string: '{"x":1}' }), /TMDL only/],
    ['LocalDateTable', write('S.SemanticModel/definition/tables/LocalDateTable_abc.tmdl', 'table x\n'), /is an auto date\/time table generated by Power BI Desktop/],
    ['DateTableTemplate', write('S.SemanticModel/definition/tables/DateTableTemplate_1.tmdl', 'table x\n'), /auto date\/time table/],
    ['broken PBIR JSON', write(page, '{"name": '), /would leave R\.Report\/definition\/pages\/p1\/page\.json as invalid JSON/],
    ['a BOM', write(page, '\uFEFF{"name":"p1"}'), /PBIP files must be UTF-8 without BOM\./],
    ['a bad PBIR name', write('R.Report/definition/pages/bad name/page.json', '{"name":"p1"}'), /PBIR object name "bad name" is invalid/],
    ['501 lines', write('docs/new.md', lines(501)), /docs\/new\.md would have 501 lines; the harness limit is 500\./],
    ['an edit that grows a long file', guard(dir, 'Edit', { file_path: path.join(dir, 'docs', 'long.md'), old_string: 'line 600\n', new_string: 'line 600\nline 601\n' }), /would have 601 lines/],
  ]) {
    assert.equal(r.decision, 'deny', label);
    assert.match(r.reason, reason, label);
  }
  // Controls: a valid page, 499 and 500 lines, and an edit that leaves a long file as long as it was.
  assert.notEqual(write(page, '{"name":"p1","displayName":"Overview"}').decision, 'deny', 'a valid page.json');
  assert.notEqual(write('docs/new.md', lines(499)).decision, 'deny', '499 lines');
  assert.notEqual(write('docs/new.md', lines(500)).decision, 'deny', '500 lines');
  assert.notEqual(guard(dir, 'Edit', { file_path: path.join(dir, 'docs', 'long.md'), old_string: 'line 600\n', new_string: 'last line\n' }).decision, 'deny', 'a 600-line file that stays at 600');
});

// ---------------------------------------------------------------- F1-79: the suite runs with a home of its own

test('F1-79: run-all.mjs gives the tests a home folder of their own, so a user-level rule of the developer never reaches them', () => {
  const dir = tempDir('runall');
  const developerHome = tempDir('devhome');
  fs.mkdirSync(path.join(developerHome, '.claude'), { recursive: true });
  fs.writeFileSync(path.join(developerHome, '.claude', 'settings.json'), JSON.stringify({ permissions: { deny: ['Bash(git switch *)'] } }));
  fs.copyFileSync(path.join(pack, 'tests', 'run-all.mjs'), path.join(dir, 'run-all.mjs'));
  // The probe runs as one of the suite's tests: its home, and every hook it starts, must not be the developer's.
  fs.writeFileSync(path.join(dir, 'home.test.mjs'), [
    "import { test } from 'node:test';",
    "import assert from 'node:assert/strict';",
    "import fs from 'node:fs';",
    "import os from 'node:os';",
    "import path from 'node:path';",
    "test('home', () => {",
    "  const developer = process.env.W2F_DEVELOPER_HOME;",
    "  assert.ok(developer, 'the outer test names the developer home');",
    "  assert.notEqual(path.resolve(os.homedir()).toLowerCase(), path.resolve(developer).toLowerCase(), 'the tests read another home');",
    "  assert.equal(fs.existsSync(path.join(os.homedir(), '.claude', 'settings.json')), false, 'and it holds no settings');",
    "  assert.equal(path.resolve(process.env.HOME).toLowerCase(), path.resolve(os.homedir()).toLowerCase(), 'HOME and USERPROFILE agree');",
    '});',
    '',
  ].join('\n'));
  const env = { ...process.env, HOME: developerHome, USERPROFILE: developerHome, W2F_DEVELOPER_HOME: developerHome };
  delete env.NODE_TEST_CONTEXT; // the copy runs as a top-level runner, not as a child of this one
  const r = spawnSync(process.execPath, [path.join(dir, 'run-all.mjs')], { cwd: dir, env, encoding: 'utf8' });
  assert.equal(r.status, 0, r.stdout + r.stderr);
});

test('F1-79: the guard reads the user-level rules of the home it is given (the reason the suite needs a home of its own)', () => {
  const dir = project({ 'docs/a.md': '# a\n' });
  const ruled = tempDir('ruledhome');
  fs.mkdirSync(path.join(ruled, '.claude'), { recursive: true });
  fs.writeFileSync(path.join(ruled, '.claude', 'settings.json'), JSON.stringify({ permissions: { deny: ['Bash(git switch *)'] } }));
  assert.equal(guard(dir, 'Bash', { command: 'git switch -c feature/x' }).decision, 'allow', 'an empty home: routine');
  assert.equal(guard(dir, 'Bash', { command: 'git switch -c feature/x' }, { home: ruled }).decision, null, 'a user deny rule: the guard lets it speak');
});

// ---------------------------------------------------------------- F1-91: the report editor registers a theme

test('F1-91: bi-pbir-editor may write the theme files of a report under StaticResources/, and nothing else outside definition/', () => {
  const dir = project();
  const write = (rel) => scope(dir, 'bi-pbir-editor', 'Write', { file_path: path.join(dir, rel), content: '{}' });
  for (const rel of ['powerbi/Sales.Report/StaticResources/RegisteredResources/BIHarnessDefault.json',
    'powerbi/Sales.Report/StaticResources/SharedResources/BaseThemes/CY24SU10.json', 'powerbi/Sales.Report/definition/report.json']) {
    assert.equal(write(rel), null, rel);
  }
  for (const rel of ['powerbi/Sales.Report/report.json', 'powerbi/Sales.Report/definition.pbir', 'powerbi/Sales.SemanticModel/definition/model.tmdl',
    'StaticResources/RegisteredResources/x.json', 'powerbi/Sales.SemanticModel/StaticResources/x.json']) {
    assert.equal(write(rel), 'deny', rel);
  }
});

// ---------------------------------------------------------------- F1-92: the validator in quotes and backslashes (pin)

test('F1-92: a quoted --files path and backslash spellings of the validator pass for every scoped subagent; a second command still does not', () => {
  const dir = project();
  for (const agent of ['bi-validator', 'bi-tmdl-modeler', 'bi-rdl-editor', 'bi-pbir-editor']) {
    for (const tool of ['Bash', 'PowerShell']) {
      for (const command of [
        'node hardening/scripts/validate.mjs --files "Sales Report.Report/definition/report.json"',
        "node hardening/scripts/validate.mjs --files 'Sales Report.Report/definition/report.json'",
        'node hardening\\scripts\\validate.mjs --changed',
        'node .\\hardening\\scripts\\validate.mjs --files ".\\Sales Report.Report\\definition\\report.json"',
      ]) assert.equal(scope(dir, agent, tool, { command }), null, `${agent} ${tool}: ${command}`);
      for (const command of [
        'node hardening/scripts/validate.mjs --files "a b"; rm x', 'node hardening/scripts/validate.mjs --files "a" > x.md',
        'node hardening/scripts/validate.mjs --files "$(rm x)"',
      ]) assert.equal(scope(dir, agent, tool, { command }), 'deny', `${agent} ${tool}: ${command}`);
    }
  }
});

// ---------------------------------------------------------------- R1: Claude Code deny rules under Copilot

test('R1: under Copilot the guard denies what a deny rule of the Claude Code settings denies; Claude Code keeps its rules to itself', () => {
  const dir = project({
    '.claude/settings.json': { permissions: { deny: ['Bash(git log *)', 'PowerShell(Get-Content *)', 'Edit(/docs/locked/**)', 'Read(/docs/private/**)'] } },
    'docs/locked/a.md': '# locked\n',
    'docs/private/p.md': '# private\n',
    'docs/notes.md': '# notes\n',
  });
  const locked = path.join(dir, 'docs', 'locked', 'a.md');
  for (const [what, payload, host, rule] of [
    ['CLI: git log', cliCall(dir, 'bash', { command: 'git log -1' }), 'copilot-cli', /deny rule Bash\(git log \*\)/],
    ['CLI: an edit of a locked file', cliCall(dir, 'edit', { path: 'docs/locked/a.md', old_str: 'locked', new_str: 'open' }), 'copilot-cli', /deny rule Edit\(\/docs\/locked\/\*\*\)/],
    ['CLI: a read of a private file', cliCall(dir, 'view', { path: 'docs/private/p.md' }), 'copilot-cli', /deny rule Read\(\/docs\/private\/\*\*\)/],
    ['VS Code: Get-Content in the terminal', vsCall('run_in_terminal', { command: 'Get-Content docs/notes.md', explanation: 'x', goal: 'y', mode: 'sync' }), 'vscode', /deny rule PowerShell\(Get-Content \*\)/],
    ['VS Code: an edit of a locked file', vsCall('replace_string_in_file', { filePath: locked, oldString: 'locked', newString: 'open' }), 'vscode', /deny rule Edit/],
    ['CLI Claude registration: git log', dialectCall('Bash', { command: 'git log -1' }), null, /deny rule Bash\(git log \*\)/],
  ]) {
    const r = run(dir, payload, { host });
    assert.equal(r.decision, 'deny', what);
    assert.match(r.reason, rule, what);
    assert.match(r.reason, /GitHub Copilot does not evaluate those rules/, what);
  }
  // Lab mode changes nothing: a deny rule is a deny.
  fs.mkdirSync(path.join(dir, 'hardening'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'hardening', 'harness.config.json'), JSON.stringify({ approvals: { mode: 'lab' } }));
  assert.equal(run(dir, cliCall(dir, 'bash', { command: 'git log -1' }), { host: 'copilot-cli' }).decision, 'deny', 'lab mode');
  // What no deny rule names keeps its verdict; Claude Code (no host, no timestamp) applies its own rules, the hook has no opinion.
  assert.equal(run(dir, cliCall(dir, 'bash', { command: 'git status' }), { host: 'copilot-cli' }).decision, 'allow', 'routine');
  assert.equal(guard(dir, 'Bash', { command: 'git log -1' }).decision, null, 'Claude Code: its deny rule speaks');
  assert.equal(guard(dir, 'Edit', { file_path: locked, old_string: 'locked', new_string: 'open' }).decision, null, 'Claude Code: an edit');
});

// ---------------------------------------------------------------- R2: a deleted settings or harness config file

test('R2: a Delete File of the settings or the harness config is denied as a deletion, not as invalid JSON', () => {
  const dir = project({
    '.claude/settings.json': { permissions: { ask: [] } },
    '.claude/settings.local.json': { permissions: { allow: [] } },
    'hardening/harness.config.json': { approvals: { mode: 'ask' } },
  });
  for (const [host, hostName, build] of HOSTS) {
    for (const file of ['.claude/settings.json', '.claude/settings.local.json', 'hardening/harness.config.json']) {
      const r = run(dir, build(dir, PATCH_OF('Delete', file)), { host: hostName });
      assert.equal(r.decision, 'deny', `${host}: ${file}`);
      assert.match(r.reason, /deletes/, `${host}: ${file}: ${r.reason}`);
      assert.doesNotMatch(r.reason, /invalid JSON/, `${host}: ${file}`);
    }
  }
  // An emptied file is still what it was: invalid JSON.
  assert.match(guard(dir, 'Write', { file_path: path.join(dir, '.claude', 'settings.json'), content: '' }).reason, /invalid JSON/);
});

// ---------------------------------------------------------------- R3, R5: Grep globs and the lists of classifyPath

const policySource = fs.readFileSync(path.join(hooksDir, 'lib', 'policy.mjs'), 'utf8');
const guardSource = fs.readFileSync(path.join(hooksDir, 'lib', 'guard-pre-tool-use.mjs'), 'utf8');
/** The string items of `const NAME = new Set([...])` or `const NAME = [...]` in a module's source. */
function listIn(source, name) {
  const m = new RegExp(`const ${name} = (?:new Set\\()?\\[([^\\]]*)\\]`).exec(source);
  assert.ok(m, `${name} is declared as a list`);
  return [...m[1].matchAll(/'([^']+)'/g)].map((x) => x[1]);
}

test('R5: every secret and data extension and every hidden secret name of classifyPath has its entry in the Grep glob lists', () => {
  const secretExts = listIn(policySource, 'SECRET_EXTS');
  const secretNames = listIn(policySource, 'SECRET_BASENAMES');
  // The data test of classifyPath: `ext === '.abf' || ext === '.pbix' || base.endsWith('.rdl.data') || ...`.
  const dataLine = /\n\s*data: (.*)\n/.exec(policySource)?.[1] ?? '';
  const dataExts = [...dataLine.matchAll(/ext === '([^']+)'|base\.endsWith\('([^']+)'\)/g)].map((m) => m[1] ?? m[2]);
  assert.ok(secretExts.includes('.pem') && secretNames.includes('.pgpass') && dataExts.includes('.abf'), 'the lists were found');
  const globExts = listIn(guardSource, 'GLOB_SECRET_EXTS');
  const globNames = listIn(guardSource, 'GLOB_HIDDEN_SECRETS');
  for (const ext of secretExts) {
    assert.equal(classifyPath(`x${ext}`).secret, true, ext);
    assert.ok(globExts.includes(ext), `GLOB_SECRET_EXTS lacks the secret extension ${ext}`);
  }
  for (const ext of dataExts) {
    assert.equal(classifyPath(`x${ext}`).data, true, ext);
    assert.ok(globExts.includes(ext), `GLOB_SECRET_EXTS lacks the data extension ${ext}`);
  }
  for (const name of secretNames.filter((n) => n.startsWith('.'))) {
    assert.equal(classifyPath(name).secret, true, name);
    assert.ok(globNames.includes(name), `GLOB_HIDDEN_SECRETS lacks the hidden secret file ${name}`);
  }
  // And each entry works: a wildcard in its last character reaches it.
  const dir = project();
  const grep = (glob) => guard(dir, 'Grep', { pattern: 'x', path: dir, glob }).decision;
  for (const ext of [...secretExts, ...dataExts]) assert.equal(grep(`*${ext.slice(0, -1)}?`), 'deny', `*${ext.slice(0, -1)}?`);
  for (const name of secretNames.filter((n) => n.startsWith('.'))) assert.equal(grep(`${name.slice(0, -1)}?`), 'deny', `${name.slice(0, -1)}?`);
});

test('R3: a Grep glob that can match a Report Designer cache (*.rdl.data), a PuTTY key or git\'s credential store is denied', () => {
  const dir = project();
  const grep = (glob) => guard(dir, 'Grep', { pattern: 'x', path: dir, glob });
  for (const glob of ['*.rdl.d*', '*.rdl.dat?', 'Sales.rdl.d*', '**/*.rdl.[d]ata', '*.data', '*.pp?', '*.pp[k]', '.git-credential?', '**/.git-cred*', '*.{rdl.d*,md}']) {
    const r = grep(glob);
    assert.equal(r.decision, 'deny', glob);
    assert.match(r.reason, /Searching inside secret or data files/, glob);
  }
  for (const glob of ['*.tmdl', '*.json', '*.md', '*.dax', '*.rdl', '*.rds', '*.rdl.xml', '*.d.ts', '*.data.json', 'Sales*', '*.pbir', '*.sql']) {
    assert.equal(grep(glob).decision, null, glob);
  }
});

// ---------------------------------------------------------------- R4: same-named objects in two tables

const TWO_TABLES = [
  'table Sales', '', '\tcolumn Amount', '\t\tdataType: decimal', '', '\thierarchy Calendar', '', '\t\tlevel Year', '\t\t\tcolumn: Year', '',
  'table Budget', '', '\tcolumn Amount', '\t\tdataType: decimal', '', '\thierarchy Calendar', '', '\t\tlevel Year', '\t\t\tcolumn: Year', '',
].join('\n');
const inBudget = (from, to) => {
  const at = TWO_TABLES.indexOf('table Budget');
  return TWO_TABLES.slice(0, at) + TWO_TABLES.slice(at).replace(from, to);
};

test('R4: a level, a hierarchy or a column renamed in one of two tables is found, though the other table has one of the same name', () => {
  assert.deepEqual(removedDeclarations(TWO_TABLES, TWO_TABLES), []);
  assert.deepEqual(removedDeclarations(TWO_TABLES, inBudget('level Year', 'level Yr')), ['level calendar/year']);
  assert.deepEqual(removedDeclarations(TWO_TABLES, inBudget('hierarchy Calendar', 'hierarchy Cal')), ['hierarchy calendar', 'level calendar/year']);
  assert.deepEqual(removedDeclarations(TWO_TABLES, inBudget('column Amount', 'column Amt')), ['column amount']);
  assert.deepEqual(removedDeclarations(TWO_TABLES, inBudget('table Budget', 'table Plan')).sort(), ['column amount', 'hierarchy calendar', 'level calendar/year', 'table budget']);
  // Moving the text around keeps every object where it was: nothing is removed.
  const swapped = TWO_TABLES.slice(TWO_TABLES.indexOf('table Budget')) + TWO_TABLES.slice(0, TWO_TABLES.indexOf('table Budget'));
  assert.deepEqual(removedDeclarations(TWO_TABLES, swapped), []);
  // Through the hook: the edit is Tier 2.
  const file = 'M.SemanticModel/definition/tables/Two.tmdl';
  const dir = project({ [file]: TWO_TABLES });
  const at = TWO_TABLES.indexOf('table Budget');
  const edit = guard(dir, 'Edit', { file_path: path.join(dir, file), old_string: TWO_TABLES.slice(at), new_string: TWO_TABLES.slice(at).replace('level Year', 'level Yr') });
  assert.equal(edit.decision, 'ask', 'a level renamed in the second table');
  assert.match(edit.reason, /renames or removes model object\(s\): level calendar\/year/);
});

// ---------------------------------------------------------------- R6: the settings env and the Copilot hook files

const shippedSettings = JSON.parse(fs.readFileSync(path.join(pack, 'settings.hooks.json'), 'utf8'));
const vscodeHooks = fs.readFileSync(path.join(pack, 'vscode.hooks.json'), 'utf8');
const cliHooks = fs.readFileSync(path.join(pack, 'copilot-cli.hooks.json'), 'utf8');

test('R6: an edit that sets, changes or removes env.NODE_OPTIONS or env.PATH in the settings is denied like a hook entry change', () => {
  const settings = `${JSON.stringify({ ...shippedSettings, env: { NODE_OPTIONS: '--max-old-space-size=4096', FOO: '1' } }, null, 2)}\n`;
  const dir = project({ '.claude/settings.json': settings, '.claude/settings.local.json': '{}\n' });
  const file_path = path.join(dir, '.claude', 'settings.json');
  const edit = (old_string, new_string, file = file_path) => guard(dir, 'Edit', { file_path: file, old_string, new_string });
  for (const [label, r] of [
    ['NODE_OPTIONS changed', edit('"--max-old-space-size=4096"', '"--require ./x.js"')],
    ['NODE_OPTIONS removed', edit('"NODE_OPTIONS": "--max-old-space-size=4096",', '')],
    ['PATH added', edit('"FOO": "1"', '"FOO": "1", "PATH": "C:/nothing"')],
    ['Path (Windows spelling) added', edit('"FOO": "1"', '"FOO": "1", "Path": ""')],
    ['node_options in lower case', edit('"FOO": "1"', '"FOO": "1", "node_options": "--bogus"')],
    ['env added to the local settings', edit('{}', '{ "env": { "NODE_OPTIONS": "--bogus" } }', path.join(dir, '.claude', 'settings.local.json'))],
  ]) {
    assert.equal(r.decision, 'deny', label);
    assert.match(r.reason, /env\.(?:NODE_OPTIONS|PATH)/i, label);
  }
  // Another variable is an ordinary edit of a critical file: it asks.
  assert.equal(edit('"FOO": "1"', '"FOO": "2"').decision, 'ask', 'another variable');
});

test('R6: an edit or deletion that removes or changes a pack entry of a .github/hooks file is denied; other edits ask', () => {
  const dir = project({ '.github/hooks/bi-harness.json': vscodeHooks, '.github/hooks/bi-harness.copilot-cli.json': cliHooks });
  const vs = path.join(dir, '.github', 'hooks', 'bi-harness.json');
  const cli = path.join(dir, '.github', 'hooks', 'bi-harness.copilot-cli.json');
  const edit = (file_path, old_string, new_string) => guard(dir, 'Edit', { file_path, old_string, new_string });
  const pre = '{ "type": "command", "command": "node hardening/hooks/pre-tool-use.mjs", "cwd": ".", "timeout": 20, "env": { "BI_HARNESS_HOST": "vscode" } }';
  assert.ok(vscodeHooks.includes(pre), 'the fixture holds the shipped PreToolUse entry');
  for (const [label, r] of [
    ['VS Code: a timeout that always expires', edit(vs, pre, pre.replace('"timeout": 20', '"timeout": 1'))],
    ['VS Code: NODE_OPTIONS added to the entry', edit(vs, pre, pre.replace('"BI_HARNESS_HOST": "vscode"', '"BI_HARNESS_HOST": "vscode", "NODE_OPTIONS": "--bogus"'))],
    ['VS Code: the guard entry removed', edit(vs, pre, '{ "type": "command", "command": "echo ok" }')],
    ['VS Code: a word in front of the command', edit(vs, pre, pre.replace('"node hardening', '"echo node hardening'))],
    ['CLI: the bash command changed', edit(cli, '"bash": "node hardening/hooks/pre-tool-use.mjs"', '"bash": "true"')],
    ['VS Code: the whole file rewritten without the hooks', guard(dir, 'Write', { file_path: vs, content: '{ "hooks": {} }\n' })],
  ]) {
    assert.equal(r.decision, 'deny', label);
    assert.match(r.reason, /harness hook/, label);
  }
  for (const [host, hostName, build] of HOSTS) {
    const r = run(dir, build(dir, PATCH_OF('Delete', '.github/hooks/bi-harness.json')), { host: hostName });
    assert.equal(r.decision, 'deny', `${host}: a deleted hook file`);
    assert.match(r.reason, /deletes/, host);
  }
  // A comment, an added entry and a new hook file of the user's own are edits of a critical file: they ask.
  assert.equal(edit(vs, '"$comment": "BI Agent Harness hooks', '"$comment": "The BI Agent Harness hooks').decision, 'ask', 'a comment');
  assert.equal(edit(vs, `"PreToolUse": [\n      ${pre}`, `"PreToolUse": [\n      ${pre},\n      { "type": "command", "command": "echo extra" }`).decision, 'ask', 'an added entry');
  assert.equal(guard(dir, 'Write', { file_path: path.join(dir, '.github', 'hooks', 'mine.json'), content: '{ "hooks": {} }\n' }).decision, 'ask', 'a new file');
});

// ---------------------------------------------------------------- R7: check-hooks.mjs links the entry scripts' imports

/** A copy of the pack's hooks and the check script, as an installed project holds them. */
function packCopy() {
  const dir = tempDir('pack');
  fs.cpSync(hooksDir, path.join(dir, 'hardening', 'hooks'), { recursive: true });
  fs.mkdirSync(path.join(dir, 'hardening', 'scripts'), { recursive: true });
  fs.copyFileSync(checker, path.join(dir, 'hardening', 'scripts', 'check-hooks.mjs'));
  return dir;
}
const runChecker = (dir) => spawnSync(process.execPath, [path.join(dir, 'hardening', 'scripts', 'check-hooks.mjs')], {
  env: { ...process.env, CLAUDE_PROJECT_DIR: dir }, encoding: 'utf8',
});
/** Removes `export ` before a declaration of `name` in a module of the copy; asserts no module of lib/ imports it. */
function unexport(dir, lib, declaration) {
  const file = path.join(dir, 'hardening', 'hooks', 'lib', lib);
  const text = fs.readFileSync(file, 'utf8');
  assert.ok(text.includes(`export ${declaration}`), declaration);
  fs.writeFileSync(file, text.replace(`export ${declaration}`, declaration));
}

test('R7: check-hooks.mjs names an entry script that imports a name its module no longer exports, statically or by a dynamic import', () => {
  const name = (decl) => /(?:function|const)\s+(\w+)/.exec(decl)[1];
  for (const [lib, declaration, want] of [
    ['validators.mjs', 'function describeTabular(', /^hardening\/hooks\/session-start\.mjs:\d+: .*describeTabular/m],
    ['mcp-state.mjs', 'function recordMcpCall(', /^hardening\/hooks\/post-tool-redact\.mjs:\d+: .*recordMcpCall/m],
  ]) {
    // Only entry scripts import these names: the load of lib/ alone cannot find the fault.
    for (const f of fs.readdirSync(path.join(hooksDir, 'lib'))) {
      assert.doesNotMatch(fs.readFileSync(path.join(hooksDir, 'lib', f), 'utf8'), new RegExp(`import[^;]*\\b${name(declaration)}\\b[^;]*from`), `${f} imports ${name(declaration)}`);
    }
    const dir = packCopy();
    unexport(dir, lib, declaration);
    const r = runChecker(dir);
    assert.equal(r.status, 1, `${lib}: ${r.stdout}${r.stderr}`);
    assert.match(r.stdout, want, lib);
    assert.doesNotMatch(r.stdout, /[A-Za-z]:[\\/]/, 'no folder of this machine in the output');
  }
  const clean = runChecker(packCopy());
  assert.equal(clean.status, 0, clean.stdout + clean.stderr);
  assert.match(clean.stdout, /hook files parse and the \d+ modules of hardening\/hooks\/lib load/);
});

test('R7: the import reader takes renamed, multi-line and dynamic imports and leaves the rest', async () => {
  const { importedNames } = await import('../scripts/check-hooks.mjs');
  const text = [
    "import fs from 'node:fs';",
    "import { a, b as c,",
    "  d } from './lib/x.mjs';",
    "import * as ns from './lib/y.mjs';",
    "import './lib/z.mjs';",
    "const { e, f: g } = await import('./lib/w.mjs');",
    "const h = (await import('../scripts/v.mjs')).h2;",
  ].join('\n');
  assert.deepEqual(importedNames(text).map(({ specifier, names, line }) => [specifier, names, line]), [
    ['./lib/x.mjs', ['a', 'b', 'd'], 2], ['./lib/w.mjs', ['e', 'f'], 6], ['../scripts/v.mjs', ['h2'], 7],
  ]);
});

// ---------------------------------------------------------------- R8: a non-object approvals reads as ask

const NOT_OBJECTS = ['auto', 'lab', 'ask', null, 0, true, [], ['auto']];

test('R8: an approvals value that is not an object is ask in loadConfig, in the raw reader and in the widening check', () => {
  for (const approvals of NOT_OBJECTS) {
    const label = JSON.stringify(approvals);
    const dir = project({ 'hardening/harness.config.json': { approvals } });
    const cfg = loadConfig(dir);
    assert.equal(cfg.approvals.mode, 'ask', label);
    assert.equal(autoApprovalState(cfg).active, false, label);
    assert.equal(labModeActive(cfg), false, label);
    assert.equal(autoApprovalActive({ approvals }), false, `${label}: the raw object reads the same way`);
    assert.equal(approvalsWidened(JSON.stringify({ approvals: { mode: 'ask' } }), JSON.stringify({ approvals })), false, `ask to ${label} stays ask`);
    assert.equal(approvalsWidened(JSON.stringify({ approvals }), JSON.stringify({ approvals: { mode: 'auto' } })), true, `${label} to auto widens`);
    assert.equal(guard(dir, 'Bash', { command: 'git status' }).decision, null, `${label}: no auto approval`);
  }
  // Controls: no approvals key and a valid object read as before.
  assert.equal(autoApprovalActive(loadConfig(project({ 'hardening/harness.config.json': {} }))), true, 'no approvals key: auto');
  assert.equal(autoApprovalActive(loadConfig(project({ 'hardening/harness.config.json': { approvals: { mode: 'auto' } } }))), true);
  assert.equal(approvalsWidened(JSON.stringify({ approvals: { mode: 'ask' } }), '{}'), true, 'deleting the ask setting still widens');
});

test('R8: an edit of the harness config from ask to a non-object approvals is not denied as a widening', () => {
  const ask = `${JSON.stringify({ approvals: { mode: 'ask' } }, null, 2)}\n`;
  const dir = project({ 'hardening/harness.config.json': ask });
  const file_path = path.join(dir, 'hardening', 'harness.config.json');
  for (const value of ['"auto"', '"lab"', 'null']) {
    const r = guard(dir, 'Write', { file_path, content: `{ "approvals": ${value} }\n` });
    assert.doesNotMatch(r.reason, /Only the user turns auto approval on/, value);
  }
});

// ---------------------------------------------------------------- R9: the scope guard reads abbreviated git options

test('R9: the scope guard reads an abbreviated git branch option as the option git takes it for', () => {
  const dir = project();
  for (const command of ['git branch --set-upstream-t=origin/main', 'git branch --unset-u', 'git branch --edit', 'git branch --edit-d',
    'git branch --unset-upstream', 'git branch --edit-description', 'git branch --set-upstream-to=origin/main', 'git -C . branch --unset-ups']) {
    assert.equal(scope(dir, 'bi-validator', 'Bash', { command }), 'deny', command);
    assert.equal(scope(dir, 'bi-pbir-editor', 'PowerShell', { command }), 'deny', `editor: ${command}`);
  }
  for (const command of ['git branch', 'git branch --list', 'git branch -v', 'git branch -vv', 'git branch --show-current', 'git branch --sort=-committerdate',
    'git branch --contains HEAD', 'git branch --merged main', 'git branch --no-color', 'git branch --column', 'git status']) {
    assert.equal(scope(dir, 'bi-validator', 'Bash', { command }), null, command);
  }
});
