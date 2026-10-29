// Audit 2026-10-18, group G8 (the file guard): what Read, Grep, Edit, Write and NotebookEdit may reach, the files that
// always ask, and the edits whose result the guard cannot work out. Each case was a confirmed gap before the fix
// (F1-5, F1-23, F1-30, F1-31). Fixtures are temporary projects; the hooks run on them with CLAUDE_PROJECT_DIR and an
// empty home folder (no user-level settings rules); a fake credential is built at run time.
import { after, test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { classifyPath } from '../hooks/lib/policy.mjs';
import { isTextFile, validateFileText } from '../hooks/lib/validators.mjs';

const hook = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'hooks', 'pre-tool-use.mjs');
const home = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-file-guard-home-'));
after(() => fs.rmSync(home, { recursive: true, force: true }));

const ASK = { approvals: { mode: 'ask' } };
const LAB = { approvals: { mode: 'lab' } };

/** A temporary project holding `files`, with an optional harness config. */
function project(files = {}, config) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-file-guard-'));
  for (const [rel, content] of Object.entries({ ...files, ...(config ? { 'hardening/harness.config.json': JSON.stringify(config) } : {}) })) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), content);
  }
  return dir;
}

/** Runs the PreToolUse hook in `dir`; `payload` adds fields next to tool_input (permission_mode). Returns the decision, its reason and the audit events. */
function runGuard(dir, tool_name, tool_input, payload = {}) {
  const r = spawnSync(process.execPath, [hook], {
    input: JSON.stringify({ hook_event_name: 'PreToolUse', session_id: 'file-guard', tool_name, tool_input, ...payload }),
    env: { ...process.env, CLAUDE_PROJECT_DIR: dir, HOME: home, USERPROFILE: home },
    encoding: 'utf8',
  });
  assert.equal(r.status, 0, `${tool_name} ${JSON.stringify(tool_input)}: ${r.stderr}`);
  const out = r.stdout.trim() ? JSON.parse(r.stdout).hookSpecificOutput : null;
  const log = path.join(dir, '.claude', 'logs', 'security-events.jsonl');
  const events = fs.existsSync(log) ? fs.readFileSync(log, 'utf8').trim().split('\n').map((l) => JSON.parse(l)) : [];
  return { decision: out?.permissionDecision ?? null, reason: out?.permissionDecisionReason ?? '', events };
}

/** Runs the PostToolUse check that validates what was just written; the parsed output or null. */
function runPost(dir, tool_name, tool_input) {
  const r = spawnSync(process.execPath, [path.join(path.dirname(hook), 'post-tool-validate.mjs')], {
    input: JSON.stringify({ hook_event_name: 'PostToolUse', session_id: 'file-guard', tool_name, tool_input, tool_response: 'ok' }),
    env: { ...process.env, CLAUDE_PROJECT_DIR: dir, HOME: home, USERPROFILE: home },
    encoding: 'utf8',
  });
  assert.equal(r.status, 0, r.stderr);
  return r.stdout.trim() ? JSON.parse(r.stdout) : null;
}

/** Runs `body(dir)` in a project and removes it afterwards. */
function inProject(files, config, body) {
  const dir = project(files, config);
  try {
    return body(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

// ---------------------------------------------------------------- F1-5: a Grep glob is judged by what it can match

// ripgrep's --glob overrides its hidden-file and ignore filters (probed with rg 14.1.1: --glob '.pgpass', '*', '.*', '*.*'
// and '**/*' each print the line of a hidden .pgpass, which a Read of the file never gets), so the glob itself is judged.
test('Grep: a glob that can match a secret or data file is denied, like a Read of the file (F1-5)', () => {
  inProject({ 'cfg/notes.md': 'x\n' }, undefined, (dir) => {
    const grep = (glob) => runGuard(dir, 'Grep', { pattern: 'x', path: dir, glob, output_mode: 'content' });
    for (const glob of [
      '.pgpass', '.npmrc', '.netrc', 'credentials.json', 'pgpass.conf', '**/.my.cnf', '*.publishsettings', '*.kdbx', '*.{pbix,abf}',
      '{*.md,*.pem}', '*.{md,{p12,abf}}', '**/bin/Data/**', '**/secrets/**', '*.pbi?', '*.p*', '*.[pk]ey', '**\\*.pem', '.env.*', '*.env',
      '*', '.*', '*.*', '**/*', '**', '*.md *.pem', '*.md,*.pbix', '!*.md .pgpass', '.pgpas?', '.npmr*',
    ]) {
      const r = grep(glob);
      assert.equal(r.decision, 'deny', glob);
      assert.match(r.reason, /Searching inside secret or data files/, glob);
    }
    // Names and extensions of files the project works with stay searchable; an exclusion only removes files.
    for (const glob of [
      '*.tmdl', '**/*.tmdl', '*.json', '**/*.json', '*.md', '*.{tmdl,md}', '*.dax', '*.pbir', '*.pbip', '*.rdl', '*.sql', '*.{ts,tsx}',
      '**/visuals/*/visual.json', 'definition/**/*.tmdl', '!**/secrets/**', '!*.md', '.env.example', '*.env.example',
    ]) {
      assert.equal(grep(glob).decision, null, glob);
    }
    assert.equal(grep(undefined).decision, null, 'no glob, no opinion');
    assert.equal(runGuard(dir, 'Glob', { pattern: '**/*', path: dir }).decision, null, 'Glob lists names only');
  });
});

test('Grep globs: the extension and file name lists follow classifyPath, so a wildcard stands for every one of them', () => {
  inProject({}, undefined, (dir) => {
    const grep = (glob) => runGuard(dir, 'Grep', { pattern: 'x', path: dir, glob }).decision;
    for (const ext of ['.pem', '.key', '.pfx', '.p12', '.publishsettings', '.kdbx', '.abf', '.pbix']) {
      const cls = classifyPath(`x${ext}`);
      assert.ok(cls.secret || cls.data, `${ext} is a secret or data extension for classifyPath`);
      assert.equal(grep(`*${ext.slice(0, -1)}?`), 'deny', `*${ext.slice(0, -1)}?`);
    }
    for (const name of ['.env', '.npmrc', '.netrc', '.pypirc', '.pgpass', '.pg_service.conf', '.my.cnf', '.mylogin.cnf']) {
      assert.equal(classifyPath(name).secret, true, `${name} is a secret file name for classifyPath`);
      assert.equal(grep(`${name.slice(0, -1)}?`), 'deny', `${name.slice(0, -1)}?`);
    }
    assert.equal(grep('{' + Array.from({ length: 9 }, () => 'a,b').join(',') + '}{' + Array.from({ length: 9 }, () => 'c,d').join(',') + '}'), 'deny', 'a glob with more than 256 alternatives cannot be judged');
    assert.equal(grep(`${'.env'.repeat(2000)}.md`), 'deny', 'a glob longer than any real one is refused before a pattern runs over it');
  });
});

// A hook that runs past its timeout lets the call through, so a glob built to make a pattern backtrack must not cost time.
test('Grep globs: a pattern full of stars and classes is matched in linear time', () => {
  inProject({}, undefined, (dir) => {
    const started = Date.now();
    for (const glob of [`${'*?'.repeat(40)}x`, `${'*a'.repeat(60)}*b`, `${'*'.repeat(500)}.zzz`, `${'[a-z]*'.repeat(50)}.md`, `${'*.'.repeat(80)}tmdl`]) {
      assert.equal(runGuard(dir, 'Grep', { pattern: 'x', path: dir, glob }).decision, null, glob.slice(0, 30));
    }
    assert.equal(runGuard(dir, 'Grep', { pattern: 'x', path: dir, glob: `${'*'.repeat(300)}.pe?` }).decision, 'deny', 'and a long run of stars still reaches the secret extension');
    assert.ok(Date.now() - started < 20000, `${Date.now() - started} ms`);
  });
});

// ---------------------------------------------------------------- F1-23: a credential in a notebook cell

test('NotebookEdit: a credential written into a cell is refused like the same text in a Write; the validator scans notebooks (F1-23)', () => {
  const key = ['AK', 'IA'].join('') + 'ABCDEFGHIJKLMNOP';
  inProject({ 'nb/n.ipynb': '{}\n' }, undefined, (dir) => {
    const cell = (new_source, rel = 'nb/n.ipynb') => runGuard(dir, 'NotebookEdit', { notebook_path: path.join(dir, rel), new_source, cell_id: 'c1' });
    const refused = cell(`k = "${key}"`);
    assert.equal(refused.decision, 'deny');
    assert.match(refused.reason, /Refusing to write a credential into nb\/n\.ipynb \(aws-access-key\)/);
    assert.equal(cell('print(1)').decision, null, 'a cell without a credential has no verdict');
    assert.equal(cell('print(1)', 'nb/new.ipynb').decision, null, 'a new notebook too');
    assert.equal(runGuard(dir, 'Write', { file_path: path.join(dir, 'nb', 'n.md'), content: `k = "${key}"` }).decision, 'deny', 'control: a Write of the same text');
    assert.equal(cell(`k = "${key}"`, '.claude/settings.json').decision, 'deny', 'a settings file is no notebook');
    assert.equal(cell('print(1)', 'hardening/x.ipynb').decision, 'ask', 'a notebook inside a critical folder asks, as any file there');
  });
  // The post-edit check and the validator read notebooks too.
  assert.equal(isTextFile('nb/n.ipynb'), true);
  assert.equal(isTextFile('NB/Report.IPYNB'), true);
  const notebook = JSON.stringify({ cells: [{ cell_type: 'code', source: [`k = "${key}"`] }] });
  const issues = validateFileText('nb/n.ipynb', notebook);
  assert.ok(issues.some((i) => i.level === 'error' && /credential/i.test(i.message)), JSON.stringify(issues));
  assert.deepEqual(validateFileText('nb/clean.ipynb', JSON.stringify({ cells: [] })), []);
  inProject({ 'nb/leak.ipynb': notebook, 'nb/clean.ipynb': JSON.stringify({ cells: [] }) }, undefined, (dir) => {
    const leaked = runPost(dir, 'NotebookEdit', { notebook_path: path.join(dir, 'nb', 'leak.ipynb'), new_source: 'x' });
    assert.equal(leaked?.decision, 'block', 'a notebook that holds a credential blocks after the edit');
    assert.match(leaked.reason, /Possible credential \(aws-access-key/);
    assert.equal(runPost(dir, 'NotebookEdit', { notebook_path: path.join(dir, 'nb', 'clean.ipynb'), new_source: 'x' }), null);
  });
});

// ---------------------------------------------------------------- F1-31: what steers the agent or holds evidence always asks

const CRITICAL = [
  'AGENTS.md', 'reports/CLAUDE.md', 'powerbi/CLAUDE.local.md', 'GEMINI.md', 'docs/sources/README.md', 'docs/tests/expected-values.md',
  'docs/harness/zz.md', 'docs/conventions.md', 'docs/static-checks.md', 'docs/test-packs.md', 'M.SemanticModel/modelReference.json',
  '.vscode/settings.json', '.cursor/rules/x.md', '.claude/rules/bi/x.md', 'hardening/hooks/lib/policy.mjs', '.github/hooks/x.json',
  '.githooks/pre-commit', '.mcp.json', '.gitignore', 'package.json', 'M.SemanticModel/definition/roles/Reader.tmdl',
  'M.SemanticModel/definition/dataSources.tmdl', 'M.SemanticModel/definition/expressions.tmdl', 'M.SemanticModel/definition/database.tmdl',
];
const contentOf = (rel) => (/\.json$/.test(rel) ? '{}\n' : /\.tmdl$/.test(rel) ? 'role Reader\n\tmodelPermission: read\n' : '# edited\n');

test('critical files ask in every approvals mode and under acceptEdits, not only where a settings rule happens to cover them (F1-31)', () => {
  for (const [label, config] of [['auto', undefined], ['ask', ASK], ['lab', LAB]]) {
    inProject({}, config, (dir) => {
      for (const rel of CRITICAL) {
        const r = runGuard(dir, 'Write', { file_path: path.join(dir, rel), content: contentOf(rel) }, { permission_mode: 'acceptEdits' });
        assert.equal(r.decision, 'ask', `${label}: ${rel}`);
        assert.match(r.reason, /steers the agent or holds the project's rules/, `${label}: ${rel}`);
        assert.ok(!r.events.some((e) => e.event === 'auto-approve' || e.event === 'lab-approve'), `${label}: ${rel} is never approved on its own`);
      }
    });
  }
  inProject({}, undefined, (dir) => {
    assert.match(runGuard(dir, 'Write', { file_path: path.join(dir, 'AGENTS.md'), content: '# x\n' }, { permission_mode: 'acceptEdits' }).reason, /Critical: auto mode always asks/);
  });
});

test('critical files: an Edit, a MultiEdit and an edit of a file that exists ask too; routine files still pass (F1-31)', () => {
  inProject({ 'AGENTS.md': '# Working agreement\n', 'docs/notes.md': '# notes\n', 'M.SemanticModel/definition/tables/Sales.tmdl': 'table Sales\n\n\tmeasure Revenue = 1\n' }, undefined, (dir) => {
    const mode = { permission_mode: 'acceptEdits' };
    const agents = path.join(dir, 'AGENTS.md');
    assert.equal(runGuard(dir, 'Edit', { file_path: agents, old_string: 'Working', new_string: 'Our working' }, mode).decision, 'ask');
    assert.equal(runGuard(dir, 'MultiEdit', { file_path: agents, edits: [{ old_string: 'Working', new_string: 'Our working' }] }, mode).decision, 'ask');
    // A routine file is still approved by auto mode, and an added measure is still ordinary model work.
    const note = runGuard(dir, 'Edit', { file_path: path.join(dir, 'docs', 'notes.md'), old_string: 'notes', new_string: 'Notes' }, mode);
    assert.equal(note.decision, 'allow');
    assert.match(note.reason, /auto mode: routine project file edit/);
    assert.equal(runGuard(dir, 'Edit', { file_path: path.join(dir, 'M.SemanticModel', 'definition', 'tables', 'Sales.tmdl'), old_string: 'Revenue = 1', new_string: 'Revenue = 2' }, mode).decision, 'allow');
  });
});

// ---------------------------------------------------------------- F1-30: an edit the guard cannot work out

const SALES = 'M.SemanticModel/definition/tables/Sales.tmdl';
const SALES_TEXT = 'table Sales\n\n\tmeasure Revenue = SUM(Sales[Amount])\n\n\tpartition Sales = m\n\t\tmode: import\n\t\tsource = Sql.Database("localhost", "Sales")\n';
const VISUAL = 'M.Report/definition/pages/p1/visuals/v1/visual.json';
const FILES = {
  [SALES]: SALES_TEXT,
  'docs/notes.md': '# notes\n',
  'AGENTS.md': '# Working agreement\n',
  [VISUAL]: '{"name":"v1"}\n',
  'M.Report/definition.pbir': '{"version":"4.0","datasetReference":{"byPath":{"path":"../M.SemanticModel"}}}\n',
  'M.SemanticModel/.platform': '{"metadata":{"type":"SemanticModel","displayName":"Sales"},"config":{"version":"2.0","logicalId":"4f1c2d3e-0000-4000-8000-0000000000ff"}}\n',
  'paginated/Invoices.rdl': '<?xml version="1.0" encoding="utf-8"?>\n<Report xmlns="http://schemas.microsoft.com/sqlserver/reporting/2016/01/reportdefinition"/>\n',
  'etl/P/Load.dtsx': '<?xml version="1.0"?>\n<DTS:Executable xmlns:DTS="www.microsoft.com/SqlServer/Dts"/>\n',
};

// Where the guard compares Tier 2 facts of the text (a model, a report's data sources, an SSIS package, a report's binding,
// a Fabric item's identity), an edit it cannot read asks, in every mode (a floor ask: lab asks too). A critical file asks
// as always. For any other file there is nothing to compare: no verdict, not even the routine allow of auto mode, so the
// host's own flow decides and the PostToolUse check validates what was written (a VS Code insert_edit_into_file on a note).
test('an edit whose result the guard cannot work out asks where it compares Tier 2 facts, and has no verdict elsewhere (F1-30)', () => {
  for (const [label, config] of [['auto', undefined], ['ask', ASK], ['lab', LAB]]) {
    inProject(FILES, config, (dir) => {
      const at = (rel) => path.join(dir, ...rel.split('/'));
      const absent = (rel) => ['Edit', { file_path: at(rel), old_string: 'absent text', new_string: 'x' }];
      for (const [what, [tool, input], reason] of [
        ['TMDL: old_string absent from the file', ['Edit', { file_path: at(SALES), old_string: 'mode:  import', new_string: 'mode: directQuery' }], /The guard could not work out the edited text of /],
        ['TMDL: Write without content', ['Write', { file_path: at(SALES) }], /The guard could not work out the edited text of /],
        ['TMDL: MultiEdit without a list of edits', ['MultiEdit', { file_path: at(SALES), edits: 'x' }], /The guard could not work out the edited text of /],
        ['TMDL: an empty old_string in a file that has text', ['Edit', { file_path: at(SALES), old_string: '', new_string: '\tpartition P = m\n' }], /The guard could not work out the edited text of /],
        ['RDL: old_string absent', absent('paginated/Invoices.rdl'), /The guard could not work out the edited text of /],
        ['SSIS package: old_string absent', absent('etl/P/Load.dtsx'), /The guard could not work out the edited text of /],
        ['a report binding: old_string absent', absent('M.Report/definition.pbir'), /The guard could not work out the edited text of /],
        ['a Fabric item identity: old_string absent', absent('M.SemanticModel/.platform'), /The guard could not work out the edited text of /],
        ['a critical file: old_string absent', absent('AGENTS.md'), /steers the agent/],
      ]) {
        const r = runGuard(dir, tool, input);
        assert.equal(r.decision, 'ask', `${label}: ${what}`);
        assert.match(r.reason, reason, `${label}: ${what}`);
        assert.ok(!r.events.some((e) => e.event === 'auto-approve' || e.event === 'lab-approve'), `${label}: ${what}`);
      }
      for (const [what, [tool, input]] of [
        ['a note: old_string absent', absent('docs/notes.md')],
        ['a note: an empty old_string in a file that has text', ['Edit', { file_path: at('docs/notes.md'), old_string: '', new_string: 'more' }]],
        ['a note: Write without text', ['Write', { file_path: at('docs/notes.md') }]],
        ['a PBIR visual: old_string absent', absent(VISUAL)],
        ['a PBIR visual: an empty old_string in a file that has text', ['Edit', { file_path: at(VISUAL), old_string: '', new_string: '{}' }]],
      ]) {
        const r = runGuard(dir, tool, input);
        assert.equal(r.decision, null, `${label}: ${what} has no verdict`);
        assert.ok(!r.events.some((e) => e.event === 'auto-approve' || e.event === 'lab-approve'), `${label}: ${what}`);
      }
      // Control: the same note edit with its old text in the file is recognised as routine in auto mode.
      const known = runGuard(dir, 'Edit', { file_path: at('docs/notes.md'), old_string: 'notes', new_string: 'Notes' });
      assert.equal(known.decision, label === 'ask' ? null : 'allow', `${label}: a known old text is judged normally`);
    });
  }
});

// Copilot CLI and its Claude registration spell a replace as path/old_str/new_str and a whole-file write as path/file_text. Seen
// without the host's translation (no timestamp, no host variable) they mean the same as Edit and Write, so the guard judges the
// text: a rename is Tier 2 with its own reason, not a call it could not read.
test('plain field spellings (path, old_str, new_str, file_text) are judged like any Edit or Write, not left unread (F1-30)', () => {
  const key = ['AK', 'IA'].join('') + 'ABCDEFGHIJKLMNOP';
  inProject(FILES, undefined, (dir) => {
    const sales = path.join(dir, ...SALES.split('/'));
    const notes = path.join(dir, 'docs', 'notes.md');
    const rename = runGuard(dir, 'Edit', { path: sales, old_str: 'measure Revenue', new_str: 'measure Takings' });
    assert.equal(rename.decision, 'ask');
    assert.match(rename.reason, /This edit renames or removes model object\(s\): measure revenue/);
    assert.doesNotMatch(rename.reason, /could not work out/);
    assert.match(runGuard(dir, 'Edit', { path: sales, old_str: 'mode: import', new_str: 'mode: directQuery' }).reason, /changes a storage mode/);
    const prod = SALES_TEXT.replace('Sql.Database("localhost", "Sales")', 'Sql.Database("prod-sql01", "Sales")');
    assert.match(runGuard(dir, 'Write', { path: sales, file_text: prod }).reason, /changes a data source/, 'a whole-file write');
    const ordinary = runGuard(dir, 'Edit', { path: sales, old_str: 'SUM(Sales[Amount])', new_str: 'SUM(Sales[Net])' });
    assert.equal(ordinary.decision, 'allow', 'an ordinary measure edit is routine');
    assert.match(ordinary.reason, /auto mode: routine project file edit/);
    assert.equal(runGuard(dir, 'Write', { path: notes, file_text: '# Notes\n' }).decision, 'allow', 'a note written whole');
    const leak = runGuard(dir, 'Write', { path: notes, file_text: `k = "${key}"` });
    assert.equal(leak.decision, 'deny', 'a credential in file_text is refused');
    assert.match(leak.reason, /aws-access-key/);
    assert.equal(runGuard(dir, 'Edit', { path: path.join(dir, 'AGENTS.md'), old_str: 'Working', new_str: 'Our working' }).decision, 'ask', 'a critical file by path asks');
    assert.equal(runGuard(dir, 'Edit', { path: path.join(dir, 'templates', 't.md'), old_str: 'a', new_str: 'b' }).decision, 'deny', 'a reference by path is denied');
    // The Claude fields win when both are given; an old text that is not in the file stays unreadable for the guard
    // (a CRLF/LF mismatch can make it miss a text the tool still replaces).
    const both = runGuard(dir, 'Edit', { file_path: sales, old_string: 'measure Revenue', new_string: 'measure Takings', old_str: 'absent text', new_str: 'x' });
    assert.match(both.reason, /This edit renames or removes model object\(s\)/);
    const absent = runGuard(dir, 'Edit', { path: sales, old_str: 'mode:  import', new_str: 'mode: directQuery' });
    assert.equal(absent.decision, 'ask');
    assert.match(absent.reason, /The guard could not work out the edited text of /);
  });
  // In lab mode the Tier 2 verdict is run, which tells it from the unreadable edit (a floor ask, lab asks too).
  inProject(FILES, LAB, (dir) => {
    const sales = path.join(dir, ...SALES.split('/'));
    assert.equal(runGuard(dir, 'Edit', { path: sales, old_str: 'measure Revenue', new_str: 'measure Takings' }).decision, 'allow');
    assert.equal(runGuard(dir, 'Edit', { path: sales, old_str: 'mode:  import', new_str: 'mode: directQuery' }).decision, 'ask');
  });
});

test('an edit the guard can work out is judged by its result: an empty old_string creates a missing file like a Write', () => {
  inProject({ [SALES]: SALES_TEXT }, undefined, (dir) => {
    const fresh = 'M.SemanticModel/definition/tables/Fresh.tmdl';
    const prod = 'table Fresh\n\n\tpartition Fresh = m\n\t\tmode: directQuery\n\t\tsource = Sql.Database("prod-sql01", "Sales")\n';
    const created = runGuard(dir, 'Edit', { file_path: path.join(dir, fresh), old_string: '', new_string: prod });
    assert.equal(created.decision, 'ask');
    assert.match(created.reason, /changes a data source and a storage mode/, 'the new text is judged like a Write');
    const note = runGuard(dir, 'Edit', { file_path: path.join(dir, 'docs', 'new.md'), old_string: '', new_string: '# New\n' });
    assert.equal(note.decision, 'allow', 'a new note is routine');
    const measure = runGuard(dir, 'Edit', { file_path: path.join(dir, SALES), old_string: 'SUM(Sales[Amount])', new_string: 'SUM(Sales[Net])' });
    assert.equal(measure.decision, 'allow', 'an edit with its old text in the file is judged normally');
    assert.equal(runGuard(dir, 'Edit', { file_path: path.join(dir, SALES), old_string: 'mode: import', new_string: 'mode: directQuery' }).decision, 'ask');
  });
});
