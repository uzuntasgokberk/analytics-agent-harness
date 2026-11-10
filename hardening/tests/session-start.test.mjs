// SessionStart inventory (2026-10-11 audit): a repository holding only some BI layers was described as "no project yet"
// and an Analysis Services model (a TMDL folder, or the repository root itself) was not listed at all. Fixtures: one
// repository per layer; the hook runs on each with CLAUDE_PROJECT_DIR.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const hook = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'hooks', 'session-start.mjs');

const MODEL = {
  'database.tmdl': 'database Finance\n\tcompatibilityLevel: 1600\n',
  'model.tmdl': 'model Model\n\tculture: en-US\n\nref table Sales\n',
  'tables/Sales.tmdl': 'table Sales\n\n\tmeasure Revenue = SUM ( Sales[Amount] )\n\t\tformatString: 0\n\n\tcolumn Amount\n\t\tdataType: decimal\n\t\tsourceColumn: Amount\n',
};
const RDL = '<?xml version="1.0" encoding="utf-8"?>\n<Report xmlns="http://schemas.microsoft.com/sqlserver/reporting/2016/01/reportdefinition"><ReportSections><ReportSection><Body><Height>1cm</Height></Body><Width>10cm</Width><Page/></ReportSection></ReportSections></Report>\n';
const DTSX = '<?xml version="1.0"?>\n<DTS:Executable xmlns:DTS="www.microsoft.com/SqlServer/Dts" DTS:refId="Package" DTS:DTSID="{11111111-1111-1111-1111-111111111111}" DTS:ObjectName="Load" DTS:ProtectionLevel="0" />\n';

// Variables that point git at another repository, index or object store (a `git commit` hook that runs these tests
// exports GIT_INDEX_FILE): the temporary repositories' git calls, the tests' and the hook's, run without them, as in
// vscode-hooks.test.mjs. Nor do they read the developer's global or system configuration, where core.hooksPath would
// change what the banner reports about the Git hooks.
const GIT_REPO_VARS = new Set(['GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE', 'GIT_OBJECT_DIRECTORY', 'GIT_ALTERNATE_OBJECT_DIRECTORIES', 'GIT_COMMON_DIR', 'GIT_PREFIX']);
const gitEnv = () => ({
  ...Object.fromEntries(Object.entries(process.env).filter(([k]) => !GIT_REPO_VARS.has(k.toUpperCase()))),
  GIT_CONFIG_GLOBAL: path.join(os.tmpdir(), 'bi-harness-session-no-global-gitconfig'),
  GIT_CONFIG_NOSYSTEM: '1',
});
const gitIn = (dir, ...args) => {
  const r = spawnSync('git', args, { cwd: dir, env: gitEnv(), encoding: 'utf8' });
  assert.equal(r.status, 0, `git ${args.join(' ')}: ${r.stderr}`);
};

function repo(files, prefix = '') {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-session-'));
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(dir, prefix, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content);
  }
  gitIn(dir, 'init', '-q');
  return dir;
}

function context(dir, payload = {}) {
  const r = spawnSync(process.execPath, [hook], {
    input: JSON.stringify({ hook_event_name: 'SessionStart', source: 'startup', session_id: 'session-test', ...payload }),
    env: { ...gitEnv(), CLAUDE_PROJECT_DIR: dir },
    encoding: 'utf8',
  });
  assert.equal(r.status, 0, r.stderr);
  return JSON.parse(r.stdout).hookSpecificOutput.additionalContext;
}

const NO_PBIP = /No Power BI project \(\*\.SemanticModel \/ \*\.Report\) here: the artifacts below are the scope; none of them needs one/;
const NOTHING = /No BI artifacts found/;

test('session start: an Analysis Services model at the repository root is listed, not reported as "no project yet"', () => {
  const dir = repo(MODEL);
  const out = context(dir);
  fs.rmSync(dir, { recursive: true, force: true });
  assert.match(out, /Tabular model at the repository root: TMDL folder \(database\.tmdl\), compatibility level 1600, 1 table file\(s\)/);
  assert.match(out, NO_PBIP);
  assert.doesNotMatch(out, NOTHING);
  assert.doesNotMatch(out, /No \*\.SemanticModel \/ \*\.Report folders yet/);
});

test('session start: an SSAS-only repository lists its model folder with the level and says no Power BI project is needed', () => {
  const dir = repo(MODEL, 'models/Finance');
  const out = context(dir);
  fs.rmSync(dir, { recursive: true, force: true });
  assert.match(out, /Tabular model at models\/Finance: TMDL folder \(database\.tmdl\), compatibility level 1600, 1 table file\(s\); ownership per docs\/sources\/README\.md; the user deploys and processes it/);
  assert.match(out, NO_PBIP);
});

test('session start: a reference copy under docs/sources is named as read-only, not as a model to edit', () => {
  const dir = repo(MODEL, 'docs/sources/Shared/definition');
  const out = context(dir);
  fs.rmSync(dir, { recursive: true, force: true });
  assert.match(out, /Reference copy docs\/sources\/Shared\/definition: TMDL of a model owned elsewhere, compatibility level 1600, 1 table file\(s\); read-only/);
  assert.doesNotMatch(out, /Tabular model at/);
});

test('session start: RDL-only and SSIS-only repositories are described by their own artifacts and tools', () => {
  const rdl = repo({ 'paginated/Orders.rdl': RDL, 'paginated/Invoices.rdl': RDL });
  const rdlOut = context(rdl);
  fs.rmSync(rdl, { recursive: true, force: true });
  assert.match(rdlOut, /Paginated reports: 2 \*\.rdl \(paginated\/Invoices\.rdl, paginated\/Orders\.rdl\); the engine check is the user's Report Builder run/);
  assert.match(rdlOut, NO_PBIP);
  assert.doesNotMatch(rdlOut, /Tabular model|SSIS:/);

  const ssis = repo({ 'etl/Load/Load.dtsx': DTSX, 'etl/Load/Load.dtproj': '<Project/>\n' });
  const ssisOut = context(ssis);
  fs.rmSync(ssis, { recursive: true, force: true });
  assert.match(ssisOut, /SSIS: 1 folder\(s\) with packages or projects \(etl\/Load\); ownership per docs\/sources\/README\.md; dtexec \/Validate only where dtexec exists on this machine, else NOT RUN/);
  assert.match(ssisOut, NO_PBIP);
  assert.doesNotMatch(ssisOut, /Paginated reports|Tabular model/);
});

test('session start: a Power BI project plus other layers lists every layer and shows neither "no project" line', () => {
  const dir = repo({
    'powerbi/Sales.SemanticModel/definition.pbism': '{}',
    'powerbi/Sales.SemanticModel/definition/model.tmdl': 'model Model\n',
    'powerbi/Sales.SemanticModel/definition/tables/Sales.tmdl': MODEL['tables/Sales.tmdl'],
    'powerbi/Sales.Report/definition.pbir': JSON.stringify({ version: '4.0', datasetReference: { byPath: { path: '../Sales.SemanticModel' } } }),
    'powerbi/Sales.Report/definition/pages/p1/page.json': '{}',
    'paginated/Orders.rdl': RDL,
    ...Object.fromEntries(Object.entries(MODEL).map(([k, v]) => [`models/Finance/${k}`, v])),
  });
  const out = context(dir);
  fs.rmSync(dir, { recursive: true, force: true });
  assert.match(out, /Model powerbi\/Sales\.SemanticModel: TMDL, 1 table file\(s\)/);
  assert.match(out, /Report powerbi\/Sales\.Report: PBIR, 1 page\(s\)/);
  assert.match(out, /Tabular model at models\/Finance/);
  assert.match(out, /Paginated reports: 1 \*\.rdl/);
  assert.doesNotMatch(out, NO_PBIP);
  assert.doesNotMatch(out, NOTHING);
});

test('session start: above 20 projects the banner counts models and reports per folder and still names the flagged ones', () => {
  const files = {};
  for (let i = 1; i <= 21; i++) {
    const name = `Report${String(i).padStart(2, '0')}`;
    const at = `powerbi/${i <= 11 ? 'finance' : 'sales'}/${name}`;
    files[`${at}/${name}.SemanticModel/definition.pbism`] = '{}';
    files[`${at}/${name}.SemanticModel/definition/model.tmdl`] = 'model Model\n';
    files[`${at}/${name}.Report/definition.pbir`] = JSON.stringify({ version: '4.0', datasetReference: { byPath: { path: `../${name}.SemanticModel` } } });
    files[`${at}/${name}.Report/definition/pages/p1/page.json`] = '{}';
  }
  files['powerbi/finance/Report01/Report01.SemanticModel/.pbi/cache.abf'] = 'x';
  files['powerbi/sales/Report21/Report21.SemanticModel/.pbi/unappliedChanges.json'] = '{}';
  const dir = repo(files);
  const out = context(dir);
  fs.rmSync(dir, { recursive: true, force: true });
  assert.match(out, /^- Power BI models: 21 \(21 TMDL\) in powerbi\/finance \(11\), powerbi\/sales \(10\)\. More than 20, so not listed one by one/m);
  assert.match(out, /^- Power BI reports: 21 \(21 PBIR\) in powerbi\/finance \(11\), powerbi\/sales \(10\)\. More than 20, so not listed one by one/m);
  assert.match(out, /^- 1 model\(s\) hold \.pbi\/cache\.abf with imported DATA: never read one \(blocked\)\./m);
  assert.match(out, /^- powerbi\/sales\/Report21\/Report21\.SemanticModel\/\.pbi\/unappliedChanges\.json exists/m);
  assert.doesNotMatch(out, /^- (?:Model|Report) powerbi\//m);
});

test('session start: a repository without any BI artifact says so without presuming a Power BI project', () => {
  const dir = repo({ 'README.md': '# empty\n' });
  const out = context(dir);
  fs.rmSync(dir, { recursive: true, force: true });
  assert.match(out, NOTHING);
  assert.match(out, /No layer requires another layer's files/);
  assert.doesNotMatch(out, NO_PBIP);
});

// Audit 2026-10-19, F2-39: the banner's Git lines (hardening/README.md: protected-branch warning, Git hooks installed and
// executable) and the pointer of a compacted or resumed session to the handoff files lost their tests with
// session-and-gates.test.mjs; removing those lines from session-start.mjs left every test green.
const PROTECTED = (branch) => new RegExp(`- On protected branch '${branch}': create a feature branch before editing \\(git switch -c feature/<topic>\\)\\.`);
const NOT_INSTALLED = /- Git hooks NOT installed: ask the user to run `git config core\.hooksPath hardening\/githooks`\./;
const NOT_EXECUTABLE = /Git hooks installed but missing or not executable/;
const GIT_HOOKS = ['pre-commit', 'commit-msg', 'pre-push'];

test('session start (F2-39): on a protected branch the banner says to branch first; Git hooks not installed are reported', () => {
  const dir = repo({ 'README.md': '# x\n' });
  try {
    for (const branch of ['main', 'master']) {
      gitIn(dir, 'symbolic-ref', 'HEAD', `refs/heads/${branch}`);
      const out = context(dir);
      assert.match(out, new RegExp(`- Git: branch ${branch}, `), branch);
      assert.match(out, PROTECTED(branch), branch);
      assert.match(out, NOT_INSTALLED, branch);
    }
    gitIn(dir, 'symbolic-ref', 'HEAD', 'refs/heads/feature/x');
    const feature = context(dir);
    assert.match(feature, /- Git: branch feature\/x, /);
    assert.doesNotMatch(feature, /On protected branch/, 'a feature branch is not protected');
    assert.match(feature, NOT_INSTALLED, 'the hooks are reported on every branch');
    // Another hooks folder is not the harness's: its checks do not run.
    gitIn(dir, 'config', 'core.hooksPath', '.githooks');
    assert.match(context(dir), NOT_INSTALLED, 'a core.hooksPath other than hardening/githooks');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('session start (F2-39): with core.hooksPath hardening/githooks and the hooks in place no Git hook line appears', () => {
  const dir = repo(Object.fromEntries(GIT_HOOKS.map((name) => [`hardening/githooks/${name}`, '#!/bin/sh\nexit 0\n'])));
  try {
    for (const name of GIT_HOOKS) fs.chmodSync(path.join(dir, 'hardening', 'githooks', name), 0o755);
    gitIn(dir, 'symbolic-ref', 'HEAD', 'refs/heads/feature/x');
    gitIn(dir, 'config', 'core.hooksPath', 'hardening/githooks');
    const out = context(dir);
    assert.doesNotMatch(out, /Git hooks NOT installed/);
    assert.doesNotMatch(out, NOT_EXECUTABLE);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// Git skips a hook that is not executable (a zip or a plain copy drops the bit). Windows keeps no such bit, so the hook
// does not check it there (session-start.mjs) and this case runs only where the platform keeps exec bits.
test('session start (F2-39): a Git hook that lost its exec bit, or is missing, is named', { skip: process.platform === 'win32' && 'Windows keeps no exec bit: session-start.mjs skips this check there' }, () => {
  const dir = repo(Object.fromEntries(GIT_HOOKS.map((name) => [`hardening/githooks/${name}`, '#!/bin/sh\nexit 0\n'])));
  try {
    for (const name of GIT_HOOKS) fs.chmodSync(path.join(dir, 'hardening', 'githooks', name), 0o755);
    fs.chmodSync(path.join(dir, 'hardening', 'githooks', 'pre-commit'), 0o644);
    fs.rmSync(path.join(dir, 'hardening', 'githooks', 'pre-push'));
    gitIn(dir, 'symbolic-ref', 'HEAD', 'refs/heads/feature/x');
    gitIn(dir, 'config', 'core.hooksPath', 'hardening/githooks');
    const out = context(dir);
    assert.match(out, /- Git hooks installed but missing or not executable \(pre-commit, pre-push\), so Git skips them: ask the user to run `chmod \+x hardening\/githooks\/\*`\./);
    assert.doesNotMatch(out, /Git hooks NOT installed/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// Review of PR #10, finding 2: Claude Code saves an additionalContext over 10,000 characters to a file and shows the model
// a 2,000-character preview, and the banner of 300 projects reached 10,742 to 69,928 characters in four of five layouts,
// with the MCP and handoff lines at its end. Every list is capped now, the lines the agent must act on come before the
// inventory, and a ceiling cuts the inventory from the end. Fixtures hold the smallest folders discovery needs: an empty
// definition/ makes a model TMDL and a report PBIR, model.bim makes a model TMSL, and .platform is only checked to exist.
// Each runs as a compacted session with TASKS.md and one unpersisted MCP write, so every conditional must-see line shows.
const MUST_SEE = [
  /^\[bi-harness\] Session context \(compact\)$/m,
  /^- Approvals: /m,
  /^- SQL read switch: /m,
  /^- Desktop screenshots: /m,
  /^- Git: branch main, /m,
  /^- On protected branch 'main'/m,
  /^- Git hooks NOT installed/m,
  /^- Requested local MCP mode: /m,
  /^- Before model work: read docs\/harness\/MCP\.md/m,
  /^- Earlier in this session: 1 MCP write\(s\) on /m,
  /^- Continuing work: re-read TASKS\.md before acting\.$/m,
];
const INVENTORY = /^(?: {2}- |- (?:No BI artifacts|No Power BI project|Power BI models|Model |\d+ model|Tabular model|Reference cop|Power BI reports|Report |Paginated reports|SSIS|Fabric Git-connected|Fabric Git: no directory))/m;
const OMITTED = /^- (\d+) more inventory line\(s\) left out to keep this context under Claude Code's 10,000-character limit/m;

function compactedRepo() {
  const dir = repo({
    'TASKS.md': '# Tasks\n',
    '.claude/logs/.state/session-test.json': JSON.stringify({ mcpWrites: [{ mcpServer: 'powerbi-modeling', connection: 'PBIDesktop-Sales-51234', tool: 'measure_operations' }] }),
  });
  gitIn(dir, 'symbolic-ref', 'HEAD', 'refs/heads/main');
  return dir;
}

/** 300 projects, each a model and a report in the folder `at(i, name)` returns. */
function largeRepo(at, { platform = false, tmsl = 0 } = {}) {
  const dir = compactedRepo();
  for (let i = 1; i <= 300; i++) {
    const name = `Project${String(i).padStart(3, '0')}`;
    const model = path.join(dir, at(i, name), `${name}.SemanticModel`);
    const report = path.join(dir, at(i, name), `${name}.Report`);
    fs.mkdirSync(path.join(report, 'definition'), { recursive: true });
    if (i <= tmsl) {
      fs.mkdirSync(model, { recursive: true });
      fs.writeFileSync(path.join(model, 'model.bim'), '{}');
    } else {
      fs.mkdirSync(path.join(model, 'definition'), { recursive: true });
    }
    if (platform) for (const item of [model, report]) fs.writeFileSync(path.join(item, '.platform'), '{}');
  }
  return dir;
}

/** Every must-see line present and above the first inventory line; the banner under the cap. */
function assertBanner(out, label) {
  assert.ok(out.length < 10000, `${label}: ${out.length} characters`);
  const inventoryAt = out.search(INVENTORY);
  assert.ok(inventoryAt > 0, `${label}: no inventory line`);
  for (const re of MUST_SEE) {
    const at = out.search(re);
    assert.ok(at >= 0, `${label}: missing ${re}`);
    assert.ok(at < inventoryAt, `${label}: ${re} comes after the inventory`);
  }
}

const GROUPED = (i, name) => `powerbi/area${i % 10}/${name}`;
const LAYOUTS = [
  ['grouped three deep (powerbi/<area>/<Name>/)', GROUPED, {}, /^- Power BI models: 300 \(300 TMDL\) in powerbi\/area0 \(30\), powerbi\/area1 \(30\), .*powerbi\/area9 \(30\)\. More than 20/m],
  ['one folder per project at the root', (i, name) => name, {}, /^- Power BI models: 300 \(300 TMDL\) in Project001 \(1\), .*Project010 \(1\) and 290 more\. More than 20/m],
  ['one folder per project under projects/', (i, name) => `projects/${name}`, {}, /^- Power BI models: 300 \(300 TMDL\) in projects \(300\)\. More than 20/m],
  ['grouped, .platform in every item, no fabric.directories', GROUPED, { platform: true }, /^- Fabric Git-connected directories: 300 \(powerbi\/area\d\/Project\d{3}: 2 item\(s\), .* and 297 more; from \.platform, none recorded in fabric\.directories: a reminder, not proof\); /m],
  ['grouped, 200 of the models TMSL', GROUPED, { tmsl: 200 }, /^- 200 models are TMSL \(model\.bim\): powerbi\/area\d\/Project\d{3}\/Project\d{3}\.SemanticModel, .* and 197 more\. TMSL is not supported/m],
];
for (const [label, at, options, capped] of LAYOUTS) {
  test(`session start (review finding 2): 300 projects ${label} stay under 10,000 characters, must-see lines first`, (t) => {
    const dir = largeRepo(at, options);
    try {
      const out = context(dir, { source: 'compact' });
      t.diagnostic(`${label}: ${out.length} characters`);
      assertBanner(out, label);
      assert.match(out, capped, 'the list is capped');
      assert.doesNotMatch(out, OMITTED, 'the caps alone keep this layout within the budget');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
}

// Up to 20 folders two deep keep their names (the largest 10 shown); an invalid fabric.directories is a setting to repair,
// so it stands with the must-see lines.
test('session start (review finding 2): 12 area folders stay two segments deep; an invalid fabric.directories comes before the inventory', () => {
  const dir = compactedRepo();
  try {
    fs.mkdirSync(path.join(dir, 'hardening'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'hardening', 'harness.config.json'), JSON.stringify({ fabric: { directories: 'fabric' } }));
    for (let i = 1; i <= 24; i++) {
      const name = `Project${String(i).padStart(2, '0')}`;
      fs.mkdirSync(path.join(dir, 'powerbi', `area${String(i % 12).padStart(2, '0')}`, name, `${name}.SemanticModel`, 'definition'), { recursive: true });
    }
    const out = context(dir, { source: 'compact' });
    assertBanner(out, '12 areas');
    assert.match(out, /^- Power BI models: 24 \(24 TMDL\) in powerbi\/area00 \(2\), .*powerbi\/area09 \(2\) and 2 more\. More than 20/m);
    const invalid = out.search(/^- Fabric Git: fabric\.directories in hardening\/harness\.config\.json is not a list/m);
    assert.ok(invalid > 0 && invalid < out.search(INVENTORY), 'the invalid setting is reported before the inventory');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// The caps keep every layout above within the budget, so the ceiling is proven on lists just under LIST_LIMIT: 20 models
// that each carry three warning lines, 20 legacy reports and 20 tabular models are listed one by one.
test('session start (review finding 2): above the budget the inventory is cut from the end with one line saying how many lines were left out', () => {
  const dir = compactedRepo();
  try {
    for (let i = 1; i <= 20; i++) {
      const name = `Project${String(i).padStart(2, '0')}`;
      const model = path.join(dir, 'powerbi', name, `${name}.SemanticModel`);
      fs.mkdirSync(path.join(model, '.pbi'), { recursive: true });
      for (const file of ['model.bim', '.pbi/cache.abf', '.pbi/unappliedChanges.json']) fs.writeFileSync(path.join(model, file), '{}');
      fs.mkdirSync(path.join(dir, 'powerbi', name, `${name}.Report`), { recursive: true });
      fs.writeFileSync(path.join(dir, 'powerbi', name, `${name}.Report`, 'report.json'), '{}');
      for (const [rel, text] of Object.entries(MODEL)) {
        fs.mkdirSync(path.dirname(path.join(dir, 'ssas', name, rel)), { recursive: true });
        fs.writeFileSync(path.join(dir, 'ssas', name, rel), text);
      }
    }
    const out = context(dir, { source: 'compact' });
    assertBanner(out, 'ceiling');
    const lines = out.split('\n');
    const omitted = OMITTED.exec(lines.at(-1));
    assert.ok(omitted, `the last line says how many lines were left out: ${lines.at(-1)}`);
    assert.match(out, /^- Model powerbi\/Project\d\d\/Project\d\d\.SemanticModel: TMSL \(model\.bim\), 0 table file\(s\)$/m, 'the inventory is kept from its start');
    assert.doesNotMatch(out, /^- Tabular model at /m, 'and cut from its end');
    // 20 models with three sub-lines each, 20 legacy reports with one, 20 tabular models.
    const shown = lines.filter((l) => INVENTORY.test(l)).length;
    assert.equal(shown + Number(omitted[1]), 20 * 4 + 20 * 2 + 20, 'kept and left out add up to the whole inventory');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('session start (F2-39): a compacted, resumed, cleared or forked session is pointed back to the handoff files', () => {
  const both = repo({ 'TASKS.md': '# Tasks\n', 'docs/handoff.md': '# Handoff\n' });
  const tasksOnly = repo({ 'TASKS.md': '# Tasks\n' });
  const none = repo({ 'README.md': '# x\n' });
  try {
    for (const source of ['compact', 'resume', 'clear', 'fork']) {
      assert.match(context(both, { source }), /- Continuing work: re-read docs\/handoff\.md and TASKS\.md before acting\./, source);
    }
    assert.match(context(tasksOnly, { source: 'compact' }), /- Continuing work: re-read TASKS\.md before acting\./);
    assert.doesNotMatch(context(none, { source: 'compact' }), /Continuing work/, 'no handoff file: no pointer');
    assert.doesNotMatch(context(both, { source: 'startup' }), /Continuing work/, 'a new session starts fresh');
  } finally {
    for (const dir of [both, tasksOnly, none]) fs.rmSync(dir, { recursive: true, force: true });
  }
});
