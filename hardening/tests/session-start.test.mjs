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
