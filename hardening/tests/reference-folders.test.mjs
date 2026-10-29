// Reference folders are not the repository's projects (2026-10-22): templates/ ships verified references (a live-connection
// PBIP with .platform in both item folders, an SSIS project), and the session banner listed them as the repository's model,
// report and SSIS folders, named templates/pbir/<X> a Fabric Git-connected directory, and the validator warned about the
// live connection "in a folder that holds .platform". Artifact discovery (findPbipItems, validateFiles' item folders,
// checkItemFolderFiles) now skips every reference folder (isReferenceRel: templates/, reports/<report>/source/, the
// config's `references`); the per-file checks (JSON syntax, secrets, Markdown limits, hygiene) still run on their files.
// Fixtures: one temporary repository with (a)-(d) reference folders and (e) the repository's own projects, which carry the
// same shapes so every skipped warning still fires on them.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { checkItemFolderFiles, findPbipItems } from '../hooks/lib/validators.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const HOOK = path.join(here, '..', 'hooks', 'session-start.mjs');
const CLI = path.join(here, '..', 'scripts', 'validate.mjs');

// Variables that point git at another repository, index or object store (a `git commit` hook that runs these tests
// exports GIT_INDEX_FILE), and the developer's global or system configuration: as in session-start.test.mjs.
const GIT_REPO_VARS = new Set(['GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE', 'GIT_OBJECT_DIRECTORY', 'GIT_ALTERNATE_OBJECT_DIRECTORIES', 'GIT_COMMON_DIR', 'GIT_PREFIX']);
const gitEnv = () => ({
  ...Object.fromEntries(Object.entries(process.env).filter(([k]) => !GIT_REPO_VARS.has(k.toUpperCase()))),
  GIT_CONFIG_GLOBAL: path.join(os.tmpdir(), 'bi-harness-reference-no-global-gitconfig'),
  GIT_CONFIG_NOSYSTEM: '1',
});
const git = (dir, ...args) => {
  const r = spawnSync('git', ['-c', 'core.autocrlf=false', ...args], { cwd: dir, env: gitEnv(), encoding: 'utf8' });
  assert.equal(r.status, 0, `git ${args.join(' ')}: ${r.stderr}`);
};

const schema = (p) => `https://developer.microsoft.com/json-schemas/fabric/${p}`;
const json = (o) => `${JSON.stringify(o, null, 2)}\n`;
const LOGICAL_ID = '0f0e0d0c-0b0a-4908-8706-050403020100';
const platform = (type, name) => json({ $schema: schema('gitIntegration/platformProperties/2.0.0/schema.json'), metadata: { type, displayName: name }, config: { version: '2.0', logicalId: LOGICAL_ID } });

/**
 * A live-connection PBIP as Desktop saves it (the shape of templates/pbir/Satis_SSAS): .platform in both item folders and
 * modelReference.json. Its report also names a base theme file that is missing and holds a stray notes.md, so the
 * live-connection, missing-theme and item-definition warnings all apply to it wherever it is not a reference.
 */
const livePbip = (dir, name) => ({
  [`${dir}/${name}.pbip`]: json({ $schema: schema('pbip/pbipProperties/1.0.0/schema.json'), version: '1.0', artifacts: [{ report: { path: `${name}.Report` } }] }),
  [`${dir}/${name}.Report/.platform`]: platform('Report', name),
  [`${dir}/${name}.Report/definition.pbir`]: json({ $schema: schema('item/report/definitionProperties/2.0.0/schema.json'), version: '4.0', datasetReference: { byPath: { path: `../${name}.SemanticModel` } } }),
  [`${dir}/${name}.Report/definition/version.json`]: json({ $schema: schema('item/report/definition/versionMetadata/1.0.0/schema.json'), version: '2.0.0' }),
  [`${dir}/${name}.Report/definition/report.json`]: json({
    $schema: schema('item/report/definition/report/3.3.0/schema.json'),
    themeCollection: { baseTheme: { name: 'CY26SU09', type: 'SharedResources' } },
    resourcePackages: [{ name: 'SharedResources', type: 'SharedResources', items: [{ name: 'CY26SU09', path: 'BaseThemes/CY26SU09.json', type: 'BaseTheme' }] }],
  }),
  [`${dir}/${name}.Report/definition/pages/pages.json`]: json({ $schema: schema('item/report/definition/pagesMetadata/1.0.0/schema.json'), pageOrder: ['p1'], activePageName: 'p1' }),
  [`${dir}/${name}.Report/definition/pages/p1/page.json`]: json({ $schema: schema('item/report/definition/page/2.0.0/schema.json'), name: 'p1', displayName: 'Page 1' }),
  [`${dir}/${name}.Report/notes.md`]: '# Notes\n',
  [`${dir}/${name}.SemanticModel/.platform`]: platform('SemanticModel', name),
  [`${dir}/${name}.SemanticModel/definition.pbism`]: json({ $schema: schema('item/semanticModel/definitionProperties/1.0.0/schema.json'), version: '4.2' }),
  [`${dir}/${name}.SemanticModel/modelReference.json`]: json({ connectionString: 'Data Source=localhost;Initial Catalog=Sales', connectionType: 'analysisServicesDatabaseLive' }),
});
const tabular = (dir) => ({
  [`${dir}/database.tmdl`]: 'database Finance\n\tcompatibilityLevel: 1600\n',
  [`${dir}/model.tmdl`]: 'model Model\n\tculture: en-US\n\nref table Sales\n',
  [`${dir}/tables/Sales.tmdl`]: 'table Sales\n\n\tmeasure Revenue = SUM ( Sales[Amount] )\n\t\tformatString: 0\n\n\tcolumn Amount\n\t\tdataType: decimal\n\t\tsourceColumn: Amount\n',
});
const RDL = '<?xml version="1.0" encoding="utf-8"?>\n<Report xmlns="http://schemas.microsoft.com/sqlserver/reporting/2016/01/reportdefinition"><ReportSections><ReportSection><Body><Height>1cm</Height></Body><Width>10cm</Width><Page/></ReportSection></ReportSections></Report>\n';
const DTSX = '<?xml version="1.0"?>\n<DTS:Executable xmlns:DTS="www.microsoft.com/SqlServer/Dts" DTS:refId="Package" DTS:DTSID="{11111111-1111-1111-1111-111111111111}" DTS:ObjectName="Load" DTS:ProtectionLevel="0" />\n';
const ssis = (dir, name) => ({ [`${dir}/${name}.dtsx`]: DTSX, [`${dir}/${name}.dtproj`]: '<Project/>\n' });

const BROKEN = 'templates/pbir/Sales/broken.json';
/** (a)-(d): the reference folders, plus a broken JSON file under templates/ that the per-file check must still report. */
const REFERENCES = {
  'hardening/harness.config.json': json({ references: ['setup/'] }),
  ...livePbip('templates/pbir/Sales', 'Sales'), // (a) same name and logicalId as the project's own: no "second copy" either
  [BROKEN]: '{ "broken": ',
  ...ssis('templates/ssis/Load', 'Load'), // (b)
  'reports/R/source/R.rdl': RDL, // (c)
  ...tabular('setup/Finance'), // (d) a folder of the config's `references`
  'setup/Lab.Report/notes.md': '# not a report\n', // (d) a report folder without definition.pbir: no artifact error there
};
/** (e): the repository's own projects, with the same shapes. */
const OWN = {
  '.gitignore': '**/.pbi/localSettings.json\n**/.pbi/cache.abf\n',
  ...livePbip('powerbi', 'Sales'),
  ...ssis('etl/Load', 'Load'),
  'reports/R/R.rdl': RDL,
  ...tabular('models/Finance'),
};
// A file in a reference folder; a reference folder of the fixture named in a message or the banner (a message may say
// "notes belong under ... templates/", which names no reference item).
const REF_FILE = /^(?:templates\/|reports\/R\/source\/|setup\/)/;
const REF_PATH = /templates\/(?:pbir|ssis)\/|reports\/R\/source\/|setup\//;

function withRepo(files, fn) {
  // The real path: index-view (--staged) compares Git's top-level with the project path, which must not be an 8.3 short name.
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-reference-')));
  try {
    for (const [rel, text] of Object.entries(files)) {
      fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
      fs.writeFileSync(path.join(dir, rel), text);
    }
    git(dir, 'init', '-q');
    return fn(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}
function banner(dir) {
  const r = spawnSync(process.execPath, [HOOK], {
    input: JSON.stringify({ hook_event_name: 'SessionStart', source: 'startup', session_id: 'reference-test' }),
    env: { ...gitEnv(), CLAUDE_PROJECT_DIR: dir },
    encoding: 'utf8',
  });
  assert.equal(r.status, 0, r.stderr);
  return JSON.parse(r.stdout).hookSpecificOutput.additionalContext;
}
function validate(dir, ...args) {
  const r = spawnSync(process.execPath, [CLI, ...args, '--json'], { cwd: dir, env: { ...gitEnv(), CLAUDE_PROJECT_DIR: dir }, encoding: 'utf8' });
  assert.ok(r.stdout.trim(), r.stderr);
  return { status: r.status, issues: JSON.parse(r.stdout).issues, out: r.stdout + r.stderr };
}
const refIssues = (issues) => issues.filter((i) => REF_FILE.test(i.file) || REF_PATH.test(i.message));
const brokenOnly = (issues) => assert.deepEqual(refIssues(issues).map((i) => [i.level, i.file, /^Invalid JSON/.test(i.message)]), [['error', BROKEN, true]], JSON.stringify(refIssues(issues), null, 2));

const NOTHING = /- No BI artifacts found/;
const FABRIC_LINE = /^- Fabric Git-connected directory: /gm;

test('reference folders: findPbipItems lists only the repository\'s own projects; built-in references always, `references` per config', () => {
  withRepo({ ...REFERENCES, ...OWN }, (dir) => {
    const items = findPbipItems(dir, { references: ['setup/'] }, Infinity);
    assert.deepEqual(items.models, ['powerbi/Sales.SemanticModel']);
    assert.deepEqual(items.reports, ['powerbi/Sales.Report']);
    assert.deepEqual(items.pbip, ['powerbi/Sales.pbip']);
    assert.deepEqual(items.tabular, ['models/Finance']);
    assert.deepEqual(items.rdl, ['reports/R/R.rdl']);
    assert.deepEqual(items.ssis, ['etl/Load']);
    // The Fabric-sync fallback (.platform, no fabric.directories) names the project's item folders only.
    assert.deepEqual([...items.fabric].sort(), ['powerbi/Sales.Report', 'powerbi/Sales.SemanticModel']);
    // Without the config's `references`, setup/ is an ordinary folder again; templates/ and reports/*/source/ stay skipped.
    const plain = findPbipItems(dir, {}, Infinity);
    assert.deepEqual([...plain.tabular].sort(), ['models/Finance', 'setup/Finance']);
    assert.deepEqual([...plain.reports].sort(), ['powerbi/Sales.Report', 'setup/Lab.Report']);
    assert.deepEqual(plain.rdl, ['reports/R/R.rdl']);
    assert.deepEqual(plain.ssis, ['etl/Load']);
    // checkItemFolderFiles: a stray file in a reference's item folder is no service-commit risk.
    const stray = ['templates/pbir/Sales/Sales.Report/notes.md', 'setup/Lab.Report/notes.md', 'powerbi/Sales.Report/notes.md'];
    assert.deepEqual(checkItemFolderFiles(dir, stray, fs, { references: ['setup/'] }).map((i) => i.file), ['powerbi/Sales.Report/notes.md']);
    assert.deepEqual(checkItemFolderFiles(dir, stray).map((i) => i.file), ['setup/Lab.Report/notes.md', 'powerbi/Sales.Report/notes.md'], 'without a config only the built-in references are skipped');
  });
});

test('reference folders: the session banner lists only the repository\'s own projects and Fabric directory', () => {
  withRepo({ ...REFERENCES, ...OWN }, (dir) => {
    const out = banner(dir);
    assert.match(out, /^- Model powerbi\/Sales\.SemanticModel: live connection \(modelReference\.json\), 0 table file\(s\)$/m);
    assert.match(out, /^- Report powerbi\/Sales\.Report: PBIR, 1 page\(s\), dataset byPath → \.\.\/Sales\.SemanticModel$/m);
    assert.match(out, /^- Tabular model at models\/Finance: /m);
    assert.match(out, /^- Paginated reports: 1 \*\.rdl \(reports\/R\/R\.rdl\);/m);
    assert.match(out, /^- SSIS: 1 folder\(s\) with packages or projects \(etl\/Load\);/m);
    assert.deepEqual(out.match(FABRIC_LINE), ['- Fabric Git-connected directory: ']);
    assert.match(out, /^- Fabric Git-connected directory: powerbi \(2 item\(s\); from \.platform/m);
    assert.doesNotMatch(out, REF_PATH);
    assert.doesNotMatch(out, NOTHING);
  });
});

test('reference folders: a repository whose only BI files are references has "No BI artifacts found" (references are not the scope)', () => {
  withRepo(REFERENCES, (dir) => {
    const out = banner(dir);
    assert.match(out, NOTHING);
    assert.doesNotMatch(out, /No Power BI project/);
    assert.doesNotMatch(out, FABRIC_LINE);
    assert.doesNotMatch(out, REF_PATH);
    // The full scan: the broken JSON under templates/ is still an error; nothing else is reported, and with no PBIP of
    // the repository's own the .gitignore rules are not asked for (the tracked-file check still runs over every file).
    const full = validate(dir);
    assert.equal(full.status, 1, full.out);
    brokenOnly(full.issues);
    assert.deepEqual(full.issues.filter((i) => i.file !== BROKEN), [], full.out);
  });
});

test('reference folders: the validator (full, --changed, --staged) skips their artifact checks, keeps their per-file checks', () => {
  withRepo({ ...REFERENCES, ...OWN }, (dir) => {
    // The project's own copy gets every artifact warning the reference no longer gets.
    const expectOwn = (issues, label) => {
      const own = (file, re) => assert.ok(issues.some((i) => i.level === 'warn' && i.file === file && re.test(i.message)), `${label}: ${file} ${re}\n${JSON.stringify(issues, null, 2)}`);
      own('powerbi/Sales.Report/definition.pbir', /^Live connection to Analysis Services/);
      own('powerbi/Sales.SemanticModel/modelReference.json', /^Live connection to Analysis Services/);
      own('powerbi/Sales.Report/definition/report.json', /^resourcePackages names StaticResources\/SharedResources\/BaseThemes\/CY26SU09\.json/);
      own('powerbi/Sales.Report/notes.md', /^Not part of the report item definition/);
    };
    const full = validate(dir);
    assert.equal(full.status, 1, full.out);
    brokenOnly(full.issues);
    expectOwn(full.issues, 'full');

    // The Stop gate's mode: every file is untracked, so every file is a changed one.
    const changed = validate(dir, '--changed');
    assert.equal(changed.status, 1, changed.out);
    brokenOnly(changed.issues);
    expectOwn(changed.issues, '--changed');

    // The pre-commit hook's mode.
    git(dir, 'add', '-A');
    const staged = validate(dir, '--staged');
    assert.equal(staged.status, 1, staged.out);
    brokenOnly(staged.issues);
    expectOwn(staged.issues, '--staged');
  });
});
