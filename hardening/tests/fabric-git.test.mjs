// Fabric Git item folders (docs/harness/fabric-git.md, 2026-10-15): a commit from the service deletes every file inside
// a *.SemanticModel/, *.Report/ or *.PaginatedReport/ folder that is not part of the item definition. The validator
// warns about such files (any file type, full scan and --changed), the write guard refuses to create one, the
// post-edit check warns on an edit of one that exists, and the session banner names each synced directory: those the user
// lists in fabric.directories (hardening/harness.config.json), else each directory whose item folders hold a .platform
// file. Fixtures are temporary repositories; the hooks run on them with CLAUDE_PROJECT_DIR.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  analysisServicesLiveReason, fabricItemOf, fabricSyncOf, findPbipItems, isItemDefinitionFile, resourcePackageFiles, syncedDirOf, validateArtifacts,
  validateFiles,
} from '../hooks/lib/validators.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const hooks = path.join(here, '..', 'hooks');
const validateCli = path.join(here, '..', 'scripts', 'validate.mjs');

const WS = 'fabric/Sales-Dev';
const PLATFORM = (type, name) => `${JSON.stringify({
  $schema: 'https://developer.microsoft.com/json-schemas/fabric/gitIntegration/platformProperties/2.0.0/schema.json',
  metadata: { type, displayName: name },
  config: { version: '2.0', logicalId: '00000000-0000-0000-0000-000000000001' },
}, null, 2)}\n`;
const SCHEMA = (part) => `https://developer.microsoft.com/json-schemas/fabric/item/report/definition/${part}/1.0.0/schema.json`;
const RDL = '<?xml version="1.0" encoding="utf-8"?>\n<Report xmlns="http://schemas.microsoft.com/sqlserver/reporting/2016/01/reportdefinition"><ReportSections><ReportSection><Body><Height>1cm</Height></Body><Width>10cm</Width><Page/></ReportSection></ReportSections></Report>\n';

/** A valid Fabric Git directory: model, report and paginated report, each with .platform. */
const ITEMS = {
  '.gitignore': '**/.pbi/localSettings.json\n**/.pbi/cache.abf\n',
  [`${WS}/Sales.SemanticModel/.platform`]: PLATFORM('SemanticModel', 'Sales'),
  [`${WS}/Sales.SemanticModel/definition.pbism`]: '{"version":"4.2","settings":{}}\n',
  [`${WS}/Sales.SemanticModel/definition/model.tmdl`]: 'model Model\n\tculture: en-US\n\nref table Sales\n',
  [`${WS}/Sales.SemanticModel/definition/tables/Sales.tmdl`]: 'table Sales\n\n\tmeasure Revenue = SUM ( Sales[Amount] )\n\t\tformatString: 0\n\n\tcolumn Amount\n\t\tdataType: decimal\n\t\tsourceColumn: Amount\n',
  [`${WS}/Sales.Report/.platform`]: PLATFORM('Report', 'Sales'),
  [`${WS}/Sales.Report/definition.pbir`]: `${JSON.stringify({ version: '4.0', datasetReference: { byPath: { path: '../Sales.SemanticModel' } } })}\n`,
  [`${WS}/Sales.Report/definition/version.json`]: `${JSON.stringify({ $schema: SCHEMA('versionMetadata'), version: '2.0.0' })}\n`,
  [`${WS}/Sales.Report/definition/report.json`]: `${JSON.stringify({ $schema: SCHEMA('report') })}\n`,
  [`${WS}/Sales.Report/definition/pages/p1/page.json`]: `${JSON.stringify({ $schema: SCHEMA('page'), name: 'p1', displayName: 'Page 1' })}\n`,
  [`${WS}/Invoices.PaginatedReport/.platform`]: PLATFORM('PaginatedReport', 'Invoices'),
  [`${WS}/Invoices.PaginatedReport/Invoices.rdl`]: RDL,
};
/** What the harness must never leave inside an item folder. */
const STRAY = {
  [`${WS}/Sales.Report/notes.md`]: '# Notes\n',
  [`${WS}/Sales.SemanticModel/test-pack.dax.md`]: '# Test pack\n',
  [`${WS}/Invoices.PaginatedReport/page1.png`]: '\x89PNG\r\n\x1a\n',
};

function repo(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-fabric-'));
  for (const [rel, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), content);
  }
  spawnSync('git', ['init', '-q'], { cwd: dir });
  return dir;
}

const run = (script, args, dir, payload) => spawnSync(process.execPath, [script, ...args], {
  input: payload === undefined ? '' : JSON.stringify(payload),
  env: { ...process.env, CLAUDE_PROJECT_DIR: dir },
  encoding: 'utf8',
});

// Session banner lines are matched on their facts (the directory, its item count, where the list came from, the guide it
// points to), not on their whole sentence, so a rewording keeps these tests green (follow-up audit, F2-62).
const reEscape = (s) => s.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
const SOURCES = {
  platform: 'from \\.platform, none recorded in fabric\\.directories',
  invalid: 'from \\.platform, fabric\\.directories is invalid',
  config: 'recorded in fabric\\.directories\\)',
};
/** The banner line of a synced directory: `count` is a number of items or the text that stands in for it. */
const fabricDirLine = (where, count, source) => new RegExp(
  `^- Fabric Git-connected directory: ${reEscape(where)} \\(${typeof count === 'number' ? `${count} item\\(s\\)` : reEscape(count)}; ${SOURCES[source]}.*docs/harness/fabric-git\\.md`,
);
const hasLine = (lines, re) => assert.ok(lines.some((l) => re.test(l)), `${re} in:\n${lines.join('\n')}`);

test('item folders: definition and system files pass, anything else is stray; other paths are no item folder', () => {
  const allowed = [
    'Sales.Report/definition.pbir', 'Sales.Report/definition-liveConnect.pbir', 'Sales.Report/definition/pages/p1/page.json',
    'Sales.Report/report.json', 'Sales.Report/.platform', 'Sales.Report/StaticResources/RegisteredResources/logo.png',
    'Sales.Report/CustomVisuals/v/pbiviz.json', 'Sales.Report/mobileState.json', 'Sales.Report/semanticModelDiagramLayout.json',
    'Sales.Report/.pbi/localSettings.json', 'Sales.Report/item.metadata.json',
    'Sales.SemanticModel/definition.pbism', 'Sales.SemanticModel/definition/tables/Sales.tmdl', 'Sales.SemanticModel/model.bim',
    'Sales.SemanticModel/.platform', 'Sales.SemanticModel/diagramLayout.json', 'Sales.SemanticModel/DAXQueries/Check.dax',
    'Sales.SemanticModel/TMDLScripts/Script 1.tmdl', 'Sales.SemanticModel/.pbi/editorSettings.json',
    'Sales.SemanticModel/modelReference.json',
    'Invoices.PaginatedReport/Invoices.rdl', 'Invoices.PaginatedReport/.platform',
    'Invoices.PaginatedReport/item.metadata.json', 'Invoices.PaginatedReport/item.config.json',
  ];
  const stray = [
    'Sales.Report/notes.md', 'Sales.Report/README.md', 'Sales.Report/screenshot.png', 'Sales.Report/tests/pack.dax',
    'Sales.SemanticModel/test-pack.md', 'Sales.SemanticModel/query.sql', 'Sales.SemanticModel/tables/Sales.tmdl',
    'Invoices.PaginatedReport/notes.md', 'Invoices.PaginatedReport/page1.png', 'Invoices.PaginatedReport/sub/Other.rdl',
  ];
  for (const prefix of ['', `${WS}/`, `${WS}/Finance/Q1/`]) {
    for (const rel of allowed) {
      const item = fabricItemOf(prefix + rel);
      assert.ok(item && isItemDefinitionFile(item), prefix + rel);
    }
    for (const rel of stray) {
      const item = fabricItemOf(prefix + rel);
      assert.ok(item && !isItemDefinitionFile(item), prefix + rel);
    }
  }
  // Case does not matter (Windows, Desktop); the outermost item folder is the item.
  for (const rel of ['SALES.REPORT/Definition.PBIR', 'x/sales.semanticmodel/DEFINITION/model.tmdl', 'Inv.paginatedreport/Inv.RDL']) {
    assert.ok(isItemDefinitionFile(fabricItemOf(rel)), rel);
  }
  assert.ok(!isItemDefinitionFile(fabricItemOf('fabric/WS/Sales.REPORT/Notes.MD')));
  assert.equal(fabricItemOf(`${WS}/Sales.Report/definition/pages/p1/page.json`).folder, `${WS}/Sales.Report`);
  assert.equal(fabricItemOf('Invoices.PaginatedReport/x.png').kind, 'paginatedreport');
  for (const rel of ['docs/Sales.Report.md', 'docs/tests/Sales.Report-pack.md', 'Sales.Report', 'reports/Sales/notes.md', 'Sales.Reports/x.md']) {
    assert.equal(fabricItemOf(rel), null, rel);
  }
});

test('validator CLI: a stray file of any type in an item folder is a warning in the full scan and in --changed', () => {
  const dir = repo({ ...ITEMS, ...STRAY });
  try {
    for (const args of [['--json'], ['--changed', '--json']]) {
      const r = run(validateCli, args, dir);
      assert.equal(r.status, 0, `${args.join(' ')}: ${r.stdout}${r.stderr}`);
      const { issues } = JSON.parse(r.stdout);
      for (const file of Object.keys(STRAY)) {
        const hit = issues.find((i) => i.file === file);
        assert.equal(hit?.level, 'warn', `${args.join(' ')}: ${file} ${JSON.stringify(issues)}`);
        assert.match(hit.message, /a Fabric Git commit from the service deletes every other file inside fabric\/Sales-Dev\/[^/]+\/\. Notes, test packs, screenshots and SQL belong under docs\/, tests\/ or templates\/ \(docs\/harness\/fabric-git\.md\)/);
      }
      // Definition and system files raise nothing of the kind.
      assert.ok(!issues.some((i) => !(i.file in STRAY) && /Fabric Git/.test(i.message)), JSON.stringify(issues));
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('validator: a second .rdl in a paginated item folder is a warning; a deleted path in --changed is skipped', () => {
  const dir = repo({ ...ITEMS, [`${WS}/Invoices.PaginatedReport/Invoices-copy.rdl`]: RDL });
  try {
    const rdl = validateFiles(dir, {}, [`${WS}/Invoices.PaginatedReport/Invoices.rdl`], { projectChecks: false });
    assert.ok(rdl.issues.some((i) => i.level === 'warn' && i.file === `${WS}/Invoices.PaginatedReport` && /^2 \.rdl files in one paginated report item folder/.test(i.message)), JSON.stringify(rdl.issues));
    const gone = validateFiles(dir, {}, [`${WS}/Sales.Report/removed-notes.md`], { projectChecks: false, allowMissing: true });
    assert.deepEqual(gone.issues, []);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('guard: creating a file inside an item folder outside the definition is denied; definition files and edits pass', () => {
  const dir = repo({ ...ITEMS, [`${WS}/Sales.Report/README.md`]: '# Written before the guard\n' });
  const guard = (tool_name, rel, extra) => {
    const r = run(path.join(hooks, 'pre-tool-use.mjs'), [], dir, {
      hook_event_name: 'PreToolUse', session_id: 'fabric-test', tool_name, tool_input: { file_path: path.join(dir, rel), ...extra },
    });
    assert.equal(r.status, 0, r.stderr);
    const out = r.stdout.trim() ? JSON.parse(r.stdout).hookSpecificOutput : {};
    return { decision: out.permissionDecision ?? null, reason: out.permissionDecisionReason ?? '' };
  };
  try {
    for (const rel of [`${WS}/Sales.Report/notes.md`, `${WS}/Sales.Report/page1.png`, `${WS}/Sales.SemanticModel/test-pack.dax`,
      `${WS}/Sales.SemanticModel/tables/New.tmdl`, `${WS}/Invoices.PaginatedReport/check.sql`, 'fabric/sales-dev/sales.report/Notes.MD']) {
      const v = guard('Write', rel, { content: 'x\n' });
      assert.equal(v.decision, 'deny', rel);
      assert.match(v.reason, /Not part of the (?:report|semantic model|paginated report) item definition: a Fabric Git commit from the service deletes every other file inside .*docs\/harness\/fabric-git\.md/, rel);
    }
    const second = guard('Write', `${WS}/Invoices.PaginatedReport/Second.rdl`, { content: RDL });
    assert.equal(second.decision, 'deny');
    assert.match(second.reason, /already holds fabric\/Sales-Dev\/Invoices\.PaginatedReport\/Invoices\.rdl; a paginated report item folder holds one \.rdl.*docs\/harness\/fabric-git\.md/);

    for (const [tool, rel, extra] of [
      ['Write', `${WS}/Sales.Report/definition-liveConnect.pbir`, { content: `${JSON.stringify({ version: '4.0', datasetReference: { byPath: { path: '../Sales.SemanticModel' } } })}\n` }],
      ['Write', `${WS}/Sales.Report/definition/pages/p2/page.json`, { content: `${JSON.stringify({ $schema: SCHEMA('page'), name: 'p2', displayName: 'Page 2' })}\n` }],
      ['Write', `${WS}/Sales.SemanticModel/DAXQueries/Check.dax`, { content: 'EVALUATE ROW ( "n", 1 )\n' }],
      ['Write', `${WS}/Invoices.PaginatedReport/item.config.json`, { content: '{"version":"1.0","logicalId":"x"}\n' }],
      ['Write', `${WS}/Invoices.PaginatedReport/Invoices.rdl`, { content: RDL }], // overwriting the one .rdl
      ['Edit', `${WS}/Sales.Report/README.md`, { old_string: 'Written before', new_string: 'Written long before' }],
      ['Write', 'docs/tests/sales-pack.md', { content: '# Sales test pack\n' }],
    ]) assert.notEqual(guard(tool, rel, extra).decision, 'deny', rel);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('post-edit check: an edit of an existing stray file goes back with the Fabric Git warning, a definition edit without it', () => {
  const dir = repo({ ...ITEMS, [`${WS}/Sales.Report/README.md`]: '# Notes\n' });
  const post = (rel) => {
    const r = run(path.join(hooks, 'post-tool-validate.mjs'), [], dir, {
      hook_event_name: 'PostToolUse', session_id: 'fabric-test', tool_name: 'Edit', tool_input: { file_path: path.join(dir, rel) },
    });
    assert.equal(r.status, 0, r.stderr);
    return r.stdout.trim() ? JSON.parse(r.stdout) : {};
  };
  try {
    const stray = post(`${WS}/Sales.Report/README.md`);
    assert.equal(stray.decision, undefined);
    assert.match(stray.hookSpecificOutput?.additionalContext ?? '', /Validation warnings:[\s\S]*README\.md — Not part of the report item definition: a Fabric Git commit/);
    assert.doesNotMatch(post(`${WS}/Sales.Report/definition/pages/p1/page.json`).hookSpecificOutput?.additionalContext ?? '', /Fabric Git/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('session start without fabric.directories: one line per directory whose item folders hold .platform, read for existence only', () => {
  const dir = repo({
    ...ITEMS,
    [`${WS}/Invoices.PaginatedReport/.platform`]: 'not JSON: the banner never parses .platform\n',
    'fabric/Sales-Models/Finance.SemanticModel/.platform': PLATFORM('SemanticModel', 'Finance'),
    'fabric/Sales-Models/Finance.SemanticModel/definition.pbism': '{}\n',
    'Root.Report/.platform': PLATFORM('Report', 'Root'),
    'Root.Report/definition.pbir': '{}\n',
    'powerbi/Local.Report/definition.pbir': '{}\n', // a Desktop project no workspace syncs: no .platform
    'powerbi/Local.SemanticModel/definition.pbism': '{}\n',
  });
  try {
    const r = run(path.join(hooks, 'session-start.mjs'), [], dir, { hook_event_name: 'SessionStart', source: 'startup', session_id: 'fabric-test' });
    assert.equal(r.status, 0, r.stderr);
    const out = JSON.parse(r.stdout).hookSpecificOutput.additionalContext;
    const lines = out.split('\n');
    hasLine(lines, fabricDirLine('fabric/Sales-Dev', 3, 'platform'));
    hasLine(lines, fabricDirLine('fabric/Sales-Models', 1, 'platform'));
    hasLine(lines, fabricDirLine('the repository root', 1, 'platform'));
    assert.doesNotMatch(out, /Fabric Git-connected directory: powerbi/);
    assert.equal(lines.filter((l) => l.startsWith('- Fabric Git-connected directory:')).length, 3);
    // The paginated report inside its item folder is still listed with the other .rdl files.
    assert.match(out, /Paginated reports: 1 \*\.rdl \(fabric\/Sales-Dev\/Invoices\.PaginatedReport\/Invoices\.rdl\)/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('session start: a repository without .platform files shows no Fabric Git line', () => {
  const dir = repo({ 'powerbi/Sales.Report/definition.pbir': '{}\n', 'powerbi/Sales.SemanticModel/definition.pbism': '{}\n' });
  try {
    const r = run(path.join(hooks, 'session-start.mjs'), [], dir, { hook_event_name: 'SessionStart', source: 'startup', session_id: 'fabric-test' });
    assert.equal(r.status, 0, r.stderr);
    assert.doesNotMatch(JSON.parse(r.stdout).hookSpecificOutput.additionalContext, /Fabric Git/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// Live test 2026-10-17 (docs/harness/fabric-git.md): the service commit added the base theme file report.json named under
// resourcePackages, which neither the harness nor Desktop had written; a report uploaded to the service and committed from
// there left its pre-upload copy behind; Learn lists live connections to Analysis Services as unsupported.
const THEME = { name: 'CY24SU10', reportVersionAtImport: { visual: '2.12.0', page: '2.1.0', report: '3.3.0' }, type: 'SharedResources' };
const REPORT_JSON = (packages) => `${JSON.stringify({ $schema: SCHEMA('report'), themeCollection: { baseTheme: THEME }, resourcePackages: packages })}\n`;
const SHARED = { name: 'SharedResources', type: 'SharedResources', items: [{ name: 'CY24SU10', path: 'BaseThemes/CY24SU10.json', type: 'BaseTheme' }] };
const REGISTERED = { name: 'RegisteredResources', type: 'RegisteredResources', items: [{ name: 'House.json', path: 'House.json', type: 'CustomTheme' }] };
const LIVE = (conn) => `${JSON.stringify({ version: '4.0', datasetReference: { byConnection: conn } })}\n`;
/** A report folder that passes every structural check, bound as given. */
const REPORT = (folder, pbir, platform = true) => ({
  ...(platform ? { [`${folder}/.platform`]: PLATFORM('Report', path.posix.basename(folder).replace(/\.Report$/, '')) } : {}),
  [`${folder}/definition.pbir`]: pbir,
  [`${folder}/definition/version.json`]: `${JSON.stringify({ $schema: SCHEMA('versionMetadata'), version: '2.0.0' })}\n`,
  [`${folder}/definition/report.json`]: `${JSON.stringify({ $schema: SCHEMA('report') })}\n`,
  [`${folder}/definition/pages/p1/page.json`]: `${JSON.stringify({ $schema: SCHEMA('page'), name: 'p1', displayName: 'Page 1' })}\n`,
});
const warnings = (issues, re) => issues.filter((i) => i.level === 'warn' && re.test(i.message));

test('resourcePackages: a base theme or registered resource without its file is a warning on report.json; present files pass', () => {
  assert.deepEqual(resourcePackageFiles({ resourcePackages: [SHARED, REGISTERED] }), ['StaticResources/SharedResources/BaseThemes/CY24SU10.json', 'StaticResources/RegisteredResources/House.json']);
  assert.deepEqual(resourcePackageFiles({ resourcePackages: [{ name: 'SharedResources', items: [{ path: 'BaseThemes\\CY24SU10.json' }, { name: 'no path' }] }, { items: [{ path: 'x' }] }, 'junk'] }), ['StaticResources/SharedResources/BaseThemes/CY24SU10.json']);
  assert.deepEqual(resourcePackageFiles(null), []);
  const dir = repo({ ...ITEMS, [`${WS}/Sales.Report/definition/report.json`]: REPORT_JSON([SHARED, REGISTERED]) });
  try {
    const missing = warnings(validateArtifacts(dir, { models: [], reports: [`${WS}/Sales.Report`] }), /^resourcePackages names /);
    assert.equal(missing.length, 2, JSON.stringify(missing));
    for (const w of missing) assert.equal(w.file, `${WS}/Sales.Report/definition/report.json`);
    assert.match(missing[0].message, /^resourcePackages names StaticResources\/SharedResources\/BaseThemes\/CY24SU10\.json, which does not exist\. A Fabric Git commit from the service adds a missing base theme file \(observed 2026-10-17\).*copy it from a working report \(bi-pbir-report, docs\/harness\/fabric-git\.md\)/);
    assert.match(missing[1].message, /names StaticResources\/RegisteredResources\/House\.json, which does not exist/);
    assert.ok(!missing.some((w) => w.level === 'error'), 'a missing resource never blocks a commit of a report Desktop saved');
    // The files written (the theme copied from a working report): silent. A report without resourcePackages: silent.
    fs.mkdirSync(path.join(dir, WS, 'Sales.Report', 'StaticResources', 'SharedResources', 'BaseThemes'), { recursive: true });
    fs.writeFileSync(path.join(dir, WS, 'Sales.Report', 'StaticResources', 'SharedResources', 'BaseThemes', 'CY24SU10.json'), '{}\n');
    fs.mkdirSync(path.join(dir, WS, 'Sales.Report', 'StaticResources', 'RegisteredResources'), { recursive: true });
    fs.writeFileSync(path.join(dir, WS, 'Sales.Report', 'StaticResources', 'RegisteredResources', 'House.json'), '{}\n');
    assert.deepEqual(warnings(validateArtifacts(dir, { models: [], reports: [`${WS}/Sales.Report`] }), /resourcePackages/), []);
    // The check also runs in --changed mode, where the report folder is an affected artifact.
    fs.rmSync(path.join(dir, WS, 'Sales.Report', 'StaticResources'), { recursive: true, force: true });
    const changed = validateFiles(dir, {}, [`${WS}/Sales.Report/definition/report.json`]);
    assert.equal(warnings(changed.issues, /^resourcePackages names /).length, 2, JSON.stringify(changed.issues));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('a live connection to Analysis Services is recognized from byConnection; a Power BI workspace is not', () => {
  assert.match(analysisServicesLiveReason({ byConnection: { connectionString: 'Data Source=asazure://x/y;Initial Catalog=M', connectionType: 'analysisServicesDatabaseLive' } }), /connectionType analysisServicesDatabaseLive/);
  assert.match(analysisServicesLiveReason({ byConnection: { connectionString: 'Data Source=asazure://x/y;Initial Catalog=M' } }), /Data Source is no Power BI workspace/);
  assert.match(analysisServicesLiveReason({ byConnection: { connectionString: 'data source=ssas-01;initial catalog=Finance' } }), /Data Source is no Power BI workspace/);
  assert.doesNotMatch(analysisServicesLiveReason({ byConnection: { connectionString: 'Data Source=ssas-01;Initial Catalog=Finance' } }), /ssas-01/, 'the server name is not repeated');
  for (const ref of [
    { byConnection: { connectionString: 'Data Source=powerbi://api.powerbi.com/v1.0/myorg/WS;Initial Catalog=M', connectionType: 'pbiServiceXmlaStyleLive' } },
    { byConnection: { connectionString: 'Data Source=pbiazure://api.powerbi.com;Initial Catalog=M' } },
    { byConnection: { connectionString: 'Initial Catalog=M' } }, // no Data Source: unknown, not reported
    { byPath: { path: '../Sales.SemanticModel' } }, {}, null,
  ]) assert.equal(analysisServicesLiveReason(ref), null, JSON.stringify(ref));
});

test('validator without fabric.directories: a report or model live-connected to Analysis Services inside a folder that holds .platform is a warning; the same outside it, or on a Power BI model, is not', () => {
  const as = { connectionString: 'Data Source=asazure://westeurope.asazure.windows.net/finance;Initial Catalog=Finance', connectionType: 'analysisServicesDatabaseLive' };
  const pbi = { connectionString: 'Data Source=powerbi://api.powerbi.com/v1.0/myorg/Sales-Models;Initial Catalog=Sales', connectionType: 'pbiServiceXmlaStyleLive' };
  const dir = repo({
    ...ITEMS,
    ...REPORT(`${WS}/AS.Report`, LIVE(as)),
    ...REPORT(`${WS}/Server.Report`, LIVE({ connectionString: 'Data Source=ssas-01;Initial Catalog=Finance' })),
    ...REPORT(`${WS}/Thin.Report`, LIVE(pbi)),
    ...REPORT('powerbi/AS.Report', LIVE(as), false),
    ...REPORT('powerbi/Saved.Report', LIVE(as)), // a Desktop save writes .platform too: the warning appears, and says it is a reminder
    ...REPORT(`${WS}/OnRef.Report`, `${JSON.stringify({ version: '4.0', datasetReference: { byPath: { path: '../Ref.SemanticModel' } } })}\n`),
    [`${WS}/Ref.SemanticModel/.platform`]: PLATFORM('SemanticModel', 'Ref'),
    [`${WS}/Ref.SemanticModel/definition.pbism`]: '{"version":"4.2","settings":{}}\n',
    [`${WS}/Ref.SemanticModel/modelReference.json`]: '{"connectionType":"analysisServicesDatabaseLive"}\n',
    'powerbi/Ref.SemanticModel/definition.pbism': '{"version":"4.2","settings":{}}\n',
    'powerbi/Ref.SemanticModel/modelReference.json': '{"connectionType":"analysisServicesDatabaseLive"}\n',
  });
  try {
    const items = { models: [`${WS}/Sales.SemanticModel`, `${WS}/Ref.SemanticModel`, 'powerbi/Ref.SemanticModel'], reports: [`${WS}/Sales.Report`, `${WS}/AS.Report`, `${WS}/Server.Report`, `${WS}/Thin.Report`, 'powerbi/AS.Report', 'powerbi/Saved.Report', `${WS}/OnRef.Report`] };
    const issues = validateArtifacts(dir, items);
    assert.ok(!issues.some((i) => i.level === 'error'), JSON.stringify(issues));
    const live = warnings(issues, /^Live connection to Analysis Services/);
    assert.deepEqual(live.map((i) => i.file).sort(), [`${WS}/AS.Report/definition.pbir`, `${WS}/OnRef.Report/definition.pbir`, `${WS}/Ref.SemanticModel/modelReference.json`, `${WS}/Server.Report/definition.pbir`, 'powerbi/Saved.Report/definition.pbir'], JSON.stringify(live));
    for (const w of live) assert.match(w.message, /in a folder that holds \.platform\. If a Fabric workspace syncs this directory, Git integration ignores the item \(Learn, checked 2026-10-17.*keep it in a directory no workspace syncs and publish it from Desktop\. Synced directories: \.platform, because fabric\.directories in hardening\/harness\.config\.json records none; Desktop writes \.platform too, so this is a reminder, not proof of a connection\. List the synced directories there to check only those \(docs\/harness\/fabric-git\.md\)\.$/);
    assert.match(live.find((w) => w.file.startsWith(`${WS}/OnRef`)).message, /byPath to \.\.\/Ref\.SemanticModel, which holds modelReference\.json/);
    assert.match(live.find((w) => w.file.startsWith(`${WS}/Server`)).message, /Data Source is no Power BI workspace/);
    assert.doesNotMatch(JSON.stringify(live), /asazure|ssas-01/, 'no server name in a warning');
    // --changed on one of them reaches the same check through the affected report folder.
    const changed = validateFiles(dir, {}, [`${WS}/AS.Report/definition/pages/p1/page.json`]);
    assert.equal(warnings(changed.issues, /^Live connection to Analysis Services/).length, 1, JSON.stringify(changed.issues));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('validator CLI full scan without fabric.directories: a second copy of a synced item outside its .platform folder is a warning; --changed has no inventory for it', () => {
  const other = PLATFORM('Report', 'Sales').replace('00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000002');
  const dir = repo({
    ...ITEMS,
    // Pre-Fabric copies without .platform: the report, the model and the pre-upload paginated report.
    ...REPORT('powerbi/Sales.Report', `${JSON.stringify({ version: '4.0', datasetReference: { byPath: { path: '../Sales.SemanticModel' } } })}\n`, false),
    'powerbi/Sales.SemanticModel/definition.pbism': '{"version":"4.2","settings":{}}\n',
    'powerbi/Sales.SemanticModel/definition/model.tmdl': 'model Model\n',
    'paginated/invoices.rdl': RDL, // the file name compares without case
    'reports/Legacy/rdl/Orders.rdl': RDL, // another report: silent
    // A raw copy with the same logicalId in a second directory, and a real second item with its own logicalId.
    ...REPORT('fabric/Copy/Sales.Report', `${JSON.stringify({ version: '4.0', datasetReference: { byPath: { path: '../Sales.SemanticModel' } } })}\n`),
    'fabric/Copy/Sales.SemanticModel/.platform': PLATFORM('SemanticModel', 'Sales'),
    'fabric/Copy/Sales.SemanticModel/definition.pbism': '{"version":"4.2","settings":{}}\n',
    'fabric/Copy/Sales.SemanticModel/definition/model.tmdl': 'model Model\n',
    ...REPORT('fabric/Other/Sales.Report', `${JSON.stringify({ version: '4.0', datasetReference: { byPath: { path: '../Sales.SemanticModel' } } })}\n`),
    'fabric/Other/Sales.Report/.platform': other,
    'fabric/Other/Sales.SemanticModel/.platform': PLATFORM('SemanticModel', 'Sales').replace('00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000003'),
    'fabric/Other/Sales.SemanticModel/definition.pbism': '{"version":"4.2","settings":{}}\n',
    'fabric/Other/Sales.SemanticModel/definition/model.tmdl': 'model Model\n',
    // The same paginated report synced by a second workspace: silent.
    'fabric/Other/Invoices.PaginatedReport/.platform': PLATFORM('PaginatedReport', 'Invoices'),
    'fabric/Other/Invoices.PaginatedReport/Invoices.rdl': RDL,
  });
  try {
    const r = run(validateCli, ['--json'], dir);
    assert.equal(r.status, 0, r.stdout + r.stderr);
    const copies = warnings(JSON.parse(r.stdout).issues, /^(?:Second copy of|Same name and the same \.platform logicalId)/);
    const byFile = Object.fromEntries(copies.map((i) => [i.file, i.message]));
    assert.deepEqual(Object.keys(byFile).sort(), ['fabric/Copy/Sales.Report', 'fabric/Copy/Sales.SemanticModel', 'paginated/invoices.rdl', 'powerbi/Sales.Report', 'powerbi/Sales.SemanticModel'], JSON.stringify(copies));
    assert.match(byFile['powerbi/Sales.Report'], /^Second copy of fabric\/Copy\/Sales\.Report, fabric\/Other\/Sales\.Report, fabric\/Sales-Dev\/Sales\.Report, which holds \.platform.*remove this copy with the user's approval/);
    assert.match(byFile['powerbi/Sales.SemanticModel'], /^Second copy of .*fabric\/Sales-Dev\/Sales\.SemanticModel, which holds \.platform/);
    assert.match(byFile['paginated/invoices.rdl'], /^Second copy of fabric\/Other\/Invoices\.PaginatedReport\/Invoices\.rdl, fabric\/Sales-Dev\/Invoices\.PaginatedReport\/Invoices\.rdl, which a Fabric workspace syncs: the pre-upload copy of a paginated report\. Remove it in the pull request that brings the service commit, with the user's approval, and renormalize/);
    // Without fabric.directories every copy warning names .platform as its source.
    for (const message of Object.values(byFile)) assert.match(message, /Synced directories: \.platform, because fabric\.directories in hardening\/harness\.config\.json records none;/);
    assert.match(byFile['fabric/Copy/Sales.Report'], /^Same name and the same \.platform logicalId as fabric\/Sales-Dev\/Sales\.Report: two copies of one item/);
    assert.match(byFile['fabric/Copy/Sales.SemanticModel'], /logicalId as fabric\/Sales-Dev\/Sales\.SemanticModel/);
    assert.equal(copies.length, 5, 'one warning per pair, none on the synced originals or on fabric/Other');
    const changed = run(validateCli, ['--changed', '--json'], dir);
    assert.equal(changed.status, 0, changed.stdout + changed.stderr);
    assert.deepEqual(warnings(JSON.parse(changed.stdout).issues, /^(?:Second copy of|Same name and the same)/), []);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('validator: without .platform anywhere, same-named projects and reports are not copies', () => {
  const dir = repo({
    ...REPORT('powerbi/north/Sales.Report', `${JSON.stringify({ version: '4.0', datasetReference: { byPath: { path: '../Sales.SemanticModel' } } })}\n`, false),
    'powerbi/north/Sales.SemanticModel/definition.pbism': '{"version":"4.2","settings":{}}\n',
    'powerbi/north/Sales.SemanticModel/definition/model.tmdl': 'model Model\n',
    ...REPORT('powerbi/south/Sales.Report', `${JSON.stringify({ version: '4.0', datasetReference: { byPath: { path: '../Sales.SemanticModel' } } })}\n`, false),
    'powerbi/south/Sales.SemanticModel/definition.pbism': '{"version":"4.2","settings":{}}\n',
    'powerbi/south/Sales.SemanticModel/definition/model.tmdl': 'model Model\n',
    'paginated/Invoices.rdl': RDL,
    'reports/Legacy/rdl/Invoices.rdl': RDL,
    '.gitignore': '**/.pbi/localSettings.json\n**/.pbi/cache.abf\n',
  });
  try {
    const r = run(validateCli, ['--json'], dir);
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.deepEqual(warnings(JSON.parse(r.stdout).issues, /copy|logicalId/i), []);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// fabric.directories (hardening/harness.config.json): the user records which directories a workspace syncs. With a list,
// only item folders under a listed directory count and .platform no longer matters (Desktop writes it on a project save
// too: Learn's report folder page); [] records that none is synced; a value that is no list falls back to .platform.
const CONFIG = (directories) => ({ 'hardening/harness.config.json': `${JSON.stringify({ fabric: { directories } }, null, 2)}\n` });
const AS_LIVE = { connectionString: 'Data Source=asazure://westeurope.asazure.windows.net/finance;Initial Catalog=Finance', connectionType: 'analysisServicesDatabaseLive' };
const BY_PATH = `${JSON.stringify({ version: '4.0', datasetReference: { byPath: { path: '../Sales.SemanticModel' } } })}\n`;
const COPY_RE = /^(?:Second copy of|Same name and the same \.platform logicalId)/;
const LISTED = /Synced directories: fabric\.directories in hardening\/harness\.config\.json\.$/;
const scan = (dir, args = ['--json']) => {
  const r = run(validateCli, args, dir);
  assert.equal(r.status, 0, `${args.join(' ')}: ${r.stdout}${r.stderr}`);
  return JSON.parse(r.stdout).issues;
};
const banner = (dir) => {
  const r = run(path.join(hooks, 'session-start.mjs'), [], dir, { hook_event_name: 'SessionStart', source: 'startup', session_id: 'fabric-test' });
  assert.equal(r.status, 0, r.stderr);
  return JSON.parse(r.stdout).hookSpecificOutput.additionalContext.split('\n');
};

test('fabric.directories: absent or null is not recorded, a list of project-relative directories is, any other value falls back to .platform', () => {
  for (const cfg of [undefined, {}, { fabric: {} }, { fabric: { directories: null } }]) {
    assert.deepEqual(fabricSyncOf(cfg), { source: 'platform', dirs: null, invalid: false }, JSON.stringify(cfg));
  }
  assert.deepEqual(fabricSyncOf({ fabric: { directories: [] } }), { source: 'config', dirs: [], invalid: false });
  // POSIX, without "./" or a trailing slash, duplicates once, "." for the root; the longest first.
  assert.deepEqual(fabricSyncOf({ fabric: { directories: ['./fabric/Sales-Dev/', 'fabric\\Sales-Models', 'fabric/Sales-Dev', ' . '] } }).dirs, ['fabric/Sales-Models', 'fabric/Sales-Dev', '.']);
  for (const directories of ['fabric/Sales-Dev', [1], [null], ['../other'], ['fabric/../x'], ['/fabric'], ['C:/repo/fabric'], ['fabric//x'], { dir: 'fabric' }]) {
    assert.deepEqual(fabricSyncOf({ fabric: { directories } }), { source: 'platform', dirs: null, invalid: true }, JSON.stringify(directories));
  }
  const dirs = fabricSyncOf({ fabric: { directories: ['fabric', 'fabric/Sales-Dev'] } }).dirs;
  assert.equal(syncedDirOf('FABRIC/sales-dev/Sales.Report', dirs), 'fabric/Sales-Dev', 'case-insensitive; the nearer directory wins');
  assert.equal(syncedDirOf('fabric/Sales-Models/Finance.SemanticModel', dirs), 'fabric');
  assert.equal(syncedDirOf('fabric-old/Sales.Report', dirs), null, 'a name that starts the same is no parent directory');
  assert.equal(syncedDirOf('powerbi/Sales.Report', dirs), null);
  assert.equal(syncedDirOf('powerbi/Sales.Report', ['.']), '.');
  assert.equal(syncedDirOf('fabric/Sales-Dev/Sales.Report', []), null);
  // The inventory carries the source; with a list, `fabric` is every item folder under it, .platform or not.
  const dir = repo({ ...ITEMS, ...REPORT(`${WS}/Bare.Report`, BY_PATH, false), ...REPORT('powerbi/Saved.Report', BY_PATH) });
  try {
    assert.deepEqual(findPbipItems(dir, { fabric: { directories: [WS] } }).fabric.sort(), [`${WS}/Bare.Report`, `${WS}/Invoices.PaginatedReport`, `${WS}/Sales.Report`, `${WS}/Sales.SemanticModel`]);
    assert.deepEqual(findPbipItems(dir, {}).fabric.sort(), [`${WS}/Invoices.PaginatedReport`, `${WS}/Sales.Report`, `${WS}/Sales.SemanticModel`, 'powerbi/Saved.Report']);
    assert.equal(findPbipItems(dir, {}).fabricSync.source, 'platform');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('validator with fabric.directories: a live connection to Analysis Services warns inside a listed directory, .platform or not; a Desktop-saved folder outside it is silent', () => {
  const dir = repo({
    ...ITEMS,
    ...CONFIG([WS]),
    ...REPORT(`${WS}/AS.Report`, LIVE(AS_LIVE)),
    ...REPORT(`${WS}/Finance/Bare.Report`, LIVE(AS_LIVE), false), // a workspace subfolder, no .platform yet
    ...REPORT('powerbi/Saved.Report', LIVE(AS_LIVE)), // Desktop wrote .platform; no workspace syncs powerbi/
    ...REPORT('fabric/Other/Live.Report', LIVE(AS_LIVE)), // .platform, in a directory nobody listed
    'powerbi/Ref.SemanticModel/.platform': PLATFORM('SemanticModel', 'Ref'),
    'powerbi/Ref.SemanticModel/definition.pbism': '{"version":"4.2","settings":{}}\n',
    'powerbi/Ref.SemanticModel/modelReference.json': '{"connectionType":"analysisServicesDatabaseLive"}\n',
    [`${WS}/Ref.SemanticModel/definition.pbism`]: '{"version":"4.2","settings":{}}\n',
    [`${WS}/Ref.SemanticModel/modelReference.json`]: '{"connectionType":"analysisServicesDatabaseLive"}\n',
  });
  try {
    const expected = [`${WS}/AS.Report/definition.pbir`, `${WS}/Finance/Bare.Report/definition.pbir`, `${WS}/Ref.SemanticModel/modelReference.json`];
    for (const args of [['--json'], ['--changed', '--json']]) {
      const live = warnings(scan(dir, args), /^Live connection to Analysis Services/);
      assert.deepEqual(live.map((i) => i.file).sort(), expected, `${args.join(' ')}: ${JSON.stringify(live)}`);
      for (const w of live) {
        assert.match(w.message, /inside fabric\/Sales-Dev, which a Fabric workspace syncs: Git integration ignores the item \(Learn, checked 2026-10-17.*Move it to a directory no workspace syncs and publish it from Desktop \(docs\/harness\/fabric-git\.md\)\. /);
        assert.match(w.message, LISTED);
        assert.doesNotMatch(w.message, /holds \.platform|reminder/);
      }
    }
    // The same files without the list: .platform decides again, and the warning says so.
    fs.writeFileSync(path.join(dir, 'hardening', 'harness.config.json'), '{}\n');
    const live = warnings(scan(dir), /^Live connection to Analysis Services/);
    assert.deepEqual(live.map((i) => i.file).sort(), ['fabric/Other/Live.Report/definition.pbir', `${WS}/AS.Report/definition.pbir`, 'powerbi/Ref.SemanticModel/modelReference.json', 'powerbi/Saved.Report/definition.pbir']);
    for (const w of live) assert.match(w.message, /in a folder that holds \.platform\..*Synced directories: \.platform, because fabric\.directories in hardening\/harness\.config\.json records none;/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('validator CLI full scan with fabric.directories: a same-named item outside the listed directories is a copy, .platform or not', () => {
  const own = (type, name, id) => PLATFORM(type, name).replace('00000000-0000-0000-0000-000000000001', id);
  const dir = repo({
    ...ITEMS,
    ...CONFIG([WS, 'fabric/Copy']),
    // A Desktop-saved copy under powerbi/ with its own .platform and logicalId: silent without the list.
    ...REPORT('powerbi/Sales.Report', BY_PATH, false),
    'powerbi/Sales.Report/.platform': own('Report', 'Sales', '00000000-0000-0000-0000-000000000009'),
    'powerbi/Sales.SemanticModel/.platform': own('SemanticModel', 'Sales', '00000000-0000-0000-0000-000000000008'),
    'powerbi/Sales.SemanticModel/definition.pbism': '{"version":"4.2","settings":{}}\n',
    'powerbi/Sales.SemanticModel/definition/model.tmdl': 'model Model\n',
    // A raw copy with the same logicalId in a second listed directory.
    ...REPORT('fabric/Copy/Sales.Report', BY_PATH),
    'fabric/Copy/Sales.SemanticModel/.platform': PLATFORM('SemanticModel', 'Sales'),
    'fabric/Copy/Sales.SemanticModel/definition.pbism': '{"version":"4.2","settings":{}}\n',
    'fabric/Copy/Sales.SemanticModel/definition/model.tmdl': 'model Model\n',
    // A paginated report folder with .platform in a directory nobody listed, and the pre-upload copy.
    'fabric/Other/Invoices.PaginatedReport/.platform': own('PaginatedReport', 'Invoices', '00000000-0000-0000-0000-000000000007'),
    'fabric/Other/Invoices.PaginatedReport/Invoices.rdl': RDL,
    'paginated/Invoices.rdl': RDL,
  });
  try {
    const copies = warnings(scan(dir), COPY_RE);
    const byFile = Object.fromEntries(copies.map((i) => [i.file, i.message]));
    assert.deepEqual(Object.keys(byFile).sort(), ['fabric/Copy/Sales.Report', 'fabric/Copy/Sales.SemanticModel', 'fabric/Other/Invoices.PaginatedReport/Invoices.rdl', 'paginated/Invoices.rdl', 'powerbi/Sales.Report', 'powerbi/Sales.SemanticModel'], JSON.stringify(copies));
    assert.equal(copies.length, 6, JSON.stringify(copies));
    assert.match(byFile['powerbi/Sales.Report'], /^Second copy of fabric\/Copy\/Sales\.Report, fabric\/Sales-Dev\/Sales\.Report, which lies in a directory a Fabric workspace syncs\. One item lives in one place: remove this copy with the user's approval/);
    assert.match(byFile['paginated/Invoices.rdl'], /^Second copy of fabric\/Sales-Dev\/Invoices\.PaginatedReport\/Invoices\.rdl, which a Fabric workspace syncs: the pre-upload copy of a paginated report/);
    assert.match(byFile['fabric/Copy/Sales.Report'], /^Same name and the same \.platform logicalId as fabric\/Sales-Dev\/Sales\.Report: two copies of one item/);
    for (const message of Object.values(byFile)) assert.match(message, LISTED);
    // Without the list the Desktop-saved copy (another logicalId) and the folder in fabric/Other are synced items again.
    fs.writeFileSync(path.join(dir, 'hardening', 'harness.config.json'), '{}\n');
    const before = warnings(scan(dir), COPY_RE).map((i) => i.file);
    for (const file of ['powerbi/Sales.Report', 'powerbi/Sales.SemanticModel', 'fabric/Other/Invoices.PaginatedReport/Invoices.rdl']) assert.ok(!before.includes(file), file);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// F1-124: a copy is found by its .platform logicalId, not only by its folder name. SalesCopy.Report beside Sales.Report with
// the same logicalId is a raw copy that was renamed. PLATFORM gives every item of ITEMS one logicalId, so a report, a model
// and a paginated report that share it must stay silent: they are no copies of one item.
const PLATFORM_ID = (type, name, id) => PLATFORM(type, name).replace('00000000-0000-0000-0000-000000000001', id);
const RENAMED_RE = /^Same \.platform logicalId as /;
const ANY_COPY_RE = /^Same (?:name and the same )?\.platform logicalId as /;
const pair = (a, b) => [a, b].sort().join(' + ');
/** The two folders a copy warning names (its file and the folder after "logicalId as"), whichever side carries the warning. */
const pairOf = (w) => pair(w.file, /logicalId as (.+?): two copies of one item/.exec(w.message)[1]);

test('validator CLI full scan: a renamed copy with the same .platform logicalId is one warning naming both folders; another logicalId, another kind and an unsynced folder are silent', () => {
  const dir = repo({
    ...ITEMS, // model, report and paginated report share one logicalId: different kinds are no copies
    ...CONFIG([WS]),
    ...REPORT(`${WS}/SalesCopy.Report`, BY_PATH), // Sales.Report copied and renamed: the same logicalId
    ...REPORT(`${WS}/Budget.Report`, BY_PATH, false), // another item: its own logicalId
    [`${WS}/Budget.Report/.platform`]: PLATFORM_ID('Report', 'Budget', '00000000-0000-0000-0000-000000000002'),
    ...REPORT(`${WS}/NoId.Report`, BY_PATH, false), // a .platform without a logicalId: nothing to compare
    [`${WS}/NoId.Report/.platform`]: `${JSON.stringify({ metadata: { type: 'Report', displayName: 'NoId' } })}\n`,
    // The same logicalId, but no workspace syncs fabric/Other while fabric.directories lists only WS.
    ...REPORT('fabric/Other/Sales2.Report', `${JSON.stringify({ version: '4.0', datasetReference: { byPath: { path: '../Other.SemanticModel' } } })}\n`),
    'fabric/Other/Other.SemanticModel/definition.pbism': '{"version":"4.2","settings":{}}\n',
    'fabric/Other/Other.SemanticModel/definition/model.tmdl': 'model Model\n',
  });
  try {
    const renamed = warnings(scan(dir), RENAMED_RE);
    assert.deepEqual(renamed.map(pairOf), [pair(`${WS}/Sales.Report`, `${WS}/SalesCopy.Report`)], JSON.stringify(renamed));
    assert.match(renamed[0].message, /^Same \.platform logicalId as [^:]+: two copies of one item under different names\. One item lives in one place: remove the copy \(with the user's approval\) or make it a new item with a new logicalId and displayName \(docs\/harness\/fabric-git\.md\)\. /);
    assert.match(renamed[0].message, LISTED);
    assert.equal(renamed[0].level, 'warn');
    assert.deepEqual(warnings(scan(dir), COPY_RE), [], 'no pair of these has the same name');
    // --changed has no inventory, so no copy check, as for the same-named copies.
    assert.deepEqual(warnings(scan(dir, ['--changed', '--json']), ANY_COPY_RE), []);
    // Without the list .platform decides: fabric/Other counts now, and every warning says where the directories came from.
    fs.writeFileSync(path.join(dir, 'hardening', 'harness.config.json'), '{}\n');
    const byPlatform = warnings(scan(dir), RENAMED_RE);
    assert.deepEqual(byPlatform.map(pairOf).sort(), [
      pair(`${WS}/Sales.Report`, `${WS}/SalesCopy.Report`),
      pair(`${WS}/Sales.Report`, 'fabric/Other/Sales2.Report'),
      pair(`${WS}/SalesCopy.Report`, 'fabric/Other/Sales2.Report'),
    ].sort(), JSON.stringify(byPlatform));
    for (const w of byPlatform) assert.match(w.message, /Synced directories: \.platform, because fabric\.directories in hardening\/harness\.config\.json records none;/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('validator CLI full scan with two listed directories: renamed copies of a report, a model and a paginated report are found, once each', () => {
  const dir = repo({
    ...ITEMS,
    ...CONFIG([WS, 'fabric/Copy']),
    // Sales-Dev copied to fabric/Copy with every folder renamed and the .platform files left as they were.
    ...REPORT('fabric/Copy/SalesCopy.Report', `${JSON.stringify({ version: '4.0', datasetReference: { byPath: { path: '../SalesCopy.SemanticModel' } } })}\n`),
    'fabric/Copy/SalesCopy.SemanticModel/.platform': PLATFORM('SemanticModel', 'Sales'),
    'fabric/Copy/SalesCopy.SemanticModel/definition.pbism': '{"version":"4.2","settings":{}}\n',
    'fabric/Copy/SalesCopy.SemanticModel/definition/model.tmdl': 'model Model\n',
    'fabric/Copy/InvoicesCopy.PaginatedReport/.platform': PLATFORM('PaginatedReport', 'Invoices'),
    'fabric/Copy/InvoicesCopy.PaginatedReport/InvoicesCopy.rdl': RDL,
  });
  try {
    const renamed = warnings(scan(dir), RENAMED_RE);
    assert.deepEqual(renamed.map(pairOf).sort(), [
      pair('fabric/Copy/InvoicesCopy.PaginatedReport', `${WS}/Invoices.PaginatedReport`),
      pair('fabric/Copy/SalesCopy.Report', `${WS}/Sales.Report`),
      pair('fabric/Copy/SalesCopy.SemanticModel', `${WS}/Sales.SemanticModel`),
    ].sort(), `one pair per kind, none across kinds: ${JSON.stringify(renamed)}`);
    for (const w of renamed) assert.match(w.message, LISTED);
    assert.deepEqual(warnings(scan(dir), COPY_RE), []);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('validator CLI full scan: a same-named pair keeps its own warning and a renamed one gets its own; no pair is reported twice and the logicalId compares without case', () => {
  const ID = 'c0ffee00-0000-0000-0000-00000000000a';
  const dir = repo({
    ...ITEMS,
    [`${WS}/Sales.Report/.platform`]: PLATFORM_ID('Report', 'Sales', ID),
    ...CONFIG([WS, 'fabric/Copy']),
    ...REPORT(`${WS}/SalesCopy.Report`, BY_PATH, false),
    [`${WS}/SalesCopy.Report/.platform`]: PLATFORM_ID('Report', 'SalesCopy', ID.toUpperCase()), // renamed copy, upper-case GUID
    // The same name in the second directory, the same logicalId: the old warning, once.
    ...REPORT('fabric/Copy/SalesCopy.Report', BY_PATH, false),
    'fabric/Copy/SalesCopy.Report/.platform': PLATFORM_ID('Report', 'SalesCopy', ID),
    'fabric/Copy/Sales.SemanticModel/.platform': PLATFORM_ID('SemanticModel', 'Sales', '00000000-0000-0000-0000-000000000003'), // same name as a synced model, its own logicalId: a second item
    'fabric/Copy/Sales.SemanticModel/definition.pbism': '{"version":"4.2","settings":{}}\n',
    'fabric/Copy/Sales.SemanticModel/definition/model.tmdl': 'model Model\n',
    // The same paginated report synced by a second workspace stays silent, as in the full-scan test without fabric.directories.
    'fabric/Copy/Invoices.PaginatedReport/.platform': PLATFORM('PaginatedReport', 'Invoices'),
    'fabric/Copy/Invoices.PaginatedReport/Invoices.rdl': RDL,
  });
  try {
    const all = warnings(scan(dir), ANY_COPY_RE);
    assert.deepEqual(all.map(pairOf).sort(), [
      pair(`${WS}/Sales.Report`, `${WS}/SalesCopy.Report`),
      pair(`${WS}/Sales.Report`, 'fabric/Copy/SalesCopy.Report'),
      pair(`${WS}/SalesCopy.Report`, 'fabric/Copy/SalesCopy.Report'),
    ].sort(), JSON.stringify(all));
    const sameName = all.filter((w) => /^Same name and the same \.platform logicalId as /.test(w.message));
    assert.deepEqual(sameName.map(pairOf), [pair(`${WS}/SalesCopy.Report`, 'fabric/Copy/SalesCopy.Report')], 'the same-named pair has its own message, once');
    assert.match(sameName[0].message, /^Same name and the same \.platform logicalId as [^:]+: two copies of one item\. One item lives in one place: remove the copy/);
    assert.equal(warnings(all, RENAMED_RE).length, 2, 'the renamed pairs have the new message');
    assert.equal(new Set(all.map(pairOf)).size, all.length, 'no pair twice');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('fabric.directories []: nothing is synced, so .platform raises no Fabric Git warning and the banner says so', () => {
  const dir = repo({
    ...ITEMS,
    ...CONFIG([]),
    ...REPORT('powerbi/Saved.Report', LIVE(AS_LIVE)),
    ...REPORT('powerbi/Sales.Report', LIVE(AS_LIVE), false),
    'paginated/Invoices.rdl': RDL,
  });
  try {
    assert.deepEqual(warnings(scan(dir), /^Live connection to Analysis Services|^Second copy of|^Same name and the same/), []);
    const lines = banner(dir);
    hasLine(lines, /^- Fabric Git: (?=.*\bfabric\.directories\b)(?=.*\bempty\b)/);
    assert.ok(!lines.some((l) => l.startsWith('- Fabric Git-connected directory:')), lines.join('\n'));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('a fabric.directories value that is no list of directories falls back to .platform, and the warnings and the banner say so', () => {
  const dir = repo({ ...ITEMS, ...CONFIG(WS), ...REPORT('powerbi/Saved.Report', LIVE(AS_LIVE)) });
  try {
    const live = warnings(scan(dir), /^Live connection to Analysis Services/);
    assert.deepEqual(live.map((i) => i.file), ['powerbi/Saved.Report/definition.pbir']);
    assert.match(live[0].message, /in a folder that holds \.platform\..*Synced directories: \.platform, because fabric\.directories in hardening\/harness\.config\.json is not a list of project-relative directories;/);
    const lines = banner(dir);
    hasLine(lines, /^- Fabric Git: (?=.*\bfabric\.directories\b)(?=.*\bnot a list\b)(?=.*\.platform)(?=.*docs\/harness\/fabric-git\.md)/);
    hasLine(lines, fabricDirLine(WS, 3, 'invalid'));
    hasLine(lines, fabricDirLine('powerbi', 1, 'invalid'));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('session start with fabric.directories: one line per listed directory with its item count or "not found"; .platform elsewhere is not listed', () => {
  const dir = repo({
    ...ITEMS,
    ...CONFIG([WS, 'fabric/Sales-Models']),
    [`${WS}/Finance/Q1.Report/definition.pbir`]: '{}\n', // a workspace subfolder, no .platform yet: counted
    'powerbi/Local.Report/.platform': PLATFORM('Report', 'Local'), // a Desktop save: not listed
    'powerbi/Local.Report/definition.pbir': '{}\n',
  });
  try {
    const lines = banner(dir);
    const fabricLines = lines.filter((l) => l.startsWith('- Fabric Git'));
    assert.equal(fabricLines.length, 2, lines.join('\n'));
    assert.match(fabricLines[0], fabricDirLine(WS, 4, 'config'));
    assert.match(fabricLines[1], fabricDirLine('fabric/Sales-Models', 'not found in the repository', 'config'));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
