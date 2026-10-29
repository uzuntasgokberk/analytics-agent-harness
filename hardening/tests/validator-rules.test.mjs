// Validator rules whose tests went with references.test.mjs, rdl.test.mjs, post-tool.test.mjs and
// validator-and-git.test.mjs in bfe8af5 (follow-up audit, round 2: F2-36 report fields, F2-37 RDL rules, F2-38 fail-safe
// errors, F2-40 TMDL warnings). In process, no git. Fake credentials and user paths are joined at run time.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { checkRdl, pbirFieldRefs, readModelFields, validateArtifacts, validateFileText, validateFiles, walkFiles } from '../hooks/lib/validators.mjs';

const T = '\t';

function tempProject(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-validator-rules-'));
  for (const [rel, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), content);
  }
  return dir;
}

function withProject(files, fn) {
  const dir = tempProject(files);
  try {
    return fn(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

// ---------------------------------------------------------------- F2-36: report fields against the local model

const SALES_TMDL = [
  'table Sales', '',
  `${T}measure 'Total Sales' = SUM ( Sales[Amount] )`, `${T}${T}formatString: 0`, '',
  `${T}column Amount`, `${T}${T}dataType: int64`, `${T}${T}sourceColumn: Amount`, '',
].join('\n');
const field = (kind, entity, property) => ({ [kind]: { Expression: { SourceRef: { Entity: entity } }, Property: property } });
const visualJson = (fields, extra = {}) => JSON.stringify({
  name: 'v1',
  visual: { visualType: 'card', query: { queryState: { Values: { projections: fields.map((f) => ({ field: f })) } } } },
  ...extra,
});
const VISUAL = 'R.Report/definition/pages/p1/visuals/v1/visual.json';

/** A semantic model with table Sales (measure 'Total Sales', column Amount) and a report bound to it by path. */
function boundReport(visual, extra = {}) {
  return {
    'M.SemanticModel/definition.pbism': '{}',
    'M.SemanticModel/definition/model.tmdl': 'model Model\n',
    'M.SemanticModel/definition/tables/Sales.tmdl': SALES_TMDL,
    'R.Report/definition.pbir': JSON.stringify({ version: '4.0', datasetReference: { byPath: { path: '../M.SemanticModel' } } }),
    'R.Report/definition/version.json': '{}',
    'R.Report/definition/report.json': '{}',
    'R.Report/definition/pages/p1/page.json': '{}',
    [VISUAL]: visual,
    ...extra,
  };
}
const ITEMS = { models: ['M.SemanticModel'], reports: ['R.Report'] };
const fieldIssues = (issues) => issues.filter((i) => /^(?:Uses|Filters on) /.test(i.message));

test('report fields: existing fields pass in any letter case; a missing field or table is an error on the visual naming each', () => {
  withProject(boundReport(visualJson([field('Measure', 'Sales', 'Total Sales'), field('Column', 'sales', 'amount')])), (dir) => {
    assert.deepEqual(validateArtifacts(dir, ITEMS).filter((i) => i.level === 'error'), []);
  });
  withProject(boundReport(visualJson([field('Column', 'Sales', 'Amout'), field('Column', 'Region', 'Name')])), (dir) => {
    const issues = fieldIssues(validateArtifacts(dir, ITEMS));
    assert.equal(issues.length, 1, JSON.stringify(issues));
    assert.equal(issues[0].level, 'error');
    assert.equal(issues[0].file, VISUAL);
    assert.match(issues[0].message, /^Uses .*'Sales'\[Amout\]/);
    assert.match(issues[0].message, /table 'Region'/);
    assert.match(issues[0].message, /\(\.\.\/M\.SemanticModel\)/, 'the message names the bound model');
  });
});

test('report fields: a stale filter warns, a field used and filtered is one error; aliases, variations and report extension measures resolve', () => {
  const reportFilter = {
    filterConfig: {
      filters: [{
        name: 'f1',
        field: field('Column', 'Sales', 'Amount'),
        filter: { Version: 2, From: [{ Name: 's', Entity: 'Sales', Type: 0 }], Where: [{ Condition: { Comparison: { ComparisonKind: 1, Left: { Column: { Expression: { SourceRef: { Source: 's' } }, Property: 'Discount' } }, Right: { Literal: { Value: '0D' } } } } }] },
      }],
    },
  };
  const variation = { HierarchyLevel: { Expression: { Hierarchy: { Expression: { PropertyVariationSource: { Expression: { SourceRef: { Entity: 'Sales' } }, Name: 'Variation', Property: 'Amount' } }, Hierarchy: 'Date Hierarchy' } }, Level: 'Year' } };
  const extension = { Measure: { Expression: { SourceRef: { Schema: 'extension', Entity: 'Sales' } }, Property: 'Share' } };
  const visual = visualJson([variation, extension, field('Column', 'Sales', 'Gone')], { filterConfig: { filters: [{ name: 'g', field: field('Column', 'Sales', 'Gone') }] } });
  withProject(boundReport(visual, {
    'R.Report/definition/report.json': JSON.stringify(reportFilter),
    'R.Report/definition/reportExtensions.json': JSON.stringify({ name: 'extension', entities: [{ name: 'Sales', measures: [{ name: 'Share', dataType: 'Double', expression: 'DIVIDE ( 1, 2 )' }] }] }),
  }), (dir) => {
    const issues = fieldIssues(validateArtifacts(dir, ITEMS));
    const stale = issues.filter((i) => i.file === 'R.Report/definition/report.json');
    assert.equal(stale.length, 1, JSON.stringify(issues));
    assert.equal(stale[0].level, 'warn');
    assert.match(stale[0].message, /^Filters on 'Sales'\[Discount\]/);
    const onVisual = issues.filter((i) => i.file === VISUAL);
    assert.deepEqual(onVisual.map((i) => i.level), ['error'], 'a field used and filtered is reported once, as the error');
    assert.match(onVisual[0].message, /^Uses 'Sales'\[Gone\],/);
    assert.doesNotMatch(JSON.stringify(issues), /Date Hierarchy|Share|Amount/);
  });
});

test('report fields: a report on a published model (byConnection) or a model without TMDL tables is not checked', () => {
  const byConnection = JSON.stringify({ version: '4.0', datasetReference: { byConnection: { connectionString: 'Data Source="powerbi://api.powerbi.com/v1.0/myorg/Demo";initial catalog=Model' } } });
  withProject(boundReport(visualJson([field('Measure', 'Sales', 'Anything')]), { 'R.Report/definition.pbir': byConnection }), (dir) => {
    assert.deepEqual(fieldIssues(validateArtifacts(dir, ITEMS)), []);
    assert.equal(readModelFields(path.join(dir, 'Missing.SemanticModel')), null);
  });
});

test('pbirFieldRefs resolves aliases per query scope and marks references under filterConfig', () => {
  const refs = pbirFieldRefs({
    a: { From: [{ Name: 'x', Entity: 'Sales' }], Where: [{ Column: { Expression: { SourceRef: { Source: 'x' } }, Property: 'Amount' } }] },
    filterConfig: { b: { From: [{ Name: 'x', Entity: 'Date' }], Where: [{ Column: { Expression: { SourceRef: { Source: 'x' } }, Property: 'Year' } }] } },
    c: { Column: { Expression: { SourceRef: { Source: 'unknown' } }, Property: 'Ignored' } },
    d: { Hierarchy: { Expression: { SourceRef: { Entity: 'Date' } }, Hierarchy: 'Calendar' } },
  });
  assert.deepEqual(refs, [
    { entity: 'Sales', field: 'Amount', inFilter: false },
    { entity: 'Date', field: 'Year', inFilter: true },
    { entity: 'Date', field: 'Calendar', inFilter: false },
  ]);
});

// ---------------------------------------------------------------- F2-37: RDL rules

const textbox = (name, value) => `<Textbox Name="${name}"><CanGrow>true</CanGrow><KeepTogether>true</KeepTogether><Paragraphs><Paragraph><TextRuns><TextRun><Value>${value}</Value><Style /></TextRun></TextRuns><Style /></Paragraph></Paragraphs><Style /></Textbox>`;
const cell = (name, value) => `<TablixCell><CellContents>${textbox(name, value)}</CellContents></TablixCell>`;

/** A small, valid paginated report: one SQL data source, one dataset, one parameter, a two-column detail table. */
function report({
  tablixName = 'tblOrders', dataSetName = 'Orders', connect = 'Data Source=sql.contoso.local;Initial Catalog=SalesDW',
  bodyWidth = '7cm', pageWidth = '21cm', extraColumn = false, layoutCells = true, field: fieldName = 'Amount', param = 'Start',
  dataSource = '<ConnectionProperties><DataProvider>SQL</DataProvider><ConnectString>CONNECT</ConnectString></ConnectionProperties>',
  extra = '', extraParameter = '', extraDataSource = '',
} = {}) {
  const columns = `<TablixColumn><Width>3cm</Width></TablixColumn><TablixColumn><Width>4cm</Width></TablixColumn>${extraColumn ? '<TablixColumn><Width>2cm</Width></TablixColumn>' : ''}`;
  return `<?xml version="1.0" encoding="utf-8"?>
<Report xmlns="http://schemas.microsoft.com/sqlserver/reporting/2016/01/reportdefinition" xmlns:rd="http://schemas.microsoft.com/SQLServer/reporting/reportdesigner">
  <DataSources><DataSource Name="Warehouse">${dataSource.replace('CONNECT', connect)}</DataSource>${extraDataSource}</DataSources>
  <DataSets><DataSet Name="${dataSetName}"><Query><DataSourceName>Warehouse</DataSourceName><QueryParameters><QueryParameter Name="@Start"><Value>=Parameters!${param}.Value</Value></QueryParameter></QueryParameters><CommandText>select OrderDate, Amount from rpt.Orders where OrderDate &gt;= @Start</CommandText></Query>
    <Fields><Field Name="OrderDate"><DataField>OrderDate</DataField></Field><Field Name="Amount"><DataField>Amount</DataField></Field></Fields></DataSet></DataSets>
  <ReportSections><ReportSection><Body><ReportItems>
    <Tablix Name="${tablixName}"><TablixBody><TablixColumns>${columns}</TablixColumns><TablixRows>
      <TablixRow><Height>0.6cm</Height><TablixCells>${cell('hdrDate', 'Date')}${cell('hdrAmount', 'Amount')}</TablixCells></TablixRow>
      <TablixRow><Height>0.6cm</Height><TablixCells>${cell('OrderDate', '=Fields!OrderDate.Value')}${cell('Amount', `=Fields!${fieldName}.Value`)}</TablixCells></TablixRow>
    </TablixRows></TablixBody>
    <TablixColumnHierarchy><TablixMembers><TablixMember /><TablixMember /></TablixMembers></TablixColumnHierarchy>
    <TablixRowHierarchy><TablixMembers><TablixMember><KeepWithGroup>After</KeepWithGroup><RepeatOnNewPage>true</RepeatOnNewPage></TablixMember><TablixMember><Group Name="Details" /></TablixMember></TablixMembers></TablixRowHierarchy>
    <DataSetName>${dataSetName}</DataSetName><Top>0cm</Top><Left>0cm</Left><Height>1.2cm</Height><Width>7cm</Width></Tablix>
    ${extra}
  </ReportItems><Height>2cm</Height><Style /></Body><Width>${bodyWidth}</Width>
  <Page><PageHeight>29.7cm</PageHeight><PageWidth>${pageWidth}</PageWidth><LeftMargin>2cm</LeftMargin><RightMargin>2cm</RightMargin><Style /></Page></ReportSection></ReportSections>
  <ReportParameters><ReportParameter Name="Start"><DataType>DateTime</DataType><Prompt>Start</Prompt></ReportParameter>${layoutCells ? '' : '<ReportParameter Name="End"><DataType>DateTime</DataType><Prompt>End</Prompt></ReportParameter>'}${extraParameter}</ReportParameters>
  <ReportParametersLayout><GridLayoutDefinition><NumberOfColumns>2</NumberOfColumns><NumberOfRows>1</NumberOfRows><CellDefinitions><CellDefinition><ColumnIndex>0</ColumnIndex><RowIndex>0</RowIndex><ParameterName>Start</ParameterName></CellDefinition></CellDefinitions></GridLayoutDefinition></ReportParametersLayout>
  <rd:ReportUnitType>Cm</rd:ReportUnitType>
</Report>
`;
}
const rdlErrors = (text) => checkRdl('paginated/Orders.rdl', text).filter((i) => i.level === 'error');
const rdlWarnings = (text) => checkRdl('paginated/Orders.rdl', text).filter((i) => i.level === 'warn');
const messages = (issues) => issues.map((i) => i.message).join('\n');

test('RDL: the valid report passes, with or without a byte order mark', () => {
  assert.deepEqual(checkRdl('paginated/Orders.rdl', report()), []);
  assert.deepEqual(checkRdl('paginated/Orders.rdl', `﻿${report()}`), []);
});

test('RDL: a data region named like its dataset breaks the shared namespace', () => {
  const e = rdlErrors(report({ tablixName: 'Orders' }));
  assert.equal(e.length, 1, messages(e));
  assert.match(e[0].message, /share one namespace; duplicated: orders\b/);
});

test('RDL: report item, parameter and data source names must be unique', () => {
  const items = rdlErrors(report({ extra: textbox('OrderDate', 'x') }));
  assert.equal(items.length, 1, messages(items));
  assert.match(items[0].message, /^Report item names must be unique; duplicated: orderdate\b/);
  const params = rdlErrors(report({ extraParameter: '<ReportParameter Name="start"><DataType>String</DataType></ReportParameter>' }));
  assert.match(messages(params), /^Parameter names must be unique; duplicated: start\b/m);
  const sources = rdlErrors(report({ extraDataSource: '<DataSource Name="Warehouse"><DataSourceReference>Shared</DataSourceReference></DataSource>' }));
  assert.match(messages(sources), /^Data source names must be unique; duplicated: warehouse\b/m);
});

test('RDL: Fields!, Parameters!, DataSetName and DataSourceName references that nothing defines are errors', () => {
  for (const [text, expected] of [
    [report({ field: 'Discount' }), /^Fields! references that nothing defines: Discount\b/],
    [report({ param: 'From' }), /^Parameters! references that nothing defines: From\b/],
    [report().replace('<DataSetName>Orders</DataSetName>', '<DataSetName>Sales</DataSetName>'), /^DataSetName references that nothing defines: Sales\b/],
    [report().replace('<DataSourceName>Warehouse</DataSourceName>', '<DataSourceName>Gone</DataSourceName>'), /^DataSourceName references that nothing defines: Gone\b/],
  ]) {
    const e = rdlErrors(text);
    assert.equal(e.length, 1, messages(e));
    assert.match(e[0].message, expected);
  }
});

test('RDL: every report parameter needs a cell in ReportParametersLayout', () => {
  const e = rdlErrors(report({ layoutCells: false }));
  assert.equal(e.length, 1, messages(e));
  assert.match(e[0].message, /^ReportParametersLayout needs one CellDefinition per parameter \(1 cells, 2 parameters; missing: end\)/);
});

test('RDL: tablix columns, leaf column members and cells per row must match', () => {
  const e = rdlErrors(report({ extraColumn: true }));
  assert.equal(e.length, 1, messages(e));
  assert.match(e[0].message, /^Tablix tblOrders: 3 TablixColumn, 2 leaf column members, 2 row\(s\) with another number of cells/);
});

test('RDL: a password or a placeholder id in a ConnectString is an error', () => {
  const credential = ['Pass', 'word=', 'Hunt', 'er2', 'Xyz'].join('');
  const withSecret = rdlErrors(report({ connect: `Data Source=sql.contoso.local;Initial Catalog=SalesDW;User ID=report;${credential}` }));
  assert.match(messages(withSecret), /^A password is written in a ConnectString/m);
  assert.ok(!JSON.stringify(withSecret).includes(credential), 'the value is never echoed');
  for (const connect of [
    'Data Source=powerbi://api.powerbi.com/v1.0/myorg/Sales;Initial Catalog=00000000-0000-0000-0000-000000000000',
    'Data Source=powerbi://api.powerbi.com/v1.0/myorg/WORKSPACE_NAME;Initial Catalog=MODEL_NAME',
  ]) {
    const e = rdlErrors(report({ connect }));
    assert.equal(e.length, 1, messages(e));
    assert.match(e[0].message, /^The ConnectString holds a placeholder id or value/);
  }
  // A shared data source (.rds) gets the connection checks too.
  const rds = `<?xml version="1.0" encoding="utf-8"?>\n<RptDataSource Name="Warehouse"><ConnectionProperties><Extension>SQL</Extension><ConnectString>Data Source=.;${credential}</ConnectString></ConnectionProperties></RptDataSource>\n`;
  assert.match(messages(checkRdl('paginated/Warehouse.rds', rds)), /^A password is written in a ConnectString/m);
});

test('RDL: page overflow, shared items and custom assemblies are warnings', () => {
  assert.match(messages(rdlWarnings(report({ bodyWidth: '30cm' }))), /^Body 30\.0 cm \+ margins 4\.0 cm is wider than the page \(21\.0 cm\)/m);
  assert.deepEqual(rdlWarnings(report({ bodyWidth: '30cm', pageWidth: '35cm' })), []);
  const shared = rdlWarnings(report({ dataSource: '<DataSourceReference>Warehouse</DataSourceReference>' }));
  assert.match(messages(shared), /^Shared data source or shared dataset reference: SSRS only/m);
  const code = rdlWarnings(report().replace('<rd:ReportUnitType>', '<CodeModules><CodeModule>Contoso.Rules</CodeModule></CodeModules><rd:ReportUnitType>'));
  assert.match(messages(code), /^Custom assemblies \(CodeModules\) are not supported in the Power BI service/m);
});

// ---------------------------------------------------------------- F2-38: fail-safe errors

const MiB = 1024 * 1024;

test('fail-safe: a file the validator cannot read is an error and not counted as checked', () => {
  withProject({ 'docs/a.md': '# A\n' }, (dir) => {
    const throws = () => { throw new Error('read failed'); };
    for (const allowMissing of [false, true]) {
      const r = validateFiles(dir, {}, ['docs/a.md'], { readText: throws, allowMissing });
      assert.deepEqual(r.files, [], `allowMissing ${allowMissing}`);
      assert.deepEqual(r.issues.map((i) => [i.level, i.file, i.message]), [['error', 'docs/a.md', 'Cannot read file; validation is incomplete.']], `allowMissing ${allowMissing}`);
    }
    // Only a file that is gone (a deletion in --changed or --staged) may be skipped, and only with allowMissing.
    assert.deepEqual(validateFiles(dir, {}, ['docs/gone.md'], { allowMissing: true }).issues, []);
    assert.match(validateFiles(dir, {}, ['docs/gone.md']).issues[0]?.message ?? '', /^Cannot read file/);
  });
});

test('fail-safe: a text file over 5 MiB is an error "was not checked", never a clean pass; 5 MiB itself is checked', () => {
  withProject({ 'docs/a.txt': 'x' }, (dir) => {
    const big = validateFiles(dir, {}, ['docs/a.txt'], { readText: () => 'x'.repeat(5 * MiB + 1) });
    assert.deepEqual(big.files, []);
    assert.equal(big.issues.length, 1, JSON.stringify(big.issues));
    assert.equal(big.issues[0].level, 'error');
    assert.match(big.issues[0].message, /^File was not checked: text validation limit is 5 MiB/);
    const edge = validateFiles(dir, {}, ['docs/a.txt'], { readText: () => 'x'.repeat(5 * MiB) });
    assert.deepEqual([edge.files, edge.issues], [['docs/a.txt'], []]);
  });
});

test('fail-safe: in --staged mode a file in a scan.exclude folder that cannot be read or is too large is an error too', () => {
  const cfg = { scan: { exclude: ['vendor/**'] } };
  withProject({ 'vendor/x.md': '# X\n' }, (dir) => {
    const unreadable = validateFiles(dir, cfg, ['vendor/x.md'], { mode: 'staged', readText: () => { throw new Error('read failed'); } });
    assert.deepEqual(unreadable.issues.map((i) => [i.level, i.file, i.message]), [['error', 'vendor/x.md', 'Cannot read file; validation is incomplete.']]);
    const big = validateFiles(dir, cfg, ['vendor/x.md'], { mode: 'staged', readText: () => 'x'.repeat(5 * MiB + 1) });
    assert.equal(big.issues.length, 1, JSON.stringify(big.issues));
    assert.match(big.issues[0].message, /^File was not checked: text validation limit is 5 MiB/);
    // Outside --staged the excluded file is not read at all.
    assert.deepEqual(validateFiles(dir, cfg, ['vendor/x.md'], { readText: () => { throw new Error('read'); } }).issues, []);
  });
});

test('fail-safe: a walk over the file limit or of a directory it cannot read throws instead of returning a partial list', () => {
  withProject({ 'a.json': '{}', 'b.json': '{}', 'sub/c.json': '{}' }, (dir) => {
    assert.deepEqual(walkFiles(dir, {}, 3), ['a.json', 'b.json', 'sub/c.json']);
    assert.throws(() => walkFiles(dir, {}, 2), /^Error: Scan exceeds 2 files; validation is incomplete/);
    assert.throws(() => walkFiles(path.join(dir, 'missing'), {}), /^Error: Cannot scan directory \. \(ENOENT\)/);
  });
});

// ---------------------------------------------------------------- F2-40: TMDL warnings

const TMDL_FILE = 'M.SemanticModel/definition/tables/Sales.tmdl';
const tmdlWarnings = (text) => validateFileText(TMDL_FILE, text, {}).filter((i) => i.level === 'warn');
const CLEAN_TMDL = [
  'table Sales', `${T}lineageTag: 11111111-0000-4000-8000-000000000000`, '',
  `${T}measure Total =`, `${T}${T}${T}SUM ( Sales[Amount] )`, `${T}${T}formatString: 0`, '',
  `${T}column Amount`, `${T}${T}dataType: int64`, `${T}${T}lineageTag: 11111111-0000-4000-8000-000000000001`, `${T}${T}sourceColumn: Amount`, '',
].join('\n');

test('TMDL: a clean table has no warning (the baseline of the cases below)', () => {
  assert.deepEqual(validateFileText(TMDL_FILE, CLEAN_TMDL, {}), []);
});

test('TMDL: a lineageTag used twice warns on the second line and names the first', () => {
  const text = CLEAN_TMDL.replace('000000000001', '000000000000');
  const w = tmdlWarnings(text);
  assert.equal(w.length, 1, JSON.stringify(w));
  assert.equal(w[0].line, 10);
  assert.match(w[0].message, /^Duplicate lineageTag 11111111-0000-4000-8000-000000000000 \(also line 2\)/);
});

test('TMDL: lines indented with spaces warn once, naming the lines; a fenced expression is left alone', () => {
  const text = CLEAN_TMDL.replace(`${T}column Amount`, '    column Amount').replace(`${T}${T}dataType`, '        dataType');
  const w = tmdlWarnings(text);
  assert.equal(w.length, 1, JSON.stringify(w));
  assert.equal(w[0].line, 8);
  assert.match(w[0].message, /^Line\(s\) 8, 9 start with spaces/);
  const fenced = `${CLEAN_TMDL}${T}measure Fenced = \`\`\`\n    SUM ( Sales[Amount] )\n${T}${T}\`\`\`\n`;
  assert.deepEqual(tmdlWarnings(fenced), []);
});

test('TMDL: a measure whose expression line holds a property warns as an empty expression', () => {
  const text = CLEAN_TMDL.replace(`${T}${T}${T}SUM ( Sales[Amount] )\n`, '');
  const w = tmdlWarnings(text);
  assert.equal(w.length, 1, JSON.stringify(w));
  assert.equal(w[0].line, 4);
  assert.match(w[0].message, /^Measure Total seems to have an empty expression/);
});

test('TMDL: a local user folder in a Power Query source warns (path built at run time)', () => {
  const userPath = ['C:', 'Users', 'someone', 'Documents', 'sales.csv'].join('\\');
  const text = `${CLEAN_TMDL}${T}partition Sales = m\n${T}${T}mode: import\n${T}${T}source = Csv.Document(File.Contents("${userPath}"))\n`;
  const w = tmdlWarnings(text);
  assert.equal(w.length, 1, JSON.stringify(w));
  assert.equal(w[0].line, 14);
  assert.match(w[0].message, /^Hardcoded local user path in Power Query/);
  assert.ok(!w[0].message.includes('someone'), 'the user name is not repeated in the message');
});
