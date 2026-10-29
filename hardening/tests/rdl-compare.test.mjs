// rdl-compare (scripts/rdl-compare.mjs), audit F1-111: the proof that a re-platformed paginated report changed only its
// data layer. DataSources and DataSets (and any --ignore element) are removed from both files, line ends and a byte
// order mark are normalized, and everything else must be identical. Exit 0 same, 1 different, 2 usage or read error.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { compareOutsideDataLayer } from '../scripts/rdl-compare.mjs';

const script = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'scripts', 'rdl-compare.mjs');

/** A small report: data layer, one parameter, a tablix bound to dataset D, a textbox and page setup. */
function rdl({ eol = '\n', bom = false, sources, sets, height = '2in', value = '=Fields!Amount.Value', dataSetName = 'D', prompt = 'Year' } = {}) {
  const lines = [
    '<?xml version="1.0" encoding="utf-8"?>',
    '<Report xmlns="http://schemas.microsoft.com/sqlserver/reporting/2016/01/reportdefinition">',
    sources ?? '  <DataSources><DataSource Name="Old"><ConnectionProperties><DataProvider>SQL</DataProvider><ConnectString>Data Source=old-sql;Initial Catalog=Sales</ConnectString></ConnectionProperties></DataSource></DataSources>',
    sets ?? '  <DataSets><DataSet Name="D"><Query><DataSourceName>Old</DataSourceName><CommandText>select Amount from dbo.Sales</CommandText></Query><Fields><Field Name="Amount"><DataField>Amount</DataField></Field></Fields></DataSet></DataSets>',
    '  <ReportParameters>',
    `    <ReportParameter Name="Year"><DataType>Integer</DataType><Prompt>${prompt}</Prompt></ReportParameter>`,
    '  </ReportParameters>',
    '  <ReportSections><ReportSection>',
    `    <Body><Height>${height}</Height><ReportItems>`,
    `      <Tablix Name="T"><DataSetName>${dataSetName}</DataSetName></Tablix>`,
    `      <Textbox Name="Total"><Paragraphs><Paragraph><TextRuns><TextRun><Value>${value}</Value></TextRun></TextRuns></Paragraph></Paragraphs></Textbox>`,
    '    </ReportItems></Body>',
    '    <Page><PageHeight>11in</PageHeight><PageWidth>8.5in</PageWidth></Page>',
    '  </ReportSection></ReportSections>',
    '</Report>',
    '',
  ];
  return `${bom ? '﻿' : ''}${lines.join(eol)}`;
}
// The re-platformed data layer: a shared semantic model source and a DAX dataset, spread over several lines.
const NEW_SOURCES = '  <DataSources>\n    <DataSource Name="Model"><DataSourceReference>Sales Model</DataSourceReference></DataSource>\n  </DataSources>';
const NEW_SETS = '  <DataSets>\n    <DataSet Name="D">\n      <Query><DataSourceName>Model</DataSourceName><CommandText>EVALUATE SUMMARIZECOLUMNS(\'Sales\'[Amount])</CommandText></Query>\n    </DataSet>\n  </DataSets>';
const replatformed = (extra = {}) => rdl({ bom: true, sources: NEW_SOURCES, sets: NEW_SETS, ...extra });

test('rdl-compare: a new data layer with a BOM, other line ends and other line breaks is identical outside the data layer', () => {
  assert.deepEqual(compareOutsideDataLayer(rdl({ eol: '\r\n' }), replatformed()), { same: true });
  assert.deepEqual(compareOutsideDataLayer(rdl(), rdl({ sets: '  <DataSets/>' })), { same: true }, 'a self-closing DataSets');
  assert.deepEqual(compareOutsideDataLayer(rdl(), rdl({ sources: '  <DataSources xmlns:rd="x"><DataSource Name="X" /></DataSources>' })), { same: true }, 'attributes on the container');
  assert.deepEqual(compareOutsideDataLayer(rdl({ eol: '\r' }), rdl()), { same: true }, 'old Mac line ends');
});

test('rdl-compare: layout, expressions, parameters and the dataset a tablix binds to are compared, with the first differing line', () => {
  const old = rdl({ eol: '\r\n' });
  const cases = [
    ['a Body height', replatformed({ height: '3in' }), /<Height>2in</, /<Height>3in</],
    ['a textbox expression', replatformed({ value: '=Sum(Fields!Amount.Value)' }), /Fields!Amount\.Value</, /=Sum\(/],
    ['a parameter prompt', replatformed({ prompt: 'Fiscal year' }), /<Prompt>Year</, /<Prompt>Fiscal year</],
    ['the DataSetName of a tablix (outside the data layer)', replatformed({ dataSetName: 'D2' }), /<DataSetName>D</, /<DataSetName>D2</],
  ];
  for (const [label, changed, oldLine, newLine] of cases) {
    const r = compareOutsideDataLayer(old, changed);
    assert.equal(r.same, false, label);
    assert.equal(typeof r.line, 'number', label);
    assert.match(r.old, oldLine, label);
    assert.match(r.new, newLine, label);
  }
  // The data layer is one line after stripping in both files, so the line number is the same for both inputs.
  assert.equal(compareOutsideDataLayer(old, replatformed({ height: '3in' })).line, 9);
  const longer = compareOutsideDataLayer(rdl(), `${rdl()}\n<!-- trailing -->`);
  assert.deepEqual([longer.same, longer.old, longer.new], [false, '(end of file)', '<!-- trailing -->'], 'an extra line at the end is a difference');
});

test('rdl-compare: --ignore removes one more element from the comparison', () => {
  assert.equal(compareOutsideDataLayer(rdl(), replatformed({ height: '3in' }), ['ReportSections']).same, true);
  assert.equal(compareOutsideDataLayer(rdl(), replatformed({ prompt: 'Fiscal year' }), ['ReportSections']).same, false, 'only the named element');
});

test('rdl-compare CLI: exit 0 when identical, 1 with the first difference, 2 for usage and read errors', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-rdl-compare-'));
  const cli = (...args) => spawnSync(process.execPath, [script, ...args], { encoding: 'utf8' });
  try {
    const file = (name, text) => {
      fs.writeFileSync(path.join(dir, name), text);
      return path.join(dir, name);
    };
    const old = file('old.rdl', rdl({ eol: '\r\n' }));
    const same = file('new-same.rdl', replatformed());
    const layout = file('new-layout.rdl', replatformed({ height: '3in' }));

    let r = cli(old, same);
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.match(r.stdout, /^Identical outside the data layer \(DataSources, DataSets not compared\): old\.rdl → new-same\.rdl$/m);

    r = cli(old, layout);
    assert.equal(r.status, 1, r.stdout + r.stderr);
    assert.match(r.stdout, /first difference at line 9 of the compared text/);
    assert.match(r.stdout, /^ {2}old: <Body><Height>2in<\/Height><ReportItems>$/m);
    assert.match(r.stdout, /^ {2}new: <Body><Height>3in<\/Height><ReportItems>$/m);

    r = cli(old, layout, '--ignore', 'ReportSections');
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.match(r.stdout, /DataSources, DataSets, ReportSections not compared/);

    for (const args of [[old], [], [old, same, layout], [old, same, '--ignore', '1x'], [old, same, '--ignore'], [old, same, '--verbose']]) {
      r = cli(...args);
      assert.equal(r.status, 2, `${JSON.stringify(args)}: ${r.stdout}${r.stderr}`);
      assert.match(r.stderr, /^usage: node hardening\/scripts\/rdl-compare\.mjs/m);
    }
    r = cli(old, path.join(dir, 'missing.rdl'));
    assert.equal(r.status, 2);
    assert.match(r.stderr, /^rdl-compare: ENOENT/m);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
