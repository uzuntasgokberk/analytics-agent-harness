// Second audit (2026-10-16): in approvals mode auto the guard passed a partition's storage mode, the server in its M
// source and an RDL ConnectString as routine edits; it protected where data comes from only by file name
// (dataSources.tmdl, expressions.tmdl). AGENTS.md lists a data source, a Power Query or model parameter, a storage mode
// and a refresh change as Tier 2, and .claude/rules/bi/rdl.md the server, database or model a data source reads: the
// guard now compares these facts before and after every TMDL, RDL, RDS and RSD edit.
// Third audit (2026-10-16): with data sources Dev (localhost) and Prod (prod-sql01) defined, pointing a dataset's
// <Query><DataSourceName> from Dev to Prod passed in auto mode, although the report then reads another server. The data
// source each dataset reads is now a fact too, and a dataset added or removed counts with it.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { rdlSourceFacts, tmdlSourceFacts } from '../hooks/lib/validators.mjs';

const hook = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'hooks', 'pre-tool-use.mjs');

const SALES = [
  'table Sales',
  '\tlineageTag: 4f1c2d3e-0000-4000-8000-000000000001',
  '',
  "\tmeasure 'Net Sales' = SUM(Sales[Amount])",
  '\t\tformatString: #,0',
  '',
  '\tcolumn Amount',
  '\t\tdataType: decimal',
  '\t\tsourceColumn: Amount',
  '',
  '\tpartition Sales = m',
  '\t\tmode: import',
  '\t\tqueryGroup: Facts',
  '\t\tsource =',
  '\t\t\t\tlet',
  '\t\t\t\t    Source = Sql.Database("localhost", "Sales"),',
  '\t\t\t\t    dbo_Sales = Source{[Schema="dbo",Item="Sales"]}[Data]',
  '\t\t\t\tin',
  '\t\t\t\t    dbo_Sales',
  '\t\tannotation PBI_Note = 1',
  '',
  '\trefreshPolicy',
  '\t\tpolicyType: basic',
  '\t\trollingWindowGranularity: year',
  '\t\trollingWindowPeriods: 3',
  '\t\tincrementalGranularity: day',
  '\t\tincrementalPeriods: 10',
  '\t\tsourceExpression =',
  '\t\t\t\tlet',
  '\t\t\t\t    Source = Sql.Database("localhost", "Sales")',
  '\t\t\t\tin',
  '\t\t\t\t    Source',
  '',
  '\tannotation PBI_ResultType = Table',
  '',
].join('\n');
const EXPRESSIONS = [
  'expression Server = "localhost" meta [IsParameterQuery=true, Type="Text", IsParameterQueryRequired=true]',
  '\tlineageTag: 4f1c2d3e-0000-4000-8000-000000000002',
  '\tqueryGroup: Parameters',
  '',
  '\tannotation PBI_ResultType = Text',
  '',
].join('\n');
const CALENDAR = "table Calendar\n\n\tpartition Calendar = calculated\n\t\tmode: import\n\t\tsource = CALENDAR(DATE(2020, 1, 1), DATE(2030, 12, 31))\n";
const LAKE = 'table Product\n\n\tpartition Product = entity\n\t\tmode: directLake\n\t\tsource\n\t\t\tentityName: Product\n\t\t\tschemaName: dbo\n\t\t\texpressionSource: DL_Sales\n';
const QUERY = "table Orders\n\n\tpartition Orders = query\n\t\tmode: import\n\t\tdataSource: 'SQL/localhost;Sales'\n\t\tquery = SELECT OrderId FROM dbo.Orders\n";

/** The categories whose facts differ between two texts. */
function changed(before, after) {
  const a = tmdlSourceFacts(before);
  const b = tmdlSourceFacts(after);
  return Object.keys(a).filter((k) => a[k] !== b[k]);
}
const edit = (text, from, to) => {
  assert.ok(text.includes(from), `fixture lacks ${from}`);
  return text.replace(from, to);
};

test('TMDL source facts: mode, M source, dataSource, queryGroup, refreshPolicy, expressions and defaultMode each count', () => {
  for (const [label, before, after, expected] of [
    ['partition mode', SALES, edit(SALES, 'mode: import', 'mode: directQuery'), ['storageMode']],
    ['server in the M source', SALES, edit(SALES, 'Sql.Database("localhost", "Sales"),', 'Sql.Database("prod-sql01", "Sales"),'), ['dataSource']],
    ['a step of the M source', SALES, edit(SALES, 'Item="Sales"', 'Item="SalesArchive"'), ['dataSource']],
    ['partition queryGroup', SALES, edit(SALES, 'queryGroup: Facts', 'queryGroup: Other'), ['expression']],
    ['refresh policy period', SALES, edit(SALES, 'rollingWindowPeriods: 3', 'rollingWindowPeriods: 5'), ['refreshPolicy']],
    ['refresh policy source', SALES, edit(SALES, 'Sql.Database("localhost", "Sales")\n', 'Sql.Database("prod-sql01", "Sales")\n'), ['refreshPolicy']],
    ['refresh policy removed', SALES, SALES.slice(0, SALES.indexOf('\trefreshPolicy')), ['refreshPolicy']],
    ['a new expression in a table file', SALES, `${SALES}\nexpression Archive = "x"\n`, ['expression']],
    ['a parameter value', EXPRESSIONS, edit(EXPRESSIONS, '"localhost"', '"prod-sql01"'), ['expression']],
    ['a parameter query group', EXPRESSIONS, edit(EXPRESSIONS, 'queryGroup: Parameters', 'queryGroup: Other'), ['expression']],
    ['model defaultMode', 'model Model\n\tculture: en-US\n', 'model Model\n\tculture: en-US\n\tdefaultMode: directQuery\n', ['storageMode']],
    ['legacy partition dataSource', QUERY, edit(QUERY, "'SQL/localhost;Sales'", "'SQL/prod-sql01;Sales'"), ['dataSource']],
    ['legacy partition query', QUERY, edit(QUERY, 'FROM dbo.Orders', 'FROM dbo.OrdersAll'), ['dataSource']],
    ['Direct Lake entity', LAKE, edit(LAKE, 'entityName: Product', 'entityName: ProductV2'), ['dataSource']],
    ['a data source object', 'dataSource Sales\n\tconnectionString: "Data Source=localhost"\n', 'dataSource Sales\n\tconnectionString: "Data Source=prod-sql01"\n', ['dataSource']],
    ['calculated table becomes an M table', CALENDAR, edit(CALENDAR, 'Calendar = calculated', 'Calendar = m'), ['dataSource', 'storageMode']],
    ['calculated table storage mode', CALENDAR, edit(CALENDAR, 'mode: import', 'mode: directQuery'), ['storageMode']],
  ]) assert.deepEqual(changed(before, after), expected, label);
});

test('TMDL source facts: a new or removed partition counts; a new calculated table does not', () => {
  const second = edit(SALES, '\trefreshPolicy', '\tpartition Sales2 = m\n\t\tmode: import\n\t\tsource = Sql.Database("localhost", "Sales")\n\n\trefreshPolicy');
  assert.ok(changed(SALES, second).includes('dataSource'), 'a second partition');
  assert.ok(changed(second, SALES).includes('dataSource'), 'a removed partition');
  assert.ok(changed('', SALES).includes('dataSource'), 'a new table file with an M partition');
  assert.ok(changed('', EXPRESSIONS).includes('expression'), 'a new expressions file');
  assert.ok(changed(SALES, edit(SALES, 'partition Sales = m', 'partition SalesAll = m')).includes('dataSource'), 'a renamed partition');
  assert.deepEqual(changed('', CALENDAR), [], 'a new calculated table reads no data source');
  assert.deepEqual(changed(CALENDAR, edit(CALENDAR, 'DATE(2030, 12, 31)', 'DATE(2035, 12, 31)')), [], 'its DAX is model logic, not a source');
});

test('TMDL source facts: measures, columns, descriptions, formatString, annotations, lineage tags and indentation stay routine', () => {
  for (const [label, before, after] of [
    ['a new measure', SALES, edit(SALES, '\tcolumn Amount', "\tmeasure 'Gross Sales' = SUM(Sales[Gross])\n\t\tformatString: #,0\n\n\tcolumn Amount")],
    ['a formatString', SALES, edit(SALES, 'formatString: #,0', 'formatString: #,0.00')],
    ['a new column', SALES, edit(SALES, '\tpartition Sales', '\tcolumn Qty\n\t\tdataType: int64\n\t\tsourceColumn: Qty\n\n\tpartition Sales')],
    ['a description above the partition', SALES, edit(SALES, '\tpartition Sales', '\t/// Sales rows from the warehouse\n\tpartition Sales')],
    ['an annotation inside the partition', SALES, edit(SALES, 'annotation PBI_Note = 1', 'annotation PBI_Note = 2')],
    ['a table annotation', SALES, edit(SALES, 'PBI_ResultType = Table', 'PBI_ResultType = Exception')],
    ['an expression annotation and lineage tag', EXPRESSIONS, edit(edit(EXPRESSIONS, 'PBI_ResultType = Text', 'PBI_ResultType = Number'), '000000000002', '000000000003')],
    ['spaces instead of tabs', SALES, SALES.replace(/\t/g, '    ')],
    ['CRLF line endings', SALES, SALES.replace(/\n/g, '\r\n')],
    ['a quoted partition name', SALES, edit(SALES, 'partition Sales = m', "partition 'Sales' = m")],
    ['a byte order mark', SALES, `${String.fromCharCode(0xfeff)}${SALES}`],
  ]) assert.deepEqual(changed(before, after), [], label);
});

// A block's depth was found with Math.min(...lines): past about 120,000 lines the spread threw a RangeError, and a
// guard that throws denies the write (it fails closed).
test('TMDL source facts: a partition source of 300,000 lines is classified like a short one', () => {
  const steps = Array.from({ length: 300000 }, (_, i) => `\t\t\t\t    Step${i} = Table.AddColumn(dbo_Sales, "c${i}", each ${i}),`).join('\n');
  const big = edit(SALES, '\t\t\t\tin\n\t\t\t\t    dbo_Sales', `${steps}\n\t\t\t\tin\n\t\t\t\t    dbo_Sales`);
  assert.ok(big.split('\n').length > 300000);
  assert.deepEqual(changed(big, edit(big, '"localhost", "Sales"),', '"prod-sql01", "Sales"),')), ['dataSource'], 'server');
  assert.deepEqual(changed(big, edit(big, 'Step299999 = ', 'Step299999b = ')), ['dataSource'], 'the last step');
  assert.deepEqual(changed(big, edit(big, 'mode: import', 'mode: directQuery')), ['storageMode'], 'mode');
  assert.deepEqual(changed(big, edit(big, 'rollingWindowPeriods: 3', 'rollingWindowPeriods: 5')), ['refreshPolicy'], 'the block after it');
  assert.deepEqual(changed(big, edit(big, 'formatString: #,0', 'formatString: #,0.00')), [], 'a formatString');
});

// ---------------------------------------------------------------- paginated reports

const RDL = `<?xml version="1.0" encoding="utf-8"?>
<Report xmlns="http://schemas.microsoft.com/sqlserver/reporting/2016/01/reportdefinition" xmlns:rd="http://schemas.microsoft.com/SQLServer/reporting/reportdesigner">
  <DataSources>
    <DataSource Name="Sales">
      <ConnectionProperties>
        <DataProvider>SQL</DataProvider>
        <ConnectString>Data Source=localhost;Initial Catalog=Sales</ConnectString>
        <IntegratedSecurity>true</IntegratedSecurity>
      </ConnectionProperties>
      <rd:SecurityType>Integrated</rd:SecurityType>
      <rd:DataSourceID>4f1c2d3e-0000-4000-8000-000000000010</rd:DataSourceID>
    </DataSource>
    <DataSource Name="Shared">
      <DataSourceReference>SalesShared</DataSourceReference>
    </DataSource>
    <DataSource Name="Dyn">
      <ConnectionProperties>
        <DataProvider>SQL</DataProvider>
        <ConnectString>="Data Source=" &amp; Parameters!Server.Value &amp; ";Initial Catalog=Sales"</ConnectString>
      </ConnectionProperties>
    </DataSource>
  </DataSources>
  <DataSets>
    <DataSet Name="Orders">
      <Query>
        <DataSourceName>Sales</DataSourceName>
        <CommandText>SELECT OrderId, Amount FROM dbo.Orders WHERE Year = @Year</CommandText>
      </Query>
      <Fields><Field Name="OrderId"><DataField>OrderId</DataField></Field></Fields>
    </DataSet>
    <DataSet Name="Lookup">
      <SharedDataSet><SharedDataSetReference>Regions</SharedDataSetReference></SharedDataSet>
    </DataSet>
  </DataSets>
  <ReportParameters>
    <ReportParameter Name="Year"><DataType>Integer</DataType><DefaultValue><Values><Value>2025</Value></Values></DefaultValue><Prompt>Year</Prompt></ReportParameter>
    <ReportParameter Name="Server"><DataType>String</DataType><DefaultValue><Values><Value>localhost</Value></Values></DefaultValue><Prompt>Server</Prompt></ReportParameter>
  </ReportParameters>
  <!-- <ConnectString>Data Source=old-server</ConnectString> -->
  <ReportSections><ReportSection><Body><ReportItems><Textbox Name="Title"><Value>Orders</Value></Textbox></ReportItems></Body></ReportSection></ReportSections>
</Report>
`;
const RDS = `<?xml version="1.0" encoding="utf-8"?>
<RptDataSource xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" Name="SalesShared">
  <ConnectionProperties>
    <Extension>SQL</Extension>
    <ConnectString>Data Source=localhost;Initial Catalog=Sales</ConnectString>
    <IntegratedSecurity>true</IntegratedSecurity>
  </ConnectionProperties>
  <DataSourceID>4f1c2d3e-0000-4000-8000-000000000011</DataSourceID>
</RptDataSource>
`;
const RSD = `<?xml version="1.0" encoding="utf-8"?>
<SharedDataSet xmlns="http://schemas.microsoft.com/sqlserver/reporting/2010/01/shareddatasetdefinition">
  <DataSet Name="Regions">
    <Query>
      <DataSourceReference>SalesShared</DataSourceReference>
      <CommandText>SELECT RegionId, Name FROM dbo.Region</CommandText>
    </Query>
    <Fields><Field Name="RegionId"><DataField>RegionId</DataField></Field></Fields>
  </DataSet>
</SharedDataSet>
`;
// The third audit's report: two embedded data sources, both datasets read Dev.
const INVOICES = `<?xml version="1.0" encoding="utf-8"?>
<Report xmlns="http://schemas.microsoft.com/sqlserver/reporting/2016/01/reportdefinition" xmlns:rd="http://schemas.microsoft.com/SQLServer/reporting/reportdesigner">
  <DataSources>
    <DataSource Name="Dev">
      <ConnectionProperties>
        <DataProvider>SQL</DataProvider>
        <ConnectString>Data Source=localhost;Initial Catalog=Billing</ConnectString>
        <IntegratedSecurity>true</IntegratedSecurity>
      </ConnectionProperties>
      <rd:DataSourceID>4f1c2d3e-0000-4000-8000-000000000020</rd:DataSourceID>
    </DataSource>
    <DataSource Name="Prod">
      <ConnectionProperties>
        <DataProvider>SQL</DataProvider>
        <ConnectString>Data Source=prod-sql01;Initial Catalog=Billing</ConnectString>
        <IntegratedSecurity>true</IntegratedSecurity>
      </ConnectionProperties>
      <rd:DataSourceID>4f1c2d3e-0000-4000-8000-000000000021</rd:DataSourceID>
    </DataSource>
  </DataSources>
  <DataSets>
    <DataSet Name="Invoices">
      <Query>
        <DataSourceName>Dev</DataSourceName>
        <CommandText>SELECT InvoiceId, Amount FROM dbo.Invoices</CommandText>
      </Query>
      <Fields><Field Name="InvoiceId"><DataField>InvoiceId</DataField></Field></Fields>
    </DataSet>
    <DataSet Name="Customers">
      <Query>
        <DataSourceName>Dev</DataSourceName>
        <CommandText>SELECT CustomerId FROM dbo.Customers</CommandText>
      </Query>
      <Fields><Field Name="CustomerId"><DataField>CustomerId</DataField></Field></Fields>
    </DataSet>
  </DataSets>
  <ReportSections><ReportSection><Body><ReportItems><Textbox Name="Title"><Value>Invoices</Value></Textbox></ReportItems></Body></ReportSection></ReportSections>
</Report>
`;
const ORDERS_DATASET = /<DataSet Name="Orders">[\s\S]*?<\/DataSet>/.exec(RDL)[0];
const CUSTOMERS_DATASET = /<DataSet Name="Customers">[\s\S]*?<\/DataSet>/.exec(INVOICES)[0];

/** Labels whose facts differ between two texts. */
function rdlChanged(before, after) {
  const a = rdlSourceFacts(before);
  const b = rdlSourceFacts(after);
  return [...new Set([...a.keys(), ...b.keys()])].filter((k) => a.get(k) !== b.get(k));
}

test('RDL source facts: ConnectString, provider, shared references, the data source a dataset reads and data sources or datasets added or removed each count', () => {
  for (const [label, before, after, expected] of [
    ['server in a ConnectString', RDL, edit(RDL, 'Data Source=localhost;', 'Data Source=prod-sql01;'), ['data source "Sales"']],
    ['provider', RDL, edit(RDL, '<DataProvider>SQL</DataProvider>', '<DataProvider>OLEDB</DataProvider>'), ['data source "Sales"']],
    ['integrated security', RDL, edit(RDL, '<IntegratedSecurity>true', '<IntegratedSecurity>false'), ['data source "Sales"']],
    ['shared data source reference', RDL, edit(RDL, '>SalesShared<', '>SalesProd<'), ['data source "Shared"']],
    ['shared dataset reference', RDL, edit(RDL, '>Regions<', '>RegionsProd<'), ['dataset "Lookup"']],
    ['the data source a dataset reads', RDL, edit(RDL, '<DataSourceName>Sales</DataSourceName>', '<DataSourceName>Dyn</DataSourceName>'), ['dataset "Orders"']],
    ['the audit: a dataset moved from Dev to Prod', INVOICES, edit(INVOICES, '<DataSet Name="Invoices">\n      <Query>\n        <DataSourceName>Dev<', '<DataSet Name="Invoices">\n      <Query>\n        <DataSourceName>Prod<'), ['dataset "Invoices"']],
    ['a new dataset on an existing data source', RDL, edit(RDL, '</DataSets>', '<DataSet Name="Top"><Query><DataSourceName>Sales</DataSourceName><CommandText>SELECT 1</CommandText></Query></DataSet></DataSets>'), ['dataset "Top"']],
    ['a removed dataset', RDL, edit(RDL, ORDERS_DATASET, ''), ['dataset "Orders"']],
    ['a renamed dataset', RDL, edit(RDL, 'DataSet Name="Orders"', 'DataSet Name="OrdersAll"'), ['dataset "Orders"', 'dataset "OrdersAll"']],
    ['a renamed data source', RDL, edit(RDL, 'DataSource Name="Shared"', 'DataSource Name="Shared2"'), ['data source "Shared"', 'data source "Shared2"']],
    ['a removed data source', RDL, edit(RDL, /<DataSource Name="Shared">[\s\S]*?<\/DataSource>/.exec(RDL)[0], ''), ['data source "Shared"']],
    ['a new data source', RDL, edit(RDL, '</DataSources>', '<DataSource Name="Extra"><ConnectionProperties><DataProvider>SQL</DataProvider><ConnectString>Data Source=other</ConnectString></ConnectionProperties></DataSource></DataSources>'), ['data source "Extra"']],
    ['the default of a parameter a ConnectString reads', RDL, edit(RDL, '<Value>localhost</Value>', '<Value>prod-sql01</Value>'), ['data source "Dyn"']],
    ['.rds connection', RDS, edit(RDS, 'Data Source=localhost;', 'Data Source=prod-sql01;'), ['data source "SalesShared"']],
    ['.rds extension', RDS, edit(RDS, '<Extension>SQL</Extension>', '<Extension>OLEDB</Extension>'), ['data source "SalesShared"']],
    ['.rsd data source reference', RSD, edit(RSD, '>SalesShared<', '>SalesProd<'), ['dataset "Regions"']],
  ]) assert.deepEqual(rdlChanged(before, after), expected, label);
  assert.deepEqual(rdlChanged('', RDS), ['data source "SalesShared"'], 'a new shared data source');
});

test('RDL source facts: the query, fields, parameters, layout, IDs, comments and whitespace stay routine', () => {
  for (const [label, before, after] of [
    ['CommandText', RDL, edit(RDL, 'WHERE Year = @Year', 'WHERE Year = @Year AND Amount > 0')],
    ['a field of a dataset', RDL, edit(RDL, '<Fields><Field Name="OrderId">', '<Fields><Field Name="Amount"><DataField>Amount</DataField></Field><Field Name="OrderId">')],    ['an ordinary parameter default', RDL, edit(RDL, '<Value>2025</Value>', '<Value>2026</Value>')],
    ['a text box', RDL, edit(RDL, '<Value>Orders</Value>', '<Value>All orders</Value>')],
    ['a data source ID', RDL, edit(RDL, '000000000010', '000000000012')],
    ['a commented-out connection', RDL, edit(RDL, 'Data Source=old-server', 'Data Source=older-server')],
    ['whitespace inside ConnectionProperties', RDL, edit(RDL, '<DataProvider>SQL</DataProvider>\n        <ConnectString>Data Source=localhost', '<DataProvider>SQL</DataProvider> <ConnectString>Data Source=localhost')],
    ['.rsd CommandText', RSD, edit(RSD, 'FROM dbo.Region', 'FROM dbo.Region WHERE Active = 1')],
  ]) assert.deepEqual(rdlChanged(before, after), [], label);
});

// Final audit (2026-10-18), F1-27 and F1-66: the guard saw a parameter in a ConnectString only as `Parameters!X`. RDL
// expressions are Visual Basic (case-insensitive; Microsoft documents Parameters("X") and Parameters.Item("X") beside the
// bang form), a parameter whose default feeds the one the ConnectString reads moved the server unseen, and so did a server
// written in the embedded <Code> a ConnectString calls.
const ENV_PARAMETER = '<ReportParameter Name="Env"><DataType>String</DataType><DefaultValue><Values><Value>env-host</Value></Values></DefaultValue><Prompt>Env</Prompt></ReportParameter>';
// Env feeds Server (its default is =Parameters!Env.Value), and the Dyn ConnectString reads Server.
const NESTED = edit(edit(RDL, '<Value>localhost</Value>', '<Value>=Parameters!Env.Value</Value>'), '<ReportParameter Name="Server">', `${ENV_PARAMETER}<ReportParameter Name="Server">`);
// The Dyn ConnectString calls =Code.Conn(), which returns a server written in the report's <Code>.
const CODED = edit(edit(RDL, '="Data Source=" &amp; Parameters!Server.Value &amp; ";Initial Catalog=Sales"', '=Code.Conn()'), '  <DataSources>',
  '  <Code>Public Function Conn() As String\n  Return "Data Source=code-host;Initial Catalog=Sales"\nEnd Function</Code>\n  <DataSources>');
// The Dyn ConnectString reads P1, P1's default reads P2, ... and the default of the last one is a server.
function chainReport(levels, extra = '') {
  let parameters = '';
  for (let i = 1; i <= levels; i++) {
    parameters += `<ReportParameter Name="P${i}"><DataType>String</DataType><DefaultValue><Values><Value>${i < levels ? `=Parameters!P${i + 1}.Value` : 'leaf-host'}</Value></Values></DefaultValue></ReportParameter>`;
  }
  return edit(edit(RDL, 'Parameters!Server.Value', 'Parameters!P1.Value'), '</ReportParameters>', `${parameters}${extra}</ReportParameters>`);
}
const SERVER_HOST = ['<Value>localhost</Value>', '<Value>prod-sql01</Value>'];
const YEAR = ['<Value>2025</Value>', '<Value>2026</Value>'];

test('RDL source facts: a parameter a ConnectString reads counts in every spelling Visual Basic allows (F1-27)', () => {
  for (const spelling of [
    'Parameters!Server.Value', 'parameters!Server.Value', 'PARAMETERS!SERVER.VALUE', 'Parameters!\n      Server.Value', 'Parameters![Server].Value',
    'Parameters("Server").Value', 'parameters("server").value', 'Parameters.Item("Server").Value', 'PARAMETERS . ITEM ( "SERVER" ) . VALUE',
    "Parameters('Server').Value", 'Parameters(&quot;Server&quot;).Value', 'Parameters(&#34;Server&#34;).Value', 'Parameters.Item(&apos;Server&apos;).Value',
  ]) {
    const report = edit(RDL, 'Parameters!Server.Value', spelling);
    assert.deepEqual(rdlChanged(report, edit(report, ...SERVER_HOST)), ['data source "Dyn"'], spelling);
    assert.deepEqual(rdlChanged(report, edit(report, ...YEAR)), [], `${spelling}: a parameter the ConnectString does not read`);
  }
  // Not the parameters collection: another name that ends in Parameters, or a field of that name.
  for (const spelling of ['MyParameters!Server.Value', 'Fields!Server.Value']) {
    const report = edit(RDL, 'Parameters!Server.Value', spelling);
    assert.deepEqual(rdlChanged(report, edit(report, ...SERVER_HOST)), [], spelling);
  }
  // A ConnectString in a CDATA section reads the same way.
  const cdata = edit(RDL, '="Data Source=" &amp; Parameters!Server.Value &amp; ";Initial Catalog=Sales"', '<![CDATA[="Data Source=" & Parameters("Server").Value]]>');
  assert.deepEqual(rdlChanged(cdata, edit(cdata, ...SERVER_HOST)), ['data source "Dyn"'], 'CDATA');
});

test('RDL source facts: a parameter that feeds a parameter the ConnectString reads counts, five levels deep, and a cycle ends (F1-66)', () => {
  assert.deepEqual(rdlChanged(NESTED, edit(NESTED, '<Value>env-host</Value>', '<Value>prod-sql01</Value>')), ['data source "Dyn"'], 'Env feeds Server');
  assert.deepEqual(rdlChanged(NESTED, edit(NESTED, ...YEAR)), [], 'an unrelated parameter');
  // The available values count like the default.
  const viaValidValues = edit(chainReport(1, ENV_PARAMETER), '<Value>leaf-host</Value></Values></DefaultValue>',
    '<Value>x</Value></Values></DefaultValue><ValidValues><ParameterValues><ParameterValue><Value>=Parameters!Env.Value</Value></ParameterValue></ParameterValues></ValidValues>');
  assert.deepEqual(rdlChanged(viaValidValues, edit(viaValidValues, '<Value>env-host</Value>', '<Value>prod-sql01</Value>')), ['data source "Dyn"'], 'ValidValues');
  for (const levels of [1, 2, 3, 5]) {
    const chain = chainReport(levels);
    assert.deepEqual(rdlChanged(chain, edit(chain, 'leaf-host', 'prod-sql01')), ['data source "Dyn"'], `${levels} level(s)`);
    assert.deepEqual(rdlChanged(chain, edit(chain, ...YEAR)), [], `${levels} level(s): an unrelated parameter`);
  }
  const tooDeep = chainReport(6);
  assert.deepEqual(rdlChanged(tooDeep, edit(tooDeep, 'leaf-host', 'prod-sql01')), [], 'the sixth level is past the bound');
  assert.deepEqual(rdlChanged(tooDeep, edit(tooDeep, '<Value>=Parameters!P6.Value</Value>', '<Value>other-host</Value>')), ['data source "Dyn"'], 'the fifth level is inside it');
  // P1 reads P2 and P2 reads P1; a parameter that reads itself.
  const cycle = edit(chainReport(2), 'leaf-host', '=Parameters!P1.Value &amp; "-x"');
  assert.deepEqual(rdlChanged(cycle, edit(cycle, '"-x"', '"-y"')), ['data source "Dyn"'], 'a cycle');
  const self = edit(chainReport(1), 'leaf-host', '=Parameters!P1.Value &amp; "-x"');
  assert.deepEqual(rdlChanged(self, edit(self, '"-x"', '"-y"')), ['data source "Dyn"'], 'a parameter that reads itself');
});

test('RDL source facts: the embedded code a ConnectString calls counts; code nobody calls does not (F1-66)', () => {
  assert.deepEqual(rdlChanged(CODED, edit(CODED, 'Data Source=code-host;', 'Data Source=prod-sql01;')), ['data source "Dyn"'], 'the server in the code body');
  assert.deepEqual(rdlChanged(CODED, edit(CODED, ...YEAR)), [], 'an unrelated parameter');
  assert.deepEqual(rdlChanged(CODED, edit(CODED, ...SERVER_HOST)), [], 'a parameter nothing reads any more');
  assert.deepEqual(rdlChanged(CODED, edit(CODED, '<Value>Orders</Value>', '<Value>All orders</Value>')), [], 'a text box');
  // The code can read a parameter itself (Report.Parameters in embedded code), or be called from a parameter's default.
  for (const read of ['Report.Parameters!Server.Value', 'Report.Parameters("Server").Value', 'report.parameters.item("server").value']) {
    const codeReads = edit(CODED, '"Data Source=code-host;Initial Catalog=Sales"', `"Data Source=" &amp; ${read}`);
    assert.deepEqual(rdlChanged(codeReads, edit(codeReads, ...SERVER_HOST)), ['data source "Dyn"'], read);
  }
  const defaultCalls = edit(edit(CODED, '=Code.Conn()', '="Data Source=" &amp; Parameters!Server.Value'), '<Value>localhost</Value>', '<Value>=Code.Conn()</Value>');
  assert.deepEqual(rdlChanged(defaultCalls, edit(defaultCalls, 'Data Source=code-host;', 'Data Source=prod-sql01;')), ['data source "Dyn"'], 'a default that calls the code');
  // No call, no fact: a plain ConnectString, a field named Code, and the CodeModules list are not the <Code> block.
  for (const connect of ['Data Source=localhost;Initial Catalog=Sales', '="Data Source=" &amp; Fields!Code.Value']) {
    const notCalled = edit(CODED, '=Code.Conn()', connect);
    assert.deepEqual(rdlChanged(notCalled, edit(notCalled, 'Data Source=code-host;', 'Data Source=prod-sql01;')), [], connect);
  }
  const modules = edit(CODED, '  <DataSources>', '  <CodeModules><CodeModule>Helper, Version=1.0.0.0</CodeModule></CodeModules>\n  <DataSources>');
  assert.deepEqual(rdlChanged(modules, edit(modules, 'Helper, Version=1.0.0.0', 'Helper, Version=2.0.0.0')), [], 'CodeModules');
});

// ---------------------------------------------------------------- through the real hook, as the audit reproduced it

const TABLE = 'powerbi/Sales.SemanticModel/definition/tables/Sales.tmdl';
const REPORT = 'paginated/Inv.rdl';
const SHARED_DS = 'paginated/SalesShared.rds';
const SHARED_SET = 'paginated/Regions.rsd';
const INVOICE_REPORT = 'paginated/Invoices.rdl';
const INDEXED_REPORT = 'paginated/Indexed.rdl';
const NESTED_REPORT = 'paginated/Nested.rdl';
const CODED_REPORT = 'paginated/Coded.rdl';
const FILES = {
  [TABLE]: SALES, [REPORT]: RDL, [SHARED_DS]: RDS, [SHARED_SET]: RSD, [INVOICE_REPORT]: INVOICES,
  [INDEXED_REPORT]: edit(RDL, 'Parameters!Server.Value', 'Parameters("Server").Value'), [NESTED_REPORT]: NESTED, [CODED_REPORT]: CODED,
};

/** Runs the PreToolUse hook on an Edit or Write in a temporary project holding FILES, with an optional harness config. */
function runHook(tool_name, rel, toolInput, config) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-sources-'));
  try {
    for (const [file, content] of Object.entries(FILES)) {
      fs.mkdirSync(path.dirname(path.join(dir, file)), { recursive: true });
      fs.writeFileSync(path.join(dir, file), content);
    }
    if (config) {
      fs.mkdirSync(path.join(dir, 'hardening'), { recursive: true });
      fs.writeFileSync(path.join(dir, 'hardening', 'harness.config.json'), JSON.stringify(config));
    }
    const r = spawnSync(process.execPath, [hook], {
      input: JSON.stringify({ hook_event_name: 'PreToolUse', session_id: 'tier2-sources', tool_name, tool_input: { file_path: path.join(dir, rel), ...toolInput } }),
      env: { ...process.env, CLAUDE_PROJECT_DIR: dir },
      encoding: 'utf8',
    });
    assert.equal(r.status, 0, r.stderr);
    const out = r.stdout.trim() ? JSON.parse(r.stdout).hookSpecificOutput : null;
    const log = path.join(dir, '.claude', 'logs', 'security-events.jsonl');
    const events = fs.existsSync(log) ? fs.readFileSync(log, 'utf8').trim().split('\n').map((l) => JSON.parse(l)) : [];
    return { decision: out?.permissionDecision ?? null, reason: out?.permissionDecisionReason ?? '', events };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}
const editOf = (rel, old_string, new_string) => ['Edit', rel, { old_string, new_string }];

/** Tier 2: auto (the default) asks and logs no auto approval, lab mode runs it, ask mode asks. */
function assertTier2([tool, rel, input], message, label) {
  const auto = runHook(tool, rel, input);
  assert.equal(auto.decision, 'ask', `auto: ${label}`);
  assert.match(auto.reason, message, label);
  assert.match(auto.reason, /Critical: auto mode always asks/, label);
  assert.ok(!auto.events.some((e) => e.event === 'auto-approve'), label);
  assert.equal(runHook(tool, rel, input, { approvals: { mode: 'lab' } }).decision, 'allow', `lab: ${label}`);
  assert.equal(runHook(tool, rel, input, { approvals: { mode: 'ask' } }).decision, 'ask', `ask mode: ${label}`);
}
/** Routine: auto mode allows it as a routine project file edit. */
function assertRoutine([tool, rel, input], label) {
  const auto = runHook(tool, rel, input);
  assert.equal(auto.decision, 'allow', `${label}: ${auto.reason}`);
  assert.match(auto.reason, /auto mode: routine project file edit/, label);
}
const TMDL_ASK = (what) => new RegExp(`This edit changes ${what} in powerbi/Sales\\.SemanticModel/definition/tables/Sales\\.tmdl \\(Tier 2, AGENTS\\.md\\): show the impact`);

test('hook: the audit\'s TMDL reproductions ask in auto mode (storage mode, server in the M source)', () => {
  assertTier2(editOf(TABLE, 'mode: import', 'mode: directQuery'), TMDL_ASK('a storage mode'), 'mode import to directQuery');
  assertTier2(editOf(TABLE, 'Sql.Database("localhost", "Sales"),', 'Sql.Database("prod-sql01", "Sales"),'), TMDL_ASK('a data source'), 'server in the partition source');
});

test('hook: refresh policy, a new expression, a new M table and a model defaultMode ask; a new calculated table is routine', () => {
  assertTier2(editOf(TABLE, 'rollingWindowPeriods: 3', 'rollingWindowPeriods: 5'), TMDL_ASK('a refresh policy'), 'refreshPolicy');
  assertTier2(editOf(TABLE, '\tannotation PBI_ResultType = Table\n', '\tannotation PBI_ResultType = Table\n\nexpression Archive = Sql.Database("localhost", "Archive")\n'),
    TMDL_ASK('a Power Query expression'), 'a new expression in a table file');
  assertTier2(['Write', 'powerbi/Sales.SemanticModel/definition/tables/Orders.tmdl', { content: QUERY }], /changes a data source and a storage mode in .*Orders\.tmdl/, 'a new table with a query partition');
  assertTier2(['Write', 'powerbi/Sales.SemanticModel/definition/model.tmdl', { content: 'model Model\n\tculture: en-US\n\tdefaultMode: directQuery\n' }], /changes a storage mode in .*model\.tmdl/, 'model defaultMode');
  assertRoutine(['Write', 'powerbi/Sales.SemanticModel/definition/tables/Calendar.tmdl', { content: CALENDAR }], 'a new calculated table');
});

test('hook: a measure add and a formatString change in a partitioned table stay routine in auto mode', () => {
  assertRoutine(editOf(TABLE, '\tcolumn Amount', "\tmeasure 'Gross Sales' = SUM(Sales[Gross])\n\t\tformatString: #,0\n\n\tcolumn Amount"), 'a measure add');
  assertRoutine(editOf(TABLE, 'formatString: #,0', 'formatString: #,0.00'), 'a formatString change');
});

test('hook: the audit\'s RDL reproduction and .rds and .rsd connection changes ask; CommandText stays routine', () => {
  const rdlAsk = (name, file) => new RegExp(`This edit changes ${name} in ${file.replace(/\./g, '\\.')}: the server, database, provider or shared item it reads.*\\(Tier 2, \\.claude/rules/bi/rdl\\.md\\)`);
  assertTier2(editOf(REPORT, 'Data Source=localhost;Initial Catalog=Sales', 'Data Source=prod-sql01;Initial Catalog=Sales'), rdlAsk('data source "Sales"', REPORT), 'RDL ConnectString');
  assertTier2(editOf(SHARED_DS, 'Data Source=localhost;', 'Data Source=prod-sql01;'), rdlAsk('data source "SalesShared"', SHARED_DS), '.rds connection');
  assertTier2(editOf(SHARED_SET, '>SalesShared<', '>SalesProd<'), rdlAsk('dataset "Regions"', SHARED_SET), '.rsd data source reference');
  assertRoutine(editOf(REPORT, 'WHERE Year = @Year', 'WHERE Year = @Year AND Amount > 0'), 'RDL CommandText');
  assertRoutine(editOf(SHARED_SET, 'FROM dbo.Region', 'FROM dbo.Region WHERE Active = 1'), '.rsd CommandText');
  const cdataEnd = runHook(...editOf(REPORT, '<Value>Orders</Value>', '<Value>Orders]]></Value>'));
  assert.equal(cdataEnd.decision, 'deny');
  assert.match(cdataEnd.reason, /malformed XML \("\]\]>" in text outside a CDATA section.*line \d+\)/);
});

test('hook: the third audit\'s reproduction asks: a dataset that reads Prod instead of Dev, a dataset added or removed', () => {
  const datasetAsk = (name, sentence) => new RegExp(`This edit changes dataset "${name}" in paginated/Invoices\\.rdl: .*the data source a dataset reads.*\\(Tier 2, \\.claude/rules/bi/rdl\\.md\\)\\. ${sentence}`);
  assertTier2(editOf(INVOICE_REPORT, '<DataSet Name="Invoices">\n      <Query>\n        <DataSourceName>Dev</DataSourceName>', '<DataSet Name="Invoices">\n      <Query>\n        <DataSourceName>Prod</DataSourceName>'),
    datasetAsk('Invoices', 'Dataset "Invoices" now reads Prod instead of Dev\\.'), 'DataSourceName Dev to Prod');
  assertTier2(editOf(INVOICE_REPORT, '</DataSets>', '<DataSet Name="Payments"><Query><DataSourceName>Prod</DataSourceName><CommandText>SELECT PaymentId FROM dbo.Payments</CommandText></Query></DataSet>\n  </DataSets>'),
    datasetAsk('Payments', 'Dataset "Payments" is new and reads Prod\\.'), 'a new dataset bound to Prod');
  assertTier2(editOf(INVOICE_REPORT, CUSTOMERS_DATASET, ''), datasetAsk('Customers', 'Dataset "Customers" is removed \\(it read Dev\\)\\.'), 'a dataset removed');
  const rsd = runHook(...editOf(SHARED_SET, '>SalesShared<', '>SalesProd<'));
  assert.equal(rsd.decision, 'ask');
  assert.match(rsd.reason, /Dataset "Regions" now reads SalesProd instead of SalesShared\./, '.rsd DataSourceReference');
  assertRoutine(editOf(INVOICE_REPORT, 'FROM dbo.Invoices', 'FROM dbo.Invoices WHERE Amount > 0'), 'CommandText of the same dataset');
  assertRoutine(editOf(INVOICE_REPORT, '<Field Name="InvoiceId"><DataField>InvoiceId</DataField></Field>', '<Field Name="InvoiceId"><DataField>InvoiceId</DataField></Field><Field Name="Amount"><DataField>Amount</DataField></Field>'),
    'a field of the same dataset');
});

test('hook: the server a ConnectString reads as Parameters("X"), through another parameter or through embedded code asks in auto mode (F1-27, F1-66)', () => {
  const dynAsk = (file) => new RegExp(`This edit changes data source "Dyn" in ${file.replace(/\./g, '\\.')}: the server, database, provider or shared item it reads.*\\(Tier 2, \\.claude/rules/bi/rdl\\.md\\)`);
  assertTier2(editOf(INDEXED_REPORT, ...SERVER_HOST), dynAsk(INDEXED_REPORT), 'Parameters("Server").Value');
  assertTier2(editOf(NESTED_REPORT, '<Value>env-host</Value>', '<Value>prod-sql01</Value>'), dynAsk(NESTED_REPORT), 'a parameter that feeds the one the ConnectString reads');
  assertTier2(editOf(CODED_REPORT, 'Data Source=code-host;', 'Data Source=prod-sql01;'), dynAsk(CODED_REPORT), 'the server in the embedded code');
  for (const file of [INDEXED_REPORT, NESTED_REPORT, CODED_REPORT]) assertRoutine(editOf(file, ...YEAR), `${file}: a parameter the ConnectString does not read`);
});
