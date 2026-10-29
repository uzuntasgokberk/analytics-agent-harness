// Audit 2026-10-18 (group G6, findings F1-7, F1-32, F1-33, F1-34): how the policy reads a DAX query and a model write sent
// to the Power BI modeling MCP server. Comment markers inside a string hid the rest of a query from the row-level check
// (F1-7); a table or model write that named a partition source, an M expression or a data source passed as ordinary model
// work (F1-32); a person table's plain name column was no personal column (F1-33); the first text anywhere in the input
// that held EVALUATE was judged instead of the query the server runs (F1-34). Each case below was a confirmed bypass
// before the fix, or pins what the fix must keep passing. The personal column vocabulary is the SQL read switch's.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyzeMcpCall, isRowLevelDax } from '../hooks/lib/policy.mjs';
import { personalColumnName } from '../hooks/lib/sql-read.mjs';

const hook = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'hooks', 'pre-tool-use.mjs');
const cfg = { mcp: { powerbiServer: 'powerbi-modeling' } };
const verdict = (r) => (r ? `${r.decision}${r.floor ? '/floor' : r.autoApprovable === false ? '/user' : ''}` : 'none');
const LOCAL = 'PBIDesktop-Sales';
const SESSION = 'mcp-policy';
// The MCP target rule asks before a query or write on a connection the session never confirmed. The hook cases below judge
// the policy on a confirmed one: the session state (this test's own session id) holds LOCAL as the live connection.
const CONFIRMED = {
  [`.claude/logs/.state/${SESSION}.json`]: JSON.stringify({ mcpConnections: [{ mcpServer: 'powerbi-modeling', name: LOCAL, confirmedAt: '2026-10-18T09:00:00.000Z' }] }),
};
const DAX_TOOL = 'mcp__powerbi-modeling__dax_query_operations';

/** The verdict of a write of the modeling server (tier2.test.mjs: mcp). */
const mcp = (tool, request, config = cfg) => verdict(analyzeMcpCall(`mcp__powerbi-modeling__${tool}`, { request }, config));
/**
 * The verdict of a DAX Execute (guard.test.mjs: dax). `request` adds fields to the request, `top` fields next to it; a
 * query of `undefined` leaves the query field out. The extra fields come before the query unless `queryFirst` (the
 * audit's decoys came first, so the first text with EVALUATE was the decoy).
 */
const dax = (query, { maxRows = 20, request = {}, top = {}, config = cfg, queryFirst = false } = {}) => {
  const text = query === undefined ? {} : { query };
  const fields = queryFirst ? { operation: 'Execute', maxRows, ...text, ...request } : { operation: 'Execute', maxRows, ...request, ...text };
  return verdict(analyzeMcpCall(DAX_TOOL, queryFirst ? { request: fields, ...top } : { ...top, request: fields }, config));
};

/** Runs the PreToolUse hook in a temporary project holding `files`, with an optional harness config (tier2.test.mjs). */
function runHook({ files = {}, config, tool_name, tool_input }) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-mcp-policy-'));
  try {
    for (const [rel, content] of Object.entries(files)) {
      fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
      fs.writeFileSync(path.join(dir, rel), content);
    }
    if (config) {
      fs.mkdirSync(path.join(dir, 'hardening'), { recursive: true });
      fs.writeFileSync(path.join(dir, 'hardening', 'harness.config.json'), JSON.stringify(config));
    }
    const r = spawnSync(process.execPath, [hook], {
      input: JSON.stringify({ hook_event_name: 'PreToolUse', session_id: SESSION, tool_name, tool_input }),
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
const LAB = { approvals: { mode: 'lab' } };
const ASK = { approvals: { mode: 'ask' } };

/** Auto (the default) asks and logs no auto approval; lab runs it; ask mode asks (tier2.test.mjs: assertTier2). */
function assertTier2(call, label) {
  const auto = runHook(call);
  assert.equal(auto.decision, 'ask', `auto: ${label}`);
  assert.match(auto.reason, /Critical: auto mode always asks/, label);
  assert.ok(!auto.events.some((e) => e.event === 'auto-approve'), label);
  assert.equal(runHook({ ...call, config: LAB }).decision, 'allow', `lab: ${label}`);
  assert.equal(runHook({ ...call, config: ASK }).decision, 'ask', `ask mode: ${label}`);
  return auto;
}

// ---------------------------------------------------------------- F1-7: comment markers inside strings and names

test('F1-7: a comment marker inside a string, a quoted table name or a bracketed name hides nothing from the row-level check', () => {
  for (const query of [
    // The audit's payloads: the markers sit in string literals and used to remove what lay between them.
    'EVALUATE ROW("a", "/*", "m", CONCATENATEX(Customer, Customer[Customer Name], ", "), "b", "*/")',
    'EVALUATE ROW("a", "/*") EVALUATE Customer EVALUATE ROW("b", "*/")',
    'EVALUATE ROW("a", "//", "m", CONCATENATEX(Customer, Customer[Customer Name], ", ")\n)',
    'EVALUATE ROW("a", "--", "m", CONCATENATEX(Customer, Customer[Customer Name], ", ")\n)',
    'EVALUATE ROW("a", "//" EVALUATE Customer\n)',
    'EVALUATE ROW("a", "--" EVALUATE Customer\n)',
    'EVALUATE ROW("a", "/*", "m", MAXX(Customer, Customer[Email]), "b", "*/")',
    // The same markers in a quoted table name and in a bracketed name (a measure).
    "EVALUATE ROW(\"n\", COUNTROWS('A /*'), \"m\", CONCATENATEX(Customer, Customer[Customer Name], \", \"), \"k\", COUNTROWS('B */'))",
    'EVALUATE ROW("n", [Plan/*], "m", CONCATENATEX(Customer, Customer[Customer Name], ", "), "k", [Plan2*/])',
    'EVALUATE ROW("n", [Plan//x], "m", CONCATENATEX(Customer, Customer[Customer Name], ", ")\n)',
    // The control stays as it was: no markers at all.
    'EVALUATE ROW("m", CONCATENATEX(Customer, Customer[Customer Name], ", "))',
  ]) assert.equal(dax(query, { maxRows: 50 }), 'ask/user', query);
});

test('F1-7: real comments are still comments; a name or a string that holds a marker is not one', () => {
  for (const query of [
    'EVALUATE /* total */ ROW("a", [Sales]) // note -- more',
    'EVALUATE ROW("a", [Sales]) -- it\'s a "note" [x',
    'EVALUATE ROW("a", [Sales]) /* it\'s "quoted" and [open */',
    'EVALUATE ROW("a", [Sales]) // Customer[Email] CONCATENATEX(Customer, Customer[Email], ",")',
    'EVALUATE ROW("a", [Sales]) /* EVALUATE Customer */',
    'EVALUATE ROW("a", [Sales]) // a comment at the very end',
    'EVALUATE\n// the total\nROW("a", [Sales])',
    "EVALUATE SUMMARIZECOLUMNS('Plan -- 2025'[Year], \"N\", [Sales//Plan])",
    'EVALUATE ROW("a", "http://example.test/*", "b", [Sales])',
  ]) assert.equal(dax(query), 'allow', query);
});

test('F1-7: a string, a name or a block comment that never closes cannot be read, so the query asks', () => {
  for (const query of [
    'EVALUATE ROW("a", "oops)',
    'EVALUATE ROW("a", 1) "',
    "EVALUATE SUMMARIZECOLUMNS('Date[Year], \"N\", [Sales])",
    'EVALUATE ROW("a", [Sales)',
    'EVALUATE ROW("a", 1) /* oops',
    'EVALUATE ROW("a", 1) /*',
    'EVALUATE ROW("a", 1) [',
    'EVALUATE ROW("a", "x" "y)',
  ]) assert.equal(dax(query), 'ask/user', query);
  assert.equal(isRowLevelDax('EVALUATE ROW("a", 1) /* oops', {}), true);
  assert.equal(isRowLevelDax('EVALUATE ROW("a", 1) /* closed */', {}), false);
});

test('F1-7: the judge stays fast on long hostile texts (a hook past its timeout lets the call through)', () => {
  const timed = (query) => {
    const started = Date.now();
    const result = isRowLevelDax(query, {});
    assert.ok(Date.now() - started < 2000, `${query.slice(0, 40)}: ${Date.now() - started} ms`);
    return result;
  };
  assert.equal(timed(`EVALUATE ROW("a", "${'['.repeat(100000)}", 1)`), false, 'a long run of "[" in a string');
  assert.equal(timed(`EVALUATE ROW("a", 1) ${'['.repeat(100000)}`), true, 'a long run of "[" that never closes');
  assert.equal(timed(`EVALUATE ROW("a", 1) // ${'x'.repeat(1000000)}`), false, 'a long line comment');
  assert.equal(timed(`EVALUATE ROW(${'"a/*", '.repeat(50000)} 1)`), false, 'many strings that hold a marker');
});

test('hook: a DAX query that hides a CONCATENATEX behind markers inside strings asks in auto mode', () => {
  const call = (query) => ({ files: CONFIRMED, tool_name: DAX_TOOL, tool_input: { request: { operation: 'Execute', connectionName: LOCAL, maxRows: 50, query } } });
  const bypass = runHook(call('EVALUATE ROW("a", "/*", "m", CONCATENATEX(Customer, Customer[Customer Name], ", "), "b", "*/")'));
  assert.equal(bypass.decision, 'ask');
  assert.match(bypass.reason, /Critical: auto mode always asks/);
  assert.ok(!bypass.events.some((e) => e.event === 'auto-approve'));
  assert.equal(runHook(call('EVALUATE ROW("a", "/*", "m", [Sales], "b", "*/")')).decision, 'allow');
});

// ---------------------------------------------------------------- F1-32: where a table's data comes from

const M = 'let Source = Sql.Database("prod-sql01","CRM") in Source';

test('F1-32: a partition source, an M expression or a data source in a table or model write is Tier 2 on a local connection', () => {
  for (const [tool, request] of [
    // The audit's three requests.
    ['table_operations', { operation: 'Update', connectionName: LOCAL, definitions: [{ name: 'Sales', partitions: [{ name: 'Sales', expression: M }] }] }],
    ['table_operations', { operation: 'Create', connectionName: LOCAL, definitions: [{ name: 'Customer CRM', mExpression: M }] }],
    ['model_operations', { operation: 'Update', connectionName: LOCAL, definition: { dataSources: [{ name: 'CRM', connectionString: 'Provider=MSOLEDBSQL;Data Source=prod-sql01' }] } }],
    // Other spellings of the same change.
    ['table_operations', { operation: 'Update', connectionName: LOCAL, definitions: [{ name: 'Sales', partitions: [{ name: 'Sales', source: { type: 'm', expression: M } }] }] }],
    ['table_operations', { operation: 'Update', connectionName: LOCAL, definitions: [{ name: 'Sales', partitions: [{ name: 'Sales', query: 'SELECT * FROM dbo.Sales' }] }] }],
    ['table_operations', { operation: 'Update', connectionName: LOCAL, definitions: [{ name: 'Sales', partition: { name: 'Sales', expression: M } }] }],
    ['table_operations', { operation: 'Update', connectionName: LOCAL, definitions: [{ name: 'Sales', partitions: [{ name: 'Sales', dataSource: 'CRM' }] }] }],
    ['table_operations', { operation: 'Update', connectionName: LOCAL, definitions: [{ name: 'Sales', partitions: [{ name: 'Sales', expressionSource: 'DL_Sales' }] }] }],
    ['table_operations', { operation: 'Update', connectionName: LOCAL, definitions: [{ name: 'Sales', queryGroup: 'Facts' }] }],
    ['table_operations', { operation: 'Update', connectionName: LOCAL, definitions: [{ name: 'Sales', MExpression: M }] }],
    ['table_operations', { operation: 'Update', connectionName: LOCAL, definitions: [{ name: 'Sales', m_expression: M }] }],
    ['model_operations', { operation: 'Update', connectionName: LOCAL, definition: { DataSources: [] } }],
    ['model_operations', { operation: 'Update', connectionName: LOCAL, definition: { expressions: [{ name: 'ServerName', expression: '"prod-sql01"' }] } }],
    ['model_operations', { operation: 'Update', connectionName: LOCAL, definition: { dataSources: [{ name: 'CRM', provider: 'MSOLEDBSQL' }] } }],
    ['column_operations', { operation: 'Create', connectionName: LOCAL, definitions: [{ tableName: 'Sales', name: 'Margin', connectionString: 'Data Source=prod-sql01' }] }],
    // Nested deeper than the request usually is.
    ['table_operations', { operation: 'Update', connectionName: LOCAL, definitions: [{ name: 'Sales', options: { more: { partitions: [{ expression: M }] } } }] }],
  ]) assert.equal(mcp(tool, request), 'ask/user', `${tool} ${JSON.stringify(request)}`);
});

test('F1-32: the Tier 2 reason names the change, and a remote connection stays the floor', () => {
  const request = { operation: 'Update', connectionName: LOCAL, definitions: [{ name: 'Sales', partitions: [{ name: 'Sales', expression: M }] }] };
  const verdictOf = analyzeMcpCall('mcp__powerbi-modeling__table_operations', { request }, cfg);
  assert.match(verdictOf.reason, /^A data source or Power Query change via MCP \(update\) is Tier 2/);
  assert.equal(mcp('table_operations', { ...request, connectionName: 'Fabric-WS-Model' }), 'ask/floor');
  assert.equal(mcp('table_operations', { operation: 'Update', definitions: request.definitions }), 'ask/floor', 'an unnamed connection is the floor');
  // partition_operations keeps its own reason.
  assert.match(analyzeMcpCall('mcp__powerbi-modeling__partition_operations', { request: { ...request, definitions: undefined } }, cfg).reason, /A partition change/);
});

test('F1-32 hook: the audit\'s three requests ask in auto and ask mode and run in lab mode', () => {
  const calls = [
    ['table_operations Update, a partition expression', 'table_operations', { operation: 'Update', connectionName: LOCAL, definitions: [{ name: 'Sales', partitions: [{ name: 'Sales', expression: M }] }] }],
    ['table_operations Create, an mExpression', 'table_operations', { operation: 'Create', connectionName: LOCAL, definitions: [{ name: 'Customer CRM', mExpression: M }] }],
    ['model_operations Update, dataSources', 'model_operations', { operation: 'Update', connectionName: LOCAL, definition: { dataSources: [{ name: 'CRM', connectionString: 'Provider=MSOLEDBSQL;Data Source=prod-sql01' }] } }],
  ];
  for (const [label, tool, request] of calls) {
    const auto = assertTier2({ files: CONFIRMED, tool_name: `mcp__powerbi-modeling__${tool}`, tool_input: { request } }, label);
    assert.match(auto.reason, /A data source or Power Query change/, label);
  }
});

test('F1-32: ordinary model work that carries partitions without a source, or expressions of measures and columns, stays a plain ask', () => {
  for (const [tool, request] of [
    ['table_operations', { operation: 'Create', connectionName: LOCAL, definitions: [{ name: 'New', partitions: [{ mode: 'Import' }] }] }],
    ['table_operations', { operation: 'Create', connectionName: LOCAL, definitions: [{ name: 'New', partitions: [{ name: 'New', mode: 'Import', description: 'x' }] }] }],
    ['table_operations', { operation: 'Update', connectionName: LOCAL, definitions: [{ name: 'Sales', description: 'x' }] }],
    ['table_operations', { operation: 'Update', connectionName: LOCAL, definitions: [{ name: 'Sales', partitions: ['Sales'] }] }],
    ['measure_operations', { operation: 'Create', connectionName: LOCAL, definitions: [{ name: 'Net', expression: 'SUM(Sales[Amount])' }] }],
    ['measure_operations', { operation: 'Update', connectionName: LOCAL, definitions: [{ name: 'Net', expression: 'SUM(Sales[Amount])', formatString: '#,0' }] }],
    ['column_operations', { operation: 'Create', connectionName: LOCAL, definitions: [{ tableName: 'Sales', name: 'Margin', expression: '1' }] }],
    ['calculation_group_operations', { operation: 'Create', connectionName: LOCAL, definitions: [{ name: 'Time', calculationItems: [{ name: 'YTD', expression: 'CALCULATE(SELECTEDMEASURE())' }] }] }],
    ['model_operations', { operation: 'Update', connectionName: LOCAL, definition: { description: 'x' } }],
    ['connection_operations', { operation: 'Connect', connectionString: 'Data Source=localhost:51234' }],
  ]) assert.equal(mcp(tool, request), 'ask', `${tool} ${JSON.stringify(request)}`);
  // Auto mode approves and logs the ordinary create.
  const create = runHook({ files: CONFIRMED, tool_name: 'mcp__powerbi-modeling__table_operations', tool_input: { request: { operation: 'Create', connectionName: LOCAL, definitions: [{ name: 'New', partitions: [{ mode: 'Import' }] }] } } });
  assert.equal(create.decision, 'allow');
  assert.ok(create.events.some((e) => e.event === 'auto-approve'));
});

// ---------------------------------------------------------------- F1-33: a person table's name column

test('F1-33: a name column of a person table asks, wherever the query uses it', () => {
  for (const query of [
    // The audit's payloads.
    'EVALUATE SUMMARIZECOLUMNS(Customer[Name], "Sales", [Sales Amount])',
    'EVALUATE VALUES(Customer[Name])',
    "EVALUATE SUMMARIZECOLUMNS('Customer'[Name], \"Sales\", [Sales Amount])",
    'EVALUATE SUMMARIZECOLUMNS(Employee[Name], "Sales", [Sales Amount])',
    'EVALUATE SUMMARIZECOLUMNS(Customer[Customer First Name], "Sales", [Sales Amount])',
    'EVALUATE SUMMARIZECOLUMNS(Employee[Display Name], "Sales", [Sales Amount])',
    // Other person tables and other name columns.
    'EVALUATE SUMMARIZECOLUMNS(Customer [Name], "Sales", [Sales Amount])',
    "EVALUATE SUMMARIZECOLUMNS('Dim Customer'[Display Name], \"Sales\", [Sales Amount])",
    'EVALUATE SUMMARIZECOLUMNS(Customer[Surname], "Sales", [Sales Amount])',
    'EVALUATE SUMMARIZECOLUMNS(Customer[Full Name], "Sales", [Sales Amount])',
    'EVALUATE SUMMARIZECOLUMNS(Customer[FirstName], "Sales", [Sales Amount])',
    'EVALUATE SUMMARIZECOLUMNS(Salesperson[Name], "Sales", [Sales Amount])',
    'EVALUATE SUMMARIZECOLUMNS(Patient[Name], "Sales", [Sales Amount])',
    'EVALUATE SUMMARIZECOLUMNS(Users[Name], "Sales", [Sales Amount])',
    "EVALUATE SUMMARIZECOLUMNS('Sales Rep'[Name], \"Sales\", [Sales Amount])",
    'EVALUATE SUMMARIZECOLUMNS(Sales[Client Name], "Sales", [Sales Amount])',
    'EVALUATE SUMMARIZECOLUMNS(Sales[Member Name], "Sales", [Sales Amount])',
    // Not only as a grouping column: a name per group through an aggregate, or the name inside a filter.
    'EVALUATE ADDCOLUMNS(VALUES(Customer[Region]), "who", CALCULATE(MAX(Customer[Name])))',
    'EVALUATE ROW("who", MAXX(Customer, Customer[Name]))',
    'EVALUATE ROW("n", COUNTROWS(FILTER(Customer, Customer[Name] = "Contoso")))',
    // A string with a "[" cannot pair with a later bracket and hide the column; a listed name inside it is still found.
    'EVALUATE ROW("a[", MAXX(Customer, Customer[Name]))',
    'EVALUATE ROW("a[", MAXX(Customer, Customer[Fax]))',
    'EVALUATE ROW("a[", MAXX(Customer, Customer[Ad]))',
  ]) assert.equal(dax(query), 'ask/user', query);
});

test('F1-33: each name of a person asks in a person table: the phrases, their spellings and longer names that end in one', () => {
  const column = (table, col) => dax(`EVALUATE SUMMARIZECOLUMNS(${table}[${col}], "S", [Sales])`);
  for (const table of ['Customer', "'Dim Customer'", 'Employee', 'Salesperson', 'Patient', 'Users', "'Sales Rep'"]) {
    for (const col of ['Name', 'Full Name', 'First Name', 'Last Name', 'Middle Name', 'Given Name', 'Family Name', 'Display Name', 'Nick Name',
      'Nickname', 'Maiden Name', 'Legal Name', 'Preferred Name', 'Contact Name', 'Person Name']) {
      assert.equal(column(table, col), 'ask/user', `${table}[${col}]`);
    }
  }
  // The table's own word and Name, other spellings, a plural or numbered column, a longer name that ends in a phrase.
  for (const [table, col] of [
    ['Customer', 'Customer Name'], ['Employee', 'Employee Name'], ['Patient', 'Patient Name'], ['Student', 'Student Name'], ['Users', 'User Name'],
    ['Customer', 'DisplayName'], ['Customer', 'display_name'], ['Customer', 'Display-Name'], ['Customer', 'DISPLAY NAME'], ['Customer', 'Dïsplay Name'],
    ['Customer', 'Displayname'], ['Customer', 'Names'], ['Customer', 'Name2'], ['Customer', 'Display Names'],
    ['Customer', 'Customer First Name'], ['Employee', 'Employee Last Name'], ['Customer', 'Billing Legal Name'],
    ['Customer', 'Primary Contact Name'], ['Customer', 'Previous Customer Name'], ['Employee', 'Employee Preferred Name'],
  ]) assert.equal(column(table, col), 'ask/user', `${table}[${col}]`);
});

test('F1-33: Product[Name], the place, segment and organisation names of a person table, counts of names and unqualified metadata names pass', () => {
  for (const query of [
    'EVALUATE SUMMARIZECOLUMNS(Product[Name], "Sales", [Sales Amount])',
    'EVALUATE SUMMARIZECOLUMNS(Product[Display Name], "Sales", [Sales Amount])',
    "EVALUATE SUMMARIZECOLUMNS('Date'[Month Name], \"Sales\", [Sales Amount])",
    "EVALUATE SUMMARIZECOLUMNS('T'[Hotel Name], \"Sales\", [Sales Amount])",
    'EVALUATE SUMMARIZECOLUMNS(Store[Name], "Sales", [Sales Amount])',
    'EVALUATE SUMMARIZECOLUMNS(Geography[Country Name], "Sales", [Sales Amount])',
    'EVALUATE SUMMARIZECOLUMNS(Customer[Country], "Sales", [Sales Amount])',
    // A person table's other columns that end in Name are places, segments and organisations, not a person's.
    'EVALUATE SUMMARIZECOLUMNS(Customer[Country Name], "Sales", [Sales Amount])',
    'EVALUATE SUMMARIZECOLUMNS(Customer[City Name], "Sales", [Sales Amount])',
    'EVALUATE SUMMARIZECOLUMNS(Customer[Region Name], "Sales", [Sales Amount])',
    'EVALUATE SUMMARIZECOLUMNS(Customer[State Name], "Sales", [Sales Amount])',
    'EVALUATE SUMMARIZECOLUMNS(Employee[Department Name], "Sales", [Sales Amount])',
    'EVALUATE SUMMARIZECOLUMNS(Employee[Branch Name], "Sales", [Sales Amount])',
    "EVALUATE SUMMARIZECOLUMNS('Customer Segment'[Segment Name], \"Sales\", [Sales Amount])",
    "EVALUATE SUMMARIZECOLUMNS('Sales Rep'[Territory Name], \"Sales\", [Sales Amount])",
    // The person table is only named in the query; the name column belongs to another table.
    'EVALUATE SUMMARIZECOLUMNS(Product[Name], "Customers", CALCULATE(COUNTROWS(Customer)))',
    // Counting names returns none of them.
    'EVALUATE ROW("n", DISTINCTCOUNT(Customer[Name]))',
    "EVALUATE ROW(\"n\", DISTINCTCOUNT('Customer'[Name]))",
    'EVALUATE ROW("n", [Customer Count], "m", [Active Members])',
    'EVALUATE SELECTCOLUMNS(FILTER(INFO.VIEW.COLUMNS(), [Table] = "Customer"), "c", [Name])',
    // A measure that happens to hold a word of the SQL read switch's list is no column (it is named without a table).
    'EVALUATE ROW("Mobile", [Mobile Sales], "Mail", [Direct Mail Sales])',
    'EVALUATE VAR n = 1 RETURN ROW("Mobile", [Mobile Sales] * n)',
  ]) assert.equal(dax(query), 'allow', query);
});

test('F1-33: a name on the SQL read switch\'s list asks as a word inside a longer name, not as a part of a word', () => {
  const column = (col, config = cfg) => dax(`EVALUATE SUMMARIZECOLUMNS('T'[${col}], "S", [Sales])`, { config });
  for (const col of ['Customer First Name', 'CustomerFirstName', 'Home Fax', 'Mobile Number', 'Billing Street Line', 'Primary Last Name']) {
    assert.equal(column(col), 'ask/user', col);
  }
  for (const col of ['Dobby', 'Mailbox', 'Passwordless', 'Faxon', 'Region', 'Hotel Name', 'ProductName', 'Hotels', 'Business', 'Ad Campaign']) {
    assert.equal(column(col), 'allow', col);
  }
  // The project's own list counts the same way.
  const listed = { ...cfg, sources: { sqlRead: { personalColumns: ['Loyalty Code'] } } };
  assert.equal(column('Loyalty Code Value'), 'allow');
  assert.equal(column('Loyalty Code Value', listed), 'ask/user');
  assert.equal(column('LoyaltyCodeValue', listed), 'ask/user');
  assert.equal(column('Loyalty Codex', listed), 'allow');
});

test('F1-33: the DAX guard asks about every name the SQL judge calls personal, in the words they share', () => {
  const column = (col) => dax(`EVALUATE SUMMARIZECOLUMNS(Customer[${col}], "S", [Sales])`);
  for (const col of ['Telefon', 'Müşteri Adı', 'Musteri Adi', 'Vorname', 'Prénom', 'Correo', 'Cognome', 'Doğum Tarihi', 'TC Kimlik No',
    'FirstNames', 'Mobiles', 'Faxes', 'Streets', 'Passwords', 'Email2', 'E-Mail Domain', 'User_Name']) {
    assert.equal(column(col), 'ask/user', col);
  }
  for (const col of ['Telefon', 'Müşteri Adı', 'Vorname', 'Prénom', 'FirstNames', 'Mobiles', 'Passwords']) {
    assert.equal(personalColumnName(col), true, `the SQL judge: ${col}`);
  }
  assert.equal(dax("EVALUATE ROW(\"n\", DISTINCTCOUNT(Customer[Telefon]))"), 'allow', 'counting a personal column returns no value of it');
});

// ---------------------------------------------------------------- F1-34: the query the server runs

test('F1-34: another text with EVALUATE next to the query, or no query field, makes the call ask', () => {
  const aggregate = 'EVALUATE ROW("n", [Sales])';
  assert.equal(dax(aggregate), 'allow');
  for (const [label, query, options] of [
    // The audit's decoys: a harmless EVALUATE in another field, and a row-level query in the query field.
    ['description in the request', 'EVALUATE Customer', { request: { description: 'EVALUATE ROW("n", 1)' } }],
    ['sibling of the request', 'EVALUATE Customer', { top: { note: 'EVALUATE ROW("n", 1)' } }],
    // The decoy next to a harmless query asks too: the guard cannot tell which text the server reads.
    ['description next to an aggregate', aggregate, { request: { description: 'EVALUATE ROW("n", 1)' } }],
    ['lower case decoy', aggregate, { request: { note: 'evaluate customer' } }],
    ['decoy in a nested object', aggregate, { request: { options: { notes: { first: 'EVALUATE ROW("n", 1)' } } } }],
    ['decoy in a list', aggregate, { request: { notes: ['a', 'EVALUATE ROW("n", 1)'] } }],
    ['decoy as a second query field', aggregate, { request: { Query: 'EVALUATE ROW("n", 2)' } }],
    ['decoy under another spelling of the field', aggregate, { request: { daxQuery: 'EVALUATE Customer' } }],
    // No query field at all: the EVALUATE text sits under some other name.
    ['no query field, a text field', undefined, { request: { daxText: 'EVALUATE ROW("n", 1)' } }],
    ['no query field, a list of queries', undefined, { request: { queries: ['EVALUATE ROW("n", 1)'] } }],
    ['no query field, a top-level text', undefined, { top: { text: 'EVALUATE ROW("n", 1)' } }],
    ['a query that is not text', ['EVALUATE ROW("n", 1)'], {}],
    ['a query without EVALUATE', 'DEFINE MEASURE Sales[Test] = 1', {}],
    ['an empty query', '', {}],
  ]) {
    for (const queryFirst of [false, true]) assert.equal(dax(query, { ...options, queryFirst }), 'ask/user', `${label}, query ${queryFirst ? 'first' : 'last'}`);
  }
});

test('F1-34: the query field is read as query or Query, like maxRows and connectionName; harmless extra fields pass', () => {
  const aggregate = 'EVALUATE ROW("n", [Sales])';
  assert.equal(dax(undefined, { request: { Query: aggregate } }), 'allow');
  assert.equal(dax(aggregate, { request: { description: 'total sales for the new measure', includeStatistics: false } }), 'allow');
  assert.equal(dax(aggregate, { top: { note: 'a note without the keyword' } }), 'allow');
  // An EVALUATE inside the query's own string literal is part of the query, not a second text.
  assert.equal(dax('EVALUATE ROW("s", "EVALUATE Customer")'), 'allow');
  // Nesting too deep to read asks; a few levels pass.
  const nested = (depth) => Array.from({ length: depth }).reduce((inner) => ({ more: inner }), 'x');
  assert.equal(dax(aggregate, { request: { options: nested(3) } }), 'allow');
  assert.equal(dax(aggregate, { request: { options: nested(14) } }), 'ask/user');
  // maxRows is still required.
  assert.equal(dax(aggregate, { maxRows: null }), 'ask/user');
  assert.equal(dax(aggregate, { maxRows: 51 }), 'ask/user');
});

test('hook: a decoy EVALUATE next to a row-level query asks in auto mode; the plain aggregate runs', () => {
  const call = (query, extra = {}) => ({ files: CONFIRMED, tool_name: DAX_TOOL, tool_input: { request: { operation: 'Execute', connectionName: LOCAL, maxRows: 50, ...extra, query } } });
  const decoy = runHook(call('EVALUATE Customer', { description: 'EVALUATE ROW("n", 1)' }));
  assert.equal(decoy.decision, 'ask');
  assert.match(decoy.reason, /Critical: auto mode always asks/);
  assert.ok(!decoy.events.some((e) => e.event === 'auto-approve'));
  assert.equal(runHook(call('EVALUATE ROW("n", [Sales])')).decision, 'allow');
});
