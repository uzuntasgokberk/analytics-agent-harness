// Audit of fe1dd6f (2026-10-16): the guard's technical controls were weaker than AGENTS.md's Tier 2 rule. In approvals
// mode auto, MCP deletes, relationship and partition writes on a local model, relationships.tmdl, a report's binding,
// removed TMDL declarations and reference-copy edits were plain asks that auto approval passed. Tier 2 now always asks
// in auto and ask mode (askUser: lab mode still runs it); ordinary model work keeps flowing in auto.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { DEFAULT_CONFIG } from '../hooks/lib/common.mjs';
import { claudeMcpName } from '../hooks/lib/host-vscode.mjs';
import { analyzeMcpCall, isPowerBiMcp } from '../hooks/lib/policy.mjs';
import { extractTmdlDeclarations, removedDeclarations, tmdlRelationshipFacts } from '../hooks/lib/validators.mjs';

const hook = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'hooks', 'pre-tool-use.mjs');
const cfg = { mcp: { powerbiServer: 'powerbi-modeling' } };
const verdict = (r) => (r ? `${r.decision}${r.floor ? '/floor' : r.autoApprovable === false ? '/user' : ''}` : 'none');
const mcp = (tool, request, server = 'powerbi-modeling') => verdict(analyzeMcpCall(`mcp__${server}__${tool}`, { request }, cfg));
const LOCAL = 'PBIDesktop-Sales';
// The MCP target rule (hooks/lib/mcp-state.mjs) asks before a query or write on a connection the session never
// confirmed, with or without a state file. The hook tests below judge the policy on a confirmed target, so their
// session state (session_id "tier2") holds LOCAL as the one live connection on the server.
const CONFIRMED = {
  '.claude/logs/.state/tier2.json': JSON.stringify({ mcpConnections: [{ mcpServer: 'powerbi-modeling', name: LOCAL, confirmedAt: '2026-10-16T09:00:00.000Z' }] }),
};

/** Runs the PreToolUse hook in a temporary project holding `files`, with an optional harness config. */
function runHook({ files = {}, config, tool_name, tool_input }) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-tier2-'));
  try {
    for (const [rel, content] of Object.entries(files)) {
      fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
      fs.writeFileSync(path.join(dir, rel), content);
    }
    if (config) {
      fs.mkdirSync(path.join(dir, 'hardening'), { recursive: true });
      fs.writeFileSync(path.join(dir, 'hardening', 'harness.config.json'), JSON.stringify(config));
    }
    const ti = tool_input.file_path ? { ...tool_input, file_path: path.join(dir, tool_input.file_path) } : tool_input;
    const r = spawnSync(process.execPath, [hook], {
      input: JSON.stringify({ hook_event_name: 'PreToolUse', session_id: 'tier2', tool_name, tool_input: ti }),
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

/** Auto (the default) asks and logs no auto approval; lab runs it; ask mode asks. */
function assertTier2(call, label) {
  const auto = runHook(call);
  assert.equal(auto.decision, 'ask', `auto: ${label}`);
  assert.match(auto.reason, /Critical: auto mode always asks/, label);
  assert.ok(!auto.events.some((e) => e.event === 'auto-approve'), label);
  assert.equal(runHook({ ...call, config: LAB }).decision, 'allow', `lab: ${label}`);
  assert.equal(runHook({ ...call, config: ASK }).decision, 'ask', `ask mode: ${label}`);
}

// ---------------------------------------------------------------- MCP on a local connection

test('MCP local: the audit\'s reproductions are Tier 2 now (askUser, not the floor)', () => {
  assert.equal(mcp('measure_operations', { operation: 'Delete', connectionName: LOCAL, names: ['X'] }), 'ask/user');
  assert.equal(mcp('relationship_operations', { operation: 'Update', connectionName: LOCAL }), 'ask/user');
  assert.equal(mcp('partition_operations', { operation: 'Refresh', connectionName: LOCAL }), 'ask/user');
  assert.equal(mcp('table_operations', { operation: 'Frobnicate', connectionName: LOCAL }), 'ask/user');
});

test('MCP local: renames, moves, deletes, relationships, partitions, expressions, refresh, storage mode and database writes are Tier 2', () => {
  for (const [tool, request] of [
    ['table_operations', { operation: 'Rename', connectionName: LOCAL, name: 'Sales', newName: 'Fact Sales' }],
    ['measure_operations', { operation: 'Move', connectionName: LOCAL, names: ['Net'], destinationTable: 'Measures' }],
    ['measure_operations', { operation: 'Update', connectionName: LOCAL, definitions: [{ name: 'Net', newName: 'Net Sales' }] }],
    ['column_operations', { operation: 'Delete', connectionName: LOCAL }],
    ['user_hierarchy_operations', { operation: 'DeleteLevel', connectionName: LOCAL }],
    ['relationship_operations', { operation: 'Create', connectionName: LOCAL }],
    ['relationship_operations', { operation: 'Activate', connectionName: LOCAL }],
    ['partition_operations', { operation: 'Update', connectionName: LOCAL }],
    ['named_expression_operations', { operation: 'Update', connectionName: LOCAL, name: 'ServerName' }],
    ['query_group_operations', { operation: 'Create', connectionName: LOCAL }],
    ['table_operations', { operation: 'Refresh', connectionName: LOCAL }],
    ['model_operations', { operation: 'Refresh', connectionName: LOCAL }],
    ['table_operations', { operation: 'Update', connectionName: LOCAL, definitions: [{ name: 'Sales', mode: 'DirectQuery' }] }],
    ['model_operations', { operation: 'Update', connectionName: LOCAL, definition: { defaultMode: 'DirectQuery' } }],
    ['table_operations', { operation: 'Update', connectionName: LOCAL, definitions: [{ name: 'Sales', refreshPolicy: { policyType: 'Basic' } }] }],
    ['database_operations', { operation: 'Update', connectionName: LOCAL }],
    ['database_operations', { operation: 'ImportFromTmdlFolder', connectionName: LOCAL }],
    ['database_operations', { operation: 'ExportToTmdlFolder', connectionName: LOCAL }],
    ['trace_operations', { operation: 'Start', connectionName: LOCAL }],
    ['dax_query_operations', { operation: 'ClearCache', connectionName: LOCAL }],
    ['measure_operations', { connectionName: LOCAL }],
  ]) assert.equal(mcp(tool, request), 'ask/user', `${tool} ${JSON.stringify(request)}`);
});

test('MCP local: ordinary model work stays a plain ask (auto approves and logs it)', () => {
  for (const [tool, request] of [
    ['measure_operations', { operation: 'Create', connectionName: LOCAL, definitions: [{ name: 'Net', expression: 'SUM(Sales[Amount])' }] }],
    ['measure_operations', { operation: 'Update', connectionName: LOCAL, definitions: [{ name: 'Net', description: 'Net sales', formatString: '#,0' }] }],
    ['column_operations', { operation: 'Create', connectionName: LOCAL, definitions: [{ tableName: 'Sales', name: 'Margin', expression: '1' }] }],
    ['table_operations', { operation: 'Create', connectionName: LOCAL, definitions: [{ name: 'New', partitions: [{ mode: 'Import' }] }] }],
    ['table_operations', { operation: 'CreateFieldParameter', connectionName: LOCAL }],
    ['table_operations', { operation: 'Update', connectionName: LOCAL, definitions: [{ name: 'Sales', description: 'x' }] }],
    ['user_hierarchy_operations', { operation: 'Create', connectionName: LOCAL }],
    ['perspective_operations', { operation: 'Update', connectionName: LOCAL }],
    ['culture_operations', { operation: 'Create', connectionName: LOCAL }],
    ['object_translation_operations', { operation: 'Update', connectionName: LOCAL }],
    ['calculation_group_operations', { operation: 'Create', connectionName: LOCAL }],
    ['function_operations', { operation: 'Create', connectionName: LOCAL }],
    ['model_operations', { operation: 'Update', connectionName: LOCAL, definition: { description: 'x' } }],
    ['transaction_operations', { operation: 'Begin', connectionName: LOCAL }],
    ['transaction_operations', { operation: 'Commit', connectionName: LOCAL }],
    ['connection_operations', { operation: 'Connect', connectionString: 'Data Source=localhost:51234' }],
  ]) assert.equal(mcp(tool, request), 'ask', `${tool} ${JSON.stringify(request)}`);
});

test('MCP: remote stays the floor, RLS stays askUser, members and deploy stay denied, reads stay allowed', () => {
  assert.equal(mcp('measure_operations', { operation: 'Delete', connectionName: 'Fabric-WS-Model' }), 'ask/floor');
  assert.equal(mcp('measure_operations', { operation: 'Create' }), 'ask/floor');
  assert.equal(mcp('relationship_operations', { operation: 'Update', connectionName: 'Remote-ssas' }), 'ask/floor');
  assert.equal(mcp('security_role_operations', { operation: 'Update', connectionName: LOCAL, definitions: [{ name: 'R' }] }), 'ask/user');
  assert.equal(mcp('security_role_operations', { operation: 'Update', connectionName: LOCAL, definitions: [{ name: 'R', members: [{ memberName: 'x' }] }] }), 'deny');
  assert.equal(mcp('database_operations', { operation: 'DeployToFabric', connectionName: LOCAL }), 'deny');
  assert.equal(mcp('relationship_operations', { operation: 'List', connectionName: LOCAL }), 'allow');
  assert.equal(mcp('measure_operations', { operation: 'Get', connectionName: LOCAL }), 'allow');
});

test('hook: a Tier 2 MCP write on a local model asks in auto mode; an ordinary one is approved and logged', () => {
  const call = (operation) => ({ files: CONFIRMED, tool_name: 'mcp__powerbi-modeling__measure_operations', tool_input: { request: { operation, connectionName: LOCAL, names: ['X'] } } });
  assertTier2(call('Delete'), 'measure Delete');
  const create = runHook(call('Create'));
  assert.equal(create.decision, 'allow');
  assert.ok(create.events.some((e) => e.event === 'auto-approve'));
});

// ---------------------------------------------------------------- files

const REL = 'M.SemanticModel/definition/relationships.tmdl';
const REL_TEXT = "relationship a1\n\tfromColumn: Sales.'Customer Key'\n\ttoColumn: Customer.'Customer Key'\n";
const PBIR = 'M.Report/definition.pbir';
const pbirText = (ref) => `${JSON.stringify({ version: '4.0', datasetReference: ref }, null, 2)}\n`;
const BY_PATH = { byPath: { path: '../M.SemanticModel' } };
const TABLE = 'M.SemanticModel/definition/tables/Sales.tmdl';
const TABLE_TEXT = "table Sales\n\n\tmeasure 'Net Sales' = SUM(Sales[Amount])\n\n\tmeasure Old = 1\n";

test('files: an edit of relationships.tmdl, or a relationship declared in another TMDL file, is Tier 2', () => {
  assertTier2({ files: { [REL]: REL_TEXT }, tool_name: 'Edit', tool_input: { file_path: REL, old_string: 'a1', new_string: 'a2' } }, 'relationships.tmdl edit');
  assertTier2({ tool_name: 'Write', tool_input: { file_path: REL, content: REL_TEXT } }, 'a new relationships.tmdl');
  assertTier2({
    files: { [TABLE]: TABLE_TEXT },
    tool_name: 'Edit',
    tool_input: { file_path: TABLE, old_string: 'measure Old = 1\n', new_string: "measure Old = 1\n\nrelationship r9\n\tfromColumn: Sales.'Date Key'\n\ttoColumn: Date.'Date Key'\n" },
  }, 'a relationship in a table file');
});

test('files: changing a report\'s datasetReference is Tier 2; formatting it, or a new report, is routine', () => {
  for (const ref of [{ byPath: { path: '../Other.SemanticModel' } }, { byConnection: { connectionString: 'Data Source=powerbi://api.powerbi.com/v1.0/myorg/WS' } }, {}]) {
    assertTier2({ files: { [PBIR]: pbirText(BY_PATH) }, tool_name: 'Write', tool_input: { file_path: PBIR, content: pbirText(ref) } }, JSON.stringify(ref));
  }
  assertTier2({ files: { [PBIR]: pbirText(BY_PATH) }, tool_name: 'Edit', tool_input: { file_path: PBIR, old_string: '../M.SemanticModel', new_string: '../N.SemanticModel' } }, 'byPath edit');
  const compact = runHook({ files: { [PBIR]: pbirText(BY_PATH) }, tool_name: 'Write', tool_input: { file_path: PBIR, content: JSON.stringify({ datasetReference: BY_PATH, version: '4.0' }) } });
  assert.equal(compact.decision, 'allow', 'same binding, other formatting and key order');
  const version = runHook({ files: { [PBIR]: pbirText(BY_PATH) }, tool_name: 'Edit', tool_input: { file_path: PBIR, old_string: '"4.0"', new_string: '"4.1"' } });
  assert.equal(version.decision, 'allow', 'another property');
  assert.equal(runHook({ tool_name: 'Write', tool_input: { file_path: PBIR, content: pbirText(BY_PATH) } }).decision, 'allow', 'a new report');
});

test('files: removing or renaming a TMDL declaration and editing a reference copy are Tier 2; adding a measure is routine', () => {
  assertTier2({ files: { [TABLE]: TABLE_TEXT }, tool_name: 'Edit', tool_input: { file_path: TABLE, old_string: '\n\tmeasure Old = 1\n', new_string: '\n' } }, 'removed measure');
  assertTier2({ files: { [TABLE]: TABLE_TEXT }, tool_name: 'Edit', tool_input: { file_path: TABLE, old_string: 'measure Old', new_string: 'measure Older' } }, 'renamed measure');
  const copy = 'docs/sources/Cube/definition/tables/Sales.tmdl';
  assertTier2({ files: { [copy]: TABLE_TEXT }, tool_name: 'Edit', tool_input: { file_path: copy, old_string: 'Old = 1', new_string: 'Old = 2' } }, 'reference copy');
  const added = runHook({ files: { [TABLE]: TABLE_TEXT }, tool_name: 'Edit', tool_input: { file_path: TABLE, old_string: 'measure Old = 1\n', new_string: 'measure Old = 1\n\n\tmeasure New = 2\n' } });
  assert.equal(added.decision, 'allow');
  assert.ok(added.reason.includes('auto mode: routine project file edit'), added.reason);
});

// ---------------------------------------------------------------- the modeling server under another name

test('MCP: the modeling server is recognised by its tool names, so a renamed server\'s deploy is denied', () => {
  for (const server of ['powerbi-authoring-local', 'my-pbi']) {
    assert.equal(mcp('database_operations', { operation: 'Deploy' }, server), 'deny', server);
    assert.equal(mcp('database_operations', { operation: 'DeployToFabric', connectionName: LOCAL }, server), 'deny', server);
    assert.equal(mcp('measure_operations', { operation: 'Delete', connectionName: LOCAL }, server), 'ask/user', server);
    assert.equal(mcp('measure_operations', { operation: 'Create', connectionName: LOCAL }, server), 'ask', server);
    assert.equal(mcp('table_operations', { operation: 'List' }, server), 'allow', server);
  }
  assert.equal(isPowerBiMcp('mcp__my-pbi__dax_query_operations', cfg), true);
  assert.equal(isPowerBiMcp('mcp__my-pbi__get_weather', cfg), false, 'another tool name is not the modeling vocabulary');
  assert.equal(isPowerBiMcp('mcp__sqlserver__query', cfg), false);
  for (const server of ['mssql', 'fabric-warehouse', 'postgres']) {
    assert.equal(isPowerBiMcp(`mcp__${server}__table_operations`, cfg), false, `${server}: a database-looking name keeps the SQL policy`);
    assert.equal(mcp('table_operations', { operation: 'List' }, server), 'ask/floor', server);
  }
  assert.equal(isPowerBiMcp('mcp__warehouse__database_operations', { ...cfg, sources: { sqlRead: { mcpServers: ['Warehouse'] } } }), false,
    'a server the SQL read switch names keeps the SQL policy');
});

test('config: powerbi-authoring-local is a default name; a user\'s single powerbiServer still counts next to the list', () => {
  assert.deepEqual(DEFAULT_CONFIG.mcp.powerbiServers, ['powerbi-modeling', 'powerbi-authoring-local']);
  assert.equal(DEFAULT_CONFIG.mcp.powerbiServer, 'powerbi-modeling');
  assert.equal(isPowerBiMcp('mcp__powerbi-authoring-local__custom_tool', DEFAULT_CONFIG), true);
  // As loadConfig merges { "mcp": { "powerbiServer": "my_pbi" } } over the defaults.
  const merged = { mcp: { ...DEFAULT_CONFIG.mcp, powerbiServer: 'my_pbi' } };
  assert.equal(isPowerBiMcp('mcp__my_pbi__custom_tool', merged), true);
  assert.equal(claudeMcpName('mcp_my_pbi_measure_operations', merged), 'mcp__my_pbi__measure_operations', 'VS Code names keep the custom server');
  assert.equal(claudeMcpName('mcp_powerbi-autho_database_operations', merged), 'mcp__powerbi-authoring-local__database_operations');
});

test('hook: a deploy through the server name of Microsoft\'s sample is denied', () => {
  const r = runHook({ tool_name: 'mcp__powerbi-authoring-local__database_operations', tool_input: { request: { operation: 'Deploy' } } });
  assert.equal(r.decision, 'deny');
});

// ---------------------------------------------------------------- DAX: TOPN shape, personal columns, INFO metadata

const dax = (query, config = cfg, maxRows = 20) => verdict(analyzeMcpCall('mcp__powerbi-modeling__dax_query_operations', { request: { operation: 'Execute', maxRows, query } }, config));

test('DAX: TOPN, SAMPLE and TOPNSKIP over a table\'s rows are row-level; over a grouped result they pass', () => {
  for (const query of [
    'EVALUATE TOPN(5, Customer)',
    "EVALUATE TOPN ( 5, 'Customer' )",
    'EVALUATE TOPN(10, VALUES(Customer))',
    'EVALUATE TOPN(10, ALL(Customer))',
    'EVALUATE TOPN(5, FILTER(Customer, Customer[City] = "Ankara"))',
    "EVALUATE TOPN(5, CALCULATETABLE(Sales, 'Date'[Year] = 2025), Sales[Amount], DESC)",
    'EVALUATE VAR t = TOPN(3, Sales) RETURN t',
    'EVALUATE SAMPLE(5, Sales, Sales[Amount])',
    'EVALUATE TOPNSKIP(5, 0, Customer)',
    'EVALUATE TOPN(10, SUMMARIZECOLUMNS(Customer[Customer Key], "S", [Sales]), [S])',
  ]) assert.equal(dax(query), 'ask/user', query);
  for (const query of [
    "EVALUATE TOPN(5, SUMMARIZECOLUMNS('Product'[Category], \"S\", [Sales]), [S])",
    "EVALUATE TOPN(500, SUMMARIZECOLUMNS('Product'[Category], \"S\", [Sales]), [S])",
    "EVALUATE TOPN(10, VALUES('Product'[Category]))",
    "EVALUATE TOPN(3, GROUPBY(Sales, 'Product'[Category]))",
    'EVALUATE TOPN(1, ROW("a", 1))',
    "EVALUATE SAMPLE(10, SUMMARIZECOLUMNS('Date'[Year], \"N\", [Net Sales]), 'Date'[Year])",
  ]) assert.equal(dax(query), 'allow', query);
});

test('DAX: Turkish and other non-English personal column names ask; product names and counts pass', () => {
  assert.equal(dax("EVALUATE VALUES('Musteri'[Ad Soyad])"), 'ask/user');
  assert.equal(dax("EVALUATE SUMMARIZECOLUMNS('Musteri'[Telefon], \"S\", [Sales])"), 'ask/user');
  for (const col of ['Ad', 'Soyad', 'AdSoyad', 'Adı Soyadı', 'İsim', 'ISIM', 'İsim Soyisim', 'TELEFON', 'Cep Telefonu', 'Tel', 'Tel No',
    'E-Posta', 'Eposta Adresi', 'TC', 'TC Kimlik No', 'TCKN', 'TCKimlikNo', 'Kimlik No', 'Adres', 'Fatura Adresi', 'Doğum Tarihi',
    'Dogum Tarihi', 'Maaş', 'Maas', 'Pasaport No', 'IBAN', 'Kullanıcı Adı', 'Kullanici Adi', 'KULLANICI ADI', 'Müşteri Adı',
    'Musteri Adi', 'MusteriAdi', 'Personel Adı', 'Çalışan Adı', 'Calisan Adi', 'Email', 'Vorname', 'Geburtsdatum', 'Prénom',
    'Teléfono', 'First Name', 'Mobile']) {
    assert.equal(dax(`EVALUATE SUMMARIZECOLUMNS('T'[${col}], "S", [Sales])`), 'ask/user', col);
  }
  for (const col of ['Ürün Adı', 'Urun Adi', 'Ürün İsmi', 'Adet', 'Satış Adedi', 'Hotel', 'Kategori', 'Ad Campaign', 'Bölge', 'Şehir',
    'Match Type', 'Category', 'GSM', 'Hotel Name']) {
    assert.equal(dax(`EVALUATE SUMMARIZECOLUMNS('T'[${col}], "S", [Sales])`), 'allow', col);
  }
  assert.equal(dax("EVALUATE ROW(\"n\", DISTINCTCOUNT('Musteri'[Telefon]))"), 'allow', 'counting a personal column returns no value of it');
});

test('DAX: the SQL read switch\'s personal column list counts for DAX too', () => {
  const query = "EVALUATE SUMMARIZECOLUMNS('Staff'[Sicil], \"S\", [Sales])";
  assert.equal(dax(query), 'allow');
  const listed = { ...cfg, sources: { sqlRead: { personalColumns: ['Sicil', 'loyalty_card'] } } };
  assert.equal(dax(query, listed), 'ask/user');
  assert.equal(dax("EVALUATE VALUES('Customer'[Loyalty Card])", listed), 'ask/user', 'compared as identifier keys');
});

test('DAX: metadata queries built on INFO functions pass with maxRows; data mixed in, or connection strings, ask', () => {
  for (const query of [
    'EVALUATE INFO.VIEW.COLUMNS()',
    'EVALUATE SELECTCOLUMNS(FILTER(INFO.VIEW.COLUMNS(), [Table] = "Sales"), "c", [Name])',
    'EVALUATE SELECTCOLUMNS(FILTER(INFO.VIEW.COLUMNS(), [Table] = "Sales"), "Column", [Name], "Type", [DataType]) ORDER BY [Column]',
    'EVALUATE TOPN(0, INFO.VIEW.COLUMNS())',
    'EVALUATE ADDCOLUMNS(INFO.VIEW.TABLES(), "Hidden", NOT [IsHidden])',
    'EVALUATE FILTER(INFO.FUNCTIONS(), LEFT([FUNCTION_NAME], 5) = "INFO.")',
    'EVALUATE info.view.measures()',
    'EVALUATE ROW("Tables", COUNTROWS(INFO.VIEW.TABLES()), "Columns", COUNTROWS(INFO.VIEW.COLUMNS()))',
    'DEFINE VAR _q = "EVALUATE Customer" EVALUATE INFO.DEPENDENCIES("QUERY", _q)',
  ]) assert.equal(dax(query), 'allow', query);
  const allowed = analyzeMcpCall('mcp__powerbi-modeling__dax_query_operations', { request: { operation: 'Execute', maxRows: 20, query: 'EVALUATE INFO.VIEW.COLUMNS()' } }, cfg);
  assert.match(allowed.reason, /review selected fields/);
  for (const query of [
    'EVALUATE INFO.DATASOURCES()',
    'EVALUATE FILTER(INFO.VIEW.COLUMNS(), [Name] IN VALUES(Customer[City]))',
    "EVALUATE ADDCOLUMNS(INFO.VIEW.TABLES(), \"c\", MAX('Customer'[City]))",
    'EVALUATE UNION(SELECTCOLUMNS(INFO.VIEW.TABLES(), "n", [Name]), SELECTCOLUMNS(Customer, "n", 1))',
    'EVALUATE GENERATE(INFO.VIEW.TABLES(), Customer)',
  ]) assert.equal(dax(query), 'ask/user', query);
  assert.equal(dax('EVALUATE INFO.VIEW.COLUMNS()', cfg, null), 'ask/user', 'maxRows stays required');
  assert.equal(dax('EVALUATE INFO.VIEW.COLUMNS()', cfg, 51), 'ask/user');
});

test('hook: in auto mode TOPN over a table asks and INFO.VIEW.COLUMNS runs', () => {
  const call = (query) => ({ files: CONFIRMED, tool_name: 'mcp__powerbi-modeling__dax_query_operations', tool_input: { request: { operation: 'Execute', maxRows: 5, query } } });
  const topn = runHook(call('EVALUATE TOPN(5, Customer)'));
  assert.equal(topn.decision, 'ask');
  assert.match(topn.reason, /Critical: auto mode always asks/);
  assert.equal(runHook(call('EVALUATE INFO.VIEW.COLUMNS()')).decision, 'allow');
});

// ---------------------------------------------------------------- audit 2026-10-18 (G8): declarations, relationships, item identity

const spaced = (text) => text.replace(/\t/g, '    ');

test('files (F1-25): renaming or removing an object in a space-indented TMDL file is Tier 2, like the tab-indented one', () => {
  const text = `${spaced(TABLE_TEXT)}\n    column Segment\n        dataType: string\n        sourceColumn: Segment\n`;
  assertTier2({ files: { [TABLE]: text }, tool_name: 'Edit', tool_input: { file_path: TABLE, old_string: '    measure Old', new_string: '    measure Older' } }, 'space-indented measure rename');
  assertTier2({
    files: { [TABLE]: text },
    tool_name: 'Edit',
    tool_input: { file_path: TABLE, old_string: '\n    column Segment\n        dataType: string\n        sourceColumn: Segment\n', new_string: '\n' },
  }, 'space-indented column delete');
  const added = runHook({ files: { [TABLE]: text }, tool_name: 'Edit', tool_input: { file_path: TABLE, old_string: '    measure Old = 1\n', new_string: '    measure Old = 1\n\n    measure New = 2\n' } });
  assert.equal(added.decision, 'allow', 'an added measure stays routine');
  // The helpers: indentation does not change what is declared.
  const declared = (t) => [...extractTmdlDeclarations(t)].sort();
  assert.deepEqual(declared(spaced(TABLE_TEXT)), declared(TABLE_TEXT));
  assert.deepEqual(removedDeclarations(spaced(TABLE_TEXT), TABLE_TEXT), [], 're-indenting a file removes nothing');
  assert.deepEqual(removedDeclarations('table T\n\n    measure A = 1\n', 'table T\n\n    measure B = 1\n'), ['measure a']);
});

const DATE = 'M.SemanticModel/definition/tables/Date.tmdl';
const DATE_TEXT = 'table Date\n\n\tcolumn Year\n\t\tdataType: int64\n\t\tsourceColumn: Year\n\n\thierarchy Calendar\n\n\t\tlevel Year\n\t\t\tcolumn: Year\n\n\thierarchy Fiscal\n\n\t\tlevel Year\n\t\t\tcolumn: Year\n';

test('files (F1-26): renaming or removing a hierarchy level is Tier 2; the levels of two hierarchies do not mask each other', () => {
  // Both hierarchies hold a level "Year": the first edit renames the one in Calendar, and the one in Fiscal must not hide it.
  assertTier2({ files: { [DATE]: DATE_TEXT }, tool_name: 'Edit', tool_input: { file_path: DATE, old_string: '\t\tlevel Year\n', new_string: '\t\tlevel Yr\n' } }, 'level rename');
  assertTier2({
    files: { [DATE]: DATE_TEXT },
    tool_name: 'Edit',
    tool_input: { file_path: DATE, old_string: '\thierarchy Calendar\n\n\t\tlevel Year\n\t\t\tcolumn: Year\n\n', new_string: '\thierarchy Calendar\n\n' },
  }, 'level delete');
  assertTier2({ files: { [DATE]: spaced(DATE_TEXT) }, tool_name: 'Edit', tool_input: { file_path: DATE, old_string: '        level Year\n', new_string: '        level Yr\n' } }, 'level rename, space-indented');
  assertTier2({ files: { [DATE]: DATE_TEXT }, tool_name: 'Edit', tool_input: { file_path: DATE, old_string: '\thierarchy Calendar\n', new_string: '\thierarchy Cal\n' } }, 'hierarchy rename (its levels go with it)');
  const added = runHook({
    files: { [DATE]: DATE_TEXT },
    tool_name: 'Edit',
    tool_input: { file_path: DATE, old_string: '\thierarchy Fiscal\n', new_string: '\thierarchy Fiscal\n\n\t\tlevel Quarter\n\t\t\tcolumn: Year\n' },
  });
  assert.equal(added.decision, 'allow', 'a new level is routine');
  assert.deepEqual([...extractTmdlDeclarations(DATE_TEXT)].filter((d) => d.startsWith('level')).sort(), ['level calendar/year', 'level fiscal/year']);
  assert.deepEqual(removedDeclarations(DATE_TEXT, DATE_TEXT.replace('hierarchy Calendar\n\n\t\tlevel Year', 'hierarchy Calendar\n\n\t\tlevel Yr')), ['level calendar/year']);
  assert.deepEqual(removedDeclarations('level Year\n', 'level Yr\n'), ['level year'], 'a level outside any hierarchy is keyed by its own name');
});

const MODEL = 'M.SemanticModel/definition/model.tmdl';
const MODEL_TEXT = 'model Model\n\tculture: en-US\n\nrelationship r1\n\tfromColumn: Sales.CustomerId\n\ttoColumn: Customer.CustomerId\n\nref table Sales\n';
const ORDERS = 'M.SemanticModel/definition/tables/Orders.tmdl';
const ORDERS_TEXT = 'table Orders\n\n\tcolumn Id\n\t\tdataType: int64\n\t\tsourceColumn: Id\n\nrelationship r2\n\tfromColumn: Orders.Id\n\ttoColumn: Customer.CustomerId\n';

test('files (F1-24): retargeting, re-configuring, renaming or deleting a relationship declared in model.tmdl or a table file is Tier 2', () => {
  for (const [label, file, text, old_string, new_string] of [
    ['model.tmdl: toColumn retargeted', MODEL, MODEL_TEXT, 'toColumn: Customer.CustomerId', 'toColumn: Customer.Segment'],
    ['model.tmdl: crossFilteringBehavior added', MODEL, MODEL_TEXT, '\ttoColumn: Customer.CustomerId\n', '\ttoColumn: Customer.CustomerId\n\tcrossFilteringBehavior: bothDirections\n'],
    ['model.tmdl: the whole block deleted', MODEL, MODEL_TEXT, 'relationship r1\n\tfromColumn: Sales.CustomerId\n\ttoColumn: Customer.CustomerId\n\n', ''],
    ['model.tmdl: the relationship renamed', MODEL, MODEL_TEXT, 'relationship r1', 'relationship r9'],
    ['table file: toColumn retargeted', ORDERS, ORDERS_TEXT, 'toColumn: Customer.CustomerId', 'toColumn: Customer.Segment'],
    ['table file: isActive false added', ORDERS, ORDERS_TEXT, '\ttoColumn: Customer.CustomerId\n', '\ttoColumn: Customer.CustomerId\n\tisActive: false\n'],
    ['space-indented table file: fromColumn changed', ORDERS, spaced(ORDERS_TEXT), 'fromColumn: Orders.Id', 'fromColumn: Orders.Key'],
  ]) assertTier2({ files: { [file]: text }, tool_name: 'Edit', tool_input: { file_path: file, old_string, new_string } }, label);
  // A new file that declares one counts from nothing.
  assertTier2({ tool_name: 'Write', tool_input: { file_path: ORDERS, content: ORDERS_TEXT } }, 'a new table file with a relationship');
  // A relationship is a declaration too (a rename or a removal is reported by name).
  assert.deepEqual(removedDeclarations(MODEL_TEXT, MODEL_TEXT.replace('relationship r1', 'relationship r9')), ['relationship r1']);
  assert.deepEqual(removedDeclarations(MODEL_TEXT, 'model Model\n'), ['relationship r1']);
});

test('files (F1-24): what does not change a relationship stays routine, also when the edit repeats the block as context', () => {
  const edit = (old_string, new_string, text = MODEL_TEXT) => runHook({ files: { [MODEL]: text }, tool_name: 'Edit', tool_input: { file_path: MODEL, old_string, new_string } });
  const block = MODEL_TEXT.slice(MODEL_TEXT.indexOf('relationship'));
  for (const [label, result] of [
    ['an annotation inside the block', edit('\ttoColumn: Customer.CustomerId\n', '\ttoColumn: Customer.CustomerId\n\tannotation PBI_Note = 1\n')],
    ['another object of the file', edit('culture: en-US', 'culture: tr-TR')],
    ['the block repeated as context, with another line after it changed', edit(block, block.replace('ref table Sales', 'ref table Orders'))],
    ['the whole file re-indented with spaces', runHook({ files: { [MODEL]: MODEL_TEXT }, tool_name: 'Write', tool_input: { file_path: MODEL, content: spaced(MODEL_TEXT) } })],
  ]) {
    assert.equal(result.decision, 'allow', label);
    assert.match(result.reason, /auto mode: routine project file edit/, label);
  }
  const facts = tmdlRelationshipFacts(MODEL_TEXT);
  assert.equal(tmdlRelationshipFacts(spaced(MODEL_TEXT)), facts, 'indentation');
  assert.equal(tmdlRelationshipFacts(MODEL_TEXT.replace(/\n/g, '\r\n')), facts, 'CRLF');
  assert.equal(tmdlRelationshipFacts(`${String.fromCharCode(0xfeff)}${MODEL_TEXT}`), facts, 'a byte order mark');
  assert.equal(tmdlRelationshipFacts(MODEL_TEXT.replace('\ttoColumn:', '\tannotation X = 1\n\t\tdeeper: 2\n\tlineageTag: abc\n\ttoColumn:')), facts, 'metadata lines and what hangs under them');
  assert.notEqual(tmdlRelationshipFacts(MODEL_TEXT.replace('Customer.CustomerId', 'Customer.Segment')), facts);
  assert.equal(tmdlRelationshipFacts('relationship a\n\tx: 1\nrelationship b\n\ty: 2\n'), tmdlRelationshipFacts('relationship b\n\ty: 2\nrelationship a\n\tx: 1\n'), 'the order of the blocks');
  assert.equal(tmdlRelationshipFacts('table T\n\tmeasure M = 1\n'), '', 'no relationship, no facts');
  const started = Date.now();
  tmdlRelationshipFacts(`${'relationship r\n\tx: 1\n'.repeat(50000)}${'\n'.repeat(200000)}`);
  assert.ok(Date.now() - started < 3000, 'linear on long files');
});

const PLATFORM = 'M.SemanticModel/.platform';
const platformText = (patch = {}) => `${JSON.stringify({
  $schema: 'https://developer.microsoft.com/json-schemas/fabric/gitIntegration/platformProperties/2.0.0/schema.json',
  metadata: { type: 'SemanticModel', displayName: 'Sales' },
  config: { version: '2.0', logicalId: '4f1c2d3e-0000-4000-8000-0000000000ff' },
  ...patch,
}, null, 2)}\n`;

test('files (F1-67): changing the logicalId or the type of a Fabric item in .platform is Tier 2; a new file, a displayName and the version stay routine', () => {
  const files = { [PLATFORM]: platformText() };
  const edit = (old_string, new_string) => ({ files, tool_name: 'Edit', tool_input: { file_path: PLATFORM, old_string, new_string } });
  assertTier2(edit('0000000000ff', '0000000000fe'), 'logicalId changed');
  assertTier2(edit('"type": "SemanticModel"', '"type": "Report"'), 'metadata.type changed');
  assertTier2({ files, tool_name: 'Write', tool_input: { file_path: PLATFORM, content: platformText({ config: { version: '2.0' } }) } }, 'logicalId removed');
  assertTier2({ files, tool_name: 'Write', tool_input: { file_path: PLATFORM, content: '{}\n' } }, 'identity removed');
  for (const [label, call] of [
    ['displayName', edit('"displayName": "Sales"', '"displayName": "Sales 2"')],
    ['config.version', edit('"version": "2.0"', '"version": "2.1"')],
    ['the same text again', { files, tool_name: 'Write', tool_input: { file_path: PLATFORM, content: platformText() } }],
    ['a new .platform', { tool_name: 'Write', tool_input: { file_path: PLATFORM, content: platformText() } }],
    ['a logicalId added to a file that had none', { files: { [PLATFORM]: platformText({ config: { version: '2.0' } }) }, tool_name: 'Write', tool_input: { file_path: PLATFORM, content: platformText() } }],
  ]) {
    const result = runHook(call);
    assert.equal(result.decision, 'allow', label);
    assert.match(result.reason, /auto mode: routine project file edit/, label);
  }
});
