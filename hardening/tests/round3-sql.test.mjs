// Follow-up audit, round 3 (2026-10-19): the SQL read switch (hardening/hooks/lib/sql-read.mjs).
// sql-1: a manager's or supervisor's name passed the switch in every spelling (ManagerName, managerName, manager_name,
//   and [Manager Name] too): PR #16 gave the rule to the DAX guard only (policy.mjs, ROLE_NAME_RE). The SQL judge
//   splits names at case and underscore boundaries already; it now has the rule as well, so every spelling asks.
// sql-2: Windows may hand sqlcmd, osql, isql and psql their command line in the ANSI code page, where a "best fit"
//   turns a full-width apostrophe (U+FF07) into "'", a full-width letter into its ASCII letter, and so on: the text
//   the client runs is not the text the guard judged (a string literal ends where the guard saw none). An argument of
//   these clients holding a character outside ASCII that is not a letter or digit asks, naming the character; the
//   query is also judged as a code page may fold it (full-width and accented letters too): what that reading cannot
//   pass asks, a write found only there included (sql-read.test.mjs keeps a full-width DELETE a floor).
//   Invoke-Sqlcmd (.NET), mssql-cli (Python) and SQL MCP servers receive Unicode and are left as they were.
// The client's real code page conversion is not run here (no sqlcmd or psql on the test machine).
// Every look-alike character and combining mark is built at run time from its code point.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyzeShellCommand, isRowLevelDax } from '../hooks/lib/policy.mjs';
import { analyzeSqlClient, judgeSql, personalColumnName } from '../hooks/lib/sql-read.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const preHook = path.join(here, '..', 'hooks', 'pre-tool-use.mjs');

// The switch on for one server, this machine (round2-sql.test.mjs).
const ON = { mode: 'on', servers: ['localhost'], mcpServers: ['mssql'], maxRows: 50, personalColumns: [] };
/** 'deny', 'floor' (asks in every mode), 'pass' (a plain ask auto and lab approve), or 'none'. */
function kind(cmd, sqlRead = ON) {
  const v = analyzeShellCommand(cmd, { sqlRead });
  if (!v) return 'none';
  if (v.decision === 'deny') return 'deny';
  if (v.decision === 'ask') return v.floor ? 'floor' : v.autoApprovable === false ? 'user' : 'pass';
  return v.decision;
}
const ch = (cp) => String.fromCodePoint(cp);
const hex = (cp) => cp.toString(16).toUpperCase().padStart(4, '0');
/** A word in full-width letters (U+FF21..): what a code page best fit turns back into ASCII. */
const wide = (s) => s.replace(/[A-Za-z]/g, (c) => ch(c.charCodeAt(0) + 0xfee0));
const sqlcmd = (query) => `sqlcmd -S localhost -E -Q "${query}"`;
const psql = (query) => `psql -X -h localhost -d sales -c "${query}"`;
// Turkish names, as a query of this project's users writes them: Bölge, Satış, Şehir, İstanbul.
const TURKISH_QUERY = "SELECT TOP 10 Bölge FROM dbo.Satış WHERE Şehir = N'İstanbul'";

// ---------------------------------------------------------------- sql-1: a manager's name

const MANAGER_COLUMNS = ['ManagerName', 'managerName', 'manager_name', 'MANAGER_NAME', '[Manager Name]', 'SupervisorName',
  'supervisor_name', 'AccountManagerName', 'StoreManagerName', 'ManagerFirstName', 'manager_full_name', 'ManagerNames', 'ManagerName2'];
const OTHER_COLUMNS = ['CompanyName', 'AccountName', 'ProductName', 'DepartmentName', 'RegionName', 'StoreName', 'ManagerLevel',
  'ManagerKey', 'IsManager', 'ManagerCount', 'manager_id'];

test('round3 sql-1: a manager\'s or supervisor\'s name asks in every spelling (sqlcmd and psql)', () => {
  for (const col of MANAGER_COLUMNS) {
    assert.equal(kind(sqlcmd(`SELECT TOP 10 ${col} FROM dbo.Employee`)), 'floor', col);
    assert.equal(personalColumnName(col.replace(/[[\]]/g, '')), true, col);
    assert.ok(judgeSql(`SELECT TOP 10 ${col} FROM dbo.Employee`).personal.length, col);
  }
  assert.equal(kind("psql -X -h localhost -d hr -c 'SELECT manager_name FROM employee LIMIT 10'"), 'floor');
  assert.equal(kind("psql -X -h localhost -d hr -c 'SELECT \"managerName\" FROM employee LIMIT 10'"), 'floor');
  const v = analyzeSqlClient('sqlcmd', ['-S', 'localhost', '-E', '-Q', 'SELECT TOP 10 ManagerName FROM dbo.Employee'], 'sqlcmd ...', { sqlRead: ON });
  assert.equal(v.decision, 'ask');
  assert.equal(v.floor, true);
  assert.match(v.reason, /personal or identifying columns \(ManagerName\)/);
});

test('round3 sql-1 controls: company, account, product and place names and other manager columns still pass', () => {
  for (const col of OTHER_COLUMNS) {
    assert.equal(kind(sqlcmd(`SELECT TOP 10 ${col} FROM dbo.Employee`)), 'pass', col);
    assert.equal(personalColumnName(col), false, col);
  }
  // The same rule as the spaced form, already before: an e-mail or a phone number in any spelling.
  for (const col of ['EmployeeEmail', 'employee_email', 'CustomerPhoneNumber', 'customerPhoneNumber']) {
    assert.equal(kind(sqlcmd(`SELECT TOP 10 ${col} FROM dbo.Employee`)), 'floor', col);
  }
});

test('round3 sql-1 controls: the DAX guard still counts a manager\'s name and still asks for its rows', () => {
  assert.equal(isRowLevelDax('EVALUATE ROW("n", DISTINCTCOUNT(Employee[ManagerName]))'), false);
  assert.equal(isRowLevelDax('EVALUATE ROW("n", DISTINCTCOUNT(Employee[Manager Name]))'), false);
  assert.equal(isRowLevelDax('EVALUATE SUMMARIZECOLUMNS(Employee[ManagerName])'), true);
  assert.equal(isRowLevelDax('EVALUATE SUMMARIZECOLUMNS(Customer[Company Name])'), false);
});

// ---------------------------------------------------------------- sql-2: code page look-alikes

// Quote look-alikes the audit named, and other characters a code page may turn into ASCII punctuation or a blank.
const LOOKALIKES = [0xff07, 0x2018, 0x2019, 0x02bc, 0xff02, 0x201c, 0x201d, 0x2032, 0x00b4, 0xff3c, 0x00a5, 0xff1b, 0xff0d,
  0x2013, 0x2212, 0xff0f, 0xff0a, 0x00a0, 0x3000];

test('round3 sql-2: a quote or other look-alike in a sqlcmd, osql, isql or psql query asks and names the character', () => {
  for (const cp of LOOKALIKES) {
    const c = ch(cp);
    for (const cmd of [
      sqlcmd(`SELECT TOP 10 Region FROM dbo.Sales WHERE Note = N'a${c}b'`),
      `osql -S localhost -E -Q "SELECT COUNT(*) FROM dbo.Sales WHERE Note = N'a${c}b'"`,
      `isql -S localhost -E -Q "SELECT COUNT(*) FROM dbo.Sales WHERE Note = N'a${c}b'"`,
      psql(`SELECT COUNT(*) FROM orders WHERE note = 'a${c}b'`),
      `psql -X -h localhost -d sales -c 'SELECT COUNT(*) FROM orders WHERE note = $$a${c}b$$'`,
    ]) {
      const v = analyzeShellCommand(cmd, { sqlRead: ON });
      assert.equal(v?.decision, 'ask', `U+${hex(cp)}: ${cmd}`);
      assert.equal(v.floor, true, `U+${hex(cp)}: ${cmd}`);
      assert.match(v.reason, new RegExp(`U\\+${hex(cp)}`), `U+${hex(cp)}: ${cmd}`);
    }
  }
  const v = analyzeShellCommand(sqlcmd(`SELECT TOP 10 Region FROM dbo.Sales WHERE Note = N'a${ch(0xff07)}b'`), { sqlRead: ON });
  assert.match(v.reason, /full-width apostrophe \(U\+FF07/);
  assert.match(v.reason, /code page/);
});

// A write the guard finds only in the folded reading asks, naming the character (whether the client converts depends on
// the client and the machine's code page); a write in the text as written is still denied.
test('round3 sql-2: a write hidden behind a full-width apostrophe asks, naming the character and the write', () => {
  const apos = ch(0xff07);
  for (const cmd of [
    sqlcmd(`SELECT TOP 10 Region FROM dbo.Sales WHERE Region = '${apos}; DELETE FROM dbo.Sales --'`),
    psql(`SELECT COUNT(*) FROM orders WHERE note = '${apos}; DELETE FROM orders --'`),
    `osql -S localhost -E -Q "SELECT COUNT(*) FROM t WHERE a = '${apos}; DROP TABLE t --'"`,
  ]) {
    const v = analyzeShellCommand(cmd, { sqlRead: ON });
    assert.equal(v?.decision, 'ask', cmd);
    assert.equal(v.floor, true, cmd);
    assert.match(v.reason, /U\+FF07/, cmd);
    assert.match(v.reason, /changes data, schema, permissions or the server \(in the query as Windows may hand it to (?:sqlcmd|psql|osql), a full-width apostrophe/, cmd);
  }
  // The same with the switch off; a write outside the look-alike is denied as before.
  assert.equal(kind(sqlcmd(`SELECT 1 WHERE 'a' = '${apos}; DELETE FROM t --'`), { mode: 'off' }), 'floor');
  assert.equal(kind(sqlcmd(`SELECT 1 WHERE 'a' = '${apos}'; DELETE FROM t`)), 'deny');
});

test('round3 sql-2: letters a code page folds to ASCII are read folded (full-width and accented keywords, a full-width GO)', () => {
  for (const query of [
    `SELECT TOP 1 1 ${wide('DELETE')} FROM dbo.t`,
    `SELECT TOP 1 1 ${ch(0x010e)}ELETE FROM dbo.t`, // D with caron
    `SELECT TOP 1 1 A${ch(0x0141)}TER TABLE dbo.t ADD c int`, // L with stroke: no decomposition, a best fit to L
    `SELECT TOP 1 'x\n${wide('GO')}\nDELETE FROM dbo.t --'`, // a batch line the client sees and the guard did not
  ]) {
    const v = analyzeShellCommand(sqlcmd(query), { sqlRead: ON });
    assert.equal(v?.decision, 'ask', query);
    assert.equal(v.floor, true, query);
    assert.match(v.reason, /changes data, schema, permissions or the server \(in the query as Windows may hand it to sqlcmd, /, query);
  }
  assert.equal(kind(psql(`SELECT COUNT(*) FROM t ${wide('UNION')} ${wide('SELECT')} COUNT(*) FROM u; ${wide('TRUNCATE')} t`)), 'floor');
});

test('round3 sql-2: a look-alike in another argument asks (a code page quote can split the command line)', () => {
  const q = ch(0xff02);
  for (const cmd of [
    `sqlcmd -S localhost -E -d "x${q} -o out.txt ${q}" -Q "SELECT COUNT(*) FROM t"`,
    `sqlcmd -S "localhost${q} -i other.sql ${q}" -E -Q "SELECT COUNT(*) FROM t"`,
    `psql -X -h localhost -U "reader${q} -o out.txt ${q}" -d sales -c "SELECT COUNT(*) FROM t"`,
  ]) {
    const v = analyzeShellCommand(cmd, { sqlRead: ON });
    assert.equal(v?.decision, 'ask', cmd);
    assert.equal(v.floor, true, cmd);
    assert.match(v.reason, /U\+FF02/, cmd);
  }
});

test('round3 sql-2 controls: plain ASCII, Turkish letters and full-width letters inside a literal still pass', () => {
  for (const query of [
    'SELECT TOP 10 Region FROM dbo.Sales',
    "SELECT COUNT(*) FROM dbo.Sales WHERE Region = N'North'",
    TURKISH_QUERY,
    `SELECT COUNT(*) FROM dbo.Sales WHERE Note = N'${wide('ABC')}'`,
    `SELECT COUNT(*) FROM dbo.Sales WHERE Note = N'Ali${ch(0x0307)}s${ch(0x0327)}'`, // decomposed letters: a base letter and its mark
  ]) {
    assert.equal(kind(sqlcmd(query)), 'pass', query);
  }
  assert.equal(kind(psql('SELECT COUNT(*) FROM orders')), 'pass');
  assert.equal(kind(psql("SELECT COUNT(*) FROM satis WHERE sehir = 'İstanbul'")), 'pass');
  // A Unicode client: Invoke-Sqlcmd runs in PowerShell (.NET), no code page between the guard and the query.
  assert.equal(kind(`Invoke-Sqlcmd -ServerInstance localhost -Query "SELECT COUNT(*) FROM dbo.Sales WHERE Note = N'a${ch(0x2019)}b'"`), 'pass');
});

// ---------------------------------------------------------------- the hook, end to end

function project(config) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-round3-sql-'));
  fs.mkdirSync(path.join(dir, 'hardening'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'hardening', 'harness.config.json'), `${JSON.stringify(config, null, 2)}\n`);
  return dir;
}
function guard(dir, tool_name, tool_input) {
  const r = spawnSync(process.execPath, [preHook], {
    input: JSON.stringify({ hook_event_name: 'PreToolUse', session_id: 'round3-sql', cwd: dir, tool_name, tool_input }),
    env: { ...process.env, CLAUDE_PROJECT_DIR: dir },
    encoding: 'utf8',
  });
  assert.equal(r.status, 0, r.stderr);
  const out = r.stdout.trim() ? JSON.parse(r.stdout).hookSpecificOutput : {};
  return { decision: out.permissionDecision ?? null, reason: out.permissionDecisionReason ?? '' };
}

test('round3 hook: in auto mode a manager\'s name, a look-alike and a write hidden behind one ask; plain reads pass', () => {
  const dir = project({ approvals: { mode: 'auto' }, sources: { sqlRead: { ...ON, mcpServers: [] } } });
  try {
    const manager = guard(dir, 'Bash', { command: sqlcmd('SELECT TOP 10 ManagerName FROM dbo.Employee') });
    assert.equal(manager.decision, 'ask', manager.reason);
    assert.match(manager.reason, /personal or identifying columns \(ManagerName\)/);
    assert.equal(guard(dir, 'Bash', { command: sqlcmd('SELECT TOP 10 manager_name FROM dbo.Employee') }).decision, 'ask');
    assert.equal(guard(dir, 'Bash', { command: sqlcmd('SELECT TOP 10 CompanyName FROM dbo.Customer') }).decision, 'allow');

    const apos = ch(0xff07);
    const hidden = guard(dir, 'Bash', { command: sqlcmd(`SELECT TOP 10 Region FROM dbo.Sales WHERE Region = '${apos}; DELETE FROM dbo.Sales --'`) });
    assert.equal(hidden.decision, 'ask', hidden.reason);
    assert.match(hidden.reason, /U\+FF07/);
    assert.match(hidden.reason, /DELETE FROM dbo\.Sales/);
    const literal = guard(dir, 'Bash', { command: psql(`SELECT COUNT(*) FROM orders WHERE note = 'a${ch(0x2019)}b'`) });
    assert.equal(literal.decision, 'ask', literal.reason);
    assert.match(literal.reason, /U\+2019/);
    assert.equal(guard(dir, 'Bash', { command: sqlcmd('SELECT TOP 10 Region FROM dbo.Sales') }).decision, 'allow');
    assert.equal(guard(dir, 'Bash', { command: sqlcmd(TURKISH_QUERY) }).decision, 'allow');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
