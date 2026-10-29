// The SQL read switch (Q-13, 2026-10-12): every query a SQL client or SQL MCP server would run is judged in every
// approvals mode. Writes are denied; what the guard cannot read, and every query while the switch is off, asks the
// user (lab mode included); with the switch on, a read-only, bounded query without personal columns against a listed
// server passes in auto and lab mode. Red-team cases (hidden writes, smuggled files, variables, options) are here too.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { DEFAULT_CONFIG, loadConfig } from '../hooks/lib/common.mjs';
import { analyzeMcpCall, analyzeShellCommand, classifyPath } from '../hooks/lib/policy.mjs';
import { identKey, judgeSql, maskSql, normalizeServer, personalColumnName, sqlReadOf, sqlReadWidened } from '../hooks/lib/sql-read.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const preHook = path.join(here, '..', 'hooks', 'pre-tool-use.mjs');
const startHook = path.join(here, '..', 'hooks', 'session-start.mjs');
// Fake credential words are joined at run time, never written as one literal (README, Adding a hook).
const PW = ['Pass', 'word'].join('');
const PWU = PW.toUpperCase();

const ON = { mode: 'on', servers: ['localhost', 'sql-test01'], mcpServers: ['mssql'], maxRows: 50 };
/** 'deny', 'floor' (asks in every mode), 'pass' (a plain ask auto and lab approve), or 'none'. */
function kind(cmd, sqlRead, baseDir) {
  const v = analyzeShellCommand(cmd, { sqlRead, baseDir });
  if (!v) return 'none';
  if (v.decision === 'deny') return 'deny';
  if (v.decision === 'ask') return v.floor ? 'floor' : v.autoApprovable === false ? 'user' : 'pass';
  return v.decision;
}
const cfgWith = (sqlRead) => ({ ...structuredClone(DEFAULT_CONFIG), sources: { ...DEFAULT_CONFIG.sources, sqlRead } });
function mcpKind(server, tool, input, sqlRead = ON) {
  const v = analyzeMcpCall(`mcp__${server}__${tool}`, input, cfgWith(sqlRead));
  if (!v) return 'none';
  if (v.decision === 'deny') return 'deny';
  if (v.decision === 'ask') return v.floor ? 'floor' : 'pass';
  return v.decision;
}

test('sql: the switch is off by default; a typo never opens it', () => {
  assert.equal(sqlReadOf({}).on, false);
  assert.equal(sqlReadOf(cfgWith(DEFAULT_CONFIG.sources.sqlRead)).on, false);
  for (const mode of ['On', ' on ', 'ON']) assert.equal(sqlReadOf(cfgWith({ mode })).on, true, mode);
  for (const mode of ['yes', 'true', 'onn', '', null, 1]) assert.equal(sqlReadOf(cfgWith({ mode })).on, false, String(mode));
  assert.equal(sqlReadOf(cfgWith({ mode: 'on', maxRows: 'x' })).maxRows, 50);
  assert.equal(sqlReadOf(cfgWith({ mode: 'on', maxRows: 1e9 })).maxRows, 1000);
});

test('sql: server spellings of this machine are one server; protocol and port do not matter; the instance does', () => {
  for (const s of ['.', '(local)', 'localhost', 'LOCALHOST', '127.0.0.1', 'tcp:localhost,1433', os.hostname()]) {
    assert.equal(normalizeServer(s), 'localhost', s);
  }
  assert.equal(normalizeServer('.\\SQLEXPRESS'), 'localhost\\sqlexpress');
  assert.equal(normalizeServer('tcp:sql-test01.contoso.com,1433'), 'sql-test01.contoso.com');
  assert.equal(normalizeServer('db.example.org:5432'), 'db.example.org');
});

test('sql: switch off (default): reads ask in every mode, writes are denied, even in lab mode', () => {
  assert.equal(kind('sqlcmd -S . -E -Q "SELECT COUNT(*) FROM dbo.FactSales"'), 'floor');
  assert.equal(kind('psql -X -h localhost -d lab -c "SELECT count(*) FROM sales"'), 'floor');
  assert.equal(kind('Invoke-Sqlcmd -ServerInstance . -Query "SELECT 1"'), 'floor');
  for (const cmd of [
    'sqlcmd -S . -E -Q "DELETE FROM dbo.FactSales"', 'sqlcmd -S . -Q "UPDATE t SET a = 1"', 'sqlcmd -S . -Q "DROP TABLE t"',
    'psql -X -h localhost -c "TRUNCATE sales"', 'Invoke-Sqlcmd -ServerInstance . -Query "INSERT INTO t VALUES (1)"',
    'osql -S . -E -Q "CREATE TABLE t (a int)"', 'mssql-cli -S . -Q "ALTER TABLE t ADD b int"',
  ]) assert.equal(kind(cmd), 'deny', cmd);
});

test('sql: switch on: a bounded read against a listed server passes; everything else asks', () => {
  for (const cmd of [
    'sqlcmd -S . -E -C -d SalesDW -Q "SELECT COUNT(*) AS n, SUM(SalesAmount) FROM dbo.FactSales"',
    'sqlcmd -S localhost -E -Q "SELECT TOP 10 Region, COUNT(*) FROM dbo.DimCustomer GROUP BY Region"',
    'sqlcmd -Slocalhost -E -Q "SELECT TOP (50) Region FROM dbo.DimCustomer"',
    'sqlcmd -S tcp:sql-test01,1433 -E -Q "SET NOCOUNT ON; SELECT SUM(x) FROM t"',
    'psql -X -h localhost -d lab -c "SELECT region, count(*) FROM sales GROUP BY region LIMIT 10"',
    'psql -X -h localhost -c "SELECT sum(amount) FROM sales"',
    'psql -X "postgresql://reader@localhost:5432/lab" -c "SELECT count(*) FROM sales"',
    'Invoke-Sqlcmd -ServerInstance . -Database SalesDW -Query "SELECT MAX(OrderDate) FROM dbo.FactSales"',
    'Invoke-Sqlcmd -ServerInstance:. -Query:"SELECT 1"',
    'sqlcmd -S . -Q "SELECT 1"',
    'sqlcmd -S . -Q "WITH r AS (SELECT Region FROM dbo.DimCustomer) SELECT COUNT(*) FROM r"',
    'sqlcmd -S . -Q "SELECT Region FROM dbo.DimCustomer ORDER BY Region OFFSET 0 ROWS FETCH NEXT 20 ROWS ONLY"',
    "sqlcmd -S . -Q \"SELECT COUNT(*) FROM t WHERE note = 'please DELETE me' -- DROP later\"",
    'sqlcmd -S . -Q "SELECT COUNT(*) FROM t /* UPDATE t SET a = 1 */"',
    'sqlcmd -S . -Q "SELECT COUNT(*) FROM [Update] WHERE [Delete] = 1"',
    "psql -X -h localhost -c 'SELECT count(*) FROM t WHERE body = $$DELETE FROM t$$'",
  ]) assert.equal(kind(cmd, ON), 'pass', cmd);
  for (const [cmd, why] of [
    ['sqlcmd -S prod-sql -E -Q "SELECT COUNT(*) FROM t"', /not in sources\.sqlRead\.servers/],
    ['sqlcmd -E -Q "SELECT COUNT(*) FROM t"', /name the server/],
    ['sqlcmd -S . -Q "SELECT Region, SalesAmount FROM dbo.FactSales"', /not bounded/],
    ['sqlcmd -S . -Q "SELECT Region, COUNT(*) FROM t GROUP BY Region"', /not bounded/],
    ['sqlcmd -S . -Q "SELECT TOP 51 Region FROM t"', /not bounded/],
    ['sqlcmd -S . -Q "SELECT TOP 5 PERCENT Region FROM t"', /not bounded/],
    ['sqlcmd -S . -Q "SELECT DISTINCT Region FROM t"', /not bounded/],
    ['sqlcmd -S . -Q "SELECT COUNT(*) OVER () FROM t"', /not bounded/],
    ['sqlcmd -S . -Q "SELECT TOP 10 Region FROM a UNION ALL SELECT Region FROM b"', /not bounded/],
    ['sqlcmd -S . -Q "SELECT a, (SELECT COUNT(*) FROM x) FROM t"', /not bounded/],
    ['sqlcmd -S . -Q "SELECT TOP 10 Email FROM dbo.DimSalesperson"', /personal/],
    ['sqlcmd -S . -Q "SELECT TOP 10 [Salesperson Email] FROM dbo.DimSalesperson"', /personal/],
    ['sqlcmd -S . -Q "SELECT TOP 10 * FROM dbo.DimCustomer"', /personal/],
    ['sqlcmd -S . -Q "SELECT TOP 10 c.* FROM dbo.DimCustomer c"', /personal/],
    ['sqlcmd -S . -Q "SELECT COUNT(*) FROM t WHERE Email = 1"', /personal/],
    ['sqlcmd -S . -Q "SELECT TOP 10 CustomerKey, SUM(x) FROM t GROUP BY CustomerKey"', /personal/],
    ['sqlcmd -S . -Q "SELECT TOP 5 SalespersonName FROM t"', /personal/],
    ['psql -X -h localhost -c "SELECT count(*) FROM pg_shadow WHERE passwd IS NOT NULL"', /personal/],
  ]) {
    const v = analyzeShellCommand(cmd, { sqlRead: ON });
    assert.equal(v?.floor, true, cmd);
    assert.match(v.reason, why, cmd);
  }
});

test('sql red team: writes hidden in batches, CTEs, procedures, comments, case or quoting are denied', () => {
  for (const cmd of [
    'sqlcmd -S . -Q "SELECT 1; DELETE FROM t"',
    'sqlcmd -S . -Q "SELECT 1\nGO\ndelete t"',
    'sqlcmd -S . -Q "WITH x AS (SELECT * FROM t) DELETE FROM x"',
    'sqlcmd -S . -Q "SeLeCt 1; dElEtE FrOm t"',
    'sqlcmd -S . -Q "SELECT * INTO dbo.copy FROM dbo.FactSales"',
    'psql -X -h localhost -c "SELECT * INTO TEMP t2 FROM t"',
    'sqlcmd -S . -Q "MERGE t USING s ON 1=1 WHEN MATCHED THEN DELETE;"',
    'sqlcmd -S . -Q "SELECT 1 /* x */ ; /* y */ UPDATE t SET a = 2"',
    'sqlcmd -S . -Q "EXEC xp_cmdshell \'dir\'"',
    'sqlcmd -S . -Q "EXEC sp_configure \'show advanced options\', 1"',
    "sqlcmd -S . -Q \"SELECT * FROM OPENROWSET(BULK 'C:\\x.txt', SINGLE_CLOB) a\"",
    'sqlcmd -S . -Q "BACKUP DATABASE x TO DISK = \'c:\\b.bak\'"',
    'sqlcmd -S . -Q "DBCC CHECKDB"',
    'sqlcmd -S . -Q "GRANT SELECT ON t TO public"',
    'psql -X -h localhost -c "COPY t TO PROGRAM \'cmd\'"',
    'psql -X -h localhost -c "SELECT nextval(\'s\')"',
    'psql -X -h localhost -c "SELECT pg_terminate_backend(1)"',
    'psql -X -h localhost -c "SELECT lo_export(1, \'/tmp/x\')"',
    'psql -X -h localhost -c "SELECT 1; \\! whoami"',
    'sqlcmd -S . -Q "!! whoami"',
    'sqlcmd -S . -Q ":!! whoami"',
    'sqlcmd -S . -P x -Q "SELECT 1"',
    'sqlcmd -S . -Px -Q "SELECT 1"',
    'sqlcmd -S . -z newpass',
    `Invoke-Sqlcmd -ServerInstance . -${PW} x -Query "SELECT 1"`,
    `Invoke-Sqlcmd -ConnectionString "Server=.;User ID=u;${PW}=p" -Query "SELECT 1"`,
    `psql -X "postgresql://u:${'sec'}${'ret'}@localhost/db" -c "SELECT 1"`,
    `PG${PWU}=x psql -X -h localhost -c "SELECT 1"`,
    `$env:SQLCMD${PWU} = "x"; sqlcmd -S . -Q "SELECT 1"`,
    'sqlcmd -S . -Q "INSERT INTO @t EXEC dbo.p; DELETE FROM dbo.t"',
  ]) assert.equal(kind(cmd, ON), 'deny', cmd);
});

test('sql red team: what the guard cannot read asks in every mode, also with the switch on', () => {
  for (const cmd of [
    'sqlcmd -S . -Q "EXEC dbo.usp_SalesBySalesperson"',
    'sqlcmd -S . -Q "DECLARE @s nvarchar(100) = N\'SELECT 1\'; EXEC sp_executesql @s"',
    'sqlcmd -S . -Q "EXECUTE AS USER = \'x\'; SELECT 1"',
    'sqlcmd -S . -Q "WAITFOR DELAY \'00:10\'"',
    'sqlcmd -S . -Q "SELECT * FROM OPENQUERY(remote, \'SELECT 1\')"',
    'sqlcmd -S . -Q ":r evil.sql"',
    'sqlcmd -S . -Q ":connect prod"',
    'sqlcmd -S . -Q "SELECT $(col) FROM t"',
    'sqlcmd -S . -v t=x -Q "SELECT COUNT(*) FROM t"',
    'sqlcmd -S . -o out.txt -Q "SELECT 1"',
    'sqlcmd -S . -A -Q "SELECT 1"',
    'sqlcmd -S . -Q "SELECT 1" extra',
    'sqlcmd -S . -E',
    'sqlcmd -S . -i missing.sql',
    'sqlcmd -S . -i C:/Windows/win.ini',
    'sqlcmd -S . -i *.sql',
    'echo DELETE FROM t | sqlcmd -S .',
    'sqlcmd -S . -Q "WHILE 1=1 SELECT 1"',
    'sqlcmd -S . -Q "DECLARE c CURSOR FOR SELECT 1"',
    "sqlcmd -S . -Q \"SELECT 'unterminated\"",
    'sqlcmd -S . -Q "SELECT STRING_AGG(Region, \',\') FROM t"',
    'sqlcmd -S . -Q "DECLARE @e nvarchar(max) = (SELECT TOP 1 Region FROM t FOR XML PATH(\'\')); SELECT @e"',
    'SQLCMDINI=evil.sql sqlcmd -S . -Q "SELECT 1"',
    '$env:SQLCMDSERVER = "prod"; sqlcmd -Q "SELECT 1"',
    'psql -h localhost -c "SELECT count(*) FROM t"',
    'psql -X -h localhost -v t=x -c "SELECT count(*) FROM :t"',
    'psql -X -h localhost -c "SELECT count(*) FROM :t"',
    'psql -X -h localhost -c "\\copy t to x.csv"',
    'psql -X -h localhost -c "\\gexec"',
    'psql -X -h localhost -o out.txt -c "SELECT 1"',
    'psql -X -h localhost -f -',
    'psql -X -h localhost -Xf dml.sql -c "SELECT 1"',
    'psql -X -h localhost --comm="DELETE FROM t"',
    'psql -X -h localhost -c "SELECT 1" --fi=dml.sql',
    'psql -X -h localhost -c "DO $$ BEGIN PERFORM 1; END $$"',
    'psql -X -h localhost -c "SELECT pg_sleep(100)"',
    'psql -X -h localhost -c "SELECT pg_read_file(\'/etc/passwd\')"',
    'psql -X -h localhost -c "SELECT count(*) FROM t FOR UPDATE"',
    'psql -X -h localhost -c "SET ROLE admin; SELECT 1"',
    'Invoke-Sqlcmd -ServerInstance . -Query "SELECT 1" -Inp dml.sql',
    'Invoke-Sqlcmd -ServerInstance . -Query $q',
    'Invoke-Sqlcmd -ServerInstance . -Query "SELECT 1" -Variable "x=1"',
    'Get-Content q.sql | Invoke-Sqlcmd -ServerInstance .',
    'Start-Process sqlcmd -ArgumentList "-S . -Q x"',
  ]) {
    const k = kind(cmd, ON);
    assert.ok(k === 'floor' || k === 'deny', `${cmd} -> ${k}`);
  }
});

test('sql red team, round 2: string escapes, PostgreSQL CTEs, options, servers, ties and set operators', () => {
  for (const [want, cmd] of [
    ['deny', `psql -X -h localhost -c "WITH d AS (DELETE FROM t RETURNING *) SELECT count(*) FROM d"`],
    ['deny', String.raw`psql -X -h localhost -c "SELECT count(*) FROM t WHERE x = E'\'' ; DELETE FROM t; --'"`],
    ['deny', String.raw`psql -X -h localhost -c "SELECT count(*) FROM t WHERE x = 'a\' ; DELETE FROM t; --'"`], // old backslash setting
    // One literal as written (PowerShell keeps \\), but Git Bash turns \\ into \ inside double quotes and E'\'' ends
    // before the DELETE: the bash reading is judged too.
    ['deny', String.raw`psql -X -h localhost -c "SELECT count(*) FROM t WHERE x = E'\\'' ; DELETE FROM t; --'"`],
    ['deny', 'sqlcmd -S . -Q "SELECT 1 DELETE FROM t"'], // T-SQL needs no ";"
    ['deny', 'sqlcmd -S . -Q "SELECT 1 AS a INTO [dbo].[x]"'],
    ['deny', 'psql -X -h localhost -c "CREATE TEMP TABLE x AS SELECT 1"'],
    ['deny', 'psql -X -h localhost -c "EXPLAIN ANALYZE DELETE FROM t"'],
    ['deny', 'sqlcmd -S . -Q "SELECT 1" -Q "DELETE FROM t"'],
    ['deny', `setx PG${PWU} x`],
    ['floor', 'setx SQLCMDINI evil.sql'],
    ['floor', 'sqlcmd -S . -Q "SELECT TOP 10 [E-mail] FROM DimCustomer"'],
    ['floor', 'sqlcmd -S . -Q "SELECT TOP 10 WITH TIES a FROM t ORDER BY a"'],
    ['floor', 'psql -X -h localhost -c "SELECT a FROM t LIMIT 10 UNION SELECT a FROM t2"'],
    ['pass', 'psql -X -h localhost -c "SELECT a FROM t UNION SELECT a FROM t2 LIMIT 10"'],
    ['floor', 'psql -X -h localhost "service=prod" -c "SELECT count(*) FROM t"'],
    ['floor', 'psql -X -h localhost -d "host=prod dbname=x" -c "SELECT count(*) FROM t"'],
    ['floor', 'sqlcmd -S localhost.evil.com -Q "SELECT COUNT(*) FROM t"'],
    ['floor', 'sqlcmd -S . -S prod -Q "SELECT COUNT(*) FROM t"'],
    ['floor', 'sqlcmd /S . /Q "SELECT COUNT(*) FROM t"'],
    ['floor', 'Invoke-Sqlcmd "SELECT COUNT(*) FROM t" -ServerInstance .'],
    ['floor', 'Invoke-Sqlcmd @p'],
    ['floor', 'Invoke-Sqlcmd -ServerInstance . -Query "SELECT COUNT(*) FROM t" -ConnectionString "Server=prod"'],
    ['floor', `sqlcmd -S . -Q "SELECT 1; ＤＥＬＥＴＥ FROM t"`], // full-width letters: not a query the guard recognises
    ['floor', 'sqlcmd -S . -Q "SELECT TOP 5 name FROM sys.sql_logins"'],
  ]) assert.equal(kind(cmd, ON), want, cmd);
  for (const [want, server, tool, input] of [
    ['deny', 'mssql', 'read_query', { queries: ['SELECT 1', 'DELETE FROM t'] }],
    ['deny', 'mssql', 'read_query', { args: ['DELETE FROM t'] }],
    ['deny', 'mssql', 'read_query', { query: String.raw`SELECT COUNT(*) FROM t WHERE x = E'\'' ; DELETE FROM t; --'` }],
    ['floor', 'mssql', 'read_query', { sqlText: 'SELECT a FROM t' }],
    ['floor', 'mssql', 'read_query', { input: { sql_statement: 'SELECT a FROM t' } }],
    ['floor', 'mssql', 'run_query', { payload: 'x' }],
    ['floor', 'my-db', 'query', { sql: 'SELECT 1' }],
    ['floor', 'Postgres_Prod', 'list_tables', {}],
  ]) assert.equal(mcpKind(server, tool, input), want, `${server} ${tool} ${JSON.stringify(input)}`);
});

test('sql red team, round 3 (security review 2026-10-12): quotes per dialect, hidden statements, functions, whole rows, clients', () => {
  for (const [want, cmd] of [
    // A $$ inside a name is no dollar quote in PostgreSQL; T-SQL has none at all.
    ['deny', 'psql -X -h localhost -c "SELECT count(*) AS x$$ FROM t; DROP TABLE t; SELECT count(*) AS y$$ FROM t"'],
    ['deny', 'sqlcmd -S . -Q "SELECT COUNT(*) AS x$$ FROM t; DROP TABLE t; SELECT COUNT(*) AS y$$ FROM t"'],
    // OUTPUT ... INTO writes elsewhere; a text that only writes a temporary table reads nothing.
    ['deny', 'sqlcmd -S . -Q "INSERT INTO #t(a) OUTPUT inserted.a INTO dbo.Real VALUES(1)"'],
    ['floor', 'sqlcmd -S . -Q "INSERT INTO #t(a) VALUES(1)"'],
    // sqlcmd -q stays open and runs stdin; a pipeline, a second command or a cd never rides on a passing read.
    ['floor', 'sqlcmd -S . -q "SELECT COUNT(*) FROM t"'],
    ['floor', 'echo DROP TABLE t | sqlcmd -S . -Q "SELECT COUNT(*) FROM t"'],
    ['floor', 'sqlcmd -S . -Q "SELECT COUNT(*) FROM t"; python tools/x.py'],
    ['floor', 'cd sub && sqlcmd -S . -i q.sql'],
    // T-SQL needs no ";": a second query or a query behind SET, DECLARE or a temporary-table write is seen.
    ['floor', 'sqlcmd -S . -Q "SELECT a FROM Fact SELECT COUNT(*) FROM Fact"'],
    ['floor', 'sqlcmd -S . -Q "SET NOCOUNT ON SELECT a FROM Fact"'],
    ['floor', 'sqlcmd -S . -Q "DECLARE @x int SELECT a FROM Fact"'],
    ['floor', 'sqlcmd -S . -Q "INSERT INTO #t VALUES (1) SELECT a FROM Fact"'],
    // Functions outside the built-in list, sequences, linked servers.
    ['floor', 'psql -X -h localhost -c "SELECT purge()"'],
    ['floor', "psql -X -h localhost -c \"SELECT count(*) FROM t WHERE pg_file_unlink('x')\""],
    ['floor', 'psql -X -h localhost -c "SELECT count(*) FROM generate_series(1, 1000000000)"'],
    ['floor', 'sqlcmd -S . -Q "SELECT NEXT VALUE FOR dbo.seq"'],
    ['floor', 'sqlcmd -S . -Q "SELECT COUNT(*) FROM prod.db.dbo.t"'],
    // Every column or a whole row.
    ['floor', 'sqlcmd -S . -Q "SELECT TOP 10 1, * FROM DimCustomer"'],
    ['floor', 'psql -X -h localhost -c "SELECT c FROM customer c LIMIT 10"'],
    ['floor', 'psql -X -h localhost -c "SELECT row_to_json(c) FROM customer c LIMIT 10"'],
    ['floor', 'psql -X -h localhost -c "SELECT DISTINCT ON (x) * FROM t LIMIT 10"'],
    ['floor', 'sqlcmd -S . -Q "SELECT (SELECT MAX(x) FROM t2), a FROM t"'],
    // Credentials by a shortened name, a second server key, clients the guard does not judge.
    ['deny', 'Invoke-Sqlcmd -ServerInstance . -Query "SELECT 1" -Pass x'],
    ['deny', 'Invoke-Sqlcmd -ServerInstance . -Query "SELECT 1" -Cred $c'],
    ['floor', 'Invoke-Sqlcmd -ConnectionString "Server=.;Server=prod" -Query "SELECT COUNT(*) FROM t"'],
    ['floor', 'bcp dbo.t in data.csv -S . -T'],
    ['floor', 'mysql -h localhost -e "SELECT 1"'],
    ['floor', 'sqlite3 lab.db "SELECT 1"'],
    // Still passing: wrapped aggregates, a CTE, a grouped TOP with casts, bundled psql flags.
    ['pass', 'sqlcmd -S . -Q "SELECT ROUND(SUM(SalesAmount), 2) FROM dbo.FactSales"'],
    ['pass', 'sqlcmd -S . -Q "WITH c AS (SELECT a FROM t) SELECT COUNT(*) FROM c"'],
    ['pass', 'sqlcmd -S . -Q "SELECT TOP 10 Region, CAST(SUM(x) AS decimal(18,2)) FROM t GROUP BY Region ORDER BY 2 DESC"'],
    ['pass', 'psql -XAt -h localhost -c "SELECT count(*) FROM sales"'],
    ['pass', 'psql -X -h localhost -c "SELECT a FROM t FETCH FIRST 10 ROWS ONLY"'],
  ]) assert.equal(kind(cmd, ON), want, cmd);
  // sqlcmd splits batches at GO lines before any quote: GO inside a string or bracket cannot hide a statement.
  assert.notEqual(judgeSql("SELECT COUNT(*) FROM t WHERE x = '\nGO\nDELETE FROM t\nGO\n'").kind, 'read');
  assert.equal(judgeSql('SELECT COUNT(*) AS `\nGO\nDELETE FROM t\nGO\n` FROM t').kind, 'deny');
  // psql splits a file at a ";" inside brackets: a bracket is no quote there.
  assert.equal(judgeSql('SELECT a[ ; DELETE FROM t; --] FROM t', { client: 'psql' }).kind, 'deny');
  // A text over 32 KB is not analysed.
  assert.equal(judgeSql(`SELECT COUNT(*) FROM t WHERE x IN (${'1,'.repeat(17000)}1)`).kind, 'floor');
  for (const [want, server, tool, input] of [
    // MySQL readings for a SQL MCP server of unknown dialect.
    ['floor', 'mssql', 'read_query', { query: 'SELECT 1 /*! ; DELETE FROM t */' }],
    ['deny', 'mssql', 'read_query', { query: 'SELECT 1--1; DELETE FROM t' }],
    ['deny', 'mssql', 'read_query', { query: 'SELECT "\\""; DELETE FROM t; --"' }],
    ['floor', 'mssql', 'read_query', { query: 'SELECT a FROM t LIMIT 10, 100000' }],
    // No SQL text: only a describing tool passes. Every SQL-named field is judged; too deep or too large asks.
    ['floor', 'mssql', 'read_table', { table: 't', columns: ['a'], limit: 100000 }],
    ['pass', 'mssql', 'describe_table', { table: 't' }],
    ['deny', 'mssql', 'read_query', { stmt: '/* x */ DELETE FROM t' }],
    ['pass', 'mssql', 'read_query', { query: 'SELECT COUNT(*) FROM t', description: 'list the counts' }],
    ['floor', 'mssql', 'read_query', { a: { b: { c: { d: { e: { f: { g: { query: 'SELECT COUNT(*) FROM t' } } } } } } } }],
    ['floor', 'mssql', 'read_query', { query: 'SELECT COUNT(*) FROM t', pad: 'x'.repeat(70000) }],
    // A SQL tool on a server whose name does not look like a database is still judged.
    ['deny', 'dbhub', 'execute_sql', { sql: 'DELETE FROM t' }],
    ['deny', 'azure', 'run_query', { query: 'DELETE FROM t' }],
    ['floor', 'azure', 'run_query', { query: 'SELECT COUNT(*) FROM t' }],
    ['none', 'claude_ai_Claude_Docs', 'query', { query: 'quarterly plan' }],
  ]) assert.equal(mcpKind(server, tool, input), want, `${server} ${tool} ${JSON.stringify(input).slice(0, 120)}`);
});

// ---------------------------------------------------------------- audit 2026-10-18 (group G15: findings S1 to S10)
// The names the DAX guard asks about (tests/tier2.test.mjs, "Turkish and other non-English personal column names ask")
// and the ones it lets through. The SQL judge reads the same vocabulary, in a bracketed or quoted identifier too.
const PERSONAL_NAMES = ['Ad', 'Soyad', 'AdSoyad', 'Adı Soyadı', 'İsim', 'ISIM', 'İsim Soyisim', 'TELEFON', 'Cep Telefonu', 'Tel', 'Tel No',
  'E-Posta', 'Eposta Adresi', 'TC', 'TC Kimlik No', 'TCKN', 'TCKimlikNo', 'Kimlik No', 'Adres', 'Fatura Adresi', 'Doğum Tarihi',
  'Dogum Tarihi', 'Maaş', 'Maas', 'Pasaport No', 'IBAN', 'Kullanıcı Adı', 'Kullanici Adi', 'KULLANICI ADI', 'Müşteri Adı',
  'Musteri Adi', 'MusteriAdi', 'Personel Adı', 'Çalışan Adı', 'Calisan Adi', 'Email', 'Vorname', 'Nachname', 'Geburtsdatum', 'Prénom',
  'Teléfono', 'First Name', 'Mobile', 'Courriel', 'Apellido', 'Correo', 'Cognome', 'Indirizzo', 'Telefon', 'Gehalt', 'Salaire', 'Stipendio'];
const PLAIN_NAMES = ['Ürün Adı', 'Urun Adi', 'Ürün İsmi', 'Adet', 'Satış Adedi', 'Hotel', 'Kategori', 'Ad Campaign', 'Bölge', 'Şehir',
  'Match Type', 'Category', 'GSM', 'Hotel Name', 'Region', 'SalesAmount', 'OrderDate', 'ProductName', 'Hotels', 'Business', 'Status'];
const daxAsks = (col) => analyzeMcpCall('mcp__powerbi-modeling__dax_query_operations',
  { request: { operation: 'Execute', maxRows: 20, query: `EVALUATE SUMMARIZECOLUMNS('T'[${col}], "S", [Sales])` } },
  { mcp: { powerbiServer: 'powerbi-modeling' } })?.decision === 'ask';
/** The personal names the SQL judge finds in a bounded query that selects one quoted column. */
const quotedPersonal = (col, client) => judgeSql(client === 'psql' ? `SELECT "${col}" FROM t LIMIT 10` : `SELECT TOP 10 [${col}] FROM dbo.t`, { client }).personal;
const personalAsk = (cmd, sqlRead = ON) => {
  const v = analyzeShellCommand(cmd, { sqlRead });
  assert.equal(v?.floor, true, cmd);
  assert.match(v.reason, /personal or identifying columns/, cmd);
};

test('sql audit S1: personal column names in Turkish, German, French, Spanish and Italian ask, as in the DAX guard', () => {
  for (const col of PERSONAL_NAMES) {
    assert.equal(daxAsks(col), true, `the DAX guard asks about ${col}`);
    for (const client of ['tsql', 'psql']) assert.ok(quotedPersonal(col, client).length, `${client} ${col}`);
  }
  assert.equal(daxAsks('Region'), false, 'the DAX guard lets an ordinary column through');
  for (const col of PLAIN_NAMES) {
    assert.equal(daxAsks(col), daxAsks('Region'), `the DAX guard treats ${col} like any ordinary column`);
    for (const client of ['tsql', 'psql']) assert.deepEqual(quotedPersonal(col, client), [], `${client} ${col}`);
  }
  // The audit's reproductions through the shell guard, and the unquoted spellings: a floor ask in every mode.
  for (const cmd of [
    'sqlcmd -S . -E -Q "SELECT TOP 10 Telefon, Adres FROM dbo.Musteri"',
    'sqlcmd -S . -E -Q "SELECT TOP 10 Vorname, Nachname FROM dbo.Kunde"',
    'psql -X -h localhost -c "SELECT courriel FROM clients LIMIT 10"',
    'sqlcmd -S . -E -Q "SELECT TOP 10 [Musteri Adi] FROM dbo.t"',
    'sqlcmd -S . -E -Q "SELECT TOP 10 [Müşteri Adı] FROM dbo.t"',
    'sqlcmd -S . -E -Q "SELECT TOP 10 İSİM FROM dbo.t"',
    'sqlcmd -S . -E -Q "SELECT TOP 10 MusteriAdi, Soyad FROM dbo.t"',
    'sqlcmd -S . -E -Q "SELECT TOP 10 MusteriTelefon FROM dbo.t"',
    'sqlcmd -S . -E -Q "SELECT TOP 10 e.Telefon FROM dbo.Kunde e"',
    'sqlcmd -S . -E -Q "SELECT COUNT(*) FROM dbo.Kunde WHERE Vorname = \'x\'"',
    'psql -X -h localhost -c "SELECT \\"Vorname\\" FROM kunde LIMIT 10"',
    'psql -X -h localhost -c "SELECT apellido, correo FROM cliente LIMIT 10"',
    'psql -X -h localhost -c "SELECT cognome FROM cliente ORDER BY indirizzo LIMIT 10"',
    'Invoke-Sqlcmd -ServerInstance . -Query "SELECT TOP 10 [Prénom] FROM Client"',
  ]) personalAsk(cmd);
  assert.equal(mcpKind('mssql', 'read_query', { query: 'SELECT TOP 10 Telefon FROM Musteri' }), 'floor');
  assert.equal(mcpKind('mssql', 'read_query', { query: 'SELECT TOP 10 [Musteri Adi] FROM Musteri' }), 'floor');
  assert.equal(mcpKind('mssql', 'read_query', { query: 'SELECT 1 FROM t WHERE Vorname = 1' }), 'floor');
  // A SQL MCP server of unknown dialect: brackets, double quotes and backticks all quote a name.
  for (const query of ['SELECT "Vorname" FROM t LIMIT 5', 'SELECT `Telefon` FROM t LIMIT 5', 'SELECT TOP 5 [Doğum Tarihi] FROM t']) {
    assert.equal(mcpKind('mssql', 'read_query', { query }), 'floor', query);
  }
  // What is not personal still passes.
  for (const cmd of [
    'sqlcmd -S . -E -Q "SELECT TOP 10 Region FROM t"',
    'sqlcmd -S . -E -Q "SELECT COUNT(*) FROM dbo.Sales"',
    'sqlcmd -S . -E -Q "SELECT TOP 10 [Ürün Adı], Category, GSM FROM dbo.Urun"',
    'psql -X -h localhost -c "SELECT hotel, status FROM bookings LIMIT 10"',
  ]) assert.equal(kind(cmd, ON), 'pass', cmd);
  assert.equal(mcpKind('mssql', 'read_query', { query: 'SELECT TOP 10 Region FROM t' }), 'pass');
});

test('sql audit S1: identifier keys and quoted names fold accents; the configured list keeps working', () => {
  assert.equal(identKey('Müşteri Adı'), 'musteriadi');
  assert.equal(identKey('[E-mail]'), 'email');
  assert.equal(identKey('İSİM'), 'isim');
  const decomposed = 'Müşteri Adi'.normalize('NFD'); // a u and a combining mark, not the composed ü
  assert.notEqual(decomposed, 'Müşteri Adi'.normalize('NFC'));
  assert.equal(identKey(decomposed), 'musteriadi'); // a decomposed ü and ş are the same letters
  assert.ok(maskSql('SELECT [Müşteri Adı], "Doğum Tarihi" FROM t').text.includes('qi__Musteri_Adi'));
  assert.ok(maskSql('SELECT [Müşteri Adı], "Doğum Tarihi" FROM t').text.includes('qi__Dogum_Tarihi'));
  assert.equal(personalColumnName(decomposed), true);
  assert.equal(personalColumnName('_'), false);
  assert.equal(personalColumnName(''), false);
  // Full-width letters are the same letters to a width-insensitive collation (the default of SQL Server).
  const wide = (s) => s.replace(/[A-Za-z]/g, (c) => String.fromCharCode(c.charCodeAt(0) + 0xFEE0));
  assert.notEqual(wide('Email'), 'Email');
  assert.equal(identKey(wide('Email')), 'email');
  assert.equal(personalColumnName(wide('Telefon')), true);
  personalAsk(`sqlcmd -S . -E -Q "SELECT TOP 10 ${wide('Email')}, [${wide('Musteri Adi')}] FROM t"`);
  // sources.sqlRead.personalColumns: a name, its plural, a numbered and a spaced or quoted spelling, accents folded.
  const listed = { ...ON, personalColumns: ['LoyaltyCode', 'Müşteri Kodu'] };
  for (const col of ['LoyaltyCode', 'LoyaltyCodes', 'Loyalty_Code2', '[Loyalty Code]', 'loyalty_code', 'MusteriKodu', '[Musteri Kodu]', '[Müşteri Kodu]']) {
    personalAsk(`sqlcmd -S . -E -Q "SELECT TOP 10 ${col} FROM t"`, listed);
  }
  assert.equal(kind('sqlcmd -S . -E -Q "SELECT TOP 10 Region FROM t"', listed), 'pass');
});

test('sql audit S6: plural, numbered and underscored English personal names ask', () => {
  for (const col of ['Emails', 'Addresses', 'PhoneNumbers', 'Phones', 'Mobiles', 'Faxes', 'Streets', 'Passports', 'IBANs', 'SSNs', 'Passwords',
    'FirstNames', 'Email1', 'Email_2', 'Phone2', 'Address_Line_3', 'Mobile3', 'E_Mails', 'Telefonlar', 'Adresler', 'Vornamen', 'Dogum_Tarihi2']) {
    assert.ok(personalColumnName(col), col);
    personalAsk(`sqlcmd -S . -E -Q "SELECT TOP 10 ${col} FROM dbo.t"`);
  }
  for (const cmd of [
    'sqlcmd -S . -E -Q "SELECT TOP 10 Emails FROM dbo.t"',
    'sqlcmd -S . -E -Q "SELECT TOP 10 Addresses FROM dbo.t"',
    'sqlcmd -S . -E -Q "SELECT TOP 10 PhoneNumbers FROM dbo.t"',
    'psql -X -h localhost -c "SELECT phones, emails FROM people LIMIT 10"',
  ]) personalAsk(cmd);
  // Singular names and words that only look like one stay as they were.
  for (const col of ['Region', 'Classes', 'Amount', 'Sales', 'Taxes', 'Hotels', 'Cities']) assert.equal(personalColumnName(col), false, col);
  assert.equal(personalColumnName('Email'), true);
  assert.equal(personalColumnName('Phone'), true);
});

test('sql audit S2: a shell variable in a psql query text asks, as for sqlcmd; a single-quoted dollar quote still passes', () => {
  for (const cmd of [
    'psql -X -h localhost -c "SELECT COUNT(*) FROM $TBL"',
    'T=sales psql -X -h localhost -c "SELECT COUNT(*) FROM $T"',
    'psql -X -h localhost -c "SELECT COUNT(*) FROM ${TBL}"',
    // The shell expands a variable inside a SQL string too, and a bash default value builds the keyword itself.
    'psql -X -h localhost -c "SELECT COUNT(*) FROM t WHERE a = \'$X\'"',
    'psql -X -h localhost -c "WITH d AS (${A:-DEL}ETE FROM t RETURNING 1) SELECT COUNT(*) FROM d"',
    // A bash command substitution builds the SQL itself: the inner command is judged, its output is not.
    'sqlcmd -S . -E -Q "SELECT COUNT(*) FROM `echo t`"',
    'psql -X -h localhost -c "WITH d AS (DEL`echo`ETE FROM t RETURNING 1) SELECT COUNT(*) FROM d"', // bash: DELETE
    // A positional or special parameter expands to nothing and splits a keyword: DEL$1ETE runs as DELETE.
    'psql -X -h localhost -c "WITH d AS (DEL$1ETE FROM t RETURNING 1) SELECT COUNT(*) FROM d"',
    'psql -X -h localhost -c "WITH d AS (DEL$@ETE FROM t RETURNING 1) SELECT COUNT(*) FROM d"',
    'sqlcmd -S . -E -Q "WITH d AS (DEL$1ETE FROM t OUTPUT deleted.a) SELECT COUNT(*) FROM d"',
    'sqlcmd -S . -E -Q "WITH d AS (DEL$*ETE FROM t OUTPUT deleted.a) SELECT COUNT(*) FROM d"',
    'sqlcmd -S . -E -Q "SELECT COUNT(*) FROM t WHERE Amount > $100"', // a money literal reads like $1 followed by 00
    'Invoke-Sqlcmd -ServerInstance . -Query "SELECT COUNT(*) FROM t WHERE a = $1"',
    // Single quotes expand nothing, but the guard asks as it does for sqlcmd: any variable in a query text.
    "psql -X -h localhost -c 'SELECT COUNT(*) FROM $TBL'",
    "psql -X -h localhost -c 'SELECT count(*) FROM t WHERE body = $$ $X $$'",
    // Outside single quotes the shell expands a dollar quote too ($$ is its process number, $tag a variable).
    'psql -X -h localhost -c "SELECT count(*) FROM t WHERE x = $$ ; DELETE FROM t; -- $$"',
    'psql -X -h localhost -c "SELECT count(*) FROM t WHERE x = $tag$ a $tag$"',
    "psql -X -h localhost -U \"$USER\" -c 'SELECT count(*) FROM t WHERE body = $$x$$'", // plain quoting only: anything else asks
    'sqlcmd -S . -E -Q "SELECT COUNT(*) FROM $TBL"', // the twin that always asked
  ]) assert.equal(kind(cmd, ON), 'floor', cmd);
  const v = analyzeShellCommand('psql -X -h localhost -c "SELECT count(*) FROM t WHERE x = $$ ; DELETE FROM t; -- $$"', { sqlRead: ON });
  assert.match(v.reason, /dollar quote/);
  assert.match(analyzeShellCommand('psql -X -h localhost -c "SELECT COUNT(*) FROM $TBL"', { sqlRead: ON }).reason, /shell variable/);
  // PostgreSQL dollar quotes in a single-quoted word, and a text with no dollar at all, pass.
  for (const cmd of [
    "psql -X -h localhost -c 'SELECT count(*) FROM t WHERE body = $$DELETE FROM t$$'",
    "psql -X -h localhost -c 'SELECT count(*) FROM t WHERE body = $note$a; b$note$'",
    "psql -X -h localhost -U reader -c 'SELECT count(*) FROM t WHERE body = $$x$$ AND y = $$z$$'",
    'psql -X -h localhost -c "SELECT count(*) FROM t WHERE body = \'a\'"',
  ]) assert.equal(kind(cmd, ON), 'pass', cmd);
  // A write hidden in a dollar quote is still seen where the guard reads it as SQL, and denied.
  assert.equal(kind('psql -X -h localhost -c "SELECT count(*) FROM t; DELETE FROM t; SELECT $$x$$"', ON), 'deny');
});

test('sql audit S3: a variable in a connection string or conninfo asks: it can add a server the allow-list never sees', () => {
  for (const cmd of [
    'Invoke-Sqlcmd -ConnectionString "Server=.;$cs" -Query "SELECT COUNT(*) FROM t"',
    'Invoke-Sqlcmd -ConnectionString "Server=.;${x}" -Query "SELECT COUNT(*) FROM t"',
    'Invoke-Sqlcmd -ConnectionString "Server=.;$env:CS" -Query "SELECT COUNT(*) FROM t"',
    'Invoke-Sqlcmd -ConnectionString "Server=.;$(\'Server=prod01\')" -Query "SELECT COUNT(*) FROM t"',
    'Invoke-Sqlcmd -ConnectionString "Server=.;%CS%" -Query "SELECT COUNT(*) FROM t"',
    'Invoke-Sqlcmd -ConnectionString "Server=.;Database=$db" -Query "SELECT COUNT(*) FROM t"',
    'Invoke-Sqlcmd -ConnectionString $cs -Query "SELECT COUNT(*) FROM t"',
    'Invoke-Sqlcmd -ConnectionString:"Server=.;$cs" -Query "SELECT COUNT(*) FROM t"',
    'psql -X --dbname="host=localhost $x" -c "SELECT COUNT(*) FROM t"',
    'psql -X -d "host=localhost $x" -c "SELECT COUNT(*) FROM t"',
    'psql -X "host=localhost $x" -c "SELECT COUNT(*) FROM t"',
    'psql -X -h localhost -d "lab${x}" -c "SELECT COUNT(*) FROM t"',
    'psql -X "postgresql://reader@localhost/lab?$x" -c "SELECT COUNT(*) FROM t"',
    'psql -X "postgresql://reader@localhost/lab?$(echo host=prod)" -c "SELECT COUNT(*) FROM t"',
    'psql -X -d "host=localhost $1" -c "SELECT COUNT(*) FROM t"',
  ]) assert.equal(kind(cmd, ON), 'floor', cmd);
  const v = analyzeShellCommand('Invoke-Sqlcmd -ConnectionString "Server=.;$cs" -Query "SELECT COUNT(*) FROM t"', { sqlRead: ON });
  assert.match(v.reason, /variable or expression in the connection string/);
  // The same strings without a variable pass, a listed server in the string included.
  for (const cmd of [
    'Invoke-Sqlcmd -ConnectionString "Server=.;Database=lab" -Query "SELECT COUNT(*) FROM t"',
    'psql -X -d "host=localhost dbname=lab" -c "SELECT COUNT(*) FROM t"',
    'psql -X -h localhost -d lab -c "SELECT COUNT(*) FROM t"',
    'psql -X "postgresql://reader@localhost/lab?sslmode=require" -c "SELECT COUNT(*) FROM t"',
  ]) assert.equal(kind(cmd, ON), 'pass', cmd);
  // An unlisted server in the string still asks for its own reason.
  assert.match(analyzeShellCommand('Invoke-Sqlcmd -ConnectionString "Server=prod01" -Query "SELECT COUNT(*) FROM t"', { sqlRead: ON }).reason, /not in sources\.sqlRead\.servers/);
});

test('sql audit S4: DISTINCT inside an aggregate is still one row; SELECT DISTINCT is not', () => {
  for (const cmd of [
    'sqlcmd -S . -E -Q "SELECT COUNT(DISTINCT CustomerKey) FROM dbo.Sales"',
    'sqlcmd -S . -E -Q "SELECT SUM(DISTINCT Amount) FROM dbo.Sales"',
    'sqlcmd -S . -E -Q "SELECT AVG(DISTINCT Amount) FROM dbo.Sales"',
    'sqlcmd -S . -E -Q "SELECT COUNT(DISTINCT a), COUNT(DISTINCT b) FROM t"',
    'sqlcmd -S . -E -Q "SELECT ROUND(AVG(DISTINCT Amount), 2) FROM dbo.Sales"',
    'sqlcmd -S . -E -Q "SELECT COUNT(DISTINCT x) FROM (SELECT DISTINCT a AS x FROM t) q"',
    'sqlcmd -S . -E -Q "SELECT DISTINCT TOP 10 Region FROM t"',
    'psql -X -h localhost -c "SELECT count(DISTINCT region) FROM sales"',
    'psql -X -h localhost -c "select count(distinct region) from sales"',
  ]) assert.equal(kind(cmd, ON), 'pass', cmd);
  for (const cmd of [
    'sqlcmd -S . -E -Q "SELECT DISTINCT Region FROM t"',
    'sqlcmd -S . -E -Q "SELECT DISTINCT(Region) FROM t"',
    'sqlcmd -S . -E -Q "SELECT DISTINCT COUNT(*) FROM t"',
    'sqlcmd -S . -E -Q "SELECT COUNT(DISTINCT Region), Region FROM t GROUP BY Region"',
    'sqlcmd -S . -E -Q "SELECT COUNT(DISTINCT x) OVER () FROM t"',
    'psql -X -h localhost -c "SELECT DISTINCT ON (region) region FROM sales"',
  ]) {
    const v = analyzeShellCommand(cmd, { sqlRead: ON });
    assert.equal(v?.floor, true, cmd);
    assert.match(v.reason, /not bounded/, cmd);
  }
  assert.equal(mcpKind('mssql', 'read_query', { query: 'select count(distinct region) from sales' }), 'pass');
  assert.equal(mcpKind('mssql', 'read_query', { query: 'SELECT DISTINCT region FROM sales' }), 'floor');
});

test('sql audit S5: camelCase, PascalCase and dotted MCP tool names are read word by word', () => {
  // A write verb denies (the tool carries structured arguments, not SQL).
  for (const tool of ['insertRows', 'deleteRecord', 'createIndex', 'updateRow', 'dropTable', 'truncateTable', 'alterTable', 'InsertRows',
    'bulkLoad', 'rows.insert', 'table.delete', 'upsertRecords', 'grantAccess']) {
    assert.equal(mcpKind('mssql', tool, { rows: [{ a: 1 }], id: 1, table: 't' }), 'deny', tool);
  }
  // A describing tool without SQL text passes; one that reads rows has no bound the guard sees.
  for (const tool of ['listTables', 'describeTable', 'getSchema', 'listDatabases', 'showTables', 'ListTables', 'schema.list']) {
    assert.equal(mcpKind('mssql', tool, { table: 't' }), 'pass', tool);
  }
  for (const tool of ['readTable', 'getRows', 'listRows', 'sampleData', 'frobnicate']) assert.equal(mcpKind('mssql', tool, { table: 't' }), 'floor', tool);
  // A query tool judges the SQL it carries.
  for (const tool of ['executeQuery', 'readQuery', 'runQuery', 'executeSql', 'ExecuteQuery', 'query.run']) {
    assert.equal(mcpKind('mssql', tool, { query: 'SELECT COUNT(*) FROM t' }), 'pass', tool);
    assert.equal(mcpKind('mssql', tool, { query: 'SELECT Region, SalesAmount FROM t' }), 'floor', tool);
    assert.equal(mcpKind('mssql', tool, { query: 'DELETE FROM t' }), 'deny', tool);
  }
  // On a server whose name does not look like a database, a camelCase query tool is still a SQL tool.
  assert.equal(mcpKind('azure', 'runQuery', { query: 'DELETE FROM t' }), 'deny');
  assert.equal(mcpKind('azure', 'runQuery', { query: 'SELECT COUNT(*) FROM t' }), 'floor');
  assert.equal(mcpKind('claude_ai_Claude_Docs', 'queryDocs', { query: 'quarterly plan' }), 'none');
  // snake_case and kebab-case names behave as before.
  assert.equal(mcpKind('mssql', 'write_query', { query: 'SELECT 1' }), 'deny');
  assert.equal(mcpKind('mssql', 'insert-rows', { table: 't' }), 'deny');
  assert.equal(mcpKind('mssql', 'list_tables', {}), 'pass');
  assert.equal(mcpKind('mssql', 'read_query', { query: 'SELECT COUNT(*) FROM t' }), 'pass');
});

test('sql audit S9: a temporary table of the session or a table variable may ride inside a read; a global ## table is a write', () => {
  for (const cmd of [
    'sqlcmd -S . -E -Q "INSERT INTO #t VALUES (1); SELECT COUNT(*) FROM #t"',
    'sqlcmd -S . -E -Q "DECLARE @t TABLE (a int); INSERT INTO @t VALUES (1); SELECT COUNT(*) FROM @t"',
    'sqlcmd -S . -E -Q "SELECT COUNT(*) INTO #t FROM dbo.Sales; SELECT COUNT(*) FROM #t"',
  ]) assert.equal(kind(cmd, ON), 'pass', cmd);
  for (const cmd of [
    'sqlcmd -S . -E -Q "INSERT INTO ##g VALUES (1); SELECT COUNT(*) FROM ##g"',
    'sqlcmd -S . -E -Q "INSERT ##g VALUES (1); SELECT COUNT(*) FROM ##g"',
    'sqlcmd -S . -E -Q "CREATE TABLE ##g (a int); SELECT COUNT(*) FROM ##g"',
    'sqlcmd -S . -E -Q "UPDATE ##g SET a = 2; SELECT COUNT(*) FROM ##g"',
    'sqlcmd -S . -E -Q "DELETE FROM ##g; SELECT COUNT(*) FROM ##g"',
    'sqlcmd -S . -E -Q "TRUNCATE TABLE ##g"',
    'sqlcmd -S . -E -Q "DROP TABLE ##g"',
    'sqlcmd -S . -E -Q "SELECT COUNT(*) INTO ##g FROM dbo.Sales"',
    'sqlcmd -S . -E -Q "SELECT * INTO ##g FROM dbo.Sales"',
    'sqlcmd -S . -E -Q "SELECT TOP 5 a INTO ##g FROM t"',
    'sqlcmd -S . -E -Q "INSERT INTO #t VALUES (1); INSERT INTO ##g SELECT * FROM #t"',
    'sqlcmd -S . -E -Q "INSERT INTO dbo.t VALUES (1); SELECT COUNT(*) FROM dbo.t"', // a real table: denied as before
  ]) assert.equal(kind(cmd, ON), 'deny', cmd);
  assert.equal(judgeSql('INSERT INTO ##g VALUES (1); SELECT COUNT(*) FROM ##g').kind, 'deny');
  assert.equal(judgeSql('INSERT INTO #g VALUES (1); SELECT COUNT(*) FROM #g').kind, 'read');
});

test('sql audit S10: psql --password is a password prompt like -W; --no-password and -w pass', () => {
  for (const cmd of [
    'psql -X --password -h localhost -c "SELECT COUNT(*) FROM sales"',
    'psql -X -W -h localhost -c "SELECT COUNT(*) FROM sales"',
    'psql -XW -h localhost -c "SELECT COUNT(*) FROM sales"',
    'psql -X -h localhost --password -c "SELECT COUNT(*) FROM sales"',
  ]) {
    const v = analyzeShellCommand(cmd, { sqlRead: ON });
    assert.equal(v?.floor, true, cmd);
    assert.match(v.reason, /a password prompt/, cmd);
  }
  for (const cmd of ['psql -X --no-password -h localhost -c "SELECT COUNT(*) FROM sales"', 'psql -X -w -h localhost -c "SELECT COUNT(*) FROM sales"']) {
    assert.equal(kind(cmd, ON), 'pass', cmd);
  }
});

test('sql audit S1 through the hook: personal columns in Turkish and German ask in auto and lab mode; a count passes', () => {
  for (const mode of ['auto', 'lab']) {
    const dir = project({ approvals: { mode }, sources: { sqlRead: ON } });
    try {
      for (const command of [
        'sqlcmd -S . -E -Q "SELECT TOP 10 Telefon, Adres FROM dbo.Musteri"',
        'sqlcmd -S . -E -Q "SELECT TOP 10 [Musteri Adi] FROM dbo.t"',
        'psql -X -h localhost -c "SELECT courriel FROM clients LIMIT 10"',
      ]) {
        const r = guard(dir, 'Bash', { command });
        assert.equal(r.decision, 'ask', `${mode}: ${command}`);
        assert.match(r.reason, /personal or identifying columns/, command);
        assert.ok(!r.events.some((e) => e.event === 'auto-approve'), 'nothing was approved without a prompt');
      }
      assert.equal(guard(dir, 'Bash', { command: 'sqlcmd -S . -E -Q "SELECT COUNT(*) FROM dbo.Sales"' }).decision, 'allow');
      assert.equal(guard(dir, 'Bash', { command: 'psql -X -h localhost -c "WITH d AS (DEL$1ETE FROM t RETURNING 1) SELECT COUNT(*) FROM d"' }).decision, 'ask');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }
});

test('sql: the judge stays fast on long hostile texts (a hook past its timeout lets the call through)', () => {
  const texts = ['SELECT ' + 'x,'.repeat(16000), 'select '.repeat(4600), '[a].'.repeat(8000), 'a.'.repeat(16000) + '(',
    '('.repeat(30000), "SELECT '".concat("''".repeat(15000)), '\nGO\n'.repeat(8000), 'x$$'.repeat(10000), 'a '.repeat(16000) + '*'];
  // Many different names (each one is judged for personal data) and many dollar-quote openers that never close (S1, S2).
  texts.push('SELECT ' + Array.from({ length: 3000 }, (_, i) => `Col${i}`).join(','));
  const start = Date.now();
  for (const t of texts) for (const client of ['tsql', 'psql', 'any']) judgeSql(t.slice(0, 32 * 1024), { client });
  const opens = Array.from({ length: 2000 }, (_, i) => `$t${i}$`).join(' ');
  assert.ok(analyzeShellCommand(`psql -X -h localhost -c "SELECT ${opens}"`, { sqlRead: ON }));
  assert.ok(Date.now() - start < 5000, `${Date.now() - start} ms`);
});

test('sql: the password files of SQL clients are secrets for Read, Grep, Edit and the shell (2026-10-12)', () => {
  for (const name of ['.pgpass', 'pgpass.conf', '.my.cnf', '.mylogin.cnf']) {
    assert.equal(classifyPath(`C:/Users/u/AppData/Roaming/postgresql/${name}`).secret, true, name);
    assert.equal(classifyPath(`/home/u/${name}`).secret, true, name);
    for (const cmd of [`cat ~/${name}`, `Get-Content "$env:APPDATA\\postgresql\\${name}"`, `type %APPDATA%\\postgresql\\${name}`]) {
      assert.equal(analyzeShellCommand(cmd, {})?.decision, 'deny', cmd);
    }
  }
  assert.equal(analyzeShellCommand('cat ~/*.cnf', {})?.decision, 'deny');
  assert.equal(classifyPath('docs/my.cnf.md').secret, false);
});

test('sql: a login with a user name and password: the password stays in the user\'s environment or the client\'s file', () => {
  // The user keeps the password where the client reads it (an environment variable set outside the session, .pgpass);
  // the agent names only the user. Reading the variable or the Google sign-in folder, or printing a token, is denied.
  assert.equal(kind('sqlcmd -S . -U reader -d SalesDW -Q "SELECT COUNT(*) FROM dbo.FactSales"', ON), 'pass');
  assert.equal(kind('psql -X -h localhost -U reader -d lab -c "SELECT count(*) FROM sales"', ON), 'pass');
  for (const cmd of [`node -e "console.log(process.env.${'PG'}${PWU})"`, `python -c "import os; print(os.environ['SQLCMD${PWU}'])"`,
    `python -c "import os; print(os.getenv('DB_${PWU}'))"`, `[Environment]::GetEnvironmentVariable('SQLCMD${PWU}')`, `echo %PG${PWU}%`,
    'gcloud auth print-access-token', 'gcloud auth application-default print-access-token', 'az account get-access-token',
    'gh auth token', 'Get-AzAccessToken', 'cat ~/.config/gcloud/application_default_credentials.json',
    'type %APPDATA%\\gcloud\\credentials.db', 'Get-Content $env:APPDATA\\gcloud\\access_tokens.db']) {
    assert.equal(analyzeShellCommand(cmd, {})?.decision, 'deny', cmd);
  }
  for (const p of ['C:/Users/u/AppData/Roaming/gcloud/credentials.db', '/home/u/.config/gcloud/legacy_credentials/x/adc.json']) {
    assert.equal(classifyPath(p).secret, true, p);
  }
  assert.equal(analyzeShellCommand('echo %APPDATA%', {})?.decision, undefined);
  assert.equal(analyzeShellCommand('gcloud auth list', {})?.decision, undefined);
  assert.equal(classifyPath('docs/gcloud/setup.md').secret, false);
});

test('sql security review round 4 (2026-10-12): cross-language env reads, token prints, service file, entangled read', () => {
  // A credential the user keeps in the environment for a SQL client, read from other languages: a hard deny, as for
  // node and python, not a mere prompt. Ruby/PHP ENV[], Ruby ENV.fetch, Perl %ENV, Go/PHP getenv, PHP superglobals.
  for (const cmd of [
    `ruby -e "puts ENV['PG${PWU}']"`,
    `ruby -e "puts ENV.fetch('SQLCMD${PWU}')"`,
    `perl -e "print $ENV{PG${PWU}}"`,
    `php -r "echo getenv('DB_${PWU}');"`,
    `php -r "echo $_ENV['PG${PWU}'];"`,
  ]) assert.equal(analyzeShellCommand(cmd, {})?.decision, 'deny', cmd);
  assert.notEqual(analyzeShellCommand(`ruby -e "puts ENV['HOME']"`, {})?.decision, 'deny'); // a non-secret var stays
  // Printing a sign-in token or password beyond the gcloud/az-account/gh set.
  for (const cmd of ['aws ecr get-login-password', 'aws ecr-public get-login-password', 'aws sts get-session-token',
    'az acr login --name reg --expose-token']) {
    assert.equal(analyzeShellCommand(cmd, {})?.decision, 'deny', cmd);
  }
  // The PostgreSQL connection service file can hold a password: a secret for classify and the shell, like .pgpass.
  for (const name of ['.pg_service.conf', 'pg_service.conf']) {
    assert.equal(classifyPath(`/home/u/${name}`).secret, true, name);
    assert.equal(analyzeShellCommand(`cat ~/${name}`, {})?.decision, 'deny', name);
  }
  // A SQL-read pass that runs together with another command is the floor whatever the subcommand order: strongerAsk
  // must not keep a co-command's plain ask and drop the sqlRead marker (which skipped this downgrade).
  for (const cmd of [
    'sqlcmd -S . -E -Q "SELECT COUNT(*) FROM t" && git rm foo.txt',
    'git rm foo.txt && sqlcmd -S . -E -Q "SELECT COUNT(*) FROM t"',
    'git commit --amend -m x && sqlcmd -S . -E -Q "SELECT COUNT(*) FROM t"',
  ]) assert.equal(kind(cmd, ON), 'floor', cmd);
  assert.equal(kind('sqlcmd -S . -E -Q "SELECT COUNT(*) FROM t"', ON), 'pass'); // alone it still passes
});

test('policy: an ask merged with code the guard cannot see keeps autoDefer, so auto mode never approves the line', () => {
  const v = analyzeShellCommand('git commit --amend -m x; python tools/x.py', {});
  assert.equal(v?.decision, 'ask');
  assert.equal(v.autoDefer, true);
});

test('config: a byte order mark is read past; a broken file falls back to approvals "ask"', () => {
  const make = (text) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-cfg-'));
    fs.mkdirSync(path.join(dir, 'hardening'));
    if (text !== null) fs.writeFileSync(path.join(dir, 'hardening', 'harness.config.json'), text);
    return dir;
  };
  const dirs = [make('\uFEFF{"approvals":{"mode":"ask"}}'), make('{"approvals":'), make(null)];
  try {
    assert.equal(loadConfig(dirs[0]).approvals.mode, 'ask');
    assert.equal(loadConfig(dirs[1]).approvals.mode, 'ask');
    assert.equal(loadConfig(dirs[2]).approvals.mode, DEFAULT_CONFIG.approvals.mode);
  } finally {
    for (const d of dirs) fs.rmSync(d, { recursive: true, force: true });
  }
});

test('sql: query files are read and judged; a write inside one is denied, a bounded read passes', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-sqlfile-'));
  const prev = process.env.CLAUDE_PROJECT_DIR;
  try {
    fs.writeFileSync(path.join(dir, 'read.sql'), 'SET NOCOUNT ON;\nSELECT COUNT(*) FROM dbo.FactSales;\nGO\n');
    fs.writeFileSync(path.join(dir, 'write.sql'), 'SELECT 1;\nGO\nUPDATE dbo.FactSales SET SalesAmount = 0;\n');
    fs.writeFileSync(path.join(dir, 'proc.sql'), 'DECLARE @r TABLE (a int);\nINSERT INTO @r EXEC dbo.p;\nSELECT COUNT(*) FROM @r;\n');
    // The guard resolves files against the shell's directory and keeps them inside the project (CLAUDE_PROJECT_DIR).
    const run = (cmd) => spawnSync(process.execPath, ['--input-type=module', '-e',
      `import { analyzeShellCommand } from ${JSON.stringify(new URL('../hooks/lib/policy.mjs', import.meta.url).href)};
       const v = analyzeShellCommand(${JSON.stringify(cmd)}, { sqlRead: ${JSON.stringify(ON)}, baseDir: ${JSON.stringify(dir)} });
       process.stdout.write(v ? (v.decision === 'deny' ? 'deny' : v.floor ? 'floor' : 'pass') : 'none');`],
    { env: { ...process.env, CLAUDE_PROJECT_DIR: dir }, encoding: 'utf8' }).stdout;
    assert.equal(run('sqlcmd -S . -E -i read.sql'), 'pass');
    assert.equal(run('sqlcmd -S . -E -i read.sql,write.sql'), 'deny');
    assert.equal(run('sqlcmd -S . -E -i write.sql'), 'deny');
    assert.equal(run('sqlcmd -S . -E -i proc.sql'), 'floor');
    assert.equal(run('psql -X -h localhost -f read.sql'), 'pass');
    assert.equal(run('Invoke-Sqlcmd -ServerInstance . -InputFile write.sql'), 'deny');
    // Only .sql files are read (no other file's content in a reason or the log); after a cd the file is not the guard's to read.
    fs.writeFileSync(path.join(dir, 'notes.txt'), 'X=1\n');
    assert.equal(run('sqlcmd -S . -E -i notes.txt'), 'floor');
    // F1-22 (audit 2026-10-18): a short option takes its value glued to it, so `-i.env` names the secret file and the shell guard
    // denies it before the SQL judge runs; it was a floor ask only because the name had no boundary in front of it.
    fs.writeFileSync(path.join(dir, '.env'), 'X=1\n');
    assert.equal(run('sqlcmd -S . -E -i.env'), 'deny');
    assert.equal(run('cd sub && sqlcmd -S . -E -i read.sql'), 'floor');
  } finally {
    if (prev === undefined) delete process.env.CLAUDE_PROJECT_DIR; else process.env.CLAUDE_PROJECT_DIR = prev;
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('sql: SQL clients behind wrappers and nested shells are judged the same way', () => {
  for (const cmd of ['cmd /c "sqlcmd -S . -Q \\"DELETE FROM t\\""', 'pwsh -c "sqlcmd -S . -Q \'DROP TABLE t\'"', '& sqlcmd -S . -Q "TRUNCATE TABLE t"',
    'bash -lc "psql -X -h localhost -c \'DELETE FROM t\'"']) {
    assert.equal(kind(cmd, ON), 'deny', cmd);
  }
  assert.equal(kind('& "C:/Program Files/SqlCmd/sqlcmd.exe" -S . -Q "SELECT COUNT(*) FROM t"', ON), 'pass');
  assert.equal(kind('& "C:/Program Files/SqlCmd/sqlcmd.exe" -S . -Q "SELECT COUNT(*) FROM t"'), 'floor');
});

test('sql: the judge strips comments, literals and quoted names before it looks for keywords', () => {
  assert.equal(judgeSql("SELECT COUNT(*) FROM t WHERE x = 'DROP TABLE t'").kind, 'read');
  assert.equal(judgeSql('SELECT COUNT(*) FROM t -- DELETE FROM t').kind, 'read');
  assert.equal(judgeSql('SELECT COUNT(*) FROM t /* nested /* DELETE */ still comment */').kind, 'read');
  assert.equal(judgeSql('SELECT COUNT(*) FROM t /* nested /* x */ */ DELETE FROM t').kind, 'deny');
  assert.equal(judgeSql("SELECT COUNT(*) FROM t WHERE x = N'it''s; DELETE'").kind, 'read');
  assert.equal(judgeSql('SELECT COUNT(*) FROM "Create"').kind, 'read');
  assert.equal(judgeSql('/* unterminated').kind, 'floor');
  assert.equal(judgeSql('').kind, 'floor');
  assert.deepEqual(judgeSql('SELECT COUNT(*) FROM t').unbounded, []);
});

test('sql MCP: a listed server gets the same judge; an unlisted SQL-looking server always asks; other servers are untouched', () => {
  assert.equal(mcpKind('mssql', 'read_query', { query: 'SELECT COUNT(*) FROM dbo.FactSales' }), 'pass');
  assert.equal(mcpKind('mssql', 'list_tables', {}), 'pass');
  assert.equal(mcpKind('mssql', 'read_query', { query: 'SELECT Region, SalesAmount FROM t' }), 'floor');
  assert.equal(mcpKind('mssql', 'read_query', { query: 'SELECT TOP 10 Email FROM t' }), 'floor');
  assert.equal(mcpKind('mssql', 'read_query', { query: 'SELECT 1; DELETE FROM t' }), 'deny');
  assert.equal(mcpKind('mssql', 'execute_sql', { sql: 'SELECT COUNT(*) FROM t' }), 'pass'); // a runner: judged by its SQL
  assert.equal(mcpKind('mssql', 'execute_sql', { sql: 'DELETE FROM t' }), 'deny');
  assert.equal(mcpKind('mssql', 'execute_sql', {}), 'floor'); // no SQL text the guard sees: it may read without a bound
  assert.equal(mcpKind('mssql', 'write_query', { query: 'SELECT 1' }), 'deny');
  assert.equal(mcpKind('mssql', 'insert_row', { table: 't' }), 'deny');
  assert.equal(mcpKind('mssql', 'frobnicate', { query: 'SELECT 1' }), 'floor');
  assert.equal(mcpKind('mssql', 'read_query', { query: 'SELECT COUNT(*) FROM t' }, { mode: 'off', mcpServers: ['mssql'] }), 'floor');
  assert.equal(mcpKind('postgres', 'query', { sql: 'SELECT count(*) FROM t' }), 'floor');
  assert.equal(mcpKind('azure-sql', 'list_tables', {}), 'floor');
  assert.equal(mcpKind('postgres', 'query', { sql: 'DROP TABLE t' }), 'deny');
  assert.equal(mcpKind('mssql', 'read_query', { nested: { request: { query: 'UPDATE t SET a = 1' } } }), 'deny');
  // Not SQL servers: the Power BI modeling server, Learn, GitHub and Figma keep their own rules.
  assert.notEqual(mcpKind('powerbi-modeling', 'dax_query_operations', { request: { operation: 'Execute', query: 'EVALUATE ROW("a", 1)', maxRows: 1 } }), 'floor');
  assert.equal(mcpKind('microsoft-learn', 'microsoft_docs_search', { query: 'DELETE' }), 'none');
});

test('sql: the agent may only make the switch stricter', () => {
  const on = { sources: { sqlRead: { mode: 'on', servers: ['localhost'], mcpServers: ['mssql'], maxRows: 50, personalColumns: ['segment'] } } };
  const set = (patch) => ({ sources: { sqlRead: { ...on.sources.sqlRead, ...patch } } });
  assert.equal(sqlReadWidened({}, on), true); // off -> on
  assert.equal(sqlReadWidened(on, set({ mode: 'off' })), false);
  assert.equal(sqlReadWidened(on, set({ servers: [] })), false);
  assert.equal(sqlReadWidened(on, set({ servers: ['localhost', 'prod'] })), true);
  assert.equal(sqlReadWidened(on, set({ servers: ['.'] })), false); // the same machine
  assert.equal(sqlReadWidened(on, set({ mcpServers: ['mssql', 'pg'] })), true);
  assert.equal(sqlReadWidened(on, set({ maxRows: 10 })), false);
  assert.equal(sqlReadWidened(on, set({ maxRows: 500 })), true);
  assert.equal(sqlReadWidened(on, set({ personalColumns: [] })), true);
  assert.equal(sqlReadWidened(on, set({ personalColumns: ['segment', 'city'] })), false);
});

function project(config) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-sqlguard-'));
  fs.mkdirSync(path.join(dir, 'hardening'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'hardening', 'harness.config.json'), `${JSON.stringify(config, null, 2)}\n`);
  return dir;
}
function guard(dir, tool_name, tool_input) {
  const r = spawnSync(process.execPath, [preHook], {
    input: JSON.stringify({ hook_event_name: 'PreToolUse', session_id: 'sqlread', tool_name, tool_input }),
    env: { ...process.env, CLAUDE_PROJECT_DIR: dir },
    encoding: 'utf8',
  });
  assert.equal(r.status, 0, r.stderr);
  const out = r.stdout.trim() ? JSON.parse(r.stdout).hookSpecificOutput : {};
  const log = path.join(dir, '.claude', 'logs', 'security-events.jsonl');
  const events = fs.existsSync(log) ? fs.readFileSync(log, 'utf8').trim().split('\n').map((l) => JSON.parse(l)) : [];
  return { decision: out.permissionDecision ?? null, reason: out.permissionDecisionReason ?? '', events };
}

test('sql guard: lab and auto pass a bounded read only with the switch on; ask mode still prompts; writes are denied', () => {
  const read = 'sqlcmd -S . -E -Q "SELECT COUNT(*) FROM dbo.FactSales"';
  const write = 'sqlcmd -S . -E -Q "DELETE FROM dbo.FactSales"';
  for (const [config, want] of [
    [{ approvals: { mode: 'lab' } }, 'ask'],
    [{ approvals: { mode: 'auto' } }, 'ask'],
    [{ approvals: { mode: 'lab' }, sources: { sqlRead: ON } }, 'allow'],
    [{ approvals: { mode: 'auto' }, sources: { sqlRead: ON } }, 'allow'],
    [{ approvals: { mode: 'ask' }, sources: { sqlRead: ON } }, 'ask'],
  ]) {
    const dir = project(config);
    try {
      const r = guard(dir, 'Bash', { command: read });
      assert.equal(r.decision, want, JSON.stringify(config));
      if (want === 'allow' && config.approvals.mode === 'auto') {
        assert.ok(r.events.some((e) => e.event === 'auto-approve' && /SQL read \(sources\.sqlRead on\)/.test(e.reason)), 'the read is logged');
      }
      assert.equal(guard(dir, 'PowerShell', { command: write }).decision, 'deny');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }
});

test('sql guard: the agent cannot turn the switch on or widen it; it can turn it off', () => {
  const dir = project({ approvals: { mode: 'auto' }, sources: { referenceCopies: ['docs/sources/*/definition/**'], sqlRead: { mode: 'off' } } });
  try {
    const file_path = path.join(dir, 'hardening', 'harness.config.json');
    const write = (cfg) => guard(dir, 'Write', { file_path, content: `${JSON.stringify(cfg, null, 2)}\n` }).decision;
    const base = { approvals: { mode: 'auto' }, sources: { referenceCopies: ['docs/sources/*/definition/**'] } };
    assert.equal(write({ ...base, sources: { ...base.sources, sqlRead: { mode: 'on', servers: ['localhost'] } } }), 'deny');
    fs.writeFileSync(file_path, `${JSON.stringify({ ...base, sources: { ...base.sources, sqlRead: ON } }, null, 2)}\n`); // the user turned it on
    assert.notEqual(write({ ...base, sources: { ...base.sources, sqlRead: { ...ON, mode: 'off' } } }), 'deny');
    assert.notEqual(write({ ...base, sources: { ...base.sources, sqlRead: { ...ON, servers: ['localhost'] } } }), 'deny');
    assert.equal(write({ ...base, sources: { ...base.sources, sqlRead: { ...ON, servers: [...ON.servers, 'prod'] } } }), 'deny');
    assert.equal(write({ ...base, sources: { ...base.sources, sqlRead: { ...ON, maxRows: 5000 } } }), 'deny');
    assert.equal(write({ ...base, sources: { referenceCopies: [], sqlRead: ON } }), 'deny'); // other config parts stay the user's
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('sql: the session start says whether the switch is on and for which servers', () => {
  for (const [config, want] of [
    [{}, /SQL read switch: off\. Every query/],
    [{ sources: { sqlRead: { mode: 'yes' } } }, /SQL read switch: off \(sources\.sqlRead\.mode "yes" is not "on"\)/],
    [{ sources: { sqlRead: ON } }, /SQL read switch: ON for localhost, sql-test01 and the MCP server\(s\) mssql/],
  ]) {
    const dir = project(config);
    try {
      const r = spawnSync(process.execPath, [startHook], {
        input: JSON.stringify({ hook_event_name: 'SessionStart', source: 'startup', session_id: 'sqlread' }),
        env: { ...process.env, CLAUDE_PROJECT_DIR: dir },
        encoding: 'utf8',
      });
      assert.equal(r.status, 0, r.stderr);
      assert.match(JSON.parse(r.stdout).hookSpecificOutput.additionalContext, want);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }
});

test('report CLI 0.5.0: unpack is denied, a Desktop reload or a service preview asks, the read-only helpers are routine', () => {
  assert.equal(analyzeShellCommand('powerbi-report-author unpack ./Sales.Report --input d.json --force', {})?.decision, 'deny');
  assert.equal(analyzeShellCommand('az rest --url x | powerbi-report-author unpack ./Sales.Report', {})?.decision, 'deny');
  const reload = analyzeShellCommand('powerbi-report-author preview ./Sales.Report --host desktop --reload-with-model', {});
  assert.equal(reload?.decision, 'ask');
  assert.equal(reload?.autoApprovable, false);
  assert.equal(analyzeShellCommand('powerbi-report-author preview ./Sales.Report --host service', {})?.floor, true);
  assert.equal(analyzeShellCommand('powerbi-report-author preview ./Sales.Report --host=service', {})?.floor, true);
  assert.equal(analyzeShellCommand('powerbi-report-author pack ./Sales.Report --raw | az rest --method post --url x --body @-', {})?.floor, true);
});

// Audit S7: a variable set in front of a SQL client (PATH=, LD_PRELOAD=, `env X=y`) can start another program under the client's name
// or load a library into it, while normalizeTokens dropped the `VAR=` prefix and only the SQL variables were floored, so the bounded
// read passed in auto and lab mode. A variable or `env` in front of the client is a floor ask; the SQL client and password variables
// keep their own verdicts (a startup variable is a floor ask with its own reason, a password is denied, a write is denied).
test('sql audit S7: a variable or env set in front of a SQL client is a floor ask, never a pass', () => {
  const read = 'sqlcmd -S . -E -Q "SELECT COUNT(*) FROM t"';
  assert.equal(kind(read, ON), 'pass');
  for (const cmd of ['PATH=/tmp/evil:$PATH sqlcmd -S . -E -Q "SELECT COUNT(*) FROM t"', 'LD_PRELOAD=x.so psql -X -h localhost -c "SELECT COUNT(*) FROM t"',
    `FOO=bar ${read}`, `env FOO=bar ${read}`, `env ${read}`, `env -i ${read}`, `A=1 B=2 ${read}`, `DYLD_INSERT_LIBRARIES=x.dylib ${read}`, `IFS=, ${read}`,
    `BASH_ENV=x.sh ${read}`, `LD_LIBRARY_PATH=/tmp/x ${read}`, `env PATH=/tmp/x psql -X -h localhost -c "SELECT COUNT(*) FROM t"`, `FOO=bar time ${read}`,
    `nice -n 5 FOO=bar ${read}`, `(FOO=bar ${read})`]) {
    const v = analyzeShellCommand(cmd, { sqlRead: ON });
    assert.equal(v?.decision, 'ask', cmd);
    assert.equal(v.floor, true, `${cmd}: even lab mode asks`);
    assert.match(v.reason, /a variable set in front of the client/, cmd);
    assert.equal(kind(cmd, ON), 'floor', cmd);
  }
  // The names are in the reason, the values are not.
  const v = analyzeShellCommand('PATH=/tmp/evil:$PATH LD_PRELOAD=x.so sqlcmd -S . -E -Q "SELECT COUNT(*) FROM t"', { sqlRead: ON });
  assert.match(v.reason, /\(PATH, LD_PRELOAD\)/);
  assert.doesNotMatch(v.reason, /evil|x\.so/);
  // The verdicts the client gave before still come first.
  assert.equal(kind('PATH=/tmp/evil:$PATH sqlcmd -S . -E -Q "DELETE FROM t"', ON), 'deny');
  assert.equal(kind(`PG${PWU}=x PATH=/x psql -X -h localhost -c "SELECT 1"`, ON), 'deny');
  assert.match(analyzeShellCommand('SQLCMDINI=evil.sql PATH=/x sqlcmd -S . -Q "SELECT 1"', { sqlRead: ON }).reason, /SQL client environment variable/);
  assert.equal(kind('PATH=/x sqlcmd -S . -E -Q "SELECT TOP 51 Region FROM t"', ON), 'floor');
  // Without a variable in front, and behind wrappers that set none, the bounded read still passes.
  for (const cmd of [read, `time ${read}`, `nice -n 5 ${read}`, `command ${read}`, `nohup ${read}`, `& ${read}`, 'psql -X -h localhost -c "SELECT COUNT(*) FROM t"']) {
    assert.equal(kind(cmd, ON), 'pass', cmd);
  }
  // A variable set on another command of the line is the next rule's business: the SQL read passes only as a command of its own.
  assert.equal(kind(`FOO=bar echo x; ${read}`, ON), 'floor');
  assert.equal(kind(`$env:PATH = "x"; ${read}`, ON), 'floor');
});

test('sql audit S7: through the hook a variable in front of the client is never answered allow, in auto or lab mode', () => {
  const read = 'sqlcmd -S . -E -Q "SELECT COUNT(*) FROM dbo.FactSales"';
  for (const mode of ['auto', 'lab']) {
    const dir = project({ approvals: { mode }, sources: { sqlRead: ON } });
    const control = project({ approvals: { mode }, sources: { sqlRead: ON } });
    try {
      assert.equal(guard(control, 'Bash', { command: read }).decision, 'allow', `${mode}: the plain read passes with the switch on`);
      for (const command of [`PATH=/tmp/evil:$PATH ${read}`, 'LD_PRELOAD=x.so psql -X -h localhost -c "SELECT COUNT(*) FROM t"', `FOO=bar ${read}`, `env FOO=bar ${read}`]) {
        for (const tool of ['Bash', 'PowerShell']) {
          const r = guard(dir, tool, { command });
          assert.equal(r.decision, 'ask', `${mode} ${tool}: ${command}`);
          assert.ok(!r.events.some((e) => e.event === 'auto-approve' || e.event === 'lab-approve'), `${mode}: nothing is approved`);
        }
      }
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
      fs.rmSync(control, { recursive: true, force: true });
    }
  }
});
