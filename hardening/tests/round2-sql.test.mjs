// Follow-up audit, group D (2026-10-19): the SQL read switch (hardening/hooks/lib/sql-read.mjs).
// F2-7: psql reaches every host and hostaddr of its connection (libpq): a conninfo string with several keys, a host list,
//   the hosts of a URI and its query parameters. Every one must be a listed server; what the guard cannot read asks.
// S8: a SQL MCP call larger than 64 KB, or a query text longer than 32 KB, that carries a write is denied, not asked;
//   anything else that size still asks.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { DEFAULT_CONFIG } from '../hooks/lib/common.mjs';
import { analyzeMcpCall, analyzeShellCommand } from '../hooks/lib/policy.mjs';
import { analyzeSqlClient, judgeSql } from '../hooks/lib/sql-read.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const preHook = path.join(here, '..', 'hooks', 'pre-tool-use.mjs');
// Fake credential words are joined at run time, never written as one literal (README, Adding a hook).
const PW = ['pass', 'word'].join('');

// The lead's reproduction config: one server, this machine.
const ON = { mode: 'on', servers: ['localhost'], mcpServers: ['mssql'], maxRows: 50, personalColumns: [] };
/** 'deny', 'floor' (asks in every mode), 'pass' (a plain ask auto and lab approve), or 'none'. */
function kind(cmd, sqlRead = ON) {
  const v = analyzeShellCommand(cmd, { sqlRead });
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
const Q = '-c "SELECT COUNT(*) FROM orders"';

test('round2 F2-7: every host and hostaddr of a psql conninfo string must be listed, not only the first', () => {
  for (const conn of [
    'host=localhost hostaddr=10.9.9.9 dbname=sales', // libpq connects to hostaddr
    'host=localhost host=10.9.9.9 dbname=sales', // the last host wins
    'host = localhost  hostaddr = 10.9.9.9 dbname=sales', // blanks around "="
    "host=localhost hostaddr='10.9.9.9' dbname=sales", // a quoted value
    "dbname='sales'hostaddr=10.9.9.9 host=localhost", // a key right after a quoted value, without a blank
    "host=localhost dbname='a b' hostaddr=10.9.9.9",
    'host=localhost,10.9.9.9 dbname=sales', // a host list: libpq tries each in turn
    'host=localhost hostaddr=127.0.0.1,10.9.9.9 dbname=sales',
    'host=localhost, dbname=sales', // an empty entry is libpq's default server
    "host='' dbname=sales",
  ]) {
    assert.equal(kind(`psql -X -d "${conn}" ${Q}`), 'floor', conn);
    assert.equal(kind(`psql -X "${conn}" ${Q}`), 'floor', `positional: ${conn}`);
    assert.equal(kind(`psql -X --dbname="${conn}" ${Q}`), 'floor', `--dbname: ${conn}`);
  }
  // The analyzer itself, as the audit record sketches it.
  const v = analyzeSqlClient('psql', ['-X', '-d', 'host=localhost hostaddr=10.9.9.9 dbname=s', '-c', 'SELECT COUNT(*) FROM t'], 'psql ...', { sqlRead: ON });
  assert.equal(v.decision, 'ask');
  assert.equal(v.floor, true);
  assert.match(v.reason, /server 10\.9\.9\.9 is not in sources\.sqlRead\.servers/);
});

test('round2 F2-7: every host of a psql URI (host list, query parameters) must be listed', () => {
  for (const uri of [
    'postgresql://localhost/sales?hostaddr=10.9.9.9',
    'postgresql://localhost/sales?host=10.9.9.9',
    'postgresql://localhost/sales?sslmode=require&hostaddr=10.9.9.9',
    'postgresql://localhost:5432,10.9.9.9:5432/sales', // a multi-host URI with ports
    'postgresql://localhost,10.9.9.9/sales',
    'postgres://reader@localhost,10.9.9.9/sales',
    'postgresql://[::1]:5432,[2001:db8::1]:5432/sales',
    'postgresql://localhost?x=@10.9.9.9/sales', // libpq reads up to the first "@" as the user
    'postgresql://localhost/sales?%68ost=10.9.9.9', // libpq decodes the parameter name: host
    'postgresql://localhost%2C10.9.9.9/sales', // a decoded "," makes a host list
    'postgresql://,10.9.9.9/sales',
  ]) {
    assert.equal(kind(`psql -X -d "${uri}" ${Q}`), 'floor', uri);
    assert.equal(kind(`psql -X "${uri}" ${Q}`), 'floor', `positional: ${uri}`);
  }
});

test('round2 F2-7: every -h/--host entry must be listed, each one named on its own', () => {
  for (const cmd of [
    `psql -X -h localhost,10.9.9.9 -d sales ${Q}`,
    `psql -X --host=localhost,10.9.9.9 -d sales ${Q}`,
    `psql -X -h localhost -h 10.9.9.9 -d sales ${Q}`,
    `psql -X -h localhost -d "host=localhost hostaddr=10.9.9.9" ${Q}`,
  ]) {
    assert.equal(kind(cmd), 'floor', cmd);
    assert.match(analyzeShellCommand(cmd, { sqlRead: ON }).reason, /server 10\.9\.9\.9 is not in/, cmd);
  }
});

test('round2 F2-7: a service, a broken conninfo or a server variable asks; a password key is denied', () => {
  for (const cmd of [
    `psql -X -d "service=prod" ${Q}`,
    `psql -X -h localhost -d "host=localhost dbname='x'service=prod" ${Q}`, // service right after a quoted value
    `psql -X -d "postgresql://localhost/sales?service=prod" ${Q}`,
    `psql -X -d "host=localhost dbname='sales" ${Q}`, // an unterminated quote
    `psql -X -d "host=localhost sales" ${Q}`, // a key without "="
    `psql -X -d "postgresql://[::1/sales" ${Q}`, // an unterminated IPv6 bracket
    `psql -X -d "postgresql://localhost/sales?hostaddr" ${Q}`, // a parameter without "="
    `PGHOSTADDR=10.9.9.9 psql -X -h localhost -d sales ${Q}`, // the environment prefix (STARTUP_ENV_RE, S7)
    `PGHOST=10.9.9.9 psql -X -d sales ${Q}`,
    `env PGSERVICE=prod psql -X -h localhost -d sales ${Q}`,
    `$env:PGHOSTADDR = '10.9.9.9'; psql -X -h localhost -d sales ${Q}`,
    // Windows passes psql its arguments in the code page and maps a full-width "＝" to "=": the guard cannot read them.
    `psql -X -d "dbname=sales hostaddr＝10.9.9.9 host=localhost" ${Q}`,
    `psql -X -h localhost -d "hostaddr＝10.9.9.9" ${Q}`,
    `psql -X -h localhost -d "sales hostaddr=10.9.9.9" ${Q}`,
    `psql -X -h localhost，10.9.9.9 -d sales ${Q}`,
  ]) assert.equal(kind(cmd), 'floor', cmd);
  for (const cmd of [
    `psql -X -d "host=localhost dbname='x'${PW}=abc" ${Q}`, // a password key right after a quoted value
    `psql -X -d "host=localhost ${PW} = abc" ${Q}`,
    `psql -X -d "postgresql://localhost/sales?${PW}=abc" ${Q}`,
  ]) assert.equal(kind(cmd), 'deny', cmd);
});

test('round2 F2-7: a listed server still passes, also as a host/hostaddr pair, a URI or a host list of listed names', () => {
  for (const cmd of [
    `psql -X -h localhost -d sales ${Q}`,
    `psql -X -d "host=localhost hostaddr=127.0.0.1 dbname=sales" ${Q}`, // 127.0.0.1 is this machine: normalizeServer
    `psql -X -d "host='localhost' dbname=sales sslmode=require" ${Q}`,
    `psql -X -h localhost,127.0.0.1 -d sales ${Q}`,
    `psql -X "postgresql://reader@localhost:5432/lab" ${Q}`,
    `psql -X -d "postgresql://localhost/sales?sslmode=require&application_name=probe" ${Q}`,
    `psql -X -d "postgresql://[::1]:5432/sales" ${Q}`,
    `psql -X -h localhost -d sales -U reader ${Q}`,
  ]) assert.equal(kind(cmd), 'pass', cmd);
  // A listed remote pair passes; one unlisted half asks.
  const two = { ...ON, servers: ['db1.example.org', '10.1.2.3'] };
  assert.equal(kind(`psql -X -d "host=db1.example.org hostaddr=10.1.2.3 dbname=sales" ${Q}`, two), 'pass');
  assert.equal(kind(`psql -X -d "host=db1.example.org hostaddr=10.1.2.3 dbname=sales" ${Q}`, { ...ON, servers: ['db1.example.org'] }), 'floor');
});

test('round2 S8: a SQL MCP call over 64 KB that carries a write is denied; a read that size still asks', () => {
  const pad = 'x'.repeat(70000);
  assert.equal(mcpKind('mssql', 'read_query', { query: 'DELETE FROM t', pad }), 'deny');
  assert.equal(mcpKind('mssql', 'read_query', { params: { sql: 'DROP TABLE t' }, pad }), 'deny');
  assert.equal(mcpKind('mssql', 'read_query', { query: 'SELECT count(*) FROM t', note: `${pad}; UPDATE t SET a = 1` }), 'deny');
  assert.equal(mcpKind('postgres', 'query', { sql: 'TRUNCATE t', pad }), 'deny'); // a server not listed: still denied
  assert.equal(mcpKind('mssql', 'read_query', { query: 'SELECT count(*) FROM t', pad }), 'floor');
  assert.match(analyzeMcpCall('mcp__mssql__read_query', { query: 'SELECT count(*) FROM t', pad }, cfgWith(ON)).reason, /larger than 64 KB/);
  assert.equal(mcpKind('mssql', 'read_query', { query: 'SELECT count(*) FROM t', pad }, { mode: 'off' }), 'floor');
});

test('round2 S8: a query text over 32 KB that carries a write is denied; a read that long still asks', () => {
  const blank = ' '.repeat(40000);
  for (const sql of [
    `SELECT count(*) FROM t;${blank}DELETE FROM t`,
    `SELECT count(*) FROM t WHERE a = 1${blank} ; DROP TABLE t`,
    `SELECT a INTO dbo.copy FROM t${blank}`, // SELECT ... INTO a table
    `SELECT count(*) FROM t${blank}\n:!! whoami`,
    `SELECT count(*) FROM t WHERE x IN (${'1,'.repeat(17000)}1); EXEC xp_cmdshell 'dir'`,
  ]) {
    for (const client of ['tsql', 'psql', 'any']) assert.equal(judgeSql(sql, { client }).kind, 'deny', `${client}: ${sql.slice(0, 40)}`);
  }
  assert.equal(mcpKind('mssql', 'read_query', { query: `SELECT count(*) FROM t;${blank}DELETE FROM t` }), 'deny'); // under 64 KB
  assert.equal(judgeSql(`SELECT COUNT(*) FROM t WHERE x IN (${'1,'.repeat(17000)}1)`).kind, 'floor');
  assert.equal(judgeSql(`SELECT a INTO #t FROM t${blank}`).kind, 'floor'); // a temporary table of the session is no write
  assert.match(judgeSql(`SELECT count(*) FROM t${blank}`).reason, /longer than 32 KB/);
});

test('round2 S8: the write scan of a long text stays fast on hostile input', () => {
  const start = Date.now();
  const hostile = ['select '.repeat(150000), 'select a output '.repeat(70000), 'into '.repeat(200000), `enable${' '.repeat(1e6)}x`,
    '('.repeat(1e6), "'".repeat(1e6), 'pg_create_'.repeat(100000), `sp_add${'a'.repeat(1e6)}`, 'a;'.repeat(500000)];
  for (const t of hostile) {
    for (const client of ['tsql', 'psql', 'any']) assert.notEqual(judgeSql(t, { client }).kind, 'read');
    assert.equal(judgeSql(`${t} drop table t`, { client: 'any' }).kind, 'deny');
    assert.notEqual(mcpKind('mssql', 'read_query', { query: t, pad: 'x'.repeat(70000) }), 'pass');
  }
  assert.equal(mcpKind('mssql', 'read_query', { query: `${'select '.repeat(150000)} drop table t` }), 'deny');
  assert.ok(Date.now() - start < 5000, `${Date.now() - start} ms`);
});

function project(config) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-round2-sql-'));
  fs.mkdirSync(path.join(dir, 'hardening'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'hardening', 'harness.config.json'), `${JSON.stringify(config, null, 2)}\n`);
  return dir;
}
function guard(dir, tool_name, tool_input) {
  const r = spawnSync(process.execPath, [preHook], {
    input: JSON.stringify({ hook_event_name: 'PreToolUse', session_id: 'round2-sql', cwd: dir, tool_name, tool_input }),
    env: { ...process.env, CLAUDE_PROJECT_DIR: dir },
    encoding: 'utf8',
  });
  assert.equal(r.status, 0, r.stderr);
  const out = r.stdout.trim() ? JSON.parse(r.stdout).hookSpecificOutput : {};
  return { decision: out.permissionDecision ?? null, reason: out.permissionDecisionReason ?? '' };
}

test('round2 F2-7 hook: auto mode asks for a psql conninfo whose hostaddr is not listed; the listed host still passes', () => {
  const dir = project({ approvals: { mode: 'auto' }, sources: { sqlRead: { ...ON, mcpServers: [] } } });
  try {
    const remote = guard(dir, 'Bash', { command: `psql -X -d "host=localhost hostaddr=10.9.9.9 dbname=sales" ${Q}` });
    assert.equal(remote.decision, 'ask', remote.reason);
    assert.match(remote.reason, /server 10\.9\.9\.9 is not in sources\.sqlRead\.servers/);
    assert.equal(guard(dir, 'Bash', { command: `psql -X -d "postgresql://localhost/sales?hostaddr=10.9.9.9" ${Q}` }).decision, 'ask');
    assert.equal(guard(dir, 'Bash', { command: `psql -X -h localhost -d sales ${Q}` }).decision, 'allow');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('round2 S8 hook: a SQL MCP call over 64 KB with a write is denied; a read that size asks', () => {
  const dir = project({ approvals: { mode: 'auto' }, sources: { sqlRead: ON } });
  try {
    const pad = 'x'.repeat(70000);
    const write = guard(dir, 'mcp__mssql__read_query', { query: 'DELETE FROM t', pad });
    assert.equal(write.decision, 'deny', write.reason);
    const read = guard(dir, 'mcp__mssql__read_query', { query: 'SELECT count(*) FROM t', pad });
    assert.equal(read.decision, 'ask', read.reason);
    assert.match(read.reason, /larger than 64 KB/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
