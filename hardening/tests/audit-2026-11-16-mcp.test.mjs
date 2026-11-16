// Audit 2026-11-16, MCP findings 15 and 16, replayed through the spawned hooks as Claude Code runs them (stdin JSON, no
// `timestamp`, no BI_HARNESS_HOST).
// 15: an MCP tool the policy does not know got no verdict even when its argument was a shell command or a protected file
// (mcp__terminal__run_in_terminal { command: "cat .env" }, mcp__filesystem__write_file { path: ".claude/settings.local.json" }),
// while the same command through Bash and the same file through Read or Write were denied or asked.
// 16: whether a Power BI MCP connection is local was read from its name and from the first server key alone: (a) a write
// on a connection named PBIDesktop-... was auto-approved although the session state recorded a service workspace for it;
// (b) a connect naming localhost first and another server later (a second Data Source, a Server or Location key, a
// dataSource next to a remote connection string) was auto-approved as local.
// The last test holds what must stay: it passes before and after the fix.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { analyzeMcpCall } from '../hooks/lib/policy.mjs';

const hooks = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'hooks');
const CFG = { mcp: { powerbiServer: 'powerbi-modeling' } };
const SERVER = 'powerbi-modeling';
const OTHER_SERVER = 'powerbi-authoring-local';
const LOCAL = 'PBIDesktop-Sales-51234';
// A service workspace (invented host): any powerbi:// address is another machine.
const SERVICE = 'powerbi://api.example.com/v1.0/myorg/Prod';
const LAB = { approvals: { mode: 'lab' } };

// Variables that point git at another repository (a commit hook that runs the tests exports GIT_INDEX_FILE).
const GIT_REPO_VARS = new Set(['GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE', 'GIT_OBJECT_DIRECTORY', 'GIT_ALTERNATE_OBJECT_DIRECTORIES', 'GIT_COMMON_DIR', 'GIT_PREFIX']);
const gitEnv = () => Object.fromEntries(Object.entries(process.env).filter(([k]) => !GIT_REPO_VARS.has(k.toUpperCase())));

let sessions = 0;
const nextSession = () => `audit-mcp-${process.pid}-${++sessions}`;

/** A temporary project and an empty home folder (no user settings), removed afterwards. `config`: the harness config. */
function withProject(fn, { config, files = {} } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-audit-mcp-'));
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-audit-home-'));
  try {
    for (const [rel, content] of Object.entries(files)) {
      fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
      fs.writeFileSync(path.join(dir, rel), content);
    }
    if (config) {
      fs.mkdirSync(path.join(dir, 'hardening'), { recursive: true });
      fs.writeFileSync(path.join(dir, 'hardening', 'harness.config.json'), JSON.stringify(config));
    }
    return fn({ dir, home, session: nextSession() });
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
    fs.rmSync(home, { recursive: true, force: true });
  }
}

/** Runs a hook as Claude Code does: stdin JSON, the temporary project as CLAUDE_PROJECT_DIR, no host variable. */
function hook(ctx, script, payload) {
  const env = { ...gitEnv(), CLAUDE_PROJECT_DIR: ctx.dir, HOME: ctx.home, USERPROFILE: ctx.home };
  delete env.BI_HARNESS_HOST;
  delete env.COPILOT_CLI;
  const input = { session_id: ctx.session, cwd: ctx.dir, permission_mode: 'default', tool_use_id: `toolu_${sessions}`, ...payload };
  const r = spawnSync(process.execPath, [path.join(hooks, script)], { input: JSON.stringify(input), env, encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
  assert.doesNotMatch(r.stderr, /hook error/);
  return r.stdout.trim() ? JSON.parse(r.stdout) : null;
}
/** The PreToolUse guard's answer: decision (null for none) and reason. */
function pre(ctx, tool_name, tool_input, extra = {}) {
  const out = hook(ctx, 'pre-tool-use.mjs', { hook_event_name: 'PreToolUse', tool_name, tool_input, ...extra })?.hookSpecificOutput;
  return { decision: out?.permissionDecision ?? null, reason: out?.permissionDecisionReason ?? '' };
}
const textBlock = (obj) => [{ type: 'text', text: JSON.stringify(obj) }];
const post = (ctx, tool, request, response, server = SERVER) =>
  hook(ctx, 'post-tool-redact.mjs', { hook_event_name: 'PostToolUse', tool_name: `mcp__${server}__${tool}`, tool_input: { request }, tool_response: response });
const stateOf = (ctx) => {
  const file = path.join(ctx.dir, '.claude', 'logs', '.state', `${ctx.session}.json`);
  return fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, 'utf8')) : {};
};
const recorded = (ctx, server = SERVER) => (stateOf(ctx).mcpConnections ?? []).filter((c) => c.mcpServer === server && c.name === LOCAL);
const CREATE = { operation: 'Create', connectionName: LOCAL, definitions: [{ name: 'Net Sales', expression: 'SUM(Sales[Amount])' }] };
const write = (ctx, server = SERVER, request = CREATE) => pre(ctx, `mcp__${server}__measure_operations`, { request });
const connectVerdict = (request) => analyzeMcpCall(`mcp__${SERVER}__connection_operations`, { request: { operation: 'Connect', ...request } }, CFG);
const REMOTE_CONNECT = /Connecting to a server other than this machine/;

// ---------------------------------------------------------------- 15a. a shell command in an unknown MCP tool

test('P15a: an unknown MCP tool that runs a shell command gets the shell policy\'s deny, with its reason', () => {
  withProject((ctx) => {
    // [tool, its input, the command of that input the shell policy denies]
    for (const [tool, input, command] of [
      ['mcp__terminal__run_in_terminal', { command: 'git push --force origin main' }, 'git push --force origin main'],
      ['mcp__terminal__run_in_terminal', { command: 'cat .env' }, 'cat .env'],
      ['mcp__desktop-commander__start_process', { command: 'git push --force origin main' }, 'git push --force origin main'],
      ['mcp__shell__exec', { cmd: 'cat .env' }, 'cat .env'],
      ['mcp__runner__run', { script: 'git push --force origin main' }, 'git push --force origin main'],
      ['mcp__runner__start', { commandLine: 'cat .env' }, 'cat .env'],
      ['mcp__runner__start', { timeout: 5, commandLine: 'git status', cmd: 'cat .env' }, 'cat .env'],
    ]) {
      const shell = pre(ctx, 'Bash', { command });
      assert.equal(shell.decision, 'deny', `Bash denies ${command}`);
      const mcp = pre(ctx, tool, input);
      assert.equal(mcp.decision, 'deny', `${tool} ${JSON.stringify(input)}`);
      assert.equal(mcp.reason, shell.reason, 'the shell policy\'s reason');
    }
  });
});

test('P15a: any other command in an unknown MCP tool is a floor ask that names the tool, never allow (auto and lab mode)', () => {
  for (const config of [undefined, LAB]) {
    withProject((ctx) => {
      assert.equal(pre(ctx, 'Bash', { command: 'git status' }).decision, 'allow', 'Bash runs a routine command without a prompt');
      for (const [tool, input] of [
        ['mcp__terminal__run_in_terminal', { command: 'git status' }],
        ['mcp__desktop-commander__start_process', { command: 'git push origin feature/x' }],
        ['mcp__runner__run', { script: 'echo hello' }],
      ]) {
        const mcp = pre(ctx, tool, input);
        assert.equal(mcp.decision, 'ask', `${tool} ${JSON.stringify(input)} (${config ? 'lab' : 'auto'})`);
        assert.ok(mcp.reason.includes(tool), mcp.reason);
        assert.match(mcp.reason, /where and in which shell/);
      }
    }, { config });
  }
});

// ---------------------------------------------------------------- 15b. a local file in an unknown MCP tool

test('P15b: a secret or data file named by an unknown MCP tool is denied with the reason Read gives, read-only tools included', () => {
  withProject((ctx) => {
    const env = path.join(ctx.dir, '.env');
    const read = pre(ctx, 'Read', { file_path: env });
    assert.equal(read.decision, 'deny');
    const encoded = pathToFileURL(env).href.replace(/\.env$/, '%2Eenv');
    for (const [tool, input] of [
      ['mcp__filesystem__read_file', { path: env }],
      ['mcp__filesystem__read_text_file', { path: '.env' }],
      ['mcp__filesystem__read_multiple_files', { paths: [path.join(ctx.dir, 'docs', 'a.md'), env] }],
      ['mcp__files__open', { file_path: env }],
      ['mcp__files__open', { filePath: env }],
      ['mcp__files__open', { file: env }],
      ['mcp__files__open', { filename: env }],
      ['mcp__files__open', { uri: pathToFileURL(env).href }],
      ['mcp__files__open', { uri: encoded }],
      ['mcp__files__open', { uri: '.env' }],
      ['mcp__filesystem__read_file', { path: pathToFileURL(env).href }],
      ['mcp__filesystem__read_file', { path: 'https:/../.env' }],
      ['mcp__filesystem__write_file', { path: env, content: 'x' }],
    ]) {
      const mcp = pre(ctx, tool, input);
      assert.equal(mcp.decision, 'deny', `${tool} ${JSON.stringify(input)}`);
      assert.equal(mcp.reason, read.reason, 'the reason Read gives');
    }
    const cache = pre(ctx, 'mcp__filesystem__read_file', { path: path.join(ctx.dir, 'Sales.SemanticModel', '.pbi', 'cache.abf') });
    assert.equal(cache.decision, 'deny', 'a data file');
  });
});

// Review of the fix: an unknown MCP tool's `path`, `file` or `filename` is not always a file system path (`ns:pod`, an API
// route), so an opaque spelling is denied only when its plain spelling is a secret or data file; otherwise it asks.
test('P15b: a stream, device or share spelling of a secret or data file is denied with Read\'s reason for the plain spelling', () => {
  withProject((ctx) => {
    const env = path.join(ctx.dir, '.env');
    // [the value an MCP tool sends, its plain spelling]
    for (const [value, plain] of [
      ['.env::$DATA', '.env'],
      [`${env}:x`, env],
      [`\\\\?\\${env}`, env],
      [`\\\\.\\${env}`, env],
      ['secrets/a.txt::$DATA', 'secrets/a.txt'],
      ['data/sales.pbix:s', 'data/sales.pbix'],
      // An administrative share of the project's drive (Windows: the temporary folder has a drive letter).
      ...(process.platform === 'win32' ? [[`\\\\localhost\\${env[0]}$${env.slice(2)}`, env]] : []),
    ]) {
      const read = pre(ctx, 'Read', { file_path: plain });
      assert.equal(read.decision, 'deny', `Read denies ${plain}`);
      for (const [tool, field] of [['mcp__filesystem__read_file', 'path'], ['mcp__files__open', 'file'], ['mcp__files__upload', 'filename']]) {
        const mcp = pre(ctx, tool, { [field]: value });
        assert.equal(mcp.decision, 'deny', `${tool} ${field}: ${value}`);
        assert.equal(mcp.reason, read.reason, `${value}: Read's reason for ${plain}`);
      }
    }
    // The Read guard keeps its own opaque-path deny.
    const stream = pre(ctx, 'Read', { file_path: path.join(ctx.dir, 'x:stream') });
    assert.equal(stream.decision, 'deny', 'Read of x:stream');
    assert.match(stream.reason, /Alternate data streams/);
  });
});

test('P15b: any other opaque value in an unknown MCP tool is a floor ask, read-only tools included (auto and lab mode)', () => {
  for (const config of [undefined, LAB]) {
    withProject((ctx) => {
      for (const [tool, input] of [
        ['mcp__k8s__get_resource', { path: 'ns:pod' }],
        ['mcp__api__call', { path: '/v1/items:batchGet' }],
        ['mcp__filesystem__read_file', { path: `\\\\?\\${path.join(ctx.dir, 'docs', 'a.md')}` }],
        ['mcp__files__open', { file: 'docs/a.md:stream' }],
        ['mcp__filesystem__write_file', { filename: path.join(ctx.dir, 'docs', 'a.md:hidden'), content: 'x' }],
      ]) {
        const mcp = pre(ctx, tool, input);
        assert.equal(mcp.decision, 'ask', `${tool} ${JSON.stringify(input)} (${config ? 'lab' : 'auto'})`);
        assert.ok(mcp.reason.includes(tool), mcp.reason);
        assert.match(mcp.reason, /cannot tell which file, if any/);
      }
    }, { config });
  }
});

test('P15b: the hooks\' logs and the guard configuration are never written through an unknown MCP tool', () => {
  withProject((ctx) => {
    for (const [tool, input] of [
      ['mcp__filesystem__write_file', { path: path.join(ctx.dir, '.claude', 'settings.local.json'), content: '{}' }],
      ['mcp__filesystem__write_file', { path: path.join(ctx.dir, '.claude', 'settings.json'), content: '{}' }],
      ['mcp__filesystem__edit_file', { path: path.join(ctx.dir, 'hardening', 'harness.config.json'), edits: [] }],
      ['mcp__filesystem__write_file', { path: '.github/hooks/bi-harness.json', content: '{}' }],
      ['mcp__filesystem__write_file', { path: path.join(ctx.dir, '.claude', 'logs', 'security-events.jsonl'), content: '' }],
      ['mcp__filesystem__create_directory', { path: path.join(ctx.dir, '.claude', 'logs', '.state') }],
      ['mcp__filesystem__move_file', { path: path.join(ctx.dir, '.claude', 'settings.local.json') }],
      ['mcp__filesystem__write_file', { path: 'data:/../.claude/settings.local.json', content: '{}' }],
    ]) {
      const mcp = pre(ctx, tool, input);
      assert.equal(mcp.decision, 'deny', `${tool} ${JSON.stringify(input)}`);
    }
  });
});

test('P15b: a critical file or a reference folder is a floor ask for an unknown MCP tool that may write (auto and lab mode)', () => {
  for (const config of [undefined, LAB]) {
    withProject((ctx) => {
      for (const [tool, input] of [
        ['mcp__filesystem__write_file', { path: path.join(ctx.dir, 'templates', 't.md'), content: 'x' }],
        ['mcp__filesystem__write_file', { path: path.join(ctx.dir, 'AGENTS.md'), content: 'x' }],
        ['mcp__filesystem__edit_file', { path: 'reports/Sales/source/query.sql', edits: [] }],
        ['mcp__filesystem__write_file', { path: path.join(ctx.dir, 'M.SemanticModel', 'definition', 'roles', 'Readers.tmdl'), content: 'x' }],
        ['mcp__filesystem__write_file', { path: path.join(ctx.dir, '.git', 'config'), content: 'x' }],
        ['mcp__files__search_and_replace', { path: path.join(ctx.dir, 'AGENTS.md'), search: 'a', replace: 'b' }],
      ]) {
        const mcp = pre(ctx, tool, input);
        assert.equal(mcp.decision, 'ask', `${tool} ${JSON.stringify(input)} (${config ? 'lab' : 'auto'})`);
        assert.ok(mcp.reason.includes(tool), mcp.reason);
      }
    }, { config });
  }
});

// ---------------------------------------------------------------- 16a. a recorded remote server beats a local-looking name

test('P16a: a write on a local-looking name whose recorded server is a service workspace is the floor ask, naming the server', () => {
  for (const config of [undefined, LAB]) {
    withProject((ctx) => {
      post(ctx, 'connection_operations', { operation: 'Connect', connectionName: LOCAL, connectionString: `Data Source=${SERVICE};Initial Catalog=Sales` },
        textBlock({ success: true, connectionName: LOCAL, server: SERVICE, database: 'Sales' }));
      assert.deepEqual(recorded(ctx).map((c) => c.server), [SERVICE], 'the recorder keeps the server');
      const out = write(ctx);
      assert.equal(out.decision, 'ask', `a write on ${LOCAL} recorded on ${SERVICE} (${config ? 'lab' : 'auto'})`);
      assert.ok(out.reason.includes(SERVICE), out.reason);
      assert.doesNotMatch(out.reason, /Initial Catalog|Data Source/i, 'no connection string');
      assert.equal(write(ctx, SERVER, { ...CREATE, connectionName: 'Fabric-Prod-Sales' }).decision, 'ask', 'as a connection named like a remote one');
    }, { config });
  }
});

test('P16a: the recorder keeps the remote host a connect request names, and a later list does not erase it', () => {
  for (const [label, request] of [
    ['dataSource', { dataSource: 'prodssas01' }],
    ['a duplicated Data Source', { connectionString: 'Data Source=localhost;Initial Catalog=Sales;Data Source=prodssas01' }],
    ['dataSource next to a remote connection string', { dataSource: 'localhost:51234', connectionString: 'Data Source=prodssas01;Initial Catalog=Sales' }],
    ['a Server key after Data Source', { connectionString: 'Data Source=localhost;Server=prodssas01' }],
  ]) {
    withProject((ctx) => {
      post(ctx, 'connection_operations', { operation: 'Connect', connectionName: LOCAL, ...request }, textBlock({ success: true, connectionName: LOCAL }));
      assert.deepEqual(recorded(ctx).map((c) => c.server), ['prodssas01'], `${label}: the remote host is recorded`);
      const text = fs.readFileSync(path.join(ctx.dir, '.claude', 'logs', '.state', `${ctx.session}.json`), 'utf8');
      assert.doesNotMatch(text, /Data Source|Initial Catalog/i, 'the host only, never the connection string');
      const out = write(ctx);
      assert.equal(out.decision, 'ask', label);
      assert.match(out.reason, /prodssas01/);
      // A list or get answer that names the connection without its server refreshes it without erasing the evidence.
      post(ctx, 'connection_operations', { operation: 'ListConnections' }, textBlock({ success: true, connections: [{ name: LOCAL }] }));
      assert.equal(write(ctx).decision, 'ask', `${label}: after a list`);
      post(ctx, 'connection_operations', { operation: 'GetConnection', connectionName: LOCAL }, textBlock({ success: true, connectionName: LOCAL }));
      assert.equal(write(ctx).decision, 'ask', `${label}: after a get`);
    });
  }
  // A remote host the state does not keep as written (too long) still counts as another machine; nothing of it is stored.
  const long = `${'h'.repeat(210)}.example.invalid`;
  withProject((ctx) => {
    post(ctx, 'connection_operations', { operation: 'Connect', connectionName: LOCAL, dataSource: long }, textBlock({ success: true, connectionName: LOCAL }));
    assert.equal(write(ctx).decision, 'ask', 'a remote host too long to record');
    assert.ok(!fs.readFileSync(path.join(ctx.dir, '.claude', 'logs', '.state', `${ctx.session}.json`), 'utf8').includes('hhhh'), 'the host is not stored');
  });
});

// ---------------------------------------------------------------- 16b. every server a connect names must be this machine

test('P16b: a connect is local only when every server it names is this machine', () => {
  for (const request of [
    { connectionString: 'Data Source=localhost;Initial Catalog=Sales;Data Source=prodssas01' },
    { dataSource: 'localhost', connectionString: 'Data Source=prodssas01;Initial Catalog=Sales' },
    { connectionString: 'Data Source=localhost;Server=prodssas01' },
    { connectionString: 'Data Source=localhost;Location=prodssas01' },
    { connectionString: 'data  source = localhost ; SERVER = prodssas01' },
    { connectionString: 'DataSource=localhost;Address=prodssas01' },
    { connectionString: 'Data Source=localhost;Addr=prodssas01' },
    { connectionString: 'Data Source=localhost;Network Address=prodssas01' },
    { connectionString: 'Data Source=localhost;Host=prodssas01' },
    { dataSource: 'localhost', ConnectionString: 'Data Source=prodssas01' },
    { DataSource: 'prodssas01', dataSource: 'localhost' },
    { connectionString: 'Data Source=localhost;oops' },
    { connectionString: 'Data Source="localhost";Server=prodssas01' },
    { connectionString: 'localhost' },
  ]) {
    const v = connectVerdict(request);
    assert.equal(v?.decision, 'ask', JSON.stringify(request));
    assert.equal(v.floor, true, `${JSON.stringify(request)} is the floor ask`);
    assert.match(v.reason, REMOTE_CONNECT);
  }
  const top = analyzeMcpCall(`mcp__${SERVER}__connection_operations`, { operation: 'Connect', dataSource: 'localhost', connectionString: 'Data Source=prodssas01' }, CFG);
  assert.equal(top?.floor, true, 'arguments without a request wrapper');
  withProject((ctx) => {
    const out = pre(ctx, `mcp__${SERVER}__connection_operations`, { request: { operation: 'Connect', connectionString: 'Data Source=localhost;Initial Catalog=Sales;Data Source=prodssas01' } });
    assert.equal(out.decision, 'ask', 'never auto-approved');
    assert.match(out.reason, REMOTE_CONNECT);
  });
});

// ---------------------------------------------------------------- what must stay (passes before and after the fix)

test('must stay: Power BI, GitHub, Figma, SQL and Microsoft Learn verdicts, unknown tools without a command or file, Copilot payloads', () => {
  // P16 must stay: local connects keep today's plain ask (auto approval passes it); remote ones keep the floor.
  for (const request of [
    { dataSource: 'localhost:51234' },
    { connectionString: 'Data Source=localhost:51234' },
    { connectionString: 'Data Source=localhost:51234;' },
    { connectionString: 'Data Source=localhost;Initial Catalog=Sales' },
    { connectionString: 'Provider=MSOLAP;Data Source=127.0.0.1:2383' },
    { connectionString: 'Data Source=.;Initial Catalog=x' },
    { connectionString: 'Data Source=(local)' },
  ]) {
    const v = connectVerdict(request);
    assert.equal(v?.decision, 'ask', JSON.stringify(request));
    assert.equal(v.floor, undefined, `${JSON.stringify(request)} stays local`);
    assert.equal(v.autoApprovable, undefined, JSON.stringify(request));
  }
  for (const request of [{ connectionString: 'Data Source=prodssas01' }, { connectionString: `Data Source=${SERVICE};Initial Catalog=Sales` }]) {
    assert.equal(connectVerdict(request)?.floor, true, JSON.stringify(request));
  }
  const pbi = (tool, request) => analyzeMcpCall(`mcp__${SERVER}__${tool}`, { request }, CFG);
  assert.equal(pbi('measure_operations', CREATE).decision, 'ask');
  assert.equal(pbi('measure_operations', CREATE).autoApprovable, undefined, 'ordinary model work on a local name');
  assert.equal(pbi('measure_operations', { ...CREATE, connectionName: 'Fabric-Prod-Sales' }).floor, true);
  assert.equal(pbi('database_operations', { operation: 'DeployToFabric', connectionName: LOCAL }).decision, 'deny');
  assert.equal(pbi('security_role_operations', { operation: 'Update', connectionName: LOCAL, definitions: [{ name: 'R', members: [{ memberName: 'x' }] }] }).decision, 'deny');
  assert.equal(pbi('table_operations', { operation: 'List', connectionName: LOCAL }).decision, 'allow');
  assert.equal(pbi('relationship_operations', { operation: 'Create', connectionName: LOCAL }).autoApprovable, false, 'Tier 2 on a local model');

  withProject((ctx) => {
    // A confirmed Desktop connection with a local recorded server, or none, is auto-approved as today.
    post(ctx, 'connection_operations', { operation: 'Connect', connectionName: LOCAL, dataSource: 'localhost:51234' }, textBlock({ success: true, connectionName: LOCAL }));
    assert.deepEqual(recorded(ctx).map((c) => c.server), ['localhost:51234']);
    assert.equal(write(ctx).decision, 'allow', 'recorded server localhost:51234');
    assert.equal(pre(ctx, `mcp__${SERVER}__database_operations`, { request: { operation: 'DeployToFabric', connectionName: LOCAL } }).decision, 'deny');
    assert.equal(pre(ctx, `mcp__${SERVER}__security_role_operations`, { request: { operation: 'Update', connectionName: LOCAL, definitions: [{ name: 'R', members: [{ memberName: 'x' }] }] } }).decision, 'deny');
    // A remote connection of that name on another MCP server is another connection.
    post(ctx, 'connection_operations', { operation: 'Connect', connectionName: LOCAL, connectionString: `Data Source=${SERVICE}` }, textBlock({ success: true, connectionName: LOCAL, server: SERVICE }), OTHER_SERVER);
    assert.equal(write(ctx).decision, 'allow', 'the other server\'s record does not count here');
    assert.equal(pre(ctx, `mcp__${SERVER}__connection_operations`, { request: { operation: 'Connect', connectionString: 'Data Source=localhost:51234' } }).decision, 'allow');
  });
  withProject((ctx) => {
    post(ctx, 'connection_operations', { operation: 'Connect', connectionName: LOCAL }, textBlock({ success: true, connectionName: LOCAL }));
    assert.deepEqual(recorded(ctx).map((c) => c.server), [undefined], 'no recorded server');
    assert.equal(write(ctx).decision, 'allow', 'no recorded server: the name decides, as today');
  });

  withProject((ctx) => {
    const none = (tool, input, label) => assert.equal(pre(ctx, tool, input).decision, null, label ?? `${tool} ${JSON.stringify(input)}`);
    // GitHub and Figma: their own verdicts, whatever the arguments.
    none('mcp__github__get_file_contents', { owner: 'o', repo: 'r', path: '.env' }, 'a repository path, not a local file');
    const gh = pre(ctx, 'mcp__github__create_or_update_file', { owner: 'o', repo: 'r', path: '.env', content: 'x' });
    assert.equal(gh.decision, 'ask');
    assert.match(gh.reason, /GitHub write action \(create_or_update_file\)/);
    none('mcp__figma__get_file', { file_key: 'k' });
    assert.match(pre(ctx, 'mcp__figma__create_frame', { file_key: 'k', command: 'cat .env' }).reason, /Figma write \(create_frame\)/);
    // SQL MCP servers keep the SQL policy.
    const sql = pre(ctx, 'mcp__mssql__read_query', { query: 'SELECT 1' });
    assert.equal(sql.decision, 'ask');
    assert.match(sql.reason, /not named in sources\.sqlRead\.mcpServers/);
    const drop = pre(ctx, 'mcp__postgres__execute', { command: 'DROP TABLE t' });
    assert.equal(drop.decision, 'deny');
    assert.match(drop.reason, /SQL MCP/);
    // A data: uri and a web address in a file argument are no opaque path.
    none('mcp__files__fetch', { path: 'https://example.com/a:b' });
    none('mcp__files__upload', { file: 'data:text/plain;base64,eA==' });
    // Microsoft Learn and unknown tools without a command or a file.
    none('mcp__microsoft-learn__microsoft_docs_search', { query: 'rm -rf /' });
    none('mcp__microsoft-learn__microsoft_docs_fetch', { url: 'https://docs.example.com/x' });
    none('mcp__microsoft-learn__microsoft_code_sample_search', { query: 'cat .env', language: 'powershell' });
    none('mcp__x__search', { query: 'rm -rf /' }, 'a query is no command');
    none('mcp__files__open', { uri: 'https://example.com/.env' }, 'a web address is no local file');
    // Ordinary files keep no verdict; a tool that only reads gets only the secret and data deny.
    none('mcp__filesystem__write_file', { path: path.join(ctx.dir, 'docs', 'notes.md'), content: 'x' });
    none('mcp__filesystem__read_file', { path: path.join(ctx.dir, 'AGENTS.md') });
    none('mcp__filesystem__read_text_file', { path: path.join(ctx.dir, '.claude', 'settings.local.json') });
    none('mcp__filesystem__list_directory', { path: path.join(ctx.dir, 'templates') });
    none('mcp__filesystem__get_file_info', { path: path.join(ctx.dir, 'templates', 't.md') });
    none('mcp__filesystem__directory_tree', { path: ctx.dir });
    // A Copilot payload (a timestamp, no host variable) keeps today's answer.
    const copilot = { timestamp: '2026-11-16T10:00:00.000Z' };
    assert.equal(pre(ctx, 'mcp__terminal__run_in_terminal', { command: 'cat .env' }, copilot).decision, null);
    assert.equal(pre(ctx, 'mcp__filesystem__read_file', { path: path.join(ctx.dir, '.env') }, copilot).decision, null);
    assert.equal(pre(ctx, 'mcp__filesystem__write_file', { path: path.join(ctx.dir, 'templates', 't.md'), content: 'x' }, copilot).decision, null);
  });
  // A SQL server listed in sources.sqlRead.mcpServers under a name that does not look like a database keeps the SQL policy.
  withProject((ctx) => {
    const listed = pre(ctx, 'mcp__reporting__run', { command: 'cat .env' });
    assert.equal(listed.decision, 'ask');
    assert.match(listed.reason, /SQL MCP reporting/);
  }, { config: { sources: { sqlRead: { mcpServers: ['reporting'] } } } });
});
