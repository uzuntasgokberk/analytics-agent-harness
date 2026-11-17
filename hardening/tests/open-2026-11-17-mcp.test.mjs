// Open findings 2026-11-17, MCP tools the policy does not know (the limits of audit 2026-11-16, P15), replayed through the
// spawned hook as Claude Code and the GitHub Copilot hosts run it.
// A. Under Claude Code an unknown MCP tool was judged by its top-level `command`, `cmd`, `script`, `commandLine` (strings)
//    and `file_path`, `filePath`, `file`, `filename`, `path`, `paths`, `uri` only: `source`/`destination` and their
//    siblings, nested argument objects (also inside arrays), an array-valued command or one whose `args` stand beside it,
//    and the `cwd` the command runs in were not read ({ source: ".env" } and { args: { command: "rm -rf docs" } } got no
//    verdict, { command: "rm -r .", cwd: "templates" } only the floor ask).
// B. Under GitHub Copilot (VS Code, Copilot CLI, the CLI's run of the Claude registration) an unknown MCP tool got no
//    verdict at all, even for { command: "cat .env" }, and another tool the translation does not know only its ask.
// The last tests hold what must stay: they pass before and after the fix.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const hooks = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'hooks');
const LAB = { approvals: { mode: 'lab' } };
const LOCAL = 'PBIDesktop-Sales-51234';
const email = () => ['someone', 'example.com'].join('@');

// Variables that point git at another repository (a commit hook that runs the tests exports GIT_INDEX_FILE).
const GIT_REPO_VARS = new Set(['GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE', 'GIT_OBJECT_DIRECTORY', 'GIT_ALTERNATE_OBJECT_DIRECTORIES', 'GIT_COMMON_DIR', 'GIT_PREFIX']);
const gitEnv = () => Object.fromEntries(Object.entries(process.env).filter(([k]) => !GIT_REPO_VARS.has(k.toUpperCase())));

let sessions = 0;
const nextSession = () => `open-mcp-${process.pid}-${++sessions}`;

/** A temporary project (docs/, templates/t.md) and an empty home folder, removed afterwards. `config`: the harness config. */
function withProject(fn, { config } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-open-mcp-'));
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-open-home-'));
  try {
    for (const [rel, content] of Object.entries({ 'docs/a.md': '# a\n', 'templates/t.md': '# t\n' })) {
      fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
      fs.writeFileSync(path.join(dir, rel), content);
    }
    if (config) {
      fs.mkdirSync(path.join(dir, 'hardening'), { recursive: true });
      fs.writeFileSync(path.join(dir, 'hardening', 'harness.config.json'), JSON.stringify(config));
    }
    return fn({ dir, home });
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
    fs.rmSync(home, { recursive: true, force: true });
  }
}

/**
 * The PreToolUse guard's answer, decision (null for none) and reason, with a fresh session each call (no ask-once repeat).
 * host: null (Claude Code: no host variable, no timestamp), 'vscode' or 'copilot-cli' (their hook files: BI_HARNESS_HOST;
 * the CLI's camelCase payload and flat output), 'copilot-claude' (the Claude registration run by Copilot: a timestamp).
 */
function pre(ctx, tool_name, tool_input, { host = null, extra = {} } = {}) {
  const env = { ...gitEnv(), CLAUDE_PROJECT_DIR: ctx.dir, HOME: ctx.home, USERPROFILE: ctx.home };
  delete env.BI_HARNESS_HOST;
  delete env.COPILOT_CLI;
  if (host === 'vscode' || host === 'copilot-cli') env.BI_HARNESS_HOST = host;
  const session = nextSession();
  const payload = host === 'copilot-cli'
    ? { sessionId: session, timestamp: 1763380000000, cwd: ctx.dir, toolName: tool_name, toolArgs: tool_input, ...extra }
    : { hook_event_name: 'PreToolUse', session_id: session, cwd: ctx.dir, permission_mode: 'default', tool_use_id: `toolu_${sessions}`,
      tool_name, tool_input, ...(host ? { timestamp: '2026-11-17T10:00:00.000Z' } : {}), ...extra };
  const r = spawnSync(process.execPath, [path.join(hooks, 'pre-tool-use.mjs')], { input: JSON.stringify(payload), env, encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
  assert.doesNotMatch(r.stderr, /hook error/);
  const out = r.stdout.trim() ? JSON.parse(r.stdout) : null;
  const verdict = host === 'copilot-cli' ? out : out?.hookSpecificOutput;
  return { decision: verdict?.permissionDecision ?? null, reason: verdict?.permissionDecisionReason ?? '' };
}
const label = (tool, input) => `${tool} ${JSON.stringify(input)}`;

// ---------------------------------------------------------------- A. arguments that were not read (Claude Code)

test('A: a secret file named by source, destination or a sibling key of an unknown MCP tool is denied with the reason Read gives', () => {
  withProject((ctx) => {
    const read = pre(ctx, 'Read', { file_path: path.join(ctx.dir, '.env') });
    assert.equal(read.decision, 'deny');
    assert.equal(pre(ctx, 'mcp__files__copy', { path: '.env' }).reason, read.reason, 'the top-level path, as before');
    const cases = [
      ['mcp__files__copy', { source: '.env', destination: 'docs/x.txt' }],
      ['mcp__files__copy', { source: 'docs/a.md', destination: '.env' }],
      ['mcp__files__read_and_show', { source: '.env' }],
      ['mcp__files__copy', { source: ['docs/a.md', '.env'], destination: 'docs' }],
      ...['src', 'dest', 'dst', 'target', 'from', 'to', 'input', 'output', 'directory', 'dir', 'folder'].map((key) => ['mcp__files__transfer', { [key]: '.env' }]),
      ['mcp__files__copy', { source: pathToFileURL(path.join(ctx.dir, '.env')).href }],
      // A stream spelling under a new key is judged by its plain spelling; a list under a known key, item by item.
      ['mcp__files__copy', { source: '.env::$DATA' }],
      ['mcp__files__open', { file_path: ['docs/a.md', '.env'] }],
    ];
    for (const [tool, input] of cases) {
      const mcp = pre(ctx, tool, input);
      assert.equal(mcp.decision, 'deny', label(tool, input));
      assert.equal(mcp.reason, read.reason, `${label(tool, input)}: the reason Read gives`);
    }
  });
});

test('A: a file or command inside a nested object, or an object in an array, gets the verdict of the same key at the top level', () => {
  withProject((ctx) => {
    const rmrf = pre(ctx, 'mcp__runner__run', { command: 'rm -rf docs' });
    assert.equal(rmrf.decision, 'deny', 'the top-level command, as before');
    assert.equal(rmrf.reason, pre(ctx, 'Bash', { command: 'rm -rf docs' }).reason);
    const env = pre(ctx, 'mcp__runner__run', { path: '.env' });
    assert.equal(env.decision, 'deny', 'the top-level path, as before');
    for (const [input, twin] of [
      [{ args: { command: 'rm -rf docs' } }, rmrf],
      [{ steps: [{ name: 'clean', command: 'rm -rf docs' }] }, rmrf],
      [{ a: { b: { c: { cmd: 'rm -rf docs' } } } }, rmrf],
      [{ options: { path: '.env' } }, env],
      [{ request: { file_path: '.env' } }, env],
      [{ items: [{ file_path: 'docs/a.md' }, { file_path: '.env' }] }, env],
      [{ batch: [[{ filename: '.env' }]] }, env],
      [{ request: { paths: ['docs/a.md', '.env'] } }, env],
      [{ request: { uri: '.env' } }, env],
      [{ copy: { source: '.env', destination: 'docs/x.txt' } }, env],
    ]) {
      const mcp = pre(ctx, 'mcp__runner__run', input);
      assert.equal(mcp.decision, twin.decision, JSON.stringify(input));
      assert.equal(mcp.reason, twin.reason, `${JSON.stringify(input)}: the top-level reason`);
    }
    // A command that only asks keeps the floor ask, with the bare key named as at the top level.
    const top = pre(ctx, 'mcp__runner__run', { command: 'git status' });
    assert.equal(top.decision, 'ask');
    const nested = pre(ctx, 'mcp__runner__run', { args: { command: 'git status' } });
    assert.deepEqual(nested, top, 'a nested command that asks: the same ask');
  });
});

test('A: an array-valued command, or args beside a command, is judged as the command line it makes', () => {
  withProject((ctx) => {
    for (const [input, command] of [
      [{ command: ['rm', '-rf', 'docs'] }, 'rm -rf docs'],
      [{ command: 'rm', args: ['-rf', 'docs'] }, 'rm -rf docs'],
      [{ command: 'rm', args: '-rf docs' }, 'rm -rf docs'],
      [{ command: ['rm'], args: ['-rf', 'docs'] }, 'rm -rf docs'],
      [{ cmd: ['cat', '.env'] }, 'cat .env'],
      [{ script: ['git', 'push', '--force', 'origin', 'main'] }, 'git push --force origin main'],
      [{ command: ['bash', '-c', 'rm -rf docs'] }, "bash -c 'rm -rf docs'"],
      [{ args: { command: ['rm', '-rf', 'docs'] } }, 'rm -rf docs'],
    ]) {
      const shell = pre(ctx, 'Bash', { command });
      assert.equal(shell.decision, 'deny', `Bash denies ${command}`);
      const mcp = pre(ctx, 'mcp__runner__exec', input);
      assert.equal(mcp.decision, 'deny', JSON.stringify(input));
      assert.equal(mcp.reason, shell.reason, `${JSON.stringify(input)}: the shell policy's reason`);
    }
    // An array command the shell policy does not deny is the floor ask, as a string command is.
    const ask = pre(ctx, 'mcp__runner__exec', { command: ['git', 'status'] });
    assert.equal(ask.decision, 'ask');
    assert.match(ask.reason, /where and in which shell the command in its `command` argument runs/);
  });
});

test('A: a write-side key (destination, output) is judged like a path written by a tool whose name is not read-only', () => {
  withProject((ctx) => {
    const hook = 'hardening/hooks/pre-tool-use.mjs';
    const byPath = pre(ctx, 'mcp__files__copy', { path: hook });
    assert.equal(byPath.decision, 'ask', 'the top-level path of a tool that may write: the floor ask');
    const byDestination = pre(ctx, 'mcp__files__copy', { source: 'docs/a.md', destination: hook });
    assert.deepEqual(byDestination, byPath, 'the destination: the same ask');
    // A tool whose name says it only reads still writes its destination.
    const download = pre(ctx, 'mcp__web__get_file', { url: 'https://example.com/a.md', destination: 'AGENTS.md' });
    assert.equal(download.decision, 'ask');
    assert.match(download.reason, /which may write AGENTS\.md/);
    for (const [tool, input] of [
      ['mcp__files__copy', { source: 'docs/a.md', destination: '.claude/settings.local.json' }],
      ['mcp__web__get_file', { url: 'https://example.com/x', output: path.join(ctx.dir, '.claude', 'logs', 'security-events.jsonl') }],
      ['mcp__files__move', { request: { from: 'docs/a.md', to: 'hardening/harness.config.json' } }],
    ]) {
      assert.equal(pre(ctx, tool, input).decision, 'deny', label(tool, input));
    }
  });
});

test('A: a command with a cwd is judged from that folder, as after a cd there, and from the session\'s folder', () => {
  withProject((ctx) => {
    const fromTemplates = pre(ctx, 'Bash', { command: 'rm -r .' }, { extra: { cwd: path.join(ctx.dir, 'templates') } });
    assert.equal(fromTemplates.decision, 'deny', 'Bash run in templates/');
    for (const input of [
      { command: 'rm -r .', cwd: 'templates' },
      { command: 'rm -r .', cwd: path.join(ctx.dir, 'templates') },
      { command: 'rm -r .', workdir: 'templates' },
      { command: 'rm -r .', working_directory: 'templates' },
      { command: 'rm -r .', workingDirectory: 'templates' },
      { command: ['rm', '-r', '.'], cwd: 'templates' },
      { cwd: 'templates', steps: [{ command: 'rm -r .' }] },
    ]) {
      const mcp = pre(ctx, 'mcp__runner__run', input);
      assert.equal(mcp.decision, 'deny', JSON.stringify(input));
      assert.equal(mcp.reason, fromTemplates.reason, `${JSON.stringify(input)}: Bash's reason in templates/`);
    }
    // Judged from the session's folder too: a server may ignore the argument.
    const fromRoot = pre(ctx, 'mcp__runner__run', { command: 'rm -r templates', cwd: 'docs' });
    assert.equal(fromRoot.decision, 'deny');
    assert.equal(pre(ctx, 'mcp__runner__run', { command: 'cat ../.env', cwd: 'docs' }).decision, 'deny');
    // A relative file beside a cwd is judged from that folder as well as written.
    const secret = pre(ctx, 'Read', { file_path: path.join(ctx.dir, 'secrets', 'token.txt') });
    assert.equal(secret.decision, 'deny');
    assert.equal(pre(ctx, 'mcp__files__read_file', { file: 'token.txt' }).decision, null, 'token.txt alone is an ordinary file');
    assert.deepEqual(pre(ctx, 'mcp__files__read_file', { cwd: 'secrets', file: 'token.txt' }), secret, 'secrets/token.txt: Read\'s deny');
    const reference = pre(ctx, 'mcp__files__write_file', { cwd: 'templates', path: 't.md', content: 'x' });
    assert.equal(reference.decision, 'ask', 'templates/t.md written: the floor ask');
    assert.match(reference.reason, /which may write templates\/t\.md/);
  });
});

test('A: arguments nested past the bound, or naming more files than it, are the floor ask, in auto and lab mode', () => {
  let deep = { path: '.env' };
  for (let i = 0; i < 12; i++) deep = { a: deep };
  const wide = { rows: [...Array.from({ length: 6000 }, (_, i) => `v${i}`), { path: '.env' }] };
  const many = { paths: Array.from({ length: 1100 }, (_, i) => `docs/f${i}.md`) };
  // Past the command bound a later command is not read: the deny of the last one becomes the floor ask.
  const steps = { steps: [...Array.from({ length: 30 }, (_, i) => ({ command: `echo ${i}` })), { command: 'cat .env' }] };
  for (const config of [undefined, LAB]) {
    withProject((ctx) => {
      for (const input of [deep, wide, many, steps]) {
        const mcp = pre(ctx, 'mcp__runner__run', input);
        assert.equal(mcp.decision, 'ask', `${JSON.stringify(input).slice(0, 60)} (${config ? 'lab' : 'auto'})`);
        assert.match(mcp.reason, /did not read them all/);
        assert.ok(mcp.reason.includes('mcp__runner__run'), mcp.reason);
      }
    }, { config });
  }
});

// ---------------------------------------------------------------- B. unknown MCP tools under GitHub Copilot

test('B: under every Copilot host an unknown MCP tool that names a secret file or a command the shell policy denies is denied', () => {
  withProject((ctx) => {
    // [Claude Code's name, VS Code's name, the CLI's name, the input]
    for (const [claude, vscode, cli, input] of [
      ['mcp__terminal__run_in_terminal', 'mcp_terminal_run_in_terminal', 'terminal-mcp-run_in_terminal', { command: 'cat .env' }],
      ['mcp__terminal__run_in_terminal', 'mcp_terminal_run_in_terminal', 'terminal-mcp-run_in_terminal', { command: 'git push --force origin main' }],
      ['mcp__filesystem__read_file', 'mcp_filesystem_read_file', 'filesystem-mcp-read_file', { path: path.join(ctx.dir, '.env') }],
      ['mcp__files__copy', 'mcp_files_copy', 'files-mcp-copy', { source: '.env', destination: 'docs/x.txt' }],
      ['mcp__runner__run', 'mcp_runner_run', 'runner-mcp-run', { args: { command: 'rm -rf docs' } }],
    ]) {
      const want = pre(ctx, claude, input);
      assert.equal(want.decision, 'deny', `Claude Code: ${label(claude, input)}`);
      for (const [host, tool] of [['vscode', vscode], ['copilot-cli', cli], ['copilot-claude', claude], ['copilot-claude', cli]]) {
        const got = pre(ctx, tool, input, { host });
        assert.equal(got.decision, 'deny', `${host}: ${label(tool, input)}`);
        assert.equal(got.reason, want.reason, `${host}: ${label(tool, input)}: Claude Code's reason`);
      }
    }
  });
});

test('B: a Copilot tool the translation does not know is denied for the same arguments; any other risky argument keeps its ask', () => {
  withProject((ctx) => {
    for (const input of [{ cmd: 'cat .env' }, { file_path: '.env' }, { file: '.env' }, { source: '.env' }, { command: ['rm', '-rf', 'docs'] }, { options: { uri: '.env' } }]) {
      for (const host of ['vscode', 'copilot-cli', 'copilot-claude']) {
        assert.equal(pre(ctx, 'frobnicate', input, { host }).decision, 'deny', `${host}: frobnicate ${JSON.stringify(input)}`);
      }
    }
    for (const host of ['vscode', 'copilot-cli', 'copilot-claude']) {
      const ask = pre(ctx, 'frobnicate', { cmd: 'git status' }, { host });
      assert.equal(ask.decision, 'ask', `${host}: an unknown tool's command the policy does not deny`);
      assert.match(ask.reason, /The guard does not know the tool frobnicate, so it cannot map its `cmd` argument/);
    }
  });
});

// ---------------------------------------------------------------- what must stay (passes before and after the fix)

test('must stay: ordinary values in the new keys, a cwd alone and ordinary payloads get no verdict (Claude Code)', () => {
  withProject((ctx) => {
    const none = (tool, input) => assert.equal(pre(ctx, tool, input).decision, null, label(tool, input));
    none('mcp__calendar__create_event', { title: 'Review', from: '2026-11-17T10:00:00Z', to: '2026-11-17T11:00:00Z' });
    none('mcp__mail__send_message', { to: email(), from: email(), input: 'Summarize: the release notes' });
    none('mcp__report__export', { output: 'json', target: 'production' });
    none('mcp__web__download', { source: 'https://example.com/a.csv', destination: path.join(ctx.dir, 'docs', 'a.csv') });
    none('mcp__files__copy', { source: 'docs/a.md', destination: 'docs/b.md' });
    none('mcp__files__list', { dir: 'docs', folder: 'templates' });
    none('mcp__files__get_info', { target: 'templates/t.md' });
    none('mcp__git__get_diff', { from: 'main', to: 'AGENTS.md' });
    none('mcp__runner__run', { cwd: 'templates' });
    none('mcp__runner__run', { cwd: path.join(ctx.dir, '.claude', 'logs') });
    none('mcp__sheets__append_rows', { rows: Array.from({ length: 300 }, (_, i) => ({ name: `n${i}`, value: i })) });
    none('mcp__filesystem__read_multiple_files', { paths: Array.from({ length: 300 }, (_, i) => `docs/f${i}.md`) });
    // A text key with a space is no file, and a text key is not taken from a cwd.
    none('mcp__llm__complete', { input: 'what is in config/.env', output: 'notes on key.pem' });
    none('mcp__llm__complete', { input: 'x', cwd: 'secrets' });
  });
});

test('must stay: the known servers keep their own handling, and Copilot keeps no verdict where it had none', () => {
  withProject((ctx) => {
    // Power BI, Microsoft Learn and GitHub: their own verdicts, whatever the new keys hold.
    const pbi = pre(ctx, 'mcp__powerbi-modeling__table_operations', { request: { operation: 'List', connectionName: LOCAL, options: { path: '.env' }, source: '.env' } });
    assert.equal(pbi.decision, 'allow');
    assert.match(pbi.reason, /Read-only Power BI MCP operation \(list\)/);
    assert.equal(pre(ctx, 'mcp__microsoft-learn__microsoft_docs_search', { query: 'rm -rf /' }).decision, null);
    assert.equal(pre(ctx, 'mcp__microsoft-learn__microsoft_docs_fetch', { url: 'https://learn.microsoft.com/x' }).decision, null);
    assert.equal(pre(ctx, 'mcp__github__get_file_contents', { owner: 'o', repo: 'r', path: '.env', options: { source: '.env' } }).decision, null);
    // Copilot: what the shell policy does not deny and no secret file stays without a verdict.
    for (const host of ['vscode', 'copilot-cli', 'copilot-claude']) {
      const vs = host === 'vscode';
      const cli = host === 'copilot-cli';
      assert.equal(pre(ctx, vs ? 'mcp_terminal_run_in_terminal' : cli ? 'terminal-mcp-run_in_terminal' : 'mcp__terminal__run_in_terminal', { command: 'git status' }, { host }).decision, null, host);
      assert.equal(pre(ctx, vs ? 'mcp_filesystem_write_file' : cli ? 'filesystem-mcp-write_file' : 'mcp__filesystem__write_file', { path: path.join(ctx.dir, 'templates', 't.md'), content: 'x' }, { host }).decision, null, host);
      assert.equal(pre(ctx, vs ? 'mcp_runner_run' : cli ? 'runner-mcp-run' : 'mcp__runner__run', { command: 'rm -r old', cwd: 'docs' }, { host }).decision, null, host);
      // `rm -r .` is judged from the cwd and from the session's folder (a server may ignore the cwd): from the project root it
      // takes the reference folder templates/ along, which the shell policy denies (open-2026-11-17-writers.test.mjs, part A).
      assert.equal(pre(ctx, vs ? 'mcp_runner_run' : cli ? 'runner-mcp-run' : 'mcp__runner__run', { command: 'rm -r .', cwd: 'docs' }, { host }).decision, 'deny', host);
    }
  });
});
