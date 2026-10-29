// The small hooks, follow-up audit round 2 (fix group W2-S): the prompt guard (F1-73 extraWords in any case whatever the
// host's locale, F1-74 its behaviour, F1-99 what it may claim under GitHub Copilot), the audit log (F1-75 Copilot payloads,
// the MCP query field the guard judges, Copilot MCP names as the verdict reads them), the post-edit validation (F1-114)
// and the session banner of a broken harness.config.json (F1-132). Every hook runs in a temp project; fake secrets are
// built at run time. The Copilot payloads follow GitHub's hooks reference and VS Code's hooks reference (page dated
// 10/14/2026); not run inside Copilot CLI or VS Code.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const hooks = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'hooks');
const ISO = '2026-10-19T08:00:00.000Z';

/** A temp project holding `files` (project-relative path -> text). */
function project(files = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-r2s-'));
  for (const [rel, text] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), text);
  }
  return dir;
}

/** Runs a hook in `dir` with `payload` on stdin; `host` sets BI_HARNESS_HOST (unset otherwise), `nodeArgs` go before the script. */
function run(script, dir, payload, { host, nodeArgs = [] } = {}) {
  const env = { ...process.env, CLAUDE_PROJECT_DIR: dir };
  delete env.BI_HARNESS_HOST;
  if (host) env.BI_HARNESS_HOST = host;
  const r = spawnSync(process.execPath, [...nodeArgs, path.join(hooks, script)], { input: JSON.stringify(payload), env, encoding: 'utf8' });
  if (r.error) throw r.error;
  assert.doesNotMatch(r.stderr, /hook error/, `${script}: ${r.stderr}`);
  return { status: r.status, stdout: r.stdout, stderr: r.stderr, out: r.stdout.trim() ? JSON.parse(r.stdout) : null };
}

const rows = (dir, name) => {
  const file = path.join(dir, '.claude', 'logs', name);
  return fs.existsSync(file) ? fs.readFileSync(file, 'utf8').trim().split('\n').map((l) => JSON.parse(l)) : [];
};
const sha12 = (text) => createHash('sha256').update(text).digest('hex').slice(0, 12);
const fakeToken = () => ['gh', 'p_'].join('') + 'A'.repeat(36);

// ------------------------------------------------------------------------------------------------ user-prompt-guard.mjs

/**
 * A preload that gives String#toLocaleLowerCase and #toLocaleUpperCase `locale` as their default, as on a host whose OS
 * locale it is: Node takes its default locale from the OS (on Windows LANG and LC_ALL do not change it), so a test
 * cannot switch it otherwise.
 */
function localePreload(dir, locale) {
  const file = path.join(dir, `locale-${locale}.cjs`);
  fs.writeFileSync(file, [
    'const lower = String.prototype.toLocaleLowerCase;',
    'const upper = String.prototype.toLocaleUpperCase;',
    `String.prototype.toLocaleLowerCase = function (l) { return lower.call(this, l ?? ${JSON.stringify(locale)}); };`,
    `String.prototype.toLocaleUpperCase = function (l) { return upper.call(this, l ?? ${JSON.stringify(locale)}); };`,
    '',
  ].join('\n'));
  return ['--require', file];
}

const prompt = (dir, text, opts) => run('user-prompt-guard.mjs', dir, { hook_event_name: 'UserPromptSubmit', session_id: 'r2s-prompt', prompt: text }, opts);
const reminded = (r) => /Tier 2/.test(r.out?.hookSpecificOutput?.additionalContext ?? '');

test('F1-73: deployReminder.extraWords match in any case, Turkish I/ı/İ/i included, whatever the host locale', () => {
  const dir = project({ 'hardening/harness.config.json': JSON.stringify({ deployReminder: { extraWords: ['yayınla', 'ship it', 'CANLIYA AL'] } }) });
  try {
    for (const locale of ['en-US', 'tr-TR']) {
      const nodeArgs = localePreload(dir, locale);
      for (const text of ['raporu yayınla', 'raporu YAYINLA', 'Raporu Yayınla', 'raporu yayinla', 'SHIP IT tonight', 'Ship it', 'modeli canlıya al', 'MODELİ CANLIYA AL', 'Modeli Canlıya Al']) {
        const r = prompt(dir, text, { nodeArgs });
        assert.equal(r.status, 0, `${locale} ${text}: ${r.stderr}`);
        assert.ok(reminded(r), `${locale}: "${text}" gets the Tier 2 reminder`);
      }
      for (const text of ['add a measure for net sales', 'yayın akışını anlat', 'shipping costs by region']) {
        const r = prompt(dir, text, { nodeArgs });
        assert.equal(r.stdout, '', `${locale}: "${text}" gets no reminder`);
      }
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('F1-74: built-in deploy words get the reminder, an ordinary prompt gets nothing, a token is blocked in Claude Code', () => {
  const dir = project();
  try {
    for (const text of ['publish this report to production', 'please DEPLOY the model', 'git push the branch', 'is prod up to date?']) {
      const r = prompt(dir, text);
      assert.equal(r.status, 0, text);
      assert.equal(r.stderr, '', text);
      assert.equal(r.out.hookSpecificOutput.hookEventName, 'UserPromptSubmit', text);
      assert.match(r.out.hookSpecificOutput.additionalContext, /^\[bi-harness\] Reminder: deployment and publishing are never the agent's/, text);
    }
    const plain = prompt(dir, 'add a measure for net sales');
    assert.deepEqual([plain.status, plain.stdout, plain.stderr], [0, '', ''], 'no output for an ordinary prompt');
    const token = fakeToken();
    const blocked = prompt(dir, `use token ${token} please`);
    assert.equal(blocked.status, 2);
    assert.equal(blocked.stdout, '');
    assert.match(blocked.stderr, /^\[bi-harness\] Message blocked: it contains what looks like a credential \(github-token\)\. It was NOT sent to Claude\./);
    const events = rows(dir, 'security-events.jsonl');
    assert.deepEqual(events.map((e) => [e.event, e.ids, e.session]), [['prompt-blocked', ['github-token'], 'r2s-prom']]);
    assert.doesNotMatch(blocked.stderr + JSON.stringify(events), new RegExp(token), 'the value is never echoed or logged');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('F1-99: under GitHub Copilot the guard says what the host does with exit 2 and never that the message was withheld', () => {
  const dir = project();
  try {
    const token = fakeToken();
    const text = `use token ${token} please`;
    const variants = [
      // Copilot CLI and the cloud agent, their own hook file: camelCase, no event name (GitHub hooks reference).
      ['copilot-cli', { sessionId: 'r2s-cli', timestamp: 1760000000000, cwd: dir, prompt: text }, /GitHub Copilot CLI .*exit 2 on a submitted prompt as a warning and the run continues/],
      // VS Code's hook file.
      ['vscode', { hook_event_name: 'UserPromptSubmit', session_id: 'r2s-vsc', timestamp: ISO, cwd: dir, prompt: text }, /VS Code's hooks reference does not say that a hook can hold a message back/],
      // VS Code runs the CLI's hook file too, with its own snake_case payload (F2-11): the host is VS Code, not the CLI.
      ['copilot-cli', { hook_event_name: 'UserPromptSubmit', session_id: 'r2s-vcl', timestamp: ISO, cwd: dir, prompt: text }, /VS Code's hooks reference does not say that a hook can hold a message back/],
      // The Claude registration run by Copilot (no host variable, a timestamp Claude Code never sends).
      [undefined, { hook_event_name: 'UserPromptSubmit', session_id: 'r2s-dia', timestamp: ISO, cwd: dir, prompt: text }, /GitHub Copilot ran this hook through the Claude registration/],
    ];
    for (const [host, payload, says] of variants) {
      const r = run('user-prompt-guard.mjs', dir, payload, { host });
      const label = `${host ?? 'copilot-claude'} ${payload.sessionId ?? payload.session_id}`;
      assert.equal(r.status, 2, `${label}: exit 2 is the one way the notice is surfaced`);
      assert.equal(r.stdout, '', label);
      assert.match(r.stderr, /^\[bi-harness\] Credential in your message: it contains what looks like a credential \(github-token\)\./, label);
      assert.match(r.stderr, says, label);
      assert.match(r.stderr, /treat the message as sent to the model/, label);
      assert.match(r.stderr, /Rotate this credential now/, label);
      assert.doesNotMatch(r.stderr, /NOT sent|Message blocked|to Claude/, `${label}: no claim the host does not keep`);
      assert.doesNotMatch(r.stderr, new RegExp(token), label);
    }
    const events = rows(dir, 'security-events.jsonl');
    assert.deepEqual(events.map((e) => [e.event, e.ids, e.host, e.session]), [
      ['prompt-credential', ['github-token'], 'copilot-cli', 'r2s-cli'],
      ['prompt-credential', ['github-token'], 'vscode', 'r2s-vsc'],
      ['prompt-credential', ['github-token'], 'vscode', 'r2s-vcl'],
      ['prompt-credential', ['github-token'], 'copilot-claude', 'r2s-dia'],
    ]);
    assert.doesNotMatch(JSON.stringify(events), new RegExp(token));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ------------------------------------------------------------------------------------------------------- audit-log.mjs

const DAX_TOOL = 'mcp__powerbi-modeling__dax_query_operations';
const audit = (dir, tool_name, tool_input, extra = {}) => {
  run('audit-log.mjs', dir, { hook_event_name: 'PostToolUse', session_id: 'r2s-audit', tool_name, tool_input, ...extra });
  return rows(dir, 'tool-audit.jsonl').pop();
};

test('audit log: an MCP query is the request\'s query field, the one the guard judges, never another text with EVALUATE', () => {
  const dir = project();
  try {
    const query = 'EVALUATE ROW("x", 1)';
    const decoy = 'EVALUATE { "decoy" }';
    const digest = { chars: query.length, sha256: sha12(query) };
    assert.deepEqual(audit(dir, DAX_TOOL, { note: decoy, request: { operation: 'Execute', query } }).target.query, digest, 'a text beside the request');
    assert.deepEqual(audit(dir, DAX_TOOL, { request: { description: decoy, operation: 'Execute', Query: query } }).target.query, digest, 'a description in the request; Query in any case');
    assert.deepEqual(audit(dir, DAX_TOOL, { operation: 'Execute', query }).target.query, digest, 'arguments without a request wrapper');
    assert.equal(audit(dir, DAX_TOOL, { request: { operation: 'Execute', statement: decoy } }).target.query, undefined, 'no query field: no digest');
    assert.equal(audit(dir, DAX_TOOL, { request: { operation: 'Execute', query, QUERY: decoy } }).target.query, undefined, 'two query fields: the guard reads neither');
    assert.equal(audit(dir, DAX_TOOL, { query: decoy, request: { operation: 'Execute' } }).target.query, undefined, 'a query beside the request is not the request\'s');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('audit log: a SQL MCP server\'s query keeps its digest in a sql or statement field; a Power BI call reads only query', () => {
  const dir = project();
  try {
    const sql = 'SELECT COUNT(*) FROM dbo.Orders';
    const digest = { chars: sql.length, sha256: sha12(sql) };
    assert.deepEqual(audit(dir, 'mcp__contoso-sql__run_query', { sql }).target.query, digest, 'a sql field');
    assert.deepEqual(audit(dir, 'mcp__contoso-sql__execute', { request: { Statement: sql } }).target.query, digest, 'a Statement field in a request');
    assert.deepEqual(audit(dir, 'mcp__contoso-sql__execute', { query: sql, note: 'SELECT 1' }).target.query, digest, 'a query field wins');
    assert.equal(audit(dir, 'mcp__contoso-sql__execute', { sql, statement: 'SELECT 1' }).target.query, undefined, 'two candidate fields: no digest');
    assert.equal(audit(dir, DAX_TOOL, { request: { operation: 'Execute', sql: 'EVALUATE { 1 }' } }).target.query, undefined, 'a Power BI call has no sql field');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('audit log: a Copilot MCP name is split as the verdict reads it: known and configured servers, else the last -mcp-', () => {
  const dir = project({ 'hardening/harness.config.json': JSON.stringify({ mcp: { powerbiServers: ['contoso-mcp-bi'] } }) });
  try {
    const serverTool = (name) => {
      const t = audit(dir, name, { request: { operation: 'Read' } }).target;
      return [t?.server, t?.tool];
    };
    assert.deepEqual(serverTool('my-mcp-server-mcp-run_query'), ['my-mcp-server', 'run_query'], 'an unknown server at the last -mcp-');
    assert.deepEqual(serverTool('github-mcp-server-push_files'), ['github-mcp-server', 'push_files'], 'the CLI\'s built-in GitHub server');
    assert.deepEqual(serverTool('contoso-mcp-bi-mcp-measure_operations'), ['contoso-mcp-bi', 'measure_operations'], 'a configured server');
    assert.deepEqual(serverTool('powerbi-modeling-mcp-dax_query_operations'), ['powerbi-modeling', 'dax_query_operations']);
    assert.deepEqual(serverTool(DAX_TOOL), ['powerbi-modeling', 'dax_query_operations'], 'Claude\'s own name');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('F1-75: under Copilot every tool call gets a tool-audit row with the host\'s tool name and the target the guard read', () => {
  const dir = project({ 'docs/a.md': '# a\n' });
  try {
    const cli = (payload) => run('audit-log.mjs', dir, { timestamp: 1760000000000, cwd: dir, ...payload }, { host: 'copilot-cli' });
    const vscode = (payload) => run('audit-log.mjs', dir, { timestamp: ISO, cwd: dir, ...payload }, { host: 'vscode' });
    const query = 'EVALUATE { 1 }';
    // Copilot CLI's own hook file: camelCase, no event name; postToolUse has a toolResult, postToolUseFailure an error.
    cli({ sessionId: 'cli-a1', toolName: 'bash', toolArgs: { command: 'git status' }, toolResult: { resultType: 'success', textResultForLlm: 'ok' } });
    cli({ sessionId: 'cli-a2', toolName: 'bash', toolArgs: { command: 'git sttus' }, error: 'git: not a git command' });
    cli({ sessionId: 'cli-a3', toolName: 'view', toolArgs: JSON.stringify({ path: path.join(dir, 'docs', 'a.md') }), toolResult: { resultType: 'success', textResultForLlm: '# a' } });
    cli({ sessionId: 'cli-a4', toolName: 'powerbi-modeling-mcp-dax_query_operations', toolArgs: { request: { operation: 'Execute', query } }, toolResult: { resultType: 'success', textResultForLlm: '[]' } });
    // VS Code: snake_case with an event name and VS Code's tool names.
    vscode({ hook_event_name: 'PostToolUse', session_id: 'vsc-a1', tool_name: 'run_in_terminal', tool_input: { command: 'git status', explanation: 'x' }, tool_response: 'ok' });
    vscode({ hook_event_name: 'PostToolUse', session_id: 'vsc-a2', tool_name: 'read_file', tool_input: { filePath: path.join(dir, 'docs', 'a.md'), startLine: 1, endLine: 2 }, tool_response: '# a' });
    const patch = ['*** Begin Patch', '*** Add File: docs/new.md', '+# new', '*** Update File: docs/a.md', '@@', '-# a', '+# A', '*** End Patch'].join('\n');
    vscode({ hook_event_name: 'PostToolUse', session_id: 'vsc-a3', tool_name: 'apply_patch', tool_input: { input: patch, explanation: 'e' }, tool_response: 'ok' });
    // The Claude registration run by the CLI: Claude's names, the CLI's argument shapes, a timestamp.
    run('audit-log.mjs', dir, { hook_event_name: 'PostToolUse', session_id: 'dia-a1', timestamp: ISO, cwd: dir, tool_name: 'Read', tool_input: { path: path.join(dir, 'docs', 'a.md') }, tool_result: { result_type: 'success', text_result_for_llm: '# a' } });
    assert.deepEqual(rows(dir, 'tool-audit.jsonl').map((r) => [r.event, r.session, r.tool, r.target, r.ok, r.error]), [
      ['PostToolUse', 'cli-a1', 'bash', 'git status', true, undefined],
      ['PostToolUseFailure', 'cli-a2', 'bash', 'git sttus', false, 'git: not a git command'],
      ['PostToolUse', 'cli-a3', 'view', 'docs/a.md', true, undefined],
      ['PostToolUse', 'cli-a4', 'powerbi-modeling-mcp-dax_query_operations', { server: 'powerbi-modeling', tool: 'dax_query_operations', operation: 'execute', query: { chars: query.length, sha256: sha12(query) } }, true, undefined],
      ['PostToolUse', 'vsc-a1', 'run_in_terminal', 'git status', true, undefined],
      ['PostToolUse', 'vsc-a2', 'read_file', 'docs/a.md', true, undefined],
      ['PostToolUse', 'vsc-a3', 'apply_patch', ['docs/new.md', 'docs/a.md'], true, undefined],
      ['PostToolUse', 'dia-a1', 'Read', 'docs/a.md', true, undefined],
    ]);
    assert.deepEqual(rows(dir, 'sessions.jsonl'), [], 'no tool call lands in sessions.jsonl');
    // An event with a name of its own keeps its log: VS Code's SubagentStart is a session record, not a tool call.
    vscode({ hook_event_name: 'SubagentStart', session_id: 'vsc-s1', agent_type: 'bi-validator' });
    assert.deepEqual(rows(dir, 'sessions.jsonl').map((r) => [r.event, r.session, r.agent]), [['SubagentStart', 'vsc-s1', 'bi-validator']]);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ------------------------------------------------------------------------------------------------ post-tool-validate.mjs

const BAD_RDL = '<?xml version="1.0"?>\n<Report xmlns="http://schemas.microsoft.com/sqlserver/reporting/2016/01/reportdefinition"><ReportSections><ReportSection><Body><ReportItems><Textbox Name="A"/><Textbox Name="A"/></ReportItems><Height>1in</Height></Body><Width>1in</Width><Page/></ReportSection></ReportSections></Report>\n';
const RELOAD = /Power BI Desktop only picks up external PBIP edits/;

test('F1-114: RDL errors go back as context, a broken PBIP file blocks, the Desktop reminder comes once per session', () => {
  const dir = project({
    'reports/r/Bad.rdl': BAD_RDL,
    'S.SemanticModel/definition.pbism': '{"a":',
    'S.SemanticModel/definition/tables/T.tmdl': 'table T\n',
  });
  try {
    const post = (rel, session = 'r2s-ptv-1') => run('post-tool-validate.mjs', dir, {
      hook_event_name: 'PostToolUse', session_id: session, tool_name: 'Write', tool_input: { file_path: path.join(dir, rel), content: 'x' }, tool_response: {},
    }).out;
    const rdl = post('reports/r/Bad.rdl');
    assert.equal(rdl.decision, undefined, 'an RDL change takes several edits: no block');
    assert.match(rdl.hookSpecificOutput.additionalContext, /^\[bi-harness\] reports\/r\/Bad\.rdl is not consistent yet\. Finish the change, then make sure these are fixed before you stop/);
    assert.match(rdl.hookSpecificOutput.additionalContext, /ERROR reports\/r\/Bad\.rdl .*names must be unique; duplicated: a/, 'with the error');
    assert.doesNotMatch(rdl.hookSpecificOutput.additionalContext, RELOAD, 'an RDL file is no PBIP edit');
    const pbism = post('S.SemanticModel/definition.pbism');
    assert.equal(pbism.decision, 'block');
    assert.match(pbism.reason, /^\[bi-harness\] S\.SemanticModel\/definition\.pbism failed validation/);
    assert.match(pbism.hookSpecificOutput.additionalContext, RELOAD, 'the first PBIP write of the session');
    assert.equal(post('S.SemanticModel/definition/tables/T.tmdl'), null, 'the second one: no reminder again');
    assert.match(post('S.SemanticModel/definition/tables/T.tmdl', 'r2s-ptv-2').hookSpecificOutput.additionalContext, RELOAD, 'another session is reminded');
    const state = JSON.parse(fs.readFileSync(path.join(dir, '.claude', 'logs', '.state', 'r2s-ptv-1.json'), 'utf8'));
    assert.deepEqual(state.changedFiles, ['reports/r/Bad.rdl', 'S.SemanticModel/definition.pbism', 'S.SemanticModel/definition/tables/T.tmdl'], 'every written file for the Stop gate');
    // Copilot CLI's own hook file: the RDL context comes back flat.
    const cli = run('post-tool-validate.mjs', dir, {
      sessionId: 'r2s-ptv-3', timestamp: 1760000000000, cwd: dir, toolName: 'create', toolArgs: { path: path.join(dir, 'reports', 'r', 'Bad.rdl'), file_text: 'x' }, toolResult: { resultType: 'success', textResultForLlm: 'ok' },
    }, { host: 'copilot-cli' }).out;
    assert.deepEqual(Object.keys(cli), ['additionalContext']);
    assert.match(cli.additionalContext, /reports\/r\/Bad\.rdl is not consistent yet/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ----------------------------------------------------------------------------------------------------- session-start.mjs

const banner = (dir) => {
  const r = run('session-start.mjs', dir, { hook_event_name: 'SessionStart', session_id: 'r2s-start', source: 'startup' });
  assert.equal(r.status, 0, r.stderr);
  return r.out.hookSpecificOutput.additionalContext.split('\n').filter((l) => l.startsWith('- Approvals:'));
};

test('F1-132: a harness.config.json that is not valid JSON is named in the banner; it never says the user chose ask', () => {
  const broken = project({ 'hardening/harness.config.json': '{ "approvals": { "mode": "lab" ' });
  const asked = project({ 'hardening/harness.config.json': JSON.stringify({ approvals: { mode: 'ask' } }) });
  const none = project();
  try {
    const [line, ...more] = banner(broken);
    assert.equal(more.length, 0);
    assert.match(line, /^- Approvals: ask, because hardening\/harness\.config\.json is not valid JSON/);
    assert.match(line, /node hardening\/scripts\/validate\.mjs/, 'where the error is named');
    assert.doesNotMatch(line, /set by the user/);
    assert.match(banner(asked)[0], /^- Approvals: ask mode \(set by the user\)/, 'a valid "ask" keeps its line');
    assert.match(banner(none)[0], /^- Approvals: auto\./, 'no file: the default');
  } finally {
    for (const dir of [broken, asked, none]) fs.rmSync(dir, { recursive: true, force: true });
  }
});

// F1-80/F1-81 (docs group): Claude Code evaluates an ask rule whatever a hook returns, so the banner must not promise lab
// mode runs Desktop without a prompt, nor that screenshots "on" run without one: the powerbi-desktop ask rules still prompt.
test('F1-81: the lab banner and the screenshot line do not promise Desktop actions without Claude Code\'s prompt', () => {
  const lab = project({ 'hardening/harness.config.json': JSON.stringify({ approvals: { mode: 'lab' }, desktop: { screenshots: 'on' } }) });
  try {
    const r = run('session-start.mjs', lab, { hook_event_name: 'SessionStart', session_id: 'r2s-lab', source: 'startup' });
    assert.equal(r.status, 0, r.stderr);
    const text = r.out.hookSpecificOutput.additionalContext;
    const labLine = text.split('\n').find((l) => l.startsWith('- Approvals: LAB mode'));
    assert.ok(labLine, text);
    assert.doesNotMatch(labLine, /including Desktop/);
    assert.match(labLine, /reload/, 'the lab line says reload still asks');
    const shots = text.split('\n').find((l) => l.startsWith('- Desktop screenshots:'));
    assert.match(shots, /Claude Code's ask rule still prompts/);
    assert.doesNotMatch(shots, /on = runs in auto and lab/);
  } finally {
    fs.rmSync(lab, { recursive: true, force: true });
  }
});
