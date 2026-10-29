// Audit trail (runs async, never blocks): tool calls, failures, notifications, loaded rules, subagent and session events.
// Reads the hook payload from stdin JSON - never from $TOOL_INPUT-style env vars, which are empty.
// The log holds targets and metadata, never contents: a project-relative path, a search pattern, a clipped command, a
// host. For an MCP call it holds server, tool, operation names, connectionName, maxRows and, for a query, its length and
// a SHA-256 prefix: never the query text, a definition, literal values or an impersonated identity. Every text it keeps
// (commands, paths, errors, notifications) has secrets and personal data (e-mail, IBAN, card, TCKN and phone-like
// numbers) masked; a long number such as an epoch time is masked too, which costs an audit log nothing. A command, and
// the error of a failed shell call, also have the passwords of a command line masked (mysql -p<password>, sqlcmd -P
// <password>, ConvertTo-SecureString '<password>', --password <password>, user:<password>@host in a URL, curl -u
// user:<password>; redactCommandSecrets in lib/policy.mjs).
// Under GitHub Copilot a tool call is read as the guard reads it (toClaudeCalls in lib/host-vscode.mjs): the row keeps
// the host's tool name and the target of the Claude-shaped call(s), and Copilot CLI's camelCase payload, which names no
// event, is a PostToolUse (or a PostToolUseFailure when it carries an error and no result; F1-75).

import { createHash } from 'node:crypto';
import { PROJECT_DIR, appendJsonl, loadConfig, projectRel, runHook } from './lib/common.mjs';
import { claudeMcpName, isCopilotClaudeDialect, isCopilotHost, toClaudeCalls } from './lib/host-vscode.mjs';
import { isPowerBiMcp, redactCommandSecrets, redactPii, redactSecrets } from './lib/policy.mjs';
import { copyIdentity } from './lib/ask-once.mjs';

// 9 to 15 digits, optionally grouped by spaces, dashes or parentheses (a phone, account or id number); not inside a
// word, a decimal or a dotted version, and not a date (2026-10-16 12:00).
const PHONE_LIKE_RE = /(?<![\w.])\+?\(?\d(?:[ ()-]{0,2}\d){8,14}(?![\w.])/g;
const DATE_RE = /^\d{4}-\d{2}-\d{2}(?!\d)/;

const mask = (value) =>
  redactPii(redactSecrets(String(value ?? '')).text).text.replace(PHONE_LIKE_RE, (m) => (DATE_RE.test(m) ? m : '[PII:phone]'));
const clip = (value, max = 300) => mask(value).slice(0, max);

// The policy's operation vocabulary (OP_KEY_RE and collectOperations in lib/policy.mjs, which does not export them).
const OP_KEY_RE = /^(?:operation|operations|operationtype|action|op|command|mode)$/i;
const OP_NAME_RE = /^[a-z][a-z0-9_.-]{0,39}$/;

/** Lower-cased operation names; free text under one of those keys (a script, a command line) is content: "(other)". */
function operations(value, out = new Set(), depth = 0) {
  if (depth > 6 || value === null || typeof value !== 'object') return out;
  for (const [key, v] of Object.entries(value)) {
    if (OP_KEY_RE.test(key)) {
      for (const op of [v].flat()) {
        if (typeof op !== 'string' || !op.trim() || out.size >= 10) continue;
        const name = op.trim().toLowerCase();
        out.add(OP_NAME_RE.test(name) ? name : '(other)');
      }
    }
    if (v && typeof v === 'object') operations(v, out, depth + 1);
  }
  return out;
}

/**
 * The query the server runs, as the guard reads it (findDaxQuery and queryRequest in lib/policy.mjs, F1-34): the one
 * field named `query` (any case) of the `request` wrapper, else of the arguments. No such field, or two, is no query:
 * another text that holds EVALUATE (a note, a description) is never taken for it.
 */
function queryField(input, names = /^query$/i) {
  const req = input?.request ?? input;
  if (!req || typeof req !== 'object' || Array.isArray(req)) return null;
  const keys = Object.keys(req).filter((key) => names.test(key));
  const query = keys.length === 1 ? req[keys[0]] : null;
  return typeof query === 'string' && query.trim() ? query : null;
}

/**
 * The query of an MCP call for its digest: a Power BI call's `query` field only (queryField); another server's (a SQL
 * MCP server) `query`, else its one `sql` or `statement` field, as the SQL read switch names its SQL fields. Two
 * candidates, or none, give no digest.
 */
const mcpQuery = (toolName, input, cfg) =>
  isPowerBiMcp(toolName, cfg) ? queryField(input) : queryField(input) ?? queryField(input, /^(?:sql|statement)$/i);

/**
 * Metadata of an MCP call; never the request content. The server and tool are the ones the verdict names: a host's
 * name (Copilot CLI's server-mcp-tool or server-tool, VS Code's mcp_label_tool) goes through claudeMcpName with the
 * project's config, so a known or configured server keeps its name and an unknown one splits at the last "-mcp-".
 */
function mcpTarget(tool, ti) {
  const cfg = loadConfig();
  const name = claudeMcpName(tool, cfg);
  const m = /^mcp__(.+?)__(.+)$/.exec(name);
  if (!m) return undefined;
  const input = ti && typeof ti === 'object' ? ti : {};
  const req = input.request && typeof input.request === 'object' && !Array.isArray(input.request) ? input.request : input;
  const ops = [...operations(input)];
  const connection = req.connectionName ?? req.ConnectionName ?? input.connectionName;
  const maxRows = req.maxRows ?? req.MaxRows;
  const query = mcpQuery(name, input, cfg);
  return {
    server: m[1],
    tool: m[2],
    ...(ops.length ? { operation: ops.join(',') } : {}),
    ...(typeof connection === 'string' && connection ? { connectionName: clip(connection, 120) } : {}),
    ...(Number.isInteger(maxRows) ? { maxRows } : {}),
    ...(query ? { query: { chars: query.length, sha256: createHash('sha256').update(query).digest('hex').slice(0, 12) } } : {}),
  };
}

const SHELL_TOOLS = ['Bash', 'PowerShell', 'Monitor'];
// A failed shell call's error holds its output, where a shell's trace (set -x) or an error message echoes the command:
// it gets the command-line rules too.
const errorOf = (tool, error) => clip(SHELL_TOOLS.includes(tool) ? redactCommandSecrets(String(error)).text : error);

function target(tool, ti = {}) {
  if (SHELL_TOOLS.includes(tool)) return clip(redactCommandSecrets(String(ti.command ?? '')).text);
  // Copilot CLI's file tools name their file as `path` (and a search folder as `paths`).
  const search = tool === 'Grep' || tool === 'Glob' || /^(?:grep|glob|rg)$/i.test(tool);
  if (ti.file_path || ti.notebook_path || (typeof ti.path === 'string' && !search)) return mask(projectRel(ti.file_path ?? ti.notebook_path ?? ti.path) ?? '(outside project)');
  if (search) return clip(`${ti.pattern ?? ''} @ ${projectRel(ti.path ?? (Array.isArray(ti.paths) ? ti.paths[0] : ti.paths)) ?? '.'}`, 200);
  if (tool === 'WebFetch') {
    try {
      return new URL(ti.url).host;
    } catch {
      return 'invalid-url';
    }
  }
  if (tool === 'Agent') return `${ti.subagent_type ?? 'general-purpose'}: ${clip(ti.description, 120)}`;
  if (tool === 'Skill') return clip(ti.skill ?? ti.name, 120);
  return mcpTarget(tool, ti);
}

/**
 * The target of a Copilot tool call: the Claude-shaped calls the guard judged (toClaudeCalls, one per file or searched
 * path), each read by `target`. One target is logged as it is, several as a list (at most 20, duplicates once).
 */
function copilotTarget(input) {
  const calls = toClaudeCalls(input, { cfg: loadConfig(), projectDir: PROJECT_DIR, event: 'PreToolUse' });
  const seen = new Set();
  const targets = [];
  for (const call of calls.slice(0, 20)) {
    const t = target(String(call.tool_name ?? ''), call.tool_input ?? {});
    const key = JSON.stringify(t ?? null);
    if (t === undefined || seen.has(key)) continue;
    seen.add(key);
    targets.push(t);
  }
  return targets.length > 1 ? targets : targets[0];
}

/**
 * The event of a payload. Copilot CLI's camelCase payloads name none (GitHub's hooks reference: only the VS Code
 * compatible form has hook_event_name), and its own hook file runs this script for postToolUse: a Copilot payload with a
 * tool and no event is a PostToolUse, or a PostToolUseFailure when it carries an `error` and no result (the
 * postToolUseFailure payload). A payload that names its event keeps it.
 */
function eventOf(input, copilot) {
  if (typeof input.hook_event_name === 'string') return input.hook_event_name;
  if (!copilot || input.tool_name === undefined) return input.hook_event_name;
  return input.error !== undefined && input.tool_response === undefined ? 'PostToolUseFailure' : 'PostToolUse';
}

await runHook('Audit', async (input) => {
  // Copilot through its own hook files (host variable) or through the Claude registration (a `timestamp`).
  const copilot = isCopilotHost() || isCopilotClaudeDialect(input);
  const event = eventOf(input, copilot);
  // agentId tells subagents of the same type apart (several reviewers or eval executors running at once).
  const base = { event, session: String(input.session_id ?? '').slice(0, 8), agent: input.agent_type, ...(input.agent_id ? { agentId: String(input.agent_id) } : {}) };
  switch (event) {
    case 'PostToolUse':
    case 'PostToolUseFailure':
      appendJsonl('tool-audit.jsonl', {
        ...base,
        tool: input.tool_name,
        // Under Copilot every registration writes its own row: `copy` says which one (BI_HARNESS_HOST, or claude).
        ...(copilot ? { copy: copyIdentity() } : {}),
        target: copilot ? copilotTarget(input) : target(String(input.tool_name ?? ''), input.tool_input),
        ok: event === 'PostToolUse',
        ...(input.error ? { error: errorOf(String(input.tool_name ?? ''), input.error) } : {}),
        ...(input.duration_ms ? { ms: input.duration_ms } : {}),
      });
      break;
    case 'Notification':
      appendJsonl('notifications.jsonl', { ...base, type: input.notification_type, message: clip(input.message) });
      break;
    case 'InstructionsLoaded':
      // Which rule or instruction file entered the context, and why (session_start, path_glob_match, ...).
      appendJsonl('instructions.jsonl', {
        ...base,
        file: projectRel(input.file_path) ?? '(outside project)',
        type: input.memory_type,
        why: input.load_reason,
        ...(input.globs ? { globs: input.globs } : {}),
      });
      break;
    case 'SubagentStop':
      appendJsonl('sessions.jsonl', { ...base, agentId: input.agent_id });
      break;
    case 'SessionEnd':
      appendJsonl('sessions.jsonl', { ...base, reason: input.reason });
      break;
    default:
      appendJsonl('sessions.jsonl', base);
  }
  return null;
});
