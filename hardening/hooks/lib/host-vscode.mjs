// GitHub Copilot hosts. VS Code's agent hooks (hardening/vscode.hooks.json, BI_HARNESS_HOST=vscode) speak almost the
// same protocol as Claude Code's (stdin JSON with tool_name and tool_input, stdout hookSpecificOutput.permissionDecision,
// exit code 2 blocks), but send VS Code's own tool names and input shapes, ignore matchers (every hook sees every tool)
// and want a Stop block nested in hookSpecificOutput. Copilot CLI and the cloud agent (hardening/copilot-cli.hooks.json,
// BI_HARNESS_HOST=copilot-cli) spell the payload in camelCase and want a flat output (a Stop block stays `{decision,
// reason}`, which agentStop reads; only a PostToolUse block has no equivalent). Copilot CLI also runs the Claude
// registration of .claude/settings*.json, without any host variable: PascalCase events, Claude's field and tool names
// (`Read`, `Edit`, `Bash`...), the CLI's own argument shapes (`path`, `paths`, `old_str`, `file_text`) and an ISO
// `timestamp` on every payload (GitHub docs, hooks reference, 2026-10-08; the lab's audit log of 2026-10-07).
// This module turns one Copilot call into the Claude-shaped calls the policy knows, merges their verdicts and reshapes
// the output. Tool names and fields: Copilot Chat's published tool schemas, VS Code's terminal and MCP tool code
// (2026-10-07) and the CLI's logged payloads; a tool this module does not know passes through unmapped and is logged, so a
// real session shows what still needs a mapping: no opinion, unless a text argument names a command, a file or an address
// (RISKY_FIELDS), which asks. A Claude Code payload passes through untouched.
import path from 'node:path';

export const VSCODE_HOST = 'vscode';
export const CLI_HOST = 'copilot-cli';
export const isVsCodeHost = () => process.env.BI_HARNESS_HOST === VSCODE_HOST;
/** GitHub Copilot CLI hooks (hardening/copilot-cli.hooks.json): camelCase events and fields, a flat output. */
export const isCopilotCliHost = () => process.env.BI_HARNESS_HOST === CLI_HOST;
export const isCopilotHost = () => isVsCodeHost() || isCopilotCliHost();
/**
 * True for a payload a Copilot host sent to the Claude registration (no host variable): Copilot stamps every payload
 * with a `timestamp` (an ISO string in the Claude dialect, epoch milliseconds in camelCase), which Claude Code never
 * sends (Claude Code 2.1.293, probed 2026-10-08: session_id, transcript_path, cwd, permission_mode, hook_event_name,
 * tool_name, tool_input, tool_use_id).
 */
export const isCopilotClaudeDialect = (input) => Boolean(input) && typeof input === 'object' && input.timestamp !== undefined;

/**
 * The Copilot host that sent a hook payload, or null for Claude Code: "copilot-cli" for the CLI's own camelCase payload
 * under its hook file; "vscode" for VS Code's hook file and for VS Code running the CLI's hook file with its own
 * snake_case payload (an event name and no camelCase `sessionId`, as isSnakeCasePayload in common.mjs reads it, F2-11);
 * "copilot-claude" for the Claude registration of .claude/settings*.json run by a Copilot host (a `timestamp`, no host
 * variable). One rule for the prompt guard, the session banner and the masking notice.
 */
export function copilotHostOf(input) {
  if (isCopilotCliHost()) {
    return Boolean(input) && typeof input === 'object' && typeof input.hook_event_name === 'string' && input.sessionId === undefined ? VSCODE_HOST : CLI_HOST;
  }
  if (isVsCodeHost()) return VSCODE_HOST;
  return isCopilotClaudeDialect(input) ? 'copilot-claude' : null;
}

const isPlainObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

/**
 * The arguments of a Copilot tool call as an object. GitHub's hooks reference types `toolArgs` `unknown` and describes
 * `tool_input` as "parsed from JSON string when possible" (2026-10-18), so the arguments can arrive as a JSON string, and
 * as the bare text of a freeform tool (apply_patch sends the patch itself, not JSON). A string that parses to an object
 * is that object, a patch text becomes {input}, and no arguments at all (undefined, null, an empty string) are {}.
 * Anything else cannot be read: `unreadable` is true and the PreToolUse verdict asks (mergeVerdicts), because a guard
 * that cannot read its input must not go silent.
 */
function readToolInput(value) {
  if (value === undefined || value === null) return { input: {} };
  if (isPlainObject(value)) return { input: value };
  if (typeof value === 'string') {
    const text = value.trim();
    if (!text) return { input: {} };
    if (text.startsWith('*** Begin Patch')) return { input: { input: value } };
    try {
      const parsed = JSON.parse(text);
      if (parsed === null) return { input: {} };
      if (isPlainObject(parsed)) return { input: parsed };
    } catch {
      // not JSON
    }
  }
  return { input: {}, unreadable: true };
}

/**
 * Copilot CLI sends `{sessionId, cwd, toolName, toolArgs, toolResult: {textResultForLlm}}` (GitHub docs, hooks reference,
 * 2026-10-07); the scripts read Claude's `session_id`, `tool_name`, `tool_input`, `tool_response`. Tool names and the
 * shape of toolArgs are not documented: the mapping below is shape-first, so a terminal command or a file path is
 * recognised by its field, and everything else passes through unmapped (logged). toolArgs (and the Claude dialect's
 * tool_input) can be a JSON string: readToolInput turns it into the object.
 */
export function fromCopilotCli(input) {
  if (!input || typeof input !== 'object') return input;
  const out = { ...input };
  if (out.session_id === undefined && out.sessionId !== undefined) out.session_id = String(out.sessionId);
  if (out.tool_name === undefined && out.toolName !== undefined) out.tool_name = String(out.toolName);
  if (out.tool_input === undefined && out.toolArgs !== undefined) out.tool_input = out.toolArgs;
  // The arguments of a tool call can arrive as a JSON string or as bare text (readToolInput): an object from here on,
  // flagged when it could not be read (the flag is this function's alone), so the audit log never spreads a string into
  // character indexes.
  delete out.tool_input_unreadable;
  if (out.tool_input !== undefined && !isPlainObject(out.tool_input)) {
    const read = readToolInput(out.tool_input);
    out.tool_input = read.input;
    if (read.unreadable) out.tool_input_unreadable = true;
  }
  if (out.tool_response === undefined && out.toolResult !== undefined) out.tool_response = out.toolResult?.textResultForLlm ?? out.toolResult;
  // The Claude dialect of the CLI carries the result as snake_case `tool_result` ({result_type, text_result_for_llm}).
  if (out.tool_response === undefined && out.tool_result !== undefined) out.tool_response = out.tool_result?.text_result_for_llm ?? out.tool_result?.textResultForLlm ?? out.tool_result;
  if (out.hook_event_name === undefined && typeof out.hookEventName === 'string') out.hook_event_name = out.hookEventName;
  if (out.prompt === undefined && typeof out.userPrompt === 'string') out.prompt = out.userPrompt;
  return out;
}

/**
 * Copilot CLI wants a flat output: {permissionDecision, permissionDecisionReason}, {additionalContext, modifiedResult}
 * and, for agentStop and subagentStop, {decision, reason}. Called as (event, result), like toHostOutput; a lone result
 * (or (result, event)) works too.
 */
export function toCopilotCliOutput(event, result) {
  if (typeof event !== 'string') [event, result] = [typeof result === 'string' ? result : undefined, event];
  if (!result) return result;
  const h = result.hookSpecificOutput ?? {};
  const out = {};
  if (h.permissionDecision) {
    out.permissionDecision = h.permissionDecision;
    if (h.permissionDecisionReason) out.permissionDecisionReason = h.permissionDecisionReason;
  }
  if (result.decision === 'block' && !out.permissionDecision) {
    if (event === 'Stop' || event === 'SubagentStop') {
      // agentStop and subagentStop read `decision` and `reason`: "block" forces another agent turn with `reason` as its
      // prompt (GitHub hooks reference, 2026-10-18); they take no additionalContext.
      out.decision = 'block';
      out.reason = result.reason;
    } else {
      // A PostToolUse block has no CLI equivalent (that event takes no decision): the reason reaches the model as context.
      out.additionalContext = [result.reason, h.additionalContext].filter(Boolean).join('\n\n');
    }
  } else if (h.additionalContext) out.additionalContext = h.additionalContext;
  const updated = h.updatedToolOutput ?? result.updatedToolOutput;
  if (updated !== undefined) out.modifiedResult = { resultType: 'success', textResultForLlm: typeof updated === 'string' ? updated : JSON.stringify(updated) };
  return Object.keys(out).length ? out : null;
}

/**
 * Output for the Claude registration run by Copilot CLI (probed with 1.0.94 on 2026-10-08): a PreToolUse decision in
 * Claude's own shape is honoured as it is; a masked tool result reaches the model only through the CLI's
 * `modifiedResult`, so a PostToolUse `updatedToolOutput` goes out in both shapes.
 */
export function toClaudeDialectOutput(result) {
  if (!result) return result;
  const updated = result.hookSpecificOutput?.updatedToolOutput ?? result.updatedToolOutput;
  if (updated === undefined) return result;
  return { ...result, modifiedResult: { resultType: 'success', textResultForLlm: typeof updated === 'string' ? updated : JSON.stringify(updated) } };
}

/** A tool name without the contributed prefix, case and separators: copilot_readFile, read_file, readFile -> readfile. */
const key = (name) => String(name ?? '').toLowerCase().replace(/^copilot_/, '').replace(/[_-]/g, '');

// Servers the hooks know by name besides the configured ones: GitHub (Copilot CLI's built-in server is
// `github-mcp-server`, GitHub CLI command reference, --disable-builtin-mcps; it keeps that name, the policy matches
// GitHub servers by name), Figma and Microsoft Learn.
const BUILTIN_MCP_SERVERS = ['github', 'github-mcp-server', 'figma', 'microsoft-learn'];

/**
 * The MCP server names the hooks know, longest first: the Power BI servers (`mcp.powerbiServers` and the older single
 * `mcp.powerbiServer`, as powerbiServersOf in policy.mjs reads them), the SQL servers named in
 * `sources.sqlRead.mcpServers` (trimmed, as sqlReadOf in sql-read.mjs reads them) and the built-in names. Read here,
 * not imported: policy.mjs and sql-read.mjs import common.mjs, which imports this module.
 */
function knownMcpServers(cfg) {
  const strings = (v) => (Array.isArray(v) ? v.filter((s) => typeof s === 'string' && s.trim()) : []);
  // Both settings count: the defaults fill powerbiServers, so a user's own powerbiServer must not be dropped.
  const powerbi = strings([...(Array.isArray(cfg?.mcp?.powerbiServers) ? cfg.mcp.powerbiServers : []), cfg?.mcp?.powerbiServer ?? 'powerbi-modeling']);
  const sql = strings(cfg?.sources?.sqlRead?.mcpServers).map((s) => s.trim());
  const seen = new Set();
  const out = [];
  for (const server of [...powerbi, ...sql, ...BUILTIN_MCP_SERVERS]) {
    if (seen.has(server.toLowerCase())) continue;
    seen.add(server.toLowerCase());
    out.push(server);
  }
  return out.sort((a, b) => b.length - a.length);
}

/** VS Code's label of a server in a tool name: lower-cased, non [a-z0-9_.-] runs replaced by `_`, cut to 13 characters. */
const vscodeLabel = (server) => String(server).toLowerCase().replace(/[^a-z0-9_.-]+/g, '_').slice(0, 13);

/** A tool part a known server's name may take: not empty, and no `mcp-` at its start or after a hyphen (F2-8). */
const knownServerTool = (tool) => tool.length > 0 && !/(?:^|-)mcp-/i.test(tool);

/**
 * An unknown server's CLI name split at the LAST "-mcp-" that leaves a server ([\w.-]) and a tool not starting with
 * `mcp-`. Server labels carry hyphens (my-mcp-server, powerbi-modeling-mcp); MCP tool names are snake_case, so a
 * "-mcp-" inside the tool is far rarer than one inside the server: my-mcp-server-mcp-tool is my-mcp-server + tool,
 * powerbi-modeling-mcp-mcp-security_role_operations is powerbi-modeling-mcp + security_role_operations.
 */
function splitAtLastMcp(raw) {
  const lower = raw.toLowerCase();
  for (let i = lower.lastIndexOf('-mcp-'); i > 0; i = lower.lastIndexOf('-mcp-', i - 1)) {
    const server = raw.slice(0, i);
    const tool = raw.slice(i + 5);
    if (tool && !/^mcp-/i.test(tool) && /^[\w.-]+$/.test(server)) return [server, tool];
  }
  return null;
}

/**
 * VS Code names an MCP tool `mcp_<label>_<tool>`: the server label lower-cased, non [a-z0-9_.-] runs replaced by `_`,
 * cut to 13 characters, with a digit suffix when two servers collide. Copilot CLI names it `<server>-mcp-<tool>`
 * (`powerbi-modeling-mcp-measure_operations`, audit log 2026-10-07) or `<server>-<tool>` (its built-in GitHub server's
 * `github-mcp-server-push_files`). The policy knows `mcp__<server>__<tool>`. A server the hooks know by name
 * (knownMcpServers, longest first) is matched before any generic split, so a name that holds "-mcp-" itself keeps its
 * server and tool (F2-8) and a configured name comes back from VS Code's cut label (F2-10): VS Code's form first, then
 * the CLI's `<server>-mcp-<tool>` and `<server>-<tool>`, case-insensitive, as the configured spelling; a tool part with
 * `mcp-` at its start or after a hyphen is no match for a known name. Two known names with the same 13-character label
 * resolve to the longer one (the digit suffix does not say which server it is). Then an unknown server: VS Code's
 * `mcp_<label>_<tool>` split at the first `_` after `mcp_`, the CLI's name at the last "-mcp-" (splitAtLastMcp).
 * A name that is none of these comes back unchanged.
 */
export function claudeMcpName(name, cfg) {
  const raw = String(name ?? '');
  if (raw.startsWith('mcp__')) return raw;
  const lower = raw.toLowerCase();
  const servers = knownMcpServers(cfg);
  if (lower.startsWith('mcp_')) {
    const byLabel = [...servers].sort((a, b) => vscodeLabel(b).length - vscodeLabel(a).length);
    for (const server of byLabel) {
      const safe = vscodeLabel(server);
      if (!lower.startsWith(`mcp_${safe}`)) continue;
      const rest = raw.slice(4 + safe.length).replace(/^\d+/, '');
      if (rest.startsWith('_') && rest.length > 1) return `mcp__${server}__${rest.slice(1)}`;
    }
  }
  for (const server of servers) {
    if (raw.slice(0, server.length).toLowerCase() !== server.toLowerCase()) continue;
    for (const sep of ['-mcp-', '-']) {
      if (raw.slice(server.length, server.length + sep.length).toLowerCase() !== sep) continue;
      const tool = raw.slice(server.length + sep.length);
      if (knownServerTool(tool)) return `mcp__${server}__${tool}`;
    }
  }
  if (lower.startsWith('mcp_')) {
    const m = /^mcp_([^_]+)_(.+)$/i.exec(raw);
    if (m) return `mcp__${m[1]}__${m[2]}`;
  }
  const cli = splitAtLastMcp(raw);
  return cli ? `mcp__${cli[0]}__${cli[1]}` : raw;
}

/** Files named by an apply_patch text (OpenAI patch grammar): Add, Update, Delete and Move headers with their lines. */
export function patchFiles(text) {
  const files = [];
  let current = null;
  for (const line of String(text ?? '').split(/\r?\n/)) {
    const header = /^\*\*\* (Add|Update|Delete) File: (.+)$/.exec(line);
    if (header) {
      current = { op: header[1], file: header[2].trim(), plus: [], minus: [] };
      files.push(current);
      continue;
    }
    const move = /^\*\*\* Move to: (.+)$/.exec(line);
    if (move) {
      files.push({ op: 'Move', file: move[1].trim(), plus: [], minus: [] });
      continue;
    }
    if (!current || /^\*\*\* /.test(line) || line.startsWith('@@')) continue;
    if (line.startsWith('+')) current.plus.push(line.slice(1));
    else if (line.startsWith('-')) current.minus.push(line.slice(1));
  }
  return files;
}

const abs = (p, projectDir) => (path.isAbsolute(String(p)) ? String(p) : path.resolve(projectDir, String(p)));

/** Claude Code's own tools with the field that marks their shape; a payload with it (and none of the CLI's) passes untouched. */
const CLAUDE_SHAPE = {
  Bash: 'command', PowerShell: 'command', Monitor: 'command', Read: 'file_path', Edit: 'file_path', Write: 'file_path',
  MultiEdit: 'file_path', NotebookEdit: 'notebook_path', Grep: 'pattern', Glob: 'pattern', LSP: 'operation', WebFetch: 'url',
};
const isClaudeShaped = (name, ti) =>
  CLAUDE_SHAPE[name] !== undefined && CLAUDE_SHAPE[name] in ti && !('paths' in ti) && !('old_str' in ti) && !('new_str' in ti) && !('file_text' in ti);
// Tools with no policy of their own (questions, task notes, the CLI's own SQLite scratch `sql`, web search, sub-agents,
// skills): no verdict and no `unmapped` row, so the audit log keeps pointing at tools that could touch files or servers.
const NO_POLICY = new Set(['skill', 'task', 'agent', 'askuserquestion', 'askuser', 'taskcomplete', 'websearch', 'sql',
  'searchcodesubagent', 'updatetodo', 'todowrite', 'todoread', 'reportintent', 'reportfindings']);
// Argument fields that name a command, a file or an address (the shapes this module maps, and their usual variants). An
// unknown tool that carries one as text may run or change something the guard never sees: its call asks (mergeVerdicts).
const RISKY_FIELDS = ['command', 'cmd', 'script', 'commandLine', 'path', 'filePath', 'file_path', 'file', 'uri', 'url', 'content'];

/**
 * The Claude-shaped calls for one Copilot tool call: shape first (the input fields), the tool name only as a hint.
 * Several files in one call (multi_replace_string_in_file, apply_patch, a search over several paths) become several
 * calls (a search keeps one call on PostToolUse, which merges no updated output). An unknown tool comes back
 * unchanged with `unmapped: true`, and with `tool_input_unmapped_risky` (the field's name) when a text argument names a
 * command, a file or an address (RISKY_FIELDS): mergeVerdicts asks then; a Claude Code payload comes back as it is. Arguments that cannot be read (see
 * readToolInput) come back as one `unmapped` call flagged `tool_input_unreadable`: mergeVerdicts turns it into an ask.
 */
export function toClaudeCalls(input, { cfg, projectDir, event } = {}) {
  const name = String(input?.tool_name ?? '');
  const read = readToolInput(input?.tool_input);
  const ti = read.input;
  const k = key(name);
  const base = { ...input, session_id: input?.session_id ?? VSCODE_HOST, host_tool: name };
  delete base.tool_input_unreadable;
  delete base.tool_input_unmapped_risky; // set below for an unknown tool, never taken from a payload
  delete base.host_delete; // set below for a Delete File, never taken from a payload
  const call = (tool_name, tool_input) => ({ ...base, tool_name, tool_input });
  const root = projectDir ?? process.cwd();
  const post = (event ?? input?.hook_event_name) === 'PostToolUse';

  // A tool with a policy of its own and arguments no one can read: nothing to judge, so the verdict asks. A tool in
  // NO_POLICY has no opinion by name, whatever it was sent.
  if ((read.unreadable || input?.tool_input_unreadable === true) && !NO_POLICY.has(k)) {
    return [{ ...base, tool_input: {}, unmapped: true, tool_input_unreadable: true }];
  }
  if (isClaudeShaped(name, ti)) return [call(name, ti)];
  if (name.startsWith('mcp__')) return [call(name, ti)];
  // An MCP tool under a host's own name: VS Code's mcp_<label>_<tool>, the CLI's <server>-mcp-<tool>, or the CLI's
  // <server>-<tool> of a server the hooks know by name (claudeMcpName), before any shape: its arguments are no file tool's.
  const mcpName = claudeMcpName(name, cfg);
  if (mcpName.startsWith('mcp__') || /^mcp_/i.test(name) || /-mcp-/i.test(name)) return [call(mcpName, ti)];
  if (NO_POLICY.has(k)) return [call(name, ti)];
  // A terminal command; a file tool whose `command` is a verb (str_replace_editor: view, create, str_replace) is not one.
  if (typeof ti.command === 'string' && (/terminal|shell|bash|powershell/.test(k) || !('filePath' in ti || 'path' in ti))) {
    return [call('Bash', { command: ti.command })];
  }
  // create_and_run_task ({workspaceFolder, task: {label, type, command, args?}}) runs a shell command as a VS Code task.
  if (isPlainObject(ti.task) && typeof ti.task.command === 'string') {
    const args = [].concat(ti.task.args ?? []).map((a) => (typeof a === 'string' ? a : a?.value)).filter((a) => typeof a === 'string');
    return [call('Bash', { command: [ti.task.command, ...args].join(' ') })];
  }
  if (Array.isArray(ti.replacements)) {
    return ti.replacements
      .filter((r) => r && typeof r.filePath === 'string')
      .map((r) => call('Edit', { file_path: abs(r.filePath, root), old_string: String(r.oldString ?? ''), new_string: String(r.newString ?? '') }));
  }
  if (typeof ti.input === 'string' && /^\*\*\* Begin Patch/m.test(ti.input)) {
    return patchFiles(ti.input).map((f) => (f.op === 'Add'
      ? call('Write', { file_path: abs(f.file, root), content: f.plus.join('\n') })
      // A deleted file writes nothing: the guard judges the call as the file emptied (`host_delete`, on the call and never in
      // a tool input), so the Tier 2 checks see the deletion instead of an edit with no text to work out.
      : f.op === 'Delete'
        ? { ...call('Edit', { file_path: abs(f.file, root), old_string: '', new_string: '' }), host_delete: true }
        : call('Edit', { file_path: abs(f.file, root), old_string: f.minus.join('\n'), new_string: f.plus.join('\n') })));
  }
  if (typeof ti.filePath === 'string') {
    const file_path = abs(ti.filePath, root);
    if (typeof ti.content === 'string') return [call('Write', { file_path, content: ti.content })];
    if ('oldString' in ti || 'newString' in ti) return [call('Edit', { file_path, old_string: String(ti.oldString ?? ''), new_string: String(ti.newString ?? '') })];
    if (typeof ti.code === 'string') return [call('Edit', { file_path, old_string: '', new_string: ti.code })];
    if (k.includes('notebook') && ('newCode' in ti || 'editType' in ti)) return [call('NotebookEdit', { notebook_path: file_path, new_source: String(ti.newCode ?? '') })];
    return [call('Read', { file_path })];
  }
  // GitHub Copilot CLI shapes (its own names view, create, edit, grep, glob, rg, or Claude's names through the Claude
  // registration): `path` + `file_text` is a Write, `path` + `old_str`/`new_str` an Edit, a bare `path` a Read (the
  // CLI's view also lists a folder), `pattern` + `paths` a Grep, `pattern` alone a Glob; the name decides grep vs glob.
  if (typeof ti.path === 'string' && !('pattern' in ti)) {
    const file_path = abs(ti.path, root);
    if (typeof ti.file_text === 'string') return [call('Write', { file_path, content: ti.file_text })];
    if ('old_str' in ti || 'new_str' in ti) return [call('Edit', { file_path, old_string: String(ti.old_str ?? ''), new_string: String(ti.new_str ?? '') })];
    if (k.includes('list')) return [call('Glob', { pattern: '*', path: file_path })];
    return [call('Read', { file_path })];
  }
  if (typeof ti.pattern === 'string') {
    const tool = /glob/.test(k) ? 'Glob' : /grep|^rg$/.test(k) || 'paths' in ti ? 'Grep' : 'Glob';
    // Every path searched is judged, one call each: ripgrep reads a file named on its command line even when it is hidden
    // or ignored, so a secret file in the second slot must reach the guard too. The strictest verdict wins (mergeVerdicts).
    // PostToolUse keeps one call: its merge drops an updated (masked) output when there are several.
    const searched = [...new Set([ti.paths, ti.path].flat(Infinity).filter((p) => typeof p === 'string' && p))];
    const targets = searched.length ? (post ? searched.slice(0, 1) : searched) : [null];
    return targets.map((p) => call(tool, { pattern: ti.pattern, ...(p ? { path: abs(p, root) } : {}), ...(typeof ti.glob === 'string' ? { glob: ti.glob } : {}) }));
  }
  if (typeof ti.query === 'string') {
    if ('includePattern' in ti || 'isRegexp' in ti || k.includes('grep') || k.includes('text')) {
      return [call('Grep', { pattern: ti.query, ...(typeof ti.includePattern === 'string' ? { glob: ti.includePattern } : {}) })];
    }
    if (k.includes('filesearch') || k.includes('findfiles')) return [call('Glob', { pattern: ti.query })];
    if (k.includes('codebase') || k.includes('semantic')) return [call('Grep', { pattern: ti.query })];
  }
  if (Array.isArray(ti.urls) || (k.includes('fetch') && typeof ti.url === 'string')) {
    // fetch_webpage: the guard has no opinion, the output masking does (secrets in a page come back redacted).
    return [call('WebFetch', { url: ti.url ?? ti.urls[0], ...(typeof ti.query === 'string' ? { prompt: ti.query } : {}) })];
  }
  // An unknown tool: logged as `unmapped`; when a text argument names a command, a file or an address, flagged so the
  // verdict asks (mergeVerdicts), with the field's name.
  const risky = RISKY_FIELDS.find((f) => typeof ti[f] === 'string' && ti[f].trim());
  return [{ ...base, tool_input: ti, unmapped: true, ...(risky ? { tool_input_unmapped_risky: risky } : {}) }];
}

const RANK = { deny: 3, ask: 2, none: 1, allow: 0 };
const decisionOf = (r) => r?.hookSpecificOutput?.permissionDecision ?? 'none';

/** The PreToolUse ask for a call whose arguments the guard could not read (readToolInput). */
const unreadableAsk = (tool) => ({
  hookSpecificOutput: {
    hookEventName: 'PreToolUse',
    permissionDecision: 'ask',
    permissionDecisionReason: `[bi-harness] The guard could not read the arguments of ${String(tool || 'this tool').slice(0, 60)} (they are not a JSON object), so it cannot check the files, commands or servers the call names. Allow it only if you can see what it does.`,
  },
});

/** The PreToolUse ask for a tool the translation does not know whose arguments name a command, a file or an address. */
const unmappedAsk = (tool, field) => ({
  hookSpecificOutput: {
    hookEventName: 'PreToolUse',
    permissionDecision: 'ask',
    permissionDecisionReason: `[bi-harness] The guard does not know the tool ${String(tool || 'this tool').slice(0, 60)}, so it cannot map its \`${String(field).slice(0, 40)}\` argument to the files, commands or servers it checks. Allow it only if you can see what it does.`,
  },
});

/**
 * One verdict for several calls. PreToolUse: deny > ask > no opinion > allow (one unknown file never turns the
 * whole call into an allow); a call whose arguments could not be read, or an unknown tool that names a command, a file or
 * an address (`calls`), adds an ask, never silence.
 * PostToolUse: a block wins; contexts are joined; an updated output survives only when there was one call.
 */
export function mergeVerdicts(event, results, calls = []) {
  const pre = event === 'PreToolUse' && Array.isArray(calls);
  const unreadable = pre ? calls.find((c) => c?.tool_input_unreadable) : undefined;
  if (unreadable) results = [...results, unreadableAsk(unreadable.host_tool ?? unreadable.tool_name)];
  const risky = pre ? calls.find((c) => c?.tool_input_unmapped_risky) : undefined;
  if (risky) results = [...results, unmappedAsk(risky.host_tool ?? risky.tool_name, risky.tool_input_unmapped_risky)];
  const list = results.filter((r) => r !== null && r !== undefined);
  if (results.length <= 1) return results[0] ?? null;
  if (event === 'PreToolUse') {
    let best = null;
    let bestRank = -1;
    for (const r of results) {
      const rank = RANK[decisionOf(r)] ?? 1;
      if (rank > bestRank) { best = r; bestRank = rank; }
    }
    if (!best || decisionOf(best) === 'none') return null;
    const same = list.filter((r) => decisionOf(r) === decisionOf(best));
    const reasons = [...new Set(same.map((r) => r.hookSpecificOutput?.permissionDecisionReason).filter(Boolean))];
    return { ...best, hookSpecificOutput: { ...best.hookSpecificOutput, permissionDecisionReason: reasons.join(' | ') } };
  }
  const blocks = list.filter((r) => r.decision === 'block');
  const contexts = [...new Set(list.map((r) => r.hookSpecificOutput?.additionalContext).filter(Boolean))];
  const out = {};
  if (blocks.length) {
    out.decision = 'block';
    out.reason = [...new Set(blocks.map((r) => r.reason).filter(Boolean))].join('\n');
  }
  if (contexts.length) out.hookSpecificOutput = { hookEventName: event, additionalContext: contexts.join('\n\n') };
  return Object.keys(out).length ? out : null;
}

/**
 * The output shape VS Code wants for a Stop block: nested in hookSpecificOutput (Claude's is top-level). A SubagentStop
 * block is not nested: VS Code reads it as top-level `decision` and `reason` (VS Code hooks reference, page dated
 * 10/14/2026), so runHook prints it as it is and never passes it here (toVsCodeOutput in common.mjs, F1-138); the
 * SubagentStop branch below is not used for VS Code.
 */
export function toHostOutput(event, result) {
  if (!result) return result;
  if ((event === 'Stop' || event === 'SubagentStop') && result.decision === 'block') {
    return { ...result, hookSpecificOutput: { ...(result.hookSpecificOutput ?? {}), hookEventName: event, decision: 'block', reason: result.reason } };
  }
  return result;
}
