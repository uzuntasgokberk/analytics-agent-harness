// Claude Code permission rules read from the settings files, so that the guard never answers "allow" for a call a
// rule denies. A PreToolUse hook's "allow" does not skip a matching ask or deny rule: Claude Code evaluates both
// whatever a hook returns (Claude Code docs, Permissions, precedence among rules and hooks, checked 2026-10-19); an
// "allow" where a rule denies would only mislead. Under GitHub Copilot, which evaluates no settings rules, the guard
// denies and asks in their place (guard-pre-tool-use.mjs).
// Matching follows the documented rule syntax closely enough to err on the blocking side; it is not a full copy.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { PROJECT_DIR, globToRegExp, toPosix } from './common.mjs';

const MANAGED_SETTINGS = {
  win32: `${(process.env.ProgramFiles ?? 'C:/Program Files').replace(/\\/g, '/')}/ClaudeCode/managed-settings.json`,
  darwin: '/Library/Application Support/ClaudeCode/managed-settings.json',
  linux: '/etc/claude-code/managed-settings.json',
};

/**
 * Settings files whose permission rules apply to this project: managed (file and managed-settings.d/*.json drop-ins,
 * Claude Code docs, Deploy managed settings), user, project, local.
 */
export function settingsFiles(root = PROJECT_DIR) {
  const managed = MANAGED_SETTINGS[process.platform];
  let dropIns = [];
  if (managed) {
    const dir = path.join(path.dirname(managed), 'managed-settings.d');
    try {
      dropIns = fs.readdirSync(dir).filter((n) => n.toLowerCase().endsWith('.json')).map((n) => path.join(dir, n));
    } catch {
      // no drop-in folder
    }
  }
  return [
    managed,
    ...dropIns,
    path.join(os.homedir(), '.claude', 'settings.json'),
    path.join(root, '.claude', 'settings.json'),
    path.join(root, '.claude', 'settings.local.json'),
  ].filter(Boolean);
}

const ruleCache = new Map();

/** Every rule string of one kind (deny, ask, allow) across the settings files. Broken or missing files add none. */
export function loadRules(kind, root = PROJECT_DIR) {
  const key = `${kind}|${root}`;
  if (ruleCache.has(key)) return ruleCache.get(key);
  const rules = [];
  for (const file of settingsFiles(root)) {
    try {
      const list = JSON.parse(fs.readFileSync(file, 'utf8').replace(/^\uFEFF/, ''))?.permissions?.[kind];
      if (Array.isArray(list)) rules.push(...list.filter((r) => typeof r === 'string'));
    } catch {
      // no file or no rules
    }
  }
  ruleCache.set(key, rules);
  return rules;
}

const RULE_RE = /^([A-Za-z_][\w-]*)(?:\(([\s\S]*)\))?$/;
const EDIT_TOOLS = new Set(['Edit', 'Write', 'MultiEdit', 'NotebookEdit']);
const READ_TOOLS = new Set(['Read', 'Grep', 'Glob', 'LSP']);
const SHELL_RULE_TOOLS = { Bash: new Set(['Bash', 'Monitor']), PowerShell: new Set(['PowerShell']) };

/** `Bash(git push *)`: `*` is any text; a trailing `:*` is the older prefix form. */
function commandRe(spec) {
  const s = spec.trim().replace(/:\*$/, ' *');
  return new RegExp(`^${s.split('*').map((p) => p.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('[\\s\\S]*')}$`, 'i');
}

/** `Edit(/templates/**)` (project root), `~/x` (home), `//x` (absolute), `**\/*.pem` or `.env` (any folder). */
function pathRe(spec, root) {
  const p = toPosix(spec.trim());
  const rootPosix = toPosix(path.resolve(root));
  let glob;
  if (p.startsWith('//')) glob = p.slice(2);
  else if (p.startsWith('~/')) glob = `${toPosix(os.homedir())}/${p.slice(2)}`;
  else if (p.startsWith('/')) glob = `${rootPosix}${p}`;
  else if (p.startsWith('./')) glob = `${rootPosix}/${p.slice(2)}`;
  else if (p.startsWith('**/') || !p.replace(/\/$/, '').includes('/')) glob = `**/${p.replace(/^\*\*\//, '')}`;
  else glob = `${rootPosix}/${p}`;
  if (glob.endsWith('/')) glob += '**';
  return globToRegExp(glob);
}

function splitCommands(command) {
  const full = String(command ?? '').trim();
  return [full, ...full.split(/\s*(?:&&|\|\||;|\||\r?\n)\s*/).map((s) => s.trim()).filter(Boolean)];
}

/**
 * True when one rule string matches the tool call. `targets` are the absolute POSIX spellings of the file the call
 * touches (as written and resolved); `command` is the shell command.
 */
export function ruleMatches(rule, tool, { command, targets = [] } = {}, root = PROJECT_DIR) {
  const m = RULE_RE.exec(String(rule).trim());
  if (!m) return false;
  const [, ruleTool, spec] = m;
  if (spec !== undefined && spec.trim().startsWith('!')) return false; // an exception to another rule
  if (ruleTool.startsWith('mcp__')) {
    const re = new RegExp(`^${ruleTool.split('*').map((s) => s.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.*')}(?:__.*)?$`);
    return re.test(tool);
  }
  if (SHELL_RULE_TOOLS[ruleTool]) {
    if (!SHELL_RULE_TOOLS[ruleTool].has(tool)) return false;
    if (spec === undefined || spec.trim() === '' || spec.trim() === '*') return true;
    const re = commandRe(spec);
    return splitCommands(command).some((c) => re.test(c));
  }
  const applies = ruleTool === 'Edit' || ruleTool === 'Write' ? EDIT_TOOLS.has(tool) : ruleTool === 'Read' ? READ_TOOLS.has(tool) : ruleTool === tool;
  if (!applies) return false;
  if (spec === undefined || spec.trim() === '' || spec.trim() === '**') return true;
  if (!(EDIT_TOOLS.has(tool) || READ_TOOLS.has(tool))) return false; // WebFetch(domain:...) and the like: not judged here
  const re = pathRe(spec, root);
  return targets.some((t) => re.test(toPosix(t)));
}

/** The first rule of `kind` that matches, or null. */
export function matchingRule(kind, tool, call, root = PROJECT_DIR) {
  return loadRules(kind, root).find((rule) => ruleMatches(rule, tool, call, root)) ?? null;
}
