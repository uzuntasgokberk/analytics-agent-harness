// SessionStart: injects a short, factual snapshot (git state, PBIP inventory, harness health)
// so Claude starts every session - and every post-compaction continuation - with the right context.

import fs from 'node:fs';
import path from 'node:path';
import {
  PROJECT_DIR, appendJsonl, autoApprovalState, currentBranch, git, isGitRepo, labModeActive, loadConfig, matchesAny, pruneState, runHook,
  readState, screenshotsOf, updateState,
} from './lib/common.mjs';
import { pendingMcpWrites, persistenceMessage } from './lib/mcp-state.mjs';
import { describeModel, describeReport, describeTabular, fabricSyncOf, findPbipItems, syncedDirLabel, syncedDirOf } from './lib/validators.mjs';
import { copilotHostOf, isVsCodeHost } from './lib/host-vscode.mjs';
import { sqlReadOf } from './lib/sql-read.mjs';

/**
 * Why hardening/harness.config.json cannot be used, or null when it can or does not exist. loadConfig reads such a file
 * as approvals "ask" with every other setting at its default and says nothing, so the banner must not report the
 * fallback as the user's choice (F1-132). Read as loadConfig reads it: a byte order mark is skipped.
 */
function configProblem() {
  try {
    JSON.parse(fs.readFileSync(path.join(PROJECT_DIR, 'hardening', 'harness.config.json'), 'utf8').replace(/^﻿/, ''));
    return null;
  } catch (err) {
    if (err?.code === 'ENOENT') return null;
    return err instanceof SyntaxError ? 'is not valid JSON' : `cannot be read (${err?.code ?? 'error'})`;
  }
}

/**
 * The banner as one text of at most BANNER_BUDGET characters. Claude Code saves an additionalContext over 10,000
 * characters to a file and gives the model its path and a preview of the first 2,000 (hooks reference), so a long
 * inventory used to push the MCP and handoff lines out of what the model reads. The lines the agent must act on (`head`)
 * come first and are always kept; the inventory, capped list by list, is cut from the end only when a repository still
 * outgrows the budget, and one line says how many lines were left out. The margin below 10,000 is deliberate: the
 * reference does not say how the host counts.
 */
const BANNER_BUDGET = 9000;
function fitBanner(head, inventory) {
  const all = [...head, ...inventory];
  if (all.join('\n').length <= BANNER_BUDGET) return all.join('\n');
  const omitted = (n) => `- ${n} more inventory line(s) left out to keep this context under Claude Code's 10,000-character limit: find a project with Glob and name the one you work on.`;
  const kept = [...head];
  // Room for the omitted line is reserved first, at its longest (every inventory line left out).
  let size = head.join('\n').length + 1 + omitted(inventory.length).length;
  for (const line of inventory) {
    if (size + 1 + line.length > BANNER_BUDGET) break;
    kept.push(line);
    size += 1 + line.length;
  }
  kept.push(omitted(inventory.length - (kept.length - head.length)));
  return kept.join('\n');
}

await runHook('SessionStart', async (input) => {
  const cfg = loadConfig();
  const source = input.source ?? 'startup';
  const lines = [`[bi-harness] Session context (${source})`];

  const approvals = autoApprovalState(cfg);
  const broken = configProblem();
  if (broken) {
    lines.push(`- Approvals: ask, because hardening/harness.config.json ${broken}: every setting falls back to its default and the hooks ask as in "ask" mode until the user repairs the file (\`node hardening/scripts/validate.mjs\` names the error). Do not rewrite the file to change the approvals; tell the user.`);
  } else if (labModeActive(cfg)) {
    lines.push(`- Approvals: LAB mode${cfg.approvals.until ? ` until ${cfg.approvals.until}` : ''} (set by the user for tests). No guard prompts for anything it can judge, scripts included; Claude Code's own ask rules still prompt (Desktop open, reload and screenshots among them: reload asks in every mode; screenshots per desktop.screenshots, below); the floor still asks (push, publish/deploy, service workspaces, remote servers, database clients, GitHub/Figma writes, unanalysable commands, SQL queries the SQL read switch does not pass) and every deny stays. The agent never turns lab mode on and may switch to "auto" or "ask".`);
  } else if (approvals.active) {
    lines.push(`- Approvals: auto${cfg.approvals.until ? ` until ${cfg.approvals.until}` : ''}. Routine work runs without a prompt; critical actions (publish, deploy, push, servers, personal data, installs, RLS, data sources, harness files) ask; denied ones stay blocked. Do not ask the user for routine steps; ask for decisions you cannot infer.`);
  } else if (approvals.reason) {
    lines.push(`- Approvals: ${approvals.reason}, so the hooks ask as in "ask" mode.`);
  } else {
    lines.push('- Approvals: ask mode (set by the user). Claude Code prompts as usual; never switch it to auto.');
  }

  // The SQL read switch (sources.sqlRead): what happens when the agent runs a query.
  const sql = sqlReadOf(cfg);
  if (sql.on) {
    lines.push(`- SQL read switch: ON for ${sql.servers.join(', ') || 'no server'}${sql.mcpServers.length ? ` and the MCP server(s) ${sql.mcpServers.join(', ')}` : ''} (set by the user). A read-only query, bounded to one aggregate row or TOP/LIMIT ${sql.maxRows}, without personal columns, against a listed server, run as a command of its own, passes in auto and lab mode; anything else asks; DML and DDL are denied. The login the agent uses must be read-only (no write, DDL or EXECUTE grants): the guard reads text, the server enforces. Record each result with [sql] in docs/decisions.md. The agent may only make the switch stricter.`);
  } else {
    lines.push(`- SQL read switch: off${sql.rawMode !== undefined && sql.rawMode !== 'off' ? ` (sources.sqlRead.mode ${JSON.stringify(sql.rawMode)} is not "on")` : ''}. Every query of a SQL client or SQL MCP server asks the user, in every approvals mode; DML and DDL are denied. Run SQL only when the user asked for it; record each result with [sql].`);
  }
  // The Desktop screenshot switch (desktop.screenshots): a capture shows the data on the page.
  const shots = screenshotsOf(cfg);
  const shotsMode = shots.known ? shots.mode : `ask (the value ${JSON.stringify(shots.raw)} was not recognised, so ask applies)`;
  lines.push(`- Desktop screenshots: ${shotsMode} (desktop.screenshots in hardening/harness.config.json): off = denied, ask = asks in every mode, on = the guard approves it in auto and lab; Claude Code's ask rule still prompts. Screenshots are data: they stay outside the repository (docs/harness/desktop.md).`);

  const [nodeMajor, nodeMinor] = process.versions.node.split('.').map(Number);
  if (nodeMajor < 18 || (nodeMajor === 18 && nodeMinor < 17)) lines.push(`- WARNING: Node ${process.versions.node} is too old for the harness hooks (need >= 18.17).`);
  // The installer's manifest: the harness version and where the hooks were registered (a clone of the harness has none).
  try {
    const m = JSON.parse(fs.readFileSync(path.join(PROJECT_DIR, '.claude', 'bi-agent-harness.json'), 'utf8'));
    if (m?.version) lines.push(`- Harness v${m.version}${m.hooks ? `; hooks registered ${m.hooks === 'shared' ? 'for the team (.claude/settings.json)' : 'for this machine only (.claude/settings.local.json)'}` : ''}`);
  } catch {
    // no manifest
  }
  // Copilot through its own hook files (host variable) or through the Claude registration of .claude/settings*.json
  // (no host variable, but a `timestamp` Claude Code never sends).
  // VS Code also runs the CLI's hook file with its own snake_case payload: that is VS Code, not the CLI (copilotHostOf).
  const hostKind = copilotHostOf(input);
  if (hostKind) {
    const host = hostKind === 'vscode'
      ? (isVsCodeHost() ? 'VS Code Copilot' : 'VS Code Copilot (through the Copilot CLI hook file)')
      : hostKind === 'copilot-claude' ? 'GitHub Copilot through the Claude registration (.claude/settings*.json)' : 'GitHub Copilot CLI';
    // VS Code's hooks reference (page dated 10/14/2026, read 2026-10-19) documents no PostToolUse field that replaces tool
    // output, so the masking hook can only warn there (post-tool-redact.mjs, maskNotice); the CLI documents modifiedResult.
    const runs = hostKind === 'vscode'
      ? 'The guard, validation and audit log run; subagent scopes do not (no agent_type here). Output masking is a warning, not a guarantee: VS Code documents no way for a hook to replace tool output, so a value the harness reports as sensitive may still be visible to you; never repeat, store, copy or use it, and tell the user.'
      : 'The guard, validation, masking and audit log run; subagent scopes do not (no agent_type here).';
    lines.push(`- Host: ${host} hooks. ${runs} The Skill, Agent and ToolSearch tools of Claude Code do not exist: read \`.claude/skills/<name>/SKILL.md\` and \`.claude/agents/<name>.md\` by path. After the session, check \`.claude/logs/tool-audit.jsonl\` for "unmapped": a tool the hooks could not judge.`);
  }

  if (isGitRepo()) {
    const branch = currentBranch();
    const dirty = (git(['status', '--porcelain']) ?? '').split('\n').filter(Boolean).length;
    lines.push(`- Git: branch ${branch}, ${dirty ? `${dirty} uncommitted change(s)` : 'clean'}`);
    if (cfg.git.protectedBranches.includes(branch)) {
      lines.push(`- On protected branch '${branch}': create a feature branch before editing (git switch -c feature/<topic>).`);
    }
    const hooksPath = git(['config', '--get', 'core.hooksPath'])?.trim();
    if (hooksPath !== 'hardening/githooks') lines.push('- Git hooks NOT installed: ask the user to run `git config core.hooksPath hardening/githooks`.');
    else if (process.platform !== 'win32') {
      // Git skips a hook that is not executable; a zip or a plain copy can drop the bit. Windows ignores it.
      const skipped = ['pre-commit', 'commit-msg', 'pre-push'].filter((name) => {
        try {
          fs.accessSync(path.join(PROJECT_DIR, 'hardening', 'githooks', name), fs.constants.X_OK);
          return false;
        } catch {
          return true;
        }
      });
      if (skipped.length) {
        lines.push(`- Git hooks installed but missing or not executable (${skipped.join(', ')}), so Git skips them: ask the user to run \`chmod +x hardening/githooks/*\`.`);
      }
    }
  } else {
    lines.push('- Not a git repository: nothing is versioned, so no rollback. Suggest `git init` before editing PBIP files.');
  }

  lines.push(`- Requested local MCP mode: ${process.env.PBI_MCP_MODE || 'readonly'}; connection and server capabilities are NOT verified by this hook.`);
  lines.push('- Before model work: read docs/harness/MCP.md; discover live tools/resources, confirm the exact target and pass the same connection to reviewers.');
  // A resumed or compacted session whose MCP writes were never persisted (lib/mcp-state.mjs; the Stop gate holds them).
  const pending = pendingMcpWrites(readState(input.session_id));
  if (pending.count) lines.push(`- Earlier in this session: ${persistenceMessage(pending)}`);
  if (['compact', 'resume', 'clear', 'fork'].includes(source)) {
    const handoff = ['docs/handoff.md', 'TASKS.md'].filter((f) => fs.existsSync(path.join(PROJECT_DIR, f)));
    if (handoff.length) lines.push(`- Continuing work: re-read ${handoff.join(' and ')} before acting.`);
  }

  // The BI layers present. Any subset is a complete repository: an Analysis Services model, paginated reports or SSIS
  // packages alone never call for a Power BI project, and a missing layer's files, tools and checks are not required.
  // They go to `inventory`, after every line above: its size grows with the repository (fitBanner).
  const inventory = [];
  const items = findPbipItems(PROJECT_DIR, cfg);
  const found = items.models.length + items.reports.length + items.tabular.length + items.rdl.length + items.ssis.length;
  if (!found) {
    inventory.push('- No BI artifacts found (no *.SemanticModel or *.Report folder, no TMDL model folder with database.tmdl, no *.rdl, no SSIS project): create one with its owning skill (bi-semantic-model Create for a model, bi-paginated-report for an RDL, .claude/rules/bi/ssis.md for a package), or install the harness into the root of an existing repository (README.md). No layer requires another layer\'s files.');
  } else if (!items.models.length && !items.reports.length) {
    inventory.push('- No Power BI project (*.SemanticModel / *.Report) here: the artifacts below are the scope; none of them needs one.');
  }
  // Every list is capped, whatever the repository holds. Up to LIST_LIMIT items of a kind, one line each. Above it, one
  // summary line per kind, counted per folder, plus the items that need attention by name: in a repository with
  // hundreds of projects the per-item list cost every session tens of thousands of characters while the agent works on
  // one project at a time.
  const LIST_LIMIT = 20;
  // The first `max` entries of a list and how many more.
  const some = (list, max = 3) => `${list.slice(0, max).join(', ')}${list.length > max ? ` and ${list.length - max} more` : ''}`;
  // Up to three flagged items one line each, more on one line: one line per item is one line per project at worst.
  const flagged = (list, one, many) => (list.length > 3 ? [many(list)] : list.map(one));
  // Counted per folder two segments deep (powerbi/<area>). One folder per project (<Name>/ or projects/<Name>/) makes
  // that one entry per project, so above LIST_LIMIT entries one segment deep, and the largest FOLDER_LIMIT either way
  // (ties by name: directory order differs between file systems).
  const FOLDER_LIMIT = 10;
  const perFolder = (rels) => {
    let counts;
    for (const depth of [2, 1]) {
      counts = new Map();
      for (const rel of rels) {
        const folder = rel.split('/').slice(0, -1).slice(0, depth).join('/') || '.';
        counts.set(folder, (counts.get(folder) ?? 0) + 1);
      }
      if (counts.size <= LIST_LIMIT) break;
    }
    return some([...counts].sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0)).map(([folder, n]) => `${folder} (${n})`), FOLDER_LIMIT);
  };
  const countBy = (list, key) => {
    const counts = new Map();
    for (const x of list) counts.set(key(x), (counts.get(key(x)) ?? 0) + 1);
    return [...counts].map(([k, n]) => `${n} ${k}`).join(', ');
  };
  const models = items.models.map((rel) => describeModel(PROJECT_DIR, rel));
  if (models.length > LIST_LIMIT) {
    inventory.push(`- Power BI models: ${models.length} (${countBy(models, (m) => m.format)}) in ${perFolder(items.models)}. More than ${LIST_LIMIT}, so not listed one by one: find a project with Glob **/<Name>.SemanticModel and name the one you work on.`);
    inventory.push(...flagged(models.filter((x) => x.format.startsWith('TMSL')),
      (m) => `- Model ${m.path}: TMSL (model.bim) is not supported: this harness edits TMDL only. Ask the user to save the model as TMDL in Power BI Desktop.`,
      (list) => `- ${list.length} models are TMSL (model.bim): ${some(list.map((m) => m.path))}. TMSL is not supported: this harness edits TMDL only. Ask the user to save such a model as TMDL in Power BI Desktop.`));
    const cached = models.filter((m) => m.hasDataCache);
    if (cached.length) inventory.push(`- ${cached.length} model(s) hold .pbi/cache.abf with imported DATA: never read one (blocked).`);
    inventory.push(...flagged(models.filter((x) => x.hasUnappliedChanges),
      (m) => `- ${m.path}/.pbi/unappliedChanges.json exists: external Power Query edits are lost when those pending changes are applied in Desktop.`,
      (list) => `- ${list.length} models hold .pbi/unappliedChanges.json: ${some(list.map((m) => m.path))}. External Power Query edits to such a model are lost when its pending changes are applied in Desktop: check the project's .pbi folder first.`));
  } else {
    for (const m of models) {
      inventory.push(`- Model ${m.path}: ${m.format}, ${m.tables} table file(s)`);
      if (m.format.startsWith('TMSL')) inventory.push('  - TMSL (model.bim) is not supported: this harness edits TMDL only. Ask the user to save the model as TMDL in Power BI Desktop.');
      if (m.hasDataCache) inventory.push(`  - ${m.path}/.pbi/cache.abf holds imported DATA: never read it (blocked).`);
      if (m.hasUnappliedChanges) inventory.push(`  - ${m.path}/.pbi/unappliedChanges.json exists: external Power Query edits are lost when those pending changes are applied in Desktop.`);
    }
  }
  // A TMDL export of a model owned elsewhere (sources.referenceCopies) is read-only; an owned model is edited here.
  const isCopy = (rel) => matchesAny(`${rel}/database.tmdl`, cfg.sources?.referenceCopies ?? []);
  const tabularLine = (rel) => {
    const t = describeTabular(PROJECT_DIR, rel);
    const where = rel === '.' ? 'the repository root' : t.path;
    return isCopy(rel)
      ? `- Reference copy ${t.path}: TMDL of a model owned elsewhere, compatibility level ${t.level ?? 'not stated'}, ${t.tables} table file(s); read-only, changes go to its owner as requests (bi-data-sources).`
      : `- Tabular model at ${where}: TMDL folder (database.tmdl), compatibility level ${t.level ?? 'not stated'}, ${t.tables} table file(s); ownership per docs/sources/README.md; the user deploys and processes it (bi-semantic-model/ssas-tabular.md).`;
  };
  if (items.tabular.length > LIST_LIMIT) {
    inventory.push(`- Tabular models: ${items.tabular.length} TMDL folders (database.tmdl) in ${perFolder(items.tabular.map((t) => `${t}/database.tmdl`))}. More than ${LIST_LIMIT}, so not listed one by one; ownership per docs/sources/README.md; the user deploys and processes them (bi-semantic-model/ssas-tabular.md).`);
    inventory.push(...flagged(items.tabular.filter(isCopy), tabularLine,
      (list) => `- Reference copies: ${list.length} TMDL folders of models owned elsewhere (${some(list)}); read-only, changes go to their owners as requests (bi-data-sources).`));
  } else {
    inventory.push(...items.tabular.map(tabularLine));
  }
  const reports = items.reports.map((rel) => describeReport(PROJECT_DIR, rel));
  if (reports.length > LIST_LIMIT) {
    inventory.push(`- Power BI reports: ${reports.length} (${countBy(reports, (r) => r.format)}) in ${perFolder(items.reports)}. More than ${LIST_LIMIT}, so not listed one by one: find a project with Glob **/<Name>.Report; its definition.pbir names the model. PBIR-Legacy (report.json) is not editable externally; ask the user to upgrade such a report to PBIR in Desktop before editing it.`);
  } else {
    for (const r of reports) {
      inventory.push(`- Report ${r.path}: ${r.format}, ${r.pages} page(s), dataset ${r.binding}`);
      if (r.format === 'PBIR-Legacy') inventory.push('  - PBIR-Legacy report.json is not editable externally; ask the user to upgrade to PBIR in Desktop.');
    }
  }
  if (items.rdl.length) inventory.push(`- Paginated reports: ${items.rdl.length} *.rdl (${some(items.rdl)}); the engine check is the user's Report Builder run (bi-paginated-report).`);
  if (items.ssis.length) inventory.push(`- SSIS: ${items.ssis.length} folder(s) with packages or projects (${some(items.ssis)}); ownership per docs/sources/README.md; dtexec /Validate only where dtexec exists on this machine, else NOT RUN (.claude/rules/bi/ssis.md).`);
  // Fabric Git: one line per directory a workspace syncs. The user records them in fabric.directories (workspace and
  // branch go to docs/conventions.md); without that list, each directory whose item folders hold a .platform file, a
  // reminder only (Desktop writes .platform too). Each line says which source it used. Above three directories, one line
  // for all: without fabric.directories, .platform in every project folder makes each project a directory of its own.
  const sync = items.fabricSync ?? fabricSyncOf(cfg);
  const userSteps = "Commit and Update in the workspace are the user's (docs/harness/fabric-git.md)";
  const fabricLines = (dirs, why) => flagged(dirs,
    (d) => `- Fabric Git-connected directory: ${d.label} (${d.count}; ${why}); ${userSteps}`,
    (list) => `- Fabric Git-connected directories: ${list.length} (${some(list.map((d) => `${d.label}: ${d.count}`))}; ${why}); ${userSteps}`);
  // A setting the user must repair is no inventory: it goes with the lines the ceiling never cuts.
  if (sync.invalid) lines.push('- Fabric Git: fabric.directories in hardening/harness.config.json is not a list of project-relative directories, so .platform marks the synced item folders (docs/harness/fabric-git.md).');
  if (sync.source === 'config') {
    if (!sync.dirs.length) inventory.push('- Fabric Git: no directory is synced (fabric.directories is empty in hardening/harness.config.json); .platform files are not read as a connection.');
    inventory.push(...fabricLines([...sync.dirs].sort().map((dir) => {
      const n = items.fabric.filter((rel) => syncedDirOf(rel, sync.dirs) === dir).length;
      const found = dir === '.' || fs.existsSync(path.join(PROJECT_DIR, dir));
      return { label: syncedDirLabel(dir), count: found ? `${n} item(s)` : 'not found in the repository' };
    }), 'recorded in fabric.directories'));
  } else {
    const fabricDirs = new Map();
    for (const rel of items.fabric) {
      const dir = path.posix.dirname(rel);
      fabricDirs.set(dir, (fabricDirs.get(dir) ?? 0) + 1);
    }
    inventory.push(...fabricLines([...fabricDirs].map(([dir, n]) => ({ label: syncedDirLabel(dir), count: `${n} item(s)` })),
      `from .platform, ${sync.invalid ? 'fabric.directories is invalid' : 'none recorded in fabric.directories'}: a reminder, not proof`));
  }

  // This session's state file exists from here on (the guard's MCP target rule applies with or without it: no file is
  // no confirmed connection, lib/mcp-state.mjs); writing it also keeps a resumed session's state out of the pruning below.
  updateState(input.session_id, (s) => {
    s.startedAt ??= new Date().toISOString();
  });
  pruneState();
  appendJsonl('sessions.jsonl', { event: 'SessionStart', source, session: String(input.session_id ?? '').slice(0, 8) });
  return { hookSpecificOutput: { hookEventName: 'SessionStart', additionalContext: fitBanner(lines, inventory) } };
});
