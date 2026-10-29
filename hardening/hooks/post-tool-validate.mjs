// PostToolUse (Edit|Write): validates the file that was just written and feeds errors back to Claude.
// Also records the file for the Stop gate and reminds once per session that Desktop must reload PBIP edits.
// A paginated report keeps data sources, datasets, parameters and layout in one file, so a change made in several
// edits is inconsistent in between: its errors go back as context, and the Stop gate enforces them.

import fs from 'node:fs';
import path from 'node:path';
import { PROJECT_DIR, firstTimeInSession, loadConfig, projectRel, runHook, updateState } from './lib/common.mjs';
import { classifyPath } from './lib/policy.mjs';
import { checkItemFolderFiles, formatIssues, isTextFile, validateFileText } from './lib/validators.mjs';

// Only writes are validated: the Claude Code matcher restricts this hook to Edit|Write, but a host that ignores matchers
// (VS Code Copilot) sends every tool here, and a file that was merely read must not block the session.
const WRITE_TOOLS = new Set(['Edit', 'Write', 'MultiEdit', 'NotebookEdit']);

await runHook('PostToolUse', async (input) => {
  if (!WRITE_TOOLS.has(String(input.tool_name ?? ''))) return null;
  const rel = projectRel(input.tool_input?.file_path ?? input.tool_input?.notebook_path);
  if (!rel || !isTextFile(rel)) return null;
  let text;
  try {
    text = fs.readFileSync(path.join(PROJECT_DIR, rel), 'utf8');
  } catch {
    return null;
  }
  updateState(input.session_id, (s) => {
    s.changedFiles = [...new Set([...(s.changedFiles ?? []), rel])];
  });

  // A file inside a Fabric item folder that is not part of the item definition (the guard lets an existing one be
  // edited): the warning goes back as context, since a service commit would delete it.
  const issues = [...validateFileText(rel, text, { cfg: loadConfig(), root: PROJECT_DIR }), ...checkItemFolderFiles(PROJECT_DIR, [rel])];
  const errors = issues.filter((i) => i.level === 'error');
  const warnings = issues.filter((i) => i.level === 'warn');
  const cls = classifyPath(rel);
  const deferErrors = cls.kind === 'rdl' && errors.length > 0;
  const context = [];
  if (deferErrors) {
    context.push(`${rel} is not consistent yet. Finish the change, then make sure these are fixed before you stop (the Stop gate checks again):\n${formatIssues(errors, 15)}`);
  }
  if (warnings.length) context.push(`Validation warnings:\n${formatIssues(warnings, 10)}`);
  if (cls.inPbip && firstTimeInSession(input.session_id, 'desktop-reload')) {
    context.push('Reminder: Power BI Desktop only picks up external PBIP edits when the user applies the change prompt or restarts Desktop. You cannot verify visuals here; tell the user exactly what to check.');
  }

  const out = {};
  if (errors.length && !deferErrors) {
    out.decision = 'block';
    out.reason = `[bi-harness] ${rel} failed validation. Fix it before continuing:\n${formatIssues(errors, 15)}`;
  }
  if (context.length) out.hookSpecificOutput = { hookEventName: 'PostToolUse', additionalContext: `[bi-harness] ${context.join('\n\n')}` };
  return Object.keys(out).length ? out : null;
});
