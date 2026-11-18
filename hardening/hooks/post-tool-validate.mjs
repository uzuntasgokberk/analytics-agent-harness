// PostToolUse (Edit|Write): validates the file that was just written and feeds errors back to Claude.
// Also records the file for the Stop gate and reminds once per session that Desktop must reload PBIP edits.
// A paginated report keeps data sources, datasets, parameters and layout in one file, so a change made in several
// edits is inconsistent in between: its errors go back as context, and the Stop gate enforces them.

import fs from 'node:fs';
import path from 'node:path';
import { prepareSessionRoot } from './lib/session-root.mjs';

// The session's project root before common.mjs is first evaluated (lib/session-root.mjs): in a worktree session the file is
// the worktree's, validated and recorded as such. The modules that read the root are loaded after it, dynamically.
await prepareSessionRoot();
const { HOME_DIR, PROJECT_DIR, firstTimeInSession, loadConfig, projectRel, rootStateKey, runHook, updateState } = await import('./lib/common.mjs');
const { classifyPath } = await import('./lib/policy.mjs');
const { checkItemFolderFiles, formatIssues, isTextFile, validateFileText } = await import('./lib/validators.mjs');

// Only writes are validated: the Claude Code matcher restricts this hook to Edit|Write, but a host that ignores matchers
// (VS Code Copilot) sends every tool here, and a file that was merely read must not block the session.
const WRITE_TOOLS = new Set(['Edit', 'Write', 'MultiEdit', 'NotebookEdit']);

await runHook('PostToolUse', async (input) => {
  if (!WRITE_TOOLS.has(String(input.tool_name ?? ''))) return null;
  const target = input.tool_input?.file_path ?? input.tool_input?.notebook_path;
  // The project's file; in a worktree session a file outside the worktree is the main checkout's, validated from its root
  // and recorded under its key as before (it is never left unchecked).
  let root = PROJECT_DIR;
  let rel = projectRel(target);
  if (!rel && target && PROJECT_DIR !== HOME_DIR) [root, rel] = [HOME_DIR, projectRel(path.resolve(PROJECT_DIR, String(target)), HOME_DIR)];
  if (!rel || !isTextFile(rel)) return null;
  let text;
  try {
    text = fs.readFileSync(path.join(root, rel), 'utf8');
  } catch {
    return null;
  }
  // Per checkout: `changedFiles` for the main checkout, its worktree key in a worktree session (rootStateKey).
  const key = root === PROJECT_DIR ? rootStateKey('changedFiles') : 'changedFiles';
  updateState(input.session_id, (s) => {
    s[key] = [...new Set([...(s[key] ?? []), rel])];
  });

  // A file inside a Fabric item folder that is not part of the item definition (the guard lets an existing one be
  // edited): the warning goes back as context, since a service commit would delete it.
  const issues = [...validateFileText(rel, text, { cfg: loadConfig(), root }), ...checkItemFolderFiles(root, [rel])];
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
