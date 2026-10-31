// Subagent scope guard entry point (PreToolUse); the guard itself is lib/guard-agent-scope.mjs. Loaded inside
// try/catch so that a module that fails to load blocks the call (exit 2) instead of letting it through unguarded
// (Node's exit code 1 is a non-blocking error for Claude Code). Keep this file this small.
try {
  await import('./lib/guard-agent-scope.mjs');
} catch (err) {
  // The error object of a syntax error does not name its file, so scripts/check-hooks.mjs finds the file and line (node
  // --check on every hook file, then each module loaded on its own). Its time is capped well inside this hook's timeout
  // (10 s in settings.hooks.json), because a hook that times out does not block the call; without the script the load
  // error alone is printed. BI_HARNESS_CHECK_BUDGET_MS may raise the 3 s to at most 6 s (a slow machine, README Limits).
  let found = '';
  try {
    found = await (await import('../scripts/check-hooks.mjs')).describeFirstFailure({ budgetMs: 3000, maxBudgetMs: 6000 });
  } catch {
    // The pointer is optional; the call is blocked either way.
  }
  process.stderr.write(
    `[bi-harness] The subagent scope guard could not load (${found || (err && err.message ? err.message : String(err))}). Guard hooks fail closed, so this action was blocked. Find the broken file and line: node hardening/scripts/check-hooks.mjs\n`,
  );
  process.exitCode = 2;
}
