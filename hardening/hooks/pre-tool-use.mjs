// PreToolUse guard entry point (registered in settings.hooks.json); the guard itself is lib/guard-pre-tool-use.mjs.
// It is loaded inside try/catch on purpose: when a module fails to load (a syntax error, a missing file) Node exits
// with code 1, which Claude Code treats as a non-blocking error, so the call would run unguarded. Exit code 2 blocks
// it: guard hooks fail closed. Keep this file this small.
try {
  await import('./lib/guard-pre-tool-use.mjs');
} catch (err) {
  // The error object of a syntax error does not name its file, so scripts/check-hooks.mjs finds the file and line (node
  // --check on every hook file, then each module loaded on its own). Its time is capped well inside this hook's timeout
  // (20 s in settings.hooks.json), because a hook that times out does not block the call; without the script the load
  // error alone is printed.
  let found = '';
  try {
    found = await (await import('../scripts/check-hooks.mjs')).describeFirstFailure({ budgetMs: 5000 });
  } catch {
    // The pointer is optional; the call is blocked either way.
  }
  process.stderr.write(
    `[bi-harness] The PreToolUse guard could not load (${found || (err && err.message ? err.message : String(err))}). Guard hooks fail closed, so this action was blocked. Find the broken file and line: node hardening/scripts/check-hooks.mjs\n`,
  );
  process.exitCode = 2;
}
