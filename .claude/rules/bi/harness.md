---
paths:
  - ".claude/**"
  - "hardening/**"
  - ".mcp.example.json"
  - ".mcp.json"
---

# Harness maintenance rules

- Change harness files only when the user asked; edits to settings, agents, skills, commands, the hardening pack and `.mcp.example.json` need approval by design.
- Knowledge (what goes where, how to think about PBIP and Fabric) belongs in Markdown skills, agents and rules. Add JavaScript only for enforcement the model must not skip
  (hooks, Git and CI checks) and for tests of that enforcement. It lives in `hardening/`; nothing outside that folder may depend on it.
- Text under `.claude/skills/bi-semantic-model/references/` is Microsoft's: never edit it. Update it only by re-copying:
  diff it against a newer upstream commit and read the diff, copy the changed files, record the new commit in its
  `UPSTREAM.md` and in `THIRD_PARTY_NOTICES.md`, and rewrite `SHA256SUMS` with every file of the folder except
  `UPSTREAM.md` (`hardening/tests/round2-scripts.test.mjs` checks every file against it).
- Editing a live guard (`hardening/hooks/**`) changes the hook that judges your next edit: add the new code first, then
  switch the callers, and remove the old code last. A half-applied edit can crash the guard, which fails closed and
  blocks every write until the user repairs it (`hardening/README.md`, Limits). `node hardening/scripts/check-hooks.mjs`
  names the broken file and line.
- Hooks read their payload from stdin JSON (`tool_input`, `tool_response`), never from env vars such as `$TOOL_INPUT`, which are empty. Guard hooks (PreToolUse) fail closed; logging hooks never throw.
- Every behaviour change in `hardening/` needs a test in `hardening/tests/`; run `npm --prefix hardening test` and show the result.
  The installer leaves the upstream tests out of an installed copy: add the test of a local change there anyway
  (`tests/run-all.mjs` runs every `*.test.mjs` with Node's built-in runner).
- Hooks are Node.js with zero dependencies, registered as the plain shell string `node hardening/hooks/<script>.mjs`
  (no `args`, no quotes, no `${CLAUDE_PROJECT_DIR}`): Claude Code runs it in Git Bash or PowerShell from the project
  root, and GitHub Copilot CLI runs the same registration in PowerShell or bash from the repository root without
  substituting placeholders (probed 2026-10-08). Never put a shell variable or inline code into a hook command.
- Never put a real credential in tests; build fake values at run time from parts, as `SECRET` in
  `hardening/tests/user-prompt-guard.test.mjs` does.
