---
name: bi-handoff
description: Write TASKS.md and docs/handoff.md so another session or agent can continue exactly where this one stopped
disable-model-invocation: true
---

Prepare a handoff. Do not start new work.

1. Run `git status --short`, `git branch --show-current`, `git log --oneline -5` and
   the static check (`docs/static-checks.md`); keep the outputs.
2. Update `TASKS.md`: move finished items to Done, keep In Progress accurate, add Blocked items with the reason.
   Add new decisions, assumptions, open questions and test results to `docs/decisions.md`.
3. Rewrite `docs/handoff.md` using its existing template:
   - goal of the current task and acceptance criteria
   - what is done (files and objects) and what is not
   - exact next steps as commands or file edits, in order
   - open Tier 2 questions for the user
   - validation state (summary line) and uncommitted files
   - MCP server/target, connection, resources used, persistence state and test evidence or blockers
   - things the user must still verify in Power BI Desktop
4. Keep both files free of data values and credentials, and each under 500 lines.
5. Reply with a three-line summary and the path of the handoff file.
