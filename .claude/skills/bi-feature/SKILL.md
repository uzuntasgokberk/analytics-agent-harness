---
name: bi-feature
description: Implement the next approved BI task (Power BI, SSAS tabular, SSRS) end to end (branch, edit, validate, review, commit locally)
argument-hint: "[task from TASKS.md; default = next open task]"
disable-model-invocation: true
---

Implement one task: $ARGUMENTS (in GitHub Copilot: the text typed after the command) (if empty, take the next open item in `TASKS.md`).

Use this loop; reuse authorization already given for the requested scope:

1. Read `AGENTS.md`, `TASKS.md`, `docs/handoff.md`; run `git status` and `git branch --show-current`.
2. If on `main`/`master`, create `feature/<topic>` with `git switch -c`.
3. Name the layers in scope (`bi-map`, Which layers are in scope): a layer the task does not touch gets no files, tools
   or checks. Path A: follow `docs/harness/MCP.md`, discover tools/resources and confirm the target connection. Path B
   (MCP prohibited or absent): read the files. State the acceptance criteria in 2-4 bullets, each with its expected
   value and source; if they are missing or ambiguous, stop and ask.
4. Implement directly for a small change; delegate model/report work when it benefits the task.
   Pass the confirmed target/connection and acceptance criteria. Serialize writes to the same model.
5. Run the static check (`docs/static-checks.md`) and show its summary; fix all errors.
6. Review: `bi-dax-reviewer` when DAX changed (a PBIP or an Analysis Services TMDL folder), `bi-report-reviewer` when
   pages/visuals changed, `bi-rdl-analyst` when an RDL changed, `bi-source-analyst` when a partition, SQL text, the
   registry or an SSIS package changed. Apply "Must fix" findings, then validate again.
7. Check `git diff --stat`; preserve unrelated user changes and exclude them from this commit.
8. Update `TASKS.md` (move the item to Ready for review while the user still has a Desktop or Report Builder check,
   to Done when every check passed, with a one-line result) and `docs/decisions.md` (decisions taken,
   assumptions made, test results with their evidence).
9. Commit locally with `/bi-commit` conventions (one logical change per commit). Do not push.
10. Report static checks, MCP assertions against the updated model (Path B: the test pack handed over,
    `docs/tests/<topic>.dax`, a Report Builder or SSIS pack per `docs/test-packs.md`, engine result "NOT RUN"), review
    summary and the remaining checks of the user (Desktop, Report Builder, the package run) separately. Record where
    MCP changes were persisted.

Obtain missing scope/authorization (Tier 2) before: renaming/deleting model objects or pages, relationships, RLS, data sources,
parameters, `definition.pbir`, new dependencies or custom visuals (`AGENTS.md` has the full list); deploy, publish and
push are never the agent's.
Never mark a task Done without validation output. Never weaken a check to make it pass.
If the context is getting long, finish the current step, then update `TASKS.md` and `docs/handoff.md`.
