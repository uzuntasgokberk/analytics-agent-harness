---
name: bi-plan
description: Analyze a BI change request (Power BI, SSAS tabular, SSRS) and produce a plan with Tier 2 decisions (read-only; best in Plan Mode)
argument-hint: "<change request, e.g. add YoY KPIs to the Sales overview page>"
disable-model-invocation: true
---

Analyze this change request for this BI project. Do not modify files. Use Claude Plan Mode for
an enforced read-only session; this command text by itself is only a workflow instruction.

Request: $ARGUMENTS (in GitHub Copilot: the text typed after the command)

Read `AGENTS.md`, `TASKS.md`, `docs/handoff.md` (if present) and the affected TMDL/PBIR files. Then answer
with these sections, in this order. For model work on Path A, first follow `docs/harness/MCP.md` to discover
relevant metadata and resources; on Path B the files and `docs/sources/` are the metadata. Report unavailable
capabilities without inventing results:

1. **Requirement**: one paragraph in business language; list assumptions separately.
2. **Acceptance criteria**: checkable bullets (numbers that must match, pages and visuals that must show them).
3. **Model impact**: tables, measures, columns, relationships, parameters to add or change (file paths).
4. **Report impact**: pages and visuals to add or change (PBIR folder names if they exist).
   Sections 3 and 4 cover the layers in scope only (`bi-map`, Which layers are in scope): a paginated report
   (`*.rdl`: datasets, parameters, layout) or an SSIS package (`*.dtsx`: destination, mappings, connections) in scope
   gets its own impact lines, with the contract to its neighbour layer; a layer the request does not touch gets none.
5. **Risks**: broken references, performance, RLS, data exposure, `.pbi/unappliedChanges.json`.
6. **Tier 2 decisions for the user**: renames/deletes, relationships, RLS, data sources, bindings,
   new custom visuals (`AGENTS.md` has the full list); deploy and publish steps are handed over, never planned for
   the agent. Recommend an option for each.
7. **Plan**: small ordered steps, each ending in the static check; mark which subagent does
   which step (`bi-tmdl-modeler`, `bi-pbir-editor`, `bi-rdl-editor`, `bi-ssis-editor`, reviewers).
8. **Verification in Power BI Desktop, Report Builder or the package run**: what the user must check by hand, and
   which checks stay NOT RUN on this machine (no Desktop, Report Builder, `dtexec` or engine here).

If something critical is unknown, say "unknown" and ask; don't invent table or column names.
