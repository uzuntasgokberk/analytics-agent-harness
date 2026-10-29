# Example prompts

Medium-level requests for daily work, one section per artifact. Replace the `<...>` placeholders. Each example says what
the agent should do and where it should stop, so you can tell when the harness is working. The shortest set, from
junior to expert, is in the README ("Examples to try"); the parts one by one are [below](#see-each-part-at-work).

Good prompts name the artifact, the business rule and the expected result, and say what must not happen. Write in any
language; the agent answers in yours. Whatever you ask, the agent asks you at most **one question per turn**, with its
recommended answer, and proceeds on stated defaults for every other open point (recorded in `docs/decisions.md`).

## Power BI projects (PBIP)

**A measure with a business rule**

```text
In <Model>, add a measure "Gross Margin %" to the Sales table: gross margin divided by net sales, blank when net sales
is zero, formatted as a percentage with one decimal and placed in the "Margin" display folder. Net sales already
excludes returns. Give me the DAX test pack, do not commit.
```

Expect: `bi-map` → `bi-semantic-model`; the table file read in full; `DIVIDE`, a `///` description, a `formatString`, no
`lineageTag`; the static check; Path A runs a row-capped query, Path B writes `docs/tests/gross-margin.dax` (total, one
slice, the zero case, a date boundary). No Tier 2 stop: a new measure is an everyday change.

**A report page from requirements**

```text
Plan a "Regional performance" page in <Report> for regional managers: they decide where to send sales support each
week. Show net sales vs. target, margin %, the trend of the last 12 months and the ranking of regions. Use existing
measures only; list anything missing. Plan first with /bi-plan, then wait for me.
```

Expect: `bi-report-design` (reader, question, page type, visual choice) and `bi-pbir-report`; a page plan with visual
types, positions and the measure behind each block; missing measures listed with a recommendation each (model work
outside the request, not Tier 2); no file changes until you approve.

**A safe rename across model and report**

```text
Rename the column Customer[Cust_Seg] to "Customer Segment" everywhere it is used. Show me the impact first.
```

Expect: every reference found (TMDL, the RLS role filter, visuals, filters, bookmarks, DAX in paginated reports); an
impact list including what the repository cannot see (other published reports); a Tier 2 stop before any edit; after
approval one batch that changes the declaration and all references, `sourceColumn` unchanged.

**A report on a published model you do not own**

```text
<Report> is live-connected to the published model "Finance". Add a visual calculation "% of total" to the
"Revenue by product" matrix. The model belongs to the finance team; do not change it.
```

Expect: `bi-data-sources` (cube path, field gate: names from the reference copy or your field list) and
`bi-pbir-report` (`PATTERNS.md`); a visual calculation in the visual, not a model change; a note that a live
connection to SQL Server Analysis Services needs version 2025 or later for visual calculations, and that the server can
still refuse one (build 17.0.25.223 did in testing), in which case a report measure does the job.

## Analysis Services tabular models (SSAS, Azure AS)

**A calculation group on a model this repository owns**

```text
The registry says models/Sales is our SQL Server 2022 Analysis Services model. Add a "Time Intelligence" calculation
group with Current, YTD, PY and YoY %, using the marked date table. Tell me what to process after I deploy.
```

Expect: `bi-semantic-model` with `ssas-tabular.md`; the compatibility level read from `database.tmdl` (calculation
groups need 1500; 2022 runs up to 1600); the group added in TMDL; processing named for you (`calculate` for the new
calculation group); the deployment keeping partitions and role members; a test pack for a test deployment.

**A model that is still a Model.bim**

```text
Our Analysis Services project has Model.bim. Add a measure "Open Orders" to the Orders table.
```

Expect: nothing edited. The harness works on TMDL only: the agent explains why, recommends converting `Model.bim` to a
TMDL folder (Tabular Editor or Microsoft's TMDL API), says that it changes how the team deploys (Tier 2), and offers to
run an installed converter into a new folder after your approval.

**A change to a cube owned by another team**

```text
The cube "Inventory" is owned by the supply chain team; its TMDL copy is in docs/sources/inventory/definition.
We need a measure "Stock Cover Days". What can you do?
```

Expect: `bi-data-sources`, cube path; the measure written as a change request in
`docs/sources/inventory/requests/` with a TMDL snippet, the reports affected and the risk; the reference copy edited
only if you approve (Tier 2); no deployment, no connection to the cube.

## Paginated reports (SSRS, Report Server, Power BI service)

**A parameterized list report from SQL**

```text
Create Orders.rdl: a landscape A4 list of open orders from the view rpt.OpenOrders (columns in docs/sources/sql/
open_orders.sql), with a date range (Start, End) and a multi-value Region parameter whose values come from a query.
Repeat the header on each page, totals per region, page numbers in the footer. Do not publish.
```

Expect: `bi-paginated-report` (`PATTERNS.md`) and the rule `rdl`; a dataset with `@Start`, `@End` and `IN (@Region)`;
`ValidValues` from a lookup dataset; a parameter grid cell per parameter; a tablix whose width plus margins fits A4
landscape; the static check; the Report Builder runs you should do (named parameter sets) and the reconciliation of row
counts and totals.

**A paginated report on a Power BI semantic model**

```text
Build an invoice-style RDL on the semantic model "Sales" (workspace "Finance"): one page per customer with the order
lines of a chosen month. Write the DAX dataset; I will set the data source in Report Builder.
```

Expect: a DAX dataset (`SUMMARIZECOLUMNS` with `@` parameters mapped in `QueryParameters`), no placeholder workspace or
model ids, the data source left to you in Report Builder, grouping and page breaks per customer, Build permission and
the DirectQuery timeout named where they apply.

**Moving SSRS reports to the Power BI service**

```text
Inventory the RDL files under paginated/ for a move to the Power BI service: what moves as is, what must change and
who does each step. Change nothing yet.
```

Expect: `bi-paginated-report` (`MIGRATION.md`); a table per report (shared data sources and datasets to embed, custom
assemblies, subreports, `User!UserID` and `Globals!ExecutionTime` differences); the gateway binding and credentials as
your steps; no file changes, no publishing. Rebuilding one as an interactive report would be `bi-migration` instead.

## Across artifacts

**Migration with reconciliation**

```text
Rebuild the MicroStrategy dossier "Store KPIs" (definitions and SQL in reports/store-kpis/source/) as a PBIP. Grade
the evidence, prove the grain from the SQL, map every metric and plan the reconciliation. I can provide an unmasked
export for March. Do not build yet.
```

Expect: `bi-migration`; an evidence table with labels; the five scope points settled one question per turn (the first
asked with a recommendation, the others stated as defaults until you answer); grain traps checked in the SQL; a
mapping table; a reconciliation plan with expected values from your March export.

**Review before a pull request**

```text
/bi-review changed
```

Expect: the static check, then `bi-dax-reviewer`, `bi-report-reviewer` (with the design checklist) and, when sources
or roles changed, `bi-security-auditor`, in parallel; one merged report with file:line findings; no edits.

**Before switching agents**

```text
/bi-handoff
```

Expect: `TASKS.md` and `docs/handoff.md` updated with the goal, what is done, the exact next steps, open Tier 2
questions, the validation state and what you must still check in Desktop, so another session or agent
(`docs/harness/other-agents.md`) can continue.

## See each part at work

One short request per part, to see when it comes into play. In Claude Code a skill shows as `Skill(name)`, a subagent
as `Agent(name)`, a hook message starts with `[bi-harness]`, and the hardening pack writes `.claude/logs/*.jsonl`.
Use a branch of a test project (`git switch -c try-parts`).

### Skills

| Skill | Request | You see |
|---|---|---|
| `bi-map` | Which layer, skill and agent own "add a slicer to the Overview page"? Change nothing. | `Skill(bi-map)`, the matching row of the intent table, Path A or B |
| `bi-semantic-model` | List the measures in the Sales table that have no format string or description. | Discover: `model.tmdl`, then only the Sales table file; file:line findings |
| `bi-data-sources` | Map every table of <Model> to its source type, role, grain and storage mode. | a source map; "not verified" where the files do not say |
| `bi-pbir-report` | Which visuals on <page> overlap or lie outside the page? | page and visual JSON read; positions compared with the page size |
| `bi-report-design` | Is the pie chart on <page> the right visual? Answer by the design rules. | the question the visual answers, the rule, an alternative |
| `bi-paginated-report` | What must change in <report>.rdl before it can run in the Power BI service? | `MIGRATION.md` read; shared sources, custom code, time zone, gateway |
| `bi-migration` | Grade the evidence in reports/<report>/source/ for a rebuild; change nothing. | an evidence table with labels, missing inputs, scope questions |
| `bi-commit` | `/bi-commit add margin measure` | static check, staged files listed, one Conventional Commit, no push |

### Subagents

| Subagent | Request | You see |
|---|---|---|
| `bi-tmdl-modeler` | Have bi-tmdl-modeler add the measure "Order Count" to Sales. | `Agent(bi-tmdl-modeler)`; the edit, the static check, a test pack |
| `bi-pbir-editor` | Have bi-pbir-editor set the title of the card on <page> to "Net sales". | `Agent(bi-pbir-editor)`; a copied property shape, not a guessed one |
| `bi-rdl-editor` | Have bi-rdl-editor add "Page N of M" to the footer of <report>.rdl. | `Agent(bi-rdl-editor)`; `Globals!PageNumber`, the static check |
| `bi-ssis-editor` | Have bi-ssis-editor add the column <column> to the data flows of the three packages in etl/<project>. | `Agent(bi-ssis-editor)`; column metadata from the DDL under docs/sources, the static check, `/Validate` or NOT RUN |
| `bi-rdl-analyst` | Have bi-rdl-analyst explain what each parameter of <report>.rdl really does. | parameters with default, All/NULL behaviour and where they are used |
| `bi-dax-reviewer` | Have bi-dax-reviewer review the measures I changed today. | Must fix / Should fix / Looks good with file:line |
| `bi-report-reviewer` | Have bi-report-reviewer review <page>. | structure, design checklist, accessibility, data exposure |
| `bi-security-auditor` | Run bi-security-auditor on the whole repository. | a severity table; masked values, never the secret itself |
| `bi-source-analyst` | Have bi-source-analyst check the registry against the partitions. | registry gaps, grain and key findings, "folding not verified" |
| `bi-validator` | Have bi-validator run the static check on the whole repository. | the validator's summary line quoted, errors grouped by file |
| `bi-doc-generator` | Have bi-doc-generator write the measure dictionary for Sales. | `docs/model/measures-sales.md`, missing descriptions listed, not invented |

With the hardening pack, a subagent cannot leave its scope: ask bi-doc-generator to write
`<Model>.SemanticModel/notes.md` and the write is denied with "may only write to docs/**".

### Commands

| Command | You see |
|---|---|
| `/bi-doctor` | one table: each capability, its status and path, and the fix |
| `/bi-onboard` | an inventory of the models, reports and packages, one question with defaults, and drafts of `docs/sources/README.md`, `docs/conventions.md` and `TASKS.md` |
| `/bi-plan <request>` | eight sections, the subagent per step, Tier 2 decisions; no file changes |
| `/bi-feature <task>` | branch, edit, static check, review, `TASKS.md` moves to Ready for review or Done, a local commit |
| `/bi-review changed` | reviewers in parallel, one merged `## BI review` |
| `/bi-handoff` | `TASKS.md` and `docs/handoff.md` rewritten for the next session or agent |

### Hooks (with the hardening pack)

| Event | Do or ask | You see |
|---|---|---|
| SessionStart | start a session on `main` | context with the branch, "On protected branch 'main'", Git hook status, the projects found |
| UserPromptSubmit | paste a fake token: `ghp_` followed by 36 letters | "Message blocked … NOT sent to Claude" |
| UserPromptSubmit | "publish this report to production" | a reminder that publishing is never the agent's: it hands you the steps |
| PreToolUse, data | "read <Model>.SemanticModel/.pbi/cache.abf" | denied: imported data; a line in `security-events.jsonl` |
| PreToolUse, shell | "use sed to rename Amount in Sales.tmdl" | denied with a pointer to the Edit tool |
| PreToolUse, rename | "rename the measure Total Sales to Net Sales" in TMDL | an approval prompt naming the removed declaration |
| PreToolUse, TMDL only | "add a measure to Model.bim" | denied with the conversion steps |
| PreToolUse, MCP | a DAX query without a row cap, or a Figma write | an approval prompt with the reason |
| PreToolUse, scope | the bi-doc-generator example above | denied: outside the subagent's scope |
| PostToolUse, validation | write a TMDL line indented with spaces, or a `page.json` whose `name` differs from its folder | a warning sent back with the edit |
| PostToolUse, masking | "show the partition source" when it holds a password | the value replaced by `[REDACTED:...]` |
| Stop | leave two measures with the same name, or a broken `page.json`, and say "done" | finishing is blocked: "must be unique" or "Invalid JSON" (the model-wide checks run here) |
| InstructionsLoaded, audit | open a table file (`tables/*.tmdl`) | `instructions.jsonl` lists `tmdl.md`, `dax.md`, `power-query-m.md`; every tool call in `tool-audit.jsonl` |
| Git hooks | `git commit -m "fix stuff"`; stage `cache.abf`; `git push origin main` | refused by commit-msg, pre-commit and pre-push |

### Rules

Rules load when a matching file is read: a table file (`tables/*.tmdl`) brings `tmdl`, `dax` and `power-query-m`;
`expressions.tmdl` `tmdl` and `power-query-m`; `functions.tmdl` `tmdl` and `dax`; a role file `tmdl` and `rls-security`;
any other `.tmdl` file (`model.tmdl`, `relationships.tmdl`, `database.tmdl`) `tmdl` alone; a `.rdl` file `rdl`; PBIR
JSON `pbir`; `docs/sources/` `sources`; any `.md` `markdown`; `.claude/` and `hardening/` `harness`. `/context` lists the loaded ones; with the hardening pack, `instructions.jsonl` records why.
