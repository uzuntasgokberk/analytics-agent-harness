---
name: bi-semantic-model
description: Author, review and optimize tabular models in TMDL - the semantic model of a Power BI Project and an Analysis Services tabular model (SQL Server, Azure Analysis Services) the repository owns - measures and DAX, tables, columns, relationships, hierarchies, calculation groups, field parameters, RLS design, performance and AI readiness. Adapted from Microsoft's semantic-model-authoring skill with two explicit paths - Path A when a Power BI modeling MCP server is available, Path B (files only) when MCP is prohibited or unavailable. Use for any semantic model change, review or question.
---

# Semantic models and tabular models (TMDL)

Adapted from Microsoft's [semantic-model-authoring](https://github.com/microsoft/skills-for-fabric/tree/main/skills/semantic-model-authoring)
skill (MIT, see `references/UPSTREAM.md`). The guidelines in `references/` are Microsoft's, unmodified. This file
keeps Microsoft's workflow selector and rules and rescopes them to TMDL files with two explicit paths.

**TMDL only.** The harness edits a model only as a TMDL folder (`definition/` of a PBIP, or a folder with
`database.tmdl` and `model.tmdl`). A `Model.bim` (TMSL) is read, never edited: stop and say so. Offer the conversion
(section 7); it rewrites the whole definition and changes how the team deploys, so it is Tier 2.

**Out of scope, never done by the agent:** deploy, refresh, Fabric REST management, connection binding,
permissions, RLS or OLS membership. Upstream describes these workflows; here you give the user the steps.

## 1. Pick the path first

MCP is the most reliable route when the organization allows it. Some do not. Decide from evidence, once per
session and per capability (`bi-map`, section 3), and say which path you are on.

| | Path A: MCP available | Path B: files only |
|---|---|---|
| Use when | Power BI modeling MCP tools are visible (ToolSearch or `/mcp`) and the server connects | MCP is prohibited by policy, not registered, blocked, or the user says no MCP |
| Learn the model | MCP list/get; DAX `INFO.VIEW.*` queries when list/get is unavailable | read the TMDL files; optional user-run metadata queries |
| Test | bounded DAX queries on the confirmed model | no engine here: write a test query pack, the user runs it |
| Author | TMDL and PBIR files by default; MCP writes only when the server runs readwrite and the user asked | TMDL edits |
| Persist | Desktop save as PBIP, or export to a staging folder, then `git diff` | already in the files |

Path A details (discovery, connection identity, bounded queries, persistence): `docs/harness/MCP.md`.

A prohibition is a decision, not an obstacle. Do not start the server by other means, script XMLA or TOM to get
around it, or install a substitute. Continue on Path B and report what stayed unproven. Upstream says hand-authored
TMDL is an anti-pattern while MCP is registered; this harness authors by files unless the server is readwrite
and the user asked, because every change stays a reviewable diff.

## 2. Workflows

| The user wants | Workflow |
|---|---|
| see what the model contains | Discover |
| add or change measures, tables, columns, relationships, DAX | Modify |
| build a new model | Create |
| make or edit a field parameter | Field parameter |
| faster DAX or a slow visual | Optimize |
| audit or review a model | Analyze |
| make names consistent across a model | Standardize names |
| prepare for Copilot or Data Agents | AI readiness |

Load the references a workflow names before acting. Do not work from memory.

### Discover

- **A:** MCP list/get for tables, columns, measures, relationships, partitions, roles. If list/get needs write access
  you lack, run `INFO.VIEW.*` queries with the DAX query tool; load `references/metadata-discovery.md` first and
  never write INFO queries from memory. Start narrow: scope estimate, then only the objects the task needs.
- **B:** read `definition/model.tmdl` (the `ref table` list), then only the affected `tables/*.tmdl`,
  `relationships.tmdl`, `expressions.tmdl`, `roles/`. For a large model, ask the user to run the scope and inventory
  queries from `metadata-discovery.md` in Desktop's DAX query view and paste the metadata-only result.

### Modify

1. Discover, and note the storage mode: it decides which guideline applies. Anything but plain Import (live,
   composite, DirectQuery, Dual, Direct Lake): read `.claude/skills/bi-data-sources/storage-modes.md` first.
   A model deployed to Analysis Services (`database.tmdl`, or the registry says so): read
   [ssas-tabular.md](ssas-tabular.md) first; its compatibility level limits what you may use.
2. Load: `modeling-guidelines.md` always; `tmdl-guidelines.md` for TMDL edits; `dax-guidelines.md` for any DAX;
   `naming-conventions.md` when naming; `direct-lake-guidelines.md` for Direct Lake.
3. Plan exactly what to add, change or remove. Check naming conflicts and duplicates. **When the requested measure or
   object already exists:** say so, prove it with tests, extend its pack, and do not add a second one. The rule covers
   the same number only: what the request needs and no existing measure gives (a fiscal year-to-date growth next to a
   calendar YoY) is still built, in the same batch. Changing an existing result is a new request: show the affected
   visuals and the values before and after, then ask. A measure and its
   calculation-group twin change together or not at all. Before a rename or delete,
   find every reference in the model and the report (`bi-map`), including `perspectives/` and `cultures/` (section 8).
   Items marked Tier 2 in `AGENTS.md` need the user's approval after you have shown their impact.
4. Execute in order. New table: partitions, columns, relationships, measures. Relationships need matching key types.
   Measures need their referenced objects to exist.
5. Persist and validate (section 3).

### Create

1. Gather requirements: purpose, source connection details and schemas, key entities. If source information is
   missing, ask; never guess.
2. Storage mode: OneLake source means Direct Lake; otherwise Import; DirectQuery only when the user asks.
3. Design a star schema. When facts have dates, add a separate date dimension (an M partition rather than a DAX
   calculated table unless asked).
4. Load `modeling-guidelines.md` (and `direct-lake-guidelines.md`).
5. Build the whole model in one pass, in the shape its target needs, and create nothing the request did not name:
   - **Power BI project:** scaffold the PBIP shell first per `references/pbip.md`, in the folder `docs/conventions.md`
     names (recommended `powerbi/`): `<Name>.SemanticModel/definition.pbism` and `definition/`,
     `<Name>.Report/definition.pbir` with `byPath`, `<Name>.pbip`, plus a `.platform` in each item folder and the
     report files listed in `bi-pbir-report/STRUCTURE.md` (Minimal shapes), which `pbip.md` leaves out.
     `definition/database.tmdl` takes the header Power BI Desktop writes for the team's Desktop version
     (`compatibilityLevel`, and `compatibilityMode` when present): copy it from a model Desktop saved in this
     repository, never the level of an Analysis Services model or server (next bullet). A model in a directory a Fabric
     workspace syncs is proven by
     the user's Update from Git before anything builds on it ([fabric-git.md](../../../docs/harness/fabric-git.md));
     changing a level is Tier 2 (`AGENTS.md`): you propose, the user decides.
   - **Analysis Services model this repository will own** (the request or the registry names a SQL Server or Azure
     Analysis Services server): a TMDL folder, recommended `models/<Model>/`, with `database.tmdl`
     (`compatibilityLevel` the server supports, [ssas-tabular.md](ssas-tabular.md)), `model.tmdl` with its `ref table`
     lines, `tables/*.tmdl`, `relationships.tmdl`, and the data source the server needs: `dataSource <Name> = provider`
     in `dataSources.tmdl` (`impersonationMode`, a connection string that names only server and database) with
     `partition <Table> = query` partitions that name it in `dataSource:`, the form that loads in TOM; a structured
     (M) data source is not verified here, so copy its shape only from an existing model of the user. Add the
     registry block (`docs/sources/README.md`: owner this repository,
     server, level, what the deployment keeps). **No PBIP shell, no `.pbip`, no report:** a report that reads the model
     is a live-connection PBIP and is built only when asked.
   Then per table: partitions, columns, relationships, measures. Use parameters for servers and databases; credentials
   never go into files. The request's named source, parameters and relationships are its approved scope
   (`AGENTS.md`); record their impact.
   **A:** MCP can build in session; export produces only TMDL, so scaffold the PBIP shell (when the target is a Power BI
   project) before exporting.
   **B:** write the files directly.
6. Validate. The user opens the `.pbip` in Power BI Desktop; for an Analysis Services model, the user deploys it to a
   test server and processes it ([ssas-tabular.md](ssas-tabular.md), Hand-over), and the pack runs there.
7. A report on the new model is report work: plan the page with `bi-report-design` and write it with `bi-pbir-report`
   (house template: `docs/design-to-report.md`). A new calculated column or measure is ordinary model work, not Tier 2.

### Field parameter

Load `references/field-parameters.md`. Its Tier 1 route is Path A (an MCP operation), its Tier 2 route is Path B
(hand-authored TMDL); these tiers name tool routes, not the approval tiers of `AGENTS.md`. The
`semantic-model-rest-api.md` it mentions is not part of this harness. The matching slicer and visual are report work.
In a query, the label column of a field parameter comes with its fields column (they form a composite key):
`SUMMARIZE ( 'P', 'P'[P Order], 'P'[P], 'P'[P Fields] )`.

### Optimize

Load `references/dax-perf-decision-guide.md` first, `references/dax-perf-patterns.md` only for candidate patterns.
Their "Tier 1" (DAX patterns, same result) and "Tier 2" (query structure, result shape may change: ask first) are
the guide's own pattern tiers, not the approval tiers of `AGENTS.md`. Diagnosis needs a trace-capable client. **A:** MCP trace operations when available and authorized. **B:** the agent
cannot trace; have the user capture timings with Desktop's Performance Analyzer or DAX Studio and paste the
summaries. Mark every proposed rewrite "not measured" until timings exist.

### Analyze

Discover, load the guidelines, evaluate against them, present findings by severity (critical, recommended, optional)
each with the rule violated and a fix, and wait for approval before applying anything through Modify. A Best Practice
Analyzer report the user ran in Tabular Editor (for example with Microsoft's published rules) is evidence too: read the
exported results; run the tool only when it is installed and the user asks.

### Standardize names

Load `references/naming-conventions.md` and `docs/conventions.md` (the team's rules win). List every object whose name
differs, with the proposed name and every reference in the model and the reports. Renames are Tier 2: propose them in
batches (one table or one display folder at a time), apply a batch only after approval, and keep `sourceColumn` values
unchanged. Each batch renames the perspective and translation entries too (section 8). A display name that only one
visual needs belongs to the visual, not the model (`bi-pbir-report`).

### AI readiness

Load `references/semantic-model-ai-readiness.md`. Classify each gap as agent-editable metadata or user action in
Power BI's "Prep data for AI" experience. Do not invent business context.

## 3. Validate

**Always:** (1) the structure of the target: a PBIP per `references/pbip.md` (required files exist and `byPath`
resolves); an Analysis Services TMDL folder has `database.tmdl` and `model.tmdl`, and every `ref table` has its file;
(2) re-check each change against the modeling guidelines; (3) the static check in `docs/static-checks.md`.

**Path A adds:** for each new measure run a bounded aggregate query on the confirmed model that contains the change;
for new tables or partitions ask the user to refresh (the agent does not) and report the outcome.

**Path B adds:** write a test query pack (`docs/tests/<topic>.dax`, format in `docs/test-packs.md`), and the user runs
it in Desktop's DAX query view or DAX Studio (for an Analysis Services model: SSMS or DAX Studio against a test
deployment). Per changed measure: the expected total, one filtered slice, the blank or
zero case, one date boundary; per new table or partition, one row-count block against the source's counts. Aggregates
only, never raw rows. The user also opens the project in Desktop, or deploys and processes the Analysis Services
model, and reports load errors (TMDL errors name file and line). Until then the engine result is NOT RUN.

Report three things separately: static result; engine result or "not run (Path B)"; what only Desktop can confirm.

## 4. Rules

- **Must:** understand the source schema before designing; load the guidelines before creating or editing; keep one
  writer; follow the path you announced.
- **Prefer:** star schema; the model's existing conventions over new ones; TMDL over TMSL; explicit measures with a
  `formatString` and a `///` description; validating after every change.
- **Avoid:** hardcoded workspace ids, servers or credentials; reading `cache.abf`; guessing MCP operations or
  parameters (the live tool schema wins); concurrent writers on one model.
- **Deny:** managing RLS or OLS membership: refuse and point the user to the Power BI service.

## 5. When something fails

| Symptom | Action |
|---|---|
| MCP connection fails | switch to Path B and tell the user |
| TMDL error on open | read the named file and line, fix syntax, reload `references/tmdl-guidelines.md` |
| DAX error in a measure | check table, column and measure names and that referenced objects exist |
| refresh credential error | stop; the user fixes credentials in Desktop or the service; never retry or work around |
| prohibited tool or MCP call | do not look for a workaround; continue on Path B |

## 6. Reference index

| Topic | File | Load when |
|---|---|---|
| Modeling best practices | `references/modeling-guidelines.md` | before creating or editing any model |
| Naming | `references/naming-conventions.md` | naming or renaming objects |
| TMDL syntax and objects | `references/tmdl-guidelines.md` | before generating or editing TMDL |
| PBIP folder structure | `references/pbip.md` | working with PBIP folders |
| DAX language | `references/dax-guidelines.md` | writing or reviewing DAX |
| Field parameters | `references/field-parameters.md` | creating or editing one |
| Metadata discovery (INFO.VIEW) | `references/metadata-discovery.md` | discovering metadata with DAX |
| DAX performance | `references/dax-perf-decision-guide.md`, then `references/dax-perf-patterns.md` | optimizing |
| Direct Lake | `references/direct-lake-guidelines.md` | the model reads from OneLake |
| Analysis Services | [ssas-tabular.md](ssas-tabular.md) | the model is deployed to SQL Server or Azure Analysis Services |
| AI readiness | `references/semantic-model-ai-readiness.md` | preparing for Copilot or Data Agents |
| Translations, perspectives | `references/tmdl-guidelines.md` (Translations / Cultures, Perspectives), section 8 | the model has `cultures/` or `perspectives/` |

## 7. A model in Model.bim (TMSL)

1. Say that the harness edits TMDL only and that nothing was changed.
2. Recommend the conversion and who does it:
   - **Power BI project** (`definition.pbism` with `model.bim`): the user saves the semantic model in TMDL format in
     Power BI Desktop. The conversion is one way; copy the project first.
   - **Analysis Services model**: Tabular Editor or Microsoft's TMDL API (`TmdlSerializer`) writes a TMDL folder from
     `Model.bim`. Check the installed tool's `--help` before proposing a command; never guess flags.
3. With the user's approval and an installed converter, you may run it into a **new** folder; never delete or
   overwrite `Model.bim`. Then point the registry's `definition:` at the TMDL folder (`docs/sources/README.md`).
4. If the team deploys from a tool that reads only `Model.bim` (for example a Visual Studio Analysis Services
   project), switching to TMDL changes their deployment: name it as a Tier 2 decision.

## 8. Translations, perspectives and Q&A metadata

`definition/cultures/<locale>.tmdl` holds the translations of one culture and, in the model's own culture, the
`linguisticMetadata` JSON that Q&A and Copilot use for synonyms. `definition/perspectives/<Name>.tmdl` lists the tables,
columns, measures and hierarchies one audience sees. Both name model objects by name, so a rename that skips them
leaves entries that point at nothing.

- **Rename:** rename the object's entry in every culture and perspective file in the same batch. Keep the translated
  caption; it changes only when the meaning changed, and then the user supplies it.
- **Remove:** remove its entries too. A perspective left with no tables is removed with the user's approval
  (`modeling-guidelines.md`).
- **Add:** a new object is in no perspective unless its table entry says `includeAll`. Follow the rule
  `docs/decisions.md` or the perspective's description records; without one, leave it out and name the perspectives in
  your answer (no question). List the cultures that have no caption for it. Never invent a translation: write the
  caption the user gives; one you propose goes into `docs/decisions.md` for review by someone who speaks the
  language, not into the culture file.
- **Q&A metadata:** in the `linguisticMetadata` JSON change only the occurrences of the old object name, never the
  synonym terms. When the structure is unclear, leave it and tell the user to check the Q&A synonyms in Desktop.
- **A new culture or perspective** needs its `ref cultureInfo` or `ref perspective` line in `model.tmdl`.

The hardening validator reports a perspective or translation entry for an object the model does not define.
