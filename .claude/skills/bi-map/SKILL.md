---
name: bi-map
description: Router and map for Microsoft BI work - Power BI projects (PBIP), Analysis Services tabular models (TMDL) and paginated reports (RDL, SSRS) - what lives where (model TMDL, report PBIR, paginated RDL, project and Git files), who may edit it, which skill, agent or tool handles each intent, and which path applies when MCP is allowed (Path A) or prohibited (Path B). Use first for any Power BI, SSAS or SSRS request, for "where is X" or "how does this work", and before choosing between MCP and file edits.
---

# Microsoft BI map

A BI solution splits into layers with different owners: the model (a Power BI semantic model or an Analysis Services
tabular model), the interactive report, the paginated report and the project files. Decide the layer first; the layer
decides the files, the skill, the agent and the kind of evidence.

The structure follows Microsoft's *Skills for Fabric* layering (agents route, skills carry procedures,
shared docs hold common knowledge, MCP servers act). Optional hooks are a safety net the model cannot skip.

| Layer in this repo | Where | Job |
|---|---|---|
| Agent | `.claude/agents/bi-expert.md` (main session), specialists beside it | route, delegate, report evidence |
| Skills | `.claude/skills/`: this router, `bi-semantic-model` (Microsoft-based), `bi-data-sources`, `bi-pbir-report`, `bi-report-design`, `bi-paginated-report`, `bi-migration`; the seven the user invokes: `/bi-onboard`, `/bi-plan`, `/bi-feature`, `/bi-review`, `/bi-handoff`, `/bi-doctor`, `/bi-commit` | procedures, loaded on demand |
| Common | `AGENTS.md`, `docs/`, `.claude/rules/bi/` | agreement, MCP and Desktop guides, static checks, test packs, decision record, file-type conventions |
| Hands (optional) | MCP: `powerbi-modeling`, `microsoft-learn`; CLIs: `powerbi-report-author`, `powerbi-desktop` | live model metadata, DAX tests, current docs, PBIR properties, rendering |
| Safety net (optional) | `hardening/` (hooks, Git hooks, CI; needs Node) | deny, ask, redact, validate |

## 1. Which layer is the request about?

| Layer | Holds | Files | Who edits |
|---|---|---|---|
| Semantic model | tables, columns, relationships, measures, RLS roles, parameters, sources | `*.SemanticModel/definition/**` (TMDL) | text edits within the rules; Desktop rewrites on save |
| Analysis Services tabular model | the same objects, deployed to SQL Server or Azure Analysis Services | a TMDL folder with `database.tmdl` (the registry names it) | text edits when this repository owns it; the user deploys and processes |
| Report | pages, visuals, filters, bookmarks, themes, which model it binds | `*.Report/definition/**` (PBIR), `definition.pbir` | text edits within the rules; Desktop rewrites on save |
| Paginated report (SSRS, Report Server, Power BI service) | datasets (queries), parameters, tablix layout, page setup | `*.rdl` (SSRS also `*.rds`, `*.rsd`) | text edits within the rules; Report Builder rewrites on save |
| Project and delivery | entry point, Git hygiene, item metadata, local caches | `*.pbip`, `.gitignore`, `.platform`, `.pbi/**`; `fabric/<workspace>/` (the directory a Fabric workspace syncs) | mostly Desktop and Fabric; the user decides; the agent edits the item files under `fabric/<workspace>/`, never the sync ([fabric-git.md](../../../docs/harness/fabric-git.md)) |
| ETL feeding a source (SSIS) | packages that load the tables a model reads | `etl/<project>/`: `*.dtsx`, `*.dtproj`, `*.params`, `*.conmgr` | text edits when the registry names this repository as owner (`.claude/rules/bi/ssis.md`); validate with `dtexec /Validate`; the user runs and deploys; owned elsewhere: read only, changes go to its owner |
| ETL in Data Factory or Fabric pipelines | pipelines that load the tables | the service | not covered by this harness: record the load in the registry |

Delivery target: the **Power BI service** takes PBIP/PBIR from the standard Power BI Desktop. Power BI reports for
**Power BI Report Server** (`.pbix` from Desktop optimized for Report Server, which has no PBIP)
are outside this harness. Paginated reports (`.rdl`) work the same on Reporting Services, Report Server and the
service.

What a number *is* is a model question; how it is *shown* is a report question; where it *lives and
ships* is a project question. A wrong number is a model question until a bounded query says otherwise.
File-by-file anatomy, formats, versions, limits and delivery: [references/anatomy.md](references/anatomy.md).

### Which layers are in scope

The request and the files decide the layers, never a fixed chain: a repository with only an Analysis Services model,
only paginated reports or only SSIS packages is complete, and no layer requires another layer's files, tools or
checks. Name the layers in one line before acting (the hardening pack's session start lists what it found). Create
only what the request names: an owned Analysis Services model gets a TMDL folder and a registry entry, no PBIP shell
(`bi-semantic-model`, Create); a package gets no model; a model gets no report.

| Scope | Files you change | Static check | Engine evidence (A) or hand-over (B) |
|---|---|---|---|
| Power BI only | `*.SemanticModel/definition/**`, `*.Report/definition/**` | validator; report CLI when installed | bounded DAX through MCP; else a pack the user runs in Desktop |
| Analysis Services only | the TMDL folder (`database.tmdl`, also when it is the repository root), `docs/sources/README.md` | validator (the same model-wide checks) | MCP against a confirmed local or test server; else a pack for SSMS or DAX Studio after the user deploys and processes |
| Paginated only | `*.rdl`, `*.rds`, `*.rsd`, `*.rptproj` | validator; `rdl-compare` for a re-platform | none here: the user's Report Builder runs, then reconciliation |
| SSIS only | `etl/<project>/**` (owned per the registry) | validator; `dtexec /Validate` only where `dtexec` exists (else NOT RUN) | none here: the user's run against a test database and the row counts |

When two layers meet in one request, check the contract between them from the files on both sides, for the layers
in scope only; `docs/test-packs.md` (Reconcile) holds the comparison rules.

| Boundary | What must agree | Where to look |
|---|---|---|
| source → SSIS destination | table and column names and types; the grain and keys the registry states | `docs/sources/sql/*.schema.sql`, the registry, the package's destination mappings |
| SSIS destination (or source) → model | the partition query or `sourceColumn` names equal the table's columns; the grain the measures assume | the package, `tables/*.tmdl` partitions and columns |
| model → report | every field a visual binds exists (the validator checks a `byPath` model; a live model needs the reference copy or the user's field list) | `*.Report/definition/**`, `definition.pbir` |
| model → paginated report | the dataset's DAX names existing objects; each report parameter maps to a query parameter; a rename reaches the RDL | `*.rdl` datasets, `QueryParameters` |
| two consumers of one source | the same filters (period, members, status, currency) on both sides before any numbers are compared | `docs/test-packs.md`, Reconcile |

## 2. Intent to owner

| The user wants | Layer and files | Use | Evidence |
|---|---|---|---|
| what is in the model, where X is defined, what depends on X or uses it | model and report | `bi-semantic-model` (Discover); search TMDL and PBIR text | file and line evidence |
| new or changed measure, DAX, format string | model `tables/*.tmdl` | `bi-semantic-model` (Modify); agent `bi-tmdl-modeler` | static check; bounded query (A) or test pack (B) |
| new calculated column or table, a column from a query the model already has | model | `bi-semantic-model` (Modify) | static check; bounded query (A) or test pack (B) |
| new source, relationship, partition source, parameter, storage mode | model (Tier 2 in AGENTS.md) | `bi-semantic-model` (Modify, Create) | static check; user approval |
| a new model from scratch: a Power BI project, or an Analysis Services model this repository will own | model; the target decides the shape (a PBIP shell, or a TMDL folder plus a registry entry and no PBIP) | `bi-semantic-model` (Create) | static check; Desktop opens the `.pbip`, or the user's test deployment |
| load or change the data an SSIS package writes (a project this repository owns) | ETL `etl/<project>/**` | `.claude/rules/bi/ssis.md`; agents `bi-ssis-editor` (several packages), `bi-source-analyst` (review) | static check; `dtexec /Validate` where `dtexec` exists, else NOT RUN; the user's run and row counts |
| model review, best practices, performance | model | `bi-semantic-model` (Analyze, Optimize); agent `bi-dax-reviewer` | findings by severity; timings from the user (B) |
| field parameter | model side; the slicer and visual are report work | `bi-semantic-model` (Field parameter), then `bi-pbir-report` | static check; Desktop check |
| page, visual, formatting, filter, bookmark, theme | report `definition/**`, theme files under `StaticResources/` | `bi-pbir-report`; agents `bi-pbir-editor`, `bi-report-reviewer` | static check; Desktop check |
| plan a page, choose visuals, layout, color, accessibility, review a report's design | report | `bi-report-design`, then `bi-pbir-report` for the files | design checklist; Desktop check |
| where data comes from: SQL, cube, files, web APIs; storage modes (live, composite, DirectQuery, Direct Lake); a partition, source or SQL change; the user supplies SQL or cube TMDL | model; cubes are shared | `bi-data-sources`; agent `bi-source-analyst` (read-only review) | source map, then static check; SQL run and refresh are the user's |
| change a tabular model this repository owns on SQL Server or Azure Analysis Services (a TMDL folder) | model; deployment and processing are the user's | `bi-semantic-model` ([ssas-tabular.md](../bi-semantic-model/ssas-tabular.md)) | static check; test pack against a test deployment |
| the model is a `Model.bim` (TMSL), in a PBIP or an Analysis Services project | not editable: TMDL only | `bi-semantic-model`, section 7 (conversion, Tier 2) | nothing changed until converted |
| build a page from a design (Figma frame or image) | report; a missing measure waits for the user (`bi-report-design`, section 1) | `docs/design-to-report.md`, then `bi-pbir-report` | page plan, then static check and Desktop check |
| start from or match a house template (a reference PBIP) | report and project | `docs/design-to-report.md` (house template), then `bi-pbir-report` | token list, static check, Desktop check |
| rebuild a report from another BI tool or an older report (definitions, SQL, screenshots, exports) | model and report | `bi-migration`, then the owning skills | evidence table, mapping, reconciliation (`docs/test-packs.md`) |
| work on a report bound to a published model (no local TMDL, the model belongs to others) | report; the model is read-only | `bi-data-sources` (cube path, field gate), `bi-pbir-report` (`PATTERNS.md`) | names shown from the reference copy or the user's field list |
| build many pages or visuals that share chrome | report | `bi-pbir-report` (`PATTERNS.md`, project generator) | idempotent run, static check |
| a printable, exportable or pixel-exact report; an RDL change; parameters or page setup of a paginated report | paginated `*.rdl` | `bi-paginated-report` (`PATTERNS.md`) | static check; the user runs it in Report Builder; reconciliation |
| move SSRS or Report Server reports to the Power BI service as paginated reports (the same RDL) | paginated | `bi-paginated-report` (`MIGRATION.md`) | inventory of what does not move; the user publishes and binds data sources |
| move an SSRS report from native SQL onto a semantic model, same rows for the same parameters | model and paginated | `bi-paginated-report` (`REPLATFORM.md`); agents `bi-rdl-analyst`, `bi-tmdl-modeler`, `bi-rdl-editor` | data layer comparison, DAX check pack, row counts against the procedure |
| rebuild an SSRS report as an interactive Power BI report | model and report | `bi-migration`, then the owning skills | evidence table, mapping, reconciliation |
| see how a page renders | report | `docs/harness/desktop.md` (open runs in approvals mode `auto`; a screenshot follows `desktop.screenshots`, default `ask`; `reload`, `ask` mode and no pack ask the user) | screenshot review or the user's check |
| rename, delete or move an object | model, report and paginated reports | find every reference first (TMDL incl. `perspectives/` and `cultures/`, PBIR, DAX dataset queries in RDL files), get approval, change all sides | no dangling reference |
| rebind a report to another model | `definition.pbir` (Tier 2) | edit only after approval | binding resolves |
| numbers look wrong, or must match another system | model first | bounded query (A) or a test pack the user runs (B), per `docs/test-packs.md`; then decide model or report | query result against an expected value |
| Desktop will not open, edits do not show, diff noise, merge conflict | project | [references/troubleshooting.md](references/troubleshooting.md) | static check output |
| what is this file, formats and versions, migration, Git and CI | project | [references/anatomy.md](references/anatomy.md), [fabric-git.md](../../../docs/harness/fabric-git.md) (Fabric Git integration), `/bi-commit` | none needed |
| security or data exposure review | project | agent `bi-security-auditor`, [references/security-review.md](references/security-review.md) | findings by severity |
| model or report documentation | model and report | agent `bi-doc-generator` | files under `docs/` |
| deploy, publish, refresh, credentials, RLS membership, connection binding | **outside the agent** | hooks deny or ask when installed; give the user the steps | user action |
| natural-language data question | not PBIP work | answer from a bounded aggregate query or ask | query result |

To find references before a rename: MCP dependencies and metadata when connected (Path A), plus a search of
the TMDL and PBIR text on both paths. A report visual, filter, bookmark or conditional format can hold a field name.

## 3. Paths: is MCP allowed?

Some organizations prohibit MCP. The harness works either way. Decide per capability, from evidence, and say
which path you are on.

| Capability | Check | Path A: available | Path B: unavailable or prohibited |
|---|---|---|---|
| Power BI modeling MCP | ToolSearch or `/mcp` lists its tools and it connects | discover, test and (readwrite only) author through MCP: `docs/harness/MCP.md` | read TMDL, edit files, user-run test queries: `bi-semantic-model` section 1 |
| Microsoft Learn | Learn MCP tools, or WebFetch to learn.microsoft.com is allowed | fetch current docs and cite links | use the bundled references and say current docs were not checked |
| Report CLI `powerbi-report-author` (Microsoft, npm) | `powerbi-report-author --version` works | its catalog, formatting and `validate` are the source of truth for PBIR properties | copy a working visual, keep `$schema`, validate against the schema in the editor, Desktop opens the project |
| Desktop CLI `powerbi-desktop` (Microsoft, npm) | `powerbi-desktop --version` works; `status` lists Desktop instances | reload and screenshot with the user's approval: `docs/harness/desktop.md` | the user opens the project and reports what they see |
| Hardening pack (Node) | `node --version` is 18.17 or later and `node hardening/scripts/validate.mjs --help` prints its usage; a `hardening/` folder without a working Node is Path B | run its validator as `docs/static-checks.md` shows, as a command of its own (pre-approved once the hooks are registered with `--enable-hooks`) | manual checklist in `docs/static-checks.md` |
| Power BI Desktop (Windows) | the user has the project open, or `powerbi-desktop status` lists an instance | the user applies the change and runs the pack; MCP tests the loaded model | not on this machine: the pack and the visual checks are the user's elsewhere; results NOT RUN here |
| Report Builder (RDL) | the user confirms it is installed (it is not on PATH) | the user runs the named parameter sets and exports | NOT RUN: the runs wait for a machine with Report Builder |
| `dtexec` (SSIS) | `where.exe dtexec` finds it (in PowerShell a bare `where` is `Where-Object` and prints nothing), or the versioned `...\<version>\DTS\Binn\DTExec.exe` exists | `dtexec /F <package>.dtsx /Validate`: package structure only (`.claude/rules/bi/ssis.md`) | NOT RUN: the user validates in Visual Studio (SSDT) or on a machine with `dtexec` |
| SSMS or DAX Studio (Analysis Services) | the user confirms, and a test deployment exists | the user runs the pack against it | NOT RUN until the model is deployed and the pack has run |

Check a tool by running it or by the user's word, never by the presence of a folder or a config file. A missing tool
leaves the file work intact: its check is reported as NOT RUN (nobody ran it) or BLOCKED (no expected value, no
reachable target) per `docs/test-packs.md`, and the result stays unproven, never "passed".

A prohibition is a decision, not an obstacle. Do not work around it: no other launch method, no scripted XMLA
or TOM, no substitute tool. Never install the CLI or start a server yourself; ask the user.

Path B is complete, not a degraded mode: every workflow has a Path B step. What changes is the evidence.
Without an engine, say "not run" and give the user a test pack to run in Power BI Desktop.

## 4. Rules

- **Must:** classify the layer first; load the owning skill or reference before editing instead of
  working from memory; understand the model before designing; keep one writer; validate; report static,
  engine and Desktop evidence separately.
- **Prefer:** star schema, existing model conventions over new ones, TMDL over TMSL, explicit measures
  with format strings, parameters for servers and paths, the smallest reversible diff.
- **Avoid:** hardcoded workspace ids, servers or credentials; reading `cache.abf`; editing Desktop-owned
  files; guessing PBIR schemas, roles or enum values (copy a working visual or check the published
  schema); concurrent writers on one model; overwriting a visual the user finished in Desktop; a Desktop action
  without the approval `docs/harness/desktop.md` requires (`open` runs in approvals mode `auto`; a screenshot follows
  `desktop.screenshots`; `reload`, `ask` mode and no pack ask the user).
- **Deny (never by the agent):** deploy or publish, refreshing shared models, handling credentials,
  managing RLS or OLS membership, force push, bypassing hooks. Give the user the steps instead.

## 5. Before saying done

`AGENTS.md` "Done means" applies. Add: name the layer you changed, list what you verified and how,
and list what only Power BI Desktop can confirm.

## Sources (reviewed 2026-09-29)

- Microsoft [Skills for Fabric](https://github.com/microsoft/skills-for-fabric) (MIT): `semantic-model-authoring`
  and `powerbi-report-cli` skills. See `THIRD_PARTY_NOTICES.md`.
- Learn: [PBIP overview](https://learn.microsoft.com/en-us/power-bi/developer/projects/projects-overview),
  [report folder](https://learn.microsoft.com/en-us/power-bi/developer/projects/projects-report),
  [semantic model folder](https://learn.microsoft.com/en-us/power-bi/developer/projects/projects-dataset),
  [TMDL](https://learn.microsoft.com/en-us/analysis-services/tmdl/tmdl-overview).
