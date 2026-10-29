---
name: bi-onboard
description: Describe an existing BI repository to the harness after installing it - finds every Power BI project, Analysis Services model, cube, paginated report and SSIS project by its files, drafts the source registry, the conventions and the first tasks, and asks only what the files cannot show (ownership, delivery, MCP, Fabric sync)
allowed-tools: Read Grep Glob Edit(/docs/sources/README.md) Edit(/docs/conventions.md) Edit(/TASKS.md) Write(/docs/sources/README.md) Write(/docs/conventions.md) Write(/TASKS.md) Bash(git status *) Bash(git rev-parse *) Bash(git branch --show-current) Bash(node hardening/scripts/validate.mjs *)
disable-model-invocation: true
---

Run once after installing the harness into a repository that already holds BI work, and again after adding projects.
It reads the project files and changes none of them. It writes only drafts the user reviews: `docs/sources/README.md`,
`docs/conventions.md` and `TASKS.md`. No folder layout is required; artifacts are found by their files.

1. **Branch.** `git branch --show-current`. On a protected branch (`main`, `master`), stop and suggest
   `git switch -c chore/bi-onboard`.
2. **Find the artifacts** with Glob, skipping `.git/`, `node_modules/`, `bin/`, `obj/`, `.pbi/`:

   | Artifact | Signature | What to note |
   |---|---|---|
   | Power BI project | `**/*.pbip`, `**/*.SemanticModel/definition.pbism`, `**/*.Report/definition.pbir` | TMDL `definition/` or `model.bim` (TMSL: TMDL only, conversion is Tier 2); a live connection (`modelReference.json`, or `byConnection` in `definition.pbir`); PBIR (`definition/pages/`) or PBIR-Legacy (`report.json` at the report root: read only) |
   | Fabric Git-connected directory (candidate) | `**/.platform` (one per item folder) | a hint, not proof: Desktop writes `.platform` on a project save too. The folder that holds the item folders is the candidate directory: its path, the item types (`<Name>.SemanticModel`, `<Name>.Report`, `<Name>.PaginatedReport`); whether a workspace syncs it, and which workspace and branch, come from the user ([fabric-git.md](../../../docs/harness/fabric-git.md)) |
   | Analysis Services tabular | `**/database.tmdl` outside `*.SemanticModel`; `**/*.bim` next to `*.smproj` | `compatibilityLevel`; TMSL means conversion first |
   | Multidimensional cube | `**/*.cube`, `**/*.dim`, `**/*.dwproj` | read-only source |
   | Paginated report | `**/*.rdl`, `**/*.rds`, `**/*.rsd`, `**/*.rptproj` | embedded or shared data source |
   | SSIS | `**/*.dtsx`, `**/*.dtproj`, `**/*.params`, `**/*.conmgr` | `ProtectionLevel`, `TargetServerVersion`; packages that exist only in SSISDB or as an `.ispac` come into Git through Visual Studio's Integration Services Import Project Wizard, run by the user; register the project afterwards |
   | SQL text | `**/*.sql` | queries, views, procedures, schema DDL |
   | Binary report | `**/*.pbix` | not editable: the user saves it as PBIP in Desktop |

3. **Read only what describes each artifact.** Server and database names, never credentials:
   - models: `expressions.tmdl` parameters and partition sources (`Sql.Database`, `AnalysisServices.Database`,
     files, web);
   - RDL: each `DataSource` and whether it points at a shared `.rds`;
   - SSIS: connection managers and the protection level.
4. **Ask once, only what the files cannot show.** One question per turn (`AGENTS.md`): "Do these defaults hold?",
   listing the four decisions below as its sub-points, each with the recommended default; the user corrects any of
   them in one answer:
   - who owns each model, cube and package: this repository (edited here), or another team (read-only, changes go
     as requests);
   - where each report is delivered: the Power BI service, SSRS or Report Server, or an Analysis Services server;
   - whether MCP is allowed (Path A or B, `bi-map` section 3);
   - which candidate directories a Fabric workspace really syncs, with workspace and branch (only the user knows).
   
   Without an answer, use the defaults and label them `[inference]`.
5. **Write the drafts** (add, never remove existing text):
   - `docs/sources/README.md`, under `## Sources`: one block per source (database, cube, file folder, web API) with
     its readers (the artifacts that use it) and server and database from the files (`[source]`). Owner comes from
     the user's answer or "not stated". Refresh is "not stated". Credentials: "set in Desktop or the gateway, never
     in files".
   - `docs/conventions.md`: where models, reports, paginated reports and SSIS live, the naming seen, the delivery
     targets, the directory each Fabric workspace syncs with workspace and branch. Only facts from the files or the
     user.
   - With the hardening pack, give the user (never write it yourself: the guard denies it) the line for
     `hardening/harness.config.json` built from the directories they confirmed, for example
     `"fabric": { "directories": ["fabric/Sales-Dev"] }`, or `[]` when no workspace syncs any. Without an answer, no
     line: the Fabric Git checks then fall back to `.platform` and say so.
   - `TASKS.md`, under Todo: one line per finding that needs work, for example:
     - a `Model.bim` to convert, a PBIR-Legacy report, a `.pbix` to save as PBIP;
     - an `EncryptSensitiveWithUserKey` package;
     - a SQL source without schema DDL, a server hard-coded in M.
6. **Static check** (`docs/static-checks.md`).
7. **Report.** One table: artifact, path, format, owner, delivery target, finding. Then the next steps:
   `/bi-doctor` if it has not run, then the first real task with `/bi-plan`.

Never here: edit a model, report, RDL or package; connect to a server or run SQL; write a credential or a connection
string with a secret; decide ownership for the user without labelling it `[inference]`.
