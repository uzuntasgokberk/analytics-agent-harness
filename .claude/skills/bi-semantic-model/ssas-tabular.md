# Tabular models on Analysis Services

A tabular model on SQL Server Analysis Services or Azure Analysis Services at compatibility level 1200 or higher is the
same Tabular Object Model as a Power BI semantic model: TMDL, DAX and the guidelines in `references/` apply as they are
([TMDL overview](https://learn.microsoft.com/analysis-services/tmdl/tmdl-overview)). Three things differ: who owns the
model, what its server supports, and how a change reaches users. A Multidimensional model is not tabular: see the cube
path in `bi-data-sources`.

## Owned here, or owned elsewhere

| The registry (`docs/sources/README.md`) says | You |
|---|---|
| `owner: this repository` and `definition:` points to the model's TMDL folder | edit it like any semantic model (this skill); the user deploys and processes it |
| `owner: this repository` but the source is a `Model.bim` | TMDL only: nothing is edited until it is converted (`SKILL.md`, section 7) |
| another owner, or no entry for it | treat it as a cube: read only, changes as requests (`bi-data-sources`, cube path) |
| a reference copy under `docs/sources/<model>/definition/` | a copy, not the source: request first, edit only after approval |

Never infer ownership from a folder name or from the request alone; when the registry does not say, ask.

## Before a change

- **Level and server.** Read `compatibilityLevel` in `database.tmdl` and the server in
  the registry. SQL Server 2019 runs up to level 1500, 2022 up to 1600, 2025 and Azure Analysis Services up to 1700
  ([compatibility levels](https://learn.microsoft.com/analysis-services/tabular-models/compatibility-level-for-tabular-models-in-analysis-services);
  Learn, not re-checked on 2026-10-19, also for the levels below). Raising the level is irreversible: Tier 2.
- **Only what that level supports.** Calculation groups need 1500. DAX user-defined functions need 1702, so no
  Analysis Services server runs them. Direct Lake is Fabric only; visual calculations belong to reports. For any newer
  feature, check its Learn page for Analysis Services; if it is not documented there, say "not verified on Analysis
  Services" and offer what the server supports.
- **One source of truth.** A deployment replaces the server's model definition with the repository's, except what the
  deployment tool is told to keep. A change made on the server outside the repository (SSMS, a script, another project)
  is lost. When the registry says the server is also changed directly, ask the user to compare first (export the
  server model to TMDL and diff it, or a schema compare tool).

## Editing

- TMDL only: `.claude/rules/bi/tmdl.md`. A `Model.bim` is read, never edited (`SKILL.md`, section 7).
- Credentials: impersonation accounts, passwords and data source credentials are entered in the deployment tool
  (Tabular Editor, SSMS) when deploying, never written in a file. A data source or connection change is Tier 2.
- Partitions: tables on a server often have partitions that a refresh job creates. Do not add, remove or redefine
  partitions without approval, and say whether the deployment must keep the server's partitions.
- Roles: permissions and row filters are model design (Tier 2); members are never edited by the agent.
- Never read a workspace database (`bin/Data/` of a Visual Studio project; it holds imported data) or `.abf` backups.

## Hand-over

Deploying, processing and connecting to a shared or production server stay the user's. On Path A you read a local or
test server's model metadata and run bounded DAX there only through MCP (`docs/harness/MCP.md`; a server not on this
machine needs the user's confirmation first). Report:

1. What changed, per object, and the static check result.
2. Deployment, by the user, from the TMDL folder: Tabular Editor, or Microsoft's TMDL API
   ([deploy a TMDL model](https://learn.microsoft.com/analysis-services/tmdl/tmdl-how-to)). Tell the tool to keep the
   server's partitions and role members unless the change is about them, and deploy to a test server first.
3. Processing, by the user: a measure or other metadata needs none; a calculated column, calculated table or calculation
   group needs `calculate`; a new or changed source column needs `full` on its table; `automatic` processes whatever
   the deployment left unprocessed ([refresh types](https://learn.microsoft.com/analysis-services/tmsl/refresh-command-tmsl)).
4. Consumers outside the repository read the model by name: Excel PivotTables (MDX), Power BI reports with a live
   connection, paginated reports. A rename or delete breaks them; list what the repository shows and name the rest as
   not searchable from here.
5. Tests: the DAX test pack (`docs/test-packs.md`) runs in SSMS or DAX Studio against a test deployment before
   production.
