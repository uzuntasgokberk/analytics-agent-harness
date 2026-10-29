---
name: bi-data-sources
description: Work out where a Power BI model's data comes from (SQL database, tabular cube / Analysis Services / published semantic model, files, web APIs) and what the agent may change for each - partitions and M queries, the SQL text kept in docs/sources, live connections, composite models, DirectQuery, Direct Lake, shared cube TMDL. Use before touching a partition, expression or source-dependent relationship, and whenever the user supplies SQL or cube definitions.
---

# Data sources

The model layer behaves differently depending on where the data lives. Decide the source type first; it decides what the agent may change.

## 1. Read the registry, then classify

Read `docs/sources/README.md` (the user's registry) and the files it points to (`docs/sources/sql/*.sql`, `docs/sources/<cube>/definition/**`).
Registry paths start at the repository root; older registries write them relative to `docs/sources/`, so when a path does not resolve, look there before you call a file missing. If the source in question is missing or incomplete, ask for: type,
role (fact, dimension, lookup), grain, keys, storage mode, owner, refresh. Never guess grain or keys from names.

Check the registry against the files:

| Evidence in the project | Source type |
|---|---|
| partition `source` uses `Sql.Database`, `Sql.Databases` or `Value.NativeQuery` | SQL database |
| `AnalysisServices.Database` / `AnalysisServices.Databases` in a partition or expression | tabular cube (Analysis Services, or a published semantic model through XMLA) |
| `definition.pbir` uses `byConnection` and there is no local `*.SemanticModel` | report on a published model in Fabric (live connection, "thin report") |
| the `*.SemanticModel` folder holds `modelReference.json` and no `definition/` | report with a live connection to Analysis Services (SQL Server or Azure) |
| `mode: directQuery` or `dual` on a table | DirectQuery or composite; `import` is Import |
| `Csv.Document`, `Excel.Workbook`, `Folder.Files`, SharePoint functions | files |

Classify **per table**, not per project: a composite model can mix SQL, cube and files. If the registry and the files disagree, report the conflict and stop. If you are unsure whether something is a cube, ask.

A table that is not plain Import has its own limits: read [storage-modes.md](storage-modes.md) before changing a live-connected report, a composite model (`entity` partitions, `EXTERNALMEASURE`), a DirectQuery or Dual table, a Direct Lake table, a file or folder source or a `Web.Contents` query.

## 2. SQL path

You may: edit the SQL text under `docs/sources/sql/` (a proposal: the user runs it against the database); mirror it in the partition M; add or change columns, relationships, measures; propose the follow-up steps.
You may not: connect to the database or run SQL on your own (the exception is a bounded, read-only query the user asked for: the SQL read switch judges it, `docs/harness/faq.md`; record the result with `[sql]`), hold credentials, or hard-code server and database names (they come from parameters in `expressions.tmdl`; changing them is Tier 2).

- **Order of a change:** SQL file, then partition M, then `column` / `sourceColumn` in TMDL (the name must equal the SQL output name), then relationships and measures, then a search of the report for affected fields.
  End with what the user must do: run the SQL change in the database, refresh in Desktop.
- **M:** prefer navigating to a table or view; if a native query is needed, keep it in the registry's `.sql` file and mirror it, use `Value.NativeQuery(..., [EnableFolding = true])` where the source allows it, and keep later steps foldable.
  Name explicit columns (no `select *`); filter and type in SQL where possible; do not implement the same business rule in SQL and in DAX. Query folding can only be confirmed in Desktop ("View Native Query"): write "folding not verified".
- **Fact and dimension** come from the registry. Fact: state the grain, foreign keys to dimensions, numeric columns hidden with `summarizeBy: none` and explicit measures. Dimension: one unique key (`isKey`), attributes, no measures. (Microsoft's `modeling-guidelines.md` lists "Set `isKey`" under DON'T; the item belongs with the DO list, as Tabular Editor's Best Practice rules show: follow this line.)
  Relationships: many-to-one from the fact key to the dimension key, single direction, one active per role; role-playing dates use inactive relationships with `USERELATIONSHIP`. A new relationship is Tier 2.
- **Storage mode** (Import, DirectQuery, Dual) and **incremental refresh** policies are Tier 2; follow the registry and the current Learn page for DirectQuery limits.
  A table with a `refreshPolicy`, or a query that uses `RangeStart`/`RangeEnd`: read [incremental-refresh.md](incremental-refresh.md) first.
- Credentials and privacy levels are set in Desktop or the service, never in M, SQL or the registry.
- **After the user edits a query in Desktop** the partition is the newer truth: re-sync the `.sql` file from it and say so. Desktop's Power Query editor can rewrite the call
  (for example into `Value.NativeQuery(...)`) and change column data types (for example decimal to double); point out type changes and let the user decide.

## 3. Cube path

A cube is usually shared and owned outside this repository. Four cases:

- **The repository owns the model** (the registry names this repository as owner and `definition:` points to its
  TMDL folder): it is not a cube to request changes from. Edit it
  with `bi-semantic-model` and its `ssas-tabular.md`: the server's compatibility level limits what you may use, and
  the user deploys and processes. A folder name or the request alone does not make a model owned; the registry does.
- **No cube definition in the repo** (live connection or composite over a published model): the cube is read-only. You may edit the report layer, including report measures, visual calculations and per-visual names and formats (`.claude/skills/bi-pbir-report/PATTERNS.md`), and local objects of a composite model.
  Anything that needs a change in the cube becomes a **change request**: `docs/sources/<cube>/requests/YYYY-MM-DD-<topic>.md` with what, why, a TMDL snippet, the reports and measures affected, the risk and who applies it.
- **Cube TMDL shared in the repo** (`docs/sources/<cube>/definition/**`): it is a **reference copy**. Read it to learn tables, columns, measures, relationships, formats and descriptions, and to write correct DAX and report bindings.
  Answer a request for a cube change with a change request first: it is what the owner applies. Edit the copy only after the user approves (Tier 2: other reports depend on the cube): follow the TMDL rules, search every PBIR file and every composite object that uses the changed name, and keep the copy and the request in step.
  The cube owner deploys; the agent never deploys, runs MDX or changes a live connection, and reads the cube's
  metadata only through the modeling MCP as section 5 and `docs/harness/MCP.md` allow.
- **A Multidimensional cube** (SSAS Multidimensional: `.cube`, `.dim`, `.dsv` project files, MDX) is not a tabular model:
  it has no TMDL and this harness has no rules for its files. Treat it as owned elsewhere even when its project is in the
  repository: read only, a change is a request written in prose; never edit its project files.

The reference copy is not a local model: do not put it under `*.SemanticModel`, and never present an edit of the copy as if the cube had changed. It needs tables, relationships and measures:
leave out `dataSources.tmdl` (connection and account details) and per-user `*.tmuo` files from Visual Studio or Tabular Editor (the `.gitignore` excludes both).
Without `dataSources.tmdl` a copy whose partitions name a data source does not load in TOM (MCP `ConnectFolder`: "refers to an object which cannot be found"). To load it, add a local `dataSources.tmdl` stub with only the data source names (`dataSource <Name> = provider`, no connection string); Git ignores it. A Path A copy comes from `database_operations` `ExportToTmdlFolder` into a staging folder outside the repository, then the files go in with the edit tools.

**Field gate for a report on a published model:** bind only names you can show, from the reference copy or from the field list the user reads in Desktop, never from the source tool's labels.

## 4. Grain traps

Check these before any measure, and before trusting a total that "looks right": each one produces totals that look plausible and are wrong.

| Trap | Symptom | What to do |
|---|---|---|
| **Pre-aggregated column**: the view already returns `COUNT(DISTINCT ...)`, an average or a ratio per group | a `SUM` over a finer split counts the same item twice; averages of averages | keep the measure at the source's grain; a `SUM` that matches an older report is parity, not correctness: let the user choose and record it |
| **Row multiplication**: a `LEFT JOIN` to a child table repeats header amounts on every child row | `SUM` inflates header-level amounts | measure at the grain that owns the amount (`MIN`/`MAX` per key or a separate fact); test: row count against distinct keys |
| **Rolling window**: `WHERE date >= CURRENT_DATE - n` | old data disappears at refresh; a saved date slicer drifts out of the window | no incremental refresh; a date table limited to the same window; relative date slicers (`PATTERNS.md`) |
| **Missing or composite key** | relationships fail or duplicate rows | prove uniqueness with a test query; never guess a key from a column name |
| **Codes stored as text** | `MIN`, `MAX` and sorting work alphabetically | cast in SQL, or say in the mapping that the column is text |

Write each finding into the registry (`docs/sources/README.md`) and, when it changes a number, into `docs/decisions.md`.

## 5. Path A and Path B

Path A: the modeling MCP may read the metadata of a cube or tabular model on this machine as `AGENTS.md` and
`docs/harness/MCP.md` allow (confirm the exact target; the hardening guard asks before a local connection in `ask`
mode and logs it in `auto`); any other server needs the user's confirmation first, and the connection stays read-only
here. Path B: the registry, the SQL files and the shared TMDL are everything you know; say
"not verified" for anything they do not show. Prohibited MCP is a decision, not an obstacle.

## 6. Report back

A source map (table, source type, role, storage mode, who may change it, evidence), what you changed, the Tier 2 items with a recommendation, and the hand-offs: run SQL in the database, owner applies the cube request, the user deploys and processes an owned model, refresh in Desktop.
