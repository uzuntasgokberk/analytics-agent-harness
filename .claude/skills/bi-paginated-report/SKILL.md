---
name: bi-paginated-report
description: Paginated reports (RDL) for SQL Server Reporting Services, Power BI Report Server and the Power BI service - build and edit reports on SQL, Analysis Services or semantic model sources (data source choice, datasets, parameters, tablix layout, page setup), checks with the user in Report Builder, reconciliation, moving existing SSRS reports to the Power BI service as paginated reports, and re-platforming an SSRS report from native SQL onto a semantic model. Rebuilding a report as an interactive Power BI report is bi-migration. Use for any .rdl, .rds or .rsd file and for printable, exportable or pixel-exact reports.
---

# Paginated reports (RDL, SSRS)

An `.rdl` file is one XML document: data sources, datasets (queries), parameters, the layout (tablix, textboxes)
and the page setup. Power BI Report Builder and SQL Server Reporting Services (SSRS) read the same format (schema
2016/01). There is no engine in this repository: the user opens and runs the report in Report Builder; you prove what
you can with the static check and give the user the runs that prove the rest.

## 1. Paginated or a PBIP report?

| Signal | Choice |
|---|---|
| row-level detail lists, many columns, printed, PDF or Excel exports, invoices, statements | paginated |
| a fixed page layout carried over from another tool | paginated |
| a parameter form people run and download | paginated |
| exploration, cross-filtering, slicing, visuals that interact | PBIP report (`bi-pbir-report`) |

Both can read one Power BI semantic model, so a business rule lives in one place. Record the choice in
`docs/decisions.md`.

## 2. Data source: decide per report

| Source | When | What to know |
|---|---|---|
| Power BI semantic model (DAX) | the model already holds the logic | needs Build permission; a DirectQuery model has a fixed 10-minute query timeout (Learn; not re-checked on 2026-10-19; use the XMLA endpoint for longer); renaming a model object breaks the dataset query |
| SQL Server, Oracle, ODBC, SSAS on premises | the query belongs to the database | runs through a gateway; after publishing, a gateway admin binds the report's data source to a gateway connection; stored procedures with parameters work |
| Azure SQL, Fabric warehouse or lakehouse SQL endpoint, Azure AS, Dataverse | cloud sources | native; credentials or SSO are set in the service |
| shared data source (`.rds`) or shared dataset (`.rsd`) | SSRS only | not supported in the Power BI service: embed them, or use a named connection or a semantic model |

- The connection string names a server and a database or a workspace and a model, nothing else. Credentials are
  set in Report Builder, the service or the gateway, never in the file.
- A semantic model connection needs the real workspace and model; never write a placeholder id (Report Builder fails
  with an access error or crashes). Ask the user for the model's address in the service.
- Changing a report's data source is Tier 2 (`AGENTS.md`). Keep SQL query text in `docs/sources/sql/` like any SQL
  source (`bi-data-sources`, section 2) and mirror it in the dataset.

## 3. Workflow

1. Read `docs/sources/README.md`, `docs/decisions.md`, the RDL if it exists, and `git status`.
2. Pin the requirement: columns and their order, grouping and totals, parameters (type, default, multi-value,
   available values), page size and orientation, exports (PDF, Excel, CSV), who runs it and how often.
3. Decide the data source (section 2) and write the dataset query in the source's language ([PATTERNS.md](PATTERNS.md)).
4. Build or change the layout: a tablix for lists and matrices, page setup by the numbers ([PATTERNS.md](PATTERNS.md)).
5. Run the static check (`docs/static-checks.md`) and review the XML you changed.
6. Hand over the engine check: open in Report Builder, Run with the named parameter sets, export to PDF and Excel,
   report what fails. Until then the report is "not run".
7. Reconcile: row count and totals per parameter set against the source (`docs/test-packs.md`); without expected
   values the status is "validation BLOCKED".
8. Publishing is the user's: Report Builder (Publish), the report server portal or their script. After a Power BI
   publish the data source must be bound to a gateway connection; give the steps, never run them.

## 4. Editing rules

The full list is `.claude/rules/bi/rdl.md`; the ones that break reports most often:

- Dataset, data region and group names share one namespace and must be unique together ("More than one dataset,
  data region, or grouping has the name …"); report item names (textboxes too) are unique in the report.
- Every `Fields!X.Value`, `Parameters!X.Value`, `DataSetName` and `DataSourceName` must resolve.
- A field has a `Name` (used in expressions) and a `DataField` (the column the query returns).
- Body width plus left and right margins must fit the page width, or PDF and print get extra blank pages. A report
  meant only for screen and Excel may be wider: say so in the report back.
- Keep numbers and dates typed (the `Format` property, not `Format()` in a textbox expression), so Excel gets numbers.
- A report the user saved in Report Builder is the reference: make small edits, never regenerate it.
- In a Visual Studio report project (`*.rptproj`), a report, shared data source or shared dataset you add, rename or
  remove changes its project entry in the same batch (copy an entry of the same kind); its deployment settings are
  deployment, never the agent's: hand over the steps (`.claude/rules/bi/rdl.md`).

## 5. Evidence

| Kind | How |
|---|---|
| static | the hardening validator (XML, names, references, credentials, placeholders, page fit) or the manual checklist |
| engine | Report Builder: the user runs it; record the parameter values and the result |
| numbers | the same parameters against the source query or the semantic model (`docs/test-packs.md`) |
| service | after publishing: data source binding, credentials, one run in the browser, render time |

Static results say nothing about query results or rendering; report each kind separately.

## 6. Moving SSRS reports: three routes

| Goal | Route |
|---|---|
| the same report in the Power BI service, still querying its source | [MIGRATION.md](MIGRATION.md): what does not move, the built-in tools, the data source binding, the behaviour that changes |
| the same report and the same rows, reading a semantic model instead of the database | [REPLATFORM.md](REPLATFORM.md): the business rule moves into the model's SQL, only the data layer of the RDL changes, and a comparison proves it |
| an interactive Power BI report instead | `bi-migration` |

Record the route chosen per report in `docs/decisions.md`.

## 7. Report back

Changed (file, datasets, parameters, layout); static result; the Report Builder runs the user must do, with
parameter values; reconciliation status; Tier 2 items (data source, publishing); exports and page fit notes.
