---
paths:
  - "**/*.rdl"
  - "**/*.rds"
  - "**/*.rsd"
  - "**/*.rptproj"
---

# RDL rules (paginated reports)

- Edit with the file tools and keep the file as you found it: XML well-formed, the same schema namespace, the same
  encoding (with or without a byte order mark) and line endings. Report Builder and SSRS read both.
- A report the user saved in Report Builder is the reference: make the smallest edit; never regenerate or reformat it.
- Names: datasets, data regions (tablix, chart, map, gauge) and groups share one namespace; report items (textbox,
  rectangle, image, subreport) another; parameters and data sources are unique too.
- References resolve: `Fields!X.Value` to a field of the data region's dataset, `Parameters!X` to a report parameter,
  `DataSetName` and `DataSourceName` to existing elements; every parameter has a `CellDefinition` in
  `ReportParametersLayout`.
- A tablix has as many `TablixColumn` elements as leaf column members and cells per row.
- No credentials in a connection string; no placeholder ids for a semantic model or workspace. Changing the server,
  database or model a data source reads, or the data source a dataset reads (`DataSourceName`), is Tier 2. A report
  parameter's default, prompt or available values is an ordinary change, not Tier 2, unless a data source's
  ConnectString expression reads that parameter (as `Parameters!X`, `Parameters("X")` or `Parameters.Item("X")`, in any
  letter case; also through another parameter's default or available values, up to five levels, or through the
  report's `<Code>` when the ConnectString calls it, as `=Code.Conn()`): then it is the server, and the guard asks.
- Before adding a text box, look for one that already shows the same thing (a title, a parameter line); change it or
  ask which one should stay instead of showing the same value twice.
- Body width plus left and right margins fits the page width, with a few millimetres to spare (an exact fit adds blank
  pages in print layout and PDF), unless the report is for screen and Excel only.
- Keep values typed: number and date formats go into the `Format` property.
- New `rd:ReportID`, `rd:DataSourceID` and similar GUIDs are new; never copy one from another element or report.
- A Visual Studio report project (`*.rptproj`) lists its reports, shared data sources and shared datasets. When you
  add, rename or remove one of them, change its entry in the same batch by copying an existing entry of the same kind;
  without the entry Visual Studio neither shows nor deploys the file. A shared data source is referenced by name
  (`DataSourceReference`): a rename changes every report that uses it. The project's deployment settings (target
  server, folders, overwrite options) are deployment, which is never the agent's (`AGENTS.md`): never change them;
  hand the user the steps. If the project file's format is
  unclear, ask the user to add the item in Visual Studio instead.
- `<report>.rdl.data` beside a report is Report Designer's preview cache (Visual Studio): it holds query results.
  Never read or commit it; `.gitignore` excludes it.
- A report a Fabric workspace syncs (preview): `<Name>.PaginatedReport/` holds only `<Name>.rdl` and `.platform`; upload
  to the service first and commit from there (files that start in Git do not render); rename only in the service; delete
  the whole folder, never just the `.rdl`; moved to another workspace it stays bound to its original dataset (rebind in
  Report Builder, republish). Once the service commit is in Git, the pre-upload copy under `paginated/` goes in the same
  pull request (a deletion: the user approves) and the synced file is renormalized: one item, one place. Guide:
  [fabric-git.md](../../../docs/harness/fabric-git.md).
- Procedures and patterns: `.claude/skills/bi-paginated-report/SKILL.md`, `PATTERNS.md`, `MIGRATION.md`.
