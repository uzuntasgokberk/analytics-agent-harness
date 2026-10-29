# Storage modes and connectors

Read with `SKILL.md` when a table is not a plain Import table from SQL: a live connection, a composite model,
DirectQuery, Direct Lake, files or a web API. Facts below come from Microsoft Learn (links per section;
not re-checked on 2026-10-19); features move fast, so fetch the page again before relying on a limit that matters.

## Live connection to a model you do not own (SSAS, Azure AS, a published model)

- The report has no model of its own. A published model in Fabric: `definition.pbir` uses `byConnection`. SQL Server or
  Azure Analysis Services: `definition.pbir` uses `byPath` to a `<Name>.SemanticModel` folder that holds only
  `definition.pbism` and `modelReference.json` (schema `semanticModel/modelReference/2.0.0`; for a tabular database on
  Analysis Services `connectionType` is `analysisServicesDatabaseLive`, `isMultiDimentional` false, and the connection
  string names server and database). You change the report layer only: report measures (`reportExtensions.json`;
  a visual binds one with `"SourceRef": { "Schema": "extension", "Entity": "<table>" }`), visual calculations,
  formatting. Anything else is a change request.
- Visual calculations on a live connection to SQL Server Analysis Services need SSAS 2025 or later, and even then the
  server may refuse them ("unsupported visual calculation expressions ... feature switch is off", seen on 17.0.25.223).
  Read the server version from the registry, open the visual once in Desktop, and use a report measure when it fails
  or the version is older or unknown.
- A thin report's `byConnection` string names the workspace and `semanticmodelid`. Fabric Git integration exports
  `byPath` only when report and model share a workspace, and a reference to an item in another workspace never binds
  automatically on deployment: each stage rebinds (deployment pipelines' autobinding, or a build script). Direct Lake,
  SQL analytics endpoint, warehouse and KQL connection strings in `expressions.tmdl` are workspace-specific too and need
  per-stage parameters. Guide: [fabric-git.md](../../../docs/harness/fabric-git.md).

## Composite model (DirectQuery to a published model or AS, plus local tables)

- Remote tables appear locally with entity partitions (`mode: directQuery`, `expressionSource` pointing at the
  `AnalysisServices.Database` expression) and remote measures as `EXTERNALMEASURE(...)`. They mirror the owner's model:
  do not edit their columns, partitions or external measures; ask the owner for changes.
- You may add local tables, local measures and relationships (a relationship is Tier 2).
- A relationship between tables of different source groups (for example a local Import table and a remote table) is
  a **limited relationship**: INNER JOIN semantics, no blank row for unmatched keys (they drop out of totals), `RELATED`
  cannot be used, RLS has topology restrictions. Say so before creating one, and check that both sides have the same
  grain (a monthly target against daily facts needs a month level). Learn: model relationships, "Limited relationships".

## DirectQuery

- Every query runs at the source. Power Query steps must condense into one native query (fold); a step that cannot
  fold (an index column, procedural or custom-function logic, a merge across sources) fails or forces Import. Do the
  work in the SQL view or query (a proposal to its owner) or at query time in DAX, not in M.
- Calculated columns are limited to row-level expressions that fold; prefer the SQL view.
- Changing a table's storage mode (DirectQuery, Import, Dual) is Tier 2, and possible only while every step still
  folds. Dual keeps an imported copy that must be refreshed and stay consistent with the source. Learn: DirectQuery in
  Power BI, "DirectQuery limitations".

## Direct Lake

- Tables map Delta tables one to one through entity partitions (`mode: directLake`); there is no Power Query. Data
  preparation happens in the lakehouse or warehouse, which its owner changes, not the model.
- The shared expression tells the flavour: `Sql.Database` on a SQL analytics endpoint is Direct Lake on SQL;
  `AzureStorage.DataLake` on OneLake is Direct Lake on OneLake.
- Calculated columns and calculated tables that reference Direct Lake tables: not supported on Direct Lake on SQL; on
  OneLake, calculated columns are user context only (preview) and calculated tables are in preview. Prefer an existing
  column (often from the date dimension through its relationship) or a column added in the warehouse.
- Views on a SQL endpoint fall back to DirectQuery (Direct Lake on SQL) or are not supported (OneLake). Gateways are
  not supported. Learn: Direct Lake overview, "Considerations and limitations".

## Files and web APIs

- Paths, folders and base URLs are parameters (`expressions.tmdl`), never personal paths.
- A source the service cannot reach directly (a local file or folder, an on-premises database) refreshes only through a
  data gateway; cloud sources such as SharePoint Online do not need one. Moving a source (a local file to SharePoint)
  is a data source change (Tier 2).
- A folder of CSV files drifts: new columns appear, old files lack them. Type columns explicitly and let missing ones be
  null (`[MissingField = MissingField.UseNull]` as the options record of `Table.TransformColumnTypes`, or
  `Table.SelectColumns(..., MissingField.UseNull)`) so old files still combine.
- Excel: read a named table (`Kind = "Table"`) rather than a sheet when you can; sheet renames break navigation.
- `Web.Contents`: keep the base URL static (a parameter) as the first argument and put variable parts in
  `RelativePath` and `Query`. A URL assembled by concatenation is a dynamic data source, which the Power BI service
  cannot refresh. Learn: data refresh, "Refresh and dynamic data sources".
- Credentials, API keys and tokens go into data source settings in Desktop or the service, never into M or files.
