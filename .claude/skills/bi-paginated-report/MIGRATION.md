# Moving SSRS reports to Power BI paginated reports

Facts from Microsoft Learn ("Plan to migrate .rdl reports to Power BI", "Paginated reports in Power BI: FAQ",
"Supported data sources for Power BI paginated reports"; checked 2026-10). Fetch them again before relying on a limit.

## 1. Inventory before anything moves

For every `.rdl`, list: data sources (provider, server, shared or embedded), datasets (stored procedure or text,
shared or embedded), parameters, subreports and drillthrough targets, custom code, page size, and who uses it.
Retire reports nobody runs instead of moving them.

| Found | In the Power BI service |
|---|---|
| shared data source (`DataSourceReference`, `.rds`) | not supported: embed it (or use a named connection) |
| shared dataset (`SharedDataSet`, `.rsd`) | not supported: embed it, or read a Power BI semantic model instead |
| custom assembly (`CodeModules`) | not supported: move the logic to embedded code or upstream |
| linked report, custom fonts | not supported |
| embedded code (`Code`) | supported |
| stored procedures with parameters through a gateway | supported for SQL Server |
| map visuals on SQL Server spatial data through a gateway | not supported (spatial types) |
| more than 250 data sources in one report | not publishable |

## 2. Behaviour that changes

- `User!UserID` returns the user principal name (`name@domain`), not `DOMAIN\name`: revise data filters built on it.
- `Globals!ExecutionTime` is UTC: check footers and date defaults.
- DateTime parameters are read in US format (MM/DD/YYYY) in the service.
- A query against a DirectQuery semantic model times out after 10 minutes; the dataset `Timeout` defaults to
  600 seconds.
- Cascading parameters are evaluated one after another: pre-aggregate the lookup queries.

## 3. Moving

- SQL Server 2022 Reporting Services and Power BI Report Server have a built-in publish to Power BI; older SSRS
  versions use Microsoft's RDL Migration Tool (GitHub), which converts shared data sources and datasets to embedded
  ones and publishes reports that pass its checks. Report Builder can also open each report and publish it.
- The agent prepares files (embedding a shared data source or dataset into the RDL is a normal edit; changing which
  server or database it reads is Tier 2) and lists what the user runs. It never publishes.

## 4. After publishing (the user)

1. Bind each data source to a gateway connection; this needs gateway admin rights on that connection. The server and
   database in the RDL must match the gateway connection exactly.
2. Set credentials (SSO, OAuth2 or basic) where the source needs them.
3. Run every report once in the browser with typical parameters; compare row counts and totals with the old server
   and note render times. Long renders: consider subscriptions.

## 5. Repointing many reports to another server

A bulk data source change is Tier 2: list every report and its current connection, show the new one, change the
files with a reviewed edit or script (never credentials), validate each file, then re-bind the data sources in the
service. Keep the old and new values in `docs/decisions.md`.
