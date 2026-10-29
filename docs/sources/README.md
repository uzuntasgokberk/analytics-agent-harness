# Data sources

The agent reads this registry before it touches a partition, an expression or a relationship that depends on a source. Fill one block per source; paths in a block start at the repository root. **No credentials, tokens or connection strings with secrets.** `/bi-onboard` drafts the first version from the files it finds.

```text
docs/sources/
  README.md                  this registry
  sql/<name>.sql             the full SQL of each query or view the model uses
  sql/<database>.schema.sql  schema-only DDL from the database owner: the evidence for grain and keys
  <cube>/definition/         TMDL export of a cube (reference copy, optional)
  <cube>/requests/           change requests for the cube owner (the agent writes these)
```

What the agent may do: SQL source: edit the `.sql` text and the model that mirrors it; it runs only a bounded, read-only query the user asked for, under the SQL read switch (`docs/harness/faq.md`, Running SQL). Cube owned elsewhere: read-only; it writes a change request and edits a shared TMDL copy only after approval (Tier 2); the owner deploys.
Tabular model this repository owns (SQL Server or Azure Analysis Services): it edits the model's source like a semantic model, within the server's compatibility level; you deploy and process it.
SSIS project this repository owns: it edits the packages within `.claude/rules/bi/ssis.md`; you run and deploy them; its connection managers take their authentication from the `authentication:` and `loader login:` lines below, and its target (SSISDB or Azure-SSIS IR) from `target:`.
A cube copy keeps tables, relationships and measures; leave out `dataSources.tmdl` and `*.tmuo` user files (ignored by Git; a local names-only `dataSources.tmdl` stub may exist so that the copy loads in TOM on Path A, and Path B needs none). The grain traps to record are in `.claude/skills/bi-data-sources/SKILL.md`, section 4.

## Projects in this repository

<!-- One line per project, so an agent can find them without a search. Example:
- powerbi/Sales.pbip: Sales.SemanticModel (Import) and Sales.Report; reads sales_fact below
- models/Finance/: Analysis Services tabular model this repository owns (database.tmdl, level 1600)
- paginated/InvoiceList.rdl: paginated report on the Sales model
- etl/CurrencyRates/: SSIS project this repository owns; loads the exchange-rate staging table
- fabric/Sales-Dev/: the directory the Fabric workspace "Sales-Dev" syncs (branch main); Sales.SemanticModel and Sales.Report (byPath); see docs/harness/fabric-git.md
-->

## Sources

Evidence labels as in `docs/decisions.md`. "Not verified" means the files do not show it; the agent queries the
database only when the user asked (the SQL read switch, `docs/harness/faq.md`; the result is marked `[sql]`). Owner and
refresh marked "not stated" wait for the user. "Expected values `[user]`" are the control figures in
`docs/tests/expected-values.md`. A fact read through MCP is marked "(MCP)": Path B cannot see it.

<!-- Example (fictional). Replace with your own blocks.

### sales_fact
- type: sql
- role: fact
- server / database: parameters `ServerName` / `DatabaseName` (see expressions.tmdl)
- authentication: Windows (gateway) | SQL login <reader name> | Microsoft Entra ID; the password is never in a file
- schema: docs/sources/sql/sales.schema.sql (schema-only handover from the DBA)
- query: docs/sources/sql/sales_fact.sql
- grain: one row per order line
- keys: OrderLineId (unique); DateKey, CustomerKey, ProductKey (foreign keys)
- window: full history (or: rolling, last 90 days, so no incremental refresh and relative date slicers)
- pre-aggregated columns: none (or: ItemCount is COUNT(DISTINCT item) per group, so never SUM it across a finer split)
- row multiplication: none (or: header amounts repeat per order line through a LEFT JOIN)
- personal data: CustomerEmail is not imported; CustomerName is a report attribute, never in test output
- storage mode: import
- refresh: daily 06:00, owner: BI team

### sales_cube
- type: cube
- role: cube (measures live in the cube)
- connection: the published model "Sales" (live connection)
- definition: docs/sources/sales_cube/definition/   (TMDL shared on 2026-01-15)
- owner: finance data team; changes go through docs/sources/sales_cube/requests/

### sales_tabular
- type: tabular model on SQL Server Analysis Services 2022 (compatibility level 1600)
- role: the model this repository owns
- definition: models/Sales/   (TMDL folder; a Model.bim must be converted first)
- owner: this repository; the user deploys (Tabular Editor) and processes it
- deployment keeps: partitions, role members, data source credentials (set on the server)
- changed directly on the server: no (or: yes, so compare the server model before deploying)

### currency_rates_load
- type: ssis (project deployment model)
- role: loads the staging table the Sales model reads for exchange rates
- definition: etl/CurrencyRates/   (owner: this repository; the user runs and deploys it)
- target: SSISDB on <server> (or: Azure-SSIS IR in Data Factory <name>)
- loader login: bi_loader (SQL login; CREATE TABLE and ALTER ON SCHEMA::stg on the test database only; password in the SSISDB environment)
- ddl: etl/CurrencyRates/sql/ (tables the package needs; the user runs the scripts)
- jobs: etl/CurrencyRates/jobs/ (SQL Agent job scripts; the user runs them in SSMS)
- schedule: SQL Agent, daily 05:30, owner: BI team
-->
