# Templates

References the agent copies from and never edits (a permission rule denies it). Put your organization's standards here,
so every report starts from the same base.

| Folder | What | Who fills it |
|---|---|---|
| `report-dossier/` | the three documents every migrated or re-platformed report keeps: overview, mapping, decisions | ships with the harness; the agent copies it to `reports/<report>/docs/` |
| `house/` | your house standard: a reference Power BI project (theme, page size, chrome such as header, logo and navigation), the report theme JSON, and a house RDL (page setup, header and footer, fonts, parameter panel) | you; optional |
| `ssis/AWSampleETL/` | a working SSIS project: one package (`LoadDimProduct.dtsx`: an Execute SQL Task, then a data flow with OLE DB source, Data Conversion, Derived Column and OLE DB destination), `Project.params` that set both connections by expression, `DontSaveSensitive`, `TargetServerVersion` SQL Server 2025, and the `CREATE TABLE` script of its target table | ships with the harness; committed 2026-10-21 after the owner ran it |
| `pbir/Satis_SSAS/` | a working Power BI project on a live connection to an Analysis Services tabular model: one 1280 × 720 page with a registered background image and custom theme, twelve visuals of six types ([its README](pbir/Satis_SSAS/README.md)) | ships with the harness; opened and rendered in Power BI Desktop (2026-10-22) |

How the agent uses a house template: `docs/design-to-report.md` (house template) for interactive reports, and
`bi-paginated-report` for paginated ones (copy the house RDL's page setup, header and footer; never retype them). The
template decides the look; the model decides the numbers. To change a template, edit it yourself and commit it on its own.

## The shipped references: when the agent falls back to them

They exist so that the agent never writes a file shape from memory when neither the repository nor you can hand one
over. Each is the last source in a fixed order, and the agent copies the shape only, never the names, connections or
bindings.

| Reference | The order it closes | What it proves | What it does not |
|---|---|---|---|
| `ssis/AWSampleETL/` | `.claude/rules/bi/ssis.md`, new project or package: (1) a working package in this repository, (2) one you hand over, (3) this project | the XML of a package and project that Visual Studio builds and runs: control flow, data flow component metadata, error outputs, project parameters feeding connection managers, protection level | any component it lacks (Lookup, Conditional Split, flat file source, Script Component): the agent asks you to add one in Visual Studio |
| `pbir/Satis_SSAS/` | `bi-pbir-report`, Before you edit, step 2: (1) this report, (2) another report of the repository Desktop saved, (3) `house/`, (4) this project, (5) the report CLI catalog and the schema for what the copy lacks | the PBIP, `.platform`, live-connection `modelReference.json`, theme registration and the page background shape that Desktop renders (the page schema leaves the background image untyped, so no static check proves it) | pie, donut, gauge, map and other types it lacks, bookmarks, drillthrough, report measures, mobile layout, RLS: the agent asks you for a blank visual made in Desktop |

Copying from a shipped reference: new GUIDs and `refId`s (SSIS) or new 20-character ids and `.platform` `logicalId`s
(PBIR), connections from `docs/sources/README.md` (a data source change, Tier 2), columns and fields from your DDL and
your model, every `$schema` kept. Never open a reference in Desktop or Visual Studio in place: copy it to a scratch
folder first (`docs/design-to-report.md`, section 3).
