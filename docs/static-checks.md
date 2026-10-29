# Static checks

A static check reads files; it never runs the model. It catches structure and hygiene mistakes early. It does
**not** compile TMDL or DAX, validate every JSON Schema rule, test RLS, or render a report.

## Which check to run

| You have | Run |
|---|---|
| the optional hardening pack (Node 18.17+ on PATH: `node --version`; the `hardening/` folder alone is not the check) | `node hardening/scripts/validate.mjs --changed` (`--staged` before a commit, no flag for the whole repository) |
| a hook file of the pack you edited, or every tool call blocked | `node hardening/scripts/check-hooks.mjs`: `node --check` on every hook file and a load of each module; the first failure as `file:line: message` |
| Microsoft's report CLI, `powerbi-report-author` | `powerbi-report-author validate <path-to-.Report-folder>` after every batch of PBIR edits |
| Analysis Services tabular models (TMDL folders) | a TMDL folder (with `database.tmdl` and `model.tmdl`, also when that folder is the repository root) gets the same syntax and model-wide checks as a PBIP model (unique measure names, DAX references, perspective and translation entries); deployment and processing are the user's |
| paginated reports (`*.rdl`) | the hardening validator checks them too; the engine check is the user's Report Builder run |
| a re-platformed paginated report (old and new RDL) | `node hardening/scripts/rdl-compare.mjs <old.rdl> <new.rdl>`: identical outside data sources and datasets |
| SSIS packages (`*.dtsx`, `*.dtproj`, `*.params`, `*.conmgr`) | the hardening validator checks them (XML, DTS namespace, unique DTSIDs, protection level against the project, credentials); then `dtexec /F <package>.dtsx /Validate` when `dtexec` exists on this machine, which proves package structure only (`.claude/rules/bi/ssis.md`); without `dtexec` that step is NOT RUN and the user validates in Visual Studio (SSDT) or on a machine that has it |
| neither | the manual checklist below |

Use every check that applies to the layers in scope, and only those (a repository without SSIS needs no `dtexec`;
one without PBIR needs no report CLI). Report which ones ran and the summary line of each. A check that could not run
is "NOT RUN", never "passed".

The validator is a static check only: it does not compile DAX, run a query, test RLS or render a report; engine,
reconciliation and Desktop checks are reported separately (its text output says so under the summary line).
Run the validator as a command of its own: once the pack's hooks are registered (`--enable-hooks`), a permission rule
pre-approves that exact command. In approvals mode `auto` the guard also passes a chain (`;`, `&&`, `|`) whose parts are
all routine; another chain, or any chain in `ask` mode, may prompt. Besides structure and hygiene it reports fields a visual uses that a local (`byPath`) model does
not define (error; stale filters are warnings), DAX references to measures, columns or tables the model lacks
(warning), and perspective or translation entries for objects the model no longer has (error). Reports on a published model are not checked against a reference copy: use the manual item below.
Fabric Git ([fabric-git.md](harness/fabric-git.md)), all warnings because Microsoft's supported-items list changes: a
`report.json` resource (base theme, custom theme) without its file; a report or model live-connected to Analysis Services
inside a synced directory (Fabric Git ignores it); and, in the full scan only (no flag), a second copy of a synced item
outside the synced directories, such as the pre-upload copy of a paginated report, or a second synced folder of the
same type that carries the same `.platform` `logicalId` under another name (a renamed copy). Synced directories are those the
user lists in `fabric.directories` of `hardening/harness.config.json`; without a list, item folders that hold
`.platform` count, which Desktop writes too, so each message says which source it used.

## Manual checklist

Model (TMDL)

- [ ] Edited files follow the syntax rules in `.claude/skills/bi-semantic-model/references/tmdl-guidelines.md`:
      tabs for indentation, names with spaces or `.` `=` `:` `'` in single quotes, `///` descriptions.
- [ ] No duplicate measure name in the model, no copied `lineageTag`, no BOM.
- [ ] Every new measure has a `formatString` and a `///` description.
- [ ] A new table has its `ref table` line in `model.tmdl`.
- [ ] Every referenced table, column and measure exists (search the TMDL).
- [ ] A renamed or removed object is renamed or removed in `perspectives/*.tmdl` and `cultures/*.tmdl` too.
- [ ] No credential, key or personal path in M or TMDL.

Report (PBIR)

- [ ] Every edited JSON file is valid JSON and keeps its `$schema`.
- [ ] Page, visual and bookmark folder names use letters, digits, `_` and `-`; the `name` property equals the folder.
- [ ] `pages.json` lists exactly the page folders and `activePageName` exists.
- [ ] Every field a visual uses exists in the model (for a report bound to a published model: in its reference copy or the user's field list).
- [ ] `definition.pbir` `byPath` resolves to a folder that contains `definition.pbism`.

Paginated report (RDL)

- [ ] The XML is well-formed (`&` written as `&amp;`, every tag closed) and keeps its namespace and encoding.
- [ ] Dataset, data region and group names are unique together; report item names are unique.
- [ ] Every `Fields!`, `Parameters!`, `DataSetName` and `DataSourceName` reference resolves; every parameter has a
      `CellDefinition` in `ReportParametersLayout`.
- [ ] Each tablix has as many `TablixColumn` elements as leaf column members and cells per row.
- [ ] No credential or placeholder id in a `ConnectString`; body width plus margins fits the page (or the report is
      for screen and Excel only, and you said so).

SSIS package (`*.dtsx`)

- [ ] Well-formed XML with the DTS namespace (`www.microsoft.com/SqlServer/Dts`); encoding and line endings kept.
- [ ] Every `DTS:DTSID` is unique and every `refId` follows its parent's path; a copied object got a new GUID.
- [ ] `ProtectionLevel` equals the project's (`.dtproj`); no password or connection string with a secret.
- [ ] Connection managers, servers and expressions on connections are unchanged unless approved (Tier 2).
- [ ] When a model reads the destination table, its columns match the model's partition or `sourceColumn` names
      (`bi-map`, Which layers are in scope).

Repository

- [ ] `.gitignore` contains `**/.pbi/localSettings.json` and `**/.pbi/cache.abf`.
- [ ] Nothing forbidden is staged: `.env*`, keys, certificates, `cache.abf`, `*.pbix`, `*.rdl.data`, `.pbi/localSettings.json`, `*.tmuo`, an Analysis Services project's `bin/` output, `*.user` files, or report exports with data (PDF, Excel, CSV).
- [ ] `*.SemanticModel/`, `*.Report/` and `*.PaginatedReport/` folders hold only the item definition: a Fabric Git
      commit from the service deletes any other file there; notes, test packs, screenshots and SQL go under `docs/`,
      `tests/` or `templates/` ([Fabric Git integration](harness/fabric-git.md)).
- [ ] An item a Fabric workspace syncs exists once: no same-named `.Report`, `.SemanticModel` or `.rdl` outside its
      synced directory and no second synced folder of the same type with its `logicalId` under another name
      (`docs/conventions.md`; `.platform` alone does not prove a sync); a report or model
      live-connected to Analysis Services stays under `powerbi/`; every file
      `report.json` names under `resourcePackages` exists under `StaticResources/`.
- [ ] Markdown files you wrote stay under 500 lines.

## Reporting

State which checks ran, each summary line, and what you checked by hand. Static results say nothing about DAX
results, RLS or how the report renders; report those separately (engine result or "not run", and what only Power BI
Desktop can confirm).
