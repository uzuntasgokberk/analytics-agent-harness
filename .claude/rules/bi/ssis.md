---
paths:
  - "**/*.dtsx"
  - "**/*.dtproj"
  - "**/*.conmgr"
  - "**/*.params"
  - "**/*.dtsConfig"
---

# SSIS rules (Integration Services packages)

- Ownership comes from `docs/sources/README.md`: a project the registry names this repository as owner of (under
  `etl/<project>/`) is edited here; a package owned elsewhere is read-only and a change goes to its owner as a request.
  Folders listed in `references` of `hardening/harness.config.json` are read-only (the guard denies writes there):
  never edit them, and copy from them only when asked.
- Edit with the file tools and keep the file as you found it: well-formed XML, the DTS namespace
  (`www.microsoft.com/SqlServer/Dts`), encoding and line endings. Keep every `DTS:DTSID` and `DTS:refId`; a new object
  gets a new GUID (never a copied one) and a `refId` that follows its parent's path.
- Secrets never go into a package or project file. Use `ProtectionLevel` `DontSaveSensitive` with project or package
  parameters for passwords (`Project.params`, `*.params`); the user sets values in Visual Studio, the catalog
  environment or the SQL Server Agent job. `EncryptSensitiveWithUserKey` (the default) works only for the account that
  saved the package. Every package in a project uses the project's protection level (`.dtproj`). SSIS does not read
  shell environment variables (`SQLCMDPASSWORD` belongs to sqlcmd only): a SQL login's password is such a sensitive
  project parameter, its value set by the user as above (SSISDB environment, Agent job step), never in a file.
- Authentication comes from the registry: a connection manager takes the `authentication:` line of its source's block
  in `docs/sources/README.md` (Windows, a SQL login by name, Microsoft Entra ID) and, in a package that writes, the
  `loader login:` line; never the read-only reader login. Without those lines ask (the connection is Tier 2 anyway).
- A connection string, server, password or protection level change is a data source change (Tier 2): the guard asks,
  also when a component or a task (`SQLTask:Connection`) is pointed at another connection manager, a connection is set
  by an expression, or the value of a package parameter or variable such an expression reads changes
  (`@[$Package::X]`, `@[User::X]`, followed through a variable's own expression). `.dtproj`,
  `Project.params`, `*.conmgr` and legacy `*.dtsConfig` files always ask. `TargetServerVersion` in `.dtproj` must match the target SSIS
  server, like a model's compatibility level; change it only on the user's word.
- Script Task and Script Component code is compiled into `<BinaryItem>` elements: never edit it as text (the guard
  denies it); describe the change and let the user make it in Visual Studio (SSDT).
- Never edit build outputs or per-user files: `*.ispac`, `bin/`, `obj/`, `*.dtproj.user` (denied).
- The guard asks when an edit changes or removes an existing `DTS:DTSID` or `refId` (not `lineageId` or other
  attributes). Renaming only `DTS:ObjectName` leaves the object's `refId` paths stale; Visual Studio repairs them on its
  next save, so rename in Visual Studio when the name matters.
- Check a change with `dtexec /F <package>.dtsx /Validate` (runs nothing, but opens every connection: it runs without a
  prompt only while every server in the package is this machine). A data flow with `DelayValidation` (what a generated
  package usually sets) is not validated at all by `/Validate`: its component metadata, error outputs and tables are
  checked only when the package runs. Report such a `/Validate` as "package structure only", never as a pass of the
  package; the first run against a test database is the test (a generated package passed `/Validate` and failed its
  first run on a missing error-output column, 2026-10-07). Use the `dtexec` that matches `TargetServerVersion`
  (SQL Server 2025: `170\DTS\Binn\DTExec.exe`); the one on PATH can be an older release. Running a package loads data, even
  locally: the user runs it against a test database. Deploying to the SSIS catalog (SSISDB: Deployment Wizard,
  `dtutil /SQL`, `SSISDeploy.exe`, catalog procedures) is a deployment: the user does it, never the agent.
- Without `dtexec` on this machine (`where.exe dtexec`, which works in Git Bash and PowerShell, or the versioned path above) the `/Validate` step is NOT RUN:
  the static check and the SSIS checklist in `docs/static-checks.md` still run, and the user validates in Visual
  Studio (SSDT) or on a machine that has `dtexec`. Never install it or substitute another runner.
- Build without Visual Studio: Microsoft's Standalone SSIS DevOps Tools (Download Center id 102263, version 1.0.0.0 of
  2024-07-15, needs .NET Framework 4.6.2; Learn "ssis-devops-standalone", read 2026-10-15) build a `.dtproj` into an
  `.ispac`: `SSISBuild.exe -project:<file>.dtproj [-configuration:<name>] [-output:<folder>]`. The `.ispac` is a build
  output (Git ignores it). The same download ships `SSISDeploy.exe`, a deployment (above): the agent never runs it. The
  static check does not run SSISBuild; the user installs the tools and may run the build as evidence that it compiles.
- Project type in Visual Studio: "Integration Services Project" is the default here. "Integration Services Project
  (Azure-Enabled)" is the same project plus execution on an Azure-SSIS integration runtime in Azure Data Factory: only
  when the registry names ADF as the target. The "Integration Services Import Project Wizard" is not a project type: it
  creates a project from an `.ispac` or from a project in SSISDB (how packages that exist only in production get into
  Git; the user runs it, then registers the project). The registry's `target:` line (SSISDB on a server, or Azure-SSIS
  IR) decides, and `TargetServerVersion` follows it (Learn; not re-checked on 2026-10-15).
- A new project or package from scratch (no `.dtproj` yet): copy the shape of a package that already works, in this
  order: (1) a working package in this repository, (2) one the user hands over, (3) the harness reference
  `templates/ssis/AWSampleETL/` (Execute SQL Task and one data flow: OLE DB source, Data Conversion, Derived Column,
  OLE DB destination; connections set from project parameters; `DontSaveSensitive`; SQL Server 2025), read-only like
  all of `templates/`. Copy the shape only: every object gets a new GUID and `refId`, connection managers come from the
  registry, column metadata from the DDL under `docs/sources/`; never write component metadata, lineage ids or
  error-output columns from memory (a hand-built data flow passed `/Validate` and failed its first run).
  Never search the machine for a package to copy (other folders, drives, `%USERPROFILE%`, sample folders under Program
  Files): a package found that way is not the user's evidence and may hold credentials. A component none of the three
  holds (Lookup, Conditional Split, a flat file source, a Script Component): ask the user to add it in Visual Studio
  and hand the package over, then fill it.
- First gate of a new project: write only the first package and the project files, run the static check (and
  `/Validate`, above) and stop; the user builds and runs it in Visual Studio against the test database. Write the
  remaining packages only after that run passes. A failing run gets two fix attempts, then the task is Blocked
  (`TASKS.md`) with at most 12 numbered steps for the user. Five packages and a master package written this way passed
  6/6 `dtexec /Validate` and 12/12 row-count reconciliations (2026-10-22).
- Register a new project in `docs/sources/README.md` (owner: this repository, the tables it loads); when a model reads
  those tables, the destination columns must equal the model's partition or `sourceColumn` names (`bi-map`, Which
  layers are in scope). No model or report is created for a package unless the request names one.
- Tables that do not exist: the agent never runs DDL (the guard denies writes to a database). Write the `CREATE TABLE`
  as a reviewable script in `etl/<project>/sql/<schema>.<table>.sql`; the user runs it once on the test database. A
  demo package may start its control flow with an Execute SQL Task `IF OBJECT_ID('<schema>.<table>') IS NULL CREATE
  TABLE ...` when the registry names the schema. Grants are the user's and go to the loader login on the test database
  only (`CREATE TABLE`, `ALTER ON SCHEMA::<staging schema>`), never to the reader login.
- SQL Server Agent jobs: the agent never creates one (it needs `SQLAgentUserRole`, and an SSIS step runs under a proxy
  only a sysadmin creates). Write `etl/<project>/jobs/<Job>.sql` with `sp_add_job`, `sp_add_jobstep` (subsystem
  `SSIS`, the `/ISSERVER` command for a catalog package), `sp_add_schedule`, `sp_attach_schedule`, `sp_add_jobserver`
  and a placeholder for the proxy name; the user reviews and runs it in SSMS.
- Change data capture: the Attunity CDC components (CDC Control Task, CDC Source, CDC Splitter) and the CDC Service for
  Oracle are no longer available in SQL Server 2025 Integration Services and left support on 2025-12-13; Microsoft
  points to Data Factory in Fabric or Azure Data Factory (Learn "What's new in Integration Services in SQL Server 2025"
  and the SQL Server blog of 2024-02-28, read 2026-10-15). For a 2025 target use a plain source query on
  `cdc.fn_cdc_get_net_changes_<capture_instance>` with an LSN state table, or Change Tracking, or a watermark column,
  whichever the registry's grain allows. Enabling CDC (`sys.sp_cdc_enable_db`, `sys.sp_cdc_enable_table`) is the
  DBA's, never the agent's. Not tested in this harness: a CDC package is proven by its test pack like any other.
- Prove a change with a test pack (`docs/test-packs.md`, SSIS): the validate result (or NOT RUN), then the user's run
  against a test database and row counts against the source file.
- Format references: [MS-DTSX2] (package XML), [MS-ISPAC] (project deployment file), Learn "Access Control for
  Sensitive Data in Packages" (protection levels).
