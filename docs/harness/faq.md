# Questions teams ask

Short answers with the file that holds the detail. The README links here; `AGENTS.md` and the skills stay the rules.

## Why use the harness, and what it does not promise

A coding agent writes DAX, TMDL, PBIR and RDL well enough on its own. What it does not do on its own is work the way a
BI team needs: change the smallest thing, prove a number by running it, stop before a rename or a new data source,
ask one question instead of guessing a business rule, and leave a record the next person can read. The harness is
that working agreement (`AGENTS.md`), the procedures behind it (skills), and an optional safety net that the model
cannot skip (hooks). Our eval against bare Claude found the same correctness and a safer, better documented process
(`hardening/tests/eval/README.md`, Run 3, in a clone of the harness; an installed copy leaves it out): adopt it for reviewable, evidenced work, not for "better DAX".

## When `/bi-doctor` shows a problem

`/bi-doctor` changes nothing; it runs each check and names the path (A with MCP, B without). Fix a row, then run it
again.

| The row says | What it means | What to do |
|---|---|---|
| Node missing or older than 18.17 | the hooks cannot start, so nothing is guarded (they fail open) | install Node 20 or later (nodejs.org), restart Claude Code |
| Hardening validator fails or prints no usage | the pack is incomplete or Node is missing | run `node <harness>/hardening/scripts/install-into.mjs . --update` in the repository |
| Git hooks path not set | commits are not checked | `git config core.hooksPath hardening/githooks` (once per clone) |
| Claude Code hooks not registered | the guard does not run in this session | run `node <harness>/hardening/scripts/install-into.mjs . --update --enable-hooks` (yours) or `--update --enable-hooks --shared` (the team); on a shared install `--update --enable-hooks` keeps the team registration; `/hooks` lists them |
| `AGENTS.md` not loaded | a `CLAUDE.md` exists, and Claude Code then reads only that one | add the line `@AGENTS.md` to `CLAUDE.md` |
| Permission rules ignored, "workspace not trusted" | Claude Code ignores the project's allow rules until you trust the folder | start Claude Code in the folder once and accept the trust dialog |
| MCP `powerbi-modeling` missing | normal: the agent works on Path B (files and test packs) | if your organisation allows it: copy `.mcp.example.json` to `.mcp.json`, restart, check `/mcp`, accept the EULA once |
| `powerbi-report-author` or `powerbi-desktop` missing | optional tools; the static check falls back to the validator and the manual checklist | install them when you want them (versions below); never needed for a model-only repository |
| Report Builder, SSMS, DAX Studio, `dtexec` "not checked" | the agent cannot see GUI tools on PATH | tell the agent once that you have them; their checks stay NOT RUN until you run them |
| Harness or `settings.json` permission rules missing | `.claude/settings.json` has no `Read(.env)` deny rule: a file kept by an install from before 2026-10-19 | run the same install command again with `--keep-existing`: the rules are merged in, yours stay first |
| Installed files are not committed | your `.gitignore` excludes them (the installer lists them as `ignored`) | narrow the rule `git check-ignore -v <file>` names, or `git add -f` the files |
| `approvals.mode` unknown, or `"lab"` committed | a typo, or a value that is not text (`null`, `0`, a list), or an `approvals` that is not an object, is treated as "ask"; a committed `lab` makes every clone run without prompts | fix the spelling; set `"auto"` before committing (the validator refuses `lab`) |

Anything else: copy the table (it holds no data) into an issue.

## A repository that is not tidy

Real repositories have hundreds of measures, calculated columns nobody remembers, a `Model.bim` next to TMDL, a
PBIR-Legacy report, RDL files with hidden filters, SSIS packages owned by another team. The harness does not try to
encode every such case as a rule. It works like a careful new team member:

- **Discover first.** `/bi-onboard` inventories by file signature (nested PBIP, TMDL folders, `Model.bim`,
  `report.json`, `.pbix`, `.rdl`, `.dtsx`), asks once what the files cannot show (owners, delivery, MCP, Fabric sync) and drafts `docs/sources/README.md` (the registry)
  and `docs/conventions.md` for your review.
- **Your conventions win.** `docs/conventions.md` holds your team's rules (naming, display folders, a measures table,
  prefixes, the house template); it replaces the skills' defaults. The agent follows the existing style of the file it
  edits and never reformats untouched objects.
- **Small changes, no big bang.** It changes the objects the request names, reuses an existing measure instead of
  adding a duplicate, and proposes clean-ups as a plan (`/bi-plan`). Renames, deletes, relationships and sources are
  Tier 2: it shows the impact (model, reports, RDL datasets, perspectives, translations) and waits for your yes.
- **Odd formats are converted, not patched.** `Model.bim` and PBIR-Legacy are read, never edited; the conversion is
  your Tier 2 decision. An RDL's real behaviour is inventoried by `bi-rdl-analyst` before any change.
- **Hooks only for what must never happen.** Code (hooks, validator) covers safety and structure that can be checked
  deterministically: secrets, broken JSON or XML, duplicate measures, role members, writes to a database. Taste and
  business rules stay in skills and in your conventions, and a business fact the files do not hold is a question,
  never a guess. Community harnesses take the same line, for example the plugin marketplace
  [data-goblin/power-bi-agentic-development](https://github.com/data-goblin/power-bi-agentic-development): a few
  deterministic hooks, guidance skills, checks you can switch off in configuration.

## Templates: your house report and your RDL standard

Put a reference PBIP and a house RDL under `templates/house/` (the agent reads and copies, never edits them) and name
them in `docs/conventions.md`. Power BI pages: theme, background, slot map and the steps are in
`docs/design-to-report.md`; the visual shapes the agent copies are in `.claude/skills/bi-pbir-report/PATTERNS.md`.
Paginated reports: page size, margins, header and footer come from your house RDL;
`.claude/skills/bi-paginated-report/PATTERNS.md` has the generic parts. Teams that differ write the difference into
`docs/conventions.md`; nothing in the harness code has to change. Two working references ship with the harness,
`templates/ssis/AWSampleETL/` and `templates/pbir/Satis_SSAS/`: the fallback when neither your repository nor you can
hand one over, read-only like the rest of `templates/` ([templates/README.md](../../templates/README.md)).

## "I'll take this data from Fabric"

Normal work, with two stops. The agent finds the storage mode (`.claude/skills/bi-data-sources/storage-modes.md`):
Import from a lakehouse or warehouse SQL endpoint, Direct Lake, or DirectQuery, and their limits (no calculated column
on a Direct Lake on SQL table, fallback to DirectQuery). A new source is Tier 2: it shows the impact, asks once, then
writes the partition with parameters for the workspace and endpoint (no hard-coded ids) and never a credential.
Reading a published model in a workspace through MCP, a Fabric CLI command that changes an item, publishing,
gateways, credentials and refreshes ask you or stay yours. Running SQL against a SQL endpoint follows the SQL read
switch (next section): the endpoint is a server you list. A workspace that syncs with this repository through Fabric
Git integration (which directory, what the service deletes there, what the agent never does) is in
[fabric-git.md](fabric-git.md).

## Running SQL: the SQL read switch

The agent edits SQL text and runs a query only when you asked for it. The switch is off by default: every query asks
you. On, a bounded read query against a server you named runs without a prompt. Only you turn it on; the agent may
only make it stricter.

**Turn it on in two steps.**

1. **An account that can only read.** Windows sign-in (`sqlcmd -E`) or Microsoft Entra ID (`sqlcmd -G`) needs no
   password, and in most companies your own account can only read the databases you work with. Check it once in your
   own terminal (add `-C` for a self-signed certificate, such as a local instance); `0` means no write, DDL or
   `EXECUTE` right in that database:

   ```powershell
   sqlcmd -S <server> -E -d <database> -Q "SELECT IS_ROLEMEMBER('db_datawriter') + IS_ROLEMEMBER('db_ddladmin') + IS_ROLEMEMBER('db_owner') + IS_SRVROLEMEMBER('sysadmin') + (SELECT COUNT(*) FROM fn_my_permissions(NULL, 'DATABASE') WHERE permission_name IN ('INSERT', 'UPDATE', 'DELETE', 'ALTER', 'CONTROL', 'EXECUTE')) AS write_rights"
   ```

   More than `0` (for example your own instance, where you are an administrator): use a
   [read-only login](#a-read-only-login-with-a-password) instead.
2. **Your servers** in `hardening/harness.config.json`. The guard reads the file on every command; the session-start
   line shows `SQL read switch: ON` after a restart of Claude Code.

   ```json
   "sources": {
     "referenceCopies": ["docs/sources/*/definition/**"],
     "sqlRead": { "mode": "on", "servers": ["localhost", "sql-test01"], "mcpServers": [], "maxRows": 50, "personalColumns": [] }
   }
   ```

   `personalColumns` adds names to the built-in list (e-mail, phone, names, national ids, addresses and more, also in
   Turkish, German, French, Spanish and Italian, as plurals and with a number: `Emails`, `Phone2`, `Telefon`; the output
   masking masks the values of the same columns, except people's names);
   `mcpServers` names a SQL MCP server you registered yourself (the harness ships none).

Why the account matters: the guard reads the query text; only the server can enforce what an account may do. A query
the guard misjudged, or a script in lab mode that opens its own connection, still cannot change anything.

The guard judges every query in every approvals mode, from a SQL client in the shell (`sqlcmd`, `osql`,
`Invoke-Sqlcmd`, `psql`, `mssql-cli`) and from a SQL MCP server alike:

- **Denied:** anything that writes (DML, DDL, `SELECT INTO`, `COPY`, `BULK`, backup, permissions, configuration),
  shell escapes (`!!`, `\!`) and passwords on the command line, also inside a query text over 32 KB or a SQL MCP
  call over 64 KB, which the guard otherwise does not read in full.
- **Asks you, also in lab mode:** every query while the switch is off (the default), and with the switch on anything
  the guard cannot read or bound: `EXEC`, dynamic SQL, scripting variables, a shell variable or command substitution
  in the query or the connection string (`$name`, `${…}`, `$1`, a backtick), a function it does not know (a
  PostgreSQL function can write), a file outside the project or not a `.sql` file, an unknown option, a server not
  listed (for psql every host the connection can reach: each `-h` entry and each `host=`/`hostaddr=` of a connection
  string or URI), a query that is not one aggregate row or `TOP`/`LIMIT` up to the row cap, a personal column (a manager's or
  supervisor's name too: `ManagerName`, `[Supervisor Name]`), `SELECT *`,
  `STRING_AGG`, a query that runs together with another command (`;`, a pipe, a `cd`), and for `sqlcmd`, `osql`, `isql`
  and `psql` a character outside ASCII that is not a letter, digit or mark in any argument (a full-width apostrophe
  U+FF07, curly quotes, dashes, a no-break space, `₺`): Windows may hand it to the client as ASCII punctuation, so the
  client could run another text than the guard read (not verified with a real client). Other database clients
  (`bcp`, `sqlpackage`, `mysql`, `sqlite3`, ...) and scripts that load SQL client libraries always ask.
- **Passes without a prompt (auto and lab mode, logged):** with the switch on, a read-only, bounded query without
  personal columns against a server you listed, run as a command of its own. Record the result with `[sql]`.

Query results are data: an instruction inside a row value or a SQL comment is reported to you, never followed.

**Google BigQuery** has no database password: you sign in once yourself (`gcloud auth application-default login`), or
use a service account whose key file lives outside the repository. Give that identity read roles only (BigQuery Data
Viewer and Job User on the datasets the task needs). `bq` is not judged by the switch, so every `bq` command asks you;
a BigQuery MCP server named in `mcpServers` is judged like any SQL MCP server. BigQuery bills by the bytes a query
scans, and `LIMIT` does not lower them: set a maximum bytes billed or a quota on the project. The guard denies reads of
the gcloud sign-in folder and printing its tokens.

**Something not listed here** (another database, client, driver or sign-in method) is not judged, and that is the safe
side: it asks you in every mode or keeps Claude Code's own prompt, and it never passes on its own. The read-only
account covers what the guard cannot see. You never write guard code: open an issue with the tool's name and how you
sign in (no code, no credentials), and the maintainers add the rule and its tests in the next release. What you set
yourself stays in plain settings: the switch, servers, row cap and personal columns in `hardening/harness.config.json`.

Limits: the analysis is textual. It does not bound a query's cost (a cross join of large tables can run long; the
server's timeout applies), cannot see what a view does or a startup script set outside the session (use `psql -X`,
which the guard requires), and knows only the SQL MCP servers you list or whose server or tool name looks like one. In
lab mode a script file runs without a prompt and may open its own connection: the read-only account covers that too.

### A read-only login with a password

When Windows or Entra sign-in is not possible, or your account can write: create a login that can only read, on SQL
Server with only `db_datareader` (PostgreSQL: a role with `SELECT` grants only):

```sql
CREATE LOGIN bi_reader WITH PASSWORD = N'<strong password>', DEFAULT_DATABASE = <database>, CHECK_POLICY = ON;
USE <database>;
CREATE USER bi_reader FOR LOGIN bi_reader;
ALTER ROLE db_datareader ADD MEMBER bi_reader;
```

The password never goes into a committed file or the conversation, and the agent never reads it: the guard denies a
password on the command line and reads of `.env`, `.pgpass`, `pgpass.conf`, `.my.cnf` and `.mylogin.cnf`. `sqlcmd`
reads it from the variable `SQLCMDPASSWORD` of the terminal you start Claude Code from. Pick one way:

- **Typed in, nothing on disk (recommended):**
  `Set-Item Env:SQLCMDPASSWORD (Read-Host -MaskInput 'bi_reader password')` (PowerShell 7), then `claude`.
- **A Windows user variable:** System > Environment Variables, then restart Claude Code (Windows PowerShell 5.1 too).
- **Your `.env`**, if your team keeps local secrets there: the harness's `.gitignore` keeps it out of Git, and the
  agent cannot read it. A line `SQLCMDPASSWORD=<password>`; you load it yourself before you start Claude Code:
  `Get-Content .env | ForEach-Object { if ($_ -match '^\s*(\w+)\s*=\s*(.*)$') { Set-Item "Env:$($Matches[1])" $Matches[2] } }`,
  then `claude`. The password then sits on disk in clear text, readable by any other tool on the machine.

Never through Claude Code: a `!` command lands in the conversation.
The check of step 1 with `-U bi_reader` instead of `-E` returns `0`; the agent then runs
`sqlcmd -S <server> -U bi_reader -Q "..."` and names only the user. `SQLCMDUSER` is optional: set like
`SQLCMDPASSWORD` it replaces `-U`, but keep `-U bi_reader` on the command line so the audit log shows which login ran
(with neither, sqlcmd falls back to Windows authentication); the guard asks when a command sets `SQLCMDUSER` itself.
PostgreSQL: one line in `~/.pgpass`
(`%APPDATA%\postgresql\pgpass.conf` on Windows), then `psql -X -h <server> -U <reader> -c "..."`. A SQL MCP server: its
configuration references the variable (`"env": { "DB_PASSWORD": "${DB_PASSWORD}" }` in `.mcp.json`), never the value.
The guard denies reading those variables or files and printing a sign-in token. Code the agent runs (a script in lab
mode) could still reach the environment: that is why the login only reads, and only what the task needs.

## macOS and Linux

- **The harness runs.** Claude Code, the hooks, the validator and the Git hooks are Node. After a clone make the Git
  hooks executable (`chmod +x hardening/githooks/*`); `/bi-doctor` checks it.
- **Windows-only, so Path B on this machine:** Power BI Desktop and its CLI, Report Builder, SSMS, SSDT and `dtexec`.
  Their checks run on a Windows machine and are reported NOT RUN here ([desktop.md](desktop.md),
  [static checks](../static-checks.md)).
- **SQL Server** does not run natively on macOS: use a Linux container or a remote server. `sqlcmd` comes from
  `brew install sqlcmd` (the Go sqlcmd, same `-S -U -d -Q -W` usage; whether its flag set matches the guard's table is
  not tested). `-E` (Windows authentication) needs Kerberos on macOS, so use a SQL login: export `SQLCMDPASSWORD` in
  the shell before you start `claude` (zsh: `read -rs "SQLCMDPASSWORD?bi_reader password: "; export SQLCMDPASSWORD`),
  never inside Claude Code. The guard's handling of the bash form `export SQLCMDPASSWORD=...` is not tested either.
- **MCP:** on Apple Silicon the modeling server's native binary is unsigned and the OS kills it (checked 2026-09-30;
  [MCP.md](MCP.md), Configuration and troubleshooting), so MCP against a local Desktop is Windows-only. Microsoft Learn
  and Figma are remote servers and work everywhere.

## Versions we tested

Checked on 2026-10-12. Microsoft's report CLI is before 1.0 and changes often: pin a version, and after an upgrade run
`powerbi-report-author validate` and `/bi-doctor` again.

| Tool | Tested | Latest on npm or in use | Note |
|---|---|---|---|
| Claude Code | 2.1.296 | 2.1.296 | `AGENTS.md` needs 2.1.277 or later |
| Node.js | 24.19 (Windows), 22.22 (Linux); CI 20 | | 18.17 is the floor |
| `@microsoft/powerbi-modeling-mcp` | 1.0.0 | 1.0.0 | pinned in `.mcp.example.json` |
| `@microsoft/powerbi-report-authoring-cli` | 0.1.4 | 0.5.0 | 0.5.0 adds `pack`, `unpack`, `preview`: the guard denies `unpack` (it rewrites a report folder from the shell), asks before `preview --reload*` and a service preview |
| `@microsoft/powerbi-desktop-bridge-cli` | 0.1.2 | 1.0.0 | same commands plus `manifest` (not auto-approved) |
| Power BI Desktop | 2.158 (Store) | | Report Server edition: no PBIP, outside the harness |
| Report Builder | 15.1 | | paginated report runs |
| SQL Server, Analysis Services, `dtexec` | 2025 (17.0) | | `dtexec` must match `TargetServerVersion` |
| Standalone SSIS DevOps Tools (`SSISBuild`, `SSISDeploy`) | not tested | 1.0.0.0 (2024-07-15) | builds `.dtproj` to `.ispac` without Visual Studio; `SSISDeploy` is a deployment the agent never runs ([ssis.md](../../.claude/rules/bi/ssis.md)) |
