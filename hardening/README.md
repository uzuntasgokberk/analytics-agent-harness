# Hardening pack (optional)

The harness in `.claude/` works without this folder. The pack adds **checks the model cannot skip**: Claude Code hooks, Git hooks, a static
validator and a CI template. It is JavaScript because hooks must be programs; it is optional because the core states the same rules as instructions.
Needs Node.js 18.17 or later **on PATH** (the hooks run `node`), no dependencies.

Use it when several people or agents share the repository or it holds anything sensitive. Skip it when Node is not allowed or the organization enforces this centrally.

## Enable

1. Copy this folder into your repository as `hardening/` (or run `node hardening/scripts/install-into.mjs <repo> --hardening`;
   later, `--update` refreshes the files you did not change, using the manifest `.claude/bi-agent-harness.json`).
   `--domain <list>` (comma-separated) names the knowledge domains: only `bi` exists and is the default, any other name
   is refused; the manifest records `"domains": ["bi"]` and `--update` reads it (a manifest without the field counts as
   `bi`). Version 2 adds further domains under `domains/<name>/` in the harness repository without changing any
   installed path.
2. Register the hooks: `install-into.mjs <repo> --hardening --enable-hooks --shared` puts [settings.hooks.json](settings.hooks.json)
   (`permissions` and `hooks`) into `.claude/settings.json`, committed for the team; without `--shared` into
   `.claude/settings.local.json`, this machine only (`--update` re-applies whichever the manifest recorded; on an installed pack use `--update --enable-hooks [--shared]`; once the manifest records `--shared`, `--enable-hooks` alone keeps the team registration in `.claude/settings.json`); or merge the file by hand.
   Each hook is the plain shell string `node hardening/hooks/<script>.mjs`, which Claude Code and GitHub Copilot CLI
   both run from the repository root ([REFERENCE.md](REFERENCE.md), Registration).
3. `git config core.hooksPath hardening/githooks` once per clone.
4. Optional: copy `ci/bi-validate.yml` to `.github/workflows/` and make the job a required check.
5. Restart Claude Code; `/hooks` lists what is active. **Disable:** remove the `hooks` block and `git config --unset core.hooksPath`; nothing else depends on this folder, and a later `--update` leaves the hooks off (`--update --enable-hooks` registers them again). Remove everything: [Remove](../docs/harness/getting-started.md#remove).
6. **GitHub Copilot** (VS Code, Copilot CLI, the cloud agent) runs the same scripts through its own agent hooks:
   `install-into.mjs --enable-hooks` writes [vscode.hooks.json](vscode.hooks.json) to `.github/hooks/bi-harness.json`
   and [copilot-cli.hooks.json](copilot-cli.hooks.json) to `.github/hooks/bi-harness.copilot-cli.json` (or copy them
   yourself). VS Code needs the setting `chat.useHooks` and a trusted workspace. The scripts translate Copilot's tool
   names and input shapes (`hooks/lib/host-vscode.mjs`); subagent scopes do not apply there. Copilot CLI also runs
   the Claude registration of step 2 (it reads `.claude/settings*.json` in a folder you trusted in the CLI): since
   2026-10-08 that registration is the same shell string, so the CLI runs each hook once per file it finds (two or
   three times per call; a model write is recorded once and every copy repeats the verdict given to the same Stop
   event) instead of refusing every tool as its earlier exec form did. Its file
   tools (`view`, `edit`, `create`, `grep`, `glob`) and MCP tools (`<server>-mcp-<tool>`, `<server>-<tool>`) are judged by shape,
   verified with real CLI sessions on probe payloads and with `tests/copilot-claude-dialect.test.mjs`. Start the CLI
   with `--allow-all-tools` and keep the mode `auto`; a deploy typed on the command line asks even in `lab` mode
   (Approvals). VS Code and the cloud agent: verified with synthetic payloads only; in your first session ask for
   `cat .env`, expect the `[bi-harness]` denial, then check `.claude/logs/tool-audit.jsonl` for `"event":"unmapped"`
   (`docs/harness/other-agents.md`).

## Run by hand

```bash
node hardening/scripts/validate.mjs --changed   # or --staged, or no flag for everything
npm --prefix hardening test                          # this pack's tests (in a clone of the harness; the installer leaves them out)
node hardening/scripts/check-hooks.mjs   # names the broken hook file and line when every tool call is blocked (Git Bash and PowerShell)
```

The test command runs the suite with a home folder of its own, so your `~/.claude/settings.json` rules do not change
the verdicts (`node --test` on one file still reads your home).
With no `*.test.mjs` in `hardening/tests/` (an installed copy without local tests) the test command exits with code 3,
not 0: "no tests here", neither a pass nor a failed test, and no validation of your project (that is the validator).

## What it does

| Event | Script | Effect |
|---|---|---|
| SessionStart | `session-start.mjs` | git state, protected-branch warning, Git hooks installed and executable, the artifacts found (PBIP models and reports, Analysis Services TMDL folders including the repository root, paginated reports, SSIS projects; any subset is complete; reference folders, `templates/`, `reports/<report>/source/` and the config's `references`, are not the repository's projects: the banner and the validator's item-folder checks skip them, their files still get the per-file checks), each directory a Fabric workspace syncs (`fabric.directories`, else each directory whose item folders hold `.platform`; the line says which), MCP mode, MCP writes a resumed session never persisted |
| UserPromptSubmit | `user-prompt-guard.mjs` | blocks a message that contains a credential before it reaches the model (in Claude Code; under GitHub Copilot it warns and asks for rotation, see Limits) |
| PreToolUse | `pre-tool-use.mjs` (loads `lib/guard-pre-tool-use.mjs`) | denies, asks or allows (Approvals below): secret and data files, destructive Git/shell, shell writes that would bypass the write guards, Desktop-owned files, credential content, invalid JSON, Markdown over 500 lines, reference copies of shared models, renames, role members, any `Model.bim` edit (TMDL only), risky MCP calls, a DAX query or write on an MCP connection this session never confirmed (guard, fail-closed); under GitHub Copilot CLI (recognised by `COPILOT_CLI`), which runs the guard once per registration, a later copy of the same ask for the same call stays silent and is logged as `repeat` (the Copilot app and VS Code are not probed for it and still prompt per copy unless they set `COPILOT_CLI`) |
| PreToolUse | `agent-scope.mjs` (loads `lib/guard-agent-scope.mjs`) | subagent limits (`agentScopes` in `harness.config.json`): reviewers read-only (shell changes denied in every spelling, MCP read-only), editors write only inside their folders, through Edit/Write; the command takes no arguments |
| PostToolUse | `post-tool-validate.mjs`, `post-tool-redact.mjs` | validates what was written; masks secrets (and PII in the output of any MCP server: text, any value of a field named like personal data such as Email or Phone, also by the Turkish, German, French, Spanish and Italian words of the SQL read switch and its `personalColumns`, never a person's name or a salary, and a whole number of 9 to 15 digits, or of 16 to 19 that passes the card checksum (on older Node too), without a field name of its own; a value nested deeper than 12 levels is judged as its JSON text; a named total, count or amount is never masked for its size; JSON held in a text, such as an MCP answer's text block, is masked as that data, and a slice of JSON by the field names it holds; a Read or shell command of a large MCP answer (any server's) that Claude Code saved to a file is masked as MCP output) in tool output; under VS Code, which documents no output replacement, a warning to the model instead of a guaranteed mask; records the MCP connections confirmed and the model writes not yet persisted (session state) |
| PostToolUseFailure | `post-tool-redact.mjs` | a failed call's error text cannot be replaced by any host: when it holds a secret (or PII where masking covers the tool) the model is told the values may be visible and must not be used (Limits) |
| Stop, SubagentStop | `stop-gate.mjs` | blocks finishing while uncommitted files have validation errors (at most twice; an MCP block counts as the first of the two), and once while MCP writes are only in the model's memory (no change under the model's own folder that declares every object the writes named, a diff that does marks them persisted; a write that named more than the 20 objects it records stays pending, its further names "not checked"; a disconnect, an export to a staging folder or an answer without an explicit success signal does not clear them; the main agent only); on SubagentStop only the editors `bi-tmdl-modeler` and `bi-pbir-editor` (the registration's matcher; under VS Code, which ignores matchers, the script filters by `agent_type`) |
| InstructionsLoaded, SubagentStart, SubagentStop, Notification, SessionEnd, PostToolUse, PostToolUseFailure | `audit-log.mjs` | usage trail in `.claude/logs/`: `tool-audit.jsonl` (tools with `Skill` and `Agent` names; targets and metadata, never contents: an MCP call keeps server, tool, operation, connection, `maxRows` and a query's length and hash; a command keeps its words, with secrets and command-line passwords masked: `mysql -p<password>`, `sqlcmd -P <password>`, `ConvertTo-SecureString '<password>'`, `--password <password>` (and PowerShell's `-Pass`), `user:<password>@host`, `curl -u user:<password>`, `redis-cli -a <password>`, `sqlpackage /TargetPassword:<password>`, `dtexec /De <password>`), `instructions.jsonl` (which rule loaded and why), `sessions.jsonl`, `notifications.jsonl`; `security-events.jsonl` comes from the guards, the masking hook and the prompt guard |

Git hooks (`githooks/`): pre-commit validates what is staged, commit-msg enforces Conventional Commits, pre-push protects `main`.
Validator (`scripts/validate.mjs`): JSON syntax, PBIP structure and bindings, PBIR names, fields a visual uses that its local model does not define (a half-done rename, a typo), DAX references the model lacks (warning), perspective and translation entries (`perspectives/`, `cultures/`) that name a renamed or removed object, paginated reports (RDL: well-formed XML, unique names, references, parameter layout, tablix cells, credentials and placeholder ids, page fit), duplicate measures, credentials, forbidden files (including per-user `*.tmuo`), files of any type inside an item folder that a Fabric Git commit from the service would delete (warning; [Fabric Git](../docs/harness/fabric-git.md)), a `report.json` resource (base theme, custom theme) without its file, a live connection to Analysis Services inside a synced directory (Fabric Git ignores the item) and, in the full scan only, a second copy of a synced item outside the synced directories or a second synced folder of the same type with the same `.platform` `logicalId` under another name (all warnings: Microsoft's supported-items list changes; synced directories below), `.gitignore` gaps, Markdown size.
The full scan and `scripts/release-check.mjs` (in a clone of the harness only; the installer leaves it out) skip the folders in `scan.exclude` of `harness.config.json`, among them Microsoft's vendored references and the Claude desktop app's git worktrees (`.claude/worktrees/**`, each checked when the scan runs inside it). The pre-commit hook still checks a staged file in those folders for credentials; only the structure checks skip them.
`release-check.mjs` also warns, without failing, about a dated marker in Markdown older than 90 days (`checked <date>`, `reviewed <date>`, `Checked against <source> on <date>`, `Verified with <tool> on <date>`, `read <date>`, `probed <date>`, `seen <date>`; `not re-checked on <date>` is none), so a fact taken from Learn or another web page is fetched again before a release; it counts Markdown lines like the validator.
RDL comparison (`scripts/rdl-compare.mjs <old.rdl> <new.rdl>`): proves a re-platformed paginated report changed only its data
sources and datasets (`bi-paginated-report`, `REPLATFORM.md`).
Paths are compared in canonical form, so a project opened through a symlink, a junction or a Windows 8.3 short name gets the same checks.
Hooks are registered as the plain shell string `node hardening/hooks/<script>.mjs` (payload on stdin): Claude Code runs it in Git Bash or PowerShell from the project root, Copilot CLI in PowerShell or bash from the repository root; no `args`, quotes or `${CLAUDE_PROJECT_DIR}`, which the CLI does not substitute ([REFERENCE.md](REFERENCE.md), Registration). Guards fail closed, also when a module fails to load
(the entry scripts load the guard in `try` and exit 2, with the broken file and line in the message; Node's own exit code 1 would let the call through); logging hooks never throw.

Every hook with matcher and failure mode, the decision protocol, subagent scopes, the MCP policy, the security model and debugging: [REFERENCE.md](REFERENCE.md).

## Approvals: auto (default), ask or lab

Most users want the agent to work without a yes/no for every step. `approvals.mode` in `hardening/harness.config.json`
sets how the pack's PreToolUse guard answers:

| Mode | Routine work | Critical actions | Denied actions |
|---|---|---|---|
| `"auto"` (default; also when the key is missing) | runs without a prompt | always ask | always blocked |
| `"ask"` (for a developer who wants to see each step) | Claude Code's normal prompts | always ask | always blocked |
| `"lab"` (a local test session, set by you) | runs without a prompt | run without a prompt, except the floor | always blocked |

- **Lab mode** is for testing on your own machine with test data: SSIS runs, scripts and MCP writes on local
  models (role writes included) run without a prompt; the guard passes Desktop's `open`, never `reload`, and Claude
  Code's ask rules for `open`, `reload` and the screenshots prompt in every mode (below). The **floor** still asks:
  `git push`, publish/deploy, a service
  workspace or remote server, GitHub and Figma writes, a `git switch` or `checkout` to a commit that holds the guard's
  own files differently (or that git cannot compare), commands too deeply nested to analyse (shells beyond three
  levels, `{ }` blocks beyond six levels or 200), text a shell or interpreter would run as code that the guard cannot
  read (a pipe or a here-string), an edit of a file that steers the agent or holds evidence (`roles/*.tmdl`,
  `AGENTS.md`, `hardening/**`), an edit of a model, paginated, SSIS, binding or `.platform` file whose result the guard
  cannot work out, a SQL query the SQL read switch does not pass (below), other database clients and SQL client
  libraries in a script, and a deploy typed on the command line (a `-Deploy` switch, TMSL `createOrReplace`,
  `Invoke-ASCmd`, a
  `deploy*.ps1` script: a project's own deploy script passed as a routine script run before 2026-10-08; one hidden
  inside a script the guard cannot see is still yours to catch). Every deny stays (secrets, force push, protected
  branches, role and workspace members). Writes outside the project keep Claude Code's own prompt; the harness's own
  files and every other critical file ask through the guard's own floor ask, whether or not a settings rule covers
  them. Each lab approval is logged (`"event": "lab-approve"`). Lab mode is for a
  machine where every action is acceptable; never combine it with an agent that prompts for every tool on its own
  (Copilot CLI without `--allow-all-tools`): those prompts carry no judgement and stop being read. Turn it
  on yourself, never through the agent (the guard refuses that): set `"approvals": { "mode": "lab" }`, optionally with
  an `until`, in your editor or in Claude Code with `!` (no hook checks `!` commands). The agent may switch back to
  `"auto"` or `"ask"`. For no Claude Code prompts at all, run the session in a permission mode that accepts edits; the
  pack cannot remove prompts that your own settings `ask` rules require.

Once you change `harness.config.json`, `--update` keeps it and never adds the keys of the shipped
`harness.config.json` it lacks (a key only the pack's defaults have is not listed: the default applies); the update
output lists them (`config: missing <key> (default <value>)`, `config: unknown <key>`), so you can merge them.

### Synced directories (`fabric.directories`)

The project-relative directories Fabric workspaces sync, for example `"fabric": { "directories": ["fabric/Sales-Dev"] }`
(`"."` is the repository root). With a list, the Fabric Git warnings and the session banner look only at item folders
under those directories; `[]` says none is synced. `null` (the default) or a value that is no list of directories:
item folders that hold `.platform` count, which Desktop writes on a project save too, so those messages are reminders.
Every message names its source. Only you edit it (the guard denies the agent); record workspace and branch in
`docs/conventions.md` ([Fabric Git](../docs/harness/fabric-git.md)).

### The SQL read switch (`sources.sqlRead`)

`hooks/lib/sql-read.mjs` judges every query of `sqlcmd`, `osql`, `isql`, `mssql-cli`, `Invoke-Sqlcmd` and `psql`, and of
SQL MCP servers, in every approvals mode. Writes (DML, DDL, `SELECT INTO`, `COPY`, `BULK`, backup, permissions,
configuration procedures), shell escapes (`!!`, `\!`) and passwords on the command line are denied. `"mode": "off"`
(the default): every query is a floor ask. `"mode": "on"` (only you set it; the guard denies the agent any widening):
a query passes without a prompt in `auto` and `lab` (and is logged as an approval) when it names a server listed in
`servers`, every statement is a read (a statement may also write a temporary table of the session, `#t`, or a table
variable, `@t`: `INSERT`, `UPDATE`, `DELETE`, `TRUNCATE`, `CREATE TABLE`, `DROP TABLE` and `SELECT … INTO #t`; a global
`##t` table is shared with every session, so a write to it is denied), it is bounded (one aggregate row, `COUNT(DISTINCT x)` included but not `SELECT DISTINCT`, or
`TOP`/`LIMIT`/`FETCH FIRST` up to `maxRows`, default 50; a `GROUP BY` needs one) and it names no personal column (the
built-in list, also as a plural or with a number (`Emails`, `Phone2`), a manager's or supervisor's name (`ManagerName`) and in Turkish, German, French, Spanish and Italian
(`Telefon`, `Vorname`, `[Müşteri Adı]`), plus `personalColumns`, which also count for DAX queries through the modeling MCP
server) and runs as a command of its own (not next to another command, in a pipeline or a nested shell).
Everything the guard cannot read is a floor ask: `EXEC` and procedures, dynamic SQL, a function outside the built-in
list, a four-part (linked-server) name, sqlcmd `:r`, `:connect`, `$(...)` and `-q`, psql meta-commands and variables,
psql without `-X`, a psql connection whose hosts are not all listed (each `-h`/`--host` entry, each `host=` and
`hostaddr=` of a conninfo, each host of a URI and its `?host=`/`?hostaddr=` parameters; a `service=`, a conninfo or URI
the guard cannot read, a `%` in a URI's hosts or parameters, a character outside ASCII in a connection argument), a query file outside the project or not a `.sql` file, a file read after a `cd`, an unknown option,
a startup or server variable (`SQLCMDINI`, `PGHOST`, ...) or any variable or `env` set in front of the client (`PATH=`, `LD_PRELOAD=`), a shell or PowerShell expansion in a query, a connection string
or a psql conninfo (`$name`, `${…}`, `$env:`, `$1`, a backtick, `%NAME%`), a psql dollar quote (`$$`, `$tag$`) outside a
single-quoted command, a password prompt (`-W`, `--password`), for `sqlcmd`, `osql`, `isql` and `psql` a character
outside ASCII that is not a letter, digit or mark in any argument (U+FF07, curly quotes, dashes: a Windows code page may
hand it to the client as ASCII; a query is also judged as such a conversion would read it), a text over 32 KB without a write (a longer text is
searched only for writes, which are denied). Each dialect's quoting is read its own
way (T-SQL batches split at `GO` first; PostgreSQL `E''` only and backslash escapes everywhere; for a SQL MCP server
also MySQL) and the bash reading of `\\` inside double quotes too; the strictest verdict wins. Other database clients
(`bcp`, `sqlpackage`, `mysql`, `sqlite3`, ...) and the SQL client libraries in a script are floor asks. SQL MCP servers:
those in `mcpServers` get the same judge on every SQL-named field and every SQL-looking string; a call over 64 KB is
searched only for writes (denied; up to 8 MB) and otherwise asks; a write verb in the tool
name is denied (names are read word by word: `insertRows`, `insert_rows` and `rows.insert` are one name); a call without SQL text passes only for a describing tool (`list_tables`, `describe_table`); an unlisted
server whose server or tool name looks like a database always asks. The user turns the switch on only for an account
that can only read: the guard reads text, the server enforces. Limits: textual analysis; a query's cost is not
bounded; a view's body is not seen. Tests: `tests/sql-read.test.mjs` (a security review's cases in round 3) and
`tests/round2-sql.test.mjs`.

- **Routine** (auto answers `allow`): edits of model, report, paginated report and docs files in the project (`*.tmdl`
  except the critical ones below, PBIR/PBIP JSON, `.platform` (a change of an existing `config.logicalId` or `metadata.type` is Tier 2 and asks), `definition.pbir`/`.pbism`, `*.pbip`, `*.rdl`, `*.md`,
  `*.dax`, `*.sql`, SSIS `*.dtsx` that keep their connections and object ids); commands that look at files inside the project (judged
  from the shell's real directory; no wildcards or recursion for programs that read contents, no listing piped into a
  reader, no option that writes or runs a program, no variable set in front of the command, no parenthesized expression
  such as `gc ('.e'+'nv')`, no PowerShell provider path (`Env:`, `HKLM:\`, `Environment::`, `FileSystem::`), a comma list
  judged item by item, `cd` only to one folder inside the project), local
  Git (`status`, `diff`, `log`, `add`, `commit`, `switch`, also with `-C` to a folder inside the project; not `--orphan`, `git grep -O`, a forced or abbreviated forced
  option, or `--git-dir`/`--work-tree`/`--namespace`; a file named by `git blame --contents`, `commit -F`, `--file`, `-t`,
  `--template` or `--pathspec-from-file` only inside the project; `git switch` only to a commit that holds the guard's
  files (`hardening/hooks`, `hardening/scripts`, `hardening/githooks`, `hardening/harness.config.json`,
  `.claude/settings.json`, `.github/hooks`) as HEAD does; `git diff` never with `/dev/null`, `NUL` or a path outside the
  project, which run as `--no-index` and are denied), the pack's own checks (the validator, `rdl-compare`,
  the git hook runner, the tests and the hooks, with file arguments inside the project; `check-hooks.mjs` with no
  argument; `npm --prefix hardening test` and `run validate[:name]`, script arguments only after `--`), `dtexec /Validate`
  of a package whose servers are all this machine, the Power BI
  Desktop CLI (not `reload`; screenshots only with `desktop.screenshots` `on`) and report CLI; and the guard's own in-repository asks
  (a local MCP connection; on a named local connection, ordinary model edits: measures, columns, tables, hierarchies,
  perspectives, cultures, descriptions and format strings). Each
  auto-approved ask is logged in `.claude/logs/security-events.jsonl` (`"event": "auto-approve"`). Script files and
  inline code that writes files or starts programs are never approved in auto: Claude Code's own flow decides (lab runs them).
  `settings.hooks.json` allows the npm checks only as the exact forms and their `-- *` forms, and `check-hooks.mjs`
  only without an argument, in both shells; an install made earlier keeps its old `npm --prefix hardening test *` rules
  (the installer adds rules and never removes them), and the guard's own ask covers the look-alike forms there.
- **Desktop screenshots** (`desktop.screenshots`): `ask` (default, also a missing or unknown value) asks in every mode,
  lab included; `off` denies (the report CLI's `preview` too, since it renders pages); `on` makes `powerbi-desktop
  screenshot`/`screenshot-all` routine, and auto and lab log each capture. Only you widen it; the agent may make it
  stricter. A screenshot shows the data on the page: in a company keep `ask` or `off`, set `on` on a machine with test
  data. An `--output`/`--output-dir` inside the repository is denied in every mode, also after a `cd` of the same
  command line (`exports/` and folders outside follow the switch); after a `cd` the guard cannot follow (a variable, `cd`
  alone, `popd`, a missing folder) a relative output asks and auto mode never answers.
  `npx @microsoft/powerbi-desktop-bridge-cli` and `npx @microsoft/powerbi-report-authoring-cli` are judged
  as `powerbi-desktop` and `powerbi-report-author`, routine only with `--no` (an installed copy; without it npx
  downloads the package); another package or an option such as `--registry` next to them asks.
- **Critical** (asks in both modes): publish, deploy and processing (Fabric CLI, the Power BI, Reporting Services and
  Analysis Services cmdlets, `rs.exe` scripts, pbi-tools, Tabular Editor, the SSIS and Analysis Services deployment
  utilities), `git push`, a service workspace or any server other than this
  machine, MCP writes on an unnamed or remote connection, an MCP query or write on a connection the session never
  confirmed (`lab` runs it), Tier 2 changes (AGENTS.md; `lab` runs them): renames and
  deletes (TMDL declarations, tab or space indented, hierarchy levels included; MCP), relationships (`relationships.tmdl`,
  a relationship added, removed, renamed or edited in any TMDL file, MCP), a
  change of a report's `datasetReference` in `definition.pbir`, reference-copy edits, and on a local MCP connection
  partition (also a partition source, M expression, data source or connection string named in a table or model write),
  Power Query expression, parameter, refresh, refresh-policy, storage-mode and database writes and any
  operation the guard does not classify as ordinary; database, Analysis Services and SSIS clients, row-level or
  personal-column DAX, GitHub and Figma writes, `git apply`, running an SSIS package or deploying it to SSISDB, Desktop
  `reload`, other `find` actions that change files (auto mode never approves them), a git file option or a
  harness-script argument outside the project, a variable set in front of a SQL client, an npm command with options after
  the script name; edits of row-level security roles, `dataSources.tmdl`, `expressions.tmdl`, `database.tmdl`,
  `modelReference.json`, SSIS connections and protection levels, `*.dtproj`, `*.params`, `*.conmgr`, `*.dtsConfig`, and of what steers
  the agent (`AGENTS.md`/`CLAUDE.md`/`GEMINI.md` in any folder, `.claude/**`, `.git/**`, `.githooks/**`, `hardening/**`,
  `.mcp*.json`, `.github/**`, `.cursor/**`, `.vscode/**`, `.gitignore`, `.gitattributes`, `package.json` and
  `package-lock.json` at the root, `docs/harness/**`, `docs/conventions.md`, `docs/static-checks.md`,
  `docs/test-packs.md`) or carries authority and evidence (`docs/sources/README.md`, the registry that decides ownership;
  `docs/tests/expected-values.md`, the user's control figures). File edits that change where data comes from are Tier 2
  too: in any TMDL file a partition's `mode`, `source`, `dataSource` or `queryGroup` (a new or removed partition counts;
  a calculated table's DAX does not), a `refreshPolicy`, a named `expression` or the model's `defaultMode`, and in
  `.rdl`, `.rds` and `.rsd` files a data source's connection properties or shared reference (with the default and
  available values of a report parameter its ConnectString reads, as `Parameters!X`, `Parameters("X")` or
  `Parameters.Item("X")` in any letter case, through other parameters up to five levels, and the report's `<Code>` when
  the ConnectString calls `Code.`), a dataset's `DataSourceReference`, `SharedDataSetReference` or `DataSourceName` (which source a dataset reads), or a data source
  or dataset added or removed (`CommandText` stays routine). Masked JSON text keeps every digit of its unmasked numbers
  on Node 21 or later; on older Node such numbers may be rounded and the event lists `json-text-precision-lost`; an
  integer of 16 digits or more is still judged by its own digits (a card's checksum).
  In Claude Code's plan mode auto and lab approve nothing; a read-only Power BI MCP operation and a bounded DAX query on a
  confirmed connection still get the guard's `allow`, which Claude Code honours there only for a call it counts as
  read-only (Claude Code docs, Permissions, checked 2026-10-19). Anything the guard does not recognise as routine keeps
  Claude Code's own permission flow, and every `ask` rule in `.claude/settings.json` (installs, `gh`, `az`, `fab`, `rm`,
  history-changing Git, `npx`, Desktop's `open`, `reload` and screenshots, the binding files) prompts whatever the
  guard answers (below). Under
  GitHub Copilot, which does not read those rules, the guard asks itself where an ask rule matches (installs, `gh`, `az`,
  `fab`, `rm`, `Remove-Item`) and denies where a deny rule matches.
- **Denied** (both modes): secret and data files (including the credential stores of git, the cloud and tool CLIs, SSH,
  GPG and PuTTY: `.git-credentials`, `~/.kube/config`, `.ssh/`, `*.ppk`), commands that print a sign-in token (`gh auth
  token`, `gh auth status --show-token`/`-t`, `az account get-access-token`, `gcloud auth print-access-token`),
  PowerShell reads of environment variables
  (`Get-ChildItem env:`, `Get-Content Env:X`, `Set-Location Env:`, `Get-ChildItem Environment::`), credentials in files, role and workspace membership (TMDL role
  members, `Add-RoleMember`, `Add-PowerBIWorkspaceUser`, `Grant-Rs*`), `Model.bim` edits, destructive
  commands (git options in any abbreviation git accepts, `--orphan`, `git grep -O`, repointing options, and git
  redirects into guarded files, `templates/` or a report's `source/`; `find -delete`, `-exec` or `-fprint` on `.git`,
  `.claude`, `.githooks`, `.github`, `hardening`, a reference folder or outside the project; `find -exec sed -i`/`perl -i`;
  a CLI `--out`/`--output` to a guardrail file), any change to the hooks' logs and session state in `.claude/logs/`
  (shell writes, copies, moves and deletes, Edit/Write; reading them stays open), network transfers (also from inline `node -e`/`python -c` code and .NET network classes), `templates/`,
  a report's `source/` folder and every folder listed in `references` of `harness.config.json` (project-relative
  prefixes, e.g. a lab's `setup/`): Edit/Write, shell writes and deletes, writes through a variable in a command that
  names such a folder, and inline code that writes files and names one; a script file's writes stay out of sight, so
  keep interpreters (`node *`) out of the settings allow list. Also SSIS build outputs (`*.ispac`, `bin/`, `obj/`), `*.dtproj.user`,
  Script Task binaries, and a new file inside a `*.SemanticModel/`, `*.Report/` or `*.PaginatedReport/` folder that is not
  part of the item definition, or a second `.rdl` in a paginated report folder (a service commit deletes it).
- **Always ask** (both modes; an explicit hook `ask`, so it does not depend on a settings rule, and the hook returns it
  whatever the permission mode, `acceptEdits` included, and on every host, Copilot included): SSIS `.dtproj`,
  `.params`, `.conmgr` and `.dtsConfig` files, a package edit that changes a connection (its connection string, the
  connection manager a component or an Execute SQL task uses, a connection property expression, or the value of a
  package parameter or variable such an expression reads), the protection level or an existing `DTS:DTSID` or `refId`,
  and a change of an existing `config.logicalId` or `metadata.type` of a `.platform` file (`lab` runs these). The other
  critical files above, and an edit of a model, paginated, SSIS, binding or `.platform` file whose result the guard
  cannot work out (an old text not found as written, a Copilot `insert_edit_into_file`), ask the same way and `lab`
  leaves them to you too. Claude Code docs (Hooks, checked 2026-10-06): a hook's `ask` prompts, also in its auto mode; other permission
  modes are not described.
- Claude Code evaluates settings `deny` and `ask` rules whatever a hook returns, in every permission mode (Claude Code
  docs, Permissions, "Precedence among rules, hooks, and mods", checked 2026-10-19). The guard still never answers
  `allow` when a settings deny rule matches, and answers it for a settings ask rule only in the routine categories above
  (Desktop's `open` and, with `on`, its screenshots; `npx --no` of the two CLIs; edits of `.platform`,
  `definition.pbir`, `definition.pbism` and `*.pbip`): Claude Code still prompts for those; the guard's approval
  decides only under Copilot, which reads no settings rules. `tests/settings-rules.test.mjs` checks every rule of
  `.claude/settings.json`.
- `until` (optional): an ISO date and time with a time zone (`2026-10-07T18:00:00+03:00` or `...Z`) ends auto at that
  time; the session start message says when auto is off and why.
- Only you widen it: the guard denies the agent switching `"ask"` to `"auto"`, deleting an `"ask"` setting, removing
  `until` or moving it later, writing `bypassPermissions` or `disableAllHooks` into a settings file, and removing a pack
  hook from it or changing how it runs (its event, matcher, command, type, timeout or flags; adding hooks passes); the
  same holds for the pack's entries in `.github/hooks/*.json`, and for `env.NODE_OPTIONS`, `env.PATH` and `env.PATHEXT`
  in the settings. A `mode` that is not text (`null`, `0`, a list), or an `approvals` that is not an object
  (`"approvals": "auto"`), reads as `"ask"`, so writing it switches to ask. The agent may switch to
  `"ask"` or end auto earlier.
- Auto changes prompts, not the agent's rules: it still asks for decisions it cannot infer, including a Tier 2 change the
  request did not name (AGENTS.md), and it never publishes, deploys, holds credentials or disables hooks.
- Without this pack, Claude Code's permission modes do the same job more coarsely: `"permissions": { "defaultMode":
  "acceptEdits" }` in project settings, or its classifier-based `auto` mode (user-level settings only).

## Limits

A safety net, not a sandbox: shell analysis is textual (a command built at run time, or a path computed in a script, is
not visible to it; a `>` inside a quoted string is read as a redirect, except in the words the guard treats as text (a
commit message, a tag message, a search pattern), and its target is judged like a real one, which fails closed), masking
runs after the tool has executed, local Git hooks can be skipped, static checks do not
compile DAX. A hook that times out does not block the call, and neither does a hook that cannot start: with no `node`
on PATH, or a Node too old to parse the hooks, every call runs unguarded (Claude Code docs, Hooks). The installer
refuses the pack without Node 18.17+ on PATH; after a Node change, check that `/hooks` still lists the hooks and that
`npm --prefix hardening test` passes. The permission rules from `settings.hooks.json` still apply then. The PreToolUse guards
(`pre-tool-use.mjs`, `agent-scope.mjs`) fail closed. The other six hooks fail open by design: a load error exits 1 and a
runtime error is printed to stderr, neither blocks, and neither leaves an audit row. The prompt guard
(`user-prompt-guard.mjs`) and output masking (`post-tool-redact.mjs`) must not block every message, so a broken file means
no credential check on prompts and no masking until it is fixed; a Stop gate (`stop-gate.mjs`) that failed closed would
mean "do not stop", so a crash would keep the agent running, and a broken one lets it finish unchecked; an audit log
(`audit-log.mjs`) that failed closed would block all work on a logging error, and a broken one records nothing; the
post-edit validator (`post-tool-validate.mjs`) and the session banner (`session-start.mjs`) only inform.
`node hardening/scripts/check-hooks.mjs` names the broken file. In `bypassPermissions` mode
the `Edit(/hardening/**)` ask rule of `.claude/settings.json` still prompts before edits of the pack's own files (Claude
Code docs, Permission modes, "Actions no mode auto-approves", checked 2026-10-19); without that rule only review
protects the hook code.
Without the pack the core still denies secret reads and destructive commands with permission rules (forced `git switch`, `git add -f` and `git commit --no-verify` among them, and the git reads that write a file, run a configured program or compare a file outside the repository: `--output`, `--no-index`, `--ext-diff`, `--textconv`, a `git diff` path such as `/x`, `C:/x`, `~/x` or `../x`; as text rules they miss `git switch -C`, a flag inside a combined option such as `git add -Af`, the abbreviations git accepts (`--no-verif`, `--discard`), `--orphan` and an outside path the text does not show, which only the pack denies). Add Claude Code's `sandbox`, its
[managed settings](https://code.claude.com/docs/en/settings) (an administrator's file the user cannot override) and a
required CI check for anything that must not slip through. A credential found anywhere: rotate it; deleting the line does not clean Git history.
Under GitHub Copilot a PreToolUse verdict blocks and a Stop block sends the agent back for another turn (the CLI's
`agentStop` reads `decision: block` with the reason as the next prompt; VS Code reads its nested Stop block; both follow
GitHub's reference and are not yet seen in a live session); a PostToolUse block reaches the model as context; under
VS Code masking is a warning: the masked output is sent, but the model may see the values and is told not to use them; subagent
scopes do not apply, so the shell and file guards, the pre-commit hook and CI are the net there; the VS Code
and cloud-agent hooks are verified against the documented protocols and the published tool schemas only, and a tool
the translation does not know is logged as `unmapped` and gets no verdict, unless a text argument names a command or a
local file (`command`, `cmd`, `script`, `commandLine`, `file_path`, `file`, a `uri` that is `file:` or has no scheme),
which asks once per call like the guard's other asks (a `url` gets no verdict, like a web fetch); a call whose arguments
cannot be read asks. The prompt guard cannot hold a message back under Copilot: GitHub's hooks reference
treats exit 2 on a submitted prompt as a warning (the run continues) and drops the output of a config-file
userPromptSubmitted hook, and VS Code's reference does not document withholding a prompt; a credential typed there
counts as sent (the hook says so and asks for rotation); the deploy reminder never reaches the model under Copilot (VS
Code shows it to the user as a `systemMessage`, the CLI shows nothing). Known gaps, kept: the error text of a failed
tool call (PostToolUseFailure) reaches the model unmasked, since no host lets a hook replace it: the masking hook adds a
warning that the error held sensitive values (Claude Code and the Copilot CLI; VS Code has no such event) and the audit
log masks its error row; a key whose last word is password in camelCase, with
a prefix or on a YAML line is masked only when its value holds a digit, a sign or a space (`password=<word>` and
`"password": "<word>"` mask any word); an unquoted value with spaces is masked whole only when another `;key=` pair
follows it. Masking is textual: a private key is masked across lines, from its BEGIN marker to its END marker or
the end of the text, but any other secret split across two lines is not masked (the prompt guard and the
validator see the file, not the split); a Grep with no glob relies on ripgrep skipping hidden and ignored files, while
an explicit glob is judged by what it can match, because `--glob` overrides those filters (a bare `*`, `**/*` or
`dir/**` is denied: name the file type) and a wildcard in the name of a visible secret file (`*credentials.json`) stays
open, and so does a Grep over the folder `~/.kube` or `~/.docker`; the file itself stays denied to Read and the shell. Publish, deploy and processing from the
shell are floor asks, not denies: `AGENTS.md` forbids them to the agent, and the ask keeps you in the loop when you
choose to run one through the session; membership changes are denied outright.
The guard spells out Windows 8.3 short names in a command by comparing each word's project-relative spelling before and
after resolving, so a project folder written as a short path (a GitHub Windows runner's `RUNNER~1` profile) or reached
through a symlink or junction no longer turns `HEAD~1` into a file path. The file words of a reader (`cat`, `head`, `grep`,
`Get-Content`, `Select-String`, a pager) are also judged as the shell opens them: a link or a `..` after one that reaches a
secret or data file is denied like its plain name, and one that leaves the project is not routine.

**Slow machines.** Two environment variables give the hooks more time where git or Node start slowly (a CI runner):
`BI_HARNESS_GIT_TIMEOUT_MS`, the time one git call of a hook may take (default 3000, at most 10000), and
`BI_HARNESS_CHECK_BUDGET_MS`, how long a guard that cannot load looks for the broken file before it blocks with the load
error alone (default 5000 for the PreToolUse guard, at most 12000; 3000 and at most 6000 for the subagent scope guard).
Each only raises its default. The git timeout is per call, and all git calls of one hook share 12 s (60 s in the Stop
gate): a hung git holds a hook that long at most, however many calls it makes, and a call that finds the time spent
answers like a failed git (the guard then asks or denies; the Stop gate keeps the rule it applies without Git). Both
stay below the hook timeouts (20 s for the guard and the session start, 90 s for the Stop gate), because
[a hook that times out does not block the call](#limits). `npm --prefix hardening test` sets 10000 and 12000 unless
they are set.

**If every tool call is blocked** with "The PreToolUse guard could not load": a hook file has an error, and the guard
fails closed by design. The message names the broken file and line (`hardening/hooks/lib/policy.mjs:20: SyntaxError: ...`).
To check the whole pack, run `node hardening/scripts/check-hooks.mjs` from your own terminal (Git Bash or PowerShell, or
`!` in Claude Code, which no hook checks): it runs `node --check` on every hook file one by one, loads each module of
`hooks/lib` and checks that every name an entry script imports is exported, prints the failure as `file:line: message` and exits 1 (0 when the pack is clean). Fix that file (or
`git checkout -- hardening/hooks`), then continue the session.

## Changing the pack

Logic goes in `hooks/lib/`, entry scripts stay thin; every behaviour change needs a test in `tests/` (build fake secrets at run time); register new hooks in `settings.hooks.json`.
