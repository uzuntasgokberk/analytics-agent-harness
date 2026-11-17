# Hardening pack (optional)

The harness in `.claude/` works without this folder. The pack adds **checks the model cannot skip**: Claude Code hooks, Git hooks, a static
validator and a CI template. It is JavaScript because hooks must be programs; it is optional because the core states the same rules as instructions.
Needs Node.js 18.17 or later **on PATH** (the hooks run `node`), no dependencies.

Use it when several people or agents share the repository or it holds anything sensitive. Skip it when Node is not allowed or the organization enforces this centrally.

## Enable

1. Copy this folder into your repository as `hardening/` (or run `node hardening/scripts/install-into.mjs <repo> --hardening`;
   later, `--update` refreshes the files you did not change, using the manifest `.claude/bi-agent-harness.json`).
   A symbolic link or a junction at any path the installer manages (`CLAUDE.md -> AGENTS.md`, `.claude/skills -> ../skills`),
   pointing inside the repository or outside it, stops it with exit 2 and nothing changed: replace the link by the file or
   folder itself, or install into another folder.
   `--domain <list>` (comma-separated) names the knowledge domains: only `bi` exists and is the default, any other name
   is refused; the manifest records `"domains": ["bi"]` and `--update` reads it (a manifest without the field counts as
   `bi`). Version 2 adds further domains under `domains/<name>/` in the harness repository without changing any
   installed path.
2. Register the hooks: `install-into.mjs <repo> --hardening --enable-hooks --shared` puts [settings.hooks.json](settings.hooks.json)
   (`permissions`, `hooks` and `env`) into `.claude/settings.json`, committed for the team; without `--shared` into
   `.claude/settings.local.json`, this machine only (`--update` re-applies whichever the manifest recorded; on an installed pack use `--update --enable-hooks [--shared]`; once the manifest records `--shared`, `--enable-hooks` alone keeps the team registration in `.claude/settings.json`); or merge the file by hand.
   Each hook is the plain shell string `node hardening/hooks/<script>.mjs`, which GitHub Copilot CLI runs from the
   repository root and Claude Code from the session's current folder, the root until a `cd` moves the main session.
   The `env` entry `CLAUDE_BASH_MAINTAIN_PROJECT_WORKING_DIR=1` keeps it there, merged without replacing a value of
   yours, and the `cd` guard is the fallback ([REFERENCE.md](REFERENCE.md#registration), with what is measured).
3. `git config core.hooksPath hardening/githooks` once per clone.
4. Optional: copy `ci/bi-validate.yml` to `.github/workflows/` and make the job a required check.
5. Restart Claude Code; `/hooks` lists what is active. **Disable:** remove the `hooks` block and `git config --unset core.hooksPath` (the `env` entry of step 2 may stay: it only returns the shell tools to the start folder after each command); nothing else depends on this folder, and a later `--update` leaves the hooks off (`--update --enable-hooks` registers them again). Remove everything: [Remove](../docs/harness/getting-started.md#remove).
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
| SessionStart | `session-start.mjs` | git state, protected-branch warning, Git hooks installed and executable, the artifacts found (PBIP models and reports, Analysis Services TMDL folders including the repository root, paginated reports, SSIS projects; any subset is complete; reference folders, `templates/`, `reports/<report>/source/` and the config's `references`, are not the repository's projects: the banner and the validator's item-folder checks skip them, their files still get the per-file checks; above 20 models, reports or tabular folders, one line per kind counts them per folder (the 10 largest) and names only the flagged ones, at most 3 of each: TMSL, `unappliedChanges.json`, reference copies, and the number holding `cache.abf`; the banner stays under 9,000 characters with the lines to act on first, [REFERENCE.md](REFERENCE.md#hooks)), each directory a Fabric workspace syncs (`fabric.directories`, else each directory whose item folders hold `.platform`; the line says which), MCP mode, MCP writes a resumed session never persisted |
| UserPromptSubmit | `user-prompt-guard.mjs` | blocks a message that contains a credential before it reaches the model (in Claude Code; under GitHub Copilot it warns and asks for rotation, see Limits) |
| PreToolUse | `pre-tool-use.mjs` (loads `lib/guard-pre-tool-use.mjs`) | denies, asks or allows (Approvals below): secret and data files, destructive Git/shell, a Bash or PowerShell `cd` that would leave Claude Code's main session in a project subfolder (every hook runs from the session's folder and could not find its script there, so the guards would stop; Bash returns with a subshell `(cd x && ...)`, PowerShell with `Push-Location x; try { ... } finally { Pop-Location }`; no claim while `CLAUDE_BASH_MAINTAIN_PROJECT_WORKING_DIR` is set, which the installer writes into the settings `env` with this guard as the fallback, in a subagent or under GitHub Copilot: [REFERENCE.md](REFERENCE.md#registration)), shell writes that would bypass the write guards, Desktop-owned files, credential content, invalid JSON, Markdown over 500 lines, reference copies of shared models, renames, role members, any `Model.bim` edit (TMDL only), risky MCP calls, a DAX query or write on an MCP connection this session never confirmed (guard, fail-closed); under GitHub Copilot CLI (recognised by `COPILOT_CLI`), which runs the guard once per registration, a later copy of the same ask for the same call stays silent and is logged as `repeat` (the Copilot app and VS Code are not probed for it and still prompt per copy unless they set `COPILOT_CLI`) |
| PreToolUse | `agent-scope.mjs` (loads `lib/guard-agent-scope.mjs`) | subagent limits (`agentScopes` in `harness.config.json`): reviewers read-only (shell changes denied in every spelling, MCP read-only), editors write only inside their folders, through Edit/Write; the command takes no arguments |
| PostToolUse | `post-tool-validate.mjs`, `post-tool-redact.mjs` | validates what was written; masks secrets (and PII in the output of any MCP server: text, any value of a field named like personal data such as Email or Phone, also by the Turkish, German, French, Spanish and Italian words of the SQL read switch and its `personalColumns`, never a person's name or a salary, and a whole number of 9 to 15 digits, or of 16 to 19 that passes the card checksum (on older Node too), without a field name of its own; a value nested deeper than 12 levels is judged as its JSON text; a named total, count or amount is never masked for its size; JSON held in a text, such as an MCP answer's text block, is masked as that data, and a slice of JSON by the field names it holds; a Read or shell command of a large MCP answer (any server's) that Claude Code saved to a file is masked as MCP output) in tool output; under VS Code, which documents no output replacement, a warning to the model instead of a guaranteed mask; records the MCP connections confirmed and the model writes not yet persisted (session state) |
| PostToolUseFailure | `post-tool-redact.mjs` | a failed call's error text cannot be replaced by any host: when it holds a secret (or PII where masking covers the tool) the model is told the values may be visible and must not be used (Limits) |
| Stop, SubagentStop | `stop-gate.mjs` | blocks finishing while uncommitted files have validation errors (at most twice; an MCP block counts as the first of the two), and once while MCP writes are only in the model's memory (no change under the model's own folder that declares every object the writes named, a diff that does marks them persisted; a write that named more than the 20 objects it records stays pending, its further names "not checked"; a pending write past the 200 the state keeps, and a name the record keeps out of it (one that reads like a credential, or over 128 characters), count as unchecked until an export or a save into the model folder; a disconnect, an export to a staging folder or an answer without an explicit success signal does not clear them; the main agent only); on SubagentStop only the editors `bi-tmdl-modeler` and `bi-pbir-editor` (the registration's matcher; under VS Code, which ignores matchers, the script filters by `agent_type`) |
| InstructionsLoaded, SubagentStart, SubagentStop, Notification, SessionEnd, PostToolUse, PostToolUseFailure | `audit-log.mjs` | usage trail in `.claude/logs/`: `tool-audit.jsonl` (tools with `Skill` and `Agent` names; targets and metadata, never contents: an MCP call keeps server, tool, operation, connection, `maxRows` and a query's length and hash; a command keeps its words, with secrets and command-line passwords masked: `mysql -p<password>`, `sqlcmd -P <password>`, `ConvertTo-SecureString '<password>'`, `--password <password>` (and PowerShell's `-Pass`), `user:<password>@host`, `curl -u user:<password>`, `redis-cli -a <password>`, `sqlpackage /TargetPassword:<password>`, `dtexec /De <password>`), `instructions.jsonl` (which rule loaded and why), `sessions.jsonl`, `notifications.jsonl`; `security-events.jsonl` comes from the guards, the masking hook and the prompt guard |

Git hooks (`githooks/`): pre-commit validates what is staged, commit-msg enforces Conventional Commits, pre-push protects `main`. The staged check reads a file from disk when Git reports its working copy equal to the index, and from the index otherwise (unstaged edits, deletions, skip-worktree and assume-unchanged entries); only a regular file is read from disk: a symlink, a directory or a missing path comes from the index, so a tracked link is judged by its link text and never followed outside the repository.
Validator (`scripts/validate.mjs`): JSON syntax, PBIP structure and bindings, PBIR names, fields a visual uses that its local model does not define (a half-done rename, a typo), DAX references the model lacks in measures and calculated columns (warning), relationship ends (`relationships.tmdl`) that name a table or column the model does not define (error: Desktop does not load the model, Analysis Services does not deploy it; no claim about a column when the table's columns could not be read: none was read, or its members are indented with spaces, which the per-file check already warns about), perspective and translation entries (`perspectives/`, `cultures/`) that name a renamed or removed object, paginated reports (RDL: well-formed XML, unique names, references, parameter layout, tablix cells, credentials and placeholder ids, page fit), duplicate measures, credentials, forbidden files (including per-user `*.tmuo`), files of any type inside an item folder that a Fabric Git commit from the service would delete (warning; [Fabric Git](../docs/harness/fabric-git.md)), a `report.json` resource (base theme, custom theme) without its file, a live connection to Analysis Services inside a synced directory (Fabric Git ignores the item) and, in the full scan only, a second copy of a synced item outside the synced directories or a second synced folder of the same type with the same `.platform` `logicalId` under another name (all warnings: Microsoft's supported-items list changes; synced directories below), `.gitignore` gaps, Markdown size. It scans the text of a `.envrc` that git tracks, has staged or would add (untracked and not ignored); one that git ignores, or any when git cannot answer, is not read (audit 2026-11-17). A tracked `.envrc` with a credential, or an untracked one that git does not ignore, blocks the Stop gate (`validate --changed`) on a file the agent may not read or edit, so you have to fix it.
The full scan and `scripts/release-check.mjs` (in a clone of the harness only; the installer leaves it out) skip the folders in `scan.exclude` of `harness.config.json`, among them Microsoft's vendored references and the Claude desktop app's git worktrees (`.claude/worktrees/**`, each checked when the scan runs inside it). The pre-commit hook still checks a staged file in those folders for credentials; only the structure checks skip them.
`release-check.mjs` also warns, without failing, about a dated marker in Markdown older than 90 days (`checked <date>`, `reviewed <date>`, `Checked against <source> on <date>`, `Verified with <tool> on <date>`, `read <date>`, `probed <date>`, `seen <date>`; `not re-checked on <date>` is none), so a fact taken from Learn or another web page is fetched again before a release; it counts Markdown lines like the validator.
RDL comparison (`scripts/rdl-compare.mjs <old.rdl> <new.rdl>`): proves a re-platformed paginated report changed only its data
sources and datasets (`bi-paginated-report`, `REPLATFORM.md`).
Paths are compared in canonical form, so a project opened through a symlink, a junction or a Windows 8.3 short name gets the same checks.
Hooks are registered as the plain shell string `node hardening/hooks/<script>.mjs` (payload on stdin): Claude Code runs it in Git Bash or PowerShell from the session's current folder (the project root until a `cd` moves the main session, which the guard denies), Copilot CLI in PowerShell or bash from the repository root; no `args`, quotes or `${CLAUDE_PROJECT_DIR}`, which the CLI does not substitute ([REFERENCE.md](REFERENCE.md), Registration). Guards fail closed, also when a module fails to load
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
  `Invoke-ASCmd`, the Fabric CLI's `del`, `move`, `copy`, `mklink`, `table` and its command mode `fab -c "..."`,
  `pbi-tools.core deploy`, the Fabric cmdlets (every verb but `Get-`) and `Invoke-AzRestMethod`, `msbuild /t:Deploy`
  (`-t:`, `/target:`), `devenv /Deploy`, `SSISDeploy`, a script named `deploy*` of any script type (`.ps1`, `.sh`,
  `.bash`, `.cmd`, `.bat`, `.py`, `.js`, `.mjs`, `.cjs`, `.ts`) and a task runner's `deploy*` target (npm, pnpm, bun,
  yarn, make, just; audit 2026-11-16): a project's own deploy script passed as a routine script run before 2026-10-08;
  one hidden inside a script the guard cannot see is still yours to catch), and an MCP tool the policy does not know
  whose input holds a command the shell policy does not deny, names a critical file or a reference folder (unless the
  tool's name says it only reads), or names a file by a stream, device or share spelling the guard cannot place, a
  `database_operations` write that carries a definition, `eval` or `Invoke-Expression` of text the command does not hold
  (`eval "$(...)"`) and `git fetch --stdin` (audit 2026-11-17). Every deny stays (secrets, force push, protected
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
  reader, no option that writes or runs a program (`sort` with an output option in any spelling `getopt_long` accepts,
  `--outp=f` and `-uof` included, or `--compress-program`; `node --check` with a preload or loader option or `--run`;
  `node --check` or `-c` only for files inside the project, `--version` or `-v` only alone), no option that widens
  what is read or names a file (grep's `--recursive`, `--dereference-recursive` and `--directories` under every prefix,
  value form and cluster; `git grep --untracked` and `--no-exclude-standard`, which reach ignored files; `date -f`,
  grep `--file` and `--exclude-from`, `sort --random-source`, a file named by an option is judged like one the command
  reads; `wc` and `sort --files0-from`; `date --set` or an operand that is no `+FORMAT`), ripgrep only with options on
  an allowlist (no `-u`, `--hidden`, `--no-ignore*`, `--follow`, `--pre`, `--hostname-bin`, `--ignore-file`, and a glob
  only as a plain extension glob of a file type the harness works with: `*.md`, `*.tmdl`, not `*`, `.*`, `**` or
  `*.json`; audit 2026-11-16), no variable set in front of the command, no parenthesized expression
  such as `gc ('.e'+'nv')`, no PowerShell provider path (`Env:`, `HKLM:\`, `Environment::`, `FileSystem::`), a comma list
  judged item by item, `cd` only to one folder inside the project), local
  Git (`status`, `diff`, `log`, `add`, `commit`, `switch`, also with `-C` to a folder inside the project; not `--orphan`, `git grep -O`, a `git branch` short-option cluster that deletes, moves, copies or forces (`-qd`, `-qf`), a forced or abbreviated forced
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
  utilities, and the floor list of the lab mode above: Fabric CLI writes and command mode, Fabric cmdlets, `msbuild
  /t:Deploy`, a `deploy*` script of any type, a task runner's `deploy*` target), `git push` (also `git send-pack` and
  `git subtree push`, which get the verdicts of the equivalent push), a service workspace or any server other than this
  machine, MCP writes on an unnamed or remote connection (a connection whose name looks local counts as remote when
  the session state records another machine for it), an MCP query or write on a connection the session never
  confirmed (`lab` runs it), Tier 2 changes (AGENTS.md; `lab` runs them): renames and
  deletes (TMDL declarations, tab or space indented, hierarchy levels included; MCP), relationships (`relationships.tmdl`,
  a relationship added, removed, renamed or edited in any TMDL file, MCP), a
  change of a report's `datasetReference` in `definition.pbir`, reference-copy edits, and on a local MCP connection
  partition (also a partition source, M expression, data source or connection string named in a table or model write),
  Power Query expression, parameter, refresh, refresh-policy, storage-mode and database writes and any
  operation the guard does not classify as ordinary; database, Analysis Services and SSIS clients, row-level or
  personal-column DAX, GitHub and Figma writes, `git apply` and `patch` (`--dry-run`, `--help` and `--version` stay routine), running an SSIS package or deploying it to SSISDB, Desktop
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
  GPG and PuTTY: `.git-credentials`, `~/.kube/config`, `.ssh/`, `*.ppk`, also with a wildcard in the file name
  (`~/.config/gh/*.yml`, `~/.kube/c*`; audit 2026-11-17); also direnv's `.envrc`, a file named
  `.credentials.json` (Claude Code's own sign-in file) and the GitHub CLI token file on Windows, `%APPDATA%\GitHub
  CLI\hosts.yml`, for Read, Grep, Glob, Edit, Write and the shell, and `.claude/settings.json` denies `Read(.envrc)`,
  `Read(**/.envrc)` and `Read(**/.credentials.json)` without the pack too; the validator's "must never be committed" checks
  (tracked files in the full scan, staged files in the pre-commit check) do not refuse a `.envrc`, because projects
  commit it on purpose (direnv: `use flake`, `layout python`), but refuse one inside a credential folder (`secrets/`,
  `.ssh/`) and a `.credentials.json`; a file word whose bracket class or brace expansion
  can spell a secret or data name (`cat .en[v]`, `cat {.,}env`) is denied like the name, and `file -f` of a secret file
  like `cat`), commands that print a sign-in token or a stored credential (`gh auth
  token`, `gh auth status --show-token`/`-t`, `az account get-access-token`, `gcloud auth print-access-token`,
  `gcloud config config-helper`, `git credential fill`, `git credential-<helper> get`, `gh auth git-credential get`,
  `Get-PowerBIAccessToken`, `kubectl config view --raw`/`--flatten`, `aws configure export-credentials`, `aws configure
  get aws_secret_access_key` and the session token; audit 2026-11-16), a password printed out of a credential object or
  a SecureString whatever the variable is named (`GetNetworkCredential()`, `ConvertFrom-SecureString -AsPlainText`,
  `Get-Secret -AsPlainText`, `Marshal` calls, `Net.NetworkCredential` then `.Password`; audit 2026-11-17),
  a variable that holds a connection URL, a DSN, a credential or an account key (`$DATABASE_URL`, `$SENTRY_DSN`,
  `$DB_PWD`; `$Env:X` and `${ENV:X}` read like `$env:X`), `file -m` of a secret file and the Environment key read
  through `[Microsoft.Win32.Registry]` (audit 2026-11-17),
  PowerShell reads of environment variables
  (`Get-ChildItem env:`, `Get-Content Env:X`, `Set-Location Env:`, `Get-ChildItem Environment::`) and the registry's
  or WMI's copy of them (`reg query|export|save` of an Environment key, `Get-ItemProperty HKCU:\Environment`, a listing
  of the key above it, `Win32_Environment`, `wmic environment`), credentials in files, role and workspace membership (TMDL role
  members, `Add-RoleMember`, `Add-PowerBIWorkspaceUser`, `Grant-Rs*`), `Model.bim` edits, destructive
  commands (git options in any abbreviation git accepts, `--orphan`, `git grep -O`, repointing options, and git
  redirects into guarded files, `templates/` or a report's `source/`; `find -delete`, `-exec` or `-fprint` on `.git`,
  `.claude`, `.githooks`, `.github`, `hardening`, a reference folder or outside the project; `find -exec sed -i`/`perl -i`;
  a CLI `--out`/`--output` to a guardrail file; `rm`, `Remove-Item`, `mv`, `Rename-Item`, `git mv` or `git rm` of `.git`, `.claude`,
  `.githooks`, `hardening`, `.github`, `.vscode` or `.cursor`; a copy into a guardrail folder by its name, `cp x .claude`;
  a push to a protected branch in any spelling git resolves to it (`main`, `heads/main`, `refs/heads/main`; `@` counts
  as `HEAD`; a branch name is compared without case: `MAIN`), also through `git send-pack` and `git subtree push`; a
  `git fetch` or `git pull` refspec into a protected branch that is forced (`+`, `-f`, `--refmap`), comes from a local
  path (`git fetch . HEAD~1:main`) or is set by `-c remote.<name>.fetch=` or `git config`; `git checkout -B`, `git
  worktree add -B` and `git subtree split -b` onto it; `git config --remove-section`/`--rename-section` of a section
  that holds a protected key, and `git config -e`; `git checkout-index -f` (`-a` denied, `-f --stdin` asks); `git -C
  <dir> checkout`/`restore` of a guardrail file like the plain spelling (audit 2026-11-17); `git update-ref` that sets a
  protected branch (or
  `HEAD` while one is checked out; `--stdin` asks); `git branch -f`, `-M` and `-C` onto a protected branch; `git stash -a`
  or `--all`, which takes the ignored files (`.claude/settings.local.json`, where a default install registers the hooks,
  and `.claude/logs/`), and `git stash push <pathspec>` in a guardrail or reference folder),
  any change to the hooks' logs and session state in `.claude/logs/`
  (shell writes, copies, moves and deletes, Edit/Write; reading them stays open), network transfers (also from inline `node -e`/`python -c` code and .NET network classes; `certutil -urlcache`, `bitsadmin /transfer` and `/addfile`, and a program that opens an http, https or ftp URL: `start`, `Start-Process`, `explorer`, `Invoke-Item`, `rundll32 url.dll`, `xdg-open`, `open`;
  a browser given a URL (`msedge`, `chrome`, also `--app=<url>`; audit 2026-11-17)), `templates/`,
  a report's `source/` folder and every folder listed in `references` of `harness.config.json` (project-relative
  prefixes, e.g. a lab's `setup/`): Edit/Write, shell writes and deletes, writes through a variable in a command that
  names such a folder, and inline code that writes files and names one; the folder itself and a path reached after a
  `cd`, `pushd` or `Push-Location` of the same command line count like a path inside it (delete, move, rename, write,
  extraction, `git rm`, `git mv`, `git checkout <rev> -- <path>`, `git restore <path>`), and so does a writing program
  run inside it; a delete, move or rename of a folder that holds a reference folder (`rm -r reports`, `git rm -r`) is
  denied like the folder itself, the walk below bounded to 3 levels and 500 folders (audit 2026-11-17); more programs count as writers of their operand on guardrail paths, reference folders and guarded file
  types (`gzip`, `gunzip`, `bzip2`, `xz`, `dos2unix`, `unix2dos`, `shred`, `ex`, `ed`, `vim`, `chmod`, `chown`,
  `Set-ItemProperty`, `Start-Transcript`, `uniq IN OUT`, `patch`, `iconv -o`, `split`, `yq -i`, `certutil
  -encode|-decode`, `icacls`, `attrib`, tar `-C`, unzip `-d`, 7z `-o`, `Expand-Archive`, `Compress-Archive`,
  `[IO.File]::Delete|Move|Copy|Replace`, `[IO.Directory]::...`, `(Get-Item x).Delete()`, `npm --prefix <dir> pkg set`;
  audit 2026-11-16); a script file's writes stay out of sight, so
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
which asks once per call like the guard's other asks, and is denied when its arguments (an unknown MCP tool's too) name
a secret or data file or a command the shell policy denies (audit 2026-11-17; a `url` gets no verdict, like a web
fetch); a call whose arguments cannot be read asks. The prompt guard cannot hold a message back under Copilot: GitHub's hooks reference
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
open, and so does a Grep over the folder `~/.kube`, `~/.docker` or `~/.config/gh`; `*.json` as a Grep glob stays open
too (PBIR needs it) although it can match a `.credentials.json` (`.cred*` and `.*.json` are denied); the file itself stays denied to Read and the shell. Publish, deploy and processing from the
shell are floor asks, not denies: `AGENTS.md` forbids them to the agent, and the ask keeps you in the loop when you
choose to run one through the session; membership changes are denied outright.
The guard spells out Windows 8.3 short names in a command by comparing each word's project-relative spelling before and
after resolving, so a project folder written as a short path (a GitHub Windows runner's `RUNNER~1` profile) or reached
through a symlink or junction no longer turns `HEAD~1` into a file path. The file words of every program but `echo`,
`printf`, `Write-Output` and `Write-Host`, and every redirect target (`> x`, `<x`), are also judged as the shell opens
them, a glob by its folder before the wildcard (`b/cred*`), each item of a PowerShell list (`README.md,b\credentials`),
an option's glued value (`-fb/credentials`, `if=b/credentials`)
and, on Windows, a device, local administrative-share or stream spelling by its drive path (`\\?\C:\...`,
`//localhost/C$/...`, `b\credentials::$DATA`): a link or a `..` after one that reaches a secret or data file, also as the
path of a git `<rev>:<path>` word (`git show HEAD:b/credentials`, `:0:b/credentials`, placed from git's folder and from the
top of the project), is denied like its plain name, also when a lister or `find` passes it on, and one that leaves the
project is not routine. A
command on the link itself (`rm b`, `git add b`) is judged like one on the folder it points to. A listing that only names
data files, alone or into stages that handle names (`ls reports/*.pbix | wc -l`, `Get-ChildItem reports\*.pbix |
Measure-Object`, a `ForEach-Object` block that only reads `$_.Name`, `$_.FullName` or another name property), reads none
of them; a later stage that opens files (`xargs`, `cat`, `Get-Content`, any other `ForEach-Object` block,
`Select-String`, `Import-*`) makes it a read, and a listing that names a secret file is denied as before.
Judged as written only: a word with a variable or `~` (`"$PWD/b/x"`, `$f`, `~/b/x`) or a wildcard in its first segment
(`*/credentials`), and a path a command computes (`$(...)`, `Join-Path`, `Resolve-Path`, `(Get-Item b).FullName`,
`[IO.File]::ReadAllText`). A word longer than 4096 characters once `/./` and doubled separators are dropped is not
resolved either (walking it could outlast the hook's timeout), and it is never routine. On Windows a `\\?\UNC\...` device
path and a stream inside a path (`b::$INDEX_ALLOCATION\credentials`) are judged as written too: they get no verdict
through a link, never an allow.
The `cd` guard ([REFERENCE.md](REFERENCE.md#registration)) makes no claim about a `cd` it cannot see: `"$(cd reports)"`
inside a PowerShell double-quoted string, a `cd` in text the command does not hold (`eval "$(...)"`, `iex $cmd`) and a
`cd` inside a sourced script. A `cd` inside `eval`, `Invoke-Expression`/`iex`, a bash function body or a .NET location
call with a literal folder (`[Environment]::CurrentDirectory = 'x'`) is judged like the plain `cd` (audit 2026-11-17).
It over-denies a PowerShell `function f { cd reports }` even when `f` is never called.

**Spellings still open (audit 2026-11-17).** Git: `git fetch origin feature/x:main` from a named remote without force
gets no verdict, like `git fetch origin main:main`; a named remote whose URL is a local path, and a repository given as
a bare folder name, are not seen as local. Secrets and network: a wildcard in a folder segment of a credential path
(`~/.config/*/hosts.yml`), a registry key path split across statements or held in a variable, a browser given an address
without a scheme (`msedge example.com`), text browsers (`lynx`, `w3m`) and `[Diagnostics.Process]::Start('msedge', url)`
get no verdict; `patch` only asks, because its targets are inside the diff. `eval` and `cd`: when an `eval` holds more
than one command, a `cd` in it does not move the folder later commands are placed from;
`[IO.Directory]::Delete('reports',$true)` is checked against the reference folder itself only. Validator: in any file it
scans, a plain `NAME=value` whose value has no token shape is found only for the key names the credential rule knows (it
has no bare `token` key). Not run: the ripgrep rows, `git stash -a` on a live session, a live modeling server, hooks in
a session.

**Git worktrees under `.claude/worktrees/` (audit 2026-11-17).** With the repository as project and a worktree as session
folder, shell writes there are denied and every Edit or Write asks; without `CLAUDE_BASH_MAINTAIN_PROJECT_WORKING_DIR`
all shell commands are denied ([REFERENCE.md](REFERENCE.md#registration)). Not changed; tested on a fixture only.
The post-edit validator and the Stop gate skip the worktree's files; CI checks them, and the pre-commit hook does
when no `CLAUDE_PROJECT_DIR` points it at the main checkout (not run).

**Over-denials the audit added.** `git branch -M main` (use `git branch -m main`), `chmod`, `gzip -c` and `vim` on a
guarded file type, and a file word with more than 256 brace alternatives are denied; `pnpm deploy` asks. Added
2026-11-17: a connection-URL variable is denied as a client's argument (`pg_dump "$DATABASE_URL"`; `psql`'s whole
connection word asks), also `$GOOGLE_APPLICATION_CREDENTIALS`; a fetch or pull from any local path into a protected
branch, a sibling clone included; `git config --remove-section remote.<name>` with no protected key; `git checkout-index
-f -a --prefix=out/`; `rm reports` without `-r`; `Remove-Item . -Recurse` from the root. Floor asks: `eval "$(ssh-agent
-s)"` and any `database_operations` write with an argument beyond its operation and connection. An unknown MCP tool's
`destination` or `output` is judged as a write though its name says it reads; an array command, joined and quoted.

**Role members in lab mode (audit 2026-11-17).** A `database_operations` write that carries a definition (an import of
TMDL or TMSL) is a floor ask in every mode, so lab mode no longer passes it; its payload shape is not parsed.

**MCP limits (audit 2026-11-17).** Under Claude Code an MCP tool the policy does not know is judged by what its input
holds at any depth: a command (`command`, `cmd`, `script`, or a list of words with `args`) by the shell policy, a local
file (`file_path`, `path`, `source`, `destination` and their siblings, a `file:` uri) by the file rules, taken from a
`cwd` when it names one ([REFERENCE.md](REFERENCE.md#mcp-policy-path-a-with-the-pack)); the Claude desktop app's
terminal tool (`mcp__terminal__run_in_terminal`) asks on every call. Past its size bounds the call is the floor ask.
Under GitHub Copilot an unknown MCP tool, or any unmapped tool (the CLI's `<server>-<tool>` names cannot be told from
one), whose arguments name a secret or data file, or a command the shell policy denies, is denied; not applied there:
the overflow ask, the write denies for the guard configuration and the hook logs, and the asks for critical files and
reference folders. Still open: a path with a space under `target`, `from`, `to`, `input` or `output`, a value with a
scheme under the new keys, keys of another case and arguments packed into a JSON string are not read. Reconnecting under
the same name to localhost replaces a recorded remote server. The modeling server's own behaviour (whether it accepts a
caller's connection name, which duplicate key it honours, how its answers spell the server) was not checked live: a
Desktop answer that spells this machine as a fully qualified name, or a quoted Data Source, makes writes ask. Run
[docs/harness/path-a-live-check.md](../docs/harness/path-a-live-check.md) before a release.

**Slow machines.** Two environment variables give the hooks more time where git or Node start slowly (a CI runner):
`BI_HARNESS_GIT_TIMEOUT_MS`, the time one git call of a hook may take (default 3000, at most 10000), and
`BI_HARNESS_CHECK_BUDGET_MS`, how long a guard that cannot load looks for the broken file before it blocks with the load
error alone (default 5000 for the PreToolUse guard, at most 12000; 3000 and at most 6000 for the subagent scope guard).
Each only raises its default. The git timeout is per call, and all git calls of one hook share 12 s; the Stop gate's
share 60 s under Claude Code and 20 s under GitHub Copilot CLI and VS Code (the hook files set `BI_HARNESS_HOST`), or
under the Copilot CLI's run of the Claude registration (`COPILOT_CLI=1`, which the CLI sets for every hook copy): a hung
git holds a hook that long at most, however many calls it makes, and a call that finds the time spent answers like a
failed git (the guard then asks or denies; the Stop gate keeps the rule it applies without Git). The Stop gate's wait
for another copy of itself on the same event (at most 15 s) counts against its share. Each budget stays at
least a third below the timeout its host registers (the guard and the session start 20 s on every host; the Stop gate
90 s in `settings.hooks.json`, 30 s in `copilot-cli.hooks.json` and `vscode.hooks.json`), because
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
