---
name: bi-doctor
description: Check this machine and repository for the harness (read-only) - instructions, skills, Git hooks, Node, MCP, CLIs, model format - and say which path (A or B) each capability is on
allowed-tools: Bash(git status *) Bash(git rev-parse *) Bash(git branch --show-current) Bash(node --version) Bash(node hardening/scripts/validate.mjs --help) Bash(claude --version) Bash(powerbi-report-author --version) Bash(powerbi-desktop --version) Bash(powerbi-desktop status) Bash(npm view *) Bash(where *) Bash(where.exe *) PowerShell(where.exe *) Bash(which *)
disable-model-invocation: true
---

Check the setup. Change nothing: no file edits, no installs, no configuration. Run each command on its own (a chained
command needs approval). A command that fails or is missing is a finding, not an error to fix.

1. **Platform.** OS and shell. On macOS or Linux, Power BI Desktop, Report Builder, SSMS and the modeling MCP server's
   Desktop connection are not available here: those checks happen on a Windows machine (Path B on this machine).
2. **Instructions and agent.** Is `AGENTS.md` in your instructions? Are you running as `bi-expert`? Which `bi-*`
   skills can you see? `claude --version`, compared with the version that reads `AGENTS.md` without a `CLAUDE.md`
   (`docs/harness/faq.md`, Versions we tested). Read
   `.claude/settings.json`: `permissions.deny` must contain `Read(.env)`, otherwise the harness's permission rules are
   missing (a settings file kept by an older install): the fix is the same install command again with `--keep-existing`.
3. **Repository.** `git rev-parse --is-inside-work-tree`, `git branch --show-current` (a protected branch such as
   `main` means: create a feature branch before editing), `git status --short`.
4. **Hardening pack** (when `hardening/` exists; the folder alone proves nothing): `node --version` (18.17 or later)
   and `node hardening/scripts/validate.mjs --help` must print its usage, otherwise the pack is "missing" and the
   static check is the manual checklist (Path B); `git rev-parse --git-path hooks` must print `hardening/githooks`; on
   macOS and Linux, `ls -l hardening/githooks` must show the three hooks as executable; read `.claude/settings.local.json`
   and `.claude/settings.json` to see whether the hooks of `hardening/settings.hooks.json` are registered.
   Read `hardening/harness.config.json` against the shipped one (as `install-into.mjs --update` does: `config:
   missing` / `config: unknown`; a key only `DEFAULT_CONFIG` in `hardening/hooks/lib/common.mjs` has is not missing,
   its default applies) and report the top-level and second-level keys it lacks, with the default that applies
   (`DEFAULT_CONFIG`), and the keys the pack does not know (a
   typo or a removed key; entries of `agentScopes` may be the user's own subagents). Never add a key: the user merges.
5. **MCP.** With ToolSearch, look for the `powerbi-modeling`, `microsoft-learn` and `figma` tools. Say whether
   `.mcp.json` exists; `.mcp.example.json` alone is not a connection. Never start a server.
6. **CLIs.** `powerbi-report-author --version`, `powerbi-desktop --version` and, if present, `powerbi-desktop status`.
   Never install one. For each installed npm tool report three versions: installed (`--version`), tested
   (`docs/harness/faq.md`, Versions we tested) and latest on npm (`npm view <package> version`: a read of the public
   registry over the network; skip it offline and say so). Packages: `@microsoft/powerbi-modeling-mcp`,
   `@microsoft/powerbi-report-authoring-cli`, `@microsoft/powerbi-desktop-bridge-cli`. Give the update command to the
   user; never run it.
7. **Projects and formats.** Glob for `**/*.SemanticModel/definition.pbism`, `**/*.Report/definition.pbir`,
   `**/database.tmdl` (a TMDL folder at the repository root counts), `**/*.rdl`, `**/*.rptproj`, `**/*.dtsx`,
   `**/*.dtproj` and `**/*.bim`. A `Model.bim` (TMSL) means TMDL only applies: name the conversion.
   A root `report.json` in a `*.Report` folder means PBIR-Legacy (not editable). Fabric Git-connected directories are
   those `fabric.directories` in `hardening/harness.config.json` or `docs/conventions.md` records; `**/.platform` files
   only mark item folders as Fabric-shaped (Desktop writes them too), so without a record name their parent directory
   as a candidate, not as connected. Say that Commit and Update in the workspace are the user's
   ([fabric-git.md](../../../docs/harness/fabric-git.md)). Any subset of layers is complete:
   never report a missing layer (no PBIP, no RDL, no SSIS) as a finding.
8. **Tools of the artifacts present** (only those rows; a repository without SSIS needs no `dtexec` row): Power BI
   Desktop for PBIP (`powerbi-desktop status`, or the user's word); Report Builder for RDL (not on PATH: the user
   confirms); `dtexec` for SSIS (`where.exe dtexec` on Windows, or the versioned `...\<version>\DTS\Binn\DTExec.exe`;
   in PowerShell a bare `where` is `Where-Object` and prints nothing);
   SSMS or DAX Studio for an Analysis Services model (the user confirms, and names a test server). A missing tool
   means that layer's engine check is the user's on another machine and is reported NOT RUN here; never install one.
9. **Installation.** `.claude/bi-agent-harness.json` exists: installed with the installer, `--update` works.
   Missing: a template or a hand copy; the first `--update` only adds files and lists differences.

Answer with one table, then the fixes in order of value:

| Capability | Status | Path | Fix |
|---|---|---|---|

Statuses: works, missing, not on this OS, not checked (say why). Each fix is one concrete command or action for the
user; never apply it yourself. A capability is "works" only when its command ran here or the user confirmed it; a
folder, a config file or an `.mcp.json` entry is not evidence.
