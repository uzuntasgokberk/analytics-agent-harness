# Getting started

For anyone who keeps Power BI projects (PBIP), Analysis Services models, paginated reports (RDL) or SSIS packages in a
Git repository and wants Claude Code to work on them with this harness.

## Two repositories, one install

| Repository | What it is | Where |
|---|---|---|
| The harness (`bi-agent-harness`) | the source you install and update from | cloned once, anywhere **outside** your BI repository, e.g. `C:\tools\bi-agent-harness` |
| Your BI repository | your PBIP, TMDL, RDL, SSIS and SQL files | the harness is installed **into its root** and committed there |

Never put one repository inside the other and never next to it as a sibling: Claude Code reads `.claude/` and
`AGENTS.md` from the folder you open it in. Several projects in one repository need one install at the root. No folder
layout is required: the harness finds projects by their files (`*.SemanticModel`, `database.tmdl`, `*.rdl`,
`*.dtsx`); `/bi-onboard` writes down what it found.

## Install (10 minutes)

Needs: Git, Claude Code, Node.js 18.17 or later on PATH (for the installer and the hardening pack; without Node copy the
files by hand, as the harness repository's README says under "Who downloads what"), Power BI Desktop for PBIP work
(Report Builder for RDL, SSMS or DAX Studio for Analysis Services, Visual Studio with SSIS projects for SSIS).

```powershell
git clone https://github.com/uzuntasgokberk/analytics-agent-harness C:\tools\bi-agent-harness      # once per machine
cd C:\repos\my-bi-repo
git switch -c chore/bi-harness
node C:\tools\bi-agent-harness\hardening\scripts\install-into.mjs . --hardening --enable-hooks --shared
git add -A
git commit -m "chore: add BI Agent Harness"
```

`--enable-hooks --shared` registers the hooks in `.claude/settings.json` (committed: the whole team has them) and sets
`core.hooksPath`; `--enable-hooks` alone keeps them in `.claude/settings.local.json` (yours only). On a repository that
already has the pack use `--update --enable-hooks [--shared]`; once the manifest records `--shared`, `--enable-hooks`
alone keeps the team registration in `.claude/settings.json` (a teammate's per-machine step never removes it; to move it
to your machine on purpose, delete the `hooks` block from `.claude/settings.json` and the `"hooks"` line from
`.claude/bi-agent-harness.json`, commit, then run `--update --enable-hooks`). Without `--hardening` you get the
instructions, skills and agents without any Node code.

A differing `AGENTS.md`, `.claude/` or `hardening/` file stops the install until you review it and run again with
`--keep-existing`. A symbolic link or a junction at any path the installer manages, inside the repository or out of it,
stops it with exit 2 ("Linked installation paths") and changes nothing: replace the link by the file or folder itself, or
install into another folder. A file an earlier install wrote and you did not change is no conflict: the install lists it as
`installed` and `--update` refreshes it, so the install command can be run twice. A `.claude/settings.json` you keep receives the harness's permission rules (added where missing;
your own rules stay first) and `"agent": "bi-expert"` when it names no agent (`merged   : ...` in the output); the rest
stays yours and every update lists it as kept. Installed with `--keep-existing` before 2026-10-19? Run the same install
command with `--keep-existing` once more; `/bi-doctor` checks that the `Read(.env)` deny rule is there.

Optional, per machine: copy `.mcp.example.json` to `.mcp.json` to allow the Power BI modeling MCP server and
Microsoft Learn (Path A). Without it everything still works on Path B: the agent writes test packs you run in Desktop.

## First session

1. Open Claude Code in the BI repository. Restart it after the install.
2. `/bi-doctor`: checks the instructions, hooks, Node, MCP and CLIs, and says which path (A or B) each capability is on.
3. `/bi-onboard`: finds your models, reports, paginated reports and packages, asks once what the files cannot show (owners, delivery, MCP, Fabric sync), and drafts
   `docs/sources/README.md`, `docs/conventions.md` and `TASKS.md`. Review and commit the drafts.
4. Ask for real work in plain words, or start with `/bi-plan`. Examples: `docs/example-prompts.md`.

## How much it asks you

`approvals.mode` in `hardening/harness.config.json` (details: `hardening/README.md`, Approvals):

| Mode | For | Prompts |
|---|---|---|
| `auto` (default) | daily work | routine work runs; servers, Desktop `reload`, screenshots (default `ask`), publish and harness files ask |
| `ask` | seeing every step | Claude Code's normal prompts |
| `lab` | tests on your own machine with test data | nothing the guard recognises asks, except the floor (push, publish or deploy, remote servers, database clients and the rest of the list in `hardening/README.md`, Approvals), Desktop `reload` and screenshots (default `ask`) |

Only you change the mode, in your editor or with `!` typed in Claude Code's own input box (not in a terminal); the
agent can make it stricter, never looser. The `ask` rules of `.claude/settings.json` prompt in every mode, and the
guard's own ask does the same on every host, Copilot included, so edits of the harness's own files (`hardening/`,
`.claude/`, `.gitignore`) always ask: the agent cannot quietly change its own safety net. If your repository has a
`CLAUDE.md`, add the line `@AGENTS.md` to it: Claude Code reads `CLAUDE.md` instead of `AGENTS.md` when both exist.
Layout and the rest of the picture: [`layout.md`](layout.md) and `docs/harness/how-it-works.md`.

## Teammates

They clone the BI repository and get the harness, and with `--enable-hooks --shared` the hooks, with it. Each runs
once per clone: `git config core.hooksPath hardening/githooks`. If the hooks were registered per machine instead
(`--enable-hooks`), each teammate runs `node <harness>\hardening\scripts\install-into.mjs . --update --enable-hooks`
once, or the owner switches to `--update --enable-hooks --shared` and commits the result.

## Update

```powershell
git -C C:\tools\bi-agent-harness pull
node C:\tools\bi-agent-harness\hardening\scripts\install-into.mjs . --update
```

`--update` stops with no change when the repository has no manifest (run the install first) or when the harness source is
older than the install: a clone that does not contain the commit the manifest records (an older clone or another branch:
pull it; a harness whose history was rewritten: pulling cannot help), or, where no commits can be compared (a copy that
is no Git checkout such as a zip, or an install from one), a lower pack version than the manifest records. If that source
is the one you want, run once with `--update --allow-older`.
It re-registers the hooks only while the settings file still holds them, never sets `core.hooksPath`, and removes the
permission rules the harness no longer ships (listed; your own rules stay).
Files you changed are kept and listed on every update; merge those by hand. A shared `.claude/settings.json` you changed
is never overwritten, but the update still re-applies the harness hook groups and the pack's permission rules to it.
Commit the result with `.claude/bi-agent-harness.json`. A manifest entry outside what the harness installs (outside the
repository, in `.git`, a project file, local state) is never removed: the update lists it as `refused` and drops it
from the manifest; check `git log -p -- .claude/bi-agent-harness.json` to see who added it. Installed files your own
`.gitignore` excludes are listed as `ignored`: narrow the rule or `git add -f` them; the installer never changes your
rules beyond the lines it appends.
A kept `hardening/harness.config.json` does not receive the keys of the shipped `hardening/harness.config.json` it lacks
(a key only the pack's defaults have is not listed: the default applies): the update output lists each missing key with
the default that applies, and each key the pack does not know, so you can merge them.

## Remove

Delete the `hooks` block from `.claude/settings.local.json`, or from `.claude/settings.json` if you installed with
`--shared`; run `git config --unset core.hooksPath`; delete every file `.claude/bi-agent-harness.json` lists (this
includes `.github/hooks/bi-harness.json` and `.github/hooks/bi-harness.copilot-cli.json`; after an install from before
2026-10-19, delete those two by hand), then the manifest itself.
