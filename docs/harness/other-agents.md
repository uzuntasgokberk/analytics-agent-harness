# Using the harness with other coding agents

The harness is written for Claude Code, but its knowledge is plain files any agent can read: `AGENTS.md` (the working
agreement), the skills (`.claude/skills/*/SKILL.md`), the agent checklists (`.claude/agents/`), the rules
(`.claude/rules/bi/`) and `docs/`. What differs between agents is what loads automatically and what is enforced.
Checked against each tool's documentation on 2026-10-07 (VS Code agent skills, custom agents and custom instructions
pages; GitHub's repository instructions and Copilot CLI pages; Cursor rules; Gemini CLI configuration reference) and
on 2026-10-10 for OpenAI Codex (the AGENTS.md, skills and hooks pages at `learn.chatgpt.com/docs`, where the
`developers.openai.com/codex` links redirect), and on 2026-10-17 for GitHub Copilot again (the custom agents
configuration and hooks reference pages, the Copilot CLI pages on custom agents and MCP servers, VS Code's custom
agents page); and on 2026-10-25 for the Copilot custom agent pages (GitHub's custom agents configuration, Copilot CLI
custom agents and hooks reference; VS Code's custom agents, file reference and tools reference, dated 2026-10-21); tools
change fast, so check again before relying on a detail.

## What each agent picks up

| | Instructions | Skills | Agent checklists | Workflows | File-type rules | Guards |
|---|---|---|---|---|---|---|
| Claude Code | `AGENTS.md` ([versions](faq.md#versions-we-tested)) | loaded on demand | subagents | user-invoked skills: `/bi-plan`, `/bi-feature`, … | loaded by path | permission rules; hooks with the hardening pack |
| GitHub Copilot in VS Code | `AGENTS.md` (setting `chat.useAgentsMdFile`, on by default) | `.claude/skills/` is scanned (`disable-model-invocation` honoured) | `.github/agents/bi-expert.agent.md` and the editors' `.github/agents/<name>.agent.md` (shipped, see "Editors as Copilot subagents") and `.claude/agents/` in the Claude format (VS Code's file reference of 2026-10-21 lists ten properties for that format, `skills` among them, and does not say whether a listed skill is preloaded, so each specialist's first line still tells the model to read its skill file) | user-invoked skills: `/bi-plan`, `/bi-feature`, … | `.github/instructions/bi-*.instructions.md` (shipped pointers with the rules' globs) | the hardening pack's hooks through VS Code's agent hooks (`.github/hooks/bi-harness.json`), Git hooks, CI |
| Copilot CLI | `AGENTS.md` (the nearest one in the tree), `CLAUDE.md`, `.github/copilot-instructions.md` | `.claude/skills/` loaded as project skills (observed, below) | `.github/agents/bi-expert.agent.md` (`/agent`, then pick it, or `--agent bi-expert`), the editors' `.github/agents/<name>.agent.md` and the specialists of `.claude/agents/` (observed, below; of two files with one name the `.github/agents` one wins) | skills listed as commands (`/bi-plan`, …; not exercised) | the same pointers and `.claude/rules/bi/*.md` itself (both listed by `copilot instruction list`) | the pack's hooks, both in the CLI dialect (`.github/hooks/bi-harness.copilot-cli.json`) and through the Claude registration (`.claude/settings*.json`), Git hooks, CI |
| Copilot cloud agent (github.com) | `AGENTS.md` | by path | `.github/agents/` (`bi-expert` and the editors) | by path | the same pointers | the `bash` hooks of the same file; no local servers, Desktop or MCP: Path B only |
| Cursor | `AGENTS.md` (root and nested) | by path from `AGENTS.md` | by path | by path | by path | none of Claude's |
| Gemini CLI | `AGENTS.md` once `context.fileName` names it | by path | by path | by path | by path | none of Claude's |
| OpenAI Codex (CLI, IDE extension) | `AGENTS.md` natively (root down to the working directory, 32 KiB combined by default) | by path (Codex discovers `.agents/skills/` only, not `.claude/skills/`) | by path | by path | by path | none of Claude's; Codex has its own hooks, the harness ships none for them (below) |

"By path" means the agent reads the file because `AGENTS.md` names it; nothing loads it automatically.

## What stays enforced on every agent

Claude Code's permission rules run only in Claude Code; under Copilot the guard asks where an ask rule of the settings
would, and denies where a deny rule would. The hardening hooks run in Claude Code and, since 2026-10-07,
in GitHub Copilot through its agent hooks (VS Code, Copilot CLI and the cloud agent read `.github/hooks/*.json`; the
installer's `--enable-hooks` writes `bi-harness.json` for VS Code and `bi-harness.copilot-cli.json` for the CLI and
the cloud agent; Copilot CLI also runs the Claude registration of `.claude/settings*.json`). There the guard, the
validation and the audit log work as in Claude Code, and so does the output masking in the CLI (its documented
`modifiedResult`); VS Code documents no PostToolUse field that replaces tool output, so there the masked output is sent
but may be ignored, and the agent is told the values may be visible and must not be used (a warning, not a guarantee).
Subagent scopes do not run (Copilot sends no `agent_type`), the prompt guard cannot hold back a message with a
credential (it says so and asks for rotation; its deploy reminder never reaches the model: the CLI drops it, VS Code
shows it to the user as a `systemMessage`; GitHub's and VS Code's hooks references, read
2026-10-19), and in the CLI a Stop gate block is sent as `agentStop`'s `decision: block`, which sends the agent back
with the reason as the next prompt (GitHub's hooks reference; not yet seen in a live session). Copilot CLI was
exercised once on the end-to-end lab task (2026-10-07/08, Sonnet) and probed again with short sessions after
the fixes (2026-10-08): the knowledge files, the records, the shell guard, the file-tool guard and the masking
work; what remains is under "Copilot CLI" below. VS Code Copilot and the cloud agent are built to the documented
protocols and the published tool schemas and verified with synthetic payloads only (VS Code's output masking sends a
field its protocol does not document, so it is treated as a warning): your first session verifies them
(below). With Cursor, Gemini, Codex or a Copilot session without hooks, the safety net is:

- the Git hooks (`git config core.hooksPath hardening/githooks`): invalid files, credentials and data files cannot be
  committed, commit messages follow Conventional Commits, `main` is not pushed to directly;
- the CI check (`hardening/ci/bi-validate.yml`) as a required status check on the server;
- your review of every diff before you accept it.

Keep the modeling MCP server read-only with other agents: the checks that cap DAX result rows and refuse deploys are
hooks, and without them nothing stops a write.

## Setup per agent

**GitHub Copilot (VS Code).** Nothing to install for instructions, skills and agents. In the agent picker choose
`bi-expert` (`.github/agents/bi-expert.agent.md`, which sends the model to `.claude/agents/bi-expert.md`, `AGENTS.md`
and `bi-map`). VS Code also lists the specialists of `.claude/agents/` (Claude format). It does not load their
`skills:`, so the first line of each specialist tells the model to read its skill file; their `tools:` name the MCP
servers twice, `mcp__powerbi-modeling` for Claude Code and `powerbi-modeling/*` for Copilot, and each host ignores the
other's spelling (GitHub documents that unrecognised tool names are ignored; Claude Code refuses a subagent only when
none of its entries resolves, and a specialist with both spellings launched in a fresh Claude Code 2.1.301 session on
2026-10-17). `powerbi-modeling/*` hands every specialist, the read-only reviewers included, the whole modeling server,
and the pack's per-agent scopes do not run in Copilot: the server itself must be `--readonly` there (above).
`.github/agents/bi-expert.agent.md` carries `disable-model-invocation: true`: in VS Code no other agent can invoke it
as a subagent, and on GitHub.com the cloud agent never auto-selects it (the CLI reads the property too, below), so
pick it yourself. VS Code also sees `.claude/agents/bi-expert.md` under the same name, a Claude-format file that cannot
carry the property; the CLI keeps the `.github/agents` file (below), VS Code is not probed, so check which one the
picker opens (the editors' pairs raise the same question, below). The
rules load through `.github/instructions/bi-*.instructions.md`, generated pointers with the same
globs as `.claude/rules/bi/*.md` (`node hardening/scripts/sync-copilot-instructions.mjs` after a rule's `paths:`
change; a test checks they match). The workflows are skills that only you invoke (`disable-model-invocation: true`),
the same files Claude Code uses: type `/bi-onboard`, `/bi-plan`, `/bi-feature`, `/bi-review`, `/bi-handoff`,
`/bi-doctor` or `/bi-commit` in Copilot Chat. (VS Code prompt files are deprecated for Agent Host sessions and VS Code recommends
skills instead, so the harness does not ship any.) For the hooks: enable the setting `chat.useHooks`, trust the
workspace, and keep `.github/hooks/bi-harness.json` (written by `install-into.mjs --enable-hooks` from
`hardening/vscode.hooks.json`). VS Code runs every `.github/hooks/*.json` file, so `bi-harness.copilot-cli.json` too.
[VS Code's agent hooks page](https://code.visualstudio.com/docs/copilot/customization/hooks) (dated 2026-10-28) names
two harnesses: the Copilot harness, shared with Copilot CLI, also reads `.claude/settings.json` and
`.claude/settings.local.json` without any setting, so it runs the Claude registration as well; the older Local harness
reads them only with `chat.useClaudeHooks`. Either way the same scripts run a second or third time: each model write is
recorded once, one verdict per Stop event, nested where VS Code reads it, while a guard ask still prompts once per copy:
the one-ask rule applies only under Copilot CLI, recognised by `COPILOT_CLI` (below), and VS Code's Copilot harness is
not probed. Under the Local harness keep `chat.useClaudeHooks` off: that run's masking notice is the CLI's and
claims a redaction VS Code does not document; the Copilot harness has no such switch. Neither harness is probed in VS
Code. Verify once: ask the agent to run `cat .env`; expect a
`[bi-harness]` denial; then look at `.claude/logs/tool-audit.jsonl` for `"event":"unmapped"`, a tool the hooks
could not judge, and report it. For MCP, VS Code reads
`.vscode/mcp.json` (top-level `servers`) and the portable `.mcp.json` at the project root (top-level `mcpServers`). The
`--${PBI_MCP_MODE:-readonly}` argument in `.mcp.example.json` is expanded by Claude Code and by Copilot CLI (probed,
below); VS Code's handling of it is not probed, so for VS Code write the mode literally:

```json
{
  "servers": {
    "powerbi-modeling": { "type": "stdio", "command": "npx", "args": ["-y", "@microsoft/powerbi-modeling-mcp@1.0.0", "--start", "--readonly"] },
    "microsoft-learn": { "type": "http", "url": "https://learn.microsoft.com/api/mcp" }
  }
}
```

On Windows, if `npx` does not start, use `"command": "cmd"` with `"args": ["/c", "npx", ...]`. `.vscode/` is ignored
by Git except `extensions.json`, so this file stays on your machine.

**GitHub Copilot CLI and the cloud agent.** Both read `AGENTS.md` and `.github/agents/bi-expert.agent.md` (`copilot
--agent bi-expert` in the CLI, or pick it in the session), and the editors' `.github/agents/*.agent.md` below. The hooks come from `.github/hooks/bi-harness.copilot-cli.json`
(GitHub's dialect: camelCase events, `toolName`/`toolArgs`, a flat decision; `preToolUse` fails closed on a non-zero
exit, every event fails open on a timeout) and, in the CLI, from the Claude registration as well (below). The CLI's
tool names are documented (GitHub's hooks reference) and its argument shapes are not, so the shapes were taken from a
logged session and the scripts judge by shape (a `command`; `path`
with `file_text` or `old_str`/`new_str`; `pattern` with `paths`; MCP tools named `<server>-mcp-<tool>` or
`<server>-<tool>`) and log
anything else as `unmapped`: run the same `cat .env` check, then read the audit log. The cloud agent runs only the
`bash` variant on GitHub's machines: it cannot reach your SQL Server, Analysis Services or Desktop, so it works on
Path B (files and test packs you run).

MCP in the CLI: it reads Claude Code's `.mcp.json` (per checkout, in any folder from the working directory up to the
repository root), `.github/mcp.json` (shared, committed) and `~/.copilot/mcp-config.json` (this user; `copilot mcp add`
writes it, the interactive `/mcp add` form saves without naming a file). Project files win over the user file,
`.mcp.json` over `.github/mcp.json` in the same folder and a closer folder over a farther one, and project files load
only in a folder you trusted. Keep the server name one the MCP policy knows, `powerbi-modeling` or
`powerbi-authoring-local` (the pack's default `mcp.powerbiServers`; `hardening/harness.config.json` can change them): the
hooks turn the CLI's `<server>-mcp-<tool>` names into `mcp__<server>__<tool>` and match the server by name (the
names they know, the configured Power BI servers, the servers in `sources.sqlRead.mcpServers`, `github`, `figma`,
`microsoft-learn` and the CLI's built-in `github-mcp-server`, longest first in both spellings, `<server>-mcp-<tool>`
and `<server>-<tool>`, before any split, so a server whose own name holds `-mcp-` keeps its name; an unknown name
splits at the last `-mcp-`); under
another name the policy recognises the modeling server only by its tool names, and not at all when the name looks like
a database. The README's copy of `.mcp.example.json` works unchanged: the CLI expands `--${PBI_MCP_MODE:-readonly}` as
Claude Code does (probed, below), so the server starts read-only unless the shell that starts the CLI sets another
`PBI_MCP_MODE` (the [Path A live check](path-a-live-check.md) sets `readwrite` for one run: start the CLI from a shell
without it). Without a project `.mcp.json`, one line registers the server for this user (on Windows with `cmd /c npx`
if `npx` does not start, as for VS Code):
`copilot mcp add powerbi-modeling -- npx -y @microsoft/powerbi-modeling-mcp@1.0.0 --start --readonly`; GitHub
documents that a trusted project `.mcp.json` with a `powerbi-modeling` entry replaces that registration. A modeling
server under another name runs beside yours, and a CLI plugin can register one with `--start` alone, which starts it
read-write: check `copilot mcp list` and keep such a server out with `--disable-mcp-server <name>` (one session) or
`copilot mcp disable <name>` (saved in your configuration). A custom
agent the CLI runs as a subagent follows `AGENTS.md` only with `include-custom-instructions: true` in its frontmatter;
the shipped `bi-expert.agent.md` is picked as the session agent and tells the model to read `AGENTS.md` itself.

What the Copilot CLI sessions showed (1.0.94; the end-to-end lab task of 2026-10-07/08 and probe sessions after the
fixes on 2026-10-08; 1.0.99-2 for the MCP probe and 1.0.100-1 for the agent probe of 2026-10-17):

- **The MCP example starts a read-only server.** Probed in prompt mode with `--trust-folder` in a scratch clone whose
  `.mcp.json` is a copy of `.mcp.example.json`, the machine's other MCP servers turned off, no model connected and no
  modeling tool called. The CLI loaded the project file and expanded the argument when it started the server: with
  `PBI_MCP_MODE` unset the server process received `--start --readonly`, with `PBI_MCP_MODE=read-only` it received
  `--start --read-only`, and both times the server's output in the CLI log (`--log-level all`) read
  `Tool Mode: ReadOnly`. GitHub's MCP page does not document this expansion: it is observed behaviour, so check again
  after a CLI update. The tool list does not show the mode: read-only, the server still registers all 21 tools, their
  create, update, delete, refresh and `DeployToFabric` operations included, and its log says write operations are
  "controlled by WriteGuard", that is, refused when called (not exercised). Read the mode from that log line or from
  the server's command line. The server's `--help` (1.0.0) says `--start` alone uses the default ReadWrite mode and
  does not say what it does with an argument it does not know, which is why VS Code, not probed, gets the mode written
  literally (above). On the probe machine an installed CLI plugin had registered `powerbi-modeling-mcp` with
  `@latest --start`, a read-write server beside the project's; `--disable-mcp-server` kept it out of the probe.

- **The CLI loads the harness's agents, skills and rules.** Three prompt-mode runs in a scratch clone with only
  `view`, `grep` and `glob` available, every MCP server off and writes and shell denied. The CLI's own events
  (`--output-format json`: `session.custom_agents_updated`, `session.skills_loaded`) list the 10 specialists of
  `.claude/agents/` and the 14 skills of `.claude/skills/` as `project` items, and `copilot instruction list` shows
  `.claude/rules/bi/*.md` next to their `.github/instructions` pointers. Of the two files named `bi-expert` it keeps
  `.github/agents/bi-expert.agent.md` (its description, `disableModelInvocation: true` and, with `--agent bi-expert`,
  its first sentence). `--agent bi-dax-reviewer` ran with the Claude `tools:` list (`mcp__…`, `ToolSearch`,
  `powerbi-modeling/*`) without an error, and its profile carried the read-your-skill line. Asked a BI question without
  `--agent`, the model answered directly and delegated to no agent; the list the delegation tool offers is not logged,
  so what `disable-model-invocation` blocks in the CLI is not shown. Not exercised: whether `powerbi-modeling/*` gives a
  specialist the server's tools (the servers were off). The CLI's `copilot app` command opens the GitHub Copilot app;
  whether the app's sessions load the same files is not probed.

- **Installed CLI plugins join every session.** On the probe machine the `fabric-skills` and `powerbi-authoring`
  plugins added 4 agents and 26 skills next to the harness's, among them two `semantic-model-authoring` skills that
  overlap `bi-semantic-model`, and the read-write `powerbi-modeling-mcp` above. Pick `bi-expert`, which routes through
  `bi-map`, name the harness skill when the model reaches for a plugin's, and see what is installed with
  `copilot plugin list`; `copilot plugin disable <name>` turns one off (the CLI has no flag that does it for one
  session).

- **The CLI runs every registration it finds**: both `.github/hooks/*.json` files and the Claude registration in
  `.claude/settings.json` or `.claude/settings.local.json`, in a folder you trusted in the CLI, with `command` as a
  shell string (PowerShell on Windows, bash elsewhere) from the repository root; `args` are ignored and
  `${CLAUDE_PROJECT_DIR}` is not substituted. Since 2026-10-08 the Claude registration is the plain string
  `node hardening/hooks/<script>.mjs`, which runs there; its earlier exec form (`"command": "node"`, `args`) ran bare
  `node`, failed on the payload and made the CLI refuse every tool (`Denied by preToolUse hook from "repo settings"
  (hook errored)`). Each hook now runs three times per call, one copy after another: the VS Code file, the CLI file,
  then the Claude registration (Copilot CLI 1.0.103, probed 2026-10-28). Each `ask` was a prompt of its own; a deny or
  a refused prompt ends the call, an allow or no answer lets the next copy run. So under Copilot CLI, recognised by
  `COPILOT_CLI` (set for every copy; observed, not documented), the first copy of a guard ask asks, and a later copy of
  the same ask for the same call prints nothing and is logged as `repeat` in `security-events.jsonl`. The GitHub Copilot
  app also ran all three copies and prompted once per copy (the 2026-10-22 lab); whether it sets `COPILOT_CLI` is not
  probed, so like VS Code's Copilot harness it still prompts per copy unless it does. Any host started from a shell
  that exports `COPILOT_CLI=1` inherits it and counts as the CLI, and a state record forged under `.claude/logs/`
  through a spelling the shell guard does not match (`.claude//logs`, a variable, a script) still silences the copies
  (`hardening/REFERENCE.md`, PreToolUse). The CLI passes no call id and stamps every call of one model message with one instant, so a
  call is its session, instant, tool and raw arguments, and the ask its reason; whatever the guard cannot read or
  record asks. A model write is recorded once per call (its tool, request and timestamp), and every later copy repeats
  the verdict the first copy gave the same Stop event (its timestamp) instead of counting a second stop. The audit log
  keeps one row per copy, each with its `copy` (`vscode`, `copilot-cli`, `claude`). Keep the Claude registration: it
  is what a team commits in `.claude/settings.json`; `--update --enable-hooks` replaces the old form.
- **File and MCP tools are judged by shape.** `view`, `edit`, `create`, `grep`, `glob`, `rg` and Claude's names with the
  CLI's fields (`path`, `paths`, `old_str`, `new_str`, `file_text`) become the Claude calls the policy knows, as do MCP
  tools named `<server>-mcp-<tool>` or `<server>-<tool>`: a `view` of `.env`, an edit of `templates/`, a Desktop-owned file or an MCP deploy
  is refused, a `grep` over several `paths` is judged path by path, arguments sent as a JSON string are read like the
  object and arguments that cannot be read ask, a masked result reaches the model (`modifiedResult`), and a tool the
  translation does not know is logged as `unmapped` instead of being guarded. Verified with probe payloads in real CLI
  sessions and in `hardening/tests/copilot-claude-dialect.test.mjs`.
- **Start the CLI with `--allow-all-tools` and keep the harness mode `auto`.** Without the flag the CLI asks for every
  tool call on its own, and the user stops reading: in the lab session a model deploy was approved that way. Never
  combine `lab` mode with the CLI's own prompts: `lab` turns the harness's judgement off and the prompts give none back.
  Since 2026-10-08 the guard asks for a deploy typed on the command line (a `-Deploy` switch, `createOrReplace`,
  `Invoke-ASCmd`, a `deploy*.ps1` script) in every mode, `lab` included; a deploy hidden inside a script it cannot see
  is still yours to catch. In the CLI a PreToolUse verdict blocks and a Stop block sends the agent back for another turn
  (`decision: block`); a PostToolUse block reaches the model as context, so the pre-commit hook and CI stay the net
  behind the guard.

**Editors as Copilot subagents.** Each agent that can write (`bi-tmdl-modeler`, `bi-pbir-editor`, `bi-rdl-editor`,
`bi-ssis-editor`, `bi-doc-generator`) has a second file, `.github/agents/<name>.agent.md`: the same `name`, a `tools`
list in Copilot's spellings and a short body that sends the model to the Claude file. Why: in the owner's lab (GitHub
Copilot app, 2026-10-22) the main agent delegated to `bi-pbir-editor` twice and both times the subagent answered that it
had only `view`, `grep` and `glob`, so the main agent made the edits itself; the read-only reviewers worked, so they have
no copy. GitHub's alias table lists `Edit`, `MultiEdit`, `Write` and `NotebookEdit` as compatible aliases of its `edit`
tool and `Bash`, `shell` and `powershell` of `execute` (custom agents configuration, read 2026-10-25), so the Claude
`tools:` list should have mapped; in the app it did not, and why is not known. The copies list GitHub's lower-case
primary aliases (`read`, `search`, `edit`, `execute`), the CLI's runtime names (`view`, `grep`, `glob`, `edit`, `create`,
`str_replace_editor`, `bash`, `powershell`; the hooks translate each, a test checks it), VS Code Local's names
(`edit/editFiles`, `edit/createFile`, `edit/createDirectory`, `execute/runInTerminal`, `read/readFile`, `search/...`;
VS Code's tools reference warns not to assume they map to Copilot harness tools) and, where the Claude file has them,
the two MCP servers. Each host ignores a name it does not know (GitHub: "All unrecognized tool names are ignored";
VS Code, Local: "Unavailable tools are ignored"). The copies carry no `disable-model-invocation`: its default is `false`,
and VS Code defines it as preventing other agents from invoking the agent as a subagent, so `bi-expert` can delegate.
`bi-pbir-editor.md` and `bi-pbir-editor.agent.md` give one id (GitHub: the id is the file name without `.md` or
`.agent.md`); the CLI keeps the `.github/agents` file (observed for `bi-expert`, 2026-10-17), while neither VS Code page
says which one wins, so check the picker. The scope hook does not run in Copilot (no `agent_type`), so each copy tells the
model to stay in its folders, write with the edit tools only and hand everything else back: a request to the model, not a
guard. Not verified: a live delegation from `bi-expert` to an editor in the Copilot app, the CLI or VS Code. Without
`disable-model-invocation` the cloud agent may also pick an editor on its own from its description, outside `bi-expert`'s
loop; the copy's first instruction (read `AGENTS.md`) is what holds it to the working agreement there.

**Cursor.** Reads `AGENTS.md`; nothing else to set up. Its own rules live in `.cursor/rules/`; the harness does not
ship any, because `AGENTS.md` already points at the rules by path. Configure MCP in Cursor's settings.

**Gemini CLI.** Add `AGENTS.md` to the context files in `.gemini/settings.json`:

```json
{ "context": { "fileName": ["AGENTS.md", "GEMINI.md"] } }
```

MCP servers go under `mcpServers` in the same file.

**OpenAI Codex (CLI and IDE extension).** Reads `AGENTS.md` natively: from the project root down to the working
directory, `AGENTS.override.md` first, one file per folder, up to `project_doc_max_bytes` (32 KiB by default; the
harness's `AGENTS.md` is about 12 KB). Everything else is by path: Codex discovers skills only under `.agents/skills/`
(repository root, working directory, `~/.agents/skills`), so the `$skill` menu does not list `.claude/skills/`; tell it
to read `.claude/skills/bi-map/SKILL.md` first. Codex has hooks of its own (`<repo>/.codex/hooks.json` or
`[[hooks.PreToolUse]]` tables in `.codex/config.toml`, the same `hooks` → event → `matcher` / `type: "command"` shape
and the same stdin fields as Claude Code's, a block by exit code 2 or `hookSpecificOutput.permissionDecision: "deny"`;
project hooks run only in a trusted `.codex/` layer and after you trust each hook's hash with `/hooks`). The harness
does not ship a registration for them: Codex parses an `"ask"` decision but does not support it, and the harness's
floor (push, deploy, publish, scripts) is an ask, so a copied registration would silently drop exactly those checks.
Not tested by us. MCP servers go into Codex's `config.toml`; keep the modeling server read-only.

## Switching agents in the middle of a task

Before you switch (for example when a usage limit ends a Claude session), run `/bi-handoff` (Claude Code, or
Copilot Chat: the same user-invoked skill). It writes `TASKS.md` and `docs/handoff.md`; `AGENTS.md` tells the next agent to read
both before acting, so it continues from the recorded state instead of rediscovering it.

The harness works best with strong models. A weaker model may skip the router: tell it to start with
`.claude/skills/bi-map/SKILL.md` and to say which path (A or B) it is on. A first message that works with any model:
"Read `AGENTS.md` and `.claude/skills/bi-map/SKILL.md`, say which path you are on (A: a modeling MCP server answers;
B: files only), then `<the task>`."
