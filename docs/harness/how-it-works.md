# How the harness works

The README gives the short version. This page says what loads when in Claude Code, how the path, Tier 2 and the
evidence play out in a session, and where the records live. The rules themselves stay in the files that own them:
`AGENTS.md` (the loop, Tier 2, verification), `bi-map` section 3 (Path A and B per capability),
`hardening/README.md` (approvals modes, what the guard asks and denies).

## What loads when (Claude Code)

| Piece | Where | Loads | Source |
|---|---|---|---|
| Working agreement | `AGENTS.md` | at session start, as project instructions, when no `CLAUDE.md` or `CLAUDE.local.md` exists in the folder or above it (the Claude Code version: [faq.md](faq.md#versions-we-tested)). With a `CLAUDE.md`, only that file loads: put the line `@AGENTS.md` in it | [memory](https://code.claude.com/docs/en/memory) |
| Main agent | `.claude/agents/bi-expert.md`, chosen by `"agent": "bi-expert"` in `.claude/settings.json` | at session start; it replaces the default system prompt | [subagents](https://code.claude.com/docs/en/sub-agents) |
| Skills | `.claude/skills/<name>/SKILL.md` | on demand when the description matches, or by `/<name>`; seven are user-invoked only (`disable-model-invocation: true`) | [skills](https://code.claude.com/docs/en/skills) |
| Rules | `.claude/rules/bi/*.md` with `paths:` frontmatter | when a matching file is read, written or edited; `markdown.md` for any `.md`, `harness.md` for `.claude/**` and `hardening/**` | [memory, rules](https://code.claude.com/docs/en/memory) |
| Subagents | `.claude/agents/*.md` | when the main agent delegates (`Agent(name)`) | [subagents](https://code.claude.com/docs/en/sub-agents) |
| Hooks | `hardening/settings.hooks.json`, merged into `.claude/settings.local.json` or `.claude/settings.json` | around every tool call, at session start, on every prompt, when the agent wants to finish | [hooks](https://code.claude.com/docs/en/hooks) |
| MCP servers | `.mcp.json` (from `.mcp.example.json`) | at session start, if you created the file | [MCP](https://code.claude.com/docs/en/mcp) |

`/context` lists what is loaded; with the hardening pack, `.claude/logs/instructions.jsonl` records which rule loaded
and why. A weaker model may skip the router: tell it to start with `.claude/skills/bi-map/SKILL.md`.

## A task, step by step

The contract is `AGENTS.md`, "One loop". What you see in a session:

- The agent reads `TASKS.md`, `docs/handoff.md`, `docs/decisions.md` and `docs/conventions.md` first, then `bi-map`
  routes the request (`Skill(bi-map)`), and the owning skill loads.
- It names the path it is on. Path A and B are decided per capability (`bi-map`, section 3): the modeling MCP server
  is the one that changes the evidence (engine result vs. a test pack you run); the report CLI, the Desktop CLI and the
  hardening pack each have an A and a B as well. A prohibition is a decision, not an obstacle.
- A business fact the files do not hold is one question with a recommended answer; everything else proceeds on a
  default that changes no existing result, recorded in `docs/decisions.md`.
- One writer at a time: the agent's text edits, or Desktop, or an authorized MCP write.
- The static check runs after every batch of edits, the changed logic is reviewed, and the answer separates static,
  engine and Desktop evidence (`AGENTS.md`, "Verification"). Missing engine access is "not tested", never "passed".

## Tier 2 in practice

The list is in `AGENTS.md`, "Editing boundaries". How it plays out:

- A request that names the change sets its scope ("rename X to Y" is the approval for that rename); the agent still
  shows the impact first: references in the model and the reports, other reports or users affected, what it cannot
  test.
- One approval per scope; it is reused for that exact scope and never stretched. "Do not ask me" approves only the
  Tier 2 items the request names.
- A denied or unapproved step stops the whole change: no partial application, files left consistent.
- The hardening pack's guard has its own set, not the whole Tier 2 list. A TMDL rename or delete and a relationship edit
  (in any TMDL file) ask in `auto` and `ask` mode and are never auto-approved; only `lab` runs them. The files whose
  edit it cannot judge (roles, data sources, expressions, the registry, the harness's own files) ask in `lab` too, and
  role members are denied. `hardening/README.md`, "Approvals", has the lists.

## Approvals modes

`approvals.mode` in `hardening/harness.config.json`: `auto` (default), `ask` or `lab`; the table and the exact
categories are in `hardening/README.md`, "Approvals". Only you widen the mode; the agent can make it stricter. You
change it in your editor or with a `!` command typed in Claude Code's own input box (not in a terminal); the `ask`
rules of `.claude/settings.json` prompt in every mode.

## The records

- `TASKS.md`: state per task. `docs/decisions.md`: decisions, assumptions, known issues, open questions, test results,
  each result with the command or pack, the commit it ran against and its evidence label. `docs/handoff.md`: where the
  last session stopped, for the next session or agent (`/bi-handoff`).
- `docs/sources/README.md`: the registry; it decides what the agent may change. `docs/conventions.md`: your deviations
  from the defaults, including your layout.
- The answer of every task follows one template: Changed, Static, Model check, Verify in Power BI Desktop, Open
  decisions (`.claude/agents/bi-expert.md`).
