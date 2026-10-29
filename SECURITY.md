# Security policy

## Report a vulnerability privately

Use GitHub's private vulnerability reporting: the repository's **Security** tab, then **Report a vulnerability**
([direct link](https://github.com/uzuntasgokberk/analytics-agent-harness/security/advisories/new)). Do not open a
public issue, discussion or pull request for a security problem.

Include:

- the harness `version` and `commit` from `.claude/bi-agent-harness.json` in the repository where it happened;
- the host and its version (Claude Code, Copilot CLI, the Copilot app, VS Code) and the approvals mode
  (`hardening/harness.config.json`);
- the smallest command, tool call or hook payload that reproduces it, with the verdict you expected and the one you got.

**Never send secrets or data**, in a report or anywhere else: no real passwords, tokens, keys or connection strings, no
customer rows, and no files from `.claude/logs/` (they hold the commands, paths and session details of your machine).
Reproduce with fake values; if a real credential was exposed, rotate it first.

This is a personal project maintained on a best-effort basis. Fixes go to the latest `main` only; update with
`git pull` in your harness clone and `install-into.mjs <repo> --update`.

## What counts

- The guard lets a call through that the documentation says it denies or asks for (a secret read, destructive Git or
  shell, a publish or deploy, a write into a reference folder, a role or data source change).
- Output masking misses a credential shape it claims to mask.
- The installer reads, writes or deletes outside the target repository, or removes a file the user changed.
- A hook that should fail closed lets calls through.

The documented limits are not vulnerabilities: hooks fail open when `node` is missing or too old, commands typed with
the `!` prefix are not checked, shell analysis is textual, and masking runs after the tool
([README, Safety model and limits](README.md#safety-model-and-limits)).

## What the harness never does

The agent never deploys or publishes, refreshes a shared model, handles credentials, manages RLS or OLS membership,
force-pushes, disables hooks, changes data in your databases or runs SQL or MDX on its own; it hands you the steps
instead. The hardening pack is a safety net, not a sandbox: it denies and asks for the cases above, masks secrets in
tool output and logs every tool call to `.claude/logs/` on your machine, which is never committed. Its hooks and
scripts make no network calls; the optional MCP servers in `.mcp.example.json` are yours to enable.
