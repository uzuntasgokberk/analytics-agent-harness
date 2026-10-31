# Contributing

Thank you for helping. This repository is maintained by one person, so the process is short and fixed.

## Issues first, pull requests by invitation

- **Open an issue** for a bug, a case the harness got wrong, or a question. Use the templates: they ask for the host
  (Claude Code, Copilot CLI, the Copilot app, VS Code), the harness version from `.claude/bi-agent-harness.json` and
  the installer output.
- **Pull requests are by invitation only.** If the fix is agreed in the issue, the maintainer asks you for one; an
  uninvited pull request is closed with a pointer to the issue.
- **Security problems never go into an issue**: see [SECURITY.md](SECURITY.md).
- Never paste data, logs from `.claude/logs/`, connection strings, customer names or paths from your own projects into
  an issue or a pull request. Reproduce with fake values.

## Three identifiers never change

Every repository that installed the harness depends on them; a change that renames or moves one is refused:

1. The installer path `hardening/scripts/install-into.mjs`.
2. The manifest file `.claude/bi-agent-harness.json` and its existing fields (`harness`, `domains`, `version`,
   `commit`, `hooks`, `mergedRules`, `files`); new fields may be added.
3. Every skill, agent, rule, hook and file name the installer copies (`.claude/`, `docs/`, `templates/`, `hardening/`,
   `.github/agents/`, `.github/instructions/` and the root files it lists).

The public name of the repository is `analytics-agent-harness`; the installed pack keeps its internal name
`bi-agent-harness`. Further domains come as `domains/<name>/` in this repository, beside the paths above.

## How a change is made

- Keep it small and tied to a case the harness got wrong.
- Knowledge goes into Markdown (skills, rules, docs); enforcement goes into `hardening/` with a test first. Every
  behaviour change in `hardening/` needs a test in `hardening/tests/` ([.claude/rules/bi/harness.md](.claude/rules/bi/harness.md)).
- Markdown files stay under 500 lines (`AGENTS.md` under 200).
- Commits follow Conventional Commits (`feat(skill): ...`, `fix(hooks): ...`).
- Contributions are licensed under the repository's license, GPL-3.0-or-later with the attribution term in
  [NOTICE](NOTICE).

## Run the checks locally

Node.js 18.17 or later is the documented minimum (`engines` in `hardening/package.json`); CI tests Node 24 only, on
Windows and Ubuntu. From the repository root:

```bash
node hardening/scripts/check-hooks.mjs      # every hook file parses and its imports load
npm --prefix hardening test                 # the pack's tests
node hardening/scripts/validate.mjs         # the static check over the repository
node hardening/scripts/release-check.mjs    # personal data, broken links, Markdown limits, frontmatter
```

The first three must pass everywhere before a pull request. `release-check` walks the file system, so it passes on a
clean checkout or a `git archive` export; in a working clone, local gitignored state (`.claude/logs/`,
`.claude/settings.local.json`) shows as findings and makes it exit 1. CI (`.github/workflows/ci.yml`) runs the same
steps on a clean checkout. More on the tests and the eval: [README, Testing the harness](README.md#testing-the-harness).

## Releases

1. A pull request with CI green on both jobs (Windows and Ubuntu), then an independent review of its diff.
2. The owner merges it.
3. An annotated tag on the merge commit, `git tag -a vX.Y.Z -m "vX.Y.Z" <merge commit>`, pushed with `git push origin vX.Y.Z`.
4. A GitHub Release for the tag, with notes: what changed for a user, whether `--update` is needed, and every behaviour
   change (a new ask or deny, a changed default).
5. Check it: `node hardening/scripts/install-into.mjs <project> --update` in a project on the previous release.

The pull request that changes the pack bumps `version` in `hardening/package.json`: patch for fixes, minor for new
behaviour or a new ask, major for a change that breaks an install or an update.
