---
name: bi-commit
description: Validate and commit the current BI changes as one Conventional Commit on a feature branch. Never pushes.
disable-model-invocation: true
argument-hint: "[optional commit summary]"
allowed-tools: Bash(git status *) Bash(git diff *) Bash(git add *) Bash(git commit *) Bash(git switch *)
---

# Commit PBIP changes

## Current state

- Branch: !`git branch --show-current 2>/dev/null || echo "(not a git repository)"`
- Changes:
!`git status --short 2>/dev/null | head -50`

## Steps

1. If the branch is `main`/`master` (or empty), create a feature branch first:
   `git switch -c feature/<short-topic>` (or `fix/<topic>`). Never commit on a protected branch.
2. Run the static check (`docs/static-checks.md`) and show its summary. Stop if there are errors.
3. Review `git diff --stat` and `git diff`. If the changes contain more than one logical change,
   propose separate commits and stage them file by file (`git add <path>`); never `git add -f` (the permission rules deny it).
   Changes the user saved from Power BI Desktop are the user's: commit them on their own (for example
   `chore(report): save from Power BI Desktop`), never in the same commit as your edits.
4. Never stage `.pbi/cache.abf`, `.pbi/localSettings.json`, `*.pbix`, `.env*` (the hardening pre-commit hook,
   when installed, rejects them).
5. Write the message as `<type>(<scope>): <summary>` with PBIP scopes: `model`, `dax`, `pq`, `rls`,
   `report`, `visuals`, `harness`, `docs`. Use the user's summary if given: $ARGUMENTS (in GitHub Copilot: the text typed after the command)
6. `git commit -m "<message>"`; if the pre-commit hook fails, show its output, fix the cause, retry.
   Never use `--no-verify` (the permission rules deny it); a message that spells a flag is denied too, so pass it with `-F`.
7. Report the commit hash and message. Do not push; pushing is a separate, explicit user decision.
