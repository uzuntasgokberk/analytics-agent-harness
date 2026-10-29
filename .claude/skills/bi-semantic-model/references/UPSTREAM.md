# Upstream provenance

Every file in this folder except this one is copied **unmodified** from Microsoft's Skills for Fabric.

- Repository: https://github.com/microsoft/skills-for-fabric
- Path: `skills/semantic-model-authoring/references/`
- Commit: `6c11ad58c25992e5d1435ce7cd80d217d5598a31` (release v0.3.18, 2026-09-24)
- License: MIT, Copyright (c) 2026 Microsoft Corporation. Full text: `THIRD_PARTY_NOTICES.md` at the repository root.

## Reading notes

- Upstream calls the MCP route "Tier 1" and the no-MCP route "Tier 2". Here they are **Path A** and **Path B**
  (see `../SKILL.md`). "Tier 2" in this repository's `AGENTS.md` means something else: an item that needs the
  user's approval.
- Upstream `az rest`, `getDefinition` and `updateDefinition` mentions belong to Fabric service management,
  which this harness never does. Treat them as out of scope.
- Two files are longer than this repository's 500-line limit for authored Markdown (`tmdl-guidelines.md`,
  `dax-perf-patterns.md`). They stay verbatim so they can be diffed against upstream.

## Not copied on purpose

`connection-binding.md` and `semantic-model-rest-api.md`: Fabric REST management (deploy, permissions, connection
binding), outside a harness that never deploys. Upstream also ships `powerbi-report-cli`, a report skill that
depends on Microsoft's `powerbi-report-author` CLI; see `bi-pbir-report` and the report CLI notes in `bi-map`.

## Updating

1. Diff these files against upstream at a newer commit and read the diff.
2. Copy the changed files, then change the commit above.
3. Never edit these files in place. Put harness-specific rules in `../SKILL.md` or `.claude/rules/bi/`.
