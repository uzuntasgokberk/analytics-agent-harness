---
paths:
  - "**/*.md"
---

# Markdown rules

- Limit: 500 lines per `.md` file you write. With the hardening pack installed, its guard hook denies any write
  that grows a file past it and its validator and pre-commit hook fail on it; otherwise check by hand.
  Microsoft's vendored references are the exception (`scan.exclude` in the hardening config).
- When a document approaches the limit, split it: keep a short index file and move sections into linked
  sub-files (`docs/<topic>/<part>.md`, or reference files next to a skill's `SKILL.md`).
- `AGENTS.md` should stay under 200 lines: facts every session needs. Procedures go into skills,
  file-type conventions into `.claude/rules/bi/` with `paths:` frontmatter.
- Link with relative paths; never duplicate the same content in two files.
