# Project conventions

Optional. Conventions your team decided that differ from the harness defaults. Where a line here conflicts with
`.claude/rules/bi/` or a checklist, this file wins for that line (`AGENTS.md`). It never relaxes Tier 2, security or the
evidence rules. Keep each entry checkable, and record why in `docs/decisions.md`. `/bi-onboard` drafts a first version
from what it finds in the repository.

<!-- Examples, delete what does not apply:
- Layout: this repository keeps its Power BI projects in `src/pbip/` and its paginated reports in `ssrs/` instead of
  the recommended layout (`docs/harness/layout.md`); the registry `docs/sources/README.md` lists every project.
- All measures live in one table named `Measures` (pattern: a one-row calculated table); none on fact tables.
- No `///` descriptions in TMDL; measure and column descriptions live in docs/model/.
- Transformations happen in the source SQL: a partition is one native query, no Power Query steps after it.
- Visible names in <language>, in title case; hidden keys and base columns keep the source name in lowercase.
- Display folders are mandatory; every measure has a format string except measures that return text.
- Interactive reports follow the house template in `docs/design/` (theme, backgrounds, slot map); where it differs
  from `bi-report-design`, the template wins.
-->
