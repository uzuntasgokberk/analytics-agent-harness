---
paths:
  - "**/*.Report/definition/**/*.json"
  - "**/*.Report/definition.pbir"
---

# PBIR rules

- Keep the `$schema` of every file exactly as Power BI Desktop wrote it; the schema defines valid properties.
- Page, visual and bookmark folder names: letters, digits, `_` or `-` only. Desktop ignores anything else.
- The `name` property of `page.json` / `visual.json` equals its folder name. Renaming breaks references
  (drillthrough, bookmarks) and requires a Desktop restart.
- Adding or removing a page: update `pages/pages.json` (`pageOrder`, `activePageName`). Deleting pages is Tier 2.
- New visuals: copy a `visual.json` of the same type, from the first source in `bi-pbir-report`, Before you edit,
  step 2, and change the query/position, rather than writing one from scratch. Keep `position` inside the page size.
- Don't write literal data values (customer names, IDs) into filters or slicer states.
- `definition.pbir` binding changes (`byPath`/`byConnection`) are Tier 2.
- Structure reference: `.claude/skills/bi-pbir-report/STRUCTURE.md`.
- **Page on a canvas background (house template):** every visual sits inside exactly one panel of the background and
  takes its position from the template's slot map (the house template named in `docs/conventions.md`), never by eye. Slot = panel inset
  4 px; the theme's padding gives the same content inset in every panel; rail controls start at the logo's x; KPI
  content starts beside its icon badge and is centred on it; no rendered content crosses a panel border or the top band. When a
  visual type renders its content off-centre (the new Card does), correct its position from a measurement and write
  the numbers into the slot map. The check is a Desktop screenshot measured at 2x, not the JSON.
