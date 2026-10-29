---
paths:
  - "**/*.tmdl"
---

# TMDL rules

- Indent with tabs only. Object at N tabs, its properties at N+1, a multi-line expression at N+2
  (or wrap the expression in triple backticks to keep it verbatim).
- Quote names that contain spaces or special characters: `measure 'Sales YoY %'`; escape `'` as `''`.
- Descriptions are `///` lines directly above the object declaration, with no blank line between (TOM: "Unexpected line
  type: Empty"). A relationship has no description in the Tabular
  Object Model: a `///` above `relationship` makes Desktop refuse the project ("Property 'description' is unknown").
- A measure never takes the name of a column of its table (Desktop: "measure cannot be created because a column with the
  same name already exists"). Name the hidden base column after its content (`Target Value`) and the measure after the
  business term.
- Never invent a `lineageTag` and never copy one from another object; omit it on new objects and let
  Power BI Desktop generate it.
- Follow the property order used by neighbouring objects in the same file; don't reorder untouched objects.
- Renaming or removing a table, column, measure, hierarchy or calculation item is Tier 2: get the user's approval first (the
  hardening pack's guard also asks for each such edit in `auto` and `ask` mode, not in `lab`). Then change the declaration first and every reference (DAX, visuals, filters) in the
  same batch, so a refusal leaves nothing half renamed. Paginated reports (`*.rdl`) whose DAX datasets query the model
  are references too, and so are the model's own `perspectives/*.tmdl` and `cultures/*.tmdl` (translations and the
  `linguisticMetadata` JSON of Q&A): rename or remove the entry with the object, and keep the translated caption.
- A new object, perspectives and translations: `.claude/skills/bi-semantic-model/SKILL.md`, section 8.
- Don't touch `LocalDateTable_*` / `DateTableTemplate_*` (auto date/time tables; a permission rule denies it).
- Check the table's partition before adding a column or calculation: Direct Lake (`= entity`, `mode: directLake`),
  DirectQuery and the remote tables of a composite model (`EXTERNALMEASURE`) have limits, for example no calculated
  column on a Direct Lake on SQL table (`.claude/skills/bi-data-sources/storage-modes.md`).
- A model deployed to Analysis Services (outside `*.SemanticModel`, with `database.tmdl`): use only what its
  `compatibilityLevel` supports; the user deploys and processes it (`.claude/skills/bi-semantic-model/ssas-tabular.md`).
  Files under `docs/sources/*/definition/` are reference copies of a model owned elsewhere (`.claude/rules/bi/sources.md`).
- After a batch of edits run the static check (`docs/static-checks.md`); then tell the user to apply the change in
  Desktop, or to deploy and process a model on Analysis Services.
- Syntax reference (Microsoft's guideline): `.claude/skills/bi-semantic-model/references/tmdl-guidelines.md`.
