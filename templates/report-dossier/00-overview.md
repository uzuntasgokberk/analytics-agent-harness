# <Report>: overview

<!-- Copied from templates/report-dossier/. Facts carry an evidence label: [user] [source] [sql] [output] [image] [inference]. -->

| | |
|---|---|
| Status | NOT STARTED / IN PROGRESS / BLOCKED (why) / READY FOR REVIEW / DONE |
| Route | move as is / re-platform onto a semantic model / rebuild as an interactive report |
| Business owner | <name or team> |
| Readers and decision | <who reads it, what they decide> |
| Source | `source/<file>.rdl`, `source/<procedure>.sql` |
| New artifacts | `pbip/`, `rdl/<file>.rdl`, `sql/` |

## What the report does

<!-- One paragraph in business language: the question it answers and how often it runs. -->

## Parameters

| Parameter | Type | Default | Multi-value | All / NULL behaviour | Evidence |
|---|---|---|---|---|---|

## Done when

- [ ] The partition SQL equals the files in `sql/`.
- [ ] The old and new RDL are identical outside the data layer, or each difference is accepted in `02-decisions.md`.
- [ ] The DAX check pack in `tests/` passes.
- [ ] Row counts match the procedure for every named parameter set.
- [ ] The user ran the old and the new report with the same parameter sets and compared rows, totals and pages.
