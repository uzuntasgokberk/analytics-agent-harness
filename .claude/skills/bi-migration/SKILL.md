---
name: bi-migration
description: Rebuild a report from another BI tool or an older report (MicroStrategy, Tableau, Qlik, SSRS, Excel, a legacy Power BI file) as a PBIP - grade the evidence, settle scope, prove the source grain, map every object to the model and report, and reconcile the numbers against the source. Use when the user supplies source report definitions, SQL, screenshots or exports and wants the same report in Power BI.
---

# Migrating a report into PBIP

A migration succeeds when business logic, grain and filter context survive; screens that look alike are not the
goal. Analyze and plan before building, and get the plan approved. The work itself is ordinary PBIP work: the model
belongs to `bi-semantic-model` and `bi-data-sources`, the report to `bi-pbir-report`. This skill adds what a
migration needs on top: evidence, scope, mapping and reconciliation.

## 0. One workspace per report

In a repository with several reports, give each its own folder, `reports/<report>/` with `source/` (the inputs:
definitions, SQL, screenshots, exports without personal data; read-only), the new artifacts, `tests/` and `docs/` (copy
`templates/report-dossier/`: overview, mapping, decisions). The layout is described in
`.claude/skills/bi-paginated-report/REPLATFORM.md`, section 1; a single-report repository can use `docs/` instead.

### What the user hands over, per tool

The user copies these into `reports/<report>/source/` (the agent cannot write there). Ask only for what is missing.

| Source tool | Definition (what it means) | Control values (what it shows) |
|---|---|---|
| Tableau | the `.twb`; from a `.twbx` (a zip) the `.twb` inside it. Extracts (`.hyper`) are data: not needed; note their filters and refresh date | a crosstab export of each sheet, with the filters stated |
| Power BI (an older `.pbix`) | Desktop's "Save as" Power BI project (PBIP), which gives TMDL and PBIR | an export of each visual's data, or a DAX query result |
| Qlik Sense / QlikView | the load script and the master items (dimensions, measures with their expressions); an app export (`.qvf`, `.qvw`) is binary | a sheet object's data exported to Excel or CSV |
| MicroStrategy | the report's SQL view and its metric definitions (or an object export) | the grid exported to Excel or CSV |
| SSRS / Report Server | the `.rdl` and its shared data sources and datasets; the stored procedure text | the report exported to Excel or CSV for named parameter values |
| Excel | the workbook (formulas, pivot fields and their source range or query); a screenshot is not a definition | the sheet values for one stated filter set |
| Any tool | the source SQL, view DDL or query text | screenshots only for layout and labels |

## 1. Grade the evidence

Collect what exists and label every fact (labels: `docs/decisions.md`). Stronger evidence wins a conflict, but report
the conflict; do not resolve it silently.

| Evidence | Use | Watch out |
|---|---|---|
| the user's explicit rule `[user]` | binding | write it down as a decision |
| source tool definition `[source]`: report definition, metric formulas, filters, sort, totals | what the report means | a screenshot of the tool's editor or design view is a definition |
| source SQL or view DDL `[sql]` | grain, joins, filters, windows | the real grain lives here, not in the labels |
| a verified output `[output]`: export, query result | the only basis for expected values | same filters on both sides |
| screenshots of the consumer view `[image]` | layout, labels, which objects appear | masked values are not expected values |
| inference `[inference]` | a hypothesis | becomes an assumption with the test that would confirm it |

Missing inputs go into an input table (available / partial / missing / not applicable) before any plan.

## 2. Settle scope

Ask once, as one question per turn (`AGENTS.md`): "Does this scope hold?", with the points below as its sub-points,
each with a recommended answer; record the answers as decisions:

1. **Design:** source layout with the house style, the house template only, or the source look. A source tool's
   brand colors never enter a house-styled report (`docs/design-to-report.md`, house template).
2. **Coverage:** which pages, visuals and outputs are in scope, and which are explicitly out.
3. **Data:** a new model, an existing model, or a live connection to a published one (`bi-data-sources`). A model
   owned by another team is read-only: report-side work only (`.claude/skills/bi-pbir-report/PATTERNS.md`).
4. **Control values:** who can provide unmasked source numbers? Without them the result is "validation BLOCKED".
5. **Security:** row-level rules in the source tool; personal data in the source columns.

Then a feasibility verdict, FEASIBLE / FEASIBLE WITH BLOCKERS / NOT FEASIBLE, with one line each for source, model,
metrics, visuals and verifiability.

## 3. Inventory and grain

- List every source object: attributes or dimensions, metrics with their formulas, report, view and prompt filters,
  sorting, totals, conditional formats, drill paths, page or chapter structure.
- Prove the grain from the source query before writing any measure, and check the grain traps in `bi-data-sources`
  (section 4): pre-aggregated columns, row multiplication, rolling windows, missing keys.
- Derived metrics: when the tool hides the formula, ask for it. Never reconstruct one from screenshots alone.
- Parity with the source is the default. A correction (for example, no longer summing a distinct count) is a decision
  for the user; record it and say which numbers will differ.

## 4. Map

One row per source object: source name, the PBIP object (column, measure, visual, filter, slicer, page), and the
evidence label. Then the gaps:

- Objects without a Power BI equivalent become known issues with the closest alternative, for example a total row
  above the data, a descending column axis, chapters, or a selector with a dynamic default.
- Layout from screenshots: measure the source in pixels, map the source content area linearly onto the canvas
  content area, keep proportions and reading order. House chrome (logo, rails, background) stays where the
  template puts it.
- Labels: keep the model's names and show the source tool's wording through the visual ([PATTERNS.md](../bi-pbir-report/PATTERNS.md), section 1), unless the
  user wants the model renamed (Tier 2).

## 5. Build

Follow the owning skills. Copy chrome and visuals from the house template or a working visual; for many pages use a
project generator ([PATTERNS.md](../bi-pbir-report/PATTERNS.md#3-large-builds-a-project-generator) of `bi-pbir-report`, section 3). Stop for Tier 2 items. Write the test pack while building, not after.

## 6. Reconcile and report

Reconcile with `docs/test-packs.md`: expected values from the source, exact match unless the user sets a tolerance,
the minimum matrix. Report per page and output:

- **Built:** pages, visuals, measures, with the mapping rows they implement.
- **Verified:** static, engine (Path A) and Desktop evidence, each with how it was obtained.
- **Known issues and open questions:** from `docs/decisions.md`.
- **Status:** done, validation BLOCKED (no control values), or blocked (with the reason).

Never call a migration done before its reconciliation has passed. A user's own comparison counts as `[user]`
evidence; say when no numbers were recorded.
