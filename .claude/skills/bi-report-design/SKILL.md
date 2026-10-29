---
name: bi-report-design
description: Design rules for interactive Power BI reports - who the page is for, page types, layout and reading order, choosing a visual for the question, numbers and labels, color and themes, titles and text, interaction, accessibility, performance, and a design review checklist. Use when planning a page or report, choosing or changing visuals, building from a design, or reviewing a report's design; project rules in docs/conventions.md come first.
---

# Report design

A report page exists to answer a question for someone who has to decide or act. Design is how quickly and correctly
they get that answer. These rules are defaults; a team's own rules in `docs/conventions.md` (house template, brand,
naming, page sizes) replace the matching default. Structure and file edits: `bi-pbir-report`. Paginated layouts:
`bi-paginated-report`.

## 1. Start from the reader

Before any visual, write down in the page plan:

- **Who** reads the page and **what decision** it supports.
- **The one question** the page answers first, and the two or three follow-up questions.
- **The numbers** that answer them, each mapped to an existing measure. A missing measure is model work the request
  must name: propose it and wait for the user before adding it; in a model owned elsewhere it is a change request.
  (`AGENTS.md` does not list new measures as Tier 2; this rule keeps design work from widening the model's scope.)
- **How often** and **where** it is read (a weekly meeting on a projector, a phone, an emailed export).

A page that answers several unrelated questions becomes two pages. A request for "everything on one page" is a list of
questions: sort them and propose the pages.

## 2. Page types

| Type | Job | Typical content |
|---|---|---|
| Overview | status at a glance | 3-5 headline numbers with comparison, one trend, one breakdown |
| Analysis | explain a number | a breakdown by the dimensions that matter, slicers for scope |
| Detail | look up records | a table or matrix with a few key columns, reached by drill-through |
| Drill-through | the same question for one member | page context at the top, the member's numbers below |
| Tooltip | a little more on hover | one small visual or two numbers |

Navigation follows the questions: overview → analysis → detail. Hidden drill-through and tooltip pages are named for
what they show.

## 3. Layout

- **Reading order:** the most important number top left, then left to right and top to bottom. Slicers that scope the
  whole page sit together (a top band or a left rail), not between visuals.
- **A grid:** align visuals to shared edges, keep equal gaps, and give every page the same margins, header and slicer
  position. A house template decides these values; copy them, do not retype them.
- **Size by importance,** not by what fits. Headline numbers are large and few; a detail table gets the width it needs.
- **Density:** about 6-8 visuals per page answer a question; more than 15 is a design and performance warning.
- **Space is structure:** group related visuals with spacing before you reach for borders and backgrounds.
- **Page size:** the house size, or 1280 × 720 (16:9). Every visual stays inside the page and nothing overlaps unless it
  is deliberate (a background shape).

## 4. Choose the visual for the question

| Question | Use | Avoid |
|---|---|---|
| how much, right now | card or multi-card with a comparison (vs. target, vs. last period) | a gauge without a target |
| compare categories | bar chart (long names, many items), column chart (few items or time) | pie with more than a few slices |
| change over time | line chart; column chart for few, discrete periods | many crossing lines: use small multiples |
| part of a whole | stacked bar or 100% bar; a pie or donut only for 2-4 parts | 3D, exploding slices |
| what moved the total | waterfall chart | a table of deltas |
| two measures together | scatter (relationship), combo (different scales) | two unrelated axes on one chart without labels |
| ranking and change in rank | bar chart sorted by value; ribbon chart for rank over time | unsorted bars |
| where | a map only when location matters to the decision | a map as decoration |
| exact values, lookup | table or matrix with few columns, totals where they mean something | a wide table on an overview page |
| progress to a goal | KPI visual, or a card with target and variance | color without the number |

New reports avoid the Q&A visual: Microsoft has scheduled it for deprecation in December 2026 (Learn; not re-checked on 2026-10-19). Built-in visuals come
first; a custom visual needs a reason, a trusted source and approval (Tier 2).

## 5. Numbers and labels

- **Formats come from the model** (`formatString`); a visual-level format is the exception and is recorded.
- **Units fit the reader:** thousands or millions with the unit in the title or axis, a consistent number of decimals
  per page, percentages with the base made clear.
- **Every number has a comparison** (target, previous period, plan) or it cannot be judged.
- **Bar and column axes start at zero.** A line chart may zoom in when the change, not the level, is the point.
- **Label the data or the axis, not both;** remove gridlines and legends the labels make redundant.
- **Sort deliberately:** by value for comparisons, by the natural order for time and ordinal categories.
- **Totals only when they mean something;** a total of a ratio or a distinct count needs the right measure, not a sum.

## 6. Color and theme

- **Colors live in the report theme,** not as literals on visuals. Which theme, in this order: the project's
  `docs/design/theme.json`, the theme of a house PBIP in `templates/house/`, else the harness default
  [default-theme.json](default-theme.json) (neutral, brand-free). A report never stays on Desktop's base theme alone.
- **No custom theme yet** (`report.json` has only a `baseTheme`): register one as [THEME.md](THEME.md) says (file under
  `StaticResources/RegisteredResources/`, `customTheme` and `resourcePackages` in `report.json`, validate, Desktop check)
  and record its origin in `docs/decisions.md`. THEME.md also holds the default look and the page recipe without a house
  template. Replacing a project's theme is the user's decision.
- **One neutral base, one or two accent colors** that carry meaning (the focus series, the selection).
- **Semantic colors are reserved:** red and green (or the house pair) only for bad and good, and used the same way on
  every page.
- **Color is never the only signal:** pair it with a label, an icon or position, so color-blind readers and printouts
  still work.
- **Conditional formatting highlights exceptions,** not every cell.

## 7. Titles and text

- **A title says what the visual answers** ("Sales by region, last 12 months"), or states the finding when the page is
  a story ("North fell behind plan in Q3").
- **Subtitles carry the context** a reader would otherwise miss: the filter, the currency, the as-of date.
- **Names match the model's display names;** a different wording for one visual goes through the projection's display
  name, not a model rename (`bi-pbir-report`, `PATTERNS.md`).
- **Every visual that carries information has alt text** that states what it shows and why it matters.

## 8. Interaction

- **Cross-filtering is a feature;** turn it off between visuals only when the result would mislead.
- **Slicers:** few, at the same place on each page, synced across pages when they scope the same thing; a relative date
  slicer for rolling periods (`bi-pbir-report`, `PATTERNS.md`).
- **Drill-through for detail,** tooltip pages for a little more; bookmarks only for a clear purpose (a view toggle),
  because each one is state someone has to maintain.
- **Buttons and navigators** follow the page flow of section 2.

## 9. Accessibility

Microsoft Learn: [accessibility in Power BI](https://learn.microsoft.com/power-bi/create-reports/desktop-accessibility-overview) (WCAG 2.1).

- Alt text on every informative visual; decorative shapes are hidden from the tab order.
- A tab order that follows the reading order of section 3.
- Text contrast of at least 4.5:1; no small light-grey text on white.
- Information never in color alone (section 6); markers and labels on lines.
- Titles and labels readable at the size the page is used.

## 10. Performance

- Fewer visuals load faster; one overview page should not query everything.
- High-cardinality slicers (thousands of items) are slow and hard to use: search or a hierarchy instead.
- Tables with many rows and many measure-based conditional formats are the slowest visuals; keep them on detail pages.
- Measures that are slow in every visual are a model question (`bi-semantic-model`, Optimize), not a design question.

## 11. Design review checklist

Use before saying a page is done, and in `bi-report-reviewer`:

- [ ] The page answers its question first; the reader and decision are in the plan.
- [ ] Each visual is the right type for its question (section 4); nothing decorative carries data.
- [ ] Layout: grid, alignment, inside the page, no unintended overlap, consistent slicer position.
- [ ] Numbers: model formats, units, comparisons, zero-based bars, deliberate sorting, meaningful totals.
- [ ] Color: a theme is registered (project, house or the harness default, `THEME.md`), never the base theme alone;
      colors from it, semantic colors consistent, never the only signal; fonts Power BI ships.
- [ ] Text: titles say what is answered, context in subtitles, alt text present.
- [ ] Interaction: cross-filtering intended, slicers synced where needed, drill-through targets exist.
- [ ] Accessibility and performance items above.
- [ ] Verified in Power BI Desktop by the user or by an approved screenshot (`docs/harness/desktop.md`).

Microsoft Learn: [choosing a visual](https://learn.microsoft.com/power-bi/visuals/power-bi-visualizations-overview),
[report themes](https://learn.microsoft.com/power-bi/create-reports/desktop-report-themes).
