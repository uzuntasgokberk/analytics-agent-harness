# Report theme: which one, how a report gets it, what the default looks like

Part of `bi-report-design` (section 6). One place for the theme recipe; `bi-pbir-report/STRUCTURE.md`,
`docs/design-to-report.md` and `bi-report-reviewer` point here instead of repeating it.

## 1. Which theme

In this order; the first that exists wins. A report never stays on Desktop's base theme alone.

1. **The project's theme:** `docs/design/theme.json`, with the house template `docs/conventions.md` names
   (`docs/design-to-report.md`, section 3). Its tokens, slot map and backgrounds decide the look.
2. **A house PBIP's theme:** the theme file registered in the reference project under `templates/house/` (read-only:
   copy it, never edit it).
3. **The harness default:** [default-theme.json](default-theme.json) next to this file. Neutral, brand-free, fonts
   Power BI ships. It exists so a report built where nothing else is defined still looks finished; a project replaces
   it by adding its own theme (section 4).

Record which one a report uses in `docs/decisions.md` (the theme's origin and file name). Registering the default is
ordinary work (a theme is formatting, not a binding, source or model change); replacing a project's theme with another is a
design decision the user takes.

## 2. Registering a theme in a PBIR report

Verified with Power BI Desktop 2.158 and `powerbi-report-author` 0.1.4 on 2026-10-07 (a copy of a live-connected
report: the agent-written registration opened and rendered; Desktop wrote nothing on open).

1. Copy the theme to `<Report>/StaticResources/RegisteredResources/<Name>.json`. Letters and digits only in `<Name>`.
2. Set the theme's `"name"` to the file name **including `.json`** (`"name": "BIHarnessDefault.json"`). The report CLI
   requires the two to be equal (`PBIR_THEME_FILE_NAME_MISMATCH` otherwise); Desktop tolerates a difference (its own
   saves keep the base name and add a numeric suffix to the file), so writing them equal satisfies both.
3. In `definition/report.json` add `customTheme` next to `baseTheme` and the two resource packages. Copy
   `reportVersionAtImport` from the `baseTheme` entry; keep the base theme name the report already has.

```json
{
  "themeCollection": {
    "baseTheme": { "name": "CY24SU10", "reportVersionAtImport": { "visual": "2.12.0", "page": "2.1.0", "report": "3.3.0" }, "type": "SharedResources" },
    "customTheme": { "name": "BIHarnessDefault.json", "reportVersionAtImport": { "visual": "2.12.0", "page": "2.1.0", "report": "3.3.0" }, "type": "RegisteredResources" }
  },
  "resourcePackages": [
    { "name": "SharedResources", "type": "SharedResources", "items": [ { "name": "CY24SU10", "path": "BaseThemes/CY24SU10.json", "type": "BaseTheme" } ] },
    { "name": "RegisteredResources", "type": "RegisteredResources", "items": [ { "name": "BIHarnessDefault.json", "path": "BIHarnessDefault.json", "type": "CustomTheme" } ] }
  ]
}
```

4. `powerbi-report-author validate <Report>` (0 errors), then the Desktop check of `docs/harness/desktop.md` (`status`,
   `open`, screenshot; never `reload` after a Desktop-side change). Say in the report what the screenshot proves: the theme
   loaded, panels and fonts render; not that the numbers are right.
5. A later save from Desktop may re-register the file under a suffixed name (`<Name><digits>.json`) and rewrite
   `report.json`; keep Desktop's names from then on (the saved files are the reference).

Alternative without a file edit: the user imports the JSON in Desktop (View, Themes, Browse for themes) and saves;
Desktop writes the same structure.

## 3. What the default looks like (the visual reference)

Tokens, all in `default-theme.json` (change them there, not on visuals):

| Element | Default |
|---|---|
| Canvas | page background `#F3F4F6` (cool grey), outspace `#E6E8EB`, 1280 × 720 |
| Visual panel | white background, border `#EBEDF0` 1 px, radius 12, soft shadow (black at 92 % transparency, blur 12, distance 2, bottom right), padding 8/8/12/12; text boxes transparent, no shadow, no padding (a 76 px title box keeps its text). The panel is the theme's: never draw rectangles behind visuals |
| Text | title 12 pt Segoe UI Semibold `#333333`; subtitle 10 pt Segoe UI `#5F5F5F`; labels 10 pt; callout (card value) 28 pt Segoe UI Semibold |
| Series | `#3A7FD0` (actual), `#8A949E` (comparison, last year), `#E0574B` (accent), then teal, violet, amber, green, rose |
| Semantic | good `#1E8449`, bad `#C0392B`, neutral `#B9770E`: only for good, bad and warning, used the same way on every page |
| Line chart | 2 px lines with 4 px markers, legend on top, dotted value gridlines `#EDEDED`, no category gridlines |
| Bar chart | data labels 9 pt grey, no value gridlines (turn the value axis off on the visual when labels show) |
| Card (classic) | category label off, value 28 pt; new Card: inner box off (the panel is the box) |
| Table and matrix | grey semibold headers, banded rows `#F5F5F5`, no grid lines, row padding 6 |
| Slicer | header 10 pt grey; items on white |

Fonts: only fonts Power BI ships render everywhere (Segoe UI, Segoe UI Semibold, Segoe UI Light, Arial, Calibri,
Candara, Consolas, Georgia, Tahoma, Trebuchet MS, Verdana). A font the machine lacks falls back silently: "DIN" rendered
as a serif on a Desktop without it (seen 2026-10-07). Check a new font in a screenshot before keeping it.

Page recipe when no house template exists (the theme carries the look, the page carries these):

- 24 px page margin, 16 px gaps; title text box top left (76 px tall), the page's slicers top right (76 px, the CLI's
  minimum for a dropdown), one KPI row (112 px), then one or two chart rows filling the rest.
- A KPI card shows the number and its comparison: the new Card with a reference label (PY, YoY) when the model has the
  measures, or a classic card with the comparison named in the subtitle; the title names the measure, so the category
  label stays off. Scale a reference label with `referenceLabelValue.valueDisplayUnits` and `valuePrecision`, never with
  `,,` in its format string (Desktop 2.158 prints the commas literally); the format string carries only the sign or an
  arrow. Desktop also ignores `referenceLabelTitle.titleText` and `customFormatString` there (seen 2026-10-07).
- The comparison series is dashed and grey: a per-series `lineStyles` entry with a `selector` on the visual
  (`bi-pbir-report/PATTERNS.md`); a theme cannot style one series.
- Bars sorted by value with labels and no value axis; lines with markers; a one-series chart turns its legend off.
- Alt text on every informative visual; subtitles carry the filter, the unit and when a visual goes blank.

## 4. Replacing the default with a project theme

Add `docs/design/theme.json` (and, with a house template, the backgrounds and slot map of `docs/design-to-report.md`
section 3), register it as in section 2 under its own name, remove the default file and its `RegisteredResources` item,
validate, open in Desktop, and record the change. Existing visuals keep working: they carry no literal colors.
