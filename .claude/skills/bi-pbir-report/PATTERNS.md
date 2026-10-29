# PBIR patterns from real reports

Patterns that cost real time to discover. Property names and enum values still come from the CLI or the schema
(`SKILL.md`); this file says when to use what.

## 1. Read-only models: calculate in the report

When the model belongs to someone else (a live connection to a published model, a shared cube), change nothing in the
model. Learn: in live connection mode the model itself cannot change, but report measures, visual calculations,
calculated columns and calculated tables can be created.

| Need | Option | Lives in | Trade-off |
|---|---|---|---|
| the source tool's label on a field | projection `displayName` | that visual's query | only that visual |
| a number format the model lacks | projection `format` (a format string scoped to the visual) | that visual's query | only that visual |
| % of a row or column total, running sum, difference to previous | visual calculation: a projection whose field is `NativeVisualCalculation` | that visual | see limits below |
| one calculation reused on many visuals | report measure in `definition/reportExtensions.json` | the report | appears in the report's field list; other reports do not see it; model tests do not cover it: test it with a pack block that repeats it as `DEFINE MEASURE` (`docs/test-packs.md`) |

Shapes, from the published schemas the visual's `$schema` refers to (`visualConfiguration` for projections,
`semanticQuery` for expressions, `reportExtension/1.0.0` for report measures):

```json
{ "field": { "NativeVisualCalculation": { "Language": "dax", "Name": "Share", "DataType": "Double",
    "Expression": "DIVIDE([Items], COLLAPSEALL([Items], COLUMNS))" } },
  "queryRef": "Share", "nativeQueryRef": "Share", "format": "0.00%" }
```

A visual calculation can only use what is on the visual: add the base measure as a projection too, with
`"hidden": true` if it should not show. Limits (Learn, visual calculations, checked 2026-08-31): results are not in data
exports, you cannot sort or filter by them, they do not work in slicers or custom visuals, and a live connection to
SQL Server Analysis Services needs version 2025 or later. On such a report, read the server version in the registry
(`docs/sources/README.md`) before adding one; an older or unknown version means a report measure instead. Open a
hand-written visual calculation in Desktop once before relying on it (`docs/harness/desktop.md`): SQL Server Analysis
Services 2025 build 17.0.25.223 refused one ("unsupported visual calculation expressions ... feature switch is off"),
and the report measure that replaced it worked. A report measure in a visual's query needs `"Schema": "extension"` in
its `SourceRef` ([STRUCTURE.md](STRUCTURE.md)).

Bind field names only after the field gate in `bi-data-sources` (cube path): a reference copy of the model or the
field list the user reads in Desktop. Hidden columns of a published model become visible to users with Build
permission (Learn), so hiding is not security.

## 2. Slicers and sorting

- A Between date slicer saved in Desktop stores absolute dates. On a rolling-window source it drifts out of the
  window after a few refreshes. Use a relative date slicer instead (`data.mode` `Relative` with a range, period and
  duration, `dateRange.includeToday`, and a `general.filter` built on `Now`); copy a working one or check each
  property with the CLI.
- A single-select slicer keeps the value it was saved with. "Always the current month" needs a model column (such
  as a month offset); without one, record it as a known issue.
- `sortDefinition` orders by values. It did not reorder a matrix column axis (Desktop ignored it), so do not leave
  configuration that has no effect.

## 3. Large builds: a project generator

For many pages that share chrome and visual styles, a small deterministic script in the project (the project's code,
not the harness's), reviewed by the main agent and run within the approved scope, beats hand edits:

- It never deletes a file and never overwrites an existing visual. Regenerating one is deliberate, with an explicit
  list of ids.
- It keeps a protected list. Visuals the user finished in Desktop are the reference, are never written again, and
  their definitions leave the script.
- It reports visuals it does not know about (Desktop gives a recreated visual a new id) and leaves them alone.
- Only an explicit sync mode (a flag such as `SYNC=1`, never the default) reads a file the user saved in Desktop back
  into the generator's definitions; every other run treats that file as the reference and leaves it alone.
- It writes `pages.json` and `report.json` only when their content changes, and `page.json` only while it is still
  Desktop's blank page.
- It is idempotent: a second run changes nothing (compare hashes or `git status`). Run it against a copy first when
  the report already has content.
- It uses only template tokens: a search for colors outside the token list finds nothing.

## 4. Formatting shapes written by Desktop 2.158

Learned by making each one once in Desktop (UI Automation) and reading the saved file. Copy these shapes; change only
values. `{"id": "<state>"}` is a state or default selector; `metadata` is the field's `queryRef`.

| Need | Shape |
|---|---|
| Page navigator states | `fill`, `outline`: `show` false **and** `transparency` 100 per state (`show` alone left a fill); `text` `fontColor`/`bold`; `accentBar` `position` `'Bottom'`; each entry `"selector": {"id": "default" \| "hover" \| "selected"}` |
| New card (`cardVisual`) | role `Data`; `label` (`position` `'aboveValue'`), `value`, `outline` (`show` false), `layout` (`backgroundShow` false), `spacing` (`verticalSpacing`), each with `{"id": "default"}`; `labelDisplayUnits` `1D` = none. Its own `padding` object takes `paddingUniform`/`paddingIndividual`/`paddingTop`…, not the container's `top`/`bottom` |
| Card reference label | `referenceLabel`: `value` = `{"expr": {"Measure": ...}}`, selector `{"data": [{"dataViewWildcard": {"matchingOption": 0}}], "metadata": "<card value queryRef>", "id": "field-<guid>", "order": 0}`; `referenceLabelLayout.position` `'right'` \| `'below'`; it shows an empty chip while its measure is blank |
| Table data bars | `columnFormatting.dataBars` {`positiveColor`, `negativeColor`, `axisColor`, `reverseDirection`, `hideText`, `totalMatchingOption` `1L`}, selector `{"metadata": ...}` |
| Table icon set | `values.icon` {`kind` `"Icon"`, `layout` `'Before'`, `verticalAlignment`, `value`: `Conditional.Cases[]` of `Comparison` (`ComparisonKind` 2 is >=, 3 is <; `Right` a `Literal` like `0.05D` or a `RangePercent`) returning `'CircleHigh'`, `'SignMedium'`, `'SignLow'`}, selector `{"data": [{"dataViewWildcard": {"matchingOption": 1}}], "metadata": ...}` |
| Table fills its width | `columnHeaders.columnAdjustment` `'growToFit'`; short headers through the projection `displayName` |
| Target line on a bar chart | `y1AxisReferenceLine` (the pane calls it X-axis constant line), selector `{"id": "1"}`, `value` `1D`, `lineColor`, `style` `'dashed'`, `position` `'front'` |
| Shaded area on one series | `lineStyles` entry **without** selector `areaShow` true (all series), then `areaShow` false in the other series' entry |
| Slicer header underline | `header`: `show` true, `outlineStyle` `4D` (bottom only), `text`; turn the visual title off |

Authored from the published schemas and proven in Desktop 2.158 on a cold open. Desktop itself was not asked
for these shapes:

| Need | Shape |
|---|---|
| Field parameter in a visual | the role keeps one normal projection (the parameter's first field, e.g. Net Sales) and adds `"fieldParameters": [{"parameterExpr": {"Column": {"Expression": {"SourceRef": {"Entity": "<parameter table>"}}, "Property": "<parameter column>"}}, "index": 0, "length": 1}]` beside `projections`; the slicer binds the parameter column. Desktop shows the parameter in the field well; nothing picked = every field |
| Bookmarks | `definition/bookmarks/bookmarks.json` (`bookmarksMetadata/1.0.0`): `"items": [{"name": "<id>"}, …]` in navigator order; one `<id>.bookmark.json` (`bookmark/2.1.0`) each with `name` = file stem, `displayName`, `explorationState` {`version` `"1.3"`, `activeSection` = page name, `sections.<page>.visualContainers.<visual>.singleVisual` {`visualType`, `display` {`mode` `"hidden"`} only on the hidden one}} |
| Show/hide bookmarks that keep slicers | `options` {`targetVisualNames`: **every** visual the set toggles, `applyOnlyToTargetVisuals` true, `suppressData` true}; list the same visuals in each bookmark of the set, or one stays hidden. The slicer stays out of the targets, so its pick survives the switch |
| Bookmark navigator | `visualType` `bookmarkNavigator`, no query; shows every bookmark unless a group is chosen. In Desktop a button needs Ctrl+click; UI Automation's Toggle only selects the visual |

Gaps: the conditional formatting dialog's field picker did not accept UI Automation, so rule-based bar colors have no
learned shape yet; ask the user for one Desktop-made example before writing one.

Trap: when a name exists both as a visual object and as a container object (`padding`, `spacing`, `border`),
`formatting describe-object` returns the container's properties. Check `formatting effective-properties <type>` and
run `powerbi-report-author validate` after every edit: Desktop silently ignores unknown properties, so a render that
looks right does not prove the JSON is right.

## 5. Visuals the user finished in Desktop

When the user edits a visual in Desktop and says it is final, that file is the reference. Add it to the protected
list, record the decision in `docs/decisions.md`, commit it separately as the user's change, and never "fix" it back
to a generated version.
