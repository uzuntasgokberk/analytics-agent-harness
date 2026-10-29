# PBIR structure reference

Official schemas: https://github.com/microsoft/json-schemas/tree/main/fabric/item/report/definition
Documentation: https://learn.microsoft.com/power-bi/developer/projects/projects-report

## Folder layout

```
<Name>.Report/
├── definition.pbir                 dataset binding: byPath (../<Name>.SemanticModel) or byConnection
├── definition/
│   ├── version.json                required
│   ├── report.json                 required: report-level settings, theme, report filters
│   ├── reportExtensions.json       optional: report-level measures
│   ├── pages/
│   │   ├── pages.json              optional: pageOrder, activePageName
│   │   └── <page>/
│   │       ├── page.json           required: name, displayName, size, page filters
│   │       └── visuals/<visual>/
│   │           ├── visual.json     required: position, visual type, query, formatting
│   │           └── mobile.json     optional: mobile layout
│   └── bookmarks/
│       ├── bookmarks.json
│       └── <bookmark>.bookmark.json
├── StaticResources/RegisteredResources/   themes, images; a theme is registered per bi-report-design/THEME.md (file + report.json entries), a page background image per Page background below
├── report.json                     PBIR-Legacy only: do not edit
└── .pbi/localSettings.json         per-user: do not edit
```

## Minimal shapes

Take real values (schema versions, formatting objects) from an existing file in the same report;
these skeletons only show which properties matter.

A report built from nothing (no Desktop save to copy) needs, besides `definition.pbir`: `definition/version.json`
(`"version": "2.0.0"`), `definition/report.json` and a `.platform` file next to `definition.pbir` (a new GUID as
`config.logicalId`; Microsoft's report CLI fails without it). In `report/3.x` schemas `reportVersionAtImport` is an object
(`{ "visual": "2.12.0", "page": "2.1.0", "report": "3.3.0" }`, the schema versions in use), not the string of older
examples; the base theme name must be one Desktop ships (`bin/WebView2Resources/minerva/sharedresources/BaseThemes/`).
Checked with Desktop 2.158 and `powerbi-report-author` 0.1.4 on 2026-10-06.
Desktop 2.158.1177.0 wrote `{ "visual": "2.14.0", "report": "3.4.0", "page": "2.3.1" }` on save while the files kept
`$schema` `report/3.3.0` and `page/2.1.0` (2026-10-22): the object records Desktop's versions; never change a file's
`$schema` to match it. A complete live-connection project to copy from: `templates/pbir/Satis_SSAS/` (read-only;
`templates/README.md`).

```json
{
  "$schema": "https://developer.microsoft.com/json-schemas/fabric/item/report/definition/report/3.3.0/schema.json",
  "themeCollection": { "baseTheme": { "name": "CY26SU09", "type": "SharedResources",
    "reportVersionAtImport": { "visual": "2.12.0", "page": "2.1.0", "report": "3.3.0" } } }
}
```

- A dropdown slicer needs at least 76 px of height (the CLI's `PBIR_SLICER_HEIGHT_BELOW_FLOOR`).
- A report measure from `reportExtensions.json` is bound with `"SourceRef": { "Schema": "extension", "Entity": "<table>" }`
  (the schema name is the `name` of the extension file); without `Schema` the visual shows "Something's wrong with one
  or more fields".

`pages/pages.json`
```json
{
  "$schema": "<keep existing>",
  "pageOrder": ["a1b2c3d4e5f6a7b8c9d0", "f0e1d2c3b4a5968778695"],
  "activePageName": "a1b2c3d4e5f6a7b8c9d0"
}
```

`pages/<page>/page.json`
```json
{
  "$schema": "<keep existing>",
  "name": "a1b2c3d4e5f6a7b8c9d0",
  "displayName": "Overview",
  "displayOption": "FitToPage",
  "height": 720,
  "width": 1280
}
```

`pages/<page>/visuals/<visual>/visual.json` (outline)
```json
{
  "$schema": "<keep existing>",
  "name": "v1a2b3c4d5e6f7a8b9c0",
  "position": { "x": 40, "y": 40, "z": 1000, "width": 300, "height": 160, "tabOrder": 1000 },
  "visual": {
    "visualType": "card",
    "query": { "queryState": { "Values": { "projections": [ "<copy from a template visual>" ] } } },
    "objects": {},
    "visualContainerObjects": {}
  }
}
```

The `query` projections reference model fields (entity = table, property = column or measure). Copy the
exact structure from a visual that already binds a measure; don't hand-write field references.

The visual's `$schema` refers to sub-schemas, and most property questions are answered there: `visualConfiguration`
(projections: `displayName`, `format`, `hidden`, `active`; `sortDefinition`), `semanticQuery` (field expressions such
as `Column`, `Measure`, `NativeVisualCalculation`), `filterConfiguration` and `formattingObjectDefinitions`. Report
measures have their own schema, `reportExtension`. When to use which: [PATTERNS.md](PATTERNS.md).

## Page background

An image as the page's canvas background: `objects` in `page.json`, next to the properties of Minimal shapes (copied
from the reference's page, rendered in Desktop 2.158.1177.0 on 2026-10-22):

```json
{ "objects": { "background": [ { "properties": {
  "image": { "image": {
    "name": { "expr": { "Literal": { "Value": "'HousePage.png'" } } },
    "url": { "expr": { "ResourcePackageItem": {
      "PackageName": "RegisteredResources", "PackageType": 1, "ItemName": "HousePage.png" } } },
    "scaling": { "expr": { "Literal": { "Value": "'Fit'" } } } } },
  "transparency": { "expr": { "Literal": { "Value": "0D" } } } } } ] } }
```

`image` holds a second `image` object. The flat shape (`url` and `scaling` directly under `properties.image`) passed
the validator and Microsoft's report CLI and left the canvas empty in Desktop: the page schema types `image` as `{}`,
so no static check sees the difference; only Desktop does. `ItemName` is the image's `name` in `report.json`
`resourcePackages` (`RegisteredResources`, `"type": "Image"`), and the file is
`StaticResources/RegisteredResources/<path>`. `'Fit'` is Desktop's Image fit **Stretch** and `0D` is 0 % transparency
([design-to-report.md](../../../docs/design-to-report.md), section 3).

## Naming

- Default names are 20-character ids (`90c2e07d8e84e7d5c026`); older reports may use `ReportSection...`.
- Allowed characters: letters, digits, `_`, `-`. Anything else is ignored by Desktop.
- `pageBinding.name` (drillthrough/tooltips) must be unique when you copy pages between reports.

## Service limits (per report)

Pages, visuals per page and resource and report file sizes: [anatomy.md](../bi-map/references/anatomy.md#limits)
(`bi-map`, Limits), which keeps the Learn list with its review date.

## Data values in metadata

`visual.json`, `bookmark.json` and filters can store literal values from the model (a filter on
`'Customer'[Name] = "Contoso"` stores "Contoso"). Treat these files as potentially sensitive: never add
personal data, and flag existing literal values containing personal data in reviews.
