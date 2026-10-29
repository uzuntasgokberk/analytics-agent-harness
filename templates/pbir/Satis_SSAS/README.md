# Satis_SSAS: reference live-connection PBIP

A working Power BI project the agent copies shapes from when neither the repository nor the user has a visual, page
or project file of the kind it needs (the order: `.claude/skills/bi-pbir-report/SKILL.md`, Before you edit, step 2).
Read-only: never edit it, never open it in Desktop. The shapes matter; its bindings, titles and texts are examples.

## Provenance

- Copied byte-identical (25 files) from the live-connection project of the harness's end-to-end lab, October 2026.
- Saved by Power BI Desktop 2.158.1177.0 (Microsoft Store). Before it shipped: Microsoft's report CLI
  `powerbi-report-author` 0.1.4 `validate` passed, the harness validator reported 0 errors.
- `Satis_SSAS.Report/definition.pbir` binds `byPath` to `Satis_SSAS.SemanticModel/`, which holds no model, only
  `modelReference.json` (`analysisServicesDatabaseLive`): a live connection to an Analysis Services tabular model
  (SQL Server 2025 Analysis Services in the lab). Its `Data Source=localhost;Initial Catalog=Satis` is an example.
- `HousePage.png` (page background) comes from the harness owner's own Figma mockup and `HouseTheme.json` (custom
  theme) from its tokens; both are the owner's and ship with the harness like every other file here.
  `SharedResources/BaseThemes/CY26SU09.json` is the base theme as Desktop wrote it.
- Titles, alt texts and the page name are Turkish: a real project, kept as it was saved.

## What Desktop confirmed, and what not

Confirmed by the user in Desktop on 2026-10-22 [user]: the project opens on a live SQL Server 2025 Analysis Services
tabular model; all 12 visuals render with data; the page background shows (Format page, Canvas background, Image
names `HousePage.png`); the KPI card values fit their cards.

Not done: screenshots, pixel measurements, RLS, an accessibility check. Not covered by this project at all: pie,
donut, gauge, map and other visual types it lacks, bookmarks, drillthrough, report measures (`reportExtensions.json`),
mobile layout, a `byConnection` binding to a published model.

## Files: written by Desktop or by the agent

| File | Written by | Schema |
|---|---|---|
| `visuals/f4b391060001430d9a01` (page navigator) and the three cards `…9a06`, `…9a07`, `…9a08` | agent, then re-saved by Desktop | `visualContainer/2.14.0` |
| `visuals/f4b39106000b430d9a0b` (line chart) | the lab's file; its last writer is not recorded | `visualContainer/2.14.0` |
| the four slicers `…9a02` to `…9a05`, the table `…9a09`, the bar charts `…9a0a`, `…9a0c` | agent; validated by the CLI and rendered in Desktop | `visualContainer/2.4.0` |
| `definition/report.json` | Desktop's save: `reportVersionAtImport` visual 2.14.0, report 3.4.0, page 2.3.1 | `report/3.3.0` |
| `pages/c37d4e48a0014b8aaf01/page.json` with the page background | the nested background shape the user found, rendered in Desktop | `page/2.1.0` |

`reportVersionAtImport` records Desktop's versions; it is not the files' `$schema`, and no `$schema` is changed to
match it.

## Visual inventory (canvas 1280 × 720, display FitToPage)

Positions are rounded; the Desktop-saved visuals hold fractional values. Ids are `f4b39106000N430d9a0N`.

| Id ends | Type | x, y, width, height | Notes |
|---|---|---|---|
| `…9a01` | `pageNavigator` | 223, 0, 1057, 39 | top band |
| `…9a02` to `…9a05` | `slicer`, mode `'Dropdown'` | 20, 110 / 210 / 310 / 410, 180, 80 | left rail; the CLI's floor for a dropdown slicer is 76 px |
| `…9a06` | `cardVisual` | 240, 65, 325, 70 | reference label bound to a second measure |
| `…9a07` | `cardVisual` | 580, 65, 324, 70 | |
| `…9a08` | `cardVisual` | 936, 65, 324, 72 | |
| `…9a09` | `tableEx` | 240, 172, 632, 254 | |
| `…9a0a` | `barChart` | 896, 172, 364, 254 | |
| `…9a0b` | `lineChart` | 240, 450, 632, 250 | Year and Month as two axis fields, chronological; no YearMonth column needed |
| `…9a0c` | `barChart` | 896, 450, 364, 250 | |

These are slots of this page, not a house slot map: a new page takes its positions from its own design or template.

## The page background

`page.json` holds `objects.background[0].properties.image.image` with `name` (Literal `'HousePage.png'`), `url`
(`ResourcePackageItem`: package `RegisteredResources`, type 1, item `HousePage.png`) and `scaling` (Literal `'Fit'`,
Desktop's Image fit Stretch), plus `properties.transparency` (Literal `0D`). The full JSON:
[STRUCTURE.md](../../../.claude/skills/bi-pbir-report/STRUCTURE.md), Page background. `report.json` registers the
image and the theme under `resourcePackages`, and both files exist under `StaticResources/RegisteredResources/`.

Warning: the page schema types `image` as `{}`. A flat shape (`url` and `scaling` directly under `image`) passed the
harness validator and the report CLI and left the canvas empty in Desktop (2026-10-22). Copy this shape; only Desktop
proves it.

## How to copy from it

1. Copy files out; never open this folder in Desktop (the `.pbip` enables auto-recovery, and any save rewrites
   files). To look at it in Desktop, copy the whole project to a scratch folder first (`docs/design-to-report.md`,
   section 3).
2. A new project from it: rename the folders, the `.pbip` artifact path, the `byPath` in `definition.pbir` and each
   `.platform` `displayName`; give each `.platform` a new GUID as `logicalId`; keep every `$schema`.
3. A new page or visual: a new 20-character lowercase hex id as folder name and `name`; a page also goes into
   `pages.json` (`pageOrder`).
4. Replace every binding (`Entity`, `Property`) with fields confirmed in your model or its reference copy
   (`bi-data-sources`, field gate), and every title, alt text and display name.
5. `modelReference.json`: server and database from `docs/sources/README.md`; changing a connection is Tier 2.
6. A background: copy the block; the user copies the PNG under `StaticResources/RegisteredResources/` (the file tools
   write no binary and the guard denies a shell copy), the agent registers it in `report.json` and uses the registered
   name in both `name` and `ItemName`.
7. Then run the static check, the report CLI's `validate` where it is permitted, and ask the user to open the copy in
   Desktop.

## What the harness checks here

The validator checks every file in this folder (JSON syntax, names, secrets) and reports a broken file as an error.
It does not treat the folder as one of the repository's projects: artifact discovery skips reference folders
(`templates/`, a report's `source/`, the config's `references`; `hardening/README.md`, SessionStart), so the session
banner does not list it and no live-connection or Fabric Git reminder is raised for it (2026-10-22).
