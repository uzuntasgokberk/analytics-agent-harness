---
name: bi-pbir-report
description: Edit Power BI reports stored as PBIR JSON in a PBIP project - pages, visuals, formatting, titles, alt text, bookmarks and batch edits across visuals. Works with or without Microsoft's report CLI (Path A) and with files only (Path B). Use when creating or modifying files under *.Report/definition/.
---

# Editing PBIR reports

PBIR (`<Name>.Report/definition/`) is the documented, schema-backed report format: one JSON file per
page, visual and bookmark. The legacy single-file `report.json` at the report root (PBIR-Legacy) is not
supported for external editing and is blocked; ask the user to upgrade it to PBIR in Desktop.

From a Figma frame, an image or a house template: follow `docs/design-to-report.md` first. Which visual, layout, color
and text to use: `bi-report-design`.
Patterns from real reports (read-only models and report-side calculations, slicers and sorting, large builds with a
project generator, visuals the user finished in Desktop): [PATTERNS.md](PATTERNS.md).

## Before you edit

1. Read `definition/pages/pages.json` if present (it is optional), and the target page's `page.json`.
2. Find a visual of the same type (`"visualType"` in `visual.json`) to copy, in this order: (1) one in this report,
   (2) one Desktop saved in another report of this repository, (3) the house template under `templates/house/`, (4) the
   harness reference `templates/pbir/Satis_SSAS/` (`pageNavigator`, dropdown `slicer`, `cardVisual` with a reference
   label, `tableEx`, `barChart`, `lineChart` on a Year and Month axis, and a page background), (5) only then the CLI
   catalog and the schema (table below) for what the copy lacks; never from memory. A type none of (1) to (4) holds
   (pie, donut, gauge, map): ask the user for a blank one created in Desktop, then fill it
   (`docs/design-to-report.md`, worked example). `templates/` is read-only: copy from it, never open it in Desktop.
3. List the model fields you will bind and confirm they exist in the TMDL (`measure 'X'`, `column Y`). A report bound
   to a published model has no local TMDL: confirm the names in its reference copy under `docs/sources/` or ask the
   user to read the field list in Desktop (`bi-data-sources`, field gate).

## Which route: report CLI or files only

Microsoft's report CLI, `powerbi-report-author` (npm), is optional. Check with `powerbi-report-author --version`; never
install it yourself, ask the user. Never guess a property, role or enum value.

| | Path A: the CLI is installed and permitted | Path B: files only |
|---|---|---|
| Which properties and values are valid | `catalog describe <type>` (roles, formatting keys), `formatting describe-object <type> <object>` (property names, enum values), `formatting search <type> <regex>` | copy a working visual of the same type; look the property up in the schema that the file's `$schema` URL serves (fetch it with WebFetch; `developer.microsoft.com` is pre-approved, while shell downloads such as `curl` are blocked by the guard) and see [STRUCTURE.md](STRUCTURE.md) |
| Change | edit the JSON files. With the hardening pack its other commands go: `pack` runs in `auto`; `unpack` is denied (the user runs it); `preview --reload*` and a service preview (`--host service`) ask; `scaffold` and a plain `preview` get Claude Code's own prompt; every `preview` is denied while `desktop.screenshots` is `off` | the same |
| Validate | `powerbi-report-author validate <path-to-.Report-folder>`, then the static check | the static check, then the user opens the project in Desktop |

## Rules

- Keep each file's `$schema` unchanged; it is the contract Desktop validates against.
- Folder names = object names: letters, digits, `_`, `-` only (Desktop ignores other names). Use a 20-char
  lowercase hex id like Desktop does for new pages/visuals, and set `"name"` to the same value.
- New page: create `pages/<id>/page.json`, add `<id>` to `pageOrder` in `pages.json`.
- New visual: `pages/<page>/visuals/<id>/visual.json`, copied from the first source of "Before you edit", step 2, that
  holds its type, with new ids and your bindings and titles; update `position` (`x`, `y`, `z`, `width`, `height`) to fit
  inside the page `width`/`height`.
- Page background image: copy the `objects.background` block of the reference's `page.json` ([STRUCTURE.md](STRUCTURE.md),
  Page background), with the image under `StaticResources/RegisteredResources/` and in `report.json` `resourcePackages`.
  The page schema leaves `image` untyped, so the validator and the CLI pass a wrong shape that Desktop renders as an
  empty canvas; only Desktop shows it (observed 2026-10-22).
- Deleting pages or visuals, and changing `definition.pbir`, are Tier 2.
- A report bound by live connection (`byConnection`): before adding fields or calculations, read the registry
  (`docs/sources/README.md`) for the model's type and server version and its reference copy for field names
  (`PATTERNS.md`, read-only models).
- Don't persist literal data values in filters/slicers (names, IDs, e-mails).
- A theme `report.json` names under `resourcePackages` (the base theme `BaseThemes/<name>.json`, a custom theme) has its
  file under `StaticResources/`: write it with the reference or copy it from a working report; the validator warns about a
  missing one, and a Fabric Git commit from the service adds it ([fabric-git.md](../../../docs/harness/fabric-git.md)).
- Renaming files or folders requires a Desktop restart; say so.

## Batch edits (many visuals at once)

Scoped editor subagents use Edit/Write. For repetitive changes, return a proposed script to the
main agent; it reviews the script and executes only within the authorized scope. Then inspect
`git diff --stat` and run the static check (`docs/static-checks.md`). See [STRUCTURE.md](STRUCTURE.md) for JSON shapes
and [PATTERNS.md](PATTERNS.md), section 3, for the rules a generator must keep (never delete, never overwrite,
protected list, idempotent).

## After editing

1. Run the static check (`docs/static-checks.md`) and, when Microsoft's report CLI is installed and permitted,
   `powerbi-report-author validate <path-to-.Report-folder>`. Invalid JSON, bad names, a missing
   `page.json` or `visual.json` and broken `pages.json` references are errors.
2. Check the rendering in Power BI Desktop: the page renders, visuals show data, interactions and filters behave,
   nothing overlaps. With Microsoft's Desktop CLI and the user's approval you can reload and take screenshots
   yourself (`docs/harness/desktop.md`); otherwise tell the user exactly what to check.

MCP discovery, resources, connection ownership, bounded queries and persistence: `docs/harness/MCP.md`.
Treat file validation, engine/DAX execution and Desktop visual checks as separate evidence.
