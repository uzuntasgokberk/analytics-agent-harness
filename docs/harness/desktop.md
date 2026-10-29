# Power BI Desktop as evidence

Static checks read files and MCP queries the engine; only Power BI Desktop renders a report. This guide says what the
agent may do with Desktop and what stays with the user. Desktop evidence covers rendering and interaction, never
whether a number is right (that is a test pack: `docs/test-packs.md`).

Power BI Desktop, its CLI and Report Builder run only on Windows. On macOS follow Path B and hand the checks to a Windows
machine. Microsoft's report skill also describes a service preview for a model that is already published
(`powerbi-report-author` with `--host service --headless` and the workspace and model ids): it is a `preview`, so it
needs the user's approval, and the installed CLI's `--help` decides the flags.

## Path A: Microsoft's Desktop CLI is installed

`powerbi-desktop` (npm `@microsoft/powerbi-desktop-bridge-cli`) talks to a running Desktop through the Desktop Bridge,
a Desktop preview feature. Check with `powerbi-desktop --version`. Never install the CLI or turn on the preview
feature yourself; ask the user.

| Command | Effect | Rule |
|---|---|---|
| `status` | lists Desktop instances: PID, current file, report folder, `hasUnsavedChanges`, bridge state | read-only, run it freely |
| `open "<path>.pbip"` | starts Desktop with the project | approvals mode `auto`: run it; `ask` mode or no hardening pack: **ask first** (it starts a program that loads cached data or connects to the published model) |
| `reload --pid <pid>` | re-reads the report files of that instance | **ask first** in every mode, `lab` included (the guard leaves it to the ask rule below); never while `hasUnsavedChanges` is true |
| `screenshot <page-id> --pid <pid> --output <file>`, `screenshot-all --pid <pid> --output-dir <dir>` | captures rendered pages | `desktop.screenshots` in `hardening/harness.config.json`: `off` denied, `ask` (default) asks in every mode, `on` as `open`; a screenshot shows data, so an `--output` or `--output-dir` inside the repository is denied in every mode, also after a `cd` of the same command line (`exports/` and the temporary folder follow the switch); after a `cd` the guard cannot follow (a variable, `cd` alone, `popd`, a missing folder) a relative output asks and auto mode never answers |

- "Run it" means the agent does not ask in chat first. Claude Code still prompts before `open`, `reload` and the
  screenshots in every mode, also when the guard approves them: `.claude/settings.json` has an ask rule for each, and
  an ask rule prompts whatever a hook returns (Claude Code docs, Permissions, checked 2026-10-19).
- Two Desktop editions can sit side by side: Power BI Desktop (Microsoft Store or installer, for the Power BI service and
  PBIP) and Power BI Desktop optimized for Report Server (title bar shows a month and year; this CLI does not see it).
  `open` starts the edition registered for the file type: read `launched.executablePath` in its output; if it is the
  Report Server edition, close that window and ask the user to fix the file association. Power BI reports for Report
  Server are outside this harness: that edition has no PBIP format.
- `open` can report the PID of another bridge instance: read the new instance's PID from `status` (by
  `currentFilePath`), not from `open`.
- A project that fails to load leaves the window "Untitled" with an "Issues were found" dialog; its "Copy details to
  clipboard" names the failing TMDL object in the stack trace (for example `SingleColumnRelationship`).
- Pick the PID from `status`. Never take the first instance, and never one the user has open on another project.
- `hasUnsavedChanges: true` means the user has work in that window. A reload discards it, or their next save
  overwrites your file edits. Ask them to save or close that window without saving, then check `status` again.
- One command at a time per PID; never reload and screenshot in parallel.
- `reload` covers report (PBIR) files. Model (TMDL) changes need the project reopened or Desktop's apply prompt.
  Theme files are cached by name.
- Screenshots are data. Keep them in the session's temporary folder, never in the repository, and delete them when
  done. Never copy values from them into docs, tasks or commits. On pages with personal data, ask explicitly and
  prefer structural evidence (the page opens, visuals render without error boxes). A company keeps
  `desktop.screenshots` at `ask` or `off` (`off` also denies the report CLI's `preview`) and sets `on` only on a
  machine with test data. The guard judges `npx @microsoft/powerbi-desktop-bridge-cli ...` and
  `npx @microsoft/powerbi-report-authoring-cli ...` as `powerbi-desktop` and `powerbi-report-author`, switch included,
  and approves them only with `--no` (an installed copy), since npx otherwise downloads the package; Claude Code's
  `npx` ask rule prompts for both forms.
  Captures made by UI Automation scripts (`PrintWindow`) are outside the guard's sight
  (scripts are never routine), so they follow the same rule by the agent's discipline.
- Say what a screenshot proves (layout, rendering, error boxes, slicer states) and what it does not (that the numbers
  are right).
- Beyond the CLI (clicking ribbon buttons, "View as" with another user) the user's approval covers UI Automation on
  that Desktop PID only. Use automation patterns (Invoke, Toggle) first. Desktop's "Other user" box ignores a value set
  through the Value pattern: it needs a click and typed keys, and keys go to whatever window has the focus, so type only
  after checking that the foreground window belongs to that PID, never print the identity, and press OK only when the
  box reads back the whole value. Values read through UI Automation are data, like a screenshot.
- After a refresh Desktop can report "pending changes in your queries" with no file changed. Do not apply, discard or
  save for the user: a save writes `.pbi/unappliedChanges.json` and Desktop's own TMDL. Record it and let the user decide.
- **After any change made in Desktop's UI (and its save), never `reload`:** in Desktop 2.158 a `reload` then saved
  Desktop's in-memory report over the agent's newer file edits (seen in testing with Desktop 2.158). The safe loop is: stop the process without
  saving (the save prompt is an MSHTML dialog UI Automation cannot reach), edit the files, `open`, screenshot. A cold
  open can report `hasUnsavedChanges: true` at once; that is Desktop's own normalisation, not user work: never save it.
- **Apply external changes** ([Learn: edit PBIP files outside Desktop](https://learn.microsoft.com/en-us/power-bi/developer/projects/projects-external-editing),
  page dated 2026-09-23, checked 2026-10-16; not tested here): a preview, in the August 2026 release or later, once the
  preview feature "Detect and reload external PBIP changes" is on and Desktop restarted. When a project file is saved
  outside Desktop, a banner offers **Apply external changes**: Desktop reloads the affected report, semantic model or
  both from the files (not single files or visuals, not `cache.abf`; filters and some UI elements reset). Learn says to
  save in Desktop before editing outside it. With unsaved changes in Desktop the banner warns that they will be
  overwritten: Apply discards them, Cancel keeps them and leaves the file changes unapplied. The preview does not take
  edits to `definition.pbir`, `report.json`, `mobileState.json` or `semanticModelDiagramLayout.json` (Learn does not
  say whether `report.json` is the legacy root file or PBIR's `definition/report.json`; `definition.pbir` is a report
  binding the agent edits only as Tier 2); with `unappliedChanges.json` present, Desktop discards external edits to model
  expressions when it applies the pending changes. Learn also names the Desktop Bridge, which the CLI talks to, as a
  programmatic route; whether `reload` is that call is not checked. For the loop: where Desktop offers the banner, it
  replaces the CLI `reload` for supported files, report and model alike, selected by the user or through UI Automation
  on their approval, never over unsaved work; for the rest the rule above stays (stop without saving, edit, `open`).
- UI Automation notes (2.158): a visual on the canvas is a Group named after its title and alt text; `Invoke` selects
  it. Format pane sections are ExpandCollapse buttons, toggles are Toggle buttons with `pbi-toggle-button-*` ids,
  search the pane's field picker through its own Search box (the nearest one by screen position). File dialogs expose
  only panes: fill the File name box with `WM_SETTEXT` and press Open with `BM_CLICK` on that dialog only. A Save As
  dialog (an export from Report Builder, say) ignores a `WM_SETTEXT` name and saves under its default name and folder,
  often a synced Documents folder: type the full path while that dialog is the foreground window, read the box back,
  then press Save, and check the default folder afterwards. Theme import
  leaves a hidden "Got it" dialog that blocks closing until it is dismissed. Some dropdowns (series pickers) and the
  conditional formatting field picker refuse UI Automation: fall back to the user. Capture windows with `PrintWindow`,
  not screen copies (another window may be in front).

## Path B: no CLI, or no approval

Tell the user exactly what to open and look at: the file, the page, the visual, what it should look like and which
messages to report (a TMDL error names its file and line). Record what they report as Desktop evidence, attributed
to them ("checked by the user"). This is also the path for every page check while `desktop.screenshots` is `off`.

## Checklist for a report change

| Check | How |
|---|---|
| The project opens; no error dialog | open (A, approved) or the user (B) |
| Each changed page renders; no visual shows an error | screenshot (A) or the user (B) |
| Layout: inside the page, no unintended overlap, matches the plan | screenshot or the user |
| Slicers and filters change the visuals as intended | the user (interactions are not scripted here) |
| Row-level security | "View as role" with a member's identity: the user (B), or UI Automation when approved (A) |
| The numbers match a source | not Desktop evidence: `docs/test-packs.md` |

Source: Microsoft's report authoring skill for the `powerbi-desktop` commands (Skills for Fabric). Check
`powerbi-desktop --help` for the installed version before relying on a flag.
