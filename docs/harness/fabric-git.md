# Fabric Git integration: where the workspace folder lives

Fabric does not hand the user a repository: a workspace connects to a branch and a directory of the user's own
repository, so the harness and the Fabric items share one Git repository. This guide says where that directory lives,
what goes to Git and what does not, what the service does to the directory, and which steps stay with the user. Facts
come from Microsoft Learn (each source carries its "checked" date under Sources; fetch the page again before relying on
a limit that matters) and from two live tests, 2026-10-17 (a GitHub repository with a model, a report and a paginated
report in one directory) and 2026-10-22 (a model and a report; Update from Git failed for the model at compatibility
level 1700 and succeeded at 1606); their observations are marked with their commit ids. Other documents link here
instead of repeating it.

## One repository, one directory per workspace

- A workspace Admin connects the workspace to a Git provider (Azure DevOps, GitHub or GitHub Enterprise, cloud only),
  a repository, a branch and a directory; a Contributor can then commit and update. The Git connection is per user:
  each GitHub user signs in with their own personal access token.
- The directory is the repository root or a subdirectory. Learn: "Submodules aren't supported", so never nest a second
  `.git` in the repository. Learn suggests several workspaces on one branch, each in its own folder; that is also the
  way past the limit of 1,000 items per workspace.
- Directory names: no leading or trailing space or tab, none of `" / : < > \ * ? |`. A file's full path stays within
  250 characters, a file within 25 MB, a branch name within 244 characters.

Recommended layout, not required (the registry and `docs/conventions.md` name what exists):

```text
<bi-repo>/                          one .git; AGENTS.md, .claude/, docs/, hardening/ at the root
                                    (docs/harness/getting-started.md)
  fabric/
    Sales-Dev/                      <- workspace "Sales-Dev" connects to repo, branch main, directory fabric/Sales-Dev
      Sales.SemanticModel/          definition.pbism, definition/ (TMDL), .platform
      Sales.Report/                 definition.pbir (byPath ../Sales.SemanticModel), definition/ (PBIR), .platform
      Invoices.PaginatedReport/     Invoices.rdl, .platform (preview)
      Finance/...                   a workspace subfolder is a Git subfolder (mirrored both ways, up to 10 levels)
    Sales-Models/                   <- a second workspace: same branch, another directory
  powerbi/                          projects no workspace syncs (Desktop Publish), among them every report or model
                                    live-connected to Analysis Services (next section)
  paginated/                        paginated reports no workspace syncs (docs/harness/layout.md)
  docs/tests/  docs/sources/  templates/   everything the harness adds stays OUTSIDE the item folders
  etl/  models/                     SSIS and Analysis Services: Fabric never reads them
```

## What goes to Git (Learn, checked 2026-10-17)

The supported-items list is Microsoft's and changes; the harness checks that depend on it are warnings, never errors.

| Item | Git integration | Lives here |
|---|---|---|
| Report (PBIR) | supported, marked *preview* on the page; **except** a report connected to a model hosted in Azure Analysis Services or SQL Server Analysis Services, and a report exported by Desktop that depends on a model in My workspace | `fabric/<ws>/<Name>.Report/` |
| Report live-connected to Analysis Services (`byConnection` to an AS server, or a model folder with `modelReference.json`) | not supported: the process page says datasets connected to Analysis Services are not supported | `powerbi/`; the user publishes it from Desktop (an on-premises SSAS needs a gateway). In a connected directory it shows in the Source control pane as unsupported and is never committed, updated or deleted; the validator warns |
| Semantic model (TMDL) | supported, marked *preview*; **except** push datasets, live connections to Analysis Services and model v1 | `fabric/<ws>/<Name>.SemanticModel/` |
| Analysis Services tabular model (a TMDL folder with `database.tmdl`) | not a Fabric item: Fabric never reads it | `models/<Model>/`; deploy and process are the user's ([ssas-tabular.md](../../.claude/skills/bi-semantic-model/ssas-tabular.md)). Moving it into a Fabric semantic model is a migration of its own, Tier 2 (a new model and a new source): `bi-semantic-model` ([Create](../../.claude/skills/bi-semantic-model/SKILL.md#create)) with the storage mode from [storage-modes.md](../../.claude/skills/bi-data-sources/storage-modes.md) |
| Paginated report (`.rdl`) | supported, *preview*; rules in "Paginated reports in Git" below | `fabric/<ws>/<Name>.PaginatedReport/`; one no workspace syncs stays in `paginated/` |
| SSIS packages, SQL text, test packs, dossiers, templates | not Fabric items | `etl/`, `docs/`, `templates/`: outside every item folder |

Learn on unsupported items in a connected workspace or directory: the connection still works, the items are ignored
(not saved, not synced, not deleted) and the pane shows them, but they cannot be committed or updated. Which file
shapes mark a live connection: [storage-modes.md](../../.claude/skills/bi-data-sources/storage-modes.md).

## One item, one place

An item a workspace syncs lives only under its `fabric/<ws>/` directory: no second copy under `powerbi/` or
`paginated/`, and no second item with the same display name in the workspace (Learn: a duplicate name makes update,
commit and undo fail). The validator's full scan (no flag) warns about a same-named `.Report` or `.SemanticModel`
folder that is not synced beside one that is, about two synced `.Report` or `.SemanticModel` folders with the same
`logicalId` (a raw copy, same name or renamed), about two synced `.PaginatedReport` folders with the same `logicalId`
under different names, and about an `.rdl` with the file name of a synced paginated report outside its item folder.
Synced means under a directory of `fabric.directories` or, while none is recorded, holding `.platform` (next section).
Two synced folders with different `logicalId`s are two items. With the list, a Desktop-saved copy under `powerbi/` is a copy like any other folder
outside the listed directories. Without it, that copy holds `.platform` too and counts as synced; not verified: whether
a Desktop publish followed by a service commit keeps Desktop's `logicalId`, so such a copy may stay silent and only the
paginated case is caught by the file name.

The usual way a copy appears: a paginated report is built under `paginated/`, uploaded to the service (Learn's rule,
below), committed from there into `fabric/<ws>/<Name>.PaginatedReport/`, and the pre-upload copy stays behind
(observed 2026-10-17, commit `4022db3`: the two files were byte-identical apart from line endings). Remove the
pre-upload copy in the same pull request that brings the service commit into review; the deletion needs the user's
approval (Tier 2), and `paginated/` keeps only reports no workspace syncs.

## Item folders and .platform

- Each item is a folder named `{displayName}.{Type}`: a character a folder name cannot hold becomes its HTML number,
  and when the name is taken the service uses the item's `logicalId` instead. Semantic model: `definition.pbism` and
  `definition/` (TMDL). Report: `definition.pbir` and `definition/` (PBIR). Paginated report: the `.rdl`. What each
  file holds: [PBIP anatomy](../../.claude/skills/bi-map/references/anatomy.md).
- Every item folder also holds `.platform`: `version` "2.0", `$schema`
  `https://developer.microsoft.com/json-schemas/fabric/platform/platformProperties.json`, `config.logicalId`,
  `metadata.type` (case-sensitive), `metadata.displayName` and an optional `metadata.description`. Older folders have
  `item.metadata.json` and `item.config.json` instead; the service upgrades them to `.platform` on its next commit. A
  folder never holds all three.
- `logicalId` links the item across workspaces: a branch can sync to several workspaces (the same `logicalId` in
  each), and one workspace never holds two items with the same `logicalId`. Never change it. The one exception: a new
  item made by copying a folder gets a new `logicalId` and a new `displayName`. Renaming a folder by hand stops the
  name sync and leaves `byPath` references to fix: rename items in the service.
- The `.pbip` file is not exported and not needed: Desktop opens `<Name>.Report/definition.pbir` (Learn, PBIP FAQ). A
  `.pbip` beside the item folders does no harm (next section).
- With report and model in one workspace the service exports `definition.pbir` with `byPath`; a report on a model in
  another workspace gets `byConnection`, whose connection string carries the workspace name and `semanticmodelid`.
  Only `definition.pbir` is processed; other `*.pbir` files may coexist (anatomy, Formats and versions).
- A report's `definition/report.json` names its base theme under `resourcePackages` (`SharedResources`,
  `BaseThemes/<name>.json`). Observed 2026-10-17 (commit `18d6ecb`): the harness-built report referenced
  `BaseThemes/CY24SU10.json`, neither the harness nor a Desktop save had written the file, Desktop saved and Update from
  Git into the workspace succeeded without it, and the service commit added it under `StaticResources/SharedResources/`.
  Write the file when you write the reference, or copy it from a working report; the validator warns about a
  `resourcePackages` entry whose file is missing (`bi-pbir-report`).
- A Power BI model that syncs to Fabric does not copy the level of an Analysis Services model: its `database.tmdl`
  takes the level Power BI Desktop writes, proven with Update from Git
  ([Create](../../.claude/skills/bi-semantic-model/SKILL.md#create)). Observed 2026-10-22: a semantic model the agent
  wrote with `compatibilityLevel: 1700` (copied from an Analysis Services 2025 model) opened and refreshed in Desktop
  2.158 but failed Update from Git with `ModelOperatorOperationFailedException` (dataset import); lowered to 1606
  (PR #7, commit `35750f7`), the level of a working Fabric-synced model: Update from Git then succeeded (the user
  confirmed it on 2026-10-25). Microsoft's
  [TMDL reference](../../.claude/skills/bi-semantic-model/references/tmdl-guidelines.md) shows a Power BI model at
  1702 with `compatibilityMode: powerBI` (the failing model had no `compatibilityMode` line), so the level alone is
  not proven to be the cause; the proof is the Update.
- `.platform` marks an item folder as Fabric-shaped, not as synced: Desktop writes it on a project save too (Learn,
  report folder page). Only the user knows which directory a workspace syncs. `docs/conventions.md` records the
  workspace and branch of each directory (`/bi-onboard` drafts it); `fabric.directories` in
  `hardening/harness.config.json` lists the directories for the hardening pack's checks, for example
  `"fabric": { "directories": ["fabric/Sales-Dev"] }` (project-relative, `"."` for the repository root; only the user
  edits that file). With a list, the live-connection warning, the second-copy warning and the session banner look only
  at item folders under those directories, `.platform` or not; `[]` records that no directory is synced. Without a
  list (the default `null`) or with a value that is no list of directories, they fall back to item folders that hold
  `.platform`, a reminder, not proof of a connection. Each message names the source it used.

## What the service does to the directory

- A commit from the service "deletes files inside the item folder that aren't part of the item definition"; files
  outside item folders stay (Learn: "unrelated files not in an item folder aren't deleted"). Items of a type Git
  integration does not support are ignored in the directory, not deleted.
- **The one hard rule of this guide:** nothing of ours (test packs, dossiers, notes, screenshots, SQL) ever goes inside
  `*.SemanticModel/`, `*.Report/` or `*.PaginatedReport/`. It lives in `docs/` (test packs in `docs/tests/`), a
  migration's `reports/<report>/` or `templates/`.
- Not verified: what a service commit of the *semantic model* does to Desktop's own extras inside its folder
  (`.pbi/editorSettings.json`, `DAXQueries/`, `TMDLScripts/`, `diagramLayout.json`). The 2026-10-17 service commit
  (`18d6ecb`) touched only the report folder: it added the base theme file and changed nothing else. Check the diff
  after the first service commit of a model and record what happened in `docs/decisions.md`.
- Update takes the whole branch directory; there is no item selection. While an item changed on both sides, Update is
  disabled until the conflict is resolved; while Git has newer commits, Commit is disabled until the workspace updates.
- Line endings. Learn (process page): the service uses LF and turns CRLF item files into LF when it commits. Observed
  2026-10-17: the PBIR blobs of the service commit `18d6ecb` are LF, as Learn says; the paginated report uploaded to
  the service and committed from there (`4022db3`) arrived with the uploaded file's line endings, CRLF (472 CR in the
  blob), byte-identical otherwise to the LF copy under `paginated/`. Under the harness `.gitattributes` (`* text=auto`,
  `eol=crlf` on PBIP and RDL files) an LF blob makes no whitespace diff: the checkout is CRLF, the repository LF. A
  CRLF blob the service committed is not normalized by anything until a local `git add` of that file, which turns the
  next small edit into a whole-file diff. Normalize it once and commit (in the pull request that removes the
  pre-upload copy):

  ```bash
  git add --renormalize fabric/<ws>/<Name>.PaginatedReport/<Name>.rdl
  ```

  Not verified: whether the service writes CRLF again on its next commit of that item.
- A refresh through the enhanced refresh API leaves a Git diff on the semantic model after each refresh (Learn).
- Limits: GitHub takes 50 MB per commit (split a large commit); Azure DevOps 25 MB with a service principal and 125 MB
  with a user. A workspace holds 1,000 items, also when a branch syncs into it.

## Setting it up (the user, never the agent)

1. Create the branch and pick the directory name (for example `fabric/Sales-Dev`). The directory is typed in the
   connect dialog and created by the first sync.
2. Workspace settings > Git integration: provider, repository, branch, directory. Initial sync: when one side is empty
   it gets the other side's content; when both have content you choose the direction ("update workspace from Git"
   overwrites the workspace and asks you to confirm).
3. An export you already cloned on its own: copy its item folders into the directory as plain files, without its
   `.git`, and keep every `.platform` untouched; then connect the workspace to that directory and choose the direction.
4. `git pull`, then open `fabric/<ws>/<Name>.Report/definition.pbir` in Desktop.
5. Record the connection: the workspace and branch in `docs/conventions.md`, and, with the hardening pack, the directory
   in `fabric.directories` of `hardening/harness.config.json`, so the Fabric Git checks look there and nowhere else.

From then on the loop is: the agent edits files in the directory and runs the static check; you review the pull
request into the connected branch; in the workspace you press Update (or Commit, for work done in the service). A
developer who needs isolation branches out to their own workspace: "Branch out" creates a branch and a workspace on
the same directory. Branching out into an existing workspace loses the items not committed there.

## Team rules

- Start every piece of work with `git pull`: a commit from the workspace may have landed since the last fetch.
- One item is edited in one place at a time: in the service (then Commit) or in Git (then Update), never both before
  a sync. A change on both sides is a conflict the user resolves in the workspace.
- The connected workspace is Dev. Test and Prod get their content through a deployment pipeline (option 3 below), not
  through a Git connection of their own, unless the team chose option 1.
- A commit from the workspace lands on the connected branch directly: it goes through no pull request and no local Git
  hook (observed 2026-10-17, commits `18d6ecb` and `4022db3` on the connected branch). Learn adds that the commit
  needs a branch policy that allows direct commits and, where it does not, recommends "Checkout new branch" in the
  Source control pane and a pull request. Two ways to keep the checks (not tested here: which one the team's branch
  protection allows):
  - protect the connected branch so that it takes only pull requests, let the workspace commit to a checkout branch,
    and make `hardening/ci/bi-validate.yml` a required check;
  - or leave the branch open to the service, keep the workflow's run on push as the after-the-fact check (the branch
    must be in the workflow's push trigger, `branches:` in `bi-validate.yml`, or the check never runs), and run the
    full validator after every pull (no flag: `--changed` sees nothing after a clean pull, and the copy checks run
    only in the full scan):

    ```bash
    node hardening/scripts/validate.mjs
    ```

## Two architectures, four release options

Where the model sits decides the binding:

| Model placement | `definition.pbir` | Consequence |
|---|---|---|
| (a) model and report in one workspace | `byPath` | both sync together; Desktop opens both |
| (b) model in its own workspace, thin reports elsewhere | `byConnection` with the workspace name and `semanticmodelid` | a reference to an item in another workspace never binds automatically on deployment and stays pinned to the source object id: each stage rebinds (deployment pipelines' autobinding and rules, or a build script that rewrites the connection string) |

The rebind rule comes from Learn's "Understand dependency binding in cross-workspace deployment". A paginated report's
connection string is pinned to the source model the same way. Direct Lake, SQL analytics endpoint, warehouse and KQL
connection strings in `expressions.tmdl` are workspace-specific too and need per-stage parameters (Variable Libraries
for connections).

Release options (Learn, "CI/CD workflow options in Fabric"):

| Option | Branches | How a stage gets its content | Source of truth |
|---|---|---|---|
| 1 Git integration | a primary branch per stage (Gitflow) | each stage workspace runs `update-from-git` from its branch | Git |
| 2 Fabric Items APIs | one main branch (trunk-based) | fabric-cicd or the Bulk Import Item Definitions API; a build environment rewrites stage-specific values such as connection ids; stage workspaces are not connected to Git | Git plus the build |
| 3 Deployment pipelines | Git on the dev workspace only | deployments between Dev, Test and Prod workspaces with deployment rules and autobinding | Fabric-native, linear |
| 4 CI/CD for ISVs | per customer | per-customer workspaces | out of scope here |

Harness default: option 3 with layout (a), one connected directory per dev workspace. Take option 1 when Git must be
the single source of truth across stages; option 2 when thin reports or Direct Lake endpoints must be rewritten per
stage. A deployment plan is not a fifth option: it attaches to option 1 or 3.

## What the agent does and never does

- **Does:** edit files under the directory like any PBIP (same skills, same static check); keep item folders clean;
  give the user the Update step and what to verify in the workspace; record in `docs/conventions.md` which workspace
  and branch each directory syncs (`/bi-onboard` drafts it) and give the user the `fabric.directories` line for
  `hardening/harness.config.json` (the agent never edits that file); treat `.platform`, the `definition.pbir` binding
  and `.gitignore` as the user's (the binding is Tier 2).
- **Never:** connect, disconnect, switch or check out a branch in the workspace; press Commit or Update there; call the
  Git or Items APIs, fabric-cicd or deployment pipelines (deployment is never the agent's, `AGENTS.md`); change a
  `logicalId`; put a file that is not part of the item definition inside an item folder; download a `.pbix` from a
  Git-deployed item (Learn: unreliable).

## Paginated reports in Git (preview)

- Item folder `<Name>.PaginatedReport/` with the `.rdl` and `.platform`. Learn's rules:
  - upload the report to the service first and commit from there: a report that starts as files in Git does not
    render;
  - rename only in the service: a rename in Git does not work (delete the whole folder and recreate it);
  - delete the whole item folder, never just the `.rdl`;
  - a report moved to another workspace stays connected to its original dataset: rebind in Report Builder, republish;
  - service principals and managed endpoints are not supported.
- After the first service commit: remove the pre-upload copy and renormalize the line endings ("One item, one place"
  and "What the service does", above).
- Report Builder edits the `.rdl` in the local clone, then a pull request, then Update in the workspace. The
  `paginated/` folder of [`docs/harness/layout.md`](layout.md) is for reports no workspace syncs. File
  rules: `.claude/rules/bi/rdl.md`.

## Sources

- Fabric Git integration: [overview and supported items](https://learn.microsoft.com/en-us/fabric/cicd/git-integration/intro-to-git-integration)
  (checked 2026-10-17; the page itself was updated that day),
  [process](https://learn.microsoft.com/en-us/fabric/cicd/git-integration/git-integration-process) (checked 2026-10-17),
  [development process and branches](https://learn.microsoft.com/en-us/fabric/cicd/git-integration/manage-branches) (checked 2026-10-17),
  [source code format](https://learn.microsoft.com/en-us/fabric/cicd/git-integration/source-code-format) (checked 2026-10-15),
  [branch workspace](https://learn.microsoft.com/en-us/fabric/cicd/git-integration/branched-workspace) (checked 2026-10-15).
- PBIP: [overview](https://learn.microsoft.com/en-us/power-bi/developer/projects/projects-overview) (checked 2026-10-17),
  [report folder](https://learn.microsoft.com/en-us/power-bi/developer/projects/projects-report) (checked 2026-10-17),
  [semantic model folder](https://learn.microsoft.com/en-us/power-bi/developer/projects/projects-dataset) (checked 2026-10-15).
- Releases (checked 2026-10-15): [CI/CD workflow options](https://learn.microsoft.com/en-us/fabric/cicd/manage-deployment),
  [dependency binding](https://learn.microsoft.com/en-us/fabric/cicd/cross-workspace-dependency-binding).
- Paginated reports (checked 2026-10-15): [Git integration](https://learn.microsoft.com/en-us/power-bi/paginated-reports/paginated-github-integration).
- Live test, 2026-10-17: a GitHub repository with one connected directory holding a semantic model, a report (`byPath`)
  and a paginated report; Update from Git, then two commits from the service (`18d6ecb` report, `4022db3` paginated
  report). The repository is the user's and is not part of the harness.
- Live test, 2026-10-22: a second user repository, a semantic model and a report in one connected directory; Update
  from Git failed for the model (`ModelOperatorOperationFailedException`), retried at compatibility level 1606
  (PR #7, commit `35750f7`): Update from Git succeeded at 1606 (user confirmation, 2026-10-25; Item folders
  and .platform).
