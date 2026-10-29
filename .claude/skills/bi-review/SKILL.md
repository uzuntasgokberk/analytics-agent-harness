---
name: bi-review
description: Full review of current BI changes - validator plus DAX, report and security reviewers in parallel
argument-hint: "[scope: changed (default) | all | <path>]"
allowed-tools: Bash(git diff *) Bash(git status *)
disable-model-invocation: true
---

Review scope: $ARGUMENTS (in GitHub Copilot: the text typed after the command) (when empty, use `changed`)

1. Run the static check (`docs/static-checks.md`) for the scope (`changed`: uncommitted files; `all`: the whole repository) and keep the summary.
   For a changed SSIS package add `dtexec /F <package>.dtsx /Validate` where `dtexec` exists on this machine (package
   structure only); without it, write "dtexec: NOT RUN".
2. Determine the files in scope (`git status --short`, or the given path) and the layers they belong to; a layer with
   no changed file gets no reviewer.
3. Path A: follow `docs/harness/MCP.md` and pass the same confirmed connection to reviewers; Path B: reviewers read
   the files and check that each changed measure has a test pack (`docs/test-packs.md`). Independent reads
   can run in parallel; never switch a shared connection during review. Launch only reviewers that apply:
   - `bi-dax-reviewer` for changed `*.tmdl` files of a `*.SemanticModel/definition/` or of the TMDL folder of an
     Analysis Services model (also when that folder is the repository root); a changed reference copy under
     `docs/sources/*/definition/` is reviewed as a change request, not as a model edit
   - `bi-source-analyst` for changed partitions or `expressions.tmdl`, `docs/sources/**` (SQL text, the registry) or an
     SSIS package or project file (`*.dtsx`, `*.dtproj`, `*.params`, `*.conmgr`): the data layer and its contracts
     with the model (`bi-map`, Which layers are in scope)
   - `bi-report-reviewer` for changed `*.Report/definition/**`
   - `bi-rdl-analyst` for changed `*.rdl`, `*.rds` or `*.rsd` (datasets, parameters, references, page fit)
   - `bi-security-auditor` always for scope `all`; for `changed` when M expressions, roles, `.mcp.json`,
     `.gitignore`, `definition.pbir`, an RDL data source (`ConnectString`, `.rds`) or an SSIS connection manager or
     protection level changed
4. Merge the results into one report:

```
## BI review
Validator: <summary line>; dtexec /Validate: <result or NOT RUN>
### Must fix
### Should fix
### Security
### Verify by hand (Desktop, Report Builder, the package run; what stays NOT RUN here)
```

Deduplicate findings, keep file:line references, and do not fix anything unless the user asks.
