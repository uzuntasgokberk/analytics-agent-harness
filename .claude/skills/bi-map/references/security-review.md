# Security review checklist (PBIP)

Never print a secret you find. Report file, line and type, masked (`ghp_…`, `Password=…`).

## Credentials

- [ ] No credentials in M (`Password=`, `pwd=`, `ApiKey`, `Authorization` headers in `Web.Contents`,
      storage `AccountKey=`, SAS `sig=`). Credentials belong in Desktop/Service data source settings.
- [ ] Servers, databases, URLs are parameters (`expressions.tmdl`), not literals scattered in partitions
- [ ] `.mcp.json` uses `${VAR}` references only; package versions are pinned
- [ ] No `.env`, keys or certificates tracked (read the full `git ls-files` list); `.env.example` has empty values only
- [ ] If a credential was ever committed (`git log --all --diff-filter=A --name-only --no-renames --format=%h` lists
      every path ever added; a `git log` or `git show` of the file itself is denied): it must be **rotated**; deleting
      the file does not remove it from git history

## Data exposure

- [ ] `.pbi/cache.abf` (imported data), `*.rdl.data` (Report Designer's preview cache) and `*.pbix` are gitignored and not tracked
- [ ] PBIR filters, slicers and bookmarks don't persist personal data (names, e-mails, IDs)
- [ ] Report exports with data (PDF, Excel, CSV) and other binaries are not tracked; exports stay in `exports/` (ignored) or outside the repository
- [ ] Documentation, commit messages and TASKS/handoff notes contain no data values
- [ ] DAX query results were not pasted into files (they may contain PII)
- [ ] Screenshots of rendered pages are treated as data: taken with consent, kept outside the repository, deleted after use (`docs/harness/desktop.md`) (`desktop.screenshots`, default `ask`)
- [ ] Model exports from Visual Studio or Tabular Editor are not tracked with per-user files: `*.tmuo` (user options, deployment target) and a cube copy's `dataSources.tmdl` (account name, authentication kind)

## Row-level security

- [ ] Every table with sensitive rows is filtered directly or through a single-direction relationship
- [ ] Dynamic RLS (`USERPRINCIPALNAME()` + security table) instead of hardcoded user lists
- [ ] No real e-mail addresses or names in role definitions
- [ ] Bidirectional relationships don't let a filtered table leak through another path
- [ ] Object-level security (hidden tables/columns) reviewed together with RLS
- [ ] Hiding is not treated as security: hidden columns of a published model become visible to users with Build permission in a live connection (Learn)

## Supply chain and tooling

- [ ] Custom visuals (`CustomVisuals/`) are from AppSource or the organizational store; private `.pbiviz` files reviewed
- [ ] MCP servers limited to the ones in `.mcp.json`; no unpinned `@latest` for servers with write access
- [ ] Optional hardening: Git hooks installed (`git config core.hooksPath` = `hardening/githooks`) and CI runs the validator (`hardening/ci/bi-validate.yml`). `git config` is an ask rule for agents: read the SessionStart message instead, which reports missing Git hooks, or ask the user
- [ ] Hook approvals: `approvals.mode` in `hardening/harness.config.json` is what the team chose (`auto`, the default, or `ask`) and the session banner says the same; `node hardening/scripts/validate.mjs` has no errors. In a clone of the harness also `npm --prefix hardening test` passes, including `settings-rules.test.mjs` (no settings deny rule answered `allow`); an installed copy ships no tests (exit code 3) (`hardening/README.md`, Approvals)

## Severity

| Severity | Examples |
|---|---|
| Critical | credential in a tracked file or git history; `cache.abf`/`.pbix` with personal data tracked |
| High | hardcoded identities in RLS; personal data persisted in PBIR filters |
| Medium | literals instead of parameters for servers; unpinned MCP package |
| Low | missing descriptions on security tables; hooks not installed locally |
