---
paths:
  - "**/expressions.tmdl"
  - "**/tables/*.tmdl"
---

# Power Query (M) rules

- Never write credentials, keys or tokens in M (no `Password=`, `ApiKey=`, `Authorization` headers).
  Credentials are configured in Power BI Desktop/Service data source settings. The hardening pack, when installed,
  denies writes that contain one.
- Servers, databases, folders and URLs come from parameters in `expressions.tmdl`
  (`meta [IsParameterQuery=true, ...]`), never hardcoded, never personal paths like `C:\Users\<name>\`.
- `Web.Contents`: the base URL parameter is the whole first argument; variable parts go into `RelativePath` and
  `Query`. A URL built by concatenation is a dynamic data source, which the Power BI service cannot refresh. Say so.
- A local file or folder (or an on-premises database) refreshes in the service only through a data gateway; say so
  when you add or change such a source.
- Changing where data comes from (connector, server, database, file, folder or base URL), a new parameter (also one
  replacing a hard-coded value), the value of an existing parameter, a storage mode or an incremental refresh policy is
  Tier 2: stop and ask. A normal query edit inside the same source is not: mirroring a SQL text change in its
  partition, a new column, a renamed sheet or table. Connector limits (DirectQuery folding, Direct Lake, files, web
  APIs): `.claude/skills/bi-data-sources/storage-modes.md`.
- `RangeStart` and `RangeEnd` belong to incremental refresh: never rename or retype them, and keep the filter that uses
  them half-open and foldable (`.claude/skills/bi-data-sources/incremental-refresh.md`).
- Preserve query folding: filter and remove columns early, before steps that break folding.
- If `.pbi/unappliedChanges.json` exists, don't edit M; applying those pending changes in Desktop would overwrite yours.
- Keep `let ... in` formatting consistent with the surrounding partition; don't reformat untouched queries.
