---
paths:
  - "docs/sources/**"
---

# Source files rules

- `docs/sources/README.md` is the registry. Read it first; keep it current when a source, grain, key or owner changes. No credentials, tokens or connection strings with secrets, anywhere in this folder.
- Registry paths start at the repository root. An older registry may write them relative to `docs/sources/` (`sql/x.sql`, `<cube>/definition/`): try both before you report a file as missing.
- `sql/*.sql` holds the full text of each query or view the model uses. It is the source of truth for the query text; the partition M mirrors it. You edit it as a proposal; you run a query only when the user asked for it, bounded and read-only under the SQL read switch (docs/harness/faq.md, Running SQL), and record the result with [sql].
- The schema of a SQL source (tables, keys, types) arrives from its owner as schema-only DDL (for example SSMS "Generate Scripts") in `sql/<database>.schema.sql`, or `sql/<subfolder>/` for one file per object. It is the evidence for grain and keys (`[sql]`); you never connect to the database to read it. Without it, ask for it.
- `<cube>/definition/**` is a reference copy of a cube's TMDL, not a local model. Read it freely. A cube change is delivered as a request in `<cube>/requests/`; edit the copy only after the user approves (Tier 2; ask before you start: the hardening pack's guard also asks for each such edit in `auto` and `ask` mode, not in `lab`), to mirror that request or the owner's published version. Never deploy.
- A model the registry says this repository owns (an Analysis Services model in a TMDL folder) is not a cube to request changes from: edit it with `bi-semantic-model` (`ssas-tabular.md`); the user deploys and processes it.
- Write "not verified" for anything the files do not show (folding, row counts, data quality).
