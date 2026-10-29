# Where things go

The recommended layout of a BI repository with the harness; it is not required: the harness finds projects by their
files ([getting-started.md](getting-started.md)).

```text
<your BI repository>/
  AGENTS.md  TASKS.md  .claude/  docs/  templates/      installed by the harness (plus THIRD_PARTY_NOTICES.md,
  .mcp.example.json  .gitattributes  .gitignore lines   .vscode/extensions.json)
  .github/agents/  instructions/  hooks/                GitHub Copilot: the bi-expert and editor agents, rule pointers (always);
                                                        hooks/ holds the hook registrations (with --enable-hooks)
  hardening/                                            optional safety pack (Node 18.17+)
  powerbi/<Project>.pbip                                Power BI projects: the .pbip, <Project>.SemanticModel/ and
                                                        <Project>.Report/ side by side; a folder per team or area is fine
  fabric/<Workspace>/                                   the directory a Fabric workspace syncs (Git integration): item
                                                        folders <Name>.SemanticModel/, <Name>.Report/,
                                                        <Name>.PaginatedReport/, each with its .platform; nothing else
                                                        inside an item folder; see docs/harness/fabric-git.md
  models/<Model>/                                       Analysis Services tabular models the registry marks as yours
                                                        (TMDL folder with database.tmdl)
  paginated/<Report>.rdl (.rds, .rsd, .rptproj)         paginated reports (SSRS, Report Server, Power BI service)
  reports/<report>/                                     one workspace per migration or re-platform (one level deep):
    source/                                             what you hand over (Tableau .twb, Qlik script, old RDL,
                                                        exports); read-only for the agent
    docs/  tests/  sql/  pbip/ or rdl/                  dossier, checks, query text, the rebuilt report (a shared
                                                        model replaces pbip/; a single-report repository may use docs/)
  etl/<project>/                                        SSIS projects this repository owns (*.dtsx, *.dtproj, ...);
                                                        the .gitignore lines ignore their bin/ and obj/ only here
  templates/house/                                      yours, optional: a reference PBIP and a house RDL, read-only
  templates/ssis/AWSampleETL/                           shipped references (an SSIS project, a live-connection PBIP):
  templates/pbir/Satis_SSAS/                            the fallback when the repository and you have none to copy;
                                                        read-only, copied from, never edited
  docs/sources/README.md                                registry: every source, owner, path, refresh
  docs/sources/sql/                                     query text the models use, the DBA's schema handover (DDL)
  docs/sources/<cube>/definition/  requests/            reference copy (TMDL export) of a cube or tabular model owned elsewhere; change requests
  docs/tests/                                           test packs; expected-values.md ships as a template you fill with your control figures
  docs/design/                                          house theme, backgrounds, slot map, design pictures
  docs/model/  docs/report/                             generated documentation (bi-doc-generator)
  docs/decisions.md  docs/handoff.md  docs/conventions.md   the project's record
  exports/                                              report exports with data, ignored, never committed
```

**What to hand over for a migration:** the per-tool list (Tableau, Qlik, MicroStrategy, SSRS, Excel, an older Power
BI file) is in [`.claude/skills/bi-migration/SKILL.md`](../../.claude/skills/bi-migration/SKILL.md); put it under
`reports/<report>/source/`, which the agent reads and never edits.
