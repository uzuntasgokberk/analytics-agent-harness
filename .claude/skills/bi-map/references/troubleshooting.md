# PBIP troubleshooting

Work from evidence: read the exact error, find the file, change one thing, validate, retry.
Do not use `git reset --hard`, `git checkout .`, `git clean` or `git switch --discard-changes` to "start over" (permission rules deny or ask for them); ask
the user, or revert one file at a time.

## Triage

1. Read Desktop's error. It names the file and location when it can.
2. The static check (`docs/static-checks.md`): JSON syntax, required files, invalid PBIR names, a dangling `byPath`, duplicate
   measures, BOM, credentials. Fix errors before warnings.
3. `git status` and `git diff`: what changed last? Isolate by reverting one file at a time.
4. Ownership: did anything touch a Desktop-owned file? (anatomy.md, "Who owns what")
5. TMDL: tabs for indentation, single quotes for names with spaces or `.` `=` `:` `'`, no duplicate
   property or measure in two documents, no copied `lineageTag`.
6. PBIR: `$schema` present and unchanged, required properties, valid folder names, `pages.json` matches
   the page folders.
7. Restart Power BI Desktop and open again. Report what is still unproven.

## Symptoms

| Symptom | Likely cause | Check or fix |
|---|---|---|
| Desktop will not open the project or names a file | invalid JSON or schema, missing required property, TMDL indentation error | open the named file, validate it, fix or revert it |
| A page or visual vanished after a rename | new name breaks the PBIR naming rule, so Desktop ignores it as a private file | use letters, digits, `_`, `-`; restart Desktop |
| Edits are not visible in Desktop | Desktop has not reloaded | apply the change prompt or restart; restart is required after renaming PBIR files or folders |
| Model opens without data | no `cache.abf` (normal for a fresh clone) | refresh in Desktop |
| A measure or M edit reverted | `.pbi/unappliedChanges.json` was applied over it | resolve pending Power Query changes in Desktop before editing M |
| Visuals lost a field after a rename | PBIR filters, visuals or bookmarks still use the old name | search the PBIR text for the old name and update, or revert the rename |
| "Values for the 'pageBinding.name' property must be unique." | a copied drillthrough or tooltip page reuses a binding name | give the copy a unique `pageBinding.name` |
| A copied bookmark lost its settings | a bookmark depends on its page's visuals; invalid ones are removed | copy the page and its visuals with it |
| Whole-file diffs | CRLF against LF | fix `.gitattributes`; avoid needless re-saves in Desktop |
| Save fails or path errors on Windows | path over 260 characters | shorten the repo root |
| `cache.abf` or `localSettings.json` in `git status` | `.gitignore` lacks Desktop's defaults | add them; `git rm --cached` if already tracked |
| Merge conflict in TMDL or PBIR | two branches edited the same object file | resolve per file, validate, open in Desktop; one-object-per-file layouts keep conflicts small |
| API deployment of a report fails | the report uses `byPath` | API deployment needs `byConnection` references |
| MCP connection fails | server not registered, started or confirmed | continue with file work; report engine checks as not tested |
| Refresh credential error | data source credentials | stop; the user fixes credentials in Desktop or the Service; never retry or work around |
| Refresh fails with a column, type or query error (the user pastes the message) | a source column renamed or retyped, a query that no longer folds (DirectQuery), a privacy-level or gateway mapping, a timeout | match the message to the partition and the registry; fix names and types in the files; leave privacy levels, gateways and the refresh itself to the user |
| After the user saved in Desktop, the diff holds changes nobody asked for | Desktop re-serializes: lineageTags added, CRLF, numbers rewritten (`720.31872509960158`), empty filter cards; a Power Query edit can rewrite the partition and change data types | read the diff; keep it as the user's change in its own commit; re-sync `docs/sources/sql` from the partition; ask about type changes |
| A visual you generated looks different after the user's save, or has a new folder id | the user changed it in Desktop, or Desktop recreated it | the user's version is the reference: protect it (`bi-pbir-report`, `PATTERNS.md`), do not regenerate |
| A saved date slicer shows an old range after refresh | a Between slicer stores absolute dates | relative date slicer ([PATTERNS.md](../../bi-pbir-report/PATTERNS.md) of `bi-pbir-report`, section 2) |
| A visual calculation or report measure shows an error | unsupported visual type or connection, or a wrong field reference | Learn limits in [PATTERNS.md](../../bi-pbir-report/PATTERNS.md) of `bi-pbir-report`, section 1; open it in Desktop |
| Non-ASCII or spaced paths look garbled in git output (`"\303\274"`) | git quotes non-ASCII paths | `git -c core.quotepath=false status` |
| A script crashes or prints garbled text on non-ASCII names (Windows console) | the console code page is not UTF-8 | run that process with UTF-8 output (for example `PYTHONIOENCODING=utf-8`); write long non-ASCII text with the file tools, not shell heredocs |

## When to stop and ask

- The fix is a Tier 2 change (rename, relationship, RLS, data source, binding).
- Two attempts at the same file failed: describe both and the evidence; do not keep trying variants.
- A permission prompt or a hook denied or asked: explain what it protects and what you propose instead.
