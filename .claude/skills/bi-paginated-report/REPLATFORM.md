# Re-platform: an SSRS report onto a Power BI semantic model

The report keeps its layout and its parameters, but stops querying the database on every run: it reads an Import
semantic model instead. The goal is not a similar report but **the same rows for the same parameters**. The business
rule lives in one place, the model's SQL; the RDL only applies the parameter filters in DAX.

Choose this route when the database should not carry report load, when several reports share the same logic, or when
the rule must live in one governed model. The other routes: move the RDL as it is ([MIGRATION.md](MIGRATION.md)), or
rebuild it as an interactive report (`bi-migration`).

## 1. One workspace per report

```text
reports/<report>/
  source/   the original RDL and the stored procedure or query text (read-only for the agent)
  sql/      the partition SQL of the model, one file per table (the registry points here)
  pbip/     the semantic model (TMDL) and, optionally, a PBIR page used only to check the data
  rdl/      the new RDL
  tools/    report-specific generators: never delete, never overwrite; a Desktop save is the reference
  tests/    the DAX check pack and the reconciliation results
  docs/     00-overview.md, 01-mapping.md, 02-decisions.md, copied from templates/report-dossier/
```

`source/` is evidence: never edited, so every claim can be checked against it. A permission rule denies agent writes
there: the user copies the old RDL and the procedure into it. When the old report already lives in this repository,
the dossier cites its path until the copy exists. A shared model (one serving several reports) replaces `pbip/`: say
so in `reports/<report>/docs/02-decisions.md` (the `docs/` paths below are relative to the report folder), and add
only the measures the dataset needs. Each report moves through Todo → In Progress →
Blocked or Ready for review → Done in `TASKS.md`, with the blocker written next to a Blocked item.

## 2. Steps

1. **Analyze** (`bi-rdl-analyst`, read-only). Inventory the old RDL and the procedure: every dataset and its query,
   every parameter's real meaning (default, multi-value, how "All" and NULL behave, cascading), hidden conditions
   (dataset filters, `WHERE` clauses inside the procedure, visibility and filter expressions, `Code` functions, group and
   sort expressions), the output columns and their order. Label every fact with its evidence (`docs/decisions.md`).
   Output: `docs/00-overview.md` and a draft of `docs/01-mapping.md`.
2. **Plan.** Which SQL becomes which partition (the procedure's logic moves into model SQL, not into DAX), the grain and
   keys, sort columns, the mapping from each parameter to a model column, and how each filter is written in DAX.
   List Tier 2 items and open questions in `docs/02-decisions.md`; wait for approval.
3. **Model** (`bi-tmdl-modeler`). The partition source equals the file in `sql/`; no business rule is repeated in DAX;
   servers and databases come from parameters. A text the old report sorts by gets a sort column, because the model's
   sort order and collation can differ from SQL Server's.
4. **RDL** (`bi-rdl-editor`). Copy the old RDL and change **only the data layer**: the data source (the semantic model;
   the user sets it in Report Builder), the datasets (DAX with `@` parameters mapped in `QueryParameters`), and each
   field's `DataField`. Keep every field `Name`, dataset name, report item and parameter, so the layout and its
   expressions stay byte for byte the same. Datasets that feed parameter lists move to DAX too.
5. **Prove.** All of:
   - the partition SQL equals the file in `sql/` (static check);
   - the data layer comparison of the old and the new RDL (`docs/static-checks.md`) reports *identical outside the data
     layer*; without the hardening pack, compare the two files in a diff tool, ignoring `DataSources` and `DataSets`;
   - the DAX check pack in `tests/` passes (aggregates only; `docs/test-packs.md`);
   - for each named parameter set, the procedure's row count (the user runs it) equals the model's count for the same
     filters;
   - the user runs the old and the new report with the same parameter sets and compares rows, totals and page counts.
6. **Done** only when every proof passed and each unavoidable difference is written in `docs/02-decisions.md` with
   its cause. Results are PASS, FAIL or BLOCKED; without control values the status is "validation BLOCKED".

## 3. DAX datasets that reproduce SQL

- **A detail list** keeps rows that have no measures: select columns from a filtered table
  (`EVALUATE SELECTCOLUMNS ( CALCULATETABLE ( 'Orders', <filters> ), "OrderNo", 'Orders'[OrderNo], ... )`).
  `SUMMARIZECOLUMNS` drops rows whose measures are all blank, which changes row counts.
- **Single-value parameters:** `'Orders'[OrderDate] >= @Start`; a date range ends with `< @End + 1` so the last day is
  complete, as in [PATTERNS.md](PATTERNS.md).
- **Multi-value parameters:** Report Builder's DAX query designer writes `RSCustomDaxFilter(...)` for a parameter filter
  (it works only in paginated reports). A hand-written alternative passes `=Join(Parameters!Region.Value, "|")` and
  filters with `PATHCONTAINS(@Region, 'Geo'[Region])`; values must not contain `|`.
- **"All" and NULL:** reproduce exactly what the procedure did (no filter, or only rows without a value); write the rule
  into `docs/01-mapping.md` and test it.
- **Order:** an explicit `ORDER BY` on the sort columns; check text order and case against the procedure's output.
- **Blank and zero:** SQL `NULL`, zero and an empty string can collapse into blank in the model; test the rows that
  have them.

## 4. Report back

Per report: the state, the proofs with their results, the differences accepted and why, and what the user still has to
run (procedure counts, the old and new report side by side, publishing and binding the data source in the service).
