# Incremental refresh

Read with `SKILL.md` before you touch a table that has a `refreshPolicy`, the `RangeStart` or `RangeEnd` parameter, or
the query of such a table. Learn: "Incremental refresh and real-time data for semantic models" (configure, and the
advanced page for deployment; not re-checked on 2026-10-19); fetch it again before relying on a limit that matters.

## The contract

- **Two parameters, exact names.** `RangeStart` and `RangeEnd` in `expressions.tmdl`, both `Type="DateTime"`
  parameters (`meta [IsParameterQuery=true, Type="DateTime", ...]`). The names are case-sensitive; renaming or
  retyping either one breaks the policy. Their values in the file only limit what Desktop loads; keep the window small.
- **One filter, half-open.** The table's query filters its date column once:
  `each [OrderDate] >= RangeStart and [OrderDate] < RangeEnd`. One boundary inclusive, the other exclusive; with two
  inclusive boundaries a row on a partition edge is loaded twice, with two exclusive ones it is lost.
- **The column type.** The filtered column is a date/time column. An integer date key (`yyyymmdd`) or a `date` column
  needs the parameters converted inside the filter, as the Learn page shows; never change the column's type for it.
- **It must fold.** The filter has to reach the source as a `WHERE` clause, or each partition reads the whole table.
  Keep the steps before it foldable; folding is confirmed only in Desktop ("View Native Query"): write "folding not
  verified" until the user checks.

## What the agent may change

| Change | Tier |
|---|---|
| a column or measure of the table, a query step after the filter that still folds | normal |
| a relationship of the table | Tier 2 (`AGENTS.md`): stop and ask |
| the filter, the parameters, the date column, the policy (periods, granularity, detect data changes, real-time) | Tier 2: stop and ask |
| partitions the service created from the policy (a model downloaded from the service has one per period) | never; they are rebuilt from the policy |

- A new policy, or a change to one, is set by the user in Power BI Desktop's incremental refresh dialog, which checks
  it. You review the diff of the `refreshPolicy` block and the contract above; never write the block from memory.
- A change to the table's query goes into the policy's source expression as well as the partition, so both stay the
  same; copy the existing structure.

## Deployment (the user's)

- The policy takes effect in the service: the first refresh after publishing creates the partitions and loads the
  whole history. Say how long that may take with the source's size, if the registry gives it.
- Publishing from Desktop again replaces the service model, so the history is loaded again. A metadata-only
  deployment (for example ALM Toolkit or Tabular Editor through the XMLA endpoint) keeps the partitions. Name the
  choice as a Tier 2 decision; never run either.
- Shortening the rolling window deletes the older partitions at the next refresh. Say so before the user approves.
