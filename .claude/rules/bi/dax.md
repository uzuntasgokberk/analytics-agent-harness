---
paths:
  - "**/*.SemanticModel/definition/tables/*.tmdl"
  - "**/tables/*.tmdl"
  - "**/functions.tmdl"
  - "**/*.SemanticModel/DAXQueries/*.dax"
  - "**/*.dax"
---

# DAX rules

- Prefer `DIVIDE(numerator, denominator)` when the denominator can be zero/blank; `/` is fine for
  a known nonzero constant. Do not hide unexpected errors with `IFERROR`/`ISERROR`.
- Use `VAR ... RETURN` for any sub-expression used more than once or worth naming.
- Filter columns, not tables: `CALCULATE([m], 'T'[Col] = x)` or `KEEPFILTERS(...)`, not `FILTER('T', ...)`
  over a whole fact table.
- Time intelligence needs a marked date table with a contiguous date column; don't rely on auto date/time.
- Reference measures without a table prefix (`[Total Sales]`), columns always with one (`'Sales'[Amount]`).
- Every new measure gets a `formatString`, a `///` description and, when the table has them, a `displayFolder`.
- Measure names are unique across the model; the validator fails on duplicates.
- Test expected totals, slices and edge cases against the updated model: Path A, bounded aggregate queries with the
  MCP guide's result cap; Path B, a test pack the user runs (`docs/test-packs.md`). Static validation alone does not
  test the business result.
- Language rules, patterns and performance: `.claude/skills/bi-semantic-model/references/dax-guidelines.md`
  (Microsoft's guideline), then the `dax-perf-*` files there when optimizing.
