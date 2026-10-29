# Test packs and reconciliation

Path A runs bounded queries itself (`docs/harness/MCP.md`, section 5). Path B hands the user a test pack. Both need
the same thing written down first: what the right answer is, and where that answer comes from.

## Write the pack

One file per change or report: `docs/tests/<topic>.dax`, plain DAX query blocks that the user runs one at a time in
Desktop's DAX query view (or DAX Studio); for a model on Analysis Services or a live-connected report, in SSMS or DAX
Studio against the deployed database. Each block starts with a comment line: test id, what it proves, the filter
context, the expected result and the source of that expectation.

Control figures the user hands over (totals from finance, an export, a query result) go into
`docs/tests/expected-values.md` with who gave them and when, aggregates only; packs and the source registry cite that
file. A figure that exists only in a chat or outside the repository cannot be checked on Path B.

```dax
// T-03 · Total Sales, one month (2026-05) · expected: equals the source report's May total · source: user's export
EVALUATE
ROW ( "Total Sales", CALCULATE ( [Total Sales], 'Date'[Year Month] = "2026-05" ) )
```

- Aggregates only: never raw rows, never personal grouping keys (names, e-mails, ids of people).
- Per changed measure at least: the expected total, one filtered slice, the blank or zero case, one date boundary.
  Per new table or partition: one row-count block against the source's counts.
- Edge cases are part of every measure pack, not extras, whenever they apply:
  - A date measure gets a fiscal year, a range that crosses a calendar year (December plus January), a partial
    period (part of a month), the current incomplete period, and the first period after the history starts (its
    prior period is only partly recorded).
  - Derive expected values from `docs/tests/expected-values.md` arithmetic (or a reconciliation query) before
    falling back to "design".
  - A measure with a grain rule (targets per month or region) gets one case at the grain and one below it.
  - A measure under row-level security gets the cases of the Row-level security paragraph below, which differ for a
    static and a dynamic role.
  
  A rule that holds for whole calendar years can fail on all of these.
- Expected values from the same database the model imports check consistency, not truth: say so, and add one figure
  from outside it (the business owner's report, a signed-off total) when the user can supply it.
- A report measure (`reportExtensions.json`) is not in the model: repeat its expression in the block as
  `DEFINE MEASURE <table>[<name>] = ...` and run it against the model the report connects to; change the block when
  the report measure changes.
- The user reports results back; record the outcome in `docs/decisions.md` (Test results), never the raw output.

## Results

| Result | Meaning |
|---|---|
| PASS | matches the expected value (exact, unless the user set a tolerance) |
| FAIL | differs: record the difference and the suspected cause |
| BLOCKED | no expected value exists, or the source cannot be reached |
| NOT RUN | nobody ran it |

Never PASS without a run. "The user compared it with the source and it matches" is PASS with the evidence `[user]`;
write down that no numbers were recorded.

**Anchor every result to what it ran against:** the commit (`git rev-parse --short HEAD`) plus "and uncommitted changes
to <files>", or the files' blob hashes (`git hash-object <file>`). A model reloaded or saved by Desktop after the run
makes the result stale: run it again. Without an anchor, write "ran, not anchored", never a bare PASS. Record the
engine's value next to the expected one, so anyone can recheck the "equal".

## Reconcile against a source of truth

When a report replaces or mirrors another system (an older report, another BI tool, a SQL query), its numbers must
match that system, not only look plausible.

- **Expected values come from the source:** an export, a query result the user runs, an aggregate query the user
  asked the agent to run (the SQL read switch judges it, `docs/harness/faq.md`; recorded with `[sql]`), or values the
  user reads out.
  A masked or blurred screenshot is not an expected value, and the test is BLOCKED.
- **Tolerance:** exact match unless the user sets a tolerance. Never invent one.
- **Same filters on both sides:** period, members, status filters, currency, time zone, refresh time.
- **Parity or correction:** when the source is wrong (for example it sums a pre-aggregated count), matching it is
  parity, fixing it is a change. The user decides; record which one in `docs/decisions.md`.

Minimum matrix, pick what applies:

| Area | Cases |
|---|---|
| Totals | grand total · totals and subtotals at each level of a matrix |
| Time | one day or period · a range · the first and last day of the source window |
| Members | one member · several members · unknown or unmatched keys (blank member) |
| Data shape | blank and zero values · duplicates (row multiplication) |
| Interaction | slicer combinations · cross-filtering between visuals |
| Security and refresh | each RLS role ("View as role") · the same tests after a refresh |
| Paginated reports | per named parameter set (default, one value, several values of a multi-value list, empty result): row count and column totals against the source query · the first and last page · PDF page count and Excel export |

A paginated report has no DAX query view: the pack names the parameter sets the user runs in Report Builder and the
source query (or DAX against the same model) that gives the expected row count and totals for each.

An SSIS package has no query view either: the pack (`docs/tests/<package>.ssis.md`) gives the validate command
(`dtexec /F <package>.dtsx /Validate`, which the agent may run where `dtexec` exists; without it the step is NOT RUN
and the user validates in Visual Studio), then the run the user starts against a test database with its parameter
values, and the expected row counts and totals per destination table against the source file or query. `/Validate`
proves package structure only (a data flow with `DelayValidation` is checked only when it runs), so the first run
against a test database is the test of a new or rebuilt package. A package run is never a test against production.

Row-level security: one block without a role gives the reference values (per region, say). The pack names each role,
and the expected outcome follows the role's filter expression and the identity in effect
([Learn: RLS with Power BI](https://learn.microsoft.com/en-us/fabric/security/service-admin-row-level-security), page
dated 2026-05-13, checked 2026-10-16). It covers every measure that uses `USERELATIONSHIP` (the same page warns of
unexpected errors with it under RLS). The identity is given by the user at run time and never written into a pack or
any other file.

- **Static role** (a fixed filter such as `[Region] = "West"`, no `USERPRINCIPALNAME()`, `USERNAME()` or
  `CUSTOMDATA()`): the result does not depend on who runs it, so any run under the role tests its filter fully, an
  agent's MCP run on Desktop with `impersonation.roles` included. Expected: the role's slice of the reference values.
- **Dynamic role** (the filter matches one of those functions against a user-mapping table): a run tests the identity
  in effect (in the service's Test as role, the tester's own). Through MCP on Desktop that is the current Windows user
  (`USERPRINCIPALNAME()` returns the name at connection time,
  [Learn](https://learn.microsoft.com/en-us/dax/userprincipalname-function-dax); which form Desktop's engine gives
  that connection is not re-checked). The pack states whether that user is in the mapping, as a class and never the
  sign-in: mapped, their slice; not mapped, no rows and no error. Desktop returns `DOMAIN\User` for `USERNAME()` and a
  UPN for `USERPRINCIPALNAME()`, the service the UPN for both (same RLS page), so a `USERNAME()` rule can match in
  one and not the other.
- **Another member** of a role on `USERPRINCIPALNAME()` or `USERNAME()`: Desktop's Modeling > View as, with the role
  ticked and "Other user" with the member's sign-in (View as accepts any typed sign-in, a synthetic one included; not
  on the Learn pages, not re-checked), read in a temporary table visual with the measures under test, never saved, by
  the user or through UI Automation on their approval ([desktop.md](harness/desktop.md)); or the blocks in DAX Studio
  or SSMS with `Roles` and `EffectiveUserName` in the connection, against a deployed model (it needs administrative
  permissions in Analysis Services, workspace admin in Power BI; `domain\user` on SQL Server Analysis Services, a UPN
  on Azure Analysis Services and Power BI:
  [Learn: connection string properties](https://learn.microsoft.com/en-us/analysis-services/instances/connection-string-properties-analysis-services),
  checked 2026-10-16). A `CUSTOMDATA()` rule has no sign-in: it reads the `CustomData` connection property (same
  page), set in DAX Studio or SSMS; whether View as sets it is not re-checked. A query connection to Desktop does not
  impersonate another user: its engine refuses `EffectiveUserName`, the MCP `impersonation.userPrincipalName` route
  (not re-checked, nor whether a Windows account the machine resolves passes).
- **Fail-closed row**: a sign-in mapped to nobody returns no rows and no error. It is one row of a dynamic role's pack
  (an MCP run on Desktop gives it only when the current Windows user is not mapped), and it can fail: a rule that falls
  back to `TRUE()` for an unknown name returns every row
  ([Learn: RLS guidance](https://learn.microsoft.com/en-us/power-bi/guidance/rls-guidance), checked 2026-10-16).

Record per test: id, metric, filter context, source value, Power BI value, difference (absolute and %), result,
cause, evidence, and the anchor (commit, or the blob hash of every changed file it ran against). A report whose control values nobody can provide is reported as "validation BLOCKED", never "done".
