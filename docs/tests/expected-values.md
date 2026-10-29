# Expected values (control figures)

Control figures the user handed over as the source of truth for the test packs (`docs/test-packs.md`). Write who gave
them and when, and where they come from (a finance report, a query the DBA ran, an export). Aggregates only: no rows of
people, no e-mails, no keys of a person. When a figure changes, the user hands over the new one and the date changes;
the agent never computes a control figure from the model it is testing.

Amounts are exact decimals with two places, no thousands separator. Every figure carries its evidence label
(`docs/decisions.md`): `[user]` handed over, `[sql]` from a query the user ran against the source.

<!-- Example. Replace with your own sections.

Handed over by <role> on <date>, from <system or query>.

## Row counts

| Source object | Rows |
|---|---:|
| `dbo.FactSales` | 200000 |

## Sales amount per calendar year

`SUM(FactSales.SalesAmount)`; the year of `OrderDateKey`.

| Year | Sales amount |
|---|---:|
| 2024 | 12345678.90 |
-->
