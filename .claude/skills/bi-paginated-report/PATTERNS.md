# Paginated report patterns

Working shapes for hand edits of RDL 2016/01. When Report Builder can make the change (a new data source, a new
dataset against a semantic model), let the user make it there and edit around it; when you write XML, copy the
structure of an element that already works in the same report.

## 1. Anatomy

```text
Report (xmlns=".../reporting/2016/01/reportdefinition", xmlns:rd=".../reportdesigner")
├── DataSources/DataSource Name=…      ConnectionProperties (DataProvider, ConnectString) or DataSourceReference
├── DataSets/DataSet Name=…            Query (DataSourceName, QueryParameters, CommandType, CommandText, Timeout), Fields
├── ReportSections/ReportSection       Body (ReportItems, Height, Style), Width, Page (size, margins, header, footer)
├── ReportParameters/ReportParameter   DataType, Prompt, DefaultValue, ValidValues, MultiValue, Hidden
├── ReportParametersLayout             GridLayoutDefinition: one CellDefinition per parameter
└── Code, EmbeddedImages, Variables, Language, rd:ReportUnitType, rd:ReportID
```

`rd:` elements are designer state: keep them; give new objects new GUIDs, never copies of an existing one.

## 2. Detail table (tablix)

```xml
<Tablix Name="tblOrders">
  <TablixBody>
    <TablixColumns><TablixColumn><Width>3cm</Width></TablixColumn><TablixColumn><Width>4cm</Width></TablixColumn></TablixColumns>
    <TablixRows>
      <TablixRow><Height>0.6cm</Height><TablixCells><!-- header textboxes, one cell per column --></TablixCells></TablixRow>
      <TablixRow><Height>0.6cm</Height><TablixCells><!-- =Fields!X.Value textboxes, one cell per column --></TablixCells></TablixRow>
    </TablixRows>
  </TablixBody>
  <TablixColumnHierarchy><TablixMembers><TablixMember /><TablixMember /></TablixMembers></TablixColumnHierarchy>
  <TablixRowHierarchy><TablixMembers>
    <TablixMember><KeepWithGroup>After</KeepWithGroup><RepeatOnNewPage>true</RepeatOnNewPage></TablixMember>
    <TablixMember><Group Name="Details" /></TablixMember>
  </TablixMembers></TablixRowHierarchy>
  <DataSetName>Orders</DataSetName>
  <Top>0cm</Top><Left>0cm</Left><Height>1.2cm</Height><Width>7cm</Width>
</Tablix>
```

- Columns, leaf column members and cells per row are equal in number; the tablix width is the sum of its columns
  (plus row-header widths in a matrix).
- The header member with `KeepWithGroup` and `RepeatOnNewPage` repeats the header on every page.
- Name the tablix after its content (`tblOrders`), never after its dataset: they share a namespace with groups.
- Adding a column: a `TablixColumn`, a `TablixMember` in the column hierarchy and a cell in every row.

## 3. Page setup

| Paper | Portrait (width × height) | Landscape |
|---|---|---|
| A4 | 21 cm × 29.7 cm | 29.7 cm × 21 cm |
| Letter | 8.5 in × 11 in | 11 in × 8.5 in |

Body width < page width − left margin − right margin, with a few millimetres to spare: otherwise PDF and print split
columns over extra pages, and an exact fit rounds over (Report Builder's print layout showed a blank page after every
page for 26.7 cm on A4 landscape with 1.5 cm margins; 26.5 cm fixed it). For a
report used only on screen and in Excel, a wide body is fine: say so. `InteractiveHeight`/`InteractiveWidth` affect
the web viewer only.

## 4. Parameters

- Date range: two `DateTime` parameters; filter `Date >= @Start AND Date < DATEADD(day, 1, @End)` so the end day
  is complete. The Power BI service reads DateTime parameters in US format (MM/DD/YYYY) whatever the design.
- Defaults from `Today()` or `Globals!ExecutionTime`: in the Power BI service the execution time is UTC; check a
  default around midnight.
- Multi-value with text SQL on SQL Server: `WHERE Region IN (@Region)` (the provider expands the list).
  With a stored procedure: pass `=Join(Parameters!Region.Value, ",")` and split inside it
  (`IN (SELECT value FROM STRING_SPLIT(@Region, ','))`).
- Available values or defaults from a dataset: `ValidValues`/`DefaultValue` → `DataSetReference`. Cascading parameters
  are evaluated in order; keep their lookup queries small.
- Every parameter needs a `CellDefinition` in `ReportParametersLayout` (row and column inside the grid), otherwise the
  report fails to load ("number of defined parameters is not equal to the number of cell definitions").

## 5. Datasets by source

| Source | Parameters in the query | Notes |
|---|---|---|
| SQL Server (`SQL`) | `@Name` | `CommandType` `StoredProcedure` for procedures; `Timeout` defaults to 600 seconds |
| ODBC, OLE DB | `?` (positional) | query parameters are matched by order |
| Oracle | `:Name` | |
| Power BI semantic model, Analysis Services (DAX) | `@Name` | map each in `QueryParameters`; write the data source in Report Builder, never by hand |

DAX dataset:

```text
EVALUATE
SUMMARIZECOLUMNS (
    'Date'[Date], 'Product'[Category],
    FILTER ( VALUES ( 'Date'[Date] ), 'Date'[Date] >= @Start && 'Date'[Date] <= @End ),
    "Sales", [Sales Amount]
)
```

- `SUMMARIZECOLUMNS` drops rows where every measure is blank, like a table visual does.
- A field's `DataField` is the column as the query returns it (for DAX `Date[Date]`, `[Sales]`); its `Name` is the
  identifier used in expressions (`Date_Date`, `Sales`).
- Dataset `Filters` filter after the query returned everything; for large data put the parameter into the query.

## 6. Expressions

`=Fields!Amount.Value`, `=Sum(Fields!Amount.Value)`, `=Parameters!Start.Value`, `=Globals!PageNumber & " / " &
Globals!TotalPages`, `=IIF(Fields!Qty.Value = 0, Nothing, Fields!Amount.Value / Fields!Qty.Value)`. Embedded code
(`Code.` with a `Code` block) works in the Power BI service; custom assemblies (`CodeModules`) do not.

## 7. Exports

- Excel: numbers stay numbers when the value is numeric and the format is set with the `Format` property; textboxes
  outside the tablix that do not line up with its columns create merged cells.
- PDF and print: page fit (section 3), repeating headers, page breaks only where wanted.
- CSV and XML: data regions only, no page layout.
