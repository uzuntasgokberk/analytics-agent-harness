/*
  AWSampleETL: target table of LoadDimProduct.dtsx
  ------------------------------------------------
  Creates aw.stg_Product in BiHarnessLab when it is missing. Run it once in SSMS on the local instance, with an
  account that may create objects (not a read-only login), before the first run of the package.

  Safe to run again: nothing happens when the schema or the table exists. Where an earlier setup script already
  created the table, this script changes
  nothing there. The column list is the same as in that script; LoadDimProduct.dtsx writes every column.
  It never drops or alters a table.
*/

USE BiHarnessLab;
GO

IF SCHEMA_ID(N'aw') IS NULL
    EXEC (N'CREATE SCHEMA aw AUTHORIZATION dbo;');
GO

IF OBJECT_ID(N'aw.stg_Product', N'U') IS NULL
CREATE TABLE aw.stg_Product (
    ProductID              int            NOT NULL,
    ProductNumber          nvarchar(25)   NOT NULL,
    ProductName            nvarchar(50)   NOT NULL,
    Color                  nvarchar(15)   NULL,
    Size                   nvarchar(5)    NULL,
    ProductLine            nchar(2)       NULL,
    Class                  nchar(2)       NULL,
    Style                  nchar(2)       NULL,
    StandardCost           decimal(19,4)  NOT NULL,  -- Data Conversion: DT_CY (money) -> DT_NUMERIC(19,4)
    ListPrice              decimal(19,4)  NOT NULL,  -- Data Conversion: DT_CY (money) -> DT_NUMERIC(19,4)
    Weight                 decimal(8,2)   NULL,
    WeightUnitMeasureCode  nchar(3)       NULL,
    SubcategoryName        nvarchar(50)   NULL,
    CategoryName           nvarchar(50)   NULL,
    SellStartDate          datetime       NOT NULL,
    SellEndDate            datetime       NULL,
    MakeFlag               bit            NOT NULL,
    FinishedGoodsFlag      bit            NOT NULL,
    ProductLineName        nvarchar(20)   NULL,      -- Derived Column: R/M/T/S -> Road/Mountain/Touring/Standard
    ProductStatus          nvarchar(15)   NULL,      -- Derived Column: Current / Discontinued
    LoadDate               datetime       NOT NULL   -- Derived Column: GETDATE()
);
GO
