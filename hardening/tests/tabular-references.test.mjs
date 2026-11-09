// Model-wide references in TMDL: calculated columns and relationship ends that name a table or column the model does not
// define. A calculated column's DAX is checked like a measure's (warning); a relationship end that names a missing
// table or column is an error, because Power BI Desktop does not load such a model and Analysis Services refuses it.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { splitColumnRef, unresolvedRelationshipEnds, readModelFields, validateArtifacts } from '../hooks/lib/validators.mjs';

const T = '\t';

function withProject(files, fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-tabular-refs-'));
  try {
    for (const [rel, content] of Object.entries(files)) {
      fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
      fs.writeFileSync(path.join(dir, rel), content);
    }
    return fn(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

const SALES = [
  'table Sales', '',
  `${T}measure 'Total Amount' = SUM ( Sales[Amount] )`, `${T}${T}formatString: 0`, '',
  `${T}column Amount`, `${T}${T}dataType: int64`, `${T}${T}sourceColumn: Amount`, '',
  `${T}column CustomerKey`, `${T}${T}dataType: int64`, `${T}${T}sourceColumn: CustomerKey`, '',
  `${T}column Segment =`,
  `${T}${T}${T}VAR seg = RELATED ( 'Customer Group'[Segment Name] )`,
  `${T}${T}${T}RETURN IF ( ISBLANK ( seg ), "Other", seg )`,
  `${T}${T}dataType: string`, '',
].join('\r\n');
const CUSTOMER = [
  "table 'Customer Group'", '',
  `${T}column CustomerKey`, `${T}${T}dataType: int64`, `${T}${T}sourceColumn: CustomerKey`, '',
  `${T}column 'Segment Name'`, `${T}${T}dataType: string`, `${T}${T}sourceColumn: SegmentName`, '',
  `${T}column 'Region.Code'`, `${T}${T}dataType: string`, `${T}${T}sourceColumn: RegionCode`, '',
].join('\r\n');
const RELATIONSHIPS = [
  'relationship 1f0c2d7e-0000-4000-8000-000000000001',
  `${T}fromColumn: Sales.CustomerKey`,
  `${T}toColumn: 'Customer Group'.CustomerKey`, '',
].join('\r\n');

/** An Analysis Services tabular folder (database.tmdl), as Tabular Editor saves it. */
const tabular = (over = {}) => ({
  'models/Finance/database.tmdl': 'database Finance\n\tcompatibilityLevel: 1500\n',
  'models/Finance/model.tmdl': 'model Model\n\tculture: en-US\n',
  'models/Finance/tables/Sales.tmdl': SALES,
  'models/Finance/tables/Customer Group.tmdl': CUSTOMER,
  'models/Finance/relationships.tmdl': RELATIONSHIPS,
  ...over,
});
const TABULAR_ITEMS = { reports: [], models: [], tabular: ['models/Finance'] };
const byLevel = (issues, level) => issues.filter((i) => i.level === level);

test('tabular references: a consistent model reports no reference warning or error', () => {
  withProject(tabular(), (dir) => {
    const issues = validateArtifacts(dir, TABULAR_ITEMS);
    assert.deepEqual(byLevel(issues, 'error'), []);
    assert.deepEqual(issues.filter((i) => /references|Relationship/.test(i.message)), []);
  });
});

test('tabular references: a calculated column that names a missing column is reported like a measure (warning)', () => {
  const broken = SALES.replace("'Customer Group'[Segment Name]", "'Customer Group'[Segment Label]");
  withProject(tabular({ 'models/Finance/tables/Sales.tmdl': broken }), (dir) => {
    const issues = validateArtifacts(dir, TABULAR_ITEMS);
    const warn = issues.find((i) => /^Calculated column 'Sales'\[Segment\] references/.test(i.message));
    assert.ok(warn, JSON.stringify(issues, null, 2));
    assert.equal(warn.level, 'warn');
    assert.equal(warn.file, 'models/Finance/tables/Sales.tmdl');
    assert.match(warn.message, /'Customer Group'\[Segment Label\], which the model does not define/);
  });
});

test('tabular references: a measure that names a missing column is still a warning', () => {
  const broken = SALES.replace('SUM ( Sales[Amount] )', 'SUM ( Sales[NetAmount] )');
  withProject(tabular({ 'models/Finance/tables/Sales.tmdl': broken }), (dir) => {
    const warn = validateArtifacts(dir, TABULAR_ITEMS).find((i) => /^Measure 'Total Amount' references Sales\[NetAmount\]/.test(i.message));
    assert.equal(warn?.level, 'warn');
  });
});

test('tabular references: a relationship end that names a missing column or table is an error', () => {
  const missingColumn = RELATIONSHIPS.replace('Sales.CustomerKey', 'Sales.CustomerId');
  withProject(tabular({ 'models/Finance/relationships.tmdl': missingColumn }), (dir) => {
    const errors = byLevel(validateArtifacts(dir, TABULAR_ITEMS), 'error');
    assert.equal(errors.length, 1, JSON.stringify(errors, null, 2));
    assert.equal(errors[0].file, 'models/Finance/relationships.tmdl');
    assert.match(errors[0].message, /^Relationship 1f0c2d7e-0000-4000-8000-000000000001 \(fromColumn\) names column 'Sales'\[CustomerId\], which the model does not define/);
  });
  const missingTable = RELATIONSHIPS.replace("'Customer Group'.CustomerKey", "'Customer Groups'.CustomerKey");
  withProject(tabular({ 'models/Finance/relationships.tmdl': missingTable }), (dir) => {
    const errors = byLevel(validateArtifacts(dir, TABULAR_ITEMS), 'error');
    assert.equal(errors.length, 1, JSON.stringify(errors, null, 2));
    assert.match(errors[0].message, /\(toColumn\) names table 'Customer Groups'/);
  });
});

test('tabular references: the relationships of a Power BI project model are checked under definition/', () => {
  const files = {
    'M.SemanticModel/definition.pbism': '{}\n',
    'M.SemanticModel/definition/model.tmdl': 'model Model\n',
    'M.SemanticModel/definition/tables/Sales.tmdl': SALES,
    'M.SemanticModel/definition/tables/Customer Group.tmdl': CUSTOMER,
    'M.SemanticModel/definition/relationships.tmdl': RELATIONSHIPS.replace('Sales.CustomerKey', 'Sales.CustomerId'),
  };
  withProject(files, (dir) => {
    const errors = byLevel(validateArtifacts(dir, { reports: [], models: ['M.SemanticModel'], tabular: [] }), 'error');
    assert.equal(errors.length, 1, JSON.stringify(errors, null, 2));
    assert.equal(errors[0].file, 'M.SemanticModel/definition/relationships.tmdl');
  });
});

test('tabular references: relationship ends with quotes, dots and escaped quotes resolve', () => {
  assert.deepEqual(splitColumnRef("'Customer Group'.'Region.Code'"), ['Customer Group', 'Region.Code']);
  assert.deepEqual(splitColumnRef("'O''Brien Sales'.Amount"), ["O'Brien Sales", 'Amount']);
  assert.deepEqual(splitColumnRef('Sales.CustomerKey'), ['Sales', 'CustomerKey']);
  assert.deepEqual(splitColumnRef("Sales.'Order Date'"), ['Sales', 'Order Date']);
  assert.equal(splitColumnRef('CustomerKey'), null, 'no table part: no claim');
  assert.equal(splitColumnRef("'Unclosed.Name"), null);
  withProject(tabular(), (dir) => {
    const tables = readModelFields(path.join(dir, 'models/Finance'), fs, '');
    const text = ['relationship r1', `${T}fromColumn: Sales.CustomerKey`, `${T}toColumn: 'Customer Group'.'Region.Code'`].join('\n');
    assert.deepEqual(unresolvedRelationshipEnds(text, tables), []);
    assert.deepEqual(unresolvedRelationshipEnds(text.replace('Region.Code', 'Region.Name'), tables), [{ relationship: 'r1', end: 'toColumn', what: "column 'Customer Group'[Region.Name]" }]);
  });
});
