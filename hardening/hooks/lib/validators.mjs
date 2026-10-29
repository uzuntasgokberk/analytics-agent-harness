// PBIP validators shared by the PostToolUse/Stop hooks, hardening/scripts/validate.mjs and git hooks.
// Issue shape: { level: 'error'|'warn'|'info', file, line?, message }.

import fs from 'node:fs';
import path from 'node:path';
import { git, isReferenceRel, matchesAny, toPosix } from './common.mjs';
import { TMDL_ONLY_REASON, classifyPath, findSecrets } from './policy.mjs';

const TEXT_EXTS = new Set([
  '.tmdl', '.bim', '.json', '.pbir', '.pbism', '.pbip', '.dax', '.md', '.m', '.pq', '.txt', '.yml', '.yaml', '.rdl', '.rds', '.rsd', '.sql',
  '.mjs', '.cjs', '.js', '.ts', '.py', '.ps1', '.psm1', '.sh', '.xml', '.toml', '.ini', '.cfg', '.config',
  '.dtsx', '.dtproj', '.conmgr', '.params', '.dtsconfig', '.ipynb',
]);
const TEXT_NAMES = new Set(['.platform', '.gitignore', '.gitattributes', '.env.example', 'dockerfile', 'makefile']);
const MAX_TEXT_BYTES = 5 * 1024 * 1024;

export function isTextFile(rel) {
  const posix = toPosix(rel).toLowerCase();
  const base = posix.split('/').pop();
  return TEXT_EXTS.has(path.posix.extname(base)) || TEXT_NAMES.has(base) || posix.startsWith('hardening/githooks/');
}

export const stripBom = (text) => (text.charCodeAt(0) === 0xfeff ? text.slice(1) : text);

export function countLines(text) {
  const s = String(text ?? '');
  if (!s) return 0;
  const n = s.split(/\r\n|\r|\n/).length;
  return /(?:\r\n|\r|\n)$/.test(s) ? n - 1 : n;
}

// ---------------------------------------------------------------- edit simulation (PreToolUse)

/** Result of an Edit tool call applied to `current`, or null if old_string is not found. */
export function simulateEdit(current, oldStr, newStr, replaceAll) {
  if (typeof current !== 'string' || typeof oldStr !== 'string' || oldStr === '') return null;
  let from = oldStr;
  let to = String(newStr ?? '');
  if (!current.includes(from) && current.includes('\r\n')) {
    from = from.replace(/\r?\n/g, '\r\n');
    to = to.replace(/\r?\n/g, '\r\n');
  }
  const idx = current.indexOf(from);
  if (idx < 0) return null;
  if (replaceAll) return current.split(from).join(to);
  return current.slice(0, idx) + to + current.slice(idx + from.length);
}

// ---------------------------------------------------------------- TMDL

// One declaration per line, indented with tabs or spaces (TMDL allows both): a rename or removal of any of these breaks
// what refers to it. A relationship counts here too; its other changes are tmdlRelationshipFacts.
const DECL_RE = /^[ \t]*(table|column|measure|hierarchy|level|calculationItem|expression|function|role|perspective|culture|relationship)[ \t]+('(?:[^']|'')*'|[^\s=:'`]+)/;

/**
 * The declarations of TMDL text keyed by the table they are declared in as well: key "<table>\0<kind name>" (no table
 * part outside a table block) mapped to the "kind name" string. The same name in two tables of one text (a column
 * Amount, a hierarchy Calendar and its levels) is two objects, so a rename in one is not masked by the other.
 */
function scopedTmdlDeclarations(text) {
  const out = new Map();
  let table = null; // { name, depth } of the table whose block the current line is in
  let hierarchy = null; // { name, depth } of the hierarchy whose block the current line is in
  for (const line of stripBom(String(text ?? '')).split(/\r?\n/)) {
    const m = DECL_RE.exec(line);
    if (!m) continue;
    const depth = indentWidth(line);
    if (hierarchy && depth <= hierarchy.depth) hierarchy = null;
    if (table && depth <= table.depth) table = null;
    const name = m[2].startsWith("'") ? m[2].slice(1, -1).replace(/''/g, "'") : m[2];
    if (m[1] === 'hierarchy') hierarchy = { name, depth };
    const declared = `${m[1]} ${m[1] === 'level' && hierarchy ? `${hierarchy.name}/` : ''}${name}`.toLowerCase();
    out.set(`${table ? table.name.toLowerCase() : ''}\0${declared}`, declared);
    if (m[1] === 'table') table = { name, depth };
  }
  return out;
}

/**
 * Named model objects declared in TMDL text, as lowercase "kind name" strings. A level carries the hierarchy declared
 * above it ("level calendar/year"), so the levels of two hierarchies do not mask each other.
 */
export function extractTmdlDeclarations(text) {
  return new Set(scopedTmdlDeclarations(text).values());
}

/** The "kind name" strings of the objects declared in `before` and no longer in `after`, each object in its own table. */
export function removedDeclarations(before, after) {
  const kept = scopedTmdlDeclarations(after);
  return [...new Set([...scopedTmdlDeclarations(before)].filter(([key]) => !kept.has(key)).map(([, declared]) => declared))];
}

/** Role members in TMDL (`member ...` lines): the agent never changes them. */
export function roleMembersChanged(before, after) {
  // [ \t] instead of \s: with the m flag, \s* also crosses blank lines and makes the scan quadratic on long files.
  const members = (text) => [...String(text ?? '').matchAll(/^[ \t]*member[ \t]+(.+?)[ \t]*$/gm)].map((m) => m[1]).sort().join('\n');
  return members(before) !== members(after);
}

// Declarations that say where a model's data comes from, matched on a line without its indentation.
const PARTITION_DECL_RE = /^partition[ \t]+('(?:[^']|'')*'|[^\s=:'`]+)[ \t]*(?:=[ \t]*(.*))?$/i;
const EXPRESSION_DECL_RE = /^expression[ \t]+('(?:[^']|'')*'|[^\s=:'`]+)[ \t]*(?:=[ \t]*(.*))?$/i;
const DATA_SOURCE_DECL_RE = /^dataSource[ \t]+('(?:[^']|'')*'|[^\s=:'`]+)/i;
const TABLE_NAME_RE = /^table[ \t]+('(?:[^']|'')*'|[^\s=:'`]+)/i;
const REFRESH_POLICY_RE = /^refreshPolicy\b/i;
const DEFAULT_MODE_RE = /^defaultMode[ \t]*:[ \t]*(.*)$/i;
// Metadata inside those blocks, routine to edit: annotations, extended properties, lineage tags, descriptions.
const SOURCE_METADATA_RE = /^(?:annotation|extendedProperty|changedProperty|lineageTag|sourceLineageTag)\b|^\/\/\//i;
const SOURCELESS_PARTITIONS = new Set(['calculated', 'calculationgroup']);

/** Indentation width of a line: a tab counts 4, a space 1, so tab and space indented files compare alike. */
function indentWidth(line) {
  let width = 0;
  for (const c of line) {
    if (c === '\t') width += 4;
    else if (c === ' ') width += 1;
    else break;
  }
  return width;
}

/**
 * Where a TMDL model's data comes from, by category, for "did this edit change it" (Tier 2 in AGENTS.md: a data source,
 * a Power Query or model parameter, a storage mode or refresh change). Like ssisConnectionFacts: equal texts, no change.
 * - dataSource: each partition's kind and properties (the M, query or entity `source`, `dataSource:` and the rest) and
 *   each `dataSource` object; a new or removed partition counts. Calculated and calculation group partitions read no
 *   data source, so only their storage mode (other than import) counts.
 * - storageMode: each partition's `mode:` and the model's `defaultMode:`.
 * - refreshPolicy: each `refreshPolicy` block.
 * - expression: each named `expression` (shared M query or parameter) and each partition's `queryGroup:`.
 * Blocks follow indentation (tabs or spaces). Lines are compared without it; annotations, extended properties,
 * lineage tags and descriptions are left out, so editing them stays routine.
 */
export function tmdlSourceFacts(text) {
  const lines = stripBom(String(text ?? '')).split(/\r?\n/).map((line) => ({ depth: indentWidth(line), body: line.trim() }));
  const facts = { dataSource: [], storageMode: [], refreshPolicy: [], expression: [] };
  // Index after the block of the declaration at i: deeper and blank lines, up to the next line at its depth or above.
  const blockEnd = (i) => {
    let j = i + 1;
    while (j < lines.length && (!lines[j].body || lines[j].depth > lines[i].depth)) j++;
    return j;
  };
  // The block's properties (its shallowest lines), each with the deeper lines under it; metadata left out.
  const properties = (from, to) => {
    const body = lines.slice(from, to).filter((l) => l.body);
    // A reduce, not Math.min(...): a spread of a long block (an M query of 120,000+ lines) throws a RangeError.
    const depth = body.reduce((min, l) => (l.depth < min ? l.depth : min), Infinity);
    const out = [];
    for (const l of body) {
      if (l.depth <= depth || !out.length) out.push({ name: /^[^\s:=]*/.exec(l.body)[0].toLowerCase(), lines: [l.body] });
      else out[out.length - 1].lines.push(l.body);
    }
    return out.filter((p) => !SOURCE_METADATA_RE.test(p.lines[0]));
  };
  let table = '';
  for (let i = 0; i < lines.length; i++) {
    const { body } = lines[i];
    if (!body) continue;
    let m;
    if ((m = TABLE_NAME_RE.exec(body))) {
      table = unquoteName(m[1]);
    } else if ((m = PARTITION_DECL_RE.exec(body))) {
      const end = blockEnd(i);
      const key = `partition ${table}/${unquoteName(m[1])}`;
      const kind = (m[2] ?? '').trim().toLowerCase();
      const sourceless = SOURCELESS_PARTITIONS.has(kind);
      if (!sourceless) facts.dataSource.push(`${key} = ${kind}`);
      for (const p of properties(i + 1, end)) {
        if (p.name === 'mode') {
          const mode = p.lines.join(' ').replace(/^mode[ \t]*:?[ \t]*/i, '').toLowerCase();
          if (!sourceless || mode !== 'import') facts.storageMode.push(`${key} mode: ${mode}`);
        } else if (p.name === 'querygroup') facts.expression.push(`${key} ${p.lines.join('\n')}`);
        else if (!sourceless) facts.dataSource.push(`${key} ${p.lines.join('\n')}`);
      }
      i = end - 1;
    } else if (REFRESH_POLICY_RE.test(body)) {
      const end = blockEnd(i);
      facts.refreshPolicy.push([`refreshPolicy ${table}`, ...properties(i + 1, end).map((p) => p.lines.join('\n'))].join('\n'));
      i = end - 1;
    } else if ((m = EXPRESSION_DECL_RE.exec(body))) {
      const end = blockEnd(i);
      const head = `expression ${unquoteName(m[1])} = ${(m[2] ?? '').trim()}`;
      facts.expression.push([head, ...properties(i + 1, end).map((p) => p.lines.join('\n'))].join('\n'));
      i = end - 1;
    } else if ((m = DATA_SOURCE_DECL_RE.exec(body))) {
      const end = blockEnd(i);
      facts.dataSource.push([`dataSource ${unquoteName(m[1])}`, ...properties(i + 1, end).map((p) => p.lines.join('\n'))].join('\n'));
      i = end - 1;
    } else if ((m = DEFAULT_MODE_RE.exec(body))) {
      facts.storageMode.push(`defaultMode: ${m[1].trim().toLowerCase()}`);
    }
  }
  return Object.fromEntries(Object.entries(facts).map(([category, list]) => [category, list.sort().join('\n\n')]));
}

const RELATIONSHIP_DECL_RE = /^relationship[ \t]+\S/i;

/**
 * The relationships declared in TMDL text, for "did this edit change one" (Tier 2 in AGENTS.md: a relationship changes how
 * every visual and measure filters across tables). Each `relationship <name>` block with its properties (columns,
 * cardinality, cross-filter direction, active flag, ...), the blocks sorted. Like tmdlSourceFacts: a block follows
 * indentation (tabs or spaces), lines are compared without it, and annotations, extended properties, lineage tags and
 * descriptions are left out, so editing them stays routine. Equal texts, no change; a relationship added, removed,
 * renamed or edited anywhere, in any TMDL file, differs.
 */
export function tmdlRelationshipFacts(text) {
  const lines = stripBom(String(text ?? '')).split(/\r?\n/).map((line) => ({ depth: indentWidth(line), body: line.trim() }));
  const blocks = [];
  for (let i = 0; i < lines.length; i++) {
    if (!RELATIONSHIP_DECL_RE.test(lines[i].body)) continue;
    const block = [lines[i].body];
    let metadata = -1; // depth of a metadata property whose deeper lines go with it
    let j = i + 1;
    for (; j < lines.length && (!lines[j].body || lines[j].depth > lines[i].depth); j++) {
      const { body, depth } = lines[j];
      if (!body || (metadata >= 0 && depth > metadata)) continue;
      metadata = SOURCE_METADATA_RE.test(body) ? depth : -1;
      if (metadata < 0) block.push(body);
    }
    blocks.push(block.join('\n'));
    i = j - 1;
  }
  return blocks.sort().join('\n\n');
}

function checkTmdl(rel, text) {
  const issues = [];
  const add = (level, message, line) => issues.push({ level, file: rel, ...(line ? { line } : {}), message });
  const lines = text.split(/\r?\n/);
  const spaceLines = [];
  const userPathLines = [];
  const tags = new Map();
  let fenced = false;

  lines.forEach((line, i) => {
    if ((line.match(/```/g) || []).length % 2 === 1) fenced = !fenced;
    if (!fenced && /^ +\S/.test(line)) spaceLines.push(i + 1);
    if (/[A-Za-z]:\\(?:Users|Documents and Settings)\\/i.test(line)) userPathLines.push(i + 1);
    const tag = /^\s*lineageTag:\s*(\S+)/.exec(line);
    if (tag) {
      if (tags.has(tag[1])) add('warn', `Duplicate lineageTag ${tag[1]} (also line ${tags.get(tag[1])}). Never copy lineageTags between objects.`, i + 1);
      else tags.set(tag[1], i + 1);
    }
    if (!fenced && /^relationship\s/.test(line) && i > 0 && lines[i - 1].trim().startsWith('///')) {
      add('error', 'A relationship has no description in the Tabular Object Model: a /// line above it stops Power BI Desktop from loading the model ("Property \'description\' is unknown").', i + 1);
    }
    // A description must touch its object: TOM refuses a blank line after /// ("InvalidLineType: Empty", tested 2026-10-06).
    // Only when the next object sits at the same depth, so a DAX comment inside an expression is left alone.
    const doc = /^(\t*)\/\/\//.exec(line);
    if (!fenced && doc && i + 1 < lines.length && lines[i + 1].trim() === '') {
      const next = lines.slice(i + 1).find((l) => l.trim() !== '');
      if (next && /^\t*/.exec(next)[0].length === doc[1].length && TMDL_OBJECT_RE.test(next)) {
        add('error', 'A /// description must sit directly above its object: a blank line after it stops Power BI Desktop and TOM from loading the model ("Unexpected line type: Empty").', i + 1);
      }
    }
    const decl = /^(\t*)measure\s+('(?:[^']|'')*'|[^\s=:'`]+)\s*=\s*$/.exec(line);
    if (decl) {
      const next = lines.slice(i + 1).find((l) => l.trim() !== '');
      const depth = next ? /^\t*/.exec(next)[0].length : 0;
      if (depth <= decl[1].length + 1) add('warn', `Measure ${decl[2]} seems to have an empty expression (multi-line DAX goes one tab deeper than the properties).`, i + 1);
    }
  });
  if (spaceLines.length) {
    add('warn', `Line(s) ${spaceLines.slice(0, 5).join(', ')}${spaceLines.length > 5 ? ', …' : ''} start with spaces; TMDL indentation uses tabs.`, spaceLines[0]);
  }
  if (userPathLines.length) {
    add('warn', 'Hardcoded local user path in Power Query (breaks for other users and leaks a user name). Use a parameter in expressions.tmdl.', userPathLines[0]);
  }
  return issues;
}

// ---------------------------------------------------------------- model fields and references

const TABLE_DECL_RE = /^table\s+('(?:[^']|'')*'|[^\s=:'`]+)/;
// TMDL object declarations that can carry a /// description (not DAX or M lines inside an expression).
const TMDL_OBJECT_RE =
  /^\t*(?:database|model|table|column|measure|partition|hierarchy|level|relationship|role|tablePermission|columnPermission|perspective|perspective(?:Table|Column|Measure|Hierarchy)|culture|expression|dataSource|calculationGroup|calculationItem|function|calendar|queryGroup|kpi)\s/;
const MEMBER_DECL_RE = /^\t(column|measure|hierarchy)\s+('(?:[^']|'')*'|[^\s=:'`]+)\s*(?:=\s*(.*))?$/;
const unquoteName = (name) => (name.startsWith("'") ? name.slice(1, -1).replace(/''/g, "'") : name);
const tabDepth = (line) => /^\t*/.exec(line)[0].length;

function measureExpression(lines, i, first) {
  const head = first.trim();
  if (head.startsWith('```')) {
    const body = [head.slice(3)];
    for (let j = i + 1; j < lines.length && !lines[j].trim().startsWith('```'); j++) body.push(lines[j]);
    return body.join('\n');
  }
  const body = [first];
  const depth = tabDepth(lines[i]);
  for (let j = i + 1; j < lines.length; j++) {
    if (lines[j].trim() !== '' && tabDepth(lines[j]) < depth + 2) break;
    body.push(lines[j]);
  }
  return body.join('\n');
}

/**
 * Tables of a TMDL model folder: lowercase name -> { name, fields (lowercase column, measure and hierarchy names),
 * measures: [{ name, file, expression }] }. Null when there are no TMDL tables or one cannot be read, so callers
 * skip reference checks instead of reporting false errors.
 */
export function readModelFields(modelDir, io = fs, sub = 'definition') {
  const tablesDir = path.join(modelDir, sub, 'tables');
  let files;
  try {
    files = io.readdirSync(tablesDir).filter((f) => f.endsWith('.tmdl'));
  } catch {
    return null;
  }
  const tables = new Map();
  for (const file of files) {
    let lines;
    try {
      lines = stripBom(io.readFileSync(path.join(tablesDir, file), 'utf8')).split(/\r?\n/);
    } catch {
      return null;
    }
    let table = null;
    lines.forEach((line, i) => {
      const t = TABLE_DECL_RE.exec(line);
      if (t) {
        const name = unquoteName(t[1]);
        table = tables.get(name.toLowerCase()) ?? { name, fields: new Set(), columns: new Set(), measures: [] };
        tables.set(name.toLowerCase(), table);
        return;
      }
      const m = table && MEMBER_DECL_RE.exec(line);
      if (!m) return;
      const name = unquoteName(m[2]);
      table.fields.add(name.toLowerCase());
      if (m[1] === 'column') table.columns.add(name.toLowerCase());
      if (m[1] === 'measure') table.measures.push({ name, file, expression: measureExpression(lines, i, m[3] ?? '') });
    });
  }
  return tables.size ? tables : null;
}

function bracketEnd(s, i) {
  for (let j = i + 1; j < s.length; j++) {
    if (s[j] !== ']') continue;
    if (s[j + 1] === ']') j++;
    else return j;
  }
  return s.length - 1;
}

/** DAX without comments and string literals, plus the literals (lowercase): names of columns an expression adds. */
function daxCode(expression) {
  const s = String(expression ?? '');
  const strings = new Set();
  let code = '';
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === '"') {
      let j = i + 1;
      let value = '';
      for (; j < s.length; j++) {
        if (s[j] === '"' && s[j + 1] === '"') { value += '"'; j++; } else if (s[j] === '"') break;
        else value += s[j];
      }
      strings.add(value.toLowerCase());
      code += ' ';
      i = j;
    } else if ((c === '/' && s[i + 1] === '/') || (c === '-' && s[i + 1] === '-')) {
      while (i + 1 < s.length && s[i + 1] !== '\n') i++;
    } else if (c === '/' && s[i + 1] === '*') {
      const end = s.indexOf('*/', i + 2);
      i = end < 0 ? s.length : end + 1;
      code += ' ';
    } else if (c === '[') {
      const end = bracketEnd(s, i);
      code += s.slice(i, end + 1);
      i = end;
    } else if (c === "'") {
      let j = i + 1;
      while (j < s.length && !(s[j] === "'" && s[j + 1] !== "'")) j += s[j] === "'" ? 2 : 1;
      code += s.slice(i, j + 1);
      i = j;
    } else code += c;
  }
  return { code, strings };
}

const DAX_REF_RE = /('(?:[^']|'')+'|[\p{L}_][\p{L}\p{N}_]*)?\[((?:[^\]]|\]\])+)\]/gu;
const IMPLICIT_COLUMN_RE = /^(?:value\d*|date)$/; // table constructors, GENERATESERIES, CALENDAR

/**
 * References in a DAX expression that the model does not define. Unqualified [Name] must be a measure or a column of
 * some table (row context) or a column the expression adds; Table[Name] must exist in that table, and the table in the
 * model (DAX has no Variable[Column] syntax).
 */
export function unresolvedDaxRefs(expression, tables) {
  const { code, strings } = daxCode(expression);
  const known = new Set([...tables.values()].flatMap((t) => [...t.fields]));
  const out = new Set();
  for (const m of code.matchAll(DAX_REF_RE)) {
    if (!m[1] && code[m.index - 1] === '.') continue; // Sales[OrderDate].[Year]: a date variation, not a field
    const field = m[2].replace(/\]\]/g, ']');
    const key = field.toLowerCase();
    if (m[1]) {
      const table = tables.get(unquoteName(m[1]).toLowerCase());
      if (!table?.fields.has(key)) out.add(`${m[1]}[${field}]`);
    } else if (!known.has(key) && !strings.has(key) && !IMPLICIT_COLUMN_RE.test(key)) {
      out.add(`[${field}]`);
    }
  }
  return [...out];
}

// Where a perspective or culture file names model objects: the table entry and its members, by keyword and tab depth.
const METADATA_LAYOUT = {
  perspective: { table: [1, /^perspectiveTable$/], member: [2, /^perspective(?:Column|Measure|Hierarchy)$/] },
  culture: { table: [3, /^table$/], member: [4, /^(?:column|measure|hierarchy)$/] },
};
const METADATA_DECL_RE = /^\t*(\w+)\s+('(?:[^']|'')*'|[^\s=:'`]+)\s*$/;

/**
 * Tables and members that a perspective (`perspectives/*.tmdl`) or culture (`cultures/*.tmdl`) file names and the
 * model does not define: what a rename or delete leaves behind. Returned as 'Table' or 'Table'[Member].
 */
export function unresolvedMetadataRefs(text, tables, kind) {
  const layout = METADATA_LAYOUT[kind];
  const out = [];
  let table = null;
  for (const line of stripBom(text).split(/\r?\n/)) {
    const m = METADATA_DECL_RE.exec(line);
    if (!m) continue;
    const depth = tabDepth(line);
    const name = unquoteName(m[2]);
    if (depth === layout.table[0] && layout.table[1].test(m[1])) {
      table = { name, entry: tables.get(name.toLowerCase()) };
      if (!table.entry) out.push(`'${name}'`);
    } else if (depth === layout.member[0] && layout.member[1].test(m[1]) && table?.entry) {
      if (!table.entry.fields.has(name.toLowerCase())) out.push(`'${table.name}'[${name}]`);
    } else if (depth < layout.member[0]) {
      table = null;
    }
  }
  return out;
}

/**
 * Model fields a PBIR document uses, as { entity, field, inFilter }. Query aliases (From, SourceRef.Source) are
 * resolved; inFilter marks references under filterConfig.
 */
export function pbirFieldRefs(data) {
  const refs = [];
  const entityOf = (expression, aliases) => {
    const src = expression?.SourceRef;
    if (typeof src?.Entity === 'string') return src.Entity;
    return typeof src?.Source === 'string' ? aliases.get(src.Source) ?? null : null;
  };
  const visit = (node, aliases, inFilter) => {
    if (Array.isArray(node)) {
      node.forEach((n) => visit(n, aliases, inFilter));
      return;
    }
    if (!node || typeof node !== 'object') return;
    let scope = aliases;
    if (Array.isArray(node.From)) {
      scope = new Map(aliases);
      for (const f of node.From) if (typeof f?.Name === 'string' && typeof f?.Entity === 'string') scope.set(f.Name, f.Entity);
    }
    for (const key of ['Column', 'Measure', 'PropertyVariationSource']) {
      const ref = node[key];
      const entity = ref && typeof ref.Property === 'string' ? entityOf(ref.Expression, scope) : null;
      if (entity) refs.push({ entity, field: ref.Property, inFilter });
    }
    const h = node.Hierarchy;
    const hEntity = h && typeof h.Hierarchy === 'string' ? entityOf(h.Expression, scope) : null; // auto date/time variations have no SourceRef here
    if (hEntity) refs.push({ entity: hEntity, field: h.Hierarchy, inFilter });
    for (const [key, value] of Object.entries(node)) visit(value, scope, inFilter || key === 'filterConfig');
  };
  visit(data, new Map(), false);
  return refs;
}

// ---------------------------------------------------------------- RDL (paginated reports)

// XML 1.0 Name production (5th edition) without ":"; a QName is NCName or NCName:NCName (Namespaces in XML 1.0).
const NC_START = 'A-Z_a-z\\u00C0-\\u00D6\\u00D8-\\u00F6\\u00F8-\\u02FF\\u0370-\\u037D\\u037F-\\u1FFF\\u200C\\u200D\\u2070-\\u218F\\u2C00-\\u2FEF\\u3001-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFFD\\u{10000}-\\u{EFFFF}';
const NC_CHAR = `${NC_START}\\-.0-9\\u00B7\\u0300-\\u036F\\u203F\\u2040`;
const QNAME_RE = new RegExp(`^[${NC_START}][${NC_CHAR}]*(?::[${NC_START}][${NC_CHAR}]*)?$`, 'u');
const NAME_START_RE = new RegExp(`^[${NC_START}]`, 'u');
const NAME_TOKEN_RE = /[^\s/>=<"'?]+/y; // a candidate name up to the next delimiter; QNAME_RE then judges it
const XML_WS_RE = /[ \t\r\n]*/y;
const XML_DECL_RE = /^<\?xml[ \t\r\n]+version[ \t\r\n]*=[ \t\r\n]*(["'])1\.[0-9]+\1(?:[ \t\r\n]+encoding[ \t\r\n]*=[ \t\r\n]*(["'])[A-Za-z][\w.-]*\2)?(?:[ \t\r\n]+standalone[ \t\r\n]*=[ \t\r\n]*(["'])(?:yes|no)\3)?[ \t\r\n]*\?>/;
const BAD_AMP_RE = /&(?!(?:amp|lt|gt|quot|apos|#[0-9]+|#x[0-9a-fA-F]+);)/;

/**
 * XML well-formedness, dependency-free (Node has no XML parser): a tokenizer that checks the XML declaration (only at
 * the very start), comments, CDATA, processing instructions, element and attribute names (QName: at most one colon),
 * attributes (name="value" or name='value', whitespace between them, no duplicate, no "<" in a value, "&" only as a
 * reference), "/>" and matching end tags, exactly one root and nothing but whitespace, comments and processing
 * instructions outside it, and "&", "<" and "]]>" in text. A DOCTYPE is skipped, its entity declarations are not read.
 * Namespace prefixes are not checked against their declarations. Returns null or { message, line }.
 */
export function xmlProblem(text) {
  const s = stripBom(String(text ?? ''));
  const lineAt = (pos) => s.slice(0, pos).split('\n').length;
  const fail = (message, pos) => ({ message, line: lineAt(pos) });
  const badAmp = (from, to) => {
    const amp = s.indexOf('&', from);
    if (amp < 0 || amp >= to) return null;
    const m = BAD_AMP_RE.exec(s.slice(amp, to));
    return m ? fail('unescaped "&" (write &amp;, also inside expressions such as ="a" & "b")', amp + m.index) : null;
  };
  const skipWs = (pos) => { XML_WS_RE.lastIndex = pos; XML_WS_RE.exec(s); return XML_WS_RE.lastIndex; };
  const nameAt = (pos) => { NAME_TOKEN_RE.lastIndex = pos; return NAME_TOKEN_RE.exec(s)?.[0] ?? ''; };
  const stack = []; // [name, position of its start tag]
  let roots = 0;
  let i = 0;
  while (i < s.length) {
    const lt = s.indexOf('<', i);
    const textEnd = lt < 0 ? s.length : lt;
    if (!stack.length) {
      const extra = s.slice(i, textEnd).search(/[^ \t\r\n]/);
      if (extra >= 0) return fail(roots ? 'text after the root element' : 'text before the root element', i + extra);
    }
    const amp = badAmp(i, textEnd);
    if (amp) return amp;
    // XML 1.0 (CharData) forbids "]]>" in text; comments, CDATA sections and attribute values are read elsewhere.
    const cdataEnd = s.slice(i, textEnd).indexOf(']]>');
    if (cdataEnd >= 0) return fail('"]]>" in text outside a CDATA section (XML 1.0 forbids it; write ]]&gt;)', i + cdataEnd);
    if (lt < 0) break;

    if (s.startsWith('<!--', lt)) {
      const end = s.indexOf('-->', lt + 4);
      if (end < 0) return fail('unclosed <!--', lt);
      const body = s.slice(lt + 4, end);
      if (body.includes('--') || body.endsWith('-')) return fail('a comment must not contain "--" or end with "-"', lt);
      i = end + 3;
      continue;
    }
    if (s.startsWith('<![CDATA[', lt)) {
      const end = s.indexOf(']]>', lt + 9);
      if (end < 0) return fail('unclosed <![CDATA[', lt);
      if (!stack.length) return fail('CDATA section outside the root element', lt);
      i = end + 3;
      continue;
    }
    if (s.startsWith('<?', lt)) {
      const end = s.indexOf('?>', lt + 2);
      if (end < 0) return fail('unclosed <?', lt);
      const target = nameAt(lt + 2);
      if (target.toLowerCase() === 'xml') {
        if (lt !== 0) return fail('the XML declaration <?xml ...?> must be at the very start of the file (nothing before it, not even whitespace)', lt);
        if (target !== 'xml' || !XML_DECL_RE.test(s)) return fail('malformed XML declaration (expected <?xml version="1.0" encoding="..."?>)', lt);
      } else if (!QNAME_RE.test(target) || !/^(?:[ \t\r\n]|\?>)/.test(s.slice(lt + 2 + target.length, lt + 4 + target.length))) {
        return fail('invalid processing instruction target', lt);
      }
      i = end + 2;
      continue;
    }
    if (s.startsWith('<!DOCTYPE', lt)) {
      if (roots || stack.length) return fail('<!DOCTYPE must come before the root element', lt);
      let j = lt + 9;
      let quote = null;
      let depth = 0;
      for (; j < s.length; j++) {
        const c = s[j];
        if (quote) { if (c === quote) quote = null; } else if (c === '"' || c === "'") quote = c;
        else if (c === '[') depth++;
        else if (c === ']') depth--;
        else if (c === '>' && depth <= 0) break;
      }
      if (j >= s.length) return fail('unclosed <!DOCTYPE', lt);
      i = j + 1; // skipped: entity declarations are not read
      continue;
    }
    if (s.startsWith('<!', lt)) return fail('invalid markup "<!" (a comment starts with <!--, a CDATA section with <![CDATA[)', lt);

    if (s[lt + 1] === '/') {
      const name = nameAt(lt + 2);
      if (!QNAME_RE.test(name)) return fail(lt + 2 >= s.length ? 'unclosed tag' : 'invalid end tag name', lt);
      const close = skipWs(lt + 2 + name.length);
      if (close >= s.length) return fail('unclosed tag', lt);
      if (s[close] !== '>') return fail(`malformed end tag </${name}`, lt);
      const open = stack.pop();
      if (!open || open[0] !== name) return fail(open ? `</${name}> closes <${open[0]}>` : `</${name}> has no opening tag`, lt);
      i = close + 1;
      continue;
    }

    if (lt + 1 >= s.length) return fail('unclosed tag', lt);
    if (!NAME_START_RE.test(s.slice(lt + 1, lt + 3))) return fail('unescaped "<" in text (write &lt;, also inside expressions such as =a < b)', lt);
    const name = nameAt(lt + 1);
    if (!QNAME_RE.test(name)) return fail(`invalid tag name "${name}"`, lt);
    if (!stack.length && ++roots > 1) return fail('more than one root element', lt);
    const seen = new Set();
    let j = lt + 1 + name.length;
    let selfClosing = false;
    for (;;) {
      const afterWs = skipWs(j);
      const spaced = afterWs > j;
      j = afterWs;
      if (j >= s.length) return fail('unclosed tag', lt);
      const c = s[j];
      if (c === '>') break;
      if (c === '/') {
        if (s[j + 1] !== '>') return fail(`"/" in <${name}> must be followed by ">"`, j);
        selfClosing = true;
        j += 1;
        break;
      }
      if (c === '<') return fail('unexpected "<" inside a tag', j);
      const attr = nameAt(j);
      if (!attr) return fail(`unexpected ${c === '"' || c === "'" ? 'quote' : `"${c}"`} in <${name}>`, j);
      if (!QNAME_RE.test(attr)) return fail(`invalid attribute name "${attr}" in <${name}>`, j);
      if (!spaced) return fail(`attribute ${attr} needs whitespace before it`, j);
      if (seen.has(attr)) return fail(`attribute ${attr} appears twice in <${name}>`, j);
      seen.add(attr);
      j = skipWs(j + attr.length);
      if (s[j] !== '=') return fail(`attribute ${attr} has no value (write ${attr}="...")`, Math.min(j, s.length - 1));
      j = skipWs(j + 1);
      const q = s[j];
      if (q !== '"' && q !== "'") return fail(`attribute ${attr} has no quoted value`, Math.min(j, s.length - 1));
      const end = s.indexOf(q, j + 1);
      const value = end < 0 ? s.slice(j + 1) : s.slice(j + 1, end);
      const less = value.indexOf('<');
      // A closing quote missing where the tag ends: the value runs on through ">" into the next tag, or to the end.
      if (end < 0 || (less >= 0 && value.slice(0, less).includes('>'))) return fail(`attribute ${attr} has no closing ${q}`, j);
      if (less >= 0) return fail(`attribute ${attr} has "<" in its value (write &lt;)`, j + 1 + less);
      const ampInValue = badAmp(j + 1, end);
      if (ampInValue) return ampInValue;
      j = end + 1;
    }
    if (!selfClosing) stack.push([name, lt]);
    i = j + 1;
  }
  if (stack.length) {
    const [name, pos] = stack[stack.length - 1];
    return fail(`<${name}> is not closed`, pos);
  }
  return roots ? null : { message: 'no root element', line: 1 };
}

/** Outermost `<tag …>…</tag>` or `<tag … />` blocks of a well-formed text, nested ones included in their parent. */
function outerBlocks(s, tag) {
  const re = new RegExp(`<(/?)${tag}(?=[\\s/>])[^>]*?(/?)>`, 'g');
  const out = [];
  let depth = 0;
  let start = -1;
  for (const m of s.matchAll(re)) {
    if (m[1]) { if (--depth === 0) out.push(s.slice(start, m.index + m[0].length)); }
    else if (m[2]) { if (depth === 0) out.push(m[0]); }
    else { if (depth++ === 0) start = m.index; }
  }
  return out;
}
const innerOf = (block, tag) => block.replace(new RegExp(`^<${tag}[^>]*>|</${tag}>$`, 'g'), '');
const withoutNested = (block, tag) => {
  const inner = innerOf(block, tag);
  return outerBlocks(inner, tag).reduce((acc, nested) => acc.replace(nested, ''), inner);
};
function leafMembers(membersBlock) {
  let n = 0;
  for (const member of outerBlocks(innerOf(membersBlock, 'TablixMembers'), 'TablixMember')) {
    const nested = outerBlocks(innerOf(member, 'TablixMember'), 'TablixMembers')[0];
    n += nested ? leafMembers(nested) : 1;
  }
  return n;
}
const SIZE_IN = { in: 1, cm: 1 / 2.54, mm: 1 / 25.4, pt: 1 / 72, pc: 1 / 6 };
const toInches = (v) => { const m = /^\s*([\d.]+)\s*(in|cm|mm|pt|pc)\s*$/i.exec(v ?? ''); return m ? Number(m[1]) * SIZE_IN[m[2].toLowerCase()] : null; };
const RDL_NS_RE = /xmlns="http:\/\/schemas\.microsoft\.com\/sqlserver\/reporting\/(\d{4}\/\d{2})\/reportdefinition"/;
const PLACEHOLDER_RE = /0{8}-0{4}-0{4}-0{4}-0{12}|&lt;[^&]*&gt;|\b(?:TODO|CHANGEME|PLACEHOLDER|your[-_ ]?(?:workspace|model|server|tenant))\b|\b(?:WORKSPACE|MODEL|DATASET|SERVER|DATABASE|TENANT|DB)_(?:NAME|ID)\b/i;

/** Checks of an .rdl report (and .rds/.rsd shared items) that catch what breaks Report Builder or the service. */
export function checkRdl(rel, text) {
  const issues = [];
  const add = (level, message, line) => issues.push({ level, file: rel, ...(line ? { line } : {}), message });
  const xml = xmlProblem(text);
  if (xml) {
    add('error', `Malformed XML: ${xml.message}. Report Builder cannot open the file.`, xml.line);
    return issues;
  }
  const s = stripBom(text).replace(/<!--[\s\S]*?-->/g, '');
  for (const cs of s.matchAll(/<ConnectString>([\s\S]*?)<\/ConnectString>/g)) {
    if (/(?:^|;)\s*(?:password|pwd)\s*=/i.test(cs[1])) add('error', 'A password is written in a ConnectString. Credentials belong in Report Builder, the service or the gateway.');
    if (PLACEHOLDER_RE.test(cs[1])) add('error', 'The ConnectString holds a placeholder id or value; Report Builder fails (access error or crash). Use the real server, workspace and model the user gives you.');
  }
  if (!/<Report[\s>]/.test(s)) return issues; // shared data source or dataset: XML and connection checks only
  if (!RDL_NS_RE.test(s)) add('warn', 'The root element has no RDL report definition namespace (expected .../reporting/2016/01/reportdefinition).');

  const dupes = (names) => [...new Set(names.filter((n, i) => names.indexOf(n) !== i))];
  const named = (tags) => [...s.matchAll(new RegExp(`<(?:${tags}) Name="([^"]+)"`, 'g'))].map((m) => m[1].toLowerCase());
  const shared = dupes(named('DataSet|Tablix|Chart|Map|GaugePanel|CustomReportItem|Group'));
  if (shared.length) add('error', `Datasets, data regions and groups share one namespace; duplicated: ${shared.join(', ')}. Rename the data region or group, not the dataset fields.`);
  const items = dupes(named('Textbox|Rectangle|Image|Line|Subreport|Tablix|Chart|Map|GaugePanel|CustomReportItem'));
  if (items.length) add('error', `Report item names must be unique; duplicated: ${items.slice(0, 5).join(', ')}.`);
  for (const [tags, label] of [['ReportParameter', 'Parameter'], ['DataSource', 'Data source']]) {
    const d = dupes(named(tags));
    if (d.length) add('error', `${label} names must be unique; duplicated: ${d.join(', ')}.`);
  }

  const dataSets = new Set(named('DataSet'));
  const dataSources = new Set(named('DataSource'));
  const params = new Set(named('ReportParameter'));
  const fields = new Set(named('Field'));
  const missing = (re, known) => [...new Set([...s.matchAll(re)].map((m) => m[1]).filter((n) => !known.has(n.toLowerCase())))];
  const refs = [
    [missing(/<DataSetName>([^<]+)<\/DataSetName>/g, dataSets), 'DataSetName'],
    [missing(/<DataSourceName>([^<]+)<\/DataSourceName>/g, dataSources), 'DataSourceName'],
    [missing(/Parameters!([\p{L}\p{N}_]+)\.(?:Value|Label|Count|IsMultiValue)\b/gu, params), 'Parameters!'],
    [missing(/Fields!([\p{L}\p{N}_]+)\.(?:Value|IsMissing|UniqueName)\b/gu, fields), 'Fields!'],
  ];
  for (const [names, kind] of refs) if (names.length) add('error', `${kind} references that nothing defines: ${names.slice(0, 5).join(', ')}.`);

  const layout = /<ReportParametersLayout>([\s\S]*?)<\/ReportParametersLayout>/.exec(s)?.[1];
  if (layout != null) {
    const cells = [...layout.matchAll(/<ParameterName>([^<]+)<\/ParameterName>/g)].map((m) => m[1].toLowerCase());
    const absent = [...params].filter((p) => !cells.includes(p));
    if (absent.length || cells.length !== params.size) {
      add('error', `ReportParametersLayout needs one CellDefinition per parameter (${cells.length} cells, ${params.size} parameters${absent.length ? `; missing: ${absent.join(', ')}` : ''}); the report fails to load.`);
    }
  }

  for (const block of outerBlocks(s, 'Tablix').flatMap(function all(b) { return [b, ...outerBlocks(innerOf(b, 'Tablix'), 'Tablix').flatMap(all)]; })) {
    const name = /^<Tablix Name="([^"]+)"/.exec(block)?.[1] ?? '?';
    const own = withoutNested(block, 'Tablix');
    const columns = (own.match(/<TablixColumn>/g) ?? []).length;
    const hierarchy = outerBlocks(/<TablixColumnHierarchy>([\s\S]*?)<\/TablixColumnHierarchy>/.exec(own)?.[1] ?? '', 'TablixMembers')[0];
    const leaves = hierarchy ? leafMembers(hierarchy) : columns;
    const rows = outerBlocks(own, 'TablixRow').map((r) => (r.match(/<TablixCell(?:\s*\/)?>/g) ?? []).length);
    const badRows = rows.filter((n) => n !== columns).length;
    if (columns !== leaves || badRows) {
      add('error', `Tablix ${name}: ${columns} TablixColumn, ${leaves} leaf column members${badRows ? `, ${badRows} row(s) with another number of cells` : ''}; they must be equal or the report fails to load.`);
    }
  }

  // Every report section has its own body and page.
  const sections = [...s.matchAll(/<ReportSection>([\s\S]*?)<\/ReportSection>/g)].map((m) => m[1]);
  const cm = (v) => `${(v * 2.54).toFixed(1)} cm`;
  const mm = (v) => `${(v * 25.4).toFixed(1)} mm`;
  (sections.length ? sections : [s]).forEach((section, n) => {
    const where = sections.length > 1 ? `Report section ${n + 1}: body` : 'Body';
    const body = toInches(/<\/Body>\s*<Width>([^<]+)<\/Width>/.exec(section)?.[1]);
    const page = /<Page>([\s\S]*?)<\/Page>/.exec(section)?.[1] ?? '';
    const statedWidth = toInches(/<PageWidth>([^<]+)</.exec(page)?.[1]);
    const pageWidth = statedWidth ?? 8.5; // RDL default: Letter portrait
    const margins = ['LeftMargin', 'RightMargin'].map((m) => toInches(new RegExp(`<${m}>([^<]+)<`).exec(page)?.[1]) ?? 0);
    if (!body) return;
    const spare = Math.round((pageWidth - (body + margins[0] + margins[1])) * 10000) / 10000; // no float noise at an exact fit
    const size = statedWidth ? `the page (${cm(pageWidth)})` : `the default page (no PageWidth: Letter portrait, ${cm(pageWidth)})`;
    if (spare < -0.01) {
      add('warn', `${where} ${cm(body)} + margins ${cm(margins[0] + margins[1])} is wider than ${size}: PDF and print add pages for the overflow. Fine only for a screen and Excel report; say so.`);
    } else if (spare < 0.04) {
      // An exact fit rounds over in print layout: Report Builder rendered a blank page after every page (2026-10-06).
      const fit = spare < 0 ? `is ${mm(-spare)} wider than ${size}` : `leaves only ${mm(spare)} spare on ${size}`;
      add('warn', `${where} ${cm(body)} + margins ${cm(margins[0] + margins[1])} ${fit}: print layout and PDF can add a blank page after each page. Leave at least 1 mm.`);
    }
  });
  if (/<DataSourceReference>|<SharedDataSet>/.test(s)) add('warn', 'Shared data source or shared dataset reference: SSRS only, not supported in the Power BI service. Embed it before publishing to Power BI.');
  if (/<CodeModules>/.test(s)) add('warn', 'Custom assemblies (CodeModules) are not supported in the Power BI service; move the logic to embedded code or upstream.');
  return issues;
}

// Elements that only ever say where data comes from; counted wherever they stand.
const RDL_CONNECTION_TAGS = ['ConnectString', 'DataSourceReference', 'SharedDataSetReference'];
// What a dataset reads: an embedded data source (DataSourceName in its Query), a shared data source (.rsd) or a shared
// dataset (.rdl). Exported so the guard can say which source a dataset reads now and read before.
export const RDL_DATASET_ROUTES = ['DataSourceName', 'DataSourceReference', 'SharedDataSetReference'];
// The report parameters an RDL expression reads. Expressions are Visual Basic, so `Parameters` and the parameter name are
// case-insensitive, and Microsoft documents three spellings: Parameters!X, Parameters("X") and Parameters.Item("X")
// (embedded code writes Report.Parameters!X). The quotes can be XML entities in the file. Names come back lower-cased.
const RDL_PARAMETER_READ_RE = /\bparameters\s*(?:!\s*\[?([\p{L}\p{N}_]+)|(?:\.\s*item\s*)?\(\s*(["'])([^"']+)\2\s*\))/giu;
const rdlParameterReads = (expression) =>
  [...expression.replace(/&(?:quot|apos|#0*(?:34|39)|#x0*(?:22|27));/gi, '"').matchAll(RDL_PARAMETER_READ_RE)].map((m) => (m[1] ?? m[3]).trim().toLowerCase());
// A call into the report's embedded code (`=Code.Conn()`), not a field or parameter named Code (`Fields!Code.Value`).
const RDL_CODE_CALL_RE = /(?<![\w!.])code\s*\./i;
// A ConnectString can read a parameter whose default reads another one: follow the chain this many levels.
const RDL_PARAMETER_DEPTH = 5;

/**
 * Where a paginated report (.rdl), shared data source (.rds) or shared dataset (.rsd) reads data, as a Map from label
 * to facts, for "did this edit change it" (Tier 2 in .claude/rules/bi/rdl.md). Equal maps mean nothing changed.
 * - `data source "<Name>"`: a DataSource's or RptDataSource's ConnectionProperties (DataProvider or Extension,
 *   ConnectString, IntegratedSecurity, Prompt) and DataSourceReference, plus the default and available values of each
 *   report parameter its ConnectString expression reads (Parameters!X, Parameters("X") or Parameters.Item("X"), in any
 *   letter case; then the parameters those values read, RDL_PARAMETER_DEPTH levels in all) and, when the expression
 *   calls embedded code (Code.F()), the report's <Code> block; a new, removed or renamed data source counts. A
 *   DataSourceDefinition (a shared data source as the report server stores it) counts as a whole.
 * - `dataset "<Name>"`: the data source a dataset reads, `DataSourceName: <source>` (its Query in an .rdl),
 *   DataSourceReference (.rsd) or SharedDataSetReference (.rdl); a new, removed or renamed dataset counts.
 * - `connection`: a ConnectString, DataSourceReference or SharedDataSetReference outside those elements.
 * Comments are left out; the query (CommandText), fields, parameters and layout are not facts.
 */
export function rdlSourceFacts(text) {
  let s = stripBom(String(text ?? '')).replace(/<!--[\s\S]*?-->/g, '');
  const facts = new Map();
  const add = (label, value) => facts.set(label, facts.has(label) ? `${facts.get(label)}\n${value}` : value);
  const norm = (t) => t.replace(/\s+/g, ' ').trim();
  const values = (block, tag) =>
    [...block.matchAll(new RegExp(`<(?:[\\w.-]+:)?${tag}(?=[\\s/>])[^>]*?(?:/>|>([\\s\\S]*?)</(?:[\\w.-]+:)?${tag}\\s*>)`, 'g'))].map((m) => norm(m[1] ?? ''));
  const nameOf = (block) => /^<[^>]*?\sName\s*=\s*(["'])([\s\S]*?)\1/.exec(block)?.[2] ?? '';
  const parameters = new Map(outerBlocks(s, 'ReportParameter').map((b) => [nameOf(b).toLowerCase(), b]));
  const code = values(s, 'Code').join(' ');
  for (const [tag, kind] of [['DataSource', 'data source'], ['RptDataSource', 'data source'], ['DataSourceDefinition', 'shared data source'], ['DataSet', 'dataset']]) {
    for (const block of outerBlocks(s, tag)) {
      const name = nameOf(block);
      const label = name ? `${kind} "${name}"` : kind;
      if (tag === 'DataSourceDefinition') add(label, norm(innerOf(block, tag)));
      else if (tag === 'DataSet') {
        for (const ref of RDL_DATASET_ROUTES) for (const v of values(block, ref)) add(label, `${ref}: ${v}`);
      } else {
        add(label, '');
        for (const v of values(block, 'ConnectionProperties')) add(label, `connection: ${v}`);
        for (const v of values(block, 'DataSourceReference')) add(label, `DataSourceReference: ${v}`);
        // The server can come from a parameter's default or available values: follow the parameters the ConnectString
        // reads, those their values read in turn, and the embedded code it calls (which can read parameters itself).
        const queue = [];
        let usesCode = false;
        const scan = (expression, depth) => {
          for (const p of rdlParameterReads(expression)) queue.push([p, depth]);
          if (!usesCode && RDL_CODE_CALL_RE.test(expression)) {
            usesCode = true;
            add(label, `code: ${code}`);
            scan(code, depth);
          }
        };
        for (const c of values(block, 'ConnectString')) scan(c, 1);
        const seen = new Set();
        for (const [p, depth] of queue) {
          if (seen.has(p)) continue;
          seen.add(p);
          const param = parameters.get(p) ?? '';
          const [dflt, valid] = [values(param, 'DefaultValue').join(' '), values(param, 'ValidValues').join(' ')];
          add(label, `parameter ${p}: ${dflt} | ${valid}`);
          if (depth < RDL_PARAMETER_DEPTH) scan(`${dflt} ${valid}`, depth + 1);
        }
      }
      s = s.split(block).join('');
    }
  }
  for (const tag of RDL_CONNECTION_TAGS) for (const v of values(s, tag)) add('connection', `${tag}: ${v}`);
  return facts;
}

// ---------------------------------------------------------------- PBIR / PBIP JSON

const PBIR_NAME_RE = /^[\p{L}\p{N}_-]+$/u;
export const isValidPbirName = (name) => PBIR_NAME_RE.test(name);

/** Page/visual/bookmark names encoded in a PBIR path (they must be word chars or hyphens). */
export function pbirNameSegments(rel) {
  const m = /(?:^|\/)[^/]+\.report\/definition\/(.*)$/i.exec(toPosix(rel));
  if (!m) return [];
  const parts = m[1].split('/');
  const names = [];
  if (parts[0] === 'pages' && parts.length > 2) {
    names.push(parts[1]);
    if (parts[2] === 'visuals' && parts.length > 4) names.push(parts[3]);
  }
  if (parts[0] === 'bookmarks' && parts.length === 2 && /\.bookmark\.json$/i.test(parts[1])) {
    names.push(parts[1].replace(/\.bookmark\.json$/i, ''));
  }
  return names;
}

function checkPbipJson(rel, data, root, io) {
  const issues = [];
  const add = (level, message) => issues.push({ level, file: rel, message });
  const lower = rel.toLowerCase();
  const inDefinition = /(?:^|\/)[^/]+\.report\/definition\//i.test(rel);

  if (inDefinition && data && typeof data === 'object' && !Array.isArray(data) && !data.$schema) {
    add('warn', 'Missing "$schema". Keep the schema URL Power BI Desktop wrote; editors validate against it.');
  }
  for (const [kind, re] of [['page', /\/pages\/([^/]+)\/page\.json$/i], ['visual', /\/visuals\/([^/]+)\/visual\.json$/i]]) {
    const m = re.exec(rel);
    if (inDefinition && m && data?.name && data.name !== m[1]) {
      add('warn', `${kind}.json "name" (${data.name}) differs from its folder (${m[1]}). Renames break references; restart Desktop after renaming.`);
    }
  }
  if (lower === 'definition.pbir' || lower.endsWith('/definition.pbir')) {
    const ref = data?.datasetReference;
    if (!ref) add('error', 'definition.pbir has no datasetReference.');
    else if (Boolean(ref.byPath) === Boolean(ref.byConnection)) add('error', 'datasetReference must contain exactly one of byPath or byConnection.');
    else if (ref.byPath) {
      const p = String(ref.byPath.path ?? '');
      if (!p || path.isAbsolute(p) || /^[A-Za-z]:|^\\/.test(p)) add('error', 'datasetReference.byPath.path must be relative (absolute paths are not supported).');
      else if (root && !io.existsSync(path.join(path.resolve(root, path.dirname(rel), toPosix(p)), 'definition.pbism'))) {
        add('error', `datasetReference.byPath points to "${p}", which has no definition.pbism.`);
      }
    }
  }
  if (lower.endsWith('.pbip') && Array.isArray(data?.artifacts) && root) {
    for (const artifact of data.artifacts) {
      const p = artifact?.report?.path;
      if (!p || !io.existsSync(path.resolve(root, path.dirname(rel), toPosix(p), 'definition.pbir'))) add('error', `.pbip points to a missing report definition "${p ?? ''}".`);
    }
  }
  return issues;
}

// ---------------------------------------------------------------- SSIS packages and projects

// Protection levels as a package stores them (MS-DTSX2, ProtectionLevelEnum); a missing attribute is the default 1.
const SSIS_LEVELS = ['DontSaveSensitive', 'EncryptSensitiveWithUserKey', 'EncryptSensitiveWithPassword', 'EncryptAllWithPassword', 'EncryptAllWithUserKey', 'ServerStorage'];
const SSIS_NS = 'www.microsoft.com/SqlServer/Dts';

/** The package's protection level name (`.dtsx` root attribute) or the project's (`.dtproj`), or null. */
export function ssisProtectionLevel(text, ext) {
  const s = stripBom(String(text ?? ''));
  if (ext === '.dtproj') return /\bSSIS:ProtectionLevel="(\w+)"/.exec(s)?.[1] ?? null;
  const root = /<DTS:Executable\b[^>]*>/.exec(s)?.[0];
  if (!root) return null;
  const n = /\bDTS:ProtectionLevel="(\d)"/.exec(root)?.[1];
  return SSIS_LEVELS[n === undefined ? 1 : Number(n)] ?? null;
}

// SSIS expressions name a package parameter, a project parameter or a variable as @[$Package::X], @[$Project::X] and
// @[Namespace::X] (@[X] or @X when the namespace is left out). Names come back lower-cased, with the namespace when written.
const SSIS_REFERENCE_RE = /@(?:\[([^\]]+)\]|([\p{L}_][\p{L}\p{N}_]*))/gu;
const ssisReferences = (expression) => [...expression.matchAll(SSIS_REFERENCE_RE)].map((m) => (m[1] ?? m[2]).trim().toLowerCase());
// A connection's property expression can read a variable whose own expression reads a parameter: follow the chain this far.
const SSIS_REFERENCE_DEPTH = 5;

/** The package parameters (`$package::name`) and variables (`namespace::name`) of a package, lower-cased, with their values and expressions. */
function ssisNamedValues(s) {
  const named = new Map();
  const head = (block) => /^<(?:[^>"']|"[^"]*"|'[^']*')*>/.exec(block)?.[0] ?? '';
  const attr = (tag, name) => new RegExp(`\\bDTS:${name}\\s*=\\s*(["'])([\\s\\S]*?)\\1`).exec(tag)?.[2];
  const put = (key, value, expression) => named.set(key, [...(named.get(key) ?? []), { value, expression }]);
  for (const block of outerBlocks(s, 'DTS:PackageParameter')) {
    const name = attr(head(block), 'ObjectName');
    if (name !== undefined) put(`$package::${name.toLowerCase()}`, /<DTS:Property\b[^>]*\bDTS:Name="ParameterValue"[^>]*>([^<]*)</.exec(block)?.[1] ?? '', '');
  }
  for (const block of outerBlocks(s, 'DTS:Variable')) {
    const tag = head(block);
    const name = attr(tag, 'ObjectName');
    if (name !== undefined) put(`${(attr(tag, 'Namespace') ?? 'User').toLowerCase()}::${name.toLowerCase()}`, /<DTS:VariableValue\b[^>]*>([^<]*)</.exec(block)?.[1] ?? '', attr(tag, 'Expression') ?? '');
  }
  return named;
}

/**
 * Connection targets and secrets of a package or project file, for "did this edit change where data comes from": connection
 * strings, protection levels, the connection a component or a task uses (`connectionManagerRefId`, `SQLTask:Connection`),
 * connection property expressions and the values of the package parameters and variables those expressions read.
 */
export function ssisConnectionFacts(text) {
  const s = stripBom(String(text ?? ''));
  const facts = [];
  for (const m of s.matchAll(/\bDTS:ConnectionString="([^"]*)"/g)) facts.push(`cs:${m[1]}`);
  for (const m of s.matchAll(/<DTS:Property\s+DTS:Name="(?:ServerName|ConnectionString|InitialCatalog)"[^>]*>([^<]*)</g)) facts.push(`prop:${m[1]}`);
  for (const m of s.matchAll(/\b(?:DTS|SSIS):ProtectionLevel="(\w+)"/g)) facts.push(`pl:${m[1]}`);
  // Which connection a component uses, and connection properties set by expressions.
  for (const m of s.matchAll(/\bconnectionManager(?:RefId|ID)="([^"]*)"/g)) facts.push(`ref:${m[1]}`);
  for (const m of s.matchAll(/<DTS:PropertyExpression\s+DTS:Name="(ConnectionString|ServerName|InitialCatalog)"[^>]*>([^<]*)</gi)) facts.push(`expr:${m[1]}=${m[2]}`);
  // Package configurations (.dtsConfig) set connection properties at run time.
  for (const m of s.matchAll(/<Configuration\b[^>]*Path="([^"]*)"[^>]*>[\s\S]*?<ConfiguredValue>([^<]*)<\/ConfiguredValue>/g)) facts.push(`cfg:${m[1]}=${m[2]}`);
  for (const m of s.matchAll(/<DTS:Password\b[\s\S]*?<\/DTS:Password>/g)) facts.push(`pw:${m[0].length}:${m[0].slice(-40)}`);
  const live = s.replace(/<!--[\s\S]*?-->/g, '');
  // Which connection a task uses: the Connection attribute of its task data, SQLTask:Connection="{DTSID of the manager}".
  for (const m of live.matchAll(/\b\w+:\w*Connection="[^"]*"/g)) facts.push(`task:${m[0]}`);
  // What the property expressions of a connection manager read: the value of each package parameter and variable they
  // name, and of those a variable's own expression names in turn.
  const named = ssisNamedValues(live);
  const queue = outerBlocks(live, 'DTS:ConnectionManager').flatMap((block) =>
    [...block.matchAll(/<DTS:PropertyExpression\b[^>]*>([^<]*)</g)].flatMap((m) => ssisReferences(m[1]).map((ref) => [ref, 1])));
  const seen = new Set();
  for (const [ref, depth] of queue) {
    if (seen.has(ref)) continue;
    seen.add(ref);
    for (const key of ref.includes('::') ? [ref] : [...named.keys()].filter((k) => k.endsWith(`::${ref}`))) {
      for (const { value, expression } of named.get(key) ?? []) {
        facts.push(`value:${key}=${value}${expression ? ` <= ${expression}` : ''}`);
        if (expression && depth < SSIS_REFERENCE_DEPTH) for (const r of ssisReferences(expression)) queue.push([r, depth + 1]);
      }
    }
  }
  return facts.sort().join('\n');
}

/**
 * Object identities of a package: every `DTS:DTSID` GUID (upper-cased) and every `refId` path (executables,
 * connection managers, data flow components and their columns). `.claude/rules/bi/ssis.md`: keep them all.
 */
export function ssisIds(text) {
  const s = stripBom(String(text ?? ''));
  const ids = new Set();
  for (const m of s.matchAll(/\bDTS:DTSID="([^"]*)"/g)) ids.add(`DTSID ${m[1].toUpperCase()}`);
  for (const m of s.matchAll(/\brefId="([^"]*)"/g)) ids.add(`refId ${m[1]}`);
  return ids;
}

/** Script Task and Script Component binaries (`<BinaryItem>`): rebuilt by Visual Studio, never edited as text. */
export const ssisBinaryItems = (text) => [...stripBom(String(text ?? '')).matchAll(/<BinaryItem\b[\s\S]*?<\/BinaryItem>/g)].map((m) => m[0]).join('\n');

export function checkSsis(rel, text, { root, io = fs } = {}) {
  const issues = [];
  const add = (level, message, line) => issues.push({ level, file: rel, ...(line ? { line } : {}), message });
  const xml = xmlProblem(text);
  if (xml) {
    add('error', `Malformed XML: ${xml.message}. Visual Studio (SSIS) and dtexec cannot load the file.`, xml.line);
    return issues;
  }
  const ext = path.posix.extname(rel).toLowerCase();
  const s = stripBom(text);
  const level = ssisProtectionLevel(s, ext);
  if (level === 'EncryptSensitiveWithUserKey' || level === 'EncryptAllWithUserKey') {
    add('warn', `ProtectionLevel ${level}: only the account that saved it can decrypt, so other developers, the build and SQL Server Agent fail to connect. Use DontSaveSensitive with parameters for secrets (or a password level whose password stays out of the repository).`);
  }
  if (ext !== '.dtsx') return issues;
  if (!s.includes(SSIS_NS)) add('error', `No DTS namespace (${SSIS_NS}): not an SSIS package, or the root element was damaged.`);
  const seen = new Map();
  for (const m of s.matchAll(/\bDTS:DTSID="(\{[^"]+\})"/g)) {
    const line = s.slice(0, m.index).split('\n').length;
    const id = m[1].toUpperCase();
    if (seen.has(id)) add('error', `DTSID ${m[1]} is used twice (also line ${seen.get(id)}). Every object needs its own GUID; a copied object must get a new one.`, line);
    else seen.set(id, line);
  }
  // Every package in a project uses the project's protection level (MS-ISPAC, Project element).
  if (root && level) {
    const dir = path.posix.dirname(toPosix(rel));
    try {
      const project = io.readdirSync(path.join(root, dir)).find((n) => n.toLowerCase().endsWith('.dtproj'));
      const projectLevel = project ? ssisProtectionLevel(io.readFileSync(path.join(root, dir, project), 'utf8'), '.dtproj') : null;
      if (projectLevel && projectLevel !== level) {
        add('error', `ProtectionLevel ${level} differs from the project's ${projectLevel} (${project}); every package in a project must use the project's level.`);
      }
    } catch {
      // no project folder to compare with
    }
  }
  return issues;
}

// ---------------------------------------------------------------- per-file validation

/** The error text for a credential findSecrets reported (masked preview, never the value). */
const credentialMessage = (s) => `Possible credential (${s.id}: ${s.preview}). Remove it; use parameters/env vars and set credentials in Desktop/Service.`;

export function validateFileText(rel, text, { cfg, root, io = fs, mode } = {}) {
  const issues = [];
  const add = (level, message, line) => issues.push({ level, file: rel, ...(line ? { line } : {}), message });
  const cls = classifyPath(rel);
  const maxLines = cfg?.markdown?.maxLines ?? 500;

  // The lab switch is personal: staged (the pre-commit hook) or in a full scan (CI, a release) it is an error. Not in
  // `changed` mode: the Stop gate must not block a test session for the user's own switch in the working tree.
  if ((mode === 'staged' || mode === 'full') && /^hardening[\\/]harness\.config\.json$/i.test(rel)) {
    try {
      const approvals = JSON.parse(stripBom(text))?.approvals?.mode;
      if (typeof approvals === 'string' && approvals.trim().toLowerCase() === 'lab') {
        add('error', 'approvals.mode is "lab": the lab switch is personal and for a test session; committed or shipped, every clone runs in lab mode (no prompt but the floor). Set it back to "auto" or "ask" before committing (hardening/README.md, Approvals).');
      }
    } catch {
      // not JSON: the JSON check below reports it
    }
  }

  if (cls.pbipText && text.charCodeAt(0) === 0xfeff) add('error', 'UTF-8 BOM found. PBIP files must be UTF-8 without BOM.', 1);
  for (const s of findSecrets(text)) add('error', credentialMessage(s), s.line);
  if (cls.kind === 'markdown') {
    const n = countLines(text);
    if (n > maxLines) add('error', `Markdown has ${n} lines (limit ${maxLines}). Split it into linked sub-files.`);
  }
  if (cls.kind === 'json' && !cls.jsonc) {
    let data;
    try {
      data = JSON.parse(stripBom(text));
    } catch (err) {
      add('error', `Invalid JSON: ${err.message}`);
    }
    if (data !== undefined) issues.push(...checkPbipJson(rel, data, root, io));
  }
  if (cls.kind === 'bim') add('warn', TMDL_ONLY_REASON);
  if (cls.kind === 'tmdl') issues.push(...checkTmdl(rel, text));
  if (cls.kind === 'rdl') issues.push(...checkRdl(rel, text));
  if (cls.kind === 'ssis') issues.push(...checkSsis(rel, text, { root, io }));
  for (const name of pbirNameSegments(rel)) {
    if (!isValidPbirName(name)) add('error', `PBIR object name "${name}" is invalid (letters, digits, "_" or "-" only); Power BI Desktop ignores it.`);
  }
  return issues;
}

// ---------------------------------------------------------------- Fabric item folders

// A Fabric Git commit from the service "deletes files inside the item folder that aren't part of the item definition"
// (docs/harness/fabric-git.md). What an item folder may hold, from Microsoft Learn (checked 2026-10-15):
//   report folder          https://learn.microsoft.com/en-us/power-bi/developer/projects/projects-report
//   semantic model folder  https://learn.microsoft.com/en-us/power-bi/developer/projects/projects-dataset
//   paginated report       https://learn.microsoft.com/en-us/power-bi/paginated-reports/paginated-github-integration
// item.metadata.json and item.config.json are the version-1 system files that .platform replaces in every item type
// (https://learn.microsoft.com/en-us/fabric/cicd/git-integration/source-code-format). modelReference.json is the
// live-connection definition that checkModelFolder accepts in place of definition/, so it is allowed too.
const ITEM_FOLDER_RE = /^((?:[^/]+\/)*?)([^/]+\.(semanticmodel|report|paginatedreport))\/(.+)$/i;
const ITEM_FILES = {
  report: /^(?:[^/]+\.pbir|report\.json|\.platform|mobilestate\.json|semanticmodeldiagramlayout\.json|item\.(?:metadata|config)\.json|(?:definition|staticresources|customvisuals|\.pbi)\/.+)$/,
  semanticmodel: /^(?:definition\.pbism|model\.bim|modelreference\.json|\.platform|diagramlayout\.json|item\.(?:metadata|config)\.json|(?:definition|daxqueries|tmdlscripts|\.pbi)\/.+)$/,
  paginatedreport: /^(?:[^/]+\.rdl|\.platform|item\.(?:metadata|config)\.json)$/,
};
const ITEM_LABEL = { report: 'report', semanticmodel: 'semantic model', paginatedreport: 'paginated report' };

/**
 * The item folder a project-relative path lies inside (the outermost `*.SemanticModel/`, `*.Report/` or
 * `*.PaginatedReport/` segment): { folder, kind, inner } with kind in lower case, or null outside item folders.
 */
export function fabricItemOf(rel) {
  const m = ITEM_FOLDER_RE.exec(toPosix(rel));
  return m ? { folder: `${m[1]}${m[2]}`, kind: m[3].toLowerCase(), inner: m[4] } : null;
}

/** True when a file inside an item folder belongs to the item definition or its system files (a service commit keeps it). */
export const isItemDefinitionFile = (item) => ITEM_FILES[item.kind].test(item.inner.toLowerCase());

/** The .rdl files directly inside a paginated report item folder (project-relative). */
export function paginatedRdls(root, folder, io = fs) {
  try {
    return io.readdirSync(path.join(root, folder)).filter((n) => /\.rdl$/i.test(n)).map((n) => `${folder}/${n}`);
  } catch {
    return [];
  }
}

/** Why a file does not belong in its item folder, or null. Shared by the validator and the write guard. */
export function itemFolderProblem(item) {
  if (!item || isItemDefinitionFile(item)) return null;
  return `Not part of the ${ITEM_LABEL[item.kind]} item definition: a Fabric Git commit from the service deletes every other file inside ${item.folder}/. Notes, test packs, screenshots and SQL belong under docs/, tests/ or templates/ (docs/harness/fabric-git.md).`;
}

/**
 * Warnings for files inside item folders that are not part of the item definition, and for a paginated report folder
 * with more than one .rdl. Any file type counts (a screenshot is the usual stray file), so callers pass the paths
 * before the text filter; a listed path that no longer exists (a deletion in --changed or --staged) is skipped, and so
 * is a path in a reference folder (`isReferenceRel`, with the config's `references` when `cfg` is given): no workspace
 * syncs a reference.
 */
export function checkItemFolderFiles(root, relFiles, io = fs, cfg = null) {
  const issues = [];
  const paginated = new Set();
  for (const rel of relFiles) {
    if (isReferenceRel(toPosix(rel), cfg)) continue;
    const item = fabricItemOf(rel);
    if (!item || !io.existsSync(path.join(root, rel))) continue;
    const problem = itemFolderProblem(item);
    if (problem) issues.push({ level: 'warn', file: rel, message: problem });
    else if (item.kind === 'paginatedreport' && /\.rdl$/i.test(item.inner)) paginated.add(item.folder);
  }
  for (const folder of paginated) {
    const rdls = paginatedRdls(root, folder, io);
    if (rdls.length > 1) {
      issues.push({ level: 'warn', file: folder, message: `${rdls.length} .rdl files in one paginated report item folder; the item definition is one .rdl, and a Fabric Git commit from the service keeps only that one. Give each report its own <Name>.PaginatedReport/ folder (docs/harness/fabric-git.md).` });
    }
  }
  return issues;
}

// ---------------------------------------------------------------- project discovery and artifact checks

/**
 * The BI artifacts of a repository, as project-relative POSIX paths: *.SemanticModel and *.Report folders, *.pbip
 * files, TMDL folders of Analysis Services models (`tabular`; "." when the repository root is the model), *.rdl files
 * and the folders that hold SSIS projects or packages (`ssis`). Any subset can be present: a repository with only an
 * RDL or an SSIS project is complete. `fabric` lists the *.SemanticModel, *.Report and *.PaginatedReport folders a
 * Fabric workspace syncs, per `fabricSync` (`fabricSyncOf(cfg)`): those under a directory of fabric.directories, or,
 * when none is recorded, those that hold a .platform file (only found, never read). Reference folders (`isReferenceRel`:
 * templates/, reports/<report>/source/, the config's `references`) are not the repository's projects and are skipped;
 * their files still get the per-file checks (walkFiles, validateFileText).
 */
export function findPbipItems(root, cfg, maxDepth = 4) {
  const sync = fabricSyncOf(cfg);
  const items = { models: [], reports: [], pbip: [], tabular: [], rdl: [], ssis: [], fabric: [], fabricSync: sync };
  const synced = (rel) => (sync.source === 'config' ? syncedDirOf(rel, sync.dirs) !== null : fs.existsSync(path.join(root, rel, '.platform')));
  const exclude = cfg?.scan?.exclude ?? [];
  // The repository root itself can be the TMDL folder of an Analysis Services model (database.tmdl beside model.tmdl).
  if (isTabularFolder(root, '')) items.tabular.push('.');
  const visit = (relDir, depth) => {
    let entries = [];
    try {
      entries = fs.readdirSync(path.join(root, relDir), { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      const rel = relDir ? `${relDir}/${e.name}` : e.name;
      if (e.isDirectory()) {
        if (e.name === '.git' || e.name === 'node_modules' || matchesAny(`${rel}/`, exclude) || isReferenceRel(`${rel}/`, cfg)) continue;
        if (/\.(?:semanticmodel|report|paginatedreport)$/i.test(e.name) && synced(rel)) items.fabric.push(rel);
        if (/\.semanticmodel$/i.test(e.name)) items.models.push(rel);
        else if (/\.report$/i.test(e.name)) items.reports.push(rel);
        else if (isTabularFolder(root, rel)) items.tabular.push(rel);
        else if (depth < maxDepth) visit(rel, depth + 1);
      } else if (e.isFile() && !matchesAny(rel, exclude)) {
        if (/\.pbip$/i.test(e.name)) items.pbip.push(rel);
        else if (/\.rdl$/i.test(e.name)) items.rdl.push(rel);
        else if (/\.(?:dtproj|dtsx)$/i.test(e.name) && !items.ssis.includes(relDir || '.')) items.ssis.push(relDir || '.');
      }
    }
  };
  visit('', 0);
  return items;
}

const exists = (...p) => fs.existsSync(path.join(...p));
const listDirs = (dir, io = fs) => {
  try {
    return io.readdirSync(dir, { withFileTypes: true }).filter((e) => e.isDirectory()).map((e) => e.name);
  } catch {
    return [];
  }
};
const readJson = (file, io = fs) => {
  try {
    return JSON.parse(stripBom(io.readFileSync(file, 'utf8')));
  } catch {
    return null;
  }
};

export function describeReport(root, rel) {
  const dir = path.join(root, rel);
  const pbir = readJson(path.join(dir, 'definition.pbir'));
  const ref = pbir?.datasetReference;
  return {
    path: rel,
    format: exists(dir, 'definition') ? 'PBIR' : exists(dir, 'report.json') ? 'PBIR-Legacy' : 'unknown',
    pages: listDirs(path.join(dir, 'definition', 'pages')).length,
    binding: ref?.byPath ? `byPath → ${ref.byPath.path}` : ref?.byConnection ? 'byConnection (live connection to a Service model)' : 'none',
  };
}

/** A TMDL folder of an Analysis Services model (`findPbipItems().tabular`): its compatibility level and table files. */
export function describeTabular(root, rel) {
  const dir = path.join(root, rel);
  let level = null;
  try {
    level = /^\s*compatibilityLevel:\s*(\d+)/m.exec(stripBom(fs.readFileSync(path.join(dir, 'database.tmdl'), 'utf8')))?.[1] ?? null;
  } catch {
    // unreadable: the validator reports it
  }
  let tables = 0;
  try {
    tables = fs.readdirSync(path.join(dir, 'tables')).filter((f) => f.endsWith('.tmdl')).length;
  } catch {
    // no tables folder yet
  }
  return { path: rel, level, tables };
}

export function describeModel(root, rel) {
  const dir = path.join(root, rel);
  let tables = 0;
  try {
    tables = fs.readdirSync(path.join(dir, 'definition', 'tables')).filter((f) => f.endsWith('.tmdl')).length;
  } catch {
    // TMSL or empty
  }
  return {
    path: rel,
    format: exists(dir, 'definition') ? 'TMDL'
      : exists(dir, 'model.bim') ? 'TMSL (model.bim)'
      : exists(dir, 'modelReference.json') ? 'live connection (modelReference.json)' : 'unknown',
    tables,
    hasDataCache: exists(dir, '.pbi', 'cache.abf'),
    hasUnappliedChanges: exists(dir, '.pbi', 'unappliedChanges.json'),
  };
}

// ---------------------------------------------------------------- Fabric Git: items the service ignores, resources, copies

// Learn, "Overview of Fabric Git integration" (checked 2026-10-17): Git integration supports a report except one connected
// to a model hosted in Azure Analysis Services or SQL Server Analysis Services, and a semantic model except a live
// connection to Analysis Services; an unsupported item shows in the Source control pane and is never committed, updated
// or deleted. The list is Microsoft's and changes, so every check that rests on it is a warning (docs/harness/fabric-git.md).
// .platform marks an item folder as Fabric-shaped, not as synced: Desktop writes it on a project save too (Learn, report
// folder page), so the files cannot show which directory a workspace syncs. The user records that in fabric.directories
// (`fabricSyncOf`); without it .platform is the signal, and every warning says which source it used.

/** A project-relative directory of `fabric.directories` in POSIX form ("." for the repository root), or null when it is none. */
function syncedDirEntry(value) {
  if (typeof value !== 'string') return null;
  let d = value.trim().replace(/\\/g, '/');
  while (d.startsWith('./')) d = d.slice(2);
  d = d.replace(/\/+$/, '');
  if (d === '' || d === '.') return '.';
  if (d.startsWith('/') || /^[A-Za-z]:/.test(d) || d.split('/').some((s) => s === '..' || s === '.' || s === '')) return null;
  return d;
}

/**
 * Which directories a Fabric workspace syncs, and where the harness learned it (docs/harness/fabric-git.md):
 *   - `fabric.directories` in hardening/harness.config.json, a list the user records (`source: 'config'`): only item
 *     folders under a listed directory count as synced and .platform no longer matters; [] records that none is synced;
 *   - nothing recorded (absent or null, the default): every item folder that holds .platform counts (`source:
 *     'platform'`), a reminder only, because Desktop writes .platform on a project save too;
 *   - a value that is no list of project-relative directories: .platform as well, with `invalid` set for the message.
 */
export function fabricSyncOf(cfg) {
  const raw = cfg?.fabric?.directories;
  if (raw === undefined || raw === null) return { source: 'platform', dirs: null, invalid: false };
  const dirs = Array.isArray(raw) ? raw.map(syncedDirEntry) : [null];
  if (dirs.some((d) => d === null)) return { source: 'platform', dirs: null, invalid: true };
  // Longest first, so a path inside two listed directories is reported under the nearer one.
  return { source: 'config', dirs: [...new Set(dirs)].sort((a, b) => b.length - a.length), invalid: false };
}

/** The listed directory (`fabricSyncOf().dirs`) a project-relative path lies in, or null; case-insensitive (Windows, Desktop). */
export function syncedDirOf(rel, dirs) {
  const p = toPosix(rel).toLowerCase();
  return (dirs ?? []).find((d) => d === '.' || p === d.toLowerCase() || p.startsWith(`${d.toLowerCase()}/`)) ?? null;
}

/** "the repository root" for ".", else the directory itself. */
export const syncedDirLabel = (dir) => (dir === '.' ? 'the repository root' : dir);

/** The sentence every Fabric Git warning that depends on the synced directories ends with: which source it used. */
function fabricSourceNote(sync) {
  if (sync?.source === 'config') return 'Synced directories: fabric.directories in hardening/harness.config.json.';
  const why = sync?.invalid
    ? 'fabric.directories in hardening/harness.config.json is not a list of project-relative directories'
    : 'fabric.directories in hardening/harness.config.json records none';
  return `Synced directories: .platform, because ${why}; Desktop writes .platform too, so this is a reminder, not proof of a connection. List the synced directories there to check only those (docs/harness/fabric-git.md).`;
}

/** A relative byPath target of a datasetReference, or null (absolute paths are reported by checkPbipJson). */
const byPathOf = (ref) => {
  const p = ref?.byPath?.path;
  return typeof p === 'string' && p && !path.isAbsolute(p) && !/^[A-Za-z]:|^\\/.test(p) ? p : null;
};

/**
 * Why a report's datasetReference is a live connection to Analysis Services, or null: `byConnection` with
 * connectionType `analysisServicesDatabaseLive`, or a Data Source that is no Power BI workspace (`powerbi://`,
 * `pbiazure://`). The server name is not repeated in the reason.
 */
export function analysisServicesLiveReason(ref) {
  const conn = ref?.byConnection;
  if (!conn || typeof conn !== 'object') return null;
  if (String(conn.connectionType ?? '') === 'analysisServicesDatabaseLive') return 'byConnection with connectionType analysisServicesDatabaseLive';
  const source = /(?:^|;)\s*Data Source\s*=\s*([^;]*)/i.exec(String(conn.connectionString ?? ''))?.[1]?.trim();
  if (source && !/^(?:powerbi|pbiazure):\/\//i.test(source)) return 'byConnection whose Data Source is no Power BI workspace (powerbi://)';
  return null;
}

/**
 * Warnings for a report or model item folder a Fabric workspace syncs (`fabricSyncOf`: under a directory of
 * fabric.directories, or holding .platform when none is recorded) that Fabric Git ignores: a live connection to
 * Analysis Services.
 */
function checkFabricUnsupported(root, rel, kind, io, sync = fabricSyncOf(null)) {
  const dir = path.join(root, rel);
  const listed = sync.source === 'config' ? syncedDirOf(rel, sync.dirs) : null;
  if (sync.source === 'config' ? listed === null : !io.existsSync(path.join(dir, '.platform'))) return [];
  const message = (why) => (listed !== null
    ? `Live connection to Analysis Services (${why}) inside ${syncedDirLabel(listed)}, which a Fabric workspace syncs: Git integration ignores the item (Learn, checked 2026-10-17: it shows as unsupported in the Source control pane and is never committed or updated). Move it to a directory no workspace syncs and publish it from Desktop (docs/harness/fabric-git.md). ${fabricSourceNote(sync)}`
    : `Live connection to Analysis Services (${why}) in a folder that holds .platform. If a Fabric workspace syncs this directory, Git integration ignores the item (Learn, checked 2026-10-17: it shows as unsupported in the Source control pane and is never committed or updated): keep it in a directory no workspace syncs and publish it from Desktop. ${fabricSourceNote(sync)}`);
  if (kind === 'semanticmodel') {
    return io.existsSync(path.join(dir, 'modelReference.json'))
      ? [{ level: 'warn', file: `${rel}/modelReference.json`, message: message('modelReference.json') }]
      : [];
  }
  const ref = readJson(path.join(dir, 'definition.pbir'), io)?.datasetReference;
  let why = analysisServicesLiveReason(ref);
  const target = byPathOf(ref);
  if (!why && target && io.existsSync(path.join(path.resolve(dir, toPosix(target)), 'modelReference.json'))) why = `byPath to ${target}, which holds modelReference.json`;
  return why ? [{ level: 'warn', file: `${rel}/definition.pbir`, message: message(why) }] : [];
}

/** The files a report's `definition/report.json` names under resourcePackages, as paths relative to the report folder. */
export function resourcePackageFiles(reportJson) {
  const out = [];
  for (const pkg of Array.isArray(reportJson?.resourcePackages) ? reportJson.resourcePackages : []) {
    if (typeof pkg?.name !== 'string' || !pkg.name) continue;
    for (const item of Array.isArray(pkg.items) ? pkg.items : []) {
      if (typeof item?.path === 'string' && item.path) out.push(`StaticResources/${pkg.name}/${toPosix(item.path)}`);
    }
  }
  return out;
}

/**
 * A resourcePackages entry whose file is missing is a warning, not an error like a missing definition.pbism: Desktop
 * saved the report without its base theme file, Update from Git into the workspace succeeded, and the Fabric Git commit
 * from the service then added the file (observed 2026-10-17, docs/harness/fabric-git.md). An error would also block a
 * commit of a report Desktop saved.
 */
function checkResourcePackages(root, rel, io) {
  const reportJson = readJson(path.join(root, rel, 'definition', 'report.json'), io);
  return resourcePackageFiles(reportJson)
    .filter((file) => !io.existsSync(path.join(root, rel, file)))
    .map((file) => ({ level: 'warn', file: `${rel}/definition/report.json`, message: `resourcePackages names ${file}, which does not exist. A Fabric Git commit from the service adds a missing base theme file (observed 2026-10-17); a missing registered resource (custom theme, image) has nothing to supply it. Write the file with the reference or copy it from a working report (bi-pbir-report, docs/harness/fabric-git.md).` }));
}

/** `config.logicalId` of an item folder's .platform, or null (unreadable, not JSON, absent). */
const logicalIdOf = (root, rel, io) => {
  const id = readJson(path.join(root, rel, '.platform'), io)?.config?.logicalId;
  return typeof id === 'string' && id ? id.toLowerCase() : null;
};

/**
 * Warnings for a second copy of an item a Fabric workspace syncs (docs/harness/fabric-git.md, "One item, one place").
 * Full scan only: it needs the whole inventory (`findPbipItems`), whose `fabric` lists the synced item folders: those
 * under a directory of fabric.directories, or those that hold .platform when none is recorded (`items.fabricSync`).
 * Names compare case-insensitively (Windows, Desktop).
 *   - a .Report or .SemanticModel folder with the same name as a synced one, when this one is not synced (a hand-built,
 *     older or Desktop-saved copy), or when both are synced and hold .platform with the same logicalId (a raw copy);
 *   - two synced folders of one kind (.Report, .SemanticModel or .PaginatedReport) with different names and the same
 *     logicalId (a raw copy that was renamed): one warning per pair, in one directory or two. A pair with the same name
 *     is left to the first bullet (a paginated report that two workspaces sync is not reported); a report and a model
 *     that share a logicalId are not copies of one item;
 *   - an .rdl with the same file name as the .rdl of a synced <Name>.PaginatedReport/ folder, outside every such folder
 *     (the pre-upload copy under paginated/).
 * Two synced folders with different logicalIds are two items (two workspaces, two projects): silent. Without a list,
 * whether a Desktop publish followed by a service commit keeps Desktop's logicalId is not verified, so a Desktop-saved
 * copy under powerbi/ (it holds .platform too) of an item the service committed may stay silent; with a list it is a
 * copy like any other folder outside the listed directories (docs/harness/fabric-git.md).
 */
export function checkDuplicateFabricItems(root, items, io = fs) {
  const fabric = new Set((items.fabric ?? []).map((f) => f.toLowerCase()));
  if (!fabric.size) return [];
  const sync = items.fabricSync ?? fabricSyncOf(null);
  const note = fabricSourceNote(sync);
  const issues = [];
  const base = (p) => path.posix.basename(p).toLowerCase();
  const kind = (p) => /\.(semanticmodel|report|paginatedreport)$/i.exec(p)?.[1].toLowerCase();
  const group = (list, key) => list.reduce((m, p) => m.set(key(p), [...(m.get(key(p)) ?? []), p]), new Map());
  const fabricByName = group(items.fabric ?? [], base);
  const seenPairs = new Set();
  for (const folder of [...(items.models ?? []), ...(items.reports ?? [])]) {
    const twins = (fabricByName.get(base(folder)) ?? []).filter((t) => t.toLowerCase() !== folder.toLowerCase());
    if (!twins.length) continue;
    if (fabric.has(folder.toLowerCase())) {
      const id = logicalIdOf(root, folder, io);
      const same = twins.filter((t) => id && logicalIdOf(root, t, io) === id);
      for (const t of same) {
        const pair = [folder.toLowerCase(), t.toLowerCase()].sort().join('|');
        if (seenPairs.has(pair)) continue;
        seenPairs.add(pair);
        issues.push({ level: 'warn', file: folder, message: `Same name and the same .platform logicalId as ${t}: two copies of one item. One item lives in one place: remove the copy (with the user's approval) or make it a new item with a new logicalId and name (docs/harness/fabric-git.md). ${note}` });
      }
    } else {
      const synced = sync.source === 'config' ? 'which lies in a directory a Fabric workspace syncs' : 'which holds .platform';
      issues.push({ level: 'warn', file: folder, message: `Second copy of ${twins.join(', ')}, ${synced}. One item lives in one place: remove this copy with the user's approval, or give it another name (docs/harness/fabric-git.md). ${note}` });
    }
  }
  // A renamed raw copy: synced folders of one kind with one logicalId and different names. A pair with the same name is the
  // loop above's, with its own message (a paginated report that two workspaces sync stays silent); a report and a model
  // that share a logicalId are not copies of one item, so the kind is part of the key.
  const idOf = new Map((items.fabric ?? []).map((f) => [f, logicalIdOf(root, f, io)]));
  for (const copies of group((items.fabric ?? []).filter((f) => idOf.get(f)), (f) => `${kind(f)}|${idOf.get(f)}`).values()) {
    for (let i = 0; i < copies.length; i++) {
      for (const t of copies.slice(i + 1)) {
        if (base(t) === base(copies[i])) continue;
        issues.push({ level: 'warn', file: copies[i], message: `Same .platform logicalId as ${t}: two copies of one item under different names. One item lives in one place: remove the copy (with the user's approval) or make it a new item with a new logicalId and displayName (docs/harness/fabric-git.md). ${note}` });
      }
    }
  }
  const inside = new Map();
  const outside = [];
  for (const rdl of items.rdl ?? []) {
    const item = fabricItemOf(rdl);
    if (item?.kind === 'paginatedreport' && fabric.has(item.folder.toLowerCase())) inside.set(base(rdl), [...(inside.get(base(rdl)) ?? []), rdl]);
    else outside.push(rdl);
  }
  for (const rdl of outside) {
    const twins = inside.get(base(rdl));
    if (twins) issues.push({ level: 'warn', file: rdl, message: `Second copy of ${twins.join(', ')}, which a Fabric workspace syncs: the pre-upload copy of a paginated report. Remove it in the pull request that brings the service commit, with the user's approval, and renormalize the synced file's line endings (docs/harness/fabric-git.md). ${note}` });
  }
  return issues;
}

function checkReportFolder(root, rel, io, sync) {
  const exists = (...parts) => io.existsSync(path.join(...parts));
  const issues = [];
  const add = (level, file, message) => issues.push({ level, file, message });
  const dir = path.join(root, rel);
  const def = path.join(dir, 'definition');
  if (!exists(dir, 'definition.pbir')) add('error', rel, 'Missing definition.pbir (required).');
  issues.push(...checkFabricUnsupported(root, rel, 'report', io, sync));
  if (!io.existsSync(def)) {
    if (exists(dir, 'report.json')) add('info', `${rel}/report.json`, 'PBIR-Legacy format: report.json does not support external edits. Upgrade to PBIR in Power BI Desktop.');
    else add('error', rel, 'Missing report definition/ or legacy report.json.');
    return issues;
  }
  for (const required of ['version.json', 'report.json']) {
    if (!exists(def, required)) add('error', `${rel}/definition`, `Missing required ${required}.`);
  }
  issues.push(...checkResourcePackages(root, rel, io));
  const pagesDir = path.join(def, 'pages');
  if (!io.existsSync(pagesDir)) {
    add('error', `${rel}/definition`, 'Missing required pages/ folder.');
    return issues;
  }
  const pages = listDirs(pagesDir, io);
  const meta = readJson(path.join(pagesDir, 'pages.json'), io);
  if (meta) {
    const order = meta.pageOrder ?? [];
    if (!Array.isArray(order) || order.some((name) => typeof name !== 'string')) {
      add('error', `${rel}/definition/pages/pages.json`, 'pageOrder must be an array of page names.');
    } else for (const name of order) {
      if (!pages.includes(name)) add('error', `${rel}/definition/pages/pages.json`, `pageOrder lists "${name}" but no such page folder exists.`);
      if (order.indexOf(name) !== order.lastIndexOf(name)) add('error', `${rel}/definition/pages/pages.json`, `Duplicate pageOrder entry "${name}".`);
    }
    if (meta.activePageName && !pages.includes(meta.activePageName)) {
      add('error', `${rel}/definition/pages/pages.json`, `activePageName "${meta.activePageName}" does not exist.`);
    }
  }
  for (const page of pages) {
    const pageRel = `${rel}/definition/pages/${page}`;
    if (!isValidPbirName(page)) add('error', pageRel, `Invalid page folder name "${page}"; Power BI Desktop ignores it.`);
    if (!exists(pagesDir, page, 'page.json')) add('error', pageRel, 'Missing page.json.');
    for (const visual of listDirs(path.join(pagesDir, page, 'visuals'), io)) {
      if (!isValidPbirName(visual)) add('error', `${pageRel}/visuals/${visual}`, `Invalid visual folder name "${visual}".`);
      if (!exists(pagesDir, page, 'visuals', visual, 'visual.json')) add('error', `${pageRel}/visuals/${visual}`, 'Missing visual.json.');
    }
  }
  issues.push(...checkReportFields(root, rel, pages, io));
  return issues;
}

/** Fields used by a report bound byPath to a TMDL model must exist in that model (or in its report extensions). */
function checkReportFields(root, rel, pages, io) {
  const dir = path.join(root, rel);
  const target = readJson(path.join(dir, 'definition.pbir'), io)?.datasetReference?.byPath?.path;
  if (typeof target !== 'string' || !target || path.isAbsolute(target) || /^[A-Za-z]:|^\\/.test(target)) return [];
  const tables = readModelFields(path.resolve(dir, toPosix(target)), io);
  if (!tables) return [];
  const extensions = readJson(path.join(dir, 'definition', 'reportExtensions.json'), io)?.entities;
  for (const entity of Array.isArray(extensions) ? extensions : []) {
    if (typeof entity?.name !== 'string') continue;
    const key = entity.name.toLowerCase();
    const table = tables.get(key) ?? { name: entity.name, fields: new Set(), measures: [] };
    for (const m of Array.isArray(entity.measures) ? entity.measures : []) if (typeof m?.name === 'string') table.fields.add(m.name.toLowerCase());
    tables.set(key, table);
  }
  const files = ['definition/report.json'];
  for (const page of pages) {
    files.push(`definition/pages/${page}/page.json`);
    for (const visual of listDirs(path.join(dir, 'definition', 'pages', page, 'visuals'), io)) files.push(`definition/pages/${page}/visuals/${visual}/visual.json`);
  }
  const issues = [];
  for (const file of files) {
    const missing = { fields: new Set(), filters: new Set() };
    for (const ref of pbirFieldRefs(readJson(path.join(dir, file), io))) {
      const table = tables.get(ref.entity.toLowerCase());
      const name = !table ? `table '${ref.entity}'` : table.fields.has(ref.field.toLowerCase()) ? null : `'${ref.entity}'[${ref.field}]`;
      if (name) missing[ref.inFilter ? 'filters' : 'fields'].add(name);
    }
    for (const name of missing.fields) missing.filters.delete(name);
    if (missing.fields.size) {
      issues.push({ level: 'error', file: `${rel}/${file}`, message: `Uses ${[...missing.fields].join(', ')}, which the model (${target}) does not define. Power BI Desktop cannot render a visual with a missing field; fix the field or finish the model change (a rename in progress?).` });
    }
    if (missing.filters.size) {
      issues.push({ level: 'warn', file: `${rel}/${file}`, message: `Filters on ${[...missing.filters].join(', ')}, which the model (${target}) does not define. Power BI Desktop flags them in the filter pane; remove the stale filter or restore the field.` });
    }
  }
  return issues;
}

const MEASURE_RE = /^\t*measure\s+('(?:[^']|'')*'|[^\s=:'`]+)/gm;

function checkModelFolder(root, rel, io, sync) {
  const exists = (...parts) => io.existsSync(path.join(...parts));
  const issues = [];
  const add = (level, file, message) => issues.push({ level, file, message });
  const dir = path.join(root, rel);
  if (!exists(dir, 'definition.pbism')) add('error', rel, 'Missing definition.pbism (required).');
  issues.push(...checkFabricUnsupported(root, rel, 'semanticmodel', io, sync));
  if (exists(dir, '.pbi', 'unappliedChanges.json')) {
    add('warn', `${rel}/.pbi/unappliedChanges.json`, 'Pending Power Query changes exist; applying them in Desktop overwrites external edits to M expressions.');
  }
  if (!exists(dir, 'definition')) {
    // A live connection to an Analysis Services model outside Fabric keeps only modelReference.json (schema
    // semanticModel/modelReference); a TMSL model.bim gets the TMDL-only warning from the per-file check.
    if (exists(dir, 'modelReference.json')) return issues;
    if (!exists(dir, 'model.bim')) add('error', rel, 'Missing the TMDL model definition/ folder (or modelReference.json for a live connection).');
    return issues;
  }
  return [...issues, ...checkModelDefinition(root, rel, 'definition', io)];
}

/**
 * Model-wide checks of a TMDL definition folder (`<model>/<sub>/tables/*.tmdl`): unique measure names, DAX references,
 * and perspective and translation entries that still name a renamed or removed object.
 */
function checkModelDefinition(root, rel, sub, io) {
  const issues = [];
  const add = (level, file, message) => issues.push({ level, file, message });
  // A model at the repository root ("." from findPbipItems or affectedArtifacts) reports plain paths (tables/X.tmdl).
  const defRel = [rel, sub].filter((p) => p && p !== '.').join('/');
  const at = (...parts) => [defRel, ...parts].filter(Boolean).join('/');
  const tablesDir = path.join(root, defRel, 'tables');
  const seen = new Map();
  let files = [];
  try {
    files = io.readdirSync(tablesDir).filter((f) => f.endsWith('.tmdl'));
  } catch {
    return issues;
  }
  for (const file of files) {
    let text = '';
    try {
      text = io.readFileSync(path.join(tablesDir, file), 'utf8');
    } catch {
      add('error', at('tables', file), 'Cannot read model table; duplicate measure validation is incomplete.');
      continue;
    }
    for (const m of text.matchAll(MEASURE_RE)) {
      const name = (m[1].startsWith("'") ? m[1].slice(1, -1).replace(/''/g, "'") : m[1]).toLowerCase();
      if (seen.has(name)) {
        add('error', at('tables', file), `Measure "${name}" is also defined in ${seen.get(name)}; measure names must be unique in the model.`);
      } else seen.set(name, file);
    }
  }
  const tables = readModelFields(path.join(root, rel), io, sub);
  for (const table of tables?.values() ?? []) {
    for (const m of table.measures) {
      if (table.columns?.has(m.name.toLowerCase())) {
        add('error', at('tables', m.file), `Measure '${m.name}' has the name of a column of table '${table.name}'; Power BI Desktop refuses to load the model. Rename one of them.`);
      } else {
        // Allowed by the engine, but an unqualified [Name] then reads as the measure: Learn advises against it.
        const other = [...tables.values()].find((t) => t !== table && t.columns?.has(m.name.toLowerCase()));
        if (other) add('warn', at('tables', m.file), `Measure '${m.name}' has the name of a column of table '${other.name}'. It loads, but an unqualified [${m.name}] means the measure; name the column after its content (Learn: Calculated columns, naming).`);
      }
      const missing = unresolvedDaxRefs(m.expression, tables);
      if (missing.length) {
        add('warn', at('tables', m.file), `Measure '${m.name}' references ${missing.join(', ')}, which the model does not define (renamed or removed?).`);
      }
    }
  }
  if (!tables) return issues;
  for (const [folder, kind] of [['perspectives', 'perspective'], ['cultures', 'culture']]) {
    let names = [];
    try {
      names = io.readdirSync(path.join(root, defRel, folder)).filter((f) => f.endsWith('.tmdl'));
    } catch {
      continue;
    }
    for (const file of names) {
      let text = '';
      try {
        text = io.readFileSync(path.join(root, defRel, folder, file), 'utf8');
      } catch {
        continue;
      }
      const missing = unresolvedMetadataRefs(text, tables, kind);
      if (missing.length) {
        add('error', at(folder, file), `The ${kind} names ${missing.join(', ')}, which the model does not define: rename or remove the entry with the object.`);
      }
    }
  }
  return issues;
}

/** True for a TMDL model folder outside a PBIP (an Analysis Services project): it holds database.tmdl and model.tmdl. */
const isTabularFolder = (root, rel, io = fs) => io.existsSync(path.join(root, rel, 'database.tmdl')) && io.existsSync(path.join(root, rel, 'model.tmdl'));

/**
 * Folder-level checks of the given inventory. `items.fabricSync` (`fabricSyncOf`; set by findPbipItems and validateFiles
 * from the config) says which directories a Fabric workspace syncs; without it .platform is the signal.
 */
export function validateArtifacts(root, items, io = fs) {
  const sync = items.fabricSync ?? fabricSyncOf(null);
  return [
    ...items.reports.flatMap((r) => checkReportFolder(root, r, io, sync)),
    ...items.models.flatMap((m) => checkModelFolder(root, m, io, sync)),
    ...(items.tabular ?? []).flatMap((t) => checkModelDefinition(root, t, '', io)),
    // Only the full scan's inventory carries `fabric` and `rdl`; --changed and --staged pass none and get no copy check.
    ...checkDuplicateFabricItems(root, items, io),
  ];
}

/** .gitignore coverage and files that must never be tracked. */
export function checkRepoHygiene(root, hasPbip) {
  const issues = [];
  if (hasPbip) {
    let gitignore = '';
    try {
      gitignore = fs.readFileSync(path.join(root, '.gitignore'), 'utf8');
    } catch {
      // reported below
    }
    for (const rule of ['**/.pbi/localSettings.json', '**/.pbi/cache.abf']) {
      if (!gitignore.includes(rule)) issues.push({ level: 'error', file: '.gitignore', message: `Missing "${rule}"; Power BI local settings or the data cache could be committed.` });
    }
  }
  const tracked = git(['ls-files', '-z'], { cwd: root });
  for (const file of (tracked ?? '').split('\0').filter(Boolean)) {
    const cls = classifyPath(file);
    if (cls.secret || cls.data || cls.localOnly) {
      issues.push({ level: 'error', file, message: 'Tracked in git but must never be committed. Run `git rm --cached` on it and rotate any exposed credential.' });
    }
  }
  return issues;
}

/** Walks the project (honoring scan.exclude) and returns project-relative file paths. */
export function walkFiles(root, cfg, maxFiles = 100000) {
  const exclude = cfg?.scan?.exclude ?? [];
  const out = [];
  const stack = [''];
  while (stack.length) {
    const relDir = stack.pop();
    let entries = [];
    try {
      entries = fs.readdirSync(path.join(root, relDir), { withFileTypes: true });
    } catch (err) {
      throw new Error(`Cannot scan directory ${relDir || '.'} (${err.code ?? 'read failure'}).`);
    }
    for (const e of entries) {
      const rel = relDir ? `${relDir}/${e.name}` : e.name;
      if (e.isDirectory()) {
        if (e.name !== '.git' && e.name !== 'node_modules' && !matchesAny(`${rel}/`, exclude)) stack.push(rel);
      } else if (e.isFile() && !matchesAny(rel, exclude)) {
        out.push(rel);
        if (out.length > maxFiles) throw new Error(`Scan exceeds ${maxFiles} files; validation is incomplete. Narrow scan.exclude deliberately.`);
      }
    }
  }
  return out.sort();
}

/** PBIP artifact folders that contain any of the given files. */
export function affectedArtifacts(relFiles) {
  const models = new Set();
  const reports = new Set();
  const tabular = new Set();
  for (const f of relFiles) {
    const posix = toPosix(f);
    const m = /^(.*?[^/]+\.(semanticmodel|report))(?:\/|$)/i.exec(posix);
    if (m) (m[2].toLowerCase() === 'report' ? reports : models).add(m[1]);
    else if (/\.tmdl$/i.test(posix)) {
      // A TMDL folder outside a PBIP: tables/, roles/, cultures/, perspectives/ sit one level below its root.
      const dir = path.posix.dirname(posix);
      tabular.add(/^(?:tables|roles|cultures|perspectives)$/i.test(path.posix.basename(dir)) ? path.posix.dirname(dir) : dir);
    }
  }
  return { models: [...models], reports: [...reports], tabular: [...tabular], pbip: [] };
}

function dedupe(issues) {
  const seen = new Set();
  return issues.filter((i) => {
    const key = `${i.level}|${i.file}|${i.line ?? ''}|${i.message}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/** Validates the given files (+ the PBIP artifacts they belong to). */
export function validateFiles(root, cfg, relFiles, { readText, projectChecks = true, io = fs, allowMissing = false, mode } = {}) {
  const read = readText ?? ((rel) => io.readFileSync(path.join(root, rel), 'utf8'));
  const exclude = cfg?.scan?.exclude ?? [];
  const listed = [...new Set(relFiles.map(toPosix))];
  const candidates = listed.filter((f) => !matchesAny(f, exclude));
  const files = candidates.filter(isTextFile);
  // Every file type, not only text: a screenshot inside an item folder is deleted by a service commit as well.
  const issues = [...checkItemFolderFiles(root, candidates, io, cfg)];
  // F1-107: scan.exclude keeps vendored text, test fixtures and other worktrees out of the structure checks, never out
  // of the commit's credential check. A staged file in an excluded folder is checked for credentials only.
  if (mode === 'staged') {
    for (const rel of listed.filter((f) => matchesAny(f, exclude) && isTextFile(f))) {
      let text;
      try {
        text = read(rel);
      } catch {
        if (!allowMissing || io.existsSync(path.join(root, rel))) issues.push({ level: 'error', file: rel, message: 'Cannot read file; validation is incomplete.' });
        continue;
      }
      if (typeof text !== 'string' || Buffer.byteLength(text) > MAX_TEXT_BYTES) {
        issues.push({ level: 'error', file: rel, message: `File was not checked: text validation limit is ${MAX_TEXT_BYTES / 1024 / 1024} MiB.` });
        continue;
      }
      for (const s of findSecrets(text)) issues.push({ level: 'error', file: rel, line: s.line, message: credentialMessage(s) });
    }
  }
  const checked = [];
  for (const rel of files) {
    let text;
    try {
      text = read(rel);
    } catch {
      if (!allowMissing || io.existsSync(path.join(root, rel))) {
        issues.push({ level: 'error', file: rel, message: 'Cannot read file; validation is incomplete.' });
      }
      continue;
    }
    if (typeof text !== 'string' || Buffer.byteLength(text) > MAX_TEXT_BYTES) {
      issues.push({ level: 'error', file: rel, message: `File was not checked: text validation limit is ${MAX_TEXT_BYTES / 1024 / 1024} MiB.` });
      continue;
    }
    checked.push(rel);
    issues.push(...validateFileText(rel, text, { cfg, root, io, mode }));
  }
  if (projectChecks) {
    const affected = affectedArtifacts(files);
    // A whole artifact may have been intentionally deleted. Surviving bindings catch broken links. An item in a reference
    // folder is not the repository's project (findPbipItems skips it too); its files got the per-file checks above.
    const own = (rel) => !isReferenceRel(`${rel}/`, cfg);
    affected.models = affected.models.filter((rel) => own(rel) && io.existsSync(path.join(root, rel)));
    affected.reports = affected.reports.filter((rel) => own(rel) && io.existsSync(path.join(root, rel)));
    affected.tabular = affected.tabular.filter((rel) => own(rel) && isTabularFolder(root, rel, io));
    affected.fabricSync = fabricSyncOf(cfg);
    issues.push(...validateArtifacts(root, affected, io));
  }
  return { files: checked, issues: dedupe(issues) };
}

export function formatIssues(issues, max = 20) {
  const lines = issues.slice(0, max).map((i) => `${i.level.toUpperCase().padEnd(5)} ${i.file}${i.line ? `:${i.line}` : ''} — ${i.message}`);
  if (issues.length > max) lines.push(`… and ${issues.length - max} more`);
  return lines.join('\n');
}
