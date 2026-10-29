// The SQL read switch (`sources.sqlRead` in hardening/harness.config.json, Q-13). The agent edits SQL text; it runs a
// query only when the user asked for it. This module judges every query a SQL client (sqlcmd, osql, isql, mssql-cli,
// Invoke-Sqlcmd, psql) or a SQL MCP server would run, in every approvals mode:
// - deny: anything that changes data, schema, permissions or the server (DML, DDL, BULK, BACKUP, DBCC, xp_, shell
//   escapes such as sqlcmd `:!!` and psql `\!`), and credentials on the command line;
// - floor ask (the user sees it in every mode, lab included): what the guard cannot read or bound (a file outside the
//   project, stdin, scripting and shell variables, an option it does not know, EXEC, dynamic SQL, a function it does not
//   know, a server not listed), and every query while the switch is "off" (the default);
// - plain ask (auto and lab approve it and log it; ask mode prompts): with the switch "on", a query against a listed
//   server whose every statement is read-only, bounded (one aggregate row, or TOP/LIMIT/FETCH up to maxRows) and names
//   no personal column, run as a command of its own (policy.mjs).
// The analysis is textual and conservative: a false deny or a prompt is the safe failure, never a silent pass.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { PROJECT_DIR, projectRel } from './common.mjs';

const deny = (reason) => ({ decision: 'deny', reason });
const floor = (reason) => ({ decision: 'ask', reason, autoApprovable: false, floor: true });
const pass = (reason) => ({ decision: 'ask', reason, sqlRead: true });

/** Programs that send SQL text to a server and are judged here. Other database clients ask (policy.mjs, DB_CLIENTS). */
export const SQL_QUERY_CLIENTS = new Set(['sqlcmd', 'osql', 'isql', 'mssql-cli', 'invoke-sqlcmd', 'psql']);

export const DEFAULT_PERSONAL_COLUMNS = Object.freeze([
  'email', 'emailaddress', 'mail', 'phone', 'phonenumber', 'mobile', 'telephone', 'fax', 'ssn', 'socialsecuritynumber',
  'tckn', 'tckimlikno', 'nationalid', 'taxid', 'passport', 'passportnumber', 'iban', 'accountnumber', 'creditcard',
  'cardnumber', 'address', 'addressline1', 'addressline2', 'street', 'birthdate', 'dateofbirth', 'dob', 'password',
  'passwordhash', 'firstname', 'lastname', 'middlename', 'fullname', 'customername', 'salespersonname', 'employeename',
  'contactname', 'personname', 'username', 'loginname', 'sql_logins', 'password_hash', 'loginproperty', 'pwdcompare',
]);

const PERSON_WORD_RE = /customer|salesperson|employee|contact|person|client|member|patient|student|user|login/;

// The words of a personal column name, one vocabulary for this judge and the DAX guard (policy.mjs): English words
// anywhere in the name; Turkish, German, French, Spanish and Italian words on the name with its letters folded to ASCII
// (Müşteri Adı is musteri adi). Short words count only as a word of their own ([Tel No], not [Hotel]); "ad" only as the
// whole name or before soyad, so [Ad Campaign] and a product's [Ürün Adı] pass while [Ad], [Ad Soyad] and [Müşteri Adı] ask.
export const PERSONAL_NAME_RE = /e-?mail|phone|address|birth|ssn|iban|passport|salary|user\s*name|(?:customer|person|employee|contact|salesperson|rep)\s*name/i;
export const PERSONAL_WORD_RE = new RegExp([
  '^\\s*ad\\s*$',
  '(?<![a-z0-9])(?:isim|tel|tc)(?![a-z0-9])',
  '(?<![a-z0-9])(?:ad[\\s_-]*soyad|soyad|soyisim|telefon|e[\\s_-]?posta|tc[\\s_-]*(?:kimlik|kn)|kimlik|adres|dogum|maas|pasaport' +
    '|(?:kullanici|musteri|personel|calisan|uye|hasta|ogrenci|temsilci|yetkili|kisi)[\\s_-]*(?:adi|ismi|ad(?![a-z0-9]))' +
    '|vorname|nachname|geburt|gehalt|prenom|naissance|salaire|courriel|apellido|nacimiento|salario|correo|cognome|indirizzo|nascita|stipendio)',
].join('|'), 'i');
/** Folds accented Latin letters to ASCII one character for one (İ, ı → i; ş → s; ğ → g; é → e), so positions stay. */
export const foldLatin = (s) => s.replace(/[À-ɏ]/g, (c) => (c === 'ı' ? 'i' : c.normalize('NFD')[0]));
// A name as ASCII: composed and unified first (a decomposed ü is a u and a mark, a full-width letter is its ASCII
// letter, which a width-insensitive collation also reads as the same name), then folded.
const asciiOf = (s) => foldLatin(String(s).normalize('NFKC'));
// Identifier keys ignore case, accents, quotes and separators: [E-mail], e_mail and EMail are one name.
export const identKey = (s) => asciiOf(s).toLowerCase().replace(/^qi__/, '').replace(/[^a-z0-9]/g, '');
const DEFAULT_PERSONAL = new Set(DEFAULT_PERSONAL_COLUMNS.map(identKey));

/** An identifier as lower-case ASCII words: MusteriAdi, Musteri_Adi and a quoted [Müşteri Adı] all read "musteri adi". */
function nameWords(name) {
  return asciiOf(name)
    .replace(/^qi__/i, '')
    .replace(/([a-z])([A-Z])/g, '$1 $2').replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2') // camelCase, and TCKimlik
    .replace(/([A-Za-z])([0-9])/g, '$1 $2').replace(/([0-9])([A-Za-z])/g, '$1 $2')
    .replace(/[^A-Za-z0-9]+/g, ' ')
    .trim()
    .toLowerCase();
}

// A manager's or a supervisor's name is a person's name in any table (ManagerName, manager_name, [Account Manager Name],
// ManagerFirstName); a manager's level, key or count is not. Read on a name's key (letters and digits, its plural and
// number already dropped). The DAX guard has the same rule for a column (policy.mjs, ROLE_NAME_RE).
export const ROLE_NAME_KEY_RE = /(?:manager|supervisor)(?:full|first|last|given|family|display|preferred|legal)?name$/;

/**
 * True when one identifier (a column, a quoted name) names people: it is on the built-in or configured list (`listed`,
 * identifier keys; also as a plural or with a number, Emails and Phone2), ends in email, phone, ... or a person's name
 * (the suffix rules: a person word or a manager's or supervisor's role before "name"), or holds a word of the shared
 * vocabulary.
 */
export function personalColumnName(name, listed = DEFAULT_PERSONAL) {
  const words = nameWords(name);
  if (!words) return false;
  const key = words.replace(/ /g, '');
  const forms = new Set([key, key.replace(/[0-9]+$/, '')]);
  for (const f of [...forms]) {
    if (f.endsWith('s')) forms.add(f.slice(0, -1));
    if (f.endsWith('es')) forms.add(f.slice(0, -2));
  }
  for (const f of forms) {
    if (!f) continue;
    if (listed.has(f) || /(?:email|phone|mobile|password|passwd|iban|ssn|tckn)$/.test(f)
      || (/name$/.test(f) && (PERSON_WORD_RE.test(f) || /^(?:first|last|middle|full|given|family|sur)/.test(f) || ROLE_NAME_KEY_RE.test(f)))) return true;
  }
  return PERSONAL_NAME_RE.test(words) || PERSONAL_WORD_RE.test(words);
}

/** The switch with defaults filled in. Any spelling other than "on" is "off": a typo never opens the switch. */
export function sqlReadOf(cfg) {
  const raw = cfg?.sources?.sqlRead;
  const obj = raw && typeof raw === 'object' && !Array.isArray(raw) ? raw : {};
  const list = (v) => (Array.isArray(v) ? v.filter((x) => typeof x === 'string' && x.trim()).map((x) => x.trim()) : []);
  const max = Number.isInteger(obj.maxRows) && obj.maxRows >= 1 ? Math.min(obj.maxRows, 1000) : 50;
  return {
    on: typeof obj.mode === 'string' && obj.mode.trim().toLowerCase() === 'on',
    rawMode: obj.mode,
    servers: list(obj.servers).map(normalizeServer).filter(Boolean),
    mcpServers: list(obj.mcpServers).map((s) => s.toLowerCase()),
    maxRows: max,
    personal: new Set([...DEFAULT_PERSONAL, ...list(obj.personalColumns).map(identKey)]),
  };
}

/**
 * True when `after` opens the switch further than `before`: turned on, a server or MCP server added, a higher row cap,
 * a personal column removed. The agent may only make it stricter (only the user widens it, as with approvals).
 */
export function sqlReadWidened(beforeCfg, afterCfg) {
  const b = sqlReadOf(beforeCfg);
  const a = sqlReadOf(afterCfg);
  if (a.on && !b.on) return true;
  if (a.servers.some((s) => !b.servers.includes(s))) return true;
  if (a.mcpServers.some((s) => !b.mcpServers.includes(s))) return true;
  if (a.maxRows > b.maxRows) return true;
  for (const p of b.personal) if (!a.personal.has(p)) return true;
  return false;
}

const LOCAL_ALIASES = new Set(['.', '(local)', 'localhost', '127.0.0.1', '::1', '[::1]', os.hostname().toLowerCase()]);

/** A server name in one spelling: lower case, no protocol or port; this machine's aliases become "localhost". */
export function normalizeServer(value) {
  let s = String(value ?? '').trim().toLowerCase();
  if (!s) return '';
  s = s.replace(/^(?:tcp|np|lpc|admin):/, '');
  let instance = '';
  const slash = s.indexOf('\\');
  if (slash >= 0) { instance = s.slice(slash); s = s.slice(0, slash); }
  s = s.replace(/,\d+$/, '');
  if (!s.startsWith('[') && (s.match(/:/g) ?? []).length === 1) s = s.replace(/:\d+$/, '');
  if (LOCAL_ALIASES.has(s)) s = 'localhost';
  return s + instance;
}

// ---------------------------------------------------------------- SQL text

/**
 * Masks a SQL text for keyword scanning: comments become a space, string literals become '', quoted identifiers
 * become one word "qi__name" that no keyword matches. Each dialect reads quotes its own way, as its server and client
 * split statements:
 * - "tsql": -- and nested /* *\/ comments, '..' and N'..' strings, [..] and ".." identifiers (a backtick is no quote);
 * - "psql": the same comments, '..' and E'..' strings, $tag$..$tag$ strings (only where PostgreSQL starts one: not
 *   inside a name such as x$$), ".." identifiers (a bracket is no quote: psql splits a file at a ";" inside one);
 * - "mysql": -- only before a space, # and non-nested /* *\/ comments, '..' and ".." strings, `..` identifiers.
 * `backslash` says where a backslash escapes the next character inside a string: "none", "estrings" (PostgreSQL E'..'
 * only, the default since 9.1) or "all" (PostgreSQL with standard_conforming_strings off, MySQL). Where the dialect is
 * uncertain the caller masks every way and keeps the strictest verdict: a literal or comment that ends earlier under
 * one reading must not hide a statement. Returns { text, error }; on an error, text is what was read before it.
 */
export function maskSql(sql, { backslash = 'none', dialect = 'tsql' } = {}) {
  const s = String(sql ?? '');
  const mysql = dialect === 'mysql';
  let out = '';
  let i = 0;
  while (i < s.length) {
    const c = s[i];
    const n = s[i + 1];
    if ((c === '-' && n === '-' && (!mysql || i + 2 >= s.length || /\s/.test(s[i + 2]))) || (mysql && c === '#')) {
      while (i < s.length && s[i] !== '\n') i++;
      out += ' ';
      continue;
    }
    if (c === '/' && n === '*') {
      let depth = 1;
      i += 2;
      while (i < s.length && depth) {
        if (!mysql && s[i] === '/' && s[i + 1] === '*') { depth++; i += 2; } else if (s[i] === '*' && s[i + 1] === '/') { depth--; i += 2; } else i++;
      }
      if (depth) return { text: out, error: 'an unterminated comment' };
      out += ' ';
      continue;
    }
    if (c === "'" || (mysql && c === '"')) {
      // An E'..' string: the E stands right before the quote and is not the end of a longer name.
      const eString = (s[i - 1] === 'E' || s[i - 1] === 'e') && !/[\w$]/.test(s[i - 2] ?? '');
      const escapes = backslash === 'all' || (backslash === 'estrings' && c === "'" && eString);
      i++;
      while (i < s.length) {
        if (escapes && s[i] === '\\') { i += 2; continue; }
        if (s[i] === c && s[i + 1] === c) { i += 2; continue; }
        if (s[i] === c) break;
        i++;
      }
      if (i >= s.length) return { text: out, error: 'an unterminated string literal' };
      i++;
      out += "''";
      continue;
    }
    if (c === '$' && dialect === 'psql' && !/[\w$]/.test(s[i - 1] ?? '')) {
      const tag = /^\$(?:[A-Za-z_][A-Za-z0-9_]*)?\$/.exec(s.slice(i, i + 66));
      if (tag) {
        const end = s.indexOf(tag[0], i + tag[0].length);
        if (end < 0) return { text: out, error: 'an unterminated dollar-quoted string' };
        i = end + tag[0].length;
        out += "''";
        continue;
      }
    }
    if ((c === '[' && dialect === 'tsql') || (c === '"' && !mysql) || (c === '`' && mysql)) {
      const close = c === '[' ? ']' : c;
      let j = i + 1;
      let word = '';
      while (j < s.length) {
        if (s[j] === close && s[j + 1] === close) { word += close; j += 2; continue; }
        if (s[j] === close) break;
        word += s[j];
        j++;
      }
      if (j >= s.length) return { text: out, error: 'an unterminated quoted identifier' };
      out += ` qi__${asciiOf(word).replace(/[^\w]+/g, '_') || '_'} `; // letters folded to ASCII: [Müşteri Adı] keeps its words
      i = j + 1;
      continue;
    }
    out += c;
    i++;
  }
  return { text: out, error: null };
}

/** Statements of a masked text: split on ";" and on sqlcmd/SSMS batch lines ("GO", "GO 5"). */
function statementsOf(masked) {
  return masked
    .split(GO_LINE_RE)
    .flatMap((batch) => batch.split(';'))
    .map((st) => st.trim())
    .filter(Boolean);
}
// A batch separator line. [ \t] and not \s: \s spans lines, which makes the scan quadratic on long texts.
const GO_LINE_RE = /^[ \t]*go(?:[ \t]+\d+)?[ \t]*\r?$/gim;
// Longer SQL texts are not analysed in full (the scan grows faster than linearly, and a hook past its timeout lets the
// call through): only searched for writes in one linear pass (writeInRawText), else the user's call.
const MAX_SQL_TEXT = 32 * 1024;

// Words and calls that change data, schema, permissions or the server, or run a shell: never from the agent. These parts
// scan in time linear in the text's length; DENY_STATEMENT_RE adds two "... INTO" scans, which read a statement again
// from every SELECT or OUTPUT.
const DENY_WORD_PARTS = [
  String.raw`\b(?:insert|update|delete|merge|upsert|truncate|drop|create|alter|grant|revoke|deny|backup|restore|dbcc|shutdown|kill|reconfigure|vacuum|cluster|reindex|analy[sz]e|lock|copy|attach|detach|checkpoint|replace\s+into)\b`,
  String.raw`\b(?:enable|disable)\s+trigger\b`, String.raw`\bbulk\s+insert\b`, String.raw`\bopenrowset\s*\(\s*bulk\b`, String.raw`\bcomment\s+on\b`,
  String.raw`\brefresh\s+materialized\b`, String.raw`\bsecurity\s+label\b`, String.raw`\bimport\s+foreign\b`, String.raw`\bxp_\w+`,
  String.raw`\bsp_(?:configure|add\w*|drop\w*|change\w*|set\w*|rename\w*|password|grant\w*|revoke\w*|oa\w+|start_job|send_dbmail|execute_external_script|attach\w*|detach\w*|delete\w*|update\w*)\b`,
  String.raw`\b(?:lo_import|lo_export|lo_unlink|lo_put|lo_from_bytea|pg_file_write|pg_terminate_backend|pg_cancel_backend|pg_reload_conf|pg_rotate_logfile|pg_promote|pg_switch_wal|set_config|nextval|setval|pg_create_\w+|pg_drop_\w+)\s*\(`,
];
const DENY_STATEMENT_RE = new RegExp([
  ...DENY_WORD_PARTS,
  String.raw`\bselect\b[^;]*?\binto\s+(?:temp(?:orary)?\s+|unlogged\s+)?(?:##|(?![#@]))\w`,
  String.raw`\boutput\b[^;]*?\binto\b`, // T-SQL OUTPUT ... INTO: a write into another table, also from a temporary-table write
].join('|'), 'i');
// A text longer than the full judge reads (MAX_SQL_TEXT) is searched for writes in one linear pass over its raw text: the
// same words and calls, and INTO before a table name (SELECT ... INTO, OUTPUT ... INTO) in place of the two INTO scans.
const DENY_LONG_TEXT_RE = new RegExp([...DENY_WORD_PARTS, String.raw`\binto\s+(?:temp(?:orary)?\s+|unlogged\s+)?(?:##|(?![#@]))\w`].join('|'), 'i');

/**
 * The write in a SQL text of any length, found in time linear in its length, or null. The raw text is searched, strings
 * and comments included (a write word in a literal denies too: the safe failure for a text the full judge does not read).
 */
function writeInRawText(text) {
  if (/^[ \t]*(?::[ \t]*)?!!/m.test(text)) return 'sqlcmd "!!" runs an operating system command';
  if (/\\!/.test(text)) return 'psql "\\!" runs a shell command';
  const m = DENY_LONG_TEXT_RE.exec(text);
  return m ? `the text holds "${preview(text.slice(Math.max(0, m.index - 30), m.index + 50))}", which changes data, schema, permissions or the server` : null;
}

// Statements and calls the guard cannot bound or see through: the user's call.
const FLOOR_STATEMENT_RE = new RegExp([
  String.raw`\b(?:exec|execute|sp_executesql|call|waitfor|openquery|opendatasource|openrowset|cursor|while|goto|notify|listen|prepare|revert|setuser)\b`,
  String.raw`\bfetch\b(?!\s+(?:first|next)\s+\d+\s+rows?\s+only\b)`, String.raw`^\s*do\b`,
  String.raw`\bfor\s+(?:update|share|no\s+key\s+update|key\s+share)\b`, String.raw`\bset\s+(?:role|session\s+authorization)\b`,
  String.raw`\bnext\s+value\s+for\b`, // a sequence moves on
  // A four-part name: a linked server. The lookbehind starts a name only at its first character (else the scan is
  // quadratic on one long name); quoted names are qi__ words and match the same pattern.
  String.raw`(?<![\w$])[A-Za-z_][\w$]*\s*\.\s*(?:[A-Za-z_][\w$]*)?\s*\.\s*(?:[A-Za-z_][\w$]*)?\s*\.\s*[A-Za-z_]`,
  String.raw`\bsp_\w+`, String.raw`\bfn_\w*(?:file|trace|log)\w*\s*\(`,
  String.raw`\b(?:dblink\w*|pg_read_file|pg_read_binary_file|pg_ls_dir|pg_stat_file|pg_sleep\w*|pg_advisory\w*|query_to_xml\w*|table_to_xml\w*|current_setting)\s*\(`,
].join('|'), 'i');
// A local write the agent may use inside a read query: a table variable (@t) or a temporary table of this session (#t).
// A global temporary table (##t) is shared with every session of the server: writing it is a write.
const LOCAL_WRITE_RE = /^\s*(?:insert\s+(?:into\s+)?(?:#(?!#)|@)|update\s+(?:#(?!#)|@)|delete\s+(?:from\s+)?(?:#(?!#)|@)|truncate\s+table\s+#(?!#)|create\s+table\s+#(?!#)|drop\s+table\s+(?:if\s+exists\s+)?#(?!#)|declare\s+@\w+\s+(?:as\s+)?table\b)/i;
// Statements that read nothing and change nothing (their contents are still judged for packing and personal data).
const NEUTRAL_STATEMENT_RE = /^\s*(?:set\s+(?:nocount|ansi_\w+|quoted_identifier|arithabort|concat_null_yields_null|numeric_roundabort|xact_abort|language|dateformat|datefirst|transaction\s+isolation\s+level\s+read\s+(?:un)?committed|statement_timeout|search_path|client_encoding)\b|use\s+\w+\s*$|print\b|begin\s+tran(?:saction)?\b\s*\w*\s*$|commit\b|rollback\b|declare\s+@\w+\s+(?!(?:as\s+)?(?:table|cursor)\b)|raiserror\b|throw\b)/i;
const QUERY_START_RE = /^\s*\(*\s*(?:select|with|values|show|explain(?!\s+analy[sz]e)|table)\b/i;
const AGGREGATE_RE = /\b(?:count|count_big|sum|avg|min|max|stdev|stdevp|var|varp|stddev\w*|variance|bool_and|bool_or|every|bit_and|bit_or|approx_count_distinct|checksum_agg)\s*\(/gi;
const ROW_PACKING_RE = /\b(?:string_agg|array_agg|json_agg|jsonb_agg|json_object_agg|xmlagg|group_concat|listagg|array\s*\(|concat_ws)\s*\(?|\bfor\s+(?:xml|json)\b/i;

/** Paren depth at each index of a masked text. */
function depths(text) {
  const d = new Array(text.length);
  let level = 0;
  for (let i = 0; i < text.length; i++) {
    if (text[i] === '(') { d[i] = level; level++; continue; }
    if (text[i] === ')') { level = Math.max(0, level - 1); d[i] = level; continue; }
    d[i] = level;
  }
  return d;
}

/** Matches of `re` (global) at paren depth 0 of a masked text. */
const atTop = (text, re, dep = depths(text)) => [...text.matchAll(re)].filter((m) => dep[m.index] === 0);

/**
 * Whether one query statement returns a bounded result: one row (an aggregate without GROUP BY, or no FROM at all), or
 * TOP / LIMIT / FETCH FIRST up to maxRows at the outer level. Set operators need every branch bounded or an outer
 * LIMIT. Window functions (OVER) and row-packing functions (STRING_AGG, FOR XML) never count as a bound.
 */
function bounded(stmt, maxRows) {
  const dep = depths(stmt);
  if (/\bwith\s+ties\b/i.test(stmt) || atTop(stmt, /\blimit\s+all\b/gi, dep).length) return false;
  const setOps = atTop(stmt, /\b(?:union|intersect|except|minus)\b/gi, dep);
  const lastOp = setOps.length ? setOps[setOps.length - 1].index : -1;
  // An outer LIMIT / FETCH bounds the whole statement only after the last set operator.
  // MySQL's LIMIT offset, count counts the second number.
  const outerLimit = [...atTop(stmt, /\blimit\s+(\d+)(?:\s*,\s*(\d+))?/gi, dep), ...atTop(stmt, /\bfetch\s+(?:first|next)\s+(\d+)\s+rows?\s+only\b/gi, dep)]
    .filter((m) => m.index > lastOp);
  if (atTop(stmt, /\blimit\s+(?!\d)/gi, dep).length) return false; // LIMIT ALL, LIMIT (SELECT ...), LIMIT @n
  if (outerLimit.length && outerLimit.every((m) => Number(m[2] ?? m[1]) <= maxRows)) return true;
  if (/\bover\s*\(/i.test(stmt)) return false;
  if (setOps.length) {
    let start = 0;
    const branches = [];
    for (const op of setOps) { branches.push(stmt.slice(start, op.index)); start = op.index + op[0].length; }
    branches.push(stmt.slice(start));
    return branches.every((b) => branchBounded(b, maxRows));
  }
  return branchBounded(stmt, maxRows);
}

function branchBounded(stmt, maxRows) {
  const dep = depths(stmt);
  const tops = atTop(stmt, /\btop\s*(?:\(\s*(\d+)\s*\)|(\d+))(\s+percent\b)?/gi, dep);
  if (tops.length) return tops.every((m) => !m[3] && Number(m[1] ?? m[2]) <= maxRows);
  if (/\btop\b/i.test(stmt.replace(/\btop\s*(?:\(\s*\d+\s*\)|\d+)/gi, ' '))) return false; // TOP (@n), TOP (SELECT ...)
  if (atTop(stmt, /\bgroup\s+by\b/gi, dep).length) return false;
  const selects = atTop(stmt, /\bselect\b/gi, dep);
  if (!selects.length) return /^\s*\(*\s*(?:show|explain)\b/i.test(stmt);
  const tail = stmt.slice(selects[selects.length - 1].index); // after a CTE's bodies: the outer query
  const tailDep = depths(tail);
  const from = atTop(tail, /\bfrom\b/gi, tailDep)[0];
  if (!from) return true; // no FROM: one row of expressions
  const list = tail.slice(0, from.index);
  // SELECT DISTINCT returns many rows; DISTINCT inside a call (COUNT(DISTINCT x), SUM(DISTINCT x)) is still one row.
  if (atTop(list, /\bdistinct\b/gi).length) return false;
  // One row: an aggregate of the outer query, also inside another call (ROUND(SUM(x), 2)); one inside a scalar
  // subquery of the list does not count (SELECT (SELECT MAX(x) FROM t2), a FROM t returns every row of t).
  return new RegExp(AGGREGATE_RE.source, 'i').test(withoutSubqueries(list));
}

/** A masked text with every parenthesised subquery "(SELECT ...)" blanked out. */
function withoutSubqueries(text) {
  let out = text;
  for (;;) {
    const m = /\(\s*(?:select|with)\b/i.exec(out);
    if (!m) return out;
    let level = 0;
    let j = m.index;
    for (; j < out.length; j++) {
      if (out[j] === '(') level++;
      else if (out[j] === ')' && --level === 0) break;
    }
    out = `${out.slice(0, m.index)} ${out.slice(j + 1)}`;
  }
}

/**
 * Personal identifiers a statement names: the config list, *email / *phone, a person word + name, the multilingual
 * vocabulary (personalColumnName) read on the statement folded to ASCII, SELECT *.
 */
function personalIn(stmt, personal, dialect) {
  const found = new Set();
  const judged = new Map(); // each name once: a long text repeats the same names
  for (const m of asciiOf(stmt).matchAll(/[A-Za-z_][\w$#]*/g)) {
    if (!judged.has(m[0])) judged.set(m[0], personalColumnName(m[0], personal));
    if (judged.get(m[0])) found.add(m[0].replace(/^qi__/i, ''));
  }
  // Every column at once: SELECT *, t.*, TABLE t, and a "*" that is a select item anywhere (TOP 10 1, *; DISTINCT
  // ON (x) *). A "*" before FROM, a comma or the end is a select item; multiplication has an operand there.
  const noCount = stmt
    .replace(/\b(?:count|count_big)\s*\(\s*(?:all\s+|distinct\s+)?\*\s*\)/gi, ' ')
    .replace(/\bexists\s*\(\s*select\s+\*/gi, 'exists (select 1');
  if (/\bselect\b(?:\s+(?:distinct|all))?(?:\s+top\s*\(?\s*\d+\s*\)?(?:\s+percent)?)?\s*\*|[\w)]\s*\.\s*\*|\btable\s+\w|\*\s*(?:,|\bfrom\b|$)/i.test(noCount)) found.add('*');
  // Rows per person: a person word after GROUP BY / PARTITION BY / ORDER BY (one scan from the first one).
  const by = /\b(?:group|partition|order)\s+by\b/i.exec(stmt);
  if (by) {
    for (const w of stmt.slice(by.index).matchAll(/[A-Za-z_]\w*/g)) if (PERSON_WORD_RE.test(w[0].toLowerCase()) && !/^(?:asc|desc)$/i.test(w[0])) found.add(w[0].replace(/^qi__/i, ''));
  }
  // PostgreSQL returns a whole row for a bare table name or alias in the select list (SELECT c FROM customer c).
  if (dialect === 'psql') for (const w of wholeRows(stmt)) found.add(`${w} (a whole row)`);
  return [...found];
}

const NOT_ALIAS = new Set(['where', 'join', 'inner', 'left', 'right', 'full', 'cross', 'outer', 'on', 'group', 'order', 'having',
  'union', 'except', 'intersect', 'minus', 'limit', 'offset', 'fetch', 'window', 'natural', 'using', 'lateral', 'tablesample',
  'with', 'for', 'option', 'pivot', 'unpivot', 'apply', 'as', 'select', 'from', 'and', 'or', 'not', 'then', 'else', 'end', 'when', 'over']);
const IDENT = String.raw`[A-Za-z_][\w$]*`;
const FROM_NAME_RE = new RegExp(String.raw`\b(?:from|join)\s+(${IDENT}(?:\s*\.\s*${IDENT})*)(?:\s+(?:as\s+)?(${IDENT}))?`, 'gi');
const SELECT_ITEM_RE = new RegExp(String.raw`^(${IDENT})(?:\s+(?:as\s+)?${IDENT})?$`, 'i');

/** Bare table names or aliases a select list names as an item (each one a whole row in PostgreSQL). */
function wholeRows(stmt) {
  const names = new Set();
  for (const m of stmt.matchAll(FROM_NAME_RE)) {
    names.add(identKey(m[1].split('.').pop()));
    if (m[2] && !NOT_ALIAS.has(m[2].toLowerCase())) names.add(identKey(m[2]));
  }
  for (const m of stmt.matchAll(new RegExp(String.raw`\)\s*(?:as\s+)?(${IDENT})`, 'gi'))) {
    if (!NOT_ALIAS.has(m[1].toLowerCase())) names.add(identKey(m[1]));
  }
  if (!names.size) return [];
  const selects = [...stmt.matchAll(/\bselect\b/gi)];
  if (selects.length > 100) return ['(more subqueries than the guard checks)'];
  const dep = depths(stmt);
  const froms = [...stmt.matchAll(/\bfrom\b/gi)];
  const found = [];
  for (const sel of selects) {
    const base = dep[sel.index];
    let end = stmt.length;
    const from = froms.find((f) => f.index > sel.index && dep[f.index] === base);
    if (from) end = from.index;
    for (let k = sel.index; k < end; k++) if (stmt[k] === ')' && dep[k] < base) { end = k; break; }
    const list = stmt.slice(sel.index + 6, end)
      .replace(/^\s*distinct\s+on\s*\([^)]*\)/i, ' ').replace(/^\s*(?:distinct|all)\b/i, ' ')
      .replace(/^\s*top\s*(?:\(\s*\d+\s*\)|\d+)(?:\s+percent)?(?:\s+with\s+ties)?/i, ' ');
    const listDep = depths(list);
    let start = 0;
    const items = [];
    for (let k = 0; k <= list.length; k++) {
      if (k === list.length || (list[k] === ',' && listDep[k] === 0)) { items.push(list.slice(start, k).trim()); start = k + 1; }
    }
    for (const item of items) {
      const m = SELECT_ITEM_RE.exec(item);
      if (m && names.has(identKey(m[1]))) found.push(m[1].replace(/^qi__/i, ''));
    }
  }
  return found;
}

// Calls a read query may make: built-in aggregate, window, conversion, date, string, math and metadata functions of
// T-SQL and PostgreSQL that read nothing else and change nothing (and type names written like calls, decimal(10,2)).
// Any other call is the user's: in PostgreSQL a function can write or reach out (pg_*, dblink, a user function), in SQL
// Server a function can call an extended procedure, and generate_series or a cross join of calls can run for hours.
const KNOWN_FUNCTIONS = new Set(`count count_big sum avg min max stdev stdevp var varp stddev stddev_pop stddev_samp variance
  var_pop var_samp bool_and bool_or every bit_and bit_or approx_count_distinct checksum_agg grouping grouping_id
  percentile_cont percentile_disc row_number rank dense_rank ntile lag lead first_value last_value cume_dist percent_rank
  cast convert try_cast try_convert parse try_parse coalesce isnull nullif iif choose greatest least
  round floor ceiling ceil abs sign power sqrt square exp log log10 ln mod div trunc pi
  year month day datepart datename datefromparts datetimefromparts eomonth dateadd datediff datediff_big datetrunc
  date_bucket isdate getdate getutcdate sysdatetime sysutcdatetime sysdatetimeoffset date_trunc date_part extract now
  current_date to_char to_date to_number to_timestamp make_date make_timestamp age date
  lower upper len length char_length character_length datalength trim ltrim rtrim btrim left right substring substr
  replace concat format charindex patindex position strpos replicate repeat reverse stuff space str quotename translate
  lpad rpad initcap split_part isnumeric
  decimal numeric varchar nvarchar char nchar varbinary binary float real datetime2 datetimeoffset time timestamp
  timestamptz interval bit character
  db_name object_id object_name schema_name serverproperty current_database version newid rand random`.split(/\s+/).filter(Boolean));
// Words that stand before a parenthesis without being a call.
const NOT_FUNCTIONS = new Set(`in exists values over as from join on and or not top select where when then else case any
  all some using filter within group lateral apply union except intersect minus by having limit offset fetch is between
  like ilike with set rows range partition order distinct into table end recursive nulls only cross outer inner full
  natural escape row array tablesample pivot unpivot for of at zone desc asc option sets cube rollup contains freetext
  containstable freetexttable returning`.split(/\s+/).filter(Boolean));
// A name followed by "(" is a call, except an alias with its column list: AS p (a, b), ) p (a, b), WITH c (a) AS.
const CALL_RE = new RegExp(String.raw`(?<![\w$#@.])(?<!\bas\s+)(?<!\bwith\s+)(?<!\)\s*)(${IDENT}(?:\s*\.\s*${IDENT})*)\s*\(`, 'gi');

/** Calls in a masked statement that are not known built-in functions. */
function unknownCalls(stmt) {
  const out = new Set();
  for (const m of stmt.matchAll(CALL_RE)) {
    const name = m[1].replace(/\s+/g, '').toLowerCase();
    if (!NOT_FUNCTIONS.has(name) && !KNOWN_FUNCTIONS.has(name)) out.add(m[1].replace(/\s+/g, '').replace(/qi__/gi, ''));
  }
  return [...out];
}

const preview = (s, n = 80) => {
  const t = String(s).replace(/\s+/g, ' ').trim();
  return t.length > n ? `${t.slice(0, n - 1)}…` : t;
};

/**
 * Judges one SQL text. Returns { kind: 'deny' | 'floor' | 'read', reason, statements, unbounded, personal, preview }.
 * `client` is "tsql" (the sqlcmd family), "psql" or "any" (a SQL MCP server, dialect unknown); client commands of
 * sqlcmd and psql are judged too.
 */
export function judgeSql(sql, { client = 'tsql', maxRows = 50, personal = DEFAULT_PERSONAL } = {}) {
  const text = String(sql ?? '');
  if (text.length > MAX_SQL_TEXT) {
    // Too long to read in full; its writes are still looked for (linear), so a write is denied, not only asked about.
    const write = writeInRawText(text);
    if (write) return { kind: 'deny', reason: `${write} (a text longer than ${MAX_SQL_TEXT / 1024} KB is read only for writes)` };
    return { kind: 'floor', reason: `the query text is longer than ${MAX_SQL_TEXT / 1024} KB, which the guard does not analyse` };
  }
  if (client === 'any' && text.includes('/*!')) return { kind: 'floor', reason: 'a MySQL executable comment (/*! ... */) that the server runs as SQL' };
  // T-SQL has one reading of a string; PostgreSQL two (E'..' only, or every string with backslash escapes, the old
  // setting); a SQL MCP server ("any") may be T-SQL, PostgreSQL or MySQL. Every reading is judged and the strictest
  // verdict wins.
  const readings = READINGS[client] ?? READINGS.any;
  const results = readings.map((r) => judgeOne(text, { ...r, client, maxRows, personal }));
  const worst = results.find((r) => r.kind === 'deny') ?? results.find((r) => r.kind === 'floor');
  if (worst) return worst;
  return {
    ...results[0],
    unbounded: [...new Set(results.flatMap((r) => r.unbounded))],
    personal: [...new Set(results.flatMap((r) => r.personal))],
  };
}
const READINGS = {
  tsql: [{ dialect: 'tsql', backslash: 'none' }],
  psql: [{ dialect: 'psql', backslash: 'estrings' }, { dialect: 'psql', backslash: 'all' }],
};
READINGS.any = [...READINGS.tsql, ...READINGS.psql, { dialect: 'mysql', backslash: 'all' }];

// Words that start a result set (WITH, EXPLAIN and SHOW lead into one or are one; they are not counted twice).
const QUERY_WORD_RE = /\b(?:select|values|table)\b/gi;
const SET_OP_RE = /\b(?:union|intersect|except|minus)\b/gi;

function judgeOne(text, { client, dialect, backslash, maxRows, personal }) {
  if (!text.trim()) return { kind: 'floor', reason: 'the query text is empty' };
  // Denies first, over the whole text: a later write is never hidden behind an earlier statement that only asks.
  // Client commands: sqlcmd's "!!" and ":!!" run the operating system, psql's "\!" a shell.
  if (/^[ \t]*(?::[ \t]*)?!!/m.test(text)) return { kind: 'deny', reason: 'sqlcmd "!!" runs an operating system command' };
  if (/\\!/.test(text)) return { kind: 'deny', reason: 'psql "\\!" runs a shell command' };
  // sqlcmd splits batches at GO lines before the server reads any quote: a GO inside a string or a bracket still ends
  // the batch there. Each batch is masked on its own, so a quote can never carry a statement across a GO.
  const batches = dialect === 'tsql' ? text.split(GO_LINE_RE) : [text];
  // A text the masking cannot finish (an unterminated quote or comment) is read up to that point for the deny check,
  // then asks: a write before the unreadable part is denied, not only asked about.
  const parts = [];
  let maskError = null;
  for (const batch of batches) {
    const { text: m, error } = maskSql(batch, { backslash, dialect });
    parts.push(m);
    maskError ??= error;
  }
  const masked = parts.join('\n;\n');
  const statements = statementsOf(masked);
  for (const st of statements) {
    const rest = LOCAL_WRITE_RE.test(st) ? st.replace(LOCAL_WRITE_RE, ' ') : st;
    if (DENY_STATEMENT_RE.test(rest)) return { kind: 'deny', reason: `the statement "${preview(st)}" changes data, schema, permissions or the server` };
  }
  if (maskError) return { kind: 'floor', reason: `${maskError} in the query` };
  // Then what the guard cannot follow: sqlcmd's ":r", ":connect", ":out", ":setvar" and scripting variables, psql's
  // backslash commands and variables.
  if (/^[ \t]*:[ \t]*[a-z]/im.test(text)) return { kind: 'floor', reason: 'a sqlcmd command (":r", ":connect", ":out", ":setvar", ...) the guard does not follow' };
  if (/\$\(/.test(text)) return { kind: 'floor', reason: 'a sqlcmd scripting variable $(...) whose value the guard cannot see' };
  if (/\\[a-z]/i.test(masked)) return { kind: 'floor', reason: 'a psql meta-command (\\copy, \\o, \\i, \\gexec, \\set, \\connect, ...) the guard does not follow' };
  if (client === 'psql' && /(?:^|[^:\w]):['"]?[A-Za-z_]/.test(masked)) return { kind: 'floor', reason: 'a psql variable (:name) whose value the guard cannot see' };
  if (!statements.length) return { kind: 'floor', reason: 'no statement in the query text' };
  const unbounded = [];
  const named = new Set();
  let reads = 0;
  for (const st of statements) {
    if (ROW_PACKING_RE.test(st)) return { kind: 'floor', reason: `the statement "${preview(st)}" packs many rows into one value (STRING_AGG, FOR XML, ...)` };
    const local = LOCAL_WRITE_RE.test(st);
    const rest = local ? st.replace(LOCAL_WRITE_RE, ' ') : st;
    if (FLOOR_STATEMENT_RE.test(rest)) return { kind: 'floor', reason: `the statement "${preview(st)}" runs code the guard cannot see into (EXEC, a procedure, a cursor, a loop, a remote, linked-server or file call, a lock, a sequence)` };
    const calls = unknownCalls(st);
    if (calls.length) return { kind: 'floor', reason: `the statement calls ${calls.slice(0, 3).join(', ')}, which is not a built-in function the guard knows: a function can change data or reach out` };
    // T-SQL needs no ";" between statements: one statement text may hold several. Count the queries at the outer level
    // (a UNION joins two into one; a CTE body sits in parentheses); a write or setting may carry none, a query one.
    const dep = depths(rest);
    const queries = atTop(rest, QUERY_WORD_RE, dep).length - atTop(rest, SET_OP_RE, dep).length;
    for (const p of personalIn(st, personal, dialect)) named.add(p);
    if (local) {
      if (queries > (/^\s*insert\b/i.test(st) ? 1 : 0)) return { kind: 'floor', reason: `the statement "${preview(st)}" holds more than one statement (separate them with ";")` };
      continue;
    }
    if (NEUTRAL_STATEMENT_RE.test(st)) {
      if (queries > 0) return { kind: 'floor', reason: `the statement "${preview(st)}" holds more than one statement (separate them with ";")` };
      continue;
    }
    if (!QUERY_START_RE.test(st)) return { kind: 'floor', reason: `the statement "${preview(st)}" is not a plain query the guard recognises` };
    if (queries > 1) return { kind: 'floor', reason: `the statement "${preview(st)}" holds more than one query (separate them with ";")` };
    reads++;
    if (!bounded(st, maxRows)) unbounded.push(preview(st));
  }
  if (!reads) return { kind: 'floor', reason: 'the text reads nothing (no query statement)' };
  return { kind: 'read', statements: statements.length, reads, unbounded, personal: [...named], preview: preview(masked, 200) };
}

// ---------------------------------------------------------------- SQL clients on the command line

export const CREDENTIAL_ENV_RE = /\b(?:SQLCMDPASSWORD|PGPASSWORD|PGPASSFILE)\b/i;
export const STARTUP_ENV_RE = /\b(?:SQLCMDINI|SQLCMDSERVER|SQLCMDUSER|SQLCMDDBNAME|SQLCMDMAXVARTYPEWIDTH|PSQLRC|PGSERVICE|PGSERVICEFILE|PGHOST|PGHOSTADDR|PGOPTIONS|PGDATABASE)\b/i;
const MAX_SQL_FILE = 32 * 1024;

// Options per client (case matters for short options, as the clients read them). values: options that take a value;
// flags: options without one; deny / floor: options with that verdict; query / file / server: what the value is.
const CLIENT_SPECS = {
  tsql: {
    values: ['-S', '-U', '-d', '-Q', '-q', '-i', '-o', '-v', '-l', '-t', '-h', '-s', '-w', '-y', '-Y', '-f', '-c', '-a', '-H', '-K', '-F', '-P', '-z', '-Z',
      '--server', '--query', '--input-file', '--database', '--user-name', '--password'],
    flags: ['-E', '-x', '-X', '-b', '-m', '-V', '-r', '-R', '-C', '-N', '-W', '-I', '-G', '-g', '-M', '-u', '-j', '-p', '-k', '-e', '-A', '-L', '-?', '--help', '--version'],
    deny: { '-P': 'a password on the command line (-P)', '-z': 'a password change (-z)', '-Z': 'a password change (-Z)', '--password': 'a password on the command line' },
    floor: { '-o': 'the output goes to a file (-o)', '-A': 'a dedicated administrator connection (-A)', '-L': 'a scan for servers on the network (-L)', '-v': 'scripting variables (-v) change the query text at run time',
      '-q': 'sqlcmd -q stays open after the query and runs whatever stdin sends (use -Q)' },
    query: ['-Q', '-q', '--query'], file: ['-i', '--input-file'], server: ['-S', '--server'],
  },
  psql: {
    values: ['-h', '-p', '-U', '-d', '-c', '-f', '-F', '-R', '-T', '-o', '-L', '-v', '-P',
      '--host', '--port', '--username', '--dbname', '--command', '--file', '--field-separator', '--record-separator', '--table-attr', '--output', '--log-file', '--set', '--variable', '--pset'],
    flags: ['-X', '-A', '-t', '-q', '-w', '-W', '-1', '-e', '-E', '-a', '-b', '-n', '-x', '-z', '-0', '-H', '-S', '-s',
      '--no-psqlrc', '--no-align', '--tuples-only', '--quiet', '--no-password', '--password', '--single-transaction', '--echo-queries', '--echo-hidden', '--echo-all', '--echo-errors', '--no-readline', '--expanded', '--html', '--single-line', '--single-step', '--csv', '--help', '--version'],
    deny: {},
    floor: { '-o': 'the output goes to a file (-o)', '--output': 'the output goes to a file', '-L': 'a log file (-L)', '--log-file': 'a log file',
      '-v': 'psql variables (-v) change the query text at run time', '--set': 'psql variables change the query text at run time', '--variable': 'psql variables change the query text at run time',
      '-P': 'a print option (-P) can start a pager', '--pset': 'a print option can start a pager', '-s': 'single-step mode waits for input', '--single-step': 'single-step mode waits for input', '-W': 'a password prompt', '--password': 'a password prompt' },
    query: ['-c', '--command'], file: ['-f', '--file'], server: ['-h', '--host'],
  },
};

/**
 * Parses a client's arguments by its spec. Unknown options are problems (the guard cannot follow). With `bundles`
 * (psql reads its options with getopt) a cluster such as -XAt is several flags, and a value option ends it (-Xc "..").
 */
function parseOptions(spec, args, { bundles = false } = {}) {
  const found = { query: [], file: [], server: [], positional: [], dbnames: [], problems: [], deny: null, all: [] };
  const expanded = [];
  for (const a of args) {
    if (bundles && /^-[A-Za-z0-9]{2,}$/.test(a) && spec.flags.includes(a.slice(0, 2))) {
      let k = 1;
      for (; k < a.length && spec.flags.includes(`-${a[k]}`); k++) expanded.push(`-${a[k]}`);
      if (k < a.length) expanded.push(`-${a.slice(k)}`); // a value option with its value attached, or an unknown rest
      continue;
    }
    expanded.push(a);
  }
  args = expanded;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (!a.startsWith('-') || a === '-') { found.positional.push(a); continue; }
    let name = a;
    let value;
    if (a.startsWith('--') && a.includes('=')) { name = a.slice(0, a.indexOf('=')); value = a.slice(a.indexOf('=') + 1); }
    else if (!a.startsWith('--') && a.length > 2 && spec.values.includes(a.slice(0, 2))) { name = a.slice(0, 2); value = a.slice(2); }
    if (spec.deny[name]) { found.deny = spec.deny[name]; continue; }
    const known = spec.values.includes(name) || spec.flags.includes(name);
    if (!known) { found.problems.push(`an option the guard does not know (${a})`); continue; }
    if (spec.values.includes(name) && value === undefined) {
      if (i + 1 >= args.length) { found.problems.push(`${name} without a value`); continue; }
      value = args[++i];
    }
    if (spec.floor[name]) found.problems.push(spec.floor[name]);
    found.all.push(name);
    if (spec.query.includes(name)) found.query.push(value);
    if (spec.file.includes(name)) found.file.push(value);
    if (spec.server.includes(name)) found.server.push(value);
    if (name === '-d' || name === '--dbname') found.dbnames.push(value);
  }
  return found;
}

/**
 * Reads a query file named on the command line: a .sql file inside the project, not too large; else an error. Only
 * .sql files are read, so no other file (.env, a key) ever reaches a reason or the log.
 */
function readSqlFile(file, baseDir) {
  const name = String(file ?? '');
  if (!name || name === '-' || /[*?]/.test(name)) return { error: `the input "${name}" is stdin or a wildcard` };
  if (!/\.sql$/i.test(name)) return { error: 'the input file is not a .sql file' };
  const abs = path.resolve(baseDir ?? PROJECT_DIR, name);
  if (projectRel(abs) === null) return { error: `the input file ${name} is outside the project` };
  try {
    const st = fs.statSync(abs);
    if (!st.isFile() || st.size > MAX_SQL_FILE) return { error: `the input file ${name} is not a readable file under ${MAX_SQL_FILE / 1024} KB` };
    return { text: fs.readFileSync(abs, 'utf8').replace(/^﻿/, '') };
  } catch {
    return { error: `the input file ${name} cannot be read` };
  }
}

// Invoke-Sqlcmd parameters (PowerShell: case-insensitive, `-Name value` or `-Name:value`). Abbreviations are not
// followed: an unknown name is a problem, so a shortened -InputFile can never hide a file next to a judged -Query; a
// shortened credential parameter is denied like the full name.
const PS_VALUE = new Set(['serverinstance', 'database', 'query', 'inputfile', 'connectionstring', 'querytimeout', 'connectiontimeout',
  'hostnameincertificate', 'applicationname', 'applicationintent', 'maxcharlength', 'maxbinarylength', 'errorlevel', 'severitylevel',
  'outputas', 'encrypt', 'username', 'workstationid', 'statisticsvariable', 'erroraction', 'warningaction', 'informationaction']);
const PS_FLAG = new Set(['trustservercertificate', 'abortonerror', 'includesqlusererrors', 'suppressprovidercontextwarning', 'ignoreprovidercontext',
  'outputsqlerrors', 'disablevariables', 'disablecommands', 'multisubnetfailover', 'verbose', 'debug']);
const PS_DENY = { password: 'a password on the command line', credential: 'a credential on the command line', accesstoken: 'an access token on the command line', newpassword: 'a password change' };
const PS_FLOOR = { variable: '-Variable changes the query text at run time', dedicatedadministratorconnection: 'a dedicated administrator connection' };

function parseInvokeSqlcmd(args) {
  const found = { query: [], file: [], server: [], problems: [], deny: null, connection: [] };
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (!a.startsWith('-')) { found.problems.push(`a positional argument (${a}) the guard does not follow`); continue; }
    const m = /^-([A-Za-z]+)(?::(.*))?$/.exec(a);
    if (!m) { found.problems.push(`an argument the guard does not know (${a})`); continue; }
    const name = m[1].toLowerCase();
    if (PS_DENY[name]) { found.deny = PS_DENY[name]; continue; }
    // PowerShell takes any unambiguous prefix of a parameter name (-Pass is -Password, -Cred is -Credential).
    const secretPrefix = !PS_VALUE.has(name) && !PS_FLAG.has(name) && !PS_FLOOR[name] && Object.keys(PS_DENY).find((k) => k.startsWith(name));
    if (secretPrefix) { found.deny = PS_DENY[secretPrefix]; continue; }
    let value = m[2];
    if (PS_VALUE.has(name) || PS_FLOOR[name]) {
      if (value === undefined && PS_VALUE.has(name)) value = args[++i];
      if (PS_FLOOR[name]) { found.problems.push(PS_FLOOR[name]); if (value === undefined) i++; continue; }
    } else if (!PS_FLAG.has(name)) { found.problems.push(`a parameter the guard does not know (-${m[1]})`); continue; }
    if (name === 'query') found.query.push(value);
    if (name === 'inputfile') found.file.push(value);
    if (name === 'serverinstance') found.server.push(value);
    if (name === 'connectionstring') found.connection.push(value);
  }
  return found;
}

// A shell or PowerShell expansion the guard cannot read: $name, ${...}, $env:NAME, a positional or special parameter
// ($1, $@, $?, $$), a backtick (bash command substitution). The shell replaces it before the client starts, so the
// text that runs is not the text the guard judged. ($(...) is a floor of its own in judgeOne.)
const SHELL_EXPANSION_RE = /\$(?:\{|env:|[A-Za-z_0-9@*#?!$-])|`/i;
// In a connection string or conninfo also a PowerShell subexpression $(...), a cmd %NAME% and a backtick: any of them can
// add a server key that the allow-list never sees (SqlClient uses the last Server= key).
const CONNECTION_EXPANSION_RE = /\$(?:[{(]|env:|[A-Za-z_0-9@*#?!$-])|%[A-Za-z_][^%\s;]*%|`/i;

/**
 * A psql text without its dollar-quote delimiters ($$ and $tag$, where PostgreSQL opens one and finds the matching end),
 * so that a body such as $$DELETE FROM t$$ is not read as the variable $DELETE; `quoted` says whether there was one.
 * What the bodies hold stays in the text: the shell expands them as it expands everything else.
 */
function withoutDollarQuotes(text) {
  const open = /(?<![\w$])\$(?:[A-Za-z_]\w*)?\$/g;
  let out = '';
  let from = 0;
  for (let m = open.exec(text); m; m = open.exec(text)) {
    const end = text.indexOf(m[0], m.index + m[0].length);
    if (end < 0) continue; // never closed: the masking reports it
    out += `${text.slice(from, m.index)} ${text.slice(m.index + m[0].length, end)} `;
    from = end + m[0].length;
    open.lastIndex = from;
  }
  return { text: out + text.slice(from), quoted: from > 0 };
}

/**
 * True when the shell expands nothing in a command line: its quoting is plain (no double quote, backslash or backtick)
 * and every "$" stands inside single quotes. Anything unclear is not literal.
 */
const shellLiteral = (sub) => !/["`\\]/.test(String(sub ?? '')) && !String(sub ?? '').replace(/'[^']*'/g, '').includes('$');

// ---------------------------------------------------------------- psql connections (libpq, fe-connect.c)

const CONNINFO_BLANK = new Set([' ', '\t', '\n', '\r', '\v', '\f']);
// Windows hands a command line to psql in its code page and maps a character outside it to a look-alike (a full-width
// "＝" becomes "="), so the guard cannot tell what psql reads from a connection argument with one.
const NON_ASCII_RE = /[^\t-\r\x20-\x7e]/;
const NON_ASCII_PROBLEM = 'a character outside ASCII in a connection argument, which psql may read as another character (Windows code pages)';

/**
 * The keyword/value pairs of a libpq connection string ("host=a dbname='b c'") as conninfo_parse reads them, or { error }:
 * a keyword runs to "=" or a blank, blanks may stand around "=", a value is single-quoted or runs to the next blank, a
 * backslash takes the next character as it is, and the next keyword may follow a closing quote without a blank.
 */
function conninfoPairs(s) {
  const pairs = [];
  let i = 0;
  const blanks = () => { while (i < s.length && CONNINFO_BLANK.has(s[i])) i++; };
  for (;;) {
    blanks();
    if (i >= s.length) return { pairs };
    let key = '';
    while (i < s.length && s[i] !== '=' && !CONNINFO_BLANK.has(s[i])) key += s[i++];
    blanks();
    if (!key || s[i] !== '=') return { error: `no keyword=value at "${preview(key || s.slice(i), 20)}"` };
    i++;
    blanks();
    let value = '';
    if (s[i] === "'") {
      for (i++; ; ) {
        if (i >= s.length) return { error: 'an unterminated quoted value' };
        if (s[i] === '\\') { i++; if (i < s.length) value += s[i++]; continue; }
        if (s[i] === "'") { i++; break; }
        value += s[i++];
      }
    } else {
      while (i < s.length && !CONNINFO_BLANK.has(s[i])) {
        if (s[i] === '\\') i++;
        if (i < s.length) value += s[i++];
      }
    }
    pairs.push([key, value]);
  }
}

/**
 * The parameters of a postgresql:// URI as conninfo_uri_parse_options reads it, or { error } / { deny }: a user up to the
 * first "@" before any "/", then hosts (name[:port] or [IPv6][:port], separated by ","), returned as one "host" pair, a
 * database after "/" and keyword=value parameters after "?". libpq decodes %XX in the hosts and in parameter names (it
 * can spell "host" or ","), so a percent sign there is not read.
 */
function uriPairs(c) {
  let rest = c.replace(/^postgres(?:ql)?:\/\//i, '');
  const at = rest.search(/[@/]/);
  if (at >= 0 && rest[at] === '@') {
    if (rest.slice(0, at).includes(':')) return { deny: 'a password in the connection URI' };
    rest = rest.slice(at + 1);
  }
  const hosts = [];
  let i = 0;
  for (;;) {
    if (rest[i] === '[') {
      const end = rest.indexOf(']', i);
      if (end < 0) return { error: 'an unterminated "[" in the URI' };
      hosts.push(rest.slice(i + 1, end));
      i = end + 1;
      if (i < rest.length && !':/?,'.includes(rest[i])) return { error: `"${rest[i]}" after an IPv6 address in the URI` };
    } else {
      const start = i;
      while (i < rest.length && !':/?,'.includes(rest[i])) i++;
      hosts.push(rest.slice(start, i));
    }
    if (rest[i] === ':') while (i < rest.length && !'/?,'.includes(rest[i])) i++; // the port
    if (rest[i] !== ',') break;
    i++;
  }
  const hostText = hosts.join(',');
  if (rest[i] === '/') while (i < rest.length && rest[i] !== '?') i++; // the database name
  const query = rest[i] === '?' ? rest.slice(i + 1) : '';
  if (hostText.includes('%') || query.includes('%')) return { error: 'a percent-encoded character in the URI hosts or parameters' };
  const pairs = hostText ? [['host', hostText]] : [];
  const params = query.split('&');
  if (params[params.length - 1] === '') params.pop(); // libpq allows one "&" at the end
  for (const param of params) {
    const kv = param.split('=');
    if (kv.length !== 2) return { error: `the URI parameter "${preview(param, 20)}" is not one keyword=value` };
    pairs.push(kv);
  }
  return { pairs };
}

/** The entries of a libpq host or hostaddr list ("a,b"; libpq tries each one in turn); an empty one is libpq's default. */
function hostEntries(value, key) {
  const out = { servers: [], problems: [] };
  for (const h of String(value).split(',')) {
    if (h.trim()) out.servers.push(h);
    else out.problems.push(`an empty ${key} entry, which libpq replaces by a default server the guard cannot see`);
  }
  return out;
}

/**
 * The servers a psql connection argument (a -d value or a positional argument) can reach, with what keeps the guard from
 * knowing them, or { deny }. libpq reads it as a URI when it starts with postgresql:// or postgres://, as keyword=value
 * pairs when it holds "=", else as a database or user name. It connects to every host and hostaddr it names (a later key
 * wins, a list is tried in turn), so all of them are returned. The guard's words and bash's reading of them are parsed.
 */
function psqlConnection(value) {
  const out = { servers: [], problems: [] };
  const raw = String(value ?? '');
  if (NON_ASCII_RE.test(raw)) return { servers: [], problems: [NON_ASCII_PROBLEM] };
  for (const c of new Set([raw, raw.replace(/\\([\\"`$])/g, '$1')])) {
    const uri = /^postgres(?:ql)?:\/\//i.test(c);
    if (!uri && !c.includes('=')) continue;
    const parsed = uri ? uriPairs(c) : conninfoPairs(c);
    if (parsed.deny) return { deny: parsed.deny };
    if (parsed.error) { out.problems.push(`a connection string the guard cannot read (${parsed.error})`); continue; }
    for (const [key, val] of parsed.pairs) {
      const k = key.toLowerCase();
      if (k === 'password') return { deny: 'a password in the connection string' };
      if (k === 'service') out.problems.push('a connection service (service=) whose server the guard cannot see');
      if (k === 'host' || k === 'hostaddr') {
        const e = hostEntries(val, k);
        out.servers.push(...e.servers);
        out.problems.push(...e.problems);
      }
    }
  }
  return out;
}

// ---------------------------------------------------------------- Windows code pages (sqlcmd, osql, isql, psql)

// Windows may hand these clients their command line in the ANSI code page (a program that reads it as narrow text: psql
// for certain, the sqlcmd family not verified), and a "best fit" turns a character outside the code page into a
// look-alike: a full-width apostrophe (U+FF07) becomes "'", a full-width letter its ASCII letter, a curly quote or a dash
// its ASCII one in some code pages. The client then runs another text than the guard judged (a string literal ends where
// the guard saw none), and the command line may split into other arguments. Invoke-Sqlcmd (.NET), mssql-cli (Python) and
// SQL MCP servers receive Unicode and are not judged this way.
const CODE_PAGE_CLIENTS = new Set(['sqlcmd', 'osql', 'isql', 'psql']);
// A character outside ASCII that is not a letter, a digit or a combining mark (punctuation, a symbol, a blank, a format
// character), a modifier letter (U+02BC, U+02B9 look like quotes) or a click letter (U+01C0..U+01C3: bars and "!").
const CODE_PAGE_LOOKALIKE_RE = /[^\x00-\x7f\p{L}\p{M}\p{N}]|[\p{Lm}\u{1c0}-\u{1c3}]/u;
// ASCII other than a letter or digit: a letter or digit whose compatibility form holds one (U+2474 is "(1)") counts too.
const ASCII_PUNCTUATION_RE = /[\x00-\x2f\x3a-\x40\x5b-\x60\x7b-\x7f]/;
const CHARACTER_NAMES = {
  0xff07: 'a full-width apostrophe', 0xff02: 'a full-width quotation mark', 0x2018: 'a left single quotation mark',
  0x2019: 'a right single quotation mark', 0x201c: 'a left double quotation mark', 0x201d: 'a right double quotation mark',
  0x02bc: 'a modifier letter apostrophe', 0x2032: 'a prime', 0x00b4: 'an acute accent', 0xff3c: 'a full-width backslash',
  0x00a5: 'a yen sign', 0x20a9: 'a won sign', 0xff1b: 'a full-width semicolon', 0x2013: 'an en dash', 0x2014: 'an em dash',
  0x2212: 'a minus sign', 0x00a0: 'a no-break space', 0x3000: 'an ideographic space',
};
/** A character for a reason: its name where known, its code point, and the character itself when it is visible. */
function describeCharacter(c) {
  const cp = c.codePointAt(0);
  const visible = /^[\p{L}\p{N}\p{P}\p{S}]$/u.test(c) ? `, ${c}` : '';
  return `${CHARACTER_NAMES[cp] ?? 'the character'} (U+${cp.toString(16).toUpperCase().padStart(4, '0')}${visible})`;
}
/** The first character of a text that a code page may turn into ASCII punctuation or a blank, or null. */
function codePageLookalike(text) {
  for (const c of String(text ?? '')) {
    if (c <= '\x7f') continue;
    if (CODE_PAGE_LOOKALIKE_RE.test(c) || ASCII_PUNCTUATION_RE.test(c.normalize('NFKC'))) return c;
  }
  return null;
}
// Letters a best fit maps to an ASCII letter that have no Unicode decomposition: dotless i, L, D, H and T with a stroke, O
// with a stroke.
const LETTER_FOLDS = { '\u{131}': 'i', '\u{141}': 'L', '\u{142}': 'l', '\u{110}': 'D', '\u{111}': 'd', '\u{126}': 'H',
  '\u{127}': 'h', '\u{166}': 'T', '\u{167}': 't', '\u{d8}': 'O', '\u{f8}': 'o' };
const LETTER_FOLD_RE = new RegExp(`[${Object.keys(LETTER_FOLDS).join('')}]`, 'g');
/**
 * A text as a code page may hand it to the client: compatibility forms folded (a full-width letter or apostrophe is its
 * ASCII one), marks dropped (a D with caron is D, Satış is Satis), the letters above mapped. One plausible reading, not
 * every code page's: the look-alike check (codePageLookalike) asks for the punctuation whatever its reading.
 */
function codePageFold(text) {
  return String(text).normalize('NFKD').replace(/\p{M}/gu, '').replace(LETTER_FOLD_RE, (c) => LETTER_FOLDS[c]);
}
/** The first character of a text that codePageFold changes, or null. */
function firstFoldedCharacter(text) {
  for (const c of String(text ?? '')) if (codePageFold(c) !== c) return c;
  return null;
}

/** The servers, query texts and problems of one SQL client command line, or { deny }. */
function parseClient(prog, args, baseDir, cdSeen, sub) {
  const client = prog === 'psql' ? 'psql' : 'tsql';
  const p = prog === 'invoke-sqlcmd' ? parseInvokeSqlcmd(args) : parseOptions(CLIENT_SPECS[client], args, { bundles: client === 'psql' });
  if (p.deny) return { deny: p.deny };
  const problems = [...p.problems];
  const texts = [...p.query];
  const servers = client === 'psql' ? [] : [...p.server]; // psql: every entry of every -h, below
  // After a cd in the same command line the client reads its file from another folder than the guard would.
  if (cdSeen && p.file.length) problems.push('the command changes folder (cd) before the client reads its file, so the guard cannot tell which file runs');
  else for (const v of p.file) {
    for (const f of String(v ?? '').split(',').map((x) => x.trim()).filter(Boolean)) {
      const r = readSqlFile(f, baseDir);
      if (r.error) problems.push(r.error); else texts.push(r.text);
    }
  }
  for (const cs of p.connection ?? []) {
    if (/(?:^|;)\s*(?:password|pwd)\s*=/i.test(cs)) return { deny: 'a password in the connection string' };
    // SqlClient uses the last of several server keys: every one must be a listed server.
    for (const m of String(cs).matchAll(/(?:^|;)\s*(?:server|data\s+source|address|addr|network\s+address)\s*=\s*([^;]+)/gi)) servers.push(m[1]);
    if (CONNECTION_EXPANSION_RE.test(cs)) problems.push('a variable or expression in the connection string, whose value the guard cannot see (it can add a server)');
  }
  if (client === 'psql') {
    if (!p.all.includes('-X') && !p.all.includes('--no-psqlrc')) problems.push('psql reads ~/.psqlrc at start unless -X is given');
    // -h a,b: libpq tries each host of the list in turn (an empty -h is ignored: libpq's default, and no server named).
    for (const h of p.server) {
      if (!h) continue;
      const e = NON_ASCII_RE.test(h) ? { servers: [], problems: [NON_ASCII_PROBLEM] } : hostEntries(h, 'host');
      servers.push(...e.servers);
      problems.push(...e.problems);
    }
    // libpq connects to every host and hostaddr a connection string names (-d or the first positional overrides -h):
    // all of them must be listed servers (psqlConnection).
    for (const c of [...p.positional, ...p.dbnames]) {
      if (/(?:^|\s|[?&])password\s*=/i.test(c)) return { deny: 'a password in the connection string' };
      if (/(?:^|\s|[?&])service\s*=/i.test(c)) problems.push('a connection service (service=) whose server the guard cannot see');
      const conn = psqlConnection(c);
      if (conn.deny) return { deny: conn.deny };
      servers.push(...conn.servers);
      problems.push(...conn.problems);
      if (CONNECTION_EXPANSION_RE.test(c)) problems.push('a variable or expression in the connection string, whose value the guard cannot see (it can add a server)');
    }
  } else if (prog !== 'invoke-sqlcmd' && p.positional.length) {
    problems.push(`an argument the guard does not follow (${p.positional[0]})`);
  }
  // A shell variable in a query text: the shell expands it, in a string or comment too, before the client reads it. psql
  // reads $$ and $tag$ as quotes, not as variables; they stay literal only where the shell expands nothing.
  const dollars = texts.map((t) => (client === 'psql' ? withoutDollarQuotes(String(t ?? '')) : { text: String(t ?? ''), quoted: false }));
  if (dollars.some((d) => SHELL_EXPANSION_RE.test(d.text))) problems.push('a shell variable or substitution in the query text');
  else if (dollars.some((d) => d.quoted) && !shellLiteral(sub)) problems.push('a dollar quote ($$ or $tag$) in a command the shell may expand (single-quote the query)');
  if (prog === 'invoke-sqlcmd' && texts.length > 1) problems.push('more than one query source');
  // A look-alike in any argument (the query, a server, a database, a file name): Windows may hand it to the client as
  // ASCII punctuation, which can end a string literal or split the command line into other options (-o, -i).
  const lookalike = CODE_PAGE_CLIENTS.has(prog) ? args.map(codePageLookalike).find(Boolean) : null;
  if (lookalike) problems.push(`${describeCharacter(lookalike)} in an argument, which Windows may hand to ${prog} as an ASCII quote, punctuation or blank (a code page "best fit"), so the client may run another text than the guard judged`);
  if (!texts.length && !problems.length) problems.push('no query on the command line (interactive or stdin)');
  // texts holds the command line's queries first (p.query), then the files' texts.
  return { servers: [...new Set(servers.map(normalizeServer).filter(Boolean))], texts, queries: p.query.length, problems: [...new Set(problems)], client };
}

/**
 * Verdict for one SQL client subcommand. `ctx.sqlRead` is the config value (`cfg.sources.sqlRead`); without one (as in
 * tests that pass none) the switch is off. `ctx.cdSeen`: an earlier subcommand changed folder.
 */
export function analyzeSqlClient(prog, args, sub, ctx = {}) {
  const sw = sqlReadOf({ sources: { sqlRead: ctx.sqlRead } });
  if (CREDENTIAL_ENV_RE.test(sub)) return deny(`${prog}: a database password variable (SQLCMDPASSWORD, PGPASSWORD, PGPASSFILE) on the command line. Credentials stay with the user.`);
  const parsed = parseClient(prog, args, ctx.baseDir, ctx.cdSeen, sub);
  if (parsed.deny) return deny(`${prog}: ${parsed.deny}. Credentials stay with the user; never put one on a command line.`);
  // The guard's words keep a backslash as PowerShell does; bash turns \\ \" \$ \` inside double quotes into one
  // character. Both texts are judged, so a literal that ends earlier in bash cannot hide a statement.
  const texts = parsed.texts.flatMap((t) => {
    const bash = String(t ?? '').replace(/\\([\\"`$])/g, '$1');
    return bash === t ? [t] : [t, bash];
  });
  // A client that may read its command line through a Windows code page: each query on the command line (and its bash
  // twin) is judged again as the client may read it (codePageFold: DELETE in full-width letters or with a D with caron is
  // DELETE, a full-width apostrophe a quote). A file's text is read as bytes, without that conversion.
  const folded = new Map(); // a folded text: the first character the fold changed
  if (CODE_PAGE_CLIENTS.has(prog)) {
    for (const q of parsed.texts.slice(0, parsed.queries)) {
      for (const t of new Set([String(q ?? ''), String(q ?? '').replace(/\\([\\"`$])/g, '$1')])) {
        const f = codePageFold(t);
        if (f !== t && !texts.includes(f)) { texts.push(f); folded.set(f, firstFoldedCharacter(t)); }
      }
    }
  }
  const judged = texts.map((t) => judgeSql(t, { client: parsed.client, maxRows: sw.maxRows, personal: sw.personal }));
  const viaCodePage = (j) => {
    const c = j ? folded.get(texts[judged.indexOf(j)]) : null;
    return c ? ` (in the query as Windows may hand it to ${prog}, ${describeCharacter(c)} read as "${codePageFold(c)}")` : '';
  };
  // The texts as written come first: a write in one of them is denied. A write only in a folded reading asks (with the
  // character that made it): whether the client converts at all depends on the client and the machine's code page.
  const denied = judged.find((j) => j.kind === 'deny');
  if (denied && !viaCodePage(denied)) return deny(`${prog}: ${denied.reason}. The agent never changes data, schema, permissions or a server (AGENTS.md); the user runs such SQL.`);
  const label = `${prog} (sources.sqlRead ${sw.on ? 'on' : 'off'})`;
  if (STARTUP_ENV_RE.test(sub)) return floor(`${label}: a SQL client environment variable (SQLCMDINI, SQLCMDSERVER, PSQLRC, PGHOST, ...) changes the server or runs a startup script the guard cannot see. Confirm the server and the query.`);
  const unreadable = denied ?? judged.find((j) => j.kind === 'floor');
  if (parsed.problems.length || unreadable) {
    return floor(`${label}: ${[...parsed.problems, unreadable && `${unreadable.reason}${viaCodePage(unreadable)}`].filter(Boolean).join('; ')}. The guard cannot judge this query: confirm it is a bounded read you asked for.`);
  }
  if (!sw.on) {
    return floor(`${label}: the agent runs SQL only when you asked for it. Approve only a read-only, aggregate query you asked for; the result is recorded with [sql]. To let bounded reads against named servers pass, turn on sources.sqlRead in hardening/harness.config.json (README, Defaults you should know).`);
  }
  if (!parsed.servers.length) return floor(`${label}: name the server (${prog === 'psql' ? '-h' : prog === 'invoke-sqlcmd' ? '-ServerInstance' : '-S'}) so the guard can match it against sources.sqlRead.servers.`);
  const outside = parsed.servers.filter((s) => !sw.servers.includes(s));
  if (outside.length) return floor(`${label}: server ${outside.join(', ')} is not in sources.sqlRead.servers (${sw.servers.join(', ') || 'none'}). Confirm the server.`);
  const unbounded = judged.flatMap((j) => j.unbounded);
  if (unbounded.length) return floor(`${label}: the query is not bounded ("${unbounded[0]}"): use one aggregate row, or TOP/LIMIT/FETCH FIRST up to ${sw.maxRows} rows (a GROUP BY needs one too).`);
  const personal = [...new Set(judged.flatMap((j) => j.personal))];
  if (personal.length) return floor(`${label}: the query names personal or identifying columns (${personal.slice(0, 5).join(', ')}): rows of people stay with the user.`);
  const firsts = judged.filter((_, i) => parsed.texts.includes(texts[i])); // each text as written, not its bash twin
  const statements = firsts.reduce((n, j) => n + j.statements, 0);
  return pass(`SQL read (sources.sqlRead on): server ${parsed.servers.join(', ')}, ${statements} statement(s), read-only and bounded, no personal columns; record the result with [sql]. Query: ${firsts.map((j) => j.preview).join(' | ').slice(0, 200)}`);
}

// ---------------------------------------------------------------- SQL MCP servers

export const SQL_MCP_NAME_RE = /sql|postgres|mysql|mariadb|sqlite|snowflake|bigquery|redshift|oracle|duckdb|database|warehouse|lakehouse|kusto|cosmos|mongo|(?:^|[-_.])(?:db|pg|adx)(?:$|[-_.])/i;
// A write verb in a tool name wins over a read word (write_query is a write); a generic runner (execute_sql, run_query)
// is judged by the SQL text it carries.
const SQL_MCP_WRITE_RE = /(?:^|_|-)(?:write|insert|update|delete|drop|create|alter|truncate|merge|upsert|grant|revoke|modify|load|import|bulk|backup|restore|kill|set|put|patch|post)(?:_|-|$)/i;
const SQL_MCP_READ_RE = /(?:^|_|-)(?:query|select|read|list|describe|get|show|schema|search|explain|sample|count|execute|exec|run)(?:_|-|$)/i;
// Field names that carry SQL, judged by their words (sqlText, sql_statement, queries, stmt, command, script, ...), so a
// field such as "description" is not one.
const SQL_FIELD_WORD_RE = /^(?:sql\w*|quer\w*|statements?|stmts?|commands?|cmds?|scripts?|q|text|input|args?|code|body)$/i;
const sqlNamed = (key) => String(key).replace(/([a-z0-9])([A-Z])/g, '$1 $2').split(/[^A-Za-z0-9]+/).some((w) => SQL_FIELD_WORD_RE.test(w));
// A string that looks like SQL wherever it sits: a statement keyword at the start, or a ";" between words.
const LOOKS_LIKE_SQL_RE = /^\s*(?:\(\s*)*(?:select|with|insert|update|delete|merge|upsert|truncate|drop|create|alter|grant|revoke|deny|exec|execute|call|do|copy|backup|restore|dbcc|declare|set|use|values|table|show|explain|begin|commit|rollback)\b|\w\s*;\s*\w/i;
// Tools that only describe the database (names of tables and columns); a tool that reads rows is not one of them.
const METADATA_TOOL_RE = /(?:^|_|-)(?:list|describe|schemas?|tables|columns|databases|views|indexes|ping|health|info|metadata)(?:_|-|$)/i;
const DATA_TOOL_RE = /(?:^|_|-)(?:read|select|query|queries|sample|rows?|data|fetch|export|dump|execute|exec|run|sql|search|count|explain|preview)(?:_|-|$)/i;
const MAX_MCP_INPUT = 64 * 1024;
// A larger call is still searched for writes (one linear pass over each SQL string, writeInRawText) up to this size, so a
// write in it is denied; past it the call asks unread. A tool call's input is far smaller in practice.
const MAX_MCP_WRITE_SCAN = 8 * 1024 * 1024;
// A tool name read word by word, so the tests above see insertRows, InsertRows, insert-rows and insert.rows as insert_rows.
const toolWords = (tool) => String(tool).replace(/([a-z0-9])([A-Z])/g, '$1_$2').replace(/([A-Z]+)([A-Z][a-z])/g, '$1_$2').replace(/[^A-Za-z0-9]+/g, '_');

/**
 * Every string an MCP call carries as SQL: SQL-named fields (strings and arrays, nested) and SQL-looking strings
 * anywhere. Deeper than six levels the guard stops and says so (tooDeep).
 */
function sqlFields(value, depth = 0, out = { texts: [], tooDeep: false }, named = false) {
  if (value === null || value === undefined || (typeof value !== 'string' && typeof value !== 'object')) return out;
  if (depth > 6) { out.tooDeep = true; return out; }
  if (typeof value === 'string') { if (named || LOOKS_LIKE_SQL_RE.test(value)) out.texts.push(value); return out; }
  for (const [k, v] of Object.entries(value)) sqlFields(v, depth + 1, out, named || sqlNamed(k));
  return out;
}

/**
 * Verdict for an MCP tool call of a SQL server, or null when the call is not one. A call is a SQL call when
 * `sources.sqlRead.mcpServers` names the server, when the server's name looks like a database, or when the tool's name
 * does (…sql…, or a query tool that carries SQL text). The caller leaves the Power BI servers out.
 */
export function analyzeSqlMcp(server, tool, input, cfg) {
  const sw = sqlReadOf(cfg);
  const name = String(server).toLowerCase();
  const listed = sw.mcpServers.includes(name);
  let size = Infinity;
  try { size = JSON.stringify(input ?? {}).length; } catch { /* unserialisable: too large to judge */ }
  const large = size > MAX_MCP_INPUT;
  const fields = size <= MAX_MCP_WRITE_SCAN ? sqlFields(input ?? {}) : null;
  const words = toolWords(tool);
  const sqlTool = /sql/i.test(tool) || (/(?:^|_|-)quer(?:y|ies)(?:_|-|$)/i.test(words) && (large || fields.texts.some((t) => LOOKS_LIKE_SQL_RE.test(t))));
  if (!listed && !SQL_MCP_NAME_RE.test(name) && !sqlTool) return null;
  if (SQL_MCP_WRITE_RE.test(words)) {
    return deny(`SQL MCP tool ${tool} on ${server} writes to or runs code on a database. The agent never changes data, schema or permissions (AGENTS.md).`);
  }
  if (large) {
    // Too large to judge in full: its SQL strings are only searched for writes (linear), so a write is denied, the rest asks.
    const write = fields?.texts.map((t) => writeInRawText(String(t))).find(Boolean);
    if (write) return deny(`SQL MCP ${server}: ${write} (a call larger than ${MAX_MCP_INPUT / 1024} KB is read only for writes). The agent never changes data, schema or permissions (AGENTS.md).`);
    return floor(`SQL MCP ${server}: the call is larger than ${MAX_MCP_INPUT / 1024} KB, which the guard does not analyse. Confirm what it runs.`);
  }
  // The server's dialect is unknown: every reading of its strings is judged (judgeSql, client "any").
  const judged = fields.texts.map((t) => judgeSql(t, { client: 'any', maxRows: sw.maxRows, personal: sw.personal }));
  const denied = judged.find((j) => j.kind === 'deny');
  if (denied) return deny(`SQL MCP ${server}: ${denied.reason}. The agent never changes data, schema or permissions (AGENTS.md).`);
  if (!listed) return floor(`SQL MCP server ${server} is not named in sources.sqlRead.mcpServers: every call is the user's. Confirm the server and what it reads.`);
  const label = `SQL MCP ${server} (sources.sqlRead ${sw.on ? 'on' : 'off'})`;
  if (!sw.on) return floor(`${label}: the agent reads a database only when you asked for it. Approve only a read you asked for; the result is recorded with [sql].`);
  if (fields.tooDeep) return floor(`${label}: the call nests its input deeper than the guard reads. Confirm what it runs.`);
  if (!SQL_MCP_READ_RE.test(words)) return floor(`${label}: the tool ${tool} is not a recognised read (query, list, describe, get, show, schema). Confirm what it does.`);
  const unreadable = judged.find((j) => j.kind === 'floor');
  if (unreadable) return floor(`${label}: ${unreadable.reason}. Confirm it is a bounded read you asked for.`);
  const unbounded = judged.flatMap((j) => j.unbounded);
  if (unbounded.length) return floor(`${label}: the query is not bounded ("${unbounded[0]}"): use one aggregate row, or TOP/LIMIT/FETCH FIRST up to ${sw.maxRows} rows.`);
  const personal = [...new Set(judged.flatMap((j) => j.personal))];
  if (personal.length) return floor(`${label}: the query names personal or identifying columns (${personal.slice(0, 5).join(', ')}).`);
  if (!fields.texts.length) {
    // Without SQL text only a tool that describes the database passes; a tool that reads rows (read_table, get_rows)
    // has no bound the guard can see.
    if (METADATA_TOOL_RE.test(words) && !DATA_TOOL_RE.test(words)) return pass(`SQL MCP ${server} (sources.sqlRead on): ${tool} without query text (schema or metadata).`);
    return floor(`${label}: ${tool} carries no query text the guard recognises, so it may read rows without a bound. Confirm what it runs.`);
  }
  return pass(`SQL read (sources.sqlRead on): MCP ${server}, ${judged.reduce((n, j) => n + j.statements, 0)} statement(s), read-only and bounded, no personal columns; record the result with [sql]. Query: ${judged.map((j) => j.preview).join(' | ').slice(0, 200)}`);
}
