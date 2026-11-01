// Security policy shared by hooks, the validator and git hooks:
// secret/PII detection and redaction, path classification, shell policy, Power BI MCP policy.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { PROJECT_DIR, canonicalPathOf, foreignShare, git, globToRegExp, isReferenceRel, projectRel, projectRelForms, referencePrefixes, screenshotsOf, toPosix, withoutTrailingDots } from './common.mjs';
import { matchingRule } from './permissions.mjs';
import { splitPipeline, splitStatements, splitSubcommands, tokenize, withoutComments } from './shell-split.mjs';
import {
  CREDENTIAL_ENV_RE, SQL_MCP_NAME_RE, SQL_QUERY_CLIENTS, STARTUP_ENV_RE, analyzeSqlClient, analyzeSqlMcp, identKey, sqlReadOf,
  PERSONAL_NAME_RE, PERSONAL_WORD_RE, foldLatin, personalColumnName,
} from './sql-read.mjs';

// ================================================================ secrets
// Passwords on a command line or in a URL (the rules at the end of SECRET_RULES). The value must be a literal: not a
// placeholder or a variable (<value>, ${VAR}, %VAR%, $env:X, (Read-Host), ***, [REDACTED]), not an option (-h), not a
// word a document uses for it (password, secret, your..., changeme), with a letter or digit and 4 or more characters.
const anyCase = (words) => words.replace(/[a-z]/gi, (c) => `[${c.toLowerCase()}${c.toUpperCase()}]`);
const LITERAL_START = String.raw`(?![\s"'\x60;|&<>{}()$%*\[\\-])`;
// A word a document writes for the value: your..., example..., and password, pwd or secret alone, in the plural or with
// a word that says "put it here" (-pPASSWORD, PasswordHere, secret_value, PassPhrase). Any other word that starts with
// them is a value (-pSecretSauce, PassportBlue).
const PLACEHOLDER_SUFFIX = 's?(?:[_-]?(?:here|goes[_-]?here|value|key|phrase|text|string|placeholder|token)s?)?';
const PLACEHOLDER_WORD = String.raw`(?!(?:${anyCase('your|example|changeme|placeholder|dummy|xxx|redacted')})[\w-]*(?:["'\s,;}\])@:/]|$)|(?:${anyCase(`(?:pass(?:w(?:or)?d)?|pwd|secret)${PLACEHOLDER_SUFFIX}`)})(?:["'\s,;}\])@:/]|$))`;
const literalOf = (stop) => String.raw`${LITERAL_START}${PLACEHOLDER_WORD}(?=[^${stop}]*[A-Za-z0-9])[^${stop}]{4,}`;
const cmdQuoted = (q) => String.raw`${q}(?<secret>${literalOf(String.raw`${q}\r\n`)})(?=${q})`;
const cmdBare = (stop = String.raw`\s"'\x60;|&<>`) => String.raw`(?<secret>${literalOf(stop)})`;
const quotedRules = (id, before, flags) => ['"', "'"].map((q) => ({ id, re: new RegExp(before + cmdQuoted(q), flags) }));
const bareRule = (id, before, flags) => ({ id, re: new RegExp(before + cmdBare(), flags) });
// A program (any letter case, a path before it, .exe after it) and, later on the same command, its option. Quoted
// arguments in between are skipped whole, so a ";" or "-p" inside a string is not an option. The option is judged for
// that program only: -p<value> is a password for mysql but a port for psql, -P a password for sqlcmd but a port for mysql.
// At most 200 arguments lie between them, so a long line of program names costs a fixed amount per name (not a scan to its end).
const BETWEEN_ARGS = String.raw`(?:[^\r\n"';|&\x60]|"[^"\r\n]*"|'[^'\r\n]*'){0,200}?`;
const afterProgram = (programs, option) => String.raw`(?<![\w.-])(?:${anyCase(programs)})(?:\.[eE][xX][eE])?["']?(?![\w-])${BETWEEN_ARGS}[ \t]${option}`;
const MYSQL_CLIENTS = 'mysql(?:dump|admin|import|show|check|pump|slap|binlog|sh)?|mariadb(?:-(?:dump|admin|import|show|check|slap|binlog))?|mycli';
const SQLCMD_CLIENTS = 'sqlcmd|osql|isql|bcp|mssql-cli';
// --password, --admin-password and PowerShell's -Password followed by a space or a colon (an = is password-assignment's).
// PowerShell takes any unambiguous start of a parameter name: -Pass, -Passw, -Passwo and -Passwor are -Password too.
const PASSWORD_OPTION = String.raw`(?<![\w-])(?:--[\w-]*(?:password|passwd|pwd)|-(?:pass(?:w(?:o(?:r(?:d)?)?)?)?|passwd|pwd))(?:[ \t]+|:[ \t]*)`;
const SECURE_STRING = String.raw`\bConvertTo-SecureString[ \t]+(?:-(?:AsPlainText|Force)[ \t]+)*(?:-String[ \t]+)?`;
// An option word and every start of it down to `min` letters, any letter case: abbrev('Decrypt', 2) reads /De to /Decrypt.
const abbrev = (word, min) => anyCase(word.slice(0, min)) + [...word.slice(min)].reduceRight((rest, c) => `(?:${anyCase(c)}${rest})?`, '');
// A user and password pair of one argument (curl -u user:<value>): the user part, then the value after the first ":".
const userPassRules = (id, before, flags) => [
  ...['"', "'"].map((q) => ({ id, re: new RegExp(String.raw`${before}${q}[^${q}\r\n:]*:(?<secret>${literalOf(String.raw`${q}\r\n`)})(?=${q})`, flags) })),
  { id, re: new RegExp(String.raw`${before}[^\s"'\x60;|&<>:]*:${cmdBare()}`, flags) },
];
// A key whose last word is password, passwd or pwd: alone, after a separator (db_password, db.password, DB-PASSWORD) or
// in camelCase (adminPassword, sqlPwd). Written in its letter cases, since camelCase is told by case: these rules take no
// i flag. The rules match the word and read the key before it with a lookbehind, so a long text costs a step per word.
const PW_WORD = String.raw`(?:[Pp]ass(?:wor)?d|PASS(?:WOR)?D|[Pp]wd|PWD)`;
const PW_CAMEL = String.raw`(?:Pass(?:wor)?d|PASS(?:WOR)?D|Pwd|PWD)`;
// The key starts with a letter, "_" or "$" (an option such as '--password' is no key).
const PW_KEY_BEHIND = String.raw`(?:(?:[A-Za-z_$][\w.-]{0,80}[_.-])?${PW_WORD}|[A-Za-z_$][\w.-]{0,80}[a-z0-9]${PW_CAMEL})`;
// A setting, not a value: true, false, null, none (hasPassword: true, "resetPassword": null).
const NOT_SETTING = String.raw`(?!["']?(?:${anyCase('true|false|null|none|nil|undefined')})(?![\w-]))`;
// The value of these keys holds a digit or a sign (a quoted one also a space): a word alone is a label, a setting or code
// there (password: required, "showPassword": "Show", an adminPassword read by Read-Host or config.get(...)), so an
// all-letter word is left alone (a documented limit; password=<word> and "password": "<word>" keep masking any word).
// A quoted value of several words that holds the word password is a label ("Confirm password").
const SIGN = '0-9!#$%&*+/=?@^~';
const bareValue = (stop) => String.raw`(?<secret>${LITERAL_START}${PLACEHOLDER_WORD}(?![!&*|>@])(?=[^${stop}]*[${SIGN}])[^${stop}]{4,})`;
const fieldQuotedRules = (before, flags) => ['"', "'"].map((q) => ({
  id: 'password-field',
  re: new RegExp(String.raw`${before}${q}(?!(?=[^${q}\r\n]*[ \t])[^${q}\r\n]*${anyCase('pass(?:wor)?d')})(?=[^${q}\r\n]*[${SIGN} ])(?<secret>${literalOf(String.raw`${q}\r\n`)})(?=${q})`, flags),
}));
const PASSWORD_FIELD_RULES = [
  // A quoted key of JSON, a Python dict or a JavaScript object, its value in quotes: {"adminPassword": "..."}, {'password': '...'}.
  ...['"', "'"].flatMap((q) => fieldQuotedRules(String.raw`${PW_WORD}(?<=${q}${PW_KEY_BEHIND})${q}[ \t]*:[ \t]*${NOT_SETTING}`, 'g')),
  // A YAML line (or a list item) whose key names a password: the value in quotes, or a bare value to the end of the line
  // (a comment after it may follow).
  ...fieldQuotedRules(String.raw`${PW_WORD}(?<=^[ \t]*(?:-[ \t]+)?["']?${PW_KEY_BEHIND})["']?[ \t]*:[ \t]*${NOT_SETTING}`, 'gm'),
  { id: 'password-field', re: new RegExp(String.raw`${PW_WORD}(?<=^[ \t]*(?:-[ \t]+)?${PW_KEY_BEHIND})[ \t]*:[ \t]*${NOT_SETTING}${bareValue(String.raw`\s"'\x60`)}(?=(?:[ \t]+#.*|[ \t]*)\r?$)`, 'gm') },
  // A camelCase key anywhere: adminPassword=..., $adminPassword = '...', { adminPassword: '...' }. The snake, dotted and
  // single-word keys with "=" are password-assignment's.
  ...fieldQuotedRules(String.raw`(?<=[a-z0-9])${PW_CAMEL}[ \t]*[:=][ \t]*${NOT_SETTING}`, 'g'),
  { id: 'password-field', re: new RegExp(String.raw`(?<=[a-z0-9])${PW_CAMEL}[ \t]*=[ \t]*${NOT_SETTING}${bareValue(String.raw`\s"'\x60;|&<>(){}[\],`)}`, 'g') },
];

// High-signal rules only. A named group `secret` marks the part to redact; otherwise the whole match. A secret stands
// last in its match: redactWith replaces its last occurrence (a username or a key word may spell the same characters).
export const SECRET_RULES = [
  // The whole block, BEGIN marker to END marker, or to the end of the text when the key is cut off. The newlines may be
  // real or the two characters \n of a JSON string (a service account's private_key): the body is whatever lies between.
  { id: 'private-key', re: /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?(?:-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----|$)/g },
  { id: 'github-token', re: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}\b/g },
  { id: 'github-fine-grained-pat', re: /\bgithub_pat_[A-Za-z0-9_]{50,255}/g },
  { id: 'azure-storage-key', re: /\bAccountKey=(?<secret>[A-Za-z0-9+/]{40,}={0,2})/gi },
  { id: 'azure-sas-signature', re: /\bsig=(?<secret>[A-Za-z0-9%+/]{30,}(?:%3D|=){0,2})/gi },
  { id: 'entra-client-secret', re: /(?<![A-Za-z0-9_~.-])[A-Za-z0-9_~.-]{3}\dQ~[A-Za-z0-9_~.-]{31,34}(?![A-Za-z0-9_~.-])/g },
  { id: 'aws-access-key', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { id: 'slack-token', re: /\bxox[abposr]-[A-Za-z0-9-]{10,}/g },
  { id: 'anthropic-key', re: /\bsk-ant-[A-Za-z0-9_-]{20,}/g },
  { id: 'openai-key', re: /\bsk-(?:proj-|svcacct-)[A-Za-z0-9_-]{20,}|\bsk-[A-Za-z0-9]{40,}\b/g },
  { id: 'google-api-key', re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { id: 'npm-token', re: /\bnpm_[A-Za-z0-9]{36}\b/g },
  { id: 'jwt', re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g },
  { id: 'bearer-token', re: /\bBearer\s+(?<secret>[A-Za-z0-9\-._~+/]{20,}=*)/g },
  // Connection strings, M records and env files (key=value). Placeholders such as <value>, ${VAR}, {{var}},
  // %VAR%, *** or [REDACTED] are ignored; a value needs at least one letter or digit. The value is, in this order, one
  // ODBC braces value (Pwd={a;b}, where a password may hold any character), one quoted value (it ends at its closing
  // quote, so it may hold ";" and spaces), a value with spaces that a connection string ends with ";" or the end of the
  // line (only after an earlier ";", so a sentence about Password=... is not read as one), and a plain value up to the
  // next space or ";". The four rules before the plain one run first, since it would mask only the start of their value.
  { id: 'password-assignment', re: /(?<![A-Za-z0-9$])(?:password|passwd|pwd)\s*=\s*\{(?!\{)(?<secret>(?![<*%$[\\])(?=[^}\r\n]{0,200}[A-Za-z0-9])(?:[^}\r\n]|\}\}){4,200})(?=\})/gi },
  { id: 'password-assignment', re: /(?<![A-Za-z0-9$])(?:password|passwd|pwd)\s*=\s*"(?<secret>(?![;"'\s{<*%$[\\])(?=[^"\r\n]*[A-Za-z0-9])[^"\r\n]{4,})(?=")/gi },
  { id: 'password-assignment', re: /(?<![A-Za-z0-9$])(?:password|passwd|pwd)\s*=\s*'(?<secret>(?![;"'\s{<*%$[\\])(?=[^'\r\n]*[A-Za-z0-9])[^'\r\n]{4,})(?=')/gi },
  { id: 'password-assignment', re: /(?:password|passwd|pwd)(?<=;[ \t]*(?:password|passwd|pwd))[ \t]*=[ \t]*(?<secret>(?![{<*%$[\\])(?=[^;"'\r\n=]{4})(?=[^;"'\r\n=]*[A-Za-z0-9])[^;"'\s=](?:[^;"'\r\n=]*[^;"'\s=])?)(?=[ \t]*(?:;|\r?\n|$))/gi },
  // The same value with spaces as the first pair of a connection string, or after a pair that a space separates: it
  // ends at a ";" that another pair of the string follows (a value of three words, then ";Server=db").
  { id: 'password-assignment', re: /(?<![A-Za-z0-9$])(?:password|passwd|pwd)[ \t]*=[ \t]*(?<secret>(?![{<*%$[\\])(?=[^;"'\r\n=]{4})(?=[^;"'\r\n=]*[A-Za-z0-9])[^;"'\s=](?:[^;"'\r\n=]*[^;"'\s=])?)(?=[ \t]*;[ \t]*[A-Za-z][\w .-]{0,40}=)/gi },
  // A quoted value inside a JSON string, its quotes escaped (\"a;b c\"): it ends at the escaped closing quote.
  { id: 'password-assignment', re: /(?<![A-Za-z0-9$])(?:password|passwd|pwd)\s*=\s*\\"(?<secret>(?![;\s{<*%$[\\])(?=(?:[^"\\\r\n]|\\[^"\r\n]){0,200}[A-Za-z0-9])(?:[^"\\\r\n]|\\[^"\r\n]){4,})(?=\\")/gi },
  {
    id: 'password-assignment',
    re: /(?<![A-Za-z0-9$])(?:password|passwd|pwd)\s*=\s*["']?(?<secret>(?![;"'\s{<*%$[\\])(?=[^;"'\s]*[A-Za-z0-9])[^;"'\s]{4,})/gi,
  },
  {
    // The value may hold spaces and escapes ("correct horse battery staple"); it ends at its closing quote.
    id: 'password-json-field',
    re: /"(?:password|passwd|pwd|client_?secret|secret)"\s*:\s*"(?<secret>(?![\s{<*%$[\\])(?=(?:[^"\\]|\\.)*[A-Za-z0-9])(?:[^"\\]|\\.){4,})"/gi,
  },
  {
    // The key may follow a prefix and "_" (aws_secret_access_key, my_api_key), never a letter or digit.
    id: 'credential-assignment',
    re: /(?<![A-Za-z0-9])(?:client[_-]?secret|api[_-]?key|access[_-]?token|auth[_-]?token|secret[_-]?(?:access[_-]?)?key|x-api-key|subscription[_-]?key|sas[_-]?token)["']?\s*[:=]\s*["']?(?<secret>(?![{<*%$[\\])(?!(?:your|example|changeme|placeholder|dummy|xxx|redacted)[\w-]*(?:["'\s,;}\])]|$))[A-Za-z0-9\-._~+/=]{12,})/gi,
  },
  ...PASSWORD_FIELD_RULES,
  // Passwords on a command line, which the audit log keeps and a tool may print (mysql -u app -p<value>), and in a URL
  // (scheme://user:<value>@host, which the e-mail rule of redactPii would otherwise take for an address).
  ...quotedRules('db-client-password', afterProgram(MYSQL_CLIENTS, '-p'), 'g'),
  bareRule('db-client-password', afterProgram(MYSQL_CLIENTS, '-p'), 'g'),
  ...quotedRules('db-client-password', afterProgram(SQLCMD_CLIENTS, '-P[ \\t]*'), 'g'),
  bareRule('db-client-password', afterProgram(SQLCMD_CLIENTS, '-P[ \\t]*'), 'g'),
  // redis-cli -a <value> or --pass <value>; sqlpackage /TargetPassword:<value>, /SourcePassword:, /tp:, /sp: (any case).
  ...quotedRules('db-client-password', afterProgram('redis-cli', '(?:-a|--pass)[ \\t]+'), 'g'),
  bareRule('db-client-password', afterProgram('redis-cli', '(?:-a|--pass)[ \\t]+'), 'g'),
  ...quotedRules('db-client-password', afterProgram('sqlpackage', `[/-](?:${anyCase('targetpassword|sourcepassword|tp|sp')}):`), 'g'),
  bareRule('db-client-password', afterProgram('sqlpackage', `[/-](?:${anyCase('targetpassword|sourcepassword|tp|sp')}):`), 'g'),
  // curl -u user:<value> (--user, -U and --proxy-user too, the value attached or after a space); dtexec and dtutil
  // /De[crypt] <value>, the package password.
  ...userPassRules('password-option', afterProgram('curl', '(?:-u|--user|-U|--proxy-user)[ \\t]*'), 'g'),
  ...quotedRules('password-option', afterProgram('dtexec|dtutil', `[/-]${abbrev('decrypt', 2)}[ \\t]+`), 'g'),
  bareRule('password-option', afterProgram('dtexec|dtutil', `[/-]${abbrev('decrypt', 2)}[ \\t]+`), 'g'),
  ...quotedRules('password-option', PASSWORD_OPTION, 'gi'),
  ...quotedRules('secure-string', SECURE_STRING, 'gi'),
  { id: 'secure-string', re: new RegExp(String.raw`["'](?<secret>${literalOf(String.raw`"'\r\n`)})(?=["'][ \t]*\|[ \t]*ConvertTo-SecureString\b)`, 'gi') },
  { id: 'url-credentials', re: new RegExp(String.raw`\b[A-Za-z][A-Za-z0-9+.-]{0,31}://[^\s:/?#@"'<>]*:(?<secret>${literalOf(String.raw`\s/?#@"'<>`)})(?=@)`, 'g') },
];

// Forms of a password that only a command line has, for the audit log (which knows its text is a command): a bare word
// after a space is the password in `mongosh --password hunter2` or `docker login -p hunter2`, but it is any word in prose
// about the option ("--password option"), so these never run on a prompt, a file or a tool's output.
const COMMAND_SECRET_RULES = [
  bareRule('password-option', PASSWORD_OPTION, 'gi'),
  bareRule('secure-string', SECURE_STRING, 'gi'),
  bareRule('db-client-password', String.raw`(?<![\w.-])(?:docker|podman)(?:\.exe)?["']?[ \t]+login\b${BETWEEN_ARGS}[ \t]-p[ \t]+`, 'gi'),
  bareRule('db-client-password', afterProgram('mongosh|mongo|cqlsh', '-p[ \\t]+'), 'g'),
];

/**
 * The line number of an index: the line breaks are found once (on the first call) and each index is placed among them by
 * a binary search, so a text with many hits costs O(n + hits * log n), not a slice and a split of the text per hit.
 */
function lineFinder(text) {
  let breaks;
  return (index) => {
    if (!breaks) {
      breaks = [];
      for (let i = text.indexOf('\n'); i !== -1; i = text.indexOf('\n', i + 1)) breaks.push(i);
    }
    let lo = 0;
    let hi = breaks.length;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (breaks[mid] < index) lo = mid + 1;
      else hi = mid;
    }
    return lo + 1;
  };
}
const mask = (value) => `${value.slice(0, 4)}… (${value.length} chars)`;

/**
 * Finds secrets without echoing them: returns rule id, line number and a masked preview. One hit per secret: the first
 * rule (in SECRET_RULES order) that finds a value reports it, wherever another rule's match starts (a key's quote or its
 * last word).
 */
export function findSecrets(text, rules = SECRET_RULES) {
  const src = String(text ?? '');
  const lineOf = lineFinder(src);
  const hits = [];
  const seen = new Set();
  for (const rule of rules) {
    rule.re.lastIndex = 0;
    for (const m of src.matchAll(rule.re)) {
      // The secret ends its match (redactWith): its last occurrence there is where it stands.
      const at = m.groups?.secret ? m.index + m[0].lastIndexOf(m.groups.secret) : m.index;
      if (seen.has(at)) continue;
      seen.add(at);
      hits.push({ id: rule.id, line: lineOf(m.index), preview: mask(m.groups?.secret ?? m[0]) });
    }
  }
  return hits;
}

function redactWith(text, rules, label) {
  let out = String(text ?? '');
  let count = 0;
  const ids = new Set();
  for (const rule of rules) {
    rule.re.lastIndex = 0;
    out = out.replace(rule.re, (...args) => {
      const match = args[0];
      const groups = args[args.length - 1];
      if (rule.check && !rule.check(match)) return match;
      count++;
      ids.add(rule.id);
      const token = `[${label}:${rule.id}]`;
      if (!(groups && typeof groups === 'object' && groups.secret)) return token;
      // The last occurrence: the secret ends its match, and an earlier word of the match may spell the same characters.
      const at = match.lastIndexOf(groups.secret);
      return match.slice(0, at) + token + match.slice(at + groups.secret.length);
    });
  }
  return { text: out, count, ids: [...ids] };
}

export const redactSecrets = (text) => redactWith(text, SECRET_RULES, 'REDACTED');
/** Secrets masked in a shell command: SECRET_RULES, then the forms only a command line has (COMMAND_SECRET_RULES). */
export function redactCommandSecrets(text) {
  const general = redactWith(text, SECRET_RULES, 'REDACTED');
  const command = redactWith(general.text, COMMAND_SECRET_RULES, 'REDACTED');
  return { text: command.text, count: general.count + command.count, ids: [...new Set([...general.ids, ...command.ids])] };
}

// ================================================================ PII (for data returned by MCP queries)

function isValidTckn(value) {
  const d = [...value].map(Number);
  if (d.length !== 11 || d[0] === 0) return false;
  const odd = d[0] + d[2] + d[4] + d[6] + d[8];
  const even = d[1] + d[3] + d[5] + d[7];
  const d10 = (((odd * 7 - even) % 10) + 10) % 10;
  const d11 = d.slice(0, 10).reduce((a, b) => a + b, 0) % 10;
  return d[9] === d10 && d[10] === d11;
}

function luhn(digits) {
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0;
  for (let i = 0; i < digits.length; i++) {
    let n = Number(digits[digits.length - 1 - i]);
    if (i % 2 === 1) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
  }
  return sum % 10 === 0;
}

function isValidIban(value) {
  const iban = value.replace(/\s/g, '');
  if (iban.length < 15 || iban.length > 34) return false;
  const moved = iban.slice(4) + iban.slice(0, 4);
  let rem = 0;
  for (const ch of moved) {
    const code = /[A-Z]/.test(ch) ? String(ch.charCodeAt(0) - 55) : ch;
    for (const digit of code) rem = (rem * 10 + Number(digit)) % 97;
  }
  return rem === 1;
}

export const PII_RULES = [
  // The local part starts where its run of characters starts (not at each "." or "-" inside it), so a long run without
  // "@" is read once: linear time, where a start at every word boundary cost time squared (100 KB took 5 s).
  { id: 'email', re: /(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,24}\b/g },
  { id: 'iban', re: /\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b/g, check: isValidIban },
  // Not after "0." or "0," (a decimal fraction, as DAX results print ratios) and not before ".25" (an amount).
  { id: 'payment-card', re: /(?<!\d\.)\b\d(?:[ -]?\d){12,18}\b(?!\.\d)/g, check: (m) => luhn(m.replace(/\D/g, '')) },
  { id: 'tckn', re: /\b[1-9]\d{10}\b/g, check: isValidTckn },
];

export const redactPii = (text) => redactWith(text, PII_RULES, 'PII');

// ================================================================ path classification

const ENV_TEMPLATE = /^\.env\.(?:example|sample|template)$/i;
// Credential stores: ONE list for classifyPath (the Read, Grep, Glob, Edit and Write guards) and for the shell guard's name scan
// (SHELL_SECRET_RE and SHELL_SECRET_DIR_RE below are built from these lists), so the two cannot disagree about a file.
// SQL client password files count too: PostgreSQL's .pgpass (pgpass.conf on Windows), MySQL's .my.cnf and .mylogin.cnf, and
// git's .git-credentials.
const SECRET_BASENAMES = new Set(['.env', '.npmrc', '.netrc', '.pypirc', 'credentials.json', 'id_rsa', 'id_ed25519', 'id_ecdsa',
  '.pgpass', 'pgpass.conf', '.pg_service.conf', 'pg_service.conf', '.my.cnf', '.mylogin.cnf', 'application_default_credentials.json',
  '.git-credentials']);
// Google Cloud's sign-in folder (gcloud and BigQuery: credentials.db, access_tokens.db, application default credentials).
const GCLOUD_DIR_RE = /(?:^|\/)(?:\.config|appdata\/roaming)\/gcloud(?:\/|$)/;
const SECRET_EXTS = new Set(['.pem', '.key', '.pfx', '.p12', '.publishsettings', '.kdbx', '.ppk']);
// Folders that hold nothing but credentials (every file below them counts) and the credential files of the cloud and tool CLIs
// (a home folder holds them: ~/.aws/credentials, ~/.kube/config). `/` is either slash, a `*` is the rest of a name.
export const CREDENTIAL_DIRS = ['.aws', '.azure', '.ssh', '.gnupg'];
export const CREDENTIAL_PATHS = ['.aws/credentials', '.azure/accessTokens.json', '.azure/azureProfile.json', '.azure/msal_token_cache.*',
  '.azure/service_principal_entries.json', '.config/gh/hosts.yml', '.kube/config', '.docker/config.json'];
const regexLiteral = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const CREDENTIAL_PATH_RE = new RegExp(`(?:^|/)(?:${CREDENTIAL_PATHS.map((p) => regexLiteral(p).replace(/\\\*/g, '[^/]*')).join('|')})$`, 'i');
const JSON_EXTS = new Set(['.json', '.pbir', '.pbism', '.pbip']);
const PBIP_TEXT_EXTS = new Set(['.tmdl', '.json', '.pbir', '.pbism', '.pbip', '.dax']);

/** Classifies a (project-relative or absolute) path for the guard hooks and the validator. */
export function classifyPath(p) {
  const posix = toPosix(p);
  const lower = posix.toLowerCase();
  const base = lower.split('/').pop();
  const ext = path.posix.extname(base);
  const inPbip = /(?:^|\/)[^/]+\.(?:report|semanticmodel)\//.test(lower);
  const secret =
    base === '.env' ||
    (base.startsWith('.env.') && !ENV_TEMPLATE.test(base)) ||
    SECRET_BASENAMES.has(base) ||
    SECRET_EXTS.has(ext) ||
    GCLOUD_DIR_RE.test(lower) ||
    CREDENTIAL_PATH_RE.test(lower) ||
    lower.split('/').some((part) => part === 'secrets' || CREDENTIAL_DIRS.includes(part));
  return {
    path: posix,
    secret,
    // Imported data: Desktop's cache and .pbix, Report Designer's preview cache (*.rdl.data) of a Visual Studio
    // Reporting Services project, and the workspace database of a Visual Studio Analysis Services project.
    data: ext === '.abf' || ext === '.pbix' || base.endsWith('.rdl.data') || /(?:^|\/)bin\/data(?:\/|$)/.test(lower),
    // Per-user settings: Desktop's localSettings.json, Visual Studio / Tabular Editor user options (*.tmuo).
    // Per-user settings: Desktop's localSettings.json, Visual Studio / Tabular Editor user options (*.tmuo), SSIS
    // project user options (*.dtproj.user).
    localOnly: /(?:^|\/)\.pbi\/localsettings\.json$/.test(lower) || ext === '.tmuo' || base.endsWith('.dtproj.user'),
    desktopOwned:
      /(?:^|\/)\.pbi\/(?:localsettings\.json|cache\.abf)$/.test(lower) ||
      /(?:^|\/)[^/]+\.report\/(?:report|mobilestate|semanticmodeldiagramlayout)\.json$/.test(lower) ||
      /(?:^|\/)[^/]+\.semanticmodel\/diagramlayout\.json$/.test(lower),
    autoDateTable: /(?:^|\/)definition\/tables\/(?:localdatetable_|datetabletemplate_)[^/]*\.tmdl$/.test(lower),
    kind:
      ext === '.tmdl' ? 'tmdl'
      : ext === '.md' ? 'markdown'
      : ext === '.dax' ? 'dax'
      : ext === '.rdl' || ext === '.rds' || ext === '.rsd' ? 'rdl'
      : ext === '.dtsx' || ext === '.dtproj' || ext === '.conmgr' || ext === '.params' || ext === '.dtsconfig' ? 'ssis'
      : ext === '.bim' ? 'bim'
      : JSON_EXTS.has(ext) || base === '.platform' ? 'json'
      : 'other',
    jsonc: lower.startsWith('.vscode/'), // VS Code files may contain comments
    inPbip,
    pbipText: (inPbip || ext === '.pbip') && (PBIP_TEXT_EXTS.has(ext) || base === '.platform'),
  };
}

/** The harness models are TMDL only; Model.bim (TMSL) is read, never edited. */
export const TMDL_ONLY_REASON =
  'This harness works on TMDL only and never edits Model.bim (TMSL). Convert the model to a TMDL folder first: Power BI Desktop saves a Power BI project as TMDL; an Analysis Services model is converted with Tabular Editor or Microsoft\'s TMDL API (TmdlSerializer). The conversion rewrites the whole definition, so the user decides (Tier 2).';

export function describePathBlock(p, cls) {
  if (cls.data) {
    return `${p} contains imported DATA (cache.abf, .pbix, a Report Designer preview cache *.rdl.data or an Analysis Services workspace database). Reading it would send business data to the model and is blocked. Work from TMDL/PBIR/RDL metadata instead.`;
  }
  return `${p} is a secret/credential file and is blocked for the agent. Use placeholders (e.g. \${ENV_VAR}) and ask the user if a real value is needed.`;
}

// ================================================================ shell policy (Bash, PowerShell, Monitor)

const deny = (reason) => ({ decision: 'deny', reason });
const ask = (reason) => ({ decision: 'ask', reason });
/**
 * An ask that auto approval (approvals.mode "auto") never passes: it reaches outside the repository (publish, deploy,
 * push, a service workspace, a database or Analysis Services server, GitHub, Figma) or exposes data rows.
 */
const askUser = (reason) => ({ decision: 'ask', reason, autoApprovable: false });
/**
 * The floor: an ask that even lab mode leaves to the user, because it leaves this machine (push, publish/deploy, a
 * service workspace or remote server, GitHub and Figma writes) or cannot be analysed at all.
 */
const askFloor = (reason) => ({ decision: 'ask', reason, autoApprovable: false, floor: true });
/**
 * Of two asks, a floor ask wins, then the one auto approval must not pass; otherwise the first stays. An autoDefer
 * (code the guard cannot see into) survives the merge, so auto mode never approves a command line that runs one.
 */
const strongerAsk = (a, b) => {
  const winner = !a ? b : !b ? a : a.floor ? a : b.floor ? b : a.autoApprovable === false || b.autoApprovable !== false ? a : b;
  return winner && !winner.autoDefer && (a?.autoDefer || b?.autoDefer) ? { ...winner, autoDefer: true } : winner;
};

// Longer commands are refused before analysis: the textual analysis grows faster than linearly, and a hook that runs
// past its timeout lets the call through (Claude Code docs, Hooks). 32 KB analyses in well under a second.
const MAX_SHELL_COMMAND = 32 * 1024;
/**
 * Bash drops a backslash before an ordinary character (gi\t is git, .\env is .env), joins `\<newline>` without a space
 * and reads `\\` as one literal backslash. The tokenizer keeps the backslash of `docs\a.md` (a Windows path), so this
 * reading is judged next to it. A backslash before whitespace, a quote, `;`, `|`, `&`, `$` or a backtick stays: the
 * tokenizer already escapes those the bash way.
 */
const bashReading = (cmd) => cmd.replace(/\\\r?\n/g, '').replace(/\\(?:\\|([^\s'"`;|&$]))/g, '$1');

/**
 * Spellings of one command that its shell would run the same way: PowerShell drops a backtick before an ordinary
 * character (r`m is rm) and reads a backtick at the end of a line as a continuation, bash drops a backslash before an
 * ordinary character (bashReading) and runs `...` as a command; escaped and doubled quotes hide a nested command from
 * the quote matching. Each spelling is judged and the strictest verdict wins.
 */
function shellVariants(cmd) {
  const out = [cmd];
  if (cmd.includes('`')) {
    const joined = cmd.replace(/`\r?\n/g, ' '); // `git push `<newline> --force origin x` is one statement in PowerShell
    out.push(cmd.replace(/`([^\r\n])/g, '$1'), joined, joined.replace(/`([^\r\n])/g, '$1'));
  }
  // PowerShell gives a backslash no meaning: `echo a\;git push` is two statements there and one word in bash.
  if (/\\[;&|]/.test(cmd)) out.push(cmd.replace(/\\([;&|])/g, '$1'));
  if (cmd.includes('\\')) out.push(bashReading(cmd));
  if (cmd.includes('^')) out.push(cmd.replace(/\^([^\r\n])/g, '$1')); // cmd.exe escape: p^ush is push
  if (/\\["']|""/.test(cmd)) out.push(cmd.replace(/\\(["'])/g, ' ').replace(/["'`]/g, ' '));
  // An empty quoted part joins its neighbours into one word in both shells: `.cl''aude` and `.cl""aude` are `.claude`.
  if (/''|""/.test(cmd)) out.push(cmd.replace(/''|""/g, ''));
  return [...new Set(out)];
}
const SEVERITY = { deny: 3, ask: 2 };
/** The strictest of several verdicts: deny over ask over none; of two asks, the one auto approval must not pass. */
function strictest(verdicts) {
  let best = null;
  for (const v of verdicts) {
    if (!v) continue;
    const rank = SEVERITY[v.decision] ?? 0;
    const bestRank = SEVERITY[best?.decision] ?? 0;
    if (!best || rank > bestRank) best = v;
    else if (rank === 2 && bestRank === 2) best = strongerAsk(best, v);
  }
  return best;
}

// Trailing dots (Windows drops them: `.env.` opens `.env`) and `:` (an alternate data stream, `.env::$DATA`) count too.
// A wildcard before the name (`*.env`) counts like the name; the stores of cloud and tool credentials (~/.aws/credentials,
// ~/.azure/*, gh's hosts.yml, .git-credentials, the kube and docker configs, SQL client password files, keys) count like
// keys. The names, extensions, folders and files come from the lists next to classifyPath, never from a second spelling here.
// A short option takes its value glued to it (`rg x -g.env`, `git commit -F.env`), so a letter after a dash is a boundary, too.
const SECRET_NAMES_PATTERN = [...SECRET_BASENAMES].filter((name) => name !== '.env').map(regexLiteral).join('|');
const SECRET_EXTS_PATTERN = [...SECRET_EXTS].map((ext) => regexLiteral(ext.slice(1))).join('|');
const CREDENTIAL_PATHS_PATTERN = CREDENTIAL_PATHS.map((p) => regexLiteral(p).replace(/\//g, '[\\\\/]').replace(/\\\*/g, '\\w+')).join('|');
const CREDENTIAL_DIRS_PATTERN = CREDENTIAL_DIRS.map(regexLiteral).join('|');
const SHELL_SECRET_RE = new RegExp(
  String.raw`(?:^|[\s'"\`=:(<>|;&,/\\*?]|(?<=[\s'"\`]-[A-Za-z]))(?:\.env(?!\.(?:example|sample|template)\b)(?:\.[\w-]+)?|[\w.-]+\.(?:${SECRET_EXTS_PATTERN}|abf|pbix|rdl\.data)|${SECRET_NAMES_PATTERN}|(?:\.config|AppData[\\/]Roaming|%APPDATA%|\$env:APPDATA)[\\/]gcloud(?:[\\/][^\s'"\`]*)?|${CREDENTIAL_PATHS_PATTERN})\.*(?=$|[\s'"\`),;|&<>:])`,
  'i');
const SHELL_SECRET_DIR_RE = new RegExp(
  String.raw`(?:^|[\s'"\`=:(<>|;&,/\\]|(?<=[\s'"\`]-[A-Za-z]))(?:secrets|bin[\\/]data|${CREDENTIAL_DIRS_PATTERN})(?:[\\/]|(?=$|[\s'"\`),;|&<>]))`, 'i');
const SECRET_VAR_RE = /(SECRET|TOKEN|PASSW|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CONN(?:ECTION)?_?STR)/i;
// Personal access token variables: PAT in capitals, or "pat" joined to another word in any case (github_pat,
// $env:azdo_pat_token; PowerShell and Windows ignore case). A bare lowercase $pat is usually something else
// (a UI Automation pattern, a path), so only that one passes.
const SECRET_PAT_VAR_RE = /(?:^|_)PAT(?:_|$)/;
const SECRET_PAT_PART_RE = /(?:^|_)pat_|_pat$/i;
const isSecretVarName = (name) => SECRET_VAR_RE.test(name) || SECRET_PAT_VAR_RE.test(name) || SECRET_PAT_PART_RE.test(name);
const SECRET_VAR_LOOKUP_RE = /process\.env\s*(?:\.\s*|\[\s*['"`])([A-Za-z_]\w*)|os\.(?:environ\s*(?:\[\s*|\.\s*get\s*\(\s*)|getenv\s*\(\s*)['"]([A-Za-z_]\w*)|GetEnvironmentVariable\s*\(\s*['"]([A-Za-z_]\w*)|%([A-Za-z_]\w*)%/gi;
// The same read from other languages: Ruby/PHP ENV['X'] and ENV.fetch('X'), Perl %ENV ($ENV{X} or $ENV{'X'}), Go/PHP
// getenv('X'), PHP superglobals $_ENV['X'] / $_SERVER['X']. node, python, PowerShell and cmd are the regex above; the
// `$VAR` scan catches ${X} but reads $ENV{X} as the variable "ENV", so %ENV access needs its own alternative.
const SECRET_VAR_LOOKUP2_RE = /(?:\$_(?:ENV|SERVER)|\bENV)\s*\[\s*['"]([A-Za-z_]\w*)|\bENV\.fetch\s*\(\s*['"]([A-Za-z_]\w*)|\$ENV\{\s*['"]?([A-Za-z_]\w*)|\bgetenv\s*\(\s*['"]([A-Za-z_]\w*)/gi;
const TOKEN_PRINT_RE = /\bgcloud\s+auth\s+(?:application-default\s+)?print-(?:access|identity)-token\b|\baz\s+account\s+get-access-token\b|\baz\s+acr\s+login\b[^|;&\n]*--expose-token\b|\baws\s+ecr(?:-public)?\s+get-login-password\b|\baws\s+sts\s+get-session-token\b|\bgh\s+auth\s+token\b|\bgh\s+auth\s+status\b[^|;&\n]*\s(?:--show-token\b|-[A-Za-z]*t[A-Za-z]*\b)|\bGet-AzAccessToken\b/i;
// Paths a shell write must never reach: the agent's own instructions and safety net, the Git and editor configuration
// (.github/, .vscode/, .cursor/, .gitignore, .gitattributes), the installer's manifest and the hooks' own logs and session
// state (.claude/logs/, which the guards read back: lib/ask-once.mjs, lib/mcp-state.mjs). The Edit guard keeps the same
// set with the user (CRITICAL_WRITE_RE in guard-pre-tool-use.mjs) and denies the logs (HOOK_LOGS_RE there).
const GUARD_PATH_RE =
  /(?:^|[\s'"`=/\\])(?:\.claude[\\/](?:settings(?:\.local)?\.json|agents[\\/]|skills[\\/]|commands[\\/]|rules[\\/]|bi-agent-harness(?:\.json\b|[\\/])|logs(?:[\\/]|(?=$|[\s'"`;|&),])))|hardening(?:[\\/]|(?=$|[\s'"`;|&),]))|\.githooks(?:[\\/]|\b)|\.github[\\/]|\.vscode[\\/]|\.cursor[\\/]|\.mcp(?:\.example)?\.json\b|package\.json\b|\.gitignore\b|\.gitattributes\b)/i;
// The same writers without the redirect (redirect targets are judged one by one) and never inside an option such as
// grep's -ln or -rm: a short program name counts only when no letter, digit or "-" stands before it.
const WRITE_PROG_RE =
  /\b(?:sed|perl)\s+(?:-\w*\s+)*-\w*i|(?<![\w-])tee\b|(?<![\w-])(?:mv|rm|cp|chmod|chown|ln|truncate|unlink|touch)\b|\b(?:set-content|add-content|out-file|remove-item|move-item|copy-item|rename-item|new-item|clear-content)\b|\bgit\s+(?:checkout|restore|rm|mv)\b/i;
// Clients that connect to SQL Server, Analysis Services or SSIS. AGENTS.md: the agent edits SQL text and never runs
// it; deploying and processing a model is the user's.
const DB_CLIENTS = new Set(['sqlcmd', 'osql', 'isql', 'bcp', 'sqlpackage', 'mssql-cli', 'dtutil', 'invoke-sqlcmd', 'invoke-ascmd',
  'usql', 'mysql', 'mariadb', 'mysqlsh', 'sqlite3', 'duckdb', 'sqlplus', 'sql', 'snowsql', 'bq', 'clickhouse-client', 'mongosh', 'mongo',
  'redis-cli', 'cqlsh', 'trino', 'presto', 'pgcli', 'mycli', 'litecli']);
// SqlServer module (Invoke-ProcessASDatabase, Read-SqlTableData, Backup-SqlDatabase...) and dbatools (Invoke-DbaQuery...).
const DB_CMDLET_RE =
  /^(?:invoke-process(?:asdatabase|table|partition|dimension|cube)|(?:read|write)-sql\w*data|(?:backup|restore)-(?:as|sql)database|merge-partition|\w+-dba\w+)$/;
// Role membership on a server is the user's (AGENTS.md; the TMDL guard denies member edits for the same reason):
// Analysis Services roles (SqlServer module), workspace users (MicrosoftPowerBIMgmt), Reporting Services roles
// (ReportingServicesTools: Grant-/Revoke-Rs*).
const ROLE_MEMBER_CMDLET_RE = /^(?:(?:add|remove)-rolemember|(?:add|remove)-powerbiworkspaceuser|(?:grant|revoke)-rs\w+)$/;
// Client libraries and drivers a script can load to query, process or deploy.
const DB_LIBRARY_RE =
  /\bMicrosoft\.(?:AnalysisServices|SqlServer\.(?:Management|Dts))\b|\b(?:System|Microsoft)\.Data\.(?:SqlClient|OleDb|Odbc)\b|\bMSOLAP\b|\bADODB\.Connection\b|\b(?:pyodbc|pymssql|pyadomd)\b/i;
// Programs that only read or print text: naming a library in a search or a file name loads nothing.
const TEXT_READERS = new Set(['grep', 'egrep', 'fgrep', 'rg', 'cat', 'type', 'findstr', 'select-string', 'sls', 'get-content', 'gc',
  'head', 'tail', 'less', 'more', 'wc', 'echo', 'printf', 'write-output', 'write-host', 'ls', 'dir', 'get-childitem', 'gci', 'test-path', 'find']);
// dtexec options may be shortened to their bracketed prefix: /Va[lidate].
const DTEXEC_VALIDATE_RE = /^[/-]va(?:l(?:i(?:d(?:a(?:t(?:e)?)?)?)?)?)?$/i;
const NET_PROGRAMS = new Set([
  'curl', 'wget', 'nc', 'ncat', 'netcat', 'telnet', 'scp', 'sftp', 'ftp', 'tftp', 'socat', 'ssh',
  'invoke-webrequest', 'iwr', 'invoke-restmethod', 'irm', 'start-bitstransfer',
]);
const NET_INLINE_RE =
  /(?:^|[\s;|&(`'"/\\])(?:curl|wget)(?:\.exe)?\s+(?:-|https?:|[\w.-]+\.[a-z]{2,})|New-Object\s+(?:System\.)?Net\.WebClient|\[System\.Net\.(?:WebClient|Http)/i;
// .NET network classes and cmdlets used inside a PowerShell expression; judged per subcommand, not for text readers or
// git, so a search or a commit message that names them is not blocked.
const NET_DOTNET_RE =
  /New-Object\s+(?:System\.)?Net\.(?:Sockets|Http|WebRequest|HttpWebRequest|WebSockets)|\[(?:System\.)?Net\.(?:Sockets|Http|WebRequest|HttpWebRequest|WebSockets|WebClient)|\bInvoke-(?:WebRequest|RestMethod)\b|\bStart-BitsTransfer\b/i;
// Network calls inside inline interpreter code (node -e, python -c, perl -e, ruby -e, deno eval, bun -e).
const INLINE_NET_RE =
  /\bfetch\s*\(|\b(?:require|import)\s*\(\s*['"](?:node:)?(?:https?|http2|net|dgram|tls)['"]|\bfrom\s+['"](?:node:)?(?:https?|http2|net|dgram|tls)['"]|\b(?:urllib|requests|httpx|aiohttp|socket|ftplib|smtplib|telnetlib)\b|\bhttp\.client\b|\bXMLHttpRequest\b|\bWebSocket\b|\bNet::HTTP\b|\bLWP::|\bIO::Socket\b|\bDeno\.connect\b/i;
// Deploy, publish, process or sign in: Fabric CLI, fabric-cicd, the Power BI cmdlets (MicrosoftPowerBIMgmt: every
// verb but Get-/Disconnect-), pbi-tools, Tabular Editor 2 and 3, the SSIS wizard, az, Reporting Services (rs.exe
// scripts and the ReportingServicesTools writers) and Analysis Services (SqlServer module processing, backup, restore,
// the deployment utility). Membership cmdlets are denied earlier (ROLE_MEMBER_CMDLET_RE). Judged per subcommand and without
// the words that are text (a commit message, a search pattern), so searching for or committing such a word stays free.
const DEPLOY_RE =
  /\b(?:fab(?:\.exe)?\s+(?:deploy|import|export|create|cp|mv|rm|set|run|api|mkdir|ln|auth|job|acl|label|start|stop|assign|unassign)\b|publish_all_items|unpublish_all_orphan_items|Invoke-PowerBIRestMethod|(?:Connect|Login|Publish|New|Remove|Set|Add|Copy|Import|Export|Restore|Resume|Invoke)-PowerBI\w*|pbi-tools(?:\.exe)?\s+deploy|TabularEditor3?(?:\.exe)?\b[^|;&\n]*\s-(?:D|deploy)\b|ISDeploymentWizard\b|az(?:\.cmd)?\s+(?:rest|resource|login|powerbi)\b|rs(?:\.exe)?\s+(?:-\S+\s+\S+\s+)*-(?:i\s+\S+\.rss\b|s\s+\S*reportserver)|(?:Write|Set|New|Remove|Copy|Publish)-Rs(?:Rest)?\w+|Invoke-Process(?:ASDatabase|Table|Partition|Cube|Dimension)\b|Merge-Partition\b|(?:Backup|Restore)-ASDatabase\b|Microsoft\.AnalysisServices\.Deployment(?:\.exe)?\b)/i;
// A Copilot CLI session in lab mode once ran a project's `script-model.ps1 -Deploy -Replace` without a
// prompt, because lab passes the script-run ask and the guard cannot see what a script does. A deploy typed on the
// command line is the floor in every mode: a `-Deploy` switch, TMSL `createOrReplace`, `Invoke-ASCmd`, or a script
// named deploy*.ps1. Judged per subcommand and never for text readers or git, so searching for, printing or
// committing such a word stays free.
const DEPLOY_SWITCH_RE = /(?:^|\s)-{1,2}deploy(?:[:=\s]|$)|\bcreateOrReplace\b|\bInvoke-ASCmd\b|(?:^|[\s"'`=\\/])deploy[^\s"'`\\/]*\.ps1\b/i;
const SAFE_WITH_SECRET_PATH = new Set(['ls', 'dir', 'test', '[', 'stat', 'file', 'test-path']);

// Words of a command that are text, not file names: a commit message, a search pattern. What they say ("fix: ignore .env
// files", `grep Publish-PowerBIReport`) touches no file, so the secret-name scan leaves them out; the words next to them
// (`grep -r secret .env`, `git commit -m x .env`) stay in it. A word is dropped only where the command's own syntax makes it
// certain: an option the guard does not know could take the next word as its value (`rg -g .env foo` searches .env,
// `git commit -F -m .env` commits it), so any unknown option before the text leaves every word in the scan. `git commit -F
// <file>` stays in it too, because the commit reads that file.
const GREP_LIKE = new Set(['grep', 'egrep', 'fgrep', 'rg']);
const GIT_MESSAGE_SUBCOMMANDS = new Set(['commit', 'tag', 'merge', 'stash', 'notes']);
const GIT_SEARCH_SUBCOMMANDS = new Set(['log', 'show', 'diff', 'rev-list', 'shortlog', 'whatchanged', 'reflog']);
// Short flags that take no value in grep, rg and git grep alike, and the few more that grep itself has.
const SEARCH_FLAGS = 'invwxclLhHoqsFaIP';
const GREP_FLAGS = `${SEARCH_FLAGS}rRzZTUbEG`;
// Options of git commit, log and the like that take no separate value: plain flags, a number (-5) and a long option with its
// value attached. Any other option may take the word after it.
const GIT_PLAIN_OPTION_RE = /^(?:-[asvqeoipw]+|-\d+|--(?:amend|no-edit|all|signoff|allow-empty|allow-empty-message|verbose|quiet|dry-run|edit|oneline|stat|graph|decorate|patch|name-only|name-status|no-merges|merges|first-parent|reverse|follow|abbrev-commit|no-color|color|shortstat|numstat|summary|raw|invert-grep|all-match|regexp-ignore-case|extended-regexp|fixed-strings|perl-regexp|no-pager)|--[\w-]+=[\s\S]*)$/;
/**
 * Index of the pattern among the words of grep, rg or git grep: the first word that is not an option (after `--` every word
 * is one). -1 when there is none, when an option supplies the patterns (-e, -f, a cluster holding one, --regexp, --file, any
 * longer spelling that starts --re or --fi, rg's --files) and so leaves every word a file name, or when an option other than
 * the plain `flags` stands before it: it could take the next word as its value.
 */
function searchPatternAt(words, flags) {
  if (words.some((w) => /^-[A-Za-z0-9]*[ef]/.test(w) || /^--(?:re|fi)/i.test(w))) return -1;
  for (let i = 0; i < words.length; i++) {
    const w = words[i];
    if (w === '--') return i + 1 < words.length ? i + 1 : -1;
    if (/^-[A-Za-z]+$/.test(w) && [...w.slice(1)].every((c) => flags.includes(c))) continue; // plain flags
    if (/^--[\w-]+=/.test(w)) continue; // a long option with its value attached
    if (w.startsWith('-') && w !== '-') return -1;
    return i;
  }
  return -1;
}
/** The indexes among `args` of the words of one command that are text rather than file names. */
function textWordIndexes(prog, args) {
  const text = new Set();
  if (GREP_LIKE.has(prog)) {
    const at = searchPatternAt(args, prog === 'rg' ? SEARCH_FLAGS : GREP_FLAGS);
    if (at >= 0) text.add(at);
  } else if (prog === 'findstr') {
    // Switches are /x words with their value attached (/c:text, /g:file); /c: and /g: take the search strings off the word list.
    let given = false;
    args.forEach((a, i) => {
      if (/^[/-]c:/i.test(a)) text.add(i);
      given ||= /^[/-][cg]:/i.test(a);
    });
    const at = given ? -1 : args.findIndex((a) => !/^[/-]/.test(a));
    if (at >= 0) text.add(at);
  } else if (prog === 'select-string' || prog === 'sls') {
    // -Pattern (four letters or more of it) names the pattern; without it the first word is the pattern, when it is not an option.
    let named = false;
    for (let i = 0; i < args.length; i++) {
      const m = /^-([A-Za-z]{4,7})(?::([\s\S]*))?$/.exec(args[i]);
      if (!m || !'pattern'.startsWith(m[1].toLowerCase())) continue;
      named = true;
      if (m[2] !== undefined) text.add(i);
      else if (i + 1 < args.length) text.add(++i);
    }
    if (!named && args.length && !args[0].startsWith('-')) text.add(0);
  } else if (prog === 'git') {
    // The value of a global option is never the subcommand: `git --attr-source commit show -m HEAD:.env` is a show.
    const at = gitSubcommandIndex(args);
    const sub = (args[at] ?? '').toLowerCase();
    // An option the guard does not know could take the next word as its value: from there on only the words that are one
    // word by themselves (-m<message>, --grep=<text>) are text; `plain` is false once such an option has been seen.
    let plain = true;
    if (GIT_MESSAGE_SUBCOMMANDS.has(sub)) {
      // -m<message>, --message=<message> are one word; -m <message>, --message <message> and clusters of plain flags ending in m
      // (-am <message>) take the next word. A letter that takes a value (-S, -u, -F, -C, -c, -t) before the m would change
      // which word is the message, so such a cluster is not read.
      for (let i = at + 1; i < args.length && args[i] !== '--'; i++) {
        const m = /^-([asvqoiep]*)m([\s\S]*)$/.exec(args[i]);
        if (/^--message=/.test(args[i]) || (m && m[2])) text.add(i);
        else if (args[i] === '--message' || m) {
          if (plain && i + 1 < args.length) text.add(++i);
        } else if (args[i].startsWith('-') && !GIT_PLAIN_OPTION_RE.test(args[i])) plain = false;
      }
    } else if (GIT_SEARCH_SUBCOMMANDS.has(sub)) {
      // --grep, --author and --committer, -S<string> and -G<regex>: attached to the option, or the next word.
      for (let i = at + 1; i < args.length && args[i] !== '--'; i++) {
        if (/^--(?:grep|author|committer)=/.test(args[i]) || /^-[SG][\s\S]/.test(args[i])) text.add(i);
        else if (/^--(?:grep|author|committer)$/.test(args[i]) || args[i] === '-S' || args[i] === '-G') {
          if (plain && i + 1 < args.length) text.add(++i);
        } else if (args[i].startsWith('-') && !GIT_PLAIN_OPTION_RE.test(args[i])) plain = false;
      }
    } else if (sub === 'grep') {
      // Only the words before `--` can hold the pattern; `git grep -- <pathspec>` has none.
      const words = args.slice(at + 1);
      const end = words.indexOf('--');
      const found = searchPatternAt(end < 0 ? words : words.slice(0, end), `${SEARCH_FLAGS}E`);
      if (found >= 0) text.add(at + 1 + found);
    }
  }
  return text;
}
/**
 * textWordIndexes of one subcommand, none while it holds an unquoted `(` (PowerShell evaluates a parenthesized expression, so
 * `git commit -m (gc(".env"))` commits the file and `echo (fab deploy x)` runs the command, whatever the word's place), none
 * while a backtick stands before a quote (PowerShell reads `"` as a literal quote there, so the words and lines between the two
 * quotes are not one string, but the quote walker and the tokenizer see one: ``git commit -m `"x<newline>gc .env<newline>z`"``
 * runs `gc .env`) and none when `free` is false (the pipeline goes on into something that is not a plain reader, which may run
 * the text). A word with a wildcard, brace, tilde, variable, redirect, `&` or line break stays in the scan unless every place it
 * stands in is quoted: unquoted, the shell expands it into other words or ends the command there (`grep *.env README.md` reads
 * every .env file, `grep <.env x` reads .env, `grep x&fab deploy y f` runs fab).
 */
function textWordsOf(sub, prog, args, free = true) {
  if (!free || hasUnquotedParen(sub) || /`["']/.test(sub)) return new Set();
  const text = textWordIndexes(prog, args);
  for (const i of text) {
    const w = args[i];
    if (!/[*?[{~$&<>|;\r\n\x85]/.test(w)) continue;
    // The word as written must stand quoted in every place; one that quotes only a part of it (.e'*') is not found as it is.
    // An option written in one word with its value (`--message="a -> b"`, `-m"x"`) counts by the places of that value.
    const quotedEverywhere = ([prefix, value]) => {
      if (prefix && !sub.includes(`${prefix}"`) && !sub.includes(`${prefix}'`)) return false;
      const places = sub.split(value).length - 1;
      return places > 0 && places === sub.split(`${prefix}"${value}"`).length + sub.split(`${prefix}'${value}'`).length - 2;
    };
    if (!optionValueForms(w).some(quotedEverywhere)) text.delete(i);
  }
  return text;
}
/**
 * The ways a text word can be written with one quoted part: the whole word (`"a -> b"`), or an option prefix followed by the
 * quoted rest (`--message="a -> b"`, `-m"a -> b"`, `-am'a -> b'`), as [prefix, quoted part] pairs. An option name is short,
 * so prefixes past 40 characters are not tried (a long message stays fast to judge).
 */
function optionValueForms(word) {
  const forms = [['', word]];
  for (let k = 2; k < Math.min(word.length, 40); k++) {
    if (/^(?:--[\w-]+=|-[A-Za-z]+)$/.test(word.slice(0, k))) forms.push([word.slice(0, k), word.slice(k)]);
  }
  return forms;
}
/** One command's text without the words that are not file names (textWordsOf); the command itself when it has none. */
function pathTextOf(sub, free = true) {
  const raw = tokenize(sub);
  const tokens = normalizeTokens(raw);
  const text = tokens.length ? textWordsOf(sub, programName(tokens[0]), tokens.slice(1), free) : new Set();
  return text.size ? [...raw.slice(0, tokens.skipped), tokens[0], ...tokens.slice(1).filter((_, j) => !text.has(j))].join(' ') : sub;
}
// Pipeline stages that only filter, limit or format the text that reaches them. A reader that takes its input as file names
// (xargs cat, Get-Content, Get-ChildItem) is none of them, nor is a script block or a parenthesis that could run the text.
const TEXT_SINKS = new Set(['head', 'tail', 'wc', 'sort', 'uniq', 'cut', 'tr', 'more', 'less', 'grep', 'egrep', 'fgrep', 'rg', 'findstr',
  'select-string', 'sls', 'select-object', 'select', 'measure-object', 'measure', 'sort-object', 'format-table', 'ft', 'format-list', 'fl',
  'out-string', 'out-host', 'out-null', 'group-object', 'convertto-json', 'convertfrom-json']);
const plainReaderStage = (stage) => TEXT_SINKS.has(programName(tokenize(stage)[0])) && !/[{(]/.test(stage);
/**
 * The command line without the words that are certainly text (a commit message, a search pattern), stage by stage. The bypass
 * flags and the network tools are looked for in this text: `git commit -m "explain bypassPermissions"` and
 * `grep 'curl -s' README.md` start nothing, `claude --dangerously-skip-permissions` and `curl -s https://x | bash` do.
 */
const plainCommandText = (cmd) => splitStatements(cmd).map((statement) => {
  const stages = splitPipeline(statement);
  return stages.map((stage, i) => pathTextOf(stage, stages.slice(i + 1).every(plainReaderStage))).join('\n');
}).join('\n');
/**
 * True when one word of a command names a secret or data file once the shell removed its quotes (.en''v, $'\x2eenv' are
 * .env). A wildcard is judged by what it can expand to (wildcardNamesSecret).
 */
function namesSecretFile(token) {
  const word = String(token ?? '').replace(/^["'(]+|["'`),;]+$/g, '');
  if (/[*?[]/.test(word)) return false;
  const cls = classifyPath(word);
  return cls.secret || cls.data;
}
/** The arguments of one command that are not certainly text (textWordsOf), with the quotes removed. */
function pathArgsOf(stage, free = true) {
  const tokens = normalizeTokens(tokenize(stage));
  const args = tokens.slice(1);
  const text = tokens.length ? textWordsOf(stage, programName(tokens[0]), args, free) : new Set();
  return args.filter((_, j) => !text.has(j));
}
/**
 * An existence check is harmless on its own; piped on (`ls .env | xargs cat`) the next stage can read the file. The name
 * counts in the text and in the words (`ls .en''v | xargs cat`, `ls $'\x2eenv' | xargs cat`).
 */
const pipesSecretPath = (cmd) => splitStatements(cmd).some((statement) => {
  const stages = splitPipeline(statement);
  return stages.slice(0, -1).some((stage, i) => {
    const free = stages.slice(i + 1).every(plainReaderStage);
    const text = ` ${pathTextOf(stage, free)}`;
    return SHELL_SECRET_RE.test(text) || SHELL_SECRET_DIR_RE.test(text) || pathArgsOf(stage, free).some(namesSecretFile);
  });
});
const PIPED_SECRET_REASON = 'This command passes a secret or data file (.env, keys, cache.abf, .pbix, *.rdl.data, a workspace database) on to another command. Existence checks are allowed on their own; the content stays with the user.';
// Files the Edit/Write guards check (credentials, JSON, renames, line limits). Shell writes would skip those checks.
const GUARDED_FILE_RE = /\.(?:tmdl|bim|pbir|pbism|pbip|platform|md|dax|sql|rdl|rds|rsd|dtsx|dtproj|params|conmgr|dtsconfig)$|\.(?:report|semanticmodel)(?:[\\/]|$)/i;
const SHELL_WRITERS = new Set([
  'tee', 'tee-object', 'set-content', 'sc', 'add-content', 'ac', 'out-file', 'new-item', 'ni', 'clear-content', 'clc',
  'copy-item', 'cpi', 'copy', 'cp', 'move-item', 'mi', 'move', 'mv', 'rename-item', 'rni', 'ren', 'touch', 'truncate',
  'export-csv', 'epcsv', 'export-clixml',
  // Copy, extract and link programs write where their arguments point.
  'robocopy', 'xcopy', 'tar', 'unzip', '7z', 'expand-archive', 'mklink', 'fsutil', 'new-hardlink',
]);
// Redirect targets: `> f`, `>> f`, `1> f`, `2> f`, `&> f`, `*> f`, `>| f`, `>& f`. A stream duplication (`2>&1`, `>&2`)
// names no file. A `<`, `>` or `&` right before the operator belongs to another operator (`<>`, `>>`, `&&`).
const REDIRECT_TARGET_RE = /(?:^|[^<>&])(?:[\d*]*>>?\|?|&>>?)(?:&(?!\d))?\s*(?:"([^"]*)"|'([^']*)'|([^\s;|&<>]+))/g;
/** The files a command line redirects into, quotes removed: the one matcher every writer check and the scope guard use. */
export const redirectTargets = (text) => [...String(text ?? '').matchAll(REDIRECT_TARGET_RE)].map((m) => m[1] ?? m[2] ?? m[3]);
/**
 * The files a command line reads through an input redirect outside quotes (third review, item 2): `<file`, `< file`,
 * `0<file`, `<>file` (opened to read and write), the word joined from its quoted parts (`<"b/x"`). Not a here-document or
 * a here-string (`<<`, `<<<`), process substitution (`<(...)`) or a descriptor (`<&3`); a `<` inside quotes is text.
 */
function inputRedirectTargets(text) {
  const s = String(text ?? '');
  const out = [];
  let quote = null;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (quote) {
      if (c === quote) quote = null;
      else if (quote === '"' && c === '\\') i++;
      continue;
    }
    if (c === "'" || c === '"') {
      quote = c;
      continue;
    }
    if (c !== '<' || s[i - 1] === '<' || /[<(&]/.test(s[i + 1] ?? '')) continue;
    let j = i + 1;
    if (s[j] === '>') j++;
    while (s[j] === ' ' || s[j] === '\t') j++;
    let word = '';
    let inner = null;
    for (; j < s.length; j++) {
      const d = s[j];
      if (inner) {
        if (d === inner) inner = null;
        else word += d;
      } else if (d === "'" || d === '"') inner = d;
      else if (/[\s;|&<>()]/.test(d)) break;
      else word += d;
    }
    if (word) out.push(word);
    i = j - 1;
  }
  return out;
}
// The same targets as whole shell words, quoted parts included (`> ".cl"aude/x` is one word, `.claude/x`): the guardrail
// check reads each in every spelling (fileWordSpellings).
const REDIRECT_WORD_RE = /(?:^|[^<>&])(?:[\d*]*>>?\|?|&>>?)(?:&(?!\d))?\s*((?:"[^"]*"|'[^']*'|[^\s;|&<>"'])+)/g;
const redirectWords = (text) => [...String(text ?? '').matchAll(REDIRECT_WORD_RE)].map((m) => m[1]);
/**
 * The spellings of one shell word that names a file: as written, with its quotes removed (bash and PowerShell join the
 * quoted parts of a word: `.cl''aude`, `.cla'u'de` and `".cl"aude` are `.claude`) and as the tokenizer reads it (bash's
 * ANSI-C `$'\x2eclaude'` decoded).
 */
const fileWordSpellings = (word) => {
  const w = String(word ?? '');
  return [...new Set([w, w.replace(/["']/g, ''), ...tokenize(w)])].filter(Boolean);
};
/** A shell word placed in a folder without collapsing `..` as text: projectRelForms walks it from where a link points. */
const placedIn = (from, word) => (path.isAbsolute(word) ? word : `${String(from).replace(/[\\/]+$/, '')}/${word}`);
/**
 * True when a word that names a file reaches a guardrail path (`test` on a POSIX path, GUARD_PATH_RE by default): in any
 * spelling (fileWordSpellings), or resolved from the shell's folder `base` to its project-relative forms (projectRelForms:
 * `//` and `/./` collapsed, a trailing dot dropped, an existing symlink or junction followed), so `.claude//settings.json`,
 * `./.claude/./settings.json` and `c/settings.json`, where `c` is a link to `.claude`, count too. A word holding a variable or
 * a wildcard is judged as written only, and so is a relative word after a `cd` the guard cannot place (`base` null).
 */
function fileWordReaches(word, base, test = (rel) => GUARD_PATH_RE.test(` ${rel}`)) {
  const spellings = fileWordSpellings(word);
  if (spellings.some(test)) return true;
  return spellings.some((s) => {
    if (/[$%`*?[]/.test(s)) return false;
    if (process.platform !== 'win32' && FOREIGN_ABSOLUTE_RE.test(s)) return false;
    const native = process.platform === 'win32' ? nativePath(s) : s;
    if (base === null && !path.isAbsolute(native)) return false;
    return projectRelForms(placedIn(base || PROJECT_DIR, native)).some(test);
  });
}
// A word longer than this is never walked (third review, item 1): canonicalPathOf walks a missing path back one segment at a
// time, so a 32 KB word through a link took 21 s, past the hook's timeout. Such a word is unresolvable: no secret check by its
// resolved forms (the plain-name checks still apply) and never routine (pathsStayInside), so it asks or is denied, never passes.
const MAX_RESOLVED_WORD = 4096;
// resolvedFileForms per shell folder and word, for one command line (third review, item 1): the secret check, the pipe-stage
// rule and the routine check of every spelling resolve a word once. analyzeShellCommand starts a fresh one for each command;
// routineShell keeps the one of the same command line (the guard judges a command first, then asks whether it is routine).
let formsMemo = { command: undefined, map: new Map() };
/** Starts the memo of resolvedFileForms for `command`; `reuse` keeps the current one when it belongs to the same command. */
function startFormsMemo(command, { reuse = false } = {}) {
  if (!reuse || formsMemo.command !== command) formsMemo = { command, map: new Map() };
}
/**
 * The paths one file word of a command opens once its shell resolves it from its folder `base` (audit 2026-10-31, second
 * round, A1; third round, R3): each spelling of the word (fileWordSpellings), the value of an option written in one word
 * with it (`-Path:x`, `--file=x`) and each item of a PowerShell list (`README.md,b\credentials`), placed in `base` without
 * collapsing `..` as text, as its project-relative forms (projectRelForms: `..` collapsed as text, and walked from where a
 * link points) and, when the walk leaves the project, as that absolute path. A wildcard word is placed by its folder before
 * the first wildcard, the pattern kept after it (`b/cred*` with b -> .aws gives `.aws/cred*`). [] for a word holding a
 * variable, a wildcard in its first segment (`*.md`, `b*`), a Windows spelling off Windows, and a relative word after a `cd` the
 * guard cannot place (`base` null). The secret check of a command and the routine check classify every one of them. null
 * for a word over MAX_RESOLVED_WORD characters, which is not walked. Resolved once per command line (formsMemo).
 */
function resolvedFileForms(word, base) {
  const key = `${base === null ? '' : base || PROJECT_DIR}\u0000${word}`;
  if (formsMemo.map.has(key)) return formsMemo.map.get(key);
  // A long word padded with `./` or repeated separators (`b/./././credentials`) opens what the short spelling opens: it is
  // judged by that one. Its first two characters stay (`//host`, `\\?\`).
  let w = String(word ?? '');
  if (w.length > MAX_RESOLVED_WORD) w = w.slice(0, 2) + w.slice(2).replace(/([\\/])(?:\.?[\\/])+/g, '$1');
  const forms = w.length > MAX_RESOLVED_WORD ? null : walkedFileForms(w, base);
  formsMemo.map.set(key, forms);
  return forms;
}
/** resolvedFileForms without the memo and the length limit: the walk itself. */
function walkedFileForms(word, base) {
  const out = new Set();
  const spellings = fileWordSpellings(word).flatMap((s) => {
    const valued = /^(?:--[\w-]+=|-[A-Za-z]+:)(?=.)/.exec(s);
    return valued ? [s, s.slice(valued[0].length)] : [s];
  }).flatMap((s) => (s.includes(',') && !s.startsWith('-') ? [s, ...s.split(',')] : [s]));
  for (const spelling of spellings) {
    // Windows opens a device, administrative-share or stream spelling as the drive path (windowsDrivePath, R5).
    const s = process.platform === 'win32' ? windowsDrivePath(spelling) : spelling;
    if (!s || /[$%`]/.test(s)) continue;
    const wild = /[*?[]/.exec(s);
    const literal = wild ? s.slice(0, wild.index).replace(/[^\\/]*$/, '') : s; // a wildcard word: its folder, up to the last separator
    if (!literal) continue;
    const pattern = wild ? `/${toPosix(s.slice(literal.length))}` : '';
    if (process.platform !== 'win32' && FOREIGN_ABSOLUTE_RE.test(literal)) continue;
    const native = process.platform === 'win32' ? nativePath(literal) : literal;
    if (base === null && !path.isAbsolute(native)) continue;
    const placed = withoutTrailingDots(placedIn(base || PROJECT_DIR, native));
    // projectRelForms with one walk (every word of a command comes here): `..` collapsed as text, and walked as bash does.
    const lexical = projectRel(placed);
    if (lexical) out.add(`${lexical}${pattern}`);
    const walked = canonicalPathOf(placed);
    out.add(`${projectRel(walked) ?? toPosix(walked)}${pattern}`);
  }
  return [...out];
}
/**
 * A Windows spelling as the file system opens it (audit 2026-10-31, third round, R5): the drive path behind a device
 * spelling (`\\?\C:\x`, `//./C:/x`) or a local administrative share (`\\localhost\C$\x`, `//127.0.0.1/C$/x`, the machine's
 * own name; LOCAL_HOSTS), and a file without its stream (`x\credentials::$DATA`, `x\a.md:stream`; only after a separator, so
 * a drive `C:` stays). null for any other device path (`\\?\UNC\...`, `\\.\pipe\x`): it names no file the walk can place.
 */
function windowsDrivePath(s) {
  let p = String(s ?? '');
  if (/^[\\/]{2}[?.][\\/]/.test(p)) {
    if (!/^[\\/]{2}[?.][\\/][A-Za-z]:(?:[\\/]|$)/.test(p)) return null;
    p = p.slice(4);
  } else {
    const share = /^[\\/]{2}([^\\/]+)[\\/]([A-Za-z])\$(?=[\\/]|$)/.exec(p);
    if (share && LOCAL_HOSTS.has(share[1].toLowerCase())) p = `${share[2]}:${p.slice(share[0].length) || '\\'}`;
  }
  return p.replace(/([\\/][^\\/:]+):[^\\/]*$/, '$1');
}
/** True when one of the paths a word opens (resolvedFileForms) is a secret or data file; false for a word too long to resolve. */
const opensSecretFile = (word, base) => (resolvedFileForms(word, base) ?? []).some((form) => {
  const cls = classifyPath(form);
  return cls.secret || cls.data;
});
// A guardrail folder by its project-relative path: the folder itself, or a guardrail path read as a folder (`.claude/agents`).
// A link to or from one lets a later write reach the guardrail files under a name no path check knows.
const GUARD_ROOT_REL_RE = /^(?:\.claude|hardening|\.github|\.githooks|\.vscode|\.cursor)$/i;
const guardLinkRel = (rel) => {
  const n = path.posix.normalize(toPosix(rel)).replace(/\/+$/, '');
  return GUARD_ROOT_REL_RE.test(n) || GUARD_PATH_RE.exec(` ${n}/`)?.index === 0;
};
/**
 * True when one of a link command's words (linkWordsOf) is a guardrail folder of this project: each word in every spelling
 * (fileWordSpellings), resolved to its project-relative forms (projectRelForms) from the shell's folder and, for a relative
 * word, also from each other word and that word's folder, since a link's target is read from where the link is
 * (`ln -s ../.claude docs/c`, `ln -t .github x`). Only the project-relative form counts: a path outside the project is no
 * guardrail (`ln -s /opt/hardening x`, `ln -s ../other-repo/.github g`), and neither is a folder of that name elsewhere in
 * it (`docs/hardening`). A word with a variable or a wildcard, and a relative word after a `cd` the guard cannot place, are
 * not judged.
 */
function linkReachesGuard(words, base) {
  const placeable = (s) => !/[$%`*?[]/.test(s) && !(process.platform !== 'win32' && FOREIGN_ABSOLUTE_RE.test(s));
  const spellings = words.map((w) => fileWordSpellings(w).filter(placeable).map((s) => (process.platform === 'win32' ? nativePath(s) : s)));
  const start = base || PROJECT_DIR;
  return spellings.some((own, i) => own.some((s) => {
    if (path.isAbsolute(s)) return projectRelForms(s).some(guardLinkRel);
    if (base === null) return false;
    const others = spellings.flatMap((o, j) => (j === i ? [] : o)).map((o) => path.resolve(start, o));
    return [start, ...others, ...others.map((o) => path.dirname(o))].some((from) => projectRelForms(placedIn(from, s)).some(guardLinkRel));
  }));
}
/**
 * The link names and targets of a command that creates a symbolic link, a junction or a hard link: `ln`, `mklink` (also
 * behind `cmd /c`), and `New-Item`/`ni` with an -ItemType (or -Type, any prefix PowerShell accepts) of SymbolicLink,
 * Junction or HardLink; [] for any other command. Every word that is no option counts, the value of `-Path:x` too.
 */
function linkWordsOf(prog, args) {
  if (prog === 'ln') return args.flatMap((a) => (a.startsWith('--target-directory=') ? [a.slice(19)] : a.startsWith('-') ? [] : [a]));
  if (prog === 'mklink') return args.filter((a) => !/^\/[dhj]$/i.test(a));
  if (prog !== 'new-item' && prog !== 'ni') return [];
  let link = false;
  const words = [];
  for (let i = 0; i < args.length; i++) {
    const type = /^-(?:it(?:e(?:m(?:t(?:y(?:pe?)?)?)?)?)?|ty(?:pe?)?)(?::(.*))?$/i.exec(args[i]);
    if (type) {
      // FileSystem provider: the value is a prefix of the item type (`sym`, `j`); a wildcard may match a link type too.
      const kind = String(type[1] ?? args[++i] ?? '').toLowerCase();
      if (kind && (/[*?]/.test(kind) || ['symboliclink', 'junction', 'hardlink'].some((k) => k.startsWith(kind)))) link = true;
      continue;
    }
    const colon = /^-[A-Za-z]+:(.+)$/.exec(args[i]);
    if (colon) words.push(colon[1]);
    else if (!args[i].startsWith('-')) words.push(args[i]);
  }
  return link ? words : [];
}
// Names a wildcard may expand to: a content reader given `*.env` or `.e*v` reads the secret like a plain name would.
// Only a pattern with a literal dot counts (`*.pem`, `.e*v`); a bare `*` or `a*` is merely not routine (Claude Code prompts).
const SECRET_SAMPLES = ['.env', '.env.local', 'x.pem', 'x.key', 'x.pfx', 'x.p12', 'x.publishsettings', 'x.kdbx', 'x.abf', 'x.pbix',
  'x.rdl.data', '.npmrc', '.netrc', '.pypirc', '.git-credentials', 'id_rsa', 'id_ed25519', 'id_ecdsa', '.pgpass', 'pgpass.conf',
  '.pg_service.conf', 'pg_service.conf', '.my.cnf', '.mylogin.cnf'];
function wildcardNamesSecret(token) {
  const base = toPosix(String(token ?? '').replace(/^["'(]+|["'`),;]+$/g, '')).split('/').pop();
  if (!/[*?[]/.test(base) || !base.includes('.')) return false;
  const re = globToRegExp(base);
  return SECRET_SAMPLES.some((s) => re.test(s));
}
const INTERPRETERS = new Set(['node', 'python', 'python3', 'py', 'perl', 'ruby', 'pwsh', 'powershell', 'deno', 'bun']);
// Running a script file: what it writes is not visible to the shell analysis. The harness's own checks are exempt.
const SCRIPT_RUNNERS = new Set([...INTERPRETERS, 'bash', 'sh', 'zsh', 'rscript', 'tsx', 'ts-node']);
const SCRIPT_FILE_RE = /\.(?:mjs|cjs|js|ts|py|ps1|sh|bash|zsh|rb|pl|r)$/i;
// Environment dumps through an interpreter or the OS; reading one named variable stays allowed.
const ENV_DUMP_RE = /process\.env\b(?!\s*(?:\.\s*\w|\[))|os\.environ\b(?!\s*(?:\[|\.\s*get\b))|\bGetEnvironmentVariables\b|\/proc\/[\w$]+\/environ\b/i;
// PowerShell's Environment provider read like a file: `Get-Content Env:X`, `gi env:*`, `Get-ChildItem Environment::`,
// `Microsoft.PowerShell.Core\Environment::X`, also as the value of a parameter (-Path:Env:X) or one item of a comma list. It
// prints the variables, secrets included, so these readers are denied like `Get-ChildItem env:` always was.
const ENV_PROVIDER_RE = /^[$@(]*(?:-[A-Za-z]+[:=])?[$@(]*(?:env:|(?:[\w.-]+[\\/])?environment::)/i;
const ENV_PROVIDER_READERS = new Set(['get-childitem', 'gci', 'ls', 'dir', 'get-item', 'gi', 'get-itemproperty', 'gp',
  'get-itempropertyvalue', 'gpv', 'get-content', 'gc', 'cat', 'type', 'select-string', 'sls', 'copy-item', 'cpi', 'copy', 'cp']);
const namesEnvProvider = (word) => word.split(',').some((part) => ENV_PROVIDER_RE.test(part));
// The same read nested in parentheses behind another command, which prints it: `Write-Host (Get-Item Env:X).Value`.
const NESTED_ENV_READ_RE = new RegExp(String.raw`(?:^|[\s(;|&{])(?:${[...ENV_PROVIDER_READERS].join('|')})\s+(?:-\w+[:\s]\s*)*["'$@(]*(?:env:|(?:[\w.-]+[\\/])?environment::)`, 'i');
const FILE_API_RE =
  /\b(?:WriteAll(?:Text|Lines|Bytes)|AppendAll(?:Text|Lines)|writeFileSync|appendFileSync|writeFile|appendFile|createWriteStream|copyFileSync|renameSync|rmSync|unlinkSync|cpSync)\b|\bopen\s*\([^)]*['"][wax]\+?b?['"]|\.write_(?:text|bytes)\s*\(|\bshutil\.(?:copy\w*|move|rmtree)\b/i;
// Inline code that starts other programs: what they do is out of the shell analysis's sight.
const PROCESS_API_RE = /\bchild_process\b|\b(?:execSync|execFileSync|spawnSync|spawn|execFile)\s*\(|\bsubprocess\b|\bos\.(?:system|popen)\b|\bProcess\]?::Start\b|\bDeno\.(?:run|Command)\b|\bBun\.spawn/i;
// One stream or document writer, without capturing (for the guardrail check).
const DOC_WRITER_RE = /(?:\.Save|\bStreamWriter\]?(?:::new)?|\b(?:File|XmlWriter)\]?::(?:Create|OpenWrite))\s*\(/i;
// Inline code flags per interpreter (node -c is --check, not code).
const INLINE_CODE_FLAGS = {
  node: /^(?:-e|-p|-pe|--eval|--print)$/, bun: /^(?:-e|--eval|-p|--print)$/, deno: /^eval$/,
  python: /^-c$/, python3: /^-c$/, py: /^-c$/, perl: /^-[eE]$/, ruby: /^-e$/,
};
const inlineCode = (prog, args) => Boolean(INLINE_CODE_FLAGS[prog]) && args.some((a) => INLINE_CODE_FLAGS[prog].test(a));
// Document and stream writers: XmlDocument/XDocument .Save(), ElementTree .write(), StreamWriter, File.Create/OpenWrite.
const DOC_WRITE_RE = /(?:\.Save|(?<!std(?:out|err))\.write|\bStreamWriter\]?(?:::new)?|\b(?:File|XmlWriter)\]?::(?:Create|OpenWrite))\s*\(([^;|]*)/gi;
const WRITE_TO_GUARDED_REASON =
  'Change PBIP and TMDL, paginated (RDL), Markdown, DAX, SQL and SSIS files with the Edit or Write tool, not from the shell: the harness checks credentials, JSON, XML, renames, object ids and line limits there, and the user reviews the diff. A reference folder (templates/, a report\'s source/, the config\'s "references") is not written at all. Shell commands may read files, run git and the static check.';

const GUARDED_MENTION_RE = /\.(?:tmdl|bim|pbir|pbism|pbip|md|dax|sql|rdl|rds|rsd|dtsx|dtproj|params|conmgr|dtsconfig)\b|\.(?:report|semanticmodel)[\\/]/i;
const CD_PROGRAMS = new Set(['cd', 'pushd', 'chdir', 'set-location', 'sl', 'push-location']);
// Back to a folder this command line cannot name (the directory stack): relative paths after it cannot be placed.
const POP_PROGRAMS = new Set(['popd', 'pop-location']);
const GUARD_DIR_RE = /(?:^|\/)(?:\.claude|hardening|\.githooks)(?:\/|$)/i;
const PATH_PARAMS = new Set(['-path', '-literalpath', '-lp', '-pspath', '-filepath', '-destination', '-destinationpath', '-name', '-target']);
const VALUE_PARAMS = new Set(['-value', '-encoding', '-itemtype', '-type', '-delimiter', '-stream', '-filter', '-include', '-exclude', '-inputobject', '-width']);

const DELETE_PROGRAMS = new Set(['rm', 'del', 'erase', 'remove-item', 'ri', 'rmdir', 'rd', 'unlink']);
// The folders a delete never reaches, by any delete program and in any letter case (Windows): the repository history and the
// harness guardrails.
const DELETE_GUARD_RE = /(?:^|\/)(?:\.git|\.claude|\.githooks|hardening)(?:\/|$)/i;
// Writers that put what the pipe carries into their own file argument (`ls hardening | tee list.txt`): behind xargs they act
// on the piped names instead.
const PIPE_SINKS = new Set(['tee', 'tee-object', 'out-file', 'export-csv', 'epcsv', 'export-clixml']);
const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * True when a command's text names a reference folder: `templates/`, a report's `source/` folder or a prefix from the
 * config's `references` (passed by the guard in ctx). Used to treat variables and inline code in such a command as
 * possible reference writes.
 */
function mentionsReference(text, references) {
  const t = toPosix(String(text ?? '')).toLowerCase();
  if (/(?:^|[^\w.-])templates\/|(?:^|[^\w.-])reports\/[^/\s'"]+\/source\//.test(t)) return true;
  return referencePrefixes({ references }).some((q) => new RegExp(`(?:^|[^\\w.-])${escapeRe(q)}`).test(t));
}

/** Path arguments of a writer: values of path parameters and positional arguments (not -Value content). */
function writerTargets(args) {
  const out = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i].toLowerCase();
    if (PATH_PARAMS.has(a)) out.push(args[++i]);
    else if (VALUE_PARAMS.has(a)) i++;
    else if (!a.startsWith('-')) out.push(args[i]);
  }
  return out;
}

// A command's own output file: `--out f`, `--out=f`, `--output f`, `-OutFile f`, `-OutputPath f`, `-DestinationPath f`.
const OUTPUT_OPTION_RE = /^(--?(?:out|output|out-?file)|-outfile|-outputpath|-destinationpath)(?:=(.*))?$/i;
/** The values of the output options among a command's arguments: the files it writes. */
const outputOptionValues = (args) => args.flatMap((a, i) => {
  const m = OUTPUT_OPTION_RE.exec(a);
  const value = m ? (m[2] ?? args[i + 1]) : undefined;
  return value === undefined ? [] : [value];
});

/**
 * True when a shell subcommand writes a file the Edit/Write guards would check. `guardedMention` says whether the
 * whole command names such a file, so a target held in a variable ($p = "x.tmdl"; Set-Content $p) counts too.
 */
function writesGuardedFile(sub, prog, args, guardedMention, inPbipFolder = false, inReference = () => false) {
  const target = (token) => {
    const t = String(token ?? '').replace(/["'`),;]+$/, '');
    if (!t || /^(?:\/dev\/null|\$null|nul)$/i.test(t)) return false;
    // Windows drops trailing dots and spaces and reads `file:stream` as the file: 'docs/notes.md.' writes docs/notes.md.
    const [, drive = '', rest] = /^([A-Za-z]:)?([\s\S]*)$/.exec(t);
    const w = withoutTrailingDots(drive + rest.replace(/:[\s\S]*$/, ''));
    return GUARDED_FILE_RE.test(t) || GUARDED_FILE_RE.test(w) || (guardedMention && t.replace(/^["'(]+/, '').startsWith('$')) || (inPbipFolder && !path.isAbsolute(t) && !/^[A-Za-z]:/.test(t)) ||
      inReference(t.replace(/^["'(]+/, '')) || inReference(w.replace(/^["'(]+/, ''));
  };
  if (redirectTargets(sub).some(target)) return true;
  // git writes no file but through a redirect; its other words are a commit message or a revision, not a writer's arguments.
  if (prog === 'git') return false;
  if (SHELL_WRITERS.has(prog) && writerTargets(args).some(target)) return true;
  // In-place editors: sed -i, perl -pi, awk/gawk -i inplace (the file is the last positional argument).
  if (['sed', 'perl', 'awk', 'gawk'].includes(prog) && args.some((a) => /^-\w*i/.test(a) || /^--in-?place/.test(a)) && args.some(target)) return true;
  for (const value of outputOptionValues(args)) if (target(value)) return true;
  for (const m of sub.matchAll(DOC_WRITE_RE)) {
    const first = /^\s*\(*\s*(?:"([^"]*)"|'([^']*)'|([^\s,)]+))/.exec(m[1]);
    if (GUARDED_MENTION_RE.test(m[1]) || (first && target(first[1] ?? first[2] ?? first[3]))) return true;
  }
  const scripted = INTERPRETERS.has(prog) || sub.trimStart().startsWith('[');
  return scripted && FILE_API_RE.test(sub) && guardedMention;
}

// Commands inside a string run by another shell: sh/bash -c, -lc; pwsh -c, -Command; cmd /c|/k (with /s, /q);
// Invoke-Expression|iex. The commands inside { } are scriptBlocks; -EncodedCommand is encodedCommandOf.
const NESTED_COMMAND_RE =
  /(?:\b(?:ba|z|da)?sh|pwsh|powershell)(?:\.exe)?\s+(?:-\w+\s+)*-(?:[a-z]*c|command)\s+(["'])([\s\S]*?)\1|\bcmd(?:\.exe)?\s+(?:\/[sqd]\s+)*\/[ck]\s+(["'])([\s\S]*?)\3|\b(?:Invoke-Expression|iex)\s+(?:-Command\s+)?(["'])([\s\S]*?)\5/gi;
// Script blocks and function bodies: `& { }`, `Invoke-Command -ScriptBlock { }`, `if (...) { }`, `try { } catch { }`, `foreach (...) { }`,
// `function f { }`, `f() { }`, `$sb = { }`. Every { } that is not `${ }` or `@{ }` holds commands. Of nested blocks the innermost
// come first and are blanked, so a block that holds other blocks is judged with its own commands.
const BLOCK_RE = /(?<![$@])\{([^{}]*)\}/g;
const MAX_BLOCK_PASSES = 6;
const MAX_BLOCKS = 200;
/** The distinct bodies of the { } blocks of a command, and whether blocks nested deeper than the passes remain. */
function scriptBlocks(cmd) {
  const bodies = new Set();
  let text = cmd;
  for (let pass = 0; pass < MAX_BLOCK_PASSES && text.includes('{'); pass++) {
    const next = text.replace(BLOCK_RE, (_, body) => {
      if (/[A-Za-z0-9]/.test(body)) bodies.add(body);
      return ' ';
    });
    if (next === text) break;
    text = next;
  }
  return { bodies: [...bodies], tooDeep: new RegExp(BLOCK_RE.source).test(text) };
}
const BLOCKS_REASON = 'This command holds more, or more deeply nested, { } script blocks than the harness analyses. Write the inner commands directly.';
const NESTING_REASON = 'This command nests shells more than three levels deep, which the harness does not analyse. Write the inner command directly.';
// Programs that run code they read from a pipe: `... | iex`, `... | pwsh -`, `... | bash`.
const PIPE_EXECUTORS = new Set(['iex', 'invoke-expression', 'pwsh', 'powershell', 'bash', 'sh', 'zsh', 'dash', 'cmd', 'node', 'python', 'python3', 'py', 'perl', 'ruby']);
/** True when a shell or interpreter at the end of a pipe would run its stdin as code: no script file, no inline command. */
function readsCodeFromStdin(prog, args) {
  const positional = args.filter((a) => a !== '-' && !a.startsWith('-') && !/^\/[a-z?]/i.test(a));
  if (prog === 'pwsh' || prog === 'powershell') {
    return positional.length === 0 && !args.some((a) => /^-(?:c|co|com|comm|comma|comman|command|f|file|e|ec|enc|encodedcommand)$/i.test(a));
  }
  if (SHELL_PROGRAMS.has(prog)) return positional.length === 0 && !args.some((a) => /^-[a-z]*c[a-z]*$/.test(a));
  if (prog === 'cmd') return !args.some((a) => /^\/[ck]$/i.test(a));
  if (INTERPRETERS.has(prog)) {
    return positional.length === 0 && !inlineCode(prog, args) && !args.includes('-m') && !args.some((a) => /^(?:--version|-v|--check|-c|--help|-h)$/i.test(a));
  }
  return false;
}
/** The word of a bash here-string (`<<< word`, `0<<<word`) among the tokens of a command, and the tokens without it; null when there is none. */
function hereString(tokens) {
  const at = tokens.findIndex((t) => /^\d*<<</.test(t));
  if (at < 0) return null;
  const glued = tokens[at].replace(/^\d*<<</, '');
  return { word: glued || tokens[at + 1] || '', tokens: tokens.filter((_, j) => j !== at && (glued || j !== at + 1)) };
}

// Statement, pipeline and word splitting are quote-aware (shell-split.mjs): a `;` or `|` inside quotes never splits,
// and 's/a/b/; s/c/d'"'"'s/' is one word, so an in-place editor keeps its file argument. `a & b` runs a in the
// background and then b (bash); a leading `& prog` is PowerShell's call operator and stays.

// Wrappers that run the next word as a program; their own options (and option values) are skipped.
const WRAPPERS = new Set(['env', 'command', 'builtin', 'exec', 'nohup', 'time', 'nice', 'timeout', 'xargs', 'stdbuf', 'ionice', 'chrt', 'setsid']);
const WRAPPER_VALUE_OPTS = /^-(?:n|u|s|k|I|L|P|d|E|-signal|-kill-after|-max-args|-max-procs|-delimiter|-unset|-chdir|C)$/;
// Shell keywords before a command: `if git push ...`, `then`, `do`, `!`.
const SHELL_KEYWORDS = new Set(['if', 'then', 'else', 'elif', 'do', 'while', 'until', '!', '{', '(']);

// Start-Process <file> [-ArgumentList] <args>: the program's own arguments are a comma list ('push','-f') or one string ('push -f')
// after -ArgumentList or in the second position. Its other parameters (-Wait, -WorkingDirectory docs, -Verb RunAs) are not arguments.
const START_VALUE_PARAMS = ['workingdirectory', 'verb', 'windowstyle', 'credential', 'redirectstandardinput', 'redirectstandardoutput', 'redirectstandarderror', 'environment'];
function startProcessArguments(rest) {
  const words = [];
  for (let k = 0; k < rest.length; k++) {
    const name = /^-([A-Za-z]+)$/.exec(rest[k])?.[1].toLowerCase();
    const isList = name === 'args' || (name !== undefined && abbreviates(name, 'argumentlist', 3));
    if (name !== undefined && !isList) {
      if (START_VALUE_PARAMS.some((p) => abbreviates(name, p, 2))) k++; // a parameter and its value
      continue;
    }
    const from = isList ? k + 1 : k;
    if (from >= rest.length) break;
    let end = from + 1;
    while (end < rest.length && (rest[end - 1].endsWith(',') || rest[end].startsWith(','))) end++;
    words.push(...tokenize(rest.slice(from, end).join(' ').replace(/^@\(|\)$/g, '').split(',').join(' ')));
    k = end - 1;
  }
  return words;
}

function normalizeTokens(input) {
  const tokens = [...input];
  // A subshell or group glued to the program: `(git push`, `{git`.
  if (tokens.length && /^[({]+./.test(tokens[0])) tokens[0] = tokens[0].replace(/^[({]+/, '');
  let i = 0;
  while (i < tokens.length) {
    const t = tokens[i];
    const lower = t.toLowerCase();
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(t) || SHELL_KEYWORDS.has(t)) i++;
    else if (WRAPPERS.has(t) && tokens.length > i + 1) {
      i++;
      while (i < tokens.length - 1 && (tokens[i].startsWith('-') || /^\d+(?:\.\d+)?[smhd]?$/.test(tokens[i]) || /^[A-Za-z_][A-Za-z0-9_]*=/.test(tokens[i]))) {
        i += WRAPPER_VALUE_OPTS.test(tokens[i]) && i + 2 < tokens.length ? 2 : 1;
      }
    }
    // PowerShell call and dot-source operators, cmd /c|/k and Start-Process name the program that really runs next.
    else if ((t === '&' || t === '.') && tokens.length > i + 1) i++;
    // wsl runs the rest as a Linux command: skip its own options (-d/--distribution, -u/--user, --cd, -e/--exec, --).
    else if (/^wsl(?:\.exe)?$/i.test(t) && tokens.length > i + 1) {
      i++;
      while (i < tokens.length - 1 && tokens[i].startsWith('-')) {
        i += /^(?:-d|--distribution|-u|--user|--cd|--shell-type)$/i.test(tokens[i]) && i + 2 < tokens.length ? 2 : 1;
      }
    }
    else if (/^cmd(?:\.exe)?$/i.test(t) && tokens.length > i + 2 && tokens.slice(i + 1).some((a) => /^\/[ck]$/i.test(a))) {
      i = tokens.findIndex((a, j) => j > i && /^\/[ck]$/i.test(a)) + 1;
    } else if (['start-process', 'saps', 'start'].includes(lower) && tokens.length > i + 1) {
      i++;
      if (tokens[i] === '' && tokens.length > i + 1) i++; // start "" prog (window title)
      if (/^-(?:filepath|file|path)$/i.test(tokens[i]) && tokens.length > i + 1) i++;
      // The words after the program are the program's own arguments, not Start-Process's parameters.
      if (lower !== 'start') tokens.splice(i + 1, tokens.length - i - 1, ...startProcessArguments(tokens.slice(i + 1)));
    }
    // bash case: `case WORD in pattern) command ;; pattern) command ;; esac` - the word, `in` and an arm's pattern come before its command.
    else if (t === 'case' && tokens.indexOf('in', i) > i) i = tokens.indexOf('in', i) + 1;
    else if (/^\(?[^\s()]*\)$/.test(t) && tokens.length > i + 1) i++;
    else break;
  }
  const out = tokens.slice(i);
  out.skipped = i; // how many leading words were assignments, keywords or wrappers (routineSubcommand)
  return out;
}

const programName = (token) => path.posix.basename(toPosix(token || '')).toLowerCase().replace(/\.(?:exe|cmd|bat)$/, '');
const hasShortFlag = (args, letter) => args.some((a) => /^-[a-zA-Z]+$/.test(a) && a.includes(letter));

// Microsoft's Power BI CLIs run through npx too: `npx @microsoft/powerbi-desktop-bridge-cli screenshot ...` is
// `powerbi-desktop screenshot ...` and `npx @microsoft/powerbi-report-authoring-cli preview ...` is
// `powerbi-report-author preview ...` (also `npx.cmd`, `npm exec`, `npm x`, a version suffix, `-p <package> <bin>`).
// The command is then judged as the CLI itself: the screenshot switch, the preview rules and the routine lists see the
// same program. npx of any other package stays what it is (not routine; Claude Code's own rules).
const NPX_BINS = { '@microsoft/powerbi-desktop-bridge-cli': 'powerbi-desktop', '@microsoft/powerbi-report-authoring-cli': 'powerbi-report-author' };
const NPX_PACKAGE_RE = /^(@microsoft\/powerbi-(?:desktop-bridge|report-authoring)-cli)(?:@.*)?$/i;
// npx and npm exec options that change neither where the package comes from nor what runs. Any other option
// (--registry, --userconfig, --prefix, --cache, --workspace, --node-options, ...) can fetch another package.
const NPX_PLAIN_OPTS = /^(?:-y|--yes|--no|--no-install|-q|--quiet|-s|--silent)$/i;
const npxBinOf = (pkg) => NPX_BINS[(NPX_PACKAGE_RE.exec(pkg ?? '')?.[1] ?? '').toLowerCase()];
/**
 * `{ prog, args }` of the Power BI CLI an npx command runs, or the pair unchanged. Every `-p` package must be one of
 * the two CLIs and every other option a plain one: another package could put its own `powerbi-desktop` bin first, and
 * --registry fetches the "same" package from elsewhere. A CLI package named with either is `mixed` (checkSubcommand
 * asks; never routine). `call` is the command of `-c`/`--call` when only the CLI packages are named; checkSubcommand
 * judges it as a nested command.
 * `viaNpx` marks an unwrapped command; `installedOnly` is true with `--no` (or the old `--no-install`, which npm
 * converts to it) and without `--yes`. Without it npx downloads a missing package into its cache with no prompt (npm
 * docs, npm exec: `--yes` is assumed when standard input is not a TTY), and installing the CLI is the user's
 * (docs/harness/desktop.md): so only an installed-only command is routine, and none is auto-approved without it.
 */
function unwrapNpx(prog, args) {
  let rest;
  if (prog === 'npx') rest = args;
  else if (prog === 'npm' && /^(?:exec|x)$/i.test(args[0] ?? '')) rest = args.slice(1);
  else return { prog, args };
  const packages = [];
  let call;
  let other = false;
  let i = 0;
  while (i < rest.length && rest[i].startsWith('-')) {
    if (rest[i] === '--') {
      i++;
      break;
    }
    const m = /^(-p|--package|-c|--call)(?:=(.*))?$/i.exec(rest[i]);
    if (m) {
      const value = m[2] ?? rest[i + 1] ?? '';
      if (/^(?:-p|--package)$/i.test(m[1])) packages.push(value);
      else call = value;
      i += m[2] === undefined ? 2 : 1;
    } else {
      if (!NPX_PLAIN_OPTS.test(rest[i])) other = true;
      i++;
    }
  }
  const first = rest[i] ?? '';
  if (other || packages.some((p) => !npxBinOf(p))) {
    return packages.some(npxBinOf) || rest.some((a) => npxBinOf(a)) ? { prog, args, mixed: true } : { prog, args };
  }
  const opts = rest.slice(0, i);
  const installedOnly = opts.some((a) => /^--no(?:-install)?$/i.test(a)) && !opts.some((a) => /^(?:-y|--yes)$/i.test(a));
  if (call !== undefined) return packages.length ? { prog, args, call, installedOnly } : { prog, args };
  // The package itself as the command, or its bin after `-p <package>`.
  const bin = npxBinOf(first) ?? packages.map(npxBinOf).find((b) => b === programName(first));
  if (!bin) return { prog, args };
  const tail = rest.slice(i + 1);
  return { prog: bin, args: tail[0] === '--' ? tail.slice(1) : tail, viaNpx: true, installedOnly };
}

const NPX_DOWNLOAD_REASON = 'Without --no, npx downloads the Power BI CLI when it is not installed, and installing it is the user\'s (docs/harness/desktop.md): add --no to run only an installed copy, or confirm.';

/** The file or folder a Desktop screenshot writes: `--output <file>`, `--output=<file>`, `--output-dir <dir>`, `--output-dir=<dir>`. */
function screenshotOutputs(args) {
  const out = [];
  for (let i = 0; i < args.length; i++) {
    const m = /^--output(?:-dir)?(?:=(.*))?$/i.exec(args[i]);
    if (!m) continue;
    if (m[1] !== undefined) out.push(m[1]);
    else if (args[i + 1] !== undefined && !args[i + 1].startsWith('-')) out.push(args[++i]);
  }
  return out;
}

/**
 * The project-relative path of a file or folder a command writes, when it lies inside the repository and outside
 * `exports/` (the one output folder .gitignore keeps out of Git); null when it lies outside; undefined when the guard
 * cannot place it (a variable, another user's `~name`). `~` is the home folder; off Windows a Windows spelling names no
 * local path and counts as outside. Relative paths start from the shell's directory (`base`, see shellDir); `null` there is
 * a directory the guard lost track of after a `cd`, so a relative path cannot be placed either (undefined).
 */
function repositoryOutput(value, base = PROJECT_DIR) {
  const v = String(value ?? '').replace(/^["'(]+|["'`),;]+$/g, '').replace(/^~(?=[\\/]|$)/, () => os.homedir());
  if (!v) return null;
  if (/[$%]|^~/.test(v)) return undefined;
  if (process.platform !== 'win32' && (FOREIGN_ABSOLUTE_RE.test(v) || FOREIGN_ABSOLUTE_RE.test(nativePath(v)))) return null;
  if (base === null && !path.isAbsolute(nativePath(v))) return undefined;
  const rel = projectRel(path.resolve(base || PROJECT_DIR, nativePath(v)));
  return rel !== null && !/^exports(?:\/|$)/i.test(rel) ? rel : null;
}

/**
 * The directory relative paths start from at this subcommand: the hook payload's (`baseDir`), moved by the literal `cd`s of
 * the command line (`cdBase`, set by analyzeShellCommand); null once a `cd` went somewhere the guard cannot place (F1-16).
 * Shells started with a command string (`bash -c`, `pwsh -c`, `eval`, `npx -c`) inherit it; the strings analyzeShellCommand
 * reads before it walks the statements (Invoke-Expression, cmd /c, `$( )`) still start from the payload's folder.
 */
const shellDir = (ctx) => (ctx.cdBase === undefined ? (ctx.baseDir || PROJECT_DIR) : ctx.cdBase);

/**
 * The shell's directory after `cd <word>` from `from` (an absolute folder, or null when it is unknown already): that folder
 * when the guard can place it, else null. Placeable is a literal path of a folder that exists now: a `cd` that fails leaves
 * the next command where it was (`;`, `||` and a new line still run it), so a folder that is not there places nothing. Not
 * placeable either: `cd` alone (home), `cd -`, `pushd +1`, a variable, a substitution, `~name`, a wildcard, a PowerShell
 * provider drive, and a Windows spelling off Windows.
 */
function movedDirectory(from, word) {
  const w = String(word ?? '').replace(/^["'(]+|["'`),;]+$/g, '').replace(/^~(?=[\\/]|$)/, () => os.homedir());
  if (!w || w === '-' || /[$%`*?[]|^~|^[+-]\d+$/.test(w) || ENV_PROVIDER_RE.test(w) || PROVIDER_PATH_RE.test(w)) return null;
  const native = nativePath(w);
  if (process.platform !== 'win32' && (FOREIGN_ABSOLUTE_RE.test(w) || FOREIGN_ABSOLUTE_RE.test(native))) return null;
  if (from === null && !path.isAbsolute(native)) return null;
  try {
    const to = path.resolve(from ?? PROJECT_DIR, native);
    if (foreignShare(to)) return null; // a share is not looked up: the guard never connects to a host a command names
    return fs.statSync(to).isDirectory() ? to : null;
  } catch {
    return null;
  }
}

const SHELL_PROGRAMS = new Set(['bash', 'sh', 'zsh', 'dash', 'pwsh', 'powershell']);
// PowerShell reads every unambiguous prefix of a switch and takes `-`, `--` or `/` in front of it: -enc, -EncodedC, -Win, /c.
const pwshSwitch = (arg) => /^(?:--?|\/)([A-Za-z][A-Za-z-]*)$/.exec(String(arg ?? ''))?.[1].toLowerCase() ?? '';
const abbreviates = (name, full, min = 1) => name.length >= min && full.startsWith(name);
/**
 * How PowerShell reads one word of its command line: 'command', 'file' or 'encoded' (they end the options), 'value'
 * (the next word is its value: -WindowStyle Hidden, -ExecutionPolicy Bypass), 'switch', or null for a word that is not an option.
 */
function pwshOption(arg) {
  const n = pwshSwitch(arg);
  if (!n) return null;
  if (n === 'ec' || abbreviates(n, 'encodedcommand')) return 'encoded';
  if (abbreviates(n, 'command') || abbreviates(n, 'commandwithargs', 8)) return 'command';
  if (abbreviates(n, 'file')) return 'file';
  if (['ep', 'wd', 'of', 'if', 'ea'].includes(n) || abbreviates(n, 'executionpolicy', 2) || abbreviates(n, 'windowstyle') ||
    abbreviates(n, 'workingdirectory', 2) || abbreviates(n, 'outputformat') || abbreviates(n, 'inputformat', 2) ||
    abbreviates(n, 'encodedarguments', 8) || abbreviates(n, 'configurationname', 6) || abbreviates(n, 'configurationfile', 6) ||
    abbreviates(n, 'custompipename', 2) || abbreviates(n, 'settingsfile', 3) || abbreviates(n, 'psconsolefile', 2) || abbreviates(n, 'version')) {
    return 'value';
  }
  return 'switch';
}
/** True when the word after a value option is that option's value (a following option is not). */
const takesNext = (kind, next) => kind === 'value' && next !== undefined && pwshOption(next) === null;

/** The Base64 word that follows -EncodedCommand (or any prefix of it) on a PowerShell command line, or undefined. */
function encodedCommandOf(prog, args) {
  if (prog !== 'pwsh' && prog !== 'powershell') return undefined;
  for (let i = 0; i < args.length; i++) {
    const kind = pwshOption(args[i]);
    if (kind === 'encoded') return /^[A-Za-z0-9+/=]+$/.test(args[i + 1] ?? '') ? args[i + 1] : undefined;
    if (kind === 'command' || kind === 'file' || kind === null) return undefined; // the options end here
    if (takesNext(kind, args[i + 1])) i++;
  }
  return undefined;
}

/** The command a shell runs from its arguments (`bash -lc ...`, `pwsh -NoProfile -Command ...`, `powershell git ...`). */
function shellInlineCommand(prog, args) {
  if (prog === 'pwsh' || prog === 'powershell') {
    for (let i = 0; i < args.length; i++) {
      const a = args[i];
      const kind = pwshOption(a);
      if (kind === 'command') return args.slice(i + 1).join(' ');
      if (kind === 'file' || kind === 'encoded') return null; // a script file, or decoded elsewhere
      if (takesNext(kind, args[i + 1])) i++;
      else if (kind === null && !a.startsWith('-')) return args.slice(i).join(' '); // a bare command (Windows PowerShell's default)
    }
    return null;
  }
  const flag = args.findIndex((a) => /^-[a-z]*c[a-z]*$/.test(a));
  return flag >= 0 ? args.slice(flag + 1).join(' ') : null;
}

/** The file (or module) a program runs as code, if any: interpreters, shells with a script, a script run directly. */
function scriptOf(prog, args, first) {
  if (SHELL_PROGRAMS.has(prog)) {
    if (prog === 'pwsh' || prog === 'powershell') {
      const f = args.findIndex((a) => /^-(?:f|file)$/i.test(a));
      return f >= 0 ? args[f + 1] : undefined;
    }
    return args.some((a) => /^-[a-z]*c[a-z]*$/.test(a)) ? undefined : args.find((a) => !a.startsWith('-'));
  }
  if (SCRIPT_RUNNERS.has(prog)) {
    if (inlineCode(prog, args)) return undefined;
    if (prog === 'node' && args.some((a) => /^(?:--check|-c)$/.test(a))) return undefined; // a syntax check runs nothing
    const m = args.indexOf('-m');
    if (m >= 0 && /^py/.test(prog)) return `the module ${args[m + 1] ?? ''}`.trim();
    return args.find((a) => !a.startsWith('-'));
  }
  return SCRIPT_FILE_RE.test(first) ? first : undefined;
}

// The harness's own checks, by name: the validator, the RDL comparison, the git hook runner, the hook-pack check (it takes
// no argument: routineSubcommand), the test runner, the tests and the hooks themselves (run by hand with a payload).
// Everything else under hardening/ is an ordinary script run: the installer writes into any directory and sets
// core.hooksPath there, the Copilot sync writes .github/.
const HARNESS_CHECK_RE = /^(?:scripts\/(?:validate|rdl-compare|githook|check-hooks)\.mjs|tests\/run-all\.mjs|tests\/[\w-]+\.test\.mjs|hooks\/(?:lib\/)?[\w-]+\.mjs)$/i;
/**
 * The path below hardening/ (scripts/validate.mjs) of one of the harness's own checks, or null: inside <project>/hardening/
 * after resolving the path (no ../ tricks), named above.
 */
function harnessCheckOf(script, base = PROJECT_DIR) {
  if (/^the module /.test(script)) return null;
  try {
    const harness = canonicalPathOf(path.join(PROJECT_DIR, 'hardening'));
    const rel = path.relative(harness, canonicalPathOf(path.resolve(base || PROJECT_DIR, script)));
    return rel !== '' && !rel.startsWith('..') && !path.isAbsolute(rel) && HARNESS_CHECK_RE.test(toPosix(rel)) ? toPosix(rel) : null;
  } catch {
    return null;
  }
}
/** True for one of the harness's own checks (harnessCheckOf). */
const insideHarness = (script, base = PROJECT_DIR) => harnessCheckOf(script, base) !== null;

/**
 * Windows 8.3 short names in a command (HARDEN~1\HARNES~1.JSO) spelled out, so path checks see the long names. A token
 * below the folder is compared by its relative spelling, before and after resolving: under a folder that is not canonical
 * itself (a symlink, a junction, macOS /var -> /private/var, a runner's RUNNER~1 profile) every absolute path differs from
 * its resolved form, while `HEAD~1` keeps the same relative name and stays a revision. A token outside it is compared whole.
 */
function expandShortNames(cmd, base = PROJECT_DIR) {
  const root = base || PROJECT_DIR;
  return cmd.replace(/[^\s'"`;|&<>()]*~\d[^\s'"`;|&<>()]*/g, (token) => {
    try {
      const written = path.resolve(root, token);
      const real = canonicalPathOf(written);
      const relWritten = path.relative(root, written);
      if (relWritten !== '..' && !relWritten.startsWith(`..${path.sep}`) && !path.isAbsolute(relWritten)) {
        const relReal = path.relative(canonicalPathOf(root), real);
        return toPosix(relReal).toLowerCase() === toPosix(relWritten).toLowerCase() ? token : toPosix(real);
      }
      return real.toLowerCase() === written.toLowerCase() ? token : toPosix(real);
    } catch {
      return token;
    }
  });
}

/** Decoded text of PowerShell's -EncodedCommand (UTF-16LE Base64), or null when it is not readable text. */
function decodeEncodedCommand(b64) {
  try {
    const text = Buffer.from(b64, 'base64').toString('utf16le');
    // A command is mostly plain ASCII; random bytes decode to rare code points.
    const plain = (text.match(/[\t\n\r\x20-\x7E]/g) ?? []).length;
    return text.trim() && plain / text.length >= 0.9 ? text : null;
  } catch {
    return null;
  }
}

// Configuration keys that make git run a program or read other configuration: monitor, pager, editor, SSH and askpass
// commands, external diff and text converters, merge drivers, aliases, includes, credential helpers, filters. Set through
// `git config`, `-c key=value` or `--config-env`, they turn a later routine `git status` or `git diff` into a program run.
// core.hooksPath has its own rule above the switch (the harness's own hooks path stays allowed). trace2.normalTarget,
// eventTarget and perfTarget send git's trace to a file or socket like GIT_TRACE2* (GIT_TRACE_VAR_RE), whatever the value.
const GIT_PROGRAM_KEY_RE =
  /(?:^|[\s"'`])(?:core\.(?:fsmonitor|fsmonitorhookversion|pager|editor|sshcommand|askpass|gitproxy|alternaterefscommand)|(?:diff|merge)\.(?:[\w-]+\.)?(?:external|textconv|command|driver)|alias\.[\w-]+|include(?:if\.[^\s=]+)?\.path|credential(?:\.[^\s=]+)?\.helper|filter\.[\w-]+\.(?:clean|smudge|process)|sequence\.editor|gpg\.program|ssh\.variant|uploadpack\.[\w-]+|receive\.[\w-]+|url\.[^\s=]+\.insteadof|protocol\.[\w-]+\.allow|safe\.directory|http\.(?:proxy|sslcainfo|sslcert|sslkey|extraheader)|trace2\.(?:normal|event|perf)target)(?:[=\s]|$)/i;
// The same through the environment (`GIT_PAGER=x git log`), plus the variables that point git at another repository or
// configuration file.
const GIT_ENV_RE =
  /^GIT_(?:EXTERNAL_DIFF|PAGER|EDITOR|SSH|SSH_COMMAND|ASKPASS|EXEC_PATH|CONFIG(?:_GLOBAL|_SYSTEM|_NOSYSTEM|_PARAMETERS|_COUNT|_KEY_\d+|_VALUE_\d+)?|SEQUENCE_EDITOR|PROXY_COMMAND|DIR|WORK_TREE|COMMON_DIR|ALTERNATE_OBJECT_DIRECTORIES|OBJECT_DIRECTORY|NAMESPACE)=/i;
// The same variables as global options, before the subcommand: --git-dir, --work-tree, --namespace and --exec-path, with
// `=` or with the value as the next word.
const GIT_REPOINT_OPT_RE = /^--(?:git-dir|work-tree|namespace|exec-path)(?:=|$)/i;
const GIT_ENV_REASON =
  'This sets a GIT_* variable or a global git option (--git-dir, --work-tree, --namespace, --exec-path) that makes git run a program or read another repository or configuration (GIT_EXTERNAL_DIFF, GIT_PAGER, GIT_EDITOR, GIT_SSH*, GIT_ASKPASS, GIT_CONFIG*, GIT_DIR, GIT_WORK_TREE, GIT_NAMESPACE). Only the user changes git configuration.';
const GIT_ORPHAN_REASON =
  'git switch --orphan and git checkout --orphan start a branch with an empty tree: every tracked file leaves the working tree, hardening/ (the hooks) and .claude/ (the settings) included, and nothing guards the commands after it. The user creates an orphan branch.';
// GIT_TRACE and its kin (GIT_TRACE_PACKET, GIT_TRACE_PACKFILE, GIT_TRACE_PERFORMANCE, GIT_TRACE_SETUP, GIT_TRACE_CURL,
// GIT_TRACE_PACK_ACCESS, GIT_TRACE_SHALLOW, GIT_TRACE_REFS, GIT_TRACE_FSMONITOR, GIT_TRACE2, GIT_TRACE2_EVENT, GIT_TRACE2_PERF):
// a value that names a file (any path), an af_unix: socket or another name makes git append its trace (commands, paths,
// protocol and pack data) to that target, outside the Edit/Write checks (round 3). Empty, 0, 1, true/false, yes/no, on/off
// and 2..10 (standard error or an open descriptor) write nowhere new. Every GIT_TRACE* name counts, so a key a later git adds
// is judged too, except the trace2 settings that name no target (their values are patterns, counts and ids).
const GIT_TRACE_VAR_RE = /^GIT_TRACE\w*$/i;
const GIT_TRACE_SETTING_RE = /^GIT_TRACE2_(?:CONFIG_PARAMS|ENV_VARS|EVENT_NESTING|MAX_FILES|PARENT_SID|PARENT_NAME)$/i;
const GIT_TRACE_HARMLESS_RE = /^(?:|0|1|true|false|yes|no|on|off|[2-9]|10)$/i;
const GIT_TRACE_REASON =
  'This sets a GIT_TRACE* variable (GIT_TRACE, GIT_TRACE_PACKET, GIT_TRACE_CURL, GIT_TRACE2_EVENT, ...) to a file, an af_unix: socket or a name the guard cannot vouch for: git appends its trace to that target, outside the Edit/Write checks. 1 or true (standard error) and a descriptor 2..10 stay allowed; only the user sends git traces to a file.';
// The shell builtins that set a variable for the commands after them (bash, cmd's set, setx for good).
const VARIABLE_SETTERS = new Set(['export', 'declare', 'typeset', 'local', 'readonly', 'set', 'setx']);
// PowerShell cmdlets that write an item of the Environment provider (`Set-Item env:NAME value`, `ni Env:\NAME -Value x`).
const ENV_ITEM_WRITERS = new Set(['set-item', 'si', 'new-item', 'ni', 'set-content', 'sc', 'add-content', 'ac']);
const ENV_ITEM_RE = /(?:^|[:\\])(?:env:[\\/]?|environment::)([A-Za-z_]\w*)$/i;
// PowerShell's `$env:NAME = value` (also `${env:NAME}`, `+=`) and [Environment]::SetEnvironmentVariable('NAME', value).
const PS_ENV_SET_RE = /(?:^|[\s;({&|])\$(?:\{env:([A-Za-z_]\w*)\}|env:([A-Za-z_]\w*))\s*(\+?)=(?!=)\s*(?:"([^"]*)"|'([^']*)'|([^\s;|&)}]*))/gi;
const SET_ENV_CALL_RE = /SetEnvironmentVariable\s*\(\s*["']([A-Za-z_]\w*)["']\s*,\s*(?:"([^"]*)"|'([^']*)'|([^\s,)]*))/gi;

/**
 * The deny for one environment variable a command line sets, or null: a GIT_ENV_RE variable (any value), or a GIT_TRACE*
 * target (GIT_TRACE_VAR_RE) whose value is not one of the harmless ones. `value` null means the guard cannot read it.
 */
function gitVariableVerdict(name, value) {
  if (GIT_ENV_RE.test(`${name}=`)) return deny(GIT_ENV_REASON);
  if (GIT_TRACE_VAR_RE.test(name) && !GIT_TRACE_SETTING_RE.test(name) && (value === null || !GIT_TRACE_HARMLESS_RE.test(value.trim()))) return deny(GIT_TRACE_REASON);
  return null;
}

/** gitVariableVerdict for each `NAME=value` word among `words` (other words are skipped); the first deny, or null. */
function gitAssignmentsVerdict(words) {
  for (const word of words) {
    const m = /^([A-Za-z_]\w*)=([\s\S]*)$/.exec(String(word ?? '').replace(/^[({]+/, ''));
    const verdict = m && gitVariableVerdict(m[1], m[2]);
    if (verdict) return verdict;
  }
  return null;
}

/**
 * The deny for a GIT_* variable that a command sets for the commands after it (gitVariableVerdict), or null: the bash and
 * cmd builtins (`export GIT_TRACE=/x`, `declare -x`, `set NAME=value`), `setx NAME value` (for good), PowerShell's
 * `$env:NAME = value` and SetEnvironmentVariable (value judged), and an Environment provider write (`Set-Item env:NAME`,
 * value not read: any GIT_TRACE* target counts). `text` is the command without its text words (a commit message).
 */
function gitVariableSetVerdict(prog, args, text) {
  if (VARIABLE_SETTERS.has(prog)) {
    const verdict = gitAssignmentsVerdict(args);
    if (verdict) return verdict;
    const words = args.filter((a) => !/^[-/][A-Za-z]$/.test(a)); // setx's own switches: /m, /k, ...
    if (prog === 'setx' && words.length >= 2 && !words[0].includes('=')) {
      const named = gitVariableVerdict(words[0], words[1]);
      if (named) return named;
    }
  }
  if (ENV_ITEM_WRITERS.has(prog)) {
    for (const a of args) {
      const name = ENV_ITEM_RE.exec(a)?.[1];
      const verdict = name && gitVariableVerdict(name, null);
      if (verdict) return verdict;
    }
  }
  for (const m of text.matchAll(PS_ENV_SET_RE)) {
    const verdict = gitVariableVerdict(m[1] ?? m[2], m[3] ? null : (m[4] ?? m[5] ?? m[6]));
    if (verdict) return verdict;
  }
  for (const m of text.matchAll(SET_ENV_CALL_RE)) {
    const verdict = gitVariableVerdict(m[1], m[2] ?? m[3] ?? (/^[$(]/.test(m[4]) ? null : m[4]));
    if (verdict) return verdict;
  }
  return null;
}
// Global options that take their value as the next word when written without `=`. That word is not the subcommand:
// `git --attr-source status push -f origin main` is a push.
const GIT_VALUE_GLOBAL_RE = /^(?:-C|-c|--git-dir|--work-tree|--namespace|--super-prefix|--config-env|--attr-source)$/;

/** Where the subcommand starts in the words after `git`: the global options before it, and the value of those that take one, are skipped. */
function gitSubcommandIndex(args) {
  let i = 0;
  while (i < args.length && args[i].startsWith('-')) i += GIT_VALUE_GLOBAL_RE.test(args[i]) ? 2 : 1;
  return i;
}

// The long options of each git subcommand that the checks judge. git reads any unambiguous prefix of a long option as that
// option (`git commit --no-verif` is --no-verify, `git switch --discard` is --discard-changes, `git grep --no-ind` is
// --no-index), so spellOutGitOptions reads an abbreviation as the full name, also as `--opt=value`. A prefix that git
// refuses as ambiguous reads as the first judged option it begins (the list is in order of severity): never as no option.
// Only subcommands that take abbreviations are listed: diff, log and show read full names only (git 2.52), and
// `git diff --text` is an option of its own, not an abbreviation of --textconv.
const GIT_JUDGED_OPTIONS = {
  add: ['force', 'pathspec-from-file'],
  blame: ['contents', 'ignore-revs-file'],
  branch: ['delete', 'force', 'move', 'copy'],
  'cat-file': ['textconv'],
  checkout: ['force', 'orphan'],
  clean: ['force'],
  commit: ['no-verify', 'amend', 'file', 'template', 'pathspec-from-file'],
  gc: ['prune'],
  grep: ['no-index', 'textconv', 'open-files-in-pager'],
  push: ['no-verify', 'force', 'force-with-lease', 'force-if-includes', 'mirror', 'delete', 'prune', 'all', 'branches'],
  reset: ['hard'],
  restore: ['worktree'],
  switch: ['discard-changes', 'force', 'force-create', 'orphan'],
};
// Options of those subcommands that are proper prefixes of a judged option and are options in their own right: git takes
// them as written (`git grep --text` is -a, `git blame --ignore-rev <rev>` names a revision, not a file).
const GIT_OWN_OPTIONS = { blame: ['ignore-rev'], grep: ['text'] };

/** The words after the git subcommand `sub`, each abbreviation of a judged long option spelled out: `--no-verif` is `--no-verify`, `--forc=x` is `--force=x`. */
function spellOutGitOptions(sub, rest) {
  if (!Object.hasOwn(GIT_JUDGED_OPTIONS, sub)) return rest;
  return rest.map((a) => {
    const m = /^--([A-Za-z][A-Za-z-]*)(=[\s\S]*)?$/.exec(a);
    const name = m?.[1].toLowerCase();
    if (!name || GIT_OWN_OPTIONS[sub]?.includes(name)) return a;
    const full = GIT_JUDGED_OPTIONS[sub].find((option) => option.startsWith(name));
    return full ? `--${full}${m[2] ?? ''}` : a;
  });
}

/**
 * `sub` with the quoted words that are certainly text (textWordsOf: a commit message, a search pattern) emptied, unless a
 * redirect names the word as its target: a `>` inside `-m "rename a.md -> b.md"` is no redirect. The value of an option
 * written in one word with it is emptied the same way (`--message="..."`, `-m"..."`, `-am"..."`, `--grep="..."`). A word the
 * command spells in another way stays (an escaped quote inside it), and so does any redirect of the command itself.
 */
function withoutQuotedText(sub, words) {
  let out = sub;
  for (const word of new Set(words)) {
    // The word itself quoted, or an option prefix (`--message=`, `-m`, `-am`) followed by the quoted rest of the word.
    for (const [prefix, value] of optionValueForms(word)) {
      for (const q of ['"', "'"]) if (!prefix || out.includes(`${prefix}${q}`)) out = out.replace(new RegExp(`(?<![>&|$]\\s*)${escapeRe(prefix)}${q}${escapeRe(value)}${q}`, 'g'), `${prefix}""`);
    }
  }
  return out;
}

// The options of git blame, commit and add that name a file git reads (F1-57): blame --contents <file> (the text it blames in
// place of the working file), --ignore-revs-file <file> and -S <file>; commit -F/--file <file> (the message) and
// -t/--template <file>; --pathspec-from-file <file> of commit and add. The content reaches the output or the commit.
const GIT_FILE_OPTIONS = { add: ['pathspec-from-file'], blame: ['contents', 'ignore-revs-file'], commit: ['file', 'template', 'pathspec-from-file'] };
// Short options of git commit that take a value: the rest of a cluster (-aFfile) is theirs, or the next word.
const GIT_COMMIT_VALUE_LETTERS = 'mCcFtSu';
// Short options of git grep that take a value (-e, -f, -m, -A, -B, -C): the rest of a cluster is theirs.
const GIT_GREP_VALUE_LETTERS = 'efmABC';

/** The file names that the options of git blame, commit and add name (`rest` has its option abbreviations spelled out). */
function gitFileValues(sub, rest) {
  const out = [];
  if (!Object.hasOwn(GIT_FILE_OPTIONS, sub)) return out;
  for (let i = 0; i < rest.length && rest[i] !== '--'; i++) {
    const a = rest[i];
    const long = /^--([A-Za-z][A-Za-z-]*)(?:=([\s\S]*))?$/.exec(a);
    if (long) {
      if (GIT_FILE_OPTIONS[sub].includes(long[1].toLowerCase())) out.push(long[2] ?? rest[++i]);
    } else if (sub === 'blame' && a.startsWith('-S')) {
      out.push(a.length > 2 ? a.slice(2) : rest[++i]);
    } else if (sub === 'commit' && /^-[A-Za-z]/.test(a)) {
      for (let k = 1; k < a.length; k++) {
        if (!GIT_COMMIT_VALUE_LETTERS.includes(a[k])) continue;
        const value = a.slice(k + 1);
        if ('Ft'.includes(a[k])) out.push(value || rest[++i]);
        else if (!value && 'mCc'.includes(a[k])) i++; // the next word is a message or a commit, not an option
        break;
      }
    }
  }
  return out.filter((f) => typeof f === 'string' && f !== '' && f !== '-');
}

/** True when a file option of git blame, commit or add names a file the guard cannot vouch for: outside the project, a secret, a variable or `~` path, or unplaceable. */
const gitReadsOutside = (sub, rest, base) => gitFileValues(sub, rest).some((f) => base === null || !pathsStayInside([f], base));

/**
 * The verdict for a git file option that reads outside the project: the user decides (a secret file is denied earlier, by
 * the name scan). The file is placed from the shell's folder and from the folder `-C` moves git to (`globalOpts`): both
 * must hold it inside the project.
 */
function gitFileRead(sub, rest, ctx, globalOpts = []) {
  const base = shellDir(ctx);
  return gitReadsOutside(sub, rest, base) || gitReadsOutside(sub, rest, gitBase(globalOpts, base))
    ? askUser(`git ${sub} reads a file named on its command line (--contents, -F/--file, --template, --pathspec-from-file) that lies outside the project, is a variable or ~ path, or cannot be placed from the shell's folder: its content reaches the output or the commit. Name a file inside the project, or confirm.`)
    : null;
}

/** True for `git grep -O[<cmd>]` and `--open-files-in-pager[=<cmd>]` (F2-1), also inside a cluster of short options (`-nOcmd`). */
function opensPager(sub, rest) {
  if (sub !== 'grep') return false;
  const end = rest.indexOf('--');
  const clusterOpensPager = (word) => {
    for (const letter of word.slice(1)) {
      if (letter === 'O') return true;
      if (GIT_GREP_VALUE_LETTERS.includes(letter)) return false;
    }
    return false;
  };
  return (end < 0 ? rest : rest.slice(0, end)).some((a) => /^--open-files-in-pager(?:=|$)/i.test(a) || (/^-[A-Za-z0-9]/.test(a) && clusterOpensPager(a)));
}

/** The long option `word` names among `names`: the exact name, or a prefix that only one of them begins with; else null. */
function longOptionName(word, names) {
  const m = /^--([A-Za-z][\w-]*)(?:=|$)/.exec(word);
  if (!m) return null;
  const name = m[1].toLowerCase();
  if (names.includes(name)) return name;
  const matches = names.filter((n) => n.startsWith(name));
  return matches.length === 1 ? matches[0] : null;
}

/** The folder a git command runs in: the shell's folder, moved by each global `-C <dir>`; null when the guard cannot place it. */
function gitBase(globalOpts, base) {
  let dir = base;
  for (let j = 0; j < globalOpts.length; j++) {
    if (globalOpts[j] !== '-C') continue;
    const value = globalOpts[++j] ?? '';
    dir = dir === null || /[$%`*?[]|^~/.test(value) ? null : path.resolve(dir, nativePath(value));
  }
  return dir;
}

// F2-2: the files that make the guard run: the pack's code (hooks, git hooks, the scripts they call), its configuration
// (approvals mode included) and package file, its registration for Claude Code and for GitHub Copilot, and the other git
// hooks folder the harness may use. A switch or checkout to a commit that holds them differently replaces or removes
// them in the working tree: on a branch from before the install the hooks are gone, and every later PreToolUse hook
// fails to start, so the commands after it run unguarded. The pack's docs, tests and CI template run nothing: a branch
// that changes only those is an ordinary switch.
const GUARD_FILES = ['hardening/hooks', 'hardening/githooks', 'hardening/scripts', 'hardening/harness.config.json', 'hardening/package.json',
  '.claude/settings.json', '.claude/settings.local.json', '.github/hooks', '.githooks'];
// A name git accepts for a branch (git check-ref-format, simplified): only such a name is looked up as refs/heads/<name>
// or guessed from a remote-tracking branch.
const BRANCH_NAME_RE = /^(?![-./])(?!.*(?:\.\.|@\{|\/\/|\/\.|\.lock(?:\/|$)))[^\s~^:?*[\\\x00-\x1f\x7f]+(?<![./])$/;
const guardDiffs = new Map();

/** The guard's files that differ between HEAD and `rev` ('' when none, also when neither holds them), or null when git cannot compare them. */
function guardFilesChangedAt(rev) {
  // From the project root, where the guard's files are: a switch in another repository leaves them alone anyway.
  if (!guardDiffs.has(rev)) guardDiffs.set(rev, git(['diff-tree', '--name-only', '-r', 'HEAD', `${rev}^{commit}`, '--', ...GUARD_FILES]));
  return guardDiffs.get(rev);
}

/**
 * Whether checking out `target` (a branch, a commit, `-`) keeps the guard's files as HEAD holds them: 'same', 'different',
 * or 'unresolved' (git failed, or nothing of that name resolves). git switch and checkout take an existing local branch
 * of that name first, then any commit, then (their --guess) a remote-tracking branch of that name as a new branch.
 */
function guardChangeAt(target) {
  if (target === 'HEAD' || target === '@') return 'same';
  if (target.startsWith('-') && target !== '-') return 'unresolved'; // a word after `--`: never handed to git as an option
  const name = target === '-' ? '@{-1}' : target;
  const branchName = BRANCH_NAME_RE.test(name);
  const local = (branchName ? guardFilesChangedAt(`refs/heads/${name}`) : null) ?? guardFilesChangedAt(name);
  let changes = local === null ? [] : [local];
  if (local === null && branchName) {
    const refs = git(['for-each-ref', '--format=%(refname)', `refs/remotes/*/${name}`]) ?? '';
    changes = refs.split('\n').filter((r) => /^refs\/remotes\/[^/]+\//.test(r) && r.slice(r.indexOf('/', 13) + 1) === name).map(guardFilesChangedAt);
  }
  if (!changes.length || changes.includes(null)) return 'unresolved';
  return changes.some((c) => c.trim()) ? 'different' : 'same';
}

// The long options of git switch and git checkout (git 2.52), and those that take the next word as their value.
const MOVE_OPTIONS = {
  switch: ['create', 'force-create', 'guess', 'discard-changes', 'quiet', 'recurse-submodules', 'progress', 'merge', 'conflict', 'detach',
    'track', 'force', 'orphan', 'overwrite-ignore', 'ignore-other-worktrees'],
  checkout: ['guess', 'overlay', 'quiet', 'recurse-submodules', 'progress', 'merge', 'conflict', 'detach', 'track', 'force', 'orphan',
    'overwrite-ignore', 'ignore-other-worktrees', 'ours', 'theirs', 'patch', 'unified', 'inter-hunk-context', 'ignore-skip-worktree-bits',
    'pathspec-from-file', 'pathspec-file-nul'],
};
const MOVE_VALUE_OPTIONS = ['create', 'force-create', 'orphan', 'conflict', 'unified', 'inter-hunk-context', 'pathspec-from-file'];
const MOVE_VALUE_LETTERS = { switch: 'cC', checkout: 'bBU' };

/**
 * The commits a git switch or checkout (`words`: the words after the subcommand) moves the working tree to: the start point
 * of a new branch (HEAD when none), the commit of --detach (HEAD when none), the branch or commit named. checkout's file
 * forms move nothing (`--`, --patch, --ours/--theirs, --pathspec-from-file, a tree-ish with paths); its single word is a
 * commit when it resolves as one, else a file to restore (`maybePath`).
 */
function moveTargets(sub, words) {
  let create = false;
  let detach = false;
  let fileForm = false;
  const positional = [];
  const rest = withoutRedirects(words); // `2>&1` and `> /dev/null` are the shell's
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    if (a === '--') {
      fileForm = sub === 'checkout';
      positional.push(...rest.slice(i + 1));
      break;
    }
    if (a === '-' || !a.startsWith('-')) {
      positional.push(a);
    } else if (a.startsWith('--')) {
      const name = longOptionName(a.replace(/^--no-/, '--'), MOVE_OPTIONS[sub]);
      if (MOVE_VALUE_OPTIONS.includes(name) && !a.includes('=')) i++;
      if (name === 'create' || name === 'force-create') create = true;
      else if (name === 'detach') detach = true;
      else if (['patch', 'ours', 'theirs', 'pathspec-from-file'].includes(name)) fileForm = true;
    } else {
      for (let k = 1; k < a.length; k++) {
        if (MOVE_VALUE_LETTERS[sub].includes(a[k])) {
          if (k === a.length - 1) i++; // -c <branch>, -qb <branch>; -cfoo holds its value
          if ('cCbB'.includes(a[k])) create = true;
          break;
        }
        if (a[k] === 'd') detach = true;
        if (sub === 'checkout' && 'p23'.includes(a[k])) fileForm = true;
      }
    }
  }
  if (fileForm) return { targets: [] };
  if (create || detach) return { targets: positional.length ? positional : ['HEAD'] };
  if (sub === 'switch') return { targets: positional };
  return { targets: positional.length === 1 ? positional : [], maybePath: true };
}

/** F2-2: a floor ask when a git switch or checkout moves the working tree to a commit whose guard files differ from HEAD's, or that the guard cannot compare; else null. */
function guardMoveVerdict(sub, rest, base) {
  const { targets, maybePath } = moveTargets(sub, rest);
  for (const target of targets) {
    const change = guardChangeAt(target);
    if (change === 'same') continue;
    // checkout <word> restores a file when the word names no commit: the file checks judged it already.
    if (change === 'unresolved' && maybePath && base !== null && !foreignShare(path.resolve(base, nativePath(target))) &&
      fs.existsSync(path.resolve(base, nativePath(target)))) continue;
    return askFloor(change === 'different'
      ? `git ${sub} ${target} moves the working tree to a commit whose harness files (hardening/, .claude/settings.json, .github/hooks) differ from the current ones: it replaces or removes the guard's own files and its registration, and the guard may stop working for every later command (on a branch from before the install the hooks are gone). Confirm the target, or switch in your own terminal.`
      : `The guard cannot tell what ${target} holds for its own files (hardening/, .claude/settings.json, .github/hooks): git did not resolve it, or failed. A git ${sub} to a commit without them removes the guard's files and its registration, and the guard may stop working for every later command. Confirm the target.`);
  }
  return null;
}

// F2-6: git diff runs as `git diff --no-index` when one of its two paths lies outside the repository (or it runs outside
// one), and then prints any two files of the machine. The null device in any spelling counts as outside: /dev/null and
// any /dev path, and Windows' NUL device (nul, NUL:, nul.txt, dir\nul).
const NULL_DEVICE_RE = /^(?:\/dev\/[\s\S]*|(?:[\s\S]*[\\/])?nul(?:\.[^\\/]*)?:?)$/i;
const IMPLICIT_NO_INDEX_REASON = 'git diff with the null device (/dev/null, NUL) or a path outside the project runs as git diff --no-index, which compares any two files on the machine, credentials included. Read project files with the Read tool and compare inside the repository (git diff <revision> -- <path in the project>).';

/**
 * The words of git diff that git may take for paths: every word after `--`, and before it every word that is no option
 * and not the search text of -S, -G or -I (they take the next word; it never reaches the --no-index comparison as a path).
 * Other options with a value written apart are not told apart: their value counts as a path, which only makes a value
 * that looks like an outside path (`--src-prefix /a/`) a deny.
 */
function diffPathWords(words) {
  const out = [];
  const rest = withoutRedirects(words); // `> /dev/null` is the shell's
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    if (a === '--') {
      out.push(...rest.slice(i + 1));
      break;
    }
    if (/^-[SGI]$/.test(a)) i++;
    else if (!a.startsWith('-')) out.push(a);
  }
  return out;
}

/**
 * Where a word of git diff lands as a path from `base`: 'outside' the project (the null device, ~, an absolute path or one
 * that climbs out, a link out of the project), 'unplaceable' (a variable, or a relative path when the shell's folder is
 * unknown) or 'inside'. A revision (HEAD~2, origin/main, a..b, HEAD:docs/x.md) reads as a name inside the project.
 */
function gitPathPlace(word, base) {
  if (NULL_DEVICE_RE.test(word) || word.startsWith('~')) return 'outside';
  if (/[$%`]/.test(word)) return 'unplaceable';
  const native = nativePath(word);
  if (process.platform !== 'win32' && FOREIGN_ABSOLUTE_RE.test(native)) return 'outside';
  // A share (\\host\share, //host/share) of a project that is not on one: outside, without asking the network for it.
  if (/^[\\/]{2}[^\\/]/.test(native) && !/^[\\/]{2}[^\\/]/.test(PROJECT_DIR)) return 'outside';
  if (base === null && !path.isAbsolute(native)) return 'unplaceable';
  const absolute = path.resolve(base ?? PROJECT_DIR, native);
  return projectRel(absolute) === null || projectRel(canonicalPathOf(absolute)) === null ? 'outside' : 'inside';
}

/** The places of the words git diff may compare as files (`rest`: the words after `diff`, `base`: where git runs). */
const diffPathPlaces = (rest, base) => diffPathWords(rest).map((w) => gitPathPlace(w, base));

// git push options that take the next word as their value when written without `=`: that word is no repository and no
// refspec (F2-5). The long options are git 2.52's, for reading an abbreviation.
const PUSH_OPTIONS = ['verbose', 'quiet', 'repo', 'all', 'branches', 'mirror', 'delete', 'tags', 'dry-run', 'porcelain', 'force',
  'force-with-lease', 'force-if-includes', 'recurse-submodules', 'thin', 'receive-pack', 'exec', 'set-upstream', 'progress', 'prune',
  'no-verify', 'verify', 'follow-tags', 'signed', 'atomic', 'push-option', 'ipv4', 'ipv6'];
const PUSH_VALUE_OPTIONS = ['repo', 'recurse-submodules', 'receive-pack', 'exec', 'push-option'];

/** The repository and refspec words of git push: options and the values of -o, --push-option, --repo, --receive-pack, --exec and --recurse-submodules left out. */
function pushWords(words) {
  const out = [];
  const rest = withoutRedirects(words); // `2>&1` is no refspec
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    if (a === '--') {
      out.push(...rest.slice(i + 1));
      break;
    }
    if (!a.startsWith('-')) out.push(a);
    else if (/^-[vqdnfu46]*o$/.test(a) || (!a.includes('=') && PUSH_VALUE_OPTIONS.includes(longOptionName(a, PUSH_OPTIONS)))) i++;
  }
  return out;
}

/** True when a push refspec with a `*` can update a protected branch: its destination (its source when it has no `:`) matches refs/heads/<branch>. */
function patternReaches(refspec, protectedBranches) {
  const dest = refspec.includes(':') ? refspec.slice(refspec.indexOf(':') + 1) : refspec;
  if (!dest.includes('*')) return false;
  const re = new RegExp(`^${dest.split('*').map(escapeRe).join('.*')}$`, 'i');
  return protectedBranches.some((b) => re.test(`refs/heads/${b}`) || re.test(`heads/${b}`) || re.test(b));
}

// Round 3: a git push that names no refspec (and no --all, --branches, --tags, --mirror) sends what the configuration says:
// the remote.<name>.push refspecs, else push.default (matching: every branch that exists on both sides, main among them;
// upstream/tracking: the branch's upstream, which may be main), and remote.<name>.mirror=true makes any push to that remote
// a mirror push. `-c key=value` and `--config-env` before `push` set them for this call. The keys as `git config` writes:
const PUSH_CONFIG_KEY_RE = /(?:^|[\s"'`])(?:push\.default|remote\.[^\s=]+\.(?:push|mirror))(?:[=\s]|$)/i;
const PUSH_CONFIG_REASON =
  'This sets push.default, remote.<name>.push or remote.<name>.mirror, which decide what a later git push without a refspec sends (matching, a refs/heads/* refspec or a mirror reach main). Only the user changes git configuration.';
// The project's push settings, read once per process (a hook judges one command, whose spellings and comment readings may
// judge the same push several times): undefined until read, null when git could not read them or holds none.
let pushConfigText;

/** The section, subsection and variable of a git configuration key that judges a push, or null: push.default, remote.<name>.push, remote.<name>.mirror. */
function pushConfigKey(key) {
  if (/^push\.default$/i.test(key)) return { name: 'push.default' };
  const m = /^remote\.([\s\S]+)\.(push|mirror)$/i.exec(key);
  return m ? { name: m[2].toLowerCase(), remote: m[1] } : null;
}

/**
 * The push settings that apply to a push without a refspec: the project's git configuration (one `git config
 * --get-regexp` from the project root), then the `-c` and `--config-env` values of this call (`globalOpts`) on top, in
 * git's order (a later value of push.default wins; refspecs add up). A key from --config-env takes its value from a variable
 * the guard does not read: `hidden`. When git cannot read the configuration (or holds none of these keys) only `-c` counts.
 */
function pushSettings(globalOpts) {
  const entries = [];
  if (pushConfigText === undefined) pushConfigText = git(['config', '-z', '--get-regexp', '^(push\\.default|remote\\..*\\.(push|mirror))$']);
  for (const entry of (pushConfigText ?? '').split('\0')) {
    if (!entry) continue;
    const nl = entry.indexOf('\n'); // -z: the key, a newline, the value; a key alone is a boolean true
    entries.push(nl < 0 ? [entry, null] : [entry.slice(0, nl), entry.slice(nl + 1)]);
  }
  const hidden = [];
  for (let j = 0; j < globalOpts.length; j++) {
    const a = globalOpts[j];
    const env = a === '--config-env' || /^--config-env=/i.test(a);
    if (a !== '-c' && !env) continue;
    const pair = a.includes('=') ? a.slice(a.indexOf('=') + 1) : globalOpts[++j] ?? '';
    const eq = pair.indexOf('=');
    const key = eq < 0 ? pair : pair.slice(0, eq);
    if (env) hidden.push(key);
    else entries.push([key, eq < 0 ? null : pair.slice(eq + 1)]);
  }
  const settings = { pushDefault: '', refspecs: [], mirrors: new Set(), hidden: hidden.filter((key) => pushConfigKey(key)) };
  for (const [key, value] of entries) {
    const k = pushConfigKey(key);
    if (k?.name === 'push.default') settings.pushDefault = String(value ?? '').toLowerCase();
    else if (k?.name === 'push' && value) settings.refspecs.push({ remote: k.remote, refspec: value });
    else if (k?.name === 'mirror') {
      if (value === null || /^(?:true|yes|on|1)$/i.test(value)) settings.mirrors.add(k.remote);
      else settings.mirrors.delete(k.remote);
    }
  }
  return settings;
}

/**
 * The deny for a git push that names no refspec when the configuration sends a protected branch, forces or mirrors
 * (pushSettings), or null. `remote` is the repository word (undefined: git picks one, so every remote's settings count).
 * Configured refspecs are judged like written ones: `+` (force), `:` (matching) and `:dst` (delete) deny, and so does a
 * destination or `*` pattern on a protected branch. push.default=matching is denied whenever branches are protected (like
 * --all); upstream/tracking when the branch's upstream (branch.<name>.merge) is protected.
 */
function configuredPushVerdict(remote, globalOpts, protectedBranches, branch) {
  const s = pushSettings(globalOpts);
  const inScope = (r) => remote === undefined || r === remote;
  if (s.hidden.length) {
    return deny(`git push takes ${s.hidden.join(', ')} from a variable (--config-env) the guard does not read: it decides what a push without a refspec sends. Set nothing on the command line, or name the branch: git push origin <feature-branch>.`);
  }
  const mirror = [...s.mirrors].find(inScope);
  if (mirror !== undefined) {
    return deny(`remote.${mirror}.mirror is true (git configuration or -c): a push to that remote is a mirror push, which force-updates and deletes remote branches. Force pushes, mirror pushes and remote branch deletion are blocked (they destroy shared history).`);
  }
  const blocked = `Direct pushes to ${protectedBranches.join('/')} are blocked. Push a feature branch and open a PR.`;
  const refspecs = s.refspecs.filter((r) => inScope(r.remote));
  for (const { remote: r, refspec } of refspecs) {
    if (/^[+:]/.test(refspec)) {
      return deny(`git push without a refspec follows remote.${r}.push = ${refspec} (git configuration or -c), which forces (+), pushes every matching branch (:) or deletes a remote branch. Force pushes, mirror pushes and remote branch deletion are blocked; name the branch: git push origin <feature-branch>.`);
    }
    const target = refspec.split(':').pop().replace(/^refs\/heads\//, '');
    if (protectedBranches.includes(target) || (target === 'HEAD' && protectedBranches.includes(branch)) || patternReaches(refspec, protectedBranches)) {
      return deny(`git push without a refspec follows remote.${r}.push = ${refspec} (git configuration or -c), which reaches a protected branch. ${blocked} Name the branch: git push origin <feature-branch>.`);
    }
  }
  // A named remote with refspecs of its own never reads push.default; with none named, every remote may be the one.
  if (remote !== undefined && refspecs.length) return null;
  if (s.pushDefault === 'matching' && protectedBranches.length) {
    return deny(`push.default is matching (git configuration or -c): git push without a refspec pushes every branch that also exists on the remote, ${protectedBranches.join('/')} among them. ${blocked} Name the branch: git push origin <feature-branch>.`);
  }
  if ((s.pushDefault === 'upstream' || s.pushDefault === 'tracking') && branch && branch !== 'HEAD') {
    const merge = (git(['config', '--get', `branch.${branch}.merge`]) ?? '').trim().replace(/^refs\/heads\//, '');
    if (protectedBranches.includes(merge)) {
      return deny(`push.default is ${s.pushDefault} and the upstream of ${branch} is ${merge}: git push without a refspec pushes ${branch} onto ${merge}. ${blocked} Name the branch: git push origin <feature-branch>.`);
    }
  }
  return null;
}

// git config options that change nothing and take no separate value (scope and output flags), and the ones whose value is
// the next word when written without `=`. Any other option (and every abbreviation git accepts: `--unse` is --unset) may
// change the configuration, so a command with one is no read by the one-key rule.
const CONFIG_READ_FLAGS = /^(?:--(?:local|global|system|worktree|bool|int|bool-or-int|path|expiry-date|null|name-only|show-origin|show-scope|includes|no-includes|type=[\w-]+|file=[\s\S]+|blob=[\s\S]+)|-z)$/;
const CONFIG_READ_VALUE_OPTS = /^(?:--file|-f|--blob|--type)$/;

/**
 * True when a `git config` command only reads (F1-135): --get, --get-all, --get-regexp, --get-urlmatch, --list or -l without
 * an option that changes the configuration, `git config get <key>` (git 2.46+), or exactly one key (a word with a dot) and
 * no value, with scope and output flags only. Judged on the words after `config`, so a commit message that says
 * "config --get" makes no other git command a read.
 */
function gitConfigReads(sub, rest) {
  if (sub !== 'config') return false;
  const words = withoutRedirects(rest);
  if (words.some((a) => /^--(?:un|rep|ad|ed|ren|rem|com)/i.test(a) || /^-[a-z]*e/.test(a))) return false;
  if (words.some((a) => /^(?:--get(?:-all|-regexp|-urlmatch|-color|-colorbool)?|--list|-l)$/.test(a))) return true;
  const positional = [];
  for (let k = 0; k < words.length; k++) {
    const a = words[k];
    if (CONFIG_READ_VALUE_OPTS.test(a)) k++;
    else if (a.startsWith('-')) {
      if (!CONFIG_READ_FLAGS.test(a)) return false;
    } else positional.push(a);
  }
  return (positional.length === 1 && positional[0].includes('.')) || (positional.length === 2 && positional[0] === 'get' && positional[1].includes('.'));
}

function checkGit(args, raw, ctx) {
  const i = gitSubcommandIndex(args);
  const sub = (args[i] || '').toLowerCase();
  const globalOpts = args.slice(0, i);
  const rest = spellOutGitOptions(sub, args.slice(i + 1));
  const spelled = [...args.slice(0, i + 1), ...rest];
  const protectedBranches = ctx.protectedBranches || [];

  // Reading the setting (gitConfigReads: --get, --list, `get <key>`, one key without a value) changes nothing; session
  // start reads it too. The only hooks path the harness ships is hardening/githooks (F1-133: .githooks is no exception).
  const readsConfig = gitConfigReads(sub, rest);
  if (/core\.hookspath/i.test(raw) && !readsConfig && !/core\.hookspath[=\s]+hardening\/githooks\s*$/i.test(raw)) {
    return deny('Changing core.hooksPath would disable the harness git hooks.');
  }
  // `git -c alias.p=push p ...`: an alias defined on the command line hides the real subcommand from every rule.
  if (/(?:^|\s)-c\s*alias\.|--config-env[= ]alias\./i.test(raw)) {
    return askFloor('This git command defines an alias on the command line, which hides the real subcommand. Write the subcommand itself.');
  }
  // Another repository, work tree, ref namespace or program folder, by option: denied like the variables (GIT_ENV_RE).
  if (globalOpts.some((a) => GIT_REPOINT_OPT_RE.test(a))) return deny(GIT_ENV_REASON);
  // A program-running key set persistently (git config) or for this call (-c, --config-env before the subcommand).
  const inlineKey = globalOpts.some((a, j) => ((a === '-c' || a === '--config-env') && GIT_PROGRAM_KEY_RE.test(` ${args[j + 1] ?? ''}`))
    || (/^(?:-c|--config-env)=/i.test(a) && GIT_PROGRAM_KEY_RE.test(` ${a.replace(/^[^=]*=/, '')}`)));
  if (inlineKey || (sub === 'config' && !readsConfig && GIT_PROGRAM_KEY_RE.test(` ${rest.join(' ')}`))) {
    return deny('This sets a git configuration key that runs a program or redirects git (pager, editor, fsmonitor, SSH, diff drivers, aliases, includes, credential helpers, trace2 targets): a later routine git command would run it. Only the user changes git configuration.');
  }
  // What a later git push without a refspec sends (configuredPushVerdict): set for good only by the user.
  if (sub === 'config' && !readsConfig && PUSH_CONFIG_KEY_RE.test(` ${rest.join(' ')}`)) return deny(PUSH_CONFIG_REASON);
  // --output writes a file, --ext-diff and --textconv run the configured driver, --no-index compares any two files on the
  // machine: with `git diff/log/show` on the settings allow list, only a deny here keeps them from running silently.
  if (spelled.some((a) => /^--output(?:=|$)/i.test(a))) return deny('git --output writes a file without the Edit/Write checks. Show the output, or write the file with the Write tool.');
  if (spelled.some((a) => /^--(?:ext-diff|textconv)$/i.test(a))) return deny('--ext-diff and --textconv run the diff driver or text converter set in git configuration, a program the guard cannot see.');
  if (spelled.some((a) => /^--no-index$/i.test(a))) return deny('git diff --no-index compares any two files on the machine, credentials included. Read project files with the Read tool and compare inside the repository.');
  // git runs the value of -O / --open-files-in-pager through the shell with the names of the matching files (F2-1).
  if (opensPager(sub, rest)) return deny('git grep -O and --open-files-in-pager run a program: the pager, or the command given, is started through the shell with the names of the matching files, and the guard cannot see it. Read the matches with git grep alone.');
  switch (sub) {
    case 'push': {
      if (rest.includes('--no-verify')) return deny('git push --no-verify bypasses the harness pre-push hook.');
      const destructive = rest.some(
        (a) => /^--(?:force|force-with-lease|force-if-includes|mirror|delete|prune)(?:=.*)?$/.test(a) || /^[+:]/.test(a),
      );
      if (destructive || hasShortFlag(rest, 'f') || hasShortFlag(rest, 'd')) {
        return deny('Force pushes, mirror pushes and remote branch deletion are blocked (they destroy shared history).');
      }
      // The first word is the repository; the values of -o, --repo and the like are neither (pushWords). --all and --branches
      // push every local branch, and a refspec pattern (refs/heads/*) every branch it matches: main among them (F2-5).
      // Without a refspec git follows the configuration (remote.<name>.push, push.default, remote.<name>.mirror): judged below.
      const refspecs = pushWords(rest).slice(1);
      const targets = refspecs.map((r) => r.split(':').pop().replace(/^refs\/heads\//, ''));
      const branch = ctx.getBranch?.();
      const hitsProtected =
        targets.some((t) => protectedBranches.includes(t)) ||
        (refspecs.length === 0 && protectedBranches.includes(branch)) ||
        (targets.includes('HEAD') && protectedBranches.includes(branch)) ||
        (protectedBranches.length > 0 && (rest.some((a) => /^--(?:all|branches)$/.test(a)) || refspecs.some((r) => patternReaches(r, protectedBranches))));
      if (hitsProtected) return deny(`Direct pushes to ${protectedBranches.join('/')} are blocked. Push a feature branch and open a PR.`);
      if (refspecs.length === 0 && !rest.some((a) => /^--(?:all|branches|tags|mirror)$/.test(a))) {
        const configured = configuredPushVerdict(pushWords(rest)[0], globalOpts, protectedBranches, branch);
        if (configured) return configured;
      }
      return askFloor('git push publishes commits to the remote (Tier 2, outward-facing). Confirm branch and remote.');
    }
    case 'commit': {
      if (rest.includes('--no-verify') || hasShortFlag(rest, 'n')) return deny('git commit --no-verify bypasses the PBIP pre-commit validation.');
      const reads = gitFileRead(sub, rest, ctx, globalOpts);
      if (reads) return reads;
      const branch = ctx.getBranch?.();
      if (branch && protectedBranches.includes(branch)) {
        return ask(`You are on protected branch '${branch}'. The harness expects commits on feature/* or fix/* branches (git switch -c feature/<topic>).`);
      }
      if (rest.includes('--amend')) return ask('git commit --amend rewrites the last commit; make sure it was not pushed yet.');
      return null;
    }
    case 'add':
      if (rest.includes('--force') || hasShortFlag(rest, 'f')) {
        return deny('git add --force would stage ignored files (cache.abf, localSettings.json, .env).');
      }
      return gitFileRead(sub, rest, ctx, globalOpts);
    case 'blame':
      return gitFileRead(sub, rest, ctx, globalOpts);
    case 'reset':
      return rest.includes('--hard') ? deny('git reset --hard discards uncommitted work.') : null;
    case 'clean':
      return rest.includes('--force') || hasShortFlag(rest, 'f') ? deny('git clean -f permanently deletes untracked files.') : null;
    case 'checkout':
      if (rest.some((a) => /^--orphan(?:=|$)/.test(a))) return deny(GIT_ORPHAN_REASON);
      if (rest.includes('.') || rest.includes('--force') || hasShortFlag(rest, 'f')) return deny('This git checkout discards uncommitted changes.');
      return guardMoveVerdict(sub, rest, gitBase(globalOpts, shellDir(ctx)));
    case 'switch':
      if (rest.some((a) => /^--orphan(?:=|$)/.test(a))) return deny(GIT_ORPHAN_REASON);
      if (rest.includes('--force') || rest.includes('--discard-changes') || rest.some((a) => /^--force-create(?:=|$)/.test(a)) || hasShortFlag(rest, 'f') || hasShortFlag(rest, 'C')) {
        return deny('This git switch discards uncommitted changes or moves a branch by force (-f, --discard-changes, -C). Commit or stash first, then switch.');
      }
      return guardMoveVerdict(sub, rest, gitBase(globalOpts, shellDir(ctx)));
    case 'diff': {
      // The implicit --no-index (F2-6): a deny like the explicit option; two words the guard cannot place may be one.
      const places = diffPathPlaces(rest, gitBase(globalOpts, shellDir(ctx)));
      if (places.includes('outside')) return deny(IMPLICIT_NO_INDEX_REASON);
      if (places.length >= 2 && places.includes('unplaceable')) {
        return askUser('git diff compares two files as git diff --no-index when one of its two paths lies outside the repository, and a variable or a folder the guard cannot place hides where these point. Name revisions or paths inside the project, or confirm.');
      }
      return null;
    }
    case 'restore': {
      // -W is --worktree, also inside a cluster of short options (`-qW`); only --staged without it leaves the files alone.
      const worktree = rest.includes('--worktree') || hasShortFlag(rest, 'W');
      if ((rest.includes('.') || rest.includes(':/')) && !(rest.includes('--staged') && !worktree)) {
        return deny('git restore . discards all uncommitted changes.');
      }
      return null;
    }
    case 'stash':
      return ['drop', 'clear'].includes((rest[0] || '').toLowerCase()) ? deny('git stash drop/clear loses stashed work.') : null;
    case 'branch': {
      // Combined short flags count too: -Df, -df, -fd.
      const deletes = hasShortFlag(rest, 'd') || rest.includes('--delete');
      const forced = hasShortFlag(rest, 'D') || (deletes && (hasShortFlag(rest, 'f') || rest.includes('--force')));
      return forced ? deny('Force-deleting branches is blocked; use git branch -d after merging.') : null;
    }
    case 'filter-branch':
    case 'filter-repo':
      return deny('History rewriting is blocked.');
    case 'reflog':
      return ['expire', 'delete'].includes((rest[0] || '').toLowerCase()) ? deny('Expiring the reflog removes recovery points.') : null;
    case 'update-ref':
      return rest.includes('-d') ? deny('Deleting refs is blocked.') : null;
    case 'gc':
      return rest.some((a) => a.startsWith('--prune')) ? deny('git gc --prune removes recovery points.') : null;
    case 'rm':
      return rest.includes('--cached') ? null : ask('git rm deletes files. Deleting report pages, visuals or model objects is Tier 2.');
    case 'apply':
    case 'am':
      // A patch changes files without the Edit checks, harness files included; a dry run only reads.
      return rest.some((a) => /^--(?:check|stat|numstat|summary)$/.test(a))
        ? null
        : askUser(`git ${sub} writes the patch's changes to files without the Edit/Write checks and can change harness files. Show the patch and let the user apply it.`);
    default:
      return null;
  }
}

// find actions that change files or run programs (F1-9): -delete, -fprint/-fprint0/-fprintf/-fls (they write a file) and
// -exec/-execdir/-ok/-okdir (a program per match). Auto approval never passes one; one aimed at .git, .claude, .githooks,
// .github or hardening, or at a folder outside the project, is denied.
const FIND_EXEC_RE = /^-(?:exec|execdir|ok|okdir)$/;
const FIND_WRITE_RE = /^-(?:fprint\w*|fls)$/;
const FIND_PROTECTED_RE = /(?:^|\/)(?:\.git|\.claude|\.githooks|\.github|hardening)(?:\/|$)/i;

/** Where a find start point or output file lies: 'protected' (FIND_PROTECTED_RE), 'outside' the project, 'unknown' (a variable, a wildcard, ~name, or a folder the guard lost track of after a `cd`) or 'inside'. */
function findPlace(value, base) {
  const v = String(value ?? '').replace(/^["'(]+|["'`),;]+$/g, '').replace(/^~(?=[\\/]|$)/, () => os.homedir());
  if (!v || /[$%`*?[]|^~/.test(v)) return 'unknown';
  const native = nativePath(v);
  if (process.platform !== 'win32' && (FOREIGN_ABSOLUTE_RE.test(v) || FOREIGN_ABSOLUTE_RE.test(native))) return 'outside';
  if (base === null && !path.isAbsolute(native)) return 'unknown';
  const absolute = path.resolve(base ?? PROJECT_DIR, native);
  const rel = projectRel(absolute);
  const real = projectRel(canonicalPathOf(absolute));
  if (rel === null || real === null) return 'outside';
  return FIND_PROTECTED_RE.test(rel) || FIND_PROTECTED_RE.test(real) ? 'protected' : 'inside';
}

/**
 * The verdict for `find` (null for a find that only looks). The programs `-exec` runs are commands of their own and are
 * judged first (`find -exec ssh ...`, `-exec git push`); every -exec of the expression counts, not only the first. A program that
 * only reads or prints (TEXT_READERS: grep, cat, wc, ls...) changes nothing; any other, -delete and the -fprint family are
 * actions that change files. In-place editors (`-exec sed -i`, `perl -i`) write every matched file outside the Edit/Write
 * checks: denied. The rest is the user's call, which auto mode never answers (askUser).
 */
function checkFind(args, ctx, depth) {
  const lower = args.map((a) => a.toLowerCase());
  const execs = [];
  for (let i = 0; i < args.length; i++) {
    if (!FIND_EXEC_RE.test(lower[i])) continue;
    const end = args.findIndex((a, j) => j > i && (a === ';' || a === '\\;' || a === '+'));
    execs.push(args.slice(i + 1, end < 0 ? undefined : end));
    if (end < 0) break;
    i = end;
  }
  if (depth < 3) {
    for (const words of execs) {
      const verdict = analyzeShellCommand(words.join(' '), ctx, depth + 1);
      if (verdict?.decision === 'deny' || verdict?.autoApprovable === false) return verdict;
    }
  }
  const written = args.filter((_, i) => i > 0 && FIND_WRITE_RE.test(lower[i - 1]));
  const runs = execs.map((words) => {
    const tokens = normalizeTokens(words);
    return { prog: programName(tokens[0]), args: tokens.slice(1) };
  });
  const readsOnly = (run) => TEXT_READERS.has(run.prog) && !(run.prog === 'rg' && run.args.some((a) => /^--pre(?:=|$)/.test(a)));
  if (!lower.includes('-delete') && !written.length && runs.every(readsOnly)) return null;

  // The start points: the words before the expression (after find's own -H, -L, -P, -D and -O options); `.` when there is none.
  let s = 0;
  while (s < args.length) {
    if (/^-[HLP]$/.test(args[s]) || /^-O\d?$/.test(args[s])) s++;
    else if (args[s] === '-D') s += 2;
    else break;
  }
  const starts = [];
  for (; s < args.length && !/^(?:-|!|\\?\()/.test(args[s]); s++) starts.push(args[s]);
  if (!starts.length) starts.push('.');
  const base = shellDir(ctx);
  const places = [...starts, ...written].map((p) => findPlace(p, base));
  if (places.includes('protected')) {
    return deny('find -delete, -exec and -fprint on .git, .claude, .githooks, .github or hardening are blocked: they hold the repository history and the harness guardrails. Change them with the Edit tool so the user can review the change.');
  }
  if (places.includes('outside')) {
    return deny('find -delete, -exec and -fprint on a folder outside the project are blocked: the harness works inside the project.');
  }
  if (runs.some((run) => ['sed', 'perl', 'awk', 'gawk'].includes(run.prog) && run.args.some((a) => /^-\w*i/.test(a) || /^--in-?place/.test(a)))) {
    return deny('find -exec sed -i (or perl -i, awk -i inplace) edits every file it matches in place, outside the Edit/Write checks for credentials, JSON, XML, renames, object ids and line limits. Edit the files with the Edit tool, one at a time, so the user can review the diff.');
  }
  // A reference folder (templates/, a report's source/ folder, the config's "references") is read-only, the folder itself too.
  const inReference = (t) => {
    const rel = projectRel(path.resolve(base ?? PROJECT_DIR, t));
    return rel !== null && isReferenceRel(`${rel}/`, { references: ctx.references });
  };
  if (written.some((f) => GUARDED_FILE_RE.test(f)) || [...starts, ...written].some(inReference)) return deny(WRITE_TO_GUARDED_REASON);
  return askUser('find -delete, -fprint and -fls, and -exec with a program that changes files, act on every file they match, so auto mode never approves them. Confirm the folder and the action.');
}

// F2-15: bash's variable builtins print every variable, the exported ones with their values, when no NAME follows: bare
// `export`, `declare` and `typeset`, also with listing options only (`declare -x`, `typeset -x`, `export -n`, `declare -r`,
// `declare --`, `declare +x`), and -p prints the named variables' values too (`declare -p NAME`, `typeset -p`). -f and -F
// list functions only. A NAME (`export NAME=value`, `declare -a arr`, `typeset -i n=1`) sets or shows that variable alone.
// `local` prints a function's own variables only, and `readonly` the read-only ones (the shell's own, unless a profile
// marks more): both stay.
const VARIABLE_LISTERS = new Set(['export', 'declare', 'typeset']);

/** True when `prog args` is a variable builtin (VARIABLE_LISTERS) that prints variables with their values: -p, or no NAME and no function option. */
function dumpsVariables(prog, args) {
  if (!VARIABLE_LISTERS.has(prog)) return false;
  const words = withoutRedirects(args); // `export > x` and `declare 2>&1` name no variable
  if (words.some((a) => /^-[A-Za-z]*p/.test(a))) return true;
  const options = words.filter((a) => a === '--' || /^[-+][A-Za-z]*$/.test(a));
  return options.length === words.length && !options.some((a) => /[fF]/.test(a.slice(1)));
}

function checkSubcommand(sub, ctx) {
  // Before normalizing: `env -0` would otherwise be read as an env wrapper around nothing.
  if (ENV_DUMP_RE.test(sub) || /^\s*(?:\S*[\\/])?env(?:\.exe)?(?:\s+(?:-0|--null))+\s*$/i.test(sub)) {
    return deny('Dumping environment variables can expose credentials.');
  }
  const rawTokens = tokenize(sub);
  const tokens = normalizeTokens(rawTokens);
  // GIT_* variables set in front of any command (`GIT_TRACE=/x git status`, `env GIT_PAGER=x bash -c '...'`) or alone
  // (`GIT_TRACE=/x; export GIT_TRACE`): they reach every git the command line starts (gitVariableVerdict).
  const assigned = gitAssignmentsVerdict(rawTokens.slice(0, tokens.skipped));
  if (assigned) return assigned;
  if (!tokens.length) return null;
  // `npx @microsoft/powerbi-desktop-bridge-cli ...` is judged as `powerbi-desktop ...` (unwrapNpx).
  const npx = unwrapNpx(programName(tokens[0]), tokens.slice(1));
  const { prog, args } = npx;
  const raw = tokens.join(' ');

  if (['sudo', 'su', 'doas', 'runas'].includes(prog)) return deny('Privilege escalation is blocked.');

  // Secret and data files named on the command line: in the text, in a word the quotes hid (.en''v is .env once
  // tokenized), or behind a wildcard a content reader would expand (*.env). Listers show names only. Only file names count:
  // a commit message or a search pattern may say ".env" (textWordIndexes).
  const textFree = ctx.textFree !== false; // false: the pipeline goes on into something that is not a plain reader
  const textWords = textWordsOf(sub, prog, args, textFree);
  const pathArgs = textWords.size ? args.filter((_, j) => !textWords.has(j)) : args;
  const pathText = ` ${textWords.size ? pathTextOf(sub, textFree) : sub}`;
  // A file word also counts as the shell opens it (opensSecretFile), for every program that opens files, like the plain name:
  // through a link (`b/credentials`, `b/cred*`, `README.md,b\credentials`, b -> .aws) or a `..` after one (`a/../credentials`,
  // a -> .aws/cache), inside the project or out of it (A1, R3, R4). A printer's words are text (`echo b`), its redirect
  // target is not (`echo x > b/credentials`): every redirect outside the text words counts, whatever the program.
  const namesSecret = SHELL_SECRET_RE.test(pathText) || SHELL_SECRET_DIR_RE.test(pathText) || pathArgs.some(namesSecretFile)
    || (!LISTERS.has(prog) && prog !== 'find' && pathArgs.some(wildcardNamesSecret))
    || (!PRINTERS.has(prog) && pathArgs.some((w) => opensSecretFile(w, shellDir(ctx))))
    || redirectTargets(pathText).some((t) => opensSecretFile(t, shellDir(ctx)))
    || inputRedirectTargets(sub).some((t) => opensSecretFile(t, shellDir(ctx))); // `cat <b/credentials` (third review, item 2)
  if (namesSecret && !SAFE_WITH_SECRET_PATH.has(prog)) {
    const gitSafe = prog === 'git' && /^(?:check-ignore|ls-files|status)$/.test(args[0] || '');
    const untrack = prog === 'git' && args[0] === 'rm' && args.includes('--cached');
    if (!gitSafe && !untrack) {
      return deny('This command touches a secret or data file (.env, keys, cache.abf, .pbix, *.rdl.data, a workspace database, a credential store). The harness blocks that for the agent; use placeholders or ask the user.');
    }
  }
  if (prog === 'git' && rawTokens.some((t) => GIT_ENV_RE.test(t))) return deny(GIT_ENV_REASON);
  // The same variables set for the commands after this one: export/declare/set/setx, $env:, SetEnvironmentVariable, Set-Item env:.
  const setsGitVariable = gitVariableSetVerdict(prog, args, pathText);
  if (setsGitVariable) return setsGitVariable;

  // Environment dumps and secret-named variables
  if ((prog === 'env' && args.length === 0) || prog === 'printenv' || (prog === 'set' && args.length === 0)) {
    return deny('Dumping environment variables can expose credentials.');
  }
  if (dumpsVariables(prog, args)) return deny('Dumping environment variables can expose credentials.');
  if (ENV_PROVIDER_READERS.has(prog) && args.some((a, j) => !textWords.has(j) && namesEnvProvider(a))) return deny('Dumping environment variables can expose credentials.');
  if (hasUnquotedParen(sub) && NESTED_ENV_READ_RE.test(sub)) return deny('Dumping environment variables can expose credentials.');
  for (const m of sub.matchAll(/\$(?:env:|\{env:|\{)?([A-Za-z_][A-Za-z0-9_]*)/g)) {
    if (isSecretVarName(m[1])) return deny(`The command references the secret variable $${m[1]}. Credentials must stay out of the agent's shell.`);
  }
  // The same variable read by name from code: process.env.X or ['X'], os.environ['X'], os.environ.get('X'),
  // os.getenv('X'), [Environment]::GetEnvironmentVariable('X'), cmd's %X%. A password the user keeps in the
  // environment for a SQL client (SQLCMDPASSWORD, PGPASSWORD) stays with the client.
  for (const m of sub.matchAll(SECRET_VAR_LOOKUP_RE)) {
    const name = m[1] ?? m[2] ?? m[3] ?? m[4];
    if (isSecretVarName(name)) return deny(`The command reads the secret variable ${name}. Credentials must stay out of the agent's shell.`);
  }
  for (const m of sub.matchAll(SECRET_VAR_LOOKUP2_RE)) {
    const name = m[1] ?? m[2] ?? m[3] ?? m[4];
    if (isSecretVarName(name)) return deny(`The command reads the secret variable ${name}. Credentials must stay out of the agent's shell.`);
  }
  // Commands that print a sign-in token into the conversation (F1-65: gh auth status prints it with --show-token or -t).
  if (TOKEN_PRINT_RE.test(sub)) return deny('This prints a sign-in token (gcloud print-access-token, az account get-access-token, gh auth token, gh auth status --show-token/-t, Get-AzAccessToken). Credentials stay with the user; the tools sign in on their own.');

  // A write target inside a reference folder (built-in, or the config's `references` passed in ctx by the guard).
  const inReference = (t) => isReferenceRel(projectRel(path.resolve(ctx.baseDir ?? PROJECT_DIR, t)), { references: ctx.references });
  const redirectText = prog === 'git' && textWords.size ? withoutQuotedText(sub, [...textWords].map((j) => args[j])) : sub;
  if (writesGuardedFile(redirectText, prog, args, ctx.guardedMention, ctx.cwd === 'pbip', inReference)) return deny(WRITE_TO_GUARDED_REASON);
  // git: after the redirect check above (`git show HEAD:x.md > docs/notes.md` writes a guarded file), then its own options.
  if (prog === 'git') return checkGit(args, raw, ctx);
  if (DELETE_PROGRAMS.has(prog) && writerTargets(args).some((t) => inReference(String(t ?? '').replace(/^["'(]+/, '').replace(/["'`),;]+$/, '')))) {
    return deny('A reference folder (templates/, a report\'s source/ folder, or the config\'s "references") is read-only: nothing in it is deleted or changed (AGENTS.md).');
  }
  if (ROLE_MEMBER_CMDLET_RE.test(prog)) {
    return deny('Role membership on a server is managed by the user (Power BI service, SSMS), never by the agent.');
  }

  // A shell started with its command in the arguments (quoted or not): judge that command too.
  const depth = ctx.depth ?? 0;
  if (SHELL_PROGRAMS.has(prog) && depth >= 3 && shellInlineCommand(prog, args)) {
    return askFloor('This command nests shells more than three levels deep, which the harness does not analyse. Write the inner command directly.');
  }
  if (SHELL_PROGRAMS.has(prog) && depth < 3) {
    const inner = shellInlineCommand(prog, args);
    const verdict = inner ? analyzeShellCommand(inner, ctx, depth + 1) : null;
    if (verdict) return verdict;
  }
  // eval runs its words as one command line (bash joins them with spaces and parses the result): judge that line.
  if (prog === 'eval' && args.length) {
    if (depth >= 3) return askFloor(NESTING_REASON);
    const verdict = analyzeShellCommand(args.join(' '), ctx, depth + 1);
    if (verdict) return verdict;
  }
  // `npx -p @microsoft/powerbi-desktop-bridge-cli -c "powerbi-desktop screenshot ..."`: npx runs the call in a shell.
  if (npx.call !== undefined) {
    if (depth >= 3) return askFloor('This command nests shells more than three levels deep, which the harness does not analyse. Write the inner command directly.');
    const verdict = analyzeShellCommand(npx.call, ctx, depth + 1);
    // Without --no, npx may download the package first: an ask is then never auto-approved (unwrapNpx).
    if (verdict?.decision === 'ask' && !npx.installedOnly && verdict.autoApprovable !== false) return { ...verdict, autoApprovable: false, reason: `${verdict.reason} ${NPX_DOWNLOAD_REASON}` };
    if (verdict) return verdict;
  }

  // A script file run through an interpreter or directly (./x.sh, & x.ps1), any extension, or a module (python -m).
  // Held until the denies and the server asks below had their say, so it never hides one of them.
  // autoDefer: in auto mode these are not approved by the guard either; Claude Code's own permission flow decides, since
  // the guard cannot see what the code does.
  const script = scriptOf(prog, args, tokens[0]);
  let scriptAsk = script && !insideHarness(script, ctx.baseDir)
    ? { ...ask(`This runs ${script} as code. What it writes skips the Edit/Write checks (credentials, JSON, XML, renames, line limits): review it first; the Stop gate, the pre-commit hook and CI validate its output.`), autoDefer: true }
    : null;
  // Inline code that writes files and names a reference folder: denied outright, because an allow rule for the
  // interpreter (e.g. `Bash(node *)`) would otherwise let it run without a prompt.
  if (inlineCode(prog, args) && (FILE_API_RE.test(sub) || DOC_WRITER_RE.test(sub)) && mentionsReference(sub, ctx.references)) {
    return deny('This inline code writes files and names a reference folder (templates/, a report\'s source/ folder, or the config\'s "references"), which is read-only (AGENTS.md).');
  }
  if (!scriptAsk && inlineCode(prog, args) && (FILE_API_RE.test(sub) || DOC_WRITER_RE.test(sub) || PROCESS_API_RE.test(sub))) {
    scriptAsk = { ...ask('This inline code writes files or starts programs, which the shell analysis cannot follow and the Edit/Write checks never see. Review it, or use the Edit tool for project files.'), autoDefer: true };
  }

  // Destructive deletes
  if (prog === 'rm') {
    const recursive = args.some((a) => a === '--recursive' || (/^-[a-zA-Z]+$/.test(a) && /[rR]/.test(a)));
    const force = args.some((a) => a === '--force' || (/^-[a-zA-Z]+$/.test(a) && a.includes('f')));
    if (recursive && force) return deny('rm -rf is blocked. Delete specific files, one step at a time, after confirming with the user.');
    if (args.some((a) => DELETE_GUARD_RE.test(toPosix(a)))) return deny('Deleting harness or git metadata is blocked.');
    if (args.some((a) => /\.report\/definition\/pages\//i.test(toPosix(a)))) return ask('Deleting report pages or visuals is Tier 2. Confirm with the user.');
    return null;
  }
  if (['remove-item', 'ri', 'del', 'erase', 'rd', 'rmdir'].includes(prog)) {
    const recurse = args.some((a) => /^-r(?:ecurse)?$/i.test(a) || /^\/s$/i.test(a));
    const force = args.some((a) => /^-fo(?:rce)?$/i.test(a) || /^\/q$/i.test(a));
    if (recurse && force) return deny('Recursive forced deletes are blocked.');
    // The same folders as `rm` (F1-77): `Remove-Item .claude` is `rm .claude`.
    if (writerTargets(args).some((a) => DELETE_GUARD_RE.test(toPosix(String(a ?? '').replace(/^["'(]+|["'`),;]+$/g, ''))))) return deny('Deleting harness or git metadata is blocked.');
    return null;
  }
  // find -delete, -fprint and -exec: judged apart (checkFind), never approved by auto mode when they change files (F1-9).
  if (prog === 'find') {
    const verdict = checkFind(args, ctx, depth);
    if (verdict) return verdict;
  }

  // Network egress (before the asks below: a deny must never turn into an ask)
  if (NET_PROGRAMS.has(prog)) return deny(`${prog} is blocked (network egress / exfiltration risk). Use WebFetch for documentation.`);
  if (inlineCode(prog, args) && INLINE_NET_RE.test(sub)) {
    return deny('Network calls from inline code are blocked like curl (exfiltration risk). Use WebFetch for documentation.');
  }
  if (!TEXT_READERS.has(prog) && prog !== 'git' && NET_DOTNET_RE.test(sub)) {
    return deny('.NET network classes and web cmdlets are blocked like curl (exfiltration risk). Use WebFetch for documentation.');
  }
  if (prog === 'rsync' && args.some((a) => /^[\w.-]+@?[\w.-]*:|^rsync:\/\//.test(a))) return deny('Remote rsync is blocked.');
  if (prog === 'npm' && args[0] === 'pkg' && ['set', 'delete'].includes(args[1])) {
    return deny('npm pkg set/delete changes package.json scripts, which the harness allows to run without prompts.');
  }

  // GitHub CLI: reading is local; anything that creates, changes or calls the API with a write method is outward-facing.
  if (prog === 'gh') {
    const verb = args.filter((a) => !a.startsWith('-')).slice(0, 2).join(' ').toLowerCase();
    const readOnly = /^(?:status|auth status|search \w+|(?:pr|issue|repo|release|run|workflow|gist|label|cache) (?:list|view|status|diff|checks|watch))$/.test(verb)
      || (/^api\b/.test(verb) && !args.some((a) => /^(?:-X|--method)$/i.test(a) || /^--method=/i.test(a) || /^-X\w/.test(a)) && !args.some((a) => /^(?:-f|-F|--field|--raw-field|--input)$/i.test(a)));
    if (!readOnly) return askFloor(`gh ${verb || ''} acts on GitHub (outward-facing, Tier 2). Confirm the repository and the action.`.replace(/\s+/g, ' '));
  }
  // SQL clients: every query is judged in every approvals mode (sql-read.mjs, the sources.sqlRead switch).
  if (SQL_QUERY_CLIENTS.has(prog)) {
    const verdict = analyzeSqlClient(prog, args, sub, ctx);
    // A variable set in front of the client (PATH=/tmp/evil:$PATH sqlcmd, LD_PRELOAD=x.so psql, env X=y psql) can start another
    // program under the client's name or load a library into it: not the command the SQL read judged, so it is never a pass
    // (S7). The SQL client and password variables keep the verdicts analyzeSqlClient gave them above.
    const inFront = rawTokens.slice(0, tokens.skipped).map((t, i) => (i === 0 ? t.replace(/^[({]+/, '') : t))
      .filter((t) => /^[A-Za-z_][A-Za-z0-9_]*=/.test(t) || programName(t) === 'env');
    if (verdict?.sqlRead && inFront.length) {
      const names = inFront.map((t) => (t.includes('=') ? t.slice(0, t.indexOf('=')) : 'env')).join(', ');
      return askFloor(`${prog}: a variable set in front of the client (${names}) can start another program under its name or load a library into it, so the SQL read switch does not pass it. Run the client without it, or confirm.`);
    }
    return verdict;
  }
  // A variable that points later SQL clients at another server, a startup script or a password, set for this shell or
  // for good (setx, export, $env:, SetEnvironmentVariable).
  const setsVariable = /^(?:setx|export|set|set-item|si|sv|set-variable)$/.test(prog) || /\$env:|SetEnvironmentVariable/i.test(sub);
  if (setsVariable && CREDENTIAL_ENV_RE.test(sub)) return deny('This sets a database password variable (SQLCMDPASSWORD, PGPASSWORD, PGPASSFILE). Credentials stay with the user.');
  if (setsVariable && STARTUP_ENV_RE.test(sub)) {
    return askFloor('This sets a SQL client variable (SQLCMDINI, SQLCMDSERVER, PSQLRC, PGHOST, PGSERVICE, ...) that changes the server or runs a startup script for later queries, which the guard cannot see. Confirm it.');
  }
  // The Desktop screenshot switch (desktop.screenshots, common.mjs): a capture shows the data on the page. "off" denies
  // it, "ask" (default, also unknown values) is a floor ask, "on" is a plain ask that auto and lab approve and log
  // (DESKTOP_ROUTINE keeps a settings ask rule from turning it back into a prompt). Any argument counts, so options
  // written before the subcommand do not hide it.
  const screenshots = screenshotsOf({ desktop: { screenshots: ctx.screenshots } }).mode;
  if (npx.mixed) {
    return askFloor('This npx command names another package next to a Power BI CLI, so the powerbi-desktop or powerbi-report-author it runs may come from that package and the screenshot switch cannot judge it. Run the CLI on its own (npx @microsoft/powerbi-desktop-bridge-cli ...), or confirm.');
  }
  if (prog === 'powerbi-desktop' && args.some((a) => /^screenshot(?:-all)?$/i.test(a))) {
    // An image written inside the repository goes into Git with the page's data: denied in every mode, "on" included.
    // exports/ (ignored by .gitignore) and folders outside the project follow the switch below.
    const outputs = screenshotOutputs(args).map((o) => repositoryOutput(o, shellDir(ctx)));
    const inRepository = outputs.find((rel) => typeof rel === 'string');
    if (inRepository !== undefined) {
      return deny(`This screenshot would be written to ${inRepository}, inside the repository: a screenshot shows page data; write it to the session's temporary folder or exports/ (ignored), never into the repository (docs/harness/desktop.md).`);
    }
    if (screenshots === 'off') {
      return deny('Power BI Desktop screenshots are off (desktop.screenshots in hardening/harness.config.json): the user looks at the page and reports what they see (docs/harness/desktop.md, Path B).');
    }
    if (screenshots !== 'on') {
      return askFloor('A Desktop screenshot shows the data on the page. desktop.screenshots is "ask" in hardening/harness.config.json: confirm this capture, or set it to "on" for a machine with test data (docs/harness/desktop.md).');
    }
    if (outputs.includes(undefined)) {
      return askUser('Desktop screenshot (desktop.screenshots is "on"): its output path uses a variable the guard cannot place, so it cannot tell whether the image lands inside the repository (a relative path after a cd the guard cannot follow is unplaceable too). Write it to the temporary folder or exports/ by its path, or confirm (docs/harness/desktop.md).');
    }
    if (npx.viaNpx && !npx.installedOnly) {
      return askUser(NPX_DOWNLOAD_REASON);
    }
    return ask('Desktop screenshot (desktop.screenshots is "on" in hardening/harness.config.json): the capture shows the data on the page; it stays outside the repository (docs/harness/desktop.md).');
  }
  // Microsoft's report CLI 0.5.0: `unpack` rewrites a report folder from the shell; `preview --reload*` reloads Desktop
  // (unsaved work there is lost); `preview --host service` renders a published model; with desktop.screenshots "off" a
  // preview is denied too, since it renders the pages.
  if (prog === 'powerbi-report-author') {
    const verb = (args[0] ?? '').toLowerCase();
    if (verb === 'unpack') {
      return deny('powerbi-report-author unpack rewrites a .Report folder from the shell (--force swaps the files), outside the Edit/Write checks. Run it yourself; the agent then reviews the diff and runs the static check.');
    }
    if (verb === 'preview' && screenshots === 'off') {
      return deny('powerbi-report-author preview renders report pages, and Desktop screenshots are off (desktop.screenshots in hardening/harness.config.json): the user looks at the page and reports what they see (docs/harness/desktop.md, Path B).');
    }
    if (verb === 'preview') {
      const host = args.map((a, i) => (/^--host=/i.test(a) ? a.slice(7) : /^--host$/i.test(a) ? args[i + 1] : null)).find(Boolean);
      if (String(host ?? '').toLowerCase() === 'service') {
        return askFloor('A preview on the Power BI service renders a published model in a workspace: confirm the workspace and the model (docs/harness/desktop.md).');
      }
      if (args.some((a) => /^--reload(?:-with-model)?$/i.test(a))) {
        return askUser('preview --reload reloads the report (and --reload-with-model the model) in Power BI Desktop, which discards unsaved work there. Check `powerbi-desktop status` first (docs/harness/desktop.md).');
      }
    }
  }
  // Databases, Analysis Services and SSIS: they act on a server and the guard cannot judge what they send (only the
  // SQL clients above are judged by the SQL read switch), so the user decides in every approvals mode, lab included.
  if (DB_CLIENTS.has(prog) || DB_CMDLET_RE.test(prog)) {
    return askFloor(`${prog} connects to a database, an Analysis Services server or an SSIS store, and the guard cannot judge what it sends. AGENTS.md: the agent edits SQL text and runs only the reads you asked for; approve only when you asked for this, and record it in docs/decisions.md.`);
  }
  if ((!TEXT_READERS.has(prog) || ctx.feedsExecutor) && DB_LIBRARY_RE.test(sub)) {
    return askFloor('This loads SQL Server or Analysis Services client libraries (AMO/TOM/ADOMD, SMO, SqlClient, SSIS runtime): a script that can query, process or deploy on a server. Deployment and processing are the user\'s; approve only when the user asked for this.');
  }
  if (prog === 'dtexec' && !args.some((a) => DTEXEC_VALIDATE_RE.test(a))) {
    return askUser('dtexec runs an SSIS package, which loads or changes data. /Validate (/Va) checks a package without running it.');
  }

  // The harness's own checks read the files named after them (validate --files, rdl-compare, githook commit-msg), and the shipped
  // allow rules (`node hardening/scripts/validate.mjs *`, `npm --prefix hardening run validate -- *`) run any arguments without a
  // prompt: a file outside the project, or one the guard cannot place, is the user's call (F1-57). An npm command that starts like
  // the harness's own but carries more after the script name changes which package or program runs (F1-58).
  const harnessArgs = (what, rest) => {
    const base = shellDir(ctx);
    return base !== null && pathsStayInside(rest, base, { wildcards: true })
      ? null
      : askUser(`${what} reads the files named on its command line, and one lies outside the project, is a variable or ~ path, is a secret or data file, or cannot be placed from the shell's folder. Name files inside the project, or confirm.`);
  };
  if (prog === 'node' && script && insideHarness(script, ctx.baseDir)) {
    const verdict = harnessArgs(`node ${script}`, withoutRedirects(args.slice(args.indexOf(script) + 1)));
    if (verdict) return verdict;
  }
  if (prog === 'npm') {
    const run = harnessNpmRun(withoutRedirects(args), shellDir(ctx));
    if (run && !run.exact) {
      return askUser('This npm command starts like the harness\'s own test or validation but carries more after the script name (--prefix, --node-options, --script-shell, --userconfig, -w, ...), which changes the package or the program npm runs. Run npm --prefix hardening test or npm --prefix hardening run validate, with script arguments after "--" only, or confirm.');
    }
    const verdict = run && harnessArgs('npm --prefix hardening', run.tail);
    if (verdict) return verdict;
  }

  if (scriptAsk) return scriptAsk;
  return null;
}

/**
 * True when a pipeline stage changes the files whose names reach it through the pipe (F1-77): a delete, move, copy or
 * in-place edit run by xargs (`| xargs rm`, `| xargs -I{} rm {}`, `| xargs sed -i ...`), a cmdlet that takes its path from the
 * pipeline (`| Remove-Item`, `| ri`, `| Move-Item`, `| Set-Content`), or one inside a `{ }` block (`| % { ri $_ }`). A writer
 * that only puts the piped text into its own file (`| tee list.txt`, `| Out-File x`) acts on that file, which the direct
 * checks judge.
 */
function pipeStageWrites(stage) {
  const raw = tokenize(stage);
  const tokens = normalizeTokens(raw);
  const prog = programName(tokens[0]);
  const viaXargs = raw.slice(0, tokens.skipped).some((t) => programName(t) === 'xargs');
  const writes = (p, text) => SHELL_WRITERS.has(p) || DELETE_PROGRAMS.has(p) ||
    (!TEXT_READERS.has(p) && (WRITE_PROG_RE.test(text) || FILE_API_RE.test(text) || DOC_WRITER_RE.test(text)));
  if ((viaXargs || !PIPE_SINKS.has(prog)) && writes(prog, stage)) return true;
  return scriptBlocks(stage).bodies.some((body) => splitSubcommands(body).some((s) => writes(programName(normalizeTokens(tokenize(s))[0]), s)));
}
/** True when a pipeline stage names a guardrail path (GUARD_PATH_RE) or a folder no delete reaches (DELETE_GUARD_RE) among its file words. */
function stageNamesGuard(stage) {
  const words = pathArgsOf(stage);
  return GUARD_PATH_RE.test(` ${words.join(' ')}`) || words.some((w) => DELETE_GUARD_RE.test(toPosix(w)));
}

/**
 * Policy for one shell command. Returns {decision:'deny'|'ask', reason} or null.
 * ctx: { protectedBranches: string[], getBranch: () => string|null, sqlRead, screenshots: 'off'|'ask'|'on' }
 */
export function analyzeShellCommand(command, ctx = {}, depth = 0) {
  const raw = String(command ?? '');
  if (depth === 0 && raw.length > MAX_SHELL_COMMAND) {
    return deny(`This command is ${raw.length} characters long; the guard analyses at most ${MAX_SHELL_COMMAND}. Split it, or put long content in a file written with the Edit or Write tool.`);
  }
  // One memo of resolved file words per command line (formsMemo): its spellings, readings and nested commands share it.
  if (!ctx.formsMemoStarted) {
    startFormsMemo(raw);
    ctx = { ...ctx, formsMemoStarted: true };
  }
  if (depth === 0 && !ctx.variant) {
    const variants = shellVariants(raw);
    if (variants.length > 1) return strictest(variants.map((v) => analyzeShellCommand(v, { ...ctx, variant: true }, 0)));
  }
  // bash and PowerShell drop their comments (`# ...` to the end of the line, `<# ... #>`): that reading is judged next to the
  // text at every depth, so a word after `#` (`git restore . # --staged`) or a block comment inside a command (`git <# x #>
  // push --force`) hides nothing. The splitter keeps the text of a `#` comment, and a quote there opens nothing.
  if (ctx.commentReading !== raw) {
    const uncommented = withoutComments(raw);
    if (uncommented !== raw) {
      return strictest([raw, uncommented].map((text) => analyzeShellCommand(text, { ...ctx, commentReading: text }, depth)));
    }
  }
  const cmd = expandShortNames(raw.replace(/\\\r?\n/g, ' '), ctx.baseDir);
  if (!cmd.trim()) return null;

  const plainCmd = plainCommandText(cmd); // without the words that are text: a commit message or a search pattern may name them
  if (/--dangerously-skip-permissions|disableAllHooks|bypassPermissions/i.test(plainCmd)) {
    return deny('Disabling permissions or hooks is not allowed from the agent.');
  }
  if (NET_INLINE_RE.test(plainCmd)) return deny('Network transfer commands are blocked (exfiltration risk). Use WebFetch for documentation.');
  if (pipesSecretPath(cmd)) return deny(PIPED_SECRET_REASON);

  let pendingAsk = null;
  if (depth < 3) {
    // Commands inside a string run by another shell (NESTED_COMMAND_RE).
    for (const m of cmd.matchAll(NESTED_COMMAND_RE)) {
      const inner = analyzeShellCommand(m[2] ?? m[4] ?? m[6], ctx, depth + 1);
      if (inner?.decision === 'deny') return inner;
      pendingAsk = strongerAsk(pendingAsk, inner);
    }
    // Commands inside script blocks and function bodies: every { } (scriptBlocks).
    const blocks = scriptBlocks(cmd);
    for (const body of blocks.bodies.slice(0, MAX_BLOCKS)) {
      const inner = analyzeShellCommand(body, ctx, depth + 1);
      if (inner?.decision === 'deny') return inner;
      pendingAsk = strongerAsk(pendingAsk, inner);
    }
    if (blocks.tooDeep || blocks.bodies.length > MAX_BLOCKS) pendingAsk = strongerAsk(pendingAsk, askFloor(BLOCKS_REASON));
    // Command substitution and subexpressions run their contents: $(...), @(...), <(...), >(...) and bash `...`.
    for (const m of cmd.matchAll(/[$@<>]\(([^()]*(?:\([^()]*\)[^()]*)*)\)|`([^`\r\n]+)`/g)) {
      const inner = analyzeShellCommand(m[1] ?? m[2], ctx, depth + 1);
      if (inner?.decision === 'deny') return inner;
      pendingAsk = strongerAsk(pendingAsk, inner);
    }
  } else if (new RegExp(NESTED_COMMAND_RE.source, 'i').test(cmd) || new RegExp(BLOCK_RE.source).test(cmd)) {
    // Beyond three nested shells the analysis stops; what it cannot see goes to the user instead of passing.
    pendingAsk = strongerAsk(pendingAsk, askFloor('This command nests shells more than three levels deep, which the harness does not analyse. Write the inner command directly.'));
  }
  // Judged per subcommand (a read of hardening/ next to an unrelated write is not a guardrail change), with the folder
  // a `cd` moved into: relative write targets inside a guardrail or PBIP folder count as such.
  // The shell's directory from the hook payload: a write with a bare file name inside a guardrail or PBIP folder counts.
  const basePosix = ctx.baseDir ? toPosix(path.resolve(ctx.baseDir)) : '';
  const baseRel = ctx.baseDir ? projectRel(path.resolve(ctx.baseDir)) ?? '' : '';
  const startCwd = basePosix && (GUARD_DIR_RE.test(baseRel) || /\/\.claude(?:\/|$)/i.test(basePosix)) ? 'guard'
    : /\.(?:report|semanticmodel)(?:\/|$)/i.test(baseRel) ? 'pbip' : null;
  const subCtx = { ...ctx, depth, guardedMention: GUARDED_MENTION_RE.test(cmd) || mentionsReference(cmd, ctx.references), cwd: startCwd, feedsExecutor: false };
  let subCount = 0;
  let sawSqlReadPass = false;
  for (const statement of splitStatements(cmd)) {
    // A pipeline that ends in a program reading code from stdin (`... | iex`, `... | bash`): its text is code.
    const stages = splitPipeline(statement);
    const executor = stages.slice(1).find((s) => PIPE_EXECUTORS.has(programName(normalizeTokens(tokenize(s))[0])));
    if (executor && depth < 3) {
      for (const stage of stages.slice(0, stages.indexOf(executor))) {
        for (const q of stage.matchAll(/"([^"]*)"|'([^']*)'/g)) {
          const inner = analyzeShellCommand(q[1] ?? q[2], ctx, depth + 1);
          if (inner?.decision === 'deny') return inner;
          pendingAsk = strongerAsk(pendingAsk, inner);
        }
      }
      // The executor runs what the pipe carries: Invoke-Expression always, a shell or interpreter when it was given no
      // script and no inline command (`| bash`, `| pwsh -`, `| python3 -`, `| node`). That text is code the guard cannot
      // read (decoded, concatenated or fetched at run time): the floor, also in lab mode.
      const exTokens = normalizeTokens(tokenize(executor));
      const exProg = programName(exTokens[0]);
      if (/^(?:iex|invoke-expression)$/.test(exProg) || readsCodeFromStdin(exProg, exTokens.slice(1))) {
        pendingAsk = strongerAsk(pendingAsk, askFloor(`This pipes text into ${exProg}, which runs it as code the guard cannot read. Write the command itself, or run a script file from the project.`));
      }
    }
    // A here-string (`bash <<< 'git push -f origin feat'`) is the program's stdin like a pipe is: its word is judged, and a
    // shell or interpreter given no script and no inline command runs it as code the guard cannot read: the floor.
    for (const stage of stages) {
      const here = hereString(normalizeTokens(tokenize(stage)));
      const hereProg = here ? programName(here.tokens[0]) : '';
      if (!PIPE_EXECUTORS.has(hereProg) || !(/^(?:iex|invoke-expression)$/.test(hereProg) || readsCodeFromStdin(hereProg, here.tokens.slice(1)))) continue;
      if (depth < 3) {
        const inner = analyzeShellCommand(here.word, ctx, depth + 1);
        if (inner?.decision === 'deny') return inner;
        pendingAsk = strongerAsk(pendingAsk, inner);
      }
      pendingAsk = strongerAsk(pendingAsk, askFloor(`This feeds text (a here-string) into ${hereProg}, which runs it as code the guard cannot read. Write the command itself, or run a script file from the project.`));
    }
    for (const sub of splitSubcommands(statement)) {
      subCount++;
      const tokens = normalizeTokens(tokenize(sub));
      if (CD_PROGRAMS.has(programName(tokens[0]))) {
        const target = tokens.slice(1).find((a) => !a.startsWith('-')) ?? '';
        // A drive switch into the Environment provider (Set-Location Env:) makes the next bare Get-ChildItem dump the variables.
        if (tokens.slice(1).some(namesEnvProvider)) return deny('Dumping environment variables can expose credentials.');
        if (GUARD_DIR_RE.test(toPosix(target))) subCtx.cwd = 'guard';
        else if (/\.(?:report|semanticmodel)(?:\/|$)/i.test(toPosix(target))) subCtx.cwd = 'pbip';
        subCtx.cdSeen = true; // later relative paths no longer start from the payload's directory (sql-read.mjs)
        subCtx.cdBase = movedDirectory(shellDir(subCtx), target); // where relative paths start now, null when unplaceable (F1-16)
        continue;
      }
      if (POP_PROGRAMS.has(programName(tokens[0]))) {
        subCtx.cdBase = null; // back to a folder this command line does not name
        continue;
      }
      // PowerShell -EncodedCommand (any prefix of the switch, after any options): decode and judge it; unreadable means unreviewable.
      const encoded = encodedCommandOf(programName(tokens[0]), tokens.slice(1));
      if (encoded !== undefined) {
        if (depth >= 3) pendingAsk = strongerAsk(pendingAsk, askFloor(NESTING_REASON));
        else {
          const decoded = decodeEncodedCommand(encoded);
          if (decoded === null) return deny('This runs an encoded PowerShell command the harness cannot read. Write the command in plain text.');
          const inner = analyzeShellCommand(decoded, ctx, depth + 1);
          if (inner?.decision === 'deny') return inner;
          pendingAsk = strongerAsk(pendingAsk, inner ?? ask('This runs an encoded PowerShell command. Write it in plain text so it can be reviewed.'));
        }
      }
      // A guardrail write: a redirect into a guardrail path, or a writing program (PowerShell aliases included) in a
      // subcommand that names one. Text readers (grep, cat, ls...) never write except through a redirect.
      const prog0 = programName(tokens[0]);
      // Each target in every spelling the shell would open (quotes joined, ANSI-C decoded) and resolved from the shell's
      // folder (`//`, `/./`, an existing link followed): fileWordReaches.
      const redirectToGuard = [...redirectTargets(sub), ...redirectWords(sub)].some((t) => {
        if (!t || /^(?:\/dev\/null|\$null|nul)$/i.test(t)) return false;
        return fileWordReaches(t, shellDir(subCtx)) || (subCtx.cwd === 'guard' && !path.isAbsolute(t) && !/^[A-Za-z]:/.test(t));
      });
      // A link to or from a guardrail folder does not exist yet when the line is judged, so the write through it that
      // follows (`ln -s .claude c && printf x > c/settings.json`) would pass every path check: the link is the change.
      if (linkReachesGuard(linkWordsOf(prog0, tokens.slice(1)), shellDir(subCtx))) {
        return deny('Harness guardrail folders (.claude and its settings, agents, skills, commands, rules and logs, hardening/, .githooks, .github/, .vscode/, .cursor/) cannot be linked from the shell (ln, mklink, New-Item -ItemType SymbolicLink, Junction or HardLink): a write through the link would change the guardrail files under another name. Create such a link yourself if you need it.');
      }
      // A command's own output file is a write like a redirect, for any program (F1-59): `powerbi-report-author validate x --out
      // .claude/settings.json`, or a relative name that lands in a guardrail folder from the shell's folder. git has its own
      // --output rule (checkGit) and its other words are messages and revisions; text readers never write.
      // Read like a redirect target (fileWordReaches): quotes joined, `//` and `./` collapsed, an existing link followed.
      const outputToGuard = prog0 !== 'git' && !TEXT_READERS.has(prog0) && outputOptionValues(tokens.slice(1)).some((t) => {
        if (!t || /^(?:\/dev\/null|\$null|nul)$/i.test(t)) return false;
        return fileWordReaches(t, shellDir(subCtx));
      });
      const programWrites = SHELL_WRITERS.has(prog0) || DELETE_PROGRAMS.has(prog0) ||
        (!TEXT_READERS.has(prog0) && (WRITE_PROG_RE.test(sub) || FILE_API_RE.test(sub) || DOC_WRITER_RE.test(sub) || /\bgit\s+(?:apply|am)\b/i.test(sub)));
      // F1-77: the same change through a pipe, the paths named in an earlier stage (`find hardening | xargs rm`, `gci .claude | ri`).
      const at = stages.indexOf(sub);
      const pipedToGuard = at > 0 && pipeStageWrites(sub) && stages.slice(0, at).some(stageNamesGuard);
      // A writing program's file words are read like redirect targets (fileWordReaches): `cp x .claude//settings.json`.
      const argsToGuard = programWrites && pathArgsOf(sub).some((w) => fileWordReaches(w, shellDir(subCtx)));
      if ((redirectToGuard || outputToGuard || pipedToGuard || (programWrites && (GUARD_PATH_RE.test(` ${sub}`) || subCtx.cwd === 'guard' || argsToGuard))) && !/core\.hookspath[=\s]+hardening\/githooks\s*$/i.test(sub)) {
        return deny('Harness guardrail files (.claude settings, agents, skills, commands and rules, the hook logs and session state in .claude/logs/, hardening/, .githooks, .github/, .vscode/, .cursor/, .gitignore, .gitattributes, .mcp.json, package.json) cannot be changed from the shell, also through a pipe. Use the Edit tool so the user can review the change.');
      }
      // The words that are text (a commit message, a search pattern: textWordsOf) are left out of the secret-name scan and of the
      // deploy words below, as long as the pipeline goes on only into plain readers: a later stage might run the text.
      const textFree = at >= 0 && stages.slice(at + 1).every(plainReaderStage);
      // A stage whose file words open a secret or data file as the shell resolves them (opensSecretFile: `ls b | xargs cat`,
      // b -> .aws) passes it on like a plain name does (pipesSecretPath above), from the folder a `cd` moved to (R3).
      if (at >= 0 && at < stages.length - 1 && pathArgsOf(sub, textFree).some((w) => opensSecretFile(w, shellDir(subCtx)))) return deny(PIPED_SECRET_REASON);
      const verdict = checkSubcommand(sub, { ...subCtx, feedsExecutor: Boolean(executor), textFree });
      if (verdict?.decision === 'deny') return verdict;
      if (verdict?.sqlRead) sawSqlReadPass = true;
      pendingAsk = strongerAsk(pendingAsk, verdict);
      // A project's own deploy script or a TMSL deploy typed on the command line: the floor, also in lab mode.
      if (!TEXT_READERS.has(prog0) && prog0 !== 'git' && DEPLOY_SWITCH_RE.test(sub)) {
        pendingAsk = strongerAsk(pendingAsk, askFloor('This command line deploys or processes a model (a -Deploy switch, createOrReplace, Invoke-ASCmd or a deploy*.ps1 script): deployment is the user\'s (Tier 2), also in lab mode. Confirm the server and database first.'));
      }
      // Deploy and publish commands (DEPLOY_RE) are judged per subcommand too, without the words that are text: searching for
      // or committing `fab deploy` stays free. Printing it, reading a file named so and everything the guard cannot tell from a
      // command (`rg --pre "fab deploy x"`, `echo hi &fab deploy x`, `echo (fab deploy x)`) still count.
      if (DEPLOY_RE.test(textFree ? pathTextOf(sub) : sub)) {
        pendingAsk = strongerAsk(pendingAsk, askFloor('This looks like a deployment/publish to Fabric or the Power BI Service (Tier 2). Confirm the exact workspace and item first.'));
      }
    }
  }
  // The SQL read switch passes a query only as a command of its own: next to another command, in a pipeline or inside
  // a nested shell, the approval would cover what the other part runs (sql-read.mjs). Track whether any subcommand was
  // a SQL-read pass, not just the merged verdict: strongerAsk can keep a co-command's plain ask (e.g. `git rm`) and
  // drop the sqlRead marker, which would otherwise skip this downgrade when the SQL read is not the first subcommand.
  if (sawSqlReadPass && (depth > 0 || subCount > 1)) {
    pendingAsk = askFloor(`${pendingAsk?.sqlRead ? pendingAsk.reason : 'A SQL read'} — but it runs together with other commands (or inside another shell), and the SQL read switch passes a query only as a command of its own. Run the query alone, or confirm the whole line.`);
  }
  return pendingAsk;
}

// ================================================================ routine shell commands (auto approval)

// Programs that only look (list, read, search, format) or move inside the project. Auto approval lets these run without
// a prompt while every path they name stays inside the project (pathsStayInside).
const LOOKING_PROGRAMS = new Set([
  'ls', 'dir', 'cat', 'type', 'head', 'tail', 'wc', 'grep', 'egrep', 'fgrep', 'rg', 'findstr', 'sort', 'uniq', 'cut', 'tr',
  'cd', 'pushd', 'mkdir',
  'get-childitem', 'gci', 'get-content', 'gc', 'select-string', 'sls', 'test-path', 'get-item', 'gi', 'get-itemproperty',
  'measure-object', 'measure', 'select-object', 'select', 'where-object', 'sort-object', 'format-table', 'ft',
  'format-list', 'fl', 'out-string', 'convertfrom-json', 'convertto-json', 'set-location', 'sl', 'push-location',
  'resolve-path', 'split-path', 'join-path', 'get-filehash', 'compare-object', 'group-object', 'get-member',
]);
// Git commands that read or record locally; push, pull, reset, restore, checkout, stash, tag, config and the like are not.
const LOCAL_GIT = new Set(['status', 'diff', 'log', 'show', 'add', 'commit', 'switch', 'rev-parse', 'ls-files', 'check-ignore',
  'blame', 'grep', 'describe', 'shortlog', 'cat-file', 'ls-tree', 'merge-base']);

// Programs whose arguments are text, not files to read.
const PRINTERS = new Set(['echo', 'printf', 'write-output', 'write-host', 'true', 'false', 'sleep', 'start-sleep', 'date',
  'get-date', 'pwd', 'get-location', 'hostname', 'which', 'where', 'get-command', 'get-help', 'get-process']);

/** Git Bash spells C:\x as /c/x. */
const nativePath = (a) => a.replace(/^\/([A-Za-z])(?=\/|$)/, '$1:');
// A Windows drive (C:\x, C:/x, C:) or UNC (\\server\share, //server/share) spelling. On macOS and Linux path.resolve
// reads such a token as a relative name inside the shell's directory, so a read of C:\Windows\win.ini would count as a
// read inside the project; it names another file system and is never a project path there.
const FOREIGN_ABSOLUTE_RE = /^(?:[A-Za-z]:(?:[\\/]|$)|\\\\|\/\/[^/])/;

// Listers show names, not contents: a wildcard in their arguments is fine.
const LISTERS = new Set(['ls', 'dir', 'get-childitem', 'gci', 'test-path', 'resolve-path', 'split-path', 'join-path', 'get-item',
  'gi', 'cd', 'pushd', 'set-location', 'sl', 'push-location', 'mkdir']);
// Programs that read the contents of the files named or piped to them.
const CONTENT_READERS = new Set(['cat', 'type', 'head', 'tail', 'wc', 'grep', 'egrep', 'fgrep', 'rg', 'findstr', 'sort', 'uniq',
  'cut', 'get-content', 'gc', 'select-string', 'sls', 'get-filehash']);
const MOVERS = new Set(['cd', 'pushd', 'set-location', 'sl', 'push-location']);
// A PowerShell provider path names no file of the project: a drive (Env:X, HKLM:\Software, Function:f, Cert:\, SQLSERVER:\SQL),
// a provider-qualified path (Environment::X, FileSystem::C:\x, Microsoft.PowerShell.Core\FileSystem::\\server\share) or a file
// stream (notes.md:stream); path.resolve would read it as a folder name inside the project. A single letter is a Windows drive,
// and a URL (https://...) or a search text with a space after the colon ("TODO: fix") is no provider path.
const PROVIDER_PATH_RE = /^(?:[\w.-]+\\)?[A-Za-z][\w.-]+::?(?![\\/]{2}|\s)/;

/**
 * The words of a looking command that can be paths: options are out, a parameter's value after a colon (-Path:Env:X) is the
 * path, and a comma list is an array of paths in PowerShell, so every item of it counts.
 */
function pathWordsOf(args) {
  const out = [];
  for (const arg of args) {
    const valued = /^-[A-Za-z]+:(?=.)/.exec(arg);
    const value = valued ? arg.slice(valued[0].length) : arg;
    if (valued ? /^\$(?:true|false|null)$/i.test(value) : arg.startsWith('-') || /^\/[A-Za-z?]{1,2}$/.test(arg)) continue; // an option (cmd style /s too)
    out.push(...value.split(',').filter(Boolean));
  }
  return out;
}

/**
 * True while every argument that can be a path is a file inside the project that no rule protects, resolved against
 * the shell's working directory: a looking command must not read ~/.aws, another drive or a secret file. Variables and
 * ~ can point anywhere; a wildcard can match a secret file, except for programs that only list names.
 */
function pathsStayInside(args, base = PROJECT_DIR, { wildcards = false } = {}) {
  for (const a of pathWordsOf(args)) {
    if (/[$%]|^~/.test(a)) return false;
    if (ENV_PROVIDER_RE.test(a) || PROVIDER_PATH_RE.test(a)) return false; // a provider path is no file of the project
    if (!wildcards && /[*?[]/.test(a)) return false;
    if (process.platform !== 'win32' && (FOREIGN_ABSOLUTE_RE.test(a) || FOREIGN_ABSOLUTE_RE.test(nativePath(a)))) return false;
    if (a.length > MAX_RESOLVED_WORD) return false; // never walked, so never routine (third review, item 1)
    const absolute = path.resolve(base, nativePath(a));
    const real = canonicalPathOf(absolute);
    const rel = projectRel(absolute);
    if (rel === null || projectRel(real) === null) return false;
    const cls = classifyPath(rel);
    if (cls.secret || cls.data) return false;
    // As the shell opens it (resolvedFileForms, audit 2026-10-31 A1): path.resolve collapses `..` as text, but bash walks a
    // `..` after a link from where the link points. A walk out of the project, or to a secret or data file, is not routine.
    const forms = resolvedFileForms(a, base);
    if (!forms || forms.some((form) => {
      const formCls = classifyPath(form);
      return path.isAbsolute(form) || formCls.secret || formCls.data;
    })) return false;
    const targets = [toPosix(absolute), toPosix(real), ...forms.map((form) => toPosix(path.join(PROJECT_DIR, form)))];
    if (matchingRule('deny', 'Read', { targets })) return false;
  }
  return true;
}

/** Options that make a reading program read everything, write a file or run another program. */
function unsafeLookingOptions(prog, args, lower) {
  if (/^[ef]?grep$/.test(prog)) return lower.some((a) => /^-[a-z]*r[a-z]*$/i.test(a) || /^--(?:recursive|dereference-recursive|directories=recurse)$/.test(a) || a === '-d');
  if (prog === 'findstr') return lower.includes('/s');
  if (prog === 'rg') return lower.some((a) => /^(?:-u+|--no-ignore\S*|--hidden|-\.|--pre(?:-glob)?(?:=.*)?|-z|--search-zip)$/.test(a));
  if (prog === 'sort') return lower.some((a) => /^(?:-o|--output(?:=.*)?|--compress-program(?:=.*)?)$/.test(a) || /^-[a-z]*o/.test(a));
  if (prog === 'uniq') return args.filter((a) => !a.startsWith('-')).length > 1; // uniq IN OUT writes OUT
  return false;
}

/**
 * True when `dtexec /F <package> /Validate` reaches only this machine. Validation opens every connection manager, so
 * each Data Source/Server host in the package and in the .conmgr and .params files of its folder must be local, and no
 * connection may be set by an expression. A package from a server store (/SQL, /DTS, /ISServer) is not routine.
 */
function ssisPackageLocal(args, base = PROJECT_DIR) {
  const i = args.findIndex((a) => /^[/-]f(?:ile)?$/i.test(a));
  if (i < 0 || !args[i + 1]) return false;
  // /Set, /Conn[ection], /Conf[igFile] and /Par[ameter] replace connections at run time: not judged from the files.
  if (args.some((a) => /^[/-](?:set|conn\w*|conf\w*|par\w*)$/i.test(a))) return false;
  try {
    const pkg = path.resolve(base, nativePath(args[i + 1]));
    if (foreignShare(pkg)) return false; // a package on a share is not read: the guard never connects to a host a command names
    const dir = path.dirname(pkg);
    const texts = [fs.readFileSync(pkg, 'utf8'),
      ...fs.readdirSync(dir).filter((n) => /\.(?:conmgr|params)$/i.test(n)).map((n) => fs.readFileSync(path.join(dir, n), 'utf8'))];
    if (texts.some((t) => /DTS:PropertyExpression\s+DTS:Name="(?:ConnectionString|ServerName|InitialCatalog)"/i.test(t))) return false;
    const hosts = texts.flatMap((t) => [...t.matchAll(/(?:Data Source|Server|Address)\s*=\s*([^;"&<]+)/gi)].map((m) => m[1]));
    return hosts.every((h) => LOCAL_HOSTS.has(h.trim().toLowerCase().replace(/^tcp:/, '').replace(/[:,]\d+$/, '').replace(/\\.*$/, '')));
  } catch {
    return false;
  }
}

// Git options that run programs or write files: -c (core.pager, core.fsmonitor, diff.external...), --exec-path,
// --config-env, --output, external diff and text conversion drivers. Case matters, as it does to git: -C is the folder.
const GIT_UNSAFE_OPT_RE = /^(?:-c|-c=.*|--exec-path(?:=.*)?|--config-env(?:=.*)?)$/;
const GIT_OUTPUT_OPT_RE = /^(?:--output(?:=.*)?|--ext-diff|--textconv)$/i;
// The subcommands of the Power BI CLIs that only read or show; others may write or save over the user's files.
// Desktop CLI `manifest` stays out on purpose (it prints the bridge's connection details; tests/approvals.test.mjs).
// `screenshot` and `screenshot-all` are routine only as far as the shell goes: checkSubcommand judges them first by
// desktop.screenshots ("off" denies, "ask" asks in every mode), so only "on" lets auto and lab run them.
// Report CLI 0.5.0 adds read-only helpers (expr, theme, doctor, the preview-* listings) and `pack` (prints a Fabric
// definition payload; piping it into `az rest` is a publish, the floor).
const DESKTOP_ROUTINE = new Set(['status', 'open', 'screenshot', 'screenshot-all', '--version', '-v']);
const REPORT_AUTHOR_ROUTINE = new Set(['validate', 'catalog', 'formatting', 'expr', 'theme', 'doctor', 'pack',
  'preview-pages', 'preview-visuals', 'preview-filters', 'preview-themes', '--version', '-v']);

/** A program's arguments without its redirections (`> file`, `>> log`, `2>&1`, `&>x`): they are no argument of the program. */
function withoutRedirects(args) {
  const out = [];
  for (let i = 0; i < args.length; i++) {
    const m = /^(?:\d*>>?|&>>?|\d*>\|)(&\d+|[\s\S]*)$/.exec(args[i]);
    if (!m) out.push(args[i]);
    else if (m[1] === '') i++; // `>` alone: the next word is its target
  }
  return out;
}

/** True when `value` (npm's --prefix) names the harness folder, <project>/hardening, as seen from `base`. */
function isHarnessFolder(value, base) {
  if (base === null || !value || /[$%`*?[]|^~/.test(value)) return false;
  try {
    return path.relative(canonicalPathOf(path.join(PROJECT_DIR, 'hardening')), canonicalPathOf(path.resolve(base, nativePath(value)))) === '';
  } catch {
    return false;
  }
}

/**
 * `npm --prefix hardening test` and `npm --prefix hardening run validate[:name]`: the harness's own tests and validation, each
 * optionally followed by `-- <args>` (the script's own arguments: npm reads nothing after `--`). `--prefix` must name the
 * harness folder as seen from `base`. Returns null for any other npm command. `exact` is false when more than that stands
 * after the script name: `--prefix other`, `--node-options=--require x`, `--script-shell`, `--userconfig`, `-w`,
 * `--ignore-scripts=false` change which package or program runs (F1-58). `tail` holds the words after `--`.
 */
function harnessNpmRun(args, base) {
  let i = 0;
  let prefix;
  if (/^--prefix$/i.test(args[0] ?? '')) {
    prefix = args[1];
    i = 2;
  } else if (/^--prefix=/i.test(args[0] ?? '')) {
    prefix = args[0].slice(9);
    i = 1;
  }
  if (prefix === undefined || !isHarnessFolder(prefix, base)) return null;
  const verb = (args[i] ?? '').toLowerCase();
  if (verb === 'test') i += 1;
  else if (verb === 'run' && /^validate(?::[\w-]+)?$/i.test(args[i + 1] ?? '')) i += 2;
  else return null;
  if (i === args.length) return { exact: true, tail: [] };
  return args[i] === '--' ? { exact: true, tail: args.slice(i + 1) } : { exact: false, tail: [] };
}

/** Whether one subcommand is routine. `state.base` is the shell's directory; a routine `cd` moves it. */
function routineSubcommand(sub, state) {
  const raw = tokenize(sub);
  const tokens = normalizeTokens(raw);
  if (!tokens.length) return true;
  // Variables set for the command change what it runs (GIT_EXTERNAL_DIFF, GIT_CONFIG_COUNT/KEY/VALUE = the -c form).
  if (raw.slice(0, tokens.skipped).some((t) => /^[A-Za-z_][A-Za-z0-9_]*=/.test(t) || programName(t) === 'env')) return false;
  // `npx --no @microsoft/powerbi-desktop-bridge-cli status` is as routine as `powerbi-desktop status`; without --no
  // npx may download the package first, which is not routine (unwrapNpx).
  const unwrapped = unwrapNpx(programName(tokens[0]), tokens.slice(1));
  if (unwrapped.viaNpx && !unwrapped.installedOnly) return false;
  const { prog, args } = unwrapped;
  const lower = args.map((a) => a.toLowerCase());
  const base = state.base;
  if (PRINTERS.has(prog)) return true;
  if (MOVERS.has(prog)) {
    // Exactly one target inside the project: no bare `cd` (home), `cd -` (back), drive roots (`/c`, `C:`), wildcards.
    const positional = args.filter((a) => !a.startsWith('-') || a === '-'); // Set-Location -Path docs: ['docs']
    if (positional.length !== 1) return false;
    const target = positional[0];
    if (target === '-' || /^\/[A-Za-z]\/?$/.test(target) || /^[A-Za-z]:$/.test(target) || /[*?[]/.test(target)) return false;
    if (!pathsStayInside([target], base)) return false;
    state.base = path.resolve(base, nativePath(target));
    return true;
  }
  if (LOOKING_PROGRAMS.has(prog)) {
    if (unsafeLookingOptions(prog, args, lower)) return false;
    // A search pattern may look like a provider path ("env:", "TODO:"): it names no file. A variable in it ($env:X) still counts.
    const text = textWordIndexes(prog, args);
    const paths = args.filter((a, j) => !(text.has(j) && !/[$%]|^~/.test(a) && (ENV_PROVIDER_RE.test(a) || PROVIDER_PATH_RE.test(a))));
    return pathsStayInside(paths, base, { wildcards: LISTERS.has(prog) });
  }
  if (prog === 'find') return !lower.some((a) => /^-(?:exec|execdir|ok|okdir|delete|fprint\w*|fls)$/.test(a)) && pathsStayInside(args, base, { wildcards: true });
  if (prog === 'git') {
    const i = gitSubcommandIndex(args);
    // Global options before the subcommand: -c key=value (an alias can run anything), --exec-path, --config-env, and
    // --git-dir, --work-tree, --namespace (another repository's configuration, files outside the project).
    // A subcommand's own -c (git switch -c <branch>, git log -c) is not that.
    if (args.slice(0, i).some((a, j) => GIT_UNSAFE_OPT_RE.test(a) || GIT_REPOINT_OPT_RE.test(a) || (a === '-C' && !pathsStayInside([args[j + 1] ?? ''], base)))) return false;
    // Each -C starts from the one before it: the folder git runs in must lie inside the project too (`-C .. -C ../x` from docs/).
    const gitDir = gitBase(args.slice(0, i), base);
    if (gitDir === null || projectRel(gitDir) === null || projectRel(canonicalPathOf(gitDir)) === null) return false;
    const gitSub = lower[i] ?? '';
    const gitArgs = [...args.slice(0, i + 1), ...spellOutGitOptions(gitSub, args.slice(i + 1))];
    // Output and diff-driver options can write a file or run a program from any subcommand; --no-index compares any two
    // files on the machine.
    if (gitArgs.some((a) => GIT_OUTPUT_OPT_RE.test(a) || /^--no-index$/i.test(a))) return false;
    // -O / --open-files-in-pager runs a program (F2-1); a file option that reads outside the project, from the shell's folder
    // or from git's (-C), is the user's call (F1-57).
    if (opensPager(gitSub, gitArgs.slice(i + 1)) || gitReadsOutside(gitSub, gitArgs.slice(i + 1), base) || gitReadsOutside(gitSub, gitArgs.slice(i + 1), gitDir)) return false;
    if (gitSub === 'branch') return !gitArgs.slice(i + 1).some((a) => /^-(?:d|D|m|M|c|C|-delete|-move|-copy|-force|f)$/.test(a.toLowerCase()));
    // A forced switch (-f, --discard-changes, -C) drops uncommitted work and --orphan empties the working tree, the hooks
    // included; -c (create) is routine, so the case matters. A switch to a commit whose guard files differ from HEAD's (or
    // that git cannot compare) replaces or removes them (F2-2).
    if (gitSub === 'switch') {
      if (gitArgs.slice(i + 1).some((a) => /^--(?:force|discard-changes|force-create|orphan)(?:=|$)/.test(a) || (/^-[a-zA-Z]+$/.test(a) && /[fC]/.test(a)))) return false;
      return guardMoveVerdict('switch', gitArgs.slice(i + 1), gitBase(args.slice(0, i), base)) === null;
    }
    // git diff with the null device or a path outside the project is an implicit --no-index (F2-6); a variable may be one.
    if (gitSub === 'diff') return diffPathPlaces(gitArgs.slice(i + 1), gitBase(args.slice(0, i), base)).every((p) => p === 'inside');
    return LOCAL_GIT.has(gitSub);
  }
  if (prog === 'node') {
    if (lower.some((a) => /^(?:--version|-v)$/.test(a))) return true;
    if (lower.some((a) => /^(?:--check|-c)$/.test(a))) return pathsStayInside(args, base);
    const argv = withoutRedirects(args); // `2>&1` and `> /dev/null` are the shell's, not the script's
    const check = argv[0] === undefined ? null : harnessCheckOf(argv[0], base);
    if (check === null) return false;
    // The pack's hook check reads no argument: with one it is not the check the pack ships. The others read the files named
    // after them, which must lie inside the project like the files a looking command reads (F1-57).
    return /^scripts\/check-hooks\.mjs$/i.test(check) ? argv.length === 1 : pathsStayInside(argv.slice(1), base);
  }
  if (/^py(?:thon3?)?$/.test(prog)) return lower.some((a) => /^(?:--version|-v)$/.test(a));
  if (prog === 'npm') {
    if (lower.length === 1 && lower[0] === '--version') return true;
    // Only the two forms of harnessNpmRun, nothing else after the script name (F1-58).
    const run = harnessNpmRun(withoutRedirects(args), base);
    return run !== null && run.exact && pathsStayInside(run.tail, base);
  }
  // reload discards unsaved work in Desktop, which the guard cannot see: it keeps Claude Code's prompt.
  if (prog === 'powerbi-desktop') return DESKTOP_ROUTINE.has(lower[0] ?? '');
  // --out (--output, -OutFile and the like) writes the result envelope to a file: not routine.
  if (prog === 'powerbi-report-author') return REPORT_AUTHOR_ROUTINE.has(lower[0] ?? '') && !args.some((a) => OUTPUT_OPTION_RE.test(a));
  if (prog === 'dtexec') return args.some((a) => DTEXEC_VALIDATE_RE.test(a)) && ssisPackageLocal(args, base);
  return false;
}

/**
 * True when every part of a shell command is a recognised routine one: looking at files inside the project, local
 * git, the harness's own checks, the Power BI Desktop and report CLIs. Relative paths are judged from the shell's
 * working directory (`cwd`, from the hook payload), which must be inside the project. No redirect into a file, no pipe
 * into a program that runs code, no listing piped into a program that reads the listed files. Anything else is not
 * routine, and auto approval leaves it to Claude Code's permission rules.
 */
export function routineShell(command, cwd = PROJECT_DIR) {
  const cmd = String(command ?? '').trim();
  if (!cmd || cmd.length > MAX_SHELL_COMMAND) return false;
  startFormsMemo(cmd, { reuse: true }); // the words analyzeShellCommand resolved for this command line
  const start = path.resolve(cwd || PROJECT_DIR);
  if (projectRel(start) === null || projectRel(canonicalPathOf(start)) === null) return false;
  // Every spelling a shell would run (shellVariants: backticks, carets, a backslash before ; & |), each also read without its
  // comments (withoutComments), must be routine.
  return [...new Set(shellVariants(cmd).flatMap((v) => [v, withoutComments(v)]))].every((spelling) => routineSpelling(spelling, start));
}

/**
 * True when a `(` stands outside single and double quotes (and outside a `#` comment): a PowerShell grouping expression
 * or a bash subshell. Its value is code the guard cannot read; inside quotes a parenthesis is only text.
 */
function hasUnquotedParen(text) {
  let quote = null;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quote) {
      if (c === quote) quote = null;
    } else if (c === "'" || c === '"') {
      quote = c;
    } else if (c === '#' && (i === 0 || /\s/.test(text[i - 1]))) {
      while (i + 1 < text.length && text[i + 1] !== '\n' && text[i + 1] !== '\r') i++; // a comment runs to the end of the line
    } else if (c === '(') {
      return true;
    }
  }
  return false;
}

function routineSpelling(cmd, start) {
  // Code inside the command: $(...), backticks, process substitution, script blocks, subexpressions.
  if (/\$\(|`|<\(|>\(|[{}]|@\(/.test(cmd)) return false;
  // A parenthesized expression is code too: `gc ('.e'+'nv')` and `gc (Join-Path . '.env')` build a path the guard cannot read.
  if (hasUnquotedParen(cmd)) return false;
  // A redirect into anything but the null device is a write, whatever the stream number (`1>`, `2>`, `&>`).
  if (redirectTargets(cmd).some((t) => !/^(?:\/dev\/null|\$null|nul)$/i.test(t))) return false;
  const state = { base: start };
  for (const statement of splitStatements(cmd)) {
    const stages = splitPipeline(statement);
    const progs = stages.map((s) => programName(normalizeTokens(tokenize(s))[0]));
    if (progs.slice(1).some((p) => PIPE_EXECUTORS.has(p) && p !== 'node')) return false;
    // `ls | xargs cat`, `Get-ChildItem -Recurse | Select-String`: the reader reads every listed file.
    if (progs.some((p, i) => i > 0 && CONTENT_READERS.has(p) && progs.slice(0, i).some((q) => LISTERS.has(q) || q === 'find'))) return false;
    if (!stages.every((s) => routineSubcommand(s, state))) return false;
  }
  return true;
}

// ================================================================ MCP policy

// Exact operations, never prefix matches: GetAndDelete/ExecuteXMLA are not reads.
const READ_OPERATIONS = new Set(['get', 'list', 'find', 'search', 'getstats', 'getstatistics',
  'getstatus', 'gethelp', 'getdefinition', 'getschema', 'getconnection', 'getcurrentconnection',
  'getlastused', 'listconnections', 'listlocalinstances', 'listdesktopinstances', 'getvalidculturenames', 'validate',
  // Return text or metadata only (role permissions, a TMDL/TMSL script as text); nothing runs on the model.
  'help', 'getpermissions', 'listpermissions', 'geteffectivepermissions', 'exporttmdl', 'exporttmsl']);
const MODEL_TOOLS = new Set(['connection_operations', 'database_operations', 'model_operations',
  'table_operations', 'column_operations', 'measure_operations', 'relationship_operations',
  'dax_query_operations', 'partition_operations', 'user_hierarchy_operations',
  'calculation_group_operations', 'security_role_operations', 'perspective_operations',
  'named_expression_operations', 'function_operations', 'culture_operations',
  'object_translation_operations', 'calendar_operations', 'query_group_operations',
  'transaction_operations', 'trace_operations']);
const DENY_VERBS = ['deploy', 'publish'];
const ASK_VERBS = ['delete', 'drop', 'remove', 'clear', 'refresh', 'process', 'overwrite', 'import', 'export'];
// Tier 2 on a local model (AGENTS.md, Editing boundaries): every write of these tools is the user's call.
const TIER2_MCP_TOOLS = new Map([
  ['relationship_operations', 'A relationship change'],
  ['partition_operations', 'A partition change (data source, Power Query, storage mode or refresh)'],
  ['named_expression_operations', 'A Power Query expression or parameter change'],
  ['query_group_operations', 'A Power Query query group change'],
  ['database_operations', 'A database-level write (create, update, import or export of the whole model)'],
]);
// Ordinary model work on a local connection: a plain ask that auto approval passes and logs. Measures, calculated
// columns, tables (descriptions and format strings are their updates), DAX functions, calculation groups, calendars,
// hierarchies, perspectives, cultures, translations, model properties and transaction control. Any other operation of
// a write tool (move, activate, trace, an operation this list does not know) is Tier 2: the user decides.
const ORDINARY_MCP_WRITES = new Map([
  ['measure_operations', /^(?:create|update)/],
  ['column_operations', /^(?:create|update)/],
  ['table_operations', /^(?:create|update)/],
  ['function_operations', /^(?:create|update)/],
  ['calculation_group_operations', /^(?:create|update)/],
  ['calendar_operations', /^(?:create|update)/],
  ['user_hierarchy_operations', /^(?:create|update|add|reorder)/],
  ['perspective_operations', /^(?:create|update|add)/],
  ['culture_operations', /^(?:create|update)/],
  ['object_translation_operations', /^(?:create|update|set)/],
  ['model_operations', /^update/],
  ['transaction_operations', /^(?:begin|commit|rollback)$/],
]);
// Values of a `mode` key (collected as operations, since some servers name the operation `mode`) that are storage modes.
const STORAGE_MODES = new Set(['import', 'directquery', 'dual', 'directlake', 'push', 'default']);

// Where a table's data comes from, in a write of any tool: an M expression, a legacy data source, a connection string, a
// query group, a provider, a named expression. A partition may carry only these plain keys: a source, an expression or
// a query of its own is that data.
const DATA_SOURCE_KEY_RE = /^(?:mexpression|datasources?|connectionstrings?|querygroups?|providers?|expressionsource|expressions|namedexpressions)$/;
const PLAIN_PARTITION_KEYS = new Set(['name', 'description', 'mode']);

/** True when a write names a data source or Power Query: one of those keys anywhere, or a partition with more than its plain keys. */
function namesDataSource(value, inPartition = false, depth = 0) {
  if (value === null || typeof value !== 'object') return false;
  if (depth > 12) return true; // too deep to read: the user decides
  if (Array.isArray(value)) return value.some((v) => namesDataSource(v, inPartition, depth + 1));
  return Object.entries(value).some(([key, v]) => {
    const name = key.toLowerCase().replace(/[^a-z]/g, '');
    return DATA_SOURCE_KEY_RE.test(name) || (inPartition && !PLAIN_PARTITION_KEYS.has(name))
      || namesDataSource(v, inPartition || name.includes('partition'), depth + 1);
  });
}

/** The Tier 2 category of an MCP write on a local model, or null for ordinary model work. `input` is the tool input. */
function tier2McpWrite(tool, ops, text, input) {
  const verbs = ops.filter((op) => !STORAGE_MODES.has(op) && !READ_OPERATIONS.has(op));
  if (verbs.some((op) => /^(?:delete|drop|remove|clear(?!cache))/.test(op))) return 'Deleting model objects';
  if (verbs.some((op) => /rename|^move/.test(op)) || /"new_?name"\s*:/.test(text)) {
    return 'Renaming or moving model objects (DAX, visuals and downstream reports that name them break)';
  }
  if (verbs.some((op) => /^(?:refresh|process)/.test(op))) return 'A refresh';
  if (/"(?:refreshpolicy|incrementalrefresh\w*)"\s*:/.test(text)) return 'A refresh policy change';
  if (TIER2_MCP_TOOLS.has(tool)) return TIER2_MCP_TOOLS.get(tool);
  if (namesDataSource(input)) return 'A data source or Power Query change';
  const ordinary = ORDINARY_MCP_WRITES.get(tool);
  if (!ordinary || !verbs.length || !verbs.every((op) => ordinary.test(op))) return 'An operation the guard does not classify as ordinary model work';
  const modeChange = ops.some((op) => STORAGE_MODES.has(op)) || /"(?:storagemode|defaultmode)"\s*:/.test(text);
  if (modeChange && !verbs.every((op) => op.startsWith('create'))) return 'A storage mode change';
  return null;
}
const OP_KEY_RE = /^(?:operation|operations|operationtype|action|op|command|mode)$/i;
const GITHUB_WRITE_RE = /(?:^|_)(?:create|update|merge|push|delete|fork|add|remove|close|reopen|lock|dismiss|request|assign|submit|write|edit|approve|comment)(?:_|$)/;

function collectOperations(value, out = [], depth = 0) {
  if (depth > 6 || value === null || typeof value !== 'object') return out;
  for (const [key, v] of Object.entries(value)) {
    if (OP_KEY_RE.test(key)) {
      if (typeof v === 'string') out.push(v.trim().toLowerCase());
      else if (Array.isArray(v)) v.filter((x) => typeof x === 'string').forEach((x) => out.push(x.trim().toLowerCase()));
      else if (v !== null && typeof v !== 'object') out.push(String(v)); // a number: an unknown operation
    }
    if (v && typeof v === 'object') collectOperations(v, out, depth + 1);
  }
  return out;
}

/**
 * The query the server runs: the `query` (or `Query`) field of the request and nothing else. Null, so the call asks, when
 * that field is missing, given twice or not text with an EVALUATE, and when any other text of the input also holds
 * EVALUATE (a description, a note): the guard could judge one query while the server runs another.
 */
function findDaxQuery(input) {
  const req = queryRequest(input);
  const keys = Object.keys(req).filter((key) => key.toLowerCase() === 'query');
  const query = keys.length === 1 ? req[keys[0]] : null;
  if (typeof query !== 'string' || !/\bEVALUATE\b/i.test(query) || holdsEvaluate(input, req, keys[0])) return null;
  return query;
}
/** True when a text of `value` other than the field `skipKey` of `skipOwner` holds EVALUATE; nesting too deep to read counts. */
function holdsEvaluate(value, skipOwner, skipKey, depth = 0) {
  if (typeof value === 'string') return /\bEVALUATE\b/i.test(value);
  if (value === null || typeof value !== 'object') return false;
  if (depth > 12) return true;
  return Object.entries(value).some(([key, v]) => !(value === skipOwner && key === skipKey) && holdsEvaluate(v, skipOwner, skipKey, depth + 1));
}

// Functions that pack many rows into one value (one cell can hold every e-mail of a table).
const ROW_PACKING_RE = /\b(?:CONCATENATEX|TOJSON|TOCSV)\s*\(/i;
// Columns whose values identify people; grouping by them returns personal data even in an "aggregate" query.
// Bracketed names ([Email], 'Customer'[Phone], a measure [Salary]); each name is judged on its own.
const BRACKET_NAME_RE = /\[((?:[^\]]|\]\])*)\]/g;
// The words of a personal column name (English, Turkish, German, French, Spanish and Italian: PERSONAL_NAME_RE,
// PERSONAL_WORD_RE, foldLatin, personalColumnName) are the SQL read switch's own (sql-read.mjs): one vocabulary for both guards.
/**
 * True when a bracketed name is a personal column: the shared words, or the SQL read switch's list (its built-in names
 * and the project's `sources.sqlRead.personalColumns`), compared as identifier keys like the SQL judge does. The SQL
 * judge's whole-name rules (suffixes, plurals, a person's name) count too.
 */
function personalName(raw, listed) {
  const name = raw.replace(/\]\]/g, ']');
  const folded = foldLatin(name);
  return PERSONAL_NAME_RE.test(folded) || PERSONAL_WORD_RE.test(folded) || listed.has(identKey(name)) || listed.has(identKey(folded))
    || personalColumnName(name, listed);
}
/** The words of a column name, lower case and folded to ASCII, split at separators and where a lower case letter meets an upper case one (FirstName: first, name). */
function columnWords(name) {
  return foldLatin(name.replace(/\]\]/g, ']').normalize('NFKC')).replace(/([a-z0-9])([A-Z])/g, '$1 $2').toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
}
/** True when a listed personal name (an identifier key) is a run of up to six whole words of `name`: Customer First Name holds first name. */
function holdsListedName(name, listed) {
  const words = columnWords(name);
  for (let i = 0; i < words.length; i++) {
    for (let j = i, key = ''; j < words.length && j < i + 6; j++) {
      key += words[j];
      if (listed.has(key)) return true;
    }
  }
  return false;
}
// A name column called like its table holds people's names: Customer[Customer], 'Salesperson'[Salesperson].
const SELF_NAMED_PERSON_RE = /(?:'|\b)(customer|salesperson|employee|contact|person|client|member|patient|student)'?\s*\[\s*\1\s*\]/gi;
// A key or ID of a person: Customer[Customer Key], Sales[Salesperson Key]. Grouping by it returns one row per person,
// not groups. Keys of products, orders or dates (Product[Product Key], Sales[Sales Order ID]) group ordinary BI
// facts and pass; a person's name column (Customer[Customer]) is caught by SELF_NAMED_PERSON_RE wherever it appears.
const PERSON_WORD_RE = /customer|salesperson|employee|contact|person|client|member|patient|student|user|rep\b/;
function identityColumn(ref) {
  const m = /^\s*(?:'((?:[^']|'')*)'|([A-Za-z_][\w]*))?\s*\[((?:[^\]]|\]\])*)\]\s*$/.exec(ref);
  if (!m) return false;
  const table = (m[1] ?? m[2] ?? '').replace(/''/g, "'").trim().toLowerCase();
  const col = m[3].replace(/\]\]/g, ']').trim().toLowerCase();
  if (!/(?:^|[\s_-])(?:key|id|guid|number|no)$/.test(col)) return false;
  return PERSON_WORD_RE.test(col) || PERSON_WORD_RE.test(table);
}
// A column named with its table, read in masked text: 'Customer'[Name] (group 1: the quoted table, masked), Customer[Name]
// (group 2), then the bracketed name (group 3, masked). Strings, quoted names and brackets are masked, so none pairs up with another.
const QUALIFIED_COLUMN_RE = /(?:'(_*)'|(?<![\w.])([A-Za-z_]\w*))\s*\[(_*)\]/g;
// The person words of a table name, one by one (Dim Customer: customer).
const PERSON_WORDS_RE = new RegExp(PERSON_WORD_RE.source, 'g');
// The names of a person, spelled with letters and digits only (nick name and nickname are one entry).
const PERSON_NAME_PHRASES = ['fullname', 'firstname', 'lastname', 'middlename', 'givenname', 'familyname', 'displayname',
  'nickname', 'maidenname', 'legalname', 'preferredname', 'contactname', 'personname'];
/**
 * A person table's name column, identityColumn's counterpart for names. A column of a table named like a person (a
 * customer, an employee, a salesperson ...) holds that person's name when it is Name, Full Name, First Name, Last Name,
 * Middle Name, Given Name, Family Name, Display Name, Nick Name, Maiden Name, Legal Name, Preferred Name, Contact Name,
 * Person Name, the table's word and Name (Customer Name), or a longer name that ends in one of those (Customer First Name).
 * Any other column that ends in "name" names a place, a segment or an organisation (Customer[Country Name],
 * Employee[Department Name]) and passes; so does Product[Name], a table that is no person's. Names on the SQL read
 * switch's list ask on any table (personalName).
 */
function personNameColumn(table, column) {
  const words = [...foldLatin(table.replace(/''/g, "'")).toLowerCase().matchAll(PERSON_WORDS_RE)].map((m) => m[0]);
  if (!words.length) return false;
  const phrases = [...PERSON_NAME_PHRASES, ...words.map((word) => `${word}name`)];
  const spelled = columnWords(column).join('');
  // A plural or a numbered column (Names, Name2) is the same name.
  return [spelled, spelled.replace(/[0-9]+$/, '').replace(/s$/, '')].some((form) => form === 'name' || phrases.some((phrase) => form.endsWith(phrase)));
}
// A manager's or a supervisor's name is a person's name in any table (Employee[Manager Name], Store[Manager Name],
// Customer[Account Manager Name]); a company, an account or a department name is not (Customer[Company Name]).
const ROLE_NAME_RE = /(?:manager|supervisor)(?:full|first|last|given|family|display|preferred|legal)?names?[0-9]*$/;
const roleNameColumn = (column) => ROLE_NAME_RE.test(columnWords(column).join(''));
const COLUMN_REF_MASKED_RE = /^\s*(?:'_*'|[A-Za-z_][\w]*)?\s*\[_*\]\s*$/;
// Aggregates that read a personal column without returning its values.
const COUNTING_PREFIX_RE = /(?:DISTINCTCOUNT(?:NOBLANK)?|COUNTA?|COUNTBLANK|ISBLANK|LEN)\s*\(\s*(?:'(?:[^']|'')*'|[\w ]+)?\s*$/i;

// ---------------------------------------------------------------- DAX result shape (what an EVALUATE returns)
// Masks string literals, quoted names and bracketed names with "_" of the same length, so commas and parentheses
// inside them do not count and positions stay aligned.
const maskDax = (q) => q.replace(/"(?:[^"]|"")*"|'(?:[^']|'')*'|\[(?:[^\]]|\]\])*\]/g, (s) => s[0] + '_'.repeat(Math.max(0, s.length - 2)) + s[s.length - 1]);
// Where a comment can start: the leftmost lexeme wins, and a string ("" inside), a quoted name ('' inside) or a bracketed
// name (]] inside) is taken whole, so a marker inside one ("/*", "--", [Sales//Plan]) opens nothing. The last two
// alternatives are an opener without its closer. A line comment ends at any line break, vertical tab, form feed or NEL:
// the guard may end a comment early, never late.
const DAX_LEXEME_RE = /"(?:[^"]|"")*"|'(?:[^']|'')*'|\[(?:[^\]]|\]\])*\]|\/\*[\s\S]*?\*\/|(?:\/\/|--)(?:(?![\v\f\u0085]).)*|["'[]|\/\*/g;
/** The query with every comment replaced by a space, or null when a string, a name or a block comment never closes. */
function stripDaxComments(text) {
  let out = '';
  let from = 0;
  for (const m of text.matchAll(DAX_LEXEME_RE)) {
    if (/^(?:\/\*|["'[])$/.test(m[0])) return null;
    if (m[0][0] === '/' || m[0][0] === '-') {
      out += `${text.slice(from, m.index)} `;
      from = m.index + m[0].length;
    }
  }
  return out + text.slice(from);
}
const GROUPED_RESULT_FUNCS = new Set(['ROW', 'SUMMARIZECOLUMNS', 'SUMMARIZE', 'GROUPBY', 'DATATABLE']);
// The first argument is the rows the function returns (filtered, extended or re-ordered).
const ROW_PASSING_FUNCS = new Set(['CALCULATETABLE', 'FILTER', 'ADDCOLUMNS', 'SELECTCOLUMNS', 'KEEPFILTERS', 'ORDERBY',
  'TREATAS', 'SUBSTITUTEWITHINDEX', 'ADDMISSINGITEMS', 'INDEX', 'WINDOW', 'OFFSET']);
// Every argument that is a table becomes part of the result.
const ROW_COMBINING_FUNCS = new Set(['UNION', 'INTERSECT', 'EXCEPT', 'CROSSJOIN', 'NATURALINNERJOIN', 'NATURALLEFTOUTERJOIN', 'GENERATE', 'GENERATEALL']);
const COLUMN_VALUE_FUNCS = new Set(['VALUES', 'DISTINCT', 'ALL', 'ALLNOBLANKROW', 'ALLSELECTED']);

/** Splits the arguments of the call whose "(" is at masked[open], or null when unbalanced. */
function daxArgs(masked, open) {
  const args = [];
  let depth = 0;
  let start = open + 1;
  for (let i = open; i < masked.length; i++) {
    const ch = masked[i];
    if (ch === '(' || ch === '{') depth++;
    else if (ch === ')' || ch === '}') {
      depth--;
      if (depth === 0) { args.push([start, i]); return { args, end: i + 1 }; }
    } else if (ch === ',' && depth === 1) { args.push([start, i]); start = i + 1; }
  }
  return null;
}

/** Top-level VAR definitions and the RETURN expression of a VAR block, as [start, end] ranges of masked. */
function daxVarBlock(masked, start, end) {
  const vars = new Map();
  let i = start;
  const re = /\s*VAR\s+([A-Za-z_][\w]*)\s*=/iy;
  for (;;) {
    re.lastIndex = i;
    const m = re.exec(masked);
    if (!m || re.lastIndex > end) break;
    // The definition runs to the next top-level VAR or RETURN.
    let depth = 0;
    let j = re.lastIndex;
    for (; j < end; j++) {
      const ch = masked[j];
      if (ch === '(' || ch === '{') depth++;
      else if (ch === ')' || ch === '}') depth--;
      else if (depth === 0 && /\s/.test(ch) && /^\s(?:VAR|RETURN)\b/i.test(masked.slice(j, j + 8))) break;
    }
    vars.set(m[1].toLowerCase(), [re.lastIndex, j]);
    i = j;
  }
  const ret = /\s*RETURN\b/iy;
  ret.lastIndex = i;
  return vars.size && ret.exec(masked) ? { vars, body: [ret.lastIndex, end] } : { vars, body: [start, end] };
}

/** True when the table expression masked[start, end) can return the rows of a model table (not grouped values).
 * `src` is the masked query, or { masked, text } with the unmasked text at the same positions (column names). */
function daxReturnsRows(src, start, end, vars, depth = 0) {
  if (depth > 20) return true;
  const masked = typeof src === 'string' ? src : src.masked;
  const text = typeof src === 'string' ? null : src.text;
  // A grouping column that identifies rows (a key, an ID, a name column) turns a grouped result into rows.
  const groupsByIdentity = (ranges) => ranges.some(([a, b]) => COLUMN_REF_MASKED_RE.test(masked.slice(a, b)) && (text === null || identityColumn(text.slice(a, b))));
  let s = start;
  let e = end;
  while (s < e && /\s/.test(masked[s])) s++;
  while (e > s && /\s/.test(masked[e - 1])) e--;
  if (s >= e) return true;
  if (masked[s] === '(') {
    const call = daxArgs(masked, s);
    if (call && call.end === e && call.args.length === 1) return daxReturnsRows(src, call.args[0][0], call.args[0][1], vars, depth + 1);
  }
  if (masked[s] === '{') return false; // a table constructor holds the query's own values
  const block = daxVarBlock(masked, s, e);
  if (block.vars.size) {
    const scope = new Map([...vars, ...block.vars]);
    return daxReturnsRows(src, block.body[0], block.body[1], scope, depth + 1);
  }
  const word = /^([A-Za-z_][\w.]*)\s*/.exec(masked.slice(s, e));
  if (word && masked[s + word[0].length] === '(') {
    const name = word[1].toUpperCase();
    const call = daxArgs(masked, s + word[0].length);
    if (!call || call.end !== e) return true;
    const arg = (k) => call.args[k] ?? [e, e];
    if (GROUPED_RESULT_FUNCS.has(name)) {
      // SUMMARIZE and GROUPBY take the table first; SUMMARIZECOLUMNS groups by its leading column arguments.
      return groupsByIdentity(name === 'SUMMARIZE' || name === 'GROUPBY' ? call.args.slice(1) : call.args);
    }
    // TOPN, SAMPLE and TOPNSKIP return some of their table's rows: as row-level as that table (TOPN(5, Customer) is
    // five customers; TOPN over SUMMARIZECOLUMNS is grouped).
    if (name === 'TOPN' || name === 'SAMPLE') return daxReturnsRows(src, ...arg(1), vars, depth + 1);
    if (name === 'TOPNSKIP') return daxReturnsRows(src, ...arg(2), vars, depth + 1);
    // INFO.* and INFO.VIEW.* return model metadata, not data, when the query body names no table column (a filter on
    // data, Customer[City] = ..., makes them count as rows). INFO.DATASOURCES holds connection strings: it asks.
    if (name.startsWith('INFO.')) return !(src.infoMetadata && name !== 'INFO.DATASOURCES');
    if (ROW_PASSING_FUNCS.has(name)) return daxReturnsRows(src, ...arg(0), vars, depth + 1);
    if (ROW_COMBINING_FUNCS.has(name)) return call.args.some(([a, b]) => daxReturnsRows(src, a, b, vars, depth + 1));
    if (COLUMN_VALUE_FUNCS.has(name)) {
      // VALUES('T'[C]) lists one column's values (as SUMMARIZECOLUMNS would); VALUES('T'), several columns at once
      // (ALL(T[a], T[b]) is that table's rows) and a key or name column return rows.
      if (call.args.length !== 1) return true;
      // DISTINCT(<table expression>) is as row-level as the expression; a bare table name counts as rows below.
      if (!COLUMN_REF_MASKED_RE.test(masked.slice(...arg(0)))) return daxReturnsRows(src, ...arg(0), vars, depth + 1);
      return groupsByIdentity(call.args);
    }
    return true; // a function this check does not know
  }
  const name = masked.slice(s, e);
  if (/^[A-Za-z_][\w]*$/.test(name) && vars.has(name.toLowerCase())) {
    const [a, b] = vars.get(name.toLowerCase());
    return daxReturnsRows(src, a, b, vars, depth + 1); // the depth limit ends any cycle
  }
  return true; // a table name, or something this check does not parse
}

/** Each EVALUATE's table expression, without its ORDER BY / START AT, as [start, end] ranges of masked. */
function daxEvaluateBodies(masked) {
  const hits = [...masked.matchAll(/\bEVALUATE\b/gi)];
  return hits.map((hit, k) => {
    const start = hit.index + hit[0].length;
    const stop = k + 1 < hits.length ? hits[k + 1].index : masked.length;
    let depth = 0;
    for (let i = start; i < stop; i++) {
      const ch = masked[i];
      if (ch === '(' || ch === '{') depth++;
      else if (ch === ')' || ch === '}') depth--;
      else if (depth === 0 && /^\b(?:ORDER\s+BY|START\s+AT)\b/i.test(masked.slice(i, i + 12)) && /\W/.test(masked[i - 1] ?? ' ')) return [start, i];
    }
    return [start, stop];
  });
}

// A column named with its table ('Customer'[City], Sales[Amount]) in masked text; keywords before a bracket do not count.
const TABLE_COLUMN_RE = /(?:'_*'|(?<![\w.])([A-Za-z_]\w*))\s*\[/g;
const DAX_KEYWORDS = new Set(['RETURN', 'NOT', 'AND', 'OR', 'IN', 'VAR', 'ASC', 'DESC', 'BY', 'EVALUATE', 'DEFINE', 'MEASURE', 'TABLE', 'COLUMN']);
const namesTableColumn = (masked) => [...masked.matchAll(TABLE_COLUMN_RE)].some((m) => !m[1] || !DAX_KEYWORDS.has(m[1].toUpperCase()));

/**
 * Conservative shape check, not a DAX parser or proof that a result is free of personal data. `cfg` adds the SQL read
 * switch's personal column list (built-in names and `sources.sqlRead.personalColumns`) to the built-in words.
 */
export function isRowLevelDax(query, cfg) {
  // Comments go first and only outside strings and names; a string, name or comment that never closes cannot be read.
  const original = stripDaxComments(String(query ?? ''));
  if (original === null) return true;
  const listed = sqlReadOf(cfg).personal;
  const masked = maskDax(original);
  // A name ends at a "]": the text after the last one holds none, and a long run of "[" there (in a string, say) would
  // cost time squared for nothing.
  const personal = [...original.slice(0, original.lastIndexOf(']') + 1).matchAll(BRACKET_NAME_RE)].filter((m) => personalName(m[1], listed));
  // Columns named with their table (Customer[Name]) are read again on the masked text, where no string or name can pair
  // with another: judged on their own, as a person table's name column, as a manager's name, and by the SQL read switch's list as a word
  // inside a longer name (Customer[Home Fax]). Only a column gets the last test: a measure called [Mobile Sales] has none.
  const nameColumns = [...masked.matchAll(QUALIFIED_COLUMN_RE)].filter((m) => {
    if (m[2] !== undefined && DAX_KEYWORDS.has(m[2].toUpperCase())) return false; // RETURN [Measure]
    const close = m.index + m[0].length - 1;
    const column = original.slice(close - m[3].length, close);
    const table = m[1] === undefined ? m[2] : original.slice(m.index + 1, m.index + 1 + m[1].length);
    return personNameColumn(table, column) || roleNameColumn(column) || personalName(column, listed) || holdsListedName(column, listed);
  });
  for (const m of [...personal, ...nameColumns, ...original.matchAll(SELF_NAMED_PERSON_RE)]) {
    if (!COUNTING_PREFIX_RE.test(original.slice(Math.max(0, m.index - 60), m.index))) return true;
  }
  const q = original.replace(/"(?:[^"]|"")*"|'(?:[^']|'')*'|\[(?:[^\]]|\]\])*\]/g, ' identifier ');
  if (ROW_PACKING_RE.test(q)) return true;
  // Grouped results (SUMMARIZECOLUMNS, ROW, VALUES of a column, model metadata from INFO.*) pass through the usual
  // wrappers (CALCULATETABLE, FILTER, ADDCOLUMNS, TOPN, VAR ... RETURN, UNION); a table's own rows do not. Every
  // EVALUATE of a query (a test block may hold two) is judged on its own.
  const bodies = daxEvaluateBodies(masked);
  return bodies.length === 0 || bodies.some(([a, b]) =>
    daxReturnsRows({ masked, text: original, infoMetadata: !namesTableColumn(masked.slice(a, b)) }, a, b, new Map()));
}

/** The configured names of the Power BI modeling server: `mcp.powerbiServers` and the older single `mcp.powerbiServer`. */
export function powerbiServersOf(cfg) {
  const list = Array.isArray(cfg?.mcp?.powerbiServers) ? cfg.mcp.powerbiServers : [];
  return [...new Set([...list, cfg?.mcp?.powerbiServer].filter((s) => typeof s === 'string' && s))];
}

/**
 * True for the Power BI modeling server: a configured name, or any server whose tool is one of the modeling server's
 * 21 tools (MODEL_TOOLS, the live list of @microsoft/powerbi-modeling-mcp 1.0.0), since a user may register it under
 * another name (Microsoft's sample uses powerbi-authoring-local). A server the SQL read switch names, or whose name
 * looks like a database (mssql, warehouse), keeps the SQL policy: generic names such as table_operations are not proof.
 */
export function isPowerBiMcp(toolName, cfg) {
  const name = String(toolName ?? '');
  if (powerbiServersOf(cfg).some((server) => name.startsWith(`mcp__${server}__`))) return true;
  const m = /^mcp__(.+?)__(.+)$/.exec(name);
  return Boolean(m) && MODEL_TOOLS.has(m[2]) && !SQL_MCP_NAME_RE.test(m[1]) && !sqlReadOf(cfg).mcpServers.includes(m[1].toLowerCase());
}

function queryRequest(input) {
  // Published servers use either a request wrapper or direct arguments. Other shapes need review.
  const req = input?.request ?? input;
  return req && typeof req === 'object' && !Array.isArray(req) ? req : {};
}

// Tools that run a query, a trace or transaction control, or change the connection: none changes the model definition.
const NON_DEFINITION_TOOLS = new Set(['connection_operations', 'dax_query_operations', 'trace_operations', 'transaction_operations']);

/**
 * A Power BI modeling MCP call in the guard's own vocabulary (MODEL_TOOLS, READ_OPERATIONS, the operation keys), for the
 * session state of hooks/lib/mcp-state.mjs; null for any other tool. `read`: every operation is a metadata read.
 * `needsTarget`: a DAX execute or any other operation that is not a read, outside connection_operations. `modelWrite`:
 * an operation that is not a read and may change the model definition (not a query, a trace or transaction control).
 */
export function powerBiMcpCall(toolName, toolInput, cfg) {
  if (!isPowerBiMcp(toolName, cfg)) return null;
  const tool = /^mcp__.+?__(.+)$/.exec(String(toolName))?.[1] ?? '';
  const ops = collectOperations(toolInput ?? {});
  const req = queryRequest(toolInput);
  const raw = req.connectionName ?? req.ConnectionName;
  const read = ops.length > 0 && ops.every((op) => READ_OPERATIONS.has(op));
  return {
    tool,
    ops,
    request: req,
    connectionName: typeof raw === 'string' ? raw.trim() : '',
    read,
    needsTarget: tool !== 'connection_operations' && ((tool === 'dax_query_operations' && ops.includes('execute')) || !read),
    modelWrite: !read && !NON_DEFINITION_TOOLS.has(tool),
  };
}

const startsWithAny = (op, verbs) => verbs.some((v) => op === v || op.startsWith(v));

// Figma: reads pass; anything else (create a file, draw, upload, Code Connect, generate) writes to a shared design.
const FIGMA_READ_RE = /^(?:get_|list_|search_|whoami$)/;

/** Policy for MCP tool calls. Returns {decision, reason} or null (normal permission flow). */
export function analyzeMcpCall(toolName, toolInput, cfg) {
  const m = /^mcp__(.+?)__(.+)$/.exec(String(toolName ?? ''));
  if (!m) return null;
  const [, server, tool] = m;

  // Any server named for GitHub (GitHub, github-enterprise, github_server, github-mcp-server), like Figma below (F2-9).
  if (/github/i.test(server)) {
    return GITHUB_WRITE_RE.test(tool) ? askFloor(`GitHub write action (${tool}) is outward-facing (Tier 2).`) : null;
  }
  if (/figma/i.test(server)) {
    return FIGMA_READ_RE.test(tool)
      ? null
      : askFloor(`Figma write (${tool}). Only into a new file or a draft page the user named for this mockup, never into existing frames; confirm the target file and page.`);
  }
  // SQL MCP servers: named in sources.sqlRead.mcpServers, or a server or tool name that looks like one (sql-read.mjs).
  // The Power BI servers run DAX and keep their own policy below.
  if (!isPowerBiMcp(toolName, cfg)) return analyzeSqlMcp(server, tool, toolInput, cfg);

  const ops = collectOperations(toolInput ?? {});
  const text = JSON.stringify(toolInput ?? {}).toLowerCase();

  const deployValue = tool === 'database_operations' && /"(?:deploy|publish)[a-z]*"/.test(text);
  if (ops.some((op) => startsWithAny(op, DENY_VERBS)) || deployValue) {
    return deny('Deploying/publishing a semantic model from the agent is blocked (Tier 2). Use the CI/CD pipeline or let the user publish from Power BI Desktop.');
  }
  if (ops.some((op) => !/^[a-z]+$/.test(op))) {
    return askUser(`Unknown MCP operation spelling (${ops.join(', ')}). Use the operation names of the live tool schema.`);
  }
  // An export is a read, except with restricted information: data source connection strings and credentials.
  if (/"includerestricted(?:information)?"\s*:\s*true/.test(text)) {
    return askFloor('This export includes restricted information (data source connection strings, possibly credentials), which the agent never handles. Export without it.');
  }
  // Row-level security: members are the user's on every connection (as for TMDL and the role-member cmdlets); a role
  // change is Tier 2 and never passes auto approval, even on a local model.
  if (tool === 'security_role_operations' && !(ops.length && ops.every((op) => READ_OPERATIONS.has(op)))) {
    if (/member/.test(text)) return deny('Role membership is managed by the user (Power BI service, SSMS), never by the agent.');
    return askUser(`Row-level security role change via MCP (${ops.join(', ') || 'unknown operation'}): Tier 2, confirm it.`);
  }
  if (tool === 'connection_operations' && /powerbi:\/\/|asazure:\/\/|api\.powerbi\.com|fabric\.microsoft\.com|workspace/.test(text)) {
    return askFloor('Connecting to a model in a Fabric/Power BI Service workspace: changes there affect shared (possibly production) models. Confirm the workspace.');
  }
  if (tool === 'connection_operations' && ops.includes('connect') && !localConnection(queryRequest(toolInput))) {
    return askFloor('Connecting to a server other than this machine (an Analysis Services or other remote model): it may be shared or production. Confirm the server and database.');
  }
  if (ops.some((op) => /api$|withapi/.test(op))) {
    return askFloor(`This MCP operation (${ops.join(', ')}) calls the Power BI service. Refreshing or changing a published model is the user's.`);
  }
  if (tool === 'dax_query_operations' && ops.includes('execute')) {
    const query = findDaxQuery(toolInput);
    const req = queryRequest(toolInput);
    const maxRows = req.maxRows ?? req.MaxRows;
    if (!query || isRowLevelDax(query, cfg) || !Number.isInteger(maxRows) || maxRows < 1 || maxRows > 50) {
      return askUser('DAX execution needs one aggregate/bounded EVALUATE and an explicit maxRows of 1..50 (row-level results can expose personal data). TOPN can return extra ties. If the live tool lacks a row-cap parameter, review the query before execution.');
    }
    if (ops.every((op) => op === 'execute')) return { decision: 'allow', reason: 'Bounded Power BI DAX query; review selected fields for personal data.' };
  }
  if (MODEL_TOOLS.has(tool) && ops.length && ops.every((op) => READ_OPERATIONS.has(op))) {
    return { decision: 'allow', reason: `Read-only Power BI MCP operation (${ops.join(', ')}).` };
  }
  // Writes reach whatever model the connection points at. Only a connection named as local (Desktop, this machine's
  // Analysis Services, a TMDL folder) may pass under auto approval; an omitted name means "the last connection".
  const onLocalModel = tool === 'connection_operations' || LOCAL_CONNECTION_NAME_RE.test(String(queryRequest(toolInput).connectionName ?? ''));
  // On a local model, Tier 2 changes (AGENTS.md) are the user's: auto approval never passes them; lab mode does.
  const tier2 = onLocalModel && tool !== 'connection_operations' ? tier2McpWrite(tool, ops, text, toolInput) : null;
  if (tier2) {
    return askUser(`${tier2} via MCP (${ops.join(', ') || 'no operation'}) is Tier 2 (AGENTS.md): auto mode always asks. Show its impact, make sure the model is committed to git, then confirm.`);
  }
  const askFor = onLocalModel ? ask : askFloor;
  const where = onLocalModel ? '' : ' Name a local connection (connectionName) so the guard can tell where it goes; on a shared or published model it is the user\'s.';
  if (ops.some((op) => startsWithAny(op, ASK_VERBS))) {
    return askFor(`Destructive or bulk model operation via MCP (${ops.join(', ')}). Make sure the model is committed to git first.${where}`);
  }
  return askFor(`Power BI MCP write, connection change, or unknown operation. Verify the live tool schema, exact model/connection and persistence path before approval.${where}`);
}

// Connection names the modeling MCP gives local targets: Desktop, Analysis Services on this machine, TMDL or .bim files.
const LOCAL_CONNECTION_NAME_RE = /^(?:PBIDesktop-|Local-(?:localhost|127\.0\.0\.1)\b|TMDL-|BIM-)/i;
const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '::1', '[::1]', '.', '(local)', os.hostname().toLowerCase()]);

/** True when a Connect request targets this machine (Desktop's port, local Analysis Services). */
function localConnection(req) {
  const fromString = /(?:^|;)\s*(?:data source|server|datasource|address)\s*=\s*([^;]+)/i.exec(String(req.connectionString ?? ''))?.[1];
  const target = String(req.dataSource ?? fromString ?? '').trim().toLowerCase();
  if (!target) return false;
  const host = target.replace(/^(?:tcp:)?/, '').replace(/[:,]\d+$/, '').replace(/\\.*$/, '');
  return LOCAL_HOSTS.has(host);
}
