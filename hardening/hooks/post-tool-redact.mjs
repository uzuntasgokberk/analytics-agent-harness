// PostToolUse (Read|Grep|Bash|PowerShell|WebFetch|mcp__*): data-loss prevention.
// Replaces secrets (and, for MCP results of any server, PII: redaction.piiInMcpOutput) in the tool output before Claude sees it.
// Under VS Code, whose hooks reference documents no output replacement, the masked output is sent all the same and the
// model is warned that the values may be visible instead of being told they were redacted (maskNotice).
// PostToolUseFailure (the same tools): no host lets a hook replace a failed call's error text, so an error holding
// sensitive values only gets that warning (failureNotice).
// For a Power BI MCP call it also records the connections it confirmed and the model writes it ran (lib/mcp-state.mjs).
// updatedToolOutput keeps the original shape: values are replaced in place; keys, objects and arrays never change.
// PII also covers values that are not text: any text in a field named like personal data (Email, Phone, IBAN), and any
// number there unless the field counts or totals it. A number is masked only there, or when it has no field name of its
// own (the whole output, or an item of an array whose field is empty or neither personal nor an aggregate) and is a
// whole number of 9 to 15 digits (a national id, phone or account number returned as a JSON number or BigInt); such an
// unnamed whole number of 16 to 19 digits is masked only when it passes a checksum rule (a payment card), never for its
// size. A number under any other field name (Total Sales, Customer Count, Amount, Year) is never masked for its size or
// its checksum, so totals still reconcile. When PII applies, a text value that holds JSON (an MCP answer's content[].text, a nested result string, a
// whole string output) is masked as that data, its keys included in the field rules, and written back as JSON (compact,
// or indented by 2 spaces when it had line breaks) only when a value in it changed; text that does not parse as JSON
// keeps the text rules. Every number the rewrite keeps is written back digit for digit, integer or decimal in any
// exponent form (the reviver's source and JSON.rawJSON), so a 19-digit fixed decimal still reconciles; exact digits need
// Node 21 or later. Older Node reads doubles and masks the text all the same, privacy before precision: a literal a
// double cannot keep (more digits than it holds; "1.0" and "1E+5" keep their value) is written back rounded, and the
// redaction event lists json-text-precision-lost; an integer of 16 digits or more is still judged by its own digits (a
// card's checksum), not by the rounded double. A subtree nested deeper than 12 levels is judged as its JSON text and,
// when something in it is masked, comes back as that masked text. Secrets are masked in the whole text first, since some of their rules
// read a JSON key. A text that is not one JSON value (a slice of a file, a jq stream, an answer cut off at the output
// limit) gets the field rule on each "key": value member it holds (JSON or a Python dict print), then the text rules.
// An MCP answer over Claude Code's output limit is saved to a file and this hook gets only a note pointing to it: the
// saved file's name and the note's path to it stay out of the text rules, and a Read, Grep or shell command whose input
// names a saved MCP answer, of any server, is masked as MCP output (its whole output when it names other files too).

import { appendJsonl, loadConfig, runHook } from './lib/common.mjs';
import { claudeMcpName, copilotHostOf } from './lib/host-vscode.mjs';
import { isPowerBiMcp, redactPii, redactSecrets } from './lib/policy.mjs';
import { DEFAULT_PERSONAL_COLUMNS, foldLatin, identKey, sqlReadOf } from './lib/sql-read.mjs';

// Field names that hold a person's identifier: the vocabulary of PII_RULES (e-mail, IBAN, card, TCKN) plus phone,
// national id, passport, tax and account numbers, address, birth date and sign-in name, in English and in the other
// languages the SQL read switch and the DAX guard know (hooks/lib/sql-read.mjs: Turkish Telefon, Tel No, Cep Telefonu,
// E-Posta, Adres, Dogum Tarihi, Pasaport; German, French, Spanish and Italian words). Matched on the words of the key,
// its letters folded to ASCII (CustomerEmail, Customer[Phone], Musteri[Telefon], national_id); never on metadata words
// such as name, id or description, never on a person's name (Customer Name, Musteri Adi stay readable) and never on a
// salary (not an identifier). Distinctive words match anywhere (emailaddress); short or common ones only as whole words
// (Smartphone, Fairfax, automobile pass, Hotel). The project's personal columns count too (personalKeyOf).
const PII_KEY_RE = new RegExp(
  'e ?mail|tckn|kimlik|iban|passport|user ?principal|' +
    'e ?posta|\\btelefon|\\badres|pasaport|dogum|courriel|correo|geburt|naissance|nacimiento|nascita|indirizzo|' +
    '\\b(?:(?:tele)?phone(?: ?no| ?number)?|mobile|gsm|fax|ssn|social security|national id(?:entity)?|identity (?:no|number)|' +
    'tax (?:id|no|number)|(?:card|account) (?:no|number)|birth ?date|birthday|date of birth|dob|upn|address(?:es)?|tel|tc)s?\\b',
);
// A number in such a field that counts or summarises it (Customers with Email, Phone Count, % Valid IBAN, Telefon Sayisi)
// is no identifier.
const AGGREGATE_KEY_RE = /\b(?:count|cnt|number of|no of|total|sum|avg|average|min|max|distinct|rate|ratio|share|percent|pct|with|without|missing|has|valid|invalid|toplam|adet|sayi|sayisi|ortalama|oran|yuzde)\b/;

/** The words of a key, lower-cased, letters folded to ASCII: "CustomerEmail" and "Musteri[E-Posta]" give "customer email". */
const keyWords = (key) =>
  ` ${foldLatin(String(key).normalize('NFKC'))
    .replace(/(?<=[A-Z])(?=[A-Z][a-z])/g, ' ')
    .replace(/(?<=[A-Za-z0-9][a-z0-9])(?=[A-Z])/g, ' ')
    .replace(/[^A-Za-z0-9]+/g, ' ')
    .toLowerCase()} `;
const aggregateKey = (key) => String(key).includes('%') || AGGREGATE_KEY_RE.test(keyWords(key));
// A value a secret rule has masked already ([REDACTED:password-json-field], under "password") keeps that token.
const MASK_TOKEN_RE = /^\[(?:REDACTED|PII):[a-z0-9-]+\]$/;

// The SQL read switch's personal columns (built in, and sources.sqlRead.personalColumns) as identifier keys, the built-in
// names of people left out (names stay readable; a name the project lists itself counts). The guard compares the name
// in the brackets of a key, not its table: Personel[Sicil No] is the column "Sicil No".
const BUILTIN_NAME_KEYS = new Set(DEFAULT_PERSONAL_COLUMNS.filter((c) => /name$/i.test(c)).map(identKey));
const columnNames = (key) => {
  const named = [...String(key).matchAll(/\[((?:[^\]]|\]\])*)\]/g)].map((m) => m[1].replace(/\]\]/g, ']'));
  return named.length ? named : [String(key)];
};
/** Whether a field name is personal data: the identifier vocabulary above, or a column of the project's personal list. */
function personalKeyOf(cfg) {
  const own = cfg.sources?.sqlRead?.personalColumns;
  const configured = new Set((Array.isArray(own) ? own : []).filter((c) => typeof c === 'string').map(identKey));
  const listed = new Set([...sqlReadOf(cfg).personal].filter((k) => k && (!BUILTIN_NAME_KEYS.has(k) || configured.has(k))));
  const known = new Map(); // a table has few distinct field names and many values
  return (key) => {
    const text = String(key);
    if (!known.has(text)) {
      if (known.size >= 5000) known.clear();
      known.set(text, PII_KEY_RE.test(keyWords(text)) || columnNames(text).some((name) => listed.has(identKey(name))));
    }
    return known.get(text);
  };
}

/** The digits of a whole number, a JSON number or a BigInt of either sign; 0 for a fraction or any other value. */
const integerDigits = (v) => {
  if (typeof v === 'bigint') return (v < 0n ? -v : v).toString().length;
  return typeof v === 'number' && Number.isInteger(v) && Math.abs(v) < 1e21 ? String(Math.abs(v)).length : 0;
};

/**
 * Rewrites every scalar through `decide(value, key, item)`; an array's items take the key of the field that holds them,
 * and `item` says the scalar sits in an array (it has no field name of its own). Deeper than 12 levels a subtree is
 * judged as its JSON text (the recursion stops there; the text is read again from its top): it is kept as it was when
 * nothing in it is masked, and replaced by the masked text otherwise, so no subtree passes unjudged.
 */
function mapScalars(value, decide, key = '', depth = 0, item = false) {
  if (value === null || typeof value !== 'object' || isRaw(value)) return decide(value, key, item);
  if (depth > 12) {
    const text = jsonOf(value);
    const judged = decide(text, key, item);
    return judged === text ? value : judged;
  }
  if (Array.isArray(value)) return value.map((v) => mapScalars(v, decide, key, depth + 1, true));
  return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, mapScalars(v, decide, k, depth + 1)]));
}

// A JSON text is read with each number's own spelling where Node can write it back (21+: the reviver's source and
// JSON.rawJSON): every numeric literal, integer or decimal in any exponent form, stays a raw JSON value, is judged by its
// value and, unless masked, is written back exactly as it came (Power BI's fixed decimal has 19 digits, a double 17).
// Without JSON.rawJSON a number is a double: maskJsonText still rewrites the text and logs a literal it could not keep.
const RAW_JSON = typeof JSON.rawJSON === 'function';
const isRaw = (value) => RAW_JSON && JSON.isRawJSON?.(value) === true;
// Without JSON.rawJSON an integer of 16 digits or more that a double cannot hold is read as a BigInt: the literal is
// swapped for a stand-in string before parsing (a private-use character and its digits) and the reviver turns it back,
// so the card and TCKN checks see its own digits (a rounded card fails the checksum). A BigInt left unmasked is written
// back as the double, as before. A text that holds the stand-in character itself is read as doubles only.
const STAND_IN = '';
const STAND_IN_RE = /|\\u[eE]000/;
const BIG_INTEGER_RE = /^-?\d{16,}$/;
/** A value as JSON text, a BigInt with its digits (a subtree judged as text); a text without a BigInt is left as written. */
function jsonOf(value) {
  let big = false;
  const text = JSON.stringify(value, (_key, v) => (typeof v === 'bigint' ? ((big = true), `${STAND_IN}${v}`) : v));
  return big ? text.replace(/"(-?\d+)"/g, '$1') : text;
}
/** Parses a JSON text; `inexact` says a number was read as a double (no JSON.rawJSON, or no source from the reviver). */
function parseNumbers(body) {
  let inexact = false;
  const standIn = !RAW_JSON && !STAND_IN_RE.test(body);
  const source = standIn
    ? body.replace(LITERAL_RE, (whole, literal) => (literal !== undefined && BIG_INTEGER_RE.test(literal) && !doubleKeeps(literal) ? `"${STAND_IN}${literal}"` : whole))
    : body;
  const value = JSON.parse(source, (_key, v, context) => {
    if (standIn && typeof v === 'string' && v[0] === STAND_IN) {
      inexact = true;
      return BigInt(v.slice(1));
    }
    if (typeof v !== 'number') return v;
    if (RAW_JSON && typeof context?.source === 'string') return JSON.rawJSON(context.source);
    inexact = true;
    return v;
  });
  return { value, inexact };
}
/** The value a numeric literal is judged by: a BigInt for an integer a double cannot hold, a double otherwise. */
const numberOf = (src) => (/^-?\d+$/.test(src) && String(Number(src)) !== src ? BigInt(src) : Number(src));
/** The decimal value a numeric literal spells, as significant digits and exponent: "1.50", "15E-1" and "1.5" give "15e-1". */
function decimalOf(src) {
  const m = /^(-?)(\d+)(?:\.(\d+))?(?:[eE]([+-]?\d+))?$/.exec(src);
  if (!m) return src;
  const all = (m[2] + (m[3] ?? '')).replace(/^0+/, '');
  const digits = all.replace(/0+$/, '');
  return digits ? `${m[1]}${digits}e${Number(m[4] ?? 0) - (m[3]?.length ?? 0) + all.length - digits.length}` : '0';
}
/** A double writes the literal back with its value ("1.0", "1E+5", "1e21", "-0.5"), not only a near one. */
const doubleKeeps = (src) => Number.isFinite(Number(src)) && decimalOf(String(Number(src))) === decimalOf(src);
// A string, skipped whole, or a numeric literal outside strings (group 1).
const LITERAL_RE = /"(?:[^"\\]|\\.)*"|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/g;
/** A JSON text holds a numeric literal a double would change (more digits than a double keeps, or out of its range). */
const losesDigits = (body) => [...body.matchAll(LITERAL_RE)].some((m) => m[1] !== undefined && !doubleKeeps(m[1]));
const PRECISION_LOST = 'json-text-precision-lost';

// An MCP answer over Claude Code's output limit is saved to <session>/tool-results/mcp-<server>-<tool>-<epoch ms>.txt (or
// .json), the names cleaned as in the hook's mcp__<server>__<tool>, and PostToolUse gets only a note pointing to it:
// "... Output has been saved to <path>. ..." (Claude Code 2.1.301, probed 2026-10-16). Any server: the Power BI modeling
// server's, a SQL server's, a GitHub server's answer is masked as MCP output when it is read back.
const SAVED_FILE = 'mcp-[A-Za-z0-9_-]+-\\d{13}\\.(?:txt|json)\\b';
const SAVED_NAME_RE = new RegExp(`\\b${SAVED_FILE}`);
// Kept out of the PII text rules, whose card checksum the 13-digit epoch passes one time in ten: the file name, and in
// the note the path from "Output has been saved to " to it.
const SAVED_PATH_RE = new RegExp(`(?<=Output has been saved to )[^\\n"'<>|@]*?tool-results[\\\\/]${SAVED_FILE}|\\b${SAVED_FILE}`, 'g');
/** A string of the call's input (Read's file_path, Grep's path, a shell command, Copilot's paths) names a saved MCP answer. */
function namesSavedMcpAnswer(toolInput) {
  const strings = [];
  const collect = (value, depth) => {
    if (typeof value === 'string') strings.push(value);
    else if (value && typeof value === 'object' && depth < 3) Object.values(value).forEach((v) => collect(v, depth + 1));
  };
  collect(toolInput, 0);
  return strings.some((s) => SAVED_NAME_RE.test(s));
}

// A member of JSON, or of a Python dict print, in a text that is not one JSON value: a slice of a saved answer (Read with
// offset and limit, head), a jq stream, an answer cut off at the output limit. 1: the key's quote, 2: the key, 3: its
// value, a string or a number. A number without a key of its own is not judged here: the text rules check it.
const MEMBER_RE = /(["'])((?:(?!\1)[^\\\n]|\\.)*)\1\s*:\s*("(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*'|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?(?![\w.]))/g;
/** A JSON key's text with its escapes read; the raw text when it is no JSON string body. */
const unquoteKey = (raw) => {
  try {
    return JSON.parse(`"${raw}"`);
  } catch {
    return raw;
  }
};

/**
 * What the model is told about the values this hook masked: one notice for every kind of output (a file or shell read,
 * an MCP answer, a saved MCP answer read back). Claude Code replaces the output with updatedToolOutput, and Copilot CLI
 * with modifiedResult ("Replacement tool result", GitHub's hooks configuration reference, read 2026-10-19; probed with
 * CLI 1.0.94 on 2026-10-08), so there the values were redacted. VS Code's hooks reference (page dated 10/14/2026, read
 * 2026-10-19) documents no PostToolUse field that replaces tool output (only decision, reason and additionalContext):
 * updatedToolOutput is still sent, harmless if ignored, but the model may have the values, so it is told that and never
 * that they were redacted. No block: the value would already be shown, and a block would stop every masked read.
 */
function maskNotice({ count, ids, tool, hostTool, vscode }) {
  const kinds = ids.join(', ');
  if (vscode) {
    return `[bi-harness] This ${hostTool || tool} output contained ${count} sensitive value(s) (${kinds}). VS Code documents no way for a hook to replace tool output, so they may be visible to you unmasked. Do not repeat, store, copy or use them (not in an answer, a file, a query, a command or a commit); tell the user that this output held sensitive values, and ask the user if a real value is required.`;
  }
  return `[bi-harness] ${count} sensitive value(s) were redacted from this ${tool} output (${kinds}). Do not try to recover them; tell the user if a real value is required.`;
}

/**
 * A failed tool call (PostToolUseFailure): its `error` text reaches the model unchanged. Claude Code adds a hook's
 * additionalContext "alongside the error" and documents no field that replaces it (hooks reference, read 2026-10-19);
 * Copilot CLI's postToolUseFailure takes additionalContext only (GitHub hooks reference, read 2026-10-19); VS Code has
 * no such event. So an error that holds a secret (or PII where masking covers this tool) cannot be masked: the model is
 * told the values may be visible and must not be used, and the event is logged without them.
 */
function failureNotice(input, cfg) {
  const tool = String(input.tool_name ?? '');
  const error = typeof input.error === 'string' ? input.error : JSON.stringify(input.error ?? '');
  if (!error) return null;
  const pii = cfg.redaction.piiInAllTools || (cfg.redaction.piiInMcpOutput && claudeMcpName(tool, cfg).startsWith('mcp__'));
  let text = error;
  let count = 0;
  const ids = new Set();
  for (const pass of [cfg.redaction.secrets && redactSecrets, pii && redactPii]) {
    if (!pass) continue;
    const r = pass(text);
    count += r.count;
    r.ids.forEach((id) => ids.add(id));
    text = r.text;
  }
  if (!count) return null;
  const kinds = [...ids].join(', ');
  const hostTool = typeof input.host_tool === 'string' && input.host_tool ? input.host_tool : tool;
  appendJsonl('security-events.jsonl', { event: 'sensitive-error', tool, count, ids: [...ids], session: String(input.session_id ?? '').slice(0, 8) });
  return {
    hookSpecificOutput: {
      hookEventName: 'PostToolUseFailure',
      additionalContext: `[bi-harness] The error of this ${hostTool} call contained ${count} sensitive value(s) (${kinds}). No hook can replace the error text of a failed call, so they may be visible to you unmasked. Do not repeat, store, copy or use them (not in an answer, a file, a query, a command or a commit); tell the user that this error held sensitive values.`,
    },
  };
}

/** True for a failed call: the event names itself, or (Copilot CLI's camelCase payload names none) an error and no result. */
const isFailure = (input) =>
  input.hook_event_name === 'PostToolUseFailure' || (input.hook_event_name === undefined && input.error !== undefined && input.tool_response === undefined);

await runHook('PostToolUse', async (input) => {
  const cfg = loadConfig();
  // A failed call records no MCP state (a clear failure leaves no trace) and has no output to mask, only an error.
  if (isFailure(input)) return failureNotice(input, cfg);
  const tool = String(input.tool_name ?? '');
  // The session's MCP targets and in-memory writes (lib/mcp-state.mjs), before any return: a write without an answer
  // still ran, and masking turned off must not turn the record off. A failure here, a broken module included (loaded
  // here, not at the top), never touches the masking.
  if (isPowerBiMcp(tool, cfg)) {
    try {
      const { recordMcpCall } = await import('./lib/mcp-state.mjs');
      recordMcpCall(input, cfg);
    } catch {
      // State is a reminder for the guard and the Stop gate; masking goes on.
    }
  }
  // Every MCP tool's answer is masked (a SQL server's rows as much as a model query's), whatever name the host gives the
  // tool: mcp__<server>__<tool>, Copilot CLI's <server>-mcp-<tool>, VS Code's mcp_<label>_<tool>.
  const mcpCall = claudeMcpName(tool, cfg).startsWith('mcp__');
  // A Read, search or shell command of a saved MCP answer (any server's) returns that answer: it is masked as one. A
  // command that names other files too is masked whole, since its output cannot be told apart by file.
  const savedAnswer = !mcpCall && cfg.redaction.piiInMcpOutput && namesSavedMcpAnswer(input.tool_input);
  const pii = cfg.redaction.piiInAllTools || (cfg.redaction.piiInMcpOutput && (mcpCall || savedAnswer));
  if (!cfg.redaction.secrets && !pii) return null;
  if (input.tool_response === undefined) return null;
  const personalKey = personalKeyOf(cfg);

  let count = 0;
  // JSON texts rewritten with a number a double could not keep (no JSON.rawJSON); logged as an id, not counted.
  let lost = 0;
  const ids = new Set();
  const apply = (result) => {
    count += result.count;
    result.ids.forEach((id) => ids.add(id));
    return result.text;
  };
  const mark = (id) => {
    count++;
    ids.add(id);
    return `[PII:${id}]`;
  };
  // A text that parses as JSON, masked as data; undefined when it is no JSON, so the text rules apply instead. Only a
  // changed value rewrites the text. Privacy comes before precision: a text read as doubles is rewritten even when it
  // holds a literal a double cannot keep, and that loss is logged. A failure undoes this text's counts; nothing here throws.
  const maskJsonText = (text) => {
    const body = text.trim();
    if (!body.startsWith('{') && !body.startsWith('[')) return undefined;
    const before = { count, lost, ids: [...ids] };
    const undo = () => {
      count = before.count;
      lost = before.lost;
      ids.clear();
      before.ids.forEach((id) => ids.add(id));
    };
    try {
      const { value, inexact } = parseNumbers(body);
      const masked = mapScalars(value, decide);
      if (count === before.count) return text;
      if (inexact && losesDigits(body)) lost++;
      const start = text.indexOf(body);
      // A BigInt left unmasked (read through a stand-in without JSON.rawJSON) is written back as the double.
      const json = JSON.stringify(masked, (_key, v) => (typeof v === 'bigint' ? Number(v) : v), body.includes('\n') ? 2 : undefined);
      return text.slice(0, start) + json + text.slice(start + body.length);
    } catch {
      undo();
      return undefined;
    }
  };
  // A text that is not one JSON value: each member under a personal key is masked as the field rule says (a non-empty
  // string, a number unless the key counts it), then the text rules run on all of it but a saved answer's path.
  const maskText = (text) => {
    const members = text.replace(MEMBER_RE, (whole, quote, rawKey, literal) => {
      const key = quote === '"' ? unquoteKey(rawKey) : rawKey;
      if (!personalKey(key)) return whole;
      const isString = literal[0] === '"' || literal[0] === "'";
      if (isString ? !literal.slice(1, -1).trim() || MASK_TOKEN_RE.test(literal.slice(1, -1).trim()) : aggregateKey(key)) return whole;
      return `${whole.slice(0, whole.length - literal.length)}${quote}${mark('personal-field')}${quote}`;
    });
    let out = '';
    let at = 0;
    for (const m of members.matchAll(SAVED_PATH_RE)) {
      out += apply(redactPii(members.slice(at, m.index))) + m[0];
      at = m.index + m[0].length;
    }
    return out + apply(redactPii(members.slice(at)));
  };
  // Each value is decided once: a personal field as a whole, an unnamed identifier-length number, JSON in a text as
  // data, or the text rules.
  const decide = (value, key, item) => {
    if (typeof value === 'string') {
      if (pii && value.trim() && !MASK_TOKEN_RE.test(value.trim()) && personalKey(key)) return mark('personal-field');
      let text = value;
      if (cfg.redaction.secrets) text = apply(redactSecrets(text));
      if (!pii) return text;
      return maskJsonText(text) ?? maskText(text);
    }
    // A number read from a JSON text with its literal (raw JSON) is judged by its value and, kept, written back as it came.
    const number = isRaw(value) ? numberOf(value.rawJSON) : value;
    if (!pii || (typeof number !== 'number' && typeof number !== 'bigint')) return value;
    // The key decides first: a personal field is masked whatever the number, any other named field keeps it.
    if (personalKey(key) && !aggregateKey(key)) return mark('personal-field');
    const unnamed = key === '' || (item && !aggregateKey(key));
    const digits = unnamed ? integerDigits(number) : 0;
    if (digits >= 9 && digits <= 19) {
      // A checksum-valid TCKN or card keeps its own rule id; any other unnamed number of 9 to 15 digits is masked as a
      // number, one of 16 to 19 digits only by a checksum.
      const known = redactPii(String(number));
      if (known.count) return apply(known);
      return digits <= 15 ? mark('number') : value;
    }
    return value;
  };
  const updated = mapScalars(input.tool_response, decide);
  if (!count) return null;

  // A rewrite that rounded a number is logged as an id; `count` holds only the masked values.
  const logged = lost ? [...ids, PRECISION_LOST] : [...ids];
  appendJsonl('security-events.jsonl', { event: 'redaction', tool, ...(savedAnswer && { source: 'saved-mcp-answer' }), count, ids: logged, session: String(input.session_id ?? '').slice(0, 8) });
  return {
    hookSpecificOutput: {
      hookEventName: 'PostToolUse',
      updatedToolOutput: updated,
      // VS Code runs the CLI's hook file too, with its own payload (copilotHostOf): the warning, not "were redacted".
      additionalContext: maskNotice({ count, ids: [...ids], tool, hostTool: typeof input.host_tool === 'string' ? input.host_tool : '', vscode: copilotHostOf(input) === 'vscode' }),
    },
  };
});
