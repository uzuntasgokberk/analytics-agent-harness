// Quote-aware splitting of a shell command line (bash and PowerShell spellings). A `;`, `|`, `&&`, `||` or newline
// inside quotes never ends a statement, and adjacent quoted parts form one word, so `sed -i 's/a/b/; s/c/d'"'"'s/' x.md`
// is one statement with four words and the file argument stays with `sed`. Parentheses are not grouping here on
// purpose: `(cd x; git push)` still splits at the `;`, so the inner program is judged (the stricter direction).
// Backslashes are Windows path separators as often as bash escapes here, so a backslash escapes only what a shell
// needs it for (whitespace, quotes, `;`, `|`, `&`, `$`, a backtick), inside double quotes only a `"`, and
// `C:\Tools\x\.ssh\k` or `setup\data\y.csv` keep every backslash.
// A `#` that starts a word begins a comment in bash and PowerShell (`<#` too): inside it a quote opens nothing, so
// `echo hi # it's` + newline + `rm -rf x` is two statements, as the shells run it. The separators inside a comment still
// cut (the stricter direction: cmd.exe has no `#` comments). A carriage return alone ends a statement too (PowerShell).

/** A backslash outside quotes escapes the next character only when it is one of these. */
const ESCAPABLE = new Set([' ', '\t', '\n', '\r', "'", '"', '`', ';', '|', '&', '$']);

/**
 * True when a `#` at `i` starts a word: a comment in bash and PowerShell (`echo a#b` is none). After `{` too (a PowerShell
 * block `{# ...`): a `${#x}` read as a comment only makes the splitter cut more, never less.
 */
const commentStart = (text, i) => text[i] === '#' && (i === 0 || /[\s;|&<>(){]/.test(text[i - 1]));

const ANSI_C_SIMPLE = { a: '\x07', b: '\b', e: '\x1b', E: '\x1b', f: '\f', n: '\n', r: '\r', t: '\t', v: '\v', '\\': '\\', "'": "'", '"': '"', '?': '?' };
/**
 * The escape at `text[i]` (a backslash) inside bash's ANSI-C quoting $'...', as bash decodes it: `\xHH` (1-2 hex digits),
 * `\NNN` (1-3 octal digits), `\uHHHH`, `\UHHHHHHHH`, `\cX` and the single letters; an unknown escape keeps its backslash.
 * Returns the decoded text and the index after the escape.
 */
function ansiCEscape(text, i) {
  const next = text[i + 1];
  if (Object.hasOwn(ANSI_C_SIMPLE, next)) return { value: ANSI_C_SIMPLE[next], end: i + 2 };
  const numeric = [[/^x([0-9A-Fa-f]{1,2})/, 16], [/^([0-7]{1,3})/, 8], [/^u([0-9A-Fa-f]{1,4})/, 16], [/^U([0-9A-Fa-f]{1,8})/, 16]];
  for (const [re, radix] of numeric) {
    const m = re.exec(text.slice(i + 1, i + 10));
    if (!m) continue;
    const code = parseInt(m[1], radix);
    return { value: code <= 0x10ffff ? String.fromCodePoint(code) : '', end: i + 1 + m[0].length };
  }
  if (next === 'c' && i + 2 < text.length) return { value: String.fromCharCode(text.charCodeAt(i + 2) & 0x1f), end: i + 3 };
  return { value: `\\${next}`, end: i + 2 };
}

/**
 * The command line as bash and PowerShell read it without their comments: a `#` that starts a word runs to the end of the
 * line, a PowerShell block comment `<# ... #>` (at the start of a word) to its `#>`, outside quotes. The policy judges this
 * reading next to the text itself (the strictest verdict wins), so a word after `#` (`git restore . # --staged`) or a block
 * comment inside a command (`git <# x #> push --force`) changes nothing.
 */
export function withoutComments(cmd) {
  const text = String(cmd ?? '');
  let out = '';
  let quote = null;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quote) {
      if (c === '\\' && i + 1 < text.length && (quote === '$' || (quote === '"' && text[i + 1] === '"'))) { out += c + text[++i]; continue; }
      if ((quote === '"' && c === '"') || (quote !== '"' && c === "'")) quote = null;
      out += c;
      continue;
    }
    if (c === '\\' && i + 1 < text.length && ESCAPABLE.has(text[i + 1])) { out += c + text[++i]; continue; }
    if (c === "'" || c === '"') { quote = c; out += c; continue; }
    if (c === '$' && text[i + 1] === "'") { quote = '$'; out += "$'"; i++; continue; }
    const wordStart = i === 0 || /[\s;|&(){]/.test(text[i - 1]);
    if (c === '<' && text[i + 1] === '#' && wordStart) {
      const end = text.indexOf('#>', i + 2);
      i = end < 0 ? text.length : end + 1;
      out += ' ';
      continue;
    }
    if (commentStart(text, i)) {
      while (i + 1 < text.length && text[i + 1] !== '\n' && text[i + 1] !== '\r') i++;
      out += ' ';
      continue;
    }
    out += c;
  }
  return out;
}

/**
 * Walks `text` and cuts it at every separator found outside quotes: statement separators (`;`, `&&`, `||`, newline,
 * a background `&`) and/or pipe separators (`|`, `|&`). $'...' is ANSI-C quoting (single quotes with escapes).
 */
function walk(text, { statements = true, pipes = true } = {}) {
  const parts = [];
  let start = 0;
  let quote = null; // "'", '"' or '$' (inside $'...')
  let comment = false; // inside a `#` comment: quotes and escapes open nothing, separators still cut, a line end closes it
  let i = 0;
  const cut = (end, next) => {
    parts.push(text.slice(start, end));
    start = next;
  };
  while (i < text.length) {
    const c = text[i];
    if (quote) {
      if (c === '\\' && i + 1 < text.length && (quote === '$' || (quote === '"' && text[i + 1] === '"'))) { i += 2; continue; }
      if ((quote === '"' && c === '"') || (quote !== '"' && c === "'")) quote = null;
      i++;
      continue;
    }
    if (comment) {
      if (c === '\n' || c === '\r') comment = false;
      else if (c !== ';' && c !== '&' && c !== '|') { i++; continue; }
    } else {
      if (c === '\\' && i + 1 < text.length && ESCAPABLE.has(text[i + 1])) { i += 2; continue; }
      if (c === "'" || c === '"') { quote = c; i++; continue; }
      if (c === '$' && text[i + 1] === "'") { quote = '$'; i += 2; continue; }
      if (commentStart(text, i)) { comment = true; i++; continue; }
    }
    if (statements) {
      // A line ends a statement: \n, \r\n, and a carriage return alone (PowerShell runs `a<CR>b` as two statements).
      if (c === '\n' || c === '\r') { const n = c === '\r' && text[i + 1] === '\n' ? 2 : 1; cut(i, i + n); i += n; continue; }
      if (c === ';') { cut(i, i + 1); i++; continue; }
      if (c === '&' && text[i + 1] === '&') { cut(i, i + 2); i += 2; continue; }
      if (c === '|' && text[i + 1] === '|') { cut(i, i + 2); i += 2; continue; }
      // a lone & with whitespace on both sides runs the left side in the background: two statements
      if (c === '&' && /\s/.test(text[i - 1] ?? '') && /\s/.test(text[i + 1] ?? '') && text[i + 1] !== '&') { cut(i, i + 1); i++; continue; }
    }
    // `>|` is bash's noclobber override of a redirect, not a pipe: the target stays with its statement.
    if (pipes && c === '|' && text[i + 1] !== '|' && text[i - 1] !== '|' && text[i - 1] !== '>') {
      const n = text[i + 1] === '&' ? 2 : 1;
      cut(i, i + n);
      i += n;
      continue;
    }
    i++;
  }
  parts.push(text.slice(start));
  return parts.map((p) => p.trim()).filter(Boolean);
}

/** Statements of a command line: split on `;`, `&&`, `||`, newlines and a background `&`, outside quotes. */
export const splitStatements = (cmd) => walk(String(cmd ?? ''), { statements: true, pipes: false });

/** Stages of one statement: split on `|` and `|&` outside quotes (never on `||`). */
export const splitPipeline = (statement) => walk(String(statement ?? ''), { statements: false, pipes: true });

/** Statements and stages in one list, in order (what the old regex split called subcommands). */
export const splitSubcommands = (cmd) => splitStatements(cmd).flatMap(splitPipeline);

/**
 * Words of one subcommand with the quotes removed: adjacent quoted and unquoted parts join into one word
 * ('a'"b"c is abc), an escaped space or quote stays in the word, Windows backslashes stay, an unterminated quote runs
 * to the end. Bash's ANSI-C quoting is decoded as bash does it ($'\x2eenv' is .env; a NUL ends that quoted part), and
 * the words of a `#` comment are kept as written (a quote there opens nothing).
 */
export function tokenize(sub) {
  const text = String(sub ?? '');
  const words = [];
  let word = '';
  let has = false;
  let quote = null;
  let comment = false;
  let cut = false; // a NUL inside $'...': bash drops the rest of that quoted part
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quote === '$') {
      if (c === "'") { quote = null; cut = false; continue; }
      if (c === '\\' && i + 1 < text.length) {
        const { value, end } = ansiCEscape(text, i);
        i = end - 1;
        if (value.includes('\0')) cut = true;
        if (!cut) word += value;
        continue;
      }
      if (!cut) word += c;
      continue;
    }
    if (quote) {
      if (c === '\\' && i + 1 < text.length && quote === '"' && text[i + 1] === '"') { word += text[++i]; continue; }
      if ((quote === '"' && c === '"') || (quote !== '"' && c === "'")) { quote = null; continue; }
      word += c;
      continue;
    }
    if (c === '\n' || c === '\r') comment = false;
    if (!comment) {
      if (c === '\\' && i + 1 < text.length && ESCAPABLE.has(text[i + 1])) { word += text[++i]; has = true; continue; }
      if (c === "'" || c === '"') { quote = c; has = true; continue; }
      if (c === '$' && text[i + 1] === "'") { quote = '$'; has = true; i++; continue; }
      if (commentStart(text, i)) comment = true;
    }
    if (/\s/.test(c)) {
      if (has) words.push(word);
      word = '';
      has = false;
      continue;
    }
    word += c;
    has = true;
  }
  if (has) words.push(word);
  return words;
}
