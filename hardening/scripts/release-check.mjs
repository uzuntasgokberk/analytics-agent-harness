#!/usr/bin/env node
// Maintainers' release check: run it over the repository before every release (the installer does not ship it).
//   node hardening/scripts/release-check.mjs [root] [--names <file.json>] [--json]
// It reports file, line and rule only, never the matched text. Exit code 1 when anything is found.
// Export scan, before the repository or a copy of it goes public: run it on an export of the branch (`git archive <branch>
// | tar -x -C <empty folder>`: tracked files only, no local settings or logs) with --names <file outside the repository>
// listing what must not be published (an account name, a machine prefix, a lab folder). A plain string matches in any
// case, a "/regex/" entry as written (so "/DESKTOP-/" passes "powerbi-desktop").
//   personal data   machine names (DESKTOP-xxxx), user paths (C:\Users\<name>, C:/Users/<name>, /c/Users/<name> in Git
//                   Bash, /home/<name>, /Users/<name>; a <placeholder>, Microsoft's FIRSTN~1.LAS and a whole name that
//                   is only a stand-in pass in any file: one letter, someone, user, username, name. A stand-in names
//                   nobody, so a real account called that leaks no person either; a longer name such as user1 is found),
//                   e-mail addresses outside the allowed domains, credential-shaped strings, and every name listed in the
//                   optional --names file (a JSON array of strings or /regex/ strings: project names, workspace names,
//                   people), which stays outside the repository so the check itself does not carry them
//   links           relative Markdown links that point to a file that does not exist
//   limits          Markdown over 500 lines (AGENTS.md over 200), counted like the validator and the guard (a final
//                   newline ends the last line), except the folders in harness.config.json scan.exclude
//   frontmatter     every skill and agent file starts with YAML frontmatter whose name matches its folder or file
//   files           files that must never be in a release: logs, local settings, .mcp.json, install manifests
//   config          hardening/harness.config.json carries no lab values (references, approvals until, a mode other than auto)
//   stale           a warning, not a finding (the exit code ignores it): a dated marker in Markdown older than 90 days
//                   ("checked <date>", "reviewed <date>", "Checked against <source> on <date>", "Verified with <tool>
//                   <version> on <date>", "read <date>", "probed <date>", "seen <date>", also wrapped over two lines;
//                   "not re-checked on <date>" is none), so a fact taken from a web page (Learn, the Claude Code docs,
//                   npm) is fetched again before the release and its date moved. Tests fix its clock with the
//                   environment variable BI_RELEASE_CHECK_NOW (an ISO date and time).

import fs from 'node:fs';
import path from 'node:path';
import { matchesAny } from '../hooks/lib/common.mjs';
import { countLines } from '../hooks/lib/validators.mjs';

const args = process.argv.slice(2);
const flag = (name) => {
  const i = args.indexOf(name);
  return i === -1 ? null : args[i + 1] ?? null;
};
const json = args.includes('--json');
const root = path.resolve(args.find((a) => !a.startsWith('--') && a !== flag('--names')) ?? process.cwd());
const namesFile = flag('--names');

const toPosix = (p) => p.replace(/\\/g, '/');
const findings = [];
const report = (file, line, rule, detail = '') => findings.push({ file: toPosix(file), line, rule, detail });

// Every file without a NUL byte is text, whatever its name: a release or an export publishes a .dtsx, .pbir, .platform,
// .params or CODEOWNERS as well as the Markdown and the code (the scan read a list of extensions before and skipped them).
const isText = (rel) => !fs.readFileSync(path.join(root, rel)).includes(0);

function config() {
  try {
    return JSON.parse(fs.readFileSync(path.join(root, 'hardening', 'harness.config.json'), 'utf8'));
  } catch {
    return {};
  }
}
const cfg = config();
// The validator's glob matching: `**` spans directories. (The former inline conversion turned a trailing `**` into one
// path segment, so `.claude/worktrees/**` missed every file below a worktree's root.)
const excludeGlobs = cfg.scan?.exclude ?? ['.git/**', 'node_modules/**'];
const excluded = (rel) => rel.startsWith('.git/') || matchesAny(rel, excludeGlobs);

function walk(dir) {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    const rel = toPosix(path.relative(root, full));
    if (rel === '.git' || rel.startsWith('.git/')) continue;
    if (entry.isDirectory()) out.push(...walk(full));
    else out.push(rel);
  }
  return out;
}
const files = walk(root).sort();
const read = (rel) => fs.readFileSync(path.join(root, rel), 'utf8');

// 1. personal data and credentials
// A credential assignment in the forms this repository's files use (F2-49): `Key=value` (a connection string, a shell or
// JS assignment, also with the value in quotes or ODBC braces, Pwd={...}), `"key": "value"` (JSON, a JS object, quoted
// YAML) and a YAML `key: value` line. A placeholder after the opening quote or brace passes: ***, [REDACTED, [PII,
// <...>, {{...}}, %VAR%, $VAR/${VAR} (also escaped, \${VAR}), a string concatenation, an ellipsis.
const CREDENTIAL_KEY = String.raw`(?:Password|Passwd|Pwd|AccountKey|SharedAccessSignature|client_secret)`;
const PLACEHOLDER = String.raw`(?!\*{3}|\[(?:REDACTED|PII)|<|\\?\{|%|\\?\$|"\s*\+|'\s*\+|\.\.\.|…)`;
const CREDENTIAL_RE = new RegExp(
  [
    String.raw`${CREDENTIAL_KEY}\s*=\s*["'{]?${PLACEHOLDER}[^;\s"'\`<}]{6,}`,
    String.raw`${CREDENTIAL_KEY}["']?\s*:\s*["']${PLACEHOLDER}[^"'\s\`<]{6,}`,
    String.raw`^\s*(?:-\s+)?${CREDENTIAL_KEY}\s*:\s*${PLACEHOLDER}[^\s#"'\`{<]{6,}\s*$`,
  ].join('|'),
  'i',
);
const ALLOWED_MAIL = /@(?:example\.com|contoso\.com|users\.noreply\.github\.com|example\.org)$/i;
const PATTERNS = [
  [/\bDESKTOP-[A-Z0-9]{4,}\b/, 'machine-name'],
  // user-path: C:\Users\<name>, C:/Users/<name>, /home/<name> (Linux) and /Users/<name> (macOS; also Git Bash's
  // /c/Users/<name> and WSL's /mnt/c/Users/<name>). Fine: a <placeholder>, Microsoft's FIRSTN~1.LAS and a whole
  // name that is only a stand-in (one letter, someone, user, username, name), as the repository's own tests write it.
  [/(?:[A-Za-z]:[\\\/]+Users[\\\/]+|\/(?:home|Users)\/+)(?!FIRSTN~1\.LAS|<|(?:[A-Za-z]|someone|user(?:name)?|name)(?![^\\\/\s"'`]))[^\\\/\s"'`]+/, 'user-path'],
  [/\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b/, 'github-token'],
  [/\bAKIA[0-9A-Z]{16}\b/, 'aws-key'],
  [/\bsk-[A-Za-z0-9]{20,}\b/, 'api-key'],
  [/\b(?:eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,})\b/, 'jwt'],
  [CREDENTIAL_RE, 'credential'],
];
// --names file: a JSON array; each entry is a string ("Name" or "/regex/flags") or { "pattern": ..., "allowedIn": [files] }
// (for example the author's name, allowed in LICENSE, NOTICE and the README's attribution).
// The g and y flags are dropped: they make .test() stateful (lastIndex carries over), so every other line holding the
// name was missed (F2-25).
const toRegExp = (n) => (/^\/.*\/[a-z]*$/.test(n) ? new RegExp(n.slice(1, n.lastIndexOf('/')), n.slice(n.lastIndexOf('/') + 1).replace(/[gy]/g, '')) : new RegExp(n.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i'));
const names = namesFile ? JSON.parse(fs.readFileSync(path.resolve(namesFile), 'utf8')) : [];
const NAME_RULES = names.map((n) => (typeof n === 'string' ? { re: toRegExp(n), allowedIn: [] } : { re: toRegExp(n.pattern), allowedIn: n.allowedIn ?? [] }));
const SELF = 'hardening/scripts/release-check.mjs';

for (const rel of files) {
  if (!isText(rel) || excluded(rel) || rel === SELF || rel === 'hardening/tests/release-check.test.mjs') continue;
  const lines = read(rel).split(/\r?\n/);
  lines.forEach((text, i) => {
    for (const [re, rule] of PATTERNS) if (re.test(text)) report(rel, i + 1, rule);
    for (const m of text.matchAll(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g)) if (!ALLOWED_MAIL.test(m[0])) report(rel, i + 1, 'e-mail');
    NAME_RULES.forEach((rule, k) => { if (!rule.allowedIn.includes(rel) && rule.re.test(text)) report(rel, i + 1, 'listed-name', `#${k + 1}`); });
  });
}

// 2. relative Markdown links
for (const rel of files) {
  if (!rel.endsWith('.md') || excluded(rel)) continue;
  const lines = read(rel).split(/\r?\n/);
  lines.forEach((text, i) => {
    for (const m of text.matchAll(/\]\(([^)\s]+)(?:\s+"[^"]*")?\)/g)) {
      let target = m[1];
      if (/^(?:https?:|mailto:|#|<)/i.test(target)) continue;
      target = target.split('#')[0];
      if (!target) continue;
      try { target = decodeURIComponent(target); } catch { /* keep as is */ }
      const resolved = path.resolve(path.dirname(path.join(root, rel)), target);
      if (!fs.existsSync(resolved)) report(rel, i + 1, 'broken-link', target);
    }
  });
}

// 3. Markdown limits
const maxLines = cfg.markdown?.maxLines ?? 500;
for (const rel of files) {
  if (!rel.endsWith('.md') || excluded(rel)) continue;
  // The validator's and the guard's count: a final newline ends the last line instead of starting another (F1-103).
  const n = countLines(read(rel));
  if (n > maxLines) report(rel, n, 'markdown-limit', `${n} lines`);
  if (rel === 'AGENTS.md' && n > 200) report(rel, n, 'agents-limit', `${n} lines`);
}

// 4. frontmatter of skills and agents
function frontmatter(rel) {
  const text = read(rel);
  const m = /^---\r?\n([\s\S]*?)\r?\n---(?:\r?\n|$)/.exec(text);
  if (!m) return null;
  const fields = {};
  for (const line of m[1].split(/\r?\n/)) {
    const kv = /^([A-Za-z_-]+):\s*(.*)$/.exec(line);
    if (kv) fields[kv[1]] = kv[2].trim();
  }
  return fields;
}
for (const rel of files) {
  const skill = /^\.claude\/skills\/([^/]+)\/SKILL\.md$/.exec(rel);
  const agent = /^\.claude\/agents\/([^/]+)\.md$/.exec(rel);
  if (!skill && !agent) continue;
  const fm = frontmatter(rel);
  if (!fm) { report(rel, 1, 'frontmatter-missing'); continue; }
  if (!fm.name) report(rel, 1, 'frontmatter-name-missing');
  if (!fm.description) report(rel, 1, 'frontmatter-description-missing');
  const expected = (skill ?? agent)[1];
  if (fm.name && fm.name !== expected) report(rel, 1, 'frontmatter-name-mismatch', expected);
}

// 5. files that never ship
const FORBIDDEN = [/^\.claude\/logs\/(?!\.gitkeep$)/, /^\.claude\/settings\.local\.json$/, /^\.mcp\.json$/, /^\.claude\/bi-agent-harness\.json$/, /^\.vscode\/(?!extensions\.json$)/, /(?:^|\/)node_modules\//, /(?:^|\/)\.DS_Store$/, /^\.env(?:\.|$)(?!example$)/, /\.(?:pbix|abf|pfx|pem|key|p12)$/i];
for (const rel of files) if (FORBIDDEN.some((re) => re.test(rel))) report(rel, 0, 'forbidden-file');

// 6. release configuration
if (fs.existsSync(path.join(root, 'hardening', 'harness.config.json'))) {
  if (Array.isArray(cfg.references) && cfg.references.length) report('hardening/harness.config.json', 0, 'config-references', 'must be empty in a release');
  if (cfg.approvals?.until) report('hardening/harness.config.json', 0, 'config-until', 'a release carries no until');
  if (cfg.approvals?.mode && cfg.approvals.mode !== 'auto') report('hardening/harness.config.json', 0, 'config-mode', `mode ${cfg.approvals.mode}`);
}

// 7. dated markers: "checked 2026-10-17", "reviewed 2026-09-29", "Checked on 2026-10-12", "checked 2026-10" (day 01),
//    "Checked against each tool's documentation on 2026-10-07", "Checked with Desktop 2.158 and powerbi-report-author
//    0.1.4 on 2026-10-06", "Verified with ... on 2026-10-07", "Re-checked on ...", "read 2026-10-15", "probed 2026-10-08",
//    "seen 2026-10-07" (F1-93). Up to ten words may stand between the word and "on <date>", none ending a sentence or
//    clause, and the marker may wrap onto the next line but not across a blank one. "not (re-)checked on <date>" and
//    "never verified on <date>" say the fact was not checked: no marker. A bare date ("(Learn, x, 2026-08-31)",
//    "ms.date: ...") is none either. The marker does not say which page it rests on, so every one counts; the maintainer
//    fetches the page again and moves the date. A warning, never a finding: nothing in a release is wrong because a
//    date is old.
const STALE_DAYS = 90;
const SP = String.raw`(?:[ \t]+(?:\r?\n[ \t]*)?|\r?\n[ \t]*)`; // spaces with at most one line break: never a blank line
const WORD = String.raw`[^\s]*[^\s.;!?]`; // a word that does not end a sentence or clause
const DATE = String.raw`((\d{4})-(\d{2})(?:-(\d{2}))?)\b`;
const MARKER_RE = new RegExp(
  String.raw`(?<!\b(?:not|never)\s+(?:re-)?)\b(?:re-)?(?:(?:checked|reviewed|verified|probed|seen)(?:(?:${SP}${WORD}){0,10}?${SP}on)?|read)${SP}${DATE}`,
  'gi',
);
const warnings = [];
const clock = process.env.BI_RELEASE_CHECK_NOW;
const now = clock ? Date.parse(clock) : Date.now();
if (Number.isNaN(now)) {
  console.error(`release-check: BI_RELEASE_CHECK_NOW="${clock}" is not an ISO date and time.`);
  process.exit(2);
}
for (const rel of files) {
  if (!rel.endsWith('.md') || excluded(rel)) continue;
  const text = read(rel);
  for (const m of text.matchAll(MARKER_RE)) {
    const [year, month, day] = [Number(m[2]), Number(m[3]), Number(m[4] ?? 1)];
    if (month < 1 || month > 12 || day < 1 || day > 31) continue;
    const days = Math.floor((now - Date.UTC(year, month - 1, day)) / 86400000);
    // The line of the date, which a wrapped marker puts on the line after its first word.
    const line = text.slice(0, m.index + m[0].length - m[1].length).split('\n').length;
    if (days > STALE_DAYS) warnings.push({ file: rel, line, rule: 'stale-check', detail: `${m[2]}-${m[3]}-${m[4] ?? '01'}, ${days} days; fetch the source again` });
  }
}

const byRule = {};
for (const f of findings) byRule[f.rule] = (byRule[f.rule] ?? 0) + 1;
if (json) {
  console.log(JSON.stringify({ root: toPosix(root), files: files.length, findings, warnings }, null, 2));
} else {
  for (const f of findings) console.log(`${f.file}:${f.line} ${f.rule}${f.detail ? ` (${f.detail})` : ''}`);
  for (const w of warnings) console.log(`WARN ${w.file}:${w.line} ${w.rule} (${w.detail})`);
  console.log(`release-check: ${files.length} files, ${findings.length} finding(s)${findings.length ? ` [${Object.entries(byRule).map(([k, v]) => `${k} ${v}`).join(', ')}]` : ''}, ${warnings.length} warning(s)`);
}
process.exit(findings.length ? 1 : 0);
