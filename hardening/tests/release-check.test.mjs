// Release check (scripts/release-check.mjs): personal data, broken links, Markdown limits, frontmatter, forbidden files
// and lab values in the config. Fake values are built at run time; the check prints file, line and rule, never the match.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const script = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'scripts', 'release-check.mjs');
const run = (root, ...extra) => spawnSync(process.execPath, [script, root, ...extra], { encoding: 'utf8' });
// F1-145: the stale rule reads its clock from BI_RELEASE_CHECK_NOW (tests only), so a date built here and the child's
// day count use the same instant; one second before UTC midnight, where a second clock read would cross into the next day.
const NOW = '2026-03-31T23:59:59.900Z';
const runAt = (root, ...extra) => spawnSync(process.execPath, [script, root, ...extra], { encoding: 'utf8', env: { ...process.env, BI_RELEASE_CHECK_NOW: NOW } });
const iso = (daysAgo) => new Date(Date.parse(NOW) - daysAgo * 86400000).toISOString().slice(0, 10);
const write = (root, rel, text) => {
  fs.mkdirSync(path.dirname(path.join(root, rel)), { recursive: true });
  fs.writeFileSync(path.join(root, rel), text);
};
const clean = (root) => {
  write(root, 'AGENTS.md', '# Agreement\n\nSee [the docs](docs/a.md).\n');
  write(root, 'docs/a.md', '# A\n\nBack to [AGENTS.md](../AGENTS.md#top) and [outside](https://example.com/x).\n');
  write(root, '.claude/skills/bi-map/SKILL.md', '---\nname: bi-map\ndescription: routes\n---\n\n# Map\n');
  write(root, '.claude/agents/bi-expert.md', '---\nname: bi-expert\ndescription: main\n---\n\n# Expert\n');
  write(root, 'hardening/harness.config.json', JSON.stringify({ markdown: { maxLines: 500 }, references: [], approvals: { mode: 'auto' }, scan: { exclude: ['vendor/**'] } }));
  write(root, 'vendor/long.md', Array.from({ length: 600 }, (_, i) => `line ${i}`).join('\n'));
};

test('release-check: a clean tree has no finding and exits 0', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-release-check-'));
  try {
    clean(root);
    const r = run(root);
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.match(r.stdout, /0 finding\(s\)/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('release-check: finds personal data, listed names, broken links, limits, frontmatter, forbidden files and config values, and never prints the match', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-release-check-'));
  try {
    clean(root);
    const token = `ghp_${'a'.repeat(36)}`;
    const mail = `${'someone'}@${'corp-mail'}.example.net`;
    // F1-112: the four credential shapes, joined at run time so this file holds none of them.
    const aws = ['AK', 'IA', 'ABCDEFGHIJKLMNOP'].join('');
    const apiKey = ['s', 'k-', 'a'.repeat(24)].join('');
    const jwt = ['ey', 'J', 'a'.repeat(22), '.', 'b'.repeat(22), '.', 'c'.repeat(12)].join('');
    const credential = ['Pass', 'word=Hunt', 'er2Xyz'].join('');
    write(root, 'docs/keys.md', ['# Keys', `aws ${aws}`, `api ${apiKey}`, `jwt ${jwt}`, `conn Server=x;${credential};`].join('\n'));
    write(root, '.claude/agents/bi-noname.md', '---\ndescription: no name\n---\n\n# No name\n');
    write(root, 'docs/b.md', [
      '# B',
      `machine ${'DESKTOP'}-${'AB12CD'} and ${'C:\\Users\\'}${'realname'}\\x`,
      `token ${token}`,
      `mail ${mail}`,
      'see [gone](missing.md) and [ok](a.md)',
      'the project OldLabName here',
    ].join('\n'));
    write(root, 'docs/long.md', Array.from({ length: 501 }, (_, i) => `line ${i}`).join('\n'));
    write(root, 'AGENTS.md', `# Agreement\n${Array.from({ length: 205 }, () => 'rule').join('\n')}\n`);
    write(root, '.claude/skills/bi-plan/SKILL.md', '# No frontmatter\n');
    write(root, '.claude/agents/bi-other.md', '---\nname: bi-wrong\n---\n');
    write(root, '.claude/logs/tool-audit.jsonl', '{}\n');
    write(root, '.mcp.json', '{}\n');
    write(root, 'hardening/harness.config.json', JSON.stringify({ references: ['setup/'], approvals: { mode: 'lab', until: '2030-01-01T00:00:00Z' }, scan: { exclude: ['vendor/**'] } }));
    const names = path.join(root, '..', `names-${path.basename(root)}.json`);
    fs.writeFileSync(names, JSON.stringify(['OldLabName', { pattern: '/Agreement/', allowedIn: ['AGENTS.md'] }]));
    try {
      const r = run(root, '--names', names);
      assert.equal(r.status, 1);
      for (const rule of ['machine-name', 'user-path', 'github-token', 'aws-key', 'api-key', 'jwt', 'credential', 'e-mail', 'listed-name', 'broken-link', 'markdown-limit', 'agents-limit', 'frontmatter-missing', 'frontmatter-name-missing', 'frontmatter-name-mismatch', 'frontmatter-description-missing', 'forbidden-file', 'config-references', 'config-until', 'config-mode']) {
        assert.match(r.stdout, new RegExp(`\\b${rule}\\b`), `missing rule ${rule}:\n${r.stdout}`);
      }
      // Each rule at its own line, so a regression in one shape is not hidden by another (F1-112).
      for (const [line, rule] of [[2, 'aws-key'], [3, 'api-key'], [4, 'jwt'], [5, 'credential']]) {
        assert.match(r.stdout, new RegExp(`^docs/keys\\.md:${line} ${rule}$`, 'm'), `${rule} at docs/keys.md:${line}:\n${r.stdout}`);
      }
      assert.match(r.stdout, /^\.claude\/agents\/bi-noname\.md:1 frontmatter-name-missing$/m);
      assert.match(r.stdout, /^hardening\/harness\.config\.json:0 config-mode \(mode lab\)$/m);
      for (const value of [aws, apiKey, jwt, credential, 'er2Xyz']) assert.ok(!r.stdout.includes(value), 'the check never prints a credential it found');
      assert.match(r.stdout, /docs\/b\.md:5 broken-link \(missing\.md\)/);
      assert.doesNotMatch(r.stdout, /Agreement/, 'a name allowed in a file is not reported there');
      assert.doesNotMatch(r.stdout, new RegExp(token));
      assert.doesNotMatch(r.stdout, new RegExp(mail.replace('.', '\\.')));
      assert.doesNotMatch(r.stdout, /realname|AB12CD/);
      assert.doesNotMatch(r.stdout, /vendor\/long\.md/, 'scan.exclude folders are not checked');
      const j = JSON.parse(spawnSync(process.execPath, [script, root, '--names', names, '--json'], { encoding: 'utf8' }).stdout);
      assert.ok(j.findings.some((f) => f.file === 'docs/b.md' && f.rule === 'e-mail' && f.line === 4));
    } finally {
      fs.rmSync(names, { force: true });
    }
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

// F1-103: the limits count lines like the validator and the guard (countLines): a final newline ends the last line, it
// does not start another, so a 500-line Markdown file and a 200-line AGENTS.md pass with LF and with CRLF.
test('release-check: Markdown limits count lines like the validator; 500 lines and a 200-line AGENTS.md ending in a newline pass, 501 and 201 are found', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-release-check-'));
  const lines = (n, eol = '\n') => Array.from({ length: n }, (_, i) => `line ${i + 1}${eol}`).join('');
  try {
    clean(root);
    write(root, 'docs/ok.md', lines(500));
    write(root, 'docs/ok-crlf.md', lines(500, '\r\n'));
    write(root, 'AGENTS.md', lines(200));
    let r = run(root, '--json');
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.deepEqual(JSON.parse(r.stdout).findings, [], 'exactly at the limit is within it');
    write(root, 'docs/over.md', lines(501));
    write(root, 'AGENTS.md', lines(201));
    r = run(root);
    assert.equal(r.status, 1, r.stdout + r.stderr);
    assert.match(r.stdout, /^docs\/over\.md:501 markdown-limit \(501 lines\)$/m);
    assert.match(r.stdout, /^AGENTS\.md:201 agents-limit \(201 lines\)$/m);
    assert.doesNotMatch(r.stdout, /ok(?:-crlf)?\.md/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

// F1-122: Node and Git Bash print forward slashes (C:/Users/<name>, /c/Users/<name>), Linux has /home/<name> and macOS
// /Users/<name>; all of them leak a user name like the backslash form does. A <placeholder>, Microsoft's FIRSTN~1.LAS and a
// name that is only a stand-in (one letter, someone, user, username, name) stay clean, and so does text without a name.
test('release-check: a user path is found with forward slashes, in Git Bash, Linux and macOS spelling; placeholders and stand-in names are clean', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-release-check-'));
  const name = ['jo', 'hn'].join('');
  const userPathLines = (j, file) => j.findings.filter((f) => f.file === file && f.rule === 'user-path').map((f) => f.line);
  try {
    clean(root);
    write(root, 'docs/d.md', [
      '# D',
      `forward slashes: C:/Users/${name}/repo`, // 2
      `Git Bash: /c/Users/${name}/repo`, // 3
      `Linux: /home/${name}/repo`, // 4
      `macOS: /Users/${name}/repo`, // 5
      'a placeholder: C:/Users/<name>/repo', // 6: clean
    ].join('\n'));
    write(root, 'docs/e.md', [
      '# E',
      'placeholders: C:\\Users\\<name>\\x, /c/Users/<name>/x, /home/<name>/x, /Users/<user>/x, C:/Users/FIRSTN~1.LAS/x', // 2: clean
      'stand-ins: C:/Users/u/x, /home/u/x, /home/someone/x, /Users/username/x, C:/Users/user/x, /home/name', // 3: clean
      'only a whole name is a stand-in: /home/user1/x', // 4
      `backslashes: C:\\Users\\${name}\\x`, // 5
      'no name: C:/Users/ and /home/ and /Users/ are folders', // 6: clean
    ].join('\n'));
    const r = run(root, '--json');
    assert.equal(r.status, 1, r.stdout + r.stderr);
    const j = JSON.parse(r.stdout);
    assert.deepEqual(userPathLines(j, 'docs/d.md'), [2, 3, 4, 5], 'the four spellings are found, the placeholder line is not');
    assert.deepEqual(userPathLines(j, 'docs/e.md'), [4, 5], 'placeholders, stand-in names and bare folders are clean; the backslash form still counts');
    assert.equal(j.findings.filter((f) => f.rule === 'user-path').length, 6, 'no other file has a user-path finding');
    assert.doesNotMatch(run(root).stdout, new RegExp(name), 'the check prints file, line and rule, never the name');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

// Residual (follow-up audit): the stand-in names pass wherever they appear. They are kept on purpose: a stand-in identifies
// nobody, so a real account with one of these names leaks no person either; only the whole name counts, so a longer name
// that starts with one (the usual real account) is still found.
test('release-check: stand-in names pass in any file, as whole names only; a longer name that starts with one is found', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-release-check-'));
  try {
    clean(root);
    write(root, 'docs/f.md', [
      '# F',
      'C:/Users/user/Documents/x and C:\\Users\\name\\x and /home/someone/notes.txt and /home/u/x', // 2: clean
      'C:/Users/username2/x', // 3
      '/home/u.smith/x', // 4
      '/home/someone.else/x', // 5
      'C:/Users/userx/x', // 6
    ].join('\n'));
    const j = JSON.parse(run(root, '--json').stdout);
    assert.deepEqual(j.findings.filter((f) => f.rule === 'user-path').map((f) => `${f.file}:${f.line}`), ['docs/f.md:3', 'docs/f.md:4', 'docs/f.md:5', 'docs/f.md:6']);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

// A fact taken from a web page carries "checked <date>"; after 90 days the maintainer fetches the page again. The rule is
// a warning: the exit code stays 0, and the summary counts it apart from the findings.
test('release-check: a "checked" or "reviewed" marker older than 90 days is a warning that does not fail the check; recent ones and excluded folders are silent', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-release-check-'));
  try {
    clean(root);
    write(root, 'docs/c.md', [
      '# C',
      `Facts from Learn, checked ${iso(120)} (links under Sources).`, // stale
      `Sources (reviewed ${iso(10)}).`, // recent
      `Checked on ${iso(100)}. Pin a version.`, // stale, "Checked on"
      `Learn pages; checked ${iso(200).slice(0, 7)}). Fetch them again.`, // month only: day 01, stale
      'ms.date: 2020-01-01 is not a marker; neither is "checked in" nor checked 2020.',
    ].join('\n'));
    write(root, 'vendor/old.md', `# Vendored\n\nchecked ${iso(400)}\n`);
    const r = runAt(root);
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.match(r.stdout, /0 finding\(s\), 3 warning\(s\)/, r.stdout);
    assert.match(r.stdout, new RegExp(`^WARN docs/c\\.md:2 stale-check \\(${iso(120)}, 120 days; fetch the source again\\)$`, 'm'), r.stdout);
    assert.match(r.stdout, new RegExp(`^WARN docs/c\\.md:4 stale-check \\(${iso(100)}, 100 days`, 'm'), r.stdout);
    assert.match(r.stdout, /^WARN docs\/c\.md:5 stale-check \(\d{4}-\d{2}-01, \d+ days/m);
    assert.doesNotMatch(r.stdout, /c\.md:3 |c\.md:6 |vendor\/old\.md/);
    const j = JSON.parse(runAt(root, '--json').stdout);
    assert.deepEqual(j.findings, []);
    assert.deepEqual(j.warnings.map((w) => [w.file, w.line, w.rule]), [['docs/c.md', 2, 'stale-check'], ['docs/c.md', 4, 'stale-check'], ['docs/c.md', 5, 'stale-check']]);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

// F1-145: the day count comes from one clock. Without BI_RELEASE_CHECK_NOW a date built at 23:59:59.9 UTC was 120 days old
// in the test and 121 in the child, 200 ms later; with it, the count is exact.
test('release-check: BI_RELEASE_CHECK_NOW fixes the clock of the stale rule; an unreadable value stops the check', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-release-check-'));
  try {
    clean(root);
    write(root, 'docs/c.md', `# C\n\nFacts from Learn, checked ${iso(91)}.\nSources (reviewed ${iso(90)}).\n`);
    const r = runAt(root, '--json');
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.deepEqual(JSON.parse(r.stdout).warnings.map((w) => [w.line, w.detail]), [[3, `${iso(91)}, 91 days; fetch the source again`]], '91 days warns, 90 does not');
    const bad = spawnSync(process.execPath, [script, root], { encoding: 'utf8', env: { ...process.env, BI_RELEASE_CHECK_NOW: 'yesterday' } });
    assert.equal(bad.status, 2, bad.stdout + bad.stderr);
    assert.match(bad.stderr, /BI_RELEASE_CHECK_NOW/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

// F1-93: the dated markers the repository writes besides "checked <date>": "Checked against ... on <date>", "Checked with
// <tool> <version> on <date>", "Verified ... on <date>", "read <date>", "probed <date>", "seen <date>", and a marker
// wrapped over two lines. "not re-checked on <date>" says the fact was NOT checked, so it is no marker.
test('release-check: the repository\'s other dated markers warn too, wrapped ones included; "not re-checked" and loose dates are silent', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-release-check-'));
  const old = iso(120);
  try {
    clean(root);
    write(root, 'docs/m.md', [
      '# Markers', // 1
      `Checked against each tool's documentation on ${old} (Codex: ${iso(119)}).`, // 2: warn
      `Checked with Desktop 2.158 and \`powerbi-report-author\` 0.1.4 on ${old}.`, // 3: warn
      `Verified with Power BI Desktop 2.158 and \`powerbi-report-author\` 0.1.4 on ${old} (a copy).`, // 4: warn
      `(Learn "ssis-devops-standalone", read ${old}) build a project.`, // 5: warn
      `runs from the project root (probed ${old}).`, // 6: warn
      `falls back to a serif (seen ${old}).`, // 7: warn
      `one of the examples. Checked against each tool's`, // 8
      `documentation on ${old} (Codex: ${iso(119)}).`, // 9: warn, at the date's line
      `Re-checked on ${old} with Learn.`, // 10: warn, a check that was done again
      `TargetServerVersion follows it (Learn; not re-checked on ${old}).`, // 11: silent
      `The value was not checked on ${old}; never verified on ${old} either.`, // 12: silent
      `Checked against Learn. The release on ${old} changed nothing.`, // 13: silent, another sentence
      `the files read by Desktop on ${old} and seen in the log on 2020.`, // 14: silent ("read" takes the date directly)
      `Limits (Learn, visual calculations, ${old}): a date without a marker word.`, // 15: silent
      `Checked against`, // 16
      '', // 17
      `on ${old}, a new paragraph.`, // 18: silent, a blank line ends the marker
    ].join('\n'));
    const r = runAt(root, '--json');
    assert.equal(r.status, 0, r.stdout + r.stderr);
    const j = JSON.parse(r.stdout);
    assert.deepEqual(j.warnings.map((w) => w.line), [2, 3, 4, 5, 6, 7, 9, 10], JSON.stringify(j.warnings, null, 1));
    assert.ok(j.warnings.every((w) => w.detail === `${old}, 120 days; fetch the source again`), JSON.stringify(j.warnings, null, 1));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('release-check: a /regex/ entry with the g or y flag reports every line holding the name, not every other one (F2-25)', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-release-check-'));
  try {
    clean(root);
    const name = ['Lab', 'person'].join('');
    write(root, 'docs/people.md', `# People\n\nContact ${name} today\n${name} wrote this\nalso ${name}\n`);
    for (const flags of ['gi', 'yi', 'i']) {
      const names = path.join(root, '..', `${path.basename(root)}-names-${flags}.json`);
      fs.writeFileSync(names, JSON.stringify([`/${name.toLowerCase()}/${flags}`]));
      try {
        const r = run(root, '--names', names);
        const lines = r.stdout.split('\n').filter((l) => / listed-name /.test(l)).map((l) => l.split(' ')[0]);
        assert.deepEqual(lines, ['docs/people.md:3', 'docs/people.md:4', 'docs/people.md:5'], `/${flags}: ${r.stdout}`);
      } finally {
        fs.rmSync(names, { force: true });
      }
    }
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('release-check: a credential in JSON, a JS assignment, ODBC braces or a YAML line is found; placeholders are not (F2-49)', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-release-check-'));
  try {
    clean(root);
    const value = ['Pr0d', 'Secret', 'Value9'].join('');
    const key = ['pass', 'word'].join('');
    write(root, 'docs/a.json', `{ "${key}": "${value}" }\n`);
    write(root, 'docs/b.mjs', `const ${key} = "${value}";\n`);
    write(root, 'docs/c.md', `Driver={ODBC};${['P', 'wd'].join('')}={${value}};\n`);
    write(root, 'docs/d.yml', `db:\n  ${key}: ${value}\n`);
    write(root, 'docs/e.yml', `db:\n  - ${key}: '${value}'\n`);
    write(root, 'docs/clean.md', [
      '# Placeholders',
      `{"${key}": "\${DB_PASSWORD}", "${key}": "***", "${key}": "<secret>", "${key}": "[REDACTED:x]", "Password": "[PII:personal-field]"}`,
      `${key}: \${{ secrets.DB }}`,
      `${key}: <your password>`,
      `Pwd={{db_password}};`,
      `const ${key} = "\${x}";`,
      'Password: see the vault.',
    ].join('\n'));
    const r = run(root);
    const found = r.stdout.split('\n').filter((l) => / credential$/.test(l)).map((l) => l.split(' ')[0]).sort();
    assert.deepEqual(found, ['docs/a.json:1', 'docs/b.mjs:1', 'docs/c.md:1', 'docs/d.yml:2', 'docs/e.yml:2'], r.stdout);
    assert.ok(!r.stdout.includes(value), 'the value is never printed');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

// 2026-10-29 (export scan): the personal-data scan read a list of extensions, so a user path or a listed name in a .dtsx,
// .pbir, .platform, .params or CODEOWNERS, which a release or a public export publishes too, was never found. Every file
// without a NUL byte is scanned now; a binary file is not.
test('release-check: personal data and listed names are found in a text file of any extension; a binary file is skipped', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-release-check-'));
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-release-check-names-'));
  try {
    clean(root);
    const userPath = `${'C:\\Users\\'}${'realname'}\\Documents`;
    const files = ['etl/P/Load.dtsx', 'etl/P/Project.params', 'powerbi/S.Report/definition.pbir', 'powerbi/S.Report/.platform', '.github/CODEOWNERS'];
    for (const rel of files) write(root, rel, `<a>\n${userPath}\n</a>\n`);
    write(root, 'docs/image.bin', Buffer.concat([Buffer.from([0x89, 0x50, 0x00, 0x01]), Buffer.from(`\n${userPath}\n`)]));
    const r = run(root);
    assert.equal(r.status, 1, r.stdout);
    const found = r.stdout.split('\n').filter((l) => / user-path$/.test(l)).sort();
    assert.deepEqual(found, files.map((rel) => `${rel}:2 user-path`).sort(), r.stdout);
    assert.doesNotMatch(r.stdout, /image\.bin/, 'a file with a NUL byte is binary and not read');
    assert.ok(!r.stdout.includes('realname'), 'the match is never printed');

    // The export scan: a names file outside the tree; a plain string in any case, a /regex/ entry as written.
    for (const rel of files) fs.rmSync(path.join(root, rel));
    const account = ['lab', 'owner'].join('');
    write(root, '.github/CODEOWNERS', `* @${account.toUpperCase()}-x\n`);
    write(root, 'powerbi/S.SemanticModel/.platform', ['{ "displayName": "powerbi-desktop-model" }', `{ "logicalId": "${'DESKTOP'}-" }`].join('\n'));
    const names = path.join(outside, 'names.json');
    fs.writeFileSync(names, JSON.stringify([account, '/DESKTOP-/']));
    const n = run(root, '--names', names);
    assert.equal(n.status, 1, n.stdout);
    const listed = n.stdout.split('\n').filter((l) => / listed-name /.test(l)).sort();
    assert.deepEqual(listed, ['.github/CODEOWNERS:1 listed-name (#1)', 'powerbi/S.SemanticModel/.platform:2 listed-name (#2)'], n.stdout);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
    fs.rmSync(outside, { recursive: true, force: true });
  }
});
