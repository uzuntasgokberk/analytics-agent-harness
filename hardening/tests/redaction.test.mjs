// Personal-data redaction of tool output (post-tool-redact.mjs): real identifiers go, decimal numbers stay.
// Found in eval run 2: three YoY ratios from a DAX query (0. followed by 16 digits) were redacted as payment cards.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { SECRET_RULES, findSecrets, redactCommandSecrets, redactPii, redactSecrets } from '../hooks/lib/policy.mjs';
import { personalColumnName } from '../hooks/lib/sql-read.mjs';

const hooks = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'hooks');
const DAX_TOOL = 'mcp__powerbi-modeling__dax_query_operations';

/**
 * Runs a hook as Claude Code does (stdin JSON) in a fresh project folder, with `config` as its harness.config.json when
 * given and `nodeArgs` before the script; returns its answer and its log lines. `payload` may be a function of the
 * project folder (a payload that names a file in it).
 */
function runHook(script, payload, config, nodeArgs = []) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-redact-'));
  try {
    if (config) {
      fs.mkdirSync(path.join(dir, 'hardening'));
      fs.writeFileSync(path.join(dir, 'hardening', 'harness.config.json'), JSON.stringify(config));
    }
    const env = { ...process.env, CLAUDE_PROJECT_DIR: dir };
    delete env.BI_HARNESS_HOST;
    const body = typeof payload === 'function' ? payload(dir) : payload;
    const r = spawnSync(process.execPath, [...nodeArgs, path.join(hooks, script)], { input: JSON.stringify({ session_id: 'redaction-test', ...body }), env, encoding: 'utf8' });
    assert.equal(r.status, 0, r.stderr);
    assert.doesNotMatch(r.stderr, /hook error/);
    const log = (name) => {
      const file = path.join(dir, '.claude', 'logs', name);
      return fs.existsSync(file) ? fs.readFileSync(file, 'utf8').trim().split('\n').map((l) => JSON.parse(l)) : [];
    };
    return {
      out: r.stdout.trim() ? JSON.parse(r.stdout) : null,
      events: log('security-events.jsonl'),
      audit: log('tool-audit.jsonl'),
      notifications: log('notifications.jsonl'),
      instructions: log('instructions.jsonl'),
    };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}
const redactOutput = (tool_name, tool_response, config, nodeArgs) =>
  runHook('post-tool-redact.mjs', { hook_event_name: 'PostToolUse', tool_name, tool_input: {}, tool_response }, config, nodeArgs);

// Fake values built at run time. 12345678901 fails the TCKN checksum, so it is masked as a plain long number.
const EMAIL = ['someone', 'example.com'].join('@');
const LONG_ID = Number(['12345', '678901'].join(''));

// Builds a Luhn-valid digit string at run time (no real card number in the repository).
function luhnValid(prefix, length) {
  for (let last = 0; last <= 9; last++) {
    const digits = (prefix + '0'.repeat(length)).slice(0, length - 1) + last;
    let sum = 0;
    for (let i = 0; i < digits.length; i++) {
      let n = Number(digits[digits.length - 1 - i]);
      if (i % 2 === 1) { n *= 2; if (n > 9) n -= 9; }
      sum += n;
    }
    if (sum % 10 === 0) return digits;
  }
  throw new Error('unreachable');
}

test('a card-like number is redacted, alone, grouped or in JSON', () => {
  const card = luhnValid('4000123412341', 16);
  for (const text of [card, `${card.slice(0, 4)} ${card.slice(4, 8)} ${card.slice(8, 12)} ${card.slice(12)}`, `{"c":"${card}"}`]) {
    assert.match(redactPii(text).text, /\[PII:payment-card\]/, text);
  }
});

test('decimal fractions and amounts with a decimal point are not cards (DAX results)', () => {
  const digits = luhnValid('1492925134892923', 16);
  for (const text of [`"[YoY]":0.${digits}`, `-0.${digits}`, `${digits}.25`]) {
    assert.equal(redactPii(text).text, text, text);
  }
});

// A comma is a CSV separator as often as a decimal comma: next to a comma the number is still checked (Fable, run 2).
test('a card between CSV columns is still redacted', () => {
  const card = luhnValid('4000123412341', 16);
  for (const text of [`${card},1`, `1,${card}`, `${card.slice(0, 4)} ${card.slice(4, 8)} ${card.slice(8, 12)} ${card.slice(12)},1`]) {
    assert.match(redactPii(text).text, /\[PII:payment-card\]/, text);
  }
});

test('e-mail addresses are redacted', () => {
  assert.equal(redactPii('owner: someone@example.com').text, 'owner: [PII:email]');
});

// 2026-10-16 audit of fe1dd6f: only string values were masked, so an identifier the MCP client returns as a JSON number
// reached the model unmasked. Since the number rule of 2026-10-16 (below) a long number under a field name that is not
// personal ('Customer[Customer Id]') stays; the same number without a field name of its own is masked.
test('Power BI MCP output: an unnamed long whole number and an e-mail are both masked and counted; keys and structure stay', () => {
  const response = { results: [{ rows: [{ 'Customer[Customer Id]': LONG_ID, 'Customer[Contact]': EMAIL, '[Margin]': 1234567.5 }], values: [[LONG_ID, 2026]] }] };
  const { out, events } = redactOutput(DAX_TOOL, response);
  const updated = out?.hookSpecificOutput?.updatedToolOutput;
  assert.ok(Array.isArray(updated?.results) && Array.isArray(updated.results[0].rows), 'arrays stay arrays');
  assert.deepEqual(Object.keys(updated.results[0].rows[0]), Object.keys(response.results[0].rows[0]), 'keys are never masked');
  assert.deepEqual(updated.results[0].rows[0], { 'Customer[Customer Id]': LONG_ID, 'Customer[Contact]': '[PII:email]', '[Margin]': 1234567.5 });
  assert.deepEqual(updated.results[0].values, [['[PII:number]', 2026]]);
  assert.match(out.hookSpecificOutput.additionalContext, /2 sensitive value\(s\)/);
  assert.equal(events.length, 1);
  assert.equal(events[0].count, 2);
  assert.deepEqual(events[0].ids.sort(), ['email', 'number']);
});

// 2026-10-16 reproduction against the real hook: the magnitude rule ran before the key, so legitimate totals and counts
// of 9 or more digits came back as [PII:number] and expected-value reconciliation broke.
const REPRO_ROW = { 'Customer[Phone]': '05321234567', NationalID: LONG_ID, '[Total Sales]': 100000000, '[Customer Count]': 100000000, Year: 2026 };
const REPRO_MASKED = { ...REPRO_ROW, 'Customer[Phone]': '[PII:personal-field]', NationalID: '[PII:personal-field]' };

test('Power BI MCP output: a number is masked by its field name, never by its size under a named field', () => {
  const { out, events } = redactOutput(DAX_TOOL, { rows: [REPRO_ROW] });
  assert.deepEqual(out?.hookSpecificOutput?.updatedToolOutput, { rows: [REPRO_MASKED] }, 'Total Sales, Customer Count and Year stay');
  assert.equal(events[0].count, 2);
  assert.deepEqual(events[0].ids, ['personal-field']);
  const amount = Number(['123456', '789012'].join(''));
  assert.equal(redactOutput(DAX_TOOL, { rows: [{ Amount: amount, '[Total Sales]': [100000000, amount] }] }).out, null, 'an amount and a list of totals stay');
});

test('Power BI MCP output: a number without a field name of its own is masked when it has 9 to 15 digits', () => {
  const sixteen = Number(['12345678', '90123456'].join(''));
  const { out } = redactOutput(DAX_TOOL, { rows: [[LONG_ID, 100000000, 99999999, 2026, sixteen, 123456789.5]] });
  assert.deepEqual(out?.hookSpecificOutput?.updatedToolOutput, { rows: [['[PII:number]', '[PII:number]', 99999999, 2026, sixteen, 123456789.5]] });
  assert.deepEqual(redactOutput(DAX_TOOL, [-LONG_ID]).out?.hookSpecificOutput?.updatedToolOutput, ['[PII:number]'], 'the whole output, either sign');
  assert.deepEqual(redactOutput(DAX_TOOL, LONG_ID).out?.hookSpecificOutput?.updatedToolOutput, '[PII:number]');
});

// 2026-10-16 decision: the number rule above let a 16-digit card returned as a JSON number through, so a number without
// a field name of its own and 16 to 19 digits is checked against the checksum rules only, never masked for its size.
test('Power BI MCP output: an unnamed number of 16 to 19 digits is masked only by a checksum rule, never under a named field', () => {
  const cardText = luhnValid('4000123412341', 16);
  const card = Number(cardText);
  const notCard = Number(cardText.slice(0, 15) + ((Number(cardText[15]) + 1) % 10));
  const { out, events } = redactOutput(DAX_TOOL, { rows: [[card, notCard]], totals: [{ '[Total Sales]': card }] });
  assert.deepEqual(out?.hookSpecificOutput?.updatedToolOutput, { rows: [['[PII:payment-card]', notCard]], totals: [{ '[Total Sales]': card }] });
  assert.equal(events[0].count, 1);
  assert.deepEqual(events[0].ids, ['payment-card']);
});

test('a 19-digit card in a JSON text is checked digit for digit', { skip: typeof JSON.rawJSON !== 'function' && 'needs the reviver source (Node 21+)' }, () => {
  const card = luhnValid('4000123412341', 19);
  const result = redactOutput(DAX_TOOL, { content: [{ type: 'text', text: `[[${card}],{"[Total Sales]":${card}}]` }] });
  assert.deepEqual(result.out?.hookSpecificOutput?.updatedToolOutput, { content: [{ type: 'text', text: `[["[PII:payment-card]"],{"[Total Sales]":${card}}]` }] });
});

test('Power BI MCP output: measure values, counts and years under nine digits stay, and nothing to mask gives no answer', () => {
  const { out, events } = redactOutput(DAX_TOOL, { rows: [{ '[Total Sales]': 1234567, '[Year]': 2026, '[Margin %]': 0.4231, '[Big Total]': 99999999.5 }] });
  assert.equal(out, null);
  assert.deepEqual(events, []);
});

test('Power BI MCP output: a field named like personal data is masked whatever its type; a count of it is not', () => {
  const phone = ['0555', '000', '00', '00'].join(' ');
  const response = { rows: [
    { Email: 5551234, 'Customer[Phone]': phone, NationalID: 4242 },
    { '[Customers with Email]': 1234, 'Customer[Phone Count]': 77, HasEmail: true, 'Customer[Customer Name]': 'Contoso' },
  ] };
  const { out, events } = redactOutput(DAX_TOOL, response);
  const rows = out?.hookSpecificOutput?.updatedToolOutput?.rows;
  assert.deepEqual(rows[0], { Email: '[PII:personal-field]', 'Customer[Phone]': '[PII:personal-field]', NationalID: '[PII:personal-field]' });
  assert.deepEqual(rows[1], response.rows[1], 'counts, booleans and other fields stay');
  assert.equal(events[0].count, 3);
});

// Since the number rule of 2026-10-16 a named field that is not personal ('Customer[Ref]') keeps its number, so the
// checksum case is tested on a number without a field name of its own.
test('an unnamed long number that is a checksum-valid TCKN keeps its own rule id', () => {
  const d = [1, 0, 0, 0, 0, 0, 0, 0, 1];
  const odd = d[0] + d[2] + d[4] + d[6] + d[8];
  const even = d[1] + d[3] + d[5] + d[7];
  d.push((((odd * 7 - even) % 10) + 10) % 10);
  d.push(d.reduce((a, b) => a + b, 0) % 10);
  const { out } = redactOutput(DAX_TOOL, { rows: [[Number(d.join(''))]] });
  assert.deepEqual(out?.hookSpecificOutput?.updatedToolOutput, { rows: [['[PII:tckn]']] });
});

test('an array under a personal field is masked item by item', () => {
  const { out } = redactOutput(DAX_TOOL, { phones: ['0555 000 00 01', '0555 000 00 02'], tags: ['a', 'b'] });
  assert.deepEqual(out?.hookSpecificOutput?.updatedToolOutput, { phones: ['[PII:personal-field]', '[PII:personal-field]'], tags: ['a', 'b'] });
});

// F1-48: this test took mcp__github__get_issue for "outside Power BI MCP output"; every MCP server is masked now (below),
// so a tool that is no MCP tool stands for the rest.
test('outside MCP output (default config) numbers and field names are not PII-masked', () => {
  assert.equal(redactOutput('WebFetch', { id: LONG_ID, email: 'x' }).out, null);
});

// 2026-10-16 reproduction against the real hook: MCP servers answer with content blocks holding their JSON as text, and
// the field and number rules only walked objects, so the same row came back unchanged (the text rules catch neither).
const textBlock = (value, indent) => ({ content: [{ type: 'text', text: JSON.stringify(value, null, indent) }] });
const updatedOf = (result) => result.out?.hookSpecificOutput?.updatedToolOutput;

test('Power BI MCP output: JSON inside a text block is masked as data and written back compact', () => {
  const result = redactOutput(DAX_TOOL, textBlock({ rows: [REPRO_ROW] }));
  assert.deepEqual(updatedOf(result), textBlock({ rows: [REPRO_MASKED] }), 'Phone and NationalID masked, Total Sales intact');
  assert.equal(result.events[0].count, 2);
  assert.deepEqual(updatedOf(redactOutput(DAX_TOOL, textBlock([[LONG_ID, 2026]]))), textBlock([['[PII:number]', 2026]]), 'unnamed inside the text');
});

test('Power BI MCP output: a pretty-printed JSON text keeps its line breaks', () => {
  const text = updatedOf(redactOutput(DAX_TOOL, textBlock({ rows: [REPRO_ROW] }, 2)))?.content?.[0]?.text;
  assert.equal(text, JSON.stringify({ rows: [REPRO_MASKED] }, null, 2));
  assert.match(text, /\n {6}"\[Total Sales\]": 100000000,\n/);
});

test('Power BI MCP output: a text that is not JSON keeps the text rules', () => {
  for (const text of [`mail ${EMAIL}, id ${LONG_ID}, total 100000000`, `{not json ${EMAIL}`, `[Total Sales] for ${EMAIL}`]) {
    const masked = { content: [{ type: 'text', text: text.replace(EMAIL, '[PII:email]') }] };
    assert.deepEqual(updatedOf(redactOutput(DAX_TOOL, { content: [{ type: 'text', text }] })), masked, text);
  }
});

test('Power BI MCP output: JSON in a string output, a nested result string or a JSON text inside JSON is masked too', () => {
  const json = JSON.stringify({ rows: [REPRO_ROW] });
  const masked = JSON.stringify({ rows: [REPRO_MASKED] });
  assert.equal(updatedOf(redactOutput(DAX_TOOL, json)), masked, 'a string tool_response');
  assert.equal(updatedOf(redactOutput(DAX_TOOL, `\n ${json}\n`)), `\n ${masked}\n`, 'the whitespace around it stays');
  assert.deepEqual(updatedOf(redactOutput(DAX_TOOL, { data: { result: json } })), { data: { result: masked } });
  assert.deepEqual(updatedOf(redactOutput(DAX_TOOL, textBlock({ success: true, result: json }))), textBlock({ success: true, result: masked }));
});

// 2026-10-16 probe of Claude Code 2.1.301 (the CLI's MCP result handling; the hooks docs say only that the shape depends
// on the tool): tool_response for an MCP tool is the bare list of content blocks, a text block keeping its _meta, not
// the {content: [...]} envelope; a server that sends structuredContent arrives as its JSON text, after any non-text block.
test('Power BI MCP output: the shapes Claude Code hands over (bare block list, structuredContent as text) are masked in place', () => {
  const json = JSON.stringify({ rows: [REPRO_ROW] });
  const masked = JSON.stringify({ rows: [REPRO_MASKED] });
  const meta = { 'com.example/rows': 1 };
  const blocks = redactOutput(DAX_TOOL, [{ type: 'text', text: json, _meta: meta }]);
  assert.deepEqual(updatedOf(blocks), [{ type: 'text', text: masked, _meta: meta }], 'a list in, a list out; type and _meta stay');
  assert.equal(blocks.events[0].count, 2);
  const image = { type: 'image', source: { type: 'base64', media_type: 'image/png', data: 'iVBORw0KGgo=' } };
  assert.deepEqual(updatedOf(redactOutput(DAX_TOOL, [image, { type: 'text', text: json }])), [image, { type: 'text', text: masked }]);
});

// 2026-10-16 probe of Claude Code 2.1.301: an MCP answer over the output limit is saved to
// <session>/tool-results/mcp-<server>-<tool>-<epoch ms>.txt and PostToolUse gets only a note pointing to it. The model
// then reads the file in slices (Read with offset and limit, jq, head), which only the text rules masked.
const callTool = (tool_name, tool_input, tool_response, config) => runHook('post-tool-redact.mjs', { hook_event_name: 'PostToolUse', tool_name, tool_input, tool_response }, config);
const EPOCH = luhnValid('1760000000', 13); // passes the card checksum, as one epoch in ten does
// A session folder whose first three groups are all digits and pass the card checksum (rare, but a path all the same).
const CARD_SESSION = ((d) => `${d.slice(0, 8)}-${d.slice(8, 12)}-${d.slice(12)}-a1b2-c3d4e5f6a7b8`)(luhnValid('4000123412341', 16));
const savedFile = (serverTool = 'powerbi-modeling-dax_query_operations', session = 'a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d') =>
  `D:\\Claude Config\\projects\\C--repo\\${session}\\tool-results\\mcp-${serverTool}-${EPOCH}.txt`;
const savedNote = (file) => `Error: result (123,456 characters) exceeds maximum allowed tokens. Output has been saved to ${file}.\nFormat: JSON. Use jq to make structured queries.`;
const readOf = (file, content) => ({ type: 'text', file: { filePath: file, content, numLines: content.split('\n').length, startLine: 40, totalLines: 4000 } });
const shellOf = (stdout) => ({ stdout, stderr: '', interrupted: false, isImage: false });
// A slice of a pretty-printed answer: not one JSON value, so only its members can be judged.
const SLICE = ['    {', '      "Customer[Phone]": "05321234567",', `      "NationalID": ${LONG_ID},`, '      "[Total Sales]": 100000000,', '      "[Customers with Email]": 1234,', '      "Year": 2026'].join('\n');
const SLICE_MASKED = SLICE.replace('"05321234567"', '"[PII:personal-field]"').replace(String(LONG_ID), '"[PII:personal-field]"');

test('a saved MCP answer: the note keeps its path, though the epoch passes the card checksum; other text is still masked', () => {
  assert.equal(redactPii(EPOCH).count, 1, 'the epoch alone reads as a card');
  assert.equal(redactPii(CARD_SESSION).count, 1, 'and so does this session folder');
  const note = savedNote(savedFile(undefined, CARD_SESSION));
  assert.equal(redactOutput(DAX_TOOL, note).out, null, 'nothing to mask in the note: its whole path stays');
  const card = luhnValid('4000123412341', 16);
  assert.equal(updatedOf(redactOutput(DAX_TOOL, `${note} ${card}`)), `${note} [PII:payment-card]`);
  const all = { redaction: { secrets: true, piiInMcpOutput: true, piiInAllTools: true } };
  assert.equal(callTool('Bash', { command: 'ls tool-results' }, shellOf(`mcp-powerbi-modeling-dax_query_operations-${EPOCH}.txt\n`), all).out, null, 'a listing keeps the name');
});

test('a saved Power BI MCP answer read in slices is masked as Power BI MCP output, its members by their keys', () => {
  const file = savedFile();
  const slice = callTool('Read', { file_path: file, offset: 40, limit: 6 }, readOf(file, SLICE));
  assert.deepEqual(updatedOf(slice), readOf(file, SLICE_MASKED), 'Phone and NationalID masked; totals, counts, years and the path stay');
  assert.deepEqual(slice.events.map((e) => [e.tool, e.source, e.count, e.ids]), [['Read', 'saved-mcp-answer', 2, ['personal-field']]]);
  const whole = callTool('Read', { file_path: file }, readOf(file, JSON.stringify({ rows: [REPRO_ROW] })));
  assert.deepEqual(updatedOf(whole), readOf(file, JSON.stringify({ rows: [REPRO_MASKED] })), 'a whole file is masked as data');
  const lines = (row) => `${JSON.stringify(row)}\n${JSON.stringify(row)}\n`;
  const jq = callTool('Bash', { command: `jq -c '.rows[]' "${file}"` }, shellOf(lines(REPRO_ROW)));
  assert.deepEqual(updatedOf(jq), shellOf(lines(REPRO_MASKED)), 'a jq stream');
  const python = "{'Customer[Phone]': '05321234567', 'NationalID': 12345678901, '[Total Sales]': 100000000}";
  const printed = callTool('Bash', { command: `python -c "import json; print(json.load(open(r'${file}'))['rows'][0])"` }, shellOf(python));
  assert.deepEqual(updatedOf(printed), shellOf("{'Customer[Phone]': '[PII:personal-field]', 'NationalID': '[PII:personal-field]', '[Total Sales]': 100000000}"), 'a Python dict print');
  // A server name with hyphens in it; a command naming other files too is masked whole.
  const other = savedFile('my-pbi-server-dax_query_operations');
  const mixed = callTool('PowerShell', { command: `Get-Content '${other}' -TotalCount 6; Get-Content notes.txt` }, shellOf(`${SLICE}\n"Owner Email": "x"`));
  assert.deepEqual(updatedOf(mixed), shellOf(`${SLICE_MASKED}\n"Owner Email": "[PII:personal-field]"`));
});

// F1-48: this test said a saved answer of another MCP server is not PII-masked, which was the Power BI-only design. PII
// masking holds for every MCP server (above), so it holds on this path too: a large SQL, GitHub or documentation answer
// that Claude Code saved to a file and the model reads back (Read, Grep, a shell command) is masked as MCP output.
test('a saved answer of any MCP server read back is masked as MCP output, its members by their keys (F1-48)', () => {
  for (const serverTool of ['github-get_issue', 'mssql-read_data', 'my-sql-server-read_data', 'microsoft-learn-microsoft_docs_search']) {
    const file = savedFile(serverTool);
    const slice = callTool('Read', { file_path: file, offset: 40, limit: 6 }, readOf(file, SLICE));
    assert.deepEqual(updatedOf(slice), readOf(file, SLICE_MASKED), `${serverTool}: Phone and NationalID masked; totals, counts, years and the path stay`);
    assert.deepEqual(slice.events.map((e) => [e.tool, e.source, e.count, e.ids]), [['Read', 'saved-mcp-answer', 2, ['personal-field']]], serverTool);
  }
  const sql = savedFile('mssql-read_data');
  const whole = callTool('Read', { file_path: sql.replace(/\.txt$/, '.json') }, readOf(sql, JSON.stringify({ rows: [REPRO_ROW] })));
  assert.deepEqual(updatedOf(whole), readOf(sql, JSON.stringify({ rows: [REPRO_MASKED] })), 'a whole .json file is masked as data');
  const lines = (row) => `${JSON.stringify(row)}\n${JSON.stringify(row)}\n`;
  const jq = callTool('Bash', { command: `jq -c '.rows[]' "${sql}"` }, shellOf(lines(REPRO_ROW)));
  assert.deepEqual(updatedOf(jq), shellOf(lines(REPRO_MASKED)), 'a jq stream');
  const grep = callTool('Grep', { pattern: 'Phone', path: sql }, '40:      "Customer[Phone]": "05321234567",');
  assert.equal(updatedOf(grep), '40:      "Customer[Phone]": "[PII:personal-field]",', 'a search of the file');
  const mixed = callTool('PowerShell', { command: `Get-Content '${sql}' -TotalCount 6; Get-Content notes.txt` }, shellOf(`${SLICE}\n"Owner Email": "x"`));
  assert.deepEqual(updatedOf(mixed), shellOf(`${SLICE_MASKED}\n"Owner Email": "[PII:personal-field]"`), 'a command naming other files too is masked whole');
  // The note an MCP tool of any server returns keeps its path (the epoch can pass the card checksum), as for Power BI above.
  assert.equal(callTool('mcp__mssql__read_data', {}, savedNote(savedFile('mssql-read_data', CARD_SESSION))).out, null);
});

test('an ordinary file, a name that is no saved answer, or a saved answer with redaction.piiInMcpOutput off is not PII-masked (F1-48)', () => {
  assert.equal(callTool('Read', { file_path: 'C:\\repo\\notes.json' }, readOf('C:\\repo\\notes.json', SLICE)).out, null);
  assert.equal(callTool('Bash', { command: 'jq -c .rows[] data.json' }, shellOf(SLICE)).out, null);
  // A saved answer's name ends in the 13 digits of an epoch in milliseconds.
  const short = savedFile('github-get_issue').replace(EPOCH, '12345');
  assert.equal(callTool('Read', { file_path: short }, readOf(short, SLICE)).out, null);
  const off = { redaction: { secrets: true, piiInMcpOutput: false, piiInAllTools: false } };
  for (const serverTool of ['github-get_issue', 'powerbi-modeling-dax_query_operations']) {
    const file = savedFile(serverTool);
    assert.equal(callTool('Read', { file_path: file }, readOf(file, SLICE), off).out, null, serverTool);
  }
});

test('Power BI MCP output: an answer cut off at the output limit is masked by its members', () => {
  const cut = (row) => `${JSON.stringify({ rows: [row] }).slice(0, -3)}\n\n[The tool output was truncated.]`;
  const result = redactOutput(DAX_TOOL, [{ type: 'text', text: cut(REPRO_ROW) }]);
  assert.deepEqual(updatedOf(result), [{ type: 'text', text: cut(REPRO_MASKED) }]);
  assert.equal(result.events[0].count, 2);
});

test('Power BI MCP output: a JSON text with nothing to mask stays as it came, number spelling included', () => {
  assert.equal(redactOutput(DAX_TOOL, { content: [{ type: 'text', text: '{"[Margin %]": 1.0, "[Rows]": 1E+5, "Year": 2026}' }] }).out, null);
});

test('Power BI MCP output: an integer longer than a double holds is written back digit for digit', { skip: typeof JSON.rawJSON !== 'function' && 'needs JSON.rawJSON (Node 21+)' }, () => {
  const key = '1234567890'.repeat(2);
  const text = `{"[Order Key]":${key},"Customer[Email]":"x","ids":[${key}]}`;
  const expected = `{"[Order Key]":${key},"Customer[Email]":"[PII:personal-field]","ids":[${key}]}`;
  assert.deepEqual(updatedOf(redactOutput(DAX_TOOL, { content: [{ type: 'text', text }] })), { content: [{ type: 'text', text: expected }] });
});

// 2026-10-16 third audit, reproduced against the real hook: only integers kept their digits, so once a JSON text was
// rewritten a decimal left unmasked came back as a double ('[Total Sales]' 123456789012345.6789 became ...345.67).
// Power BI's fixed decimal holds 19 digits with 4 decimals, and reconciliation compares such values.
const AUDIT_TEXT = '{"[Total Sales]":123456789012345.6789,"Phone":555}';
const inText = (text) => ({ content: [{ type: 'text', text }] });
const textOf = (result) => updatedOf(result)?.content?.[0]?.text;
const NEEDS_RAW_JSON = typeof JSON.rawJSON !== 'function' && 'needs the reviver source and JSON.rawJSON (Node 21+); this Node takes the older-Node branch, tested below';
// The older-Node branch on any Node: without JSON.rawJSON the hook reads doubles, as on Node 20 (the reviver's source
// alone cannot be written back). Node 20 and older lack it already.
const AS_DOUBLES = typeof JSON.rawJSON === 'function' ? ['--import', 'data:text/javascript,delete JSON.rawJSON'] : [];

test('Power BI MCP output: a decimal left unmasked in a rewritten JSON text keeps every digit (the audit input)', { skip: NEEDS_RAW_JSON }, () => {
  const result = redactOutput(DAX_TOOL, inText(AUDIT_TEXT));
  assert.equal(textOf(result), '{"[Total Sales]":123456789012345.6789,"Phone":"[PII:personal-field]"}');
  assert.equal(result.events[0].count, 1);
  assert.deepEqual(result.events[0].ids, ['personal-field']);
});

test('Power BI MCP output: every numeric literal form is written back as it came, named or unnamed, compact or indented', { skip: NEEDS_RAW_JSON }, () => {
  const kept = ['1.0', '1e21', '-0.5', '922337203685477.5807', '1E+5', '2.50e-3', '-0'];
  const named = [...kept, '9223372036854775807'].map((n, i) => `"[M${i}]":${n}`).join(',');
  const text = `{"Customer[Phone]":555,${named},"rows":[[${kept.join(',')}]]}`;
  const result = redactOutput(DAX_TOOL, inText(text));
  assert.equal(textOf(result), text.replace('555', '"[PII:personal-field]"'), 'only the phone changes');
  assert.equal(result.events[0].count, 1);
  const pretty = '{\n  "Phone": 555,\n  "[Fixed]": 922337203685477.5807,\n  "[Ratio]": 1.0\n}';
  assert.equal(textOf(redactOutput(DAX_TOOL, inText(pretty))), pretty.replace('555', '"[PII:personal-field]"'));
});

// 2026-10-16 decision: privacy before precision. Without JSON.rawJSON a text is still masked as JSON (field rules
// included) and written back, so a number a double cannot keep comes back rounded and the event says so.
test('older Node (no JSON.rawJSON): a text is masked as JSON all the same; a number a double cannot keep is rounded and logged', () => {
  const text = `{"[Total Sales]":123456789012345.6789,"Customer[Email]":"${EMAIL}","Phone":555}`;
  const result = redactOutput(DAX_TOOL, inText(text), undefined, AS_DOUBLES);
  // The field rule's id (personal-field) for both, so the text was read as JSON; the decimal is the double's.
  assert.equal(textOf(result), '{"[Total Sales]":123456789012345.67,"Customer[Email]":"[PII:personal-field]","Phone":"[PII:personal-field]"}');
  assert.equal(result.events.length, 1);
  assert.equal(result.events[0].count, 2, 'the lost precision is listed, not counted as a masked value');
  assert.deepEqual(result.events[0].ids.sort(), ['json-text-precision-lost', 'personal-field']);
  // The audit input, a 19-digit integer and a 4-decimal fixed value: the phone is masked, the number rounded.
  for (const [t, expected] of [
    [AUDIT_TEXT, '{"[Total Sales]":123456789012345.67,"Phone":"[PII:personal-field]"}'],
    ['{"[Order Key]":9223372036854775807,"Phone":555}', '{"[Order Key]":9223372036854776000,"Phone":"[PII:personal-field]"}'],
    ['{"[Amount]":922337203685477.5807,"Phone":555}', '{"[Amount]":922337203685477.6,"Phone":"[PII:personal-field]"}'],
  ]) {
    const r = redactOutput(DAX_TOOL, inText(t), undefined, AS_DOUBLES);
    assert.equal(textOf(r), expected, t);
    assert.deepEqual(r.events.map((e) => [e.count, e.ids]), [[1, ['personal-field', 'json-text-precision-lost']]], t);
  }
});

test('older Node (no JSON.rawJSON): numbers a double keeps give no precision id; nothing to mask logs nothing', () => {
  const text = '{"Phone":555,"[A]":1.0,"[B]":1E+5,"[C]":1e21,"[D]":-0.5,"[E]":0.1,"Note":"123456789012345.6789","Year":2026}';
  const result = redactOutput(DAX_TOOL, inText(text), undefined, AS_DOUBLES);
  // A double writes 1.0 and 1E+5 back with the same value in its own spelling; digits inside a string are no number.
  assert.equal(textOf(result), '{"Phone":"[PII:personal-field]","[A]":1,"[B]":100000,"[C]":1e+21,"[D]":-0.5,"[E]":0.1,"Note":"123456789012345.6789","Year":2026}');
  assert.deepEqual(result.events[0].ids, ['personal-field']);
  const untouched = redactOutput(DAX_TOOL, inText('{"[Total Sales]":123456789012345.6789}'), undefined, AS_DOUBLES);
  assert.equal(untouched.out, null);
  assert.deepEqual(untouched.events, [], 'no rewrite, so nothing rounded');
});

test('a secret in a JSON key and value pair is masked in the whole text before the text is read as JSON', () => {
  const secret = ['s3cr', 'etValue9'].join('');
  const result = redactOutput(DAX_TOOL, textBlock({ password: secret, 'Customer[Phone]': '0555' }));
  assert.deepEqual(updatedOf(result), textBlock({ password: '[REDACTED:password-json-field]', 'Customer[Phone]': '[PII:personal-field]' }));
  assert.deepEqual(result.events[0].ids.sort(), ['password-json-field', 'personal-field']);
});

// F1-48: the first line took a GitHub MCP tool for a tool without PII masking; any MCP tool has it now, so it uses WebFetch.
test('JSON in text is read as data only where PII masking applies (MCP output, or piiInAllTools)', () => {
  assert.equal(redactOutput('WebFetch', textBlock({ id: LONG_ID, email: 'x' })).out, null);
  const all = { redaction: { secrets: true, piiInMcpOutput: true, piiInAllTools: true } };
  assert.deepEqual(updatedOf(redactOutput('Bash', { stdout: JSON.stringify({ rows: [REPRO_ROW] }) }, all)), { stdout: JSON.stringify({ rows: [REPRO_MASKED] }) });
});

// 2026-10-16 audit of fe1dd6f: the audit log kept the first 200 characters of every MCP request with only secrets
// masked, so an impersonated user's e-mail, a personal column name or a query's literal values landed in tool-audit.jsonl.
const audit = (tool_name, tool_input, extra = {}) => runHook('audit-log.mjs', { hook_event_name: 'PostToolUse', tool_name, tool_input, ...extra });
const sha12 = (text) => createHash('sha256').update(text).digest('hex').slice(0, 12);

test('audit log: an MCP DAX query is logged as metadata (operation, connection, maxRows, length and hash), never its content', () => {
  const upn = ['x', 'example.com'].join('@');
  const query = 'EVALUATE ROW("Sales", CALCULATE([Total Sales], Customer[City] = "Contoso Town"))';
  const { audit: rows } = audit(DAX_TOOL, { request: { operation: 'Execute', connectionName: 'localhost:51234', maxRows: 10, query, impersonation: { userPrincipalName: upn } } });
  assert.equal(rows.length, 1);
  const line = JSON.stringify(rows[0]);
  assert.doesNotMatch(line, /@/, 'no impersonated identity');
  assert.doesNotMatch(line, /EVALUATE|Total Sales|Customer|Contoso|impersonation|userPrincipalName/i, 'no query text, column or literal');
  assert.deepEqual(rows[0].target, {
    server: 'powerbi-modeling', tool: 'dax_query_operations', operation: 'execute', connectionName: 'localhost:51234', maxRows: 10,
    query: { chars: query.length, sha256: sha12(query) },
  });
});

test('audit log: Copilot CLI MCP names are split too; definitions and free text under an operation key stay out', () => {
  const query = 'EVALUATE { 1 }';
  assert.deepEqual(audit('powerbi-modeling-mcp-dax_query_operations', { operation: 'Execute', query }).audit[0].target,
    { server: 'powerbi-modeling', tool: 'dax_query_operations', operation: 'execute', query: { chars: query.length, sha256: sha12(query) } });
  const create = audit('mcp__powerbi-modeling__measure_operations', { request: { operation: 'Create', definitions: [{ name: 'Customer Margin', expression: 'SUM ( Sales[Amount] )' }] } });
  assert.deepEqual(create.audit[0].target, { server: 'powerbi-modeling', tool: 'measure_operations', operation: 'create' });
  const shell = audit('mcp__terminal__run', { command: 'cat /home/someone/notes.txt' });
  assert.deepEqual(shell.audit[0].target, { server: 'terminal', tool: 'run', operation: '(other)' });
});

test('audit log: other tools keep their targets with e-mails and phone-like numbers masked; dates and paths stay', () => {
  const phone = ['+90', '555', '000', '00', '00'].join(' ');
  const bash = audit('Bash', { command: `grep -rn ${EMAIL} docs; echo ${phone}; git log --since "2026-10-16 12:00"` }).audit[0].target;
  assert.equal(bash, 'grep -rn [PII:email] docs; echo [PII:phone]; git log --since "2026-10-16 12:00"');
  assert.equal(audit('Read', { file_path: 'docs/notes.md' }).audit[0].target, 'docs/notes.md');
  const failed = audit('Bash', { command: 'x' }, { hook_event_name: 'PostToolUseFailure', error: `no such user ${EMAIL}` }).audit[0];
  assert.equal(failed.error, 'no such user [PII:email]');
  const note = runHook('audit-log.mjs', { hook_event_name: 'Notification', notification_type: 'x', message: `mail from ${EMAIL}` }).notifications[0];
  assert.equal(note.message, 'mail from [PII:email]');
});

// Audit 2026-10-19, F2-32: the audit log's secret masking (mask() runs redactSecrets on every text it keeps) and its
// InstructionsLoaded record lost their tests with session-and-gates.test.mjs: without redactSecrets in mask() a token
// reached tool-audit.jsonl in clear, and without the record instructions.jsonl stayed empty, with every test green. The
// routes below reach mask() with and without the command-line rules (redactCommandSecrets) in front of it.
const fakeGithubToken = () => ['gh', 'p_'].join('') + 'A1b2'.repeat(9); // built at run time: never a credential literal

test('audit log: a token is masked in a command, a search pattern, an error and a notification (F2-32)', () => {
  const token = fakeGithubToken();
  const rows = {
    command: audit('Bash', { command: `echo ${token}` }).audit[0],
    pattern: audit('Grep', { pattern: token, path: 'docs' }).audit[0],
    error: audit('WebFetch', { url: 'https://example.com/x' }, { hook_event_name: 'PostToolUseFailure', error: `401 with ${token}` }).audit[0],
    notification: runHook('audit-log.mjs', { hook_event_name: 'Notification', notification_type: 'x', message: `token ${token} expired` }).notifications[0],
  };
  for (const [route, row] of Object.entries(rows)) {
    assert.ok(row, `${route}: a row is written`);
    assert.ok(!JSON.stringify(row).includes(token.slice(4)), `${route}: no part of the token after its prefix is kept`);
  }
  assert.equal(rows.command.target, 'echo [REDACTED:github-token]');
  assert.equal(rows.pattern.target, '[REDACTED:github-token] @ docs');
  assert.equal(rows.error.error, '401 with [REDACTED:github-token]');
  assert.equal(rows.notification.message, 'token [REDACTED:github-token] expired');
});

test('audit log: InstructionsLoaded records which rule file entered the context, its type, why and its globs (F2-32)', () => {
  const rule = runHook('audit-log.mjs', (dir) => ({
    hook_event_name: 'InstructionsLoaded', file_path: path.join(dir, '.claude', 'rules', 'bi', 'tmdl.md'),
    memory_type: 'Project', load_reason: 'path_glob_match', globs: ['**/*.tmdl'],
  })).instructions;
  assert.equal(rule.length, 1);
  const { ts, ...row } = rule[0];
  assert.match(ts, /^\d{4}-\d{2}-\d{2}T/);
  assert.deepEqual(row, { event: 'InstructionsLoaded', session: 'redactio', file: '.claude/rules/bi/tmdl.md', type: 'Project', why: 'path_glob_match', globs: ['**/*.tmdl'] });
  // A file outside the project (the user's own memory) is not named; a load without globs records none.
  const user = runHook('audit-log.mjs', (dir) => ({
    hook_event_name: 'InstructionsLoaded', file_path: path.join(path.dirname(dir), 'elsewhere', 'CLAUDE.md'), memory_type: 'User', load_reason: 'session_start',
  })).instructions;
  assert.deepEqual(user.map(({ ts: _, ...r }) => r), [{ event: 'InstructionsLoaded', session: 'redactio', file: '(outside project)', type: 'User', why: 'session_start' }]);
});

// ---------------------------------------------------------------------------------------------------------------
// 2026-10-19 audit: F1-8 (private key body), F1-41 (password spellings), F1-42 (personal field words), F1-43 (passwords
// on a command line in the audit log), F1-48 (PII masking for every MCP server). Fake secrets are built at run time.

// F1-8: the private-key rule masked only the BEGIN line, so the base64 body of a key reached the model while the hook said
// the key was redacted. The rule spans the block now, also with the newlines escaped inside a JSON string.
const KEY_BODY = ['MIIEvQIBADANBgkqhkiG9w0BAQEFAASC', 'x'.repeat(40)].join('');
const keyMarker = (edge, kind = '') => ['-----', edge, ' ', kind, 'PRIVATE KEY', '-----'].join('');
const keyBlock = (kind = '') => `${keyMarker('BEGIN', kind)}\n${KEY_BODY}\n${keyMarker('END', kind)}`;
const SERVICE_EMAIL = ['svc', 'example.com'].join('@');

test('a private key in a Bash result is masked from its BEGIN to its END marker; the lines around it stay (F1-8)', () => {
  const result = callTool('Bash', { command: 'cat key.pem' }, shellOf(`key follows\n${keyBlock()}\ndone\n`));
  assert.deepEqual(updatedOf(result), shellOf('key follows\n[REDACTED:private-key]\ndone\n'));
  assert.deepEqual(result.events.map((e) => [e.count, e.ids]), [[1, ['private-key']]]);
  assert.match(result.out.hookSpecificOutput.additionalContext, /1 sensitive value\(s\)/);
});

test('a service account key read from a JSON file is masked whole and the file text stays valid JSON (F1-8)', () => {
  const content = JSON.stringify({ type: 'service_account', private_key: `${keyBlock()}\n`, client_email: SERVICE_EMAIL });
  const result = callTool('Read', { file_path: 'service-account.json' }, readOf('service-account.json', content));
  const masked = updatedOf(result).file.content;
  assert.doesNotMatch(masked, /MIIEvQ|BEGIN|END/);
  assert.deepEqual(JSON.parse(masked), { type: 'service_account', private_key: '[REDACTED:private-key]\n', client_email: SERVICE_EMAIL });
  assert.deepEqual(result.events.map((e) => [e.count, e.ids]), [[1, ['private-key']]]);
});

test('every private key label is masked whole, two blocks apart; a certificate and a public key stay (F1-8)', () => {
  for (const kind of ['RSA ', 'EC ', 'DSA ', 'OPENSSH ', 'ENCRYPTED ']) {
    assert.equal(redactSecrets(`a\r\n${keyBlock(kind).replace(/\n/g, '\r\n')}\r\nb`).text, 'a\r\n[REDACTED:private-key]\r\nb', kind);
  }
  const pgp = ['-----BEGIN PGP ', 'PRIVATE KEY BLOCK-----\nVersion: x\n\n', KEY_BODY, '\n-----END PGP ', 'PRIVATE KEY BLOCK-----'].join('');
  assert.equal(redactSecrets(`${pgp}\nmid\n${keyBlock('RSA ')}`).text, '[REDACTED:private-key]\nmid\n[REDACTED:private-key]');
  const others = ['CERTIFICATE', 'PUBLIC KEY'].map((kind) => `-----BEGIN ${kind}-----\n${KEY_BODY}\n-----END ${kind}-----`).join('\n');
  assert.equal(redactSecrets(others).text, others);
});

test('a private key cut off before its END marker is masked to the end of the text (F1-8)', () => {
  assert.equal(redactSecrets(`before\n${keyMarker('BEGIN')}\n${KEY_BODY}\nlast line`).text, 'before\n[REDACTED:private-key]');
  const cut = callTool('Bash', { command: 'head -c 100 key.pem' }, shellOf(`${keyMarker('BEGIN')}\n${KEY_BODY.slice(0, 30)}`));
  assert.deepEqual(updatedOf(cut), shellOf('[REDACTED:private-key]'));
});

test('audit log: a private key in an error row is masked whole (F1-8)', () => {
  const failed = audit('Bash', { command: 'cat key.pem' }, { hook_event_name: 'PostToolUseFailure', error: `Exit code 1\n${keyBlock()}\n` }).audit[0];
  assert.equal(failed.error, 'Exit code 1\n[REDACTED:private-key]\n');
});

// F1-41: password-assignment skipped an ODBC value in braces, a quoted value that holds ";" and a value with spaces;
// password-json-field refused spaces. The words that spell a password are joined here, never written whole.
const PW_KEY = ['Pass', 'word'].join('');
const PWD_KEY = ['Pw', 'd'].join('');
const SECRET = ['S3cr3t', 'Pa55'].join('');
const PHRASE = ['correct horse', ' battery staple'].join('');

test('a password in braces, in quotes with ";", with spaces or in a JSON field is masked whole (F1-41)', () => {
  const cases = [
    [`Driver={ODBC Driver 18 for SQL Server};Server=db;Uid=app;${PWD_KEY}={${SECRET};w0rd};`, `Driver={ODBC Driver 18 for SQL Server};Server=db;Uid=app;${PWD_KEY}={[REDACTED:password-assignment]};`],
    [`${PWD_KEY}={ab}}cd1234}`, `${PWD_KEY}={[REDACTED:password-assignment]}`],
    [`Server=db;Uid=app;${PW_KEY}=${PHRASE};Encrypt=yes`, `Server=db;Uid=app;${PW_KEY}=[REDACTED:password-assignment];Encrypt=yes`],
    [`Server=db; Uid=app; ${PW_KEY} = ${PHRASE}`, `Server=db; Uid=app; ${PW_KEY} = [REDACTED:password-assignment]`],
    [`Server=db;${PW_KEY}="ab;cdefgh12";Encrypt=yes`, `Server=db;${PW_KEY}="[REDACTED:password-assignment]";Encrypt=yes`],
    [`${PW_KEY}='abcd;efgh 1234'`, `${PW_KEY}='[REDACTED:password-assignment]'`],
    [`${PWD_KEY}="my pass word 1"`, `${PWD_KEY}="[REDACTED:password-assignment]"`],
    [`{"${PW_KEY.toLowerCase()}": "${PHRASE}"}`, '{"password": "[REDACTED:password-json-field]"}'],
    [`{"client_secret": "ab\\"cd efgh"}`, '{"client_secret": "[REDACTED:password-json-field]"}'],
  ];
  for (const [text, expected] of cases) assert.equal(redactSecrets(text).text, expected, text);
});

test('a password in braces is masked in a tool result and the audit log keeps no part of it (F1-41)', () => {
  const connection = `Driver={ODBC Driver 18 for SQL Server};Server=db;Uid=app;${PWD_KEY}={${SECRET};w0rd};`;
  const result = callTool('Bash', { command: 'cat odbc.txt' }, shellOf(connection));
  assert.equal(updatedOf(result).stdout, `Driver={ODBC Driver 18 for SQL Server};Server=db;Uid=app;${PWD_KEY}={[REDACTED:password-assignment]};`);
  assert.deepEqual(result.events.map((e) => [e.count, e.ids]), [[1, ['password-assignment']]]);
  const row = audit('Bash', { command: `python tools/q.py --cs "${connection}"` }).audit[0];
  assert.doesNotMatch(row.target, /S3cr3t|w0rd/);
  assert.match(row.target, /Driver=\{ODBC Driver 18 for SQL Server\};Server=db;Uid=app;/);
});

test('placeholders, variables and a sentence about a password are not password values (F1-41)', () => {
  for (const text of [
    `Server=db;${PWD_KEY}=\${DB_PASSWORD};`, `Server=db;${PWD_KEY}={{db_password}};`, `Server=db;${PWD_KEY}={<password>};`, `Server=db;${PWD_KEY}=<your password>;`,
    `Server=db;${PWD_KEY}=%DB_PASSWORD%;`, `Server=db;${PWD_KEY}={0};`, `Server=db;${PWD_KEY}=***;`, `Server=db;${PWD_KEY}="";Name="abcdefgh"`,
    `Server=db;${PWD_KEY}="\${DB_PASSWORD}";`, `Server=db;${PWD_KEY}='<value>';`, `{"password": "", "pwd": "***", "secret": "<value>", "password": "\${VAR}", "client_secret": "   "}`,
    `Never write ${PW_KEY}=... in M code (no ${PW_KEY}=, ${PWD_KEY}=, ApiKey)`, `- [ ] No credentials in M (\`${PW_KEY}=\`, \`${PWD_KEY}=\`, \`ApiKey\`)`,
  ]) assert.equal(redactSecrets(text).text, text, text);
});

test('an unquoted value with spaces is read as one only in a connection string; a command keeps its words (F1-41)', () => {
  // After an earlier ";" it runs to the next ";" or the end of the line.
  assert.equal(redactSecrets(`Server=db;${PW_KEY}=${PHRASE}\nnext line`).text, `Server=db;${PW_KEY}=[REDACTED:password-assignment]\nnext line`);
  // Anywhere else the value ends at the first space, as before: an environment prefix before a command, a sentence, a flag.
  assert.equal(redactSecrets(`DB_${PW_KEY.toUpperCase()}=abc123 npm run migrate; echo ok`).text, 'DB_PASSWORD=[REDACTED:password-assignment] npm run migrate; echo ok');
  assert.equal(redactSecrets(`${PW_KEY.toLowerCase()}=${SECRET} --flag`).text, 'password=[REDACTED:password-assignment] --flag');
  assert.equal(redactSecrets(`Server=db;${PW_KEY}=${SECRET} Database=sales;`).text, `Server=db;${PW_KEY}=[REDACTED:password-assignment] Database=sales;`);
});

test('a password that spells part of its own key is still the text replaced (F1-41)', () => {
  assert.equal(redactSecrets(`${PW_KEY}=word`).text, `${PW_KEY}=[REDACTED:password-assignment]`);
  assert.equal(redactSecrets(`{"${PW_KEY.toLowerCase()}": "word"}`).text, '{"password": "[REDACTED:password-json-field]"}');
});

test('findSecrets reports the braces form and the spaces form with the line they stand on (F1-41)', () => {
  const text = `ok\nDriver={SQL Server};${PWD_KEY}={${SECRET};w0rd}\nServer=db;${PW_KEY}=${PHRASE};`;
  assert.deepEqual(findSecrets(text).map((h) => [h.id, h.line]), [['password-assignment', 2], ['password-assignment', 3]]);
});

// F1-42: the redactor's personal-field words missed the Turkish phone words and ignored sources.sqlRead.personalColumns,
// which the guard treats as personal; a query the guard asked about and the user approved returned those values.
function personalFieldsOf(keys, config, value = '05321234567') {
  const row = Object.fromEntries([...keys.map((k) => [k, value]), ['[Total]', 100]]);
  const { out } = redactOutput(DAX_TOOL, { rows: [row] }, config);
  const masked = out ? out.hookSpecificOutput.updatedToolOutput.rows[0] : row;
  assert.equal(masked['[Total]'], 100, 'the total stays a number');
  return keys.filter((k) => masked[k] === '[PII:personal-field]');
}
const bracketName = (key) => key.slice(key.indexOf('[') + 1, -1);

test('Turkish and European words for a phone, e-mail, identity, address, birth date and passport are personal fields (F1-42)', () => {
  const identifiers = ['Musteri[Telefon]', 'Musteri[Tel No]', 'Musteri[Cep Telefonu]', 'Musteri[TelefonNo]', 'Müşteri[Telefon Numarası]', 'Musteri[E-Posta]', 'Musteri[EPosta]',
    'Musteri[Adres]', 'Musteri[Doğum Tarihi]', 'Musteri[Pasaport No]', 'Musteri[TC Kimlik No]', 'Musteri[TC]', 'Kunde[Telefonnummer]', 'Kunde[Geburtsdatum]', 'Client[Courriel]',
    'Client[Date Naissance]', 'Cliente[Correo]', 'Cliente[Fecha Nacimiento]', 'Cliente[Indirizzo]', 'Cliente[Data Nascita]', 'Customer[Address]'];
  assert.deepEqual(personalFieldsOf(identifiers), identifiers);
  // The guard asks about every one of them, so the redactor and the guard agree on what the user approved.
  for (const key of identifiers) assert.equal(personalColumnName(bracketName(key)), true, key);
});

test('a person\'s name, a salary, a product and a total are no personal field (F1-42)', () => {
  // The guard asks about names and a salary too (and about Smartphone, which it reads by substring); the redactor masks the
  // values of identifier fields only: a name stays readable, a salary is not an identifier, a whole word decides.
  const readable = ['Musteri[Musteri Adi]', 'Musteri[Ad]', 'Musteri[Soyad]', 'Customer[Customer Name]', 'Customer[First Name]', 'Kunde[Vorname]', 'Calisan[Maas]', 'Employee[Salary]'];
  for (const key of readable) assert.equal(personalColumnName(bracketName(key)), true, `the guard asks about ${key}`);
  const other = ['Product[Smartphone]', 'Hotel[Rooms]', 'Telekom[Sales]', 'Chip[Intel]', 'Customer[City]', 'Product[Product Name]'];
  assert.deepEqual(personalFieldsOf([...readable, ...other]), []);
});

test('the personal columns of the SQL read switch are personal fields, by the column name in the brackets (F1-42)', () => {
  const config = { sources: { sqlRead: { mode: 'on', personalColumns: ['LoyaltyCode', 'Sicil No', 'Müşteri Kodu', 'FullName'] } } };
  const keys = ['Musteri[LoyaltyCode]', 'Personel[Sicil No]', 'Personel[SicilNo]', 'Musteri[Musteri Kodu]', 'Musteri[Full Name]', 'Musteri[City]', 'Musteri[Loyalty Code Group]'];
  assert.deepEqual(personalFieldsOf(keys, config), keys.slice(0, 5));
  // Without the list only the built-in words count: a name of a person is not one, however the guard lists it.
  assert.deepEqual(personalFieldsOf(keys), []);
  // A built-in column of the switch that is no name counts without any entry.
  assert.deepEqual(personalFieldsOf(['Customer[Street]', 'Customer[Credit Card]', 'Login[Password Hash]']), ['Customer[Street]', 'Customer[Credit Card]', 'Login[Password Hash]']);
});

test('a field named Password is a personal field of an MCP answer, and a value a secret rule masked keeps its token (F1-42)', () => {
  const rows = [{ Password: SECRET, PasswordHash: 'abc123', Name: 'Contoso' }];
  assert.deepEqual(updatedOf(redactOutput('mcp__mssql__read_data', { rows })).rows[0], { Password: '[PII:personal-field]', PasswordHash: '[PII:personal-field]', Name: 'Contoso' });
  const text = redactOutput('mcp__mssql__read_data', textBlock({ [PW_KEY.toLowerCase()]: SECRET }));
  assert.deepEqual(updatedOf(text), textBlock({ password: '[REDACTED:password-json-field]' }));
  assert.deepEqual(text.events[0].ids, ['password-json-field']);
});

test('a count or a total of a personal field is no personal field, in Turkish too (F1-42)', () => {
  const row = { 'Musteri[Telefon Sayisi]': 4242, 'Musteri[Telefon]': 5321234567, '[Toplam E-Posta]': 17, '[Customers with Phone]': 99, 'Musteri[Adres]': 'Atlas Sokak 1' };
  const { out } = redactOutput(DAX_TOOL, { rows: [row] });
  assert.deepEqual(updatedOf({ out }).rows[0], { ...row, 'Musteri[Telefon]': '[PII:personal-field]', 'Musteri[Adres]': '[PII:personal-field]' });
});

// F1-43: the audit log masked only SECRET_RULES, which knew no password on a command line, so a command the user approved
// (mysql -p<password>) was written to tool-audit.jsonl as typed, and the log is meant to be shared.
const CMD_SECRET = ['S3cr3t', 'Pa55w0rd'].join('');

test('audit log: a password on a command line is masked (F1-43)', () => {
  const cases = [
    ['Bash', `mysql -h db -u app -p${CMD_SECRET} -e "select 1"`, 'mysql -h db -u app -p[REDACTED:db-client-password] -e "select 1"'],
    ['PowerShell', `$s = ConvertTo-SecureString '${CMD_SECRET}' -AsPlainText -Force`, "$s = ConvertTo-SecureString '[REDACTED:secure-string]' -AsPlainText -Force"],
    ['Bash', `python tools/q.py --cs "Driver={ODBC Driver 18};Server=db;Uid=app;${PWD_KEY}={${CMD_SECRET}}"`, `python tools/q.py --cs "Driver={ODBC Driver 18};Server=db;Uid=app;${PWD_KEY}={[REDACTED:password-assignment]}"`],
    ['Bash', `sqlcmd -S . -U sa -P ${CMD_SECRET} -Q "select 1"`, 'sqlcmd -S . -U sa -P [REDACTED:db-client-password] -Q "select 1"'],
    ['Bash', `git clone https://app:${CMD_SECRET}@git.example.com/r.git`, 'git clone https://app:[REDACTED:url-credentials]@git.example.com/r.git'],
    ['Bash', `mongosh --host db --username app --password ${CMD_SECRET}`, 'mongosh --host db --username app --password [REDACTED:password-option]'],
    ['Bash', `docker login -u app -p ${CMD_SECRET} registry.example.com`, 'docker login -u app -p [REDACTED:db-client-password] registry.example.com'],
    ['PowerShell', `Invoke-Sqlcmd -ServerInstance . -Username sa -Password ${CMD_SECRET} -Query "select 1"`, 'Invoke-Sqlcmd -ServerInstance . -Username sa -Password [REDACTED:password-option] -Query "select 1"'],
    ['PowerShell', `Invoke-Sqlcmd -ServerInstance . -Username sa -Password '${CMD_SECRET}' -Query "select 1"`, `Invoke-Sqlcmd -ServerInstance . -Username sa -Password '[REDACTED:password-option]' -Query "select 1"`],
  ];
  for (const [tool, command, expected] of cases) {
    const row = audit(tool, { command }).audit[0];
    assert.equal(row.target, expected, command);
    assert.doesNotMatch(JSON.stringify(row), /S3cr3t|Pa55w0rd/);
  }
});

test('audit log: a command with no password in it is logged as typed (F1-43)', () => {
  for (const command of ['mkdir -p dir', 'grep -P "a+" notes.txt', 'mysql -u app -p -e "select 1"', 'mysql -P 3306 -h db', 'psql -h db -p 5432 -U app', 'ssh -p 2222 host',
    'docker login --password-stdin -u app', 'docker run -p 8080:80 img', 'Invoke-Sqlcmd -Password $cred -Query x', 'sqlcmd -S . -E -Q "select 1"', 'tool --password $PW']) {
    assert.equal(audit('Bash', { command }).audit[0].target, command, command);
  }
});

test('command-line passwords in any text: a placeholder, a variable or the option of another program is left alone (F1-43)', () => {
  const SAME = ['ro', 'ot'].join(''); // a user name that is also the password: the user name is not the text replaced
  const SPACED = ['my pass', ' 1'].join('');
  const SEMICOLON = ['my pass', ';1'].join('');
  const SVC = ['svc', 'user'].join('');
  const masked = [
    [`mysql -u root -p${CMD_SECRET}`, 'mysql -u root -p[REDACTED:db-client-password]'],
    [`mysql -u ${SAME} -p${SAME}`, `mysql -u ${SAME} -p[REDACTED:db-client-password]`],
    [`"C:/Program Files/MySQL/bin/mysql.exe" -u root -p${CMD_SECRET}`, '"C:/Program Files/MySQL/bin/mysql.exe" -u root -p[REDACTED:db-client-password]'],
    [`mysqldump -u app -p'${SPACED}' db | gzip`, `mysqldump -u app -p'[REDACTED:db-client-password]' db | gzip`],
    [`SQLCMD -S . -P "${SEMICOLON}" -Q x`, 'SQLCMD -S . -P "[REDACTED:db-client-password]" -Q x'],
    [`bcp t out f -S . -U sa -P${CMD_SECRET} -c`, 'bcp t out f -S . -U sa -P[REDACTED:db-client-password] -c'],
    [`'${CMD_SECRET}' | ConvertTo-SecureString -AsPlainText -Force`, "'[REDACTED:secure-string]' | ConvertTo-SecureString -AsPlainText -Force"],
    [`ConvertTo-SecureString -String "${CMD_SECRET}" -AsPlainText -Force`, 'ConvertTo-SecureString -String "[REDACTED:secure-string]" -AsPlainText -Force'],
    [`az sql server create --admin-password '${CMD_SECRET}'`, "az sql server create --admin-password '[REDACTED:password-option]'"],
    [`redis://:${CMD_SECRET}@host:6379/0`, 'redis://:[REDACTED:url-credentials]@host:6379/0'],
    [`postgres://${SVC}:${SVC}@db/sales`, `postgres://${SVC}:[REDACTED:url-credentials]@db/sales`],
  ];
  for (const [text, expected] of masked) assert.equal(redactSecrets(text).text, expected, text);
  for (const text of [
    'mysql -u app -p -e "select 1"', 'mysql -P3306 -h db', 'mysql -p$MYSQL_PWD', 'mysql -p"$PW" db', 'mysql -p<password>', 'mysql -ppassword', 'mysql -pYourPassword1', 'mysql -pPASSWORD', `mysql -e "select '-pfoo123'"`,
    'psql -p5432 db', 'pgcli -p5432 db', 'mkdir -p dir', 'ssh -p 2222 host', 'echo mysql; ls -pfoo123', 'mysql_secure_installation -pfoo12345',
    'sqlcmd -S . -p1 -E', 'sqlcmd -S . -P $pw', 'sqlcmd -P x', 'sqlcmd -S . -P <password>', 'sqlcmd -S . -P -Q "x"', 'sqlcmd -S . -P %SQLPWD%',
    'ConvertTo-SecureString $env:PW -AsPlainText -Force', 'ConvertTo-SecureString "$pw" -AsPlainText -Force', "ConvertTo-SecureString '<password>' -AsPlainText", 'ConvertTo-SecureString converts a string',
    'tool --password', 'tool --password option', 'tool --password "<value>"', 'tool --no-password', 'Invoke-Sqlcmd -Password $cred', 'use the -Password parameter', 'docker login --password-stdin',
    'postgres://user:password@localhost:5432/db', `https://example.com:8080/path?x=${['a', 'b.example.com'].join('@')}`, 'https://user@host/', 'https://user:${TOKEN}@host/', 'https://user:<token>@host/', 'ssh://git@host:22/r.git',
  ]) assert.equal(redactSecrets(text).text, text, text);
});

test('every secret rule is global (findSecrets reads them with matchAll) and a long line costs a fixed amount per word (F1-41, F1-43)', () => {
  assert.ok(SECRET_RULES.length > 0 && SECRET_RULES.every((rule) => rule.re.flags.includes('g')), 'matchAll throws on a rule without the g flag');
  // A program name, a URL scheme or an opening brace with no closing text used to start a scan to the end of the line.
  const lines = ['mysql ', 'sqlcmd -S ', 'a.b', 'Pwd={ab ', 'docker login ', 'http://u:abcd '].map((word) => word.repeat(Math.ceil(262144 / word.length)));
  const start = Date.now();
  for (const line of lines) {
    redactSecrets(line);
    redactCommandSecrets(line);
    findSecrets(line);
  }
  assert.ok(Date.now() - start < 8000, `${Date.now() - start} ms for six lines of 256 KB`);
});

test('a password after a space is the audit log\'s to mask: the command rules do not run on prose or a tool result (F1-43)', () => {
  assert.equal(redactCommandSecrets(`mongosh -u app -p ${CMD_SECRET} db`).text, 'mongosh -u app -p [REDACTED:db-client-password] db');
  assert.equal(redactCommandSecrets('tool --password option').text, 'tool --password [REDACTED:password-option]', 'any word after the option in a command');
  assert.equal(redactSecrets('tool --password option').text, 'tool --password option', 'but not in a document, a prompt or a tool result');
  for (const command of ['psql --password -h db', 'docker login --password-stdin -u x', 'mongosh -p', 'docker run -p 8080:80 img', 'tool --password $PW']) {
    assert.equal(redactCommandSecrets(command).text, command, command);
  }
  const result = callTool('Bash', { command: 'ps' }, shellOf(`mongosh -u app -p ${CMD_SECRET} db`));
  assert.equal(result.out, null, 'a tool result keeps the text rules only');
});

// F1-48: PII masking of MCP output was documented for MCP output in general (redaction.piiInMcpOutput) but ran for the
// Power BI MCP server only, so an e-mail address in a SQL MCP server's answer reached the model.
test('PII masking covers the answer of every MCP server, whatever name the host gives its tool (F1-48)', () => {
  const rows = (email) => [{ type: 'text', text: JSON.stringify([{ Name: 'Contoso', Email: email }]) }];
  for (const tool of ['mcp__mssql__read_data', 'mcp__github__get_issue', 'jira-mcp-get_issue', 'mcp_sqlserver_read_data', DAX_TOOL]) {
    const result = callTool(tool, { query: 'SELECT TOP 5 Name, Email FROM dbo.Customer' }, rows(EMAIL));
    assert.deepEqual(updatedOf(result), rows('[PII:personal-field]'), tool);
    assert.deepEqual(result.events.map((e) => [e.tool, e.count, e.ids]), [[tool, 1, ['personal-field']]], tool);
  }
  // Text outside a field the answer names (an error, a note) gets the text rules.
  assert.deepEqual(updatedOf(callTool('mcp__mssql__read_data', {}, [{ type: 'text', text: `contact ${EMAIL}` }])), [{ type: 'text', text: 'contact [PII:email]' }]);
});

test('PII masking of MCP output is off with redaction.piiInMcpOutput false, and never reaches a tool that is no MCP tool (F1-48)', () => {
  const answer = [{ type: 'text', text: JSON.stringify([{ Email: EMAIL }]) }];
  const off = { redaction: { secrets: true, piiInMcpOutput: false, piiInAllTools: false } };
  assert.equal(callTool('mcp__mssql__read_data', {}, answer, off).out, null);
  assert.equal(callTool('mcp__powerbi-modeling__dax_query_operations', {}, answer, off).out, null);
  for (const tool of ['Bash', 'WebFetch', 'Read', 'mcp-like-tool']) assert.equal(callTool(tool, {}, answer).out, null, tool);
});

// Audit 2026-10-31, second round (A3): a value under a key the secret rules read (adminPassword, client_secret,
// aws_secret_access_key) was masked in a JSON text and in an MCP text block, but a direct object response kept it: the
// object walk judged each value without its key, and no updated output came back.
const KEYED = {
  adminPassword: ['Adm1n', 'Pa55', '2026'].join('-'),
  client_secret: ['cl1ent', 'S3cr3t', 'Value42'].join(''),
  aws_secret_access_key: ['Zx9', 'Lm2Q'.repeat(9), 'w'].join(''),
};

test('audit 2026-10-31 A3: a secret under a secret-named key is masked in a direct object as in a JSON text and an MCP text block', () => {
  const asText = redactOutput('Bash', { stdout: JSON.stringify(KEYED) });
  const expected = JSON.parse(updatedOf(asText).stdout);
  assert.deepEqual(expected, { adminPassword: '[REDACTED:password-field]', client_secret: '[REDACTED:password-json-field]', aws_secret_access_key: '[REDACTED:credential-assignment]' });
  const inBlock = redactOutput('mcp__vault__get_secret', textBlock(KEYED));
  assert.deepEqual(JSON.parse(updatedOf(inBlock).content[0].text), expected, 'MCP content[].text holding JSON');
  for (const tool of ['mcp__vault__get_secret', 'WebFetch', 'Bash', DAX_TOOL]) {
    const direct = redactOutput(tool, { ...KEYED });
    assert.deepEqual(updatedOf(direct), expected, `${tool}: the direct object`);
    assert.deepEqual([...direct.events[0].ids].sort(), [...asText.events[0].ids].sort(), `${tool}: the same rule ids`);
    assert.equal(direct.events[0].count, 3, tool);
  }
  // Nested in an object, next to other fields; an item of an array is judged as its own object's member.
  const nested = redactOutput('mcp__vault__get_secret', { result: { config: { ...KEYED, name: 'Contoso' }, list: [{ client_secret: KEYED.client_secret }] } });
  assert.deepEqual(updatedOf(nested), { result: { config: { ...expected, name: 'Contoso' }, list: [{ client_secret: expected.client_secret }] } });
});

test('audit 2026-10-31 A3: values under other keys are untouched in a direct object; a setting or a label under a secret key stays', () => {
  const plain = { name: 'Contoso', note: KEYED.adminPassword, comment: KEYED.client_secret, showPassword: 'Show', resetPassword: null, hasSecret: true, count: 3 };
  for (const tool of ['WebFetch', 'mcp__vault__get_secret']) assert.equal(redactOutput(tool, plain).out, null, tool);
  // The text path agrees: the same members as a JSON text are not masked either.
  assert.equal(redactOutput('Bash', { stdout: JSON.stringify(plain) }).out, null);
  // A value a rule masked already keeps its one token, counted once.
  const masked = redactOutput('WebFetch', { client_secret: '[REDACTED:password-json-field]' });
  assert.equal(masked.out, null);
});
