// Follow-up audit, group W2-R (2026-10-19): secret and PII masking (hooks/lib/policy.mjs, hooks/post-tool-redact.mjs,
// the error row of hooks/audit-log.mjs) and the DAX personal-name check.
// F1-71: without JSON.rawJSON an unnamed 17-19 digit card in a JSON text was read as a rounded double and missed the checksum.
// F1-72: the e-mail rule was quadratic on a long run without "@": 200 KB of MCP text passed the 20 s hook timeout unmasked.
// F1-76: aws_secret_access_key, camelCase *Password keys, YAML "password:" and Python dict keys were neither masked nor blocked.
// F1-129: past nesting depth 12 a subtree of a tool output was returned unjudged.
// Residual gaps of the PR #15 groups: command-line passwords of curl, redis-cli, sqlpackage, dtexec and PowerShell's
// -Pass abbreviations; an unquoted value with spaces in the first pair of a connection string; a quoted value inside a
// JSON-escaped string; -pSecretSauce read as a placeholder; findSecrets' line numbers costing O(n * hits); and
// Employee[Manager Name] passing the DAX check.
// Fake values only, built at run time (README, Changing the pack).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyzeMcpCall, findSecrets, redactCommandSecrets, redactPii, redactSecrets } from '../hooks/lib/policy.mjs';

const hooks = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'hooks');
const DAX_TOOL = 'mcp__powerbi-modeling__dax_query_operations';

/** Runs a hook as Claude Code does (stdin JSON) in a fresh project folder; returns its answer, its log lines and its time. */
function runHook(script, payload, nodeArgs = []) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-w2r-'));
  try {
    const env = { ...process.env, CLAUDE_PROJECT_DIR: dir };
    delete env.BI_HARNESS_HOST;
    const start = Date.now();
    const r = spawnSync(process.execPath, [...nodeArgs, path.join(hooks, script)], { input: JSON.stringify({ session_id: 'w2r-test', ...payload }), env, encoding: 'utf8' });
    const ms = Date.now() - start;
    assert.equal(r.status, 0, r.stderr);
    assert.doesNotMatch(r.stderr, /hook error/);
    const log = (name) => {
      const file = path.join(dir, '.claude', 'logs', name);
      return fs.existsSync(file) ? fs.readFileSync(file, 'utf8').trim().split('\n').map((l) => JSON.parse(l)) : [];
    };
    return { out: r.stdout.trim() ? JSON.parse(r.stdout) : null, events: log('security-events.jsonl'), audit: log('tool-audit.jsonl'), ms };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}
const redactOutput = (tool_name, tool_response, nodeArgs, tool_input = {}) =>
  runHook('post-tool-redact.mjs', { hook_event_name: 'PostToolUse', tool_name, tool_input, tool_response }, nodeArgs);
const updatedOf = (result) => result.out?.hookSpecificOutput?.updatedToolOutput;
const inText = (text) => [{ type: 'text', text }];
const textOf = (result) => updatedOf(result)?.[0]?.text;
// The older-Node branch on any Node (redaction.test.mjs: AS_DOUBLES): without JSON.rawJSON the hook reads doubles.
const AS_DOUBLES = typeof JSON.rawJSON === 'function' ? ['--import', 'data:text/javascript,delete JSON.rawJSON'] : [];

const EMAIL = ['someone', 'example.com'].join('@');
const PW = ['Tr0ub4', 'dor3x'].join('');
const PHRASE = ['correct horse', ' battery staple'].join('');
const PW_KEY = ['Pass', 'word'].join('');

/** A Luhn-valid digit string built at run time (no real card number in the repository). */
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

// ---------------------------------------------------------------- F1-72: the e-mail rule in linear time

test('F1-72: the e-mail rule reads a long run without "@" in linear time and still masks an address after it', () => {
  const runs = [
    'x' + '-a'.repeat(50000), // the audit's input: 100 KB of word characters and dashes
    'a.'.repeat(50000), // a dotted run
    encodeURIComponent('é'.repeat(15000)), // a URL-encoded text (%C3%A9...)
    `x${'@'}${'b.'.repeat(50000)}`, // a domain of 50,000 labels and no top-level domain
  ];
  const start = Date.now();
  for (const run of runs) {
    const { text, ids } = redactPii(`${run} ${EMAIL}`);
    assert.ok(text.endsWith(' [PII:email]'), `${run.slice(0, 12)}...: the address after the run is masked`);
    assert.deepEqual(ids, ['email']);
  }
  const ms = Date.now() - start;
  assert.ok(ms < 1500, `${ms} ms for four runs of 100 KB (quadratic: about 15 s)`);
});

test('F1-72: the e-mail rule keeps its matches: dots, plus, percent, underscore and dash in the local part, an address in brackets', () => {
  const at = '@';
  for (const [text, expected] of [
    [`first.last${at}example.com`, '[PII:email]'],
    [`john_doe+tag${at}mail.example.co.uk`, '[PII:email]'],
    [`mailto:a.b%c${at}example.com`, 'mailto:[PII:email]'],
    [`<x-y${at}example.com>, (z${at}example.org)`, '<[PII:email]>, ([PII:email])'],
    [`owner: ${'a'.repeat(70)}${at}example.com.`, 'owner: [PII:email].'],
  ]) assert.equal(redactPii(text).text, expected, text);
  for (const text of [`user${at}localhost`, `a${at}b.c`, `${at}example.com`, 'no address here']) assert.equal(redactPii(text).text, text, text);
});

test('F1-72: 200 KB of MCP text is masked within the hook timeout', () => {
  const result = redactOutput(DAX_TOOL, inText(`${'x' + '-a'.repeat(100000)} ${EMAIL}`));
  assert.ok(textOf(result)?.endsWith(' [PII:email]'), 'the address is masked');
  assert.ok(result.ms < 5000, `${result.ms} ms (the hook's timeout is 20 s; quadratic: about 21 s)`);
});

// ---------------------------------------------------------------- F1-71: older Node, a card longer than a double holds

test('F1-71: older Node (no JSON.rawJSON): an unnamed 17-19 digit card in a JSON text is checked digit for digit', () => {
  for (const length of [17, 18, 19]) {
    const card = luhnValid('6011123412341234', length);
    assert.ok(String(Number(card)) !== card, `${length} digits: a double cannot keep them, the case the audit found`);
    const result = redactOutput(DAX_TOOL, inText(`{"ids":[${card}]}`), AS_DOUBLES);
    assert.equal(textOf(result), '{"ids":["[PII:payment-card]"]}', `${length} digits`);
    assert.ok(result.events[0].ids.includes('payment-card'));
  }
  // The audit's second input: a 17-digit card next to a personal field, both masked.
  const card17 = luhnValid('4000123412341234', 17);
  const both = redactOutput(DAX_TOOL, inText(`{"ids":[${card17}],"Customer[Email]":"x"}`), AS_DOUBLES);
  assert.equal(textOf(both), '{"ids":["[PII:payment-card]"],"Customer[Email]":"[PII:personal-field]"}');
});

test('F1-71: older Node: a long number under a named field, or one that fails the checksum, is kept as the double (documented rounding)', () => {
  const card = luhnValid('4000123412341', 19);
  const notCard = card.slice(0, 18) + ((Number(card[18]) + 1) % 10);
  const text = `{"[Total Sales]":${card},"ids":[${notCard}],"Phone":555}`;
  const result = redactOutput(DAX_TOOL, inText(text), AS_DOUBLES);
  assert.equal(textOf(result), `{"[Total Sales]":${Number(card)},"ids":[${Number(notCard)}],"Phone":"[PII:personal-field]"}`);
  assert.deepEqual(result.events[0].ids.sort(), ['json-text-precision-lost', 'personal-field']);
});

// ---------------------------------------------------------------- F1-129: no subtree passes unjudged

test('F1-129: an e-mail nested deeper than the cap (13, 14 and 30 levels) in a JSON text is masked', () => {
  for (const depth of [13, 14, 30]) {
    let value = { note: `owner ${EMAIL}` };
    for (let i = 0; i < depth; i++) value = { a: value };
    const text = textOf(redactOutput(DAX_TOOL, inText(JSON.stringify(value))));
    assert.ok(text, `${depth} levels: the text is rewritten`);
    assert.ok(!text.includes(EMAIL), `${depth} levels: the address is gone`);
    assert.match(text, /owner \[PII:email\]/);
  }
});

test('F1-129: a token in a tool output object nested 14 levels deep is masked; a deep subtree with nothing to mask is kept as it was', () => {
  const token = ['ghp_', 'A1b2C3d4'.repeat(5)].join('');
  let value = { t: `token ${token}` };
  for (let i = 0; i < 14; i++) value = { a: value };
  const result = redactOutput('Bash', value, [], { command: 'x' });
  assert.ok(result.out, 'masked');
  assert.doesNotMatch(JSON.stringify(updatedOf(result)), /ghp_A1b2/);
  let clean = { n: 1, s: 'nothing here' };
  for (let i = 0; i < 14; i++) clean = { a: clean };
  assert.equal(redactOutput('Bash', clean, [], { command: 'x' }).out, null);
});

// ---------------------------------------------------------------- F1-76: AWS secret keys, camelCase and YAML password keys

const AWS_SECRET = ['wJalrXUtnFEMI/K7MDENG/', 'bPxRfiCYEXAMPLEKEY'].join('');

test('F1-76: an AWS secret access key is masked in an ini, env, YAML or JSON spelling, and blocked in a prompt', () => {
  for (const [text, expected] of [
    [`aws_secret_access_key = ${AWS_SECRET}`, 'aws_secret_access_key = [REDACTED:credential-assignment]'],
    [`export AWS_SECRET_ACCESS_KEY=${AWS_SECRET}`, 'export AWS_SECRET_ACCESS_KEY=[REDACTED:credential-assignment]'],
    [`  aws_secret_access_key: ${AWS_SECRET}`, '  aws_secret_access_key: [REDACTED:credential-assignment]'],
    [`{"AccessKeyId": "x", "SecretAccessKey": "${AWS_SECRET}"}`, '{"AccessKeyId": "x", "SecretAccessKey": "[REDACTED:credential-assignment]"}'],
    [`s3 = boto3.client("s3", aws_secret_access_key='${AWS_SECRET}')`, `s3 = boto3.client("s3", aws_secret_access_key='[REDACTED:credential-assignment]')`],
  ]) {
    assert.equal(redactSecrets(text).text, expected, text);
    assert.ok(findSecrets(text).length > 0, `the prompt guard blocks: ${text}`);
  }
});

test('F1-76: a key whose last word is password (camelCase, prefixed) in JSON, YAML, a Python dict or an assignment is masked', () => {
  const ADMIN = ['admin', PW_KEY].join('');
  for (const [text, expected] of [
    [`{"${ADMIN}": "${PW}!x"}`, `{"${ADMIN}": "[REDACTED:password-field]"}`],
    [`{"sqlAdmin${PW_KEY}": "${PHRASE}"}`, `{"sqlAdmin${PW_KEY}": "[REDACTED:password-field]"}`],
    [`${ADMIN}=${PW}`, `${ADMIN}=[REDACTED:password-field]`],
    [`$${ADMIN} = '${PW}'`, `$${ADMIN} = '[REDACTED:password-field]'`],
    [`${PW_KEY.toLowerCase()}: ${PW}`, `${PW_KEY.toLowerCase()}: [REDACTED:password-field]`],
    [`db:\n  host: x\n  ${PW_KEY.toLowerCase()}: "${PW}"\n`, `db:\n  host: x\n  ${PW_KEY.toLowerCase()}: "[REDACTED:password-field]"\n`],
    [`  - ${ADMIN}: ${PW}  # rotated`, `  - ${ADMIN}: [REDACTED:password-field]  # rotated`],
    [`DB_${PW_KEY.toUpperCase()}: '${PHRASE}'`, `DB_${PW_KEY.toUpperCase()}: '[REDACTED:password-field]'`],
    [`{'${PW_KEY.toLowerCase()}': '${PW}'}`, `{'${PW_KEY.toLowerCase()}': '[REDACTED:password-field]'}`],
    [`conn = {'user': 'app', 'db_${PW_KEY.toLowerCase()}': '${PW}'}`, `conn = {'user': 'app', 'db_${PW_KEY.toLowerCase()}': '[REDACTED:password-field]'}`],
  ]) {
    assert.equal(redactSecrets(text).text, expected, text);
    assert.ok(findSecrets(text).length > 0, `the prompt guard blocks: ${text}`);
  }
});

test('F1-76: booleans, placeholders, prose and other keys after a password key are left alone', () => {
  const pw = PW_KEY.toLowerCase();
  for (const text of [
    `{"has${PW_KEY}": true, "require${PW_KEY}": false, "reset${PW_KEY}": null}`, `show${PW_KEY}=false`, `${pw}: required`, `${PW_KEY}: None`,
    `${pw}: <your ${pw}>`, `${pw}: \${DB_${PW_KEY.toUpperCase()}}`, `${PW_KEY}: stored in Azure Key Vault`, `{"${pw}Policy": "strict"}`,
    `${pw}: ""`, `{"admin${PW_KEY}": ""}`, `The ${pw}: it must be rotated`, `${pw}Hint: abc123`, `my ${pw}: see the vault`, `${pw}: changeme`,
    `{"admin${PW_KEY}": "\${ADMIN_PW}"}`, `${pw}: !vault |`, `${pw}: '{{ db_${pw} }}'`, `aws_access_key_id = example`,
    // Labels and code: a word alone, a label that names the password, a cmdlet, an expression, a call.
    `{"show${PW_KEY}": "Show"}`, `{ confirm${PW_KEY}: 'Confirm ${pw}' }`, `{"forgot${PW_KEY}": "Forgot your ${pw}?"}`, `$admin${PW_KEY} = Read-Host -AsSecureString`,
    `const db${PW_KEY} = process.env.DB_${PW_KEY.toUpperCase()};`, `admin${PW_KEY} = get${PW_KEY}(1)`, `{ '--${pw}': 'a ${pw} on the command line' }`,
  ]) {
    assert.equal(redactSecrets(text).text, text, text);
    assert.deepEqual(findSecrets(text), [], text);
  }
});

test('F1-76: the audit\'s Bash output is masked whole (AWS pair, camelCase JSON key, YAML line, URI)', () => {
  const stdout = [
    `aws_access_key_id = ${['AKIA', 'ABCDEFGHIJKLMNOP'].join('')}`,
    `aws_secret_access_key = ${AWS_SECRET}`,
    `{"admin${PW_KEY}": "${PW}!x"}`,
    `${PW_KEY.toLowerCase()}: ${PW}`,
    `postgresql://reader:${PW}@dbhost:5432/sales`,
  ].join('\n');
  const result = redactOutput('Bash', { stdout, stderr: '' }, [], { command: 'cat x' });
  const masked = updatedOf(result).stdout;
  assert.doesNotMatch(masked, /Tr0ub4|wJalrX|AKIAABCD/);
  assert.equal(result.events[0].count, 5);
});

// ---------------------------------------------------------------- residual 1: passwords on a command line

test('residual 1: curl, redis-cli, sqlpackage and dtexec passwords on a command line are masked', () => {
  for (const [command, expected] of [
    [`curl -u admin:${PW} https://x.example.com`, 'curl -u admin:[REDACTED:password-option] https://x.example.com'],
    [`curl --user admin:${PW} https://x.example.com`, 'curl --user admin:[REDACTED:password-option] https://x.example.com'],
    [`curl -sS -uadmin:${PW} https://x.example.com`, 'curl -sS -uadmin:[REDACTED:password-option] https://x.example.com'],
    [`curl.exe -u "admin:${PHRASE}" https://x.example.com`, 'curl.exe -u "admin:[REDACTED:password-option]" https://x.example.com'],
    [`curl -x proxy:8080 -U 'u:${PW}' https://x.example.com`, "curl -x proxy:8080 -U 'u:[REDACTED:password-option]' https://x.example.com"],
    [`redis-cli -h db -a ${PW} ping`, 'redis-cli -h db -a [REDACTED:db-client-password] ping'],
    [`redis-cli --user app --pass '${PW}' ping`, "redis-cli --user app --pass '[REDACTED:db-client-password]' ping"],
    [`sqlpackage /Action:Publish /TargetPassword:${PW} /TargetUser:sa`, 'sqlpackage /Action:Publish /TargetPassword:[REDACTED:db-client-password] /TargetUser:sa'],
    [`SqlPackage.exe /a:Publish /tp:"${PHRASE}" /tu:sa`, 'SqlPackage.exe /a:Publish /tp:"[REDACTED:db-client-password]" /tu:sa'],
    [`sqlpackage -a:Extract -SourcePassword:${PW}`, 'sqlpackage -a:Extract -SourcePassword:[REDACTED:db-client-password]'],
    [`dtexec /F p.dtsx /De ${PW}`, 'dtexec /F p.dtsx /De [REDACTED:password-option]'],
    [`DTExec.exe /F p.dtsx /DECRYPT "${PHRASE}" /Rep E`, 'DTExec.exe /F p.dtsx /DECRYPT "[REDACTED:password-option]" /Rep E'],
    [`dtutil /FILE p.dtsx /Decrypt ${PW} /COPY FILE;q.dtsx`, 'dtutil /FILE p.dtsx /Decrypt [REDACTED:password-option] /COPY FILE;q.dtsx'],
  ]) {
    assert.equal(redactSecrets(command).text, expected, command);
    assert.equal(redactCommandSecrets(command).text, expected, command);
  }
});

test('residual 1: PowerShell\'s abbreviations of -Password take a value in a command, quoted anywhere', () => {
  for (const option of ['-Pass', '-Passw', '-Passwo', '-Passwor']) {
    assert.equal(redactCommandSecrets(`Invoke-Sqlcmd -Username sa ${option} ${PW} -Query x`).text, `Invoke-Sqlcmd -Username sa ${option} [REDACTED:password-option] -Query x`, option);
    assert.equal(redactSecrets(`Invoke-Sqlcmd ${option} '${PW}' -Query x`).text, `Invoke-Sqlcmd ${option} '[REDACTED:password-option]' -Query x`, option);
  }
  // A switch such as -PassThru takes no value: the next option or a variable is no password.
  for (const command of ['Start-Process notepad -PassThru -Wait', 'Invoke-Sqlcmd -Pass $pw -Query x', 'Get-Thing -Pass -Force', 'openssl enc -pass pass:x -in f']) {
    assert.equal(redactCommandSecrets(command).text, command, command);
  }
});

test('residual 1: placeholders and variables of those options, and the same options of other programs, are left alone', () => {
  // The options of other programs come first: the validator reads this file as text, and a string after a program name
  // would read as that program's next argument.
  for (const command of [
    'ls -a /tmp', 'grep -a pattern f', 'tar -u -f a.tar b', 'git log -u', 'tool /De abcdefgh',
    'curl -u user:password https://x', 'curl -u $USER:$PASS https://x', 'curl -u "$U:$P" https://x', 'curl -u admin: https://x', 'curl -u : --negotiate https://x',
    'curl -u admin https://x', 'curl -u "admin:<token>" https://x', 'redis-cli -a $REDIS_PW ping', 'redis-cli -h db ping',
    'sqlpackage /TargetPassword:$(pw) /a:Publish', 'sqlpackage /tp:%SQLPW% /a:Publish', 'sqlpackage /a:Publish /TargetServerName:db', 'dtexec /F p.dtsx /De <password>',
    'dtexec /F p.dtsx /Rep E',
  ]) {
    assert.equal(redactSecrets(command).text, command, command);
    assert.equal(redactCommandSecrets(command).text, command, command);
  }
});

test('residual 1: the error row of a failed shell call has its command-line passwords masked too', () => {
  const error = `Exit code 1\n+ mongosh -u app -p ${PW} db\ncurl -u admin:${PW} https://x.example.com`;
  const row = runHook('audit-log.mjs', { hook_event_name: 'PostToolUseFailure', tool_name: 'Bash', tool_input: { command: 'x' }, error }).audit[0];
  assert.doesNotMatch(JSON.stringify(row), /Tr0ub4/);
  assert.match(row.error, /mongosh -u app -p \[REDACTED:db-client-password\] db/);
});

// ---------------------------------------------------------------- residual 2 and 3: connection string values

test('residual 2: an unquoted value with spaces is masked whole when another pair of the connection string follows it', () => {
  for (const [text, expected] of [
    [`${PW_KEY}=${PHRASE};Server=db`, `${PW_KEY}=[REDACTED:password-assignment];Server=db`],
    [`Server=db ${PW_KEY}=${PHRASE};Initial Catalog=sales`, `Server=db ${PW_KEY}=[REDACTED:password-assignment];Initial Catalog=sales`],
    [`"${PW_KEY}=${PHRASE}; Data Source=db"`, `"${PW_KEY}=[REDACTED:password-assignment]; Data Source=db"`],
  ]) assert.equal(redactSecrets(text).text, expected, text);
  // Without a following pair it is still read as a word (a command, a sentence): documented in F1-41.
  assert.equal(redactSecrets(`${PW_KEY}=${PHRASE}`).text, `${PW_KEY}=[REDACTED:password-assignment] horse battery staple`);
  assert.equal(redactSecrets(`DB_${PW_KEY.toUpperCase()}=abc123 npm run migrate; echo ok`).text, 'DB_PASSWORD=[REDACTED:password-assignment] npm run migrate; echo ok');
});

test('residual 3: a quoted value inside a JSON-escaped string is read to its escaped closing quote', () => {
  const value = ['ab;cd', ' ef12'].join('');
  const stdout = JSON.stringify({ cs: `Server=db;${PW_KEY}="${value}";Encrypt=yes` });
  assert.equal(redactSecrets(stdout).text, JSON.stringify({ cs: `Server=db;${PW_KEY}="[REDACTED:password-assignment]";Encrypt=yes` }));
  assert.ok(findSecrets(stdout).length > 0);
  const result = redactOutput('Bash', { stdout, stderr: '' }, [], { command: 'cat x.json' });
  assert.doesNotMatch(updatedOf(result).stdout, /ef12/);
  // A placeholder in the escaped quotes stays.
  const placeholder = JSON.stringify({ cs: `Server=db;${PW_KEY}="\${DB_PW}";` });
  assert.equal(redactSecrets(placeholder).text, placeholder);
});

// ---------------------------------------------------------------- residual 4: the placeholder words

test('residual 4: a value that only starts with pass, pwd or secret is a password; the placeholder words stay', () => {
  for (const word of ['SecretSauce', 'PassportBlue', 'secretive']) {
    assert.equal(redactSecrets(`mysql -u app -p${word}`).text, 'mysql -u app -p[REDACTED:db-client-password]', word);
    assert.equal(redactSecrets(`https://app:${word}@db.example.com/x`).text, 'https://app:[REDACTED:url-credentials]@db.example.com/x', word);
  }
  for (const word of ['password', 'PASSWORD', 'Password', 'passwd', 'pwd', 'secret', 'Secret', 'SECRET', 'YourPassword1', 'PasswordHere', 'password_here', 'Secret-Key',
    'secrets', 'Passwords', 'PassPhrase', 'secret_value', 'PasswordGoesHere']) {
    assert.equal(redactSecrets(`mysql -u app -p${word}`).text, `mysql -u app -p${word}`, word);
  }
  assert.equal(redactSecrets('postgres://user:password@localhost:5432/db').text, 'postgres://user:password@localhost:5432/db');
});

// ---------------------------------------------------------------- residual 5: findSecrets in linear time

test('residual 5: findSecrets on 1 MB of connection strings takes linear time and keeps its line numbers', () => {
  const row = `Server=db;Uid=app;Pwd=${PW};`;
  const lines = `${row}\n`.repeat(Math.ceil(1048576 / (row.length + 1)));
  const oneLine = row.repeat(Math.ceil(1048576 / row.length));
  const start = Date.now();
  const hits = findSecrets(lines);
  const hits2 = findSecrets(oneLine);
  const ms = Date.now() - start;
  assert.ok(ms < 1500, `${ms} ms for 2 MB (O(n * hits): about 6.5 s)`);
  assert.equal(hits.length, lines.split('\n').length - 1);
  assert.deepEqual(hits.slice(0, 3).map((h) => h.line), [1, 2, 3]);
  assert.equal(hits.at(-1).line, hits.length);
  assert.ok(hits2.every((h) => h.line === 1));
});

// ---------------------------------------------------------------- residual 6: a manager's name in a DAX query

const daxVerdict = (query) => {
  const v = analyzeMcpCall(DAX_TOOL, { request: { operation: 'Execute', maxRows: 20, query } }, { mcp: { powerbiServer: 'powerbi-modeling' } });
  return v ? `${v.decision}${v.autoApprovable === false ? '/user' : ''}` : 'none';
};

test('residual 6: a manager\'s or supervisor\'s name asks in any table; organisation and place names pass', () => {
  const column = (ref) => daxVerdict(`EVALUATE SUMMARIZECOLUMNS(${ref}, "S", [Sales])`);
  for (const ref of ['Employee[Manager Name]', 'Employee[Supervisor Name]', "'Dim Employee'[ManagerName]", 'Employee[manager_name]', 'Store[Manager Name]',
    'Department[Manager Name]', 'Customer[Account Manager Name]', 'Product[Product Manager Name]', 'Employee[Line Manager Full Name]']) {
    assert.equal(column(ref), 'ask/user', ref);
  }
  for (const ref of ['Customer[Company Name]', 'Customer[Account Name]', 'Employee[Department Name]', 'Employee[Manager Level]', 'Employee[Manager Key Name Count]',
    'Manager[Region Name]', 'Product[Product Name]', 'Employee[Is Manager]']) {
    assert.equal(column(ref), 'allow', ref);
  }
  assert.equal(daxVerdict('EVALUATE ROW("n", DISTINCTCOUNT(Employee[Manager Name]))'), 'allow', 'counting names returns none of them');
});
