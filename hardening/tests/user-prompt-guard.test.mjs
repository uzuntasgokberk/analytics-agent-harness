// UserPromptSubmit (user-prompt-guard.mjs): a message that holds a credential never reaches the model (exit 2, nothing on
// stdout, stderr for the user, a prompt-blocked event without the value); a deploy word adds the Tier 2 reminder. The
// credential rules are SECRET_RULES in lib/policy.mjs, the same the output masking, the file-write guard and the audit
// log use (2026-10-19 audit: F1-8 private key body, F1-41 password spellings, F1-43 passwords on a command line).
// Fake secrets are built at run time.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const hook = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'hooks', 'user-prompt-guard.mjs');

/** Submits a prompt as Claude Code does (stdin JSON) in a fresh project folder; returns the exit status, both streams and the security events. */
function submit(prompt) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-prompt-'));
  try {
    const env = { ...process.env, CLAUDE_PROJECT_DIR: dir };
    delete env.BI_HARNESS_HOST;
    const r = spawnSync(process.execPath, [hook], { input: JSON.stringify({ hook_event_name: 'UserPromptSubmit', session_id: 'prompt-test', prompt }), env, encoding: 'utf8' });
    const file = path.join(dir, '.claude', 'logs', 'security-events.jsonl');
    const events = fs.existsSync(file) ? fs.readFileSync(file, 'utf8').trim().split('\n').map((l) => JSON.parse(l)) : [];
    return { status: r.status, stdout: r.stdout, stderr: r.stderr, events };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

const PWD_KEY = ['Pw', 'd'].join('');
const PW_KEY = ['Pass', 'word'].join('');
const SECRET = ['S3cr3t', 'Pa55w0rd'].join('');
const keyMarker = (edge) => ['-----', edge, ' ', 'PRIVATE KEY', '-----'].join('');

/** The prompt is blocked: exit 2, no answer, the rule ids and not the value on stderr and in the event. */
function assertBlocked(prompt, ids, label = prompt) {
  const r = submit(prompt);
  assert.equal(r.status, 2, `${label}: ${r.stderr}`);
  assert.equal(r.stdout, '', label);
  assert.match(r.stderr, /^\[bi-harness\] Message blocked: it contains what looks like a credential \(/, label);
  assert.match(r.stderr, new RegExp(`\\(${ids.join(', ')}\\)`), label);
  assert.doesNotMatch(r.stderr + JSON.stringify(r.events), /S3cr3t|Pa55w0rd|MIIEvQ/, `${label}: the value is never echoed`);
  assert.deepEqual(r.events.map((e) => [e.event, e.ids]), [['prompt-blocked', ids]], label);
}

test('a connection string with an ODBC password in braces is blocked (F1-41)', () => {
  assertBlocked(`use Driver={ODBC Driver 18};Server=db;Uid=app;${PWD_KEY}={${SECRET};w0rd}`, ['password-assignment']);
});

test('a password in quotes with ";", with spaces or in a JSON field is blocked (F1-41)', () => {
  assertBlocked(`Server=db;Uid=app;${PW_KEY}="ab;cdefgh12";Encrypt=yes`, ['password-assignment']);
  assertBlocked(`Server=db;Uid=app;${PW_KEY}=correct horse battery staple;`, ['password-assignment']);
  assertBlocked(`here is the file {"${PW_KEY.toLowerCase()}": "correct horse battery"}`, ['password-json-field']);
});

test('a password on a command line or in a URL is blocked (F1-43)', () => {
  assertBlocked(`run mysql -h db -u app -p${SECRET} -e "select 1"`, ['db-client-password']);
  assertBlocked(`and sqlcmd -S . -U sa -P ${SECRET} -Q "select 1"`, ['db-client-password']);
  assertBlocked(`$s = ConvertTo-SecureString '${SECRET}' -AsPlainText -Force`, ['secure-string']);
  assertBlocked(`git clone https://app:${SECRET}@git.example.com/r.git`, ['url-credentials']);
  assertBlocked(`az sql server create --admin-password '${SECRET}'`, ['password-option']);
});

test('a private key is blocked whatever lies between its markers (F1-8)', () => {
  assertBlocked(`${keyMarker('BEGIN')}\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n${keyMarker('END')}`, ['private-key']);
  assertBlocked(`{"private_key": "${keyMarker('BEGIN')}\\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\\n${keyMarker('END')}\\n"}`, ['private-key']);
});

test('a placeholder, a variable, a harmless option or a sentence about passwords is let through', () => {
  for (const prompt of [
    `use ${PWD_KEY}=\${DB_PWD} in the connection string`, `Server=db;${PWD_KEY}={{db_password}};`, `Server=db;${PWD_KEY}={<password>};`, `${PW_KEY}=<your password here>`,
    'mkdir -p dir and then grep -P "a+" notes.txt', 'mysql -u app -p -e "select 1" asks for the password', 'mysql -P 3306 -h db', 'psql -h db -p 5432',
    'docker login --password-stdin', 'Invoke-Sqlcmd -Password $cred -Query x', 'postgres://user:password@localhost:5432/db',
    'Never write a password in M code or in a TMDL file.',
  ]) {
    const r = submit(prompt);
    assert.equal(r.status, 0, `${prompt}: ${r.stderr}`);
    assert.equal(r.stderr, '', prompt);
    assert.equal(r.stdout, '', prompt);
    assert.deepEqual(r.events, [], prompt);
  }
});

test('a prompt about a deploy still gets the Tier 2 reminder', () => {
  const r = submit('please deploy the model');
  assert.equal(r.status, 0);
  assert.match(JSON.parse(r.stdout).hookSpecificOutput.additionalContext, /Tier 2/);
});
