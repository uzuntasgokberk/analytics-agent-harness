// Over-denials of the 2026-11-17 round, and the deny it left open, each measured before the change:
// 1. A password printed out of a credential object or a SecureString had no verdict: $cred.GetNetworkCredential().Password,
//    ConvertFrom-SecureString -AsPlainText, Get-Secret -AsPlainText, Marshal's SecureString calls, a NetworkCredential read back
//    by .Password.
// 2. A PowerShell $Credential (mixed or lower case, no env:) counted as an environment secret, so `$Credential = Get-Credential`
//    and `Connect-PowerBIServiceAccount -Credential $Credential` were denied.
// 3. A connection-URL variable handed to psql as its whole connection word (`psql "$DATABASE_URL" -c "select 1"`) was denied,
//    where the SQL read switch asked before.
// 4. In a project that is itself a worktree checkout (<repo>/.claude/worktrees/<name>) every writing program and relative
//    redirect was denied as a guardrail write: the project's own path holds /.claude/.
// 5. The deny of `git branch -M main` did not name the plain rename.
// Every relaxed row stands next to the neighbours that keep their verdict. The hook runs as a process with an empty home.
import { after, test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const hooksDir = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'hooks');
const preHook = path.join(hooksDir, 'pre-tool-use.mjs');
const policyUrl = pathToFileURL(path.join(hooksDir, 'lib', 'policy.mjs')).href;
const temps = [];
const tempDir = (name) => {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), `bi-harness-over-1117-${name}-`)));
  temps.push(dir);
  return dir;
};
const write = (root, files) => {
  for (const [rel, text] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(root, rel)), { recursive: true });
    fs.writeFileSync(path.join(root, rel), text);
  }
};
// A temporary project (set before the modules read CLAUDE_PROJECT_DIR) and an empty home, so no rule of the developer applies.
const dir = tempDir('project');
write(dir, { 'docs/a.md': '# a\n', 'notes.txt': 'n\n', 'sql/q.sql': 'select 1\n' });
const emptyHome = tempDir('home');
process.env.CLAUDE_PROJECT_DIR = dir;
process.env.HOME = emptyHome;
process.env.USERPROFILE = emptyHome;
const { analyzeShellCommand, routineShell } = await import('../hooks/lib/policy.mjs');
after(() => temps.forEach((t) => fs.rmSync(t, { recursive: true, force: true })));

const onFeature = { protectedBranches: ['main'], getBranch: () => 'feature/x' };
const shell = (cmd, ctx = onFeature) => analyzeShellCommand(cmd, ctx);
const decision = (cmd, ctx) => shell(cmd, ctx)?.decision ?? null;

/** The hook's environment: no host variable, the machine's git configuration left out, the empty home. */
function hookEnv(root) {
  const env = Object.fromEntries(Object.entries(process.env).filter(([k]) => !/^GIT_(?:CONFIG|DIR$|WORK_TREE$|INDEX_FILE$|COMMON_DIR$|OBJECT_DIRECTORY$|ALTERNATE)/i.test(k)));
  delete env.BI_HARNESS_HOST;
  delete env.COPILOT_CLI;
  return { ...env, CLAUDE_PROJECT_DIR: root, HOME: emptyHome, USERPROFILE: emptyHome, GIT_CONFIG_NOSYSTEM: '1', GIT_CEILING_DIRECTORIES: path.dirname(root) };
}
/** The PreToolUse hook's decision and reason for one tool call, run as a process like Claude Code runs it (auto mode, the default). */
function hook(root, tool_name, tool_input) {
  const r = spawnSync(process.execPath, [preHook], {
    input: JSON.stringify({ hook_event_name: 'PreToolUse', session_id: 'over-1117', tool_name, tool_input, cwd: root }),
    env: hookEnv(root),
    cwd: root,
    encoding: 'utf8',
  });
  assert.equal(r.status, 0, r.stderr); // a guard that did not run prints no verdict, which would read as a pass
  const out = r.stdout.trim() ? JSON.parse(r.stdout).hookSpecificOutput : null;
  return { decision: out?.permissionDecision ?? null, reason: out?.permissionDecisionReason ?? '' };
}
const hookShell = (root, tool, command) => hook(root, tool, { command });

const EN_DASH = String.fromCharCode(0x2013); // PowerShell reads it as the dash of a parameter
const TOKEN_REASON = /This prints a sign-in token or a password/;
const VAR_REASON = /secret variable/;
const GUARD_REASON = /Harness guardrail files/;

// ---------------------------------------------------------------- 1: a password out of a credential object

test('1: printing a password out of a credential object or a SecureString is denied by the call, whatever the variable is named', () => {
  for (const cmd of [
    '$cred.GetNetworkCredential().Password', '$Credential.GetNetworkCredential().Password', '$x.GetNetworkCredential() | Format-List *',
    '$p = $c.GetNetworkCredential()', 'Get-Credential | ForEach-Object GetNetworkCredential', 'Write-Output $cred.GetNetworkCredential().Password',
    'Write-Host "$($cred.GetNetworkCredential().Password)"',
    'ConvertFrom-SecureString -AsPlainText $s', 'ConvertFrom-SecureString $s -AsPlainText', 'ConvertFrom-SecureString $s -AsPlain', 'ConvertFrom-SecureString $s -as',
    'ConvertFrom-SecureString $s -a', 'ConvertFrom-SecureString $s -AsPlainText:$true', `ConvertFrom-SecureString $s ${EN_DASH}AsPlainText`,
    `Get-Secret x ${String.fromCharCode(0x2015)}AsPlainText`, '$s | ConvertFrom-SecureString -AsPlainText',
    '[Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($s))',
    '[System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($b)', '[Runtime.InteropServices.Marshal]::PtrToStringUni($p)',
    '$m = [System.Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($s)', '[Runtime.InteropServices.Marshal]::SecureStringToCoTaskMemUnicode($s)',
    '[Runtime.InteropServices.Marshal]::PtrToStringAnsi([Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocAnsi($Credential.Password))',
    '[Runtime.InteropServices.Marshal]::SecureStringToCoTaskMemAnsi($s)',
    "[Net.NetworkCredential]::new('', $s).Password", "(New-Object Net.NetworkCredential('', $s)).Password",
    "(New-Object System.Net.NetworkCredential -ArgumentList '', $s).Password", "[System.Net.NetworkCredential]::new('', $s) | Select-Object -ExpandProperty Password",
    "$n = [Net.NetworkCredential]::new('', $s); $n.Password",
    'Get-Secret -Name x -AsPlainText', 'Get-Secret x -a', 'Get-Secret -Vault v x -AsPlainText:$true',
  ]) {
    const v = shell(cmd);
    assert.equal(v?.decision, 'deny', cmd);
    assert.match(v.reason, TOKEN_REASON, cmd);
  }
});

test('1: must stay: the prompt, an encrypted blob, a vault read without -AsPlainText, a NetworkCredential without .Password, text', () => {
  for (const cmd of ['Get-Credential', '$cred = Get-Credential', "ConvertTo-SecureString 'x' -AsPlainText -Force", 'ConvertFrom-SecureString $s',
    'ConvertFrom-SecureString -SecureString $s -Key $k', "ConvertTo-SecureString 'x' -AsPlainText -Force | ConvertFrom-SecureString", 'Get-Secret x',
    'Get-Secret -Name x -Vault v', "New-Object Net.NetworkCredential('u', $s)",
    'git commit -m "stop using .GetNetworkCredential().Password"', 'git commit -m "ConvertFrom-SecureString -AsPlainText and Get-Secret -AsPlainText"',
    'grep -rn "GetNetworkCredential" docs', "Select-String -Pattern 'PtrToStringAuto' docs/a.md", 'echo "ConvertFrom-SecureString -AsPlainText"']) {
    assert.equal(decision(cmd), null, cmd);
  }
});

// ---------------------------------------------------------------- 2: a PowerShell $Credential

test('2: a mixed- or lower-case $Credential without env: gets the verdict it had before the last round', () => {
  for (const cmd of ['$Credential = Get-Credential', '$credential = Get-Credential', 'echo $Credential', 'echo $credential', 'echo ${credential}',
    'echo "$credential"', 'echo $PSCredential', 'echo $adminCredential', 'Write-Output $Credential', '$Credential.UserName']) {
    assert.equal(decision(cmd), null, cmd);
  }
  assert.deepEqual(shell('Connect-PowerBIServiceAccount -Credential $Credential'), shell('Connect-PowerBIServiceAccount -Credential $cred'));
  assert.equal(decision('Connect-PowerBIServiceAccount -Credential $Credential'), 'ask');
  assert.deepEqual(shell('Write-Output $Credential'), shell('Write-Output $cred'));
  assert.equal(routineShell('Write-Output $Credential'), routineShell('Write-Output $cred'));
  // Printing the password out of it is Part 1's deny.
  assert.match(shell('$Credential.GetNetworkCredential().Password')?.reason ?? '', TOKEN_REASON);
});

test('2: must stay: CREDENTIAL read from the environment or named like an environment variable, and every other part of the name test', () => {
  for (const cmd of ['echo $env:AZURE_CREDENTIALS', 'echo ${env:MY_CREDENTIAL}', 'echo $Env:Credential', 'echo $ENV:credential', 'Write-Output ${Env:Credential}',
    'echo $GOOGLE_APPLICATION_CREDENTIALS', 'echo $AZURE_CREDENTIALS', 'echo ${DB_CREDENTIAL}', 'echo "$AZURE_CREDENTIAL"', 'echo $CREDENTIAL',
    'echo $Password', 'echo $token', 'echo $DatabaseUrl', 'echo $credentialToken', 'echo $adminPassword', 'Write-Output $Password']) {
    const v = shell(cmd);
    assert.equal(v?.decision, 'deny', cmd);
    assert.match(v.reason, VAR_REASON, cmd);
  }
  for (const cmd of ['node -e "console.log(process.env.AZURE_CREDENTIALS)"', 'echo %AZURE_CREDENTIALS%', "[Environment]::GetEnvironmentVariable('Credential')",
    "python -c \"import os;print(os.environ['credential'])\"", 'printenv AZURE_CREDENTIALS']) {
    assert.equal(decision(cmd), 'deny', cmd);
  }
});

// ---------------------------------------------------------------- 3: a connection URL as psql's whole connection word

const LITERAL = 'postgresql://h/db';
/** The same command with a literal connection where the variable stands. */
const literalTwin = (cmd) => cmd.replace(/"?\$(?:env:)?\{?[A-Za-z_]\w*\}?"?/, LITERAL);
const askShape = (v) => ({ decision: v?.decision ?? null, floor: v?.floor === true, autoApprovable: v?.autoApprovable ?? true });

test('3: a connection-URL variable that is psql\'s whole connection word gets the verdict of a literal connection there', () => {
  for (const cmd of ['psql "$DATABASE_URL" -c "select 1"', 'psql $DATABASE_URL -f sql/q.sql', 'psql ${DATABASE_URL} -c "select 1"',
    'psql "${DATABASE_URL}" -c "select 1"', 'psql --dbname="$DATABASE_URL" -c "select 1"', 'psql --dbname=$DATABASE_URL -c "select 1"',
    'psql -d "$DATABASE_URL" -c "select 1"', 'psql -d $env:DATABASE_URL -c "select 1"', 'psql $env:DATABASE_URL -c "select 1"',
    'psql -X -h h -c "select 1" "$DATABASE_URL"', 'psql -XAt "$DATABASE_URL" -c "select 1"', 'psql "$DATABASE_URL" -c "select 1" > out.txt',
    'psql "$PG_URL" -c "select 1"', 'psql "$POSTGRES_URL" -c "select 1"', 'psql "$DB_DSN" -c "select 1"', 'psql "$PDO_DSN" -c "select 1"',
    'psql "$DATABASE_URI" -c "select 1"', 'psql "$databaseUrl" -c "select 1"']) {
    const v = shell(cmd);
    assert.notEqual(v?.decision, 'deny', cmd);
    assert.deepEqual(askShape(v), askShape(shell(literalTwin(cmd))), cmd);
    assert.deepEqual(askShape(v), { decision: 'ask', floor: true, autoApprovable: false }, cmd);
    assert.match(v.reason, /^psql \(sources\.sqlRead off\)/, cmd);
  }
});

test('3: with the SQL read switch on the variable is never a pass: the guard cannot see its server', () => {
  const on = { ...onFeature, sqlRead: { mode: 'on', servers: ['h'] } };
  assert.equal(shell(`psql -X ${LITERAL} -c "select count(*) from t"`, on)?.sqlRead, true); // the literal passes
  for (const cmd of ['psql -X "$DATABASE_URL" -c "select count(*) from t"', 'psql -X -h h -d "$DATABASE_URL" -c "select count(*) from t"',
    'psql -X --dbname=$DATABASE_URL -c "select count(*) from t"']) {
    const v = shell(cmd, on);
    assert.deepEqual(askShape(v), { decision: 'ask', floor: true, autoApprovable: false }, cmd);
    assert.equal(v.sqlRead, undefined, cmd);
    assert.match(v.reason, /a variable or expression in the connection string/, cmd);
  }
});

test('3: must stay: the variable anywhere but as the whole connection word, other names, other programs and other spellings', () => {
  for (const cmd of [
    'echo $DATABASE_URL', 'echo "$DATABASE_URL"', "printf '%s' \"$DATABASE_URL\"", 'curl "$DATABASE_URL"',
    // In the query, in another statement or stage, glued to text, as a redirect or another option's value, or as the user name.
    'psql "$DATABASE_URL" -c "select \'$DATABASE_URL\'"', 'psql "$DATABASE_URL" -c "\\! echo $DATABASE_URL"', 'psql "$DATABASE_URL" -c "select 1"; echo $DATABASE_URL',
    'psql "$DATABASE_URL" -c "select 1" | tee "$DATABASE_URL"', 'psql "x$DATABASE_URL"', 'psql "$DATABASE_URL" > "$DATABASE_URL"', 'echo $DATABASE_URL | psql',
    'psql "$DATABASE_URL" -c "select 1" 2> "$DATABASE_URL"', 'psql "$DATABASE_URL" -o "$DATABASE_URL" -c "select 1"', 'psql "$DATABASE_URL" -f "$DATABASE_URL"',
    'psql "$DATABASE_URL" -c "select 1" -v x="$DATABASE_URL"', 'psql "$DATABASE_URL" "$DATABASE_URL" -c "select 1"', 'psql -d "$DATABASE_URL" "$DATABASE_URL"',
    'psql -c "$DATABASE_URL"', 'psql -U "$DATABASE_URL" -d x', 'psql -h "$DATABASE_URL" -c "select 1"', 'psql "$DATABASE_URL$DATABASE_URL"',
    // The name without a `$`: psql's \getenv reads the variable by name, and \echo prints it.
    "psql \"$DATABASE_URL\" -c '\\getenv u DATABASE_URL' -c '\\echo :u'", 'psql "$DATABASE_URL" -c "select \'DATABASE_URL\'"',
    'bash -c \'psql "$DATABASE_URL" -c "select 1"\'',
    // Spellings outside the whole word: single quotes, a glued -d, an option psql's spec does not hold, cmd's %X%.
    'psql \'$DATABASE_URL\' -c "select 1"', 'psql -d$DATABASE_URL -c "select 1"', 'psql --dbn="$DATABASE_URL" -c "select 1"', 'psql -Z "$DATABASE_URL"',
    // A password, token, key or credential name, never covered.
    'psql "$PGPASSWORD"', 'psql -c "select 1" "$API_TOKEN"', 'sqlcmd -P $SQLCMDPASSWORD', 'psql "$DB_PWD" -c "select 1"', 'psql "$DATABASE_URL_TOKEN" -c "select 1"',
    'psql "$AZURE_STORAGE_ACCOUNT_KEY" -c "select 1"', 'psql "$GOOGLE_APPLICATION_CREDENTIALS" -c "select 1"', 'psql "$DB_URL_SECRET" -c "select 1"',
    // Programs the SQL read switch does not judge, and clients of it that take no URL or DSN as one word.
    'redis-cli -u "$REDIS_URL" ping', 'pg_dump "$DATABASE_URL"', 'mongosh "$MONGODB_URI"', 'sqlcmd -S $DATABASE_URL -Q "select 1"',
    'Invoke-Sqlcmd -ConnectionString $env:DATABASE_URL -Query "select 1"',
  ]) {
    assert.equal(decision(cmd), 'deny', cmd);
  }
  for (const cmd of ['node -e "console.log(process.env.DATABASE_URL)"', 'psql %DATABASE_URL% -c "select 1"']) {
    assert.match(shell(cmd)?.reason ?? '', /reads the secret variable DATABASE_URL/, cmd);
  }
  assert.match(shell('psql "$DATABASE_URL" -c "select \'$DATABASE_URL\'"').reason, VAR_REASON);
});

// ---------------------------------------------------------------- 4: a project that is a worktree checkout

// One fixture: a plain project, and a repository whose worktree <repo>/.claude/worktrees/wt holds the same files, next to a
// sibling worktree; the repository has its own guardrail files. Links inside the worktree point into the parent's .claude/ and
// hardening/ (a junction on Windows, a symlink elsewhere).
const top = tempDir('wt');
const FILES = { 'docs/a.md': '# a\n', 'docs/b.txt': 'b\n', 'notes.txt': 'n\n', 'hardening/hooks/x.mjs': '// x\n', '.claude/settings.json': '{}\n',
  'templates/t.md': '# t\n', '.env': 'X=1\n', '.githooks/pre-commit': '#!/bin/sh\n', 'sql/q.sql': 'select 1\n' };
const plain = path.join(top, 'plain', 'proj');
const repo = path.join(top, 'repo');
const wt = path.join(repo, '.claude', 'worktrees', 'wt');
write(plain, FILES);
write(wt, FILES);
write(repo, { '.claude/settings.json': '{}\n', '.claude/settings.local.json': '{}\n', 'hardening/hooks/pre-tool-use.mjs': '// x\n', '.githooks/pre-commit': '#!/bin/sh\n', 'notes.txt': 'n\n' });
write(path.join(repo, '.claude', 'worktrees', 'wt2'), { 'hardening/hooks/x.mjs': '// x\n', '.claude/settings.json': '{}\n', 'notes.txt': 'n\n' });
fs.symlinkSync(path.join(repo, '.claude'), path.join(wt, 'link'), 'junction');
fs.symlinkSync(path.join(repo, 'hardening'), path.join(wt, 'hlink'), 'junction');
const posix = (p) => p.replace(/\\/g, '/');

// PROJECT_DIR is read once per process: each project is judged by a child process of its own.
const JUDGE = `
const { analyzeShellCommand, routineShell } = await import(process.env.POLICY_URL);
const out = JSON.parse(process.env.CMDS).map((c) => {
  const v = analyzeShellCommand(c, { protectedBranches: ['main'], getBranch: () => 'feature/x', baseDir: process.env.BASE_DIR });
  return { decision: v?.decision ?? null, reason: v?.reason ?? '', routine: routineShell(c, process.env.BASE_DIR) };
});
process.stdout.write(JSON.stringify(out));`;
/** Each command's verdict and routine flag in `project`, from the shell folder `baseDir`; {ROOT} is the project, {REPO} the repository. */
function judgeIn(project, cmds, baseDir = project) {
  const text = cmds.map((c) => c.replaceAll('{ROOT}', posix(project)).replaceAll('{REPO}', posix(repo)));
  const r = spawnSync(process.execPath, ['--input-type=module', '-e', JUDGE], {
    env: { ...hookEnv(project), POLICY_URL: policyUrl, BASE_DIR: baseDir, CMDS: JSON.stringify(text) },
    cwd: project,
    encoding: 'utf8',
  });
  assert.equal(r.status, 0, r.stderr);
  return JSON.parse(r.stdout);
}

const IN_PROJECT = [
  // Denied in the worktree before: writes to the project's own files, relative and absolute.
  'touch notes.txt', 'echo hi > notes.txt', 'rm docs/b.txt', 'Set-Content notes.txt hi', 'mv docs/b.txt docs/c.txt', 'sed -i s/a/b/ notes.txt',
  'New-Item -ItemType File out.txt', 'git checkout -- notes.txt', 'git restore notes.txt', 'git rm docs/b.txt', 'touch docs/../notes.txt', 'echo x > $f', 'rm $f',
  'touch {ROOT}/notes.txt', 'rm {ROOT}/docs/b.txt', 'rm -r {ROOT}/docs', 'Remove-Item {ROOT}/docs/b.txt', 'mv {ROOT}/docs/b.txt {ROOT}/docs/c.txt',
  'cp {ROOT}/docs/b.txt {ROOT}/docs/c.txt', 'git rm {ROOT}/docs/b.txt', '(cd {ROOT}/docs && touch x.txt)', 'ls {ROOT}/docs | xargs rm',
  "[IO.File]::WriteAllText('notes.txt','x')", `node -e "require('fs').writeFileSync('notes.txt','x')"`, "'notes.txt' | Remove-Item",
  // Unchanged: reads, guarded types, the project's own guardrail, reference and secret paths in every spelling.
  'cat docs/a.md', 'ls', 'git status', 'mkdir out', 'echo x > {ROOT}/notes.txt', 'cd {ROOT}/docs && ls', 'find {ROOT}/docs -name x -delete', 'cp docs/a.md docs/c.md',
  'cd docs && touch x.md', 'cat .env', 'cat {ROOT}/.env', 'echo x > hardening/hooks/x.mjs', 'echo x > .claude/settings.json', 'echo x > .claude/settings.local.json',
  'echo x > .githooks/pre-commit', 'echo x > templates/t.md', 'rm -r templates', 'rm -r .claude', 'cd .claude && touch x', '(cd hardening && echo x > y.mjs)',
  'echo x > {ROOT}/.claude/settings.json', 'echo x > {ROOT}/hardening/hooks/x.mjs', 'rm -r {ROOT}/.claude', 'rm -r {ROOT}/hardening', 'rm -r {ROOT}/templates',
  'cd {ROOT}/.claude && touch x',
];

test('4: in a worktree project every command on its own files gets the plain project\'s verdict and reason', () => {
  const inPlain = judgeIn(plain, IN_PROJECT);
  const inWorktree = judgeIn(wt, IN_PROJECT);
  IN_PROJECT.forEach((cmd, i) => assert.deepEqual(inWorktree[i], inPlain[i], cmd));
  // The rows the task names, and the worktree's own guardrail, reference and secret paths.
  const at = (cmd) => inWorktree[IN_PROJECT.indexOf(cmd)];
  for (const cmd of ['touch notes.txt', 'echo hi > notes.txt', 'rm docs/b.txt', 'Set-Content notes.txt hi']) assert.equal(at(cmd).decision, null, cmd);
  for (const cmd of ['echo x > hardening/hooks/x.mjs', 'echo x > .claude/settings.json', 'echo x > .claude/settings.local.json', 'echo x > .githooks/pre-commit',
    'echo x > templates/t.md', 'rm -r templates', 'cat .env', 'echo x > {ROOT}/.claude/settings.json', 'echo x > {ROOT}/hardening/hooks/x.mjs']) {
    assert.equal(at(cmd).decision, 'deny', cmd);
  }
});

test('4: must stay: the parent\'s and a sibling\'s guardrail files, ordinary files outside the worktree and links into the parent', () => {
  const outside = [
    // The parent repository's guardrail files, relative and absolute.
    'echo x > ../../settings.json', 'echo x > ../../settings.local.json', 'echo x > ../../../hardening/hooks/pre-tool-use.mjs', 'rm -r ../../../.git',
    'echo x > ../../../.githooks/pre-commit', 'echo x > {REPO}/.claude/settings.json', 'echo x > {REPO}/.claude/settings.local.json',
    'echo x > {REPO}/hardening/hooks/pre-tool-use.mjs', 'rm -r {REPO}/.git', 'echo x > {REPO}/.githooks/pre-commit', 'rm ../../settings.json',
    'Set-Content ../../settings.json x', 'cp docs/b.txt ../../settings.json', '(cd ../.. && echo x > settings.json)', '(cd ../.. && rm settings.local.json)',
    'ls ../.. | xargs rm', 'ln -s ../.. lnk',
    // The same path inside a word (a .NET call, inline code) or piped as a string, where no argument word holds it.
    "[IO.File]::WriteAllText('../../settings.json','x')", `node -e "require('fs').writeFileSync('../../settings.json','x')"`,
    `python -c "open('../../settings.json','w').write('x')"`, "'../../settings.json' | Remove-Item", "[IO.File]::WriteAllText('link/settings.json','x')",
    `node -e "require('fs').writeFileSync('link/settings.json','x')"`, "'link/settings.json' | Remove-Item",
    // A sibling worktree's guardrail files.
    'echo x > ../wt2/hardening/hooks/x.mjs', 'echo x > ../wt2/.claude/settings.json', 'echo x > {REPO}/.claude/worktrees/wt2/hardening/hooks/x.mjs',
    'echo x > {REPO}/.claude/worktrees/wt2/.claude/settings.json',
    // Ordinary files outside the worktree: denied before, and still.
    'echo x > ../../../notes.txt', 'echo x > ../wt2/notes.txt', 'touch ../../../notes.txt', 'echo x > ~/notes.txt',
    // A junction or symlink inside the worktree that resolves into the parent's .claude/ or hardening/ (written absolute through
    // the link it had no verdict before: the resolved path is judged now).
    'echo x > link/settings.json', 'echo x > link/settings.local.json', 'echo x > {ROOT}/link/settings.json', 'echo x > hlink/hooks/pre-tool-use.mjs',
    'echo x > link/worktrees/wt2/notes.txt',
  ];
  judgeIn(wt, outside).forEach((v, i) => assert.equal(v.decision, 'deny', outside[i]));
});

test('4: must stay: a session whose project is the repository and whose shell folder is the worktree', () => {
  const cmds = ['touch notes.txt', 'echo hi > notes.txt', 'rm docs/b.txt', 'Set-Content notes.txt hi'];
  judgeIn(repo, cmds, wt).forEach((v, i) => {
    assert.equal(v.decision, 'deny', cmds[i]);
    assert.match(v.reason, GUARD_REASON, cmds[i]);
  });
});

test('4: the hook gives the plain project\'s verdicts end to end in the worktree, for the shell and the file tools', () => {
  for (const [tool, command] of [['Bash', 'touch notes.txt'], ['Bash', 'echo hi > notes.txt'], ['Bash', 'rm docs/b.txt'], ['PowerShell', 'Set-Content notes.txt hi'],
    ['Bash', 'echo x > .claude/settings.json'], ['Bash', 'cat .env']]) {
    assert.deepEqual(hookShell(wt, tool, command), hookShell(plain, tool, command), `${tool}: ${command}`);
  }
  assert.notEqual(hookShell(wt, 'Bash', 'touch notes.txt').decision, 'deny');
  assert.equal(hookShell(wt, 'Bash', 'echo x > ../../settings.json').decision, 'deny');
  assert.equal(hookShell(wt, 'Bash', 'echo x > link/settings.json').decision, 'deny');
  for (const [tool, input, expected] of [
    ['Edit', (root) => ({ file_path: path.join(root, 'docs', 'a.md'), old_string: '# a', new_string: '# b' }), 'allow'],
    ['Write', (root) => ({ file_path: path.join(root, 'notes.txt'), content: 'x\n' }), null],
    ['Write', (root) => ({ file_path: path.join(root, 'hardening', 'hooks', 'x.mjs'), content: '// y\n' }), 'ask'],
    ['Read', (root) => ({ file_path: path.join(root, '.env') }), 'deny'],
  ]) {
    const inWorktree = hook(wt, tool, input(wt));
    assert.equal(inWorktree.decision, expected, `${tool} in the worktree`);
    assert.equal(hook(plain, tool, input(plain)).decision, expected, `${tool} in the plain project`);
  }
});

// ---------------------------------------------------------------- 5: git branch -M

test('5: the deny of a forced rename onto a protected branch names git branch -m; the verdicts do not change', () => {
  for (const cmd of ['git branch -M main', 'git branch -m -f main', 'git branch -M feature/x main', 'git branch -mf feature/x main', 'git init && git branch -M main']) {
    const v = shell(cmd);
    assert.equal(v?.decision, 'deny', cmd);
    assert.match(v.reason, /move or overwrite main/, cmd);
    assert.match(v.reason, /use git branch -m main \(or git branch -m <old> main\)/, cmd);
  }
  for (const cmd of ['git branch -f main HEAD~1', 'git branch -C feature/x main']) {
    const v = shell(cmd);
    assert.equal(v?.decision, 'deny', cmd);
    assert.doesNotMatch(v.reason, /git branch -m/, cmd);
  }
  for (const cmd of ['git branch -m main', 'git branch -m feature/x main', 'git branch -M main feature/x']) assert.equal(decision(cmd), null, cmd);
});

// ---------------------------------------------------------------- end to end

test('1-3, 5: the PreToolUse hook gives the verdicts end to end', () => {
  for (const [tool, command, reason] of [['PowerShell', '$cred.GetNetworkCredential().Password', TOKEN_REASON],
    ['PowerShell', 'ConvertFrom-SecureString $s -AsPlainText', TOKEN_REASON], ['PowerShell', 'echo $Env:Credential', VAR_REASON],
    ['Bash', 'echo $DATABASE_URL', VAR_REASON], ['Bash', 'git init && git branch -M main', /git branch -m main/]]) {
    const r = hookShell(dir, tool, command);
    assert.equal(r.decision, 'deny', `${tool}: ${command}`);
    assert.match(r.reason, reason, `${tool}: ${command}`);
  }
  assert.equal(hookShell(dir, 'PowerShell', '$Credential = Get-Credential').decision, hookShell(dir, 'PowerShell', '$cred = Get-Credential').decision);
  assert.deepEqual(hookShell(dir, 'PowerShell', 'Write-Output $Credential'), hookShell(dir, 'PowerShell', 'Write-Output $cred'));
  assert.deepEqual(hookShell(dir, 'PowerShell', 'Connect-PowerBIServiceAccount -Credential $Credential'),
    hookShell(dir, 'PowerShell', 'Connect-PowerBIServiceAccount -Credential $cred'));
  const psql = hookShell(dir, 'Bash', 'psql "$DATABASE_URL" -c "select 1"');
  assert.equal(psql.decision, 'ask');
  assert.match(psql.reason, /psql \(sources\.sqlRead off\)/);
});
