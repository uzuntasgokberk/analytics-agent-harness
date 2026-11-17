// Open findings 2026-11-17, commands that printed or read a secret, or sent data out, with no verdict (or approved as routine),
// while the plain spelling of the same act was denied (or asked):
// 1. A variable that holds a connection URL or DSN (DATABASE_URL, SENTRY_DSN...), a credential, a password in a *_PWD, an account
//    or subscription key: the secret-variable rule knew SECRET, TOKEN, PASSW... only. $Env:X and ${Env:X} (PowerShell, any
//    case) also passed for a name the rule knew.
// 2. A wildcard in the last segment of a credential store's path (~/.config/gh/*.yml, ~/.kube/c*), unlike the plain name.
// 3. file -m / --magic-file reads its file and prints the lines it cannot parse, like file -f.
// 4. The environment read through .NET's registry classes ([Microsoft.Win32.Registry]::GetValue, OpenSubKey('Environment')).
// 5. A browser given a URL (msedge, chrome, firefox...), unlike start, explorer, xdg-open or Start-Process with the URL.
// 6. patch applies a diff to the files it names, which the guard does not read, unlike git apply.
// The hook runs as a process in a temporary project with a temporary home; no value of a variable appears anywhere.
import { after, test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const preHook = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'hooks', 'pre-tool-use.mjs');
const temps = [];
const tempDir = (name) => {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), `bi-harness-open-1117s-${name}-`)));
  temps.push(dir);
  return dir;
};
// A temporary project (set before the modules read CLAUDE_PROJECT_DIR) and an empty home, so no rule of the developer applies.
const dir = tempDir('project');
for (const [rel, text] of Object.entries({ 'docs/a.md': '# a\n', 'notes.txt': 'n\n', 'x.diff': '--- a/notes.txt\n+++ b/notes.txt\n', 'sub/creds/credentials.json': '{}\n' })) {
  fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
  fs.writeFileSync(path.join(dir, rel), text);
}
const emptyHome = tempDir('home');
process.env.CLAUDE_PROJECT_DIR = dir;
// `~` is the guard's os.homedir(): this process's too, so no file of the machine's real home takes part.
process.env.HOME = emptyHome;
process.env.USERPROFILE = emptyHome;
const { analyzeShellCommand, routineShell } = await import('../hooks/lib/policy.mjs');
after(() => temps.forEach((t) => fs.rmSync(t, { recursive: true, force: true })));

const shell = (cmd) => analyzeShellCommand(cmd, {});
const decision = (cmd) => shell(cmd)?.decision ?? null;

/** The hook's decision and reason for one shell command, run as a process like Claude Code runs it (auto mode, the default). */
function hook(tool_name, command) {
  const env = { ...process.env, CLAUDE_PROJECT_DIR: dir, HOME: emptyHome, USERPROFILE: emptyHome };
  delete env.BI_HARNESS_HOST;
  const r = spawnSync(process.execPath, [preHook], {
    input: JSON.stringify({ hook_event_name: 'PreToolUse', session_id: 'open-1117s', tool_name, tool_input: { command }, cwd: dir }),
    env,
    cwd: dir,
    encoding: 'utf8',
  });
  assert.equal(r.status, 0, r.stderr); // a guard that did not run prints no verdict, which would read as a pass
  const out = r.stdout.trim() ? JSON.parse(r.stdout).hookSpecificOutput : null;
  return { decision: out?.permissionDecision ?? null, reason: out?.permissionDecisionReason ?? '' };
}

const VAR_REASON = /secret variable/;
const SHELL_REASON = /touches a secret or data file/;
const ENV_REASON = 'Dumping environment variables can expose credentials.';

// ---------------------------------------------------------------- 1: secret variable names

// Connection URLs and DSNs (they carry the password), credentials, a *_PWD, and the key names the masking rules read
// (SECRET_RULES: AccountKey, subscription_key) that the shell rule lacked.
const SECRET_NAMES = ['DATABASE_URL', 'DB_URL', 'DATABASE_URI', 'DB_DSN', 'SENTRY_DSN', 'REDIS_URL', 'MONGODB_URI', 'MONGO_URL', 'POSTGRES_URL',
  'PG_URL', 'MYSQL_URL', 'AMQP_URL', 'RABBITMQ_URL', 'BROKER_URL', 'CELERY_BROKER_URL', 'SQLALCHEMY_DATABASE_URI', 'JDBC_URL', 'CONNECTION_URL',
  'POSTGRESQL_URL', 'MARIADB_URL', 'MSSQL_URL', 'DATABASE_URL_RO', 'APP_DB_URL', 'PDO_DSN', 'DSN', 'GOOGLE_APPLICATION_CREDENTIALS',
  'AZURE_CREDENTIAL', 'credential', 'DB_PWD', 'SA_PWD', 'DB_OLD_PWD', 'AZURE_STORAGE_ACCOUNT_KEY', 'AccountKey', 'APIM_SUBSCRIPTION_KEY', 'databaseUrl'];

test('1: a variable that holds a connection URL, a DSN, a credential or a key is denied in every spelling the loop reads', () => {
  assert.equal(decision('echo "$GITHUB_TOKEN"'), 'deny'); // the reference
  for (const name of SECRET_NAMES) {
    for (const cmd of [`echo $${name}`, `echo \${${name}}`, `echo "$${name}"`, `printf '%s' "$${name}"`, `echo $env:${name}`, `echo \${env:${name}}`,
      `echo $Env:${name}`, `echo $ENV:${name.toLowerCase()}`, `Write-Output \${Env:${name}}`, `node -e "console.log(process.env.${name})"`,
      `node -e "console.log(process.env['${name}'])"`, `python -c "import os;print(os.environ['${name}'])"`, `python -c "import os;print(os.getenv('${name}'))"`,
      `echo %${name}%`, `[Environment]::GetEnvironmentVariable('${name}')`, `ruby -e "puts ENV['${name}']"`]) {
      const v = shell(cmd);
      assert.equal(v?.decision, 'deny', cmd);
      assert.match(v.reason, VAR_REASON, cmd);
    }
  }
});

test('1: a name the rule knew is denied behind $Env: and ${Env:} in any case, as behind $env:', () => {
  for (const cmd of ['echo $Env:GITHUB_TOKEN', 'echo $ENV:GITHUB_TOKEN', 'echo ${Env:GITHUB_TOKEN}', 'echo ${ENV:github_token}', 'Write-Host $eNv:API_KEY']) {
    const v = shell(cmd);
    assert.equal(v?.decision, 'deny', cmd);
    assert.match(v.reason, VAR_REASON, cmd);
  }
});

test('1: must stay: ordinary variables, other URLs and the variables of the pack itself', () => {
  const plain = ['HOME', 'PATH', 'PWD', 'OLDPWD', 'OLD_PWD', 'ORIG_PWD', 'USER', 'API_URL', 'BASE_URL', 'PUBLIC_URL', 'CI', 'GITHUB_SHA', 'GITHUB_SERVER_URL', 'GITHUB_API_URL',
    'LOGO_JPG_URL', 'GIT_AUTHOR_NAME', 'CLAUDE_PROJECT_DIR', 'BI_HARNESS_HOST', 'BI_HARNESS_CHECK_BUDGET_MS', 'BI_HARNESS_GIT_TIMEOUT_MS', 'RUNNER_TEMP'];
  for (const name of plain) {
    for (const cmd of [`echo $${name}`, `echo \${${name}}`, `echo "$${name}"`, `echo %${name}%`, `node -e "console.log(process.env.${name})"`]) {
      assert.equal(decision(cmd), null, cmd);
    }
  }
  for (const cmd of ['echo $env:USERPROFILE', 'echo $env:PATH', 'echo $Env:Path', 'echo ${env:USERPROFILE}', 'echo $ENV:TEMP', 'Write-Output $PSScriptRoot']) {
    assert.equal(decision(cmd), null, cmd);
  }
  // Approved as routine before, and still.
  for (const [tool, command] of [['Bash', 'echo $HOME'], ['Bash', 'echo $PATH'], ['Bash', 'echo $PWD'], ['Bash', 'echo $API_URL'], ['Bash', 'echo $CLAUDE_PROJECT_DIR'],
    ['PowerShell', 'echo $env:USERPROFILE'], ['PowerShell', 'echo $env:PATH']]) {
    assert.equal(hook(tool, command).decision, 'allow', `${tool}: ${command}`);
  }
});

// ---------------------------------------------------------------- 2: a wildcard in the last segment of a credential store

test('2: a wildcard in the file name of a credential store is denied like the plain name', () => {
  for (const cmd of ['cat ~/.config/gh/hosts.yml', 'cat ~/.aws/cred*']) assert.equal(decision(cmd), 'deny', `reference: ${cmd}`);
  for (const cmd of ['cat ~/.config/gh/*.yml', 'cat ~/.config/gh/h*', 'cat ~/.config/gh/hosts.y?l', 'cat ~/.config/gh/*', 'cat ~/.config/gh/[h]*',
    'head -1 ~/.config/gh/hosts.*', 'cat $HOME/.config/gh/*.yml', 'cat ~/.CONFIG/GH/H*', 'cat ~/.kube/c*', 'cat ~/.kube/*', 'cat ~/.docker/*.json',
    'cat ~/.docker/c*.json', 'cat "$APPDATA/GitHub CLI/h*"', 'cat ~/AppData/Roaming/GitHub\\ CLI/*.yml', 'Get-Content "$env:APPDATA\\GitHub CLI\\h*"',
    'cat ~/.config/gh/{hosts,x}.y?l', 'cp ~/.config/gh/*.yml notes.txt']) {
    const v = shell(cmd);
    assert.equal(v?.decision, 'deny', cmd);
    assert.match(v.reason, SHELL_REASON, cmd);
  }
  // A listing names files without reading them; another file of the folder, and the same file name elsewhere, stay open.
  for (const cmd of ['ls ~/.config/gh/*', 'ls ~/.kube/*', 'cat ~/.config/gh/config.yml', 'cat */config.json', 'cat docs/*.yml', 'cat ~/.config/gh/c*.yml',
    'cat sub/*.yml', 'cat ~/.docker/x*.txt']) {
    assert.equal(decision(cmd), null, cmd);
  }
});

// ---------------------------------------------------------------- 3: file -m / --magic-file

test('3: file -m / --magic-file reads the named file like file -f, in every spelling getopt_long accepts', () => {
  assert.equal(decision('file -f sub/creds/credentials.json'), 'deny'); // the reference
  for (const cmd of ['file -m sub/creds/credentials.json docs/a.md', 'file --magic-file sub/creds/credentials.json docs/a.md', 'file --magic-file=.env docs/a.md',
    'file -msub/creds/credentials.json docs/a.md', 'file -m.env docs/a.md', 'file -C -m .env', 'file -Cm .env', 'file -bm .env docs/a.md', 'file --mag .env docs/a.md',
    'file --magic=.env docs/a.md', 'file -m x.mgc:.env docs/a.md', 'file -m ~/.aws/credentials docs/a.md', 'file -m .en[v] docs/a.md', 'file docs/a.md -m .envrc']) {
    const v = shell(cmd);
    assert.equal(v?.decision, 'deny', cmd);
    assert.match(v.reason, SHELL_REASON, cmd);
  }
  for (const cmd of ['file -m x.mgc docs/a.md', 'file -C -m x.magic', 'file --mime-type docs/a.md', 'file --mime .env', 'file .env', 'file -b .env',
    'file -f list.txt .env', 'file -- -m .env']) {
    assert.equal(decision(cmd), null, cmd);
  }
});

// ---------------------------------------------------------------- 4: the environment through .NET's registry classes

test('4: reading the Environment key through [Microsoft.Win32.Registry] or RegistryKey is denied like Get-ItemPropertyValue HKCU:\\Environment', () => {
  assert.equal(shell('Get-ItemPropertyValue HKCU:\\Environment -Name Path')?.reason, ENV_REASON); // the reference
  for (const cmd of [
    "[Microsoft.Win32.Registry]::GetValue('HKEY_CURRENT_USER\\Environment','X',$null)",
    "[Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment').GetValue('X')",
    "[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment').GetValue('X')",
    "[Microsoft.Win32.Registry]::GetValue('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment','Path','')",
    "[Microsoft.Win32.RegistryKey]::OpenBaseKey('CurrentUser','Default').OpenSubKey('Environment').GetValue('X')",
    "[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64).OpenSubKey('SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment').GetValueNames()",
    "[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\\CurrentControlSet\\Control\\Session Manager').OpenSubKey('Environment').GetValue('X')",
    "[Microsoft.Win32.Registry]::Users.OpenSubKey('S-1-5-21-1\\Environment').GetValue('X')",
    '[Microsoft.Win32.Registry]::CurrentUser.OpenSubKey("Environment").GetValue("X")',
    "[microsoft.win32.registry]::getvalue('hkey_current_user\\environment','X',$null)",
    "[Registry]::CurrentUser.OpenSubKey('Environment').GetValue('X')",
    "$k = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment'); $k.GetValue('X')",
    "[Microsoft.Win32.Registry]::CurrentUser.CreateSubKey('Environment').GetValue('X')",
    "pwsh -Command \"[Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment').GetValue('X')\"",
    "powershell -NoProfile -Command \"[Microsoft.Win32.Registry]::GetValue('HKEY_CURRENT_USER\\Environment','X',$null)\"",
    "Write-Output ([Microsoft.Win32.Registry]::GetValue('HKEY_CURRENT_USER\\Environment','X',$null))",
    "Write-Host \"$([Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment').GetValue('X'))\"",
  ]) {
    const v = shell(cmd);
    assert.equal(v?.decision, 'deny', cmd);
    assert.equal(v.reason, ENV_REASON, cmd);
  }
  // Other keys, and a message or a search that names the call, stay open.
  for (const cmd of ["[Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software\\Vendor').GetValue('X')",
    "[Microsoft.Win32.Registry]::GetValue('HKEY_CURRENT_USER\\Software\\Vendor','X',$null)",
    "[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SOFTWARE\\Microsoft\\Windows\\CurrentVersion').GetValue('ProgramFilesDir')",
    'git commit -m "use [Microsoft.Win32.Registry]::GetValue(\'HKEY_CURRENT_USER\\Environment\') no more"',
    'grep -rn "OpenSubKey(\'Environment\')" docs']) {
    assert.equal(decision(cmd), null, cmd);
  }
});

// ---------------------------------------------------------------- 5: a browser given a URL

test('5: a browser given a URL gets the deny of start <url>, also as name.exe, with a quoted URL and through Start-Process', () => {
  const reference = shell('start https://example.com/');
  assert.equal(reference?.decision, 'deny');
  const forms = ['explorer https://example.com/', 'xdg-open https://example.com/', 'open https://example.com/', 'Start-Process https://example.com/',
    'Start-Process msedge https://example.com/', 'Start-Process -FilePath msedge -ArgumentList \'https://example.com/\'', 'Start-Process chrome.exe "https://example.com/?d=1"',
    'start msedge https://example.com/', '"C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe" https://example.com/', 'msedge --new-window https://example.com/',
    'firefox -private-window https://example.com/', 'open -a Safari https://example.com/', 'MSEDGE https://example.com/', 'msedge --app=https://example.com/',
    'chrome --app="https://example.com/?q=1"', 'Start-Process msedge -ArgumentList \'--app=https://example.com/\''];
  for (const browser of ['msedge', 'chrome', 'firefox', 'brave', 'chromium', 'opera', 'iexplore', 'google-chrome', 'chromium-browser', 'microsoft-edge', 'brave-browser']) {
    forms.push(`${browser} https://example.com/?q=1`, `${browser}.exe https://example.com/?q=1`, `${browser} "https://example.com/?q=1"`, `${browser} 'http://example.com/'`);
  }
  for (const cmd of forms) {
    assert.deepEqual(shell(cmd), reference, cmd);
    assert.equal(routineShell(cmd), false, cmd);
  }
  // Without a URL word nothing changes.
  for (const cmd of ['msedge', 'chrome --version', 'explorer .', 'open docs/a.md', 'firefox docs/a.md', 'Start-Process msedge', 'echo https://example.com/']) {
    assert.equal(decision(cmd), null, cmd);
  }
});

// ---------------------------------------------------------------- 6: patch

test('6: patch gets the ask of git apply (auto mode never answers it); a dry run, --help and --version stay', () => {
  const reference = shell('git apply x.diff');
  assert.equal(reference?.decision, 'ask');
  assert.equal(reference.autoApprovable, false);
  for (const cmd of ['patch -p1 -i x.diff', 'patch -p1 < x.diff', 'patch --input=x.diff', 'patch -i x.diff notes.txt', 'patch notes.txt x.diff', 'cat x.diff | patch -p1',
    'patch -p0 -ix.diff', 'patch -R -p1 -i x.diff', 'patch.exe -p1 -i x.diff', 'patch -i --dry-run', 'patch --d . -p1 -i x.diff', 'patch -p1 -i x.diff --verbose']) {
    const v = shell(cmd);
    assert.equal(v?.decision, 'ask', cmd);
    assert.equal(v.autoApprovable, false, cmd);
    assert.match(v.reason, /patch writes the diff's changes to files without the Edit\/Write checks/, cmd);
    assert.equal(routineShell(cmd), false, cmd);
  }
  // A guarded file type or a guardrail path as the target keeps its deny.
  for (const cmd of ['patch -i x.diff docs/a.md', 'patch docs/a.md x.diff', 'patch .claude/settings.local.json x.diff']) assert.equal(decision(cmd), 'deny', cmd);
  for (const cmd of ['patch --dry-run -p1 -i x.diff', 'patch -p1 --dry-run < x.diff', 'patch --dry -p1 -i x.diff', 'patch --help', 'patch --version', 'patch -v']) {
    assert.equal(decision(cmd), null, cmd);
  }
});

// ---------------------------------------------------------------- end to end

test('1-6: the PreToolUse hook gives the verdicts end to end', () => {
  for (const [tool, command, reason] of [
    ['Bash', 'echo $DATABASE_URL', VAR_REASON], ['Bash', 'echo ${DATABASE_URL}', VAR_REASON], ['PowerShell', 'echo $env:DATABASE_URL', VAR_REASON],
    ['PowerShell', 'echo $Env:GITHUB_TOKEN', VAR_REASON], ['Bash', 'node -e "console.log(process.env.SENTRY_DSN)"', VAR_REASON],
    ['Bash', 'cat ~/.config/gh/*.yml', SHELL_REASON], ['Bash', 'file -m sub/creds/credentials.json docs/a.md', SHELL_REASON],
    ['PowerShell', "[Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment').GetValue('X')", /Dumping environment variables/],
    ['Bash', 'msedge https://example.com/?q=1', /Opening a URL from the shell/], ['PowerShell', 'Start-Process msedge https://example.com/', /Opening a URL from the shell/],
  ]) {
    const r = hook(tool, command);
    assert.equal(r.decision, 'deny', `${tool}: ${command}`);
    assert.match(r.reason, reason, `${tool}: ${command}`);
  }
  const r = hook('Bash', 'patch -p1 -i x.diff');
  assert.equal(r.decision, 'ask');
  assert.match(r.reason, /patch writes the diff's changes/);
  for (const [tool, command] of [['Bash', 'msedge'], ['Bash', 'patch --dry-run -p1 -i x.diff'], ['Bash', 'file -m x.mgc docs/a.md']]) {
    assert.notEqual(hook(tool, command).decision, 'deny', `${tool}: ${command}`);
  }
});
