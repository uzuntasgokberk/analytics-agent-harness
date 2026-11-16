// Audit 2026-11-16, the secret files and commands the lists did not know. Each case was a silent pass before the fix.
// Finding 5:  direnv's .envrc, Claude Code's own ~/.claude/.credentials.json and the GitHub CLI's token file on Windows
//             (%APPDATA%\GitHub CLI\hosts.yml) got no verdict from Read, Grep, Glob, Edit/Write or the shell (`cat .envrc` was
//             even routine), while .env and ~/.config/gh/hosts.yml were denied everywhere.
// Finding 11: a secret name behind a bracket class or a brace expansion (`cat .en[v]`, `cat {.,}env`, `Get-Content .[e]nv`)
//             got no verdict, and neither did `file -f .env`, which prints each line of the file in an error.
// Finding 12: commands that print a stored password or token (`git credential fill`, `Get-PowerBIAccessToken`,
//             `kubectl config view --raw`...) and reads of the environment through the registry or WMI got no verdict.
// The hook runs as a process in a temporary project with a temporary home; file contents and paths are fakes.
import { after, test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyzeShellCommand, classifyPath } from '../hooks/lib/policy.mjs';

const preHook = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'hooks', 'pre-tool-use.mjs');
const temps = [];
after(() => temps.forEach((dir) => fs.rmSync(dir, { recursive: true, force: true })));
const tempDir = (name) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `bi-harness-1116s-${name}-`));
  temps.push(dir);
  return dir;
};
// The hook reads user-level settings from the home it is given: an empty one, so no rule of the developer applies.
const emptyHome = tempDir('home');
// A stand-in for a user's home folder: the stores are placed under it, never under the real one.
const fakeHome = tempDir('userhome');

/** A temporary project holding `files` (fake text). */
function project(files = {}) {
  const dir = tempDir('project');
  for (const [rel, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), content);
  }
  return dir;
}

/** The hook's decision and reason for one call, run as a process like Claude Code runs it. */
function guard(dir, tool_name, tool_input) {
  const env = { ...process.env, CLAUDE_PROJECT_DIR: dir, HOME: emptyHome, USERPROFILE: emptyHome };
  delete env.BI_HARNESS_HOST;
  const r = spawnSync(process.execPath, [preHook], {
    input: JSON.stringify({ hook_event_name: 'PreToolUse', session_id: 'audit-1116s', tool_name, tool_input, cwd: dir }),
    env,
    cwd: dir,
    encoding: 'utf8',
  });
  assert.equal(r.status, 0, r.stderr); // a guard that did not run prints no verdict, which would read as a pass
  const out = r.stdout.trim() ? JSON.parse(r.stdout).hookSpecificOutput : null;
  return { decision: out?.permissionDecision ?? null, reason: out?.permissionDecisionReason ?? '' };
}
const shell = (cmd) => analyzeShellCommand(cmd, {});
const decision = (cmd) => shell(cmd)?.decision ?? null;
const posix = (p) => p.replace(/\\/g, '/');

const FILE_REASON = /is a secret\/credential file and is blocked for the agent/;
const SHELL_REASON = /touches a secret or data file/;
const GREP_GLOB_REASON = /Searching inside secret or data files/;
const ENV_REASON = 'Dumping environment variables can expose credentials.';

// ---------------------------------------------------------------- finding 5: the files the lists did not know

test('finding 5: .envrc, a .credentials.json and the GitHub CLI token file on Windows are secret files for classifyPath', () => {
  for (const p of ['.envrc', 'app/.envrc', '.ENVRC', '.claude/.credentials.json', '.Claude\\.Credentials.json', 'x/.credentials.json',
    'AppData/Roaming/GitHub CLI/hosts.yml', 'AppData\\Roaming\\GitHub CLI\\hosts.yml', 'appdata/roaming/github cli/HOSTS.YML',
    posix(path.join(fakeHome, 'AppData', 'Roaming', 'GitHub CLI', 'hosts.yml')), path.join(fakeHome, '.claude', '.credentials.json')]) {
    assert.equal(classifyPath(p).secret, true, p);
  }
  for (const p of ['.env.example', '.env.sample', '.env.template', '.claude/settings.json', '.claude/settings.local.json',
    '.claude/agents/bi-expert.md', 'docs/credentials-howto.md', 'docs/envrc.md', 'GitHub CLI/config.yml', 'hosts.yml']) {
    assert.equal(classifyPath(p).secret, false, p);
  }
});

test('finding 5: Read, Grep, Glob, Edit, Write, Bash and PowerShell deny the three stores like .env, in the project and under a home folder', () => {
  const dir = project({ 'docs/a.md': '# a\n' });
  const stores = [
    path.join(dir, '.envrc'),
    path.join(dir, 'app', '.envrc'),
    path.join(fakeHome, '.claude', '.credentials.json'),
    path.join(fakeHome, 'AppData', 'Roaming', 'GitHub CLI', 'hosts.yml'),
  ];
  // The verdicts .env and ~/.config/gh/hosts.yml got before the fix are the reference.
  const reference = [path.join(dir, '.env'), path.join(fakeHome, '.config', 'gh', 'hosts.yml')];
  for (const file of [...reference, ...stores]) {
    for (const [tool, input, reason] of [
      ['Read', { file_path: file }, FILE_REASON],
      ['Grep', { pattern: 'x', path: file }, FILE_REASON],
      ['Glob', { pattern: '*', path: file }, FILE_REASON],
      ['Write', { file_path: file, content: 'FAKE=not-a-secret\n' }, FILE_REASON],
      ['Edit', { file_path: file, old_string: 'FAKE', new_string: 'OTHER' }, FILE_REASON],
      ['Bash', { command: `cat "${posix(file)}"` }, SHELL_REASON],
      ['PowerShell', { command: `Get-Content -LiteralPath '${file}'` }, SHELL_REASON],
    ]) {
      const r = guard(dir, tool, input);
      assert.equal(r.decision, 'deny', `${tool} ${file}`);
      assert.match(r.reason, reason, `${tool} ${file}`);
    }
  }
  // Grep globs that name or can match one of them (ripgrep reads what an explicit glob names, hidden or not).
  for (const glob of ['**/.e?vrc', '.[e]nvrc', '**/.claude/.credentials.json', '.credentials.jso?', '.cred*', '**/GitHub CLI/hosts.yml', '*.{md,envrc}']) {
    const r = guard(dir, 'Grep', { pattern: 'x', path: dir, glob });
    assert.equal(r.decision, 'deny', glob);
    assert.match(r.reason, GREP_GLOB_REASON, glob);
  }
  // A JSON file of the project stays searchable by its type, and the templates of .env stay readable.
  for (const glob of ['*.json', '**/*.json', '*.{json,tmdl}']) assert.equal(guard(dir, 'Grep', { pattern: 'x', path: dir, glob }).decision, null, glob);
  for (const rel of ['.env.example', '.env.sample', '.env.template', '.claude/settings.json', '.claude/settings.local.json', 'docs/credentials-howto.md']) {
    assert.notEqual(guard(dir, 'Read', { file_path: path.join(dir, rel) }).decision, 'deny', rel);
  }
});

test('finding 5: the shell guard denies the three stores in every spelling of the home and the AppData folder', () => {
  for (const cmd of [
    'cat .envrc', 'Get-Content .envrc', 'type .envrc', 'gc .envrc', 'head -3 app/.envrc', 'cp .envrc notes.txt', 'cat .envrc.', 'cat ./.envrc',
    'cat ~/.claude/.credentials.json', 'cat $HOME/.claude/.credentials.json', 'Get-Content $env:USERPROFILE\\.claude\\.credentials.json',
    'type %USERPROFILE%\\.claude\\.credentials.json', 'Get-Content -Path:.credentials.json', 'cat ~/.claude/.cred*', 'cat .envr?',
    'cat "$APPDATA/GitHub CLI/hosts.yml"', 'type "%APPDATA%\\GitHub CLI\\hosts.yml"', 'Get-Content "$env:APPDATA\\GitHub CLI\\hosts.yml"',
    'Get-Content "$env:APPDATA/github cli/HOSTS.YML"', 'cat ~/AppData/Roaming/GitHub\\ CLI/hosts.yml', "cat '%AppData%/GitHub CLI/hosts.yml'",
  ]) {
    const v = shell(cmd);
    assert.equal(v?.decision, 'deny', cmd);
    assert.match(v.reason, SHELL_REASON, cmd);
  }
});

// ---------------------------------------------------------------- finding 11: classes, braces and file -f

test('finding 11: a file word with a bracket class or a brace expansion that can spell a secret or data name is denied like the name', () => {
  for (const cmd of [
    'cat .en[v]', 'cat .[e]nv', 'cat ./.[!.]*', 'cat .en{v,x}', 'cat {.,}env', 'Get-Content .[e]nv', 'cat [.]env', 'cat .en[a-z]',
    'cat .[^x]nv', 'cat .{e,f}{n,m}v', 'cat .e{x,{n,m}}v', 'cat .en{u..w}', 'type .en[v]', 'head -1 .[e]nv', 'gc .[e]nv',
    'cat x.{pbix,md}', 'cat cache.a[b]f', 'cat key.p[e]m', 'cat [ab].pem', 'cat docs/{x,.env}', 'cat id_rs[a]',
    'cat ~/.a[w]s/credentials', 'cat ~/.config/gh/hosts.y[m]l', 'cat "$APPDATA/GitHub CLI/host[s].yml"', 'cat .envr[c]',
    'cat ~/.claude/.credentials.js[o]n', 'Get-Content .[e]nvrc', 'cat {a,b}/.en[v]', 'cat .e[m-o]v.local',
    // glued to a parameter, a comma list, a short option or a redirect, nested in another shell or piped on: like the plain name
    'Get-Content -Path:.[e]nv', 'Get-Content README.md,.[e]nv', 'cat a,.en{v,x}', 'git commit -F.en[v]', 'cat <.en[v]',
    "bash -c 'cat .en{v,x}'", 'pwsh -Command "Get-Content .[e]nv"', 'cat .en[v] | head -1',
  ]) {
    const v = shell(cmd);
    assert.equal(v?.decision, 'deny', cmd);
    assert.match(v.reason, SHELL_REASON, cmd);
  }
  // A brace list too long to spell out is refused, quickly: the hook must not run into its timeout.
  const many = `cat x{${Array.from({ length: 300 }, (_, i) => `a${i}`).join(',')}}`;
  const started = Date.now();
  assert.equal(decision(many), 'deny', 'more than 256 alternatives');
  assert.equal(decision(`cat ${'[a-z]'.repeat(400)}.md`), null, 'a long class pattern names no secret');
  // A 30 KB line of distinct brace and class words holds more spellings than the guard judges for one line: refused, not slow.
  let line = 'cat';
  for (let i = 0; line.length < 30000; i++) line += ` ${'{a,b}'.repeat(8)}${'[ab]'.repeat(8)}${i}.md`;
  assert.equal(decision(line), 'deny', 'past the spellings judged for one command line');
  assert.ok(Date.now() - started < 5000, 'judged in well under the hook timeout');
});

test('finding 11: the hook denies a class or a brace spelling of .env from Bash and PowerShell', () => {
  const dir = project({ '.env': 'FAKE=not-a-secret\n' });
  for (const [tool, command] of [['Bash', 'cat .en[v]'], ['Bash', 'cat {.,}env'], ['Bash', 'cat ./.[!.]*'], ['PowerShell', 'Get-Content .[e]nv']]) {
    const r = guard(dir, tool, { command });
    assert.equal(r.decision, 'deny', `${tool}: ${command}`);
    assert.match(r.reason, SHELL_REASON, `${tool}: ${command}`);
  }
});

test('finding 11: file -f and --files-from read the named file like cat, in every spelling getopt_long accepts', () => {
  for (const cmd of ['file -f .env', 'file --files-from .env', 'file --files-from=.env', 'file --f .env', 'file --fil=.env', 'file -bf .env',
    'file -f.env', 'file -bLf .env', 'file -kf .env README.md', 'file -F : -f .env', 'file -f cache.abf', 'file -f ~/.aws/credentials',
    'file -f .envrc', 'file -f .en[v]', 'file README.md -f .env']) {
    const v = shell(cmd);
    assert.equal(v?.decision, 'deny', cmd);
    assert.match(v.reason, SHELL_REASON, cmd);
  }
  const dir = project({ '.env': 'FAKE=not-a-secret\n' });
  const r = guard(dir, 'Bash', { command: 'file -f .env' });
  assert.equal(r.decision, 'deny');
  assert.match(r.reason, SHELL_REASON);
  // file names the type of a file it is given; the existence checks stay open.
  for (const cmd of ['file .env', 'file -b .env', 'file -f list.txt .env', 'file -- -f .env', 'stat .env', 'ls -la .env', 'test -f .env']) {
    assert.equal(decision(cmd), null, cmd);
  }
});

// ---------------------------------------------------------------- finding 12: tokens, passwords and the environment

test('finding 12: commands that print a stored password, a token or a whole credential are denied like gh auth token', () => {
  const reference = shell('gh auth token');
  assert.equal(reference?.decision, 'deny');
  for (const cmd of [
    'git credential fill', 'git -c credential.helper= credential fill', 'echo "protocol=https" | git credential fill',
    'git credential-manager get', 'git credential-manager-core get', 'git credential-store get', 'git credential-store --file ~/x get',
    'git-credential-store get', 'git credential-wincred get', 'gh auth git-credential get',
    'Get-PowerBIAccessToken', 'Get-PowerBIAccessToken -AsString', 'MicrosoftPowerBIMgmt.Profile\\Get-PowerBIAccessToken',
    '$t = Get-PowerBIAccessToken', '(Get-PowerBIAccessToken).Authorization', 'get-powerbiaccesstoken -asstring',
    'kubectl config view --raw', 'kubectl --context dev config view --raw -o yaml', 'kubectl config view --flatten',
    'aws configure export-credentials', 'aws configure export-credentials --profile dev --format env',
    'aws configure get aws_secret_access_key', 'aws configure get default.aws_secret_access_key', 'aws configure get aws_session_token --profile dev',
    'gcloud config config-helper --format=json', 'gcloud config config-helper',
    'git commit -m "$(git credential fill)"',
  ]) {
    const v = shell(cmd);
    assert.equal(v?.decision, 'deny', cmd);
    assert.equal(v.reason, reference.reason, cmd);
  }
  // gh's other helper verbs keep the GitHub ask they had.
  for (const cmd of ['gh auth git-credential store', 'gh auth git-credential erase']) assert.equal(decision(cmd), 'ask', cmd);
  const dir = project();
  for (const [tool, command] of [['Bash', 'git credential fill'], ['PowerShell', 'Get-PowerBIAccessToken -AsString'], ['Bash', 'kubectl config view --raw']]) {
    const r = guard(dir, tool, { command });
    assert.equal(r.decision, 'deny', `${tool}: ${command}`);
    assert.match(r.reason, /This prints a sign-in token/, `${tool}: ${command}`);
  }
});

test('finding 12: reads of the environment through the registry or WMI are denied like Get-ChildItem env:', () => {
  for (const cmd of [
    'reg query HKCU\\Environment', 'reg query HKCU\\\\Environment', 'reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment"',
    'reg query HKEY_CURRENT_USER\\Environment /v Path', 'reg.exe query HKCU\\Environment', 'REG QUERY hkcu\\environment\\', 'reg query HKCU/Environment',
    'reg query HKU\\S-1-5-21-1\\Environment', 'reg query HKCU /s', 'reg export HKCU\\Environment env.reg',
    'Get-ItemProperty HKCU:\\Environment', 'gp HKCU:\\Environment', 'Get-ItemProperty -Path HKCU:\\Environment', 'Get-ItemProperty -Path:HKCU:\\Environment',
    'Get-ItemProperty Registry::HKEY_CURRENT_USER\\Environment', 'Get-ItemPropertyValue HKCU:\\Environment -Name Path', 'Get-Item HKCU:\\Environment',
    'Get-ItemProperty HKCU:Environment', "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment'",
    'Get-ItemProperty HKCU:\\Env*', 'Get-ChildItem HKCU:\\', "Get-ChildItem 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager'",
    '(Get-ItemProperty HKCU:\\Environment).Path', 'Write-Host (Get-ItemProperty HKCU:\\Environment).Path', 'Get-ItemProperty HKCU:\\Environment | Select-Object Path',
    'Get-CimInstance Win32_Environment', 'Get-CimInstance -ClassName Win32_Environment', 'gcim win32_environment',
    'Get-CimInstance -Query "SELECT * FROM Win32_Environment"', 'Get-WmiObject Win32_Environment', 'gwmi Win32_Environment',
    'Get-WmiObject -Class Win32_Environment -Filter "UserName=\'x\'"', '(Get-CimInstance Win32_Environment).VariableValue',
    'wmic environment', 'wmic environment get Name,VariableValue', 'wmic /node:localhost environment list', 'WMIC ENVIRONMENT', 'wmic path Win32_Environment get',
  ]) {
    const v = shell(cmd);
    assert.equal(v?.decision, 'deny', cmd);
    assert.equal(v.reason, ENV_REASON, cmd);
  }
  const dir = project();
  for (const command of ['reg query HKCU\\Environment', 'Get-ItemProperty HKCU:\\Environment', 'Get-CimInstance Win32_Environment', 'wmic environment']) {
    const r = guard(dir, 'PowerShell', { command });
    assert.equal(r.decision, 'deny', command);
    assert.match(r.reason, /Dumping environment variables can expose credentials\./, command);
  }
  // Other keys and classes, a file named Environment, and a search or a message that names them stay open.
  for (const cmd of ['reg query HKCU\\Software\\Vendor', 'reg query HKCU', 'Get-ItemProperty HKCU:\\Software\\Vendor', 'Get-ChildItem HKCU:\\Software',
    'Get-CimInstance Win32_OperatingSystem', 'Get-Content docs/Environment', 'cat Environment.md', 'git commit -m "read Win32_Environment and HKCU\\Environment"',
    'grep -rn Win32_Environment docs']) {
    assert.equal(decision(cmd), null, cmd);
  }
});

// ---------------------------------------------------------------- what must stay as it was (passes before and after the fix)

test('unchanged: listings, project file types, templates, existence checks, safe CLI reads and text that names the commands', () => {
  for (const cmd of ['ls *.env', 'cat *.md', 'cat *.json', 'cat a*', "find . -name '*.pem'", 'cat .env.example', 'git ls-files *.env', 'Get-ChildItem *.pem',
    'cat docs/[ab].md', 'echo {a,b}.md', 'cat docs/{a,b}.md', 'file .env', 'stat .env', 'ls -la .env', 'test -f .env', 'kubectl config view',
    'aws configure list', 'aws configure get region', 'gh auth status', 'Get-PowerBIReport', 'reg query HKCU\\Software\\Vendor', 'git config --list',
    'git commit -m "document Get-PowerBIAccessToken and git credential fill"', 'grep -rn "git credential fill" docs',
    'git log --grep="kubectl config view --raw"', 'Select-String -Pattern Get-PowerBIAccessToken -Path docs/a.md',
    // braces in code and data arguments: a group without a comma stays as written, and no group here spells a secret name
    '$h.GetEnumerator() | % {$_.Key}', 'Write-Output {$x.pem}', "jq '{a: .x, b: .y}' f.json", "awk '{print $1,$2}' a.md",
    "git log --format='{%h,%s}'", "printf '%s\\n' {a,b,c}", 'cat docs/{a,b,c}/README.md', 'Get-ChildItem | % {$_.Name,$_.Length}']) {
    assert.equal(decision(cmd), null, cmd);
  }
  const dir = project({ 'docs/credentials-howto.md': '# how\n', '.env.example': 'FAKE=\n', '.claude/settings.json': '{}\n' });
  for (const rel of ['.env.example', '.claude/settings.json', 'docs/credentials-howto.md']) {
    assert.notEqual(guard(dir, 'Read', { file_path: path.join(dir, rel) }).decision, 'deny', rel);
  }
  for (const glob of ['*.json', '**/*.json', '*.md', '*.env.example']) assert.equal(guard(dir, 'Grep', { pattern: 'x', path: dir, glob }).decision, null, glob);
});
