// SSIS packages and projects (2026-10-06): the agent may edit a package the repository owns; connections, protection
// levels, project files, build outputs and Script Task binaries are guarded. Fixture: a minimal package and project,
// enough for the guard's and validator's regex checks; it is not a full DTSX shape (components sit under the root).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyzeShellCommand } from '../hooks/lib/policy.mjs';
import { checkSsis, ssisConnectionFacts, ssisProtectionLevel } from '../hooks/lib/validators.mjs';

const hook = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'hooks', 'pre-tool-use.mjs');

const pkg = ({ level = '0', id2 = '{22222222-2222-2222-2222-222222222222}', server = '.', binary = 'AAAA' } = {}) => `<?xml version="1.0"?>
<DTS:Executable xmlns:DTS="www.microsoft.com/SqlServer/Dts"
  DTS:refId="Package"
  DTS:DTSID="{11111111-1111-1111-1111-111111111111}"
  DTS:ObjectName="Load"${level === null ? '' : `\n  DTS:ProtectionLevel="${level}"`}>
  <DTS:ConnectionManagers>
    <DTS:ConnectionManager DTS:refId="Package.ConnectionManagers[Db]" DTS:DTSID="${id2}" DTS:ObjectName="Db">
      <DTS:ObjectData>
        <DTS:ConnectionManager DTS:ConnectionString="Data Source=${server};Initial Catalog=Lab;Integrated Security=SSPI;" />
      </DTS:ObjectData>
    </DTS:ConnectionManager>
  </DTS:ConnectionManagers>
  <DTS:Executables>
    <DTS:Executable DTS:refId="Package\\Truncate" DTS:DTSID="{33333333-3333-3333-3333-333333333333}" DTS:ObjectName="Truncate" />
    <DTS:Executable DTS:refId="Package\\Load" DTS:DTSID="{44444444-4444-4444-4444-444444444444}" DTS:ObjectName="Load">
      <component refId="Package\\Load\\Dest" name="Dest">
        <connections>
          <connection refId="Package\\Load\\Dest.Connections[OleDbConnection]" connectionManagerID="Package.ConnectionManagers[Db]" connectionManagerRefId="Package.ConnectionManagers[Db]" name="OleDbConnection" />
        </connections>
      </component>
    </DTS:Executable>
  </DTS:Executables>
  <BinaryItem Name="ScriptMain.dll">${binary}</BinaryItem>
</DTS:Executable>
`;
const dtproj = (level = 'DontSaveSensitive') => `<?xml version="1.0" encoding="utf-8"?>
<Project xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <DeploymentModelSpecificContent><Manifest>
    <SSIS:Project SSIS:ProtectionLevel="${level}" xmlns:SSIS="www.microsoft.com/SqlServer/SSIS" />
  </Manifest></DeploymentModelSpecificContent>
</Project>
`;

test('validator: package protection level, duplicate DTSIDs, malformed XML and the project level', () => {
  assert.equal(ssisProtectionLevel(pkg({ level: null }), '.dtsx'), 'EncryptSensitiveWithUserKey'); // the default
  assert.equal(ssisProtectionLevel(dtproj(), '.dtproj'), 'DontSaveSensitive');
  assert.ok(checkSsis('etl/P/Load.dtsx', pkg({ level: null })).some((i) => i.level === 'warn' && /only the account that saved it/.test(i.message)));
  assert.ok(checkSsis('etl/P/Load.dtsx', pkg({ id2: '{11111111-1111-1111-1111-111111111111}' })).some((i) => i.level === 'error' && /used twice/.test(i.message)));
  assert.ok(checkSsis('etl/P/Load.dtsx', '<DTS:Executable').some((i) => i.level === 'error' && /Malformed XML/.test(i.message)));
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-ssis-'));
  fs.mkdirSync(path.join(dir, 'etl', 'P'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'etl', 'P', 'P.dtproj'), dtproj('DontSaveSensitive'));
  assert.ok(checkSsis('etl/P/Load.dtsx', pkg({ level: '2' }), { root: dir }).some((i) => i.level === 'error' && /differs from the project/.test(i.message)));
  assert.deepEqual(checkSsis('etl/P/Load.dtsx', pkg(), { root: dir }).filter((i) => i.level !== 'info'), []);
  fs.rmSync(dir, { recursive: true, force: true });
});

function guard(dir, tool_name, tool_input) {
  const r = spawnSync(process.execPath, [hook], {
    input: JSON.stringify({ hook_event_name: 'PreToolUse', session_id: 'ssis', tool_name, tool_input }),
    env: { ...process.env, CLAUDE_PROJECT_DIR: dir },
    encoding: 'utf8',
  });
  assert.equal(r.status, 0, r.stderr);
  return r.stdout.trim() ? JSON.parse(r.stdout).hookSpecificOutput : {};
}

test('guard: ordinary package edits run in auto mode; connections, protection, binaries and project files do not', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-ssis-'));
  fs.mkdirSync(path.join(dir, 'etl', 'P'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'etl', 'P', 'P.dtproj'), dtproj());
  const file_path = path.join(dir, 'etl', 'P', 'Load.dtsx');
  fs.writeFileSync(file_path, pkg());
  const edit = (old_string, new_string) => guard(dir, 'Edit', { file_path, old_string, new_string });
  assert.equal(edit('DTS:ObjectName="Truncate"', 'DTS:ObjectName="Truncate staging"').permissionDecision, 'allow');
  const server = edit('Data Source=.;', 'Data Source=prod-sql;');
  assert.equal(server.permissionDecision, 'ask');
  assert.match(server.permissionDecisionReason, /connection string|Critical/);
  assert.equal(edit('DTS:ProtectionLevel="0"', 'DTS:ProtectionLevel="1"').permissionDecision, 'ask');
  assert.equal(edit('>AAAA<', '>BBBB<').permissionDecision, 'deny');
  // Repointing a component to another connection, or setting a connection by expression, is a connection change.
  assert.equal(edit('connectionManagerRefId="Package.ConnectionManagers[Db]"', 'connectionManagerRefId="Package.ConnectionManagers[Prod]"').permissionDecision, 'ask');
  assert.equal(edit('DTS:ObjectName="Db">', 'DTS:ObjectName="Db">\n      <DTS:PropertyExpression DTS:Name="ConnectionString">"Data Source=prod;"</DTS:PropertyExpression>').permissionDecision, 'ask');
  const dtsConfig = guard(dir, 'Write', { file_path: path.join(dir, 'etl', 'P', 'Load.dtsConfig'), content: '<DTSConfiguration/>' });
  assert.equal(dtsConfig.permissionDecision, 'ask');
  assert.match(dtsConfig.permissionDecisionReason, /project, parameter, connection manager or configuration file/);
  assert.equal(edit('Integrated Security=SSPI;', `User ID=etl;${'Pass'}word=${'S3cr3t'}Value9;`).permissionDecision, 'deny');
  assert.equal(edit('<DTS:Executables>', '<DTS:Executables').permissionDecision, 'deny'); // malformed XML
  const unquoted = edit('DTS:ObjectName="Truncate"', 'DTS:ObjectName=Truncate');
  assert.equal(unquoted.permissionDecision, 'deny'); // an unquoted attribute is malformed too
  assert.match(unquoted.permissionDecisionReason, /attribute DTS:ObjectName has no quoted value/);
  for (const rel of ['etl/P/bin/Development/P.ispac', 'etl/P/P.dtproj.user', 'etl/P/obj/Development/x.dtsx']) {
    assert.equal(guard(dir, 'Write', { file_path: path.join(dir, rel), content: '<x/>' }).permissionDecision, 'deny', rel);
  }
  // Project, parameter and connection manager files always ask, explicitly (not left to the permission mode).
  for (const rel of ['etl/P/P.dtproj', 'etl/P/Project.params', 'etl/P/Db.conmgr']) {
    const out = guard(dir, 'Write', { file_path: path.join(dir, rel), content: '<x/>' });
    assert.equal(out.permissionDecision, 'ask', rel);
    assert.match(out.permissionDecisionReason, /project, parameter, connection manager or configuration file/, rel);
  }
  fs.rmSync(dir, { recursive: true, force: true });
});

test('guard: changing or removing an existing DTSID or refId asks; renaming an object does not', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-ssis-'));
  fs.mkdirSync(path.join(dir, 'etl', 'P'), { recursive: true });
  const file_path = path.join(dir, 'etl', 'P', 'Load.dtsx');
  fs.writeFileSync(file_path, pkg());
  const edit = (old_string, new_string) => guard(dir, 'Edit', { file_path, old_string, new_string });
  const changedId = edit('{33333333-3333-3333-3333-333333333333}', '{55555555-5555-5555-5555-555555555555}');
  assert.equal(changedId.permissionDecision, 'ask');
  assert.match(changedId.permissionDecisionReason, /object identities/);
  assert.equal(edit('DTS:refId="Package\\Truncate"', 'DTS:refId="Package\\Clear"').permissionDecision, 'ask');
  assert.equal(edit('refId="Package\\Load\\Dest"', 'refId="Package\\Load\\Target"').permissionDecision, 'ask'); // a component
  const removed = edit('    <DTS:Executable DTS:refId="Package\\Truncate" DTS:DTSID="{33333333-3333-3333-3333-333333333333}" DTS:ObjectName="Truncate" />\n', '');
  assert.equal(removed.permissionDecision, 'ask');
  assert.equal(edit('DTS:ObjectName="Truncate"', 'DTS:ObjectName="Clear staging"').permissionDecision, 'allow');
  fs.rmSync(dir, { recursive: true, force: true });
});

/**
 * The 8.3 short path of an existing file (Windows). The path travels in an environment variable, never inside the
 * command text, so a quote, `$` or backtick in it cannot break the command. Throws with PowerShell's error instead of
 * answering nothing.
 */
function shortPathOf(long) {
  const r = spawnSync('powershell', ['-NoProfile', '-NonInteractive', '-Command', '(New-Object -ComObject Scripting.FileSystemObject).GetFile($env:BI_HARNESS_LONG_PATH).ShortPath'], {
    encoding: 'utf8', env: { ...process.env, BI_HARNESS_LONG_PATH: long }, windowsHide: true,
  });
  const short = String(r.stdout ?? '').trim();
  if (r.error || r.status !== 0 || !short) throw new Error(`PowerShell could not read the short name of ${long}: exit ${r.status}, ${r.error?.message ?? r.stderr}`);
  return short;
}

// F1-115: a TEMP under a profile such as O'Brien put an apostrophe into the command, PowerShell failed, and the 8.3 test
// skipped as if 8.3 names were off. The helper must read such a path, and fail loudly when it cannot.
test('ssis test helper: the 8.3 lookup reads a path with an apostrophe, a dollar sign and a backtick', (t) => {
  if (process.platform !== 'win32') return t.skip('8.3 names exist only on Windows');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "bi-harness-o'b$c`d-"));
  try {
    const long = path.join(dir, 'LoadPackageWithLongName.dtsx');
    fs.writeFileSync(long, 'same file');
    const short = shortPathOf(long);
    assert.equal(fs.readFileSync(short, 'utf8'), 'same file', `${short} names the file`);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('guard: an 8.3 short file name gets the same content checks as the long name', (t) => {
  if (process.platform !== 'win32') return t.skip('8.3 names exist only on Windows');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-ssis-'));
  try {
    fs.mkdirSync(path.join(dir, 'etl', 'P'), { recursive: true });
    const long = path.join(dir, 'etl', 'P', 'LoadPackageWithLongName.dtsx');
    fs.writeFileSync(long, pkg());
    const short = shortPathOf(long);
    if (path.basename(short).toLowerCase() === path.basename(long).toLowerCase()) return t.skip('8.3 names are off on this volume');
    const out = guard(dir, 'Edit', { file_path: short, old_string: 'Data Source=.;', new_string: 'Data Source=prod-sql;' });
    assert.equal(out.permissionDecision, 'ask', short);
    assert.match(out.permissionDecisionReason, /connection string/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('shell: SSIS files and reference folders are written only with the Edit or Write tool', () => {
  const refs = { references: ['setup/'] };
  assert.equal(analyzeShellCommand('Set-Content etl/P/Load.dtsx x', {})?.decision, 'deny');
  assert.equal(analyzeShellCommand('cp a.txt etl/P/Project.params', {})?.decision, 'deny');
  assert.equal(analyzeShellCommand('cp a.txt templates/x.txt', {})?.decision, 'deny'); // built-in reference folder
  assert.equal(analyzeShellCommand('cp a.txt setup/data/y.csv', refs)?.decision, 'deny');
  assert.equal(analyzeShellCommand('echo x > setup/data/y.csv', refs)?.decision, 'deny');
  assert.equal(analyzeShellCommand('cp a.txt setup/data/y.csv', {}), null); // no "references": an ordinary folder
  assert.equal(analyzeShellCommand('cp a.txt setupx/y.csv', refs), null); // the prefix does not bleed
  assert.equal(analyzeShellCommand('cat setup/data/y.csv', refs), null); // reading stays allowed
  // Deletes, variables and inline code reach a reference folder too.
  for (const cmd of ['rm setup/sql/01.sql', 'Remove-Item -Path setup/data/y.csv', 'del setup\\data\\y.csv',
    '$p = "setup/data/y.csv"; Set-Content $p x', '$d = "setup/data"; Set-Content "$d/y.csv" x',
    `node -e "require('fs').writeFileSync('setup/x.txt', 'y')"`]) {
    assert.equal(analyzeShellCommand(cmd, refs)?.decision, 'deny', cmd);
  }
  assert.equal(analyzeShellCommand('rm templates/x.txt', {})?.decision, 'deny'); // built-in reference folder
  assert.notEqual(analyzeShellCommand('rm notes/x.txt', refs)?.decision, 'deny'); // an ordinary file: settings decide
  const inline = analyzeShellCommand(`node -e "require('fs').writeFileSync('notes/x.txt', 'y')"`, refs);
  assert.equal(inline?.decision, 'ask'); // inline writes elsewhere still ask (left to Claude Code's flow in auto mode)
});

test('guard: "references" entries are normalized; entries that would match everything are dropped', () => {
  const cases = [
    [['setup'], 'setup/ssis/P/Load.dtsx', 'deny'],
    [['setup\\'], 'setup/ssis/P/Load.dtsx', 'deny'],
    [['/setup/'], 'setup/ssis/P/Load.dtsx', 'deny'],
    [['/'], 'etl/P/Load.dtsx', 'allow'],
    [[''], 'etl/P/Load.dtsx', 'allow'],
    [['setup/'], 'setupx/P/Load.dtsx', 'allow'],
  ];
  for (const [references, rel, expected] of cases) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-ssis-'));
    try {
      fs.mkdirSync(path.join(dir, 'hardening'), { recursive: true });
      fs.writeFileSync(path.join(dir, 'hardening', 'harness.config.json'), JSON.stringify({ references }));
      fs.mkdirSync(path.join(dir, path.dirname(rel)), { recursive: true });
      const file_path = path.join(dir, rel);
      fs.writeFileSync(file_path, pkg());
      const out = guard(dir, 'Edit', { file_path, old_string: 'DTS:ObjectName="Truncate"', new_string: 'DTS:ObjectName="T2"' });
      assert.equal(out.permissionDecision, expected, `${JSON.stringify(references)} ${rel}`);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }
});

test('guard: a folder in the config "references" is read-only, like templates/ (a lab\'s outside world)', () => {
  for (const withConfig of [true, false]) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-ssis-'));
    if (withConfig) {
      fs.mkdirSync(path.join(dir, 'hardening'), { recursive: true });
      fs.writeFileSync(path.join(dir, 'hardening', 'harness.config.json'), JSON.stringify({ references: ['setup/'] }));
    }
    fs.mkdirSync(path.join(dir, 'setup', 'ssis', 'P'), { recursive: true });
    const file_path = path.join(dir, 'setup', 'ssis', 'P', 'Load.dtsx');
    fs.writeFileSync(file_path, pkg());
    // The other case names the same file only on a case-insensitive file system (Windows, macOS). On Linux it is a
    // missing file: the guard cannot find the old text there and asks, but never denies it as a reference without the entry.
    const variant = path.join(dir, 'Setup', 'ssis', 'P', 'Load.dtsx');
    const sameFile = fs.existsSync(variant);
    for (const target of [file_path, variant]) {
      const out = guard(dir, 'Edit', { file_path: target, old_string: 'DTS:ObjectName="Truncate"', new_string: 'DTS:ObjectName="T2"' });
      if (withConfig) {
        assert.equal(out.permissionDecision, 'deny', target);
        assert.match(out.permissionDecisionReason, /is a reference/);
      } else if (target === file_path || sameFile) {
        assert.equal(out.permissionDecision, 'allow', target); // no "references" entry: an ordinary package edit
      } else {
        assert.equal(out.permissionDecision, 'ask', target);
        assert.doesNotMatch(out.permissionDecisionReason, /is a reference/);
      }
    }
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('auto: validating a package is routine only while every server it connects to is this machine', () => {
  for (const [server, routine] of [['.', true], ['localhost', true], ['prod-sql', false]]) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-ssis-'));
    fs.mkdirSync(path.join(dir, 'etl', 'P'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'etl', 'P', 'Load.dtsx'), pkg({ server }));
    const out = guard(dir, 'PowerShell', { command: 'dtexec /F etl/P/Load.dtsx /Validate' });
    fs.rmSync(dir, { recursive: true, force: true });
    if (routine) assert.equal(out.permissionDecision, 'allow', server);
    else assert.notEqual(out.permissionDecision, 'allow', server);
  }
});

// Final audit (2026-10-18), F1-28 and F1-29: the connection facts held a connection's property expression but not the package
// parameter or variable it reads, and not the connection manager an Execute SQL task uses (SQLTask:Connection). A server
// could change through either as a routine edit. This package is a separate builder: the tests above edit pkg() by exact text.
const pkgSources = () => `<?xml version="1.0"?>
<DTS:Executable xmlns:DTS="www.microsoft.com/SqlServer/Dts"
  DTS:refId="Package"
  DTS:DTSID="{11111111-1111-1111-1111-111111111111}"
  DTS:ObjectName="Load"
  DTS:ProtectionLevel="0">
  <DTS:ConnectionManagers>
    <DTS:ConnectionManager DTS:refId="Package.ConnectionManagers[Dev]" DTS:DTSID="{22222222-2222-2222-2222-222222222222}" DTS:ObjectName="Dev">
      <DTS:PropertyExpression DTS:Name="ServerName">@[$Package::ServerName]</DTS:PropertyExpression>
      <DTS:ObjectData>
        <DTS:ConnectionManager DTS:ConnectionString="Data Source=.;Initial Catalog=Lab;Integrated Security=SSPI;" />
      </DTS:ObjectData>
    </DTS:ConnectionManager>
    <DTS:ConnectionManager DTS:refId="Package.ConnectionManagers[Stage]" DTS:DTSID="{44444444-4444-4444-4444-444444444444}" DTS:ObjectName="Stage">
      <DTS:PropertyExpression DTS:Name="ConnectionString">@[User::StageConnection]</DTS:PropertyExpression>
      <DTS:ObjectData>
        <DTS:ConnectionManager DTS:ConnectionString="Data Source=.;Initial Catalog=Stage;Integrated Security=SSPI;" />
      </DTS:ObjectData>
    </DTS:ConnectionManager>
    <DTS:ConnectionManager DTS:refId="Package.ConnectionManagers[Prod]" DTS:DTSID="{66666666-6666-6666-6666-666666666666}" DTS:ObjectName="Prod">
      <DTS:ObjectData>
        <DTS:ConnectionManager DTS:ConnectionString="Data Source=.;Initial Catalog=Prod;Integrated Security=SSPI;" />
      </DTS:ObjectData>
    </DTS:ConnectionManager>
  </DTS:ConnectionManagers>
  <DTS:Variables>
    <DTS:Variable DTS:CreationName="" DTS:DTSID="{aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa}" DTS:EvaluateAsExpression="True" DTS:Expression="&quot;Data Source=&quot; + @[$Package::StageServer]" DTS:Namespace="User" DTS:ObjectName="StageConnection">
      <DTS:VariableValue DTS:DataType="8">Data Source=stage-dev</DTS:VariableValue>
    </DTS:Variable>
    <DTS:Variable DTS:CreationName="" DTS:DTSID="{bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb}" DTS:Namespace="User" DTS:ObjectName="Retries">
      <DTS:VariableValue DTS:DataType="3">3</DTS:VariableValue>
    </DTS:Variable>
  </DTS:Variables>
  <DTS:PackageParameters>
    <DTS:PackageParameter DTS:CreationName="" DTS:DataType="8" DTS:DTSID="{77777777-7777-7777-7777-777777777777}" DTS:ObjectName="ServerName">
      <DTS:Property DTS:DataType="8" DTS:Name="ParameterValue">etl-dev</DTS:Property>
    </DTS:PackageParameter>
    <DTS:PackageParameter DTS:CreationName="" DTS:DataType="8" DTS:DTSID="{88888888-8888-8888-8888-888888888888}" DTS:ObjectName="StageServer">
      <DTS:Property DTS:DataType="8" DTS:Name="ParameterValue">stage-dev</DTS:Property>
    </DTS:PackageParameter>
    <DTS:PackageParameter DTS:CreationName="" DTS:DataType="3" DTS:DTSID="{99999999-9999-9999-9999-999999999999}" DTS:ObjectName="BatchSize">
      <DTS:Property DTS:DataType="3" DTS:Name="ParameterValue">100</DTS:Property>
    </DTS:PackageParameter>
  </DTS:PackageParameters>
  <DTS:Executables>
    <DTS:Executable DTS:refId="Package\\Truncate" DTS:CreationName="Microsoft.ExecuteSQLTask" DTS:DTSID="{33333333-3333-3333-3333-333333333333}" DTS:ExecutableType="Microsoft.ExecuteSQLTask" DTS:ObjectName="Truncate">
      <DTS:ObjectData>
        <SQLTask:SqlTaskData SQLTask:Connection="{22222222-2222-2222-2222-222222222222}" SQLTask:SqlStatementSource="TRUNCATE TABLE dbo.Staging" xmlns:SQLTask="www.microsoft.com/sqlserver/dts/tasks/sqltask" />
      </DTS:ObjectData>
    </DTS:Executable>
  </DTS:Executables>
</DTS:Executable>
`;

/** A temporary project holding pkgSources() as etl/P/Load.dtsx, and an Edit of that package judged by the guard. */
function sourcesProject() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-ssis-'));
  fs.mkdirSync(path.join(dir, 'etl', 'P'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'etl', 'P', 'P.dtproj'), dtproj());
  const file_path = path.join(dir, 'etl', 'P', 'Load.dtsx');
  fs.writeFileSync(file_path, pkgSources());
  return { dir, edit: (old_string, new_string) => guard(dir, 'Edit', { file_path, old_string, new_string }) };
}

test('guard: a package parameter or variable a connection reads is part of the connection; one it does not read is not (F1-28)', () => {
  const { dir, edit } = sourcesProject();
  try {
    // ServerName is read by the ServerName expression of Dev.
    const server = edit('DTS:Name="ParameterValue">etl-dev<', 'DTS:Name="ParameterValue">prod-sql01<');
    assert.equal(server.permissionDecision, 'ask');
    assert.match(server.permissionDecisionReason, /connection string|Critical/);
    // StageServer is read through the variable StageConnection, which the ConnectionString expression of Stage reads.
    assert.equal(edit('DTS:Name="ParameterValue">stage-dev<', 'DTS:Name="ParameterValue">prod-sql01<').permissionDecision, 'ask');
    assert.equal(edit('+ @[$Package::StageServer]', '+ @[$Package::ServerName]').permissionDecision, 'ask'); // the variable's expression
    assert.equal(edit('>Data Source=stage-dev<', '>Data Source=prod-sql01<').permissionDecision, 'ask'); // the variable's value
    // A parameter and a variable no connection reads stay ordinary package edits.
    assert.equal(edit('DTS:Name="ParameterValue">100<', 'DTS:Name="ParameterValue">200<').permissionDecision, 'allow');
    assert.equal(edit('>3</DTS:VariableValue>', '>5</DTS:VariableValue>').permissionDecision, 'allow');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('guard: the connection manager a task uses is part of the connection; the SQL it runs is not (F1-29)', () => {
  const { dir, edit } = sourcesProject();
  try {
    const repoint = edit('SQLTask:Connection="{22222222-2222-2222-2222-222222222222}"', 'SQLTask:Connection="{66666666-6666-6666-6666-666666666666}"');
    assert.equal(repoint.permissionDecision, 'ask');
    assert.match(repoint.permissionDecisionReason, /connection string|Critical/);
    assert.equal(edit('SQLTask:SqlStatementSource="TRUNCATE TABLE dbo.Staging"', 'SQLTask:SqlStatementSource="DELETE FROM dbo.Staging"').permissionDecision, 'allow');
    assert.equal(edit('DTS:ObjectName="Truncate"', 'DTS:ObjectName="Truncate staging"').permissionDecision, 'allow');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('validator: connection facts follow a variable expression to its parameter, end on a cycle and stop five levels down (F1-28)', () => {
  const variable = (name, value, expression = '', namespace = 'User') =>
    `<DTS:Variable${expression ? ` DTS:EvaluateAsExpression="True" DTS:Expression="${expression}"` : ''} DTS:Namespace="${namespace}" DTS:ObjectName="${name}"><DTS:VariableValue DTS:DataType="8">${value}</DTS:VariableValue></DTS:Variable>`;
  const small = (variables, expression) => `<DTS:Executable xmlns:DTS="www.microsoft.com/SqlServer/Dts" DTS:refId="Package"><DTS:ConnectionManagers><DTS:ConnectionManager DTS:refId="Package.ConnectionManagers[Db]" DTS:ObjectName="Db"><DTS:PropertyExpression DTS:Name="ServerName">${expression}</DTS:PropertyExpression></DTS:ConnectionManager></DTS:ConnectionManagers><DTS:Variables>${variables}</DTS:Variables></DTS:Executable>`;
  const moved = (text, from, to) => {
    assert.ok(text.includes(from), `fixture lacks ${from}`);
    return ssisConnectionFacts(text) !== ssisConnectionFacts(text.replace(from, to));
  };
  // Vi reads V(i+1); the last one holds the server. A connection reading V1 sees five levels.
  const chain = (n) => small(Array.from({ length: n }, (_, i) => variable(`V${i + 1}`, i + 1 < n ? `v${i + 1}` : 'leaf', i + 1 < n ? `@[User::V${i + 2}]` : '')).join(''), '@[User::V1]');
  assert.ok(moved(chain(5), '>leaf<', '>other<'), 'the fifth level');
  assert.ok(!moved(chain(6), '>leaf<', '>other<'), 'the sixth level is past the bound');
  assert.ok(moved(chain(6), '>v5<', '>w5<'), 'the fifth level of a longer chain');
  // A reads B and B reads A; a variable that reads itself.
  const cycle = small(variable('A', 'a', '@[User::B]') + variable('B', 'b', '@[User::A]'), '@[User::A]');
  assert.ok(moved(cycle, '>b<', '>c<'), 'a cycle');
  const self = small(variable('A', 'a', '@[User::A] + 1'), '@[User::A]');
  assert.ok(moved(self, '>a<', '>b<'), 'a variable that reads itself');
  // The ways an expression names a variable: another namespace, no namespace, and no brackets.
  for (const [namespace, expression] of [['Config', '@[Config::Server]'], ['User', '@[Server]'], ['User', '"Data Source=" + @Server']]) {
    assert.ok(moved(small(variable('Server', 'localhost', '', namespace), expression), '>localhost<', '>prod-sql01<'), expression);
  }
  // Nothing to resolve in the package, or nothing a connection reads.
  for (const expression of ['@[System::MachineName]', '@[$Project::Server]']) {
    assert.ok(!moved(small(variable('Server', 'localhost'), expression), '>localhost<', '>prod-sql01<'), expression);
  }
  const taskExpression = small(variable('Server', 'localhost'), '"x"').replace('</DTS:Variables>',
    '</DTS:Variables><DTS:Executable DTS:refId="Package\\Task"><DTS:PropertyExpression DTS:Name="Description">@[User::Server]</DTS:PropertyExpression></DTS:Executable>');
  assert.ok(!moved(taskExpression, '>localhost<', '>prod-sql01<'), 'a task expression is not a connection expression');
  // A variable inside a comment does not count; a comment that opens a connection manager does not hide the real one.
  const commented = small(variable('Server', 'localhost'), '@[User::Server]').replace('<DTS:Variables>', '<!-- <DTS:ConnectionManager DTS:refId="x"> --><!-- <DTS:Variable DTS:Namespace="User" DTS:ObjectName="Server"><DTS:VariableValue>old</DTS:VariableValue></DTS:Variable> --><DTS:Variables>');
  assert.ok(moved(commented, '>localhost<', '>prod-sql01<'), 'comments');
  assert.ok(!moved(commented, '>old<', '>older<'), 'commented-out variable');
  // The Connection attribute of any task data counts, whatever the prefix (synthetic prefix; SQLTask is tested above).
  const other = '<DTS:Executable xmlns:DTS="www.microsoft.com/SqlServer/Dts"><Other:Data Other:Connection="{A}" Other:SourceConnection="{B}" Other:Note="{C}" xmlns:Other="x" /></DTS:Executable>';
  assert.ok(moved(other, 'Other:Connection="{A}"', 'Other:Connection="{D}"'), 'any prefix: Connection');
  assert.ok(moved(other, 'Other:SourceConnection="{B}"', 'Other:SourceConnection="{D}"'), 'any prefix: SourceConnection');
  assert.ok(!moved(other, 'Other:Note="{C}"', 'Other:Note="{D}"'), 'another attribute of the task data');
});

test('shell: validating a package is routine; running it and deploying to SSISDB need the user', () => {
  assert.equal(analyzeShellCommand('dtexec /F etl/P/Load.dtsx /Validate', {}), null);
  for (const cmd of ['dtexec /F etl/P/Load.dtsx', 'ISDeploymentWizard /Silent /SourcePath:x.ispac /DestinationServer:. /DestinationPath:/SSISDB/F/P', 'dtutil /FILE x.dtsx /COPY SQL;x']) {
    const v = analyzeShellCommand(cmd, {});
    assert.equal(v?.decision, 'ask', cmd);
    assert.equal(v?.autoApprovable, false, cmd);
  }
});
