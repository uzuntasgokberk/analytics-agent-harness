// Validator changes found in a test run against Power BI Desktop (each one blocked Desktop or skipped a file).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { affectedArtifacts, findPbipItems, isTextFile, validateArtifacts, validateFileText, validateFiles, xmlProblem } from '../hooks/lib/validators.mjs';
import { analyzeShellCommand } from '../hooks/lib/policy.mjs';

test('.sql files are text files, so the secret scan reads them', () => {
  assert.equal(isTextFile('docs/sources/sql/view.sql'), true);
});

test('a /// description above a relationship is an error', () => {
  const text = "/// Order date\nrelationship 'Sales Order Date'\n\tfromColumn: Sales.'Order Date Key'\n\ttoColumn: Date.'Date Key'\n";
  const issues = validateFileText('m.SemanticModel/definition/relationships.tmdl', text, {});
  assert.ok(issues.some((i) => i.level === 'error' && /relationship has no description/.test(i.message)));
});

test('a /// line followed by a blank line is an error for any object, not for a DAX comment inside an expression', () => {
  const rel = "/// Order date\n\nrelationship 'Sales Order Date'\n\tfromColumn: Sales.'Order Date Key'\n\ttoColumn: Date.'Date Key'\n";
  const relIssues = validateFileText('m.SemanticModel/definition/relationships.tmdl', rel, {});
  assert.equal(relIssues.filter((i) => i.level === 'error').length, 1);
  assert.ok(relIssues.some((i) => /directly above its object/.test(i.message)));
  const measure = 'table T\n\n\t/// Net sales\n\n\tmeasure Sales = 1\n';
  assert.ok(validateFileText('m.SemanticModel/definition/tables/T.tmdl', measure, {}).some((i) => i.level === 'error' && /directly above its object/.test(i.message)));
  const daxComment = 'table T\n\n\tmeasure Sales =\n\t\t\tVAR x = 1\n\t\t\t/// a comment\n\n\t\t\tRETURN x\n\n\tmeasure Other = 2\n';
  assert.ok(!validateFileText('m.SemanticModel/definition/tables/T.tmdl', daxComment, {}).some((i) => /directly above its object/.test(i.message)));
});

test('a measure named like a column of another table is a warning, not an error', () => {
  const dir = tempProject({
    'M.SemanticModel/definition.pbism': '{}',
    'M.SemanticModel/definition/model.tmdl': 'model Model\n',
    'M.SemanticModel/definition/tables/Fact.tmdl': 'table Fact\n\n\tcolumn Amount\n\t\tdataType: int64\n\t\tsourceColumn: Amount\n',
    'M.SemanticModel/definition/tables/Dim.tmdl': "table Dim\n\n\tmeasure Amount = SUM ( 'Fact'[Amount] )\n\t\tformatString: 0\n",
  });
  const issues = validateArtifacts(dir, { models: ['M.SemanticModel'], reports: [] });
  fs.rmSync(dir, { recursive: true, force: true });
  assert.ok(issues.some((i) => i.level === 'warn' && /column of table 'Fact'\. It loads/.test(i.message)));
  assert.ok(!issues.some((i) => i.level === 'error' && /has the name of a column/.test(i.message)));
});

test('a relationship without a description passes', () => {
  const text = "relationship 'Sales Order Date'\n\tfromColumn: Sales.'Order Date Key'\n\ttoColumn: Date.'Date Key'\n";
  const issues = validateFileText('m.SemanticModel/definition/relationships.tmdl', text, {});
  assert.ok(!issues.some((i) => /relationship has no description/.test(i.message)));
});

function tempProject(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-validators-'));
  for (const [rel, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), content);
  }
  return dir;
}

test('a measure with the name of a column of its table is an error', () => {
  const dir = tempProject({
    'M.SemanticModel/definition.pbism': '{}',
    'M.SemanticModel/definition/model.tmdl': 'model Model\n',
    'M.SemanticModel/definition/tables/T.tmdl':
      "table T\n\n\tmeasure 'Target Amount' = SUM ( 'T'[Target Amount] )\n\t\tformatString: 0\n\n\tcolumn 'Target Amount'\n\t\tdataType: decimal\n\t\tsourceColumn: TargetAmount\n",
  });
  const issues = validateArtifacts(dir, { models: ['M.SemanticModel'], reports: [] });
  fs.rmSync(dir, { recursive: true, force: true });
  assert.ok(issues.some((i) => i.level === 'error' && /has the name of a column/.test(i.message)));
});

// 2026-10-11 audit: a TMDL model whose folder is the repository root was never found by the full scan, so its
// model-wide checks (duplicate measures, DAX references, perspectives) ran only in --changed mode, with "./" paths.
test('an Analysis Services model at the repository root is found by the full scan and gets the model-wide checks', () => {
  const dir = tempProject({
    'database.tmdl': 'database Finance\n\tcompatibilityLevel: 1600\n',
    'model.tmdl': 'model Model\n\nref table Sales\nref table Dim\n',
    'tables/Sales.tmdl': 'table Sales\n\n\tmeasure Revenue = SUM ( Sales[Amount] )\n\t\tformatString: 0\n\n\tcolumn Amount\n\t\tdataType: decimal\n\t\tsourceColumn: Amount\n',
    'tables/Dim.tmdl': 'table Dim\n\n\tmeasure Revenue = 1\n\t\tformatString: 0\n\n\tcolumn Key\n\t\tdataType: int64\n\t\tsourceColumn: Key\n',
    'perspectives/Finance.tmdl': 'perspective Finance\n\n\tperspectiveTable Gone\n',
  });
  const items = findPbipItems(dir, {}, Infinity);
  assert.deepEqual(items.tabular, ['.']);
  assert.deepEqual([items.models, items.reports, items.rdl, items.ssis], [[], [], [], []]);
  const full = validateArtifacts(dir, items);
  assert.ok(full.some((i) => i.level === 'error' && i.file === 'tables/Sales.tmdl' && /Measure "revenue" is also defined in Dim\.tmdl/.test(i.message)), JSON.stringify(full));
  assert.ok(full.some((i) => i.level === 'error' && i.file === 'perspectives/Finance.tmdl' && /names 'Gone'/.test(i.message)));
  assert.ok(!full.some((i) => i.file.startsWith('./')));
  // The same model through the changed-files route (the Stop gate): the root is one artifact, with plain paths.
  assert.deepEqual(affectedArtifacts(['tables/Dim.tmdl', 'model.tmdl']).tabular, ['.']);
  const changed = validateFiles(dir, {}, ['tables/Dim.tmdl']);
  assert.ok(changed.issues.some((i) => i.level === 'error' && i.file === 'tables/Sales.tmdl' && /also defined/.test(i.message)));
  fs.rmSync(dir, { recursive: true, force: true });
});

test('the inventory lists every layer: nested models, paginated reports and SSIS folders, each only once', () => {
  const dir = tempProject({
    'models/Finance/database.tmdl': 'database Finance\n\tcompatibilityLevel: 1600\n',
    'models/Finance/model.tmdl': 'model Model\n',
    'paginated/Orders.rdl': '<Report/>',
    'reports/x/rdl/Invoices.rdl': '<Report/>',
    'etl/Load/Load.dtsx': '<DTS:Executable xmlns:DTS="www.microsoft.com/SqlServer/Dts"/>',
    'etl/Load/Load.dtproj': '<Project/>',
    'etl/Load/Project.params': '<Parameters/>',
  });
  const items = findPbipItems(dir, {}, Infinity);
  fs.rmSync(dir, { recursive: true, force: true });
  assert.deepEqual(items.tabular, ['models/Finance']);
  assert.deepEqual(items.rdl.sort(), ['paginated/Orders.rdl', 'reports/x/rdl/Invoices.rdl']);
  assert.deepEqual(items.ssis, ['etl/Load']);
});

test('a semantic model folder with modelReference.json (live connection) needs no definition folder', () => {
  const dir = tempProject({
    'Live.SemanticModel/definition.pbism': '{}',
    'Live.SemanticModel/modelReference.json': '{"connectionType":"analysisServicesDatabaseLive"}',
  });
  const issues = validateArtifacts(dir, { models: ['Live.SemanticModel'], reports: [] });
  fs.rmSync(dir, { recursive: true, force: true });
  assert.ok(!issues.some((i) => /Missing the TMDL model definition/.test(i.message)));
});

function rdlWithBodyWidth(width) {
  return `<?xml version="1.0" encoding="utf-8"?>
<Report xmlns="http://schemas.microsoft.com/sqlserver/reporting/2016/01/reportdefinition">
  <ReportSections><ReportSection><Body><Height>1cm</Height></Body><Width>${width}</Width>
  <Page><PageHeight>21cm</PageHeight><PageWidth>29.7cm</PageWidth><LeftMargin>1.5cm</LeftMargin><RightMargin>1.5cm</RightMargin></Page>
  </ReportSection></ReportSections>
</Report>`;
}

test('an RDL body that fills the page width exactly gets a page-fit warning; a few millimetres of slack pass', () => {
  const exact = validateFileText('paginated/r.rdl', rdlWithBodyWidth('26.7cm'), {});
  assert.ok(exact.some((i) => /leaves only 0\.0 mm spare on the page .*blank page after each page/.test(i.message)));
  const slack = validateFileText('paginated/r.rdl', rdlWithBodyWidth('26.5cm'), {});
  assert.ok(!slack.some((i) => /blank page|wider than/.test(i.message)));
});

test('a body up to 0.01 inch too wide is reported as too wide, not as spare room', () => {
  const issues = validateFileText('paginated/r.rdl', rdlWithBodyWidth('26.72cm'), {});
  assert.ok(issues.some((i) => /is 0\.2 mm wider than the page/.test(i.message)));
  assert.ok(!issues.some((i) => /leaves only/.test(i.message)));
});

test('every report section is checked, and a missing PageWidth means Letter portrait', () => {
  const two = rdlWithBodyWidth('26.5cm').replace('</ReportSection></ReportSections>',
    '</ReportSection><ReportSection><Body><Height>1cm</Height></Body><Width>8.5in</Width><Page><LeftMargin>0in</LeftMargin><RightMargin>0in</RightMargin></Page></ReportSection></ReportSections>');
  const issues = validateFileText('paginated/r.rdl', two, {});
  assert.ok(issues.some((i) => /^Report section 2: body .*default page \(no PageWidth: Letter portrait/.test(i.message)));
  assert.ok(!issues.some((i) => /^Report section 1/.test(i.message)));
});

// 2026-10-16 audit of fe1dd6f: xmlProblem only tracked quotes, "<" and ">", so '<Report Bogus=unquoted>' passed as
// well-formed (RDL and SSIS alike). It is now a tokenizer; each case names the message prefix it must give.
test('XML well-formedness: attributes, roots, text outside the root and the declaration are checked', () => {
  const cases = [
    ['<Report Bogus=unquoted></Report>', /^attribute Bogus has no quoted value/],
    ['<Report Bogus></Report>', /^attribute Bogus has no value/],
    ['<Report Name="a" Name="b"/>', /^attribute Name appears twice in <Report>/],
    ['<Report Name="a<b"/>', /^attribute Name has "<" in its value/],
    [`<Report Name="x'></Report>`, /^attribute Name has no closing "/],
    [`<Report Name="x'><Page Size="A4"/></Report>`, /^attribute Name has no closing "/],
    ['<Report a="1"b="2"/>', /^attribute b needs whitespace before it/],
    ['<Report Name="a & b"/>', /^unescaped "&"/],
    ['<Report/><Report/>', /^more than one root element/],
    ['<Report/>junk', /^text after the root element/],
    ['junk<Report/>', /^text before the root element/],
    ['\n<?xml version="1.0"?><Report/>', /^the XML declaration <\?xml \.\.\.\?> must be at the very start/],
    ['<Report/><?xml version="1.0"?>', /^the XML declaration/],
    ['<?xml encoding="utf-8"?><Report/>', /^malformed XML declaration/],
    ['<a:b:c/>', /^invalid tag name "a:b:c"/],
    ['<Report>a < b</Report>', /^unescaped "<" in text/],
    ['<Report>a & b</Report>', /^unescaped "&"/],
    ['<Report / >', /^"\/" in <Report> must be followed by ">"/],
    ['<Report><!-- a -- b --></Report>', /^a comment must not contain "--"/],
    ['<![CDATA[x]]><Report/>', /^CDATA section outside the root element/],
    ['<Report><Body></Report></Body>', /^<\/Report> closes <Body>/],
    ['<Report>\n<Body></Body>', /^<Report> is not closed/],
    ['<DTS:Executable', /^unclosed tag/],
    ['<!-- only a comment -->', /^no root element/],
  ];
  for (const [xml, expected] of cases) {
    const problem = xmlProblem(xml);
    assert.ok(problem, `accepted: ${xml}`);
    assert.match(problem.message, expected, xml);
  }
  assert.equal(xmlProblem('\n<?xml version="1.0"?><Report/>').line, 2);
  assert.equal(xmlProblem('<Report>\n<Body></Body>').line, 1); // the start tag that is not closed
  // The audit's case end to end: an .rdl with it is an error, and the guard message carries the reason.
  const rdl = validateFileText('paginated/r.rdl', '<Report Bogus=unquoted></Report>', {});
  assert.ok(rdl.some((i) => i.level === 'error' && /^Malformed XML: attribute Bogus has no quoted value/.test(i.message)));
});

test('XML well-formedness: valid markup that a naive check gets wrong still passes', () => {
  const valid = [
    '<Report><Code><![CDATA[If a < b And c & d Then]]></Code></Report>',
    '<Report Name="a &amp; b"/>',
    `<Report Name="O'Brien"/>`,
    `<Report Name='say "hi"'/>`,
    '<Report><Page /><Body/></Report>',
    '<rd:Report xmlns:rd="urn:x" rd:Name="a"></rd:Report>',
    '<Report Filter="a > b" Name = "x"></Report  >',
    `<?xml version='1.0' encoding='UTF-8' standalone='yes'?>\n<!DOCTYPE Report [ <!ENTITY x "y"> ]>\n<Report/>\n<!-- after -->\n`,
    '<Rapor Adı="şu"><Ürün/></Rapor>',
    // Report Builder style: BOM, rd: and df: namespaces, an expression with &amp;, a comment with single dashes.
    '﻿<?xml version="1.0" encoding="utf-8"?>\n<Report MustUnderstand="df" xmlns="http://schemas.microsoft.com/sqlserver/reporting/2016/01/reportdefinition" xmlns:rd="http://schemas.microsoft.com/SQLServer/reporting/reportdesigner" xmlns:df="urn:df">\n  <!-- a - b -->\n  <df:DefaultFontFamily>Segoe UI</df:DefaultFontFamily>\n  <Value>=Fields!A.Value &amp; " (" &amp; Parameters!P.Label &amp; ")"</Value>\n  <CommandText>SELECT a FROM t WHERE x &lt; 3 AND y &gt; 1</CommandText>\n  <rd:ReportID>00000000-0000-0000-0000-00000000abcd</rd:ReportID>\n</Report>\n',
    // SSDT style: character references and escaped quotes in attribute values, CDATA SQL, a processing instruction.
    '<?xml version="1.0"?>\n<DTS:Executable xmlns:DTS="www.microsoft.com/SqlServer/Dts" DTS:Expression="@[User::A] &gt; 0 ? &quot;x&quot; : &quot;y&quot;">\n  <DTS:VariableValue DTS:DataType="8">line1&#xA;line2&#9;</DTS:VariableValue>\n  <SQLTask:SqlTaskData SQLTask:SqlStatementSource="SELECT 1&#xD;&#xA;WHERE c &gt; \'d\'" xmlns:SQLTask="www.microsoft.com/sqlserver/dts/tasks/sqltask" />\n  <property name="SqlCommand"><![CDATA[SELECT * FROM t WHERE a < 3 && b > 2]]></property>\n  <?vs-designer info?>\n</DTS:Executable>\n',
  ];
  for (const xml of valid) assert.equal(xmlProblem(xml), null, xml);
});

// Second audit of the guards (2026-10-16): "]]>" in text passed, though XML 1.0 (CharData) forbids it outside a CDATA
// section; Report Builder and Visual Studio refuse such a file.
test('XML well-formedness: "]]>" in text is refused with its line; in CDATA, comments, attributes and PIs it passes', () => {
  for (const xml of ['<Report>a]]>b</Report>', '<Report><Value>x]]></Value></Report>', '<Report><![CDATA[a]]>]]></Report>']) {
    const problem = xmlProblem(xml);
    assert.ok(problem, `accepted: ${xml}`);
    assert.match(problem.message, /^"\]\]>" in text outside a CDATA section/, xml);
  }
  assert.equal(xmlProblem('<Report>\n<Value>\n]]>\n</Value></Report>').line, 3);
  for (const xml of [
    '<Report><![CDATA[a ]] > b ]]></Report>',
    '<Report><Code><![CDATA[If x(1)(2) Then]]></Code></Report>',
    '<Report><!-- ]]> --></Report>',
    '<Report Name="a]]>b"/>',
    '<Report><?pi ]]> ?></Report>',
    '<Report>]] &gt; ]]&gt; ]]</Report>',
  ]) assert.equal(xmlProblem(xml), null, xml);
  const rdl = validateFileText('paginated/r.rdl', '<Report>\n<Value>a]]>b</Value></Report>', {});
  assert.ok(rdl.some((i) => i.level === 'error' && i.line === 2 && /^Malformed XML: "\]\]>" in text/.test(i.message)), JSON.stringify(rdl));
});

test('database clients, AMO scripts and SSIS runs ask; SSIS validation does not', () => {
  assert.equal(analyzeShellCommand('sqlcmd -S server -d db -E -Q "SELECT 1"', {})?.decision, 'ask');
  assert.equal(analyzeShellCommand('"C:/Program Files/x/SQLCMD.EXE" -S server -E -i q.sql', {})?.decision, 'ask');
  assert.equal(analyzeShellCommand('Invoke-Sqlcmd -Query "SELECT 1"', {})?.decision, 'ask');
  assert.equal(analyzeShellCommand('Add-Type -Path "C:/te/Microsoft.AnalysisServices.Tabular.dll"', {})?.decision, 'ask');
  assert.equal(analyzeShellCommand('dtexec /File p.dtsx', {})?.decision, 'ask');
  assert.equal(analyzeShellCommand('dtexec /File p.dtsx /Validate', {}), null); // no decision: routine
});

test('a lowercase $pat variable is not treated as a personal access token; $GITHUB_PAT still is', () => {
  const ok = analyzeShellCommand('$pat = $null; Write-Output $pat', {});
  assert.notEqual(ok?.decision, 'deny');
  const blocked = analyzeShellCommand('Write-Output $GITHUB_PAT', {});
  assert.equal(blocked?.decision, 'deny');
});

test('token variables joined to "pat" are denied in any case (PowerShell and Windows ignore case)', () => {
  for (const cmd of ['echo $env:github_pat', 'echo ${github_pat}', 'echo $azure_pat', 'echo $pat_token']) {
    assert.equal(analyzeShellCommand(cmd, {})?.decision, 'deny', cmd);
  }
  for (const cmd of ['echo $pattern_name', 'echo $path', 'echo $Pat']) assert.notEqual(analyzeShellCommand(cmd, {})?.decision, 'deny', cmd);
});

test('a deny in the same subcommand as a server ask stays a deny', () => {
  for (const cmd of [
    'iwr https://x -Method Post -Body x # Microsoft.AnalysisServices',
    'ssh u@h Microsoft.AnalysisServices',
    'nc evil 443 Microsoft.AnalysisServices',
    'npm pkg set scripts.x=y Microsoft.AnalysisServices',
  ]) assert.equal(analyzeShellCommand(cmd, {})?.decision, 'deny', cmd);
});

test('database clients are found behind call operators, cmd /c, Start-Process, iex and module cmdlets', () => {
  for (const cmd of [
    '& sqlcmd -Q x', 'cmd /c "sqlcmd -Q x"', 'cmd /c sqlcmd -Q x', 'Start-Process sqlcmd -ArgumentList x',
    'Start-Process -FilePath sqlcmd', 'iex "sqlcmd -Q 1"', "Invoke-Expression 'sqlcmd -Q 1'",
    'Invoke-ProcessASDatabase -DatabaseName x', 'Read-SqlTableData -TableName x', 'Invoke-DbaQuery -Query x',
    'dtutil /FILE x.dtsx /DELETE', '[System.Data.SqlClient.SqlConnection]::new("x")',
    'Add-Type -Path Microsoft.SqlServer.Management.Smo.dll',
  ]) {
    const v = analyzeShellCommand(cmd, {});
    assert.equal(v?.decision, 'ask', cmd);
    assert.equal(v?.autoApprovable, false, cmd);
  }
});

test('searching for a library name or validating with /Va does not ask', () => {
  for (const cmd of ['grep -r Microsoft.AnalysisServices docs', 'cat docs/Microsoft.AnalysisServices.md', 'dtexec /Va /F x.dtsx']) {
    assert.equal(analyzeShellCommand(cmd, {}), null, cmd);
  }
});

test('publish, deploy and push asks are never auto-approvable, also after an ordinary ask', () => {
  const ctx = { protectedBranches: ['main'], getBranch: () => 'feature/x' };
  for (const cmd of ['Publish-PowerBIReport -Path x', 'node build.js; Publish-PowerBIReport -Path x', 'git push origin feature/x', 'node a.js && git push']) {
    const v = analyzeShellCommand(cmd, ctx);
    assert.equal(v?.decision, 'ask', cmd);
    assert.equal(v?.autoApprovable, false, cmd);
  }
  assert.notEqual(analyzeShellCommand('node x.js', ctx)?.autoApprovable, false);
});

// 2026-10-07: the deploy pattern knew Publish-/New-/Remove-PowerBI*, fab deploy, pbi-tools, Tabular Editor 2, the SSIS
// wizard and az; the other ways to write to a server or process a model passed without the floor ask.
test('writes to the Power BI service, Reporting Services and Analysis Services are floor asks', () => {
  for (const cmd of [
    'Connect-PowerBIServiceAccount', 'Login-PowerBI', 'Set-PowerBIWorkspace -Id x -Name y', 'Set-PowerBIDataset -Id x -TargetStorageMode PremiumFiles',
    'Add-PowerBIRow -DatasetId x -TableName t -Rows $r', 'Copy-PowerBIReport -Id x -TargetWorkspaceId y', 'Import-PowerBIDataflow -Path x.json',
    'Restore-PowerBIWorkspace -Id x -AdminUserPrincipalName a@example.com', 'Export-PowerBIDataflow -Id x -OutFile flow.json',
    'rs -i deploy.rss -s https://srv/reportserver', 'rs.exe -s https://srv/reportserver -i deploy.rss',
    'Write-RsCatalogItem -ReportServerUri https://srv/reportserver -Path x.rdl -RsFolder /Sales',
    'Write-RsRestFolderContent -Path reports -RsFolder /Sales', 'Publish-RsProject -ProjectFile x.rptproj -Target /Sales',
    'Set-RsDataSource -Path /Sales/DS -DataSourceDefinition $d', 'New-RsDataSource -RsFolder /Sales -Name DS -Extension SQL -ConnectionString x',
    'Invoke-ProcessASDatabase -Server srv -DatabaseName Sales -RefreshType Full', 'Invoke-ProcessTable -Server srv -DatabaseName Sales -TableName Fact -RefreshType Full',
    'Invoke-ProcessPartition -Server srv -DatabaseName Sales -TableName Fact -PartitionName P1 -RefreshType Full', 'Merge-Partition -Server srv -DatabaseName Sales -TableName Fact -Target P1 -Source P2',
    'Microsoft.AnalysisServices.Deployment.exe Sales.asdatabase /s', 'TabularEditor3.exe model.bim -D srv Sales',
    'fab create ws.Workspace/Sales.SemanticModel', 'fab export ws.Workspace/Sales.Report -o out', 'fab auth login',
    // K-15 (2026-10-07): a project's own deploy script or a TMSL deploy typed on the command line, the floor in lab mode too.
    'pwsh -NoProfile -File models/Demo/deploy/script-model.ps1 -Deploy -Replace 2>&1 | Select-Object -Last 12', '& ./deploy-model.ps1',
    'powershell -NoProfile -File .\\scripts\\deploy-sales.ps1', 'Invoke-ASCmd -Server localhost -Query "<Statement/>"',
    'Invoke-ASCmd -Server localhost -InputFile createOrReplace.xmla', 'node tools/push.mjs --deploy', 'python deploy.py --deploy=prod',
  ]) {
    const v = analyzeShellCommand(cmd, {});
    assert.equal(v?.decision, 'ask', cmd);
    assert.equal(v?.floor, true, cmd);
  }
  for (const cmd of ['Get-PowerBIWorkspace -All', 'Get-RsFolderContent -RsFolder /Sales', 'Get-PowerBIReport -WorkspaceId x', 'fab ls ws.Workspace', 'Get-ChildItem reports', 'git commit -m "colors -s fix"',
    'grep -n createOrReplace docs/notes.md', 'git commit -m "add the -Deploy switch"', 'cat deploy-model.ps1', 'Write-Host createOrReplace', 'echo -Deploy', 'ls models/Demo/deploy']) {
    assert.equal(analyzeShellCommand(cmd, {}), null, cmd);
  }
  assert.equal(analyzeShellCommand('node scripts/check.mjs', {})?.floor, undefined, 'an ordinary script run keeps its ordinary ask');
  // A backup file is a data file: the data rule denies before the floor ask is reached.
  for (const cmd of ['Restore-ASDatabase -Server srv -RestoreFile x.abf -Name Sales', 'Backup-ASDatabase x.abf Sales']) {
    assert.equal(analyzeShellCommand(cmd, {})?.decision, 'deny', cmd);
  }
});

test('membership on a server (workspace users, Reporting Services roles, model roles) is denied, not asked', () => {
  for (const cmd of [
    'Add-PowerBIWorkspaceUser -Id x -UserPrincipalName a@example.com -AccessRight Admin', 'Remove-PowerBIWorkspaceUser -Id x -UserPrincipalName a@example.com',
    'Grant-RsCatalogItemRole -Identity DOMAIN\\x -RoleName Browser -Path /Sales', 'Revoke-RsCatalogItemAccess -Identity DOMAIN\\x -Path /Sales',
    'Grant-RsSystemRole -Identity DOMAIN\\x -RoleName "System User"', 'Add-RoleMember -Server srv -Database Sales -RoleName Readers -MemberName DOMAIN\\x',
  ]) {
    assert.equal(analyzeShellCommand(cmd, {})?.decision, 'deny', cmd);
  }
});

test('a script run directly asks like one run through an interpreter', () => {
  assert.equal(analyzeShellCommand('& "C:/tmp/tool.ps1" -Id 1', {})?.decision, 'ask');
  assert.equal(analyzeShellCommand('./run.sh', {})?.decision, 'ask');
  assert.equal(analyzeShellCommand('node hardening/scripts/validate.mjs', {}), null);
});

// Eval run 2: `--help` ran a full validation of 539 files; a mistyped flag did the same without a word.
test('the validator CLI prints its usage for --help and refuses an unknown flag instead of scanning everything', async () => {
  const { spawnSync } = await import('node:child_process');
  const { fileURLToPath } = await import('node:url');
  const cli = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'scripts', 'validate.mjs');
  const run = (...args) => spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8', cwd: os.tmpdir() });
  const help = run('--help');
  assert.equal(help.status, 0);
  assert.match(help.stdout, /--changed/);
  assert.doesNotMatch(help.stdout, /PBIP validation/);
  const typo = run('--chnaged');
  assert.equal(typo.status, 2);
  assert.match(typo.stderr, /unknown option --chnaged/);
});

// 2026-10-16 audit of fe1dd6f: the summary line did not say that it is a static check only, while AGENTS.md and
// docs/static-checks.md report engine, reconciliation and Desktop checks separately.
test('the validator text output says it is a static check only; --json does not, and 0 errors exit 0', async () => {
  const { spawnSync } = await import('node:child_process');
  const { fileURLToPath } = await import('node:url');
  const cli = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'scripts', 'validate.mjs');
  const dir = tempProject({ 'notes.md': '# Notes\n', 'paginated/r.rdl': rdlWithBodyWidth('26.5cm') });
  const run = (...args) => spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8', cwd: dir, env: { ...process.env, CLAUDE_PROJECT_DIR: dir } });
  try {
    const text = run();
    assert.equal(text.status, 0, text.stdout + text.stderr);
    const lines = text.stdout.trim().split(/\r?\n/);
    const summary = lines.findIndex((l) => /^Summary: 0 error\(s\)/.test(l));
    assert.ok(summary >= 0, text.stdout);
    // The marker and the guide it points to, not the whole sentence (follow-up audit, F2-62).
    assert.match(lines[summary + 1], /^Static check only:/);
    assert.match(lines[summary + 1], /docs\/static-checks\.md/);
    const json = run('--json');
    assert.equal(json.status, 0, json.stdout + json.stderr);
    assert.ok(JSON.parse(json.stdout).checked >= 2);
    assert.doesNotMatch(json.stdout, /Static check only/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
