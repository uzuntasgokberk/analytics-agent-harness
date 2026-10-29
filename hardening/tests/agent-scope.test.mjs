// Subagent scopes (hooks/agent-scope.mjs with the default agentScopes): the modeler also owns a report's test pack and
// SQL folder, the doc generator a report's docs folder (the layout of docs/conventions.md), reviewers never write. A
// shell command that could change files or git state is judged by what it really runs, in every spelling; the Power BI
// MCP server is read-only for them; every agent file has a scope (F1-46, F1-54, F1-63).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { DEFAULT_CONFIG } from '../hooks/lib/common.mjs';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const hook = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'hooks', 'agent-scope.mjs');

function decide(dir, agent, tool, tool_input) {
  const r = spawnSync(process.execPath, [hook], {
    input: JSON.stringify({ hook_event_name: 'PreToolUse', session_id: 'scope', agent_type: agent, tool_name: tool, tool_input }),
    env: { ...process.env, CLAUDE_PROJECT_DIR: dir },
    encoding: 'utf8',
  });
  assert.equal(r.status, 0, r.stderr);
  return r.stdout.trim() ? JSON.parse(r.stdout).hookSpecificOutput?.permissionDecision ?? null : null;
}

test('agent scopes: the modeler and the doc generator write inside the layout folders, reviewers do not write', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-scope-'));
  const write = (agent, rel) => decide(dir, agent, 'Write', { file_path: path.join(dir, rel), content: 'x' });
  try {
    for (const rel of ['powerbi/Sales.SemanticModel/definition/tables/Fact.tmdl', 'models/Finance/tables/Fact.tmdl', 'docs/sources/README.md',
      'docs/tests/expected-values.md', 'reports/store-kpis/tests/pack.md', 'reports/store-kpis/sql/StoreKpis.sql', 'TASKS.md']) {
      assert.equal(write('bi-tmdl-modeler', rel), null, `modeler: ${rel}`);
    }
    for (const rel of ['powerbi/Sales.Report/definition/pages/p1/page.json', 'reports/store-kpis/docs/01-model.md', 'README.md']) {
      assert.equal(write('bi-tmdl-modeler', rel), 'deny', `modeler out of scope: ${rel}`);
    }
    for (const rel of ['docs/model/measures.md', 'reports/store-kpis/docs/01-model.md', 'docs/report/pages.md']) {
      assert.equal(write('bi-doc-generator', rel), null, `doc generator: ${rel}`);
    }
    for (const rel of ['powerbi/Sales.SemanticModel/definition/tables/Fact.tmdl', 'reports/store-kpis/tests/pack.md', 'README.md']) {
      assert.equal(write('bi-doc-generator', rel), 'deny', `doc generator out of scope: ${rel}`);
    }
    for (const agent of ['bi-dax-reviewer', 'bi-report-reviewer', 'bi-security-auditor', 'bi-validator', 'bi-source-analyst', 'bi-rdl-analyst']) {
      assert.equal(write(agent, 'docs/x.md'), 'deny', agent);
      assert.equal(decide(dir, agent, 'Bash', { command: 'awk -i inplace "{print}" docs/x.md' }), 'deny', `${agent} shell edit`);
      assert.equal(decide(dir, agent, 'Bash', { command: 'git status' }), null, `${agent} git status`);
    }
    assert.equal(write('general-purpose', 'anything.md'), null, 'an agent without a scope is not limited here');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// The SSIS editor writes inside etl/<project>/ (packages, project files, sql/ and jobs/ scripts), the SSIS test pack and
// TASKS.md; a template, a model, a report or the registry are out of scope. It validates a package with dtexec /Validate
// (a check, not a change), and the Power BI modeling MCP server is read-only for it.
test('agent scopes: the SSIS editor writes inside etl/<project>/ and validates with dtexec', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-scope-'));
  const write = (rel) => decide(dir, 'bi-ssis-editor', 'Write', { file_path: path.join(dir, rel), content: 'x' });
  const edit = (rel) => decide(dir, 'bi-ssis-editor', 'Edit', { file_path: path.join(dir, rel), old_string: 'a', new_string: 'b' });
  const bash = (command) => decide(dir, 'bi-ssis-editor', 'Bash', { command });
  try {
    for (const rel of ['etl/CurrencyRates/LoadRates.dtsx', 'etl/CurrencyRates/CurrencyRates.dtproj', 'etl/CurrencyRates/Project.params',
      'etl/CurrencyRates/Connection.conmgr', 'etl/CurrencyRates/sql/stg.Rates.sql', 'etl/CurrencyRates/jobs/LoadRates.sql',
      'docs/tests/LoadRates.ssis.md', 'TASKS.md']) {
      assert.equal(write(rel), null, `ssis editor: ${rel}`);
    }
    assert.equal(edit('etl/CurrencyRates/LoadRates.dtsx'), null, 'Edit follows the same scope as Write');
    for (const rel of ['powerbi/Sales.SemanticModel/definition/tables/Fact.tmdl', 'powerbi/Sales.Report/definition/pages/p1/page.json',
      'templates/ssis/AWSampleETL/LoadDimProduct.dtsx', 'reports/store-kpis/Store.rdl', 'docs/sources/README.md', 'docs/sources/sql/Sales.schema.sql',
      'etl/loose.dtsx', 'README.md']) {
      assert.equal(write(rel), 'deny', `ssis editor out of scope: ${rel}`);
    }
    assert.equal(edit('templates/ssis/AWSampleETL/Project.params'), 'deny', 'a template is never edited');
    // Checks and probes are not changes; a package run is not judged here (the main guard asks for it), but a shell write is.
    for (const cmd of ['dtexec /F etl/CurrencyRates/LoadRates.dtsx /Validate', 'dtexec /F etl/CurrencyRates/LoadRates.dtsx /Va',
      'git status', 'node hardening/scripts/validate.mjs --changed']) {
      assert.equal(bash(cmd), null, cmd);
    }
    assert.equal(decide(dir, 'bi-ssis-editor', 'PowerShell', { command: 'where.exe dtexec' }), null, 'where.exe dtexec');
    for (const cmd of ['echo x > etl/CurrencyRates/LoadRates.dtsx', 'sed -i s/a/b/ etl/CurrencyRates/LoadRates.dtsx', 'git commit -m x',
      'dtexec /F etl/CurrencyRates/LoadRates.dtsx /Validate > out.txt', 'dtexec /F etl/CurrencyRates/LoadRates.dtsx /Validate && rm notes.txt']) {
      assert.equal(bash(cmd), 'deny', cmd);
    }
    assert.equal(decide(dir, 'bi-ssis-editor', 'PowerShell', { command: 'Set-Content etl/CurrencyRates/LoadRates.dtsx x' }), 'deny', 'PowerShell write');
    assert.equal(decide(dir, 'bi-ssis-editor', 'mcp__powerbi-modeling__measure_operations',
      { request: { operation: 'Create', connectionName: 'PBIDesktop-S-1', definitions: [{ name: 'M', expression: '1' }] } }), 'deny', 'MCP writes go back to the main agent');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// F1-46: spellings of shell changes that the first version of the guard let through (its patterns saw words, not the
// program a subcommand runs): git options before the subcommand, flags after the script, .exe interpreters, other
// writers, wrappers, chains and the PowerShell aliases and cmdlets. A scoped agent hands each one back to the main agent.
const BASH_CHANGES = [
  "find . -name '*.tmp' -delete", 'find . -name x -exec sed -i s/a/b/ {} +', 'cat notes.txt | xargs -I{} cp {} b.txt',
  'sed s/a/b/ -i notes.txt', 'sed --in-place s/a/b/ notes.txt', 'sed -i s/a/b/ notes.txt', 'awk -i inplace "{print}" notes.txt',
  'git branch newb', 'git branch -D old', 'git -C . commit -m x', 'git -c user.name=x commit -m x', 'git commit -m x',
  'git config user.name x', 'git worktree add ../w', 'git init sub', 'git notes add -m x', 'git remote add x y', 'git stash',
  'git tag v1', 'git checkout main', '/usr/bin/git commit -m x', 'GIT_DIR=.git git commit -m x', 'git -c alias.p=push p',
  'patch -p1 -i fix.diff', 'sort -o notes.txt notes.txt', 'dd if=a.txt of=b.txt', 'install a.txt b.txt', 'tar -xf x.tar', 'unzip x.zip',
  'mkdir out', 'touch notes.txt', 'cp a.txt b.txt', 'mv a.txt b.txt', 'rm notes.txt', 'echo x > notes.txt', 'echo x | tee notes.txt',
  `node.exe -e "require('fs').writeFileSync('notes.txt','x')"`, `node -e "require('fs').writeFileSync('notes.txt','x')"`,
  `python.exe -c "open('notes.txt','w').write('x')"`, `py -c "open('notes.txt','w').write('x')"`, 'powershell.exe -c "ni notes.txt"',
  'cmd /c del notes.txt', 'npm install', 'npm.cmd run build', 'npx foo', 'sudo rm notes.txt', './run.sh', 'nohup ./run.sh',
  'xargs rm notes.txt', 'env rm notes.txt', 'FOO=1 rm notes.txt', 'time git -C . commit -m x', 'echo $(rm notes.txt)',
  'echo `ni notes.txt`', 'git status && ni notes.txt', 'git status; copy a.txt b.txt', 'git status\nni notes.txt',
  'q() { tar -xf x.tar; }; q', 'function q { tar -xf x.tar; }; q',
];
const POWERSHELL_CHANGES = [
  'ni notes.txt', 'copy a.txt b.txt', 'move a.txt b.txt', 'ri notes.txt', 'rni a.txt b.txt', 'Expand-Archive x.zip -DestinationPath out',
  'Compress-Archive a.txt out.zip', 'Set-Content notes.txt x', 'Add-Content notes.txt x', "'x' | Out-File notes.txt", 'New-Item notes.txt',
  'Remove-Item notes.txt', 'Copy-Item a.txt b.txt', 'Move-Item a.txt b.txt', 'Rename-Item a.txt b.txt', 'Clear-Content notes.txt',
  'git worktree add ../x', 'git -C . commit -m x', '$null = ni notes.txt', '(ni notes.txt) | Out-Null', 'Get-ChildItem | Remove-Item',
  'Get-ChildItem | ForEach-Object { ni $_.Name }', 'if (Test-Path x) { ri x }', 'iex "ni notes.txt"', 'git status\rni notes.txt',
  '$x=ni notes.txt', '$x =ri notes.txt', '[string]$x=ni notes.txt', '$x=git -C . commit -m x', 'Set-Alias q ni; q notes.txt',
  '& $cmd notes.txt', 'function q { ni notes.txt; ni b.txt }; q',
];
const BASH_READS = [
  'git status', 'git diff', 'git log -3', 'git show HEAD:docs/x.md', 'git ls-files', 'git branch -a', 'git branch --show-current', 'git status && npm test',
  'git config --get user.name', 'git remote -v', 'git worktree list', 'git -C . status', 'git --no-pager log -1',
  'git -c core.quotepath=off diff --name-only', 'node --version', 'node hardening/scripts/validate.mjs --changed',
  'node hardening\\scripts\\validate.mjs --changed', 'npm --prefix hardening test', 'npm ls', 'sed -n 1,5p docs/x.md',
  'sort -u notes.txt', "find . -name '*.tmdl'", 'find . -name "*.rdl" -exec grep -l Foo {} +', 'grep -rn install docs',
  'grep -E "(install|copy)" docs/x.md', 'timeout 20 git log --oneline -- scripts/x.js', 'cat notes.txt | head -3',
  'powerbi-report-author validate reports/Sales.Report',
];
const POWERSHELL_READS = [
  'git status', 'Get-Content notes.txt | Select-Object -First 3', "Get-ChildItem -Recurse | Where-Object { $_.Name -like '*.tmdl' }",
  'Select-String -Path docs/*.md -Pattern copy', '$x = Get-Content notes.txt; $x.Count', '$x=Get-Content notes.txt', '$s = "abc"; $s.ToUpper()',
];
const READ_ONLY_AGENTS = ['bi-dax-reviewer', 'bi-report-reviewer', 'bi-security-auditor', 'bi-validator', 'bi-source-analyst', 'bi-rdl-analyst'];
const WRITE_SCOPED_AGENTS = ['bi-tmdl-modeler', 'bi-pbir-editor', 'bi-doc-generator', 'bi-rdl-editor', 'bi-ssis-editor'];

test('agent scopes (F1-46): every spelling of a shell change is denied for scoped agents, and their reads stay allowed', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-scope-'));
  const bash = (agent, command) => decide(dir, agent, 'Bash', { command });
  const powershell = (agent, command) => decide(dir, agent, 'PowerShell', { command });
  try {
    for (const cmd of BASH_CHANGES) assert.equal(bash('bi-dax-reviewer', cmd), 'deny', cmd);
    for (const cmd of POWERSHELL_CHANGES) assert.equal(powershell('bi-dax-reviewer', cmd), 'deny', `PowerShell: ${cmd}`);
    for (const cmd of BASH_READS) assert.equal(bash('bi-dax-reviewer', cmd), null, cmd);
    for (const cmd of POWERSHELL_READS) assert.equal(powershell('bi-dax-reviewer', cmd), null, `PowerShell: ${cmd}`);
    // Every other scoped agent gets the same judgement; the editors write only through Edit/Write inside their folders.
    for (const agent of READ_ONLY_AGENTS.slice(1).concat(WRITE_SCOPED_AGENTS)) {
      for (const cmd of ['git -C . commit -m x', 'sed s/a/b/ -i notes.txt']) assert.equal(bash(agent, cmd), 'deny', `${agent}: ${cmd}`);
      assert.equal(powershell(agent, 'ni notes.txt'), 'deny', `${agent}: ni`);
      assert.equal(bash(agent, 'git status'), null, `${agent}: git status`);
    }
    assert.equal(bash('general-purpose', 'git -C . commit -m x'), null, 'an agent without a scope is not limited here');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// F1-54: the RDL data layer comparison is a read-only check like the validator: the RDL editor and the validator are told
// to run it (their files, docs/static-checks.md). It passes only as the whole command: no output file, no second command
// (not even on the next line).
test('agent scopes (F1-54): the RDL comparison runs for the RDL agents and the validator, alone', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-scope-'));
  const bash = (agent, command) => decide(dir, agent, 'Bash', { command });
  try {
    for (const agent of ['bi-rdl-editor', 'bi-validator', 'bi-rdl-analyst']) {
      for (const cmd of ['node hardening/scripts/rdl-compare.mjs reports/Sales/source/Sales.rdl reports/Sales/Sales.rdl',
        'node scripts/rdl-compare.mjs a.rdl b.rdl --ignore Body', 'node hardening\\scripts\\rdl-compare.mjs a.rdl b.rdl',
        'node hardening/scripts/validate.mjs --changed']) {
        assert.equal(bash(agent, cmd), null, `${agent}: ${cmd}`);
      }
      assert.equal(decide(dir, agent, 'PowerShell', { command: 'node hardening/scripts/rdl-compare.mjs a.rdl b.rdl' }), null, `${agent}: PowerShell`);
    }
    for (const script of ['rdl-compare.mjs a.rdl b.rdl', 'validate.mjs --changed']) {
      for (const cmd of [`node hardening/scripts/${script} > out.txt`, `node hardening/scripts/${script} && git commit -m x`,
        `node hardening/scripts/${script}\nrm notes.txt`, `node hardening/scripts/${script}\r\nrm notes.txt`, `node hardening/scripts/${script}\rrm notes.txt`,
        `node hardening/scripts/${script} | tee out.txt`, `node ../hardening/scripts/${script}`]) {
        assert.equal(bash('bi-rdl-analyst', cmd), 'deny', JSON.stringify(cmd));
        assert.equal(bash('bi-rdl-editor', cmd), 'deny', JSON.stringify(cmd));
      }
    }
    assert.equal(bash('bi-rdl-editor', 'node hardening/scripts/install-into.mjs . --hardening'), 'deny', 'another harness script is not a check');
    assert.equal(bash('bi-rdl-editor', 'node hardening/scripts/rdl-compare.mjs.bak a.rdl b.rdl'), 'deny');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// F1-63: the Power BI modeling MCP server is read-only for the scoped agents; connection changes, writes and unknown
// operations go back to the main agent, and each refusal is logged.
test('agent scopes (F1-63): MCP is read-only for reviewers and editors, and a refusal is logged', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-scope-'));
  const mcp = (agent, tool, operation, extra = {}) =>
    decide(dir, agent, `mcp__powerbi-modeling__${tool}`, { request: { operation, connectionName: 'PBIDesktop-S-1', ...extra } });
  const events = () => {
    try {
      return fs.readFileSync(path.join(dir, '.claude', 'logs', 'security-events.jsonl'), 'utf8').trim().split('\n').filter(Boolean).map((line) => JSON.parse(line));
    } catch {
      return [];
    }
  };
  try {
    assert.equal(mcp('bi-tmdl-modeler', 'measure_operations', 'Create', { definitions: [{ name: 'M', expression: '1' }] }), 'deny', 'a write');
    assert.equal(mcp('bi-tmdl-modeler', 'connection_operations', 'Connect', { dataSource: 'localhost:51234' }), 'deny', 'a connection change');
    assert.equal(mcp('bi-tmdl-modeler', 'measure_operations', 'Frobnicate'), 'deny', 'an unknown operation');
    const logged = events().filter((e) => e.event === 'agent-scope');
    assert.deepEqual(logged.map((e) => e.tool), ['mcp__powerbi-modeling__measure_operations', 'mcp__powerbi-modeling__connection_operations',
      'mcp__powerbi-modeling__measure_operations'], 'one security-events row per refusal');
    for (const row of logged) {
      assert.equal(row.decision, 'deny');
      assert.equal(row.agent, 'bi-tmdl-modeler');
      assert.match(row.reason, /read-only MCP access/);
    }
    assert.equal(mcp('bi-tmdl-modeler', 'measure_operations', 'List'), null, 'metadata reads pass');
    assert.equal(mcp('bi-tmdl-modeler', 'measure_operations', 'Get', { references: [{ name: 'M' }] }), null);
    assert.equal(decide(dir, 'bi-tmdl-modeler', 'mcp__microsoft-learn__search', { query: 'DAX CALCULATE' }), null, 'the docs server is read-only by nature');
    assert.equal(events().filter((e) => e.event === 'agent-scope').length, 3, 'a pass logs nothing');
    assert.equal(mcp('bi-dax-reviewer', 'measure_operations', 'Update', { definitions: [{ name: 'M', expression: '2' }] }), 'deny', 'a reviewer');
    assert.equal(mcp('bi-pbir-editor', 'measure_operations', 'Delete', { references: [{ name: 'M' }] }), 'deny', 'a report editor');
    assert.equal(decide(dir, 'bi-dax-reviewer', 'mcp__github__list_issues', { repo: 'x/y' }), 'deny', 'no other MCP server is read-only by default');
    assert.equal(mcp('general-purpose', 'measure_operations', 'Create', { definitions: [{ name: 'M', expression: '1' }] }), null, 'an agent without a scope is not limited here');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// F1-78: hardening/REFERENCE.md says a core test checks it. Every agent file runs as a subagent with the scope the defaults
// give it, except the main-session agent (the `agent` setting of .claude/settings.json): a scope for that one would
// restrict the whole session, since the hook payload names it too.
test('agent scopes (F1-78): every agent file has a scope in the defaults, except the main-session agent', () => {
  const main = JSON.parse(fs.readFileSync(path.join(root, '.claude', 'settings.json'), 'utf8')).agent;
  const agents = fs.readdirSync(path.join(root, '.claude', 'agents')).filter((f) => f.endsWith('.md')).map((f) => f.slice(0, -3));
  assert.ok(agents.includes(main), `the main-session agent (${main}) has an agent file; found: ${agents.join(', ')}`);
  for (const name of agents) {
    if (name === main) assert.equal(DEFAULT_CONFIG.agentScopes[name], undefined, `${name} runs the main session: it must have no scope`);
    else assert.ok(DEFAULT_CONFIG.agentScopes[name], `${name} has no entry in agentScopes (DEFAULT_CONFIG in hooks/lib/common.mjs)`);
  }
});
