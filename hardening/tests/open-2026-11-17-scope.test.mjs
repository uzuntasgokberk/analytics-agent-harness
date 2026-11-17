// Open findings 2026-11-17, each measured before the fix:
// D. A database-level MCP write (database_operations: an import of TMDL or TMSL) carries a model definition that can add role
//    members, which only security_role_operations denied: in lab mode such a write ran without a prompt. The repository does
//    not show the modeling server's shape for that definition (docs/harness/MCP.md, the MCP tests and fixtures name the
//    operations only), so no parser reads it for members: every database-level write that carries a definition is the floor.
// E. The read-only subagent scope (guard-agent-scope.mjs) did not know the writers the shell policy gained in the 2026-11-16
//    round: a reviewer could run iconv -o, sponge, yq -i, certutil -decode, dos2unix, unix2dos, New-HardLink and the .NET file
//    calls. The scope now reads the policy's own predicate (subcommandWritesFile), so no list is copied.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyzeMcpCall } from '../hooks/lib/policy.mjs';

const hooks = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'hooks');
const cfg = { mcp: { powerbiServer: 'powerbi-modeling' } };
const verdict = (r) => (r ? `${r.decision}${r.floor ? '/floor' : r.autoApprovable === false ? '/user' : ''}` : 'none');
const mcp = (tool, request) => verdict(analyzeMcpCall(`mcp__powerbi-modeling__${tool}`, { request }, cfg));
const LOCAL = 'PBIDesktop-Sales';

/** Runs one hook script in a temporary project holding `files`; returns the decision and reason. */
function runHook(script, files, payload) {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-open-1117-scope-')));
  try {
    for (const [rel, content] of Object.entries(files)) {
      fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
      fs.writeFileSync(path.join(dir, rel), content);
    }
    const env = { ...process.env, CLAUDE_PROJECT_DIR: dir };
    delete env.BI_HARNESS_HOST;
    const r = spawnSync(process.execPath, [path.join(hooks, script)], { input: JSON.stringify({ hook_event_name: 'PreToolUse', ...payload }), env, encoding: 'utf8' });
    assert.equal(r.status, 0, r.stderr);
    const out = r.stdout.trim() ? JSON.parse(r.stdout).hookSpecificOutput : null;
    return { decision: out?.permissionDecision ?? null, reason: out?.permissionDecisionReason ?? '' };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

// ---------------------------------------------------------------- D: a database-level write that carries a definition

// Shapes a database-level write may carry its definition in. The server's real field names are not in the repository, so
// any argument beyond the operation and the connection counts.
const WITH_DEFINITION = [
  { operation: 'ImportFromTmdlFolder', connectionName: LOCAL, folderPath: 'C:/staging/Sales.SemanticModel/definition' },
  { operation: 'Update', connectionName: LOCAL, tmdl: 'role Readers\n\tmodelPermission: read\n\tmember x\n' },
  { operation: 'Create', connectionName: LOCAL, definition: { model: { roles: [{ name: 'Readers', members: [{ memberName: 'x' }] }] } } },
  { operation: 'Import', connectionName: LOCAL, tmsl: '{"createOrReplace":{"object":{"database":"Sales"},"database":{"model":{}}}}' },
  // A script under an operation key (`command`, `action`) is read as an operation of an unknown spelling: the floor too.
  { operation: 'Update', connectionName: LOCAL, command: '{"createOrReplace":{"database":{"model":{"roles":[{"name":"R","members":[{"memberName":"x"}]}]}}}}' },
];

test('D: a database-level write that carries a definition is the floor (lab mode leaves it to the user), on a local model too', () => {
  for (const request of WITH_DEFINITION) {
    assert.equal(mcp('database_operations', request), 'ask/floor', JSON.stringify(request));
    assert.match(analyzeMcpCall('mcp__powerbi-modeling__database_operations', { request }, cfg).reason, request.command ? /Unknown MCP operation spelling/ : /role members/);
    // Direct arguments (no request wrapper) read the same.
    assert.equal(verdict(analyzeMcpCall('mcp__powerbi-modeling__database_operations', request, cfg)), 'ask/floor', JSON.stringify(request));
  }
});

test('D: must stay: a database write without a definition, an export, the deploy deny, the member deny, reads and other tools', () => {
  for (const request of [{ operation: 'Update', connectionName: LOCAL }, { operation: 'ImportFromTmdlFolder', connectionName: LOCAL },
    { operation: 'ExportToTmdlFolder', connectionName: LOCAL }, { operation: 'ExportToTmdlFolder', connectionName: LOCAL, folderPath: 'C:/staging/x' }]) {
    assert.equal(mcp('database_operations', request), 'ask/user', JSON.stringify(request));
  }
  assert.equal(mcp('database_operations', { operation: 'ExportTMDL', connectionName: LOCAL }), 'allow');
  assert.equal(mcp('database_operations', { operation: 'DeployToFabric', connectionName: LOCAL, folderPath: 'x' }), 'deny');
  assert.equal(mcp('security_role_operations', { operation: 'Update', connectionName: LOCAL, definitions: [{ name: 'R', members: [{ memberName: 'x' }] }] }), 'deny');
  assert.equal(mcp('database_operations', { operation: 'ImportFromTmdlFolder', folderPath: 'x' }), 'ask/floor'); // no local connection: the floor already
  assert.equal(mcp('measure_operations', { operation: 'Create', connectionName: LOCAL, definitions: [{ name: 'Net', expression: 'SUM(Sales[Amount])' }] }), 'ask');
  assert.equal(mcp('model_operations', { operation: 'Update', connectionName: LOCAL, definition: { description: 'x' } }), 'ask');
});

test('D: in lab mode the hook asks for a database-level write with a definition and still runs one without', () => {
  // A confirmed local connection (lib/mcp-state.mjs), as in tier2.test.mjs, and lab mode.
  const files = {
    '.claude/logs/.state/open-1117-scope.json': JSON.stringify({ mcpConnections: [{ mcpServer: 'powerbi-modeling', name: LOCAL, confirmedAt: '2026-11-17T09:00:00.000Z' }] }),
    'hardening/harness.config.json': JSON.stringify({ approvals: { mode: 'lab' } }),
  };
  const call = (request) => runHook('pre-tool-use.mjs', files, { session_id: 'open-1117-scope', tool_name: 'mcp__powerbi-modeling__database_operations', tool_input: { request } });
  for (const request of [WITH_DEFINITION[0], WITH_DEFINITION[1], WITH_DEFINITION.at(-1)]) assert.equal(call(request).decision, 'ask', JSON.stringify(request));
  assert.equal(call({ operation: 'Update', connectionName: LOCAL }).decision, 'allow');
});

// ---------------------------------------------------------------- E: the read-only subagent scope and the policy's writers

/** The scope guard's decision for a subagent's shell command. */
const scope = (agent, command, tool = 'Bash') => runHook('agent-scope.mjs', {}, { session_id: 'scope', agent_type: agent, tool_name: tool, tool_input: { command } }).decision;

// Writers of the shell policy's lists that the scope's own list did not hold (measured before the fix: no verdict).
const NEW_WRITERS = ['iconv -f utf-8 -t ascii -o b.txt a.txt', 'iconv -f utf-8 -t ascii --output=b.txt a.txt', 'sponge a.txt', 'yq -i .a=1 x.yml',
  'yq --inplace .a=1 x.yml', 'certutil -decode a.b64 a.txt', 'certutil -encode a.txt a.b64', 'dos2unix a.txt', 'unix2dos a.txt', 'New-HardLink a b',
  "[IO.File]::Delete('a.txt')", "[IO.File]::WriteAllText('a.txt','b')", "[System.IO.File]::Move('a.txt','b.txt')", "[IO.Directory]::Delete('docs',$true)",
  '(Get-Item a.txt).Delete()', "$null = [IO.File]::Delete('a.txt')", "$doc.Save('a.xml')", "ls; [IO.File]::Copy('a','b')"];

test('E: a read-only agent that runs a writer of the policy\'s lists gets the deny of cp a b and tee x', () => {
  for (const agent of ['bi-dax-reviewer', 'bi-security-auditor']) {
    assert.equal(scope(agent, 'cp a b'), 'deny');
    assert.equal(scope(agent, 'tee x'), 'deny');
    for (const [tool, command] of NEW_WRITERS.map((c) => [/^[[($]|New-/.test(c) || c.startsWith('ls;') ? 'PowerShell' : 'Bash', c])) {
      assert.equal(scope(agent, command, tool), 'deny', `${agent}: ${command}`);
    }
  }
  // Writers on the lists before the fix stay denied.
  for (const command of ['install -m 644 a b', 'rsync -a a/ b/', 'dd if=a of=b', 'ln -s a b', 'truncate -s 0 a', 'patch a x.diff', 'split -l 1 a b',
    'uniq a b', 'sort -o b a', 'gzip a', 'shred a', 'attrib +r a', 'icacls a /grant Everyone:F']) {
    assert.equal(scope('bi-dax-reviewer', command), 'deny', command);
  }
  // A scope with write globs takes no shell write either.
  assert.equal(scope('bi-doc-generator', 'dos2unix docs/a.md'), 'deny');
});

test('E: must stay: the reads a reviewer needs, and readers whose output goes to the terminal', () => {
  for (const command of ['cat docs/a.md', 'grep -rn writeFileSync hardening', 'rg -n WriteAllText docs', 'git diff', 'git diff -- hardening/hooks/lib/policy.mjs',
    'git log --oneline -5', 'git status', 'git show HEAD --stat', 'node hardening/scripts/validate.mjs', 'npm --prefix hardening test', 'npm --prefix hardening run validate',
    'ls docs', 'head -5 docs/a.md', 'wc -l docs/a.md', 'sort docs/a.md', 'uniq docs/a.md', 'sed -n 1,5p docs/a.md', 'iconv -f utf-8 -t ascii a.txt',
    'yq .a x.yml', 'certutil -hashfile a SHA256', "Select-String -Path docs/a.md -Pattern 'WriteAllText'", 'Get-Content docs/a.md']) {
    assert.equal(scope('bi-dax-reviewer', command), null, command);
  }
});

test('E: the policy\'s predicate is the one list: writers, written words and file calls; readers and git are not writers', async () => {
  // Imported here: the module of the code before the fix has no such export, and a static import would stop every test of the file.
  const { subcommandWritesFile } = await import('../hooks/lib/policy.mjs');
  assert.equal(typeof subcommandWritesFile, 'function');
  for (const [prog, args, sub] of [['cp', ['a', 'b'], 'cp a b'], ['tee', ['x'], 'tee x'], ['dos2unix', ['a'], 'dos2unix a'], ['sponge', ['a'], 'sponge a'],
    ['iconv', ['-o', 'b', 'a'], 'iconv -o b a'], ['dd', ['of=b'], 'dd of=b'], ['ln', ['-s', 'a', 'b'], 'ln -s a b'], ['sort', ['-o', 'b', 'a'], 'sort -o b a'],
    ['mv', ['a', 'b'], 'mv a b'], ["[io.file]::delete('a')", [], "[IO.File]::Delete('a')"]]) {
    assert.equal(subcommandWritesFile(prog, args, sub), true, sub);
  }
  for (const [prog, args, sub] of [['cat', ['a'], 'cat a'], ['grep', ['writeFileSync', '.'], 'grep writeFileSync .'], ['git', ['log', '-S', 'WriteAllText'], 'git log -S WriteAllText'],
    ['iconv', ['-f', 'a', '-t', 'b', 'x'], 'iconv -f a -t b x'], ['sort', ['a'], 'sort a'], ['yq', ['.a', 'x.yml'], 'yq .a x.yml']]) {
    assert.equal(subcommandWritesFile(prog, args, sub), false, sub);
  }
});
