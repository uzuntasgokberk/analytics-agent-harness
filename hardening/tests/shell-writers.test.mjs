// Issue #9: writers that got no verdict while their plain forms are denied. Each command is judged by the spawned guard
// in a project of its own (PROJECT_DIR is read when the policy loads), next to its plain form.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const hook = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'hooks', 'pre-tool-use.mjs');

function guard(dir, tool_name, command) {
  const r = spawnSync(process.execPath, [hook], {
    input: JSON.stringify({ hook_event_name: 'PreToolUse', session_id: 'writers', tool_name, tool_input: { command } }),
    env: { ...process.env, CLAUDE_PROJECT_DIR: dir },
    encoding: 'utf8',
  });
  assert.equal(r.status, 0, r.stderr);
  return r.stdout.trim() ? JSON.parse(r.stdout).hookSpecificOutput : {};
}

/** A project with guardrail, guarded and secret files, and the links l -> secrets/sub and c2 -> .claude (junctions on Windows). */
function withWriterProject(fn) {
  const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-writers-')));
  const dir = path.join(root, 'project');
  try {
    for (const [rel, text] of [['.claude/settings.json', '{}\n'], ['hardening/hooks/x.mjs', '// x\n'], ['AGENTS.md', '# a\n'],
      ['README.md', '# r\n'], ['src/a.txt', 'a\n'], ['secrets/x.txt', 'x\n'], ['secrets/sub/y.txt', 'y\n']]) {
      fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
      fs.writeFileSync(path.join(dir, rel), text);
    }
    const kind = process.platform === 'win32' ? 'junction' : 'dir';
    fs.symlinkSync(path.join(dir, 'secrets', 'sub'), path.join(dir, 'l'), kind);
    fs.symlinkSync(path.join(dir, '.claude'), path.join(dir, 'c2'), kind);
    return fn(dir);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

// [tool, command, its plain form]: the plain form is denied today, the command must get the same decision and reason.
const SAME_AS_PLAIN = [
  // dd writes its of= file; install and a local rsync their last operand or install's -t folder; sponge its operand.
  ['Bash', 'dd if=src/a.txt of=hardening/hooks/x.mjs', 'cp src/a.txt hardening/hooks/x.mjs'],
  ['Bash', 'dd if=src/a.txt of=AGENTS.md', 'cp src/a.txt AGENTS.md'],
  ['Bash', 'dd if=src/a.txt of=c2/settings.json', 'cp src/a.txt c2/settings.json'],
  ['Bash', 'dd if=src/a.txt of=l/y.txt', 'cp src/a.txt l/y.txt'],
  ['Bash', 'cd hardening && dd if=../src/a.txt of=y.mjs', 'cd hardening && cp ../src/a.txt y.mjs'],
  ['Bash', 'install src/a.txt hardening/hooks/x.mjs', 'cp src/a.txt hardening/hooks/x.mjs'],
  ['Bash', 'install -m 644 src/a.txt AGENTS.md', 'cp src/a.txt AGENTS.md'],
  ['Bash', 'install -t hardening/hooks src/a.txt', 'cp -t hardening/hooks src/a.txt'],
  ['Bash', 'install --target-directory=hardening/hooks src/a.txt', 'cp --target-directory=hardening/hooks src/a.txt'],
  ['Bash', 'install src/a.txt c2/settings.json', 'cp src/a.txt c2/settings.json'],
  ['Bash', 'rsync src/a.txt hardening/hooks/x.mjs', 'cp src/a.txt hardening/hooks/x.mjs'],
  ['Bash', 'rsync -a src/a.txt AGENTS.md', 'cp -a src/a.txt AGENTS.md'],
  ['Bash', 'rsync src/a.txt c2/settings.json', 'cp src/a.txt c2/settings.json'],
  ['Bash', 'echo x | sponge hardening/hooks/x.mjs', 'echo x | tee hardening/hooks/x.mjs'],
  ['Bash', 'echo x | sponge AGENTS.md', 'echo x | tee AGENTS.md'],
  ['Bash', 'echo x | sponge -a l/y.txt', 'echo x | tee -a l/y.txt'],
  // robocopy into a guardrail folder, and out of one with /MIR, /PURGE, /MOV or /MOVE.
  ['PowerShell', 'robocopy src .claude /MIR', 'robocopy src hardening'],
  ['PowerShell', 'robocopy src c2 /E', 'robocopy src hardening'],
  ['PowerShell', 'robocopy src .claude\\agents', 'robocopy src hardening'],
  ['PowerShell', 'robocopy .claude out /MOVE', 'robocopy src hardening'],
  ['PowerShell', 'robocopy .claude out /PURGE', 'robocopy src hardening'],
  ['PowerShell', 'robocopy .vscode out /MOV', 'robocopy src hardening'],
  // Moving or renaming a guardrail folder is deleting it where the harness looks.
  ['Bash', 'mv .claude c', 'rm -r .claude'],
  ['Bash', 'mv hardening x', 'rm -r hardening'],
  ['Bash', 'mv .git g', 'rm -r .git'],
  ['PowerShell', 'Move-Item .claude c', 'Remove-Item .claude'],
  ['PowerShell', 'Rename-Item .claude c', 'Remove-Item .claude'],
  // A PowerShell subexpression that names the path.
  ['PowerShell', 'New-Item -ItemType Junction -Path c -Target (Get-Item .claude)', 'New-Item -ItemType Junction -Path c -Target .claude'],
  ['PowerShell', 'New-Item -ItemType SymbolicLink -Path c -Target (Get-Item .claude).FullName', 'New-Item -ItemType SymbolicLink -Path c -Target .claude'],
  ['PowerShell', 'New-Item -ItemType Junction -Path c -Target (Resolve-Path hardening)', 'New-Item -ItemType Junction -Path c -Target hardening'],
  ['PowerShell', 'Set-Content (Get-Item AGENTS.md).FullName x', 'Set-Content AGENTS.md x'],
  // cd -P: links resolved before `..`.
  ['Bash', 'cd -P l/.. && cat x.txt', 'cd secrets && cat x.txt'],
  ['Bash', 'cd -LP l/.. && cat x.txt', 'cd secrets && cat x.txt'],
];

test('issue #9: dd, install, rsync, sponge, robocopy, a move, a subexpression and cd -P get the decision and reason of their plain form', () => {
  withWriterProject((dir) => {
    for (const [tool_name, command, plainForm] of SAME_AS_PLAIN) {
      const plain = guard(dir, tool_name, plainForm);
      assert.equal(plain.permissionDecision, 'deny', `${tool_name}: ${plainForm} (the plain form)`);
      const out = guard(dir, tool_name, command);
      assert.equal(out.permissionDecision, 'deny', `${tool_name}: ${command}`);
      assert.equal(out.permissionDecisionReason, plain.permissionDecisionReason, `${tool_name}: ${command}`);
    }
  });
});

test('issue #9: the program word install as a subcommand, an option alone, a harmless dd, move or robocopy keep their verdict', () => {
  withWriterProject((dir) => {
    for (const [tool_name, command] of [['Bash', 'dd if=README.md of=/dev/null'], ['Bash', 'npm install'], ['Bash', 'pip install x'],
      ['Bash', 'install --help'], ['Bash', 'rsync --version'], ['Bash', 'mv src/a.txt src/b.txt'], ['PowerShell', 'robocopy src out'],
      ['PowerShell', 'robocopy .claude out'], ['Bash', 'dd if=src/a.txt of=out.txt'], ['Bash', 'install src/a.txt out.txt']]) {
      assert.equal(guard(dir, tool_name, command).permissionDecision, undefined, `${tool_name}: ${command}`);
    }
    // The remote rsync deny and the deny of a link to a folder named hardening outside the project stay (lead decision).
    for (const command of ['rsync -a src host:/x', 'rsync src/a.txt host:docs/notes.md']) {
      const out = guard(dir, 'Bash', command);
      assert.equal(out.permissionDecision, 'deny', command);
      assert.match(out.permissionDecisionReason, /Remote rsync is blocked/, command);
    }
    const link = guard(dir, 'Bash', 'ln -s /opt/hardening x');
    assert.equal(link.permissionDecision, 'deny');
    assert.match(link.permissionDecisionReason, /Harness guardrail files/);
  });
});

test('issue #9: cd -L stays logical, and a cd -P folder the guard cannot resolve is an unknown folder (never routine)', () => {
  withWriterProject((dir) => {
    assert.notEqual(guard(dir, 'Bash', 'cd -L l/.. && cat x.txt').permissionDecision, 'deny');
    assert.notEqual(guard(dir, 'Bash', 'cd -P -L l/.. && cat x.txt').permissionDecision, 'deny');
    const unknown = guard(dir, 'Bash', 'cd -P nowhere/.. && cat x.txt');
    assert.equal(unknown.permissionDecision, undefined, String(unknown.permissionDecisionReason));
    // The same line with a plain cd is routine: the folder is placed lexically.
    assert.equal(guard(dir, 'Bash', 'cd nowhere/.. && cat README.md').permissionDecision, 'allow');
  });
});
