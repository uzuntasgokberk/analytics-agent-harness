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

// [tool, command, its spelled-out form]: a copy into a guardrail folder by the folder's name puts the sources there under
// their own names (`cp src/settings.json .claude`), so it gets the deny of the copy that names a guardrail file.
const COPY_INTO_FOLDER = [
  ['Bash', 'cp src/a.txt .claude', 'cp src/a.txt hardening'],
  ['Bash', 'cp src/a.txt .claude/', 'cp src/a.txt hardening/'],
  ['Bash', 'cp src/settings.json .claude', 'cp src/settings.json .claude/settings.json'],
  ['Bash', 'cp -t .claude/agents src/a.txt', 'cp -t .claude/agents/ src/a.txt'],
  ['Bash', 'cp -rt .claude/agents src', 'cp -t .claude/agents/ src/a.txt'],
  ['Bash', 'cp -t.claude src/a.txt', 'cp src/a.txt hardening'],
  ['Bash', 'cp --target-directory=.github src/a.txt', 'cp src/a.txt .github/a.txt'],
  ['Bash', 'cp src/a.txt .github', 'cp src/a.txt .github/a.txt'],
  ['Bash', 'cp -r src .vscode', 'cp -r src .vscode/src'],
  ['Bash', 'cp src/a.txt ./.cursor/', 'cp src/a.txt .cursor/a.txt'],
  ['Bash', 'cp src/a.txt c2', 'cp src/a.txt c2/settings.json'],
  ['Bash', 'cp -- src/a.txt .claude', 'cp src/a.txt hardening'],
  ['Bash', 'cp src/a.txt .claude 2>/dev/null', 'cp src/a.txt hardening'],
  ['Bash', 'cp src/a.txt .claude > log.txt', 'cp src/a.txt hardening'],
  ['Bash', 'cp src/a.txt .claude>log.txt', 'cp src/a.txt hardening'],
  ['Bash', 'install src/a.txt .claude 2>&1', 'install src/a.txt hardening'],
  ['Bash', 'install src/a.txt .claude', 'install src/a.txt hardening'],
  ['Bash', 'install -t .claude/agents src/a.txt', 'install -t .claude/agents/ src/a.txt'],
  ['Bash', 'rsync -a src/ .github', 'rsync -a src/ .github/src'],
  ['PowerShell', 'Copy-Item src/a.txt .claude', 'Copy-Item src/a.txt hardening'],
  ['PowerShell', 'Copy-Item -Path src/a.txt -Destination .claude/agents', 'Copy-Item -Path src/a.txt -Destination .claude/agents/a.md'],
  ['PowerShell', 'Copy-Item src/a.txt -Destination:.github', 'Copy-Item src/a.txt -Destination .github/a.txt'],
  ['PowerShell', 'Copy-Item -LiteralPath src/a.txt .claude', 'Copy-Item src/a.txt hardening'],
  ['PowerShell', 'cpi -Recurse src .vscode', 'cpi -Recurse src .vscode/src'],
  ['PowerShell', 'copy src/a.txt c2', 'copy src/a.txt c2/settings.json'],
  ['PowerShell', 'xcopy src .claude /E', 'xcopy src .github/ /E'],
];

test('issue #9: a copy into a guardrail folder by its name gets the decision and reason of its spelled-out form', () => {
  withWriterProject((dir) => {
    for (const [tool_name, command, plainForm] of COPY_INTO_FOLDER) {
      const plain = guard(dir, tool_name, plainForm);
      assert.equal(plain.permissionDecision, 'deny', `${tool_name}: ${plainForm} (the spelled-out form)`);
      const out = guard(dir, tool_name, command);
      assert.equal(out.permissionDecision, 'deny', `${tool_name}: ${command}`);
      assert.equal(out.permissionDecisionReason, plain.permissionDecisionReason, `${tool_name}: ${command}`);
    }
  });
});

// [tool, command, the .claude form]: git mv of a guardrail folder, and deleting or moving .github, .vscode or .cursor, get the
// deny that the same command gets for .claude.
const LIKE_CLAUDE = [
  ['Bash', 'git mv .claude c', 'mv .claude c'],
  ['Bash', 'git mv .claude/agents x', 'mv .claude c'],
  ['Bash', 'git mv -f -- .claude c', 'mv .claude c'],
  ['Bash', 'git mv .vscode x', 'mv .claude c'],
  ['Bash', 'git mv .git g', 'mv .claude c'],
  ['Bash', 'rm -r .github', 'rm -r .claude'],
  ['Bash', 'rm -rf .vscode', 'rm -rf .claude'],
  ['Bash', 'rm .github/workflows/ci.yml', 'rm .claude/settings.json'],
  ['Bash', 'mv .github x', 'mv .claude c'],
  ['Bash', 'mv .cursor x', 'mv .claude c'],
  ['Bash', 'ls .github | xargs rm', 'ls .claude | xargs rm'],
  ['PowerShell', 'Remove-Item -Recurse .github', 'Remove-Item -Recurse .claude'],
  ['PowerShell', 'Rename-Item .vscode v', 'Rename-Item .claude c'],
  ['PowerShell', 'Move-Item .cursor x', 'Move-Item .claude c'],
  ['PowerShell', 'rmdir .cursor', 'rmdir .claude'],
];

test('issue #9: git mv of a guardrail folder, and deleting or moving .github, .vscode or .cursor, are denied like .claude', () => {
  withWriterProject((dir) => {
    for (const [tool_name, command, claudeForm] of LIKE_CLAUDE) {
      const ref = guard(dir, tool_name, claudeForm);
      assert.equal(ref.permissionDecision, 'deny', `${tool_name}: ${claudeForm} (the .claude form)`);
      const out = guard(dir, tool_name, command);
      assert.equal(out.permissionDecision, 'deny', `${tool_name}: ${command}`);
      assert.equal(out.permissionDecisionReason, ref.permissionDecisionReason, `${tool_name}: ${command}`);
    }
  });
});

test('issue #9: reading .github, .vscode or .cursor, a copy out of a guardrail folder or into another folder keep their verdict', () => {
  withWriterProject((dir) => {
    for (const command of ['ls .github', 'cat .github/workflows/ci.yml', 'git diff .github', 'git log -- .vscode']) {
      assert.equal(guard(dir, 'Bash', command).permissionDecision, 'allow', command);
    }
    for (const [tool_name, command] of [['Bash', 'cp src/a.txt out'], ['Bash', 'cp src/a.txt docs/'], ['Bash', 'rm -r build'],
      ['Bash', 'git rm --cached x.txt'], ['Bash', 'git mv docs/a.md docs/b.md'], ['Bash', 'cp -r .claude backup'],
      ['Bash', 'cp src/a.txt .claude/a.txt'], ['Bash', 'cp -S .claude src/a.txt out'], ['Bash', 'cp --suffix=.claude src/a.txt out'],
      ['PowerShell', 'Copy-Item src/a.txt out'], ['PowerShell', 'Copy-Item .claude out -Recurse'],
      ['PowerShell', 'Copy-Item -Destination out -Path .claude'], ['PowerShell', 'xcopy .claude out /E']]) {
      assert.equal(guard(dir, tool_name, command).permissionDecision, undefined, `${tool_name}: ${command}`);
    }
    const mv = guard(dir, 'Bash', 'mv docs/a.md docs/b.md');
    assert.equal(mv.permissionDecision, 'deny');
    assert.match(mv.permissionDecisionReason, /Edit or Write tool/);
  });
});

// [tool, command]: git rm without --cached of a folder no delete reaches, a path in one, the project root or the whole tree,
// placed from the folder git runs in (-C, a link), behind pathspec magic, or as a wildcard whose literal start begins one of
// those folder names at the root. `rm -r .clau*` gets no verdict (a wildcard is matched as written); git rm gets the deny.
const GIT_RM_GUARD = [
  ...['git rm -r .claude', 'git rm -rf .claude', 'git rm -r ./.claude', 'git rm -r .claude/', 'git rm -r -- .claude', 'git rm -r ".claude"',
    'git rm -r -- ".claude/"', 'git -C . rm -r .claude', 'git rm -r .claude/agents', 'git rm -r ":/.claude"', 'git rm -r ":(top).claude"',
    'git rm -r -- ":/.claude"', 'git rm -r ":(top,icase).CLAUDE"', 'git rm -r .clau*', 'git rm -r .c*', 'git rm -r *', 'git rm -r ":/.clau*"',
    'git rm -r src/../.clau*', 'git rm -r .', 'git rm -r ./', 'git rm -r :/', 'git rm -r ":(top)"', 'git rm -r -- .', 'git -C .claude rm -r .',
    'git -C src rm -r ..', 'git rm -r .github', 'git rm -r .vscode', 'git rm -r .cursor', 'git rm -r .git', 'git rm -r c2', 'git rm -r c2/*',
    'git rm -r src ".claude"',
    // Only exclusions: git takes everything else in the folder it runs in (git 2.52: the dry run of `git rm -r -n ":!docs"`
    // lists .claude). A folder the guard cannot place counts as the root.
    'git rm -r ":!docs"', 'git rm -r ":(exclude)docs"', 'git rm -r ":^docs"', 'git rm -r ":/!docs"', 'git rm -r -- ":!docs" ":!src"',
    'cd $X && git rm -r .'].map((c) => ['Bash', c]),
  ...['git rm -r .claude', "git rm -r '.claude'", 'git rm -r .\\.claude\\', 'git rm -r .clau*', 'git rm -r .', 'git rm -r ":/.claude"',
    'git -C .claude rm -r .', 'git rm -r -- .github', 'git rm -r ":!docs"',
    // Push-Location leaves the guard without a folder to place `.` in, so it counts as the root: `git -C docs rm -r .` asks.
    'Push-Location docs; git rm -r .; Pop-Location'].map((c) => ['PowerShell', c]),
];

test('git rm of a folder no delete reaches, a path in one, the root or the whole tree is denied like rm -r .claude', () => {
  withWriterProject((dir) => {
    const ref = { Bash: guard(dir, 'Bash', 'rm -r .claude'), PowerShell: guard(dir, 'PowerShell', 'Remove-Item -Recurse .claude') };
    for (const plain of Object.values(ref)) assert.equal(plain.permissionDecision, 'deny');
    assert.equal(guard(dir, 'Bash', 'rm -r .clau*').permissionDecision, undefined, 'rm -r .clau* has no verdict');
    for (const [tool_name, command] of GIT_RM_GUARD) {
      const out = guard(dir, tool_name, command);
      assert.equal(out.permissionDecision, 'deny', `${tool_name}: ${command}`);
      assert.equal(out.permissionDecisionReason, ref[tool_name].permissionDecisionReason, `${tool_name}: ${command}`);
    }
  });
});

test('git rm of other paths, below the root, behind an exclusion or with --cached keeps its verdict and reason', () => {
  withWriterProject((dir) => {
    const tier2 = guard(dir, 'Bash', 'git rm docs/a.md');
    assert.equal(tier2.permissionDecision, 'allow');
    assert.match(tier2.permissionDecisionReason, /auto-approved \(approvals\.mode=auto\): git rm deletes files\./);
    for (const [tool_name, command] of [['Bash', 'git rm -r docs'], ['Bash', 'git rm -r src'], ['Bash', 'git -C docs rm -r ":!x"'], ['Bash', 'git rm -r src ":!src/a.txt"'],
      ['Bash', 'git -C docs rm -r .'], ['Bash', '(cd docs && git rm -r .)'], ['Bash', 'git rm -r docs*'], ['Bash', 'git rm -r docs/*'],
      ['Bash', 'git rm -r docs ":(exclude).claude"'], ['Bash', 'git rm -r docs ":!.claude"'], ['PowerShell', 'git rm docs/a.md'],
      ['PowerShell', 'git -C docs rm -r .'], ['PowerShell', 'Push-Location docs; git rm docs/a.md; Pop-Location']]) {
      const out = guard(dir, tool_name, command);
      assert.equal(out.permissionDecision, tier2.permissionDecision, `${tool_name}: ${command}`);
      assert.equal(out.permissionDecisionReason, tier2.permissionDecisionReason, `${tool_name}: ${command}`);
    }
    for (const command of ['git rm --cached -r .claude', 'git rm --cached .env']) {
      assert.equal(guard(dir, 'Bash', command).permissionDecision, undefined, command);
    }
    // Denied today by the guardrail check, which runs first: the reason stays.
    for (const command of ['git rm --cached .claude/settings.local.json', 'git rm -r hardening', 'git rm -r .githooks', 'git rm .claude/settings.json']) {
      const out = guard(dir, 'Bash', command);
      assert.equal(out.permissionDecision, 'deny', command);
      assert.match(out.permissionDecisionReason, /Harness guardrail files/, command);
    }
  });
});
