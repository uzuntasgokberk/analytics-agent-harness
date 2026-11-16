// Audit 2026-11-16, routine shell commands. In auto mode the PreToolUse guard answers "allow" for a command that
// analyzeShellCommand leaves alone and routineShell calls routine: looking at files inside the project, local git, the
// harness's own checks. Each command below was answered "allow" through the spawned hook before the fix, while it runs code,
// writes a file, reads outside the project or searches hidden and ignored files:
// 1. node --check (or -c) with a preload option (-r, --require, --import, --loader) runs that code; `node --run x` runs a
//    package.json script. `-C` is --conditions (it takes a value and runs the script), not -c.
// 2. sort writes any file through an abbreviated --output (`--outp=f`, `--o=f`: getopt_long takes every unambiguous prefix)
//    and runs a program through --compress-program; a read-only subagent could write with `sort --outp=f` and `uniq IN OUT`.
// 3. grep --recu, --dereference-recursiv, --dir=recurse and clusters such as -5r; git grep --untracked --no-exclude-standard
//    (ignored files, .env included); ripgrep -uu, --glob=* (an override glob beats the hidden and ignore filters), --follow,
//    --ignore-file and --hostname-bin (runs a program).
// 4. Options that read a file: date -f FILE (prints each line it cannot parse), wc and sort --files0-from=FILE.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyzeShellCommand, routineShell } from '../hooks/lib/policy.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const preHook = path.join(here, '..', 'hooks', 'pre-tool-use.mjs');
const scopeHook = path.join(here, '..', 'hooks', 'agent-scope.mjs');
const shell = (cmd) => analyzeShellCommand(cmd, {});

/** A temporary project with a few plain files, removed after `body` ran. */
function withProject(body) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-audit-1116-'));
  try {
    for (const rel of ['docs/a.md', 'docs/b.md', 'docs/notes.md', 'hardening/hooks/lib/policy.mjs', 'hardening/scripts/validate.mjs']) {
      fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
      fs.writeFileSync(path.join(dir, rel), rel.endsWith('.md') ? '# x\n' : 'export {};\n');
    }
    return body(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

/** The PreToolUse guard's decision for one shell command, run as a process like Claude Code runs it (auto mode, the default). */
function hookDecision(dir, command, tool_name = 'Bash') {
  const r = spawnSync(process.execPath, [preHook], {
    input: JSON.stringify({ hook_event_name: 'PreToolUse', session_id: 'audit-1116', tool_name, tool_input: { command } }),
    env: { ...process.env, CLAUDE_PROJECT_DIR: dir },
    encoding: 'utf8',
  });
  assert.equal(r.status, 0, r.stderr); // a guard that did not run prints no verdict, which "not allow" would read as a pass
  return r.stdout.trim() ? JSON.parse(r.stdout).hookSpecificOutput?.permissionDecision ?? null : null;
}

/** The subagent scope guard's decision for one shell command of a subagent (read-only by default for the auditor). */
function scopeDecision(dir, command, agent = 'bi-security-auditor') {
  const r = spawnSync(process.execPath, [scopeHook], {
    input: JSON.stringify({ hook_event_name: 'PreToolUse', session_id: 'audit-1116', agent_type: agent, tool_name: 'Bash', tool_input: { command } }),
    env: { ...process.env, CLAUDE_PROJECT_DIR: dir },
    encoding: 'utf8',
  });
  assert.equal(r.status, 0, r.stderr);
  return r.stdout.trim() ? JSON.parse(r.stdout).hookSpecificOutput?.permissionDecision ?? null : null;
}

/** Every proper prefix of a long option name, shortest first (`out`: o, ou). */
const prefixesOf = (name) => Array.from({ length: name.length - 1 }, (_, n) => name.slice(0, n + 1));

/** Asserts that the hook does not answer "allow" and that the command is not routine. */
function notRoutine(dir, commands) {
  for (const cmd of commands) {
    assert.notEqual(hookDecision(dir, cmd), 'allow', cmd);
    assert.equal(routineShell(cmd), false, cmd);
  }
}

// ---------------------------------------------------------------- 1. node

test('audit 2026-11-16 (1): node --check with a preload or loader option, and node --run, are judged like running a script file', () => {
  const loads = ['node --check -r ./x.cjs docs/a.md', 'node --check --require ./x.cjs docs/a.md', 'node -c --import ./x.mjs docs/a.md',
    'node --check -r ./docs/notes.md docs/a.md', 'node --run evil -c'];
  withProject((dir) => notRoutine(dir, loads));
  // Every spelling: glued to -r, with `=`, the loader options, an underscore for a dash (node reads both), without --check.
  const spellings = [...loads, 'node --check --require=./x.cjs docs/a.md', 'node -c -r./x.cjs docs/a.md', 'node --check --import=./x.mjs docs/a.md',
    'node --check --loader ./x.mjs docs/a.md', 'node --check --experimental-loader=./x.mjs docs/a.md', 'node -c --experimental_loader ./x.mjs docs/a.md',
    'node -c --run=evil', 'node --run evil', 'node --require=./x.cjs', 'node -r ./x.cjs -e 1', 'node --import=./x.mjs -p 1',
    'node --require=./x.cjs hardening/scripts/validate.mjs', 'node -r ./x.cjs hardening/tests/run-all.mjs', 'node --version -r ./x.cjs'];
  for (const cmd of spellings) {
    const v = shell(cmd);
    assert.equal(v?.decision, 'ask', cmd);
    assert.equal(v?.autoDefer, true, `${cmd}: Claude Code's own prompt decides in auto mode, as for node tools/gen.mjs`);
    assert.equal(routineShell(cmd), false, cmd);
  }
  assert.deepEqual(Object.keys(shell('node --check -r ./x.cjs docs/a.md') ?? {}).sort(), Object.keys(shell('node tools/gen.mjs')).sort(), 'the same kind of verdict as a script run');
  // A syntax check is routine only for files inside the project and nothing else; --version only alone. Case matters: -C is
  // --conditions (it takes a value and runs the script after it), -V is no version flag.
  for (const cmd of ['node -C x docs/a.md', 'node --check --title x docs/a.md', 'node --check --env-file=x docs/a.md', 'node --check ../outside.mjs',
    'node -c -- docs/a.md', 'node --version x', 'node -v --check docs/a.md', 'node -V', 'node -C=x -c docs/a.md']) {
    assert.equal(routineShell(cmd), false, cmd);
  }
  withProject((dir) => notRoutine(dir, ['node -C x docs/a.md']));
});

// ---------------------------------------------------------------- 2. sort and uniq

test('audit 2026-11-16 (2): sort with an output option in any spelling is judged like sort --output=<file> and is never routine', () => {
  withProject((dir) => notRoutine(dir, ['sort --outp=.claude/settings.local.json docs/b.md', 'sort --o=hardening/hooks/pre-tool-use.mjs docs/b.md',
    'sort --outp=templates/t.md docs/b.md', 'sort --outp=docs/a.md docs/b.md', 'sort --compress-prog=./x.cmd docs/b.md', 'sort --out docs/a.md docs/b.md']));
  const targets = [['.claude/settings.local.json', 'deny'], ['hardening/hooks/pre-tool-use.mjs', 'deny'], ['templates/t.md', 'deny'], ['docs/a.md', 'deny'],
    ['templates/t.txt', 'deny'], ['x.txt', null]];
  for (const [target, expected] of targets) {
    const full = `sort --output=${target} docs/b.md`;
    assert.equal(shell(full)?.decision ?? null, expected, full);
    assert.equal(routineShell(full), false, full);
    const spellings = [`sort --output ${target} docs/b.md`, `sort -o ${target} docs/b.md`, `sort -o${target} docs/b.md`, `sort -uo ${target} docs/b.md`,
      `sort -nuo${target} docs/b.md`, `sort docs/b.md -o ${target}`, `sort -r docs/b.md --outp=${target}`,
      ...prefixesOf('output').flatMap((p) => [`sort --${p}=${target} docs/b.md`, `sort --${p} ${target} docs/b.md`])];
    for (const cmd of spellings) {
      assert.deepEqual(shell(cmd), shell(full), cmd);
      assert.equal(routineShell(cmd), false, cmd);
    }
  }
  // --compress-program runs a program, in every spelling; `--c` is ambiguous (--check) and counts as it.
  const run = 'sort --compress-program=./x.cmd docs/b.md';
  assert.equal(routineShell(run), false, run);
  for (const p of prefixesOf('compress-program')) {
    for (const cmd of [`sort --${p}=./x.cmd docs/b.md`, `sort --${p} ./x.cmd docs/b.md`]) {
      assert.deepEqual(shell(cmd), shell(run), cmd);
      assert.equal(routineShell(cmd), false, cmd);
    }
  }
  // Value letters end a cluster: `-t o` and `-to` set the separator, `-ko` a key; they write nothing.
  for (const cmd of ['sort -t o docs/a.md', 'sort -to docs/a.md', 'sort -k2 docs/a.md', 'sort --check docs/a.md', 'sort -c docs/a.md', 'sort -nr docs/a.md']) {
    assert.equal(routineShell(cmd), true, cmd);
  }
  // uniq IN OUT writes OUT, also with `-` (stdin) as IN; the values of -f, -s and -w are no file.
  for (const cmd of ['uniq docs/a.md docs/out.txt', 'uniq - docs/out.txt', 'uniq -c docs/a.md docs/out.txt', 'uniq -f 1 docs/a.md docs/out.txt']) {
    assert.equal(routineShell(cmd), false, cmd);
  }
  for (const cmd of ['uniq -f 1 docs/a.md', 'uniq -c -w 3 docs/a.md', 'uniq --skip-chars 2 docs/a.md']) assert.equal(routineShell(cmd), true, cmd);
});

test('audit 2026-11-16 (2): a read-only subagent may not write through sort in any spelling or through uniq IN OUT', () => {
  withProject((dir) => {
    for (const cmd of ['sort --outp=docs/a.md docs/b.md', 'sort --o=docs/a.md docs/b.md', 'sort --ou docs/a.md docs/b.md', 'sort -uo docs/a.md docs/b.md',
      'sort -odocs/a.md docs/b.md', 'sort --output=docs/a.md docs/b.md', 'sort --compress-prog=./x.cmd docs/b.md', 'uniq docs/a.md docs/out.txt',
      'uniq -c docs/a.md docs/out.txt', 'uniq - docs/out.txt', 'uniq -f 1 docs/a.md docs/out.txt', 'cat docs/a.md | uniq - docs/out.txt']) {
      assert.equal(scopeDecision(dir, cmd), 'deny', cmd);
    }
    for (const cmd of ['sort docs/a.md', 'sort -k 2 docs/a.md', 'sort -t o docs/a.md', 'uniq docs/a.md', 'uniq -c docs/a.md', 'uniq -f 1 docs/a.md',
      'cat docs/a.md | sort | uniq -c']) {
      assert.equal(scopeDecision(dir, cmd), null, cmd);
    }
  });
});

// ---------------------------------------------------------------- 3. recursive and unrestricted searches

test('audit 2026-11-16 (3): grep reads every spelling of --recursive, --dereference-recursive and --directories as that option', () => {
  withProject((dir) => notRoutine(dir, ['grep --recu FAKE .', 'grep --recursiv FAKE .', 'grep --dereference-recursiv FAKE .', 'grep --directories recurse FAKE .',
    'grep --dir=recurse FAKE .', 'grep -5r FAKE .', 'grep -rA3 FAKE .', 'grep -nd recurse FAKE .']));
  for (const [option, full, forms] of [
    ['recursive', 'grep --recursive FAKE .', (p) => [`grep --${p} FAKE .`]],
    ['dereference-recursive', 'grep --dereference-recursive FAKE .', (p) => [`grep --${p} FAKE .`]],
    ['directories', 'grep --directories=recurse FAKE .', (p) => [`grep --${p}=recurse FAKE .`, `grep --${p} recurse FAKE .`]],
  ]) {
    assert.equal(routineShell(full), false, full);
    for (const p of prefixesOf(option)) {
      for (const cmd of forms(p)) {
        assert.deepEqual(shell(cmd), shell(full), cmd);
        assert.equal(routineShell(cmd), false, cmd);
      }
    }
  }
  for (const cmd of ['grep -d recurse FAKE .', 'grep -drecurse FAKE .', 'grep -nRi FAKE .', 'grep -iR5 FAKE .', 'grep -2nr FAKE .', 'egrep --recu FAKE .',
    'fgrep --derefer FAKE .', 'egrep -3r FAKE .', 'grep --directories=read FAKE docs/a.md']) {
    assert.equal(routineShell(cmd), false, cmd);
  }
  // A value letter takes the rest of its word: `-er` searches for "r", `-A3` is a context length.
  for (const cmd of ['grep -n x docs/a.md', 'grep -er docs/a.md', 'grep -A3 x docs/a.md', 'grep -in --color=never x docs/a.md', 'grep --regexp=x docs/a.md',
    'grep --exclude=*.md x docs/a.md']) {
    assert.equal(routineShell(cmd), true, cmd);
  }
});

test('audit 2026-11-16 (3): git grep --untracked and --no-exclude-standard are not routine in any spelling', () => {
  withProject((dir) => notRoutine(dir, ['git grep --untracked --no-exclude-standard FAKE', 'git grep --untr --no-exclude-s FAKE']));
  for (const option of ['untracked', 'no-exclude-standard']) {
    for (const p of [...prefixesOf(option), option]) {
      for (const cmd of [`git grep --${p} FAKE`, `git grep -n --${p} -i FAKE docs`]) assert.equal(routineShell(cmd), false, cmd);
    }
  }
  for (const cmd of ['git grep x', 'git grep -n -i x docs', 'git grep --cached x', 'git grep --exclude-standard x']) assert.equal(routineShell(cmd), true, cmd);
});

test('audit 2026-11-16 (3): ripgrep is routine only with options that cannot widen what it reads, write or run a program', () => {
  withProject((dir) => notRoutine(dir, ['rg --unrestricted --unrestricted FAKE .', 'rg -iuu FAKE .', 'rg -nuu FAKE', "rg '-g*' FAKE .", 'rg --glob=* FAKE .',
    'rg --hostname-bin=./x.cmd FAKE docs', 'rg --follow FAKE .', 'rg --ignore-file=../x FAKE .']));
  for (const cmd of ['rg -u FAKE .', 'rg -L FAKE .', 'rg -. FAKE .', 'rg -nL FAKE .', 'rg -z FAKE .', 'rg --search-zip FAKE .', 'rg --pre=./x.sh FAKE .',
    'rg --pre-glob=* FAKE .', 'rg -a FAKE .', 'rg --text FAKE .', 'rg --binary FAKE .', 'rg --no-ignore-vcs FAKE .', 'rg --hidden FAKE .',
    "rg --glob '*' FAKE .", "rg -g '*' FAKE .", "rg -g'.*' FAKE .", 'rg --iglob=** FAKE .', 'rg --glob=**/*.md FAKE .', "rg -g '*.env' FAKE .", 'rg -g*.local FAKE .',
    'rg --glob=*.json FAKE .', 'rg --glob=*.pem FAKE .', 'rg --iglob=*.PBIX FAKE .', 'rg -g!*.md FAKE .', 'rg --type-add=x:* -t x FAKE .',
    'rg -f ../outside.txt docs', 'rg --file=../outside.txt docs', 'rg -f../outside.txt docs', 'rg -nf ../outside.txt docs', 'rg --unknown-option FAKE docs',
    'rg --hyperlink-format=x FAKE docs', 'rg -E utf-16 FAKE docs']) {
    assert.equal(routineShell(cmd), false, cmd);
  }
  // Plain flags, clusters of them, text and number values, and a plain extension glob of a file type the harness works with.
  for (const cmd of ['rg x docs', 'rg -n -i x docs', 'rg -niw x docs', 'rg -l x docs', 'rg -t md x docs', 'rg -e x docs', 'rg -C 2 x docs', 'rg -nC2 x docs',
    'rg --max-count=3 x docs', 'rg --glob=*.md x docs', "rg -g '*.tmdl' x docs", 'rg -g*.md x docs', 'rg --files docs', 'rg -f docs/a.md docs']) {
    assert.equal(routineShell(cmd), true, cmd);
  }
});

// ---------------------------------------------------------------- 4. options that read a file

test('audit 2026-11-16 (4): a file named by an option (date -f, --files0-from, grep --file) is judged like a file the command reads', () => {
  withProject((dir) => {
    notRoutine(dir, ['date -f ../outside.txt', 'date --file=C:/Windows/win.ini', 'date -f ~/.bash_history', 'date -f "$HOME/x"',
      'wc --files0-from=../outside.txt', 'sort --files0-from=../outside.txt']);
    assert.equal(hookDecision(dir, 'date -f docs/a.md'), 'allow', 'a plain file inside the project stays routine');
  });
  for (const [option, forms] of [
    ['file', (p, f) => [`date --${p}=${f}`, `date --${p} ${f}`]],
    ['reference', (p, f) => [`date --${p}=${f}`, `date --${p} ${f}`]],
  ]) {
    for (const p of [...prefixesOf(option), option]) {
      for (const f of ['../outside.txt', '~/x', '$HOME/x', 'docs/*.md', '.env']) {
        for (const cmd of forms(p, f)) assert.equal(routineShell(cmd), false, cmd);
      }
    }
  }
  for (const cmd of ['date -f../outside.txt', 'date -uf ../outside.txt', 'date -r ../outside.txt', 'date -ur../outside.txt', 'date -f .env', 'date -f docs/*.md',
    'grep --file=../outside.txt x docs/a.md', 'grep -f../outside.txt x docs/a.md', 'grep --fi=../outside.txt x docs/a.md', 'grep -nf ../outside.txt docs/a.md',
    'grep --exclude-from=../x x docs/a.md', 'sort --random-source=../outside.txt docs/a.md']) {
    assert.equal(routineShell(cmd), false, cmd);
  }
  // --files0-from reads the names of the files to read from its file (or stdin, `-`): what they name is out of sight, never routine.
  for (const [prog, full] of [['wc', 'wc --files0-from=../outside.txt'], ['sort', 'sort --files0-from=../outside.txt']]) {
    for (const p of [...prefixesOf('files0-from'), 'files0-from']) {
      for (const f of ['../outside.txt', 'docs/a.md', '-']) {
        for (const cmd of [`${prog} --${p}=${f}`, `${prog} --${p} ${f}`]) {
          assert.deepEqual(shell(cmd), shell(full.replace('../outside.txt', f)), cmd);
          assert.equal(routineShell(cmd), false, cmd);
        }
      }
    }
  }
  // --set (and an operand that is no +FORMAT, the POSIX way to set the clock) changes the system time.
  for (const p of [...prefixesOf('set'), 'set']) {
    for (const cmd of [`date --${p}=2030-01-01`, `date --${p} 2030-01-01`]) assert.equal(routineShell(cmd), false, cmd);
  }
  for (const cmd of ['date -s 2030-01-01', 'date -s2030-01-01', 'date -us 2030-01-01', 'date 010100002030', 'date -u 0101']) {
    assert.equal(routineShell(cmd), false, cmd);
  }
  for (const cmd of ['date', 'date +%F', 'date -u +%FT%TZ', 'date -d tomorrow +%F', 'date --date tomorrow', 'date -Iseconds', 'date --iso-8601=seconds',
    'date -R', 'date -f docs/a.md', 'date -r docs/a.md', 'date +%F 2>/dev/null']) {
    assert.equal(routineShell(cmd), true, cmd);
  }
});

// ---------------------------------------------------------------- what stays

// This test passes before and after the fix: the commands the fix must keep routine, and the verdicts it must not change.
test('audit 2026-11-16: the routine commands stay routine and the searches that name .env keep no verdict', () => {
  withProject((dir) => {
    for (const cmd of ['rg x docs', 'git grep x', 'git grep -n -i x docs', 'grep -n x docs/a.md', 'date +%F', 'date', 'node --check hardening/hooks/lib/policy.mjs',
      'node --version', 'node hardening/scripts/validate.mjs --changed', 'sort docs/a.md', 'uniq docs/a.md', 'wc -l docs/a.md', 'cat docs/a.md | sort | uniq -c']) {
      assert.equal(hookDecision(dir, cmd), 'allow', cmd);
    }
  });
  for (const cmd of ['rg -n --glob=*.md .env docs', 'grep -ri --color=never .env README.md']) assert.equal(shell(cmd), null, cmd);
});
