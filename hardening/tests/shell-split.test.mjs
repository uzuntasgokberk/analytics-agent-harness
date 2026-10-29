// Shell splitting (hooks/lib/shell-split.mjs): separators inside quotes do not split; adjacent quotes join into one word.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { splitStatements, splitPipeline, splitSubcommands, tokenize } from '../hooks/lib/shell-split.mjs';

test('shell-split: a ; inside a re-opened quote does not end the statement (the 2026-10-06 guard bypass)', () => {
  const cmd = `sed -i 's/a/b/; s/c/d'"'"'s/' RFC.md`;
  assert.deepEqual(splitStatements(cmd), [cmd]);
  assert.deepEqual(tokenize(cmd), ['sed', '-i', `s/a/b/; s/c/d's/`, 'RFC.md']);
});

test('shell-split: statements split on ; && || newline and a background &, outside quotes', () => {
  assert.deepEqual(splitStatements('git status; git diff && ls || echo x\ncat a & sleep 1'), ['git status', 'git diff', 'ls', 'echo x', 'cat a', 'sleep 1']);
  assert.deepEqual(splitStatements(`echo "a; b && c" ; echo 'd || e'`), ['echo "a; b && c"', `echo 'd || e'`]);
  assert.deepEqual(splitStatements('a 2>&1 && b'), ['a 2>&1', 'b'], 'a redirect & is not a background &');
  assert.deepEqual(splitStatements('(cd x; git push)'), ['(cd x', 'git push)'], 'parentheses do not hide a statement');
});

test('shell-split: pipeline stages split on | and |& but never on ||, and not inside quotes', () => {
  assert.deepEqual(splitPipeline('cat a | grep "x | y" |& tee b'), ['cat a', 'grep "x | y"', 'tee b']);
  assert.deepEqual(splitPipeline('a || b'), ['a || b']);
  assert.deepEqual(splitSubcommands('a | b; c && d | e'), ['a', 'b', 'c', 'd', 'e']);
});

test('shell-split: tokenize removes quotes, joins adjacent parts, keeps escapes and $\'...\'', () => {
  assert.deepEqual(tokenize(`echo 'a'"b"c d\\ e $'f;g'`), ['echo', 'abc', 'd e', 'f;g']);
  assert.deepEqual(tokenize(`perl -pi -e 's/a/b/; s/c/d'"'"'s/' x.md`), ['perl', '-pi', '-e', `s/a/b/; s/c/d's/`, 'x.md']);
  assert.deepEqual(tokenize(`Set-Content -Path "a b.md" -Value 'x; y'`), ['Set-Content', '-Path', 'a b.md', '-Value', 'x; y']);
  assert.deepEqual(tokenize(`echo ""`), ['echo', ''], 'an empty quoted word stays a word');
  assert.deepEqual(tokenize(`sed -i 's/a/b/ file.md`), ['sed', '-i', 's/a/b/ file.md'], 'an unterminated quote runs to the end');
  assert.deepEqual(tokenize('  '), []);
});

test('shell-split: Windows paths keep their backslashes, quoted or not', () => {
  assert.deepEqual(tokenize(`type C:\\Windows\\win.ini`), ['type', 'C:\\Windows\\win.ini']);
  assert.deepEqual(tokenize(`cat "C:\\Tools\\someone\\.ssh\\x.txt"`), ['cat', 'C:\\Tools\\someone\\.ssh\\x.txt']);
  assert.deepEqual(tokenize(`del setup\\data\\y.csv`), ['del', 'setup\\data\\y.csv']);
  assert.deepEqual(tokenize(`dir \\\\server\\share`), ['dir', '\\\\server\\share']);
  assert.deepEqual(tokenize(`echo "a\\"b" c\\;d`), ['echo', 'a"b', 'c;d'], 'escapes a shell needs still work');
  assert.deepEqual(splitStatements(`echo a\\;b; echo c`), ['echo a\\;b', 'echo c']);
});
