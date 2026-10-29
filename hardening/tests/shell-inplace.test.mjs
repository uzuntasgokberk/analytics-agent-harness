// Shell policy: an in-place editor (sed -i, perl -pi, awk -i inplace) or a writer whose script holds a `;` inside
// quotes is still a write of the named file (the 2026-10-06 bypass: the old splitter cut the command at that `;`, so
// sed lost its file argument and the write passed). Reads and git with the same characters stay quiet.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeShellCommand } from '../hooks/lib/policy.mjs';

const F = 'docs/notes.md';
const denied = [
  `sed -i 's/a/b/; s/c/d'"'"'s/' ${F}`,
  `sed -i 's/a/b'"'"'c/' ${F}`,
  `sed -i 's/a/b/' ${F} 2>&1`,
  `sed -i 's/a/b/;s/c/d/' hardening/README.md`,
  `sed -i "s/a/b/; s/c/d/" .claude/skills/bi-map/SKILL.md`,
  `"sed" -i "s/a/b/; s/c/d/" ${F}`,
  `sed -i $'s/a/b/; s/c/d/' ${F}`,
  `perl -pi -e 's/a/b/; s/c/d'"'"'s/' ${F}`,
  `awk -i inplace '{ sub(/a/, "b"); print }' ${F}`,
  `echo "x; y" | tee ${F}`,
  `printf 'a; b' > ${F}`,
  `echo 'a; b' >> ${F}`,
  `Set-Content -Path ${F} -Value 'a; b'`,
  // F1-19 (audit 2026-10-18): Windows drops trailing dots and spaces and reads file:stream as the file, so each of these
  // writes docs/notes.md.
  `Set-Content -Path '${F}.' -Value x`,
  `'x' | Out-File ${F}.`,
  `Set-Content -Path '${F}. ' -Value x`,
  `Set-Content -Path '${F}::$DATA' -Value x`,
  `Out-File -FilePath '${F}:stream' -InputObject x`,
  `echo x > ${F}.`,
  `Set-Content -Path C:\\repo\\docs\\notes.md. -Value x`,
  `Copy-Item docs/a.txt templates./b.txt`, // a trailing dot on a folder name: templates/ is a read-only reference folder
];
const quiet = [
  `grep -n "a; b" ${F}`,
  `sed -n '1,5p; 10p' ${F}`,
  `git status; git diff --stat`,
  `echo "a | b" | grep a`,
  `cat ${F} | head -5`,
  `git commit -m "feat: a; b && c"`,
  `Set-Content -Path 'docs/notes.txt.' -Value x`, // F1-19: a trailing dot on a file nothing guards
  `Set-Content -Path ${F}.bak -Value x`,
  `Get-Content '${F}.'`,
  `Out-File -FilePath 'docs/notes.txt:stream' -InputObject x`,
];

test('shell: in-place edits and writes keep their file argument when the script holds a quoted ; and are denied', () => {
  for (const cmd of denied) assert.equal(analyzeShellCommand(cmd, {})?.decision, 'deny', cmd);
});

test('shell: reads and git with the same characters stay quiet', () => {
  for (const cmd of quiet) assert.equal(analyzeShellCommand(cmd, {}), null, cmd);
});
