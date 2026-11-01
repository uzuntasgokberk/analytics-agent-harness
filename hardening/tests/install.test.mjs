// Installer (scripts/install-into.mjs): the hardening pack is refused without Node 18.17+ on PATH, because a hook that
// cannot start or parse lets every tool call through (Claude Code docs, Hooks). The core harness needs no Node.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { DEFAULT_CONFIG } from '../hooks/lib/common.mjs';

const installer = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'scripts', 'install-into.mjs');

/** The current environment without any PATH entry (Windows spells it Path), so `node` cannot be found. */
const withoutPath = () => ({ ...Object.fromEntries(Object.entries(process.env).filter(([k]) => !/^path$/i.test(k))), PATH: '' });

// The installer runs from a clone of the harness (LICENSE at its root); an installed copy cannot install further.
const harnessClone = fs.existsSync(path.join(path.dirname(installer), '..', '..', 'LICENSE'));

/** The manifest an install recorded in a target, and its hardening/ entries (the installed pack). */
const readManifest = (dir) => JSON.parse(fs.readFileSync(path.join(dir, '.claude', 'bi-agent-harness.json'), 'utf8'));
const packEntries = (manifest) => Object.fromEntries(Object.entries(manifest.files).filter(([rel]) => rel.startsWith('hardening/')));
/** SHA-256 of a file the way the installer records it: text is hashed with LF line endings. */
const digestOf = (file) => crypto.createHash('sha256').update(Buffer.from(fs.readFileSync(file).toString('latin1').replace(/\r\n/g, '\n'), 'latin1')).digest('hex');
// A `git commit -a` hook that runs these tests exports GIT_INDEX_FILE (and GIT_DIR in some setups), which would send the
// temporary repositories' git calls (the tests' and the installer's) elsewhere.
const GIT_REPO_VARS = new Set(['GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE', 'GIT_OBJECT_DIRECTORY', 'GIT_ALTERNATE_OBJECT_DIRECTORIES', 'GIT_COMMON_DIR', 'GIT_PREFIX']);
const gitEnv = () => Object.fromEntries(Object.entries(process.env).filter(([k]) => !GIT_REPO_VARS.has(k.toUpperCase())));
const git = (dir, ...args) => spawnSync('git', ['-C', dir, ...args], { encoding: 'utf8', env: gitEnv() });
const run = (...args) => spawnSync(process.execPath, [installer, ...args], { encoding: 'utf8', env: gitEnv() });

test('installer: --hardening stops without node on PATH, before reading any file', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-install-'));
  try {
    const hard = spawnSync(process.execPath, [installer, dir, '--hardening', '--dry-run'], { env: withoutPath(), encoding: 'utf8' });
    assert.equal(hard.status, 1, hard.stderr);
    assert.match(hard.stderr, /Node\.js 18\.17 or later on PATH/);
    assert.deepEqual(fs.readdirSync(dir), []);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// F1-113: this test returned early in every clone, and installed copies ship no tests, so it never ran. It now builds the
// installed copy it needs and runs that copy's installer.
test('installer: an installed copy refuses to install further, with a clear message and no change', (t) => {
  if (!harnessClone) return t.skip('runs only in a clone of the harness (LICENSE at the root)');
  const copy = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-install-'));
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-install-'));
  try {
    assert.equal(run(copy, '--hardening').status, 0);
    const copied = path.join(copy, 'hardening', 'scripts', 'install-into.mjs');
    assert.ok(fs.existsSync(copied), 'the installed copy has the installer');
    for (const args of [['--dry-run'], []]) {
      const r = spawnSync(process.execPath, [copied, dir, ...args], { encoding: 'utf8' });
      assert.equal(r.status, 1, r.stderr);
      assert.match(r.stderr, /Install from a clone of the harness repository/);
      assert.deepEqual(fs.readdirSync(dir), [], `${args.join(' ') || 'install'} wrote nothing`);
    }
  } finally {
    fs.rmSync(copy, { recursive: true, force: true });
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('installer: the core installs without node on PATH; with node the pack proceeds', (t) => {
  if (!harnessClone) return t.skip('runs only in a clone of the harness (LICENSE at the root)');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-install-'));
  try {
    const core = spawnSync(process.execPath, [installer, dir, '--dry-run'], { env: withoutPath(), encoding: 'utf8' });
    assert.equal(core.status, 0, core.stderr);
    const ok = spawnSync(process.execPath, [installer, dir, '--hardening', '--dry-run'], { encoding: 'utf8' });
    assert.equal(ok.status, 0, ok.stderr);
    assert.deepEqual(fs.readdirSync(dir), []); // --dry-run wrote nothing
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('installer: the release scan and the tests stay out of an installed copy', (t) => {
  if (!harnessClone) return t.skip('runs only in a clone of the harness (LICENSE at the root)');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-install-'));
  try {
    const r = spawnSync(process.execPath, [installer, dir, '--hardening'], { encoding: 'utf8' });
    assert.equal(r.status, 0, r.stderr);
    assert.ok(!fs.existsSync(path.join(dir, 'hardening', 'scripts', 'release-check.mjs')), 'release-check.mjs is for maintainers');
    assert.deepEqual(fs.readdirSync(path.join(dir, 'hardening', 'tests')), ['run-all.mjs']);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('installer: --enable-hooks writes the VS Code Copilot hook file once and keeps a changed one', (t) => {
  if (!harnessClone) return t.skip('runs only in a clone of the harness (LICENSE at the root)');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-install-'));
  try {
    spawnSync('git', ['-C', dir, 'init', '-q'], { encoding: 'utf8' });
    const first = spawnSync(process.execPath, [installer, dir, '--hardening', '--enable-hooks'], { encoding: 'utf8' });
    assert.equal(first.status, 0, first.stderr);
    assert.match(first.stdout, /hooks \(VS Code Copilot\): \.github\/hooks\/bi-harness\.json written/);
    assert.match(first.stdout, /hooks \(Copilot CLI and cloud agent\): \.github\/hooks\/bi-harness\.copilot-cli\.json written/);
    const file = path.join(dir, '.github', 'hooks', 'bi-harness.json');
    const shipped = fs.readFileSync(path.join(path.dirname(installer), '..', 'vscode.hooks.json'), 'utf8');
    assert.equal(fs.readFileSync(file, 'utf8'), shipped);
    assert.equal(fs.readFileSync(path.join(dir, '.github', 'hooks', 'bi-harness.copilot-cli.json'), 'utf8'), fs.readFileSync(path.join(path.dirname(installer), '..', 'copilot-cli.hooks.json'), 'utf8'));
    assert.ok(fs.existsSync(path.join(dir, '.github', 'agents', 'bi-expert.agent.md')), 'the Copilot agent pointer ships');
    for (const editor of ['bi-tmdl-modeler', 'bi-pbir-editor', 'bi-rdl-editor', 'bi-ssis-editor', 'bi-doc-generator']) {
      assert.ok(fs.existsSync(path.join(dir, '.github', 'agents', `${editor}.agent.md`)), `the Copilot file of ${editor} ships`);
    }
    assert.ok(fs.existsSync(path.join(dir, '.github', 'instructions', 'bi-tmdl.instructions.md')), 'the rule pointers ship');
    const again = spawnSync(process.execPath, [installer, dir, '--update', '--enable-hooks'], { encoding: 'utf8' });
    assert.equal(again.status, 0, again.stderr);
    assert.match(again.stdout, /bi-harness\.json unchanged/);
    fs.writeFileSync(file, '{ "hooks": {} }\n');
    const kept = spawnSync(process.execPath, [installer, dir, '--update', '--enable-hooks'], { encoding: 'utf8' });
    assert.match(kept.stdout, /bi-harness\.json kept/);
    assert.equal(fs.readFileSync(file, 'utf8'), '{ "hooks": {} }\n', 'a changed file is never overwritten');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// The PreToolUse guard tells the copies of one Copilot call apart by BI_HARNESS_HOST (hooks/lib/ask-once.mjs): each Copilot
// hook file sets its own host on every entry, and the Claude registration sets none (its copy is `claude`). Two
// registrations with one identity would count as one copy, so a second ask could not be matched to the first.
test('installer: every Copilot hook entry carries BI_HARNESS_HOST for its host, shipped and installed; the Claude registration carries none', (t) => {
  const pack = path.join(path.dirname(installer), '..');
  const copilotEntries = (file) => Object.values(JSON.parse(fs.readFileSync(file, 'utf8')).hooks).flat();
  const checkCopilot = (file, host) => {
    const entries = copilotEntries(file);
    assert.ok(entries.length >= 7, `${file}: the pack's entries`);
    for (const entry of entries) assert.equal(entry.env?.BI_HARNESS_HOST, host, `${path.basename(file)}: ${JSON.stringify(entry)}`);
    assert.ok(entries.some((e) => /pre-tool-use\.mjs/.test(JSON.stringify(e))), `${file}: the guard is registered`);
  };
  const checkClaude = (file) => {
    const text = fs.readFileSync(file, 'utf8');
    assert.match(text, /pre-tool-use\.mjs/, `${file}: the guard is registered`);
    assert.doesNotMatch(text, /BI_HARNESS_HOST/, `${file}: the Claude registration sets no host, in no entry and no env block`);
  };
  checkCopilot(path.join(pack, 'vscode.hooks.json'), 'vscode');
  checkCopilot(path.join(pack, 'copilot-cli.hooks.json'), 'copilot-cli');
  checkClaude(path.join(pack, 'settings.hooks.json'));
  if (!harnessClone) return t.skip('the installed copy is checked only in a clone of the harness (LICENSE at the root)');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-install-'));
  try {
    git(dir, 'init', '-q');
    const r = run(dir, '--hardening', '--enable-hooks');
    assert.equal(r.status, 0, r.stderr);
    checkCopilot(path.join(dir, '.github', 'hooks', 'bi-harness.json'), 'vscode');
    checkCopilot(path.join(dir, '.github', 'hooks', 'bi-harness.copilot-cli.json'), 'copilot-cli');
    checkClaude(path.join(dir, '.claude', 'settings.local.json'));
    assert.doesNotMatch(fs.readFileSync(path.join(dir, '.claude', 'settings.json'), 'utf8'), /BI_HARNESS_HOST/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('installer: --enable-hooks --shared registers the hooks in .claude/settings.json for the team, and --update keeps them', (t) => {
  if (!harnessClone) return t.skip('runs only in a clone of the harness (LICENSE at the root)');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-install-'));
  try {
    spawnSync('git', ['-C', dir, 'init', '-q'], { encoding: 'utf8' });
    const first = spawnSync(process.execPath, [installer, dir, '--hardening', '--enable-hooks', '--shared'], { encoding: 'utf8' });
    assert.equal(first.status, 0, first.stderr);
    assert.match(first.stdout, /merged into \.claude\/settings\.json \(shared: commit it/);
    const settings = path.join(dir, '.claude', 'settings.json');
    const shared = JSON.parse(fs.readFileSync(settings, 'utf8'));
    assert.ok(Array.isArray(shared.hooks?.PreToolUse) && shared.hooks.PreToolUse.length > 0, 'the hooks are in the committed settings file');
    assert.ok(shared.permissions.allow.includes('Bash(node hardening/scripts/validate.mjs *)'), 'the pack permission rules merged too');
    assert.ok(!fs.existsSync(path.join(dir, '.claude', 'settings.local.json')), 'nothing written to the local file');
    const manifestFile = path.join(dir, '.claude', 'bi-agent-harness.json');
    const manifest = JSON.parse(fs.readFileSync(manifestFile, 'utf8'));
    assert.equal(manifest.hooks, 'shared', 'the manifest records where the hooks went');
    assert.match(String(manifest.version), /^\d+\.\d+\.\d+$/, 'the manifest records the pack version');
    // An update with no flags refreshes the file and re-applies the shared hooks: never "kept: you changed it".
    const again = spawnSync(process.execPath, [installer, dir, '--update'], { encoding: 'utf8' });
    assert.equal(again.status, 0, again.stderr);
    assert.match(again.stdout, /kept     : 0 file\(s\)/);
    assert.match(again.stdout, /merged into \.claude\/settings\.json \(shared/);
    const after = JSON.parse(fs.readFileSync(settings, 'utf8'));
    assert.deepEqual(after.hooks, shared.hooks, 'the hooks survive the update unchanged');
    assert.equal(JSON.parse(fs.readFileSync(manifestFile, 'utf8')).hooks, 'shared');
    assert.ok(!fs.existsSync(path.join(dir, '.claude', 'settings.local.json')));
    // F2-13: --enable-hooks alone (a teammate's per-machine step) keeps the team registration; it used to move it to
    // settings.local.json and take it out of the committed file.
    const local = spawnSync(process.execPath, [installer, dir, '--update', '--enable-hooks'], { encoding: 'utf8' });
    assert.match(local.stdout, /merged into \.claude\/settings\.json \(shared/);
    assert.equal(JSON.parse(fs.readFileSync(manifestFile, 'utf8')).hooks, 'shared');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// F1-49: a shared .claude/settings.json the user changed is kept on EVERY update. The hook re-application recorded its
// new content as the installed state, so the second update took the file for untouched, overwrote it and deleted the
// user's own rules (a deny rule among them) without a word.
test('installer: --update keeps a user-edited shared .claude/settings.json on every run and never records it as installed', (t) => {
  if (!harnessClone) return t.skip('runs only in a clone of the harness (LICENSE at the root)');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-install-'));
  try {
    spawnSync('git', ['-C', dir, 'init', '-q'], { encoding: 'utf8' });
    const first = run(dir, '--hardening', '--enable-hooks', '--shared');
    assert.equal(first.status, 0, first.stderr);
    const settings = path.join(dir, '.claude', 'settings.json');
    const installed = readManifest(dir).files['.claude/settings.json'];
    assert.equal(installed, digestOf(settings), 'the install records the merged file as the installed state');
    // The team adds rules of its own: a deny rule, an allow rule and a hook group.
    const edited = JSON.parse(fs.readFileSync(settings, 'utf8'));
    edited.permissions.deny.push('Read(./team-notes/**)');
    edited.permissions.allow.push('Bash(my-team-tool *)');
    edited.hooks.PreToolUse.push({ matcher: 'Bash', hooks: [{ type: 'command', command: 'node my-own-hook.mjs' }] });
    fs.writeFileSync(settings, `${JSON.stringify(edited, null, 2)}\n`);
    assert.notEqual(digestOf(settings), installed);
    for (const n of [1, 2, 3]) {
      const r = run(dir, '--update');
      assert.equal(r.status, 0, r.stderr);
      assert.match(r.stdout, /kept     : 1 file\(s\)[^\n]*:\n    \.claude\/settings\.json\n/, `update ${n} lists the changed file as kept`);
      assert.match(r.stdout, /merged into \.claude\/settings\.json \(shared/, `update ${n} still re-applies the registration`);
      const after = JSON.parse(fs.readFileSync(settings, 'utf8'));
      assert.ok(after.permissions.deny.includes('Read(./team-notes/**)'), `update ${n} keeps the user's deny rule`);
      assert.ok(after.permissions.allow.includes('Bash(my-team-tool *)'), `update ${n} keeps the user's allow rule`);
      assert.ok(after.hooks.PreToolUse.some((g) => g.matcher === 'Bash' && g.hooks.some((h) => h.command === 'node my-own-hook.mjs')), `update ${n} keeps the user's hook group`);
      assert.ok(after.hooks.PreToolUse.some((g) => /hardening\/hooks\/pre-tool-use\.mjs/.test(JSON.stringify(g))), `update ${n} keeps the harness hooks registered`);
      const recorded = readManifest(dir);
      assert.equal(recorded.files['.claude/settings.json'], installed, `update ${n} leaves the recorded digest at the installed state`);
      assert.notEqual(recorded.files['.claude/settings.json'], digestOf(settings), `update ${n} never records the user's file as installed`);
      assert.equal(recorded.hooks, 'shared');
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// What the re-application does to a kept shared settings.json, by design (the header of install-into.mjs): the harness's own
// hook groups (same matcher, same scripts) go back to the shipped form, a missing one is added again, the pack's permission
// rules are added when missing, and the user's own hook groups, rules and settings stay.
test('installer: --update re-applies the harness hook groups to a kept shared settings.json and leaves the user\'s own entries', (t) => {
  if (!harnessClone) return t.skip('runs only in a clone of the harness (LICENSE at the root)');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-install-'));
  try {
    spawnSync('git', ['-C', dir, 'init', '-q'], { encoding: 'utf8' });
    const first = run(dir, '--hardening', '--enable-hooks', '--shared');
    assert.equal(first.status, 0, first.stderr);
    const shipped = JSON.parse(fs.readFileSync(path.join(path.dirname(installer), '..', 'settings.hooks.json'), 'utf8'));
    const settings = path.join(dir, '.claude', 'settings.json');
    const installed = readManifest(dir).files['.claude/settings.json'];
    const edited = JSON.parse(fs.readFileSync(settings, 'utf8'));
    edited.hooks.PreToolUse[0].hooks[0].timeout = 45; // a harness hook the user tuned
    delete edited.hooks.UserPromptSubmit; // a harness hook group the user removed
    edited.hooks.PreToolUse.push({ matcher: 'Bash', hooks: [{ type: 'command', command: 'node my-own-hook.mjs' }] });
    edited.permissions.deny.push('Read(./team-notes/**)');
    fs.writeFileSync(settings, `${JSON.stringify(edited, null, 2)}\n`);
    const r = run(dir, '--update');
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /kept     : 1 file\(s\)[^\n]*:\n    \.claude\/settings\.json\n/);
    assert.match(r.stdout, /earlier registrations? of the same hooks replaced \(a file you changed: only the harness hook groups/, 'the output says what is re-applied to a kept file');
    const after = JSON.parse(fs.readFileSync(settings, 'utf8'));
    assert.deepEqual(after.hooks.PreToolUse[0], shipped.hooks.PreToolUse[0], 'a changed timeout of a harness hook is restored (by design)');
    assert.deepEqual(after.hooks.UserPromptSubmit, shipped.hooks.UserPromptSubmit, 'a removed harness hook group is added again (by design)');
    assert.ok(after.hooks.PreToolUse.some((g) => g.matcher === 'Bash' && g.hooks.some((h) => h.command === 'node my-own-hook.mjs')), 'the user\'s own hook group stays');
    assert.ok(after.permissions.deny.includes('Read(./team-notes/**)'), 'the user\'s deny rule stays');
    assert.equal(readManifest(dir).files['.claude/settings.json'], installed, 'the file is still not the installed state');
    // The next update has nothing left to re-apply: it writes nothing and lists the file as kept again.
    const text = fs.readFileSync(settings, 'utf8');
    const again = run(dir, '--update');
    assert.equal(again.status, 0, again.stderr);
    assert.match(again.stdout, /kept     : 1 file\(s\)[^\n]*:\n    \.claude\/settings\.json\n/);
    assert.match(again.stdout, /0 entries merged into \.claude\/settings\.json \(shared/);
    assert.equal(fs.readFileSync(settings, 'utf8'), text);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// A shared settings.json the user deleted is not the installed state either: the hook registration needs a file and
// re-creates it with the hooks only, but no later update may "restore" the shipped file over it. F2-44: a deleted file
// holds no harness hook, so a plain update leaves the hooks disabled (it used to re-create the file); --enable-hooks
// --shared registers them again.
test('installer: a shared settings.json the user deleted stays deleted on a plain update, is re-created for the hooks only by --enable-hooks --shared and stays kept', (t) => {
  if (!harnessClone) return t.skip('runs only in a clone of the harness (LICENSE at the root)');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-install-'));
  try {
    git(dir, 'init', '-q');
    const first = run(dir, '--hardening', '--enable-hooks', '--shared');
    assert.equal(first.status, 0, first.stderr);
    const settings = path.join(dir, '.claude', 'settings.json');
    const installed = readManifest(dir).files['.claude/settings.json'];
    fs.rmSync(settings);
    const one = run(dir, '--update');
    assert.equal(one.status, 0, one.stderr);
    assert.match(one.stdout, /skipped  : 1 file\(s\) you deleted \(not restored\):\n    \.claude\/settings\.json\n/);
    assert.match(one.stdout, /hooks    : the hooks stay disabled: \.claude\/settings\.json holds no harness hook registration[^\n]*; --update --enable-hooks --shared registers them again\n/);
    assert.ok(!fs.existsSync(settings), 'a plain update does not re-create it');
    assert.equal(readManifest(dir).hooks, 'shared', 'the recorded choice stays');
    const two = run(dir, '--update', '--enable-hooks', '--shared');
    assert.equal(two.status, 0, two.stderr);
    assert.match(two.stdout, /skipped  : 1 file\(s\) you deleted \(not restored\):\n    \.claude\/settings\.json\n/);
    const created = JSON.parse(fs.readFileSync(settings, 'utf8'));
    assert.ok(created.hooks.PreToolUse.length > 0, 'the registration got its file');
    assert.equal(created.agent, undefined, 'it is not the shipped settings.json');
    assert.equal(readManifest(dir).files['.claude/settings.json'], installed, 'the recorded digest is not moved to the new file');
    const text = fs.readFileSync(settings, 'utf8');
    const three = run(dir, '--update');
    assert.equal(three.status, 0, three.stderr);
    assert.match(three.stdout, /kept     : 1 file\(s\)[^\n]*:\n    \.claude\/settings\.json\n/);
    assert.equal(fs.readFileSync(settings, 'utf8'), text, 'the shipped file does not come back over it');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// F1-50: a rerun with --enable-hooks but without --hardening or --update on a target that has the pack used to register
// nothing, exit 0 and rewrite the manifest WITHOUT the hardening/ entries, so no later --update refreshed the pack. The pack
// is not part of that run, so it is refused, naming the command that works.
test('installer: --enable-hooks without --update on an installed pack is refused with the right command and the manifest keeps the pack', (t) => {
  if (!harnessClone) return t.skip('runs only in a clone of the harness (LICENSE at the root)');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-install-'));
  try {
    spawnSync('git', ['-C', dir, 'init', '-q'], { encoding: 'utf8' });
    const first = run(dir, '--hardening');
    assert.equal(first.status, 0, first.stderr);
    assert.match(first.stdout, /Next: run again with --update --enable-hooks \(this machine\) or --update --enable-hooks --shared \(committed/, 'the advice after an install names the command that works');
    const manifestFile = path.join(dir, '.claude', 'bi-agent-harness.json');
    const before = fs.readFileSync(manifestFile, 'utf8');
    const pack = packEntries(JSON.parse(before));
    assert.ok(Object.keys(pack).length > 10, 'the manifest lists the pack');
    for (const flags of [['--enable-hooks'], ['--enable-hooks', '--shared']]) {
      const r = run(dir, ...flags);
      assert.equal(r.status, 1, r.stdout);
      assert.match(r.stderr, new RegExp(`register its hooks with --update ${flags.join(' ')}\\. No files changed`));
      assert.equal(fs.readFileSync(manifestFile, 'utf8'), before, 'a refused run does not rewrite the manifest');
      assert.ok(!fs.existsSync(path.join(dir, '.claude', 'settings.local.json')), 'and registers nothing');
    }
    // The command it names registers the hooks of the installed pack and keeps the manifest whole.
    const done = run(dir, '--update', '--enable-hooks');
    assert.equal(done.status, 0, done.stderr);
    const local = JSON.parse(fs.readFileSync(path.join(dir, '.claude', 'settings.local.json'), 'utf8'));
    assert.ok(Array.isArray(local.hooks?.PreToolUse) && local.hooks.PreToolUse.length > 0, 'the hooks of the installed pack are registered');
    assert.equal(spawnSync('git', ['-C', dir, 'config', 'core.hooksPath'], { encoding: 'utf8' }).stdout.trim(), 'hardening/githooks');
    const after = readManifest(dir);
    assert.equal(after.hooks, 'local');
    // The entries, not their digests: --update refreshes a file the harness changed since the first run.
    assert.deepEqual(Object.keys(packEntries(after)), Object.keys(pack), 'the pack stays recorded, so later updates keep refreshing it');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// F1-50: the error for a settings file that is not valid JSON told the user to "run again with --enable-hooks", which exited
// 0 and registered nothing. The advice it prints now is the command that works; the test runs the advice it reads.
// F1-120: the check runs before the first write, so the command that works is the same command once the file is fixed.
test('installer: the "not valid JSON" error names the command that works, and running it registers the hooks', (t) => {
  if (!harnessClone) return t.skip('runs only in a clone of the harness (LICENSE at the root)');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-install-'));
  const shared = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-install-'));
  try {
    spawnSync('git', ['-C', dir, 'init', '-q'], { encoding: 'utf8' });
    fs.mkdirSync(path.join(dir, '.claude'), { recursive: true });
    const localFile = path.join(dir, '.claude', 'settings.local.json');
    fs.writeFileSync(localFile, '{ "permissions": { "allow": ["Bash(ls *)"], } }\n'); // a trailing comma
    const failed = run(dir, '--hardening', '--enable-hooks');
    assert.equal(failed.status, 1, failed.stdout);
    assert.match(failed.stderr, /settings\.local\.json is not valid JSON/);
    const advice = /run again with ((?:--[\w-]+ ?)+)\./.exec(failed.stderr);
    assert.ok(advice, failed.stderr);
    assert.equal(advice[1].trim(), '--hardening --enable-hooks');
    assert.ok(!fs.existsSync(path.join(dir, '.claude', 'bi-agent-harness.json')), 'no file was installed before the check');
    fs.writeFileSync(localFile, '{ "permissions": { "allow": ["Bash(ls *)"] } }\n');
    const fixed = run(dir, ...advice[1].trim().split(' '));
    assert.equal(fixed.status, 0, fixed.stderr);
    assert.match(fixed.stdout, /merged into \.claude\/settings\.local\.json/);
    const local = JSON.parse(fs.readFileSync(localFile, 'utf8'));
    assert.ok(local.hooks.PreToolUse.length > 0, 'the hooks are registered');
    assert.ok(local.permissions.allow.includes('Bash(ls *)'), 'the user\'s rule stays');
    const after = readManifest(dir);
    assert.equal(after.hooks, 'local');
    assert.ok(Object.keys(packEntries(after)).length > 10, 'the pack is recorded');
    // The shared form names --shared too.
    spawnSync('git', ['-C', shared, 'init', '-q'], { encoding: 'utf8' });
    fs.mkdirSync(path.join(shared, '.claude'), { recursive: true });
    fs.writeFileSync(path.join(shared, '.claude', 'settings.json'), '{ "permissions": { "allow": ["Bash(ls *)"], } }\n');
    const sharedFailed = run(shared, '--hardening', '--enable-hooks', '--shared', '--keep-existing');
    assert.equal(sharedFailed.status, 1, sharedFailed.stdout);
    assert.match(sharedFailed.stderr, /settings\.json is not valid JSON[^\n]*run again with --hardening --enable-hooks --shared --keep-existing\./);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
    fs.rmSync(shared, { recursive: true, force: true });
  }
});

test('installer: --enable-hooks or --shared without the pack in the run is refused before any file is written', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-install-'));
  try {
    for (const args of [['--enable-hooks'], ['--shared'], ['--update', '--enable-hooks'], ['--enable-hooks', '--shared', '--dry-run']]) {
      const r = run(dir, ...args);
      assert.equal(r.status, 1, `${args.join(' ')}: ${r.stdout}`);
      assert.match(r.stderr, /The hooks belong to the hardening pack[^\n]*add --hardening\. No files changed/);
      assert.deepEqual(fs.readdirSync(dir), [], `${args.join(' ')} wrote nothing`);
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// F1-50: an install that leaves the pack out (a rerun of the core) rewrote the manifest from the core files alone. The pack
// and the recorded hooks choice vanished from it: no later --update refreshed the pack, and one that refreshed a shared
// settings.json put back the shipped file without the hooks.
test('installer: a rerun without --hardening keeps the pack and the hooks recorded in the manifest', (t) => {
  if (!harnessClone) return t.skip('runs only in a clone of the harness (LICENSE at the root)');
  const local = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-install-'));
  const shared = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-install-'));
  try {
    spawnSync('git', ['-C', local, 'init', '-q'], { encoding: 'utf8' });
    assert.equal(run(local, '--hardening', '--enable-hooks').status, 0);
    const before = readManifest(local);
    assert.ok(Object.keys(packEntries(before)).length > 10);
    const rerun = run(local);
    assert.equal(rerun.status, 0, rerun.stderr);
    const after = readManifest(local);
    assert.deepEqual(packEntries(after), packEntries(before), 'the pack stays recorded');
    assert.equal(after.hooks, 'local', 'and so does the hooks choice');
    assert.deepEqual(Object.keys(after.files), Object.keys(before.files));

    // Shared: the merged settings.json is as the install left it (no conflict since F1-121); --keep-existing changes nothing.
    spawnSync('git', ['-C', shared, 'init', '-q'], { encoding: 'utf8' });
    assert.equal(run(shared, '--hardening', '--enable-hooks', '--shared').status, 0);
    const sharedBefore = readManifest(shared);
    const sharedRerun = run(shared, '--keep-existing');
    assert.equal(sharedRerun.status, 0, sharedRerun.stderr);
    const sharedAfter = readManifest(shared);
    assert.equal(sharedAfter.hooks, 'shared');
    assert.deepEqual(Object.keys(sharedAfter.files), Object.keys(sharedBefore.files));
    assert.equal(sharedAfter.files['.claude/settings.json'], sharedBefore.files['.claude/settings.json'], 'the kept merged file stays recorded as it was');
    // The update that follows refreshes settings.json and re-applies the hooks: they are still registered afterwards.
    const update = run(shared, '--update');
    assert.equal(update.status, 0, update.stderr);
    assert.match(update.stdout, /kept     : 0 file\(s\)/);
    assert.match(fs.readFileSync(path.join(shared, '.claude', 'settings.json'), 'utf8'), /hardening\/hooks\/pre-tool-use\.mjs/);
  } finally {
    fs.rmSync(local, { recursive: true, force: true });
    fs.rmSync(shared, { recursive: true, force: true });
  }
});

// 2026-10-08: the registration changed from the exec form (`command: node`, `args`) to the shell string Copilot CLI
// also runs; an update must replace the earlier registration of the same hooks, not add a second one.
test('installer: --enable-hooks replaces an earlier registration of the same hooks instead of adding a duplicate', (t) => {
  if (!harnessClone) return t.skip('runs only in a clone of the harness (LICENSE at the root)');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-install-'));
  try {
    spawnSync('git', ['-C', dir, 'init', '-q'], { encoding: 'utf8' });
    fs.mkdirSync(path.join(dir, '.claude'), { recursive: true });
    const old = (script) => ({ type: 'command', command: 'node', args: [`\${CLAUDE_PROJECT_DIR}/hardening/hooks/${script}`], timeout: 20 });
    fs.writeFileSync(path.join(dir, '.claude', 'settings.local.json'), `${JSON.stringify({
      permissions: { allow: ['Bash(git status *)'] },
      hooks: {
        // Two groups keep their matcher (replaced in place), two had their matcher changed since (the MCP matchers:
        // swept as exec-form leftovers), one is the user's own and stays.
        PreToolUse: [{ matcher: 'Bash|PowerShell|Monitor', hooks: [old('pre-tool-use.mjs')] }, { matcher: 'Read|Grep|Glob', hooks: [old('pre-tool-use.mjs')] },
          { matcher: 'mcp__.*', hooks: [old('pre-tool-use.mjs')] }, { matcher: 'Bash', hooks: [{ type: 'command', command: 'node my-own-hook.mjs' }] }],
        PostToolUse: [{ matcher: 'Read|Grep|Bash|PowerShell|WebFetch|mcp__.*', hooks: [old('post-tool-redact.mjs')] }],
        Stop: [{ hooks: [old('stop-gate.mjs')] }],
      },
    }, null, 2)}\n`);
    const r = spawnSync(process.execPath, [installer, dir, '--hardening', '--enable-hooks'], { encoding: 'utf8' });
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /5 earlier registrations of the same hooks replaced/);
    const local = JSON.parse(fs.readFileSync(path.join(dir, '.claude', 'settings.local.json'), 'utf8'));
    const shipped = JSON.parse(fs.readFileSync(path.join(path.dirname(installer), '..', 'settings.hooks.json'), 'utf8'));
    const pre = local.hooks.PreToolUse.filter((g) => g.matcher === 'Bash|PowerShell|Monitor');
    assert.equal(pre.length, 1, 'one registration per matcher');
    assert.deepEqual(pre[0], shipped.hooks.PreToolUse[0], 'the shipped shell string replaced the exec form');
    assert.equal(local.hooks.PreToolUse.filter((g) => g.matcher === 'Bash').length, 1, 'the user\'s own hook group stays');
    assert.equal(local.hooks.PreToolUse.filter((g) => g.matcher === 'mcp__.*|.*-mcp-.*').length, 1, 'the MCP guard group exists once, under the new matcher');
    assert.equal(local.hooks.PreToolUse.filter((g) => g.matcher === 'mcp__.*').length, 0, 'the old MCP matcher is gone');
    assert.equal(local.hooks.PostToolUse.filter((g) => /post-tool-redact/.test(JSON.stringify(g))).length, 1, 'the masking group exists once');
    assert.equal(local.hooks.Stop.length, 1);
    assert.ok(!/"args"/.test(JSON.stringify(local.hooks)), 'no exec-form entry remains anywhere');
    assert.deepEqual(local.hooks.PreToolUse.map((g) => g.matcher).sort(), [...shipped.hooks.PreToolUse.map((g) => g.matcher), 'Bash'].sort());
    assert.ok(local.permissions.allow.includes('Bash(git status *)'), 'the user\'s rules stay');
    const again = spawnSync(process.execPath, [installer, dir, '--update', '--enable-hooks'], { encoding: 'utf8' });
    assert.equal(again.status, 0, again.stderr);
    assert.match(again.stdout, /0 entries (?:would be )?merged into \.claude\/settings\.local\.json; core/);
    assert.equal(fs.readFileSync(path.join(dir, '.claude', 'settings.local.json'), 'utf8'), `${JSON.stringify(local, null, 2)}\n`, 'idempotent');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// A kept config never receives the keys a newer pack learns (desktop.screenshots, 2026-10): the update lists them with
// the default that applies, and the keys the pack does not know, and leaves the file as it is.
test('installer: --update lists the keys a kept harness.config.json lacks and the ones the pack does not know', (t) => {
  if (!harnessClone) return t.skip('runs only in a clone of the harness (LICENSE at the root)');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-install-'));
  try {
    const first = spawnSync(process.execPath, [installer, dir, '--hardening'], { encoding: 'utf8' });
    assert.equal(first.status, 0, first.stderr);
    const configFile = path.join(dir, 'hardening', 'harness.config.json');
    // The user's config: written before the pack knew `desktop` and `mcp`, without redaction.piiInAllTools and
    // sources.sqlRead, with a typo at the top level and in approvals, and with a subagent of their own. F1-117: the shipped
    // config has no sources.sqlRead (the default applies), so only redaction.piiInAllTools is missing at the second level.
    const user = structuredClone(DEFAULT_CONFIG);
    delete user.desktop;
    delete user.mcp;
    delete user.sources.sqlRead;
    delete user.redaction.piiInAllTools;
    user.aprovals = { mode: 'ask' };
    user.approvals.untill = null;
    user.agentScopes['my-reviewer'] = { readOnly: true };
    const text = `${JSON.stringify(user, null, 2)}\n`;
    fs.writeFileSync(configFile, text);
    for (const args of [['--update', '--dry-run'], ['--update']]) {
      const r = spawnSync(process.execPath, [installer, dir, ...args], { encoding: 'utf8' });
      assert.equal(r.status, 0, r.stderr);
      const out = r.stdout;
      assert.match(out, /kept     : 1 file\(s\)[^\n]*:\n    hardening\/harness\.config\.json\n    config: /, 'the config lines follow the kept line');
      assert.ok(out.includes(`config: missing mcp (default ${JSON.stringify(DEFAULT_CONFIG.mcp)})`), out);
      assert.ok(out.includes(`config: missing redaction.piiInAllTools (default ${JSON.stringify(DEFAULT_CONFIG.redaction.piiInAllTools)})`), out);
      assert.doesNotMatch(out, /config: missing (?:sources\.sqlRead|fabric|agentScopes|approvals\.until)/, 'a key only the defaults have is not missing');
      if (DEFAULT_CONFIG.desktop) assert.ok(out.includes(`config: missing desktop (default ${JSON.stringify(DEFAULT_CONFIG.desktop)})`), out);
      assert.ok(out.includes('config: unknown aprovals'), out);
      assert.ok(out.includes('config: unknown approvals.untill'), out);
      assert.doesNotMatch(out, /config: missing (?:markdown|approvals|sources\.referenceCopies|mcp\.)/, 'a present key, or the children of a missing one, are not listed');
      assert.doesNotMatch(out, /config: unknown agentScopes/, 'the user\'s own subagents are not unknown keys');
      assert.equal(fs.readFileSync(configFile, 'utf8'), text, 'no key is added for the user');
    }
    fs.writeFileSync(configFile, '{ "approvals": ');
    const broken = spawnSync(process.execPath, [installer, dir, '--update', '--dry-run'], { encoding: 'utf8' });
    assert.equal(broken.status, 0, broken.stderr);
    assert.match(broken.stdout, /config: not valid JSON/);
    fs.copyFileSync(path.join(path.dirname(installer), '..', 'harness.config.json'), configFile);
    const same = spawnSync(process.execPath, [installer, dir, '--update', '--dry-run'], { encoding: 'utf8' });
    assert.doesNotMatch(same.stdout, /config: /, 'an unchanged config is refreshed, not compared');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('installer: a CLAUDE.md next to AGENTS.md gets the @AGENTS.md import once; a CLAUDE.local.md alone gets a CLAUDE.md', (t) => {
  if (!harnessClone) return t.skip('runs only in a clone of the harness (LICENSE at the root)');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-install-'));
  try {
    fs.writeFileSync(path.join(dir, 'CLAUDE.md'), '# Notes\n\nAnswer in English.');
    const dry = spawnSync(process.execPath, [installer, dir, '--dry-run'], { encoding: 'utf8' });
    assert.equal(dry.status, 0, dry.stderr);
    assert.match(dry.stdout, /CLAUDE\.md: `@AGENTS\.md` import would be appended/);
    assert.equal(fs.readFileSync(path.join(dir, 'CLAUDE.md'), 'utf8'), '# Notes\n\nAnswer in English.', '--dry-run writes nothing');
    const first = spawnSync(process.execPath, [installer, dir], { encoding: 'utf8' });
    assert.equal(first.status, 0, first.stderr);
    assert.match(first.stdout, /CLAUDE\.md: `@AGENTS\.md` import appended/);
    const text = fs.readFileSync(path.join(dir, 'CLAUDE.md'), 'utf8');
    assert.match(text, /^# Notes\n\nAnswer in English\.\n/);
    assert.equal(text.match(/^@AGENTS\.md$/gm).length, 1);
    const again = spawnSync(process.execPath, [installer, dir, '--update'], { encoding: 'utf8' });
    assert.equal(again.status, 0, again.stderr);
    assert.doesNotMatch(again.stdout, /CLAUDE\.md:/);
    assert.equal(fs.readFileSync(path.join(dir, 'CLAUDE.md'), 'utf8').match(/^@AGENTS\.md$/gm).length, 1, 'idempotent');
    fs.writeFileSync(path.join(dir, 'CLAUDE.md'), '# Notes\n\n@./AGENTS.md\n');
    const spelled = spawnSync(process.execPath, [installer, dir, '--update'], { encoding: 'utf8' });
    assert.doesNotMatch(spelled.stdout, /CLAUDE\.md:/, 'another spelling of the import counts');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  const local = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-install-'));
  try {
    fs.writeFileSync(path.join(local, 'CLAUDE.local.md'), '# Mine\n');
    const r = spawnSync(process.execPath, [installer, local], { encoding: 'utf8' });
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /CLAUDE\.md: created with the `@AGENTS\.md` import/);
    assert.match(fs.readFileSync(path.join(local, 'CLAUDE.md'), 'utf8'), /^@AGENTS\.md$/m);
  } finally {
    fs.rmSync(local, { recursive: true, force: true });
  }
});

test('installer: a source nested in another repository does not inherit that repository\'s ignore rules', (t) => {
  if (!harnessClone) return t.skip('runs only in a clone of the harness (LICENSE at the root)');
  const outer = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-outer-'));
  try {
    // An outer repository that ignores the folder the harness copy sits in.
    spawnSync('git', ['-C', outer, 'init', '-q'], { encoding: 'utf8' });
    fs.writeFileSync(path.join(outer, '.gitignore'), 'release/\n');
    const nested = path.join(outer, 'release', 'harness');
    const source = path.resolve(path.dirname(installer), '..', '..');
    for (const rel of ['AGENTS.md', 'TASKS.md', '.mcp.example.json', '.gitattributes', 'THIRD_PARTY_NOTICES.md', '.gitignore', 'LICENSE', 'NOTICE', '.claude/settings.json', '.vscode/extensions.json', 'hardening/scripts/install-into.mjs', 'hardening/settings.hooks.json']) {
      fs.mkdirSync(path.dirname(path.join(nested, rel)), { recursive: true });
      fs.copyFileSync(path.join(source, rel), path.join(nested, rel));
    }
    fs.mkdirSync(path.join(nested, 'docs'), { recursive: true });
    fs.writeFileSync(path.join(nested, 'docs', 'a.md'), '# a\n');
    fs.mkdirSync(path.join(nested, 'templates'), { recursive: true });
    fs.writeFileSync(path.join(nested, 'templates', 'README.md'), '# t\n');
    const target = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-install-'));
    try {
      const r = spawnSync(process.execPath, [path.join(nested, 'hardening', 'scripts', 'install-into.mjs'), target, '--dry-run'], { encoding: 'utf8' });
      assert.equal(r.status, 0, r.stderr);
      const added = Number(/added\s*:\s*(\d+)/.exec(r.stdout)?.[1]);
      assert.ok(added >= 10, `every source file is planned, not dropped as ignored: ${r.stdout}`);
    } finally {
      fs.rmSync(target, { recursive: true, force: true });
    }
  } finally {
    fs.rmSync(outer, { recursive: true, force: true });
  }
});

/** Writes a file (and its folders) and returns its path. */
const put = (file, text) => {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, text);
  return file;
};
/** Adds keys to the manifest of a target, each with the digest the installer would record for the file given. */
const addManifestKeys = (dir, keys) => {
  const file = path.join(dir, '.claude', 'bi-agent-harness.json');
  const m = JSON.parse(fs.readFileSync(file, 'utf8'));
  for (const [key, source] of Object.entries(keys)) m.files[key] = digestOf(source);
  fs.writeFileSync(file, `${JSON.stringify(m, null, 2)}\n`);
};

// F2-3: the manifest is committed text that a teammate or a PR can change. An update removed every key whose digest
// matched, wherever it pointed: a file outside the repository, a project file the harness never shipped, Git's own
// files, the local hook registration, and (on a case-insensitive file system) a shipped hook through a key in other case.
// A key now reaches the file system only when it is a plain relative path under what the harness installs.
test('installer: --update never removes a manifest key outside what the harness installs and lists it as refused', (t) => {
  if (!harnessClone) return t.skip('runs only in a clone of the harness (LICENSE at the root)');
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-install-'));
  const dir = path.join(parent, 'repo');
  try {
    fs.mkdirSync(dir);
    spawnSync('git', ['-C', dir, 'init', '-q'], { encoding: 'utf8' });
    const first = run(dir, '--hardening', '--enable-hooks');
    assert.equal(first.status, 0, first.stderr);
    const refused = {
      '../victim.txt': put(path.join(parent, 'victim.txt'), 'outside file\n'),
      '..\\victim-bs.txt': put(path.join(parent, 'victim-bs.txt'), 'outside file, backslash key\n'),
      'docs/../../victim-dots.txt': put(path.join(parent, 'victim-dots.txt'), 'outside file, dot segments\n'),
      [path.join(parent, 'abs-victim.txt').replace(/\\/g, '/')]: put(path.join(parent, 'abs-victim.txt'), 'outside file, absolute key\n'),
      '.git/config': path.join(dir, '.git', 'config'),
      'powerbi/Sales.SemanticModel/definition/tables/Sales.tmdl': put(path.join(dir, 'powerbi', 'Sales.SemanticModel', 'definition', 'tables', 'Sales.tmdl'), 'table Sales\n\tmeasure Total = 1\n'),
      '.claude/settings.local.json': path.join(dir, '.claude', 'settings.local.json'),
      '.claude/logs/tool-audit.jsonl': put(path.join(dir, '.claude', 'logs', 'tool-audit.jsonl'), '{"tool":"Read"}\n'),
    };
    // A folder link inside docs/ that leads outside the repository (a junction on Windows needs no privilege).
    const outside = path.join(parent, 'outside');
    const linkVictim = put(path.join(outside, 'victim-link.txt'), 'outside file, behind a link\n');
    try {
      fs.symlinkSync(outside, path.join(dir, 'docs', 'linked'), 'junction');
      refused['docs/linked/victim-link.txt'] = linkVictim;
    } catch { /* no link support here: the other keys still run */ }
    // A key in other case than a shipped file is that file on Windows and macOS: never removed through it.
    const hook = path.join(dir, 'hardening', 'hooks', 'pre-tool-use.mjs');
    const alias = { 'hardening/hooks/PRE-TOOL-USE.MJS': hook };
    // A file the harness shipped once and dropped since is still removed.
    const dropped = { '.claude/skills/old-skill/SKILL.md': put(path.join(dir, '.claude', 'skills', 'old-skill', 'SKILL.md'), '# old\n') };
    addManifestKeys(dir, { ...refused, ...alias, ...dropped });
    const contents = Object.fromEntries(Object.values({ ...refused, ...alias }).map((f) => [f, fs.readFileSync(f)]));

    for (const args of [['--update', '--dry-run'], ['--update']]) {
      const r = run(dir, ...args);
      assert.equal(r.status, 0, r.stderr);
      const removed = /removed  : (\d+) file\(s\)[^\n]*((?:\n    [^\n]*)*)/.exec(r.stdout);
      assert.ok(removed, r.stdout);
      assert.equal(removed[1], '1', `only the dropped harness file is removed: ${r.stdout}`);
      assert.equal(removed[2].trim(), '.claude/skills/old-skill/SKILL.md');
      const list = new RegExp(`refused  : ${Object.keys(refused).length} manifest key\\(s\\) outside what the harness installs \\(not removed[^\\n]*((?:\\n    [^\\n]*)*)`).exec(r.stdout);
      assert.ok(list, `the refusal is visible: ${r.stdout}`);
      assert.deepEqual(list[1].split('\n').map((l) => l.trim()).filter(Boolean).sort(), Object.keys(refused).sort());
      for (const [file, data] of Object.entries(contents)) assert.ok(fs.existsSync(file) && fs.readFileSync(file).equals(data), `${args.join(' ')} leaves ${file}`);
    }
    assert.ok(!fs.existsSync(path.join(dir, '.claude', 'skills', 'old-skill')), 'the dropped file and its emptied folder are gone');
    const after = readManifest(dir);
    for (const key of [...Object.keys(refused), ...Object.keys(alias), ...Object.keys(dropped)]) assert.ok(!Object.hasOwn(after.files, key), `${key} is dropped from the manifest`);
    assert.ok(after.files['hardening/hooks/pre-tool-use.mjs'], 'the shipped hook stays recorded');
    // The next update has nothing to refuse.
    const again = run(dir, '--update');
    assert.equal(again.status, 0, again.stderr);
    assert.doesNotMatch(again.stdout, /refused  :/);
  } finally {
    fs.rmSync(parent, { recursive: true, force: true });
  }
});

// F2-13: a teammate's `--update --enable-hooks` (the per-machine step) on a `--shared` install refreshed the committed
// .claude/settings.json to the bare harness file, merged the hooks into settings.local.json and flipped the manifest to
// "local": the next commit removed the hooks and the pack rules from every clone. The team registration is now kept.
test('installer: --enable-hooks without --shared on a shared install keeps the team registration in .claude/settings.json', (t) => {
  if (!harnessClone) return t.skip('runs only in a clone of the harness (LICENSE at the root)');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-install-'));
  try {
    spawnSync('git', ['-C', dir, 'init', '-q'], { encoding: 'utf8' });
    const first = run(dir, '--hardening', '--enable-hooks', '--shared');
    assert.equal(first.status, 0, first.stderr);
    const settings = path.join(dir, '.claude', 'settings.json');
    const manifestFile = path.join(dir, '.claude', 'bi-agent-harness.json');
    const text = fs.readFileSync(settings, 'utf8');
    const manifestText = fs.readFileSync(manifestFile, 'utf8');
    for (const args of [['--update', '--enable-hooks'], ['--hardening', '--enable-hooks', '--keep-existing'], ['--update']]) {
      const r = run(dir, ...args);
      assert.equal(r.status, 0, `${args.join(' ')}: ${r.stderr}`);
      if (args.includes('--enable-hooks')) {
        assert.match(r.stdout, /hooks    : the team registration in \.claude\/settings\.json is kept \(the manifest records "shared"\)[^\n]*remove them from \.claude\/settings\.json and "hooks" from \.claude\/bi-agent-harness\.json by hand/, `${args.join(' ')} says the registration stays shared`);
      }
      assert.match(r.stdout, /merged into \.claude\/settings\.json \(shared/, `${args.join(' ')} re-applies the shared registration`);
      const after = JSON.parse(fs.readFileSync(settings, 'utf8'));
      assert.ok(Array.isArray(after.hooks?.PreToolUse) && after.hooks.PreToolUse.length > 0, `${args.join(' ')}: the team hooks stay in settings.json`);
      assert.ok(after.permissions.allow.includes('Bash(node hardening/scripts/validate.mjs *)'), `${args.join(' ')}: the pack rules stay`);
      assert.equal(fs.readFileSync(settings, 'utf8'), text, `${args.join(' ')}: settings.json is unchanged`);
      assert.equal(fs.readFileSync(manifestFile, 'utf8'), manifestText, `${args.join(' ')}: the manifest stays "shared" and unchanged`);
      assert.ok(!fs.existsSync(path.join(dir, '.claude', 'settings.local.json')), `${args.join(' ')}: nothing goes to settings.local.json`);
    }
    // A shared settings.json is never refreshed by a run that does not merge the hooks back: here the manifest records
    // "shared" but no longer lists the pack, so no hooks are merged, and the file is kept instead of reset to the bare one.
    const m = JSON.parse(manifestText);
    for (const rel of Object.keys(m.files)) if (rel.startsWith('hardening/')) delete m.files[rel];
    fs.writeFileSync(manifestFile, `${JSON.stringify(m, null, 2)}\n`);
    const bare = run(dir, '--update');
    assert.equal(bare.status, 0, bare.stderr);
    assert.match(bare.stdout, /kept     : 1 file\(s\)[^\n]*:\n    \.claude\/settings\.json\n/);
    assert.equal(fs.readFileSync(settings, 'utf8'), text, 'the team hooks are not refreshed away');
    assert.equal(readManifest(dir).hooks, 'shared');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// F1-51: --keep-existing, the documented route for a target with its own .claude/settings.json, kept the file without
// the harness's permission rules (the deny rules for secret reads among them) or its agent. They are now merged: a union
// that keeps the user's rules first and in order, and the agent only where the file names none.
test('installer: --keep-existing merges the harness permission rules and agent into a kept .claude/settings.json', (t) => {
  if (!harnessClone) return t.skip('runs only in a clone of the harness (LICENSE at the root)');
  const shipped = JSON.parse(fs.readFileSync(path.join(path.dirname(installer), '..', '..', '.claude', 'settings.json'), 'utf8'));
  const dirs = [];
  const target = (settings) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-install-'));
    dirs.push(dir);
    spawnSync('git', ['-C', dir, 'init', '-q'], { encoding: 'utf8' });
    put(path.join(dir, '.claude', 'settings.json'), settings);
    return dir;
  };
  const read = (dir) => JSON.parse(fs.readFileSync(path.join(dir, '.claude', 'settings.json'), 'utf8'));
  const assertUnion = (s, label) => {
    for (const kind of ['allow', 'ask', 'deny']) {
      for (const rule of shipped.permissions[kind]) assert.ok(s.permissions[kind].includes(rule), `${label}: ${kind} has ${rule}`);
      assert.equal(new Set(s.permissions[kind]).size, s.permissions[kind].length, `${label}: no ${kind} rule twice`);
    }
  };
  try {
    const own = '{ "permissions": { "allow": ["Bash(my-team-tool *)"] } }\n';
    const dir = target(own);
    const plain = run(dir);
    assert.equal(plain.status, 1, 'a plain install still stops on the differing file');
    assert.match(plain.stderr, /Integration conflicts[^\n]*\n  \.claude\/settings\.json/);
    const dry = run(dir, '--keep-existing', '--dry-run');
    assert.equal(dry.status, 0, dry.stderr);
    assert.match(dry.stdout, /merged   : \.claude\/settings\.json \(\d+ permission rules would be added, agent would be set to "bi-expert"\)/);
    assert.equal(fs.readFileSync(path.join(dir, '.claude', 'settings.json'), 'utf8'), own, '--dry-run writes nothing');
    const r = run(dir, '--keep-existing');
    assert.equal(r.status, 0, r.stderr);
    const total = ['allow', 'ask', 'deny'].reduce((n, k) => n + shipped.permissions[k].length, 0);
    assert.match(r.stdout, new RegExp(`merged   : \\.claude/settings\\.json \\(${total} permission rules added, agent set to "bi-expert"\\)`));
    const s = read(dir);
    assert.equal(s.permissions.allow[0], 'Bash(my-team-tool *)', 'the user\'s rule stays first');
    assert.ok(s.permissions.deny.includes('Read(.env)'), 'the secret-read deny rule is in');
    assert.equal(s.agent, 'bi-expert');
    assertUnion(s, 'first run');
    assert.ok(!Object.hasOwn(readManifest(dir).files, '.claude/settings.json'), 'the kept file is not recorded as the installed state');
    // A second run adds nothing twice and does not rewrite the file; an update keeps it as the user's.
    const text = fs.readFileSync(path.join(dir, '.claude', 'settings.json'), 'utf8');
    const second = run(dir, '--keep-existing');
    assert.equal(second.status, 0, second.stderr);
    assert.match(second.stdout, /merged   : \.claude\/settings\.json \(0 permission rules added, agent kept\)/);
    assert.equal(fs.readFileSync(path.join(dir, '.claude', 'settings.json'), 'utf8'), text);
    const update = run(dir, '--update');
    assert.equal(update.status, 0, update.stderr);
    assert.match(update.stdout, /kept     : 1 file\(s\)[^\n]*:\n    \.claude\/settings\.json\n/);
    assert.equal(fs.readFileSync(path.join(dir, '.claude', 'settings.json'), 'utf8'), text, 'the update does not overwrite it');

    // The user's agent is never replaced.
    const mine = target('{ "agent": "mine", "permissions": { "deny": ["Read(./team-notes/**)"] } }\n');
    const kept = run(mine, '--keep-existing');
    assert.equal(kept.status, 0, kept.stderr);
    assert.match(kept.stdout, /merged   : \.claude\/settings\.json \(\d+ permission rules added, agent kept\)/);
    const k = read(mine);
    assert.equal(k.agent, 'mine');
    assert.equal(k.permissions.deny[0], 'Read(./team-notes/**)');
    assertUnion(k, 'own agent');

    // The pack variant: the core rules and the shared hooks both reach the kept file.
    const pack = target(own);
    const p = run(pack, '--hardening', '--enable-hooks', '--shared', '--keep-existing');
    assert.equal(p.status, 0, p.stderr);
    const ps = read(pack);
    assert.equal(ps.permissions.allow[0], 'Bash(my-team-tool *)');
    assert.ok(ps.permissions.deny.includes('Read(.env)'));
    assert.ok(ps.permissions.allow.includes('Bash(node hardening/scripts/validate.mjs *)'), 'the pack rules too');
    assert.ok(ps.hooks.PreToolUse.length > 0, 'and the hooks');
    assert.equal(ps.agent, 'bi-expert');
    assertUnion(ps, 'pack');
    assert.ok(!Object.hasOwn(readManifest(pack).files, '.claude/settings.json'));

    // A kept file that is not valid JSON is left as it is, and the output says so.
    const bad = '{ "permissions": { "allow": ["Bash(ls *)"], } }\n';
    const broken = target(bad);
    const b = run(broken, '--keep-existing');
    assert.equal(b.status, 0, b.stderr);
    assert.match(b.stdout, /merged   : \.claude\/settings\.json left as it is \(not valid JSON/);
    assert.equal(fs.readFileSync(path.join(broken, '.claude', 'settings.json'), 'utf8'), bad);
  } finally {
    for (const dir of dirs) fs.rmSync(dir, { recursive: true, force: true });
  }
});

// F1-89: the Copilot hook registrations were not in the manifest. An update never refreshed a copy the user had not
// touched ("kept (differs ...: merge by hand)"), and deleting the files the manifest lists left both behind, registering
// hook scripts that no longer exist. They are recorded and refreshed like the harness files now.
test('installer: the Copilot hook files are recorded in the manifest, refreshed when unchanged and kept when changed', (t) => {
  if (!harnessClone) return t.skip('runs only in a clone of the harness (LICENSE at the root)');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-install-'));
  try {
    spawnSync('git', ['-C', dir, 'init', '-q'], { encoding: 'utf8' });
    assert.equal(run(dir, '--hardening', '--enable-hooks').status, 0);
    const pack = path.join(path.dirname(installer), '..');
    const pairs = [['.github/hooks/bi-harness.json', 'vscode.hooks.json'], ['.github/hooks/bi-harness.copilot-cli.json', 'copilot-cli.hooks.json']];
    for (const [rel, src] of pairs) assert.equal(readManifest(dir).files[rel], digestOf(path.join(pack, src)), `${rel} is recorded as installed`);
    // An install from an older pack: the file as that pack wrote it, recorded with its digest.
    const vscode = path.join(dir, '.github', 'hooks', 'bi-harness.json');
    const shipped = fs.readFileSync(path.join(pack, 'vscode.hooks.json'), 'utf8');
    fs.writeFileSync(vscode, shipped.replace(/"timeout": 20/, '"timeout": 25'));
    assert.notEqual(fs.readFileSync(vscode, 'utf8'), shipped);
    addManifestKeys(dir, { '.github/hooks/bi-harness.json': vscode });
    const r = run(dir, '--update');
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /hooks \(VS Code Copilot\): \.github\/hooks\/bi-harness\.json updated/);
    assert.match(r.stdout, /removed  : 0 file\(s\)/, 'an update never takes them for files the harness dropped');
    assert.equal(fs.readFileSync(vscode, 'utf8'), shipped, 'the newer registration reaches an untouched copy');
    assert.equal(readManifest(dir).files['.github/hooks/bi-harness.json'], digestOf(path.join(pack, 'vscode.hooks.json')));
    // A copy the user changed is kept and keeps its recorded digest.
    fs.writeFileSync(vscode, '{ "hooks": {} }\n');
    const kept = run(dir, '--update');
    assert.match(kept.stdout, /bi-harness\.json kept \(differs/);
    assert.equal(fs.readFileSync(vscode, 'utf8'), '{ "hooks": {} }\n');
    assert.equal(readManifest(dir).files['.github/hooks/bi-harness.json'], digestOf(path.join(pack, 'vscode.hooks.json')));
    // The documented removal (delete the files the manifest lists) takes both registrations with it.
    for (const rel of Object.keys(readManifest(dir).files)) fs.rmSync(path.join(dir, rel), { force: true });
    for (const [rel] of pairs) assert.ok(!fs.existsSync(path.join(dir, rel)), `${rel} is removed with the rest`);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// F1-113: the plan's buckets and the preflight had no test. Integration conflicts (and the dry-run exit), --keep-existing.
test('installer: a differing integration file stops the install (exit 1, 0 with --dry-run) until --keep-existing keeps it', (t) => {
  if (!harnessClone) return t.skip('runs only in a clone of the harness (LICENSE at the root)');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-install-'));
  try {
    const own = '# my own agreement\n';
    put(path.join(dir, 'AGENTS.md'), own);
    for (const [args, status] of [[['--dry-run'], 0], [[], 1]]) {
      const r = run(dir, ...args);
      assert.equal(r.status, status, `${args.join(' ') || 'install'}: ${r.stderr}`);
      assert.match(r.stderr, /Integration conflicts \(no files changed\):\n  AGENTS\.md\n/);
      assert.match(r.stderr, /--keep-existing/);
      assert.deepEqual(fs.readdirSync(dir), ['AGENTS.md'], 'nothing else is written');
    }
    const kept = run(dir, '--keep-existing');
    assert.equal(kept.status, 0, kept.stderr);
    assert.match(kept.stdout, /skipped  : 1 existing file\(s\) - merge by hand:\n    AGENTS\.md\n/);
    assert.equal(fs.readFileSync(path.join(dir, 'AGENTS.md'), 'utf8'), own, 'the reviewed file is kept');
    assert.ok(fs.existsSync(path.join(dir, 'TASKS.md')), 'the rest is installed');
    assert.ok(!Object.hasOwn(readManifest(dir).files, 'AGENTS.md'), 'the kept file is not recorded as installed');
    const update = run(dir, '--update');
    assert.match(update.stdout, /kept     : 1 file\(s\)[^\n]*:\n    AGENTS\.md\n/);
    assert.equal(fs.readFileSync(path.join(dir, 'AGENTS.md'), 'utf8'), own);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// F1-113: what an update does with files you deleted, files the harness dropped (unchanged or changed), CRLF copies and a
// corrupt manifest.
test('installer: --update skips deleted files, removes or keeps dropped ones, reads CRLF as unchanged and stops on a corrupt manifest', (t) => {
  if (!harnessClone) return t.skip('runs only in a clone of the harness (LICENSE at the root)');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-install-'));
  try {
    assert.equal(run(dir).status, 0);
    const deleted = path.join(dir, 'docs', 'static-checks.md');
    fs.rmSync(deleted);
    const dropped = put(path.join(dir, '.claude', 'skills', 'old-a', 'SKILL.md'), '# dropped, unchanged\n');
    const changed = put(path.join(dir, '.claude', 'skills', 'old-b', 'SKILL.md'), '# dropped, as installed\n');
    addManifestKeys(dir, { '.claude/skills/old-a/SKILL.md': dropped, '.claude/skills/old-b/SKILL.md': changed });
    fs.writeFileSync(changed, '# dropped, then changed by you\n');
    const agents = path.join(dir, 'AGENTS.md');
    const crlf = fs.readFileSync(agents, 'utf8').replace(/\r?\n/g, '\r\n');
    fs.writeFileSync(agents, crlf); // a Windows checkout with autocrlf
    const r = run(dir, '--update');
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /removed  : 1 file\(s\)[^\n]*:\n    \.claude\/skills\/old-a\/SKILL\.md\n/);
    assert.match(r.stdout, /kept     : 1 file\(s\) the harness dropped but you changed:\n    \.claude\/skills\/old-b\/SKILL\.md\n/);
    assert.match(r.stdout, /skipped  : 1 file\(s\) you deleted \(not restored\):\n    docs\/static-checks\.md\n/);
    assert.match(r.stdout, /kept     : 0 file\(s\) you changed/, 'a CRLF copy is not a change');
    assert.ok(!fs.existsSync(dropped) && fs.existsSync(changed) && !fs.existsSync(deleted));
    assert.equal(fs.readFileSync(agents, 'utf8'), crlf, 'and is not rewritten');
    const m = readManifest(dir);
    assert.ok(m.files['docs/static-checks.md'], 'a deleted file stays recorded, so it is never restored');
    assert.ok(!m.files['.claude/skills/old-a/SKILL.md'] && !m.files['.claude/skills/old-b/SKILL.md']);
    const again = run(dir, '--keep-existing');
    assert.equal(again.status, 0, again.stderr);
    assert.doesNotMatch(again.stdout, /merge by hand/, 'an install rerun sees no conflict in a CRLF copy');
    // A corrupt manifest stops the run before anything changes.
    const manifestFile = path.join(dir, '.claude', 'bi-agent-harness.json');
    fs.writeFileSync(manifestFile, '{ "files": ');
    const corrupt = run(dir, '--update');
    assert.equal(corrupt.status, 1);
    assert.match(corrupt.stderr, /bi-agent-harness\.json is not valid JSON[^\n]*No files changed/);
    assert.equal(fs.readFileSync(manifestFile, 'utf8'), '{ "files": ');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// F1-113: the destination preflight. A file where the harness needs a folder stops the install before anything is written.
test('installer: a file where the harness installs a folder stops the install with no change', (t) => {
  if (!harnessClone) return t.skip('runs only in a clone of the harness (LICENSE at the root)');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-install-'));
  try {
    put(path.join(dir, '.claude', 'agents'), 'not a folder\n');
    const r = run(dir, '--hardening');
    assert.equal(r.status, 1, r.stdout);
    assert.match(r.stderr, /Unsafe installation paths \(no files changed\):[^]*\.claude[\\/]agents: symlink or incompatible file\/directory type/);
    assert.deepEqual(fs.readdirSync(dir), ['.claude']);
    assert.deepEqual(fs.readdirSync(path.join(dir, '.claude')), ['agents']);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// F1-117: a kept harness.config.json was compared with DEFAULT_CONFIG, so changing one value listed five "missing" keys
// the shipped file never had. Only the keys of the shipped file count as missing; the defaults cover the others.
test('installer: --update lists no missing config key when the kept config differs from the shipped one in a value only', (t) => {
  if (!harnessClone) return t.skip('runs only in a clone of the harness (LICENSE at the root)');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-install-'));
  try {
    assert.equal(run(dir, '--hardening').status, 0);
    const configFile = path.join(dir, 'hardening', 'harness.config.json');
    const text = fs.readFileSync(configFile, 'utf8');
    assert.match(text, /"mode": "auto"/);
    fs.writeFileSync(configFile, text.replace('"mode": "auto"', '"mode": "ask"'));
    const r = run(dir, '--update');
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /kept     : 1 file\(s\)[^\n]*:\n    hardening\/harness\.config\.json\n/);
    assert.doesNotMatch(r.stdout, /config: /, 'nothing to merge: the shipped file has no key the kept one lacks');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// F1-118: a target that ignores .claude/ or .vscode/ silently left the manifest, the shared hook registration and
// .vscode/extensions.json out of every commit while the output said "commit it". The installer names them now; it does
// not change your rules.
test('installer: files the target\'s .gitignore excludes are named, and the .gitignore keeps the user\'s lines', (t) => {
  if (!harnessClone) return t.skip('runs only in a clone of the harness (LICENSE at the root)');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-install-'));
  const clean = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-install-'));
  try {
    spawnSync('git', ['-C', dir, 'init', '-q'], { encoding: 'utf8' });
    const rules = '.claude/\n.vscode/\n';
    put(path.join(dir, '.gitignore'), rules);
    for (const args of [['--dry-run'], []]) {
      const r = run(dir, '--hardening', '--enable-hooks', '--shared', ...args);
      assert.equal(r.status, 0, r.stderr);
      const block = /ignored  : (\d+) file\(s\) the harness installs match your \.gitignore[^\n]*((?:\n    [^\n]*)*)/.exec(r.stdout);
      assert.ok(block, `the ignored files are named: ${r.stdout}`);
      assert.ok(Number(block[1]) > 50, block[1]);
      for (const rel of ['.claude/bi-agent-harness.json', '.claude/settings.json', '.vscode/extensions.json']) assert.ok(block[2].includes(`\n    ${rel}`), `${rel} is listed: ${block[2]}`);
    }
    assert.ok(fs.readFileSync(path.join(dir, '.gitignore'), 'utf8').startsWith(rules), 'the user\'s rules stay as they were');
    // Without such rules, no line.
    spawnSync('git', ['-C', clean, 'init', '-q'], { encoding: 'utf8' });
    const r = run(clean, '--hardening', '--enable-hooks', '--shared');
    assert.equal(r.status, 0, r.stderr);
    assert.doesNotMatch(r.stdout, /ignored  :/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
    fs.rmSync(clean, { recursive: true, force: true });
  }
});

// F1-121: a second run of the README's install command on an untouched --shared install stopped on its own merged
// settings.json as an integration conflict. A file still as an earlier install left it is no conflict: it is not
// overwritten, and --update refreshes it.
test('installer: a second --shared install of an untouched target succeeds and changes nothing', (t) => {
  if (!harnessClone) return t.skip('runs only in a clone of the harness (LICENSE at the root)');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-install-'));
  try {
    spawnSync('git', ['-C', dir, 'init', '-q'], { encoding: 'utf8' });
    assert.equal(run(dir, '--hardening', '--enable-hooks', '--shared').status, 0);
    const settings = path.join(dir, '.claude', 'settings.json');
    const manifestFile = path.join(dir, '.claude', 'bi-agent-harness.json');
    const text = fs.readFileSync(settings, 'utf8');
    const manifestText = fs.readFileSync(manifestFile, 'utf8');
    const r = run(dir, '--hardening', '--enable-hooks', '--shared');
    assert.equal(r.status, 0, r.stderr);
    assert.doesNotMatch(r.stderr, /Integration conflicts/);
    assert.match(r.stdout, /installed: 1 file\(s\) as an earlier install left them \(not overwritten; --update refreshes them\):\n    \.claude\/settings\.json\n/);
    assert.doesNotMatch(r.stdout, /merge by hand|a file you changed/);
    assert.equal(fs.readFileSync(settings, 'utf8'), text);
    assert.equal(fs.readFileSync(manifestFile, 'utf8'), manifestText);
    // A settings.json the user changed is still a conflict.
    fs.writeFileSync(settings, text.replace('"agent": "bi-expert"', '"agent": "mine"'));
    const changed = run(dir, '--hardening', '--enable-hooks', '--shared');
    assert.equal(changed.status, 1);
    assert.match(changed.stderr, /Integration conflicts \(no files changed\):\n  \.claude\/settings\.json\n/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// F1-120: a settings file that is not valid JSON was found after every harness file was written, leaving a half install
// (no hooks, no core.hooksPath, no .github/hooks). It is read before the first write now.
test('installer: a settings file that is not valid JSON stops the hooks run before any file is written', (t) => {
  if (!harnessClone) return t.skip('runs only in a clone of the harness (LICENSE at the root)');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-install-'));
  const shared = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-install-'));
  try {
    spawnSync('git', ['-C', dir, 'init', '-q'], { encoding: 'utf8' });
    const bad = '{ "permissions": { "allow": ["Bash(ls *)"], } }\n';
    put(path.join(dir, '.claude', 'settings.local.json'), bad);
    for (const args of [['--hardening', '--enable-hooks', '--dry-run'], ['--hardening', '--enable-hooks']]) {
      const r = run(dir, ...args);
      assert.equal(r.status, 1, r.stdout);
      assert.match(r.stderr, new RegExp(`\\.claude/settings\\.local\\.json is not valid JSON[^\\n]*run again with ${args.join(' ')}\\. No files changed\\.`));
      assert.deepEqual(fs.readdirSync(dir).sort(), ['.claude', '.git']);
      assert.deepEqual(fs.readdirSync(path.join(dir, '.claude')), ['settings.local.json']);
      assert.equal(spawnSync('git', ['-C', dir, 'config', 'core.hooksPath'], { encoding: 'utf8' }).status, 1, 'core.hooksPath is not set');
    }
    // A kept shared settings.json that is not valid JSON gives one piece of advice, not two.
    put(path.join(shared, '.claude', 'settings.json'), bad);
    const r = run(shared, '--hardening', '--enable-hooks', '--shared', '--keep-existing');
    assert.equal(r.status, 1, r.stdout);
    assert.match(r.stderr, /\.claude\/settings\.json is not valid JSON[^\n]*run again with --hardening --enable-hooks --shared --keep-existing\. No files changed\./);
    assert.doesNotMatch(r.stdout, /merged   :/);
    assert.deepEqual(fs.readdirSync(shared), ['.claude']);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
    fs.rmSync(shared, { recursive: true, force: true });
  }
});

/** Every file of a folder outside .git, with its digest: what "no file changed" compares. */
const snapshot = (dir) => {
  const out = {};
  const walk = (rel) => {
    for (const entry of fs.readdirSync(path.join(dir, rel), { withFileTypes: true })) {
      const child = rel ? `${rel}/${entry.name}` : entry.name;
      if (child === '.git') continue;
      if (entry.isDirectory()) walk(child);
      else out[child] = digestOf(path.join(dir, child));
    }
  };
  walk('');
  return out;
};
/** Changes the manifest of a target in place. */
const editManifest = (dir, change) => {
  const file = path.join(dir, '.claude', 'bi-agent-harness.json');
  const m = JSON.parse(fs.readFileSync(file, 'utf8'));
  change(m);
  fs.writeFileSync(file, `${JSON.stringify(m, null, 2)}\n`);
};
const readJson = (file) => JSON.parse(fs.readFileSync(file, 'utf8'));
/** The rule lists as the manifest records them: per kind, sorted and distinct, empty kinds left out. */
const sortedRules = (permissions) => Object.fromEntries(['allow', 'ask', 'deny'].map((k) => [k, [...new Set(permissions?.[k] ?? [])].sort()]).filter(([, r]) => r.length));
const lf = (file) => fs.readFileSync(file, 'utf8').replace(/\r\n/g, '\n');

// F2-43: the permission merge only added rules, so a rule the harness dropped from settings.hooks.json (a pre-approval a
// fix narrows) stayed in every installed registration. The manifest records the rules the registration merged; a later
// registration removes the recorded ones the harness no longer ships and keeps the user's own.
test('installer: the hook registration removes the permission rules the harness no longer ships and keeps the user\'s own', (t) => {
  if (!harnessClone) return t.skip('runs only in a clone of the harness (LICENSE at the root)');
  const shippedHooks = readJson(path.join(path.dirname(installer), '..', 'settings.hooks.json'));
  const dropped = 'Bash(node hardening/scripts/old-tool.mjs *)';
  const mine = 'Bash(my-team-tool *)';
  const local = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-install-'));
  const shared = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-install-'));
  try {
    git(local, 'init', '-q');
    assert.equal(run(local, '--hardening', '--enable-hooks').status, 0);
    const file = path.join(local, '.claude', 'settings.local.json');
    assert.deepEqual(readManifest(local).mergedRules, { '.claude/settings.local.json': sortedRules(shippedHooks.permissions) }, 'the manifest records the merged rules');
    // As if an earlier harness had shipped (and merged) a rule the current one dropped; the user added one of their own.
    const s = readJson(file);
    s.permissions.allow.push(dropped, mine);
    fs.writeFileSync(file, `${JSON.stringify(s, null, 2)}\n`);
    editManifest(local, (m) => { m.mergedRules['.claude/settings.local.json'].allow.push(dropped); });
    const text = fs.readFileSync(file, 'utf8');
    const dry = run(local, '--update', '--dry-run');
    assert.equal(dry.status, 0, dry.stderr);
    assert.match(dry.stdout, /hooks    : 1 permission rule the harness no longer ships would be removed from \.claude\/settings\.local\.json:\n    allow: Bash\(node hardening\/scripts\/old-tool\.mjs \*\)\n/);
    assert.equal(fs.readFileSync(file, 'utf8'), text, '--dry-run writes nothing');
    const r = run(local, '--update');
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /hooks    : 1 permission rule the harness no longer ships removed from \.claude\/settings\.local\.json:\n    allow: Bash\(node hardening\/scripts\/old-tool\.mjs \*\)\n/);
    const after = readJson(file);
    assert.ok(!after.permissions.allow.includes(dropped), 'the dropped rule is gone');
    assert.ok(after.permissions.allow.includes(mine), 'the user\'s rule stays');
    for (const rule of shippedHooks.permissions.allow) assert.ok(after.permissions.allow.includes(rule), `${rule} stays`);
    assert.deepEqual(readManifest(local).mergedRules['.claude/settings.local.json'], sortedRules(shippedHooks.permissions));
    // A manifest from before the record: nothing to compare; the update records the rules from now on and removes nothing.
    editManifest(local, (m) => { delete m.mergedRules; });
    const old = run(local, '--update');
    assert.equal(old.status, 0, old.stderr);
    assert.match(old.stdout, /hooks    : \.claude\/bi-agent-harness\.json had no record of the permission rules merged into \.claude\/settings\.local\.json: recorded from now on/);
    assert.doesNotMatch(old.stdout, /no longer ships removed/);
    assert.ok(readJson(file).permissions.allow.includes(mine));
    assert.deepEqual(readManifest(local).mergedRules, { '.claude/settings.local.json': sortedRules(shippedHooks.permissions) });

    // Shared, in a settings.json the team changed (kept): the dropped rule goes; the team's rules and a rule of the shipped
    // .claude/settings.json stay, even when the record names it.
    git(shared, 'init', '-q');
    assert.equal(run(shared, '--hardening', '--enable-hooks', '--shared').status, 0);
    const settings = path.join(shared, '.claude', 'settings.json');
    const installed = readManifest(shared).files['.claude/settings.json'];
    const e = readJson(settings);
    e.permissions.allow.push(dropped);
    e.permissions.deny.push('Read(./team-notes/**)');
    fs.writeFileSync(settings, `${JSON.stringify(e, null, 2)}\n`);
    editManifest(shared, (m) => {
      m.mergedRules['.claude/settings.json'].allow.push(dropped);
      m.mergedRules['.claude/settings.json'].deny = ['Read(.env)'];
    });
    const sr = run(shared, '--update');
    assert.equal(sr.status, 0, sr.stderr);
    assert.match(sr.stdout, /kept     : 1 file\(s\)[^\n]*:\n    \.claude\/settings\.json\n/);
    assert.match(sr.stdout, /hooks    : 1 permission rule the harness no longer ships removed from \.claude\/settings\.json:\n    allow: Bash\(node hardening\/scripts\/old-tool\.mjs \*\)\n/);
    const sa = readJson(settings);
    assert.ok(!sa.permissions.allow.includes(dropped), 'the dropped rule is gone');
    assert.ok(sa.permissions.deny.includes('Read(./team-notes/**)'), 'the team\'s rule stays');
    assert.ok(sa.permissions.deny.includes('Read(.env)'), 'a rule of the shipped settings.json stays');
    assert.equal(readManifest(shared).files['.claude/settings.json'], installed, 'the file is still not the installed state');
  } finally {
    fs.rmSync(local, { recursive: true, force: true });
    fs.rmSync(shared, { recursive: true, force: true });
  }
});

// F2-44: after the documented disable (remove the hooks block, unset core.hooksPath) a plain --update registered every hook
// again and set core.hooksPath. It now leaves them disabled and names the flag; only --enable-hooks sets the path.
test('installer: a plain --update leaves disabled hooks disabled and never sets an unset core.hooksPath', (t) => {
  if (!harnessClone) return t.skip('runs only in a clone of the harness (LICENSE at the root)');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-install-'));
  try {
    git(dir, 'init', '-q');
    assert.equal(run(dir, '--hardening', '--enable-hooks').status, 0);
    const file = path.join(dir, '.claude', 'settings.local.json');
    const s = readJson(file);
    delete s.hooks;
    fs.writeFileSync(file, `${JSON.stringify(s, null, 2)}\n`);
    assert.equal(git(dir, 'config', '--unset', 'core.hooksPath').status, 0);
    const text = fs.readFileSync(file, 'utf8');
    for (const args of [['--update', '--dry-run'], ['--update']]) {
      const r = run(dir, ...args);
      assert.equal(r.status, 0, r.stderr);
      assert.match(r.stdout, /hooks    : the hooks stay disabled: \.claude\/settings\.local\.json holds no harness hook registration \(\.claude\/bi-agent-harness\.json records "local"\); --update --enable-hooks registers them again\n/);
      assert.doesNotMatch(r.stdout, /merged into/);
      assert.equal(fs.readFileSync(file, 'utf8'), text, `${args.join(' ')}: no hook comes back`);
      assert.equal(git(dir, 'config', '--get', 'core.hooksPath').status, 1, `${args.join(' ')}: core.hooksPath stays unset`);
    }
    assert.equal(readManifest(dir).hooks, 'local', 'the recorded choice stays for --enable-hooks');
    // The flag it names registers them again and sets the path.
    const on = run(dir, '--update', '--enable-hooks');
    assert.equal(on.status, 0, on.stderr);
    assert.ok(readJson(file).hooks.PreToolUse.length > 0, 'the hooks are registered again');
    assert.equal(git(dir, 'config', '--get', 'core.hooksPath').stdout.trim(), 'hardening/githooks');
    // Hooks registered, core.hooksPath unset (a fresh clone of a shared install, or the user's choice): a plain update keeps
    // the hooks and leaves the path unset.
    assert.equal(git(dir, 'config', '--unset', 'core.hooksPath').status, 0);
    const plain = run(dir, '--update');
    assert.equal(plain.status, 0, plain.stderr);
    assert.match(plain.stdout, /merged into \.claude\/settings\.local\.json; core\.hooksPath is unset and stays so \(only --enable-hooks sets it\); to use the harness's Git hooks: git config core\.hooksPath hardening\/githooks\n/);
    assert.equal(git(dir, 'config', '--get', 'core.hooksPath').status, 1);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// F2-46: --enable-hooks replaced an existing core.hooksPath (a team's .husky) without a word, and in a target below the top
// of a work tree it pointed the enclosing repository at a hooks folder that repository does not have. Both stay as they are.
test('installer: --enable-hooks keeps a core.hooksPath set to another folder and sets none below the top of a work tree', (t) => {
  if (!harnessClone) return t.skip('runs only in a clone of the harness (LICENSE at the root)');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-install-'));
  const outer = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-outer-'));
  try {
    git(root, 'init', '-q');
    put(path.join(root, '.husky', 'pre-commit'), '#!/bin/sh\nexit 0\n');
    assert.equal(git(root, 'config', 'core.hooksPath', '.husky').status, 0);
    for (const args of [['--hardening', '--enable-hooks'], ['--update', '--enable-hooks']]) {
      const r = run(root, ...args);
      assert.equal(r.status, 0, r.stderr);
      assert.match(r.stdout, /merged into \.claude\/settings\.local\.json; core\.hooksPath kept as "\.husky" \(not replaced\), so the harness's Git hooks do not run; to use them instead: git config core\.hooksPath hardening\/githooks\n/);
      assert.equal(git(root, 'config', '--get', 'core.hooksPath').stdout.trim(), '.husky', `${args.join(' ')} keeps the team's hooks`);
    }
    git(outer, 'init', '-q');
    const sub = path.join(outer, 'bi');
    fs.mkdirSync(sub);
    const r = run(sub, '--hardening', '--enable-hooks', '--shared');
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /; core\.hooksPath not set: [^\n]*bi is not the top of its Git work tree \([^\n]*\), where Git would look for hardening\/githooks; install the harness at the top of the repository to use its Git hooks\n/);
    assert.equal(git(outer, 'config', '--get', 'core.hooksPath').status, 1, 'the enclosing repository is not pointed at a folder it does not have');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
    fs.rmSync(outer, { recursive: true, force: true });
  }
});

// F2-47: a target with its own THIRD_PARTY_NOTICES.md kept it, and the MIT notice of the vendored Microsoft references went
// nowhere. It is installed next to the LICENSE and NOTICE copies now, whatever the root holds.
test('installer: the third-party notice goes next to the manifest, also when the target has its own THIRD_PARTY_NOTICES.md', (t) => {
  if (!harnessClone) return t.skip('runs only in a clone of the harness (LICENSE at the root)');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-install-'));
  try {
    const own = { 'THIRD_PARTY_NOTICES.md': '# Third-party notices\n\nOur own components.\n', LICENSE: 'Our own license\n', NOTICE: 'Our notice\n' };
    for (const [name, text] of Object.entries(own)) put(path.join(dir, name), text);
    const r = run(dir);
    assert.equal(r.status, 0, r.stderr);
    const copy = path.join(dir, '.claude', 'bi-agent-harness', 'THIRD_PARTY_NOTICES.md');
    const source = path.join(path.dirname(installer), '..', '..', 'THIRD_PARTY_NOTICES.md');
    assert.ok(fs.existsSync(copy), 'the notice is installed next to the manifest');
    assert.equal(fs.readFileSync(copy, 'utf8'), fs.readFileSync(source, 'utf8'));
    assert.match(fs.readFileSync(copy, 'utf8'), /MIT License/);
    for (const [name, text] of Object.entries(own)) assert.equal(fs.readFileSync(path.join(dir, name), 'utf8'), text, `the target's own ${name} stays`);
    assert.equal(readManifest(dir).files['.claude/bi-agent-harness/THIRD_PARTY_NOTICES.md'], digestOf(source), 'recorded like the LICENSE and NOTICE copies');
    assert.deepEqual(fs.readdirSync(path.join(dir, '.claude', 'bi-agent-harness')).sort(), ['LICENSE', 'NOTICE', 'THIRD_PARTY_NOTICES.md']);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// F2-48: --update from an older harness clone put back older files and removed newer ones as "no longer shipped". The
// manifest records the source commit; an update from a source that does not contain it stops unless --allow-older.
test('installer: --update from a source that does not contain the recorded commit stops with no change unless --allow-older', (t) => {
  if (!harnessClone) return t.skip('runs only in a clone of the harness (LICENSE at the root)');
  const sourceRoot = path.resolve(path.dirname(installer), '..', '..');
  const head = git(sourceRoot, 'rev-parse', '--verify', '--quiet', 'HEAD');
  if (head.status !== 0) return t.skip('the harness source is no Git checkout with a commit');
  const tmp = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-install-')));
  try {
    // This checkout: the install records its commit, and a recorded commit it does not know stops the update.
    const dir = path.join(tmp, 'target');
    fs.mkdirSync(dir);
    assert.equal(run(dir).status, 0);
    assert.equal(readManifest(dir).commit, head.stdout.trim(), 'the install records the source commit');
    const unknown = 'f'.repeat(40);
    editManifest(dir, (m) => { m.commit = unknown; });
    const before = snapshot(dir);
    for (const args of [['--update'], ['--update', '--dry-run']]) {
      const r = run(dir, ...args);
      assert.equal(r.status, 2, `${args.join(' ')}: ${r.stdout}`);
      assert.match(r.stderr, /does not contain commit ffffffffffff, which \.claude\/bi-agent-harness\.json records for the last install or update: the source is older, on another branch, or from a harness whose history was rewritten since \(git pull cannot bring that commit back then\)[^\n]*run once with --update --allow-older to update from this source anyway; the manifest then records it\. No files changed\./);
      assert.deepEqual(snapshot(dir), before, `${args.join(' ')} changes nothing`);
    }
    // An install rerun overwrites no file: the manifest keeps the commit it records.
    const rerun = run(dir);
    assert.equal(rerun.status, 0, rerun.stderr);
    assert.match(rerun.stderr, /Warning: the harness source [^\n]*does not contain commit ffffffffffff[^\n]*the manifest keeps commit ffffffffffff\./);
    assert.equal(readManifest(dir).commit, unknown);
    // With --allow-older an install rerun records the source commit instead.
    const rerunOlder = run(dir, '--allow-older');
    assert.equal(rerunOlder.status, 0, rerunOlder.stderr);
    assert.doesNotMatch(rerunOlder.stderr, /does not contain commit/);
    assert.equal(readManifest(dir).commit, head.stdout.trim());
    editManifest(dir, (m) => { m.commit = unknown; });
    const allowed = run(dir, '--update', '--allow-older');
    assert.equal(allowed.status, 0, allowed.stderr);
    assert.equal(readManifest(dir).commit, head.stdout.trim(), '--allow-older records the source commit');
    // A value that is no object name never reaches git: it counts as none recorded.
    editManifest(dir, (m) => { m.commit = '--output=x'; });
    const odd = run(dir, '--update');
    assert.equal(odd.status, 0, odd.stderr);
    assert.equal(readManifest(dir).commit, head.stdout.trim());

    // A real older commit: a small harness source with two releases.
    const src = path.join(tmp, 'source');
    for (const rel of ['AGENTS.md', 'TASKS.md', '.mcp.example.json', '.gitattributes', 'THIRD_PARTY_NOTICES.md', '.gitignore', 'LICENSE', 'NOTICE', '.claude/settings.json', '.vscode/extensions.json', 'hardening/scripts/install-into.mjs']) {
      fs.mkdirSync(path.dirname(path.join(src, rel)), { recursive: true });
      fs.copyFileSync(path.join(sourceRoot, rel), path.join(src, rel));
    }
    put(path.join(src, 'docs', 'guide.md'), '# Guide\n\nRelease one.\n');
    put(path.join(src, 'templates', 'README.md'), '# t\n');
    assert.equal(git(src, 'init', '-q').status, 0);
    const commit = (message) => {
      assert.equal(git(src, 'add', '-A').status, 0);
      const c = git(src, '-c', 'user.email=t@example.com', '-c', 'user.name=t', '-c', 'commit.gpgsign=false', 'commit', '-q', '--no-verify', '-m', message);
      assert.equal(c.status, 0, c.stderr);
      return git(src, 'rev-parse', 'HEAD').stdout.trim();
    };
    const one = commit('release one');
    put(path.join(src, 'docs', 'guide.md'), '# Guide\n\nRelease two.\n');
    put(path.join(src, 'docs', 'new-guide.md'), '# New guide\n');
    const two = commit('release two');
    const runFrom = (...args) => spawnSync(process.execPath, [path.join(src, 'hardening', 'scripts', 'install-into.mjs'), ...args], { encoding: 'utf8', env: gitEnv() });
    const team = path.join(tmp, 'team');
    fs.mkdirSync(team);
    assert.equal(runFrom(team).status, 0);
    assert.equal(readManifest(team).commit, two);
    assert.equal(git(src, 'checkout', '-q', one).status, 0);
    const teamBefore = snapshot(team);
    const older = runFrom(team, '--update');
    assert.equal(older.status, 2, older.stdout);
    assert.match(older.stderr, new RegExp(`\\(commit ${one.slice(0, 12)}\\) does not contain commit ${two.slice(0, 12)}, `));
    assert.deepEqual(snapshot(team), teamBefore, 'no file is downgraded or removed');
    const down = runFrom(team, '--update', '--allow-older');
    assert.equal(down.status, 0, down.stderr);
    assert.match(down.stdout, /removed  : 1 file\(s\)[^\n]*:\n    docs\/new-guide\.md\n/);
    assert.equal(lf(path.join(team, 'docs', 'guide.md')), '# Guide\n\nRelease one.\n');
    assert.equal(readManifest(team).commit, one, 'the manifest records what is installed now');
    assert.equal(git(src, 'checkout', '-q', two).status, 0);
    const up = runFrom(team, '--update');
    assert.equal(up.status, 0, up.stderr);
    assert.ok(fs.existsSync(path.join(team, 'docs', 'new-guide.md')), 'the newer release adds it again');
    assert.equal(readManifest(team).commit, two);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

// Audit 2026-10-31 (S5a): the F2-48 stop compared commits only, so a source that is no Git checkout (a zip) downgraded an
// install with no stop; the version the manifest records was written but never compared. A lower pack version stops now.
test('installer: --update from a source that is no Git checkout with a lower pack version stops with no change unless --allow-older', (t) => {
  if (!harnessClone) return t.skip('runs only in a clone of the harness (LICENSE at the root)');
  const sourceRoot = path.resolve(path.dirname(installer), '..', '..');
  const tmp = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-install-')));
  try {
    // A small harness source unpacked from a zip: the files, no .git.
    const src = path.join(tmp, 'zip');
    for (const rel of ['AGENTS.md', 'TASKS.md', '.mcp.example.json', '.gitattributes', 'THIRD_PARTY_NOTICES.md', '.gitignore', 'LICENSE', 'NOTICE', '.claude/settings.json', '.vscode/extensions.json', 'hardening/scripts/install-into.mjs']) {
      fs.mkdirSync(path.dirname(path.join(src, rel)), { recursive: true });
      fs.copyFileSync(path.join(sourceRoot, rel), path.join(src, rel));
    }
    put(path.join(src, 'docs', 'guide.md'), '# Guide\n');
    put(path.join(src, 'templates', 'README.md'), '# t\n');
    put(path.join(src, 'hardening', 'package.json'), `${JSON.stringify({ name: 'pack', version: '1.2.0' })}\n`);
    const runFrom = (...args) => spawnSync(process.execPath, [path.join(src, 'hardening', 'scripts', 'install-into.mjs'), ...args], { encoding: 'utf8', env: gitEnv() });
    const team = path.join(tmp, 'team');
    fs.mkdirSync(team);
    const first = runFrom(team);
    assert.equal(first.status, 0, first.stderr);
    assert.deepEqual([readManifest(team).commit, readManifest(team).version], [undefined, '1.2.0'], 'no Git checkout: no commit, so the version decides');
    // The manifest records a newer install (1.10.0 is above 1.2.0, compared as numbers): this copy is older.
    editManifest(team, (m) => { m.version = '1.10.0'; });
    const before = snapshot(team);
    for (const args of [['--update'], ['--update', '--dry-run']]) {
      const r = runFrom(team, ...args);
      assert.equal(r.status, 2, `${args.join(' ')}: ${r.stdout}`);
      assert.match(r.stderr, /cannot be compared by commit \(it is not a Git checkout\), and its pack version 1\.2\.0 is lower than version 1\.10\.0, which \.claude\/bi-agent-harness\.json records for the last install or update: [^\n]*run once with --update --allow-older to update from this source anyway; the manifest then records it\. No files changed\./);
      assert.deepEqual(snapshot(team), before, `${args.join(' ')} changes nothing`);
    }
    // An install rerun overwrites no file: it warns, and the manifest keeps the version it records.
    const rerun = runFrom(team);
    assert.equal(rerun.status, 0, rerun.stderr);
    assert.match(rerun.stderr, /Warning: the harness source [^\n]*\(it is not a Git checkout\), and its pack version 1\.2\.0 is lower than version 1\.10\.0[^\n]*the manifest keeps version 1\.10\.0\./);
    assert.equal(readManifest(team).version, '1.10.0');
    const allowed = runFrom(team, '--update', '--allow-older');
    assert.equal(allowed.status, 0, allowed.stderr);
    assert.equal(readManifest(team).version, '1.2.0', '--allow-older records this copy');
    // An equal or lower recorded version, none, or one that is no dotted number: no stop.
    for (const recorded of ['1.2.0', '1.2', '1.1.9', undefined, 'v2', '2.0.0-beta']) {
      editManifest(team, (m) => { if (recorded === undefined) delete m.version; else m.version = recorded; });
      const r = runFrom(team, '--update');
      assert.equal(r.status, 0, `${recorded}: ${r.stderr}`);
      assert.doesNotMatch(r.stderr, /is not a Git checkout/, String(recorded));
      assert.equal(readManifest(team).version, '1.2.0', String(recorded));
    }
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

// Audit 2026-10-31 (R2): an install from a zip (a version, no commit) updated later from an OLDER Git checkout skipped both
// stops: no recorded commit, so no commit comparison, and a source commit, so no version comparison. The version decides
// wherever the commits cannot be compared; with both commits the commit comparison decides alone.
test('installer: --update from an older Git checkout over a manifest without a commit stops on the lower pack version unless --allow-older', (t) => {
  if (!harnessClone) return t.skip('runs only in a clone of the harness (LICENSE at the root)');
  const sourceRoot = path.resolve(path.dirname(installer), '..', '..');
  const tmp = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-install-')));
  try {
    const src = path.join(tmp, 'clone');
    for (const rel of ['AGENTS.md', 'TASKS.md', '.mcp.example.json', '.gitattributes', 'THIRD_PARTY_NOTICES.md', '.gitignore', 'LICENSE', 'NOTICE', '.claude/settings.json', '.vscode/extensions.json', 'hardening/scripts/install-into.mjs']) {
      fs.mkdirSync(path.dirname(path.join(src, rel)), { recursive: true });
      fs.copyFileSync(path.join(sourceRoot, rel), path.join(src, rel));
    }
    put(path.join(src, 'docs', 'guide.md'), '# Guide\n');
    put(path.join(src, 'templates', 'README.md'), '# t\n');
    put(path.join(src, 'hardening', 'package.json'), `${JSON.stringify({ name: 'pack', version: '1.0.0' })}\n`);
    assert.equal(git(src, 'init', '-q').status, 0);
    assert.equal(git(src, 'add', '-A').status, 0);
    const c = git(src, '-c', 'user.email=t@example.com', '-c', 'user.name=t', '-c', 'commit.gpgsign=false', 'commit', '-q', '--no-verify', '-m', 'release');
    assert.equal(c.status, 0, c.stderr);
    const head = git(src, 'rev-parse', 'HEAD').stdout.trim();
    const runFrom = (...args) => spawnSync(process.execPath, [path.join(src, 'hardening', 'scripts', 'install-into.mjs'), ...args], { encoding: 'utf8', env: gitEnv() });
    const team = path.join(tmp, 'team');
    fs.mkdirSync(team);
    assert.equal(runFrom(team).status, 0);
    assert.deepEqual([readManifest(team).commit, readManifest(team).version], [head, '1.0.0']);
    // As if installed from a zip of 1.0.1: a version and no commit.
    editManifest(team, (m) => { delete m.commit; m.version = '1.0.1'; });
    const before = snapshot(team);
    const r = runFrom(team, '--update');
    assert.equal(r.status, 2, r.stdout);
    assert.match(r.stderr, /cannot be compared by commit \(\.claude\/bi-agent-harness\.json records no commit to compare it with\), and its pack version 1\.0\.0 is lower than version 1\.0\.1, which [^\n]*run once with --update --allow-older to update from this source anyway; the manifest then records it\. No files changed\./);
    assert.deepEqual(snapshot(team), before, 'no file changed');
    const allowed = runFrom(team, '--update', '--allow-older');
    assert.equal(allowed.status, 0, allowed.stderr);
    assert.deepEqual([readManifest(team).commit, readManifest(team).version], [head, '1.0.0'], '--allow-older records this clone');
    // Both commits known: the commit comparison decides alone, a higher recorded version changes nothing.
    editManifest(team, (m) => { m.version = '1.0.1'; });
    const same = runFrom(team, '--update');
    assert.equal(same.status, 0, same.stderr);
    assert.doesNotMatch(same.stderr, /cannot be compared by commit/);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

// Audit 2026-10-31 (R2'): a plain rerun from an older Git checkout over a zip install kept the recorded version but wrote
// the older source's commit, so the next --update compared equal commits, skipped the version check and downgraded the
// files with no --allow-older. The manifest's version and commit describe one installed state and move together.
test('installer: a plain rerun from an older Git checkout over a zip install keeps version and commit, so the next --update still stops', (t) => {
  if (!harnessClone) return t.skip('runs only in a clone of the harness (LICENSE at the root)');
  const sourceRoot = path.resolve(path.dirname(installer), '..', '..');
  const tmp = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-install-')));
  try {
    const source = (dir, version, guide, extra = {}) => {
      for (const rel of ['AGENTS.md', 'TASKS.md', '.mcp.example.json', '.gitattributes', 'THIRD_PARTY_NOTICES.md', '.gitignore', 'LICENSE', 'NOTICE', '.claude/settings.json', '.vscode/extensions.json', 'hardening/scripts/install-into.mjs']) {
        fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
        fs.copyFileSync(path.join(sourceRoot, rel), path.join(dir, rel));
      }
      put(path.join(dir, 'docs', 'guide.md'), guide);
      for (const [rel, text] of Object.entries(extra)) put(path.join(dir, rel), text);
      put(path.join(dir, 'templates', 'README.md'), '# t\n');
      put(path.join(dir, 'hardening', 'package.json'), `${JSON.stringify({ name: 'pack', version })}\n`);
    };
    const zip = path.join(tmp, 'zip-1.0.1');
    source(zip, '1.0.1', '# Guide\n\nRelease 1.0.1.\n', { 'docs/new-guide.md': '# New guide\n' });
    const clone = path.join(tmp, 'clone-1.0.0');
    source(clone, '1.0.0', '# Guide\n\nRelease 1.0.0.\n');
    assert.equal(git(clone, 'init', '-q').status, 0);
    assert.equal(git(clone, 'add', '-A').status, 0);
    assert.equal(git(clone, '-c', 'user.email=t@example.com', '-c', 'user.name=t', '-c', 'commit.gpgsign=false', 'commit', '-q', '--no-verify', '-m', 'release 1.0.0').status, 0);
    const head = git(clone, 'rev-parse', 'HEAD').stdout.trim();
    const runFrom = (src, ...args) => spawnSync(process.execPath, [path.join(src, 'hardening', 'scripts', 'install-into.mjs'), ...args], { encoding: 'utf8', env: gitEnv() });
    const team = path.join(tmp, 'team');
    fs.mkdirSync(team);
    // 1. The zip install of 1.0.1: a version, no commit.
    assert.equal(runFrom(zip, team).status, 0);
    assert.deepEqual([readManifest(team).version, readManifest(team).commit], ['1.0.1', undefined]);
    // 2. A plain rerun from the 1.0.0 clone: it overwrites no file and warns; the manifest keeps the installed state.
    const rerun = runFrom(clone, team);
    assert.equal(rerun.status, 0, rerun.stderr);
    assert.match(rerun.stderr, /the manifest keeps version 1\.0\.1/);
    const afterRerun = readManifest(team);
    // 3. --update from the same clone still stops: the commits cannot be compared, the version is lower.
    const before = snapshot(team);
    const update = runFrom(clone, team, '--update');
    assert.equal(update.status, 2, `--update after the rerun: ${update.stdout}`);
    assert.match(update.stderr, /cannot be compared by commit \(\.claude\/bi-agent-harness\.json records no commit to compare it with\), and its pack version 1\.0\.0 is lower than version 1\.0\.1/);
    assert.deepEqual(snapshot(team), before, 'no file is downgraded or removed');
    assert.deepEqual([afterRerun.version, afterRerun.commit], ['1.0.1', undefined], 'the rerun wrote neither the older version nor the older commit');
    assert.ok(fs.existsSync(path.join(team, 'docs', 'new-guide.md')));
    // 4. --allow-older moves version and commit together to the clone's.
    const allowed = runFrom(clone, team, '--update', '--allow-older');
    assert.equal(allowed.status, 0, allowed.stderr);
    assert.deepEqual([readManifest(team).version, readManifest(team).commit], ['1.0.0', head]);
    assert.ok(!fs.existsSync(path.join(team, 'docs', 'new-guide.md')), 'only now the file of 1.0.1 goes');
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

// F2-63: --update on a target without a manifest went past the integration-conflict stop of an install: it installed the
// pack, listed a differing AGENTS.md and the user's own settings as files "you changed" and exited 0.
test('installer: --update without a manifest stops before any change and names the install', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-install-'));
  try {
    put(path.join(dir, 'AGENTS.md'), '# Our agents\n');
    for (const args of [['--update'], ['--update', '--hardening'], ['--update', '--dry-run']]) {
      const r = run(dir, ...args);
      assert.equal(r.status, 2, `${args.join(' ')}: ${r.stdout}`);
      assert.match(r.stderr, /No manifest: run the install first \(without --update\)\. [^\n]* has no \.claude\/bi-agent-harness\.json, which --update reads\. No files changed\./);
      assert.deepEqual(fs.readdirSync(dir), ['AGENTS.md'], `${args.join(' ')} wrote nothing`);
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// F2-64: an `@AGENTS.md` line inside a code block or an HTML comment counted as the import, and an import inside a line
// did not count, so a second one was appended.
test('installer: an @AGENTS.md in a code block or HTML comment is no import, one inside a line is', (t) => {
  if (!harnessClone) return t.skip('runs only in a clone of the harness (LICENSE at the root)');
  // [name, the lines after the heading, whether the import is appended]. Lines, not strings with a `\n` escape: the
  // release check would read the escape's letter and the import that follows it as an e-mail address.
  const cases = [
    ['fenced', ['```', '@AGENTS.md', '```'], true],
    ['tilde fence', ['~~~md', '@AGENTS.md', '~~~'], true],
    ['unclosed fence', ['```', '@AGENTS.md'], true],
    ['comment', ['<!--', '@AGENTS.md', '-->'], true],
    ['unclosed comment', ['<!-- notes', '@AGENTS.md'], true],
    ['code span', ['Use `@AGENTS.md` to import.'], true],
    ['trailing comma', ['Read @AGENTS.md, then work.'], true],
    ['inline', ['Read @AGENTS.md first.'], false],
    ['after a comment', ['<!-- note --> @AGENTS.md'], false],
    ['after a fence', ['```', 'x', '```', '@./AGENTS.md'], false],
    ['own line', ['@AGENTS.md   '], false],
  ];
  const dirs = [];
  try {
    for (const [name, lines, appended] of cases) {
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-install-'));
      dirs.push(dir);
      fs.writeFileSync(path.join(dir, 'CLAUDE.md'), ['# Proj', ...lines, ''].join('\r\n'));
      const r = run(dir, '--dry-run');
      assert.equal(r.status, 0, r.stderr);
      assert.equal(/CLAUDE\.md: `@AGENTS\.md` import would be appended/.test(r.stdout), appended, `${name}: ${r.stdout}`);
    }
    // The append itself happens once: the next run finds the import it wrote.
    const dir = dirs[0];
    const first = run(dir);
    assert.equal(first.status, 0, first.stderr);
    assert.match(first.stdout, /CLAUDE\.md: `@AGENTS\.md` import appended/);
    const again = run(dir, '--update');
    assert.equal(again.status, 0, again.stderr);
    assert.doesNotMatch(again.stdout, /CLAUDE\.md:/);
    assert.equal(fs.readFileSync(path.join(dir, 'CLAUDE.md'), 'utf8').match(/^@AGENTS\.md\r?$/gm).length, 2, 'the fenced line and the appended import');
  } finally {
    for (const dir of dirs) fs.rmSync(dir, { recursive: true, force: true });
  }
});

/** The snapshot of a target without its manifest: the files an install left on disk. */
const installedFiles = (dir) => {
  const { '.claude/bi-agent-harness.json': manifest, ...files } = snapshot(dir);
  assert.ok(manifest, 'the target has a manifest');
  return files;
};

// --domain (2026-10-29): the knowledge domains to install. One exists, bi, which is the default; anything else is
// refused before a file is read, naming the available domains. The manifest records the list ("domains").
test('installer: --domain defaults to bi, --domain bi installs the same, any other name is refused, the manifest records the list', (t) => {
  if (!harnessClone) return t.skip('runs only in a clone of the harness (LICENSE at the root)');
  const dirs = [];
  const fresh = () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-install-'));
    dirs.push(dir);
    git(dir, 'init', '-q');
    return dir;
  };
  try {
    const byDefault = fresh();
    const explicit = fresh();
    for (const [dir, args] of [[byDefault, []], [explicit, ['--domain', 'bi']]]) {
      const r = run(dir, '--hardening', ...args);
      assert.equal(r.status, 0, `${args.join(' ') || 'default'}: ${r.stderr}`);
      assert.match(r.stdout, /^Harness install → [^\n]*\n  domains  : bi\n/, 'the output names the domains');
      assert.deepEqual(readManifest(dir).domains, ['bi'], 'the manifest records the list');
    }
    assert.deepEqual(snapshot(explicit), snapshot(byDefault), '--domain bi installs exactly the default files');
    assert.deepEqual(readManifest(explicit).files, readManifest(byDefault).files);
    const dry = run(fresh(), '--dry-run', '--domain', 'bi');
    assert.match(dry.stdout, /^\[dry-run\] Harness install → [^\n]*\n  domains  : bi\n/);

    const empty = fresh();
    const unknown = [
      [['--domain', 'sql'], /^Unknown domain: sql\. Available domains: bi\. No files changed\.$/m],
      [['--hardening', '--domain', 'bi,sql,web'], /^Unknown domains: sql, web\. Available domains: bi\. No files changed\.$/m],
      [['--domain', 'BI'], /^Unknown domain: BI\. Available domains: bi\./m],
      [['--domain', ' , '], /^--domain names no domain\. Available domains: bi\. No files changed\.$/m],
    ];
    for (const [args, message] of unknown) {
      const r = run(empty, ...args);
      assert.equal(r.status, 2, `${args.join(' ')}: ${r.stdout}`);
      assert.match(r.stderr, message);
      assert.deepEqual(fs.readdirSync(empty), ['.git'], `${args.join(' ')} wrote nothing`);
    }
    for (const args of [['--domain'], ['--domain', '--hardening']]) {
      const r = run(empty, ...args);
      assert.equal(r.status, 2, `${args.join(' ')}: ${r.stdout}`);
      assert.match(r.stderr, /^usage: [^\n]*\[--domain <list>\]$/m, 'a --domain without a value is a usage error');
    }
    // On an installed repository too: the update is refused and nothing changes.
    const before = fs.readFileSync(path.join(byDefault, '.claude', 'bi-agent-harness.json'), 'utf8');
    const files = snapshot(byDefault);
    const refused = run(byDefault, '--update', '--domain', 'sql');
    assert.equal(refused.status, 2, refused.stdout);
    assert.match(refused.stderr, /^Unknown domain: sql\. Available domains: bi\. No files changed\.$/m);
    assert.equal(fs.readFileSync(path.join(byDefault, '.claude', 'bi-agent-harness.json'), 'utf8'), before);
    assert.deepEqual(snapshot(byDefault), files);
  } finally {
    for (const dir of dirs) fs.rmSync(dir, { recursive: true, force: true });
  }
});

// A manifest written before the field existed counts as bi: --update changes no file and adds the field. A recorded list
// this source does not ship (an older clone) or that is no list of names stops the run with no change.
test('installer: --update of a manifest without "domains" updates as bi with no file change; a recorded domain this source lacks stops it', (t) => {
  if (!harnessClone) return t.skip('runs only in a clone of the harness (LICENSE at the root)');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-install-'));
  try {
    git(dir, 'init', '-q');
    assert.equal(run(dir, '--hardening', '--enable-hooks').status, 0);
    const manifestFile = path.join(dir, '.claude', 'bi-agent-harness.json');
    const { domains: written, ...old } = readManifest(dir);
    assert.deepEqual(written, ['bi']);
    const writeManifest = (data) => fs.writeFileSync(manifestFile, `${JSON.stringify(data, null, 2)}\n`);
    const files = installedFiles(dir);
    for (const args of [['--update'], ['--update', '--enable-hooks'], ['--update', '--domain', 'bi']]) {
      writeManifest(old); // the manifest an installer without --domain wrote
      const r = run(dir, ...args);
      assert.equal(r.status, 0, `${args.join(' ')}: ${r.stderr}`);
      assert.match(r.stdout, /^Harness update → [^\n]*\n  domains  : bi\n/);
      assert.match(r.stdout, /updated  : 0 file\(s\)\n/, `${args.join(' ')} updates no file`);
      assert.match(r.stdout, /removed  : 0 file\(s\)/);
      assert.match(r.stdout, /kept     : 0 file\(s\)/);
      assert.deepEqual(installedFiles(dir), files, `${args.join(' ')} changes no installed file`);
      const { domains, ...rest } = readManifest(dir);
      assert.deepEqual(domains, ['bi'], 'the field is added');
      assert.deepEqual(rest, old, 'and nothing else in the manifest changes');
    }
    for (const [domains, status, message] of [
      [['bi', 'sql'], 2, /records the domain sql, which this harness source does not ship \(available domains: bi\)[^\n]*No files changed\./],
      ['bi', 1, /"domains" is not a list of domain names \(available: bi\); fix or delete the field[^\n]*No files changed\./],
      [[], 1, /"domains" is not a list of domain names/],
    ]) {
      writeManifest({ ...old, domains });
      const text = fs.readFileSync(manifestFile, 'utf8');
      for (const args of [['--update'], ['--hardening']]) {
        const r = run(dir, ...args);
        assert.equal(r.status, status, `${JSON.stringify(domains)} ${args.join(' ')}: ${r.stdout}`);
        assert.match(r.stderr, message);
        assert.equal(fs.readFileSync(manifestFile, 'utf8'), text, 'the manifest is not rewritten');
        assert.deepEqual(installedFiles(dir), files, 'no file changes');
      }
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// Audit 2026-10-31, second round (A2): the installer's link check covered the files it copies, not the files it generates
// or merges. With .claude/bi-agent-harness.json, CLAUDE.md or .claude/settings.local.json a link to a file outside the
// target, the manifest overwrote that file, the @AGENTS.md import was appended to it, or --enable-hooks merged into it, and
// each run exited 0; a dangling link created a new file outside. A link at any path the installer reads or writes, or at a
// folder on the way to one, now stops the run (exit 2) before the first read, with nothing written.
const LINKED_RE = /Linked installation paths \(no files changed\)/;
/** A target folder and a sibling folder outside it, under one temporary parent; `fn(dir, outside)` runs, then both go. */
function withTargetAndOutside(fn) {
  const parent = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-install-link-')));
  const dir = path.join(parent, 'repo');
  const outside = path.join(parent, 'outside');
  fs.mkdirSync(dir);
  fs.mkdirSync(outside);
  try {
    return fn(dir, outside);
  } finally {
    fs.rmSync(parent, { recursive: true, force: true });
  }
}
/** A symbolic link to a file, or false where this machine does not let the tests make one (Windows without the privilege). */
function fileLink(target, link) {
  try {
    fs.mkdirSync(path.dirname(link), { recursive: true });
    fs.symlinkSync(target, link, 'file');
    return true;
  } catch {
    return false;
  }
}
const NO_FILE_LINKS = 'this machine does not let the tests create a file symlink (Windows needs Developer Mode or an administrator); the junction cases run';

test('installer (A2): the manifest, CLAUDE.md or settings.local.json as a link to an outside file stops the run, the outside file unchanged', async (t) => {
  if (!harnessClone) return t.skip('runs only in a clone of the harness (LICENSE at the root)');
  for (const [rel, text, args] of [
    ['.claude/bi-agent-harness.json', '{ "outside": true }\n', []],
    ['CLAUDE.md', '# Outside notes\n', []],
    ['.claude/settings.local.json', '{ "outside": true }\n', ['--hardening', '--enable-hooks']],
  ]) {
    await t.test(rel, (st) => withTargetAndOutside((dir, outside) => {
      const victim = put(path.join(outside, 'victim'), text);
      if (!fileLink(victim, path.join(dir, ...rel.split('/')))) return st.skip(NO_FILE_LINKS);
      const before = snapshot(dir);
      const r = run(dir, ...args);
      assert.equal(r.status, 2, `${rel}: ${r.stdout}${r.stderr}`);
      assert.match(r.stderr, LINKED_RE);
      assert.ok(r.stderr.includes(`\n  ${rel}`), `the message names ${rel}: ${r.stderr}`);
      assert.equal(fs.readFileSync(victim, 'utf8'), text, 'the outside file is unchanged');
      assert.deepEqual(fs.readdirSync(outside), ['victim'], 'nothing is created outside');
      assert.deepEqual(snapshot(dir), before, 'nothing is written in the target');
    }));
  }
  await t.test('a dangling link at the manifest path', (st) => withTargetAndOutside((dir, outside) => {
    if (!fileLink(path.join(outside, 'new.json'), path.join(dir, '.claude', 'bi-agent-harness.json'))) return st.skip(NO_FILE_LINKS);
    const r = run(dir);
    assert.equal(r.status, 2, r.stdout + r.stderr);
    assert.match(r.stderr, LINKED_RE);
    assert.deepEqual(fs.readdirSync(outside), [], 'no file is created outside');
  }));
});

test('installer (A2): a folder on the way that is a junction or a link (.claude, docs, a dangling one) stops the run with nothing written', (t) => {
  if (!harnessClone) return t.skip('runs only in a clone of the harness (LICENSE at the root)');
  const kind = process.platform === 'win32' ? 'junction' : 'dir'; // a junction needs no privilege on Windows
  for (const [rel, args] of [['.claude', []], ['.claude', ['--hardening', '--enable-hooks']], ['docs', []]]) {
    withTargetAndOutside((dir, outside) => {
      put(path.join(outside, 'marker.txt'), 'outside\n');
      fs.symlinkSync(outside, path.join(dir, rel), kind);
      const r = run(dir, ...args);
      assert.equal(r.status, 2, `${rel} ${args.join(' ')}: ${r.stdout}${r.stderr}`);
      assert.match(r.stderr, LINKED_RE);
      assert.ok(r.stderr.includes(`\n  ${rel}`), `the message names ${rel}: ${r.stderr}`);
      assert.deepEqual(fs.readdirSync(outside), ['marker.txt'], `${rel}: nothing is written outside`);
      assert.deepEqual(fs.readdirSync(dir), [rel], `${rel}: nothing is written in the target`);
    });
  }
  // A dangling junction at .claude: the folder it names is not created.
  withTargetAndOutside((dir, outside) => {
    fs.symlinkSync(path.join(outside, 'not-yet'), path.join(dir, '.claude'), kind);
    const r = run(dir, '--hardening');
    assert.equal(r.status, 2, r.stdout + r.stderr);
    assert.match(r.stderr, LINKED_RE);
    assert.deepEqual(fs.readdirSync(outside), [], 'the folder the link names is not created');
  });
  // Without links the install and the update run as before.
  withTargetAndOutside((dir) => {
    const first = run(dir, '--hardening');
    assert.equal(first.status, 0, first.stderr);
    const update = run(dir, '--update');
    assert.equal(update.status, 0, update.stderr);
    assert.doesNotMatch(first.stderr + update.stderr, LINKED_RE);
  });
});

// Audit 2026-10-31, third round (R6): a link that stays inside the target (.claude/skills -> ../shared-skills) stops the
// install too, which is meant (the installer manages that path), but the message said the link "could lead a read or a
// write outside" the target, which is not true for it.
test('installer (R6): a link inside the target at a path the installer manages stops the run with a message that says so', (t) => {
  if (!harnessClone) return t.skip('runs only in a clone of the harness (LICENSE at the root)');
  withTargetAndOutside((dir) => {
    fs.mkdirSync(path.join(dir, '.claude'));
    fs.mkdirSync(path.join(dir, 'shared-skills'));
    fs.symlinkSync(path.join(dir, 'shared-skills'), path.join(dir, '.claude', 'skills'), process.platform === 'win32' ? 'junction' : 'dir');
    const r = run(dir);
    assert.equal(r.status, 2, r.stdout + r.stderr);
    assert.match(r.stderr, LINKED_RE);
    assert.doesNotMatch(r.stderr, /could lead a read or a write outside/, 'the link stays inside the target');
    assert.match(r.stderr, /a symbolic link or a junction at a path the installer manages, inside or outside/);
    assert.ok(r.stderr.includes('\n  .claude/skills'), r.stderr);
    assert.match(r.stderr, /Replace each link with the file or folder itself, or install into another folder/);
    assert.deepEqual(fs.readdirSync(path.join(dir, 'shared-skills')), [], 'nothing is written through the link');
  });
});
