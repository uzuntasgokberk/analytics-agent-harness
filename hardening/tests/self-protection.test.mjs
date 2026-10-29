// The pack's self-protection (audit 2026-10-18): the approvals mode every reader must read the same way (F1-44), the hook
// registration the agent may neither weaken nor widen in the settings (F1-45), and the message a broken hook file leaves
// at the moment every tool call is blocked (F1-47). Each case below was a silent pass, or an unusable message, before the fix.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { approvalsWidened, autoApprovalActive, autoApprovalState, labModeActive, loadConfig } from '../hooks/lib/common.mjs';

const pack = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const hooksDir = path.join(pack, 'hooks');
const hook = path.join(hooksDir, 'pre-tool-use.mjs');
const scopeHook = path.join(hooksDir, 'agent-scope.mjs');
const checker = path.join(pack, 'scripts', 'check-hooks.mjs');
// The pack's own registration, as the installer merges it into .claude/settings.local.json: plain shell strings.
const shipped = fs.readFileSync(path.join(pack, 'settings.hooks.json'), 'utf8');

function project(files = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-selfprot-'));
  for (const [rel, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), content);
  }
  return dir;
}
const cleanup = (dir) => fs.rmSync(dir, { recursive: true, force: true });

function runGuard(dir, tool_name, tool_input, { script = hook, args = [], payload = {} } = {}) {
  const r = spawnSync(process.execPath, [script, ...args], {
    input: JSON.stringify({ hook_event_name: 'PreToolUse', session_id: 'selfprot', tool_name, tool_input, ...payload }),
    env: { ...process.env, CLAUDE_PROJECT_DIR: dir },
    encoding: 'utf8',
  });
  const out = r.stdout.trim() ? JSON.parse(r.stdout).hookSpecificOutput : null;
  return { status: r.status, decision: out?.permissionDecision ?? null, reason: out?.permissionDecisionReason ?? '', stderr: r.stderr };
}

// ---------------------------------------------------------------- F1-44: one reading of approvals.mode

const WRONG_MODES = [null, 0, false, [], {}];

test('F1-44: loadConfig reads an approvals.mode that is not a string as ask, the way approvalsOf does', () => {
  for (const mode of WRONG_MODES) {
    const dir = project({ 'hardening/harness.config.json': JSON.stringify({ approvals: { mode } }) });
    try {
      const cfg = loadConfig(dir);
      assert.equal(cfg.approvals.mode, 'ask', JSON.stringify(mode));
      assert.equal(autoApprovalState(cfg).active, false, JSON.stringify(mode));
      assert.equal(autoApprovalActive(cfg), false, JSON.stringify(mode));
      assert.equal(labModeActive(cfg), false, JSON.stringify(mode));
      assert.equal(autoApprovalActive({ approvals: { mode } }), false, `${JSON.stringify(mode)}: the raw object reads the same way`);
    } finally {
      cleanup(dir);
    }
  }
});

test('F1-44: a valid mode, no mode and a mode typo read as before', () => {
  const read = (config) => {
    const dir = project(config === null ? {} : { 'hardening/harness.config.json': JSON.stringify(config) });
    try {
      const cfg = loadConfig(dir);
      return { mode: cfg.approvals.mode, state: autoApprovalState(cfg), lab: labModeActive(cfg) };
    } finally {
      cleanup(dir);
    }
  };
  assert.equal(read(null).state.active, true, 'no config file: auto');
  assert.equal(read({}).state.active, true, 'no approvals key: auto');
  assert.equal(read({ approvals: { until: null } }).state.active, true, 'no mode key: auto');
  assert.equal(read({ approvals: { mode: 'auto' } }).state.active, true);
  assert.equal(read({ approvals: { mode: ' Auto ' } }).state.active, true, 'a spelling with spaces and capitals counts');
  assert.equal(read({ approvals: { mode: 'lab' } }).lab, true);
  assert.deepEqual(read({ approvals: { mode: 'ask' } }).state, { active: false, reason: null });
  const typo = read({ approvals: { mode: 'manual' } });
  assert.equal(typo.state.active, false);
  assert.match(typo.state.reason, /not "auto", "ask" or "lab"/, 'a string typo still says why it is ask');
});

test('F1-44: approvalsWidened agrees with loadConfig: a wrong-shaped mode is never wider than ask', () => {
  const cfg = (mode) => JSON.stringify({ approvals: { mode } });
  for (const mode of WRONG_MODES) {
    const label = JSON.stringify(mode);
    assert.equal(approvalsWidened(cfg('ask'), cfg(mode)), false, `ask to ${label} is a switch to ask`);
    assert.equal(approvalsWidened(cfg('auto'), cfg(mode)), false, `auto to ${label} narrows`);
    assert.equal(approvalsWidened(cfg(mode), cfg('auto')), true, `${label} reads as ask, so auto widens it`);
    assert.equal(approvalsWidened(cfg(mode), cfg('lab')), true, label);
  }
  assert.equal(approvalsWidened(cfg('ask'), cfg('auto')), true);
  assert.equal(approvalsWidened(cfg('ask'), '{}'), true, 'deleting the ask setting still widens (the default is auto)');
  assert.equal(approvalsWidened(cfg('auto'), JSON.stringify({ approvals: { mode: 'auto', until: null } })), false);
  const until = (value) => JSON.stringify({ approvals: { mode: 'auto', until: value } });
  assert.equal(approvalsWidened(until('2026-10-06T18:00:00Z'), until('2026-10-06T20:00:00Z')), true, 'moving until later still widens');
  assert.equal(approvalsWidened(until('2026-10-06T18:00:00Z'), until(null)), true, 'removing until still widens');
  assert.equal(approvalsWidened(until('2026-10-06T20:00:00Z'), until('2026-10-06T18:00:00Z')), false, 'ending auto earlier narrows');
});

test('F1-44: an edit of the harness config from ask to a wrong-shaped mode is a switch to ask, never to auto', () => {
  const ask = `${JSON.stringify({ approvals: { mode: 'ask' } }, null, 2)}\n`;
  for (const bad of ['null', '0', 'false', '[]', '{}']) {
    const dir = project({ 'hardening/harness.config.json': ask });
    const file_path = path.join(dir, 'hardening', 'harness.config.json');
    try {
      assert.equal(runGuard(dir, 'Bash', { command: 'git status' }).decision, null, 'control: ask mode leaves a routine command to Claude Code');
      const edit = runGuard(dir, 'Edit', { file_path, old_string: '"mode": "ask"', new_string: `"mode": ${bad}` });
      assert.notEqual(edit.decision, 'deny', `Edit to ${bad}`);
      const write = runGuard(dir, 'Write', { file_path, content: `{ "approvals": { "mode": ${bad} } }\n` });
      assert.notEqual(write.decision, 'deny', `Write of ${bad}`);
      // What the file holds after the edit: the next call is judged in ask mode, not auto-approved.
      fs.writeFileSync(file_path, ask.replace('"mode": "ask"', `"mode": ${bad}`));
      assert.equal(runGuard(dir, 'Bash', { command: 'git status' }).decision, null, `mode ${bad}: still no auto approval`);
      assert.equal(autoApprovalActive(loadConfig(dir)), false, `mode ${bad}`);
    } finally {
      cleanup(dir);
    }
  }
});

test('F1-44: ask to auto, deleting the ask setting and ask to lab stay denied', () => {
  const ask = `${JSON.stringify({ approvals: { mode: 'ask' } }, null, 2)}\n`;
  const dir = project({ 'hardening/harness.config.json': ask });
  const file_path = path.join(dir, 'hardening', 'harness.config.json');
  try {
    for (const mode of ['auto', 'lab']) {
      assert.equal(runGuard(dir, 'Edit', { file_path, old_string: '"mode": "ask"', new_string: `"mode": "${mode}"` }).decision, 'deny', `Edit to ${mode}`);
    }
    assert.equal(runGuard(dir, 'Write', { file_path, content: '{}\n' }).decision, 'deny', 'Write of {}');
    assert.equal(runGuard(dir, 'Write', { file_path, content: `${JSON.stringify({ approvals: { mode: 'auto' } })}\n` }).decision, 'deny');
  } finally {
    cleanup(dir);
  }
});

// ---------------------------------------------------------------- F1-45: the hook registration

const settingsText = (s) => `${JSON.stringify(s, null, 2)}\n`;
const registration = () => JSON.parse(shipped);
/** The matcher group of an event that runs this script (found by name, so a reordered registration does not matter). */
const groupOf = (s, event, script) => s.hooks[event].find((g) => g.hooks.some((h) => String(h.command).includes(script)));
const eachHook = (s, event, fn) => { for (const group of s.hooks[event]) for (const h of group.hooks) fn(h, group); };
const guardHook = (s) => groupOf(s, 'PreToolUse', 'pre-tool-use.mjs').hooks[0];
const scopeHookEntry = (s) => groupOf(s, 'PreToolUse', 'agent-scope.mjs').hooks[0];

/** Settings changes that switch hooks off without taking a script name out of the file (the record's variants and more). */
const WEAKENINGS = {
  'a matcher that matches nothing': (s) => { groupOf(s, 'PreToolUse', 'pre-tool-use.mjs').matcher = 'NoSuchTool'; },
  'every PreToolUse entry moved to PostToolUse': (s) => { s.hooks.PostToolUse.push(...s.hooks.PreToolUse); s.hooks.PreToolUse = []; },
  'a timeout that always expires': (s) => eachHook(s, 'PreToolUse', (h) => { h.timeout = 0.001; }),
  'a hook type that runs no command': (s) => eachHook(s, 'PreToolUse', (h) => { h.type = 'prompt'; h.prompt = 'ok'; }),
  'a word in front of the command': (s) => { const h = guardHook(s); h.command = `echo ${h.command}`; },
  'an exit status swallowed': (s) => { const h = guardHook(s); h.command = `${h.command} || true`; },
  'the output thrown away': (s) => { const h = guardHook(s); h.command = `${h.command} > /dev/null`; },
  '--mcp-read-only after the scope hook': (s) => { const h = scopeHookEntry(s); h.command = `${h.command} --mcp-read-only`; },
  '--write ** after the scope hook': (s) => { const h = scopeHookEntry(s); h.command = `${h.command} --write **`; },
  'async switched on for a guard': (s) => { guardHook(s).async = true; },
  'an if filter that never matches': (s) => { guardHook(s).if = 'Bash(no-such-command *)'; },
  'once': (s) => { guardHook(s).once = true; },
  'the event name changed': (s) => { s.hooks.pretooluse = s.hooks.PreToolUse; delete s.hooks.PreToolUse; },
  'the timeout of the output masking': (s) => { groupOf(s, 'PostToolUse', 'post-tool-redact.mjs').hooks[0].timeout = 0.001; },
  'the Stop gate matcher': (s) => { groupOf(s, 'SubagentStop', 'stop-gate.mjs').matcher = 'no-such-agent'; },
  'a pack hook removed': (s) => { delete s.hooks.UserPromptSubmit; },
};

test('F1-45: settings edits that switch the pack\'s hooks off without removing a script name are denied', () => {
  for (const [label, weaken] of Object.entries(WEAKENINGS)) {
    for (const file of ['settings.local.json', 'settings.json']) {
      const dir = project({ [`.claude/${file}`]: shipped });
      try {
        const s = registration();
        weaken(s);
        const r = runGuard(dir, 'Write', { file_path: path.join(dir, '.claude', file), content: settingsText(s) });
        assert.equal(r.decision, 'deny', `${label} (${file})`);
        assert.match(r.reason, /harness hook/, `${label} (${file})`);
      } finally {
        cleanup(dir);
      }
    }
  }
});

test('F1-45: the same weakening as an Edit or a MultiEdit of the settings text is denied', () => {
  const dir = project({ '.claude/settings.local.json': shipped });
  const file_path = path.join(dir, '.claude', 'settings.local.json');
  try {
    const s = registration();
    const matcher = `"matcher": "${groupOf(s, 'PreToolUse', 'pre-tool-use.mjs').matcher}"`;
    const edit = { old_string: matcher, new_string: '"matcher": "NoSuchTool"' };
    assert.equal(shipped.split(matcher).length, 2, 'the edit text is in the registration once');
    assert.equal(runGuard(dir, 'Edit', { file_path, ...edit }).decision, 'deny');
    assert.equal(runGuard(dir, 'MultiEdit', { file_path, edits: [edit] }).decision, 'deny');
    const command = `"command": "${scopeHookEntry(s).command}"`;
    const flag = { old_string: command, new_string: `${command.slice(0, -1)} --write **"` };
    assert.equal(shipped.split(command).length, 2, 'the flag edit text is in the registration once');
    assert.equal(runGuard(dir, 'Edit', { file_path, ...flag }).decision, 'deny');
    // A text edit that leaves every hook as it is passes: the permission rules are not the hooks.
    const rule0 = JSON.stringify(s.permissions.allow[0]);
    const rule = { old_string: rule0, new_string: `${rule0}, "Bash(git status *)"` };
    assert.equal(shipped.split(rule0).length, 2, 'the rule edit text is in the registration once');
    assert.notEqual(runGuard(dir, 'Edit', { file_path, ...rule }).decision, 'deny');
  } finally {
    cleanup(dir);
  }
});

test('F1-45: adding hooks, rules and formatting changes keep every pack entry as it is, so they pass', () => {
  const allowed = {
    'a hook group of the user': (s) => { s.hooks.PreToolUse.push({ matcher: 'WebFetch', hooks: [{ type: 'command', command: 'node tools/my-check.mjs', timeout: 5 }] }); },
    'a new event': (s) => { s.hooks.PreCompact = [{ hooks: [{ type: 'command', command: 'echo ok' }] }]; },
    'a second copy of a pack hook': (s) => { s.hooks.Stop.push(structuredClone(groupOf(s, 'Stop', 'stop-gate.mjs'))); },
    'a pack hook in a new matcher group': (s) => { s.hooks.PreToolUse.push({ matcher: 'WebFetch', hooks: [structuredClone(guardHook(s))] }); },
    'a permission rule and a protective deny rule': (s) => { s.permissions.allow.push('Bash(git status *)'); s.permissions.deny = ['Bash(claude --dangerously-skip-permissions*)']; },
    'the groups and keys in another order': (s) => {
      for (const event of Object.keys(s.hooks)) {
        s.hooks[event] = s.hooks[event].reverse().map((g) => ({ ...Object.fromEntries(Object.entries(g).reverse()), hooks: g.hooks.map((h) => Object.fromEntries(Object.entries(h).reverse())) }));
      }
    },
  };
  for (const [label, change] of Object.entries(allowed)) {
    const dir = project({ '.claude/settings.local.json': shipped });
    try {
      const s = registration();
      change(s);
      const r = runGuard(dir, 'Write', { file_path: path.join(dir, '.claude', 'settings.local.json'), content: settingsText(s) });
      assert.notEqual(r.decision, 'deny', label);
    } finally {
      cleanup(dir);
    }
  }
  // Compact formatting of the same registration.
  const dir = project({ '.claude/settings.local.json': shipped });
  try {
    const r = runGuard(dir, 'Write', { file_path: path.join(dir, '.claude', 'settings.local.json'), content: JSON.stringify(registration()) });
    assert.notEqual(r.decision, 'deny', 'compact JSON');
  } finally {
    cleanup(dir);
  }
});

test('F1-45: the controls still deny: a removed entry, bypassPermissions, disableAllHooks, and an empty file', () => {
  const dir = project({ '.claude/settings.local.json': shipped });
  const file_path = path.join(dir, '.claude', 'settings.local.json');
  try {
    const removed = registration();
    removed.hooks.PreToolUse.splice(0, 1);
    const dropped = runGuard(dir, 'Write', { file_path, content: settingsText(removed) });
    assert.equal(dropped.decision, 'deny');
    assert.match(dropped.reason, /removes or repoints a harness hook \(hardening\/hooks\/pre-tool-use\.mjs\)/);
    const bypass = registration();
    bypass.permissions.defaultMode = 'bypassPermissions';
    assert.equal(runGuard(dir, 'Write', { file_path, content: settingsText(bypass) }).decision, 'deny');
    const off = registration();
    off.disableAllHooks = true;
    assert.equal(runGuard(dir, 'Write', { file_path, content: settingsText(off) }).decision, 'deny');
    assert.equal(runGuard(dir, 'Write', { file_path, content: '{}\n' }).decision, 'deny');
  } finally {
    cleanup(dir);
  }
});

test('F1-45: a settings file without the pack\'s hooks, or a new one, is not held to a registration it never had', () => {
  const dir = project({ '.claude/settings.json': '{ "permissions": { "allow": ["Bash(git status *)"] } }\n' });
  try {
    const hooks = { hooks: { PreToolUse: [{ matcher: 'NoSuchTool', hooks: [{ type: 'command', command: 'node tools/my-check.mjs', timeout: 0.001 }] }] } };
    assert.notEqual(runGuard(dir, 'Write', { file_path: path.join(dir, '.claude', 'settings.json'), content: settingsText(hooks) }).decision, 'deny');
    assert.notEqual(runGuard(dir, 'Write', { file_path: path.join(dir, '.claude', 'settings.local.json'), content: settingsText(hooks) }).decision, 'deny');
  } finally {
    cleanup(dir);
  }
});

test('F1-45: the exec form of an older registration, and a Windows path in the command, are held to the same rule', () => {
  const older = settingsText({
    hooks: { PreToolUse: [{ matcher: 'Bash', hooks: [{ type: 'command', command: 'node', args: ['${CLAUDE_PROJECT_DIR}/hardening/hooks/pre-tool-use.mjs'], timeout: 20 }] }] },
  });
  const windows = settingsText({
    hooks: { PreToolUse: [{ matcher: 'Bash', hooks: [{ type: 'command', command: 'node .\\hardening\\hooks\\pre-tool-use.mjs', timeout: 20 }] }] },
  });
  for (const [label, text] of [['args form', older], ['backslash form', windows]]) {
    const dir = project({ '.claude/settings.local.json': text });
    const file_path = path.join(dir, '.claude', 'settings.local.json');
    try {
      const write = (mutate) => {
        const s = JSON.parse(text);
        mutate(s);
        return runGuard(dir, 'Write', { file_path, content: settingsText(s) }).decision;
      };
      assert.equal(write((s) => { s.hooks.PreToolUse[0].hooks[0].timeout = 0.001; }), 'deny', `${label}: timeout`);
      assert.equal(write((s) => { s.hooks.PreToolUse[0].matcher = 'NoSuchTool'; }), 'deny', `${label}: matcher`);
      assert.equal(write((s) => { s.hooks.PreToolUse[0].hooks[0].type = 'prompt'; }), 'deny', `${label}: type`);
      assert.equal(write((s) => { s.hooks.PreToolUse = []; }), 'deny', `${label}: removed`);
      assert.notEqual(write((s) => { s.permissions = { deny: ['Bash(claude --dangerously-skip-permissions*)'] }; }), 'deny', `${label}: a protective rule`);
    } finally {
      cleanup(dir);
    }
  }
});

test('F1-45: agent-scope.mjs takes no scope flags, so an argument cannot replace the configured scopes', () => {
  const dir = project({});
  const reviewer = { agent_type: 'bi-dax-reviewer' };
  try {
    const rm = { command: 'rm notes.txt' };
    const control = runGuard(dir, 'Bash', rm, { script: scopeHook, payload: reviewer });
    assert.equal(control.decision, 'deny', 'control: a reviewer cannot remove a file');
    assert.doesNotMatch(control.reason, /takes no arguments/);
    for (const args of [['--mcp-read-only'], ['--read-only'], ['--write', '**'], ['--write', 'docs/**', '--mcp-read-only']]) {
      const label = args.join(' ');
      for (const [tool, input] of [['Bash', rm], ['Write', { file_path: path.join(dir, 'docs', 'x.md'), content: 'x' }]]) {
        const r = runGuard(dir, tool, input, { script: scopeHook, args, payload: reviewer });
        assert.equal(r.decision, 'deny', `${label}: ${tool}`);
        assert.match(r.reason, /takes no arguments/, `${label}: ${tool}`);
      }
    }
    // The command is wrong, not the call: a call of the main agent is refused too, so the misconfiguration cannot go unseen.
    assert.equal(runGuard(dir, 'Bash', { command: 'git status' }, { script: scopeHook, args: ['--write', '**'] }).decision, 'deny');
    // And without an argument the main agent has no scope.
    assert.equal(runGuard(dir, 'Bash', { command: 'git status' }, { script: scopeHook }).decision, null);
  } finally {
    cleanup(dir);
  }
});

// ---------------------------------------------------------------- F1-47: a broken hook file names itself

/** A copy of the pack's hooks (and, unless left out, the check script) as an installed project holds them. */
function packCopy({ withChecker = true } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-pack-'));
  fs.cpSync(hooksDir, path.join(dir, 'hardening', 'hooks'), { recursive: true });
  if (withChecker) {
    fs.mkdirSync(path.join(dir, 'hardening', 'scripts'), { recursive: true });
    fs.copyFileSync(checker, path.join(dir, 'hardening', 'scripts', 'check-hooks.mjs'));
  }
  return dir;
}
const libFile = (dir, name) => path.join(dir, 'hardening', 'hooks', 'lib', name);
/** Adds a line at the end of a file and returns its line number. */
function appendLine(file, line) {
  const text = fs.readFileSync(file, 'utf8').replace(/\r?\n?$/, '\n');
  fs.writeFileSync(file, `${text}${line}\n`);
  return text.split('\n').length;
}
const payload = JSON.stringify({ hook_event_name: 'PreToolUse', session_id: 'selfprot', tool_name: 'Bash', tool_input: { command: 'git status' } });
const runEntry = (dir, name, input = payload) => spawnSync(process.execPath, [path.join(dir, 'hardening', 'hooks', name)], {
  input, env: { ...process.env, CLAUDE_PROJECT_DIR: dir }, encoding: 'utf8',
});
const runChecker = (dir) => spawnSync(process.execPath, [path.join(dir, 'hardening', 'scripts', 'check-hooks.mjs')], {
  env: { ...process.env, CLAUDE_PROJECT_DIR: dir }, encoding: 'utf8',
});
const ENTRIES = [['pre-tool-use.mjs', 'PreToolUse guard'], ['agent-scope.mjs', 'subagent scope guard']];

test('F1-47: a syntax error in a lib file is named with its file and line by both guard entry scripts; the exit stays 2', () => {
  const dir = packCopy();
  try {
    const line = appendLine(libFile(dir, 'policy.mjs'), 'const broken = ;');
    for (const [entry, who] of ENTRIES) {
      const r = runEntry(dir, entry);
      assert.equal(r.status, 2, entry);
      assert.equal(r.stdout, '', `${entry}: a block prints nothing on stdout`);
      assert.match(r.stderr, new RegExp(`The ${who} could not load \\(hardening/hooks/lib/policy\\.mjs:${line}: SyntaxError: Unexpected token`), r.stderr);
      assert.match(r.stderr, /Find the broken file and line: node hardening\/scripts\/check-hooks\.mjs/, entry);
      assert.ok(!r.stderr.includes('node --check hardening/hooks/lib/*.mjs'), `${entry}: the hint that checks one file only is gone`);
      assert.doesNotMatch(r.stderr, /[A-Za-z]:[\\/]/, `${entry}: no folder of this machine in the message`);
    }
    const c = runChecker(dir);
    assert.equal(c.status, 1, c.stdout + c.stderr);
    assert.match(c.stdout, new RegExp(`^hardening/hooks/lib/policy\\.mjs:${line}: SyntaxError: Unexpected token`, 'm'));
    assert.doesNotMatch(c.stdout, /[A-Za-z]:[\\/]/, 'no folder of this machine in the output');
  } finally {
    cleanup(dir);
  }
});

test('F1-47: a broken common.mjs, which every hook imports, is named by both guard entry scripts', () => {
  const dir = packCopy();
  try {
    const line = appendLine(libFile(dir, 'common.mjs'), 'const broken = ;');
    for (const [entry, who] of ENTRIES) {
      const r = runEntry(dir, entry);
      assert.equal(r.status, 2, entry);
      assert.match(r.stderr, new RegExp(`The ${who} could not load \\(hardening/hooks/lib/common\\.mjs:${line}: SyntaxError`), r.stderr);
    }
  } finally {
    cleanup(dir);
  }
});

test('F1-47: a syntax error in an entry script is named too (node --check reaches every file, not the first one only)', () => {
  const dir = packCopy();
  try {
    const line = appendLine(path.join(dir, 'hardening', 'hooks', 'session-start.mjs'), 'const broken = ;');
    const c = runChecker(dir);
    assert.equal(c.status, 1, c.stdout + c.stderr);
    assert.match(c.stdout, new RegExp(`^hardening/hooks/session-start\\.mjs:${line}: SyntaxError`, 'm'));
  } finally {
    cleanup(dir);
  }
});

test('F1-47: a missing export, a missing file, a deleted guard module and an error at load time are named with the file that holds them', () => {
  const cases = [
    {
      label: 'a missing export',
      break: (dir) => {
        const file = libFile(dir, 'shell-split.mjs');
        const text = fs.readFileSync(file, 'utf8');
        assert.match(text, /export function tokenize\(/);
        fs.writeFileSync(file, text.replace('export function tokenize(', 'function tokenize('));
      },
      want: /hardening\/hooks\/lib\/(?:policy|guard-agent-scope)\.mjs:\d+.*tokenize/,
    },
    {
      label: 'a missing file',
      break: (dir) => fs.rmSync(libFile(dir, 'permissions.mjs')),
      want: /hardening\/hooks\/lib\/(?:guard-pre-tool-use|policy)\.mjs:\d+: it imports \.\/permissions\.mjs, which does not exist/,
    },
    {
      // No module imports the guard of the scope hook but its own entry script, so only the name in that script reveals it.
      label: 'a deleted guard module',
      break: (dir) => fs.rmSync(libFile(dir, 'guard-agent-scope.mjs')),
      entries: [ENTRIES[1]],
      want: /hardening\/hooks\/agent-scope\.mjs:\d+: it imports \.\/lib\/guard-agent-scope\.mjs, which does not exist/,
    },
    {
      label: 'an error at load time',
      break: (dir) => { appendLine(libFile(dir, 'shell-split.mjs'), "throw new Error('load-time failure');"); },
      want: /hardening\/hooks\/lib\/shell-split\.mjs:\d+.*load-time failure/,
    },
  ];
  for (const c of cases) {
    const dir = packCopy();
    try {
      c.break(dir);
      for (const [entry] of c.entries ?? ENTRIES) {
        const r = runEntry(dir, entry);
        assert.equal(r.status, 2, `${c.label}: ${entry}`);
        assert.match(r.stderr, c.want, `${c.label}: ${entry}: ${r.stderr}`);
        assert.doesNotMatch(r.stderr, /[A-Za-z]:[\\/]/, `${c.label}: ${entry}: no folder of this machine`);
      }
      const checked = runChecker(dir);
      assert.equal(checked.status, 1, `${c.label}: ${checked.stdout}${checked.stderr}`);
      assert.match(checked.stdout, c.want, c.label);
    } finally {
      cleanup(dir);
    }
  }
});

test('F1-47: without the check script, or with a broken one, the entry script still blocks (exit 2) and prints the load error itself', () => {
  const missing = packCopy({ withChecker: false });
  const broken = packCopy();
  try {
    appendLine(libFile(missing, 'policy.mjs'), 'const broken = ;');
    appendLine(libFile(broken, 'policy.mjs'), 'const broken = ;');
    appendLine(path.join(broken, 'hardening', 'scripts', 'check-hooks.mjs'), 'const broken = ;');
    for (const dir of [missing, broken]) {
      for (const [entry, who] of ENTRIES) {
        const r = runEntry(dir, entry);
        assert.equal(r.status, 2, entry);
        assert.match(r.stderr, new RegExp(`The ${who} could not load \\(Unexpected token`), r.stderr);
        assert.match(r.stderr, /node hardening\/scripts\/check-hooks\.mjs/, 'the pointer stays');
      }
    }
  } finally {
    cleanup(missing);
    cleanup(broken);
  }
});

test('F1-47: check-hooks.mjs lists every file that does not parse, exits 2 without a hooks folder, and never calls a cut-off check a failure', async () => {
  const dir = packCopy();
  try {
    const inLib = appendLine(libFile(dir, 'policy.mjs'), 'const broken = ;');
    const inEntry = appendLine(path.join(dir, 'hardening', 'hooks', 'stop-gate.mjs'), 'const broken = ;');
    const c = runChecker(dir);
    assert.equal(c.status, 1, c.stdout + c.stderr);
    assert.match(c.stdout, new RegExp(`^hardening/hooks/lib/policy\\.mjs:${inLib}: SyntaxError`, 'm'));
    assert.match(c.stdout, new RegExp(`^hardening/hooks/stop-gate\\.mjs:${inEntry}: SyntaxError`, 'm'));
    assert.match(c.stdout, /2 broken file\(s\), first above/);
    assert.ok(c.stdout.indexOf('lib/policy.mjs') < c.stdout.indexOf('stop-gate.mjs'), 'the modules of lib/ come first');
  } finally {
    cleanup(dir);
  }
  const bare = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-pack-'));
  try {
    fs.mkdirSync(path.join(bare, 'hardening', 'scripts'), { recursive: true });
    fs.copyFileSync(checker, path.join(bare, 'hardening', 'scripts', 'check-hooks.mjs'));
    const r = runChecker(bare);
    assert.equal(r.status, 2, r.stdout + r.stderr);
    assert.match(r.stderr, /hardening\/hooks does not exist/);
  } finally {
    cleanup(bare);
  }
  // A budget that ran out judges nothing: no file is reported as broken, and the hooks' own message falls back to the error.
  const { checkHooks, describeFirstFailure } = await import('../scripts/check-hooks.mjs');
  const cut = await checkHooks({ budgetMs: 0 });
  assert.deepEqual(cut.failures, []);
  assert.equal(cut.incomplete, true);
  assert.equal(await describeFirstFailure({ budgetMs: 0 }), '');
});

test('F1-47: check-hooks.mjs exits 0 on the pack in this repository and on a clean copy, and a healthy entry script is not affected', () => {
  const here = spawnSync(process.execPath, [checker], { encoding: 'utf8' });
  assert.equal(here.status, 0, here.stdout + here.stderr);
  assert.match(here.stdout, /hook files parse and the \d+ modules of hardening\/hooks\/lib load/);
  const dir = packCopy();
  try {
    const copy = runChecker(dir);
    assert.equal(copy.status, 0, copy.stdout + copy.stderr);
    for (const [entry] of ENTRIES) {
      const ok = runEntry(dir, entry);
      assert.equal(ok.status, 0, `${entry}: ${ok.stderr}`);
      assert.doesNotMatch(ok.stderr, /could not load/, entry);
    }
    // A guard that is healthy but gets no payload still fails closed, with its own message (not the load message).
    const empty = runEntry(dir, 'pre-tool-use.mjs', '');
    assert.equal(empty.status, 2);
    assert.match(empty.stderr, /received no payload/);
  } finally {
    cleanup(dir);
  }
});
