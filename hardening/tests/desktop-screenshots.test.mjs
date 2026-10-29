// The Desktop screenshot switch (desktop.screenshots, 2026-10-15): a Power BI Desktop screenshot shows the data on the
// page, so a company needs a switch for it; before this, `powerbi-desktop screenshot` and `screenshot-all` were routine
// and auto mode ran them without a prompt. "ask" (default, also a missing or unknown value) asks in every approvals
// mode, lab included; "off" denies them (and the report CLI's `preview`, which renders pages); "on" lets auto and lab
// run them and logs each one. Only the user widens the switch; the agent may make it stricter.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { PROJECT_DIR, screenshotsOf, screenshotsWidened } from '../hooks/lib/common.mjs';
import { analyzeShellCommand, routineShell } from '../hooks/lib/policy.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const preHook = path.join(here, '..', 'hooks', 'pre-tool-use.mjs');
const startHook = path.join(here, '..', 'hooks', 'session-start.mjs');

const SHOT = 'powerbi-desktop screenshot all --pid 1 --output-dir C:/tmp';
const SHOT_ALL = 'powerbi-desktop screenshot-all --pid 1 --output-dir C:/tmp';
const shots = (mode) => ({ desktop: { screenshots: mode } });

/** A temporary project with an optional harness config and project settings. */
function project(config, settings) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bi-harness-shots-'));
  fs.mkdirSync(path.join(dir, 'hardening'), { recursive: true });
  if (config) fs.writeFileSync(path.join(dir, 'hardening', 'harness.config.json'), `${JSON.stringify(config, null, 2)}\n`);
  if (settings) {
    fs.mkdirSync(path.join(dir, '.claude'), { recursive: true });
    fs.writeFileSync(path.join(dir, '.claude', 'settings.json'), JSON.stringify(settings));
  }
  return dir;
}

function guard(dir, tool_name, tool_input) {
  const r = spawnSync(process.execPath, [preHook], {
    input: JSON.stringify({ hook_event_name: 'PreToolUse', session_id: 'shots', tool_name, tool_input }),
    env: { ...process.env, CLAUDE_PROJECT_DIR: dir },
    encoding: 'utf8',
  });
  assert.equal(r.status, 0, r.stderr);
  const out = r.stdout.trim() ? JSON.parse(r.stdout).hookSpecificOutput : {};
  const log = path.join(dir, '.claude', 'logs', 'security-events.jsonl');
  const events = fs.existsSync(log) ? fs.readFileSync(log, 'utf8').trim().split('\n').map((l) => JSON.parse(l)) : [];
  return { decision: out.permissionDecision ?? null, reason: out.permissionDecisionReason ?? '', events };
}

/** Runs one shell command through the guard in a fresh project. */
function shell(config, command, settings) {
  const dir = project(config, settings);
  try {
    return guard(dir, 'PowerShell', { command });
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

test('screenshotsOf: trimmed and case-insensitive; missing is the default ask, an unknown value is ask and says so', () => {
  assert.deepEqual(screenshotsOf({}), { mode: 'ask', known: true, raw: undefined });
  assert.deepEqual(screenshotsOf({ desktop: {} }), { mode: 'ask', known: true, raw: undefined });
  assert.equal(screenshotsOf(shots(' On ')).mode, 'on');
  assert.equal(screenshotsOf(shots('OFF')).mode, 'off');
  assert.equal(screenshotsOf(shots('ask')).known, true);
  for (const raw of ['yes', 'true', '', 7, null]) {
    const s = screenshotsOf(shots(raw));
    assert.equal(s.mode, 'ask', JSON.stringify(raw));
    assert.equal(s.known, false, JSON.stringify(raw));
    assert.equal(s.raw, raw);
  }
});

test('policy: off denies, ask (default) is a floor ask, on is a plain ask; options before the subcommand do not hide it', () => {
  for (const cmd of [SHOT, SHOT_ALL, 'powerbi-desktop --pid 1 screenshot all', 'PowerBI-Desktop.exe SCREENSHOT all']) {
    assert.equal(analyzeShellCommand(cmd, { screenshots: 'off' })?.decision, 'deny', cmd);
    for (const ctx of [{}, { screenshots: 'ask' }, { screenshots: 'yes' }]) {
      const v = analyzeShellCommand(cmd, ctx);
      assert.equal(v?.decision, 'ask', cmd);
      assert.equal(v.floor, true, cmd);
      assert.match(v.reason, /desktop\.screenshots is "ask" in hardening\/harness\.config\.json/);
    }
    const on = analyzeShellCommand(cmd, { screenshots: ' On ' });
    assert.equal(on?.decision, 'ask', cmd);
    assert.equal(on.floor, undefined, cmd);
    assert.equal(on.autoApprovable, undefined, cmd);
  }
  for (const cmd of ['powerbi-desktop status', 'powerbi-desktop open "C:/x/Sales.pbip"']) {
    assert.equal(analyzeShellCommand(cmd, { screenshots: 'off' }), null, cmd);
  }
});

test('policy: the report CLI preview is denied while screenshots are off; otherwise its own rules stand', () => {
  for (const cmd of ['powerbi-report-author preview x', 'powerbi-report-author preview ./Sales.Report --host service',
    'powerbi-report-author preview ./Sales.Report --host desktop --reload']) {
    assert.equal(analyzeShellCommand(cmd, { screenshots: 'off' })?.decision, 'deny', cmd);
  }
  for (const mode of [undefined, 'ask', 'on']) {
    assert.equal(analyzeShellCommand('powerbi-report-author preview x', { screenshots: mode }), null, String(mode));
    assert.equal(analyzeShellCommand('powerbi-report-author preview x --host service', { screenshots: mode })?.floor, true, String(mode));
    assert.equal(analyzeShellCommand('powerbi-report-author preview x --reload', { screenshots: mode })?.autoApprovable, false, String(mode));
  }
  assert.equal(analyzeShellCommand('powerbi-report-author validate x', { screenshots: 'off' }), null);
});

test('guard: the default (no config file, or a config without the key) asks, also in auto mode', () => {
  for (const config of [null, { approvals: { mode: 'auto' } }]) {
    for (const cmd of [SHOT, SHOT_ALL]) {
      const r = shell(config, cmd);
      assert.equal(r.decision, 'ask', `${JSON.stringify(config)} ${cmd}`);
      assert.match(r.reason, /desktop\.screenshots is "ask"/);
      assert.match(r.reason, /Critical: auto mode always asks/);
      assert.ok(!r.events.some((e) => e.event === 'auto-approve'));
    }
  }
});

test('guard: ask is a floor ask, so lab mode asks too', () => {
  for (const config of [{ approvals: { mode: 'lab' } }, { approvals: { mode: 'lab' }, ...shots('ask') }, { approvals: { mode: 'lab' }, ...shots('nope') }]) {
    for (const cmd of [SHOT, SHOT_ALL]) {
      const r = shell(config, cmd);
      assert.equal(r.decision, 'ask', `${JSON.stringify(config)} ${cmd}`);
      assert.ok(!r.events.some((e) => e.event === 'lab-approve'));
    }
  }
});

test('guard: off denies in auto, lab and ask mode; status and open are unaffected; preview is denied', () => {
  for (const mode of ['auto', 'lab', 'ask']) {
    const config = { approvals: { mode }, ...shots('off') };
    for (const cmd of [SHOT, SHOT_ALL]) {
      const r = shell(config, cmd);
      assert.equal(r.decision, 'deny', `${mode} ${cmd}`);
      assert.match(r.reason, /screenshots are off/);
    }
    assert.equal(shell(config, 'powerbi-report-author preview x').decision, 'deny', mode);
  }
  const auto = { approvals: { mode: 'auto' }, ...shots('off') };
  assert.equal(shell(auto, 'powerbi-desktop status').decision, 'allow');
  assert.equal(shell(auto, 'powerbi-desktop open "C:/x/Sales.pbip"').decision, 'allow');
});

test('guard: on runs in auto and lab and logs each capture; ask mode prompts', () => {
  // The project's ask rules for the Desktop CLI, as in .claude/settings.json: "on" must still pass in auto mode.
  const settings = { permissions: { ask: ['Bash(powerbi-desktop screenshot *)', 'Bash(powerbi-desktop screenshot-all *)',
    'PowerShell(powerbi-desktop screenshot *)', 'PowerShell(powerbi-desktop screenshot-all *)'] } };
  for (const cmd of [SHOT, SHOT_ALL]) {
    for (const s of [undefined, settings]) {
      const auto = shell({ approvals: { mode: 'auto' }, ...shots('on') }, cmd, s);
      assert.equal(auto.decision, 'allow', `auto ${cmd} ${s ? 'with' : 'without'} settings`);
      assert.match(auto.reason, /auto-approved/);
      assert.ok(auto.events.some((e) => e.event === 'auto-approve' && /desktop\.screenshots is "on"/.test(e.reason)), 'the capture is logged');
    }
    const lab = shell({ approvals: { mode: 'lab' }, ...shots('On') }, cmd);
    assert.equal(lab.decision, 'allow', `lab ${cmd}`);
    assert.ok(lab.events.some((e) => e.event === 'lab-approve'));
    assert.equal(shell({ approvals: { mode: 'ask' }, ...shots('on') }, cmd).decision, 'ask', `ask ${cmd}`);
  }
});

test('screenshotsWidened: off < ask < on; a missing key is ask', () => {
  for (const [before, after, want] of [
    ['ask', 'on', true], ['off', 'ask', true], ['off', 'on', true], ['on', 'ask', false], ['on', 'off', false],
    [undefined, 'on', true], ['on', undefined, false], ['off', undefined, true], [undefined, 'off', false], ['ask', 'ask', false],
    ['nope', 'on', true], ['off', 'nope', true],
  ]) {
    const cfg = (mode) => (mode === undefined ? {} : shots(mode));
    assert.equal(screenshotsWidened(cfg(before), cfg(after)), want, `${before} -> ${after}`);
  }
});

test('guard: the agent cannot widen the switch by editing the config; it may make it stricter', () => {
  const base = { approvals: { mode: 'auto' } };
  const dir = project({ ...base, ...shots('ask') });
  try {
    const file_path = path.join(dir, 'hardening', 'harness.config.json');
    const write = (cfg) => guard(dir, 'Write', { file_path, content: `${JSON.stringify(cfg, null, 2)}\n` });
    const widen = write({ ...base, ...shots('on') });
    assert.equal(widen.decision, 'deny');
    assert.match(widen.reason, /Only the user turns Desktop screenshots on/);
    assert.notEqual(write({ ...base, ...shots('off') }).decision, 'deny');
    assert.equal(write({ ...base, desktop: { screenshots: 'ask', extra: true } }).decision, 'deny'); // other desktop keys stay the user's
    fs.writeFileSync(file_path, `${JSON.stringify({ ...base, ...shots('on') }, null, 2)}\n`); // the user turned it on
    assert.notEqual(write({ ...base, ...shots('ask') }).decision, 'deny');
    assert.notEqual(write({ ...base, ...shots('off') }).decision, 'deny');
    fs.writeFileSync(file_path, `${JSON.stringify({ ...base, ...shots('off') }, null, 2)}\n`);
    assert.equal(write(base).decision, 'deny'); // removing "off" falls back to the default "ask": wider
    fs.writeFileSync(file_path, `${JSON.stringify(base, null, 2)}\n`); // an older config without the key
    assert.notEqual(write({ ...base, ...shots('off') }).decision, 'deny');
    assert.equal(write({ ...base, ...shots('on') }).decision, 'deny');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('session start: the banner names the switch, and an unknown value', () => {
  for (const [config, want] of [
    [null, /Desktop screenshots: ask \(desktop\.screenshots in hardening\/harness\.config\.json\): off = denied/],
    [shots(' ON '), /Desktop screenshots: on \(desktop\.screenshots/],
    [shots('off'), /Desktop screenshots: off \(desktop\.screenshots/],
    [shots('yes'), /Desktop screenshots: ask \(the value "yes" was not recognised, so ask applies\)/],
  ]) {
    const dir = project(config);
    try {
      const r = spawnSync(process.execPath, [startHook], {
        input: JSON.stringify({ hook_event_name: 'SessionStart', source: 'startup', session_id: 'shots' }),
        env: { ...process.env, CLAUDE_PROJECT_DIR: dir },
        encoding: 'utf8',
      });
      assert.equal(r.status, 0, r.stderr);
      assert.match(JSON.parse(r.stdout).hookSpecificOutput.additionalContext, want);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }
});

// Two gaps of the switch, closed 2026-10-16. (1) With "on", `--output <file>` or `--output-dir <dir>` could write the
// image inside the repository, which puts page data into Git (.gitignore ignores only exports/; *.png cannot be ignored,
// StaticResources holds report images): denied in every mode. (2) `npx @microsoft/powerbi-desktop-bridge-cli ...` and
// `npx @microsoft/powerbi-report-authoring-cli ...` were not matched by program name, so neither the switch nor the
// preview rules saw them: they are now judged as `powerbi-desktop` and `powerbi-report-author`.
const MODES = ['off', 'ask', 'on'];
const posix = (p) => p.replace(/\\/g, '/');
const TMP = posix(os.tmpdir());
const verdictOf = (cmd, mode, baseDir = PROJECT_DIR) => analyzeShellCommand(cmd, { screenshots: mode, baseDir });
const shape = (v) => v && { decision: v.decision, floor: v.floor ?? false, autoApprovable: v.autoApprovable ?? true };
const IN_REPO_RE = /a screenshot shows page data; write it to the session's temporary folder or exports\/ \(ignored\), never into the repository/;

test('policy: a screenshot written inside the repository is denied under off, ask and on', () => {
  const inside = [
    'powerbi-desktop screenshot p1 --pid 1 --output docs/p1.png',
    'powerbi-desktop screenshot p1 --pid 1 --output=docs/p1.png',
    'powerbi-desktop screenshot-all --pid 1 --output-dir .',
    'powerbi-desktop screenshot-all --output-dir=shots --pid 1',
    `powerbi-desktop screenshot-all --pid 1 --output-dir "${posix(PROJECT_DIR)}/shots"`,
    'powerbi-desktop --pid 1 --output-dir reports/x screenshot-all',
    'powerbi-desktop screenshot-all --pid 1 --output-dir exports/../docs',
    'powerbi-desktop screenshot p1 --pid 1 --output $out --output-dir docs', // a variable first does not hide the next one
  ];
  for (const mode of [undefined, ...MODES]) {
    for (const cmd of inside) {
      const v = verdictOf(cmd, mode);
      assert.equal(v?.decision, 'deny', `${mode} ${cmd}`);
      assert.match(v.reason, IN_REPO_RE);
    }
  }
  // A relative output starts from the shell's directory.
  const docs = path.join(PROJECT_DIR, 'docs');
  assert.equal(verdictOf('powerbi-desktop screenshot-all --pid 1 --output-dir shots', 'on', docs)?.decision, 'deny');
  assert.equal(verdictOf('powerbi-desktop screenshot-all --pid 1 --output-dir ../exports', 'on', docs)?.decision, 'ask');
});

test('policy: exports/, a folder outside the project and a missing output option follow the switch', () => {
  for (const mode of [undefined, ...MODES, 'nope']) {
    for (const verb of ['screenshot p1', 'screenshot-all']) {
      const bare = shape(verdictOf(`powerbi-desktop ${verb} --pid 1`, mode));
      assert.ok(bare, `${mode} ${verb}`);
      for (const out of ['--output-dir exports', '--output-dir=exports/shots', '--output exports/p1.png', `--output-dir "${TMP}"`,
        `--output="${TMP}/p1.png"`, '--output-dir C:/tmp']) {
        assert.deepEqual(shape(verdictOf(`powerbi-desktop ${verb} --pid 1 ${out}`, mode)), bare, `${mode} ${verb} ${out}`);
      }
    }
  }
});

test('policy: with "on", an output path the guard cannot place (a variable) asks and is never auto-approved', () => {
  for (const out of ['--output-dir $env:TEMP/shots', '--output-dir=$PWD', '--output %TEMP%/p1.png', '--output-dir ~someone/shots']) {
    const cmd = `powerbi-desktop screenshot-all --pid 1 ${out}`;
    assert.deepEqual(shape(verdictOf(cmd, 'on')), { decision: 'ask', floor: false, autoApprovable: false }, cmd);
    assert.equal(verdictOf(cmd, 'off')?.decision, 'deny', cmd);
    assert.equal(verdictOf(cmd, 'ask')?.floor, true, cmd);
  }
  // ~ is the home folder: outside this project, so the switch decides.
  assert.deepEqual(shape(verdictOf('powerbi-desktop screenshot-all --pid 1 --output-dir ~/shots', 'on')), { decision: 'ask', floor: false, autoApprovable: true });
});

// Without --no, npx downloads a missing package into its cache with no prompt (npm docs, npm exec: --yes is assumed
// when standard input is not a TTY), and installing the CLI is the user's (docs/harness/desktop.md). So only an
// installed-only form (--no, or the old --no-install, without --yes) is routine or auto-approved; the switch, the output
// rule and the preview rules judge every form alike.
const installedOnly = (p) => /(?:^|\s)--no(?:-install)?(?:\s|$)/.test(p) && !/(?:^|\s)(?:-y|--yes)(?:\s|$)/.test(p);
const DESKTOP_NPX = ['npx @microsoft/powerbi-desktop-bridge-cli', 'npx.cmd @microsoft/powerbi-desktop-bridge-cli',
  'npx -y @microsoft/powerbi-desktop-bridge-cli@1.2.3', 'npx --yes @microsoft/powerbi-desktop-bridge-cli@latest',
  'npm exec -- @microsoft/powerbi-desktop-bridge-cli', 'npm exec @microsoft/powerbi-desktop-bridge-cli --',
  'npm x -y -- @microsoft/powerbi-desktop-bridge-cli', 'npx -p @microsoft/powerbi-desktop-bridge-cli powerbi-desktop',
  'npx --package=@microsoft/powerbi-desktop-bridge-cli powerbi-desktop', 'C:/nodejs/npx.cmd @Microsoft/PowerBI-Desktop-Bridge-CLI',
  'npx --no -y @microsoft/powerbi-desktop-bridge-cli',
  // installed-only
  'npx --no -q @microsoft/powerbi-desktop-bridge-cli', 'npx --no-install @microsoft/powerbi-desktop-bridge-cli@1.2.3',
  'npm exec --no -- @microsoft/powerbi-desktop-bridge-cli', 'npx --no -p @microsoft/powerbi-desktop-bridge-cli powerbi-desktop'];
const REPORT_NPX = ['npx @microsoft/powerbi-report-authoring-cli', 'npx.cmd -y @microsoft/powerbi-report-authoring-cli@0.5.0',
  'npm exec -- @microsoft/powerbi-report-authoring-cli', 'npx -p @microsoft/powerbi-report-authoring-cli powerbi-report-author',
  // installed-only
  'npx --no @microsoft/powerbi-report-authoring-cli', 'npm x --no-install -- @microsoft/powerbi-report-authoring-cli'];

test('policy: npx forms of the Desktop CLI follow the switch and the output rule; only --no is routine or auto-approved', () => {
  assert.ok(DESKTOP_NPX.some(installedOnly) && DESKTOP_NPX.some((p) => !installedOnly(p)));
  for (const p of DESKTOP_NPX) {
    for (const verb of ['screenshot p1', 'screenshot-all']) {
      const cmd = `${p} ${verb} --pid 1`;
      assert.equal(verdictOf(cmd, 'off')?.decision, 'deny', cmd);
      for (const mode of [undefined, 'ask']) assert.deepEqual(shape(verdictOf(cmd, mode)), { decision: 'ask', floor: true, autoApprovable: false }, `${mode} ${cmd}`);
      assert.deepEqual(shape(verdictOf(cmd, 'on')), { decision: 'ask', floor: false, autoApprovable: installedOnly(p) }, cmd);
      for (const mode of MODES) assert.equal(verdictOf(`${cmd} --output-dir docs`, mode)?.decision, 'deny', `${mode} ${cmd} --output-dir docs`);
    }
    assert.equal(verdictOf(`${p} status`, 'off'), null, p);
    assert.equal(routineShell(`${p} status`, PROJECT_DIR), installedOnly(p), p);
    assert.equal(routineShell(`${p} screenshot-all --pid 1 --output-dir exports`, PROJECT_DIR), installedOnly(p), p); // the switch decides first
    assert.equal(routineShell(`${p} reload --pid 1`, PROJECT_DIR), false, p);
    assert.equal(routineShell(`${p} manifest --pid 1`, PROJECT_DIR), false, p);
  }
  // npx runs a -c/--call command in a shell: it is judged as a nested command when only the CLI package is named.
  for (const call of ['-c "powerbi-desktop screenshot-all --pid 1"', '--call="powerbi-desktop screenshot-all --pid 1"']) {
    for (const p of ['npx -p @microsoft/powerbi-desktop-bridge-cli', 'npx --no -p @microsoft/powerbi-desktop-bridge-cli']) {
      const cmd = `${p} ${call}`;
      assert.equal(verdictOf(cmd, 'off')?.decision, 'deny', cmd);
      assert.equal(verdictOf(cmd, 'ask')?.floor, true, cmd);
      assert.deepEqual(shape(verdictOf(cmd, 'on')), { decision: 'ask', floor: false, autoApprovable: installedOnly(p) }, cmd);
      assert.equal(verdictOf(cmd.replace('--pid 1', '--pid 1 --output-dir docs'), 'on')?.decision, 'deny', cmd);
      assert.equal(routineShell(cmd, PROJECT_DIR), false, cmd);
    }
  }
});

test('policy: npx forms of the report CLI follow the preview rules; only --no is routine', () => {
  assert.ok(REPORT_NPX.some(installedOnly) && REPORT_NPX.some((p) => !installedOnly(p)));
  for (const p of REPORT_NPX) {
    assert.equal(verdictOf(`${p} preview x`, 'off')?.decision, 'deny', p);
    for (const mode of [undefined, 'ask', 'on']) {
      assert.equal(verdictOf(`${p} preview x`, mode), null, `${mode} ${p}`);
      assert.equal(verdictOf(`${p} preview x --host service`, mode)?.floor, true, `${mode} ${p}`);
      assert.equal(verdictOf(`${p} preview x --reload`, mode)?.autoApprovable, false, `${mode} ${p}`);
    }
    for (const mode of MODES) assert.equal(verdictOf(`${p} unpack x`, mode)?.decision, 'deny', `${mode} ${p}`);
    assert.equal(routineShell(`${p} validate x`, PROJECT_DIR), installedOnly(p), p);
    assert.equal(routineShell(`${p} validate x --out r.json`, PROJECT_DIR), false, p);
    assert.equal(routineShell(`${p} preview x`, PROJECT_DIR), false, p);
  }
});

test('policy: npx of any other package is unchanged; a CLI package next to another one asks', () => {
  for (const cmd of ['npx other-pkg screenshot-all --pid 1 --output-dir docs', 'npx powerbi-desktop screenshot all',
    'npx @microsoft/other-cli screenshot all', 'npx @microsoft/powerbi-desktop-bridge-cli-fork screenshot all',
    'npx -p left-pad powerbi-desktop screenshot all', 'npm exec -- left-pad preview x']) {
    for (const mode of [undefined, ...MODES]) assert.equal(verdictOf(cmd, mode), null, `${mode} ${cmd}`);
    assert.equal(routineShell(cmd, PROJECT_DIR), false, cmd);
  }
  for (const cmd of ['npx left-pad', 'npx other-pkg status', 'npx @microsoft/powerbi-desktop-bridge-cli-fork status', 'npm exec -- other status',
    'npx --registry https://registry.example.com other-pkg status']) {
    assert.equal(routineShell(cmd, PROJECT_DIR), false, cmd);
  }
  assert.equal(verdictOf('npx --registry https://registry.example.com other-pkg status', 'off'), null);
  // The bin may come from the other package, or the package from another registry, which the switch cannot judge: the
  // floor asks in every mode, also for a command that would be routine typed as the CLI.
  for (const cmd of ['npx -p @microsoft/powerbi-desktop-bridge-cli -p left-pad powerbi-desktop screenshot-all --pid 1',
    'npx -p left-pad -p @microsoft/powerbi-report-authoring-cli powerbi-report-author preview x',
    'npx -p @microsoft/powerbi-desktop-bridge-cli -p left-pad -c "powerbi-desktop status"',
    'npx --registry https://registry.example.com @microsoft/powerbi-desktop-bridge-cli status',
    'npx --registry=https://registry.example.com -y @microsoft/powerbi-desktop-bridge-cli screenshot-all --pid 1',
    'npm exec --prefix C:/x -- @microsoft/powerbi-report-authoring-cli validate x']) {
    for (const mode of [undefined, ...MODES]) assert.equal(verdictOf(cmd, mode)?.floor, true, `${mode} ${cmd}`);
    assert.equal(routineShell(cmd, PROJECT_DIR), false, cmd);
  }
});

test('guard: output inside the project is denied in auto and lab with "on"; exports/ and the temp folder pass', () => {
  for (const mode of ['auto', 'lab']) {
    const config = { approvals: { mode }, ...shots('on') };
    for (const cmd of ['powerbi-desktop screenshot p1 --pid 1 --output=docs/p1.png', 'powerbi-desktop screenshot-all --pid 1 --output-dir .']) {
      const r = shell(config, cmd);
      assert.equal(r.decision, 'deny', `${mode} ${cmd}`);
      assert.match(r.reason, IN_REPO_RE);
    }
    for (const cmd of ['powerbi-desktop screenshot-all --pid 1 --output-dir exports/shots', `powerbi-desktop screenshot-all --pid 1 --output-dir "${TMP}"`]) {
      assert.equal(shell(config, cmd).decision, 'allow', `${mode} ${cmd}`);
    }
  }
  // A variable output: auto mode asks; lab, the user's test machine, runs it.
  const variable = 'powerbi-desktop screenshot-all --pid 1 --output-dir $env:TEMP/shots';
  assert.equal(shell({ approvals: { mode: 'auto' }, ...shots('on') }, variable).decision, 'ask');
  assert.equal(shell({ approvals: { mode: 'lab' }, ...shots('on') }, variable).decision, 'allow');
  // An absolute path into the project counts like a relative one.
  const dir = project({ approvals: { mode: 'auto' }, ...shots('on') });
  try {
    const r = guard(dir, 'PowerShell', { command: `powerbi-desktop screenshot-all --pid 1 --output-dir "${posix(dir)}/docs/shots"` });
    assert.equal(r.decision, 'deny');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('guard: npx forms follow the switch end to end; without --no auto mode never runs them; another package is unchanged', () => {
  // The project's ask rule for npx, as in .claude/settings.json (settings.hooks.json has none): an installed-only
  // command passes it in auto mode, as it would typed as `powerbi-desktop`; a form that may download the package does
  // not, with or without the rule; another package is not the guard's to approve.
  const settings = { permissions: { ask: ['Bash(npx *)', 'PowerShell(npx *)'] } };
  const shot = (out, opts = '--no') => `npx ${opts} @microsoft/powerbi-desktop-bridge-cli screenshot-all --pid 1 --output-dir ${out}`.replace(/\s+/g, ' ');
  const auto = (mode) => ({ approvals: { mode: 'auto' }, ...(mode ? shots(mode) : {}) });
  const on = shell(auto('on'), shot(`"${TMP}"`), settings);
  assert.equal(on.decision, 'allow');
  assert.ok(on.events.some((e) => e.event === 'auto-approve' && /desktop\.screenshots is "on"/.test(e.reason)), 'the capture is logged');
  assert.equal(shell(auto('on'), shot('exports/shots'), settings).decision, 'allow');
  for (const s of [settings, undefined]) {
    const r = shell(auto('on'), shot(`"${TMP}"`, ''), s);
    assert.equal(r.decision, 'ask', `without --no, ${s ? 'with' : 'without'} the npx rule`);
    assert.match(r.reason, /Without --no, npx downloads the Power BI CLI/);
  }
  assert.equal(shell({ approvals: { mode: 'lab' }, ...shots('on') }, shot(`"${TMP}"`, '-y')).decision, 'allow'); // lab: the user's test machine
  assert.equal(shell(auto('on'), shot('docs'), settings).decision, 'deny');
  assert.equal(shell(auto(), shot(`"${TMP}"`), settings).decision, 'ask');
  assert.equal(shell(auto('off'), shot(`"${TMP}"`), settings).decision, 'deny');
  assert.equal(shell(auto('off'), 'npx -y @microsoft/powerbi-report-authoring-cli preview x', settings).decision, 'deny');
  assert.equal(shell(auto('off'), 'npx --no @microsoft/powerbi-desktop-bridge-cli status', settings).decision, 'allow');
  assert.equal(shell(auto(), 'npx --no @microsoft/powerbi-report-authoring-cli validate x', settings).decision, 'allow');
  assert.equal(shell(auto(), 'npx @microsoft/powerbi-desktop-bridge-cli status', settings).decision, null); // Claude Code's npx rule asks
  assert.equal(shell(auto(), 'npx -y @microsoft/powerbi-report-authoring-cli validate x').decision, null);
  assert.equal(shell(auto('on'), 'npx other-pkg status', settings).decision, null);
});

// Audit 2026-10-18, F1-16: a relative --output was resolved against the payload's folder, ignoring a `cd` earlier in the same
// command, so with "on" `cd exports && powerbi-desktop screenshot --output ../docs/s.png` was auto-approved and the image landed
// inside the repository. A literal cd, pushd, Set-Location, sl, chdir or push-location now moves the folder relative outputs start
// from; a target the guard cannot place (a variable, `cd` alone, `cd -`, ~name, popd, a folder that is not there: a failing cd
// leaves the next command where it was) leaves a relative output unplaceable, which is an ask auto mode never answers.
const SHOT_REL = 'powerbi-desktop screenshot --pid 1 --output';
const bareShape = (mode, out) => shape(verdictOf(`powerbi-desktop screenshot --pid 1 --output "${out}"`, mode));

test('F1-16: a relative screenshot output starts from the folder a literal cd moved to; one that lands inside the repository is denied in every mode', () => {
  // docs/, docs/harness/, templates/ and hardening/ exist in this repository; the folder after each cd is the one the command really runs in.
  const inside = [
    `cd docs && ${SHOT_REL} ../templates/s.png`, `cd docs; ${SHOT_REL}=../templates/s.png`, 'pushd docs; powerbi-desktop screenshot-all --pid 1 --output-dir ../M.Report',
    `Set-Location docs; ${SHOT_REL} ../templates/s.png`, `sl docs; ${SHOT_REL} ../templates/s.png`, `chdir docs; ${SHOT_REL} ../templates/s.png`,
    `push-location docs; ${SHOT_REL} ../templates/s.png`, `Set-Location -Path docs; ${SHOT_REL} ../templates/s.png`, `cd "docs" && ${SHOT_REL} ../templates/s.png`,
    `cd ./docs/ && ${SHOT_REL} ../templates/s.png`, `cd docs/harness && powerbi-desktop screenshot-all --pid 1 --output-dir ../..`,
    `cd docs && cd harness && ${SHOT_REL} ../../templates/s.png`, `cd docs\ncd harness\n${SHOT_REL} ../../templates/s.png`, `cd docs && ${SHOT_REL} s.png`,
    'cd docs && npx --no @microsoft/powerbi-desktop-bridge-cli screenshot --pid 1 --output ../templates/s.png',
    `cd hardening && ${SHOT_REL} ../docs/s.png`, // from a guardrail folder, a relative output is judged where it lands
  ];
  // A nested shell is judged twice (as the outer command line sees it, and from the folder the cd moved to): the verdict is deny in
  // every mode, but with "off" it may be the switch's own reason.
  const nested = [`cd docs && pwsh -c "${SHOT_REL} ../templates/s.png"`, `cd docs && bash -c '${SHOT_REL} ../templates/s.png'`,
    `bash -c "cd docs && ${SHOT_REL} ../templates/s.png"`, `cd docs && eval "${SHOT_REL} ../templates/s.png"`, `cd docs && & { ${SHOT_REL} ../templates/s.png }`];
  for (const mode of [undefined, ...MODES]) {
    for (const cmd of inside) {
      const v = verdictOf(cmd, mode);
      assert.equal(v?.decision, 'deny', `${mode} ${cmd}`);
      assert.match(v.reason, IN_REPO_RE, cmd);
    }
    for (const cmd of nested) assert.equal(verdictOf(cmd, mode)?.decision, 'deny', `${mode} ${cmd}`);
  }
  // The payload's folder is the start: a cd out of it, back to the root and beyond.
  const docs = path.join(PROJECT_DIR, 'docs');
  assert.equal(verdictOf(`cd ../templates && ${SHOT_REL} s.png`, 'on', docs)?.decision, 'deny');
  assert.equal(verdictOf(`cd .. && ${SHOT_REL} s.png`, 'on', docs)?.decision, 'deny', 'the project root');
  assert.equal(verdictOf(`cd ../.. && ${SHOT_REL} s.png`, 'on', docs)?.decision, 'ask', 'two folders up is outside the project');
});

test('F1-16: after a cd out of the project a relative output lands outside it and follows the switch', () => {
  for (const mode of [undefined, ...MODES]) {
    const outside = bareShape(mode, `${TMP}/s.png`);
    assert.ok(outside, mode);
    for (const cmd of [`cd .. && ${SHOT_REL} s.png`, `cd hardening && ${SHOT_REL} ../../s.png`, `Set-Location ..; ${SHOT_REL} s.png`, `cd hardening && ${SHOT_REL} "${TMP}/s.png"`]) {
      assert.deepEqual(shape(verdictOf(cmd, mode)), outside, `${mode} ${cmd}`);
    }
  }
});

test('F1-16: a cd the guard cannot place leaves a relative output unplaceable: an ask auto mode never answers, but still the switch first', () => {
  for (const cd of ['cd $X', 'cd "$HOME/x"', 'cd', 'pushd', 'cd -', 'cd ~someone', 'Set-Location $dir', 'cd "%TEMP%"', 'cd nothing-there-xyz', 'cd hardening/nothing-there', 'cd hardening; popd',
    'cd hardening; Pop-Location', 'cd *', 'pushd +1']) {
    const cmd = `${cd}; ${SHOT_REL} s.png`;
    assert.deepEqual(shape(verdictOf(cmd, 'on')), { decision: 'ask', floor: false, autoApprovable: false }, cmd);
    assert.equal(verdictOf(cmd, 'off')?.decision, 'deny', cmd);
    assert.equal(verdictOf(cmd, 'ask')?.floor, true, cmd);
    // An absolute output does not depend on the folder: the switch decides as if there were no cd.
    assert.deepEqual(shape(verdictOf(`${cd}; ${SHOT_REL} "${TMP}/s.png"`, 'on')), bareShape('on', `${TMP}/s.png`), cmd);
    // A cd the guard can follow again makes it placeable.
    assert.equal(verdictOf(`${cd}; cd ${posix(PROJECT_DIR)}/hardening; ${SHOT_REL} ../docs/s.png`, 'on')?.decision, 'deny', cmd);
  }
  // A path of the home folder is placeable: it is outside the project.
  assert.deepEqual(shape(verdictOf(`cd ~ && ${SHOT_REL} s.png`, 'on')), bareShape('on', `${TMP}/s.png`));
});

test('F1-16: through the hook, the record\'s command is denied, a cd into exports/ lands in the ignored folder, and a missing folder asks', () => {
  const dir = project({ approvals: { mode: 'auto' }, ...shots('on') });
  fs.mkdirSync(path.join(dir, 'exports'));
  fs.mkdirSync(path.join(dir, 'docs'));
  try {
    for (const tool of ['Bash', 'PowerShell']) {
      const denied = guard(dir, tool, { command: `cd exports && ${SHOT_REL} ../docs/s.png` });
      assert.equal(denied.decision, 'deny', tool);
      assert.match(denied.reason, IN_REPO_RE, tool);
    }
    assert.equal(guard(dir, 'PowerShell', { command: `Set-Location exports; ${SHOT_REL} ../docs/s.png` }).decision, 'deny');
    assert.equal(guard(dir, 'Bash', { command: 'pushd exports; powerbi-desktop screenshot-all --pid 1 --output-dir ../M.Report' }).decision, 'deny');
    assert.equal(guard(dir, 'Bash', { command: `${SHOT_REL} docs/shot.png` }).decision, 'deny', 'the control of the record');
    const ignored = guard(dir, 'Bash', { command: `cd exports && ${SHOT_REL} s.png` });
    assert.equal(ignored.decision, 'allow');
    assert.ok(ignored.events.some((e) => e.event === 'auto-approve' && /desktop\.screenshots is "on"/.test(e.reason)), 'the capture is logged');
    for (const command of [`cd missing; ${SHOT_REL} s.png`, `cd $X && ${SHOT_REL} s.png`, `cd exports; popd; ${SHOT_REL} docs/s.png`]) {
      const asked = guard(dir, 'Bash', { command });
      assert.equal(asked.decision, 'ask', command);
      assert.match(asked.reason, /Critical: auto mode always asks/, command);
    }
    assert.equal(guard(dir, 'Bash', { command: `cd exports && ${SHOT_REL} "${TMP}/s.png"` }).decision, 'allow');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// Audit 2026-10-18, F1-59: a CLI's --out aimed at a guardrail file got no verdict, so the shipped allow rule
// Bash(powerbi-report-author validate *) let the shell overwrite the harness's own settings, although a redirect to the same file is
// denied. Every program's --out, --output, --outfile (also with =) is judged like a redirect target.
const GUARDRAIL_FILES = ['.claude/settings.json', '.claude/settings.local.json', '.github/hooks/bi-harness.json', 'hardening/harness.config.json'];
const GUARDRAIL_RE = /Harness guardrail files \(.*cannot be changed from the shell/;

test('F1-59: a CLI --out/--output aimed at a guardrail file is denied for every CLI, like a redirect to the same file', () => {
  for (const p of GUARDRAIL_FILES) {
    const redirect = analyzeShellCommand(`echo {} > ${p}`, {});
    assert.equal(redirect?.decision, 'deny');
    for (const verb of ['validate x.Report', 'formatting x.Report', 'catalog', 'pack x.Report', 'doctor']) {
      for (const opt of [`--out ${p}`, `--out=${p}`, `--output ${p}`, `--output=${p}`, `-out ${p}`, `-OutFile ${p}`, `--outfile=${p}`, `--out "${posix(PROJECT_DIR)}/${p}"`]) {
        const v = analyzeShellCommand(`powerbi-report-author ${verb} ${opt}`, {});
        assert.equal(v?.decision, 'deny', `${verb} ${opt}`);
        assert.match(v.reason, GUARDRAIL_RE, `${verb} ${opt}`);
        assert.equal(routineShell(`powerbi-report-author ${verb} ${opt}`), false, `${verb} ${opt}`);
      }
    }
    for (const cmd of [`powerbi-desktop screenshot --pid 1 --output ${p}`, `powerbi-desktop screenshot-all --pid 1 --output-dir=${p}`, `npx --no @microsoft/powerbi-report-authoring-cli validate x --out ${p}`,
      `sort --output=${p} notes.txt`, `some-tool --out ${p}`, `env CI=1 powerbi-report-author validate x --out ${p}`, `bash -c "powerbi-report-author validate x --out ${p}"`,
      `cd docs && powerbi-report-author validate x --out ../${p}`]) {
      assert.equal(analyzeShellCommand(cmd, { screenshots: 'on' })?.decision, 'deny', cmd);
    }
  }
  assert.match(analyzeShellCommand('powerbi-report-author validate x.Report --out .claude/settings.json', {}).reason, GUARDRAIL_RE);
});

test('F1-59: an output file elsewhere, a read of a guardrail folder and text that only names the option are not guardrail writes', () => {
  assert.equal(analyzeShellCommand('powerbi-report-author validate x.Report --out r.json', {}), null);
  assert.equal(analyzeShellCommand('powerbi-report-author validate hardening/x --out r.json', {}), null, 'a guardrail folder as an input is a read');
  assert.match(analyzeShellCommand('powerbi-report-author validate x --out=docs/r.md', {}).reason, /Edit or Write tool/, 'a guarded file (Markdown) keeps its own deny');
  assert.match(analyzeShellCommand('powerbi-report-author validate x.Report --out x.Report/definition/report.json', {}).reason, /Edit or Write tool/, 'the PBIP deny of the record\'s control');
  for (const cmd of ['powerbi-report-author validate x --out templates/r.json', 'powerbi-report-author validate x --out=reports/R/source/x.json', 'powerbi-report-author validate x --output templates/r.json']) {
    assert.match(analyzeShellCommand(cmd, {}).reason, /reference folder/, `${cmd}: a reference folder is read-only`);
  }
  assert.equal(analyzeShellCommand('powerbi-report-author validate x --out /dev/null', {}), null);
  for (const cmd of ['echo --out .claude/settings.json', 'grep -rn -- --out .claude/settings.json docs', 'git commit -m "--out=.claude/settings.json" --allow-empty',
    'git log --grep=--out']) {
    assert.notEqual(analyzeShellCommand(cmd, {})?.decision, 'deny', cmd);
  }
  // From inside a guardrail folder every relative output file is one; the null device and a file outside are not.
  const inHardening = { baseDir: path.join(PROJECT_DIR, 'hardening') };
  assert.equal(analyzeShellCommand('powerbi-report-author validate x --out r.json', inHardening)?.decision, 'deny');
  assert.equal(analyzeShellCommand('cd hardening && powerbi-report-author validate x --out r.json', {})?.decision, 'deny');
  assert.equal(analyzeShellCommand('powerbi-report-author validate x --out /dev/null', inHardening), null);
  assert.equal(analyzeShellCommand(`powerbi-report-author validate x --out "${TMP}/r.json"`, inHardening), null);
});

test('F1-59: through the hook the record\'s commands are denied even with the shipped allow rules, in auto and ask mode', () => {
  const settings = { permissions: { allow: ['Bash(powerbi-report-author validate *)', 'Bash(powerbi-report-author catalog *)', 'Bash(powerbi-report-author formatting *)',
    'PowerShell(powerbi-report-author validate *)', 'PowerShell(powerbi-report-author catalog *)', 'PowerShell(powerbi-report-author formatting *)'] } };
  for (const config of [{ approvals: { mode: 'auto' } }, { approvals: { mode: 'ask' } }, null]) {
    const dir = project(config, settings);
    try {
      for (const p of GUARDRAIL_FILES) {
        for (const [tool, cmd] of [['Bash', `powerbi-report-author validate x.Report --out ${p}`], ['Bash', `powerbi-report-author validate x.Report --out=${p}`],
          ['PowerShell', `powerbi-report-author formatting x.Report --out ${p}`], ['Bash', `powerbi-report-author catalog --out ${p}`]]) {
          const r = guard(dir, tool, { command: cmd });
          assert.equal(r.decision, 'deny', `${JSON.stringify(config)} ${tool} ${cmd}`);
          assert.match(r.reason, GUARDRAIL_RE);
        }
      }
      assert.equal(guard(dir, 'Bash', { command: 'powerbi-report-author validate x.Report --out r.json' }).decision, null, 'an output file elsewhere is not the guard\'s to judge');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }
});
