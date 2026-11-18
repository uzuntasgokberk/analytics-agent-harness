// The session's project root for the hooks that judge paths (worktree sessions, 2026-11-17). Node built-ins only and no import
// from the pack: an entry script calls prepareSessionRoot() before it first loads common.mjs, which reads the result once when it
// is evaluated (PROJECT_DIR) and hands the payload read here to runHook, so stdin is read once.
//
// A Claude Code session or subagent whose payload `cwd` lies in a linked git worktree <home>/.claude/worktrees/<name> (the
// desktop app's worktree sessions, EnterWorktree, a subagent with worktree isolation) keeps CLAUDE_PROJECT_DIR at the main
// checkout <home>; its files are the worktree's. The worktree is verified from files only: no git process (a git that times
// out would fail open), no environment variable, never the process's own folder or this script's location (the hook process
// runs from the main checkout in the main session and from the worktree in a subagent, measured 2026-11-17). Any check that
// fails, and any read error, leaves the root at <home>, the behaviour before.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// The harness checkout this copy belongs to: common.mjs's fallback for CLAUDE_PROJECT_DIR, computed the same way.
const HARNESS_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');

const state = { prepared: false, raw: undefined, payload: null, home: null, worktreeRoot: null, worktreeName: null };

/** Reads all of stdin as readStdin in common.mjs does: resolves early when nothing arrives (5 s), '' for a terminal. */
function readStdin(timeoutMs = 5000) {
  return new Promise((resolve) => {
    if (process.stdin.isTTY) return resolve('');
    const chunks = [];
    const finish = () => {
      clearTimeout(timer);
      resolve(Buffer.concat(chunks).toString('utf8'));
    };
    const timer = setTimeout(() => {
      process.stdin.destroy();
      finish();
    }, timeoutMs);
    process.stdin.on('data', (chunk) => chunks.push(chunk));
    process.stdin.on('end', finish);
    process.stdin.on('error', finish);
  });
}

const real = (p) => fs.realpathSync.native(p);
/** True when two canonical paths name the same folder (path.relative ignores letter case on Windows). */
const same = (a, b) => path.relative(a, b) === '';
/** The first line of a small text file without a byte order mark and the line break. */
const firstLine = (file) => fs.readFileSync(file, 'utf8').replace(/^﻿/, '').split(/\r?\n/)[0].trim();

/**
 * The verified worktree `cwd` lies in, as `{ root, name }` with `root` canonical, or null. Every check must hold, all on
 * canonical paths (fs.realpathSync.native: links, junctions, letter case, 8.3 names):
 * - `cwd` is absolute and lies in W or below it, W exactly one segment below `home`/.claude/worktrees/, a real folder of `home`
 *   (neither .claude nor worktrees a link elsewhere);
 * - `home`/.git is a directory (lstat: no link);
 * - W/.git is a regular file (lstat: no link, no directory) whose first line is `gitdir: G` (a relative G from W);
 * - canonical G is a direct child of canonical `home`/.git/worktrees/;
 * - the first line of G/gitdir names W/.git (a relative value from G), compared canonically.
 */
export function verifiedWorktree(home, cwd) {
  try {
    if (typeof home !== 'string' || !home || typeof cwd !== 'string' || !cwd.trim() || !path.isAbsolute(cwd)) return null;
    const homeReal = real(home);
    const base = real(path.join(homeReal, '.claude', 'worktrees'));
    if (!same(base, path.join(homeReal, '.claude', 'worktrees'))) return null;
    const rel = path.relative(base, real(cwd));
    if (!rel || rel === '..' || rel.startsWith(`..${path.sep}`) || path.isAbsolute(rel)) return null;
    const name = rel.split(path.sep)[0];
    const root = path.join(base, name);
    const gitHome = path.join(homeReal, '.git');
    if (!fs.lstatSync(gitHome).isDirectory()) return null;
    const dotGit = path.join(root, '.git');
    if (!fs.lstatSync(dotGit).isFile()) return null;
    const pointer = /^gitdir:\s*(.+)$/.exec(firstLine(dotGit));
    if (!pointer) return null;
    const admin = real(path.resolve(root, pointer[1].trim()));
    if (!same(path.dirname(admin), real(path.join(gitHome, 'worktrees')))) return null;
    const back = firstLine(path.join(admin, 'gitdir'));
    if (!back || !same(real(path.resolve(admin, back)), real(dotGit))) return null;
    return { root, name };
  } catch {
    return null;
  }
}

/**
 * Reads the hook payload from stdin once and verifies the worktree its `cwd` names against the main checkout
 * (CLAUDE_PROJECT_DIR, else the harness checkout, as common.mjs reads it). A payload that is not JSON is no error here: the
 * root stays the main checkout and runHook handles the payload as it always did. Never throws. Returns the state.
 */
export async function prepareSessionRoot() {
  if (state.prepared) return sessionRootState();
  state.raw = await readStdin();
  state.prepared = true;
  state.home = path.resolve(process.env.CLAUDE_PROJECT_DIR || HARNESS_ROOT);
  try {
    const parsed = state.raw.trim() ? JSON.parse(state.raw) : null;
    state.payload = parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : null;
    const found = state.payload ? verifiedWorktree(state.home, state.payload.cwd) : null;
    if (found) [state.worktreeRoot, state.worktreeName] = [found.root, found.name];
  } catch {
    // not JSON, or a check that threw: the main checkout stays the root
  }
  return sessionRootState();
}

/** What prepareSessionRoot found: `prepared` false when no entry script called it (the root stays the main checkout). */
export const sessionRootState = () => ({ ...state });
