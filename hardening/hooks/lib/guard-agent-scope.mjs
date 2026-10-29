// Subagent scope guard (PreToolUse), loaded by hooks/agent-scope.mjs. The scope of the running subagent comes from the
// hook payload's `agent_type` and `agentScopes` in hardening/harness.config.json; the main agent has no scope. The hook's
// command takes no arguments: earlier versions accepted --read-only, --mcp-read-only and --write <glob>, which replaced
// the configured scopes, so an argument added to the command in the settings removed every subagent limit (F1-45).

import { appendJsonl, loadConfig, matchesAny, opaquePath, projectRelForms, runHook } from './common.mjs';
import { analyzeMcpCall, isPowerBiMcp, redirectTargets } from './policy.mjs';
// Quote-aware statements, pipe stages and words: the main policy's (policy.mjs keeps its program-name helpers private).
import { splitSubcommands, tokenize } from './shell-split.mjs';

// A command that still carries an argument is refused on every call, not run without the scopes it asked for.
const strayArgs = process.argv.slice(2);

const WRITE_TOOLS = new Set(['Edit', 'Write', 'NotebookEdit', 'MultiEdit']);
const SHELL_TOOLS = new Set(['Bash', 'PowerShell', 'Monitor']);
// The harness's own read-only checks, run on their own: the static validator, the RDL data layer comparison (F1-54: the
// agents' files and docs/static-checks.md tell them to run it), the hook-pack check (it takes no argument) and the tests.
// An npm check takes words only after `--` (npm reads nothing there): an option before them (--prefix, --node-options)
// runs other code (F1-58). Spaces and tabs only: a line break would let a second command ride along
// (`node hardening/scripts/validate.mjs`, newline, `rm notes.txt`).
const VALIDATION_ONLY = /^[ \t]*(?:npm[ \t]+(?:--prefix[ =]hardening[ \t]+)?(?:run[ \t]+validate(?::[\w-]+)?|test)(?:[ \t]+--(?:[ \t]+[\w:=./*-]+)*)?|node[ \t]+(?:hardening\/)?scripts\/(?:validate|rdl-compare)\.mjs(?:[ \t]+[\w:=./*-]+)*|node[ \t]+(?:hardening\/)?scripts\/check-hooks\.mjs)[ \t]*$/;
// Version probes are harmless and agents run them to learn what is installed.
const PROBE = /^[ \t]*(?:node|npm|npx|python3?|git|powerbi-report-author)[ \t]+(?:--version|-v)[ \t]*$/;
// Writers and state changes. Redirects are judged by their targets (policy.mjs redirectTargets, the one matcher every
// writer check uses), whatever the stream number: `1>`, `2>` and `&>` write like `>`.
const NULL_TARGET_RE = /^(?:\/dev\/null|\$null|nul)$/i;
const MUTATING =
  /\b(?:sed|perl|awk|gawk)\s+(?:-\w*\s+)*-\w*i|\btee\b|\b(?:rm|mv|cp|mkdir|rmdir|touch|chmod|chown|ln|truncate|unlink)\b|\bgit\s+(?:add|commit|push|pull|fetch|reset|checkout|switch|restore|stash|merge|rebase|tag|rm|mv|clean|apply|am|cherry-pick|revert)|\bnpm\s+(?:(?:--prefix|-C|--workspace|-w)[ =]\S+\s+|--?[\w-]+\s+)*(?:i|install|ci|uninstall|update|pkg|exec|run)\b|\bnpx\b|\b(?:node|python3?|pwsh|powershell|bash|sh|zsh)\s+-(?:e|c|command)\b|\b(?:set-content|add-content|out-file|remove-item|move-item|copy-item|new-item|rename-item|clear-content)\b/i;

// The program a subcommand really runs. The patterns above see words; this reads each subcommand the way the main policy
// does (shell-split.mjs: quote-aware statements, pipe stages and words): the program is its name without folder or
// .exe/.cmd/.bat, and `VAR=x`, `env`, `xargs`, `&` and the like are looked through. So `git -C . commit`, `sed s/a/b/ -i f`,
// `node.exe -e`, `ni f` and `xargs rm f` are the changes they are, whatever the spelling.

// Programs that write, move, delete, extract or link files wherever their arguments point: POSIX, cmd and PowerShell
// (cmdlets and their aliases). policy.mjs has the same idea, private (SHELL_WRITERS, DELETE_PROGRAMS); a scope that allows
// no shell write at all needs the longer list.
const WRITERS = new Set([
  'tee', 'rm', 'rmdir', 'unlink', 'shred', 'mv', 'cp', 'ln', 'mkdir', 'mkfifo', 'mknod', 'touch', 'truncate', 'chmod', 'chown', 'chgrp',
  'install', 'patch', 'dd', 'split', 'csplit', 'rename', 'rsync', 'scp', 'ed', 'ex', 'vi', 'vim', 'nvim',
  'tar', 'zip', 'unzip', 'gzip', 'gunzip', 'bzip2', 'bunzip2', 'xz', 'unxz', 'cpio', '7z', '7za', '7zr', '7zz', 'rar', 'unrar',
  'del', 'erase', 'rd', 'md', 'copy', 'xcopy', 'robocopy', 'move', 'ren', 'mklink', 'fsutil', 'attrib', 'icacls', 'takeown', 'cacls',
  'new-item', 'ni', 'set-content', 'sc', 'add-content', 'ac', 'clear-content', 'clc', 'out-file', 'tee-object', 'remove-item', 'ri',
  'copy-item', 'cpi', 'move-item', 'mi', 'rename-item', 'rni', 'expand-archive', 'compress-archive', 'export-csv', 'epcsv',
  'export-clixml', 'set-itemproperty', 'sp', 'new-itemproperty', 'remove-itemproperty', 'set-acl', 'start-transcript',
  'install-module', 'install-package', 'install-script', 'install-psresource', 'save-module', 'save-script', 'save-help',
  'update-help', 'update-module',
]);
// Interpreters, shells and launchers run text the guard cannot read (`node.exe -e`, `py -c`, `cmd /c`, `iex`, `sudo`).
// The harness's own checks and the version probes are exempt (isCheck).
const EXECUTORS =
  /^(?:node(?:js)?|python[\d.]*w?|py|pwsh|powershell(?:_ise)?|bash|sh|zsh|dash|ksh|csh|tcsh|fish|ruby|perl|php|lua|deno|bun|tsx|ts-node|rscript|cmd|wsl|wscript|cscript|mshta|npx|eval|source|invoke-expression|iex|invoke-command|icm|start-process|saps|start|invoke-item|ii|set-alias|sal|new-alias|nal|function|sudo|su|doas|runas)$/;
// A script run by name (./x.sh, .\run.ps1, build.bat) is code the guard cannot read either.
const SCRIPT_FILE = /\.(?:sh|bash|zsh|py|pyw|mjs|cjs|js|ts|ps1|psm1|bat|cmd|vbs|vbe|wsf|rb|pl|php|lua)$/i;
const DOT_PROGRAM = /^(?:\.{1,2}|~)[\\/]/;
// Wrappers that run another program from their arguments (policy.mjs WRAPPERS) and their options that take a value.
const WRAPPERS = new Set(['env', 'command', 'builtin', 'exec', 'nohup', 'time', 'nice', 'timeout', 'xargs', 'stdbuf', 'ionice', 'chrt', 'setsid', 'parallel']);
const WRAPPER_VALUE_OPTS = /^-(?:n|u|s|k|I|L|P|d|E|a|C|-signal|-kill-after|-max-args|-max-procs|-delimiter|-unset|-chdir)$/;
// Shell keywords before a command: `if git commit ...`, `then`, `do`, `!`.
const SHELL_KEYWORDS = new Set(['if', 'then', 'else', 'elif', 'do', 'while', 'until', '!', '{', '(']);
// git subcommands that only report. Every other one (commit, config, init, worktree, notes, an alias, ...) can change files,
// refs or configuration; branch, config, remote, worktree, notes, reflog and submodule have read forms (gitChanges).
const GIT_READ = new Set(['status', 'diff', 'log', 'show', 'ls-files', 'ls-tree', 'rev-parse', 'rev-list', 'describe', 'blame', 'annotate',
  'shortlog', 'grep', 'cat-file', 'check-ignore', 'check-attr', 'merge-base', 'name-rev', 'diff-tree', 'diff-files', 'diff-index',
  'for-each-ref', 'show-ref', 'whatchanged', 'count-objects', 'cherry', 'range-diff', 'show-branch', 'verify-commit', 'verify-tag',
  'ls-remote', 'var', 'version', 'help']);
// Settings that only change how git prints; any other `-c key=value` can name a program git then runs (core.pager,
// core.fsmonitor, alias.*, diff.external, ...).
const GIT_SAFE_CONFIG = /^(?:core\.quotepath|color\.ui|diff\.renames)=/i;
// The long options of `git branch` that change a branch, its upstream or its description (an editor), strictest first.
// git takes any unambiguous prefix of a long option for it (`--edit` is --edit-description, `--unset-u` --unset-upstream),
// so an abbreviation reads as the first of these it begins, as the shell policy reads the judged options of other
// subcommands (policy.mjs spellOutGitOptions); an ambiguous prefix, which git refuses, reads as a change.
const GIT_BRANCH_CHANGES = ['delete', 'move', 'copy', 'force', 'set-upstream-to', 'set-upstream', 'unset-upstream', 'edit-description', 'track', 'no-track', 'create-reflog'];
/** `--unset-u` -> `--unset-upstream`, `--set-upstream-t=x` -> `--set-upstream-to=x`; any other word as written. */
function spellOutBranchOption(word) {
  const m = /^--([A-Za-z][A-Za-z-]*)(=[\s\S]*)?$/.exec(word);
  const full = m ? GIT_BRANCH_CHANGES.find((option) => option.startsWith(m[1].toLowerCase())) : undefined;
  return full ? `--${full}${m[2] ?? ''}` : word;
}
const NPM_READ = new Set(['ls', 'list', 'll', 'la', 'view', 'info', 'show', 'search', 'outdated', 'explain', 'why', 'root', 'prefix', 'bin', 'help']);
// Commands inside $( ), <( ), >( ), @( ), backticks and { } blocks (PowerShell script blocks) are lines of their own.
const NESTED = /[$@<>]\(([^()]*(?:\([^()]*\)[^()]*)*)\)|`([^`\r\n]+)`|\{([^{}]*)\}/g;
// A PowerShell assignment in front of a command (`$x = ni f`, `$null=ri f`, `[string]$x=...`): the command still runs.
const ASSIGNED = /^\s*(?:\[[^\]]*\]\s*)*\$[\w:.{}[\]]+\s*(?:[-+*/%]|\?\?)?=(?!=)\s*/;

/** The program a token names: no folder, no .exe/.cmd/.bat, lower case, PowerShell escape backticks dropped. */
const programName = (token) =>
  String(token ?? '').replace(/`/g, '').replace(/\\/g, '/').split('/').pop().toLowerCase().replace(/\.(?:exe|cmd|bat)$/, '');

/**
 * The words of a subcommand from its program on: group brackets, `VAR=x` and PowerShell `$x =` assignments, shell
 * keywords, the call operators `&` and `.`, and wrappers (`env`, `xargs`, `time`, ...) with their options are looked through.
 */
function commandWords(tokens) {
  const w = [...tokens];
  let i = 0;
  while (i < w.length) {
    w[i] = w[i].replace(/^[({]+(?=.)/, '');
    const t = w[i];
    if (/^[A-Za-z_]\w*=/.test(t) || SHELL_KEYWORDS.has(t) || ((t === '&' || t === '.') && i + 1 < w.length)) i++;
    else if (/^\$[\w:.{}]+$/.test(t) && /^(?:[-+*/%]|\?\?)?=$/.test(w[i + 1] ?? '') && i + 2 < w.length) i += 2;
    else if (WRAPPERS.has(programName(t)) && i + 1 < w.length) {
      i++;
      while (i < w.length - 1 && (w[i].startsWith('-') || /^\d+(?:\.\d+)?[smhd]?$/.test(w[i]) || /^[A-Za-z_]\w*=/.test(w[i]))) {
        i += WRAPPER_VALUE_OPTS.test(w[i]) && i + 2 < w.length ? 2 : 1;
      }
    } else break;
  }
  return w.slice(i);
}

/** True when a git command (its words after `git`) could change files, refs or configuration, or make git run a program. */
function gitChanges(args) {
  let i = 0;
  // Options before the subcommand: -C <dir>, -c <key=value>, --git-dir <dir> and a few more take a value, the rest do not.
  while (i < args.length && args[i].startsWith('-')) {
    if (args[i] === '-c') {
      if (!GIT_SAFE_CONFIG.test(args[i + 1] ?? '')) return true;
      i += 2;
    } else if (/^--(?:config-env|exec-path=)/.test(args[i])) {
      return true;
    } else {
      i += /^(?:-C|--git-dir|--work-tree|--namespace|--super-prefix|--attr-source)$/.test(args[i]) ? 2 : 1;
    }
  }
  const sub = (args[i] ?? '').toLowerCase();
  if (!sub) return false; // `git`, `git --version`, `git -C dir`
  const rest = args.slice(i + 1);
  if (rest.some((a) => /^--output(?:=|$)/.test(a))) return true; // writes the output to a file
  const verb = (rest.find((a) => !a.startsWith('-')) ?? '').toLowerCase();
  const any = (re) => rest.some((a) => re.test(a));
  switch (sub) {
    case 'branch':
      // Renaming, copying, deleting, forcing or retargeting a branch, in any abbreviation; a bare name creates one, unless
      // a listing option makes it a pattern.
      if (rest.map(spellOutBranchOption).some((a) => /^--(?:delete|move|copy|force|set-upstream(?:-to)?|unset-upstream|edit-description|track|no-track|create-reflog)(?:=|$)/.test(a)) || any(/^-[a-zA-Z]*[dDmMcCfut]/)) return true;
      return rest.some((a) => !a.startsWith('-')) && !any(/^(?:--(?:list|contains|no-contains|merged|no-merged|points-at)(?:=|$)|-l$)/);
    case 'config': {
      const reads = any(/^(?:--get(?:-all|-regexp|-urlmatch|-color|-colorbool)?|--list|-l)$/) || verb === 'get' || verb === 'list';
      return !reads || any(/^(?:--unset(?:-all)?|--replace-all|--add|--edit|-e|--rename-section|--remove-section)$/);
    }
    case 'remote': return verb !== '' && verb !== 'show' && verb !== 'get-url';
    case 'worktree': return verb !== 'list';
    case 'notes': return verb !== '' && verb !== 'list' && verb !== 'show';
    case 'reflog': return verb === 'expire' || verb === 'delete';
    case 'submodule': return verb !== '' && verb !== 'status' && verb !== 'summary';
    default: return !GIT_READ.has(sub);
  }
}

/** True when an npm command (its words after `npm`) is anything but a read: install, run, exec, config, publish, ... */
function npmChanges(args) {
  let i = 0;
  while (i < args.length && args[i].startsWith('-')) i += /^(?:--prefix|-C|--workspace|-w|--userconfig|--globalconfig|--registry|--cache|--loglevel|--script-shell)$/.test(args[i]) ? 2 : 1;
  const sub = (args[i] ?? '').toLowerCase();
  return sub !== '' && !NPM_READ.has(sub);
}

/** True when `find` deletes, writes a listing to a file, or runs a command that changes state (-exec, -ok and their variants). */
function findChanges(args) {
  if (args.some((a) => /^-(?:delete|fprint0?|fprintf|fls)$/.test(a))) return true;
  return args.some((a, i) => {
    if (!/^-(?:exec|execdir|ok|okdir)$/.test(a)) return false;
    const end = args.findIndex((b, j) => j > i && (b === ';' || b === '+'));
    return changesState(args.slice(i + 1, end < 0 ? undefined : end));
  });
}

/** True when one subcommand (its words) could change files or git state, or runs code the guard cannot read. */
function changesState(tokens) {
  if (isCheck(tokens)) return false; // a check or probe heads the subcommand itself (no `VAR=x`, no wrapper in front)
  const w = commandWords(tokens);
  if (!w.length) return false;
  // A command chosen at run time (`& $name x`) or a shell function (`q() { ...; }`) hides the program from this reading.
  if (((tokens[0] === '&' || tokens[0] === '.') && /^[$(]/.test(tokens[1] ?? '')) || /^[A-Za-z_][\w-]*\(\)/.test(w[0]) || /^\(\)/.test(w[1] ?? '')) return true;
  const prog = programName(w[0]);
  const args = w.slice(1);
  if (WRITERS.has(prog) || EXECUTORS.test(prog) || SCRIPT_FILE.test(w[0]) || DOT_PROGRAM.test(w[0])) return true;
  switch (prog) {
    case 'git': return gitChanges(args);
    case 'npm': return npmChanges(args);
    case 'sed': return args.some((a) => /^-[a-zA-Z]*i/.test(a) || /^--in-?place\b/.test(a)); // the script may come before -i
    case 'awk': case 'gawk': case 'mawk': case 'nawk': return args.some((a) => /^-i/.test(a) || /^--include\b/.test(a) || /\bsystem\s*\(/.test(a));
    case 'sort': return args.some((a) => /^--output(?:=|$)/.test(a) || /^-[a-zA-Z]*o/.test(a));
    case 'find': return findChanges(args);
    default: return false;
  }
}

/** True when any subcommand of a command line, or any command nested in it, could change state (changesState). */
function shellChanges(line, depth = 0) {
  if (depth > 3) return true; // nested deeper than the guard reads
  return splitSubcommands(line).some((sub) =>
    changesState(tokenize(sub.replace(ASSIGNED, ''))) || [...sub.matchAll(NESTED)].some((m) => shellChanges(m[1] ?? m[2] ?? m[3], depth + 1)));
}

/** A validation run or version probe of the harness (VALIDATION_ONLY, PROBE), whatever the spelling of node and the path (node.exe, .\hardening\scripts\validate.mjs). */
const isCheck = (words) => {
  const text = [programName(words[0]), ...words.slice(1)].join(' ').replace(/\\/g, '/').replace(/^node \.\//, 'node ');
  return VALIDATION_ONLY.test(text) || PROBE.test(text);
};

const deny = (reason) => ({
  hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: `[bi-harness] ${reason}` },
});

await runHook(
  'PreToolUse',
  async (input) => {
    if (strayArgs.length) {
      return deny(`agent-scope.mjs takes no arguments (got: ${strayArgs.join(' ').slice(0, 100)}). Subagent scopes come from agentScopes in hardening/harness.config.json; the flags --read-only, --mcp-read-only and --write were removed because an argument in the hook's command replaced those scopes. Remove the arguments from the hook's command.`);
    }
    const scope = loadConfig().agentScopes?.[input.agent_type];
    if (!scope) return null;
    const readOnly = Boolean(scope.readOnly);
    const mcpReadOnly = readOnly || Boolean(scope.mcpReadOnly);
    const writeGlobs = Array.isArray(scope.write) ? scope.write : [];
    const tool = String(input.tool_name ?? '');
    const ti = input.tool_input ?? {};
    const who = input.agent_type ?? 'This subagent';
    const block = (reason) => {
      appendJsonl('security-events.jsonl', {
        event: 'agent-scope',
        decision: 'deny',
        tool,
        agent: input.agent_type,
        ...(input.agent_id ? { agentId: String(input.agent_id) } : {}),
        session: String(input.session_id ?? '').slice(0, 8),
        reason: reason.slice(0, 300),
      });
      return deny(reason);
    };
    if (mcpReadOnly && tool.startsWith('mcp__')) {
      if (tool.startsWith('mcp__microsoft-learn__')) return null;
      const cfg = loadConfig();
      const verdict = isPowerBiMcp(tool, cfg) ? analyzeMcpCall(tool, ti, cfg) : null;
      if (verdict?.decision !== 'allow') return block(`${who} has read-only MCP access. Return connection changes, writes and unbounded queries to the main agent.`);
      return null;
    }
    if (WRITE_TOOLS.has(tool)) {
      if (readOnly) return block(`${who} is read-only: report the proposed change instead of editing files.`);
      if (writeGlobs.length) {
        const target = ti.file_path ?? ti.notebook_path;
        // Every spelling must stay in scope: a short name (8.3) or a junction can point elsewhere.
        const forms = opaquePath(target) ? [] : projectRelForms(target);
        if (!forms.length || !forms.every((rel) => matchesAny(rel, writeGlobs))) {
          return block(`${who} may only write to ${writeGlobs.join(', ')}; ${forms[0] ?? 'this path'} is out of scope.`);
        }
      }
      return null;
    }
    if ((readOnly || writeGlobs.length) && SHELL_TOOLS.has(tool)) {
      // A lone CR ends a line in PowerShell, so it separates commands here too.
      const command = String(ti.command ?? '').replace(/\r(?!\n)/g, '\n');
      // Arbitrary scripts/interpreters can bypass path-scoped Edit/Write controls.
      const opaqueScript = /\b(?:node|python3?|pwsh|powershell|bash|sh|zsh|ruby|perl)\s|(?:^|\s)(?:\.\.?\/|\/)[^\s]+\.(?:sh|py|mjs|js|ps1)\b/i.test(command);
      const redirects = redirectTargets(command).some((t) => !NULL_TARGET_RE.test(t));
      // A validation run or a version probe passes only as the whole command: a second command, a redirect or an extra
      // line is judged. Everything else is judged by the patterns above and, per subcommand, by what it really runs (F1-46).
      const subs = splitSubcommands(command);
      const alone = subs.length === 1 && isCheck(tokenize(subs[0]));
      if (!alone && (MUTATING.test(command) || redirects || opaqueScript || shellChanges(command))) {
        return block(`${who} must use scoped Edit/Write for changes; this shell command could change files or git state.`);
      }
    }
    return null;
  },
  { failClosed: true },
);
