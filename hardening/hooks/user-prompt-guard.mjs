// UserPromptSubmit: blocks prompts that contain credentials before they reach the model,
// and reminds the model that deployment and publishing are never its own when the user talks about deploying or publishing.
// Under GitHub Copilot a hook cannot be shown to hold a prompt back (copilotNotice), so there it says so instead.

import { appendJsonl, loadConfig, runHook } from './lib/common.mjs';
import { copilotHostOf } from './lib/host-vscode.mjs';
import { findSecrets } from './lib/policy.mjs';
import { foldLatin } from './lib/sql-read.mjs';

const DEPLOY_WORDS = /\b(?:deploy\w*|publish\w*|release|production|prod|git push)\b/i;

/**
 * Text folded for a case-insensitive match that does not depend on the host's locale: accented Latin letters to ASCII
 * as the harness's other folds do (foldLatin in lib/sql-read.mjs: İ, I, ı and i all become i; ş s, é e), then
 * toLowerCase, which lowers by Unicode alone. toLocaleLowerCase lowers by the OS locale: on an en-US host YAYINLA became
 * "yayinla" and missed "yayınla", on a tr-TR host SHIP IT became "shıp ıt" and missed "ship it" (F1-73).
 */
const foldWord = (text) => foldLatin(String(text).normalize('NFKC')).toLowerCase();

/** A team's own words for a deploy, in any language: `deployReminder.extraWords`, matched as case-insensitive text. */
function mentionsDeploy(prompt, extraWords) {
  if (DEPLOY_WORDS.test(prompt)) return true;
  const text = foldWord(prompt);
  return (Array.isArray(extraWords) ? extraWords : []).some(
    (word) => typeof word === 'string' && word.trim() !== '' && text.includes(foldWord(word.trim())),
  );
}

/**
 * What a Copilot host does with this hook's exit 2, from the hosts' own references (F1-99): GitHub's hooks reference
 * (read 2026-10-19) treats exit 2 as a warning for every event but preToolUse and permissionRequest ("stderr is
 * surfaced to the user but the run continues") and drops the output of a config-file userPromptSubmitted hook; VS Code's
 * hooks reference (page dated 10/14/2026) hands stderr of an exit 2 to the model as a blocking error and does not say
 * whether the prompt is withheld. Neither documents a way to hold a prompt back, so the notice never says it was.
 * The Claude registration of .claude/settings*.json carries no host variable and is run by the CLI and by VS Code.
 */
function copilotNotice(host) {
  if (host === 'copilot-cli') {
    return 'GitHub Copilot CLI and the cloud agent cannot hold a message back for a hook: GitHub\'s hooks reference treats exit 2 on a submitted prompt as a warning and the run continues';
  }
  if (host === 'vscode') {
    return 'VS Code\'s hooks reference does not say that a hook can hold a message back (exit 2 hands this notice to the model as a blocking error)';
  }
  return 'GitHub Copilot ran this hook through the Claude registration, and its hooks references do not document a way for a hook to hold a message back (Copilot CLI treats exit 2 on a submitted prompt as a warning and the run continues)';
}

/**
 * The deploy reminder. AGENTS.md: deployment and publishing are never the agent's (it hands the user the steps), a push
 * happens only on the user's explicit request, and a remote model write is Tier 2 (F2-16: the reminder used to call
 * deploy and publish Tier 2, which reads as allowed after a yes).
 */
const DEPLOY_REMINDER =
  "[bi-harness] Reminder: deployment and publishing are never the agent's (AGENTS.md): hand the user the steps. Push only on the user's explicit request and never force-push; a change to a Fabric/Power BI Service item is a remote write (Tier 2): confirm the exact target first. Never bypass hooks.";

await runHook('UserPromptSubmit', async (input) => {
  const prompt = String(input.prompt ?? '');
  const hits = findSecrets(prompt);
  if (hits.length) {
    const ids = [...new Set(hits.map((h) => h.id))];
    const session = String(input.session_id ?? '').slice(0, 8);
    // Copilot through its own hook files (host variable) or through the Claude registration (a `timestamp`).
    const host = copilotHostOf(input);
    if (host) {
      appendJsonl('security-events.jsonl', { event: 'prompt-credential', ids, host, session });
      process.stderr.write(
        `[bi-harness] Credential in your message: it contains what looks like a credential (${ids.join(', ')}). ${copilotNotice(host)}, so treat the message as sent to the model.\n` +
          'Rotate this credential now if it is real, and send it again only masked (e.g. <TOKEN> or ${ENV_VAR}). Keep real credentials in env vars or Power BI data source settings. To the model: tell the user; never repeat, store or use the value.\n',
      );
      // Exit 2 is still the way the notice reaches the user (CLI) or the model (VS Code).
      process.exitCode = 2;
      return null;
    }
    appendJsonl('security-events.jsonl', { event: 'prompt-blocked', ids, session });
    // Exit 2 blocks the prompt and erases it from context; stderr is shown to the user only.
    process.stderr.write(
      `[bi-harness] Message blocked: it contains what looks like a credential (${ids.join(', ')}). It was NOT sent to Claude.\n` +
        'Mask it (e.g. <TOKEN> or ${ENV_VAR}) and send again. Keep real credentials in env vars or Power BI data source settings, and rotate this one if it was real.\n',
    );
    process.exitCode = 2;
    return null;
  }
  if (mentionsDeploy(prompt, loadConfig().deployReminder?.extraWords)) {
    // Under Copilot the reminder cannot reach the model (F2-55): VS Code's hooks reference documents only the common
    // output for UserPromptSubmit (continue, stopReason, systemMessage, page dated 10/14/2026), and GitHub's drops the
    // output of a config-file userPromptSubmitted hook (read 2026-10-19). VS Code shows a systemMessage to the user, so
    // there the user gets it; Copilot CLI shows nothing (documented in docs/harness/other-agents.md).
    const host = copilotHostOf(input);
    return {
      hookSpecificOutput: { hookEventName: 'UserPromptSubmit', additionalContext: DEPLOY_REMINDER },
      ...(host && { systemMessage: `${DEPLOY_REMINDER} (Shown to you: Copilot's hooks cannot add it to the model's context.)` }),
    };
  }
  return null;
});
