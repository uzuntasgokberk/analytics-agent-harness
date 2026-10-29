# Decisions

The durable record of this BI repository: why things are the way they are. `TASKS.md` says what is being done and
`docs/handoff.md` where the last session stopped; this file keeps what must outlive both. Agents add entries and never
rewrite old ones (mark an entry "superseded by D-n" instead). No data values, credentials or personal data.
When this file approaches 500 lines, move the oldest entries unchanged into `docs/decisions/<range>.md` and leave one
link line here; a repository with several reports may keep one file per report in `docs/decisions/`.

**Evidence labels:** `[user]` the user decided or confirmed · `[source]` the source system's or model's definition
(an editor or design view counts) · `[sql]` the source query or view definition · `[output]` a verified result ·
`[image]` a screenshot · `[inference]` the agent's reading of the above, which is not evidence.
Anything resting on `[image]` or `[inference]` is an assumption until something stronger confirms it.

## Decisions

<!-- D-1 · 2026-01-15 · <decision> · why · rejected: <alternatives> · authority: [user] · affects: <files, objects> -->

## Assumptions

<!-- A-1 · <assumption> · based on: [image] / [inference] · confirm with: <test id or question> -->

## Known issues

<!-- K-1 · <difference or limitation> · impact · cause · status: accepted / watching / fixed -->

## Open questions

<!-- Q-1 · <question> · default if unanswered: <recommendation> -->

## Test results

Every row names what ran (the command or the test pack), the commit it ran against, and its evidence label with the
date. NOT RUN and BLOCKED are results too: say why, and what would unblock them.

| Test | What | Result | Evidence |
|---|---|---|---|
<!-- | static | `node hardening/scripts/validate.mjs --changed` at `<hash>` | PASS: 0 errors, 0 warnings | [output] <date> | -->
<!-- | engine | `docs/tests/<model>.dax` at `<hash>`, bounded queries through MCP | PASS: 12 of 12 equal `docs/tests/expected-values.md` | [output] <date> | -->
<!-- | Desktop | `<project>.pbip` opens; page <name> renders | NOT RUN: waiting for the user | none | -->
