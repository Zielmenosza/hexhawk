# AetherFrame Next Prompt Protocol

Status: review-gated handoff protocol

## Purpose

A `NEXT PROMPT CANDIDATE` is a safe handoff draft that can help maintain momentum after a major Hermes/AetherFrame run. It is inert text only.

It does not execute automatically. It does not create an autonomous loop. It does not assume approval. It requires user review before use.

The generated prompt is a proposal, not an instruction already approved.

A bad next prompt is one that assumes permission. A good next prompt makes missing approvals obvious.

## When to generate one

Hermes should always consider producing a `NEXT PROMPT CANDIDATE` at the end of a major AetherFrame run, after the final report and recommended next action.

Generate one after major runs such as:

- release/package work;
- website/payment work;
- cleanup/provenance work;
- CI/fix work;
- AetherFrame advancement cycles.

Do not force one when:

- the run failed at preflight;
- the task was only a narrow verification;
- the safest next step is to wait for user input;
- generating a prompt would encourage deletion, deployment, payment, package delivery, release, or credential use without approval.

If no safe next prompt should be generated, say so explicitly using a `NO SAFE NEXT PROMPT` outcome and stop.

## No Safe Next Prompt outcomes

At the end of a major run, choose exactly one:

- `NEXT PROMPT CANDIDATE` — safe to draft for later human review.
- `NO SAFE NEXT PROMPT — waiting for user input` — the next step depends on missing user-provided information.
- `NO SAFE NEXT PROMPT — approval gate reached` — the next step is deployment, deletion, payment, package delivery, release, credential handling, or another approval-gated action.
- `NO SAFE NEXT PROMPT — preflight/CI failed` — the current run did not establish a safe baseline.
- `NO SAFE NEXT PROMPT — prompt would encourage unsafe escalation` — drafting the prompt would make an unapproved dangerous action too easy.

A `NO SAFE NEXT PROMPT` outcome should still include the reason, missing input or approval, and safest human next action.

## Required final-run handoff shape

Every major Hermes/AetherFrame run should end with:

1. Final report.
2. Recommended next action.
3. `NEXT PROMPT CANDIDATE`, if safe to draft.
4. Readiness flags.
5. Stop.

Hermes must never execute the generated prompt automatically.

## Required section name

Use exactly this section heading:

```md
## NEXT PROMPT CANDIDATE
```

## Required fields

Every candidate should include:

- Title
- Mission
- Current known state
- Evidence from this run
- Hard rules
- Required user inputs
- External approvals required
- Phases
- Validation
- Commit/tag instructions, only if needed
- Stop conditions
- Final report requirements

## Required readiness fields

Every candidate must include these readiness flags:

- Safe to run as-is: yes/no
- Requires user edits first: yes/no
- Requires external information first: yes/no
- Requires destructive approval: yes/no
- Requires deployment approval: yes/no
- Requires payment/credential input: yes/no
- Requires package/release approval: yes/no

Use `no` for `Safe to run as-is` whenever required inputs are placeholders, approvals are missing, or the next step touches payment, deployment, deletion, credentials, package delivery, release, or public claims.

## Safety rules

- If the next step requires a payment link, use a placeholder such as `<PASTE_REAL_PUBLIC_PAYMENT_OR_INVOICE_URL_HERE>`.
- If the next step requires credentials, do not ask Hermes to fetch or reveal them. Require user-provided non-secret public values where possible, and stop before secret handling unless explicitly approved for that session.
- If the next step requires deletion, the prompt must require explicit exact-path approval before any destructive command.
- If the next step requires deployment, the prompt must require explicit deploy approval and a separate validation gate.
- If the next step requires package delivery, the prompt must require exact package verification and private fulfillment records.
- If the next step requires public release, the prompt must require signed release gates, exact-artifact proof, signing/updater validation, and public-trust approval.
- If the next step requires payment operations, the prompt must not create real payment links unless the user provides or approves them.
- If the next step involves website changes, the prompt must separate local edit/validation from deployment approval.
- If the next step involves early-access packages, the prompt must not expose the ZIP publicly.

## Autonomous-loop prevention

A `NEXT PROMPT CANDIDATE` is never a recursive instruction. It must not ask Hermes to run itself, schedule itself, call Hermes recursively, auto-continue, or bypass human review.

Human review remains the boundary between cycles. The user may edit, reject, defer, or paste the candidate into a later session.

## Authority boundaries

For HexHawk:

- GYRE remains the sole verdict/classification authority.
- AETHERFRAME remains advisory advancement/process support only.
- Hermes/AI remains an assistant/proposal/workflow helper only.

A next prompt may preserve and cite these boundaries, but it must not promote AETHERFRAME or Hermes into release, verdict, payment, or deployment authority.

## Minimal template

```md
## NEXT PROMPT CANDIDATE

Title: <short title>

Mission:
<one bounded mission>

Current known state:
- <state item>

Evidence from this run:
- <commit/tag/CI/report/file evidence>

Hard rules:
- Do not execute this generated prompt automatically.
- Do not assume user approval.
- Do not deploy, delete, publish, sign, upload, use credentials, charge money, or deliver packages unless the prompt explicitly includes the required approval gate and the user supplies approval.
- Preserve project authority boundaries.

Required user inputs:
- <input or none>

External approvals required:
- <approval or none>

Readiness flags:
- Safe to run as-is: no
- Requires user edits first: yes
- Requires external information first: yes
- Requires destructive approval: no
- Requires deployment approval: no
- Requires payment/credential input: no
- Requires package/release approval: no

Phases:
1. State check.
2. Implement bounded change or stop at approval gate.
3. Validate.
4. Report.

Validation:
- git diff --check
- <targeted checks>

Commit/tag instructions, only if needed:
- <commit/tag instructions or "No commit/tag unless files changed and validated.">

Stop conditions:
- Stop if required user input is missing.
- Stop before approval-gated actions.
- Stop after final report.

Final report requirements:
- Evidence.
- Files changed.
- Validation.
- Guardrail confirmations.
- Recommended next action.
- NEXT PROMPT CANDIDATE if safe to draft.
```
