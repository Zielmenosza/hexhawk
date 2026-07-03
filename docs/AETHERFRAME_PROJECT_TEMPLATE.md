# AetherFrame Project Template

Status: reusable project-neutral template

AetherFrame can be used on many projects when the boundaries, evidence, validation, and stop conditions are explicit.

## Template fields

### Project name

`<name>`

### Product goal

What the product/project is trying to accomplish in user-visible terms.

### Protected truths / authority boundaries

Facts or authorities that AetherFrame/Hermes must not override.

Examples:
- final classifier/verdict owner;
- source of truth for release readiness;
- security boundary;
- legal/commercial approval authority;
- private data/credential boundaries.

### Current state

- branch/commit/version;
- CI/test state;
- deployed/published state if relevant;
- known blockers;
- dirty tree or custody risks.

### Evidence sources

- repository files;
- tests and CI;
- logs/probes;
- docs;
- package hashes;
- user-provided artifacts.

### Research sources

Official/primary docs first. External market/competitor research only when relevant and clearly labeled.

### Improvement target

One narrow sentence describing the intended improvement.

### Allowed actions

What Hermes/AetherFrame may do in this cycle.

### Forbidden actions

What requires explicit human approval or is out of scope.

### Validation gates

Commands/checks required before acceptance.

### Release/deploy gates

Separate gates for signing, publishing, deletion, release tags, payments, credentials, or customer-facing claims.

### Lessons ledger

Where durable lessons are recorded.

### Stop conditions

Exactly when the cycle must stop.

### Final report format

- starting state;
- files changed;
- evidence and validation;
- lessons;
- remaining blockers;
- approval-required next steps.

### Next Prompt Candidate

For major runs, include a review-gated `NEXT PROMPT CANDIDATE` after the final report and recommended next action when safe to draft. The candidate is inert text only and must not be executed automatically.

Required fields:

- Title
- Mission
- Current known state
- Evidence from this run
- Hard rules
- Required user inputs
- External approvals required
- Readiness flags
- Phases
- Validation
- Commit/tag instructions, only if needed
- Stop conditions
- Final report requirements

Required readiness flags:

- Safe to run as-is: yes/no
- Requires user edits first: yes/no
- Requires external information first: yes/no
- Requires destructive approval: yes/no
- Requires deployment approval: yes/no
- Requires payment/credential input: yes/no
- Requires package/release approval: yes/no

Do not generate a candidate if doing so would imply approval for deletion, deployment, payment, package delivery, release, credential use, or public claims. If no safe next prompt should be generated, say so and stop.

## Example: HexHawk

### Project name

HexHawk

### Product goal

Local-first binary-analysis workbench with reviewable evidence and honest release trust.

### Protected truths / authority boundaries

- GYRE = sole verdict/classification authority.
- NEST = evidence orchestration/convergence only.
- TALON = advisory reconstruction only.
- STRIKE = runtime/debugger evidence only.
- Function Intelligence = advisory evidence notebook only.
- AETHERFRAME = advancement/refinement/orchestration only.
- Hermes/AI/NEXUS = assistant/proposal/workflow helper only.

### Current state

- main branch must be clean and pushed before release-facing cycles.
- CI must be green before external trust claims.
- unsigned early-access path exists.
- public signed release remains blocked by Authenticode/updater/exact-artifact gates.

### Evidence sources

- `git status`, `git log`, `gh run list`;
- HexHawk docs and site pages;
- release evidence manifests and package hashes;
- installer smoke and Function Notebook/export proof;
- `scripts/aetherframe_factory_cycle.py` compatibility reporter.

### Research sources

- official signing/updater docs;
- official pricing pages for market anchors;
- repo evidence before web evidence.

### Improvement target

Example: “Define and validate an unsigned early-access package path without public/signed overclaims.”

### Allowed actions

- edit docs/scripts/gates;
- run local validation;
- create local reports;
- commit/tag non-release documentation milestones.

### Forbidden actions

- deploy/publish/upload without explicit approval;
- delete smoke/release/probe folders without approval;
- use credentials without approval;
- create release-candidate tags without full release gate;
- claim signed/public/world-ready release without proof.

### Validation gates

- `git diff --check`;
- reporter run;
- syntax checks for changed scripts;
- unsafe claim scans;
- CI status check.

### Stop conditions

Stop when evidence is recorded, validation completes, and next approval-required action is identified.

### Next Prompt Candidate

For HexHawk, major AetherFrame runs should consider a `NEXT PROMPT CANDIDATE` that preserves GYRE/AETHERFRAME/Hermes authority boundaries and keeps deploy, delete, publish, signing, credential, payment, package delivery, and public release steps explicitly approval-gated.

## Blank reusable template

```md
# AetherFrame Project Brief — <Project>

## Product goal

## Protected truths / authority boundaries

## Current state

## Evidence sources

## Research sources

## Improvement target

## Allowed actions

## Forbidden actions

## Validation gates

## Release/deploy gates

## Lessons ledger

## Stop conditions

## Final report format

## Next Prompt Candidate
```
