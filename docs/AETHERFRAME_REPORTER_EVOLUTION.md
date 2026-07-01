# AetherFrame Reporter Evolution

Status: compatibility plan

## Current reporter

`scripts/aetherframe_factory_cycle.py` is a read-only compatibility reporter. It inspects git state, CI posture, tags, key scripts/folders, release-channel posture, authority boundaries, and lightweight checks. It writes reports under `docs/aetherframe-runs/`.

## What is Factory-specific

- script filename includes `factory`;
- report title says Factory Cycle Report;
- output filenames are `factory-cycle-*.md`;
- legacy references point to Factory docs.

## What is AetherFrame-general

- bounded intake/check/report shape;
- authority-boundary checklist;
- CI/status classification;
- release-channel awareness;
- read-only safety posture;
- no deploy/sign/delete/credential behavior;
- stop before unsafe release claims.

## Migration target

Future tool name: `scripts/aetherframe_advancement_cycle.py`.

The current script may remain as a wrapper for backward compatibility, then call the new project-neutral reporter.

## What should migrate

- read-only posture inspection;
- project metadata;
- boundary checklist;
- channel/gate checklists;
- evidence report writing;
- validation summary;
- stop-condition classification.

## What should remain HexHawk-specific

- GYRE/NEST/TALON/STRIKE/Function Intelligence authority names;
- unsigned early-access release gate details;
- HexHawk installer smoke and Function Notebook proof paths;
- HexHawk website/payment release language.

## What should be configurable per project

- protected authorities;
- release/deploy gates;
- required scripts;
- evidence folders;
- validation commands;
- forbidden actions;
- report template.

## What should never be automated by the reporter

- deletion;
- deployment;
- package upload;
- signing;
- charging money;
- release-candidate/public-release tagging;
- credential use;
- verdict/classification changes.

## Human approval requirements

Require explicit user approval before any destructive or external side effect: delete, move, compress, unregister worktree, deploy, publish, upload, sign, charge, use credentials, or create release-candidate/public-release tags.

## Current compatibility note

The current reporter now labels itself as an AetherFrame Advancement Cycle compatibility reporter while preserving the old command and output path.
