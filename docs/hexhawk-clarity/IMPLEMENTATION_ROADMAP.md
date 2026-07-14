# HexHawk Clarity Implementation Roadmap

Last updated: 2026-07-14

Project persistence, reliable reopen, recorded-snapshot provenance, binary isolation, restart/cache-clear recovery, and Windows MSI/NSIS packaging are completed source/package milestones. Remaining release work is controlled installed-artifact acceptance, signing, exact signed-artifact updater validation, hosted publication, support readiness, and broader decompiler/debugger/plugin maturity. Exploitability Mode remains backlog unless repository code and tests independently prove shipment. See [`../CURRENT_STATUS.md`](../CURRENT_STATUS.md) and [`../../ROADMAP.md`](../../ROADMAP.md).

Status: staged roadmap only
Scope: small, reviewable slices for clarity, usability, and ProgramAnalysis convergence
No code is implemented by this document

## Complete current workflow in plain language

1. Open or import the binary.
2. Establish its byte identity rather than trusting path/name.
3. Collect evidence with source and proof limits.
4. Let GYRE record the authoritative classification/base-verdict snapshot.
5. Save binary, session, and snapshot linkage in the versioned project.
6. Reopen by verifying identity and resolving the backend-recorded snapshot; reject stale, malformed, unsupported, mismatched, or cross-binary authority.
7. Attach NEST's advisory lifecycle/evidence context without giving NEST verdict authority.
8. Keep AI, AETHERFRAME, and NEXUS optional, bounded, and unable to mutate authority.
9. Preserve recorded-snapshot provenance in report/export output.
10. Produce an explicit limitation or summary-only result when authority is missing; never silently fall back.

## Roadmap rules

- Do not run `git add -A`.
- Do not mix clarity work with cleanup, release, site-build, AetherFrameGuard, AetherFrame Studio, Android Hermes access, private Hermes access, APKs, generated SDK/toolchain folders, or package-manager drift.
- Keep every phase small enough to review.
- Preserve GYRE as sole verdict authority.
- Keep NEST, AETHERFRAME/Forge, TALON, STRIKE, and NEXUS advisory or evidence-only according to their boundary.
- Do not claim recovered source, dynamic truth, malware detonation, or decompiler correctness.

## Phase 1 — Product language guide and authority banner copy

Goal:
- Establish task-first language and reusable trust-boundary banners without changing behavior.

Likely files:
- `docs/hexhawk-clarity/PRODUCT_LANGUAGE_GUIDE.md`
- Later, after approval only: a new source file such as `HexHawk/src/utils/productLanguage.ts` or `HexHawk/src/utils/authorityBanners.ts`

Expected diff size:
- Docs-only: small/medium.
- Later constants file: small, 100-200 lines.

Validation commands:
- `git diff --check -- docs/hexhawk-clarity/PRODUCT_LANGUAGE_GUIDE.md`
- Later code slice: `yarn test -- productLanguage` if tests are added.

Tests:
- Constants unit test for required dual labels.
- String tests that authority banners mention GYRE/NEST/AETHERFRAME/TALON/STRIKE/NEXUS boundaries accurately.
- Search test for banned overclaim phrases.

Rollback gate:
- `docs.dualLabels.enabled` for documentation/copy rollout.

Trust-boundary risks:
- Simplified labels may hide internal authority. Mitigation: keep secondary labels in tooltips, docs, and exports.

What not to touch:
- `README.md`
- `site-build/**`
- `App.tsx`
- package files
- release/trust/private paths

## Phase 2 — Feature flags and glossary constants

Goal:
- Add stable flags and label/banner constants before UI restructuring.

Likely files:
- New `HexHawk/src/utils/featureFlags.ts` or existing feature-flag utility if one exists.
- New `HexHawk/src/utils/productLanguage.ts`.
- Focused tests under `HexHawk/src/utils/__tests__/`.

Expected diff size:
- Small, 150-300 lines including tests.

Validation commands:
- `yarn test -- featureFlags productLanguage`
- `yarn typecheck`

Tests:
- Default flags are conservative/off for new behavior.
- Dual-label strings match the product language guide.
- Authority banners include `not verdict authority` or equivalent for advisory surfaces.

Rollback gate:
- All new UI behavior off by default except docs-only copy flags if explicitly approved.

Trust-boundary risks:
- A flag must not disable boundary warnings in high-assurance mode.

What not to touch:
- Existing engine algorithms.
- Existing report export behavior.
- Package manager files.

## Phase 3 — ProgramAnalysis adapter behind existing UI

Goal:
- Make `ProgramAnalysis` the canonical analysis substrate behind the scenes without visible UI changes.

Likely files:
- `HexHawk/src/utils/disassemblyModel.ts`
- `HexHawk/src/utils/disassemblyAnalysis.ts`
- New adapter file such as `HexHawk/src/utils/programAnalysisAdapter.ts`
- Focused tests under `HexHawk/src/utils/__tests__/`
- Minimal, guarded integration point in `App.tsx` only after explicit approval; avoid broad rewrite.

Expected diff size:
- Medium, 300-600 lines including tests.

Validation commands:
- `yarn test -- disassemblyAnalysis programAnalysisAdapter`
- `yarn typecheck`

Tests:
- Function count/start/end parity against existing UI-local logic on synthetic fixtures.
- Xref parity for call, jump, conditional jump, data-like refs where supported.
- Execution block parity for simple branch/return/function fixtures.
- Warning generation for uncertain starts/ends and unresolved targets.
- Authority marker test: `ProgramAnalysis.authority === 'analysis_evidence_not_gyre_verdict'`.

Rollback flags:
- `analysis.programDb.enabled`
- `analysis.programDb.parityChecks.enabled`

Trust-boundary risks:
- ProgramAnalysis could be mistaken for verdict evidence. Mitigation: keep `advisoryOnly: true`, authority marker, and no report/verdict mutation.

What not to touch:
- Visible navigation labels.
- Verdict computation.
- Report export.
- Runtime debugger behavior.
- App.tsx thinning.

## Phase 4 — Code map function/xref browser

Goal:
- Expose Code map as the simple workspace for functions, linked references, execution blocks, imports, strings, and uncertainty.

Likely files:
- `HexHawk/src/components/FunctionBrowser.tsx`
- `HexHawk/src/components/XRefPanel.tsx`
- `HexHawk/src/components/DisassemblyList.tsx`
- `HexHawk/src/components/EnhancedInstructionRow.tsx`
- New `CodeMapWorkspace` component only after adapter parity is proven.
- `WorkflowNav.tsx` label changes behind flag.

Expected diff size:
- Medium, 400-800 lines depending on component extraction.

Validation commands:
- `yarn test -- codeMap functionBrowser xref`
- `yarn typecheck`

Tests:
- Code map renders Function records, Linked references, Execution blocks labels under flag.
- Existing Disassembly/CFG behavior remains reachable when flag is off.
- Address selection navigates consistently across list, functions, references, and blocks.
- Uncertainty/warnings are visible for inferred function/block evidence.

Rollback flag:
- `ui.codeMap.browser.enabled`

Trust-boundary risks:
- Users may treat inferred function/block boundaries as proven. Mitigation: show Maturity & limits / warnings near uncertain boundaries.

What not to touch:
- TALON logic internals.
- STRIKE/debugger behavior.
- Report export schema.

## Phase 5 — Logic overlay and maturity panel simplification

Goal:
- Make decompiler/TALON outputs understandable as advisory logic, not source recovery.

Likely files:
- `HexHawk/src/components/DecompilerView.tsx`
- `HexHawk/src/components/TalonView.tsx`
- `HexHawk/src/utils/decompilerMaturity.ts`
- `HexHawk/src/utils/decompilerEngine.ts`
- Tests for decompiler maturity/export helpers.

Expected diff size:
- Medium, 300-700 lines.

Validation commands:
- `yarn test -- decompiler maturity talon`
- `yarn typecheck`

Tests:
- Maturity & limits panel labels replace internal-first wording under flag.
- Raw IR remains accessible as advanced details.
- Maturity JSON/Markdown retains advisory authority markers.
- Pseudocode copy includes not recovered source / not verdict authority boundary.
- LLM refinement/type inference remains approval-gated and cannot mutate verdict fields.

Rollback flag:
- `talon.maturityPanel.v2.enabled`

Trust-boundary risks:
- `Confidence` can be confused with GYRE confidence. Mitigation: label as `Advisory confidence` in Logic surfaces.

What not to touch:
- Verdict computation.
- GYRE confidence math.
- AETHERFRAME report refinement.

## Phase 6 — Runtime evidence workspace

Goal:
- Merge recorded traces and live debugger sessions under one user-facing Runtime evidence workspace.

Likely files:
- `HexHawk/src/components/StrikeView.tsx`
- `HexHawk/src/components/DebuggerPanel.tsx`
- `HexHawk/src/utils/traceModel.ts`
- `HexHawk/src/utils/traceCorrelation.ts`
- New wrapper component such as `RuntimeEvidenceWorkspace.tsx`.

Expected diff size:
- Medium/large, 500-1000 lines if wrapper and tests are included.

Validation commands:
- `yarn test -- strike trace runtime`
- `yarn typecheck`

Tests:
- Recorded runtime evidence import still parses `hexhawk.trace.v1`.
- Runtime-to-code links retain `runtime_trace_correlation_not_gyre_verdict`.
- Live session controls remain explicit and do not auto-run.
- UI labels distinguish Recorded runtime evidence from Live session.
- No copy claims malware detonation, dynamic truth, or verdict mutation.

Rollback flags:
- `runtime.evidence.workspace.enabled`
- `runtime.traceCorrelation.v2.enabled`

Trust-boundary risks:
- Runtime evidence can sound stronger than static evidence. Mitigation: every runtime section says advisory evidence, not verdict by itself.

What not to touch:
- Rust debugger command semantics.
- Release/trust docs.
- Site-build.
- APK/private Hermes files.

## Phase 7 — Evidence/report envelope unification

Goal:
- Unify exports around one defensible evidence envelope while preserving GYRE authority.

Likely files:
- `HexHawk/src/components/IntelligenceReport.tsx`
- NEST export components/utilities if present.
- `HexHawk/src/utils/aetherframeReportRefinementAdapter.ts`
- New evidence envelope types/helpers.
- Focused tests around report/export authority.

Expected diff size:
- Medium/large, 500-1000 lines depending on export shape.

Validation commands:
- `yarn test -- IntelligenceReport aetherframeReport nest export`
- `yarn typecheck`

Tests:
- Report preserves `source_engine: gyre` and `gyre_is_sole_verdict_source` where expected.
- NEST evidence bundle is present only when real NEST evidence exists; no fabricated bundle.
- AETHERFRAME refinement cannot mutate classification or GYRE confidence.
- TALON/STRIKE overlays are marked advisory.
- Report wording avoids recovered-source/detonation/dynamic-truth claims.

Rollback gate:
- Keep new envelope behind a dedicated report/export flag in the implementation pass.

Trust-boundary risks:
- Report unification is the highest authority-risk phase. It can accidentally make advisory overlays look authoritative. Tests must be strict.

What not to touch:
- Signing/updater/release custody.
- site-build/trust or release-note pages.
- Package files.

## Phase 8 — Thin App.tsx into router/session provider/feature-flag host

Goal:
- Reduce `App.tsx` complexity after the analysis substrate and workspace model exist.

Likely files:
- `HexHawk/src/App.tsx`
- New providers/hooks such as:
  - `HexHawk/src/state/AnalysisSessionProvider.tsx`
  - `HexHawk/src/state/FeatureFlagProvider.tsx`
  - `HexHawk/src/routes/WorkspaceRouter.tsx`
  - `HexHawk/src/workspaces/*`

Expected diff size:
- Large. Must be split into several separate commits/slices after all earlier phases are stable.

Validation commands:
- `yarn test -- App workflow workspace`
- `yarn typecheck`
- Later native GUI proof, only when release/tester work is in scope.

Tests:
- Existing workflow navigation still works.
- Open -> Inspect -> Strings -> Code map -> Logic -> Runtime evidence -> Report path remains reachable.
- Feature flags preserve old UI when disabled.
- Authority banners still appear in each workspace.

Rollback gate:
- Do not start this phase until Phase 3-7 are stable.
- Keep old components available behind flags until parity is proven.

Trust-boundary risks:
- Large refactors can silently break export/verdict paths. Mitigation: exact UI and export regression tests before and after extraction.

What not to touch:
- Do not start from this phase.
- Do not combine with package upgrades, release work, or cleanup.

## Cross-phase validation matrix

| Validation area | Required checks |
|---|---|
| Parity | Existing function/xref/block behavior compared with ProgramAnalysis adapter |
| Usability | Top-level labels are Overview, Code map, Logic, Runtime evidence, Report |
| Authority | GYRE sole verdict authority preserved in UI/export/tests |
| Advisory overlays | TALON, STRIKE, AETHERFRAME, NEST, NEXUS cannot mutate classification |
| Uncertainty | Unknowns, inferred boundaries, unresolved links, and maturity limits are visible |
| Export | Evidence envelope preserves source, authority, proof limits, and no fabricated NEST bundle |
| No overclaiming | No recovered source, detonation, dynamic truth, AI verdict, or correctness guarantee claims |
| Rollback | Every new behavior has a flag or isolated component path |

## Recommended first code slice after approval

First code slice:

`ProgramAnalysis adapter behind existing UI, with parity checks and no visible UI change.`

Why this first:

- It is already recommended by `docs/analysis-depth/CURRENT_ANALYSIS_BASELINE.md`.
- It reduces duplicated model truth before labels and workspace changes are applied.
- It gives Code map, Logic, Runtime evidence, and Report one shared substrate.
- It can be validated without touching release, site-build, package files, private files, or adjacent products.

Precondition:

- Either cleanup/shelving happens first, or the implementation pass must be strictly path-scoped and avoid all unrelated dirty areas.

Do not start with:

- App.tsx thinning.
- Broad UI rewrite.
- Report envelope changes.
- Runtime debugger changes.
- Site-build or README edits.
- Package-manager changes.
