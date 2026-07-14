# HexHawk Engine Boundary Doctrine

Last updated: 2026-07-14

This doctrine is mandatory for HexHawk code, documents, website copy, investor material, reports, exports, project persistence, and tester operations.

## Authority hierarchy

1. **GYRE is the sole authoritative source of classification and recorded base-verdict state.** Immutable recorded snapshots preserve that authority across save, reopen, cache clearing, and process restart.
2. **NEST orchestrates evidence and lifecycle context.** NEST may link a finalized session to a recorded GYRE snapshot, but does not independently issue, rewrite, replace, or override classification. A NEST linkage is advisory unless backed by the resolved immutable recorded snapshot.
3. **AETHERFRAME/Forge is optional and non-authoritative for classification.** It must remain bounded, replayable, auditable, disableable, and subject to budgets, mutation limits, review checkpoints, uncertainty/proof-limit reporting, and stop conditions. High-assurance paths must work without uplift.
4. **NEXUS is an assistant and consumer layer.** It must not mutate authoritative verdict state.
5. **TALON, STRIKE, and ECHO are evidence/analysis surfaces.** Their outputs do not silently become verdict authority.
6. **CREST packages evidence and reports.** Packaging does not create authority.

Standalone AetherFrame core is product-agnostic and adapter-driven; HexHawk is an adapter/proving ground, not its conceptual owner. AetherFrameGuard is a separate application and must not be conflated with AetherFrame core.

## Persistence and provenance rules

- A project manifest links to persisted records; it does not duplicate editable verdict truth.
- Binary identity must be verified on open. Path and filename are location metadata only.
- Missing, malformed, unsupported, stale, mismatched, and cross-binary persisted authority must be rejected.
- No stale or cross-binary verdict data may be silently reused.
- Reports and exports must resolve provenance from the immutable recorded GYRE snapshot.
- Authoritative recorded evidence must remain distinguishable from advisory, incomplete, or unavailable evidence.
- When authority is unavailable, output must degrade honestly to summary-only reporting rather than invent or reuse a verdict.

Snapshot identifiers are authoritative only when issued and resolved by the backend-recorded GYRE snapshot path. A frontend/renderer field can display an identifier but cannot create its provenance. A schema-valid object proves shape, not authorship; a test fixture proves tested behavior, not that a production value came from GYRE. NEST, NEXUS, AETHERFRAME, and report renderers must not manufacture, repair, relabel, or mutate authoritative snapshot state.

## Public claim rules

HexHawk copy must not claim that the product:

- detonates malware unless a specific controlled feature is implemented and validated;
- bypasses protections;
- proves exploitability, shell access, or flags without native end-to-end evidence;
- lets AI, NEST, AETHERFRAME, NEXUS, or another helper decide final security truth;
- guarantees malware-classification accuracy;
- is signed, production ready, procurement ready, public-release ready, or fully installer validated without exact current evidence.

Preferred language includes local-first evidence custody, persistent projects, immutable recorded-verdict provenance, cross-binary identity isolation, GYRE authority, advisory NEST lifecycle context, bounded AI, replayable evidence, and auditable report/export lineage.

## Bridge boundary

The Bridge is an engineering-continuity mechanism. It preserves workspace, branch, commit, validation, evidence, stop-point, and custody context. It is not part of HexHawk's analysis engine, does not change GYRE logic or classification accuracy, does not produce verdicts, and is not required to run HexHawk.
