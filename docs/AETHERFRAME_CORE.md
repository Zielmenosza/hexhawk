# AetherFrame Core

Last updated: 2026-07-14

HexHawk adapter boundary: HexHawk 1.0.0 persists binary identity, advisory NEST lifecycle linkage, and immutable recorded GYRE snapshot authority in versioned projects. AetherFrame remains optional, bounded, replayable, auditable, disableable, and non-authoritative for classification; high-assurance save/reopen/report paths must work without uplift. AetherFrame must never silently replace missing, stale, or cross-binary recorded authority. See [`CURRENT_STATUS.md`](CURRENT_STATUS.md).

For the HexHawk adapter, AetherFrame may consume only authority already resolved through the backend-recorded GYRE snapshot path. Renderer/schema markers and fixture values are not provenance. AetherFrame and NEXUS cannot issue, repair, or mutate the snapshot; report lineage must point to the validated immutable record or disclose missing authority.

Date: 2026-06-03

## What AetherFrame Is

AetherFrame is a standalone, product-agnostic, language-agnostic bounded intelligence framework. It is designed to wrap reasoning, refinement, critique, mutation proposals, evidence packaging, and exports inside explicit frames.

AetherFrame is not AetherFrameGuard. AetherFrameGuard is a separate application that may use AetherFrame-style bounded advisory ideas, but it is not the AetherFrame core product and must not be treated as the implementation container for AetherFrame.

AetherFrame is also not owned by HexHawk. HexHawk can use an adapter frame, but HexHawk's GYRE/NEST authority model remains intact.

## Core Principle

AetherFrame does not own truth by default. A frame declares which source owns each field. AetherFrame may package, critique, rank, annotate, recommend, or propose mutations only inside that declared authority boundary.

Every AetherFrame pass should be able to answer:

- What is the objective?
- What evidence was used?
- Which fields are protected?
- Which fields are mutable?
- What was attempted?
- What was blocked?
- What changed?
- What remains uncertain?
- What proof limits apply?
- Can the result be replayed?

## Implemented vNext Slice

The current standalone scaffold lives in `packages/aetherframe-core`.

It includes:

- Versioned frame schema: `aetherframe.frame.v1`, with JSON Schema file `packages/aetherframe-core/schemas/frame.schema.json`.
- Versioned evidence graph schema: `aetherframe.evidence_graph.v1`, with JSON Schema file `packages/aetherframe-core/schemas/evidence_graph.schema.json`.
- Versioned mutation ledger schema: `aetherframe.mutation_ledger.v1`, with JSON Schema file `packages/aetherframe-core/schemas/mutation_ledger.schema.json`.
- Versioned replay bundle schema: `aetherframe.replay_bundle.v1`, with JSON Schema file `packages/aetherframe-core/schemas/replay_bundle.schema.json`.
- Runtime JSON load/validation helpers for frame, evidence graph, mutation ledger, and replay bundle files, backed by Ajv JSON Schema validation plus AetherFrame-specific cross-object checks.
- Schema version negotiation that rejects unknown major versions for frame, evidence graph, mutation ledger, replay bundle, and adapter-contract artifacts.
- Explicit migration stubs via `migrateAetherFrameArtifact(...)`; unsupported or future-major migrations are blocked rather than silently rewritten.
- Fixture corpus under `packages/aetherframe-core/fixtures` for empty graphs, strong/weak/conflicting/stale evidence, protected mutation attempts, package-only export, high-assurance clamp, exact replay, replay drift, and negative schema/authority fixtures.
- Negative fixtures cover unknown operating modes, missing authority model, malformed evidence nodes, replay frame/graph mismatch, and protected-field mutation proposals lacking rollback.
- Applied mutation ledger entries record before snapshot, after snapshot, diff, actor, approval source, verification result, rollback status, and proof limits.
- Authority-boundary decisions for read/summarize/refine/mutate/metadata/export operations.
- Policy-gated protected-field mutation blocking.
- Decomposed confidence breakdown with contradiction, uncertainty, source reliability, reproducibility, recency, review, and policy clamp terms.
- Mutation proposal planning with rollback-aware blocking.
- Package-only export lineage that preserves authoritative content.
- Strict frame schema validation that rejects unknown high-risk operating modes unless the schema explicitly supports them.
- Strict replay bundle/result scaffolding with deterministic stable digest ignoring generated timestamps.
- Explain replay mode with bounded commentary over strict replay artifacts.
- Counterfactual replay mode for showing what would change under a different frame policy without rewriting the original bundle.
- Drift detection over replay-relevant frame/evidence/mutation/boundary/lineage sections.
- Review queue generation for contradictions, missing evidence, high-risk mutations, authority-boundary warnings, and uncertainty hotspots.
- Adapter contract interface separate from adapter frames.
- Adapter registry helpers: `createAdapterRegistry`, `registerAdapterContract`, and `validateAdapterFrameAgainstContract`.
- Adapter registry hardening: duplicate adapter contracts are rejected, contract/frame major-version compatibility is checked, protected contract fields may not become mutable frame fields, and frame diagnostics report missing protected/authority fields.
- Replay bundle store abstraction: `createReplayBundleStore(...)` can save persisted bundles, list local bundles, load by replay id, verify digests, compare versions with drift detection, and export a local audit summary.
- Signed/hash-chained audit log option: `appendAuditLogEntry(...)` records `previousEntryDigest` / `previous_entry_digest` and `entryDigest` / `entry_digest`; when a local signing key is supplied it also records `auditSignature` / `audit_signature` using HMAC-SHA256. `verifyAuditLogChain(...)` verifies sequence, chain linkage, entry digest integrity, alias consistency, and optional signature validity for local JSONL logs.
- Migration registry: `createMigrationRegistry`, `registerMigration`, and `dryRunMigration` support explicit migration registration, dry-run diagnostics, migration proof limits, and blocked migration reporting without silently rewriting artifacts.
- Adapter manifest discovery/loading: `discoverAdapterManifests(...)` and `loadAdapterRegistryFromManifests(...)` load local `*.adapter.json` contract manifests, validate schema compatibility, register valid contracts, and return compatibility diagnostics for invalid/future-major manifests.
- Browser-safe adapter-contract subpath export `@hexhawk/aetherframe-core/browser` for UI/report integrations that must not bundle Node-only schema loading or replay persistence modules.
- HexHawk adapter contract and frame stub that preserves GYRE/NEST authority and uses package-only lineage.
- Narrow HexHawk report Markdown integration now validates its adapter lineage against the standalone core adapter contract before surfacing package-only lineage metadata.
- HexHawk JSON report lineage sidecar generation copies/preserves GYRE/NEST-owned verdict fields and marks them as not recomputed by AetherFrame.
- Small CLI exposing `validate-frame`, `replay-strict`, `replay-report`, `save-replay-bundle`, `detect-drift`, and `review`, with tested negative-path failures.

## Frame Model

A frame defines:

- frame id/name/version
- domain
- objective
- operating mode
- adapter kind
- authority model
- protected fields
- mutable fields
- evidence requirements
- confidence policy
- uncertainty policy
- mutation policy
- review policy
- replay policy
- export policy
- stop conditions
- proof-limit template

Supported operating modes:

- `observe_only`
- `package_only`
- `advisory`
- `guided_mutation`
- `bounded_auto_mutation`
- `high_assurance`
- `research_debug`

## Evidence Graph Model

Evidence graphs contain nodes and lineage edges.

Supported node kinds include:

- EvidenceNode
- ClaimNode
- MeasurementNode
- SourceNode
- DerivedInferenceNode
- ContradictionNode
- PolicyGateNode
- MutationProposalNode
- MutationAppliedNode
- MutationBlockedNode
- ReviewCheckpointNode
- UncertaintyNode
- OutcomeNode
- RollbackNode
- ExportNode

Every node records provenance, source reliability, confidence, uncertainty, replay safety, reportability, protected-field interactions, and proof limits.

No opaque `AI says so` edge should be treated as evidence. Model-assisted inference must be labeled with model/prompt/context metadata and explicit uncertainty.

## Authority Boundaries

The boundary engine classifies attempted operations as:

- allowed
- blocked
- allowed_with_review
- allowed_package_only
- allowed_metadata_only
- escalated

Blocked actions become lineage. They must not silently disappear.

## Confidence and Uncertainty

The confidence engine separates:

- base authority confidence
- posterior confidence
- allowed confidence
- uplift delta
- maximum allowed delta
- uncertainty penalty
- contradiction penalty
- source reliability adjustment
- reproducibility adjustment
- recency adjustment
- review adjustment
- policy clamp reason
- required next evidence
- proof limits

Confidence is advisory unless the frame explicitly delegates authority. Contradictions and uncertainty clamp uplift. Package-only, observe-only, and high-assurance modes do not permit advisory uplift of authoritative confidence.

## Mutation Governance

Mutation proposals record target, proposed change, rationale, evidence used, protected fields touched, risk, reversibility, rollback plan, approval requirement, stop conditions, expected outcome, and failure signal.

Mutation ledgers also support applied mutation entries. An applied entry records before snapshot, after snapshot, diff, actor, approval source, verification result, rollback status, and proof limits. Protected-field mutation proposals with no rollback plan are rejected by runtime validation and are represented as invalid negative fixtures rather than safe applied mutations.

Destructive or protected-field mutations are blocked unless a future frame explicitly delegates authority and rollback/review requirements are met.

## Replay

Replay bundles include frame, evidence graph, generated timestamp, and mutation log. Strict replay regenerates boundary decisions and lineage while ignoring explicitly generated timestamp fields for stable digest comparison.

Persistent replay bundle output is available through `saveReplayBundleFile(...)`, `loadPersistentReplayBundleFile(...)`, `createReplayBundleStore(...)`, and the CLI `save-replay-bundle` command. Persisted JSON wraps the replay bundle with a stable digest and proof limits; load verification recomputes the strict replay digest and reports whether it matches the persisted digest. The replay bundle store abstraction lists local bundles, loads the latest matching replay id, verifies digests, compares versions with drift detection, and exports a local audit summary.

The audit log prototype can be plain append-only JSONL by convention, hash-chained, or locally signed through the same `appendAuditLogEntry(...)` API. Each entry records both camelCase and snake_case digest fields (`previousEntryDigest` / `previous_entry_digest`, `entryDigest` / `entry_digest`) so CLI/JSON consumers can audit the chain without UI coupling. If a local signing key is supplied, the entry also records an HMAC-SHA256 `auditSignature` / `audit_signature`; `verifyAuditLogChain(path, signingKey)` checks sequence, chain links, digest aliases, entry digest recomputation, and optional signature validity. This is local integrity evidence, not external notarization, hardware-backed signing, or custody proof.

The non-UI `replay-report` CLI emits replay summary JSON with replay id, stable digest, boundary decisions, blocked actions, and proof limits. It is intended as the tested core artifact that future command-center UI surfaces can consume.

Replay modes currently implemented:

- `strict_replay`: deterministic digest and regenerated boundary/lineage artifacts.
- `explain_replay`: wraps strict replay with bounded commentary and proof limits.
- `drift_detection`: compares replay-relevant sections while ignoring generated timestamps.
- `counterfactual_replay`: applies an explicit frame-policy patch and reports what deterministic replay sections would change.

Drift detection compares strict replay digests and identifies replay-relevant changed sections: frame, evidence graph, mutation log, boundary decisions, and lineage. A matching replay digest proves deterministic AetherFrame replay inputs are stable; it does not prove external-world truth.

This scaffold proves strict replay, explain replay, drift detection, counterfactual replay, persistent replay bundles, digest verification, replay-store version comparison, local hash-chain audit verification, optional local HMAC audit signature verification, and non-UI replay-report JSON shape. It does not yet implement model provenance replay, external notarization/hardware-backed signing, or a full replay console UI.

## Validation and Negative Fixtures

Runtime file loaders validate JSON against the versioned schema files with Ajv. Replay bundle validation also checks that `evidenceGraph.frameId` and each evidence node frame id match the enclosing frame. Mutation ledger validation rejects protected-field mutation proposals that declare no reversibility and no rollback plan.

Negative fixtures are intentionally kept in the fixture corpus so invalid policy/schema cases remain replayable test inputs rather than disappearing:

- `invalid_unknown_operating_mode.json`
- `invalid_missing_authority_model.json`
- `invalid_malformed_evidence_node.json`
- `invalid_replay_frame_graph_mismatch.json`
- `invalid_protected_mutation_without_rollback.json`
- `invalid_schema_major_drift.json`

## Review and Challenge

The core can generate a review queue for contradiction maps, missing evidence, high-risk mutations, authority-boundary warnings, and uncertainty hotspots. Each review item records severity, rationale, affected node ids, affected fields, recommended action, export-block status, mutation-block status, and human-review requirement.

This is a first review/challenge slice. It does not yet produce a full UX command-center panel model or a persistent human-review workflow.

## HexHawk Adapter Boundary

The included HexHawk adapter contract and frame stub are adapter examples, not the core identity of AetherFrame.

The adapter contract records:

- authority model
- evidence sources
- protected fields
- supported mutation types
- validation commands
- export format
- proof-limit language
- stop conditions

For HexHawk:

- GYRE remains sole verdict authority.
- NEST remains evidence orchestration/convergence.
- AetherFrame may package lineage/proof limits only under the current adapter frame.
- AetherFrame must not mutate classification, base confidence, source engine, `gyre_is_sole_verdict_source`, or NEST evidence selection.
- The existing HexHawk report Markdown adapter now imports the standalone core package, registers the HexHawk adapter contract, validates the HexHawk adapter frame against that contract, and exposes the core frame id/schema/contract-validation status as lineage metadata. It still appends package-only lineage only; it does not rewrite the report body or verdict truth.

## CLI

After `yarn workspace @hexhawk/aetherframe-core build`, the CLI entrypoint is `packages/aetherframe-core/dist/src/cli.js` and package bin name is `aetherframe`.

Implemented commands:

```bash
node packages/aetherframe-core/dist/src/cli.js validate-frame packages/aetherframe-core/fixtures/single_strong_source.json
node packages/aetherframe-core/dist/src/cli.js replay-strict packages/aetherframe-core/fixtures/replay_exact_match.json
node packages/aetherframe-core/dist/src/cli.js save-replay-bundle packages/aetherframe-core/fixtures/replay_exact_match.json .tmp/aetherframe/replay_exact_match.persisted.json
node packages/aetherframe-core/dist/src/cli.js detect-drift packages/aetherframe-core/fixtures/replay_drift.json
node packages/aetherframe-core/dist/src/cli.js review packages/aetherframe-core/fixtures/single_strong_source.json packages/aetherframe-core/fixtures/conflicting_sources.json
```

The CLI reports validation/replay/review JSON. It does not perform external side effects.

## AetherFrame vs AetherFrameGuard

AetherFrame is the standalone bounded intelligence framework.

AetherFrameGuard is a separate application. It should not be described as AetherFrame core, and AetherFrame implementation work should not be buried inside AetherFrameGuard unless explicitly requested for that application.

## Current Limits

This is a first implementation slice. It does not yet include:

- full UI command center
- full review/challenge engine
- persistent human-review queue
- model-assisted inference capture beyond schema fields
- external side-effect execution

Those are intentionally deferred until the core remains tested and product-agnostic.
