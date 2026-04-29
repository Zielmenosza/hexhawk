# NEST Enterprise Plan

Date: 2026-04-29
Project: HexHawk
Scope: design plan for turning NEST from a strong local analyst feature into an enterprise-trustworthy system

## 1. What NEST Does Today

NEST today is an iterative analysis loop implemented primarily in [HexHawk/src/utils/nestEngine.ts](d:\Project\HexHawk\HexHawk\src\utils\nestEngine.ts), orchestrated in [HexHawk/src/components/NestView.tsx](d:\Project\HexHawk\HexHawk\src\components\NestView.tsx), and runnable headlessly through [HexHawk/scripts/run-nest.ts](d:\Project\HexHawk\HexHawk\scripts\run-nest.ts) and [src-tauri/src/bin/nest_cli.rs](d:\Project\HexHawk\src-tauri\src\bin\nest_cli.rs).

Today NEST does five useful things well:

1. It runs repeated analysis passes over the same binary instead of trusting a single pass.
2. It expands coverage based on a refinement plan: disassembly growth, CFG-following, ECHO focus, string-context, and import-context actions.
3. It measures convergence instead of blindly inflating confidence. The engine already tracks plateau, stability, contradiction burden, signal delta, and projected loss.
4. It stores per-iteration snapshots and produces iteration deltas. The CLI runner writes `result.json` and `iterations.json` artifacts for a session.
5. It feeds GYRE rather than replacing it. NEST enriches analysis, but GYRE remains the actual verdict engine.

This is enough to make NEST a differentiator for a single analyst running local sessions. It is not enough to make NEST a trusted enterprise feature.

## 2. Why It Is Not Yet Enterprise-Grade

NEST is still built like a powerful workstation feature, not a governed analysis service.

What is missing:

- Session state is local-first and UI-driven. The core engine is pure TypeScript and the main orchestration lives in the renderer. That is good for velocity, bad for audit boundaries.
- There is no durable server-side system of record for NEST sessions. `iterations.json` and `result.json` are files, not controlled records with identity, ownership, immutability, and retention policy.
- There is no authenticated API surface for enterprise callers. `nest_cli` is a local binary interface, not an API contract.
- There is no role model. Anyone with UI access can run, inspect, or re-run without reviewer or approver separation.
- There is no service-account execution path for automation, CI, corpus refresh, nightly replay, or policy-driven batch runs.
- Corpus management is file-based (`corpus/results.json`) rather than a shared governed dataset with provenance, labels, approvals, and rollback.
- Auditability is partial. Runtime evidence exists for UI validation, and NEST emits artifacts, but there is no unified append-only audit log for who ran what, with which config, against which file hash, under which policy version.
- NEST convergence is explainable, but trust packaging is incomplete. An enterprise customer needs file identity proof, iteration provenance, reviewer traceability, export manifests, and stable API replay.

In short: the analysis logic is ahead of the control plane.

## 3. Exact Blocker(s) Preventing Enterprise Trust

There are two classes of blockers: one recently cleared, and several still unresolved.

### 3.1 Previously blocking trust issue: file-bound proof

This was the hard blocker for making any enterprise trust claim. It has now been cleared for the tested crossfile workflow.

Evidence:
- [docs/final_filebound_validation.md](d:\Project\HexHawk\docs\final_filebound_validation.md)
- [docs/final_runtime_testing_and_vscode_status.md](d:\Project\HexHawk\docs\final_runtime_testing_and_vscode_status.md)

What was wrong before:
- The second binary could inherit stale metadata and plugin state.
- That meant NEST-adjacent evidence could look deterministic while actually being bound to the wrong file.

Current truth:
- The release blocker `EXPECTED_FILE_BOUND_DIVERGENCE_MISSING` is cleared.
- `appearsFileBound=true` is now proven for the tested crossfile workflow.

This matters because enterprise NEST cannot exist without file identity proof. That baseline is now available, but only for the tested workflow and not yet as a full enterprise evidence contract.

### 3.2 Remaining blockers

These are the real blockers for calling NEST enterprise-ready:

1. NEST session provenance is not immutable.
   The current artifacts can be produced and stored, but they are not tied to signed manifests, actor identity, policy version, or tamper-evident storage.

2. NEST has no first-class API boundary.
   Enterprise systems need authenticated, replayable, rate-limited, schema-stable API access. `nest_cli` is not that.

3. Corpus governance is weak.
   `corpus/results.json` supports ingestion and cross-validation, but not reviewer approval, label disputes, versioning, staged promotion, or tenant scoping.

4. Approval workflow does not exist.
   NEST can suggest and converge, but there is no reviewer/approver chain for classification changes, corpus label additions, or policy overrides.

5. Service-account automation is missing.
   There is no safe machine identity for scheduled runs, CI-based replay, regression evidence generation, or bulk enterprise workflows.

6. Exported evidence is useful but not enterprise-grade.
   Current outputs are files. They are not packaged as signed evidence bundles with manifest hashes, schema versions, replay metadata, and audit references.

7. NEST-specific runtime coverage is incomplete.
   Crossfile runtime evidence now proves file-bound analysis for the tested workflow, but the latest validation still shows `nestConfidence=null` in that path. That is not a release blocker anymore, but it is a trust gap for claiming NEST runtime fidelity end-to-end.

## 4. Target Design for NEST Enterprise

NEST Enterprise should be a governed analysis subsystem with a strict separation between:

- deterministic analysis execution
- evidence capture
- approval and review workflow
- corpus governance
- automation/API access
- export and audit surfaces

### 4.1 Architectural shape

The target design is not "put more features in NestView". The target design is a three-plane system.

#### Plane A: Analysis plane

Purpose:
- run NEST sessions deterministically
- produce iteration snapshots, deltas, convergence decisions, and final enrichment output

Implementation direction:
- keep the core convergence logic in TypeScript or port selected parts to Rust only if determinism or service deployment demands it
- move orchestration behind a Tauri command boundary first, then a service boundary if needed
- every NEST session must be keyed by:
  - `session_id`
  - `binary_sha256`
  - `binary_path` or imported object reference
  - `config_version`
  - `engine_build_id`
  - `actor_id`
  - `started_at`, `completed_at`

#### Plane B: Control plane

Purpose:
- govern who can run, review, approve, export, ingest, or automate
- store policy, role, retention, and review state

Implementation direction:
- introduce a persisted NEST session record store
- introduce RBAC with explicit permissions
- every mutation must be audit-logged

#### Plane C: Evidence plane

Purpose:
- make NEST outputs exportable, replayable, and reviewable

Implementation direction:
- every session emits an evidence bundle with:
  - session manifest
  - binary identity proof
  - iteration ledger
  - delta ledger
  - final NEST summary
  - linked GYRE verdict snapshot
  - runtime/source-fidelity markers
  - audit references
  - schema version
  - bundle hash

## 5. Required Capabilities

### 5.1 File-bound proof

Requirement:
- Every NEST session must prove exactly which binary bytes were analyzed.

Design:
- store `sha256`, `sha1`, `md5`, file size, format, architecture, and first-seen timestamp in the session manifest
- attach runtime proof when session is executed from UI workflows
- persist file identity into every iteration snapshot, not just session root
- reject session continuation if file identity changes mid-session
- include a `file_bound_proof` block in exported evidence bundles

Concrete upgrade points:
- extend NEST session artifacts written by [run-nest.ts](d:\Project\HexHawk\HexHawk\scripts\run-nest.ts)
- mirror the crossfile runtime evidence rules used in the runtime harness
- add a NEST-specific runtime gate validating that the NEST-enriched output references the current binary hash

Enterprise bar:
- a reviewer must be able to answer "which exact file did NEST analyze?" without trusting UI state

### 5.2 Iteration delta tracking

Requirement:
- Deltas must be first-class records, not just implied by adjacent snapshots.

Design:
- persist a per-iteration delta object with:
  - new signals added
  - signals removed
  - confidence delta
  - classification delta
  - contradiction delta
  - refinement action executed
  - projected gain vs actual gain
  - tool/runtime inputs consumed
- store deltas as immutable append-only rows in addition to the iteration snapshots
- expose deltas in API and export bundles

Concrete upgrade points:
- formalize the shape already implied in `NestIterationSnapshot` and convergence metrics in [nestEngine.ts](d:\Project\HexHawk\HexHawk\src\utils\nestEngine.ts)
- stop relying on UI-only timeline rendering in [NestView.tsx](d:\Project\HexHawk\HexHawk\src\components\NestView.tsx) as the primary record

Enterprise bar:
- a reviewer must be able to see exactly what iteration 4 learned that iteration 3 did not

### 5.3 Audit logs

Requirement:
- Every NEST action must be attributable.

Design:
- append-only audit stream with event types such as:
  - `nest.session.created`
  - `nest.iteration.started`
  - `nest.iteration.completed`
  - `nest.session.converged`
  - `nest.session.exported`
  - `nest.corpus.entry.proposed`
  - `nest.corpus.entry.approved`
  - `nest.policy.override.requested`
  - `nest.policy.override.approved`
- each event contains:
  - actor identity
  - actor type (`user`, `reviewer`, `approver`, `service-account`)
  - timestamp
  - session id
  - binary sha256
  - policy version
  - before/after summary where applicable

Concrete upgrade points:
- reuse the runtime evidence discipline already present in the runtime harness docs, but move from test artifacts to product audit records
- keep application logs separate from audit logs; audit logs must not be best-effort UI logs

Enterprise bar:
- no silent run, no silent re-run, no silent corpus change

### 5.4 API access

Requirement:
- NEST must be callable by other systems without scripting the UI.

Design:
- add a stable authenticated API surface, initially local Tauri commands, then optionally remote service endpoints
- minimum endpoints:
  - `POST /nest/sessions`
  - `GET /nest/sessions/{id}`
  - `GET /nest/sessions/{id}/iterations`
  - `GET /nest/sessions/{id}/artifacts`
  - `POST /nest/sessions/{id}/approve`
  - `POST /nest/corpus/entries`
  - `GET /nest/corpus/entries`
- API responses must include schema version and evidence references
- APIs must be read-only by default for non-approver roles

Concrete upgrade points:
- `nest_cli` remains useful as a backend worker or compatibility path, but not the enterprise contract
- if HexHawk stays desktop-first, expose these through Tauri commands and optional local HTTP bridge later

Enterprise bar:
- enterprise automation cannot depend on shelling out to `nest_cli` and parsing ad hoc stdout

### 5.5 Shared corpus management

Requirement:
- corpus must become a governed dataset, not a shared JSON file.

Design:
- replace or wrap `corpus/results.json` with a corpus registry model:
  - entry id
  - file hash
  - source
  - label
  - expected class
  - tags
  - notes
  - proposer
  - reviewer status
  - approval status
  - superseded-by relationship
  - tenant/team visibility
- support draft, approved, quarantined, and retired states
- cross-validation should run against an approved slice, not raw entries

Concrete upgrade points:
- keep current ingestion tools:
  - `nest_cli ingest`
  - `scripts/import-malwarebazaar.ts`
  - `scripts/cross-validate.ts`
- change their output target from flat JSON append to a governed registry

Enterprise bar:
- no production training, replay, or benchmarking against unreviewed corpus data

### 5.6 Reviewer/approver roles

Requirement:
- analysis and approval must be separable.

Design:
- minimum roles:
  - `analyst`: run sessions, annotate, propose labels
  - `reviewer`: inspect evidence, request rerun, accept/reject corpus proposals
  - `approver`: finalize label promotion, approve exports, approve policy overrides
  - `admin`: manage policy, retention, service accounts
- sensitive actions require explicit approval:
  - corpus promotion
  - label changes on approved samples
  - policy override for early convergence or ignored contradictions
  - evidence export for external sharing if org policy requires it

Concrete upgrade points:
- current NEST UI has no role boundary; role-aware controls must be added in the product shell, not only in NEST panels

Enterprise bar:
- the same person should not silently create, label, approve, and export contested evidence in one opaque step

### 5.7 Service-account automation

Requirement:
- NEST must support unattended enterprise workflows safely.

Design:
- service accounts with scoped permissions and explicit run policies
- supported jobs:
  - nightly replay of golden binaries
  - regression validation after engine changes
  - scheduled corpus cross-validation
  - ingest pipeline with approval queue only, not auto-promotion
  - evidence export for downstream SIEM or case systems
- each automated run must identify the service account in the audit trail

Concrete upgrade points:
- wrap `run-nest.ts` and `nest_cli` execution behind a job runner that stamps actor id, policy version, and artifact location

Enterprise bar:
- automation must be attributable and policy-limited

### 5.8 Exportable evidence artifacts

Requirement:
- NEST output must be shareable without screenshots and oral explanation.

Design:
- define a bundle format such as:
  - `manifest.json`
  - `binary_identity.json`
  - `session.json`
  - `iterations.json`
  - `deltas.json`
  - `final_verdict_snapshot.json`
  - `runtime_proof.json` when applicable
  - `audit_refs.json`
  - optional `review_summary.md`
- every file gets a hash listed in the manifest
- manifest includes schema version and generating build id

Concrete upgrade points:
- build on top of the existing artifact-writing pattern already used by `run-nest.ts` and runtime harness outputs
- align the manifest structure with CREST exports where possible

Enterprise bar:
- a third party should be able to verify what was run and what changed without opening the live app

## 6. Phased Implementation Plan

### Phase 0: Stabilize trust baseline

Goal:
- freeze the evidence contract before adding enterprise features

Work:
- formalize NEST session schema and iteration schema
- formalize delta schema
- add file-bound proof block to every session artifact
- add a NEST-specific runtime validation gate proving session hash alignment
- mark current desktop artifact format as schema version 1

Exit criteria:
- one session run produces deterministic, versioned, replayable artifacts

### Phase 1: Productize local governance

Goal:
- make enterprise controls work in single-host Tauri mode first

Work:
- add Tauri command boundary for NEST session lifecycle:
  - create session
  - execute iteration
  - finalize session
  - export evidence
- move audit events to backend-owned logging
- add local role model and permission checks
- add reviewer/approver states for corpus entries and exports

Exit criteria:
- NEST runs are no longer renderer-owned from a trust perspective

### Phase 2: Corpus governance

Goal:
- stop treating corpus as a shared JSON append log

Work:
- introduce corpus registry with lifecycle states
- migrate `corpus/results.json` into managed records
- require approval before an entry becomes benchmark/training eligible
- update `cross-validate.ts` to use approved corpus slice only
- add corpus provenance fields and supersession handling

Exit criteria:
- corpus ingestion, review, approval, and validation are separable and auditable

### Phase 3: Enterprise API and automation

Goal:
- support team workflows and machine-driven execution

Work:
- define stable API DTOs and authentication model
- add service-account identities and scoped policies
- implement session/job queueing for automation
- add export endpoints and artifact retrieval
- add replay endpoint for golden-binary regression runs

Exit criteria:
- another system can submit, monitor, review, and export NEST sessions without UI automation

### Phase 4: Team workflows and evidence packaging

Goal:
- make NEST usable in real review pipelines

Work:
- reviewer work queues
- approval inbox for corpus and export actions
- signed evidence bundles
- diff views between two NEST sessions on the same binary
- policy snapshots embedded into exports

Exit criteria:
- enterprise review workflow exists end-to-end with evidence bundle output

### Phase 5: Remote deployment option

Goal:
- optional centralized deployment for multi-user organizations

Work:
- lift NEST orchestration into a service container or background worker
- centralize audit store, corpus registry, and job scheduling
- keep desktop UI as a client, not the execution authority

Exit criteria:
- NEST can run in centralized mode without changing evidence semantics

## 7. Release Criteria for Calling NEST “Enterprise-Ready”

Do not call NEST enterprise-ready until all of the following are true.

### Trust and evidence

- File-bound proof is enforced for every NEST session, not only tested crossfile workflows.
- NEST runtime path shows non-null, binary-bound enrichment when the product claims NEST runtime output.
- Every session has immutable manifest, iteration ledger, and delta ledger.
- Evidence exports are versioned, hashed, and replayable.

### Governance

- Audit log is backend-owned, append-only, and covers all session, corpus, approval, and export actions.
- Reviewer and approver roles are implemented and enforced.
- Policy overrides are explicit, logged, and reviewable.

### API and automation

- A documented API exists for session creation, retrieval, iteration inspection, artifact export, and corpus management.
- Service accounts can run approved automation paths without bypassing audit or policy.
- Rate limits, auth, and schema versioning exist.

### Corpus integrity

- Corpus entries have provenance, ownership, lifecycle state, and approval status.
- Cross-validation runs only on an approved corpus slice.
- Corpus modifications are auditable and reversible.

### Operational readiness

- Golden-binary replay suite exists and passes.
- Regression evidence bundles are generated automatically after engine changes.
- Retention policy exists for session artifacts, audit logs, and corpus states.
- Failure modes are explicit: timeout, partial session, missing backend signal, stale file identity, export refusal.

### Product honesty

- The UI and exports never imply that NEST is the verdict source. GYRE remains the sole verdict source.
- The UI clearly distinguishes:
  - deterministic evidence
  - NEST-enriched analysis
  - reviewer-approved conclusions
- No enterprise marketing claim outruns the evidence contract.

## Recommended Definition

A blunt but accurate definition of NEST Enterprise would be:

> NEST Enterprise is a governed iterative analysis subsystem that produces file-bound, replayable, auditable iteration evidence; exposes authenticated API and automation surfaces; supports reviewer/approver workflows; and feeds GYRE without becoming the verdict authority.

Anything weaker than that is still an advanced analyst feature, not an enterprise product.