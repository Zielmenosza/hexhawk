# HexHawk Agent Onboarding Report

Date: 2026-06-01
Scope: orientation-only pass for safe future engineering, documentation, validation, release-hardening, and UX work.

## Orientation Scope and Inputs

Requested orientation docs and sources were read, except one missing document:

- Missing: docs/PERSONA_VALIDATION_REPORT_2026-05-16.md

All other requested files were present and inspected, including README, roadmap/boundary/assurance/investor/tester docs, core Tauri and React entrypoints, CLI, command modules, plugin API/sample plugin, and NEST/AI design docs.

No application code was modified in this pass.

---

## 1) Product Summary

HexHawk is a local-first native desktop reverse-engineing and binary-intelligence workbench.

In plain English:

- It lets an analyst load a file and collect technical evidence (metadata, hashes, strings, disassembly, CFG, plugin outputs, and optional advanced surfaces).
- It supports iterative evidence convergence (NEST) and report packaging (CREST).
- It enforces an authority boundary where GYRE remains the only final verdict authority.
- AI/BYOK and assistant layers are advisory helpers, not truth engines.

Current documented release posture is internal-tester Windows candidate, with signing/updater/public-release gaps still open.

---

## 2) Architecture Map

### GYRE
- Role: sole verdict authority (classification + base confidence).
- Evidence: doctrine and assurance docs, NEST schema/types/runtime checks enforcing source_engine=gyre and gyre_is_sole_verdict_source=true.

### NEST
- Role: evidence orchestration/convergence and session lifecycle.
- Evidence: NEST schema/spec/examples and src-tauri command implementation for create/append/finalize/export/verify identity.
- Non-role: not a verdict engine.

### AETHERFRAME / Forge
- Role: optional bounded uplift/refinement/lineage metadata.
- Constraint: must not mutate GYRE classification.
- Evidence: boundary/assurance docs and report authority-language patterns.

### TALON
- Role: decompiler and structured analyst surface.
- Evidence: TALON components and tier-gated workflow in frontend.

### STRIKE
- Role: runtime/debugger-behavior evidence surface.
- Evidence: Strike components and debugger command set.

### ECHO
- Role: signature/correlation evidence surface.
- Evidence: Echo component and related signature surfaces.

### CREST
- Role: report packaging/export surface.
- Evidence: IntelligenceReport component and report export envelope fields.

### NEXUS
- Role: assistant/consumer layer.
- Constraint: non-authoritative.

### Plugins
- Role: extensible analysis augmentations via plugin API + dynamic user plugins.
- Evidence: plugin-api contract, byte_counter sample plugin, plugin install/list/uninstall/load paths, plugin execution sandbox limits.

### CLI (nest_cli)
- Role: headless JSON-over-stdout operations for identify/inspect/strings/disassemble/cfg and MCP stdio server.
- Evidence: src-tauri/src/bin/nest_cli.rs.

### Tauri backend
- Role: trusted command boundary for file analysis, NEST lifecycle, plugin management, report-adjacent support, licensing, and LLM policy enforcement.
- Evidence: src-tauri/src/main.rs command registration and src-tauri/src/commands/* implementations.

### React frontend
- Role: analyst workflow surfaces, tab navigation, runtime gating/diagnostics, and UI-driven orchestration of Tauri commands.
- Evidence: HexHawk/src/App.tsx, components, utils, types.

---

## 3) Authority and Trust Boundaries

### Must remain true

1. GYRE is sole verdict authority.
2. NEST can organize/validate/package GYRE-linked evidence but cannot replace verdict authority.
3. AETHERFRAME/Forge can only provide optional bounded uplift/lineage metadata and cannot alter GYRE classification.
4. TALON, STRIKE, ECHO are evidence surfaces.
5. CREST packages reports and must preserve authority fields.
6. NEXUS/AI/assistant layers are advisory only.

### Must never become verdict authority

- AI outputs (including BYOK provider responses).
- AETHERFRAME/Forge uplift metadata.
- Plugins and plugin summaries.
- UI-only state or browser/dev-mode screenshots.
- Report prose alone without authority envelope fields.
- NEXUS/operator assistant suggestions.

### Hard invariants observed in source/docs

- NEST finalize rejects source_engine != gyre.
- NEST finalize rejects gyre_is_sole_verdict_source != true.
- NEST validation flags replay-critical errors if source_engine is not gyre or gyre sole-source flags are false.
- Report export envelope includes source_engine: gyre and gyre_is_sole_verdict_source: true.

---

## 4) Current Capability Inventory

| Capability | GUI support | CLI support | Backend/source support | Export/report support | Current validation status | Known caveats |
|---|---|---|---|---|---|---|
| file open/load | Yes (file dialog + fallback picker) | N/A | open_file_picker + path handling in App | Indirect | Source-implemented; docs show workflow runs | Browser mode can simulate path-only behavior, not native proof |
| identify | Indirect via inspect surfaces | Yes (nest_cli identify) | identify_format in CLI | No direct CREST field | CLI smoke historically documented | Current pass did not rerun identify command |
| inspect/metadata | Yes | Yes (nest_cli inspect) | inspect_file_metadata (+ PE extras) | Included in report context | Source-implemented; historical validations documented | Large-file hash strategy comments should be revalidated for exact behavior claims |
| hashes | Yes (metadata) | Through inspect JSON | inspect metadata returns sha256/sha1/md5 | Can be exported in report context | Source-implemented | Hash semantics for very large files should be explicitly acceptance-tested |
| strings | Yes | Yes (nest_cli strings) | find_strings (hex.rs) and extract_strings (strings.rs) | Included as evidence context | Source-implemented | Different string commands exist; parity expectations should be tested |
| disassembly | Yes | Yes (nest_cli disassemble) | disassemble_file_range (capstone + robust fallback) | Included in report context | Source-implemented; historical workflow docs | Range/arch fallback behavior needs artifact-specific runtime validation |
| CFG | Yes | Yes (nest_cli cfg) | build_cfg command | Included in report context | Source-implemented | CFG correctness and large-range perf need explicit acceptance criteria |
| GYRE verdict | Yes (verdict panels) | Indirect via NEST/final snapshot contract | correlation/verdict layers + NEST invariant checks | Yes (final_verdict_snapshot envelope) | Source + docs enforce authority markers | Must guard against UI copy drift implying non-GYRE authority |
| NEST sessions/evidence bundles | Yes (NestView lifecycle integration) | Partial (nest_cli has MCP schema tools; no full lifecycle CLI) | nest_create/append/finalize/export/summary/verify commands | Yes (bundle export command) | Source-implemented; docs include mixed historical proof statements | Schema doc still says design-only while implementation exists; alignment needed |
| CREST reports | Yes (IntelligenceReport) | No direct | IntelligenceReport export payload includes authority doctrine | Yes (JSON/Markdown report export) | Source-implemented; historical doc claims parity repair | Report export is not same as full typed NEST bundle export |
| AETHERFRAME/Forge lineage/uplift | Mentioned in docs/report doctrine | No direct | Policy/doctrine references | Disclosure expected in reports when applied | Mostly doc-level in this orientation pass | Visible lineage disclosure capture remains unproven in latest docs |
| TALON/decompiler | Yes (TalonView/DecompilerView) | No direct | Frontend + backend commands + LLM advisory path | Indirect via reports | Source-implemented | Feature-tier and runtime-mode differences must be validated in native runs |
| STRIKE/debugger/runtime evidence | Yes (Strike + Debugger panels) | No direct in nest_cli command set | debugger commands registered in backend | Indirect | Source-implemented | Live runtime behavior not proven in this pass |
| ECHO/signatures | Yes | No direct | signature/flirt command surfaces + echo UI | Indirect | Source-implemented | Match quality and workflow parity need targeted tests |
| plugins | Yes (list/run/install/uninstall surfaces) | No direct | plugin API + plugin_browser + run_plugins_on_file | Plugin outputs appear in UI/report context | Source-implemented | reload_plugin is a no-op for built-ins; live install/run GUI proof still needed |
| BYOK/AI | Yes (TALON/advisory flows) | No direct | llm_query + stronghold key commands + policy enforcement | Advisory report narration support | Source-implemented with tests documented historically | External provider calls were not proven in this pass |
| licensing/tier gates | Yes (tier gate + license panel) | No direct | verify_license + get_build_info + tier config | Affects accessible surfaces | Source-implemented | Real activation/signing/trial expiry flows need scenario tests |
| package/build/install | N/A | N/A | tauri config + package scripts + cargo workspace | Artifacts generated by build pipeline | Historically documented as passing | This orientation pass did not rerun expensive builds |
| native Tauri runtime proof | Runtime diagnostics available | N/A | hasTauriRuntime checks + runtime proof schema fields | runtime_proof expected in NEST bundle when claimed | Historically mixed docs (pass for unsigned artifact in some docs) | Must be artifact-specific and rerun for signed artifacts |
| export parity | Report export available; NEST bundle export command exists | NEST bundle via backend command path | IntelligenceReport + nest_export_session_bundle | Yes | Partially proven historically | Installed-artifact GUI export parity remains a key gate before broad release |

---

## 5) GUI Workflow Map

Beginner workflow target:

Open/Load binary -> Inspect metadata -> Strings -> Disassembly -> CFG -> Verdict -> NEST (if available) -> Report/Export.

### Step mapping

1. Open/Load binary
- Likely React sources: App.tsx (pickFile, binary path prep), TopBar/Action surfaces.
- Backend commands: open_file_picker, dialog plugin path, path sanitization helpers.

2. Inspect metadata
- React sources: App.tsx inspectFile path and metadata panels.
- Backend commands: inspect_file_metadata, inspect_pe_extras.

3. Strings
- React sources: App.tsx scanStrings and strings tab.
- Backend commands: find_strings (hex.rs path) and extract_strings (NEST backend path).

4. Disassembly
- React sources: App.tsx disassembleFile, DisassemblyList, related workspace tabs.
- Backend commands: disassemble_file_range.

5. CFG
- React sources: App.tsx buildCfg, ControlFlowGraph component.
- Backend commands: build_cfg.

6. Verdict
- React sources: BinaryVerdict, ThreatAssessment, IntelligenceReport authority envelope.
- Backend/source linkage: GYRE boundary enforced through NEST/report invariants and validation code.

7. NEST (if enabled)
- React sources: NestView lifecycle orchestration.
- Backend commands: nest_create_session, nest_append_iteration, nest_finalize_session, nest_verify_binary_identity, nest_export_session_bundle, nest_get_session_summary.

8. Report/Export
- React sources: IntelligenceReport export handlers.
- Backend/source linkage: report envelope fields source_engine and gyre_is_sole_verdict_source; typed NEST bundle export via backend lifecycle command.

---

## 6) CLI Workflow Map

CLI file inspected: src-tauri/src/bin/nest_cli.rs

### Commands found

- identify
- inspect
- strings
- disassemble
- cfg
- serve --mcp

### Example command shapes (no fabricated outputs)

- cargo build --release --bin nest_cli
- target/release/nest_cli.exe identify <path>
- target/release/nest_cli.exe inspect <path>
- target/release/nest_cli.exe strings <path>
- target/release/nest_cli.exe disassemble <path> <offset> <length>
- target/release/nest_cli.exe cfg <path> <offset> <length>
- target/release/nest_cli.exe serve --mcp

### MCP notes from source

- tools/list advertises inspect, disassemble, strings, build_cfg, nest_results, inject_agent_signal, apply_patch.
- nest_results is a live-session stub message in CLI MCP mode.
- inject_agent_signal/apply_patch return approval-gated queued responses; analyst approval is required in product UI semantics.

---

## 7) Build and Validation Map

Derived from root package.json, HexHawk/package.json, Cargo.toml, and src-tauri/Cargo.toml.

### Core commands and what each proves

- yarn install
  - Proves workspace dependency resolution and lock/install integrity.

- yarn typecheck
  - Proves TypeScript static type consistency for current source.

- yarn build
  - Proves frontend production bundle buildability.

- yarn test
  - Proves frontend unit/integration test suite status as currently authored.

- cargo check --workspace
  - Proves Rust workspace compiles semantically (without full binary/link runtime tests).

- cargo test --workspace
  - Proves Rust unit/integration test suite status as currently authored.

- yarn tauri:build
  - Proves Tauri desktop packaging path can build configured artifacts.

- cargo build --release --bin nest_cli
  - Proves standalone release CLI build path.

### Relevant additional scripts found

- HexHawk/package.json scripts include benchmark/test scaffolding such as:
  - strike:fixtures
  - strike:benchmark
  - strike:benchmark:update-baseline
  - strike:benchmark:ci
  - nest

### Important note for this onboarding pass

These expensive commands were not rerun here; report statements about pass/fail are historical/doc-backed unless explicitly marked as current command output in those docs.

---

## 8) Release/Readiness Map

### Current posture (from docs)

- Internal tester candidate: yes.
- Broad public release: not yet.

### Signing state

- Unsigned artifact posture is repeatedly documented.
- Tauri config currently shows signCommand null and updater pubkey empty.

### Updater state

- createUpdaterArtifacts currently false in config.
- Updater signing workflow still pending.

### MSI/NSIS artifacts

- Docs indicate MSI and NSIS builds are producing artifacts in historical validation passes.
- CLI smoke against extracted MSI payload is documented historically.

### Native GUI parity requirements

- Must prove packaged native Tauri/WebView2 runtime for target artifact (not browser/dev simulation).
- Must prove workflow and export parity on installed/extracted artifact intended for release.

### Export parity requirements

- Report exports should preserve authority envelope fields.
- Typed NEST evidence bundle parity should be validated through lifecycle export path.

### External tester blockers (documented)

- Unsigned artifacts / SmartScreen trust posture.
- Updater artifacts disabled and unsigned.
- Remaining support/procurement package readiness gaps.

---

## 9) Documentation Map

### README
- Product framing, architecture summary, current validation snapshot, release caveats.

### ROADMAP
- Current proven baseline, trust hierarchy guardrails, staged priorities.

### ENGINE_BOUNDARY_DOCTRINE
- Canonical authority model and public-claim constraints.

### HIGH_ASSURANCE_GUIDE
- High-assurance requirements and release preconditions.

### Dummies guide
- Beginner-oriented workflow and boundary language; includes explicit browser/dev vs native caution.

### Dummies source map
- Claim-to-source traceability map across docs/source/screenshots.

### Dummies validation report
- Documentation-time validation trail, with clear scope limits and unproven areas.

### Dummies engineering review
- Assessment of guide quality and explicit gap from UI orientation to native artifact proof.

### Tester/release docs
- TESTER_RELEASE_STATUS, RELEASE_SIGNING_AND_UPDATER_PLAN, EXTERNAL_TESTER_KNOWN_ISSUES, PILOT_READINESS_CHECKLIST collectively define current release-hardening reality and blockers.

---

## 10) Known Risks / Unproven Areas

Status labels below are from this onboarding pass perspective.

- packaged native Tauri/WebView2 operation
  - Status: partially proven historically in docs, not revalidated in this pass.

- installed-artifact GUI export parity
  - Status: historically claimed in some docs for unsigned artifact; not revalidated in this pass.

- typed NEST evidence bundle parity
  - Status: source implementation exists; end-to-end artifact-specific proof remains unconfirmed in this pass.

- exact exported authority fields
  - Status: source-implemented in IntelligenceReport and NEST validators; installed-artifact export verification still needed.

- AETHERFRAME/Forge visible lineage disclosure
  - Status: documented boundary exists; visible runtime capture remains unproven in recent docs.

- Windows signing / SmartScreen behavior
  - Status: unproven as signed; docs indicate unsigned/not-signed state.

- plugin install/run through live GUI
  - Status: source support exists; live GUI install+run acceptance proof not confirmed in this pass.

- BYOK provider calls
  - Status: source policy/commands exist; real provider call proof not performed in this pass.

- STRIKE/debugger live runtime behavior
  - Status: source commands and UI surfaces exist; live behavior proof not performed in this pass.

---

## 11) Engineering Backlog Inferred From Evidence

### P0: trust/release blockers

1. Implement and verify Authenticode signing for exe/MSI/NSIS artifacts.
2. Enable updater artifacts with valid updater signing key/pubkey wiring and verification.
3. Re-run native packaged artifact proof including report export authority checks on signed artifact.
4. Align contradictory status language across top-level docs (conservative vs parity-pass phrasing) with one canonical release evidence ledger.

### P1: workflow/UX blockers

1. Turn Dummies workflow into deterministic native acceptance harness (Open -> Inspect -> Strings -> Disassembly -> CFG -> Verdict -> NEST -> Export).
2. Make simulation/browser-mode states unmistakable in UI so they cannot be confused with native proof.
3. Improve report UX to clearly separate report envelope export from typed NEST bundle export path.
4. Validate plugin install/list/run/uninstall flow through live GUI in native runtime.

### P2: docs/polish

1. Reconcile NEST schema spec status line (design-only) with current implemented lifecycle reality.
2. Add artifact-specific release evidence matrix per build (hashes, signature status, parity status, scope).
3. Fill/replace remaining placeholder screenshots only with artifact-scoped capture provenance.
4. Keep investor/board/docs copy synchronized with current signed-vs-unsigned state.

---

## 12) Suggested Acceptance Tests (Derived From Dummies)

1. Native app launch/runtime proof
- Launch packaged app artifact.
- Verify hasTauriRuntime=true and browserMode=false.

2. Safe sample open
- Load authorized sample and verify path/identity binding.

3. Inspect
- Run inspect and verify metadata plus hashes are populated.

4. Strings
- Run strings workflow and verify non-empty or expected deterministic result shape.

5. Disassembly range
- Run disassemble over known range and validate instruction payload shape and pagination behavior.

6. CFG range
- Build CFG for known range and validate node/edge structure.

7. GYRE authority markers visible/exported
- Verify visible authority markers in UI and exported payload.

8. NEST lifecycle (if available)
- Create session, append iteration(s), finalize, verify identity checks, export bundle.

9. Report export authority envelope
- Validate exported report includes source_engine=gyre and gyre_is_sole_verdict_source=true.

10. AETHERFRAME/Forge disclosure
- If enabled, verify uplift/lineage disclosure is visible and non-authoritative.

11. Browser/dev screenshots policy
- Confirm browser/dev captures are labeled as non-native proof and excluded from release authority evidence.

---

## 13) Agent Operating Rules (Short Checklist)

Before changing HexHawk, future agents should:

1. Read authority-boundary docs first.
2. Identify exact files/modules touched by the change.
3. State trust-boundary risks explicitly before implementation.
4. Make the smallest reviewable change that solves the task.
5. Run narrow validation tied to that change.
6. Report what passed and what remains unproven.
7. Update docs whenever behavior or claims changed.

Additional guardrails:

- Do not claim native/runtime/signing/test outcomes without direct command/probe evidence.
- Do not treat browser/dev UI screenshots as native artifact proof.
- Do not allow AI/plugin/report copy to imply non-GYRE verdict authority.

---

## Orientation Conclusion

HexHawk is architecturally coherent and strongly boundary-aware in both docs and source, with explicit anti-drift safeguards around GYRE authority. The remaining risk concentration is release hardening and artifact-specific native validation evidence, not missing core command surfaces.
