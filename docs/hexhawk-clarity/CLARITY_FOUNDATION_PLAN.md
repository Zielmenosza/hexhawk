# HexHawk Clarity Foundation Plan

Last updated: 2026-07-14

Current milestone boundary: product explanation must now include versioned project save/reopen, verified binary identity, immutable recorded GYRE authority, advisory NEST lifecycle linkage, restart/cache-clear recovery, and report/export provenance. Windows MSI and NSIS candidates exist with verified hashes/metadata but are unsigned and have not passed controlled installation acceptance. See [`../CURRENT_STATUS.md`](../CURRENT_STATUS.md).

Status: planning foundation only
Scope: repo-grounded design direction for making HexHawk easier to understand and more uniquely HexHawk
No code changes are authorized by this document

## Complete current workflow in plain language

1. Open or import a binary on an authorized system.
2. Establish byte identity; path and filename are location hints, not identity.
3. Collect static, runtime, analyst, and tool evidence within their stated limits.
4. GYRE records the authoritative classification and base-verdict snapshot.
5. Save a versioned project that links the binary, analysis session, and recorded snapshot without duplicating editable verdict truth.
6. On reopen, verify binary identity and resolve the backend-recorded snapshot; reject missing, stale, malformed, unsupported, mismatched, or cross-binary authority.
7. Use NEST for advisory evidence/lifecycle context linked to that snapshot, never as a second verdict source.
8. Keep optional AI/AETHERFRAME/NEXUS bounded and non-authoritative; they cannot mutate the recorded state.
9. Generate reports/exports that preserve binary, project, session, and immutable snapshot provenance.
10. If authority cannot be resolved, show the limitation or summary-only result honestly—never reuse stale or cross-binary verdict data.

## Executive principle

HexHawk should expose a simple analyst path first and internal engine boundaries second:

Open file -> Understand the code map -> Read advisory logic -> Inspect runtime evidence -> See uncertainty clearly -> Export defensible evidence -> Know exactly what can and cannot affect the verdict.

HexHawk should not become a clone of IDA, Ghidra, Binary Ninja, or x64dbg. Those tools are powerful but often require users to understand tool-specific vocabulary and model boundaries before they can understand the binary. HexHawk's differentiator should be evidence-first clarity: one guided workspace, clear uncertainty, defensible exports, and explicit verdict boundaries.

## Repo evidence inspected for this plan

The current repo already supports this direction:

- `README.md` lists many internal parts in plain English, but still leads with engine names.
- `ROADMAP.md` records the trust hierarchy and exact-artifact/release proof discipline.
- `docs/ENGINE_BOUNDARY_DOCTRINE.md` defines mandatory authority hierarchy and public-claim rules.
- `docs/HIGH_ASSURANCE_GUIDE.md` requires deterministic evidence, policy gates, and GYRE/NEST export preservation.
- `docs/analysis-depth/CURRENT_ANALYSIS_BASELINE.md` states that deeper function/xref/CFG logic is still partly coupled to `App.tsx` and recommends integrating the typed model behind the existing UI first.
- `HexHawk/src/App.tsx` currently exposes many navigation concepts: Disassembly, CFG, Decompile, TALON, NEST, REPL, Metadata, Strings, Patch, Debugger, Diff, Agent Gate, Plugins, Help/About.
- `HexHawk/src/components/WorkflowNav.tsx` groups views into File, Analysis, Intelligence, Actions, Plugins, Help, but still exposes engine/tool labels such as CFG, TALON, NEST, Debugger, REPL.
- `HexHawk/src/components/DecompilerView.tsx` already says pseudocode and disassembly recovery are advisory and do not change GYRE/NEST verdict truth.
- `HexHawk/src/components/TalonView.tsx` contains LLM-gated advisory refinement behavior with explicit user approval and provider controls, but labels such as TALON, LLM, confidence, and type inference need simpler progressive disclosure.
- `HexHawk/src/components/StrikeView.tsx` has live session controls, recorded trace import, runtime-to-code correlation, and an advisory-only imported trace summary.
- `HexHawk/src/components/DebuggerPanel.tsx` exposes live debug controls directly; this should be nested under Runtime evidence / Live session in the simplified model.
- `HexHawk/src/utils/disassemblyModel.ts` already defines `ProgramAnalysis` with `advisoryOnly: true` and `authority: 'analysis_evidence_not_gyre_verdict'`.
- `HexHawk/src/utils/disassemblyAnalysis.ts` already builds function, block, xref, warning, and call graph evidence from instructions.
- `HexHawk/src/utils/decompilerTypes.ts`, `decompilerIr.ts`, `decompilerMaturity.ts`, and `decompilerEngine.ts` already distinguish decompiler maturity from verdict authority and state that pseudocode is not recovered source.
- `HexHawk/src/utils/traceModel.ts` and `traceCorrelation.ts` already mark imported trace evidence and trace correlation as runtime advisory evidence, not GYRE verdict authority.
- `HexHawk/src/components/IntelligenceReport.tsx` exports report sections such as Verdict, Behavioral Capabilities, Reasoning Chain, Threat Signals, Clean Indicators, and Recommended Next Steps; these need authority-envelope tightening in later phases.

## Why competitor tools feel difficult

Competitor tools are difficult not because they lack power, but because power is exposed as many separate expert surfaces:

1. Too many views
   - Disassembly, graph, decompiler, strings, imports, debugger, trace, patching, scripting, reports, and signatures often feel like separate tools.
   - Users must learn where evidence lives before they can answer what the file does.

2. Too many model layers
   - Functions, basic blocks, xrefs, symbols, p-code/IR, high-level IL, debugger state, trace events, and report artifacts often use different names and navigation rules.
   - Users see several partial truths instead of one analysis map with overlays.

3. Too many product-specific terms
   - Acronyms and engine-specific terms become the UI: CFG, xref, IR, SSA, p-code, HLIL, thunk, rebasing, rebinding.
   - These terms are useful for experts but should not be the first label.

4. Fragmented workflows
   - Static analysis, decompiler output, live debugging, recorded trace review, and report/export are often not one guided path.
   - Context gets lost when users switch panels.

5. Hidden uncertainty
   - Inferred function starts, guessed signatures, unresolved jumps, missing trace addresses, weak decompiler output, and stale report evidence may be present but not obvious.
   - Beginners may treat a decompiler line or debugger observation as ground truth.

6. Expert-first assumptions
   - The tool assumes the user understands what to do next.
   - HexHawk should instead guide from file opening to defensible evidence export.

## HexHawk product principle

HexHawk should feel like one evidence workspace with progressive detail:

1. Open file
   - User chooses a binary or sample.
   - HexHawk records identity, metadata, and current proof limits.

2. Understand the code map
   - User sees functions, linked references, execution blocks, strings/imports, and uncertain analysis areas as one navigable map.

3. Read advisory logic
   - User reads pseudocode and logic summaries as an aid, not recovered source.
   - Maturity & limits stay visible.

4. Inspect runtime evidence
   - User can review recorded runtime evidence or an explicit live session.
   - Runtime-to-code links show where behavior touches the code map.

5. See uncertainty clearly
   - Unknown instructions, inferred function boundaries, unresolved jumps, weak trace links, and advisory confidence are visible.

6. Export defensible evidence
   - Report exports preserve binary identity, evidence envelope, GYRE verdict authority, and advisory/non-authoritative overlays.

7. Know exactly what can and cannot affect the verdict
   - GYRE remains the only classification authority.
   - Everything else is evidence, packaging, advisory refinement, or assistant output.

## Five-workspace model

### 1. Overview

User goal:
- Open a file, understand current status, see the verdict when available, and know next actions.

Backing surfaces:
- `WorkflowNav.tsx`, `TopBar`, `ActionBar`, `WorkflowCta`, `CapabilitySummary`, `BinaryVerdict`, metadata/string/import summaries.

Current duplicated concepts:
- Metadata, Inspect, Verdict, Signals, Activity, and Report are separate places where status and next steps may appear.

Simplified labels:
- Verdict (GYRE)
- Evidence found
- Next action
- What is still unknown

Trust-boundary banner:
- `Verdict authority: GYRE is the only component that classifies the file. Other panels provide evidence or advice.`

First safe implementation slice:
- Add language constants and banner copy only; do not change routing or engine behavior.

Tests needed:
- UI text tests for banner presence.
- Search test that Overview does not imply TALON/STRIKE/NEST/AETHERFRAME verdict authority.

Rollback flag:
- `docs.dualLabels.enabled` for documentation and label copy.

### 2. Code map

User goal:
- Navigate what HexHawk can map statically: functions, linked references, execution blocks, imports, strings, suspicious instruction areas, and uncertainty.

Backing surfaces:
- `App.tsx` disassembly state, `DisassemblyList`, `EnhancedInstructionRow`, `FunctionBrowser.tsx`, `XRefPanel`, `ControlFlowGraph`, `disassemblyModel.ts`, `disassemblyAnalysis.ts`.

Current duplicated concepts:
- Disassembly rows, CFG blocks, FunctionMetadata in `App.tsx`, typed `FunctionModel`, `BasicBlock`, and `XRef` in `disassemblyModel.ts`.

Simplified labels:
- Code map
- Function record
- Linked reference
- Execution block
- Possible switch table

Trust-boundary banner:
- `Code map: function, reference, and block boundaries are analysis evidence. They are not GYRE verdicts.`

First safe implementation slice:
- Build `ProgramAnalysis` behind existing UI and compare parity without visible UI change.

Tests needed:
- Function count/start/end parity tests.
- Xref parity tests.
- Basic/execution block parity tests.
- Warning visibility tests for inferred/uncertain boundaries.

Rollback flags:
- `analysis.programDb.enabled`
- `analysis.programDb.parityChecks.enabled`
- `ui.codeMap.browser.enabled`

### 3. Logic

User goal:
- Read helpful pseudocode and logic summaries without mistaking them for source recovery or verdict proof.

Backing surfaces:
- `DecompilerView.tsx`, `TalonView.tsx`, `decompilerEngine.ts`, `decompilerIr.ts`, `decompilerTypes.ts`, `decompilerMaturity.ts`.

Current duplicated concepts:
- Decompiler, TALON, Raw IR, variables, confidence, maturity telemetry, LLM refinement, type inference.

Simplified labels:
- Pseudocode & logic (TALON)
- Maturity & limits
- Advisory confidence
- Advanced IR details

Trust-boundary banner:
- `Advisory logic: pseudocode is a readable aid, not recovered source and not verdict authority.`

First safe implementation slice:
- Rename/dual-label headings and group maturity into a simpler Maturity & limits panel behind a flag; keep Raw IR as advanced disclosure.

Tests needed:
- Maturity export still contains advisory authority markers.
- UI text contains `not recovered source` or equivalent boundary copy.
- TALON/LLM refinement cannot mutate verdict state.

Rollback flag:
- `talon.maturityPanel.v2.enabled`

### 4. Runtime evidence

User goal:
- Review recorded traces or an explicit live session and connect runtime behavior back to the code map.

Backing surfaces:
- `StrikeView.tsx`, `DebuggerPanel.tsx`, `traceModel.ts`, `traceCorrelation.ts`, Rust debugger commands.

Current duplicated concepts:
- STRIKE, Debugger, imported trace, timeline, registers, stack, breakpoints, runtime correlation.

Simplified labels:
- Runtime evidence (STRIKE)
- Recorded runtime evidence
- Live session
- Runtime-to-code links

Trust-boundary banner:
- `Runtime evidence: live and recorded behavior are advisory evidence. They do not change the verdict by themselves.`

First safe implementation slice:
- Create a Runtime evidence workspace wrapper that shows Recorded runtime evidence and Live session as subtabs; do not alter debugger command behavior.

Tests needed:
- Trace model retains `runtime_trace_evidence_not_gyre_verdict`.
- Correlation report retains `runtime_trace_correlation_not_gyre_verdict`.
- UI text distinguishes recorded evidence from live session.
- No copy claims malware detonation or dynamic truth.

Rollback flags:
- `runtime.evidence.workspace.enabled`
- `runtime.traceCorrelation.v2.enabled`

### 5. Report

User goal:
- Export a defensible package that clearly separates verdict authority, evidence, advisory logic, runtime observations, and optional refinement.

Backing surfaces:
- `IntelligenceReport.tsx`, NEST views/export paths, AETHERFRAME report refinement adapter, evidence bundle validation.

Current duplicated concepts:
- Verdict, threat score, confidence, reasoning chain, behavioral capabilities, threat signals, clean indicators, NEST evidence, AETHERFRAME lineage.

Simplified labels:
- Verdict (GYRE)
- Evidence bundle (NEST)
- Advisory refinement (AETHERFRAME)
- Advisory logic summary
- Runtime evidence summary
- Maturity & limits

Trust-boundary banner:
- `Report authority: GYRE owns classification. NEST packages evidence. Advisory overlays must not change the verdict.`

First safe implementation slice:
- Define a single evidence envelope shape in docs/tests first; later adapt report export to include overlays without fabricating NEST evidence.

Tests needed:
- `source_engine: gyre` remains present where expected.
- `gyre_is_sole_verdict_source` remains true where expected.
- AETHERFRAME report refinement is package-only and cannot mutate classification/confidence fields.
- Report does not claim recovered source, detonation, or dynamic truth.

Rollback flag:
- `docs.dualLabels.enabled` for copy first; report data changes need a later dedicated flag.

## Canonical ProgramAnalysis direction

HexHawk should converge on one analysis substrate:

- One analysis substrate: `ProgramAnalysis` should become the internal analysis map behind code navigation.
- One address-space model: all static, decompiler, trace, and report overlays should refer to the same normalized addresses and file identity where possible.
- One navigation/search model: selecting an address should navigate the same function record, linked reference, execution block, pseudocode line, runtime event, and report entry when available.
- One evidence envelope model: report/export data should preserve the source, confidence, authority marker, and proof limits for every overlay.
- Overlays for decompiler/runtime/report: TALON, STRIKE, and reports should attach to `ProgramAnalysis`; they should not create competing truths.
- GYRE remains the only verdict authority: ProgramAnalysis is an analysis substrate, not a verdict engine.

### Adapter-first strategy

First code slice after docs should not visibly change UI.

Recommended approach:

1. Build `ProgramAnalysis` from current `DisassembledInstruction[]` using `buildProgramAnalysis`.
2. Keep current `App.tsx` maps and UI behavior active.
3. Add parity checks comparing current function/xref/block outputs to `ProgramAnalysis` on synthetic fixtures.
4. Log or test parity differences, but do not switch user-visible behavior until parity is acceptable.
5. Add adapters from existing `FunctionMetadata`, CFG, xref maps, decompiler input, and trace correlation to/from `ProgramAnalysis`.
6. Only after parity passes, enable read-only Code map browser surfaces behind flags.

### Decompiler overlays

Decompiler/TALON overlays should attach to `ProgramAnalysis` by address/function/block:

- Pseudocode line -> source instruction address.
- IR node -> instruction address and optional execution block.
- Logic region -> function record and execution block.
- Maturity & limits -> function-level and program-level overlay.

Must remain advisory only:

- Pseudocode and IR.
- Type inference.
- Logic summaries.
- Advisory confidence.
- Maturity & limits.

### Runtime overlays

STRIKE/debugger/trace overlays should attach to `ProgramAnalysis` by address and file identity:

- Recorded trace event -> instruction/function/execution block when resolved.
- Live session snapshot -> current instruction/address when available.
- API/import event -> import record or import-like evidence.
- Runtime-to-code link -> correlation report with warnings.

Must remain advisory only:

- Live register/stack snapshots.
- Recorded trace events.
- Runtime-to-code links.
- Pattern alerts.
- Correlation confidence.

### Report/evidence overlays

Report/export should attach to one evidence envelope:

- Verdict envelope: GYRE classification/base confidence.
- Evidence bundle envelope: NEST evidence packaging/validation status.
- Code map envelope: ProgramAnalysis summary and warnings.
- Logic envelope: TALON/decompiler maturity and warnings.
- Runtime envelope: STRIKE live/recorded evidence and correlation warnings.
- Advisory refinement envelope: AETHERFRAME packaging/lineage only.
- Assistant envelope: NEXUS suggestions/proposals only.

The envelope must preserve authority markers and proof limits for every section.

## Feature flags

Recommended flags:

- `analysis.programDb.enabled`
- `analysis.programDb.parityChecks.enabled`
- `ui.codeMap.browser.enabled`
- `talon.maturityPanel.v2.enabled`
- `runtime.evidence.workspace.enabled`
- `runtime.traceCorrelation.v2.enabled`
- `docs.dualLabels.enabled`

Flag rule:
- Flags may expose or hide new surfaces, but must not bypass authority-boundary tests.

## Validation strategy

### Parity tests

- Current function counts/start/end vs `ProgramAnalysis.functions`.
- Current linked references/xrefs vs `ProgramAnalysis.xrefs`.
- Current CFG/basic-block behavior vs `ProgramAnalysis.basicBlocks` where comparable.
- Trace correlation before/after ProgramAnalysis adapter.

### Usability checks

- New top-level workspace labels are task-first: Overview, Code map, Logic, Runtime evidence, Report.
- Engine names appear as secondary labels or tooltips.
- Advanced details such as Raw IR, SSA-like variables, unresolved jumps, and trace correlation internals are progressively disclosed.

### Authority-boundary tests

- GYRE remains sole classification source.
- NEST evidence bundle cannot overwrite classification.
- AETHERFRAME/Forge cannot mutate verdict fields.
- TALON/decompiler outputs cannot mutate classification or base confidence.
- STRIKE/runtime evidence cannot mutate classification or base confidence by itself.
- NEXUS/assistant output cannot compute verdict truth.

### No-overclaim checks

Search docs/UI/export strings for prohibited or risky wording:

- recovered source
- proven source
- guaranteed correctness
- dynamic truth
- detonation
- AI verdict
- autonomous verdict
- runtime proves malware

Allowed if explicitly negated:

- not recovered source
- does not detonate
- does not change verdict

## Blunt recommendation

Before implementation, cleanup/shelving should happen or the first implementation branch must be extremely path-scoped. The current tree is dirty with unrelated AetherFrameGuard, AetherFrame Studio, Android Hermes access, site-build, private Hermes, generated SDK/toolchain, and package-manager drift.

The first code slice after this docs pass should be:

ProgramAnalysis adapter behind existing UI, with no visible UI change.

Why:

- It matches `docs/analysis-depth/CURRENT_ANALYSIS_BASELINE.md`.
- It reduces duplicated model truth before UI labels are heavily changed.
- It can be validated with parity tests.
- It preserves rollback safety through `analysis.programDb.enabled` and `analysis.programDb.parityChecks.enabled`.

What must not be touched yet:

- `App.tsx` broad rewrite or router thinning.
- Site-build/public website.
- Release/trust/private Hermes files.
- Package manager files.
- AetherFrameGuard, AetherFrame Studio, Android Hermes access.
- Runtime debugger behavior.
- Verdict computation.

If cleanup/shelving is not done first, the first code slice must explicitly avoid every dirty unrelated area and stage only reviewed HexHawk paths after separate approval.
