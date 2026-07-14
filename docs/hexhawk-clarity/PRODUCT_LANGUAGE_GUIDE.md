# HexHawk Product Language Guide

Last updated: 2026-07-14

Current product language should lead with persistent local projects, reliable reopen, verified binary identity, immutable recorded GYRE authority, advisory NEST lifecycle context, bounded non-authoritative AI, and auditable report/export provenance. Describe the Windows package as an unsigned release candidate ready for controlled local installation testing—not as signed, accepted, production ready, procurement ready, enterprise ready, updater ready, or public release ready. See [`../CURRENT_STATUS.md`](../CURRENT_STATUS.md).

Status: planning foundation only
Scope: product language, UI labels, reports, and docs direction for HexHawk clarity work
Authority: this guide does not change engine behavior, verdict authority, release posture, or validation claims

## Ten-step user story

1. Open or import a binary.
2. Establish the binary's byte identity.
3. Collect evidence and label its source and limits.
4. GYRE records authoritative classification/base-verdict state.
5. Save a versioned project linking binary, session, and recorded snapshot.
6. Reopen by verifying identity and resolving the backend-recorded snapshot; reject invalid or cross-binary linkage.
7. Let NEST add advisory lifecycle/evidence context.
8. Keep optional AI/AETHERFRAME/NEXUS bounded, reviewable, and non-authoritative.
9. Export a report that preserves binary/project/session/snapshot provenance.
10. If recorded authority is unavailable, say so and provide only the supported limited result—never a stale fallback.

## Purpose

HexHawk should let a user get value before they learn internal engine names. Internal names still matter for engineering, auditability, and high-assurance review, but the first visible label should describe the user task.

The product-language rule is:

Plain task label first, internal engine name second.

Example:

- Use `Verdict (GYRE)` in explanatory/advanced surfaces.
- Use `Verdict` in primary navigation and headings when space is tight.
- Keep `GYRE` in tooltips, docs, exports, and authority banners so the trust model remains explicit.

## Why competitor tools feel hard to learn

IDA, Ghidra, Binary Ninja, x64dbg, and similar tools are powerful, but they often expose the expert mental model before the user has a map:

- Too many views: disassembly, graph, decompiler, strings, imports, debugger, trace, patch, and reports appear as separate worlds.
- Too many model layers: functions, blocks, symbols, xrefs, IR, p-code/MLIL/HLIL, debugger state, traces, and reports are all named differently.
- Too many product-specific terms: users learn the tool vocabulary before understanding the binary.
- Fragmented workflows: static analysis, decompilation, live debugging, recorded traces, and reporting do not always feel like one path.
- Hidden or unclear uncertainty: inferred functions, unresolved jumps, weak pseudocode, unknown trace addresses, and confidence limits are easy to miss.
- Expert-first assumptions: labels like CFG, xref, IR, thunk, p-code, or SSA are precise but not friendly as the first label.

HexHawk should keep the power, but make the workflow read like a task:

Open file -> Understand the code map -> Read advisory logic -> Inspect runtime evidence -> See uncertainty clearly -> Export defensible evidence -> Know exactly what can and cannot affect the verdict.

## Dual-label dictionary

| Internal/current term | Primary user-facing label | Secondary/internal label | Use guidance | Trust note |
|---|---|---|---|---|
| GYRE | Verdict | Verdict (GYRE) | Primary classification/result surfaces | Sole verdict/classification authority |
| NEST | Evidence bundle | Evidence bundle (NEST) | Evidence packaging, convergence, export validation | Evidence orchestration only; not a verdict engine |
| AETHERFRAME/Forge | Advisory refinement | Advisory refinement (AETHERFRAME) | Optional report/package refinement, lineage, confidence context | Optional and policy-gated; cannot change classification |
| NEXUS | Assistant | Assistant (NEXUS) | Suggestions, questions, analyst help | Consumer/proposal layer only |
| TALON | Pseudocode & logic | Pseudocode & logic (TALON) | Decompiled/pseudocode and logic assistance | Advisory only; not recovered source or verdict truth |
| STRIKE | Runtime evidence | Runtime evidence (STRIKE) | Live debug state, recorded traces, runtime-to-code links | Advisory runtime evidence only |
| Disassembly | Code map | Code map / disassembly | Instruction and function navigation | Static analysis evidence only |
| ProgramAnalysis | Analysis map | ProgramAnalysis / Analysis map | Canonical internal analysis substrate | Advisory model, not GYRE verdict |
| XRef | Linked reference | Linked reference / xref | Cross-references in code map | Link confidence must be visible |
| Basic block | Execution block | Execution block / basic block | Flow chunks in code map and logic panels | Inferred boundaries must show uncertainty |
| FunctionModel | Function record | Function record / FunctionModel | Function browser, reports, evidence envelopes | Function boundaries can be inferred |
| JumpTableCandidate | Possible switch table | Possible switch table / JumpTableCandidate | Advanced control-flow detail | Candidate, not proof |
| Trace correlation | Runtime-to-code links | Runtime-to-code links / trace correlation | Links from traces/debugger to code map | Correlation does not prove behavior truth |
| Maturity | Maturity & limits | Maturity & limits / maturity telemetry | Pseudocode/code-map uncertainty panel | Maturity is not correctness |
| Confidence | Advisory confidence | Advisory confidence | Non-GYRE analysis confidence | Must not be confused with GYRE base confidence |
| Imported trace | Recorded runtime evidence | Recorded runtime evidence / imported trace | JSON traces and offline runtime data | Recorded evidence, not live detonation |
| Debugger | Live session | Live session / debugger | Active debug controls | Live observation only; verdict unaffected unless GYRE path explicitly consumes evidence |

## Primary navigation language

Preferred five-workspace labels:

1. Overview
2. Code map
3. Logic
4. Runtime evidence
5. Report

Advanced/internal labels can appear inside those workspaces:

- Code map can contain Disassembly, CFG, Functions, Linked references, Execution blocks.
- Logic can contain Pseudocode & logic (TALON), Raw IR, Maturity & limits.
- Runtime evidence can contain Recorded runtime evidence, Live session, Runtime-to-code links.
- Report can contain Verdict (GYRE), Evidence bundle (NEST), Advisory refinement (AETHERFRAME), export status.

## Authority banners

Use short, repeatable banners. Do not invent a new sentence in every component.

### Verdict / Overview

`Verdict authority: GYRE is the only component that classifies the file. Other panels provide evidence or advice.`

### Evidence bundle / NEST

`Evidence bundle: NEST packages and checks evidence. It does not replace GYRE or change the classification.`

### Advisory refinement / AETHERFRAME

`Advisory refinement: AETHERFRAME may clarify or package results when policy allows. It cannot change GYRE classification.`

### Pseudocode & logic / TALON

`Advisory logic: TALON pseudocode is a readable aid, not recovered source and not verdict authority.`

### Runtime evidence / STRIKE

`Runtime evidence: STRIKE shows live or recorded behavior evidence. Runtime links are advisory and do not change the verdict by themselves.`

### Assistant / NEXUS

`Assistant: NEXUS can suggest next steps and explain outputs. It does not compute security truth.`

## Before-vs-after usability map

| Current phrase/concept | Why it is confusing | Replacement label | Internal label retained | Affected files/surfaces | Trust-boundary risk | Safe implementation phase |
|---|---|---|---|---|---|---|
| Disassembly | Accurate but expert-first; users may not know why it matters | Code map | Disassembly | `WorkflowNav.tsx`, `App.tsx`, `DisassemblyList`, docs | Low; static evidence only | Phase 2/4 |
| CFG | Acronym-first; disconnected from code map | Flow view or execution graph inside Code map | CFG | `WorkflowNav.tsx`, `ControlFlowGraph`, `DecompilerView` | Low; inferred flow must show limits | Phase 4 |
| Decompile | Implies source recovery to some users | Logic | Decompiler/TALON | `WorkflowNav.tsx`, `DecompilerView.tsx`, `TalonView.tsx` | Medium; must state pseudocode is advisory | Phase 5 |
| TALON | Engine-name-first | Pseudocode & logic | TALON | `App.tsx`, `WorkflowNav.tsx`, `TalonView.tsx` | Medium; avoid source-recovery claims | Phase 5 |
| STRIKE | Engine-name-first | Runtime evidence | STRIKE | `StrikeView.tsx`, debugger/trace docs | High; avoid detonation/dynamic truth claims | Phase 6 |
| Debugger | Expert action-first; overlaps STRIKE | Live session | Debugger | `DebuggerPanel.tsx`, `StrikeView.tsx`, `WorkflowNav.tsx` | High; attach/run side effects must be explicit | Phase 6 |
| Imported trace evidence | Wordy and implementation-specific | Recorded runtime evidence | Imported trace | `StrikeView.tsx`, `traceModel.ts`, docs | Medium; recorded trace provenance must be clear | Phase 6 |
| Trace correlation | Internal model language | Runtime-to-code links | Trace correlation | `traceCorrelation.ts`, `StrikeView.tsx` | Medium; links are advisory | Phase 6 |
| NEST | Engine-name-first | Evidence bundle | NEST | `WorkflowNav.tsx`, `NestView`, reports/docs | High; cannot imply verdict ownership | Phase 7 |
| GYRE | Engine-name-first | Verdict | GYRE | `BinaryVerdict`, `IntelligenceReport.tsx`, docs | Critical; preserve sole authority | Phase 1/7 |
| AETHERFRAME/Forge | Architecture-first | Advisory refinement | AETHERFRAME/Forge | `IntelligenceReport.tsx`, report adapter, docs | Critical; cannot mutate classification | Phase 1/7 |
| Maturity telemetry | Internal measurement term | Maturity & limits | Maturity telemetry | `DecompilerView.tsx`, `decompilerMaturity.ts`, exports | Medium; not correctness proof | Phase 5 |
| Confidence | Ambiguous: GYRE confidence vs advisory confidence | Advisory confidence outside Verdict | Confidence | `TalonView.tsx`, `DecompilerView.tsx`, reports | High; distinguish from GYRE confidence | Phase 2/5/7 |
| XRefs | Expert abbreviation | Linked references | XRefs | `FunctionBrowser.tsx`, `XRefPanel`, code map | Low; confidence should remain visible | Phase 4 |
| Basic block | Compiler/reversing jargon | Execution block | Basic block | `disassemblyModel.ts`, code map, decompiler/sidebar | Low/medium; inferred block warnings visible | Phase 4/5 |
| FunctionModel | Type name not user concept | Function record | FunctionModel | `disassemblyModel.ts`, `FunctionBrowser.tsx` | Low; inferred function boundaries visible | Phase 3/4 |
| JumpTableCandidate | Type/internal candidate | Possible switch table | JumpTableCandidate | `disassemblyModel.ts`, code map advanced details | Medium; candidate wording required | Phase 4 |
| Raw IR | Expert detail | Advanced IR details | Raw IR | `DecompilerView.tsx`, `decompilerIr.ts` | Medium; keep progressive disclosure | Phase 5 |
| Threat Score | Could imply final truth independent of GYRE | Verdict score or GYRE-linked score | Threat score | `IntelligenceReport.tsx`, `BinaryVerdict` | Critical; tie to GYRE | Phase 7 |
| Reasoning Chain | Could imply AI/assistant verdict reasoning | Evidence reasoning | Reasoning chain | `IntelligenceReport.tsx` | High; avoid non-GYRE authority implication | Phase 7 |

## Writing rules

Use:

- `advisory`, `evidence`, `linked`, `inferred`, `recorded`, `live session`, `maturity & limits`, `not verdict authority`.

Avoid as primary labels:

- `truth`, `proven source`, `recovered source`, `detonation`, `dynamic truth`, `AI verdict`, `autonomous conclusion`, `oracle`, `guaranteed`.

Use only with explicit boundary language:

- `confidence`, `runtime`, `decompile`, `debugger`, `reasoning`, `refinement`, `correlation`.

## Test implications

Future label changes need tests that check both clarity and authority:

- UI text tests for primary labels and tooltips.
- Export text tests for `source_engine: gyre` and `gyre_is_sole_verdict_source` where applicable.
- No-authority-leak tests proving TALON, STRIKE, AETHERFRAME, NEST, and NEXUS labels do not claim verdict mutation.
- Snapshot tests for authority banners.
- Search tests for banned overclaim phrases in docs and report strings.
