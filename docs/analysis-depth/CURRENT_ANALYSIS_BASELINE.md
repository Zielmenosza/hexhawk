# HexHawk Analysis-Depth Baseline

Date: 2026-06-15
Scope: slow foundation slice for deeper disassembly, CFG, xrefs, decompiler maturity, and later debugger/trace work.

> **Historical snapshot.** This file preserves the 2026-06-15 analysis-depth baseline and its evidence limits. It does not describe the current HexHawk 1.0.0 persistence or packaging milestone. See [`../CURRENT_STATUS.md`](../CURRENT_STATUS.md). Broader decompiler/debugger maturity and Exploitability Mode remain roadmap work unless fresh native source and tests prove otherwise; manual or external-tool challenge success is not native HexHawk capability.

## Purpose

This baseline records the current source-level posture before adding a typed disassembly/program model. It is not a release-readiness update, native GUI proof, or decompiler correctness proof.

## Trust boundaries

- GYRE remains the sole classification and base-confidence authority.
- NEST remains evidence orchestration/convergence only.
- AETHERFRAME/Forge remains optional advisory packaging/refinement and must stay policy-gated.
- NEXUS remains an assistant/consumer/proposal layer only.
- TALON, STRIKE, CFG, decompiler output, debugger state, and imported traces are analyst evidence/advisory surfaces unless explicitly consumed by an existing GYRE-controlled path.
- Pseudocode is not recovered source. It is a deterministic analyst aid with warnings and maturity limits.

## Current disassembly behavior observed in source

- `HexHawk/src/App.tsx` stores disassembly as `DisassembledInstruction[]` with `address`, `mnemonic`, and `operands`.
- `HexHawk/src/components/DisassemblyList.tsx` renders a virtualized instruction list and passes each row into `EnhancedInstructionRow`.
- `EnhancedInstructionRow.tsx` classifies visible instruction rows into simple display categories such as CALL, JMP, JCOND, DATA, RET, STK, and OTHER.
- Disassembly UI already supports selected instruction state, highlighted ranges, function-start markers, loop markers, reference badges, annotations, and patch action buttons.
- Much of the deeper analysis still lives inside `App.tsx` rather than a standalone typed program model.

## Current function/xref/CFG behavior observed in source

- `App.tsx` builds reference maps from operands by detecting direct hex addresses, RIP-relative patterns, negative/backward offsets, and absolute memory operands.
- Current xref categories include call, conditional jump, jump, data, and RIP-relative references.
- Function detection in `App.tsx` is heuristic: entry instruction, call targets, prologue-like patterns, stack-allocation patterns, and selected jump targets that look like prologues.
- Function metadata includes start/end, call count, incoming calls, return count, loop flag, complexity, recursion, tail-call, calling convention guess, thunk status, and thunk target.
- CFG behavior exists in the GUI with address-to-block mapping and loop detection from graph back edges.
- The current implementation is useful but coupled to UI state, making it harder to reuse for decompiler, NEST evidence, reports, and future trace correlation.

## Current decompiler/TALON behavior observed in source/docs

- `HexHawk/src/utils/decompilerEngine.ts` already has a staged pipeline: lift, variables, blocks, structure, and pseudo-line emission.
- It explicitly states that output is deterministic, helpful, not perfect, and not reconstructed source.
- Decompiler telemetry includes advisory maturity fields and an authority boundary marker indicating TALON/VEIL guidance is not verdict authority.
- `docs/TESTER_RELEASE_STATUS.md` records current decompiler/TALON improvements: address consistency, fallback IR partitioning, 25-instruction + cross-block call argument recovery, and first-pass semantic naming heuristics.
- Existing tests include synthetic decompiler regressions and guarded real-binary regressions when `nest_cli` and samples are available.
- This slice does not change decompiler output or claim improved pseudo-C quality.

## Current debugger/STRIKE behavior observed in source

- `src-tauri/src/commands/debugger.rs` implements a Windows-native debugger backend using Windows debug APIs, with unsupported-platform errors outside Windows.
- The backend exposes session start, step, continue, breakpoints, stop/detach, state snapshots, and memory reads.
- `DebuggerPanel.tsx` provides register, stack, breakpoint, memory preview, and disassembly/hex sync UI.
- `StrikeView.tsx` layers runtime intelligence over debugger snapshots: register/flag deltas, timeline history, pattern alerts, and disassembly/hex navigation.
- This slice does not add live debugger behavior or imported trace support.

## Baseline limitation summary

- No current typed shared program model exists for disassembly, function models, xrefs, blocks, imports, data refs, string refs, jump-table candidates, call graph, and analysis warnings.
- Function/xref/CFG logic is partly duplicated or embedded in UI-side code.
- Disassembly confidence and uncertainty are not yet represented in a reusable typed model.
- Decompiler maturity exists, but deeper decompiler work needs a stable program model foundation first.
- Debugger/STRIKE can produce runtime evidence, but trace-to-program-model correlation is future work.

## First foundation slice added

This slice adds a new typed foundation under `HexHawk/src/utils/`:

- `disassemblyModel.ts`: shared advisory model types.
- `disassemblyAnalysis.ts`: first-pass synthetic-testable analysis helpers for conservative starts, ends, xrefs, block splitting, confidence, and warnings.

The new model is not yet wired into the GUI. Preserving current UI behavior is intentional for this slice.

## What remains unproven

- No native Tauri GUI workflow was rerun for this slice.
- No real-binary disassembly accuracy claims were added.
- No decompiler correctness, source recovery, or pseudo-C maturity claim was added.
- No debugger runtime or trace-import proof was added.
- No NEST evidence export integration was added yet.

## Recommended next slice

Integrate the typed program model behind the existing disassembly view without changing visible behavior:

1. Build the typed model from current `DisassembledInstruction[]` in `App.tsx`.
2. Compare current UI-local function/xref maps against `buildProgramAnalysis(...)` on synthetic fixtures.
3. Start replacing UI-local maps only after parity tests pass.
4. Keep warnings visible in developer/test surfaces before exposing them broadly in the GUI.
