/**
 * HexHawk Patch Intelligence Engine
 *
 * Detects patchable branch instructions and explains WHY each patch is
 * suggested, linking it back to the underlying GYRE signal.
 *
 * Design invariants:
 *   • NEVER auto-applies patches — every suggestion requires explicit user action
 *   • Each suggestion carries a full explainability chain
 *   • Signal linkage connects suggestions to GYRE verdict signals
 *   • Risk levels guide analyst caution (low / medium / high)
 */

import type { CorrelatedSignal, BinaryVerdictResult } from './correlationEngine';
import type { LogicRegion } from './decompilerEngine';

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

export type PatchKind = 'invert-jump' | 'nop-sled' | 'nop-call';
export type PatchRiskLevel = 'low' | 'medium' | 'high';

/** Link between a patch suggestion and the GYRE signal that triggered it */
export interface PatchSignalLink {
  /** GYRE signal ID */
  signalId: string;
  /** Human-readable finding text from the signal */
  finding: string;
  /** Evidence tier: DIRECT / STRONG / WEAK */
  tier: string;
}

/**
 * A single explainable patch suggestion.
 *
 * The suggestion is purely advisory: it describes what the patch would do
 * and why it was flagged, but does NOT modify the binary. The user must
 * explicitly queue it via the Patch Panel.
 */
export interface PatchSuggestion {
  id: string;
  address: number;
  kind: PatchKind;
  /** Display label, e.g. "JZ → JNZ (jumps if equal, ZF=1)" */
  label: string;
  /** One-sentence reason this instruction was flagged as a patch candidate */
  reason: string;
  /** Paragraph describing what applying the patch would do to execution */
  impact: string;
  /** What the analyst should verify before applying this patch */
  verifyBefore: string;
  /** Risk level: low = safe inversion; high = may corrupt stack/control flow */
  risk: PatchRiskLevel;
  /** GYRE signals that contributed to this suggestion */
  signalLinks: PatchSignalLink[];
  /** Logic region (from decompilerEngine) that contains this branch, if any */
  logicRegion?: LogicRegion;
}

// ─────────────────────────────────────────────────────────────────────────────
// Conditional jump mnemonics (x86/x64 + AArch64)
// ─────────────────────────────────────────────────────────────────────────────

const JCC_MNEMONICS = new Set([
  'je', 'jz', 'jne', 'jnz',
  'jl', 'jnge', 'jle', 'jng',
  'jg', 'jnle', 'jge', 'jnl',
  'ja', 'jnbe', 'jae', 'jnb',
  'jb', 'jnae', 'jbe', 'jna',
  'js', 'jns', 'jo', 'jno', 'jp', 'jnp',
  // AArch64
  'b.eq', 'b.ne', 'b.lt', 'b.gt', 'b.le', 'b.ge',
  'b.lo', 'b.hi', 'b.ls', 'b.hs', 'b.mi', 'b.pl',
  'cbz', 'cbnz', 'tbz', 'tbnz',
]);

/** Human-readable descriptions of each condition code */
const JCC_CONDITION: Record<string, string> = {
  je:   'jumps if equal (ZF=1)',
  jz:   'jumps if zero (ZF=1)',
  jne:  'jumps if not equal (ZF=0)',
  jnz:  'jumps if not zero (ZF=0)',
  jl:   'jumps if less-than (signed)',
  jnge: 'jumps if not greater-or-equal',
  jle:  'jumps if less-or-equal (signed)',
  jng:  'jumps if not greater',
  jg:   'jumps if greater-than (signed)',
  jnle: 'jumps if not less-or-equal',
  jge:  'jumps if greater-or-equal (signed)',
  jnl:  'jumps if not less',
  ja:   'jumps if above (unsigned)',
  jnbe: 'jumps if not below-or-equal',
  jae:  'jumps if above-or-equal (unsigned)',
  jnb:  'jumps if not below',
  jb:   'jumps if below (unsigned)',
  jnae: 'jumps if not above-or-equal',
  jbe:  'jumps if below-or-equal (unsigned)',
  jna:  'jumps if not above',
  js:   'jumps if sign flag set (result was negative)',
  jns:  'jumps if sign flag clear (result was non-negative)',
  jo:   'jumps if overflow',
  jno:  'jumps if no overflow',
  jp:   'jumps if parity set',
  jnp:  'jumps if parity clear',
  cbz:  'jumps if register is zero (AArch64)',
  cbnz: 'jumps if register is non-zero (AArch64)',
  tbz:  'jumps if bit is zero (AArch64)',
  tbnz: 'jumps if bit is non-zero (AArch64)',
};

/** Logical inversion of each conditional jump */
const JCC_INVERSION: Record<string, string> = {
  je:   'JNE', jz:   'JNZ',
  jne:  'JE',  jnz:  'JZ',
  jl:   'JGE', jnge: 'JGE',
  jle:  'JG',  jng:  'JG',
  jg:   'JLE', jnle: 'JLE',
  jge:  'JL',  jnl:  'JL',
  ja:   'JBE', jnbe: 'JBE',
  jae:  'JB',  jnb:  'JB',
  jb:   'JAE', jnae: 'JAE',
  jbe:  'JA',  jna:  'JA',
  js:   'JNS', jns:  'JS',
  jo:   'JNO', jno:  'JO',
  jp:   'JNP', jnp:  'JP',
  cbz:  'CBNZ', cbnz: 'CBZ',
  tbz:  'TBNZ', tbnz: 'TBZ',
};

// ─────────────────────────────────────────────────────────────────────────────
// Signal → patch context classification
// ─────────────────────────────────────────────────────────────────────────────

interface ClassifiedPatch {
  reason: string;
  impact: string;
  verifyBefore: string;
  risk: PatchRiskLevel;
  relevantSignals: CorrelatedSignal[];
}

/**
 * Given a conditional jump or call instruction, classify WHY it is a patch
 * candidate based on the active GYRE signals and logic region context.
 *
 * Returns null if there is no signal-driven justification for patching this
 * instruction — suppresses low-quality noise suggestions.
 */
function classifyPatchReason(
  mn: string,
  verdict: BinaryVerdictResult | null,
  logicRegion: LogicRegion | undefined,
): ClassifiedPatch | null {
  const signals = verdict?.signals ?? [];
  const relevantSignals: CorrelatedSignal[] = [];

  // ── Priority 1: Validation / license-check logic region ─────────────────
  // Branches inside a serial-comparison or validation-gate region are prime
  // patch candidates — inverting them bypasses the protection gate.
  if (logicRegion && (
    logicRegion.kind === 'serial-comparison' ||
    logicRegion.kind === 'validation-gate'
  )) {
    const valSignal = signals.find(s => s.id === 'validation-logic');
    if (valSignal) relevantSignals.push(valSignal);
    const critPatterns = signals.find(s => s.id === 'critical-patterns');
    if (critPatterns) relevantSignals.push(critPatterns);

    const regionDesc = logicRegion.kind === 'serial-comparison'
      ? 'serial-comparison check (probable license / auth gate)'
      : 'multi-condition validation gate';

    return {
      reason: `This conditional branch is inside a ${regionDesc} — inverting it may bypass the protection check.`,
      impact:
        `Inverting this jump causes execution to take the opposite branch. ` +
        `If this is the final gating branch, it may allow bypassing the check entirely. ` +
        `If the check spans multiple branches, additional patches may be needed.`,
      verifyBefore:
        `Confirm in TALON that this is the decisive branch (not an intermediate sub-check). ` +
        `Trace the "failure" path to verify it leads to rejection and not a crash or undefined state.`,
      risk: 'medium',
      relevantSignals,
    };
  }

  // ── Priority 2: Protection-guard region ─────────────────────────────────
  // Branch inside an integrity-check region — inverting may bypass anti-tamper.
  if (logicRegion && logicRegion.kind === 'protection-guard') {
    const valSignal = signals.find(s => s.id === 'validation-logic');
    if (valSignal) relevantSignals.push(valSignal);

    return {
      reason: `This branch is inside a protection-guard region (comparison + call + branch) — likely an anti-tamper or integrity-check gate.`,
      impact:
        `Inverting this jump will bypass the integrity check. ` +
        `The protected code path will execute even if the check would have failed. ` +
        `If the check verifies a cryptographic hash, the binary may misbehave with an invalid signature.`,
      verifyBefore:
        `Identify what function is called in this block (check TALON intent). ` +
        `Confirm the branch direction — some integrity checks pass on 0 (equal), others on non-zero.`,
      risk: 'high',
      relevantSignals,
    };
  }

  // ── Priority 3: Anti-debug exit gate ────────────────────────────────────
  // je/jne/jz/jnz are the canonical patterns for IsDebuggerPresent exit gates.
  const ANTIDEBUG_IDS = ['antidebug-imports', 'talon-anti-debug', 'strike-anti-debug'];
  const antidebug = signals.find(s => ANTIDEBUG_IDS.includes(s.id));
  if (antidebug && ['je', 'jne', 'jz', 'jnz', 'cbz', 'cbnz'].includes(mn)) {
    relevantSignals.push(antidebug);

    return {
      reason: `Anti-debug signal detected in this binary — this conditional branch may be an IsDebuggerPresent exit gate.`,
      impact:
        `Inverting this jump negates the debugger-detection check. ` +
        `If the original code terminates or alters behaviour when a debugger is present, ` +
        `the patched binary will continue executing normally under a debugger.`,
      verifyBefore:
        `Confirm in the disassembly that the preceding comparison checks the IsDebuggerPresent ` +
        `return value (cmp eax, 0 / test eax, eax). Ensure the branch does not also control ` +
        `legitimate logic unrelated to debugger detection.`,
      risk: 'low',
      relevantSignals,
    };
  }

  // ── Priority 4: NOP candidate — dangerous call site ────────────────────
  // Call instructions adjacent to dangerous-import signals are candidates for
  // NOP-sled suppression when the analyst wants to disable a capability.
  if (mn === 'call') {
    const DANGEROUS_IDS = ['injection-imports', 'antidebug-imports', 'exec-imports', 'dynload-imports'];
    const dangerous = signals.filter(s => DANGEROUS_IDS.includes(s.id));
    if (dangerous.length > 0) {
      relevantSignals.push(...dangerous);
      return {
        reason: `This call site is near dangerous API imports (${dangerous.map(s => s.id).join(', ')}) — NOP-ing it may disable a malicious capability.`,
        impact:
          `Replacing the call with NOPs prevents the target function from executing. ` +
          `All side effects (memory writes, API calls, handles opened) are suppressed. ` +
          `The stack is NOT affected — a CALL instruction pops its own return address; NOPs do not.`,
        verifyBefore:
          `Identify the exact function being called. Check whether it returns a value used by ` +
          `subsequent code (if so, NOP-ing may cause a null-dereference or incorrect branch downstream). ` +
          `Use TALON to confirm the call target matches a dangerous import.`,
        risk: 'high',
        relevantSignals,
      };
    }
  }

  return null;
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

function buildSignalLinks(signals: CorrelatedSignal[]): PatchSignalLink[] {
  return signals.map(s => ({
    signalId: s.id,
    finding: s.finding,
    tier: s.tier ?? 'WEAK',
  }));
}

let _suggestionCounter = 0;
function makeSuggestionId(): string {
  return `ps-${++_suggestionCounter}-${Date.now().toString(36)}`;
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

export interface PatchableInstruction {
  address: number;
  mnemonic: string;
  operands: string;
}

/**
 * Scan a disassembly listing and return explainable, signal-linked patch
 * suggestions. Suggestions are ranked by specificity:
 *   1. Branches inside validation/license-check logic regions (highest priority)
 *   2. Protection-guard region branches
 *   3. Anti-debug exit gates
 *   4. NOP candidates near dangerous call sites
 *
 * No patches are applied automatically. The caller is responsible for
 * displaying suggestions and letting the user decide whether to queue them.
 *
 * @param instructions  Flat instruction listing from the disassembler
 * @param verdict       GYRE verdict result (may be null before first run)
 * @param logicRegions  Logic regions from detectLogicRegions() (may be empty)
 * @param maxResults    Maximum suggestions to return (default 20)
 */
export function detectPatchableBranches(
  instructions: PatchableInstruction[],
  verdict: BinaryVerdictResult | null,
  logicRegions: LogicRegion[],
  maxResults = 20,
): PatchSuggestion[] {
  const suggestions: PatchSuggestion[] = [];

  // Build a fast address-to-region map using both the region base address
  // and every related instruction address within it.
  const regionByAddr = new Map<number, LogicRegion>();
  for (const region of logicRegions) {
    regionByAddr.set(region.address, region);
    for (const addr of region.relatedAddresses) {
      regionByAddr.set(addr, region);
    }
  }

  for (const ins of instructions) {
    if (suggestions.length >= maxResults) break;

    const mn = ins.mnemonic.toLowerCase().trim();

    // Only process conditional jumps and calls
    if (!JCC_MNEMONICS.has(mn) && mn !== 'call') continue;

    const logicRegion = regionByAddr.get(ins.address);
    const classified = classifyPatchReason(mn, verdict, logicRegion);
    if (!classified) continue;

    // Skip duplicates at the same address (two regions can map the same addr)
    if (suggestions.some(s => s.address === ins.address)) continue;

    const invertedMn = JCC_INVERSION[mn];
    const condDesc = JCC_CONDITION[mn];
    const kind: PatchKind = mn === 'call' ? 'nop-call' : 'invert-jump';

    let label: string;
    if (kind === 'nop-call') {
      label = `NOP call @ 0x${ins.address.toString(16).toUpperCase()}`;
    } else if (invertedMn) {
      label = condDesc
        ? `${mn.toUpperCase()} → ${invertedMn}  (${condDesc})`
        : `${mn.toUpperCase()} → ${invertedMn}`;
    } else {
      label = condDesc
        ? `Invert ${mn.toUpperCase()}  (${condDesc})`
        : `Invert ${mn.toUpperCase()}`;
    }

    suggestions.push({
      id: makeSuggestionId(),
      address: ins.address,
      kind,
      label,
      reason: classified.reason,
      impact: classified.impact,
      verifyBefore: classified.verifyBefore,
      risk: classified.risk,
      signalLinks: buildSignalLinks(classified.relevantSignals),
      logicRegion,
    });
  }

  // Rank: validation-gate first (kind 0), protection-guard (1), anti-debug (2), nop-call (3)
  return suggestions.sort((a, b) => {
    function rankKind(s: PatchSuggestion): number {
      if (!s.logicRegion) return s.kind === 'nop-call' ? 3 : 2;
      if (s.logicRegion.kind === 'serial-comparison' || s.logicRegion.kind === 'validation-gate') return 0;
      if (s.logicRegion.kind === 'protection-guard') return 1;
      return 2;
    }
    return rankKind(a) - rankKind(b);
  });
}
