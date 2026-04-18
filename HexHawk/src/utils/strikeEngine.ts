/**
 * strikeEngine — STRIKE Runtime Intelligence Layer
 *
 * Wraps native debugger snapshots with:
 *   - Delta Engine:  register / flag diffs per step
 *   - Timeline:      step history management + replay
 *   - Pattern detection: timing checks, stack pivots, ROP chains, exception probes
 *   - Correlation signals: feed into correlationEngine
 *
 * The native execution is handled by the Rust backend (debugger.rs).
 * This engine provides the frontend intelligence layer on top of raw snapshots.
 */

import type { RegisterState, DebugSnapshot } from '../components/DebuggerPanel';
import type { BehavioralTag } from './correlationEngine';

// ── Register catalogue ────────────────────────────────────────────────────────

export const REG_KEYS = [
  'rax','rbx','rcx','rdx','rsi','rdi','rsp','rbp','rip',
  'r8','r9','r10','r11','r12','r13','r14','r15',
] as const;

export type RegKey = typeof REG_KEYS[number];

export const REG_LABELS: Record<RegKey, string> = {
  rax:'RAX', rbx:'RBX', rcx:'RCX', rdx:'RDX',
  rsi:'RSI', rdi:'RDI', rsp:'RSP', rbp:'RBP', rip:'RIP',
  r8:'R8',   r9:'R9',   r10:'R10', r11:'R11',
  r12:'R12', r13:'R13', r14:'R14', r15:'R15',
};

const FLAG_BITS: Array<[number, string]> = [
  [0x0001, 'CF'], [0x0004, 'PF'], [0x0010, 'AF'], [0x0040, 'ZF'],
  [0x0080, 'SF'], [0x0100, 'TF'], [0x0200, 'IF'], [0x0400, 'DF'], [0x0800, 'OF'],
];

// ── Delta types ───────────────────────────────────────────────────────────────

export interface RegisterDelta {
  key:   RegKey;
  label: string;
  prev:  number;
  curr:  number;
}

export interface FlagDelta {
  flag: string;
  prev: boolean;
  curr: boolean;
}

export type JumpType =
  | 'sequential'
  | 'branch-taken'
  | 'call'
  | 'ret'
  | 'indirect'
  | 'exception';

export interface StrikeDelta {
  registers:  RegisterDelta[];   // changed general-purpose registers
  flags:      FlagDelta[];       // changed EFLAGS bits
  rip:        number;
  prevRip:    number;
  ripOffset:  number;            // signed: currRip − prevRip
  jumpType:   JumpType;
  hasChanges: boolean;           // any register or flag changed
}

// ── Timeline types ────────────────────────────────────────────────────────────

export interface StrikeStep {
  index:          number;
  timestamp:      number;          // Date.now() at append time
  snapshot:       DebugSnapshot;
  delta:          StrikeDelta | null;  // null for the first step
  hitBreakpoint:  boolean;
  event:          string;          // snapshot.lastEvent
}

export interface StrikeTimeline {
  sessionId:     number;
  steps:         StrikeStep[];
  playheadIndex: number;           // −1 = no steps yet
  startTime:     number;           // Date.now() at creation
}

// ── Pattern detection types ───────────────────────────────────────────────────

export type PatternTag =
  | 'timing-check'
  | 'exception-probe'
  | 'stack-pivot'
  | 'rop-chain'
  | 'nop-sled'
  | 'anti-step'
  | 'cpuid-check';

export interface StrikePattern {
  tag:         PatternTag;
  label:       string;
  description: string;
  confidence:  number;   // 0–100
  firstStep:   number;   // index in timeline.steps
  stepSpan:    number;   // how many steps the pattern spans
}

// ── Correlation signal ────────────────────────────────────────────────────────

export interface StrikeCorrelationSignal {
  hasTimingCheck:    boolean;
  hasExceptionProbe: boolean;
  hasStackPivot:     boolean;
  hasRopActivity:    boolean;
  hasAntiStep:       boolean;
  hasCpuidCheck:     boolean;
  indirectJumpRatio: number;        // indirect jumps / total steps
  detectedPatterns:  PatternTag[];
  stepCount:         number;
  behavioralTags:    BehavioralTag[];
  riskScore:         number;        // 0–100
}

// ── Helper: jump classification ───────────────────────────────────────────────

function classifyJump(
  prevRip: number,
  currRip: number,
  event: string,
): JumpType {
  const ev = event.toLowerCase();
  if (ev.includes('exception') || ev.includes('access violation')) return 'exception';

  const delta = currRip - prevRip;

  // Sequential: RIP advanced by a typical instruction length (1–15 bytes)
  if (delta > 0 && delta <= 15) return 'sequential';

  // Detect call / ret from event string when available
  if (ev.includes(' call ') || ev.includes('called')) return 'call';
  if (ev.includes(' ret')   || ev.includes('return')) return 'ret';

  // Moderate backward jump — likely branch or short ret
  if (delta < 0 && delta > -0x10000) return 'branch-taken';

  // Moderate forward jump that isn't sequential — branch
  if (delta > 15 && delta < 0x10000) return 'branch-taken';

  // Everything else (far jump / indirect)
  return 'indirect';
}

// ── Delta computation ─────────────────────────────────────────────────────────

export function computeDelta(
  prev: DebugSnapshot,
  curr: DebugSnapshot,
): StrikeDelta {
  const registers: RegisterDelta[] = [];

  for (const key of REG_KEYS) {
    if (key === 'rip') continue;                     // handled via rip/prevRip fields
    const p = (prev.registers as unknown as Record<string, number>)[key] ?? 0;
    const c = (curr.registers as unknown as Record<string, number>)[key] ?? 0;
    if (p !== c) {
      registers.push({ key, label: REG_LABELS[key], prev: p, curr: c });
    }
  }

  const flags: FlagDelta[] = [];
  for (const [bit, flag] of FLAG_BITS) {
    const prevSet = !!(prev.registers.eflags & bit);
    const currSet = !!(curr.registers.eflags & bit);
    if (prevSet !== currSet) flags.push({ flag, prev: prevSet, curr: currSet });
  }

  const rip    = curr.registers.rip;
  const prevRip = prev.registers.rip;

  return {
    registers,
    flags,
    rip,
    prevRip,
    ripOffset:  rip - prevRip,
    jumpType:   classifyJump(prevRip, rip, curr.lastEvent),
    hasChanges: registers.length > 0 || flags.length > 0,
  };
}

// ── Timeline management ───────────────────────────────────────────────────────

export function createTimeline(sessionId: number): StrikeTimeline {
  return {
    sessionId,
    steps:         [],
    playheadIndex: -1,
    startTime:     Date.now(),
  };
}

export function appendStep(
  timeline: StrikeTimeline,
  snapshot: DebugSnapshot,
): { timeline: StrikeTimeline; step: StrikeStep } {
  const prev  = timeline.steps[timeline.steps.length - 1] ?? null;
  const delta = prev ? computeDelta(prev.snapshot, snapshot) : null;

  const step: StrikeStep = {
    index:         timeline.steps.length,
    timestamp:     Date.now(),
    snapshot,
    delta,
    hitBreakpoint: snapshot.breakpoints.includes(snapshot.registers.rip),
    event:         snapshot.lastEvent,
  };

  const updated: StrikeTimeline = {
    ...timeline,
    steps:         [...timeline.steps, step],
    playheadIndex: step.index,
  };

  return { timeline: updated, step };
}

export function seekTimeline(timeline: StrikeTimeline, index: number): StrikeTimeline {
  const clamped = Math.max(0, Math.min(timeline.steps.length - 1, index));
  return { ...timeline, playheadIndex: clamped };
}

export function currentStep(timeline: StrikeTimeline): StrikeStep | null {
  if (timeline.playheadIndex < 0 || timeline.steps.length === 0) return null;
  return timeline.steps[timeline.playheadIndex] ?? null;
}

// ── Pattern labels / descriptions ─────────────────────────────────────────────

const PATTERN_META: Record<PatternTag, { label: string; description: string }> = {
  'timing-check': {
    label:       'Timing Check (RDTSC)',
    description: 'Multiple RDTSC instructions observed — likely checking for debugger slowdown',
  },
  'exception-probe': {
    label:       'Exception Probe',
    description: 'Deliberate exception or INT3 triggered during execution',
  },
  'stack-pivot': {
    label:       'Stack Pivot',
    description: 'RSP changed by more than 4 KB in one step — possible ROP stack pivot',
  },
  'rop-chain': {
    label:       'ROP Chain Activity',
    description: '4+ sequential ret-type steps — possible Return-Oriented Programming chain',
  },
  'nop-sled': {
    label:       'NOP Sled',
    description: 'Long run of +1-byte RIP advances — possible NOP sled or decoder stub',
  },
  'anti-step': {
    label:       'Anti-Single-Step',
    description: 'Execution pattern suggests single-step detection via timing or exception tricks',
  },
  'cpuid-check': {
    label:       'CPUID Hypervisor Check',
    description: 'CPUID executed — common in VM/sandbox and debugger detection',
  },
};

// ── Pattern detection ─────────────────────────────────────────────────────────

export function detectPatterns(timeline: StrikeTimeline): StrikePattern[] {
  const steps = timeline.steps;
  if (steps.length < 2) return [];

  const patterns: StrikePattern[] = [];

  const rdtscSteps:     number[] = [];
  const exceptionSteps: number[] = [];
  const cpuidSteps:     number[] = [];

  let retStreak      = 0;
  let retStreakStart  = 0;
  let maxRetStreak   = 0;
  let maxRetStart    = 0;

  let nopRun      = 0;
  let nopRunStart  = 0;
  let maxNopRun   = 0;
  let maxNopStart  = 0;

  for (let i = 0; i < steps.length; i++) {
    const ev = steps[i].event.toLowerCase();
    const d  = steps[i].delta;

    // ── Instruction-level event tags ────────────────────────────────────────
    if (ev.includes('rdtsc')) rdtscSteps.push(i);
    if (ev.includes('cpuid')) cpuidSteps.push(i);
    if (ev.includes('exception') || ev.includes('int3') || ev.includes('access violation')) {
      exceptionSteps.push(i);
    }

    if (d) {
      // ── Stack pivot: RSP jump > 4 KB ──────────────────────────────────────
      const rspDelta = d.registers.find(r => r.key === 'rsp');
      if (rspDelta && Math.abs(rspDelta.curr - rspDelta.prev) > 0x1000) {
        patterns.push({
          tag:         'stack-pivot',
          ...PATTERN_META['stack-pivot'],
          confidence: 88,
          firstStep:  i,
          stepSpan:   1,
        });
      }

      // ── ROP chain: track consecutive ret-type steps ───────────────────────
      if (d.jumpType === 'ret' || ev.includes('ret')) {
        if (retStreak === 0) retStreakStart = i;
        retStreak++;
        if (retStreak > maxRetStreak) {
          maxRetStreak = retStreak;
          maxRetStart  = retStreakStart;
        }
      } else {
        retStreak = 0;
      }

      // ── NOP sled: RIP+1, sequential ──────────────────────────────────────
      if (d.ripOffset === 1 && d.jumpType === 'sequential') {
        if (nopRun === 0) nopRunStart = i;
        nopRun++;
        if (nopRun > maxNopRun) {
          maxNopRun   = nopRun;
          maxNopStart = nopRunStart;
        }
      } else {
        nopRun = 0;
      }
    }
  }

  // ── RDTSC timing check ────────────────────────────────────────────────────
  if (rdtscSteps.length >= 2) {
    const conf = Math.min(95, 70 + rdtscSteps.length * 5);
    patterns.push({
      tag:        'timing-check',
      ...PATTERN_META['timing-check'],
      confidence: conf,
      firstStep:  rdtscSteps[0],
      stepSpan:   rdtscSteps[rdtscSteps.length - 1] - rdtscSteps[0] + 1,
    });
  }

  // ── CPUID check ───────────────────────────────────────────────────────────
  if (cpuidSteps.length >= 1) {
    patterns.push({
      tag:        'cpuid-check',
      ...PATTERN_META['cpuid-check'],
      confidence: Math.min(90, 75 + cpuidSteps.length * 5),
      firstStep:  cpuidSteps[0],
      stepSpan:   1,
    });
  }

  // ── Exception probe ───────────────────────────────────────────────────────
  if (exceptionSteps.length >= 1) {
    patterns.push({
      tag:        'exception-probe',
      ...PATTERN_META['exception-probe'],
      confidence: Math.min(90, 65 + exceptionSteps.length * 10),
      firstStep:  exceptionSteps[0],
      stepSpan:   exceptionSteps.length > 1
        ? exceptionSteps[exceptionSteps.length - 1] - exceptionSteps[0] + 1
        : 1,
    });
  }

  // ── ROP chain (4+ rets) ───────────────────────────────────────────────────
  if (maxRetStreak >= 4) {
    patterns.push({
      tag:        'rop-chain',
      ...PATTERN_META['rop-chain'],
      confidence: Math.min(93, 60 + maxRetStreak * 4),
      firstStep:  maxRetStart,
      stepSpan:   maxRetStreak,
    });
  }

  // ── NOP sled (8+ steps) ───────────────────────────────────────────────────
  if (maxNopRun >= 8) {
    patterns.push({
      tag:        'nop-sled',
      ...PATTERN_META['nop-sled'],
      confidence: Math.min(85, 50 + maxNopRun * 3),
      firstStep:  maxNopStart,
      stepSpan:   maxNopRun,
    });
  }

  // ── Anti-step: timing-check + exception within 10 steps of each other ─────
  if (
    rdtscSteps.length >= 1 &&
    exceptionSteps.length >= 1 &&
    Math.abs(rdtscSteps[0] - exceptionSteps[0]) <= 10
  ) {
    patterns.push({
      tag:        'anti-step',
      ...PATTERN_META['anti-step'],
      confidence: 82,
      firstStep:  Math.min(rdtscSteps[0], exceptionSteps[0]),
      stepSpan:   Math.abs(rdtscSteps[0] - exceptionSteps[0]) + 1,
    });
  }

  // Deduplicate by tag — keep highest confidence per tag
  const byTag = new Map<PatternTag, StrikePattern>();
  for (const p of patterns) {
    const existing = byTag.get(p.tag);
    if (!existing || p.confidence > existing.confidence) byTag.set(p.tag, p);
  }

  return Array.from(byTag.values()).sort((a, b) => b.confidence - a.confidence);
}

// ── Correlation signal extraction ─────────────────────────────────────────────

export function extractCorrelationSignals(
  timeline: StrikeTimeline,
): StrikeCorrelationSignal {
  const patterns = detectPatterns(timeline);
  const tags     = new Set(patterns.map(p => p.tag));
  const steps    = timeline.steps;

  const indirectCount = steps.filter(s => s.delta?.jumpType === 'indirect').length;
  const indirectRatio = steps.length > 0 ? indirectCount / steps.length : 0;

  const behavioralTags: BehavioralTag[] = [];
  if (tags.has('timing-check') || tags.has('exception-probe') ||
      tags.has('anti-step')    || tags.has('cpuid-check')) {
    behavioralTags.push('anti-analysis');
  }
  if (tags.has('stack-pivot') || tags.has('rop-chain')) {
    behavioralTags.push('code-injection');
  }

  let risk = 0;
  if (tags.has('stack-pivot'))     risk += 30;
  if (tags.has('rop-chain'))       risk += 25;
  if (tags.has('timing-check'))    risk += 20;
  if (tags.has('exception-probe')) risk += 15;
  if (tags.has('anti-step'))       risk += 15;
  if (tags.has('cpuid-check'))     risk += 10;
  if (tags.has('nop-sled'))        risk += 10;
  if (indirectRatio > 0.25)        risk += Math.round(indirectRatio * 25);
  risk = Math.min(100, risk);

  return {
    hasTimingCheck:    tags.has('timing-check'),
    hasExceptionProbe: tags.has('exception-probe'),
    hasStackPivot:     tags.has('stack-pivot'),
    hasRopActivity:    tags.has('rop-chain'),
    hasAntiStep:       tags.has('anti-step'),
    hasCpuidCheck:     tags.has('cpuid-check'),
    indirectJumpRatio: indirectRatio,
    detectedPatterns:  Array.from(tags),
    stepCount:         steps.length,
    behavioralTags,
    riskScore:         risk,
  };
}
