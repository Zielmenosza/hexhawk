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

import type { Breakpoint, RegisterState, DebugSnapshot } from '../components/DebuggerPanel';
import type { BehavioralTag } from './correlationEngine';
import type { DecompilerIrNode, DecompilerIrValue } from './decompilerTypes';
import { buildXRefIndex } from './disassemblyAnalysis';
import { buildFunctionIntelligence, exportFunctionIntelligenceJSON } from './functionIntelligence';
import { STRIKE_API_METHODS, generateStrikeApiSchema } from './strikeApiReference';
import type { ProgramAnalysis } from './disassemblyModel';
import {
  annotateReachingDefinitions as annotateReachingDefinitionsPass,
  constantFoldDecompilerIr as constantFoldDecompilerIrPass,
  eliminateDeadStores as eliminateDeadStoresPass,
  runMidLevelIrPasses as runMidLevelIrPassesPipeline,
} from './decompilerIr';
import {
  IMPORT_PROTOTYPES,
  formatImportPrototype,
  resolveConstantAnnotation,
  resolveImportPrototype as builtinResolveImportPrototype,
  type ImportPrototype,
} from './importPrototypes';
export {
  annotateReachingDefinitions,
  constantFoldDecompilerIr,
  eliminateDeadStores,
  runMidLevelIrPasses,
} from './decompilerIr';
export type { ReachingDefs } from './decompilerTypes';
export { formatImportPrototype, IMPORT_PROTOTYPES, resolveConstantAnnotation } from './importPrototypes';
export { STRIKE_API_METHODS, generateStrikeApiSchema } from './strikeApiReference';
export type { ImportPrototype, ImportParameterPrototype } from './importPrototypes';


/** STRIKE plugin hook events. Hooks are advisory extension points and must not mutate GYRE verdict authority. */
export type StrikeHookEvent = 'pre-analysis' | 'post-analysis' | 'custom-lifter' | 'custom-resolver';

/** Context passed before a STRIKE/GYRE/NEST analysis pipeline begins. */
export interface StrikePreAnalysisContext {
  readonly filePath?: string;
  readonly nodes?: readonly DecompilerIrNode[];
}

/** Context passed after analysis. Verdict fields are restored after hooks so plugins cannot change GYRE authority. */
export interface StrikePostAnalysisContext {
  result: StrikeAnalysisResult;
}

/** Context for plugin-provided lifters for unknown opcodes. Return lifted nodes to claim the opcode. */
export interface StrikeCustomLifterContext {
  readonly instruction: { address: number; mnemonic: string; operands: string };
}

/** Context for plugin-provided import prototype resolvers. Return an ImportPrototype to override built-ins. */
export interface StrikeCustomResolverContext {
  readonly importName: string;
}

export interface StrikeAnalysisResult {
  verdict?: {
    classification?: string;
    confidence?: string | number;
    [key: string]: unknown;
  };
  [key: string]: unknown;
}

export type StrikeHookContext =
  | StrikePreAnalysisContext
  | StrikePostAnalysisContext
  | StrikeCustomLifterContext
  | StrikeCustomResolverContext;

/** Handler contract for STRIKE hooks. Throwing handlers are logged and isolated; later hooks still run. */
export type StrikeHookHandler<TContext extends StrikeHookContext = StrikeHookContext> = (context: TContext) => unknown;

const STRIKE_HOOKS: Record<StrikeHookEvent, StrikeHookHandler[]> = {
  'pre-analysis': [],
  'post-analysis': [],
  'custom-lifter': [],
  'custom-resolver': [],
};

/** Register a STRIKE plugin hook. Handlers run in registration order and are isolated from pipeline failure. */
export function registerHook(event: StrikeHookEvent, handler: StrikeHookHandler): void {
  STRIKE_HOOKS[event].push(handler);
}

export function clearStrikeHooksForTests(): void {
  for (const event of Object.keys(STRIKE_HOOKS) as StrikeHookEvent[]) STRIKE_HOOKS[event] = [];
}

function runHookList(event: StrikeHookEvent, context: StrikeHookContext): unknown[] {
  const results: unknown[] = [];
  for (const handler of STRIKE_HOOKS[event]) {
    try {
      results.push(handler(context));
    } catch (error) {
      console.error(`STRIKE hook '${event}' failed`, error);
    }
  }
  return results;
}

export function runStrikePreAnalysisHooks(context: StrikePreAnalysisContext): void {
  runHookList('pre-analysis', context);
}

export function runStrikePostAnalysisHooks(result: StrikeAnalysisResult): StrikeAnalysisResult {
  const originalVerdict = result.verdict ? { ...result.verdict } : undefined;
  runHookList('post-analysis', { result });
  if (originalVerdict && result.verdict) {
    result.verdict.classification = originalVerdict.classification;
    result.verdict.confidence = originalVerdict.confidence;
  }
  return result;
}

export function resolveImportPrototype(name: string | undefined | null): ImportPrototype | undefined {
  if (!name) return undefined;
  for (const result of runHookList('custom-resolver', { importName: name })) {
    if (result && typeof result === 'object' && 'name' in result && 'parameters' in result) {
      return result as ImportPrototype;
    }
  }
  return builtinResolveImportPrototype(name);
}




// ── STRIKE IL opcode-tree pattern matching ────────────────────────────────────

export type WildcardPattern = { wildcard: true; bind?: string };
export type ILPattern = { opcode: string; operands?: Array<ILPattern | WildcardPattern> };
export type ILMatchBinding = DecompilerIrNode | DecompilerIrValue;
export interface ILMatchResult {
  node: DecompilerIrNode;
  bindings: Record<string, ILMatchBinding>;
}

function isWildcardPattern(pattern: ILPattern | WildcardPattern): pattern is WildcardPattern {
  return (pattern as WildcardPattern).wildcard === true;
}

function operandChildren(node: DecompilerIrNode): ILMatchBinding[] {
  switch (node.kind) {
    case 'assignment': return [node.destination, node.source];
    case 'load': return [node.destination, node.source];
    case 'store': return [node.destination, node.source];
    case 'arithmetic': return [node.destination, node.left, node.right];
    case 'compare': return [node.left, node.right];
    case 'conditional-branch': return [];
    case 'call': return node.args;
    case 'return': return node.value ? [node.value] : [];
    case 'stack-variable-candidate': return [node.variable];
    case 'register-variable-candidate': return [node.variable];
    case 'side-effect-note': return [];
    case 'unknown': return [];
  }
}

function valueOpcode(value: DecompilerIrValue): string {
  return value.kind;
}

function matchValue(
  value: ILMatchBinding,
  pattern: ILPattern | WildcardPattern,
  bindings: Record<string, ILMatchBinding>,
): boolean {
  if (isWildcardPattern(pattern)) {
    if (pattern.bind) bindings[pattern.bind] = value;
    return true;
  }

  const opcode = 'kind' in value ? value.kind : '';
  if (opcode !== pattern.opcode) return false;
  if ('address' in value) return matchNode(value, pattern, bindings);
  return (pattern.operands?.length ?? 0) === 0 || valueOpcode(value) === pattern.opcode;
}

function matchNode(
  node: DecompilerIrNode,
  pattern: ILPattern,
  bindings: Record<string, ILMatchBinding>,
): boolean {
  if (node.kind !== pattern.opcode) return false;
  const operands = pattern.operands ?? [];
  if (operands.length === 0) return true;
  const children = operandChildren(node);
  if (operands.length > children.length) return false;
  for (let i = 0; i < operands.length; i += 1) {
    if (!matchValue(children[i], operands[i], bindings)) return false;
  }
  return true;
}

export function matchIL(nodes: DecompilerIrNode[], pattern: ILPattern): ILMatchResult[] {
  const results: ILMatchResult[] = [];
  for (const node of nodes) {
    const bindings: Record<string, ILMatchBinding> = {};
    if (matchNode(node, pattern, bindings)) {
      results.push({ node, bindings });
    }
  }
  return results;
}

export interface StrikeRecoveredStructField {
  offset: number;
  name: string;
  type: string;
}

export interface StrikeRecoveredStruct {
  name: string;
  base: string;
  fields: StrikeRecoveredStructField[];
  evidenceAddresses: number[];
  advisoryOnly: true;
  authority: 'nest_type_recovery_not_gyre_verdict';
}

export interface StrikeILQuerySurface {
  matchIL(pattern: ILPattern): ILMatchResult[];
  constantFold(): DecompilerIrNode[];
  eliminateDeadStores(): DecompilerIrNode[];
  annotateReachingDefinitions(): DecompilerIrNode[];
  runMidLevelIrPasses(): DecompilerIrNode[];
  getRecoveredStructs(): StrikeRecoveredStruct[];
  buildXRefIndex(analysis: ProgramAnalysis): ReturnType<typeof buildXRefIndex>;
  registerHook(event: StrikeHookEvent, handler: StrikeHookHandler): void;
}


function strikeFieldNameForOffset(offset: number): string {
  const magnitude = Math.abs(offset);
  const width = magnitude <= 0xff ? 2 : magnitude <= 0xffff ? 4 : 8;
  const hex = magnitude.toString(16).padStart(width, '0');
  return offset < 0 ? `field_neg_${hex}` : `field_${hex}`;
}

function isMemoryValue(value: ILMatchBinding): value is Extract<DecompilerIrValue, { kind: 'memory' }> {
  return !('address' in value) && value.kind === 'memory';
}

function collectMemoryValues(node: DecompilerIrNode): Array<Extract<DecompilerIrValue, { kind: 'memory' }>> {
  return operandChildren(node).filter(isMemoryValue);
}

const STRUCT_RECOVERY_IGNORED_BASES = new Set(['rbp', 'ebp', 'rsp', 'esp', 'r11', 'fp', 'x29', 'sp']);

export function recoverStructsFromIL(nodes: DecompilerIrNode[]): StrikeRecoveredStruct[] {
  const accesses = new Map<string, Map<number, Set<number>>>();
  for (const node of nodes) {
    for (const value of collectMemoryValues(node)) {
      if (!value.base || value.offset === undefined) continue;
      if (STRUCT_RECOVERY_IGNORED_BASES.has(value.base)) continue;
      const byOffset = accesses.get(value.base) ?? new Map<number, Set<number>>();
      const evidence = byOffset.get(value.offset) ?? new Set<number>();
      evidence.add(node.address);
      byOffset.set(value.offset, evidence);
      accesses.set(value.base, byOffset);
    }
  }

  const structs: StrikeRecoveredStruct[] = [];
  for (const base of Array.from(accesses.keys()).sort()) {
    const byOffset = accesses.get(base)!;
    const offsets = Array.from(byOffset.keys()).sort((a, b) => a - b);
    if (offsets.length < 3) continue;
    const evidenceAddresses = Array.from(new Set(offsets.flatMap(offset => Array.from(byOffset.get(offset)!)))).sort((a, b) => a - b);
    structs.push({
      name: `struct_${base.replace(/[^a-zA-Z0-9_]/g, '_') || 'ptr'}`,
      base,
      fields: offsets.map(offset => ({ offset, name: strikeFieldNameForOffset(offset), type: 'u64' })),
      evidenceAddresses,
      advisoryOnly: true,
      authority: 'nest_type_recovery_not_gyre_verdict',
    });
  }
  return structs;
}

export function createStrikeQuerySurface(nodes: DecompilerIrNode[]): StrikeILQuerySurface {
  return {
    matchIL: (pattern: ILPattern) => matchIL(nodes, pattern),
    constantFold: () => constantFoldDecompilerIrPass(nodes),
    eliminateDeadStores: () => eliminateDeadStoresPass(nodes),
    annotateReachingDefinitions: () => annotateReachingDefinitionsPass(nodes),
    runMidLevelIrPasses: () => runMidLevelIrPassesPipeline(nodes),
    getRecoveredStructs: () => recoverStructsFromIL(nodes),
    buildXRefIndex,
    registerHook,
  };
}


export const strike = {
  registerHook,
  getRecoveredStructs: recoverStructsFromIL,
  buildXRefIndex,
  resolveImportPrototype,
  resolveConstantAnnotation,
  buildFunctionIntelligence,
  exportFunctionIntelligenceJSON,
  apiMethods: STRIKE_API_METHODS,
  generateApiSchema: generateStrikeApiSchema,
  runPreAnalysisHooks: runStrikePreAnalysisHooks,
  runPostAnalysisHooks: runStrikePostAnalysisHooks,
};

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

export interface StrikeBreakpointHit {
  address: number;
  enabled: boolean;
  condition?: string | null;
  hitCount?: number;
  lastEvaluation?: string | null;
}

export interface StrikeStep {
  index:          number;
  timestamp:      number;          // Date.now() at append time
  snapshot:       DebugSnapshot;
  delta:          StrikeDelta | null;  // null for the first step
  hitBreakpoint:  boolean;
  breakpointHit?: StrikeBreakpointHit;
  event:          string;          // snapshot.lastEvent
}

export interface StrikeTimeline {
  sessionId:     number;
  steps:         StrikeStep[];
  playheadIndex: number;           // −1 = no steps yet
  startTime:     number;           // Date.now() at creation
}

export const MAX_STRIKE_TIMELINE_STEPS = 5000;

// ── Pattern detection types ───────────────────────────────────────────────────

export type PatternTag =
  | 'timing-check'
  | 'exception-probe'
  | 'stack-pivot'
  | 'rop-chain'
  | 'nop-sled'
  | 'anti-step'
  | 'cpuid-check'
  // ── New signals (FLARE challenge analysis) ──────────────────────────────────
  | 'anti-debug-probe'        // TF-flag trap, INT3 probe, or IsDebuggerPresent call
  | 'self-modifying-code'     // Decoder/unpacker stub: RIP loops in small region then writes new code
  | 'oep-transfer'            // Large RIP displacement after decoder stub — Original Entry Point handoff
  | 'dynamic-api-resolution'  // Burst of indirect calls (GetProcAddress chain / shellcode import resolve)
  | 'peb-walk';               // Direct Process Environment Block access (gs:0x60 / manual import walk)

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
  hasTimingCheck:          boolean;
  hasExceptionProbe:       boolean;
  hasStackPivot:           boolean;
  hasRopActivity:          boolean;
  hasAntiStep:             boolean;
  hasCpuidCheck:           boolean;
  // New signal fields
  hasAntiDebugProbe:       boolean;  // TF probe / INT3 probe / IsDebuggerPresent
  hasUnpackingBehavior:    boolean;  // self-modifying-code or oep-transfer
  hasDynamicApiResolution: boolean;  // burst indirect calls / GetProcAddress chain
  hasPebWalk:              boolean;  // direct PEB access
  /**
   * Runtime composite: anti-debug-probe + peb-walk + dynamic-api-resolution
   * all observed in the same session.  Mirrors the static rat-composite signal
   * from correlationEngine but derived purely from runtime execution evidence.
   */
  hasRatPattern:           boolean;
  /**
   * Runtime composite: unpacking behavior (self-modifying-code / oep-transfer)
   * AND exception probe AND ROP activity observed together.  Consistent with
   * a wiper that decrypts and self-executes a payload via ROP gadgets.
   */
  hasWiperPattern:         boolean;
  indirectJumpRatio:       number;   // indirect jumps / total steps
  detectedPatterns:        PatternTag[];
  stepCount:               number;
  behavioralTags:          BehavioralTag[];
  riskScore:               number;   // 0–100
}

// ── Helper: jump classification ───────────────────────────────────────────────

function hasEventToken(event: string, token: string): boolean {
  return new RegExp(`(?:^|[^a-z0-9_])${token}(?:$|[^a-z0-9_])`, 'i').test(event);
}

function classifyJump(
  prevRip: number,
  currRip: number,
  event: string,
): JumpType {
  const ev = event.toLowerCase();
  if (ev.includes('exception') || ev.includes('access violation')) return 'exception';

  // Prefer explicit debugger event tokens over distance heuristics. A direct call
  // may advance only a few bytes in synthetic traces, and an indirect jmp can be
  // nearby; token-aware classification keeps call-stack reconstruction stable.
  if ((ev.includes('getprocaddress') || ev.includes('loadlibrary') || ev.includes('resolver')) &&
      (hasEventToken(ev, 'call') || hasEventToken(ev, 'jmp'))) return 'indirect';
  if (hasEventToken(ev, 'jmp') && hasEventToken(ev, 'call')) return 'indirect';
  if (hasEventToken(ev, 'call') || hasEventToken(ev, 'called')) return 'call';
  if (hasEventToken(ev, 'ret') || hasEventToken(ev, 'return')) return 'ret';
  if (hasEventToken(ev, 'jmp') || ev.includes('indirect jump')) return 'indirect';

  const delta = currRip - prevRip;

  // Sequential: RIP advanced by a typical instruction length (1–15 bytes)
  if (delta > 0 && delta <= 15) return 'sequential';

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

function breakpointAddressOf(bp: Breakpoint): number {
  return typeof bp === 'number' ? bp : bp.address;
}

function breakpointEnabled(bp: Breakpoint): boolean {
  return typeof bp === 'number' ? true : bp.enabled;
}

export function findBreakpointHit(snapshot: DebugSnapshot): StrikeBreakpointHit | null {
  const rip = snapshot.registers.rip;
  for (const bp of snapshot.breakpoints) {
    if (!breakpointEnabled(bp)) continue;
    if (breakpointAddressOf(bp) !== rip) continue;
    if (typeof bp === 'number') return { address: bp, enabled: true };
    return {
      address: bp.address,
      enabled: bp.enabled,
      condition: bp.condition ?? null,
      hitCount: bp.hitCount,
      lastEvaluation: bp.lastEvaluation ?? null,
    };
  }
  return null;
}

export function appendStep(
  timeline: StrikeTimeline,
  snapshot: DebugSnapshot,
): { timeline: StrikeTimeline; step: StrikeStep } {
  const prev  = timeline.steps[timeline.steps.length - 1] ?? null;
  const delta = prev ? computeDelta(prev.snapshot, snapshot) : null;
  const breakpointHit = findBreakpointHit(snapshot);

  const step: StrikeStep = {
    index:         timeline.steps.length,
    timestamp:     Date.now(),
    snapshot,
    delta,
    hitBreakpoint: breakpointHit !== null,
    breakpointHit: breakpointHit ?? undefined,
    event:         snapshot.lastEvent,
  };

  let nextSteps = [...timeline.steps, step];
  if (nextSteps.length > MAX_STRIKE_TIMELINE_STEPS) {
    // Keep only the most recent N steps to bound memory in long sessions.
    nextSteps = nextSteps
      .slice(nextSteps.length - MAX_STRIKE_TIMELINE_STEPS)
      .map((s, i) => ({ ...s, index: i }));
  }

  const currentStep = nextSteps[nextSteps.length - 1];

  const updated: StrikeTimeline = {
    ...timeline,
    steps:         nextSteps,
    playheadIndex: currentStep.index,
  };

  return { timeline: updated, step: currentStep };
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
  // ── New patterns ────────────────────────────────────────────────────────────
  'anti-debug-probe': {
    label:       'Anti-Debug Probe',
    description: 'Trap-flag manipulation, INT3 software-breakpoint probe, or explicit debugger-presence check detected',
  },
  'self-modifying-code': {
    label:       'Self-Modifying Code (Decoder Stub)',
    description: 'RIP stayed in a tight loop (≤ 512-byte window) for 20+ steps — decoder or unpack stub active',
  },
  'oep-transfer': {
    label:       'OEP Transfer (Unpack Handoff)',
    description: 'RIP jumped > 256 KB after a decoder/loop phase — Original Entry Point transfer after unpacking',
  },
  'dynamic-api-resolution': {
    label:       'Dynamic API Resolution',
    description: '3+ indirect calls in a 20-step window — possible GetProcAddress chain or shellcode import resolver',
  },
  'peb-walk': {
    label:       'PEB Walk (Manual Import Resolution)',
    description: 'Direct access to the Process Environment Block (gs:0x60/fs:0x30) — manual import table walking',
  },
};

// ── Pattern detection ─────────────────────────────────────────────────────────

/** TF flag bit in EFLAGS — used for single-step trap detection. */
const TF_BIT = 0x0100;

export function detectPatterns(timeline: StrikeTimeline): StrikePattern[] {
  const steps = timeline.steps;
  if (steps.length < 2) return [];

  const patterns: StrikePattern[] = [];

  const rdtscSteps:        number[] = [];
  const exceptionSteps:    number[] = [];
  const cpuidSteps:        number[] = [];
  const antiDebugSteps:    number[] = [];
  const indirectCallSteps: number[] = [];
  const pebWalkSteps:      number[] = [];

  let retStreak      = 0;
  let retStreakStart  = 0;
  let maxRetStreak   = 0;
  let maxRetStart    = 0;

  let nopRun      = 0;
  let nopRunStart  = 0;
  let maxNopRun   = 0;
  let maxNopStart  = 0;

  // ── Decoder stub / OEP tracking ─────────────────────────────────────────────
  // Track a sliding window of RIP values to detect tight decoder loops
  let loopWindowStart  = 0;
  let loopWindowMin    = 0;
  let loopWindowMax    = 0;
  let loopLen          = 0;
  let maxLoopLen       = 0;
  let maxLoopFirst     = 0;
  let maxLoopMinRip    = 0;
  let postLoopJumpStep = -1;
  let postLoopJumpDist = 0;
  const LOOP_WINDOW_BYTES = 512;   // RIP range that qualifies as a tight loop
  const LOOP_MIN_STEPS    = 20;    // minimum consecutive steps to declare decoder stub
  const OEP_MIN_JUMP      = 0x4_0000; // 256 KB — minimum RIP displacement for OEP transfer

  for (let i = 0; i < steps.length; i++) {
    const ev  = steps[i].event.toLowerCase();
    const d   = steps[i].delta;
    const rip = steps[i].snapshot.registers.rip;

    // ── Instruction-level event tags ────────────────────────────────────────
    if (ev.includes('rdtsc')) rdtscSteps.push(i);
    if (ev.includes('cpuid')) cpuidSteps.push(i);
    if (ev.includes('exception') || ev.includes('int3') || ev.includes('access violation')) {
      exceptionSteps.push(i);
    }

    // ── Anti-debug probe detection ──────────────────────────────────────────
    // 1. Explicit API-level probe (event string)
    if (
      ev.includes('isdebuggerpresent')    ||
      ev.includes('checkremotedebugger')  ||
      ev.includes('ntqueryinformationprocess') ||
      ev.includes('outputdebugstring')    ||
      // Debug register access (DR0–DR3 = hardware breakpoint addresses)
      ev.includes(' dr0') || ev.includes(' dr1') ||
      ev.includes(' dr2') || ev.includes(' dr3')
    ) {
      antiDebugSteps.push(i);
    }

    // 2. TF-flag manipulation: TF transitions from clear → set (trap-flag probe setup)
    if (d) {
      const tfChange = d.flags.find(f => f.flag === 'TF');
      if (tfChange && tfChange.prev === false && tfChange.curr === true) {
        // TF just armed — single-step trap probe starting
        antiDebugSteps.push(i);
      }

      // 3. TF armed + exception within 3 steps = single-step probe confirmed
      const tfArmed = d.flags.find(f => f.flag === 'TF' && f.curr === true);
      if (tfArmed) {
        for (let j = i + 1; j <= Math.min(i + 3, steps.length - 1); j++) {
          const fwdEv = steps[j].event.toLowerCase();
          if (fwdEv.includes('exception') || fwdEv.includes('single step')) {
            antiDebugSteps.push(i);
            break;
          }
        }
      }
    }

    // ── PEB walk detection ──────────────────────────────────────────────────
    if (
      ev.includes('gs:0x60') || ev.includes('gs:60')  ||
      ev.includes('fs:0x30') || ev.includes('fs:30')  ||
      ev.includes('peb')     || ev.includes('ldr')    ||
      ev.includes('inloadordermodulelist')
    ) {
      pebWalkSteps.push(i);
    }

    // ── Indirect call burst (dynamic API resolution) ─────────────────────────
    if (d && (d.jumpType === 'indirect') &&
        (ev.includes('call') || ev.includes('jmp') || ev.includes('getprocaddress') || ev.includes('loadlibrary'))) {
      indirectCallSteps.push(i);
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

      // ── Decoder stub / OEP transfer tracking ─────────────────────────────
      if (i === 0 || loopLen === 0) {
        // Start a new window
        loopWindowStart = i;
        loopWindowMin   = rip;
        loopWindowMax   = rip;
        loopLen         = 1;
      } else {
        const prevMin = loopWindowMin;
        const prevMax = loopWindowMax;
        const newMin  = Math.min(prevMin, rip);
        const newMax  = Math.max(prevMax, rip);

        if (newMax - newMin <= LOOP_WINDOW_BYTES) {
          // Still within the tight loop window
          loopWindowMin = newMin;
          loopWindowMax = newMax;
          loopLen++;
          if (loopLen > maxLoopLen) {
            maxLoopLen   = loopLen;
            maxLoopFirst = loopWindowStart;
            maxLoopMinRip = loopWindowMin;
          }
        } else {
          // RIP escaped the window
          // Check if this escape is a large jump (OEP transfer candidate)
          const jumpDist = Math.abs(rip - steps[i - 1].snapshot.registers.rip);
          if (loopLen >= LOOP_MIN_STEPS && jumpDist >= OEP_MIN_JUMP) {
            // Decoder loop followed by large displacement = OEP transfer
            postLoopJumpStep = i;
            postLoopJumpDist = jumpDist;
          }
          // Reset window
          loopWindowStart = i;
          loopWindowMin   = rip;
          loopWindowMax   = rip;
          loopLen         = 1;
        }
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

  // ── Anti-debug probe ────────────────────────────────────────────────────────
  if (antiDebugSteps.length >= 1) {
    // Confidence scales with the number of distinct probe events observed
    const conf = Math.min(95, 72 + antiDebugSteps.length * 6);
    patterns.push({
      tag:        'anti-debug-probe',
      ...PATTERN_META['anti-debug-probe'],
      confidence: conf,
      firstStep:  antiDebugSteps[0],
      stepSpan:   antiDebugSteps.length > 1
        ? antiDebugSteps[antiDebugSteps.length - 1] - antiDebugSteps[0] + 1
        : 1,
    });
  }

  // ── Self-modifying code / decoder stub ───────────────────────────────────────
  if (maxLoopLen >= LOOP_MIN_STEPS) {
    const conf = Math.min(90, 55 + Math.floor(maxLoopLen / 5) * 5);
    patterns.push({
      tag:        'self-modifying-code',
      ...PATTERN_META['self-modifying-code'],
      confidence: conf,
      firstStep:  maxLoopFirst,
      stepSpan:   maxLoopLen,
    });
  }

  // ── OEP transfer ─────────────────────────────────────────────────────────────
  if (postLoopJumpStep >= 0) {
    const megabytes = Math.round(postLoopJumpDist / 0x100000);
    const conf = Math.min(92, 68 + Math.min(20, megabytes) * 2);
    patterns.push({
      tag:        'oep-transfer',
      ...PATTERN_META['oep-transfer'],
      confidence: conf,
      firstStep:  postLoopJumpStep,
      stepSpan:   1,
    });
  }

  // ── Dynamic API resolution burst ─────────────────────────────────────────────
  // Scan for 3+ indirect calls within any 20-step sliding window
  for (let i = 0; i < indirectCallSteps.length; i++) {
    const windowEnd = indirectCallSteps[i] + 20;
    let count = 0;
    let lastInWindow = indirectCallSteps[i];
    for (let j = i; j < indirectCallSteps.length && indirectCallSteps[j] <= windowEnd; j++) {
      count++;
      lastInWindow = indirectCallSteps[j];
    }
    if (count >= 3) {
      const conf = Math.min(90, 62 + count * 4);
      patterns.push({
        tag:        'dynamic-api-resolution',
        ...PATTERN_META['dynamic-api-resolution'],
        confidence: conf,
        firstStep:  indirectCallSteps[i],
        stepSpan:   lastInWindow - indirectCallSteps[i] + 1,
      });
      break; // one report per session — dedupe will keep highest
    }
  }

  // ── PEB walk ──────────────────────────────────────────────────────────────────
  if (pebWalkSteps.length >= 1) {
    const conf = Math.min(88, 70 + pebWalkSteps.length * 6);
    patterns.push({
      tag:        'peb-walk',
      ...PATTERN_META['peb-walk'],
      confidence: conf,
      firstStep:  pebWalkSteps[0],
      stepSpan:   pebWalkSteps.length > 1
        ? pebWalkSteps[pebWalkSteps.length - 1] - pebWalkSteps[0] + 1
        : 1,
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
  if (
    tags.has('timing-check') || tags.has('exception-probe') ||
    tags.has('anti-step')    || tags.has('cpuid-check')     ||
    tags.has('anti-debug-probe')
  ) {
    behavioralTags.push('anti-analysis');
  }
  if (tags.has('stack-pivot') || tags.has('rop-chain')) {
    behavioralTags.push('code-injection');
  }
  if (tags.has('self-modifying-code') || tags.has('oep-transfer')) {
    behavioralTags.push('code-decryption');
  }
  if (tags.has('dynamic-api-resolution') || tags.has('peb-walk')) {
    behavioralTags.push('dynamic-resolution');
  }

  // ── Composite pattern detection ───────────────────────────────────────────────
  // RAT pattern: anti-debug probe + PEB walk + dynamic API resolution — the
  // runtime signature of a covertly operating remote-access trojan or
  // info-stealer that hides its imports and evades debuggers.
  const hasRatPattern =
    tags.has('anti-debug-probe') &&
    tags.has('peb-walk') &&
    tags.has('dynamic-api-resolution');

  if (hasRatPattern && !behavioralTags.includes('anti-analysis')) {
    behavioralTags.push('anti-analysis');
  }

  // Wiper pattern: unpacking behavior (self-modifying / OEP transfer) AND
  // exception probe AND ROP activity.  Indicates a binary that decrypts its
  // real payload, redirects execution via ROP, and uses exception-handler
  // manipulation to evade tracing.
  const hasWiperPattern =
    (tags.has('self-modifying-code') || tags.has('oep-transfer')) &&
    tags.has('exception-probe') &&
    tags.has('rop-chain');

  if (hasWiperPattern && !behavioralTags.includes('code-decryption')) {
    behavioralTags.push('code-decryption');
  }

  let risk = 0;
  if (tags.has('stack-pivot'))            risk += 30;
  if (tags.has('rop-chain'))              risk += 25;
  if (tags.has('self-modifying-code'))    risk += 25;
  if (tags.has('timing-check'))           risk += 20;
  if (tags.has('anti-debug-probe'))       risk += 20;
  if (tags.has('oep-transfer'))           risk += 20;
  if (tags.has('dynamic-api-resolution')) risk += 18;
  if (tags.has('exception-probe'))        risk += 15;
  if (tags.has('anti-step'))              risk += 15;
  if (tags.has('peb-walk'))               risk += 15;
  if (tags.has('cpuid-check'))            risk += 10;
  if (tags.has('nop-sled'))               risk += 10;
  if (hasRatPattern)                      risk += 20;
  if (hasWiperPattern)                    risk += 25;
  if (indirectRatio > 0.25)               risk += Math.round(indirectRatio * 25);
  risk = Math.min(100, risk);

  return {
    hasTimingCheck:          tags.has('timing-check'),
    hasExceptionProbe:       tags.has('exception-probe'),
    hasStackPivot:           tags.has('stack-pivot'),
    hasRopActivity:          tags.has('rop-chain'),
    hasAntiStep:             tags.has('anti-step'),
    hasCpuidCheck:           tags.has('cpuid-check'),
    hasAntiDebugProbe:       tags.has('anti-debug-probe'),
    hasUnpackingBehavior:    tags.has('self-modifying-code') || tags.has('oep-transfer'),
    hasDynamicApiResolution: tags.has('dynamic-api-resolution'),
    hasPebWalk:              tags.has('peb-walk'),
    hasRatPattern,
    hasWiperPattern,
    indirectJumpRatio:       indirectRatio,
    detectedPatterns:        Array.from(tags),
    stepCount:               steps.length,
    behavioralTags,
    riskScore:               risk,
  };
}

// ── Call Stack Reconstruction ─────────────────────────────────────────────────

export interface CallFrame {
  /** Address of the call instruction that entered this frame. */
  callSite:      number;
  /** Address of the function that was called (RIP at first step inside callee). */
  calleeAddress: number;
  /** Expected return address (instruction after the call). */
  returnAddress: number;
  /** Nesting depth (0 = outermost). */
  depth:         number;
}

/**
 * Walk the timeline and reconstruct a virtual call stack from call/ret events.
 * Returns the inferred stack at the current playhead position, or the full
 * history of frames seen if playheadIndex is −1.
 */
export function buildCallStack(timeline: StrikeTimeline): CallFrame[] {
  const stack: CallFrame[] = [];
  const steps = timeline.playheadIndex >= 0
    ? timeline.steps.slice(0, timeline.playheadIndex + 1)
    : timeline.steps;

  for (const step of steps) {
    const d = step.delta;
    if (!d) continue;

    if (d.jumpType === 'call') {
      stack.push({
        callSite:      d.prevRip,
        calleeAddress: d.rip,
        returnAddress: d.prevRip + (d.ripOffset < 0 ? 0 : d.ripOffset <= 15 ? d.ripOffset : 5),
        depth:         stack.length,
      });
    } else if (d.jumpType === 'ret') {
      stack.pop();
    }
  }

  return stack;
}

// ── Hot-Block Profiling ───────────────────────────────────────────────────────

export interface HotBlock {
  /** Representative RIP address for this block bucket. */
  address: number;
  /** Number of steps that executed in this bucket. */
  count:   number;
  /** Percentage of total steps in this block. */
  pct:     number;
}

/**
 * Bucket RIP addresses into `blockSize`-byte windows and count visits.
 * Returns blocks sorted by count descending (hottest first).
 */
export function computeHotBlocks(
  timeline: StrikeTimeline,
  blockSize = 64,
): HotBlock[] {
  const steps = timeline.playheadIndex >= 0
    ? timeline.steps.slice(0, timeline.playheadIndex + 1)
    : timeline.steps;

  const counts = new Map<number, number>();
  for (const step of steps) {
    const bucket = Math.floor(step.snapshot.registers.rip / blockSize) * blockSize;
    counts.set(bucket, (counts.get(bucket) ?? 0) + 1);
  }

  const total = steps.length || 1;
  return [...counts.entries()]
    .map(([address, count]) => ({ address, count, pct: Math.round((count / total) * 1000) / 10 }))
    .sort((a, b) => b.count - a.count);
}

// ── Execution Loop Detection ──────────────────────────────────────────────────

export interface ExecutionLoop {
  /** Index in timeline.steps where the first iteration begins. */
  startStep:  number;
  /** Number of steps per single loop iteration. */
  periodLen:  number;
  /** Number of detected iterations. */
  iterations: number;
  /** RIP addresses of the first iteration (representative addresses). */
  addresses:  number[];
}

/**
 * Detect repeated sequences of RIP values in the timeline using a sliding
 * window autocorrelation.  Useful for identifying tight loops, decode stubs,
 * or repeated function calls.
 *
 * Only windows where `iterations >= minIterations` are reported.
 */
export function detectExecutionLoops(
  timeline: StrikeTimeline,
  maxPeriod   = 32,
  minIterations = 3,
): ExecutionLoop[] {
  const steps = timeline.playheadIndex >= 0
    ? timeline.steps.slice(0, timeline.playheadIndex + 1)
    : timeline.steps;

  const rips = steps.map(s => s.snapshot.registers.rip);
  const results: ExecutionLoop[] = [];
  const reported = new Set<string>();

  for (let period = 2; period <= maxPeriod; period++) {
    let i = 0;
    while (i + period < rips.length) {
      // Count how many consecutive iterations match at this period
      let iters = 1;
      while (i + (iters + 1) * period <= rips.length) {
        let match = true;
        for (let k = 0; k < period; k++) {
          if (rips[i + k] !== rips[i + iters * period + k]) { match = false; break; }
        }
        if (!match) break;
        iters++;
      }

      if (iters >= minIterations) {
        const key = `${i}:${period}`;
        if (!reported.has(key)) {
          reported.add(key);
          results.push({
            startStep:  i,
            periodLen:  period,
            iterations: iters,
            addresses:  rips.slice(i, i + period),
          });
        }
        i += iters * period; // skip past this loop
      } else {
        i++;
      }
    }
  }

  // Sort: most iterations first, break ties by earlier start step
  return results.sort((a, b) => b.iterations - a.iterations || a.startStep - b.startStep);
}
