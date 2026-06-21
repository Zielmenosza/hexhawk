/**
 * HexHawk Decompiler Engine
 *
 * Converts disassembly (DisassembledInstruction[]) + CFG → readable pseudo-code.
 *
 * Pipeline:
 *   Phase 1 – Lift:     assembly strings  → typed IR statements
 *   Phase 2 – Vars:     abstract registers/stack → named variables
 *   Phase 3 – Blocks:   group IR stmts by CFG basic block
 *   Phase 4 – Structure: detect if/else, while loops from CFG edges
 *   Phase 5 – Emit:     StructuredNode → indented PseudoLine[]
 *
 * Design goals:
 *   • Deterministic – identical input always produces identical output.
 *   • Helpful, not perfect – explain behaviour; not reconstruct source.
 *   • Graceful degradation – unknown instructions fall back to raw text.
 */

import { liftInstructionsToDecompilerIr } from './decompilerIr';
import { resolveImportPrototype, type ImportPrototype } from './importPrototypes';
import { computeDecompilerMaturitySummary } from './decompilerMaturity';
import type { DecompilerMaturitySummary } from './decompilerTypes';
import { buildSSAForm, coalesceSSAVariables, type DomTree, type SSACoalescingResult } from './ssaTransform';

// ─────────────────────────────────────────────────────────
// SHARED INPUT TYPES (matching App.tsx)
// ─────────────────────────────────────────────────────────

export type DisassembledInstruction = {
  address: number;
  mnemonic: string;
  operands: string;
};

export type CfgNode = {
  id: string;
  start?: number;
  end?: number;
  block_type?: string;
  layout_depth?: number;
};

export type CfgEdge = {
  source: string;
  target: string;
  kind?: string;
  condition?: string;
};

export type CfgGraph = {
  nodes: CfgNode[];
  edges: CfgEdge[];
};

// ─────────────────────────────────────────────────────────
// IR TYPES
// ─────────────────────────────────────────────────────────

export type MemSize = 'byte' | 'word' | 'dword' | 'qword' | 'ptr';

export type IRValueTypeHint = {
  inferredType?: string;
  inferredName?: string;
};

export type IRValue = (
  | { kind: 'reg'; name: string }
  | { kind: 'const'; value: number }
  | { kind: 'mem'; base: string; index?: string; scale?: number; offset: number; size: MemSize }
  | { kind: 'expr'; text: string }
) & IRValueTypeHint;

export type IRStmt =
  | { op: 'assign'; address: number; dest: IRValue; src: IRValue }
  | { op: 'binop'; address: number; dest: IRValue; operator: string; left: IRValue; right: IRValue }
  | { op: 'uop'; address: number; dest: IRValue; operator: string; operand: IRValue }
  | { op: 'cmp'; address: number; left: IRValue; right: IRValue }
  | { op: 'test'; address: number; left: IRValue; right: IRValue }
  | { op: 'cjmp'; address: number; cond: string; trueTarget: number; falseTarget: number }
  | { op: 'jmp'; address: number; target: number | null }
  | { op: 'call'; address: number; target: number | null; name?: string; args?: IRValue[]; argRecovery?: 'register-window' | 'stack-window' | 'register-stack-window'; resolvedPrototype?: ImportPrototype }
  | { op: 'ret'; address: number }
  | { op: 'push'; address: number; value: IRValue }
  | { op: 'pop'; address: number; dest: IRValue }
  | { op: 'prologue'; address: number }
  | { op: 'epilogue'; address: number }
  | { op: 'nop'; address: number }
  | { op: 'unknown'; address: number; raw: string };

export type IRBlock = {
  id: string;
  start: number;
  end: number;
  stmts: IRStmt[];
  successors: string[];       // block ids (without back-edge targets from CFG)
  allSuccessors: string[];    // block ids including back edges
  blockType?: string;
};

// ─────────────────────────────────────────────────────────
// STRUCTURED CONTROL FLOW
// ─────────────────────────────────────────────────────────

export type StructuredNode =
  | { kind: 'seq'; nodes: StructuredNode[] }
  | { kind: 'if'; cond: string; address: number; then: StructuredNode; else?: StructuredNode; uncertain?: boolean }
  | { kind: 'while'; cond: string; address: number; body: StructuredNode }
  | { kind: 'do-while'; cond: string; address: number; body: StructuredNode }
  | { kind: 'for'; init: string; cond: string; step: string; address: number; body: StructuredNode }
  | { kind: 'switch'; expr: string; address: number; cases: Array<{ value: string; body: StructuredNode }>; defaultCase?: StructuredNode; uncertain?: boolean }
  | { kind: 'block'; irBlock: IRBlock }
  | { kind: 'label'; id: string; address: number }
  | { kind: 'goto'; target: string; address: number };

// ─────────────────────────────────────────────────────────
// OUTPUT TYPES
// ─────────────────────────────────────────────────────────

export type PseudoLineKind = 'stmt' | 'control' | 'comment' | 'header' | 'blank' | 'brace' | 'uncertain';

export type PseudoLine = {
  indent: number;
  text: string;
  address?: number;
  isUncertain?: boolean;
  kind: PseudoLineKind;
};

// — Logic region detected in a basic block —
export type LogicRegionKind =
  | 'serial-comparison'   // same reg vs multiple constants — likely license/auth check
  | 'validation-gate'     // dense cmp/test + conditional jump cluster
  | 'protection-guard'    // cryptographic hash or checksum verification pattern
  | 'loop-condition';     // back-edge loop with bounded comparison

export type LogicRegion = {
  /** Start address of the first instruction in the region */
  address: number;
  /** IR block that contains this region */
  blockId: string;
  /** Detected pattern category */
  kind: LogicRegionKind;
  /** Number of comparison instructions (cmp/test) in the cluster */
  comparisonCount: number;
  /** Estimated confidence 0–1 */
  confidence: number;
  /** Human-readable summary */
  summary: string;
  /** Addresses of the constituent cmp/test/jcc instructions */
  relatedAddresses: number[];
};

export type DecompilerMaturityTelemetry = {
  schemaVersion: '1.0.0';
  advisoryOnly: true;
  authorityBoundary: 'talon_veil_guidance_not_verdict_authority';
  architecture: Architecture;
  instructionSummary: {
    total: number;
    lifted: number;
    unknown: number;
    unknownAddresses: number[];
    failedDecodeRanges: Array<{ start: number; end: number; count: number }>;
  };
  cfgSummary: {
    blockCount: number;
    edgeCount: number;
    backEdgeCount: number;
    unreachableBlockCount: number;
    unreachableBlocks: string[];
    fallbackPartitioningUsed: boolean;
  };
  callArgumentRecovery: {
    callCount: number;
    recoveredCallCount: number;
    unresolvedCallCount: number;
    recoveredArgumentCount: number;
    registerWindowCount: number;
    stackWindowCount: number;
    registerStackWindowCount: number;
  };
  stackFrameSummary: {
    localCount: number;
    stackArgCount: number;
    registerParamCount: number;
    localNames: string[];
    stackArgNames: string[];
    registerParamNames: string[];
  };
  pseudocodeQuality: {
    uncertainLineCount: number;
    warningCount: number;
    conservativeRewriteCount: number;
    logicRegionCount: number;
  };
  /** Honest explicit-IR maturity summary. Advisory only; not verdict evidence. */
  explicitIrSummary: DecompilerMaturitySummary;
  limitations: string[];
};

export type DecompileResult = {
  functionName: string;
  startAddress: number;
  lines: PseudoLine[];
  varMap: Map<string, string>;   // IR key → friendly name
  irBlocks: IRBlock[];
  /** Structured control-flow IR/AST used to emit pseudocode. Advisory only. */
  structured: StructuredNode;
  /** SSA-version to local-name coalescing map for TALON variable presentation. */
  ssaVariableCoalescing?: SSACoalescingResult;
  /** Logic regions ranked by confidence (highest first) */
  logicRegions: LogicRegion[];
  warnings: string[];
  instrCount: number;
  cseRewriteCount?: number;
  /** Advisory maturity telemetry for UI/report/export surfaces. Not verdict evidence. */
  maturity: DecompilerMaturityTelemetry;
};

// ─────────────────────────────────────────────────────────
// PHASE 1 — OPERAND PARSING
// ─────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────
// ARCHITECTURE DETECTION
// ─────────────────────────────────────────────────────────

export type Architecture = 'x86_64' | 'arm32' | 'aarch64';

const _AARCH64_ONLY_MN = new Set([
  'blr', 'br', 'adrp', 'adr', 'tbz', 'tbnz', 'csel', 'cset', 'csetm',
  'cinc', 'cneg', 'csinc', 'csneg', 'csinv', 'ldar', 'ldxr', 'ldaxr',
  'stlr', 'stxr', 'stlxr', 'prfm', 'hint',
]);
const _ARM32_ONLY_MN = new Set([
  'bx', 'blx', 'stmfd', 'ldmfd', 'stmdb', 'ldmia', 'ldmdb', 'stmia',
  'stmea', 'ldmea', 'vpush', 'vpop', 'vmov', 'vldm', 'vstm', 'bkpt',
]);

export function detectArch(instructions: DisassembledInstruction[]): Architecture {
  if (instructions.length === 0) return 'x86_64';
  const sample = instructions.slice(0, Math.min(30, instructions.length));
  let x86 = 0, arm32 = 0, aarch64 = 0;

  for (const ins of sample) {
    const mn = ins.mnemonic.toLowerCase().trim();
    const ops = ins.operands;
    const opsL = ops.toLowerCase();

    // ── AArch64 ────────────────────────────────────────
    if (_AARCH64_ONLY_MN.has(mn)) { aarch64 += 4; continue; }
    if (mn.startsWith('b.'))       { aarch64 += 4; continue; }  // b.eq, b.ne …
    if (mn === 'cbz' || mn === 'cbnz') { aarch64 += 2; }        // also in Thumb-2, lower weight
    // x0–x30, w0–w30, xzr, wzr, x29, x30
    if (/\b[xw](?:[0-9]|[12][0-9]|30)\b/.test(ops) || /\bxzr\b|\bwzr\b/.test(opsL)) {
      aarch64 += 3;
    }
    // stp/ldp appear in AArch64 (pair load/store)
    if (mn === 'stp' || mn === 'ldp') { aarch64 += 3; }

    // ── ARM32 ──────────────────────────────────────────
    if (_ARM32_ONLY_MN.has(mn)) { arm32 += 4; continue; }
    // beq, bne, blt … (without dot — ARM32 style)
    if (/^b(?:eq|ne|lt|gt|le|ge|lo|hi|ls|hs|mi|pl|vs|vc|cs|cc|al)$/.test(mn)) { arm32 += 4; continue; }
    // Register lists: {r4, lr}, {r0-r3}
    if (/\{[^}]*(?:\blr\b|\bpc\b|\br[0-9]+)/.test(ops)) { arm32 += 3; }
    // ARM immediate without registers matching x86 names
    if (ops.includes('#') && /\br[0-9]+\b/.test(ops) && !/\b[xw][0-9]+\b/.test(ops)) { arm32 += 1; }

    // ── x86_64 ─────────────────────────────────────────
    if (/\br[abcds][px]\b|\brdi\b|\brsi\b|\br[89](?:d|b|w)?\b|\br1[0-5](?:d|b|w)?\b/.test(opsL)) {
      x86 += 3;
    }
    if (/\be[abcds][px]\b|\bedi\b|\besi\b/.test(opsL)) { x86 += 2; }
  }

  if (aarch64 > x86 && aarch64 >= arm32) return 'aarch64';
  if (arm32 > x86 && arm32 > aarch64)   return 'arm32';
  return 'x86_64';
}

// ─────────────────────────────────────────────────────────

const SIZE_PREFIXES: Record<string, MemSize> = {
  'byte ptr': 'byte',
  'word ptr': 'word',
  'dword ptr': 'dword',
  'qword ptr': 'qword',
  'xmmword ptr': 'ptr',
  'ymmword ptr': 'ptr',
  'tbyte ptr': 'ptr',
};

function parseSizePrefix(s: string): { size: MemSize; rest: string } {
  for (const [prefix, size] of Object.entries(SIZE_PREFIXES)) {
    if (s.toLowerCase().startsWith(prefix)) {
      return { size, rest: s.slice(prefix.length).trim() };
    }
  }
  return { size: 'ptr', rest: s };
}

function parseMemExpr(inner: string, size: MemSize): IRValue {
  const s = inner.trim();
  // Forms: "rbp - 0x10", "rbp + rcx*4 + 8", "rax", "0x401234", "rbp + 8"
  // Capture: base [+/- (index*scale)? [+/- offset]?]
  const fullMatch = s.match(
    /^(\w+)(?:\s*([+-])\s*(\w+)\*(\d+))?(?:\s*([+-])\s*(0x[0-9a-fA-F]+|\d+))?$/
  );
  if (fullMatch) {
    const base = fullMatch[1];
    const index = fullMatch[3];
    const scale = fullMatch[4] ? parseInt(fullMatch[4], 10) : undefined;
    const offsetSign = fullMatch[5] === '-' ? -1 : 1;
    const rawOff = fullMatch[6];
    const offset = rawOff
      ? offsetSign * (rawOff.startsWith('0x') ? parseInt(rawOff, 16) : parseInt(rawOff, 10))
      : 0;
    return { kind: 'mem', base, index, scale, offset, size };
  }
  // Simple base only
  if (/^\w+$/.test(s)) {
    return { kind: 'mem', base: s, offset: 0, size };
  }
  return { kind: 'expr', text: `*[${s}]` };
}

export function parseOperand(raw: string): IRValue {
  const s = raw.trim();
  if (!s) return { kind: 'expr', text: '' };

  // Memory operand (with optional size prefix)
  const memIdx = s.indexOf('[');
  if (memIdx !== -1) {
    const { size, rest } = parseSizePrefix(s.slice(0, memIdx).trim().toLowerCase() + ' ');
    const inner = rest.match(/\[([^\]]+)\]/)?.[1] ?? s.slice(memIdx + 1, s.lastIndexOf(']'));
    return parseMemExpr(inner.trim(), size);
  }

  // Check for size prefix without memory (shouldn't happen but guard)
  for (const [prefix, size] of Object.entries(SIZE_PREFIXES)) {
    if (s.toLowerCase().startsWith(prefix)) {
      return parseOperand(s.slice(prefix.length).trim());
    }
  }

  // Hex immediate
  if (/^-?0x[0-9a-fA-F]+$/.test(s)) {
    const v = parseInt(s, 16);
    return { kind: 'const', value: isNaN(v) ? 0 : v };
  }

  // Decimal immediate
  if (/^-?\d+$/.test(s)) {
    return { kind: 'const', value: parseInt(s, 10) };
  }

  // Register (letter-started identifier, including r8-r15 forms, xmm, ymm, zmm, segment regs)
  if (/^[a-zA-Z][a-zA-Z0-9_]*$/.test(s)) {
    return { kind: 'reg', name: s };
  }

  return { kind: 'expr', text: s };
}

function splitOperands(operands: string): string[] {
  // Split by comma — safe in Intel syntax since [] never contain commas
  if (!operands.trim()) return [];
  return operands.split(',').map(o => o.trim()).filter(Boolean);
}

function parseImmediateAddr(s: string): number | null {
  const trimmed = s.trim();
  if (/^0x[0-9a-fA-F]+$/i.test(trimmed)) return parseInt(trimmed, 16);
  if (/^\d+$/.test(trimmed)) return parseInt(trimmed, 10);
  return null;
}

// ─────────────────────────────────────────────────────────
// PHASE 2 — INSTRUCTION LIFTING
// ─────────────────────────────────────────────────────────

const BINOP_MAP: Record<string, string> = {
  add: '+', adc: '+',
  sub: '-', sbb: '-',
  imul: '*', mul: '*',
  idiv: '/', div: '/',
  and: '&', or: '|', xor: '^',
  shl: '<<', sal: '<<', shr: '>>', sar: '>>',
  ror: 'ror', rol: 'rol',
};

const COND_MAP: Record<string, string> = {
  je: '==', jz: '==',
  jne: '!=', jnz: '!=',
  jl: '<', jnge: '<', jlt: '<',
  jle: '<=', jng: '<=',
  jg: '>', jnle: '>', jgt: '>',
  jge: '>=', jnl: '>=',
  ja: '>(u)', jnbe: '>(u)',
  jae: '>=(u)', jnb: '>=(u)',
  jb: '<(u)', jnae: '<(u)',
  jbe: '<=(u)', jna: '<=(u)',
  js: '<0',
  jns: '>=0',
  jo: 'overflow',
  jno: '!overflow',
  jp: 'parity',
  jnp: '!parity',
};

const PROLOGUE_PATTERN = /^(push|sub)\s+r?sp|^mov\s+r?bp,\s*r?sp/i;

interface LiftContext {
  lastCmpLeft: IRValue | null;
  lastCmpRight: IRValue | null;
  lastTestLeft: IRValue | null;
  lastTestRight: IRValue | null;
  nextAddress: number;
}

function liftInstruction(ins: DisassembledInstruction, ctx: LiftContext): IRStmt {
  const { address, operands } = ins;
  const mn = ins.mnemonic.toLowerCase().trim();
  const ops = splitOperands(operands);

  // ── NOP ─────────────────────────────────────────────
  if (mn === 'nop' || mn === 'nopl' || mn === 'nopw') {
    return { op: 'nop', address };
  }

  // ── PROLOGUE / EPILOGUE ──────────────────────────────
  if ((mn === 'push' && ops[0] === 'rbp') || (mn === 'push' && ops[0] === 'ebp')) {
    return { op: 'prologue', address };
  }
  if (mn === 'mov' && ops.length === 2 &&
      (ops[0] === 'rbp' || ops[0] === 'ebp') &&
      (ops[1] === 'rsp' || ops[1] === 'esp')) {
    return { op: 'prologue', address };
  }
  if ((mn === 'pop' && (ops[0] === 'rbp' || ops[0] === 'ebp'))) {
    return { op: 'epilogue', address };
  }

  // ── RET ─────────────────────────────────────────────
  if (mn.startsWith('ret') || mn === 'retn' || mn === 'retq') {
    return { op: 'ret', address };
  }

  // ── CALL ────────────────────────────────────────────
  if (mn === 'call' || mn === 'callq') {
    const target = ops.length > 0 ? parseImmediateAddr(ops[0]) : null;
    const name = target !== null ? undefined : ops[0] ?? undefined;
    return { op: 'call', address, target, name, resolvedPrototype: resolveImportPrototype(name) };
  }

  // ── UNCONDITIONAL JUMP ───────────────────────────────
  if (mn === 'jmp' || mn === 'jmpq') {
    const target = ops.length > 0 ? parseImmediateAddr(ops[0]) : null;
    return { op: 'jmp', address, target };
  }

  // ── CONDITIONAL JUMP ────────────────────────────────
  if (mn in COND_MAP) {
    const condSymbol = COND_MAP[mn];
    const trueTarget = ops.length > 0 ? (parseImmediateAddr(ops[0]) ?? 0) : 0;
    const falseTarget = ctx.nextAddress;

    let cond: string;
    if (ctx.lastCmpLeft && ctx.lastCmpRight) {
      cond = `${renderValueRaw(ctx.lastCmpLeft)} ${condSymbol} ${renderValueRaw(ctx.lastCmpRight)}`;
    } else if ((ctx.lastTestLeft && ctx.lastTestRight) &&
               irValEqual(ctx.lastTestLeft, ctx.lastTestRight)) {
      // test eax, eax → eax == 0 / eax != 0
      const sign = (condSymbol === '==' || condSymbol === '<0') ? '==' : '!=';
      cond = `${renderValueRaw(ctx.lastTestLeft)} ${sign} 0`;
    } else if (ctx.lastTestLeft) {
      cond = `(${renderValueRaw(ctx.lastTestLeft)} & ${renderValueRaw(ctx.lastTestRight!)}) ${condSymbol} 0`;
    } else {
      cond = `? /* ${mn} */`;
    }
    return { op: 'cjmp', address, cond, trueTarget, falseTarget };
  }

  // ── CMP / TEST ───────────────────────────────────────
  if (mn === 'cmp' && ops.length >= 2) {
    return { op: 'cmp', address, left: parseOperand(ops[0]), right: parseOperand(ops[1]) };
  }
  if (mn === 'test' && ops.length >= 2) {
    return { op: 'test', address, left: parseOperand(ops[0]), right: parseOperand(ops[1]) };
  }

  // ── MOV / LEA ────────────────────────────────────────
  if ((mn === 'mov' || mn === 'movl' || mn === 'movq' || mn === 'movzx' ||
       mn === 'movsx' || mn === 'movsxd' || mn === 'movzxd') && ops.length >= 2) {
    return { op: 'assign', address, dest: parseOperand(ops[0]), src: parseOperand(ops[1]) };
  }
  if (mn === 'lea' && ops.length >= 2) {
    // lea dest, [base + offset] → dest = &var
    const dest = parseOperand(ops[0]);
    const src = parseOperand(ops[1]);
    return { op: 'assign', address, dest, src };
  }

  // ── XOR special: xor reg, reg → reg = 0 ─────────────
  if (mn === 'xor' && ops.length === 2 && ops[0] === ops[1]) {
    return { op: 'assign', address, dest: parseOperand(ops[0]), src: { kind: 'const', value: 0 } };
  }

  // ── BINARY OPS ──────────────────────────────────────
  if (mn in BINOP_MAP && ops.length >= 2) {
    const dest = parseOperand(ops[0]);
    const right = parseOperand(ops[1]);
    return { op: 'binop', address, dest, operator: BINOP_MAP[mn], left: dest, right };
  }

  // ── UNARY OPS ───────────────────────────────────────
  if (mn === 'inc' && ops.length === 1) {
    const dest = parseOperand(ops[0]);
    return { op: 'binop', address, dest, operator: '+', left: dest, right: { kind: 'const', value: 1 } };
  }
  if (mn === 'dec' && ops.length === 1) {
    const dest = parseOperand(ops[0]);
    return { op: 'binop', address, dest, operator: '-', left: dest, right: { kind: 'const', value: 1 } };
  }
  if (mn === 'not' && ops.length === 1) {
    const dest = parseOperand(ops[0]);
    return { op: 'uop', address, dest, operator: '~', operand: dest };
  }
  if (mn === 'neg' && ops.length === 1) {
    const dest = parseOperand(ops[0]);
    return { op: 'uop', address, dest, operator: '-', operand: dest };
  }

  // ── PUSH / POP ───────────────────────────────────────
  if (mn === 'push' && ops.length === 1) {
    return { op: 'push', address, value: parseOperand(ops[0]) };
  }
  if (mn === 'pop' && ops.length === 1) {
    return { op: 'pop', address, dest: parseOperand(ops[0]) };
  }

  // ── UNKNOWN ─────────────────────────────────────────
  return { op: 'unknown', address, raw: `${ins.mnemonic} ${operands}`.trim() };
}

function irValEqual(a: IRValue, b: IRValue): boolean {
  if (a.kind !== b.kind) return false;
  if (a.kind === 'reg' && b.kind === 'reg') return a.name === b.name;
  if (a.kind === 'const' && b.kind === 'const') return a.value === b.value;
  return false;
}

// ─────────────────────────────────────────────────────────
// PHASE 3 — VARIABLE ABSTRACTION
// ─────────────────────────────────────────────────────────

// x86-64 System V argument registers (in order)
const ARG_REGS_64    = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9'];
// x86-64 Windows argument registers (in order)
const ARG_REGS_WIN64 = ['rcx', 'rdx', 'r8', 'r9'];
// ARM32 argument registers
const ARG_REGS_ARM32   = ['r0', 'r1', 'r2', 'r3'];
// AArch64 argument registers
const ARG_REGS_AARCH64 = ['x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7'];
// x86-32 arguments are on the stack at [ebp+8], [ebp+12], …
const RETURN_REGS        = new Set(['rax', 'eax', 'al', 'ax', 'rdx:rax']);
const RETURN_REGS_ARM32  = new Set(['r0']);
const RETURN_REGS_AARCH64 = new Set(['x0', 'w0']);
const FRAME_REGS = new Set(['rbp', 'ebp', 'r11', 'fp', 'x29']);
const STACK_REGS = new Set(['rsp', 'esp', 'r13', 'sp']);

export type VarMap = Map<string, string>;

interface VarCollector {
  localsByOffset: Map<number, string>;   // negative rbp offsets → "local_N"
  argsByOffset: Map<number, string>;     // positive rbp offsets → "arg_N"
  argRegs: Map<string, string>;          // rdi/rsi/… → "param_N"
  stackVarCount: number;
  argCount: number;
  argRegCount: number;
}

function memKey(v: { base: string; offset: number }): string {
  return `mem:${v.base}:${v.offset}`;
}

function collectVars(stmts: IRStmt[], arch: Architecture = 'x86_64'): VarCollector {
  const col: VarCollector = {
    localsByOffset: new Map(),
    argsByOffset: new Map(),
    argRegs: new Map(),
    stackVarCount: 0,
    argCount: 0,
    argRegCount: 0,
  };

  for (const stmt of stmts) {
    visitIRValues(stmt, v => {
      if (v.kind === 'mem' && FRAME_REGS.has(v.base)) {
        if (v.offset < 0) {
          const key = v.offset;
          if (!col.localsByOffset.has(key)) {
            col.stackVarCount++;
            col.localsByOffset.set(key, `local_${col.stackVarCount}`);
          }
        } else if (v.offset > 0) {
          const key = v.offset;
          if (!col.argsByOffset.has(key)) {
            col.argCount++;
            col.argsByOffset.set(key, `arg_${col.argCount}`);
          }
        }
      }
    });

    // Detect assignment of arg registers to stack (function entry pattern)
    if (stmt.op === 'assign' && stmt.src.kind === 'reg') {
      const argList = arch === 'arm32' ? ARG_REGS_ARM32
                    : arch === 'aarch64' ? ARG_REGS_AARCH64
                    : ARG_REGS_64;
      const idx = argList.indexOf(stmt.src.name);
      if (idx >= 0 && !col.argRegs.has(stmt.src.name)) {
        col.argRegs.set(stmt.src.name, `param_${idx}`);
      }
    }
  }

  return col;
}

function buildVarMap(stmts: IRStmt[], arch: Architecture = 'x86_64'): VarMap {
  const col = collectVars(stmts, arch);
  const map: VarMap = new Map();

  for (const [offset, name] of col.localsByOffset) {
    map.set(`mem:rbp:${offset}`, name);
    map.set(`mem:ebp:${offset}`, name);
  }
  for (const [offset, name] of col.argsByOffset) {
    map.set(`mem:rbp:${offset}`, name);
    map.set(`mem:ebp:${offset}`, name);
  }
  for (const [reg, name] of col.argRegs) {
    map.set(`reg:${reg}`, name);
  }

  applyHeuristicVarNames(stmts, map);
  return map;
}

function typeHintName(paramName: string): string {
  const cleaned = paramName.replace(/^(lp|p)(?=[A-Z])/, '').replace(/[^a-zA-Z0-9_]/g, '');
  if (!cleaned) return 'typed_arg';
  return cleaned.charAt(0).toLowerCase() + cleaned.slice(1);
}

function withTypeHint(value: IRValue, inferredType: string, inferredName: string): IRValue {
  return { ...value, inferredType, inferredName };
}

function valueKeyForTypeHint(value: IRValue): string | null {
  if (value.kind === 'reg') return `reg:${value.name}`;
  if (value.kind === 'mem') return memKey(value);
  return null;
}

function applyImportPrototypeTypePropagation(blocks: IRBlock[]): IRBlock[] {
  return blocks.map(block => ({
    ...block,
    stmts: block.stmts.map(stmt => {
      if (stmt.op !== 'call' || !stmt.resolvedPrototype || !stmt.args?.length) return stmt;
      const args = stmt.args.map((arg, index) => {
        const param = stmt.resolvedPrototype?.parameters[index];
        if (!param) return arg;
        return withTypeHint(arg, param.type, typeHintName(param.name));
      });
      return { ...stmt, args };
    }),
  }));
}

function applyTypeHintNames(stmts: IRStmt[], map: VarMap): void {
  const used = new Set(Array.from(map.values()));
  for (const stmt of stmts) {
    if (stmt.op !== 'call' || !stmt.args?.length) continue;
    for (const arg of stmt.args) {
      if (!arg.inferredType || !arg.inferredName) continue;
      const key = valueKeyForTypeHint(arg);
      if (!key) continue;
      const current = map.get(key);
      if (current && !isGenericVarName(current)) continue;
      let candidate = arg.inferredName;
      let suffix = 2;
      while (used.has(candidate)) {
        candidate = `${arg.inferredName}_${suffix}`;
        suffix += 1;
      }
      used.add(candidate);
      map.set(key, candidate);
    }
  }
}

function isGenericVarName(name: string): boolean {
  return /^local_\d+$/.test(name) || /^arg_\d+$/.test(name) || /^param_\d+$/.test(name);
}

function applyHeuristicVarNames(stmts: IRStmt[], map: VarMap): void {
  const used = new Set<string>([...map.values()]);
  const counters = new Map<string, number>();
  const loopCounterBases = ['i', 'j', 'k', 'n'];
  let nextLoopCounter = 0;

  const reserveName = (base: string): string => {
    if (!used.has(base)) {
      used.add(base);
      return base;
    }
    const next = (counters.get(base) ?? 1) + 1;
    counters.set(base, next);
    const candidate = `${base}_${next}`;
    used.add(candidate);
    return candidate;
  };

  const renameIfGeneric = (key: string, preferredBase: string): void => {
    const current = map.get(key);
    if (current && !isGenericVarName(current)) return;
    map.set(key, reserveName(preferredBase));
  };

  const toVarKey = (value: IRValue): string | null => {
    if (value.kind === 'reg') return `reg:${value.name}`;
    if (value.kind === 'mem') return memKey(value);
    return null;
  };

  for (const stmt of stmts) {
    if (stmt.op === 'binop' && stmt.dest.kind === 'reg' && stmt.left.kind === 'reg' && stmt.dest.name === stmt.left.name) {
      const isStep = (stmt.operator === '+' || stmt.operator === '-') && stmt.right.kind === 'const' && Math.abs(stmt.right.value) <= 16;
      if (isStep) {
        const base = loopCounterBases[nextLoopCounter] ?? 'idx';
        nextLoopCounter += 1;
        renameIfGeneric(`reg:${stmt.dest.name}`, base);
      }
    }

    if (stmt.op === 'call' && stmt.name && /malloc|calloc|realloc|new/i.test(stmt.name)) {
      const firstArg = stmt.args?.[0];
      if (firstArg) {
        const k = toVarKey(firstArg);
        if (k) renameIfGeneric(k, 'size');
      }
    }

    if (stmt.op === 'assign' && stmt.dest.kind === 'reg' && stmt.src.kind === 'mem') {
      renameIfGeneric(`reg:${stmt.dest.name}`, 'ptr');
    }

    visitIRValues(stmt, v => {
      if (v.kind === 'mem' && v.index) {
        renameIfGeneric(`reg:${v.index}`, 'idx');
      }
    });
  }
}

function visitIRValues(stmt: IRStmt, fn: (v: IRValue) => void): void {
  switch (stmt.op) {
    case 'assign': fn(stmt.dest); fn(stmt.src); break;
    case 'binop': fn(stmt.dest); fn(stmt.left); fn(stmt.right); break;
    case 'uop': fn(stmt.dest); fn(stmt.operand); break;
    case 'cmp': case 'test': fn(stmt.left); fn(stmt.right); break;
    case 'push': fn(stmt.value); break;
    case 'pop': fn(stmt.dest); break;
    default: break;
  }
}


type RecentValue = { value: IRValue; instructionIndex: number };

type CallArgRecovery = {
  args: IRValue[];
  source: 'register-window' | 'stack-window' | 'register-stack-window';
};

const CALL_ARG_LOOKBACK_INSTRUCTIONS = 25;
const WIN64_STACK_ARG_START = 0x20;
const MAX_STACK_ARG_SCAN_BYTES = 0x80;

function canonicalRegName(name: string): string {
  const lo = name.toLowerCase();
  const aliases: Record<string, string> = {
    ecx: 'rcx', cx: 'rcx', cl: 'rcx',
    edx: 'rdx', dx: 'rdx', dl: 'rdx',
    edi: 'rdi', di: 'rdi', dil: 'rdi',
    esi: 'rsi', si: 'rsi', sil: 'rsi',
    r8d: 'r8', r8w: 'r8', r8b: 'r8',
    r9d: 'r9', r9w: 'r9', r9b: 'r9',
    eax: 'rax', ax: 'rax', al: 'rax',
  };
  return aliases[lo] ?? lo;
}

function argRegsForCall(arch: Architecture, regState: Map<string, RecentValue>): string[] {
  if (arch === 'arm32') return ARG_REGS_ARM32;
  if (arch === 'aarch64') return ARG_REGS_AARCH64;

  const hasWin64FrontArgs = ARG_REGS_WIN64.slice(0, 2).some(reg => regState.has(reg));
  const hasSysvFrontArgs = ARG_REGS_64.slice(0, 2).some(reg => regState.has(reg));
  if (hasWin64FrontArgs && !hasSysvFrontArgs) return ARG_REGS_WIN64;
  return ARG_REGS_64;
}

function inferCallArguments(
  arch: Architecture,
  regState: Map<string, RecentValue>,
  stackArgState: Map<number, RecentValue>,
  callIndex: number,
): CallArgRecovery | null {
  const regs = argRegsForCall(arch, regState);
  const args: IRValue[] = [];
  let sawRegisterArg = false;

  for (const reg of regs) {
    const recent = regState.get(reg);
    if (!recent || callIndex - recent.instructionIndex > CALL_ARG_LOOKBACK_INSTRUCTIONS) break;
    args.push(recent.value);
    sawRegisterArg = true;
  }

  const stackArgs = [...stackArgState.entries()]
    .filter(([offset, recent]) =>
      offset >= WIN64_STACK_ARG_START &&
      offset <= MAX_STACK_ARG_SCAN_BYTES &&
      callIndex - recent.instructionIndex <= CALL_ARG_LOOKBACK_INSTRUCTIONS
    )
    .sort(([a], [b]) => a - b)
    .map(([, recent]) => recent.value);

  if (stackArgs.length > 0) args.push(...stackArgs);
  if (args.length === 0) return null;

  const source = sawRegisterArg && stackArgs.length > 0
    ? 'register-stack-window'
    : sawRegisterArg
    ? 'register-window'
    : 'stack-window';
  return { args, source };
}

function updateCallArgState(
  stmt: IRStmt,
  regState: Map<string, RecentValue>,
  stackArgState: Map<number, RecentValue>,
  instructionIndex: number,
): void {
  if (stmt.op === 'assign') {
    if (stmt.dest.kind === 'reg') {
      regState.set(canonicalRegName(stmt.dest.name), { value: stmt.src, instructionIndex });
    } else if (stmt.dest.kind === 'mem' && STACK_REGS.has(stmt.dest.base) && stmt.dest.offset > 0) {
      stackArgState.set(stmt.dest.offset, { value: stmt.src, instructionIndex });
    }
    return;
  }

  if ((stmt.op === 'binop' || stmt.op === 'uop') && stmt.dest.kind === 'reg') {
    regState.delete(canonicalRegName(stmt.dest.name));
    return;
  }

  if (stmt.op === 'pop' && stmt.dest.kind === 'reg') {
    regState.delete(canonicalRegName(stmt.dest.name));
  }
}

type IndexedStmt = {
  globalIndex: number;
  blockIndex: number;
  stmtIndex: number;
  stmt: IRStmt;
};

function recoveryStrength(source: CallArgRecovery['source'] | undefined): number {
  switch (source) {
    case 'register-window': return 3;
    case 'register-stack-window': return 2;
    case 'stack-window': return 1;
    default: return 0;
  }
}

function recoverCallArgumentsAcrossBlocks(blocks: IRBlock[], arch: Architecture): IRBlock[] {
  const indexed: IndexedStmt[] = [];
  for (let bi = 0; bi < blocks.length; bi++) {
    for (let si = 0; si < blocks[bi].stmts.length; si++) {
      indexed.push({ globalIndex: indexed.length, blockIndex: bi, stmtIndex: si, stmt: blocks[bi].stmts[si] });
    }
  }

  if (indexed.length === 0) return blocks;

  const nextBlocks = blocks.map(b => ({ ...b, stmts: [...b.stmts] }));
  for (let i = 0; i < indexed.length; i++) {
    const cur = indexed[i];
    if (cur.stmt.op !== 'call') continue;

    const regState = new Map<string, RecentValue>();
    const stackArgState = new Map<number, RecentValue>();
    const start = Math.max(0, i - CALL_ARG_LOOKBACK_INSTRUCTIONS);
    for (let j = start; j < i; j++) {
      updateCallArgState(indexed[j].stmt, regState, stackArgState, indexed[j].globalIndex);
    }

    const recovered = inferCallArguments(arch, regState, stackArgState, cur.globalIndex);
    if (!recovered) continue;

    const existing = cur.stmt;
    const existingCount = existing.args?.length ?? 0;
    const shouldReplace =
      existingCount === 0 ||
      recovered.args.length > existingCount ||
      (recovered.args.length === existingCount && recoveryStrength(recovered.source) > recoveryStrength(existing.argRecovery));

    if (shouldReplace) {
      const updated: IRStmt = {
        ...existing,
        args: recovered.args,
        argRecovery: recovered.source,
      };
      nextBlocks[cur.blockIndex].stmts[cur.stmtIndex] = updated;
    }
  }
  return nextBlocks;
}

// ─────────────────────────────────────────────────────────
// RENDERING HELPERS (used by both structuring and emission)
// ─────────────────────────────────────────────────────────

function renderValueRaw(v: IRValue): string {
  switch (v.kind) {
    case 'reg': return v.name;
    case 'const': {
      if (v.value === 0) return '0';
      if (Math.abs(v.value) < 1000) return String(v.value);
      return `0x${(v.value >>> 0).toString(16)}`;
    }
    case 'mem': {
      let s = `[${v.base}`;
      if (v.index) s += ` + ${v.index}${v.scale && v.scale > 1 ? `*${v.scale}` : ''}`;
      if (v.offset > 0) s += ` + ${v.offset}`;
      else if (v.offset < 0) s += ` - ${Math.abs(v.offset)}`;
      return s + ']';
    }
    case 'expr': return v.text;
  }
}

function renderValue(v: IRValue, varMap: VarMap): string {
  if (v.kind === 'reg') {
    return varMap.get(`reg:${v.name}`) ?? v.name;
  }
  if (v.kind === 'mem') {
    const key = memKey(v);
    const mapped = varMap.get(key);
    if (mapped) return mapped;
    // Unnamed memory: try to make it readable
    if (v.offset === 0 && !v.index) return `*${v.base}`;
    return renderValueRaw(v);
  }
  return renderValueRaw(v);
}

function renderStmt(stmt: IRStmt, varMap: VarMap): { text: string; uncertain?: boolean } | null {
  switch (stmt.op) {
    case 'nop':
    case 'prologue':
    case 'epilogue':
      return null; // omit from pseudo-code output

    case 'assign': {
      const dest = renderValue(stmt.dest, varMap);
      const src = renderValue(stmt.src, varMap);
      return { text: `${dest} = ${src};` };
    }

    case 'binop': {
      const dest = renderValue(stmt.dest, varMap);
      const left = renderValue(stmt.left, varMap);
      const right = renderValue(stmt.right, varMap);
      if (dest === left) {
        // Compound assignment: x += 4
        return { text: `${dest} ${stmt.operator}= ${right};` };
      }
      return { text: `${dest} = ${left} ${stmt.operator} ${right};` };
    }

    case 'uop': {
      const dest = renderValue(stmt.dest, varMap);
      const op = renderValue(stmt.operand, varMap);
      if (dest === op) {
        return { text: `${dest} = ${stmt.operator}${dest};` };
      }
      return { text: `${dest} = ${stmt.operator}${op};` };
    }

    case 'cmp':
    case 'test':
      return null; // consumed by subsequent cjmp

    case 'cjmp':
      return null; // handled by control flow structure

    case 'jmp':
      return null; // structured emission owns jumps/gotos so reducible CFGs do not leak raw goto chains

    case 'call': {
      const target = stmt.name
        ? stmt.name
        : stmt.target !== null
        ? `sub_${stmt.target.toString(16)}`
        : '*indirect';
      const rawArgs = stmt.args?.map(arg => renderValue(arg, varMap)) ?? [];
      const args = stmt.resolvedPrototype
        ? stmt.resolvedPrototype.parameters.map((param, index) => `${param.name}: ${rawArgs[index] ?? '?'}`).slice(0, Math.max(stmt.resolvedPrototype.parameters.length, rawArgs.length))
        : rawArgs;
      const uncertain = stmt.argRecovery === 'stack-window' || stmt.argRecovery === 'register-stack-window';
      return { text: `${target}(${args.join(', ')});`, uncertain };
    }

    case 'ret':
      return { text: `return;` };

    case 'push': {
      const val = renderValue(stmt.value, varMap);
      return { text: `push(${val});`, uncertain: true };
    }

    case 'pop': {
      const dest = renderValue(stmt.dest, varMap);
      return { text: `${dest} = pop();`, uncertain: true };
    }

    case 'unknown':
      return { text: `/* ${stmt.raw} */`, uncertain: true };
  }
}

// ─────────────────────────────────────────────────────────
// ARM32 IR LIFTING
// ─────────────────────────────────────────────────────────

const ARM32_REG_ALIASES: Record<string, string> = {
  fp: 'r11', ip: 'r12', sp: 'r13', lr: 'r14', pc: 'r15',
};

function normalizeARM32Reg(r: string): string {
  const lo = r.toLowerCase().trim();
  return ARM32_REG_ALIASES[lo] ?? lo;
}

function parseARM32Imm(s: string): number | null {
  const t = s.trim().replace(/^#/, '');
  if (/^-?0x[0-9a-fA-F]+$/.test(t)) return parseInt(t, 16);
  if (/^-?\d+$/.test(t)) return parseInt(t, 10);
  return null;
}

function parseARM32MemExpr(expr: string): IRValue {
  const s = expr.replace(/!$/, '').trim();
  const inner = s.startsWith('[')
    ? s.slice(1, s.lastIndexOf(']')).trim()
    : s;

  // [base]
  if (/^[a-zA-Z][a-zA-Z0-9]*$/.test(inner)) {
    return { kind: 'mem', base: normalizeARM32Reg(inner), offset: 0, size: 'ptr' };
  }
  // [base, #imm]
  const immM = inner.match(/^([a-zA-Z][a-zA-Z0-9]*),\s*#(-?(?:0x[0-9a-fA-F]+|\d+))$/i);
  if (immM) {
    const base = normalizeARM32Reg(immM[1]);
    const raw = immM[2];
    const offset = /^-?0x/.test(raw) ? parseInt(raw, 16) : parseInt(raw, 10);
    return { kind: 'mem', base, offset, size: 'ptr' };
  }
  // [base, reg] or [base, reg, lsl #n]
  const regM = inner.match(/^([a-zA-Z][a-zA-Z0-9]*),\s*([a-zA-Z][a-zA-Z0-9]*)(?:,\s*lsl\s*#(\d+))?$/i);
  if (regM) {
    const base = normalizeARM32Reg(regM[1]);
    const index = normalizeARM32Reg(regM[2]);
    const scale = regM[3] ? (1 << parseInt(regM[3], 10)) : 1;
    return { kind: 'mem', base, index, scale, offset: 0, size: 'ptr' };
  }
  return { kind: 'expr', text: `*[${inner}]` };
}

function parseARM32Operand(raw: string): IRValue {
  const s = raw.trim();
  if (!s) return { kind: 'expr', text: '' };
  if (s.startsWith('[')) {
    // post-indexed: [base], #off — just use base for the memory ref
    const closeBracket = s.indexOf(']');
    return parseARM32MemExpr(s.slice(0, closeBracket + 1));
  }
  if (s.startsWith('#')) {
    const v = parseARM32Imm(s);
    return v !== null ? { kind: 'const', value: v } : { kind: 'expr', text: s };
  }
  // shifted register: r0, lsl #2 → use just the reg
  const shiftM = s.match(/^([a-zA-Z][a-zA-Z0-9]*),\s*(?:lsl|lsr|asr|ror)\s*#\d+$/i);
  if (shiftM) return { kind: 'reg', name: normalizeARM32Reg(shiftM[1]) };
  if (/^[a-zA-Z][a-zA-Z0-9_]*$/.test(s)) return { kind: 'reg', name: normalizeARM32Reg(s) };
  const v = parseARM32Imm(s);
  if (v !== null) return { kind: 'const', value: v };
  return { kind: 'expr', text: s };
}

/** Split by comma but skip commas inside [] or {} */
function splitDepthAware(operands: string): string[] {
  if (!operands.trim()) return [];
  const result: string[] = [];
  let depth = 0, current = '';
  for (const ch of operands) {
    if (ch === '[' || ch === '{') { depth++; current += ch; }
    else if (ch === ']' || ch === '}') { depth--; current += ch; }
    else if (ch === ',' && depth === 0) { result.push(current.trim()); current = ''; }
    else { current += ch; }
  }
  if (current.trim()) result.push(current.trim());
  return result;
}

const ARM32_BINOP_MAP: Record<string, string> = {
  add: '+', adc: '+', sub: '-', sbc: '-', rsb: '-',
  mul: '*', mla: '*', and: '&', orr: '|', eor: '^',
  lsl: '<<', lsr: '>>', asr: '>>', ror: 'ror', bic: '&~',
};

const ARM32_COND_MAP: Record<string, string> = {
  beq: '==', bne: '!=',
  blt: '<',  ble: '<=', bgt: '>',  bge: '>=',
  blo: '<(u)', bls: '<=(u)', bhi: '>(u)', bhs: '>=(u)',
  bmi: '<', bpl: '>=', bvs: 'overflow', bvc: '!overflow',
  bcs: '>=(u)', bcc: '<(u)', bal: 'true',
};

function liftInstructionARM32(ins: DisassembledInstruction, ctx: LiftContext): IRStmt {
  const { address } = ins;
  const mn = ins.mnemonic.toLowerCase().trim();
  const rawOps = ins.operands;
  const ops = splitDepthAware(rawOps);

  if (mn === 'nop') return { op: 'nop', address };

  // ── PROLOGUE / EPILOGUE ──────────────────────────────
  if (mn === 'push' && /\blr\b/.test(rawOps)) return { op: 'prologue', address };
  if ((mn === 'stmfd' || mn === 'stmdb') && rawOps.includes('sp') && /\blr\b/.test(rawOps)) {
    return { op: 'prologue', address };
  }
  if (mn === 'pop' && /\bpc\b/.test(rawOps)) return { op: 'epilogue', address };
  if ((mn === 'ldmfd' || mn === 'ldmia') && rawOps.includes('sp') && /\bpc\b/.test(rawOps)) {
    return { op: 'epilogue', address };
  }

  // ── RETURN ─────────────────────────────────────────
  if (mn === 'bx' && ops[0]?.toLowerCase() === 'lr') return { op: 'ret', address };
  if (mn === 'mov' && ops[0]?.toLowerCase() === 'pc' && ops[1]?.toLowerCase() === 'lr') {
    return { op: 'ret', address };
  }

  // ── CALL ───────────────────────────────────────────
  if (mn === 'bl' || mn === 'blx') {
    const target = ops[0] ? parseImmediateAddr(ops[0]) : null;
    const name = target === null ? (ops[0] ?? undefined) : undefined;
    return { op: 'call', address, target, name, resolvedPrototype: resolveImportPrototype(name) };
  }

  // ── UNCONDITIONAL BRANCH ────────────────────────────
  if (mn === 'b') {
    const target = ops[0] ? parseImmediateAddr(ops[0]) : null;
    return { op: 'jmp', address, target };
  }
  if (mn === 'bx') {
    return { op: 'jmp', address, target: null };
  }

  // ── CONDITIONAL BRANCH ─────────────────────────────
  if (mn in ARM32_COND_MAP) {
    const condSymbol = ARM32_COND_MAP[mn];
    const trueTarget = ops[0] ? (parseImmediateAddr(ops[0]) ?? 0) : 0;
    let cond: string;
    if (ctx.lastCmpLeft && ctx.lastCmpRight) {
      cond = `${renderValueRaw(ctx.lastCmpLeft)} ${condSymbol} ${renderValueRaw(ctx.lastCmpRight)}`;
    } else if (ctx.lastTestLeft && ctx.lastTestRight && irValEqual(ctx.lastTestLeft, ctx.lastTestRight)) {
      const sign = (condSymbol === '==' || condSymbol === '<0') ? '==' : '!=';
      cond = `${renderValueRaw(ctx.lastTestLeft)} ${sign} 0`;
    } else if (ctx.lastTestLeft) {
      cond = `(${renderValueRaw(ctx.lastTestLeft)} & ${renderValueRaw(ctx.lastTestRight!)}) ${condSymbol} 0`;
    } else {
      cond = `? /* ${mn} */`;
    }
    return { op: 'cjmp', address, cond, trueTarget, falseTarget: ctx.nextAddress };
  }

  // ── CMP / TST ─────────────────────────────────────
  if ((mn === 'cmp' || mn === 'cmn') && ops.length >= 2) {
    return { op: 'cmp', address, left: parseARM32Operand(ops[0]), right: parseARM32Operand(ops[1]) };
  }
  if ((mn === 'tst' || mn === 'teq') && ops.length >= 2) {
    return { op: 'test', address, left: parseARM32Operand(ops[0]), right: parseARM32Operand(ops[1]) };
  }

  // ── CBZ / CBNZ ─────────────────────────────────────
  if (mn === 'cbz' && ops.length >= 2) {
    const reg = parseARM32Operand(ops[0]);
    const trueTarget = parseImmediateAddr(ops[1]) ?? 0;
    return { op: 'cjmp', address, cond: `${renderValueRaw(reg)} == 0`, trueTarget, falseTarget: ctx.nextAddress };
  }
  if (mn === 'cbnz' && ops.length >= 2) {
    const reg = parseARM32Operand(ops[0]);
    const trueTarget = parseImmediateAddr(ops[1]) ?? 0;
    return { op: 'cjmp', address, cond: `${renderValueRaw(reg)} != 0`, trueTarget, falseTarget: ctx.nextAddress };
  }

  // ── MOV / MVN / MOVT ───────────────────────────────
  if ((mn === 'mov' || mn === 'movw') && ops.length >= 2) {
    return { op: 'assign', address, dest: parseARM32Operand(ops[0]), src: parseARM32Operand(ops[1]) };
  }
  if (mn === 'mvn' && ops.length >= 2) {
    return { op: 'uop', address, dest: parseARM32Operand(ops[0]), operator: '~', operand: parseARM32Operand(ops[1]) };
  }
  if (mn === 'movt' && ops.length >= 2) {
    const dest = parseARM32Operand(ops[0]);
    return { op: 'binop', address, dest, operator: '|', left: dest, right: parseARM32Operand(ops[1]) };
  }

  // ── LDR / STR ───────────────────────────────────────
  if ((mn === 'ldr' || mn === 'ldrb' || mn === 'ldrh' || mn === 'ldrsb' || mn === 'ldrsh' || mn === 'ldrex') && ops.length >= 2) {
    const dest = parseARM32Operand(ops[0]);
    let src: IRValue;
    if (ops[1].startsWith('=')) {
      const v = parseARM32Imm(ops[1].slice(1));
      src = v !== null ? { kind: 'const', value: v } : { kind: 'expr', text: ops[1] };
    } else {
      src = parseARM32Operand(ops[1]);
    }
    return { op: 'assign', address, dest, src };
  }
  if ((mn === 'str' || mn === 'strb' || mn === 'strh' || mn === 'strex') && ops.length >= 2) {
    return { op: 'assign', address, dest: parseARM32Operand(ops[1]), src: parseARM32Operand(ops[0]) };
  }

  // ── BINARY OPS ──────────────────────────────────────
  if (mn in ARM32_BINOP_MAP) {
    if (ops.length >= 3) {
      const dest = parseARM32Operand(ops[0]);
      const left = parseARM32Operand(ops[1]);
      const right = parseARM32Operand(ops[2].split(',')[0].trim());
      return { op: 'binop', address, dest, operator: ARM32_BINOP_MAP[mn], left, right };
    }
    if (ops.length === 2) {
      const dest = parseARM32Operand(ops[0]);
      const right = parseARM32Operand(ops[1]);
      return { op: 'binop', address, dest, operator: ARM32_BINOP_MAP[mn], left: dest, right };
    }
  }

  return { op: 'unknown', address, raw: `${ins.mnemonic} ${rawOps}`.trim() };
}

// ─────────────────────────────────────────────────────────
// AARCH64 IR LIFTING
// ─────────────────────────────────────────────────────────

const AARCH64_REG_ALIASES: Record<string, string> = { lr: 'x30', fp: 'x29' };

function normalizeAArch64Reg(r: string): string {
  const lo = r.toLowerCase().trim();
  if (lo === 'xzr' || lo === 'wzr') return lo;
  return AARCH64_REG_ALIASES[lo] ?? lo;
}

function parseAArch64Imm(s: string): number | null {
  const t = s.trim().replace(/^#/, '').split(',')[0].trim();
  if (/^-?0x[0-9a-fA-F]+$/.test(t)) return parseInt(t, 16);
  if (/^-?\d+$/.test(t)) return parseInt(t, 10);
  return null;
}

function parseAArch64MemExpr(raw: string): IRValue {
  const s = raw.replace(/!$/, '').trim();
  const inner = s.startsWith('[')
    ? s.slice(1, s.lastIndexOf(']')).trim()
    : s;
  if (/^[a-zA-Z][a-zA-Z0-9]*$/.test(inner)) {
    return { kind: 'mem', base: normalizeAArch64Reg(inner), offset: 0, size: 'ptr' };
  }
  const immM = inner.match(/^([a-zA-Z][a-zA-Z0-9]*),\s*#(-?(?:0x[0-9a-fA-F]+|\d+))$/i);
  if (immM) {
    const base = normalizeAArch64Reg(immM[1]);
    const raw2 = immM[2];
    const offset = /^-?0x/.test(raw2) ? parseInt(raw2, 16) : parseInt(raw2, 10);
    return { kind: 'mem', base, offset, size: 'ptr' };
  }
  const regM = inner.match(/^([a-zA-Z][a-zA-Z0-9]*),\s*([a-zA-Z][a-zA-Z0-9]*)(?:,\s*(?:lsl|sxtw|uxtw|sxth|sxtb)\s*#(\d+))?$/i);
  if (regM) {
    const base = normalizeAArch64Reg(regM[1]);
    const index = normalizeAArch64Reg(regM[2]);
    const scale = regM[3] ? (1 << parseInt(regM[3], 10)) : 1;
    return { kind: 'mem', base, index, scale, offset: 0, size: 'ptr' };
  }
  return { kind: 'expr', text: `*[${inner}]` };
}

function parseAArch64Operand(raw: string): IRValue {
  const s = raw.trim();
  if (!s) return { kind: 'expr', text: '' };
  if (s.startsWith('[')) {
    const closeBracket = s.lastIndexOf(']');
    return parseAArch64MemExpr(s.slice(0, closeBracket + 1));
  }
  if (s.startsWith('#')) {
    const v = parseAArch64Imm(s);
    return v !== null ? { kind: 'const', value: v } : { kind: 'expr', text: s };
  }
  const lo = s.toLowerCase();
  if (lo === 'xzr' || lo === 'wzr') return { kind: 'const', value: 0 };
  if (/^[a-zA-Z][a-zA-Z0-9_]*$/.test(s)) return { kind: 'reg', name: normalizeAArch64Reg(s) };
  const v = parseAArch64Imm(s);
  if (v !== null) return { kind: 'const', value: v };
  return { kind: 'expr', text: s };
}

const AARCH64_BINOP_MAP: Record<string, string> = {
  add: '+', adds: '+', sub: '-', subs: '-', mul: '*',
  and: '&', ands: '&', orr: '|', eor: '^',
  lsl: '<<', lsr: '>>', asr: '>>', ror: 'ror', bic: '&~', orn: '|~',
};

const AARCH64_COND_MAP: Record<string, string> = {
  'b.eq': '==', 'b.ne': '!=',
  'b.lt': '<',  'b.le': '<=', 'b.gt': '>',  'b.ge': '>=',
  'b.lo': '<(u)', 'b.ls': '<=(u)', 'b.hi': '>(u)', 'b.hs': '>=(u)',
  'b.mi': '<', 'b.pl': '>=', 'b.vs': 'overflow', 'b.vc': '!overflow',
  'b.cs': '>=(u)', 'b.cc': '<(u)', 'b.al': 'true',
};

function liftInstructionAArch64(ins: DisassembledInstruction, ctx: LiftContext): IRStmt {
  const { address } = ins;
  const mn = ins.mnemonic.toLowerCase().trim();
  const rawOps = ins.operands;
  const ops = splitDepthAware(rawOps);

  if (mn === 'nop' || mn === 'isb' || mn === 'dsb' || mn === 'dmb') return { op: 'nop', address };

  // ── PROLOGUE / EPILOGUE ──────────────────────────────
  // stp x29, x30, [sp, #-N]!  → function frame setup
  if (mn === 'stp' && /\bx29\b/.test(rawOps) && /\bx30\b/.test(rawOps) && rawOps.includes('sp')) {
    return { op: 'prologue', address };
  }
  // ldp x29, x30, [sp] or [sp], #N → frame teardown
  if (mn === 'ldp' && /\bx29\b/.test(rawOps) && /\bx30\b/.test(rawOps) && rawOps.includes('sp')) {
    return { op: 'epilogue', address };
  }

  // ── RETURN ─────────────────────────────────────────
  if (mn === 'ret') return { op: 'ret', address };

  // ── CALL ───────────────────────────────────────────
  if (mn === 'bl') {
    const target = ops[0] ? parseImmediateAddr(ops[0]) : null;
    const name = target === null ? (ops[0] ?? undefined) : undefined;
    return { op: 'call', address, target, name, resolvedPrototype: resolveImportPrototype(name) };
  }
  if (mn === 'blr') {
    return { op: 'call', address, target: null, name: ops[0], resolvedPrototype: resolveImportPrototype(ops[0]) };
  }
  if (mn === 'svc') {
    const svcNum = ops[0] ? (parseAArch64Imm(ops[0]) ?? 0) : 0;
    return { op: 'call', address, target: null, name: `svc_0x${svcNum.toString(16)}` };
  }

  // ── UNCONDITIONAL BRANCH ────────────────────────────
  if (mn === 'b') {
    const target = ops[0] ? parseImmediateAddr(ops[0]) : null;
    return { op: 'jmp', address, target };
  }
  if (mn === 'br') return { op: 'jmp', address, target: null };

  // ── CONDITIONAL BRANCH (b.eq, b.ne, …) ──────────────
  if (mn in AARCH64_COND_MAP) {
    const condSymbol = AARCH64_COND_MAP[mn];
    const trueTarget = ops[0] ? (parseImmediateAddr(ops[0]) ?? 0) : 0;
    let cond: string;
    if (ctx.lastCmpLeft && ctx.lastCmpRight) {
      cond = `${renderValueRaw(ctx.lastCmpLeft)} ${condSymbol} ${renderValueRaw(ctx.lastCmpRight)}`;
    } else if (ctx.lastTestLeft && ctx.lastTestRight && irValEqual(ctx.lastTestLeft, ctx.lastTestRight)) {
      const sign = (condSymbol === '==' || condSymbol === '<0') ? '==' : '!=';
      cond = `${renderValueRaw(ctx.lastTestLeft)} ${sign} 0`;
    } else if (ctx.lastTestLeft) {
      cond = `(${renderValueRaw(ctx.lastTestLeft)} & ${renderValueRaw(ctx.lastTestRight!)}) ${condSymbol} 0`;
    } else {
      cond = `? /* ${mn} */`;
    }
    return { op: 'cjmp', address, cond, trueTarget, falseTarget: ctx.nextAddress };
  }

  // ── CBZ / CBNZ ─────────────────────────────────────
  if (mn === 'cbz' && ops.length >= 2) {
    const reg = parseAArch64Operand(ops[0]);
    const trueTarget = parseImmediateAddr(ops[1]) ?? 0;
    return { op: 'cjmp', address, cond: `${renderValueRaw(reg)} == 0`, trueTarget, falseTarget: ctx.nextAddress };
  }
  if (mn === 'cbnz' && ops.length >= 2) {
    const reg = parseAArch64Operand(ops[0]);
    const trueTarget = parseImmediateAddr(ops[1]) ?? 0;
    return { op: 'cjmp', address, cond: `${renderValueRaw(reg)} != 0`, trueTarget, falseTarget: ctx.nextAddress };
  }

  // ── TBZ / TBNZ ─────────────────────────────────────
  if ((mn === 'tbz' || mn === 'tbnz') && ops.length >= 3) {
    const reg = parseAArch64Operand(ops[0]);
    const bit = parseAArch64Imm(ops[1]) ?? 0;
    const mask = (1 << bit) >>> 0;
    const trueTarget = parseImmediateAddr(ops[2]) ?? 0;
    const eq = mn === 'tbz' ? '==' : '!=';
    return { op: 'cjmp', address, cond: `(${renderValueRaw(reg)} & 0x${mask.toString(16)}) ${eq} 0`, trueTarget, falseTarget: ctx.nextAddress };
  }

  // ── CMP / TST ─────────────────────────────────────
  if ((mn === 'cmp' || mn === 'cmn') && ops.length >= 2) {
    return { op: 'cmp', address, left: parseAArch64Operand(ops[0]), right: parseAArch64Operand(ops[1]) };
  }
  if (mn === 'tst' && ops.length >= 2) {
    return { op: 'test', address, left: parseAArch64Operand(ops[0]), right: parseAArch64Operand(ops[1]) };
  }

  // ── MOV / MOVZ / MOVK / MOVN ───────────────────────
  if (mn === 'mov' && ops.length >= 2) {
    return { op: 'assign', address, dest: parseAArch64Operand(ops[0]), src: parseAArch64Operand(ops[1]) };
  }
  if (mn === 'movz' && ops.length >= 2) {
    const dest = parseAArch64Operand(ops[0]);
    const v = parseAArch64Imm(ops[1]);
    return { op: 'assign', address, dest, src: v !== null ? { kind: 'const', value: v } : { kind: 'expr', text: ops[1] } };
  }
  if (mn === 'movn' && ops.length >= 2) {
    return { op: 'uop', address, dest: parseAArch64Operand(ops[0]), operator: '~', operand: parseAArch64Operand(ops[1]) };
  }
  if (mn === 'movk' && ops.length >= 2) {
    const dest = parseAArch64Operand(ops[0]);
    const v = parseAArch64Imm(ops[1]);
    const src: IRValue = v !== null ? { kind: 'const', value: v } : { kind: 'expr', text: ops[1] };
    return { op: 'binop', address, dest, operator: '|', left: dest, right: src };
  }
  if (mn === 'mvn' && ops.length >= 2) {
    return { op: 'uop', address, dest: parseAArch64Operand(ops[0]), operator: '~', operand: parseAArch64Operand(ops[1]) };
  }

  // ── ADR / ADRP ─────────────────────────────────────
  if ((mn === 'adr' || mn === 'adrp') && ops.length >= 2) {
    const dest = parseAArch64Operand(ops[0]);
    const v = parseImmediateAddr(ops[1]);
    return { op: 'assign', address, dest, src: v !== null ? { kind: 'const', value: v } : { kind: 'expr', text: ops[1] } };
  }

  // ── LDR / STR and variants ─────────────────────────
  const isLoad = /^(?:ldr|ldrb|ldrh|ldrsb|ldrsh|ldrsw|ldar|ldarb|ldarh|ldxr|ldaxr)$/.test(mn);
  if (isLoad && ops.length >= 2) {
    return { op: 'assign', address, dest: parseAArch64Operand(ops[0]), src: parseAArch64Operand(ops[1]) };
  }
  const isStore = /^(?:str|strb|strh|stlr|stlrb|stlrh|stxr|stlxr)$/.test(mn);
  if (isStore && ops.length >= 2) {
    return { op: 'assign', address, dest: parseAArch64Operand(ops[1]), src: parseAArch64Operand(ops[0]) };
  }

  // ── LDP / STP (pair) — non-frame pairs ─────────────
  if (mn === 'ldp' && ops.length >= 3) {
    // lift first register only; second is unknown (emit as best-effort)
    return { op: 'assign', address, dest: parseAArch64Operand(ops[0]), src: parseAArch64Operand(ops[2]) };
  }
  if (mn === 'stp' && ops.length >= 3) {
    return { op: 'assign', address, dest: parseAArch64Operand(ops[2]), src: parseAArch64Operand(ops[0]) };
  }

  // ── BINARY OPS (3-operand) ──────────────────────────
  if (mn in AARCH64_BINOP_MAP) {
    if (ops.length >= 3) {
      const dest = parseAArch64Operand(ops[0]);
      const left = parseAArch64Operand(ops[1]);
      const right = parseAArch64Operand(ops[2].split(',')[0].trim());
      return { op: 'binop', address, dest, operator: AARCH64_BINOP_MAP[mn], left, right };
    }
    if (ops.length === 2) {
      const dest = parseAArch64Operand(ops[0]);
      const right = parseAArch64Operand(ops[1]);
      return { op: 'binop', address, dest, operator: AARCH64_BINOP_MAP[mn], left: dest, right };
    }
  }

  // ── CSEL / CSET / CINC ─────────────────────────────
  if ((mn === 'csel' || mn === 'csinc' || mn === 'csneg' || mn === 'csinv') && ops.length >= 3) {
    const dest = parseAArch64Operand(ops[0]);
    const src = parseAArch64Operand(ops[1]);
    return { op: 'assign', address, dest, src };  // approximate; loses else-branch
  }
  if ((mn === 'cset' || mn === 'csetm' || mn === 'cinc' || mn === 'cneg') && ops.length >= 2) {
    const dest = parseAArch64Operand(ops[0]);
    return { op: 'assign', address, dest, src: { kind: 'expr', text: `cond_${ops[ops.length - 1]}` } };
  }

  // ── MRS (system register read) ──────────────────────
  if (mn === 'mrs' && ops.length >= 2) {
    const dest = parseAArch64Operand(ops[0]);
    return { op: 'assign', address, dest, src: { kind: 'expr', text: ops[1] } };
  }
  if (mn === 'msr') return { op: 'nop', address };

  return { op: 'unknown', address, raw: `${ins.mnemonic} ${rawOps}`.trim() };
}

// ─────────────────────────────────────────────────────────
// PHASE 4 — BLOCK BUILDING
// ─────────────────────────────────────────────────────────

function buildIRBlocks(
  instructions: DisassembledInstruction[],
  cfg: CfgGraph | null,
  arch: Architecture = 'x86_64'
): IRBlock[] {
  if (!instructions.length) return [];

  // Build address → instruction index
  const addrToIdx = new Map<number, number>();
  for (let i = 0; i < instructions.length; i++) {
    addrToIdx.set(instructions[i].address, i);
  }

  // Get block ranges from CFG, or treat everything as one block
  type BlockRange = { id: string; start: number; end: number; blockType?: string };
  let ranges: BlockRange[];

  if (cfg && cfg.nodes.length > 0) {
    ranges = cfg.nodes
      .filter(n => n.start !== undefined)
      .map(n => ({
        id: n.id,
        start: n.start!,
        end: n.end ?? n.start! + 1,
        blockType: n.block_type,
      }));
  } else {
    const first = instructions[0].address;
    const last = instructions[instructions.length - 1].address;
    ranges = [{ id: 'block_0', start: first, end: last + 1, blockType: 'entry' }];
  }

  // Build edge map (source → [target])
  const succMap = new Map<string, string[]>();
  if (cfg) {
    for (const e of cfg.edges) {
      const targets = succMap.get(e.source) ?? [];
      targets.push(e.target);
      succMap.set(e.source, targets);
    }
  }

  const irBlocks: IRBlock[] = [];

  for (const range of ranges) {
    // Collect instructions in this block
    const blockInsns = instructions.filter(
      ins => ins.address >= range.start && ins.address <= range.end
    );
    if (blockInsns.length === 0) continue;

    // Lift instructions with context tracking
    let lastCmpLeft: IRValue | null = null;
    let lastCmpRight: IRValue | null = null;
    let lastTestLeft: IRValue | null = null;
    let lastTestRight: IRValue | null = null;
    const regState = new Map<string, RecentValue>();
    const stackArgState = new Map<number, RecentValue>();
    const stmts: IRStmt[] = [];

    for (let i = 0; i < blockInsns.length; i++) {
      const ins = blockInsns[i];
      const nextAddr = blockInsns[i + 1]?.address ?? (range.end + 1);
      const ctx: LiftContext = {
        lastCmpLeft, lastCmpRight, lastTestLeft, lastTestRight, nextAddress: nextAddr
      };
      const lifted = arch === 'arm32'   ? liftInstructionARM32(ins, ctx)
                   : arch === 'aarch64' ? liftInstructionAArch64(ins, ctx)
                   : liftInstruction(ins, ctx);
      const recovery = lifted.op === 'call'
        ? inferCallArguments(arch, regState, stackArgState, i)
        : null;
      const stmt: IRStmt = recovery && lifted.op === 'call'
        ? { ...lifted, args: recovery.args, argRecovery: recovery.source }
        : lifted;
      stmts.push(stmt);

      // Update context
      if (stmt.op === 'cmp') {
        lastCmpLeft = stmt.left; lastCmpRight = stmt.right;
        lastTestLeft = null; lastTestRight = null;
      } else if (stmt.op === 'test') {
        lastTestLeft = stmt.left; lastTestRight = stmt.right;
        lastCmpLeft = null; lastCmpRight = null;
      } else if (stmt.op !== 'nop' && stmt.op !== 'cjmp') {
        // Intermediate instruction — clear cmp state
        // (Conservative: only clear if the instruction writes to a flag-relevant reg)
        // For simplicity we keep it — most real code has cmp directly before j*
      }

      updateCallArgState(stmt, regState, stackArgState, i);
      if (stmt.op === 'call') {
        // Calls may clobber return/volatile registers; keep stack writes only for this call site.
        for (const reg of [...ARG_REGS_WIN64, ...ARG_REGS_64, ...ARG_REGS_ARM32, ...ARG_REGS_AARCH64, 'rax', 'eax', 'x0', 'w0']) {
          regState.delete(reg);
        }
        stackArgState.clear();
      }
    }

    const allSuccessors = succMap.get(range.id) ?? [];
    irBlocks.push({
      id: range.id,
      start: range.start,
      end: range.end,
      stmts,
      allSuccessors,
      successors: allSuccessors, // back edges are filtered in structuring phase
      blockType: range.blockType,
    });
  }

  return recoverCallArgumentsAcrossBlocks(irBlocks, arch);
}

function buildFallbackPartitionedIRBlocks(
  instructions: DisassembledInstruction[],
  arch: Architecture,
): IRBlock[] {
  if (instructions.length === 0) return [];

  const addrSet = new Set(instructions.map(ins => ins.address));
  const leaders = new Set<number>([instructions[0].address]);
  const lifted: IRStmt[] = [];

  let lastCmpLeft: IRValue | null = null;
  let lastCmpRight: IRValue | null = null;
  let lastTestLeft: IRValue | null = null;
  let lastTestRight: IRValue | null = null;

  for (let i = 0; i < instructions.length; i++) {
    const ins = instructions[i];
    const nextAddress = instructions[i + 1]?.address ?? (ins.address + 1);
    const ctx: LiftContext = {
      lastCmpLeft,
      lastCmpRight,
      lastTestLeft,
      lastTestRight,
      nextAddress,
    };
    const stmt = arch === 'arm32'
      ? liftInstructionARM32(ins, ctx)
      : arch === 'aarch64'
      ? liftInstructionAArch64(ins, ctx)
      : liftInstruction(ins, ctx);
    lifted.push(stmt);

    if (stmt.op === 'cmp') {
      lastCmpLeft = stmt.left;
      lastCmpRight = stmt.right;
      lastTestLeft = null;
      lastTestRight = null;
    } else if (stmt.op === 'test') {
      lastTestLeft = stmt.left;
      lastTestRight = stmt.right;
      lastCmpLeft = null;
      lastCmpRight = null;
    }

    if (stmt.op === 'cjmp') {
      if (addrSet.has(stmt.trueTarget)) leaders.add(stmt.trueTarget);
      if (instructions[i + 1]) leaders.add(instructions[i + 1].address);
    } else if (stmt.op === 'jmp') {
      if (stmt.target !== null && addrSet.has(stmt.target)) leaders.add(stmt.target);
      if (instructions[i + 1]) leaders.add(instructions[i + 1].address);
    } else if (stmt.op === 'call' || stmt.op === 'ret') {
      if (instructions[i + 1]) leaders.add(instructions[i + 1].address);
    }
  }

  const sortedLeaders = [...leaders].sort((a, b) => a - b);
  if (sortedLeaders.length === 0) return [];

  const leaderByAddress = new Map<number, string>();
  for (let i = 0; i < sortedLeaders.length; i++) {
    leaderByAddress.set(sortedLeaders[i], `fallback_block_${i}`);
  }

  const findBlockStartForAddress = (address: number): number | null => {
    for (let i = sortedLeaders.length - 1; i >= 0; i--) {
      const start = sortedLeaders[i];
      if (address >= start) return start;
    }
    return null;
  };

  const blocks: IRBlock[] = [];
  for (let i = 0; i < sortedLeaders.length; i++) {
    const start = sortedLeaders[i];
    const endExclusive = sortedLeaders[i + 1] ?? (instructions[instructions.length - 1].address + 1);
    const blockStmts = lifted.filter(s => s.address >= start && s.address < endExclusive);
    if (blockStmts.length === 0) continue;

    const successors: string[] = [];
    const last = blockStmts[blockStmts.length - 1];
    const pushSucc = (targetAddr: number | null) => {
      if (targetAddr === null) return;
      const blockStart = findBlockStartForAddress(targetAddr);
      if (blockStart === null) return;
      const id = leaderByAddress.get(blockStart);
      if (!id || successors.includes(id)) return;
      successors.push(id);
    };

    if (last.op === 'cjmp') {
      pushSucc(last.trueTarget);
      const fallthroughStart = sortedLeaders[i + 1] ?? null;
      if (fallthroughStart !== null) pushSucc(fallthroughStart);
    } else if (last.op === 'jmp') {
      pushSucc(last.target);
    } else if (last.op !== 'ret') {
      const fallthroughStart = sortedLeaders[i + 1] ?? null;
      if (fallthroughStart !== null) pushSucc(fallthroughStart);
    }

    blocks.push({
      id: leaderByAddress.get(start) ?? `fallback_block_${i}`,
      start,
      end: Math.max(start, endExclusive - 1),
      stmts: blockStmts,
      successors,
      allSuccessors: [...successors],
      blockType: i === 0 ? 'entry' : 'target',
    });
  }

  return recoverCallArgumentsAcrossBlocks(blocks, arch);
}

// ─────────────────────────────────────────────────────────
// PHASE 5 — CONTROL FLOW STRUCTURING
// ─────────────────────────────────────────────────────────

function findEntryBlock(blocks: IRBlock[]): IRBlock | null {
  // Prefer explicitly marked entry block
  const marked = blocks.find(b => b.blockType === 'entry');
  if (marked) return marked;
  // Fall back: block with no incoming edges
  const allTargets = new Set<string>();
  for (const b of blocks) {
    for (const s of b.allSuccessors) allTargets.add(s);
  }
  return blocks.find(b => !allTargets.has(b.id)) ?? blocks[0] ?? null;
}

function computeBackEdges(blocks: IRBlock[]): Set<string> {
  const backEdges = new Set<string>();
  const visited = new Set<string>();
  const onStack = new Set<string>();
  const blockMap = new Map(blocks.map(b => [b.id, b]));

  function dfs(id: string) {
    if (!blockMap.has(id)) return;
    if (onStack.has(id)) return;
    if (visited.has(id)) return;
    visited.add(id);
    onStack.add(id);
    const block = blockMap.get(id)!;
    for (const succ of block.allSuccessors) {
      if (onStack.has(succ)) {
        backEdges.add(`${id}->${succ}`);
      } else {
        dfs(succ);
      }
    }
    onStack.delete(id);
  }

  const entry = findEntryBlock(blocks);
  if (entry) dfs(entry.id);
  return backEdges;
}

function dominates(domTree: DomTree, dominator: string, node: string): boolean {
  if (dominator === node) return true;
  let cur: string | null | undefined = node;
  const seen = new Set<string>();
  while (cur !== null && cur !== undefined && !seen.has(cur)) {
    seen.add(cur);
    cur = domTree.idom.get(cur);
    if (cur === dominator) return true;
  }
  return false;
}

function computeDominanceBackEdges(blocks: IRBlock[], domTree: DomTree): Set<string> {
  const backEdges = new Set<string>();
  const blockIds = new Set(blocks.map(b => b.id));
  for (const block of blocks) {
    for (const succ of block.allSuccessors) {
      if (!blockIds.has(succ)) continue;
      if (dominates(domTree, succ, block.id)) {
        backEdges.add(`${block.id}->${succ}`);
      }
    }
  }
  return backEdges;
}

/** BFS-reachable block ids from `from`, not crossing back edges */
function reachable(
  from: string,
  blockMap: Map<string, IRBlock>,
  backEdges: Set<string>,
  stopAt?: string
): Set<string> {
  const result = new Set<string>();
  const queue = [from];
  while (queue.length) {
    const cur = queue.shift()!;
    if (result.has(cur) || cur === stopAt) continue;
    result.add(cur);
    const b = blockMap.get(cur);
    if (!b) continue;
    for (const s of b.allSuccessors) {
      if (!backEdges.has(`${cur}->${s}`) && !result.has(s)) {
        queue.push(s);
      }
    }
  }
  return result;
}

/** Find the first block in topo order reachable from both a and b */
function findJoinPoint(
  a: string,
  b: string,
  blockMap: Map<string, IRBlock>,
  backEdges: Set<string>,
  topoOrder: string[]
): string | null {
  const ra = reachable(a, blockMap, backEdges);
  const rb = reachable(b, blockMap, backEdges);
  for (const id of topoOrder) {
    if (ra.has(id) && rb.has(id)) return id;
  }
  return null;
}

/** Find first topo-ordered block reachable from all starts */
function findMultiJoinPoint(
  starts: string[],
  blockMap: Map<string, IRBlock>,
  backEdges: Set<string>,
  topoOrder: string[]
): string | null {
  if (starts.length < 2) return null;
  const reachableSets = starts.map(s => reachable(s, blockMap, backEdges));
  for (const id of topoOrder) {
    if (reachableSets.every(rs => rs.has(id))) return id;
  }
  return null;
}

function topoSort(blocks: IRBlock[], backEdges: Set<string>): string[] {
  const blockMap = new Map(blocks.map(b => [b.id, b]));
  const order: string[] = [];
  const visited = new Set<string>();

  function dfs(id: string) {
    if (visited.has(id) || !blockMap.has(id)) return;
    visited.add(id);
    const b = blockMap.get(id)!;
    for (const s of b.allSuccessors) {
      if (!backEdges.has(`${id}->${s}`)) dfs(s);
    }
    order.unshift(id);
  }

  const entry = findEntryBlock(blocks);
  if (entry) dfs(entry.id);
  // Include any disconnected blocks
  for (const b of blocks) if (!visited.has(b.id)) dfs(b.id);
  return order;
}

function extractCondFromBlock(block: IRBlock): string {
  // Find the last cjmp in the block and return its condition
  for (let i = block.stmts.length - 1; i >= 0; i--) {
    const s = block.stmts[i];
    if (s.op === 'cjmp') return s.cond;
  }
  return '? /* unknown condition */';
}

function hasCjmp(block: IRBlock): boolean {
  return block.stmts.some(s => s.op === 'cjmp');
}

function extractSwitchExprFromBlock(block: IRBlock): string {
  for (let i = block.stmts.length - 1; i >= 0; i--) {
    const s = block.stmts[i];
    if ((s.op === 'cmp' || s.op === 'test') && s.left) {
      return renderValueRaw(s.left);
    }
  }
  return 'selector';
}

function extractSwitchCaseValuesFromBlock(block: IRBlock, caseCount: number): string[] {
  const values: string[] = [];
  for (const s of block.stmts) {
    if (s.op !== 'cmp') continue;
    if (s.right.kind !== 'const') continue;
    const v = s.right.value;
    values.push(Math.abs(v) < 1000 ? String(v) : `0x${(v >>> 0).toString(16)}`);
  }

  const unique: string[] = [];
  for (const v of values) {
    if (!unique.includes(v)) unique.push(v);
    if (unique.length >= caseCount) break;
  }

  if (unique.length < caseCount) {
    for (let i = unique.length; i < caseCount; i++) {
      unique.push(String(i));
    }
  }
  return unique;
}



type IfChainSwitchCandidate = {
  switchNode: StructuredNode;
  defaultSucc: string | null;
};

function extractEqualityCase(block: IRBlock): { expr: string; value: string; cjmp: Extract<IRStmt, { op: 'cjmp' }> } | null {
  const cjmp = [...block.stmts].reverse().find((stmt): stmt is Extract<IRStmt, { op: 'cjmp' }> => stmt.op === 'cjmp');
  if (!cjmp) return null;
  const cmp = [...block.stmts].reverse().find((stmt): stmt is Extract<IRStmt, { op: 'cmp' }> => stmt.op === 'cmp');
  if (!cmp || cmp.left.kind !== 'reg' || cmp.right.kind !== 'const') return null;
  if (!cjmp.cond.includes(' == ') && !cjmp.cond.includes(' != ')) return null;
  const value = Math.abs(cmp.right.value) < 1000 ? String(cmp.right.value) : `0x${(cmp.right.value >>> 0).toString(16)}`;
  return { expr: renderValueRaw(cmp.left), value, cjmp };
}

function tryBuildIfChainSwitch(
  blockId: string,
  blockMap: Map<string, IRBlock>,
  backEdges: Set<string>,
  topoOrder: string[],
  loopHeaders: Set<string>,
  visited: Set<string>,
  depth: number,
): IfChainSwitchCandidate | null {
  const first = blockMap.get(blockId);
  if (!first) return null;
  const firstCase = extractEqualityCase(first);
  if (!firstCase) return null;

  const cases: Array<{ value: string; succ: string }> = [];
  const chainBlocks = new Set<string>();
  let currentId: string | null = blockId;
  let expectedExpr = firstCase.expr;
  let defaultSucc: string | null = null;

  while (currentId && !chainBlocks.has(currentId)) {
    const current = blockMap.get(currentId);
    if (!current) break;
    const eq = extractEqualityCase(current);
    if (!eq || eq.expr !== expectedExpr) break;
    const fwdSuccs = current.allSuccessors.filter(s => !backEdges.has(`${currentId}->${s}`));
    if (fwdSuccs.length !== 2) break;
    const trueSucc = fwdSuccs.find(s => blockMap.get(s)?.start === eq.cjmp.trueTarget) ?? fwdSuccs[0];
    const falseSucc = fwdSuccs.find(s => s !== trueSucc) ?? fwdSuccs[1];
    const caseSucc = eq.cjmp.cond.includes(' == ') ? trueSucc : falseSucc;
    const nextTestSucc = eq.cjmp.cond.includes(' == ') ? falseSucc : trueSucc;
    const nextBlock = blockMap.get(nextTestSucc);
    cases.push({ value: eq.value, succ: caseSucc });
    chainBlocks.add(currentId);

    if (!nextBlock || !extractEqualityCase(nextBlock)) {
      defaultSucc = nextTestSucc;
      break;
    }
    currentId = nextTestSucc;
  }

  if (cases.length < 3) return null;

  const switchCases = cases.map(({ value, succ }) => ({
    value,
    body: structureBlock(succ, blockMap, backEdges, topoOrder, loopHeaders, new Set(visited), defaultSucc, depth + 1),
  }));
  const defaultCase = defaultSucc
    ? structureBlock(defaultSucc, blockMap, backEdges, topoOrder, loopHeaders, new Set(visited), null, depth + 1)
    : undefined;

  return {
    switchNode: {
      kind: 'switch',
      expr: expectedExpr,
      address: first.stmts.find(s => s.op === 'cmp')?.address ?? first.start,
      cases: switchCases,
      defaultCase,
    },
    defaultSucc,
  };
}

// ── Loop-reconstruction helpers ─────────────────────────────────────────────

/** Invert a simple comparison condition string. */
function invertCond(cond: string): string {
  if (cond.includes(' != ')) return cond.replace(' != ', ' == ');
  if (cond.includes(' == ')) return cond.replace(' == ', ' != ');
  if (cond.includes(' >= ')) return cond.replace(' >= ', ' < ');
  if (cond.includes(' <= ')) return cond.replace(' <= ', ' > ');
  if (cond.includes(' > '))  return cond.replace(' > ',  ' <= ');
  if (cond.includes(' < '))  return cond.replace(' < ',  ' >= ');
  return `!(${cond})`;
}

/** All block IDs that are targets of back edges (= natural loop headers). */
function computeLoopHeaders(backEdges: Set<string>): Set<string> {
  const headers = new Set<string>();
  for (const edge of backEdges) {
    const arrow = edge.indexOf('->');
    if (arrow !== -1) headers.add(edge.slice(arrow + 2));
  }
  return headers;
}

/**
 * Returns true if a path from `from` → ... → someBlock → `target` exists where
 * the last hop is a back edge (i.e., `from` eventually loops back to `target`).
 */
function canReachViaBackEdge(
  from: string,
  target: string,
  blockMap: Map<string, IRBlock>,
  backEdges: Set<string>,
): boolean {
  const fwdReachable = reachable(from, blockMap, backEdges);
  fwdReachable.add(from);
  for (const edge of backEdges) {
    const arrow = edge.indexOf('->');
    if (arrow === -1) continue;
    const src = edge.slice(0, arrow);
    const dst = edge.slice(arrow + 2);
    if (dst === target && fwdReachable.has(src)) return true;
  }
  return false;
}

/**
 * Try to extract a for-loop step expression by scanning the reachable loop
 * body blocks (without crossing back-edges) for an increment/decrement of
 * `condRegName`.
 */
function tryExtractLoopStep(
  bodyFirstId: string,
  condRegName: string,
  blockMap: Map<string, IRBlock>,
  backEdges: Set<string>,
): string | null {
  if (!blockMap.has(bodyFirstId)) return null;

  const scanQueue: string[] = [bodyFirstId];
  const scanOrder: string[] = [];
  const seen = new Set<string>();
  while (scanQueue.length > 0) {
    const cur = scanQueue.shift()!;
    if (seen.has(cur)) continue;
    seen.add(cur);
    scanOrder.push(cur);
    const block = blockMap.get(cur);
    if (!block) continue;
    for (const succ of block.allSuccessors) {
      if (backEdges.has(`${cur}->${succ}`)) continue;
      if (!seen.has(succ)) scanQueue.push(succ);
    }
  }

  const reg = condRegName;
  for (const blockId of scanOrder) {
    const body = blockMap.get(blockId);
    if (!body) continue;
    for (const s of body.stmts) {
      if (s.op === 'binop' && s.dest.kind === 'reg' && s.dest.name === reg) {
        if (s.operator === '+' && s.right.kind === 'const') {
          return s.right.value === 1 ? `${reg}++` : `${reg} += ${s.right.value}`;
        }
        if (s.operator === '-' && s.right.kind === 'const') {
          return s.right.value === 1 ? `${reg}--` : `${reg} -= ${s.right.value}`;
        }
      }
      if (s.op === 'uop' && s.dest.kind === 'reg' && s.dest.name === reg) {
        if (s.operator === 'inc') return `${reg}++`;
        if (s.operator === 'dec') return `${reg}--`;
      }
    }
  }
  return null;
}

const MAX_STRUCT_DEPTH = 24;

function structureBlock(
  blockId: string,
  blockMap: Map<string, IRBlock>,
  backEdges: Set<string>,
  topoOrder: string[],
  loopHeaders: Set<string>,
  visited: Set<string>,
  stopAt: string | null,
  depth: number
): StructuredNode {
  if (depth > MAX_STRUCT_DEPTH || visited.has(blockId) || blockId === stopAt) {
    return { kind: 'seq', nodes: [] };
  }
  if (!blockMap.has(blockId)) return { kind: 'seq', nodes: [] };

  visited.add(blockId);
  const block = blockMap.get(blockId)!;

  // Forward successors (non-back-edges)
  const fwdSuccs = block.allSuccessors.filter(s => !backEdges.has(`${blockId}->${s}`));
  // Back-edge successors (loop targets)
  const backSuccs = block.allSuccessors.filter(s => backEdges.has(`${blockId}->${s}`));

  const blockNode: StructuredNode = { kind: 'block', irBlock: block };

  // ── DO-WHILE DETECTION: conditional latch jumps back to header ──
  if (backSuccs.length > 0 && hasCjmp(block)) {
    const loopHeader = backSuccs[0];
    const exitSucc = fwdSuccs[0] ?? null;
    const cond = extractCondFromBlock(block);

    const bodyVisited = new Set(visited);
    bodyVisited.delete(blockId);
    const headerBody = structureBlock(loopHeader, blockMap, backEdges, topoOrder,
                                      loopHeaders, bodyVisited, blockId, depth + 1);
    const bodyNode: StructuredNode = { kind: 'seq', nodes: [headerBody, blockNode] };
    const doWhileNode: StructuredNode = {
      kind: 'do-while',
      cond,
      address: block.stmts.find(s => s.op === 'cjmp')?.address ?? block.start,
      body: bodyNode,
    };

    const rest = exitSucc
      ? structureBlock(exitSucc, blockMap, backEdges, topoOrder, loopHeaders, visited, stopAt, depth + 1)
      : { kind: 'seq' as const, nodes: [] };

    return { kind: 'seq', nodes: [doWhileNode, rest] };
  }

  // ── SIMPLE SEQUENCE (single forward successor) ──────
  if (fwdSuccs.length === 0) {
    return blockNode;
  }

  if (fwdSuccs.length === 1) {
    const rest = structureBlock(fwdSuccs[0], blockMap, backEdges, topoOrder, loopHeaders, visited, stopAt, depth + 1);
    return { kind: 'seq', nodes: [blockNode, rest] };
  }

  // ── IF / ELSE or WHILE-HEADER (two forward successors) ──────────────────────
  if (fwdSuccs.length === 2 && hasCjmp(block)) {
    const cjmpStmt = [...block.stmts].reverse().find((s): s is Extract<IRStmt, { op: 'cjmp' }> => s.op === 'cjmp');
    const cond = cjmpStmt?.cond ?? '?';
    const trueSucc  = cjmpStmt
      ? fwdSuccs.find(s => blockMap.get(s)?.start === cjmpStmt.trueTarget) ?? fwdSuccs[0]
      : fwdSuccs[0];
    const falseSucc = fwdSuccs.find(s => s !== trueSucc) ?? fwdSuccs[1];

    const ifChainSwitch = tryBuildIfChainSwitch(blockId, blockMap, backEdges, topoOrder, loopHeaders, visited, depth);
    if (ifChainSwitch) {
      return { kind: 'seq', nodes: [ifChainSwitch.switchNode] };
    }

    // ── WHILE / FOR header (this block is the target of a back edge) ────────
    if (loopHeaders.has(blockId)) {
      const trueLoopsBack = canReachViaBackEdge(trueSucc, blockId, blockMap, backEdges);
      const bodySucc = trueLoopsBack ? trueSucc : falseSucc;
      const exitSucc = trueLoopsBack ? falseSucc : trueSucc;
      const whileCond = (trueSucc === bodySucc) ? cond : invertCond(cond);

      const bodyVisited = new Set(visited);
      const bodyNode = structureBlock(bodySucc, blockMap, backEdges, topoOrder, loopHeaders, bodyVisited, blockId, depth + 1);

      // Try to promote while → for if we can extract a step expression
      const cmpStmt = [...block.stmts].reverse().find(s => s.op === 'cmp' || s.op === 'test');
      let loopNode: StructuredNode;
      if (cmpStmt && (cmpStmt.op === 'cmp' || cmpStmt.op === 'test') && cmpStmt.left.kind === 'reg') {
        const stepStr = tryExtractLoopStep(bodySucc, cmpStmt.left.name, blockMap, backEdges);
        if (stepStr) {
          loopNode = { kind: 'for', init: '', cond: whileCond, step: stepStr, address: block.start, body: bodyNode };
        } else {
          loopNode = { kind: 'while', cond: whileCond, address: block.start, body: bodyNode };
        }
      } else {
        loopNode = { kind: 'while', cond: whileCond, address: block.start, body: bodyNode };
      }

      const rest = structureBlock(exitSucc, blockMap, backEdges, topoOrder, loopHeaders, visited, stopAt, depth + 1);
      return { kind: 'seq', nodes: [blockNode, loopNode, rest] };
    }

    // ── IF / ELSE (no back edge into this block) ─────────────────────────────
    const joinId = findJoinPoint(trueSucc, falseSucc, blockMap, backEdges, topoOrder);

    const thenVisited = new Set(visited);
    const elseVisited = new Set(visited);
    const thenNode = structureBlock(trueSucc, blockMap, backEdges, topoOrder, loopHeaders, thenVisited, joinId, depth + 1);
    const elseNode = structureBlock(falseSucc, blockMap, backEdges, topoOrder, loopHeaders, elseVisited, joinId, depth + 1);

    const cjmpAddr = cjmpStmt?.address ?? block.start;
    const ifNode: StructuredNode = {
      kind: 'if',
      cond,
      address: cjmpAddr,
      then: thenNode,
      else: isEmptySeq(elseNode) ? undefined : elseNode,
    };

    const rest = joinId
      ? structureBlock(joinId, blockMap, backEdges, topoOrder, loopHeaders, visited, stopAt, depth + 1)
      : { kind: 'seq' as const, nodes: [] };

    return { kind: 'seq', nodes: [blockNode, ifNode, rest] };
  }

  // ── SWITCH / JUMP-TABLE STYLE DISPATCH (3+ successors) ──
  if (fwdSuccs.length >= 3) {
    const joinId = findMultiJoinPoint(fwdSuccs, blockMap, backEdges, topoOrder);
    const caseSuccs = [...fwdSuccs];
    const hasIndirectDispatch = block.stmts.some(s => s.op === 'jmp' && s.target === null);
    const defaultSucc = caseSuccs.length >= 2 ? caseSuccs[caseSuccs.length - 1] : null;
    const explicitCases = defaultSucc ? caseSuccs.slice(0, -1) : caseSuccs;
    const caseValues = extractSwitchCaseValuesFromBlock(block, explicitCases.length);

    const switchCases = explicitCases.map((succ, idx) => {
      const caseVisited = new Set(visited);
      const caseNode = structureBlock(succ, blockMap, backEdges, topoOrder, loopHeaders, caseVisited, joinId, depth + 1);
      return { value: caseValues[idx] ?? String(idx), body: caseNode };
    });

    const defaultNode = defaultSucc
      ? structureBlock(defaultSucc, blockMap, backEdges, topoOrder, loopHeaders, new Set(visited), joinId, depth + 1)
      : undefined;

    const switchNode: StructuredNode = {
      kind: 'switch',
      expr: extractSwitchExprFromBlock(block),
      address: block.start,
      cases: switchCases,
      defaultCase: defaultNode,
      uncertain: !hasIndirectDispatch,
    };

    const rest = joinId
      ? structureBlock(joinId, blockMap, backEdges, topoOrder, loopHeaders, visited, stopAt, depth + 1)
      : { kind: 'seq' as const, nodes: [] };

    return { kind: 'seq', nodes: [blockNode, switchNode, rest] };
  }

  // ── FALLBACK: multi-successor, can't structure cleanly ──
  const nodes: StructuredNode[] = [blockNode];
  for (const s of fwdSuccs) {
    const child = structureBlock(s, blockMap, backEdges, topoOrder, loopHeaders, visited, stopAt, depth + 1);
    nodes.push(child);
  }
  return { kind: 'seq', nodes };
}

function structureIrreducibleFallback(blocks: IRBlock[]): StructuredNode {
  const nodes: StructuredNode[] = [];
  const blockIds = new Set(blocks.map(b => b.id));
  for (const block of blocks) {
    nodes.push({ kind: 'label', id: block.id, address: block.start });
    nodes.push({ kind: 'block', irBlock: block });
    const last = block.stmts[block.stmts.length - 1];
    for (const succ of block.allSuccessors) {
      if (!blockIds.has(succ)) continue;
      nodes.push({ kind: 'goto', target: succ, address: last?.address ?? block.end });
    }
  }
  return { kind: 'seq', nodes };
}

function isEmptySeq(node: StructuredNode): boolean {
  return node.kind === 'seq' && node.nodes.length === 0;
}

// ─────────────────────────────────────────────────────────
// PHASE 6 — PSEUDO-CODE EMISSION
// ─────────────────────────────────────────────────────────

function emitNode(node: StructuredNode, varMap: VarMap, indent: number, lines: PseudoLine[]): void {
  switch (node.kind) {
    case 'seq':
      for (const child of node.nodes) emitNode(child, varMap, indent, lines);
      return;

    case 'block': {
      const { irBlock } = node;
      for (const stmt of irBlock.stmts) {
        const rendered = renderStmt(stmt, varMap);
        if (!rendered) continue;
        lines.push({
          indent,
          text: rendered.text,
          address: stmt.address,
          isUncertain: rendered.uncertain,
          kind: rendered.uncertain ? 'uncertain' : 'stmt',
        });
      }
      return;
    }

    case 'if': {
      lines.push({
        indent,
        text: `if (${node.cond}) {`,
        address: node.address,
        isUncertain: node.uncertain,
        kind: 'control',
      });
      emitNode(node.then, varMap, indent + 1, lines);
      if (node.else && !isEmptySeq(node.else)) {
        lines.push({ indent, text: '} else {', kind: 'brace' });
        emitNode(node.else, varMap, indent + 1, lines);
      }
      lines.push({ indent, text: '}', kind: 'brace' });
      return;
    }

    case 'while': {
      lines.push({
        indent,
        text: `while (${node.cond}) {`,
        address: node.address,
        kind: 'control',
      });
      emitNode(node.body, varMap, indent + 1, lines);
      lines.push({ indent, text: '}', kind: 'brace' });
      return;
    }

    case 'do-while': {
      lines.push({ indent, text: 'do {', address: node.address, kind: 'control' });
      emitNode(node.body, varMap, indent + 1, lines);
      lines.push({ indent, text: `} while (${node.cond});`, kind: 'brace' });
      return;
    }

    case 'for': {
      const initPart = node.init || '';
      lines.push({
        indent,
        text: `for (${initPart}; ${node.cond}; ${node.step}) {`,
        address: node.address,
        kind: 'control',
      });
      emitNode(node.body, varMap, indent + 1, lines);
      lines.push({ indent, text: '}', kind: 'brace' });
      return;
    }

    case 'switch': {
      lines.push({
        indent,
        text: `switch (${node.expr}) {`,
        address: node.address,
        isUncertain: node.uncertain,
        kind: 'control',
      });
      for (const c of node.cases) {
        lines.push({ indent: indent + 1, text: `case ${c.value}:`, kind: 'control' });
        emitNode(c.body, varMap, indent + 2, lines);
        lines.push({ indent: indent + 2, text: 'break;', kind: 'stmt' });
      }
      if (node.defaultCase && !isEmptySeq(node.defaultCase)) {
        lines.push({ indent: indent + 1, text: 'default:', kind: 'control' });
        emitNode(node.defaultCase, varMap, indent + 2, lines);
      }
      lines.push({ indent, text: '}', kind: 'brace' });
      return;
    }

    case 'label': {
      lines.push({
        indent,
        text: `label_${node.id}:`,
        address: node.address,
        isUncertain: true,
        kind: 'uncertain',
      });
      return;
    }

    case 'goto': {
      lines.push({
        indent,
        text: `goto label_${node.target};`,
        address: node.address,
        isUncertain: true,
        kind: 'uncertain',
      });
      return;
    }
  }
}

function collectAllStmts(blocks: IRBlock[]): IRStmt[] {
  return blocks.flatMap(b => b.stmts);
}

// ─────────────────────────────────────────────────────────
// LOGIC REGION DETECTION
// ─────────────────────────────────────────────────────────

/**
 * Analyse lifted IR blocks to identify comparison-heavy and gating regions.
 * Results are sorted by confidence descending so callers can prioritise.
 *
 * Detection rules:
 *   1. Serial-comparison — same register compared against ≥3 distinct constants
 *      in a single block (e.g. license key digit checks, opcode dispatch).
 *   2. Validation-gate — ≥3 cmp/test statements in a block that ends with a
 *      conditional jump; indicates a multi-condition input-validation check.
 *   3. Protection-guard — block contains both cmp/test and a call plus a
 *      conditional branch — suggests an integrity/anti-tamper check.
 *   4. Loop-condition — back-edge block with a bounded cmp — marks loop bounds
 *      that control algorithm termination.
 */
export function detectLogicRegions(irBlocks: IRBlock[]): LogicRegion[] {
  const regions: LogicRegion[] = [];

  for (const block of irBlocks) {
    const cmpStmts  = block.stmts.filter(s => s.op === 'cmp' || s.op === 'test');
    const cjmpStmts = block.stmts.filter(s => s.op === 'cjmp');
    const callStmts = block.stmts.filter(s => s.op === 'call');

    if (cmpStmts.length === 0) continue;

    const relatedAddresses = [
      ...cmpStmts.map(s => s.address),
      ...cjmpStmts.map(s => s.address),
    ];
    const baseAddress = relatedAddresses.length > 0
      ? Math.min(...relatedAddresses)
      : block.start;

    // ─ Rule 1: Serial-comparison — same base register vs ≥3 distinct constants ─
    const lhsRegCounts = new Map<string, Set<number>>();
    for (const s of cmpStmts) {
      const stmt = s as Extract<IRStmt, { op: 'cmp' | 'test' }>;
      if (stmt.left.kind === 'reg' && stmt.right.kind === 'const') {
        const reg = stmt.left.name;
        if (!lhsRegCounts.has(reg)) lhsRegCounts.set(reg, new Set());
        lhsRegCounts.get(reg)!.add(stmt.right.value);
      }
    }
    for (const [reg, constants] of lhsRegCounts) {
      if (constants.size >= 3) {
        const conf = Math.min(0.95, 0.55 + constants.size * 0.08);
        regions.push({
          address: baseAddress,
          blockId: block.id,
          kind: 'serial-comparison',
          comparisonCount: cmpStmts.length,
          confidence: conf,
          summary: `Serial comparison: '${reg}' tested against ${constants.size} distinct constants — probable auth/license check or dispatch table`,
          relatedAddresses,
        });
        break;
      }
    }

    // ─ Rule 2: Validation-gate — ≥3 cmp/test with a trailing conditional jump ─
    if (cmpStmts.length >= 3 && cjmpStmts.length >= 1) {
      const conf = Math.min(0.90, 0.45 + cmpStmts.length * 0.10 + cjmpStmts.length * 0.05);
      regions.push({
        address: baseAddress,
        blockId: block.id,
        kind: 'validation-gate',
        comparisonCount: cmpStmts.length,
        confidence: conf,
        summary: `Validation gate: ${cmpStmts.length} comparison(s) → ${cjmpStmts.length} conditional branch(es) — multi-condition input validation or protection check`,
        relatedAddresses,
      });
    }

    // ─ Rule 3: Protection-guard — cmp/test + call + conditional branch ─
    if (cmpStmts.length >= 2 && callStmts.length >= 1 && cjmpStmts.length >= 1) {
      const namedCalls = callStmts.filter(s => {
        const c = s as Extract<IRStmt, { op: 'call' }>;
        return c.name !== undefined || c.target !== null;
      });
      if (namedCalls.length > 0) {
        const conf = Math.min(0.85, 0.50 + cmpStmts.length * 0.08);
        regions.push({
          address: baseAddress,
          blockId: block.id,
          kind: 'protection-guard',
          comparisonCount: cmpStmts.length,
          confidence: conf,
          summary: `Protection guard: ${cmpStmts.length} comparison(s) + ${namedCalls.length} call(s) + conditional branch — possible integrity/anti-tamper check`,
          relatedAddresses: [
            ...relatedAddresses,
            ...namedCalls.map(s => s.address),
          ],
        });
      }
    }

    // ─ Rule 4: Loop-condition — back-edge block with bounded cmp ─
    const isBackEdgeTarget = irBlocks.some(
      b => b.allSuccessors.includes(block.id) && b.start > block.start
    );
    if (isBackEdgeTarget && cmpStmts.length >= 1 && cjmpStmts.length >= 1) {
      const conf = Math.min(0.75, 0.40 + cmpStmts.length * 0.10);
      regions.push({
        address: baseAddress,
        blockId: block.id,
        kind: 'loop-condition',
        comparisonCount: cmpStmts.length,
        confidence: conf,
        summary: `Loop condition: back-edge block with ${cmpStmts.length} bound comparison(s) — algorithm termination or iteration-count guard`,
        relatedAddresses,
      });
    }
  }

  // Deduplicate: keep the highest-confidence region per block, except
  // protection-guard which is orthogonal and should always be surfaced.
  const blockBest = new Map<string, LogicRegion>();
  for (const r of regions) {
    const existing = blockBest.get(r.blockId);
    if (!existing || r.confidence > existing.confidence) {
      blockBest.set(r.blockId, r);
    }
  }
  const deduplicated: LogicRegion[] = [];
  for (const r of regions) {
    const best = blockBest.get(r.blockId);
    if (r === best || r.kind === 'protection-guard') {
      deduplicated.push(r);
    }
  }

  return deduplicated.sort((a, b) => b.confidence - a.confidence);
}

// ─────────────────────────────────────────────────────────
// MATURITY TELEMETRY / EXPORT HELPERS
// ─────────────────────────────────────────────────────────

function groupConsecutiveAddresses(addresses: number[]): Array<{ start: number; end: number; count: number }> {
  const sorted = [...addresses].sort((a, b) => a - b);
  const ranges: Array<{ start: number; end: number; count: number }> = [];
  for (const address of sorted) {
    const last = ranges[ranges.length - 1];
    if (!last || address > last.end + 16) {
      ranges.push({ start: address, end: address, count: 1 });
    } else {
      last.end = address;
      last.count += 1;
    }
  }
  return ranges;
}

function reachableBlockIds(blocks: IRBlock[], backEdges: Set<string>): Set<string> {
  const entry = findEntryBlock(blocks);
  if (!entry) return new Set();
  const blockMap = new Map(blocks.map(b => [b.id, b]));
  const seen = new Set<string>();
  const queue = [entry.id];
  while (queue.length > 0) {
    const id = queue.shift()!;
    if (seen.has(id)) continue;
    seen.add(id);
    const block = blockMap.get(id);
    if (!block) continue;
    for (const successor of block.allSuccessors) {
      if (!backEdges.has(`${id}->${successor}`) && !seen.has(successor)) {
        queue.push(successor);
      }
    }
  }
  return seen;
}

function buildDecompilerMaturityTelemetry(args: {
  architecture: Architecture;
  instructionCount: number;
  irBlocks: IRBlock[];
  varMap: VarMap;
  lines: PseudoLine[];
  warnings: string[];
  logicRegions: LogicRegion[];
  conservativeRewriteCount: number;
  explicitIrSummary?: DecompilerMaturitySummary;
}): DecompilerMaturityTelemetry {
  const allStmts = collectAllStmts(args.irBlocks);
  const unknownAddresses = allStmts.filter(s => s.op === 'unknown').map(s => s.address);
  const backEdges = computeBackEdges(args.irBlocks);
  const reachableIds = reachableBlockIds(args.irBlocks, backEdges);
  const unreachableBlocks = args.irBlocks.filter(block => !reachableIds.has(block.id)).map(block => block.id);
  const calls = allStmts.filter((stmt): stmt is Extract<IRStmt, { op: 'call' }> => stmt.op === 'call');
  const recoveredCalls = calls.filter(call => (call.args?.length ?? 0) > 0);
  const varNames = Array.from(args.varMap.values());
  const localNames = Array.from(new Set(varNames.filter(name => name.startsWith('local_')))).sort();
  const stackArgNames = Array.from(new Set(varNames.filter(name => name.startsWith('arg_')))).sort();
  const registerParamNames = Array.from(new Set(varNames.filter(name => name.startsWith('param_')))).sort();
  const limitations = [
    'Decompiler/disassembler maturity telemetry is advisory analyst guidance only; it is not GYRE verdict evidence.',
    'Pseudocode is lifted from bounded disassembly and should not be read as exact source recovery.',
    'Call arguments are recovered from stale-bounded register/stack windows and may be incomplete.',
    'CFG shape is derived from available static blocks/edges; unresolved indirect flow remains uncertain.',
  ];
  if (unknownAddresses.length > 0) {
    limitations.push('Some instructions could not be lifted and are preserved as uncertain raw assembly comments.');
  }
  if (args.warnings.some(w => w.includes('fallback partitioning'))) {
    limitations.push('CFG/disassembly ranges did not fully align; instruction-derived fallback partitioning was used.');
  }

  const explicitIrSummary = args.explicitIrSummary ?? computeDecompilerMaturitySummary({
    instructions: [],
    irNodes: [],
    irBlocks: args.irBlocks,
    lines: args.lines,
    warnings: args.warnings,
    fallbackPartitioningUsed: args.warnings.some(w => w.includes('fallback partitioning')),
  });

  return {
    schemaVersion: '1.0.0',
    advisoryOnly: true,
    authorityBoundary: 'talon_veil_guidance_not_verdict_authority',
    architecture: args.architecture,
    instructionSummary: {
      total: args.instructionCount,
      lifted: Math.max(0, allStmts.length - unknownAddresses.length),
      unknown: unknownAddresses.length,
      unknownAddresses,
      failedDecodeRanges: groupConsecutiveAddresses(unknownAddresses),
    },
    cfgSummary: {
      blockCount: args.irBlocks.length,
      edgeCount: args.irBlocks.reduce((count, block) => count + block.allSuccessors.length, 0),
      backEdgeCount: backEdges.size,
      unreachableBlockCount: unreachableBlocks.length,
      unreachableBlocks,
      fallbackPartitioningUsed: args.warnings.some(w => w.includes('fallback partitioning')),
    },
    callArgumentRecovery: {
      callCount: calls.length,
      recoveredCallCount: recoveredCalls.length,
      unresolvedCallCount: Math.max(0, calls.length - recoveredCalls.length),
      recoveredArgumentCount: recoveredCalls.reduce((count, call) => count + (call.args?.length ?? 0), 0),
      registerWindowCount: calls.filter(call => call.argRecovery === 'register-window').length,
      stackWindowCount: calls.filter(call => call.argRecovery === 'stack-window').length,
      registerStackWindowCount: calls.filter(call => call.argRecovery === 'register-stack-window').length,
    },
    stackFrameSummary: {
      localCount: localNames.length,
      stackArgCount: stackArgNames.length,
      registerParamCount: registerParamNames.length,
      localNames,
      stackArgNames,
      registerParamNames,
    },
    pseudocodeQuality: {
      uncertainLineCount: args.lines.filter(line => line.isUncertain || line.kind === 'uncertain').length,
      warningCount: args.warnings.length,
      conservativeRewriteCount: args.conservativeRewriteCount,
      logicRegionCount: args.logicRegions.length,
    },
    explicitIrSummary,
    limitations,
  };
}

function emptyDecompilerMaturityTelemetry(
  architecture: Architecture,
  instructionCount: number,
  warnings: string[],
): DecompilerMaturityTelemetry {
  return buildDecompilerMaturityTelemetry({
    architecture,
    instructionCount,
    irBlocks: [],
    varMap: new Map(),
    lines: [],
    warnings,
    logicRegions: [],
    conservativeRewriteCount: 0,
  });
}

export function decompilerMaturityToExport(result: DecompileResult) {
  return {
    schema: 'hexhawk.decompiler_maturity.v1',
    generatedAt: new Date().toISOString(),
    functionName: result.functionName,
    startAddress: result.startAddress,
    advisoryOnly: true,
    authorityBoundary: result.maturity.authorityBoundary,
    maturity: result.maturity,
    proofLimits: result.maturity.limitations,
  };
}

export function formatDecompilerMaturityMarkdown(result: DecompileResult): string {
  const m = result.maturity;
  const lines = [
    `# HexHawk Decompiler/Disassembler Maturity Telemetry`,
    ``,
    `Function: ${result.functionName} at 0x${result.startAddress.toString(16)}`,
    ``,
    `> Advisory only: TALON/VEIL guidance is not GYRE verdict authority and does not mutate NEST final verdicts.`,
    ``,
    `## Recovery Summary`,
    ``,
    `- Architecture: ${m.architecture}`,
    `- Instructions: ${m.instructionSummary.total} total, ${m.instructionSummary.lifted} lifted, ${m.instructionSummary.unknown} unknown`,
    `- CFG: ${m.cfgSummary.blockCount} blocks, ${m.cfgSummary.edgeCount} edges, ${m.cfgSummary.backEdgeCount} back edge(s), ${m.cfgSummary.unreachableBlockCount} unreachable block(s)`,
    `- Calls: ${m.callArgumentRecovery.recoveredCallCount}/${m.callArgumentRecovery.callCount} call site(s) with recovered arguments; ${m.callArgumentRecovery.recoveredArgumentCount} argument fact(s)`,
    `- Stack frame: ${m.stackFrameSummary.localCount} locals, ${m.stackFrameSummary.stackArgCount} stack args, ${m.stackFrameSummary.registerParamCount} register params`,
    `- Pseudocode quality: ${m.pseudocodeQuality.uncertainLineCount} uncertain line(s), ${m.pseudocodeQuality.warningCount} warning(s), ${m.pseudocodeQuality.conservativeRewriteCount} conservative CSE rewrite(s)`,
    `- Explicit IR maturity: ${m.explicitIrSummary.confidence} confidence, ${m.explicitIrSummary.fallbackMode}, ${m.explicitIrSummary.structuredBlockPercentage}% structured-block signal`,
    `- Explicit IR limits: ${m.explicitIrSummary.unknownInstructionCount} unknown instruction(s), ${m.explicitIrSummary.unresolvedCalls} unresolved call(s), ${m.explicitIrSummary.unresolvedIndirectJumps} unresolved indirect jump(s)`,
    ``,
    `## Limitations`,
    ``,
    ...m.limitations.map(limit => `- ${limit}`),
  ];
  return lines.join('\n');
}

// ─────────────────────────────────────────────────────────
// PUBLIC API
// ─────────────────────────────────────────────────────────

export interface DecompileOptions {
  startAddress?: number;
  endAddress?: number;
  functionName?: string;
}

export function decompile(
  instructions: DisassembledInstruction[],
  cfg: CfgGraph | null,
  options: DecompileOptions = {}
): DecompileResult {
  const warnings: string[] = [];

  // Slice to the requested range
  let insns = instructions;
  if (options.startAddress !== undefined || options.endAddress !== undefined) {
    const lo = options.startAddress ?? -Infinity;
    const hi = options.endAddress ?? Infinity;
    insns = instructions.filter(ins => ins.address >= lo && ins.address <= hi);
  }

  if (insns.length === 0) {
    const emptyWarnings = ['No instructions to decompile'];
    return {
      functionName: options.functionName ?? 'sub_unknown',
      startAddress: options.startAddress ?? 0,
      lines: [{ indent: 0, text: '// No instructions in range', kind: 'comment' }],
      varMap: new Map(),
      irBlocks: [],
      structured: { kind: 'seq', nodes: [] },
      logicRegions: [],
      warnings: emptyWarnings,
      instrCount: 0,
      maturity: emptyDecompilerMaturityTelemetry('x86_64', 0, emptyWarnings),
    };
  }

  const startAddress = options.startAddress ?? insns[0].address;
  const funcName = options.functionName ?? `sub_${startAddress.toString(16)}`;

  // Phase 3+4: Build IR blocks
  const arch = detectArch(insns);
  let irBlocks = applyImportPrototypeTypePropagation(buildIRBlocks(insns, cfg, arch));

  if (!irBlocks.length) {
    const fallbackBlocks = buildFallbackPartitionedIRBlocks(insns, arch);
    if (fallbackBlocks.length > 0) {
      irBlocks = applyImportPrototypeTypePropagation(fallbackBlocks);
      warnings.push('CFG did not overlap disassembly range; used instruction-derived fallback partitioning.');
    }
  }

  if (!irBlocks.length) {
    const emptyWarnings = ['No basic blocks built'];
    return {
      functionName: funcName,
      startAddress,
      lines: [{ indent: 0, text: '// Could not build basic blocks', kind: 'comment' }],
      varMap: new Map(),
      irBlocks: [],
      structured: { kind: 'seq', nodes: [] },
      logicRegions: [],
      warnings: emptyWarnings,
      instrCount: insns.length,
      maturity: emptyDecompilerMaturityTelemetry(arch, insns.length, emptyWarnings),
    };
  }

  // Phase 3: Build variable map
  const allStmts = collectAllStmts(irBlocks);
  const varMap = buildVarMap(allStmts, arch);
  applyTypeHintNames(allStmts, varMap);

  // Detect return register (arch-aware)
  const retRegs = arch === 'arm32' ? RETURN_REGS_ARM32
                : arch === 'aarch64' ? RETURN_REGS_AARCH64
                : RETURN_REGS;
  const hasRetVal = allStmts.some(s =>
    s.op === 'assign' && s.dest.kind === 'reg' && retRegs.has((s.dest as { name: string }).name)
  );

  // Build parameter list from detected arg regs / stack args (arch-aware)
  const argRegs = arch === 'arm32' ? ARG_REGS_ARM32
                : arch === 'aarch64' ? ARG_REGS_AARCH64
                : ARG_REGS_64;
  const paramNames: string[] = [];
  for (const reg of argRegs) {
    if (varMap.has(`reg:${reg}`)) paramNames.push(varMap.get(`reg:${reg}`)!);
  }
  // Also check stack args
  for (const [, name] of Array.from(varMap.entries())) {
    if (name.startsWith('arg_')) paramNames.push(name);
  }
  const uniqueParams = Array.from(new Set(paramNames)).sort();

  if (irBlocks.length > 32) {
    warnings.push(`Large function (${irBlocks.length} blocks) — control flow may be simplified.`);
  }

  // Phase 5: Structure control flow
  const blockMap = new Map(irBlocks.map(b => [b.id, b]));
  const ssaFormForStructuring = buildSSAForm(irBlocks);
  const ssaVariableCoalescing = ssaFormForStructuring.ok
    ? coalesceSSAVariables(ssaFormForStructuring)
    : undefined;
  const dominanceBackEdges = ssaFormForStructuring.ok
    ? computeDominanceBackEdges(irBlocks, ssaFormForStructuring.domTree)
    : new Set<string>();
  const backEdges = dominanceBackEdges.size > 0 ? dominanceBackEdges : computeBackEdges(irBlocks);
  const loopHeaders = computeLoopHeaders(backEdges);
  const topo = topoSort(irBlocks, backEdges);
  const entry = findEntryBlock(irBlocks);

  let structured: StructuredNode;
  if (!ssaFormForStructuring.ok && irBlocks.length > 1) {
    structured = structureIrreducibleFallback(irBlocks);
    warnings.push('Irreducible CFG detected; emitted explicit labels and gotos instead of source-like structuring.');
  } else if (entry) {
    structured = structureBlock(entry.id, blockMap, backEdges, topo, loopHeaders, new Set(), null, 0);
  } else {
    structured = { kind: 'seq', nodes: irBlocks.map(b => ({ kind: 'block' as const, irBlock: b })) };
    warnings.push('Could not find entry block — using flat block sequence.');
  }

  // Phase 6: Emit pseudo-code
  const lines: PseudoLine[] = [];

  // Function header
  const paramList = uniqueParams.length > 0 ? uniqueParams.join(', ') : '';
  lines.push({ indent: 0, text: `// ${funcName}  [${insns.length} instructions]`, kind: 'comment' });
  lines.push({ indent: 0, text: `function ${funcName}(${paramList}) {`, kind: 'header' });

  if (varMap.size > 0) {
    const locals = Array.from(varMap.values()).filter(v => v.startsWith('local_'));
    if (locals.length > 0) {
      lines.push({ indent: 1, text: `// locals: ${locals.join(', ')}`, kind: 'comment' });
    }
  }

  if (backEdges.size > 0) {
    lines.push({ indent: 1, text: `// ${backEdges.size} back edge(s) detected (loops)`, kind: 'comment' });
  }

  lines.push({ indent: 0, text: '', kind: 'blank' });

  emitNode(structured, varMap, 1, lines);

  // Inject `return` if last meaningful line doesn't end with one
  const lastMeaningful = [...lines].reverse().find(l => l.kind === 'stmt' || l.kind === 'control');
  if (!lastMeaningful || !lastMeaningful.text.startsWith('return')) {
    if (hasRetVal) {
      const retReg = [...allStmts].reverse().find((s): s is Extract<IRStmt, { op: 'ret' }> => s.op === 'ret');
      if (retReg) {
        // Look back for last assignment to eax/rax
        const retAssign = [...allStmts].reverse().find(
          s => s.op === 'assign' && s.dest.kind === 'reg' && RETURN_REGS.has(s.dest.name)
        );
        if (retAssign && retAssign.op === 'assign') {
          const retVal = renderValue(retAssign.src, varMap);
          lines.push({ indent: 1, text: `return ${retVal};`, address: retReg.address, kind: 'stmt' });
        }
      }
    }
  }

  lines.push({ indent: 0, text: '}', kind: 'brace' });

  const logicRegions = detectLogicRegions(irBlocks);

  // Run CSE pass on IR blocks to eliminate redundant computations
  const { blocks: optimizedBlocks, rewriteCount: cseRewriteCount } = applyCSE(irBlocks);

  const explicitIrNodes = liftInstructionsToDecompilerIr(insns);
  const explicitIrSummary = computeDecompilerMaturitySummary({
    instructions: insns,
    irNodes: explicitIrNodes,
    irBlocks: optimizedBlocks,
    lines,
    warnings,
    fallbackPartitioningUsed: warnings.some(w => w.includes('fallback partitioning')),
  });

  const maturity = buildDecompilerMaturityTelemetry({
    architecture: arch,
    instructionCount: insns.length,
    irBlocks: optimizedBlocks,
    varMap,
    lines,
    warnings,
    logicRegions,
    conservativeRewriteCount: cseRewriteCount,
    explicitIrSummary,
  });

  return {
    functionName: funcName,
    startAddress,
    lines,
    varMap,
    irBlocks: optimizedBlocks,
    structured,
    ssaVariableCoalescing,
    logicRegions,
    warnings,
    instrCount: insns.length,
    cseRewriteCount,
    maturity,
  };
}

// ─────────────────────────────────────────────────────────
// CSE — COMMON SUBEXPRESSION ELIMINATION PASS
// ─────────────────────────────────────────────────────────

/**
 * Produce a canonical key for an IRValue suitable for CSE hashing.
 * Two values with the same key are semantically equal and interchangeable.
 * Memory accesses are excluded because they may alias.
 */
function cseValueKey(v: IRValue): string | null {
  if (v.kind === 'reg')   return `r:${v.name}`;
  if (v.kind === 'const') return `c:${v.value}`;
  // Don't hash memory or expr — too imprecise for alias-free CSE
  return null;
}

/**
 * Produce a canonical key for a binary or unary IR expression.
 * Returns null when the expression is not CSE-eligible.
 *
 * Commutative operators (+, *, &, |, ^) are normalised so that
 * `a + b` and `b + a` yield the same key.
 */
function cseExprKey(stmt: IRStmt): string | null {
  if (stmt.op === 'binop') {
    const lk = cseValueKey(stmt.left);
    const rk = cseValueKey(stmt.right);
    if (!lk || !rk) return null;
    const op = stmt.operator;
    const COMMUTATIVE = new Set(['+', '*', '&', '|', '^']);
    // Normalise commutative operand order for stable keys
    const [a, b] = COMMUTATIVE.has(op) && lk > rk ? [rk, lk] : [lk, rk];
    return `binop:${op}:${a}:${b}`;
  }
  if (stmt.op === 'uop') {
    const ok = cseValueKey(stmt.operand);
    if (!ok) return null;
    return `uop:${stmt.operator}:${ok}`;
  }
  return null;
}

/**
 * Apply a single-pass Common Subexpression Elimination over IR blocks.
 *
 * Algorithm (global, flow-insensitive):
 *   1. Walk all blocks in their existing order.
 *   2. For each binop/uop, compute `exprKey(stmt)`.
 *   3. If this key was seen before and the destination register still holds
 *      that value (checked by tracking which registers have been modified),
 *      replace the stmt with `assign dest ← firstDest`.
 *   4. If this is the *first* time we see the key, record (key → destReg).
 *
 * Conservative: any intervening store to either operand register (or the result
 * register itself) invalidates the cached expression, preventing stale values.
 */
export function applyCSE(blocks: IRBlock[]): { blocks: IRBlock[]; rewriteCount: number } {
  // exprKey → { destReg: string, destValue: IRValue }
  const available = new Map<string, { destValue: IRValue; destReg: string }>();

  /** Remove all cached expressions whose result register or operands include modifiedReg. */
  function invalidate(modifiedReg: string): void {
    for (const [k, v] of available) {
      if (
        v.destReg === modifiedReg ||
        k.includes(`:r:${modifiedReg}`) ||
        k.includes(`r:${modifiedReg}:`)
      ) {
        available.delete(k);
      }
    }
  }

  let rewriteCount = 0;

  const resultBlocks = blocks.map(block => {
    const newStmts: IRStmt[] = block.stmts.map(stmt => {
      const key = cseExprKey(stmt);
      const destValue = 'dest' in stmt ? (stmt as { dest: IRValue }).dest : null;

      if (key) {
        const found = available.get(key);
        if (found) {
          // Replace with a cheap register copy
          const replacement: IRStmt = {
            op: 'assign',
            address: stmt.address,
            dest: (stmt as { dest: IRValue }).dest,
            src: found.destValue,
          };
          rewriteCount++;
          // If the result dest overwrites another register, invalidate it too
          if (destValue?.kind === 'reg') invalidate(destValue.name);
          return replacement;
        }
        // First occurrence — invalidate the dest register FIRST (so stale entries
        // referring to it as a result holder are removed), then record fresh entry.
        if (destValue?.kind === 'reg') {
          invalidate(destValue.name);
          available.set(key, { destValue, destReg: destValue.name });
        }
      } else {
        // Non-CSE statement: invalidate any cached results affected by this write
        if (destValue?.kind === 'reg') invalidate(destValue.name);
      }

      return stmt;
    });

    return { ...block, stmts: newStmts };
  });

  return { blocks: resultBlocks, rewriteCount };
}
