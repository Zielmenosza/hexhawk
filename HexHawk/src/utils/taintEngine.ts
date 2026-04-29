/**
 * taintEngine — Taint Analysis & Keygen Shape Detection for TALON (M6)
 *
 * Pipeline:
 *   1. taintPropagate()      — forward taint from user-input sources through IR
 *   2. detectKeygenShapes()  — find input→arith→cmp→branch patterns
 *   3. emitSMTLib2()         — serialise a KeygenShape to SMT-LIB2 for Z3
 *
 * This module is pure TypeScript (no Rust, no native deps) and operates on
 * the IRBlock[] already produced by decompilerEngine / talonEngine.
 *
 * Design notes:
 *   - Taint is tracked at the varBase level (register name, e.g. "rax").
 *     Memory taint uses the base register name prefixed with "mem:".
 *   - The analysis is intentionally unsound: it will miss cases.  The goal
 *     is high signal-to-noise for CTF key-check patterns, not soundness.
 *   - SMT-LIB2 output is simplified (linear constraints only).  Non-linear
 *     or obfuscated constraints are flagged but not solved.
 */

import type { IRBlock, IRStmt, IRValue } from './decompilerEngine';

// ─── Types ────────────────────────────────────────────────────────────────────

/** A register / memory location that carries taint. */
export type TaintVar = string;   // e.g. "rax", "rcx", "mem:rsp+0"

/** Where taint enters the function (source of user-controlled data). */
export interface TaintSource {
  address: number;
  kind: TaintSourceKind;
  vars: TaintVar[];      // which vars become tainted
  apiName?: string;      // if the source is an API call
}

export type TaintSourceKind =
  | 'api-input'          // GetDlgItemTextA/W, scanf, fgets, ReadFile, recv, ...
  | 'argv'               // argv[1], argv[2] — function argument in rcx/rdi slot
  | 'stdin-read'         // read(), fread(), fgets()
  | 'return-value';      // generic: use after call whose return is likely user data

/** A comparison between a tainted value and a constant (the key check gate). */
export interface TaintedComparison {
  address: number;
  taintedSide: 'left' | 'right' | 'both';
  taintedVar: TaintVar;
  constValue: number | null;
  /** Simplified expression for the tainted side (best-effort). */
  taintedExpr: string;
  /** Original cmp/test operator as inferred from IR context. */
  inferredOp: '==' | '!=' | '<' | '<=' | '>' | '>=' | 'unknown';
  blockId: string;
}

/** A key-check shape: source → transform chain → comparison → branch. */
export interface KeygenShape {
  id: string;
  source: TaintSource;
  transformChain: TaintTransform[];
  comparison: TaintedComparison;
  /** Address of the conditional jump that acts as the serial check gate. */
  branchAddress: number;
  /** Human-readable summary. */
  summary: string;
  /** SMT-LIB2 string for this constraint (may be empty if not reducible). */
  smtLib2: string;
  confidence: number;    // 0–100
}

/** One arithmetic transformation in the taint chain. */
export interface TaintTransform {
  address: number;
  op: string;       // '+', '-', '*', '^', '&', '|', ...
  dest: TaintVar;
  /** Right-hand operand as a string (constant or another var). */
  rhs: string;
}

/** Full result returned by runTaintAnalysis(). */
export interface TaintAnalysisResult {
  sources: TaintSource[];
  taintedVars: Set<TaintVar>;
  comparisons: TaintedComparison[];
  shapes: KeygenShape[];
  /** True if any tainted path reaches a call, memory write, or syscall
   *  that looks like output/exfiltration — may indicate data-flow beyond serial check. */
  hasDownstreamSink: boolean;
}

// ─── Known taint-source APIs ──────────────────────────────────────────────────

const INPUT_APIS: ReadonlyMap<string, TaintVar[]> = new Map([
  // Windows dialog / edit control
  ['GetDlgItemTextA',    ['rax', 'rdx']],
  ['GetDlgItemTextW',    ['rax', 'rdx']],
  ['GetWindowTextA',     ['rax', 'rdx']],
  ['GetWindowTextW',     ['rax', 'rdx']],
  // CRT
  ['scanf',              ['rax']],
  ['scanf_s',            ['rax']],
  ['sscanf',             ['rax']],
  ['fgets',              ['rax', 'rcx']],
  ['gets',               ['rax']],
  ['gets_s',             ['rax']],
  ['fread',              ['rax', 'rcx']],
  // POSIX
  ['read',               ['rax']],
  ['recv',               ['rax']],
  ['recvfrom',           ['rax']],
  // Windows I/O
  ['ReadFile',           ['r8']],    // lpBuffer = 3rd arg (r8 on win64)
  ['ReadConsoleA',       ['rdx']],
  ['ReadConsoleW',       ['rdx']],
  ['ReadConsoleInputA',  ['rdx']],
  ['ReadConsoleInputW',  ['rdx']],
]);

// APIs whose return value (rax) should be treated as user-controlled
const RETURN_TAINT_APIS = new Set([
  'atoi', 'atol', 'atoll', 'strtol', 'strtoul', 'strtoll', 'strtoull',
  'strtod', 'sscanf',
  'GetDlgItemInt',
]);

// ─── Helpers ──────────────────────────────────────────────────────────────────

function varName(v: IRValue): TaintVar | null {
  if (v.kind === 'reg') return v.name;
  if (v.kind === 'mem') return `mem:${v.base}+${v.offset}`;
  return null;
}

function exprText(v: IRValue, env: Map<TaintVar, string>): string {
  if (v.kind === 'const') return `0x${v.value.toString(16)}`;
  if (v.kind === 'reg') return env.get(v.name) ?? v.name;
  if (v.kind === 'mem') {
    const key = `mem:${v.base}+${v.offset}`;
    return env.get(key) ?? `*[${v.base}+${v.offset}]`;
  }
  if (v.kind === 'expr') return v.text;
  return '?';
}

function isTainted(v: IRValue, tainted: Set<TaintVar>): boolean {
  const n = varName(v);
  return n !== null && tainted.has(n);
}

// ─── Phase 1: Taint propagation ───────────────────────────────────────────────

/**
 * Forward-propagate taint through the IR block list.
 * Returns taint sources discovered, the live tainted-var set, and the
 * tainted-comparison list.
 */
export function taintPropagate(blocks: IRBlock[]): {
  sources: TaintSource[];
  tainted: Set<TaintVar>;
  comparisons: TaintedComparison[];
  transforms: TaintTransform[];
  hasDownstreamSink: boolean;
} {
  const tainted = new Set<TaintVar>();
  const sources: TaintSource[] = [];
  const comparisons: TaintedComparison[] = [];
  const transforms: TaintTransform[] = [];
  let hasDownstreamSink = false;

  // Assume first two integer arguments (rcx/rdi, rdx/rsi = argv) are tainted
  // when this looks like a main() entry (heuristic: first block, prologue).
  const firstBlock = blocks[0];
  if (firstBlock) {
    const hasPrologue = firstBlock.stmts.some(s => s.op === 'prologue');
    if (hasPrologue) {
      // argv[1..] — rcx/rdi on x64/ARM
      for (const reg of ['rcx', 'rdx', 'r8', 'r9', 'rdi', 'rsi', 'rdx']) {
        tainted.add(reg);
      }
      sources.push({
        address: firstBlock.start,
        kind: 'argv',
        vars: ['rcx', 'rdx', 'r8', 'r9', 'rdi', 'rsi'],
      });
    }
  }

  // Expression simplification: map varBase → simplified expression string
  const exprEnv = new Map<TaintVar, string>();

  for (const block of blocks) {
    for (const stmt of block.stmts) {
      switch (stmt.op) {
        case 'call': {
          const api = stmt.name;
          if (!api) break;

          // Check if the API is a known input source
          const inputVars = INPUT_APIS.get(api);
          if (inputVars) {
            for (const v of inputVars) tainted.add(v);
            sources.push({
              address: stmt.address,
              kind: 'api-input',
              vars: [...inputVars],
              apiName: api,
            });
          }

          // Return-value taint
          if (RETURN_TAINT_APIS.has(api)) {
            tainted.add('rax');
            sources.push({
              address: stmt.address,
              kind: 'return-value',
              vars: ['rax'],
              apiName: api,
            });
          }

          // Downstream sink detection
          if (tainted.size > 0) {
            const SINK_APIS = ['WriteFile', 'send', 'sendto', 'WriteProcessMemory',
                               'CreateFileA', 'CreateFileW', 'fwrite', 'printf', 'fprintf'];
            if (SINK_APIS.includes(api)) hasDownstreamSink = true;
          }
          break;
        }

        case 'assign': {
          const destVar = varName(stmt.dest);
          if (!destVar) break;
          if (isTainted(stmt.src, tainted)) {
            tainted.add(destVar);
            const srcExpr = exprText(stmt.src, exprEnv);
            exprEnv.set(destVar, srcExpr);
          } else if (stmt.src.kind === 'const') {
            // Constant assigned to a var — not taint, but track for cmp resolution
            exprEnv.set(destVar, `0x${stmt.src.value.toString(16)}`);
          }
          break;
        }

        case 'binop': {
          const destVar = varName(stmt.dest);
          if (!destVar) break;
          const leftTainted = isTainted(stmt.left, tainted);
          const rightTainted = isTainted(stmt.right, tainted);
          if (leftTainted || rightTainted) {
            tainted.add(destVar);
            const lExpr = exprText(stmt.left, exprEnv);
            const rExpr = exprText(stmt.right, exprEnv);
            const newExpr = `(${lExpr} ${stmt.operator} ${rExpr})`;
            exprEnv.set(destVar, newExpr);
            transforms.push({
              address: stmt.address,
              op: stmt.operator,
              dest: destVar,
              rhs: exprText(stmt.right, exprEnv),
            });
          }
          break;
        }

        case 'uop': {
          const destVar = varName(stmt.dest);
          if (!destVar) break;
          if (isTainted(stmt.operand, tainted)) {
            tainted.add(destVar);
            const inner = exprText(stmt.operand, exprEnv);
            exprEnv.set(destVar, `(${stmt.operator}${inner})`);
            transforms.push({
              address: stmt.address,
              op: stmt.operator,
              dest: destVar,
              rhs: inner,
            });
          }
          break;
        }

        case 'push': {
          if (isTainted(stmt.value, tainted)) {
            tainted.add('mem:rsp+0');
            exprEnv.set('mem:rsp+0', exprText(stmt.value, exprEnv));
          }
          break;
        }

        case 'pop': {
          const destVar = varName(stmt.dest);
          if (!destVar) break;
          if (tainted.has('mem:rsp+0')) {
            tainted.add(destVar);
            const inner = exprEnv.get('mem:rsp+0') ?? '?';
            exprEnv.set(destVar, inner);
          }
          break;
        }

        case 'cmp':
        case 'test': {
          const leftTainted = isTainted(stmt.left, tainted);
          const rightTainted = isTainted(stmt.right, tainted);
          if (!leftTainted && !rightTainted) break;

          const taintedSide: 'left' | 'right' | 'both' =
            leftTainted && rightTainted ? 'both' : leftTainted ? 'left' : 'right';

          const taintedVarRef = taintedSide === 'right'
            ? varName(stmt.right)
            : varName(stmt.left);

          const constSide = taintedSide === 'left' ? stmt.right : stmt.left;
          const constValue = constSide.kind === 'const' ? constSide.value : null;

          // Infer operator from cjmp that follows this cmp (look ahead in block)
          const cmpIdx = block.stmts.indexOf(stmt);
          let inferredOp: TaintedComparison['inferredOp'] = 'unknown';
          for (let i = cmpIdx + 1; i < block.stmts.length; i++) {
            const next = block.stmts[i];
            if (next.op === 'cjmp') {
              inferredOp = condToOp(next.cond);
              break;
            }
          }

          comparisons.push({
            address: stmt.address,
            taintedSide,
            taintedVar: taintedVarRef ?? (taintedSide === 'left' ? exprText(stmt.left, exprEnv) : exprText(stmt.right, exprEnv)),
            constValue,
            taintedExpr: taintedSide === 'right'
              ? exprText(stmt.right, exprEnv)
              : exprText(stmt.left, exprEnv),
            inferredOp,
            blockId: block.id,
          });
          break;
        }
      }
    }
  }

  return { sources, tainted, comparisons, transforms, hasDownstreamSink };
}

function condToOp(cond: string): TaintedComparison['inferredOp'] {
  const c = cond.toLowerCase();
  if (c === 'e' || c === 'z')  return '==';
  if (c === 'ne' || c === 'nz') return '!=';
  if (c === 'l' || c === 'b')   return '<';
  if (c === 'le' || c === 'be') return '<=';
  if (c === 'g' || c === 'a')   return '>';
  if (c === 'ge' || c === 'ae') return '>=';
  return 'unknown';
}

// ─── Phase 2: Keygen shape detection ─────────────────────────────────────────

/**
 * Classify each tainted comparison as a keygen shape candidate if it has
 * a reachable source and at least one transform in its chain.
 */
export function detectKeygenShapes(
  blocks: IRBlock[],
  sources: TaintSource[],
  transforms: TaintTransform[],
  comparisons: TaintedComparison[],
): KeygenShape[] {
  if (sources.length === 0 || comparisons.length === 0) return [];

  const shapes: KeygenShape[] = [];
  let shapeIdx = 0;

  for (const cmp of comparisons) {
    // Find the cjmp in the same block
    const block = blocks.find(b => b.id === cmp.blockId);
    const cjmpStmt = block?.stmts.find(s => s.op === 'cjmp');
    if (!cjmpStmt || cjmpStmt.op !== 'cjmp') continue;

    // Collect transforms for the tainted var
    const chain = transforms.filter(t => t.dest === cmp.taintedVar ||
      cmp.taintedExpr.includes(t.dest));

    // Find the most plausible source
    const src = sources[sources.length - 1]; // last input source = most recent taint

    const constStr = cmp.constValue !== null
      ? `0x${cmp.constValue.toString(16)}`
      : '<unknown>';

    const summary = chain.length > 0
      ? `Input → ${chain.map(t => t.op).join(' → ')} → compare ${cmp.inferredOp} ${constStr}`
      : `Input compared directly: ${cmp.taintedExpr} ${cmp.inferredOp} ${constStr}`;

    const confidence = calcConfidence(cmp, chain, src);

    const smtLib2 = emitSMTLib2(cmp, chain, `key${shapeIdx}`);

    shapes.push({
      id: `keygen-shape-${shapeIdx++}`,
      source: src,
      transformChain: chain,
      comparison: cmp,
      branchAddress: cjmpStmt.address,
      summary,
      smtLib2,
      confidence,
    });
  }

  return shapes;
}

function calcConfidence(
  cmp: TaintedComparison,
  chain: TaintTransform[],
  src: TaintSource,
): number {
  let score = 55;
  if (cmp.constValue !== null) score += 15;
  if (cmp.inferredOp !== 'unknown') score += 10;
  if (chain.length >= 1) score += 10;
  if (chain.length >= 3) score += 5;
  if (src.kind === 'api-input') score += 5;
  return Math.min(score, 95);
}

// ─── Phase 3: SMT-LIB2 emission ──────────────────────────────────────────────

/**
 * Emit a minimal SMT-LIB2 string for one keygen shape.
 *
 * Only linear constraints are modelled exactly.
 * Non-linear transforms (*, /) are symbolically kept as uninterpreted
 * bitvector operations so Z3 can still attempt to solve them.
 *
 * Output declares `input` as a 64-bit bitvector, expresses the transform
 * chain as let bindings, then asserts the comparison constraint, and
 * requests a model (check-sat / get-model).
 */
export function emitSMTLib2(
  cmp: TaintedComparison,
  chain: TaintTransform[],
  inputVarName = 'input',
): string {
  if (cmp.constValue === null && cmp.inferredOp === 'unknown') return '';

  const lines: string[] = [
    `; HexHawk M6 — auto-generated constraint`,
    `; Tainted expression: ${cmp.taintedExpr}`,
    `; Comparison: ${cmp.inferredOp} 0x${(cmp.constValue ?? 0).toString(16)}`,
    `(set-logic QF_BV)`,
    `(declare-fun ${inputVarName} () (_ BitVec 64))`,
  ];

  // Build let bindings from chain
  let currentExpr = `${inputVarName}`;
  const bindings: string[] = [];

  for (let i = 0; i < chain.length; i++) {
    const t = chain[i];
    const bindName = `t${i}`;
    const rhsConst = parseIntLenient(t.rhs);
    const rhsExpr = rhsConst !== null
      ? `(_ bv${rhsConst >>> 0} 64)`
      : currentExpr; // fall back to chaining

    const smtOp = toSMTBVOp(t.op);
    if (smtOp) {
      bindings.push(`(${bindName} (${smtOp} ${currentExpr} ${rhsExpr}))`);
      currentExpr = bindName;
    }
  }

  const constBV = `(_ bv${(cmp.constValue ?? 0) >>> 0} 64)`;
  const smtCmpOp = toSMTCmpOp(cmp.inferredOp);
  const constraint = smtCmpOp
    ? `(${smtCmpOp} ${currentExpr} ${constBV})`
    : `(= ${currentExpr} ${constBV})`;  // fallback: equality

  if (bindings.length > 0) {
    lines.push(`(assert (let (`);
    for (const b of bindings) lines.push(`  ${b}`);
    lines.push(`) ${constraint}))`);
  } else {
    lines.push(`(assert ${constraint})`);
  }

  lines.push(`(check-sat)`);
  lines.push(`(get-model)`);

  return lines.join('\n');
}

function parseIntLenient(s: string): number | null {
  if (s.startsWith('0x') || s.startsWith('0X')) {
    const v = parseInt(s, 16);
    return isNaN(v) ? null : v;
  }
  const v = parseInt(s, 10);
  return isNaN(v) ? null : v;
}

function toSMTBVOp(op: string): string | null {
  switch (op) {
    case '+':   return 'bvadd';
    case '-':   return 'bvsub';
    case '*':   return 'bvmul';
    case '&':   return 'bvand';
    case '|':   return 'bvor';
    case '^':   return 'bvxor';
    case '<<':  return 'bvshl';
    case '>>':  return 'bvlshr';
    case '>>>': return 'bvlshr';
    default:    return null;
  }
}

function toSMTCmpOp(op: TaintedComparison['inferredOp']): string | null {
  switch (op) {
    case '==': return '=';
    case '!=': return null; // wrap: (not (= ...)) at call site would be needed
    case '<':  return 'bvult';
    case '<=': return 'bvule';
    case '>':  return 'bvugt';
    case '>=': return 'bvuge';
    default:   return null;
  }
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Full taint analysis + keygen shape detection over a TALON IR block list.
 */
export function runTaintAnalysis(blocks: IRBlock[]): TaintAnalysisResult {
  const { sources, tainted, comparisons, transforms, hasDownstreamSink } =
    taintPropagate(blocks);

  const shapes = detectKeygenShapes(blocks, sources, transforms, comparisons);

  return { sources, taintedVars: tainted, comparisons, shapes, hasDownstreamSink };
}
