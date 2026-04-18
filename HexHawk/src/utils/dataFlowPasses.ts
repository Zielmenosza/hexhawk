/**
 * dataFlowPasses — SSA-Based Optimization Passes for TALON
 *
 * Three lightweight passes that improve pseudo-code quality:
 *
 *   1. constantFold   — evaluate `const OP const` at compile time;
 *                       propagate known-constant SSA variables
 *   2. copyPropagate  — when a def is `x = y` (identity copy), replace
 *                       downstream uses of x with y
 *   3. deadDefElim    — remove SSA defs that are never used
 *
 * These passes work on the IRValue level, producing a simplified environment
 * (Map<varBase, IRValue>) rather than rewriting IRStmt objects in place.
 * The simplified env is consumed by talonEngine to emit cleaner pseudo-code.
 *
 * Usage:
 *   const env = buildSimplifiedEnv(irBlocks, ssaForm);
 *   const simplified = simplifyValue(someIRValue, env);
 */

import type { IRBlock, IRStmt, IRValue } from './decompilerEngine';
import type { SSAForm } from './ssaTransform';

// ── Simplified Value Environment ──────────────────────────────────────────────

/**
 * Maps a varBase (e.g. "rax") to its simplified IRValue.
 * Built by the data-flow passes; used at emission time.
 */
export type SimplifiedEnv = Map<string, IRValue>;

// ── IRValue arithmetic helpers ────────────────────────────────────────────────

function isConst(v: IRValue): v is { kind: 'const'; value: number } {
  return v.kind === 'const';
}

function applyBinOp(op: string, l: number, r: number): number | null {
  switch (op) {
    case '+': return l + r;
    case '-': return l - r;
    case '*': return l * r;
    case '/': return r !== 0 ? Math.trunc(l / r) : null;
    case '%': return r !== 0 ? l % r : null;
    case '&': return (l & r) >>> 0;
    case '|': return (l | r) >>> 0;
    case '^': return (l ^ r) >>> 0;
    case '<<': return (l << (r & 31)) >>> 0;
    case '>>': return (l >>> (r & 31));
    case '>>>': return (l >>> (r & 31));
    default: return null;
  }
}

function applyUnOp(op: string, v: number): number | null {
  switch (op) {
    case '~': return (~v) >>> 0;
    case '-': return (-v);
    case '!': return v === 0 ? 1 : 0;
    default: return null;
  }
}

/** Simplify one IRValue given a known-value environment. */
export function simplifyValue(v: IRValue, env: SimplifiedEnv): IRValue {
  if (v.kind === 'reg') {
    const known = env.get(v.name);
    if (known) return known;
    return v;
  }
  if (v.kind === 'const') return v;
  if (v.kind === 'mem') {
    // Try to simplify base register
    const knownBase = env.get(v.base);
    if (knownBase && knownBase.kind === 'const') {
      // base is a known constant; don't simplify mem — would need alias analysis
    }
    return v;
  }
  return v;
}

// ── Pass 1: Constant Folding ──────────────────────────────────────────────────

/**
 * Scan all blocks for assignments of the form:
 *   dest = const OP const   (binop)
 *   dest = OP const         (uop)
 *   dest = const            (assign from literal)
 *   dest = reg              where reg is already const in env
 *
 * Returns an environment mapping varBase → simplified IRValue.
 */
export function constantFold(blocks: IRBlock[]): SimplifiedEnv {
  const env: SimplifiedEnv = new Map();

  // Multiple passes until stable (handles propagation chains)
  let changed = true;
  let maxPasses = 10;
  while (changed && maxPasses-- > 0) {
    changed = false;
    for (const block of blocks) {
      for (const stmt of block.stmts) {
        if (stmt.op === 'assign') {
          const src = simplifyValue(stmt.src, env);
          if (isConst(src) && stmt.dest.kind === 'reg') {
            if (env.get(stmt.dest.name)?.kind !== 'const' ||
                (env.get(stmt.dest.name) as { kind: 'const'; value: number }).value !== src.value) {
              env.set(stmt.dest.name, src);
              changed = true;
            }
          }
        } else if (stmt.op === 'binop') {
          const l = simplifyValue(stmt.left, env);
          const r = simplifyValue(stmt.right, env);
          if (isConst(l) && isConst(r)) {
            const result = applyBinOp(stmt.operator, l.value, r.value);
            if (result !== null && stmt.dest.kind === 'reg') {
              const newVal: IRValue = { kind: 'const', value: result };
              if (env.get(stmt.dest.name)?.kind !== 'const' ||
                  (env.get(stmt.dest.name) as { kind: 'const'; value: number }).value !== result) {
                env.set(stmt.dest.name, newVal);
                changed = true;
              }
            }
          }
          // Identity simplifications (even if not fully const)
          if (isConst(r)) {
            if ((stmt.operator === '+' || stmt.operator === '-' || stmt.operator === '|') && r.value === 0) {
              // x +/- 0 = x, x | 0 = x
              if (stmt.dest.kind === 'reg') {
                const simplified = simplifyValue(stmt.left, env);
                if (!env.has(stmt.dest.name)) {
                  env.set(stmt.dest.name, simplified);
                  changed = true;
                }
              }
            }
            if ((stmt.operator === '*' || stmt.operator === '&') && r.value === 0) {
              // x * 0 = 0, x & 0 = 0
              if (stmt.dest.kind === 'reg') {
                env.set(stmt.dest.name, { kind: 'const', value: 0 });
                changed = true;
              }
            }
            if (stmt.operator === '*' && r.value === 1) {
              // x * 1 = x
              if (stmt.dest.kind === 'reg') {
                const simplified = simplifyValue(stmt.left, env);
                if (!env.has(stmt.dest.name)) {
                  env.set(stmt.dest.name, simplified);
                  changed = true;
                }
              }
            }
            if (stmt.operator === '^' && isConst(r) && r.value === 0) {
              // x ^ 0 = x
              if (stmt.dest.kind === 'reg') {
                const simplified = simplifyValue(stmt.left, env);
                if (!env.has(stmt.dest.name)) {
                  env.set(stmt.dest.name, simplified);
                  changed = true;
                }
              }
            }
          }
          if (isConst(l) && l.value === 0 && stmt.operator === '+') {
            // 0 + x = x
            if (stmt.dest.kind === 'reg') {
              const simplified = simplifyValue(stmt.right, env);
              if (!env.has(stmt.dest.name)) {
                env.set(stmt.dest.name, simplified);
                changed = true;
              }
            }
          }
        } else if (stmt.op === 'uop') {
          const operand = simplifyValue(stmt.operand, env);
          if (isConst(operand)) {
            const result = applyUnOp(stmt.operator, operand.value);
            if (result !== null && stmt.dest.kind === 'reg') {
              const newVal: IRValue = { kind: 'const', value: result };
              env.set(stmt.dest.name, newVal);
              changed = true;
            }
          }
        }
      }
    }
  }

  return env;
}

// ── Pass 2: Copy Propagation ──────────────────────────────────────────────────

/**
 * Find all plain copy assignments (dest_reg = src_reg) and add them to env.
 * Layered on top of constantFold result — builds a unified simplified env.
 */
export function copyPropagate(blocks: IRBlock[], baseEnv: SimplifiedEnv): SimplifiedEnv {
  const env: SimplifiedEnv = new Map(baseEnv);

  let changed = true;
  let maxPasses = 10;
  while (changed && maxPasses-- > 0) {
    changed = false;
    for (const block of blocks) {
      for (const stmt of block.stmts) {
        if (stmt.op === 'assign' && stmt.dest.kind === 'reg' && stmt.src.kind === 'reg') {
          // dest = src (register copy)
          // If src has a known simplified value, propagate it to dest
          const srcSimplified = simplifyValue(stmt.src, env);
          const current = env.get(stmt.dest.name);
          if (current === undefined || current.kind === 'reg') {
            // Propagate: set dest to the simplified value of src
            if (!current || current.name !== (srcSimplified.kind === 'reg' ? srcSimplified.name : '')) {
              env.set(stmt.dest.name, srcSimplified);
              changed = true;
            }
          }
        }
      }
    }
  }

  return env;
}

// ── Pass 3: Dead Definition Analysis ─────────────────────────────────────────

export interface DeadDefReport {
  /** SSA var keys (blockId:address:varBase) that are defined but never used. */
  deadDefs: string[];
  /** Number of dead definitions found. */
  count: number;
}

/**
 * Identify SSA definitions that are never used anywhere.
 * Returns a report; does not modify the IR (it's the caller's job to
 * suppress these from pseudo-code emission if desired).
 */
export function analyzeDeadDefs(blocks: IRBlock[], ssaForm: SSAForm): DeadDefReport {
  // Collect all used SSA var keys
  const usedKeys = new Set<string>();
  for (const key of ssaForm.uses.keys()) usedKeys.add(key);

  // Also treat phi operands as uses
  for (const [, phis] of ssaForm.phis) {
    for (const phi of phis) {
      for (const op of phi.operands) {
        // operand is a use — mark the def that produced it as live
        // We approximate by marking any def with the same base+version as live
        for (const [k, v] of ssaForm.defs) {
          if (v.base === op.base && v.version === op.version) {
            usedKeys.add(k);
          }
        }
      }
    }
  }

  const deadDefs: string[] = [];
  for (const [key] of ssaForm.defs) {
    if (!usedKeys.has(key)) {
      deadDefs.push(key);
    }
  }

  return { deadDefs, count: deadDefs.length };
}

// ── Combined pass driver ──────────────────────────────────────────────────────

export interface DataFlowResult {
  /** Final simplified environment for use during pseudo-code emission. */
  env: SimplifiedEnv;
  /** Dead definition analysis report (informational). */
  deadDefReport: DeadDefReport;
  /** Number of constants folded (including propagated). */
  foldedCount: number;
  /** Number of copy assignments simplified. */
  copiesEliminated: number;
}

/**
 * Run all three passes in sequence and return a combined result.
 * This is the main entry point called by talonEngine.
 */
export function runDataFlowPasses(blocks: IRBlock[], ssaForm: SSAForm): DataFlowResult {
  const foldEnv = constantFold(blocks);
  const foldedCount = foldEnv.size;

  const fullEnv = copyPropagate(blocks, foldEnv);
  const copiesEliminated = fullEnv.size - foldedCount;

  const deadDefReport = analyzeDeadDefs(blocks, ssaForm);

  return {
    env: fullEnv,
    deadDefReport,
    foldedCount,
    copiesEliminated: Math.max(0, copiesEliminated),
  };
}

// ── Emission helper ───────────────────────────────────────────────────────────

/**
 * Given an IRValue and the simplified environment, return a cleaner string
 * representation for pseudo-code emission.
 *
 * Examples:
 *   { kind: 'reg', name: 'rax' } + env{ rax → const 42 }  →  "42"
 *   { kind: 'reg', name: 'rdi' }  (no env entry)           →  "rdi"
 *   { kind: 'const', value: 0 }                            →  "0"
 */
export function emitValue(v: IRValue, env: SimplifiedEnv): string {
  const simplified = simplifyValue(v, env);
  if (simplified.kind === 'const') {
    const n = simplified.value;
    // Show as hex if large or likely an address/flag
    if (n > 9 || n < -9) {
      return n < 0 ? `-0x${(-n).toString(16)}` : `0x${n.toString(16)}`;
    }
    return String(n);
  }
  if (simplified.kind === 'reg') return simplified.name;
  if (simplified.kind === 'mem') {
    const parts: string[] = [simplified.base];
    if (simplified.index) parts.push(`${simplified.index}*${simplified.scale ?? 1}`);
    if (simplified.offset !== 0) {
      parts.push(simplified.offset > 0 ? `+${simplified.offset}` : String(simplified.offset));
    }
    return `[${parts.join('')}]`;
  }
  if (simplified.kind === 'expr') return simplified.text;
  return '';
}
