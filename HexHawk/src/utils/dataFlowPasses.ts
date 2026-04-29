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

// ── Pass 3.5: MBA Simplification ─────────────────────────────────────────────

/**
 * Recursive expression tree used for MBA pattern matching.
 *
 * Allows multi-level pattern matching across def chains in the IR: the tree is
 * built by inlining single-def register definitions up to a configurable depth,
 * then algebraic rewrite rules are applied bottom-up.
 */
export type IRExprNode =
  | { kind: 'const'; value: number }
  | { kind: 'var';   base: string }
  | { kind: 'binop'; op: string; left: IRExprNode; right: IRExprNode }
  | { kind: 'uop';   op: string; operand: IRExprNode };

/** Maximum def-chain inlining depth. Deeper = more patterns caught at a cost
 *  of false-positives on aliased variables. 4 is sufficient for typical OLLVM
 *  and "i love mbas" style patterns which are ≤ 3 levels deep. */
const MBA_INLINE_DEPTH = 4;

/** Build a map: register name → the last IRStmt that assigns to it.
 *  Only assign/binop/uop statements are included (pure def stmts). */
function buildDefChain(blocks: IRBlock[]): Map<string, IRStmt> {
  const chain = new Map<string, IRStmt>();
  for (const block of blocks) {
    for (const stmt of block.stmts) {
      if (
        (stmt.op === 'assign' || stmt.op === 'binop' || stmt.op === 'uop') &&
        stmt.dest.kind === 'reg'
      ) {
        chain.set(stmt.dest.name, stmt);
      }
    }
  }
  return chain;
}

/**
 * Build an IRExprNode tree from an IRValue by inlining single-def register
 * chains.  Stops at `depth` 0 or when no def exists for a register (the
 * variable is opaque / comes from outside the current scope).
 */
export function buildExprTree(
  v: IRValue,
  defChain: Map<string, IRStmt>,
  depth: number = MBA_INLINE_DEPTH,
): IRExprNode {
  if (v.kind === 'const') return { kind: 'const', value: v.value };
  if (v.kind === 'reg') {
    if (depth === 0) return { kind: 'var', base: v.name };
    const def = defChain.get(v.name);
    if (!def) return { kind: 'var', base: v.name };
    switch (def.op) {
      case 'binop':
        return {
          kind: 'binop',
          op: def.operator,
          left:  buildExprTree(def.left,    defChain, depth - 1),
          right: buildExprTree(def.right,   defChain, depth - 1),
        };
      case 'uop':
        return {
          kind: 'uop',
          op: def.operator,
          operand: buildExprTree(def.operand, defChain, depth - 1),
        };
      case 'assign':
        return buildExprTree(def.src, defChain, depth - 1);
    }
  }
  // mem / expr — treat as an opaque variable
  return { kind: 'var', base: v.kind === 'reg' ? v.name : '?' };
}

// Commutative operators: matching allows either argument order
const COMMUTATIVE_OPS = new Set(['+', '*', '&', '|', '^']);

/**
 * Structural equality for expression trees.
 * Commutative binary operators accept either argument order.
 */
export function exprEqual(a: IRExprNode, b: IRExprNode): boolean {
  if (a.kind !== b.kind) return false;
  if (a.kind === 'const' && b.kind === 'const') return a.value === b.value;
  if (a.kind === 'var'   && b.kind === 'var')   return a.base === b.base;
  if (a.kind === 'uop'   && b.kind === 'uop')
    return a.op === b.op && exprEqual(a.operand, (b as typeof a).operand);
  if (a.kind === 'binop' && b.kind === 'binop') {
    if (a.op !== b.op) return false;
    const bBinop = b as typeof a;
    if (exprEqual(a.left, bBinop.left) && exprEqual(a.right, bBinop.right)) return true;
    if (COMMUTATIVE_OPS.has(a.op))
      return exprEqual(a.left, bBinop.right) && exprEqual(a.right, bBinop.left);
  }
  return false;
}

/** Return inner if e = ~(inner), else null. */
function matchNot(e: IRExprNode): IRExprNode | null {
  return e.kind === 'uop' && e.op === '~' ? e.operand : null;
}

/**
 * Apply one simplification step at the root of an expression tree.
 * Returns the simplified node if any rule matched, or null if no rule applies.
 * Does NOT recurse — call simplifyExprTree for a full bottom-up pass.
 *
 * Rules implemented:
 *   Idempotence/annihilation  x^x=0, x&x=x, x|x=x, x-x=0
 *   Complement forms          x&~x=0, ~x&x=0, x|~x=-1, x^~x=-1
 *   Double-NOT / double-neg   ~~x=x, --x=x
 *   Constant folding          ~k, -k
 *   MBA: add identity         (a|b)+(a&b) = a+b
 *   MBA: add identity         (a^b)+2*(a&b) = a+b  [2*(a&b) as <<1 or a&b+a&b]
 *   MBA: xor recovery         (a|b)-(a&b) = a^b
 *   MBA: XOR inverse          (a^b)^b = a
 *   MBA: additive inverse     (a+b)-b = a
 *   Two's complement negate   ~x+1 = -x
 *   Rotation detection        (x<<N)|(x>>>(W-N)) = ROL(x,N)
 */
function applyOneRule(e: IRExprNode): IRExprNode | null {
  // ── Unary rules ──────────────────────────────────────────────────────────
  if (e.kind === 'uop') {
    const { op, operand: inner } = e;
    if (op === '~' && inner.kind === 'uop' && inner.op === '~')
      return inner.operand;                                              // ~~x = x
    if (op === '-' && inner.kind === 'uop' && inner.op === '-')
      return inner.operand;                                              // --x = x
    if (op === '~' && inner.kind === 'const')
      return { kind: 'const', value: (~inner.value) >>> 0 };            // ~k
    if (op === '-' && inner.kind === 'const')
      return { kind: 'const', value: (-inner.value) | 0 };              // -k
    return null;
  }

  if (e.kind !== 'binop') return null;
  const { op, left: l, right: r } = e;

  // ── Idempotence & annihilation ───────────────────────────────────────────
  if (op === '^' && exprEqual(l, r)) return { kind: 'const', value: 0 };   // x^x=0
  if (op === '&' && exprEqual(l, r)) return l;                              // x&x=x
  if (op === '|' && exprEqual(l, r)) return l;                              // x|x=x
  if (op === '-' && exprEqual(l, r)) return { kind: 'const', value: 0 };   // x-x=0

  // ── Complement forms ─────────────────────────────────────────────────────
  const notL = matchNot(l), notR = matchNot(r);
  if (op === '&') {
    if (notR && exprEqual(l, notR)) return { kind: 'const', value: 0 };    // x&~x=0
    if (notL && exprEqual(notL, r)) return { kind: 'const', value: 0 };    // ~x&x=0
  }
  if (op === '|') {
    if (notR && exprEqual(l, notR)) return { kind: 'const', value: 0xffffffff }; // x|~x=-1
    if (notL && exprEqual(notL, r)) return { kind: 'const', value: 0xffffffff }; // ~x|x=-1
  }
  if (op === '^') {
    if (notR && exprEqual(l, notR)) return { kind: 'const', value: 0xffffffff }; // x^~x=-1
    if (notL && exprEqual(notL, r)) return { kind: 'const', value: 0xffffffff }; // ~x^x=-1
  }

  // ── MBA identity: (a | b) + (a & b) = a + b  ────────────────────────────
  if (op === '+' && l.kind === 'binop' && r.kind === 'binop') {
    const orSide  = l.op === '|' ? l : r.op === '|' ? r : null;
    const andSide = l.op === '&' ? l : r.op === '&' ? r : null;
    if (orSide && andSide) {
      const oL = orSide.left, oR = orSide.right;
      const aL = andSide.left, aR = andSide.right;
      if ((exprEqual(oL, aL) && exprEqual(oR, aR)) ||
          (exprEqual(oL, aR) && exprEqual(oR, aL))) {
        return { kind: 'binop', op: '+', left: oL, right: oR };
      }
    }
  }

  // ── MBA identity: (a ^ b) + 2*(a & b) = a + b  ──────────────────────────
  //   2*(a&b) appears as: (a&b)+(a&b)  or  (a&b)<<1
  const tryXorAdd = (xorSide: typeof l & { kind: 'binop' }, twoAndSide: IRExprNode) => {
    let andSide: (typeof l & { kind: 'binop' }) | null = null;
    if (twoAndSide.kind === 'binop' && twoAndSide.op === '+' &&
        exprEqual(twoAndSide.left, twoAndSide.right) &&
        twoAndSide.left.kind === 'binop' && twoAndSide.left.op === '&') {
      andSide = twoAndSide.left as typeof l & { kind: 'binop' };
    }
    if (twoAndSide.kind === 'binop' && twoAndSide.op === '<<' &&
        twoAndSide.right.kind === 'const' && twoAndSide.right.value === 1 &&
        twoAndSide.left.kind === 'binop' && twoAndSide.left.op === '&') {
      andSide = twoAndSide.left as typeof l & { kind: 'binop' };
    }
    if (!andSide) return null;
    const xL = xorSide.left, xR = xorSide.right;
    const aL = andSide.left,  aR = andSide.right;
    if ((exprEqual(xL, aL) && exprEqual(xR, aR)) ||
        (exprEqual(xL, aR) && exprEqual(xR, aL))) {
      return { kind: 'binop' as const, op: '+', left: xL, right: xR };
    }
    return null;
  };

  if (op === '+') {
    if (l.kind === 'binop' && l.op === '^') {
      const reduced = tryXorAdd(l, r);
      if (reduced) return reduced;
    }
    if (r.kind === 'binop' && r.op === '^') {
      const reduced = tryXorAdd(r, l);
      if (reduced) return reduced;
    }
  }

  // ── MBA identity: (a | b) - (a & b) = a ^ b  ────────────────────────────
  if (op === '-' && l.kind === 'binop' && r.kind === 'binop' &&
      l.op === '|' && r.op === '&') {
    const oL = l.left, oR = l.right;
    const aL = r.left, aR = r.right;
    if ((exprEqual(oL, aL) && exprEqual(oR, aR)) ||
        (exprEqual(oL, aR) && exprEqual(oR, aL))) {
      return { kind: 'binop', op: '^', left: oL, right: oR };
    }
  }

  // ── XOR inverse: (a ^ b) ^ b = a, (a ^ b) ^ a = b  ─────────────────────
  if (op === '^' && l.kind === 'binop' && l.op === '^') {
    if (exprEqual(l.right, r)) return l.left;
    if (exprEqual(l.left,  r)) return l.right;
  }

  // ── Additive inverse: (a + b) - b = a, (a + b) - a = b  ─────────────────
  if (op === '-' && l.kind === 'binop' && l.op === '+') {
    if (exprEqual(l.right, r)) return l.left;
    if (exprEqual(l.left,  r)) return l.right;
  }

  // ── Two's complement negation: ~x + 1 = -x  ─────────────────────────────
  if (op === '+' && r.kind === 'const' && r.value === 1 && notL)
    return { kind: 'uop', op: '-', operand: notL };  // ~x+1 = -x
  if (op === '+' && l.kind === 'const' && l.value === 1 && notR)
    return { kind: 'uop', op: '-', operand: notR };  // 1+~x = -x

  // ── Rotation detection: (x << N) | (x >>> (W-N))  ───────────────────────
  if (op === '|') {
    const tryRot = (
      shl: IRExprNode & { kind: 'binop' },
      shr: IRExprNode & { kind: 'binop' },
    ) => {
      if (shl.right.kind === 'const' && shr.right.kind === 'const' &&
          exprEqual(shl.left, shr.left)) {
        const s = shl.right.value, t = shr.right.value;
        if (s + t === 32) return { kind: 'binop' as const, op: 'ROL32', left: shl.left, right: shl.right };
        if (s + t === 64) return { kind: 'binop' as const, op: 'ROL64', left: shl.left, right: shl.right };
      }
      return null;
    };
    if (l.kind === 'binop' && r.kind === 'binop' && l.op === '<<' && (r.op === '>>' || r.op === '>>>')) {
      const res = tryRot(l, r);
      if (res) return res;
    }
    if (r.kind === 'binop' && l.kind === 'binop' && r.op === '<<' && (l.op === '>>' || l.op === '>>>')) {
      const res = tryRot(r, l);
      if (res) return res;
    }
  }

  return null;
}

/**
 * Bottom-up recursive simplification of an expression tree.
 * Children are simplified first, then rules are applied at the root until
 * no further reduction is possible (max 8 iterations to prevent cycles).
 */
export function simplifyExprTree(e: IRExprNode): IRExprNode {
  // Simplify children first (bottom-up)
  let result: IRExprNode;
  if (e.kind === 'binop') {
    const l = simplifyExprTree(e.left);
    const r = simplifyExprTree(e.right);
    result = { ...e, left: l, right: r };
  } else if (e.kind === 'uop') {
    result = { ...e, operand: simplifyExprTree(e.operand) };
  } else {
    result = e;
  }

  // Apply rules at root until stable
  let limit = 8;
  while (limit-- > 0) {
    const simplified = applyOneRule(result);
    if (simplified === null) break;
    result = simplifyExprTree(simplified);  // re-simplify after rule fires
  }
  return result;
}

/** Serialize an expression node to a readable string for `expr`-kind IRValues. */
function exprNodeToText(e: IRExprNode): string {
  if (e.kind === 'const') {
    const v = e.value >>> 0;            // treat as unsigned for display
    return v > 9 ? `0x${v.toString(16)}` : String(e.value);
  }
  if (e.kind === 'var')   return e.base;
  if (e.kind === 'uop')   return `${e.op}(${exprNodeToText(e.operand)})`;
  if (e.kind === 'binop') {
    const l = exprNodeToText(e.left), r = exprNodeToText(e.right);
    if (e.op === 'ROL32') return `ROL32(${l}, ${r})`;
    if (e.op === 'ROL64') return `ROL64(${l}, ${r})`;
    return `(${l} ${e.op} ${r})`;
  }
  return '?';
}

/** Convert a simplified IRExprNode back to an IRValue.
 *  Consts and vars map directly; compound expressions use the `expr` text kind. */
function exprNodeToIRValue(e: IRExprNode): IRValue {
  if (e.kind === 'const') return { kind: 'const', value: e.value };
  if (e.kind === 'var')   return { kind: 'reg', name: e.base };
  return { kind: 'expr', text: exprNodeToText(e) } as IRValue;
}

/**
 * Measure the MBA density of a single block: fraction of binary operations
 * that are bitwise (AND/OR/XOR).  A value ≥ 0.5 with at least 4 binops
 * indicates likely MBA obfuscation.
 */
export function mbaDensity(block: IRBlock): number {
  let bitwiseCount = 0;
  let binopCount   = 0;
  for (const stmt of block.stmts) {
    if (stmt.op === 'binop') {
      binopCount++;
      if (stmt.operator === '&' || stmt.operator === '|' || stmt.operator === '^') {
        bitwiseCount++;
      }
    }
  }
  return binopCount > 0 ? bitwiseCount / binopCount : 0;
}

/**
 * Pass 4: MBA Simplification.
 *
 * Scans all binop statements whose expression tree (inlined to
 * MBA_INLINE_DEPTH) matches a known Mixed Boolean-Arithmetic identity and
 * records the reduced form in the simplified environment.
 *
 * Patterns handled: (a|b)+(a&b)→a+b, (a^b)+2*(a&b)→a+b,
 * (a|b)-(a&b)→a^b, (a^b)^b→a, (a+b)-b→a, ~x+1→-x, ROL detection,
 * tautologies (x^x, x&~x, x^~x, ~~x, etc.)
 *
 * Works on the IRValue level — does NOT rewrite IRStmt objects in place.
 * The resulting environment is layered on top of the copy-propagation env.
 */
export function mbaSimplify(blocks: IRBlock[], baseEnv: SimplifiedEnv): SimplifiedEnv {
  const env: SimplifiedEnv = new Map(baseEnv);
  const defChain = buildDefChain(blocks);

  for (const block of blocks) {
    for (const stmt of block.stmts) {
      if (stmt.op !== 'binop' || stmt.dest.kind !== 'reg') continue;
      const destName = stmt.dest.name;

      // Skip if already resolved to a concrete constant by earlier passes
      if (env.get(destName)?.kind === 'const') continue;

      // Build expression tree by inlining the full RHS
      const lTree = buildExprTree(stmt.left,  defChain, MBA_INLINE_DEPTH);
      const rTree = buildExprTree(stmt.right, defChain, MBA_INLINE_DEPTH);
      const rhsTree: IRExprNode = { kind: 'binop', op: stmt.operator, left: lTree, right: rTree };

      const simplified = simplifyExprTree(rhsTree);

      // Only update env if the tree changed in a meaningful way
      if (!exprEqual(simplified, rhsTree)) {
        env.set(destName, exprNodeToIRValue(simplified));
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
  /** Number of MBA expressions reduced by Pass 4. */
  mbaSimplifiedCount: number;
}

/**
 * Run all three passes in sequence and return a combined result.
 * This is the main entry point called by talonEngine.
 */
export function runDataFlowPasses(blocks: IRBlock[], ssaForm: SSAForm): DataFlowResult {
  const foldEnv = constantFold(blocks);
  const foldedCount = foldEnv.size;

  const copyEnv = copyPropagate(blocks, foldEnv);
  const copiesEliminated = Math.max(0, copyEnv.size - foldedCount);

  // Pass 4: MBA simplification — layered on top of copy-propagation result
  const mbaEnv = mbaSimplify(blocks, copyEnv);
  const mbaSimplifiedCount = Math.max(0, mbaEnv.size - copyEnv.size);

  const deadDefReport = analyzeDeadDefs(blocks, ssaForm);

  return {
    env: mbaEnv,
    deadDefReport,
    foldedCount,
    copiesEliminated,
    mbaSimplifiedCount,
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
