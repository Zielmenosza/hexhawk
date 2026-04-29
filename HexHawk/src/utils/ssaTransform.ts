/**
 * ssaTransform — Static Single Assignment (SSA) Construction
 *
 * Converts an IRBlock[] (from decompilerEngine) into SSA form:
 *   1. Compute immediate dominators  (Cooper et al. iterative algorithm)
 *   2. Compute dominance frontiers   (Cytron et al.)
 *   3. Insert phi nodes at join points
 *   4. Rename variables              (DFS over dominator tree)
 *
 * Tracked variables: general-purpose x86-64 registers + simple stack slots.
 * Complex memory operands (heap, indirect) are not renamed — they fall through
 * as-is and cannot be safely disambiguated without alias analysis.
 *
 * The SSA form is a *separate* data structure — original IRBlock objects are
 * never mutated.  Call destroySSA() to obtain a map for code emission.
 */

import type { IRBlock, IRStmt, IRValue } from './decompilerEngine';

// ── SSA Variable ──────────────────────────────────────────────────────────────

/** An SSA-versioned variable (one static def per name). */
export interface SSAVar {
  base: string;     // original name: "rax", "rbp-8", etc.
  version: number;  // SSA version counter (starts at 0)
  /** Canonical SSA name for display: "rax₀", "rax₁", … */
  ssaName: string;
}

/** Phi node: dest = φ(op₀, op₁, …) — one operand per predecessor block. */
export interface PhiNode {
  dest: SSAVar;
  /** Operands in the same order as IRBlock.allSuccessors of the predecessor side.
   *  Indexed by the position in block.predecessors array. */
  operands: SSAVar[];
  blockId: string;
  address: number;  // block start address (for display)
}

// ── Dominator Tree ────────────────────────────────────────────────────────────

export interface DomTree {
  /** blockId → immediate dominator blockId (null for entry). */
  idom: Map<string, string | null>;
  /** blockId → list of directly dominated children. */
  children: Map<string, string[]>;
  /** Dominance frontier: blockId → set of blockIds. */
  df: Map<string, Set<string>>;
  /** Reverse post-order list of block IDs. */
  rpo: string[];
}

// ── SSA Form (output) ─────────────────────────────────────────────────────────

export interface SSAForm {
  /** Phi nodes per block. Empty array if none. */
  phis: Map<string, PhiNode[]>;
  /**
   * Maps a (blockId, address, varBase) triple → SSAVar for each definition.
   * Key: `${blockId}:${address}:${varBase}`
   */
  defs: Map<string, SSAVar>;
  /**
   * Maps a (blockId, address, varBase) triple → SSAVar for each use.
   * Key: `${blockId}:${address}:${varBase}`
   */
  uses: Map<string, SSAVar>;
  /** Dominator tree for downstream consumers (loop analysis). */
  domTree: DomTree;
  /** Total number of SSA variables created. */
  varCount: number;
  /** Whether SSA construction succeeded (false on degenerate CFGs). */
  ok: boolean;
}

// ── Tracked variable set ──────────────────────────────────────────────────────

const GP_REGS = new Set([
  'rax','rbx','rcx','rdx','rsi','rdi','rbp','rsp',
  'r8','r9','r10','r11','r12','r13','r14','r15',
  'eax','ebx','ecx','edx','esi','edi','ebp','esp',
  'r8d','r9d','r10d','r11d','r12d','r13d','r14d','r15d',
  'ax','bx','cx','dx','si','di','bp','sp',
  'al','bl','cl','dl','sil','dil','bpl','spl',
  'ah','bh','ch','dh',
]);

/**
 * Normalize x86-64 sub-register names to their 64-bit canonical form.
 *
 * In x86-64, writing eax zero-extends to rax, and reading al reads from rax.
 * Tracking sub-registers as separate SSA variables produces phantom defs/uses
 * that break copy-propagation and MBA pattern matching (e.g., a `mov eax, 0`
 * followed by `test al, al` appears as two unrelated variables instead of one).
 *
 * Note: ah/bh/ch/dh write bits 8–15 only; we map them to the full 64-bit
 * register for simplicity — the loss of precision is acceptable for the
 * decompiler's pattern-matching purposes.
 */
const ALIAS_TO_64: Readonly<Record<string, string>> = {
  // 32-bit zero-extending forms
  eax: 'rax', ebx: 'rbx', ecx: 'rcx', edx: 'rdx',
  esi: 'rsi', edi: 'rdi', ebp: 'rbp', esp: 'rsp',
  r8d: 'r8',  r9d: 'r9',  r10d: 'r10', r11d: 'r11',
  r12d: 'r12', r13d: 'r13', r14d: 'r14', r15d: 'r15',
  // 16-bit partial forms
  ax: 'rax', bx: 'rbx', cx: 'rcx', dx: 'rdx',
  si: 'rsi', di: 'rdi', bp: 'rbp', sp: 'rsp',
  r8w: 'r8',  r9w: 'r9',  r10w: 'r10', r11w: 'r11',
  r12w: 'r12', r13w: 'r13', r14w: 'r14', r15w: 'r15',
  // 8-bit low forms
  al: 'rax', bl: 'rbx', cl: 'rcx', dl: 'rdx',
  sil: 'rsi', dil: 'rdi', bpl: 'rbp', spl: 'rsp',
  r8b: 'r8',  r9b: 'r9',  r10b: 'r10', r11b: 'r11',
  r12b: 'r12', r13b: 'r13', r14b: 'r14', r15b: 'r15',
  // 8-bit high forms (bits 8–15 only; mapped conservatively to full reg)
  ah: 'rax', bh: 'rbx', ch: 'rcx', dh: 'rdx',
};

/** Extract variable base name from an IRValue if it is trackable.
 *  Sub-register names (eax, al, …) are normalized to their 64-bit root. */
function varKey(v: IRValue): string | null {
  if (v.kind === 'reg') {
    // Normalize sub-register → canonical 64-bit name first
    const canonical = ALIAS_TO_64[v.name] ?? (GP_REGS.has(v.name) ? v.name : null);
    return canonical;
  }
  if (v.kind === 'mem' && (v.base === 'rbp' || v.base === 'rsp') &&
      v.index === undefined && typeof v.offset === 'number') {
    // Simple stack slot: "rbp-8", "rbp+16", etc.
    const sign = v.offset >= 0 ? '+' : '';
    return `${v.base}${sign}${v.offset}`;
  }
  return null;
}

/** Collect all variable keys defined by a statement (LHS of assignment). */
function stmtDefs(stmt: IRStmt): string[] {
  switch (stmt.op) {
    case 'assign':
    case 'binop':
    case 'uop': {
      const k = varKey(stmt.dest);
      return k ? [k] : [];
    }
    case 'pop': {
      const k = varKey(stmt.dest);
      return k ? [k] : [];
    }
    default:
      return [];
  }
}

/** Collect all variable keys *used* by a statement (RHS / operands). */
function stmtUses(stmt: IRStmt): string[] {
  const result: string[] = [];
  function addVal(v: IRValue): void {
    const k = varKey(v);
    if (k) result.push(k);
  }
  switch (stmt.op) {
    case 'assign':  addVal(stmt.src);  break;
    case 'binop':   addVal(stmt.left); addVal(stmt.right); break;
    case 'uop':     addVal(stmt.operand); break;
    case 'cmp':
    case 'test':    addVal(stmt.left); addVal(stmt.right); break;
    case 'push':    addVal(stmt.value); break;
    default: break;
  }
  return result;
}

// ── RPO ordering ──────────────────────────────────────────────────────────────

function computeRPO(blocks: IRBlock[], entryId: string): string[] {
  const visited = new Set<string>();
  const blockMap = new Map<string, IRBlock>(blocks.map(b => [b.id, b]));
  const postOrder: string[] = [];

  function dfs(id: string): void {
    if (visited.has(id)) return;
    visited.add(id);
    const block = blockMap.get(id);
    if (block) {
      for (const succ of block.allSuccessors) dfs(succ);
    }
    postOrder.push(id);
  }

  dfs(entryId);
  return postOrder.reverse();
}

// ── Dominator computation (Cooper et al.) ─────────────────────────────────────

function computeDominators(blocks: IRBlock[], entryId: string): Map<string, string | null> {
  const rpo = computeRPO(blocks, entryId);
  const rpoIndex = new Map<string, number>(rpo.map((id, i) => [id, i]));
  const idom = new Map<string, string | null>();

  // Build predecessor map
  const preds = new Map<string, string[]>();
  for (const b of blocks) preds.set(b.id, []);
  for (const b of blocks) {
    for (const succ of b.allSuccessors) {
      preds.get(succ)?.push(b.id);
    }
  }

  // Initialize
  idom.set(entryId, null);  // entry has no dominator
  for (const id of rpo) {
    if (id !== entryId) idom.set(id, undefined as unknown as string | null);
  }

  function intersect(b1: string, b2: string): string {
    let finger1 = b1;
    let finger2 = b2;
    while (finger1 !== finger2) {
      while ((rpoIndex.get(finger1) ?? 0) > (rpoIndex.get(finger2) ?? 0)) {
        finger1 = idom.get(finger1) as string;
      }
      while ((rpoIndex.get(finger2) ?? 0) > (rpoIndex.get(finger1) ?? 0)) {
        finger2 = idom.get(finger2) as string;
      }
    }
    return finger1;
  }

  let changed = true;
  while (changed) {
    changed = false;
    for (const b of rpo) {
      if (b === entryId) continue;
      const bPreds = (preds.get(b) ?? []).filter(p => idom.has(p) && idom.get(p) !== undefined);
      if (bPreds.length === 0) continue;

      let newIdom = bPreds[0];
      for (let i = 1; i < bPreds.length; i++) {
        const p = bPreds[i];
        if (idom.get(p) !== undefined) {
          newIdom = intersect(newIdom, p);
        }
      }

      if (idom.get(b) !== newIdom) {
        idom.set(b, newIdom);
        changed = true;
      }
    }
  }

  return idom;
}

// ── Dominance frontier ────────────────────────────────────────────────────────

function computeDominanceFrontier(
  blocks: IRBlock[],
  idom: Map<string, string | null>
): Map<string, Set<string>> {
  const df = new Map<string, Set<string>>();
  for (const b of blocks) df.set(b.id, new Set());

  // Predecessor map
  const preds = new Map<string, string[]>();
  for (const b of blocks) preds.set(b.id, []);
  for (const b of blocks) {
    for (const succ of b.allSuccessors) {
      preds.get(succ)?.push(b.id);
    }
  }

  for (const b of blocks) {
    const bp = preds.get(b.id) ?? [];
    if (bp.length < 2) continue;  // not a join point
    for (const p of bp) {
      let runner: string | null = p;
      while (runner !== null && runner !== idom.get(b.id)) {
        df.get(runner)?.add(b.id);
        runner = idom.get(runner) ?? null;
      }
    }
  }

  return df;
}

// ── Phi node insertion ────────────────────────────────────────────────────────

function insertPhiNodes(
  blocks: IRBlock[],
  df: Map<string, Set<string>>,
  blockDefs: Map<string, Set<string>>
): Map<string, Set<string>> {
  // phisNeeded[blockId] = set of variables needing phi in that block
  const phisNeeded = new Map<string, Set<string>>();
  for (const b of blocks) phisNeeded.set(b.id, new Set());

  // Collect all variables across all blocks
  const allVars = new Set<string>();
  for (const [, defs] of blockDefs) {
    for (const v of defs) allVars.add(v);
  }

  for (const variable of allVars) {
    const worklist: string[] = [];
    const everOnWorklist = new Set<string>();
    const alreadyHasPhi = new Set<string>();

    // Seed worklist with all blocks that define this variable
    for (const b of blocks) {
      if (blockDefs.get(b.id)?.has(variable)) {
        worklist.push(b.id);
        everOnWorklist.add(b.id);
      }
    }

    while (worklist.length > 0) {
      const b = worklist.pop()!;
      for (const y of df.get(b) ?? []) {
        if (!alreadyHasPhi.has(y)) {
          phisNeeded.get(y)?.add(variable);
          alreadyHasPhi.add(y);
          if (!everOnWorklist.has(y)) {
            everOnWorklist.add(y);
            worklist.push(y);
          }
        }
      }
    }
  }

  return phisNeeded;
}

// ── Variable renaming ─────────────────────────────────────────────────────────

function subscript(n: number): string {
  const digits = '₀₁₂₃₄₅₆₇₈₉';
  return String(n)
    .split('')
    .map(d => digits[parseInt(d)] ?? d)
    .join('');
}

function makeSSAVar(base: string, version: number): SSAVar {
  return { base, version, ssaName: `${base}${subscript(version)}` };
}

function buildDomChildren(idom: Map<string, string | null>): Map<string, string[]> {
  const children = new Map<string, string[]>();
  for (const [b, dom] of idom) {
    if (!children.has(b)) children.set(b, []);
    if (dom !== null && dom !== undefined) {
      if (!children.has(dom)) children.set(dom, []);
      children.get(dom)!.push(b);
    }
  }
  return children;
}

interface RenameContext {
  counters: Map<string, number>;
  stacks: Map<string, SSAVar[]>;
  phis: Map<string, PhiNode[]>;
  phisNeeded: Map<string, Set<string>>;
  domChildren: Map<string, string[]>;
  blockMap: Map<string, IRBlock>;
  defs: Map<string, SSAVar>;
  uses: Map<string, SSAVar>;
  varCount: { n: number };
}

function pushVersion(base: string, ctx: RenameContext, blockId: string, address: number): SSAVar {
  const version = ctx.counters.get(base) ?? 0;
  ctx.counters.set(base, version + 1);
  const v = makeSSAVar(base, version);
  const stack = ctx.stacks.get(base) ?? [];
  stack.push(v);
  ctx.stacks.set(base, stack);
  ctx.defs.set(`${blockId}:${address}:${base}`, v);
  ctx.varCount.n++;
  return v;
}

function currentVersion(base: string, ctx: RenameContext): SSAVar {
  const stack = ctx.stacks.get(base);
  if (!stack || stack.length === 0) {
    // Variable used before any definition — create a version 0 implicitly
    const v = makeSSAVar(base, 0);
    ctx.stacks.set(base, [v]);
    ctx.counters.set(base, 1);
    ctx.varCount.n++;
    return v;
  }
  return stack[stack.length - 1];
}

function renameBlock(blockId: string, ctx: RenameContext): void {
  const block = ctx.blockMap.get(blockId);
  if (!block) return;

  // Track how many pushes we made so we can pop them after dominator-tree DFS
  const pushed = new Map<string, number>();

  function trackPush(base: string): void {
    pushed.set(base, (pushed.get(base) ?? 0) + 1);
  }

  // 1. Handle phi node dests in this block
  const blockPhis = ctx.phis.get(blockId) ?? [];
  for (const phi of blockPhis) {
    const v = pushVersion(phi.dest.base, ctx, blockId, block.start);
    phi.dest = v;
    trackPush(phi.dest.base);
  }

  // 2. Rename each statement
  for (const stmt of block.stmts) {
    // First rename uses (before pushing new defs)
    for (const base of stmtUses(stmt)) {
      const v = currentVersion(base, ctx);
      ctx.uses.set(`${blockId}:${stmt.address}:${base}`, v);
    }
    // Then rename defs
    for (const base of stmtDefs(stmt)) {
      const v = pushVersion(base, ctx, blockId, stmt.address);
      trackPush(v.base);
    }
  }

  // 3. Fill phi operands in successors
  for (const succId of block.allSuccessors) {
    const succPhis = ctx.phis.get(succId) ?? [];
    const succBlock = ctx.blockMap.get(succId);
    if (!succBlock) continue;

    // Find predecessor index (position of blockId in succBlock's pred list)
    for (const phi of succPhis) {
      const v = currentVersion(phi.dest.base, ctx);
      // Just push; we'll compact duplicates later
      phi.operands.push(v);
    }
  }

  // 4. Recurse into dominated children
  for (const child of ctx.domChildren.get(blockId) ?? []) {
    renameBlock(child, ctx);
  }

  // 5. Pop all versions we pushed
  for (const [base, count] of pushed) {
    const stack = ctx.stacks.get(base) ?? [];
    stack.splice(stack.length - count, count);
    ctx.stacks.set(base, stack);
  }
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Build SSA form for the given IR blocks.
 * Blocks must all belong to a single function.
 * Entry block is identified by block_type === 'entry', or blocks[0].
 */
export function buildSSAForm(irBlocks: IRBlock[]): SSAForm {
  const empty: SSAForm = {
    phis: new Map(), defs: new Map(), uses: new Map(),
    domTree: { idom: new Map(), children: new Map(), df: new Map(), rpo: [] },
    varCount: 0, ok: false,
  };

  if (irBlocks.length === 0) return empty;

  const entryBlock = irBlocks.find(b => b.blockType === 'entry') ?? irBlocks[0];
  const entryId = entryBlock.id;

  // Compute RPO, dominators, dominance frontier
  const rpo = computeRPO(irBlocks, entryId);
  const idom = computeDominators(irBlocks, entryId);
  const df = computeDominanceFrontier(irBlocks, idom);
  const domChildren = buildDomChildren(idom);

  // Collect defined variables per block
  const blockDefs = new Map<string, Set<string>>();
  for (const b of irBlocks) {
    const defs = new Set<string>();
    for (const stmt of b.stmts) {
      for (const v of stmtDefs(stmt)) defs.add(v);
    }
    blockDefs.set(b.id, defs);
  }

  // Insert phi nodes
  const phisNeeded = insertPhiNodes(irBlocks, df, blockDefs);

  // Initialize phi node objects (operands filled during rename pass)
  const phis = new Map<string, PhiNode[]>();
  const blockMap = new Map<string, IRBlock>(irBlocks.map(b => [b.id, b]));
  for (const [blockId, vars] of phisNeeded) {
    const block = blockMap.get(blockId);
    if (!block) continue;
    const blockPhiList: PhiNode[] = [];
    for (const base of vars) {
      blockPhiList.push({
        dest: makeSSAVar(base, 0),  // will be replaced during rename
        operands: [],
        blockId,
        address: block.start,
      });
    }
    phis.set(blockId, blockPhiList);
  }

  // Rename pass
  const ctx: RenameContext = {
    counters: new Map(),
    stacks: new Map(),
    phis,
    phisNeeded,
    domChildren,
    blockMap,
    defs: new Map(),
    uses: new Map(),
    varCount: { n: 0 },
  };

  try {
    renameBlock(entryId, ctx);
  } catch {
    // Malformed CFG — return partial result
    return {
      phis, defs: ctx.defs, uses: ctx.uses,
      domTree: { idom, children: domChildren, df, rpo },
      varCount: ctx.varCount.n, ok: false,
    };
  }

  return {
    phis,
    defs: ctx.defs,
    uses: ctx.uses,
    domTree: { idom, children: domChildren, df, rpo },
    varCount: ctx.varCount.n,
    ok: true,
  };
}

// ── Utility: get the SSA name for a variable use at a given address ───────────

export function getSSAUseName(
  ssaForm: SSAForm,
  blockId: string,
  address: number,
  varBase: string
): string | null {
  return ssaForm.uses.get(`${blockId}:${address}:${varBase}`)?.ssaName ?? null;
}

export function getSSADefName(
  ssaForm: SSAForm,
  blockId: string,
  address: number,
  varBase: string
): string | null {
  return ssaForm.defs.get(`${blockId}:${address}:${varBase}`)?.ssaName ?? null;
}

/**
 * Return a display-friendly list of all phi nodes across all blocks.
 * Useful for rendering in TalonView's SSA panel.
 */
export function listPhiNodes(ssaForm: SSAForm): PhiNode[] {
  const result: PhiNode[] = [];
  for (const [, phis] of ssaForm.phis) {
    for (const phi of phis) result.push(phi);
  }
  return result;
}

/**
 * Count how many unique SSA variables were created per base register.
 * Returns a sorted list (most versions first) for display.
 */
export function ssaVersionStats(ssaForm: SSAForm): Array<{ base: string; versions: number }> {
  const maxVersion = new Map<string, number>();
  for (const v of ssaForm.defs.values()) {
    maxVersion.set(v.base, Math.max(maxVersion.get(v.base) ?? 0, v.version + 1));
  }
  return Array.from(maxVersion.entries())
    .map(([base, versions]) => ({ base, versions }))
    .sort((a, b) => b.versions - a.versions);
}

// ── Post-Dominator Tree ───────────────────────────────────────────────────────

/**
 * Compute the post-dominator tree for a set of IR blocks.
 *
 * A node X post-dominates node Y if every path from Y to any exit node passes
 * through X. This is the dual of the forward dominator tree and is computed by:
 *   1. Reversing all CFG edges.
 *   2. Adding a virtual super-exit node that has edges from every true exit block.
 *   3. Running the same Cooper et al. iterative algorithm used for forward doms.
 *
 * @param blocks   All IR blocks in the function.
 * @param exitIds  Block IDs considered function exits (blocks containing `ret`).
 *                 If empty, blocks with no successors are treated as exits.
 * @returns A DomTree in post-dominator form (idom = immediate post-dominator).
 */
export function computePostDominators(blocks: IRBlock[], exitIds?: string[]): DomTree {
  if (blocks.length === 0) {
    return { idom: new Map(), children: new Map(), df: new Map(), rpo: [] };
  }

  // Determine exit blocks
  let exits: string[];
  if (exitIds && exitIds.length > 0) {
    exits = exitIds;
  } else {
    // Blocks with no successors are exits
    exits = blocks
      .filter(b => b.allSuccessors.length === 0 ||
                   b.stmts.some(s => s.op === 'ret'))
      .map(b => b.id);
    if (exits.length === 0) exits = [blocks[blocks.length - 1].id];
  }

  // Virtual super-exit node
  const SUPER_EXIT = '__post_dom_exit__';

  // Build reversed blocks: edges go from successors to predecessors
  // Plus virtual edges: SUPER_EXIT → each exit block (reversed: exits → SUPER_EXIT)
  const reverseSuccMap = new Map<string, string[]>();
  reverseSuccMap.set(SUPER_EXIT, []);

  for (const b of blocks) {
    if (!reverseSuccMap.has(b.id)) reverseSuccMap.set(b.id, []);
  }

  // In the reversed CFG, each original edge (A→B) becomes (B→A)
  for (const b of blocks) {
    for (const succ of b.allSuccessors) {
      const entry = reverseSuccMap.get(succ) ?? [];
      entry.push(b.id);
      reverseSuccMap.set(succ, entry);
    }
  }

  // Add edges: exit blocks → SUPER_EXIT (in reversed graph: SUPER_EXIT has exits as successors)
  reverseSuccMap.set(SUPER_EXIT, exits);

  // Build IRBlock-like structures for the reversed graph
  const reverseBlocks: IRBlock[] = [
    {
      id: SUPER_EXIT,
      start: 0, end: 0, stmts: [],
      allSuccessors: exits,
      successors: exits,
      blockType: 'entry',
    },
    ...blocks.map(b => ({
      ...b,
      allSuccessors: reverseSuccMap.get(b.id) ?? [],
      successors: reverseSuccMap.get(b.id) ?? [],
    })),
  ];

  // Run forward dominator computation on the reversed CFG (= post-dominator)
  const idomRaw = computeDominators(reverseBlocks, SUPER_EXIT);

  // Remove the super-exit node from results
  idomRaw.delete(SUPER_EXIT);
  // Remap super-exit references to null (post-dom of exit blocks = null)
  const idom = new Map<string, string | null>();
  for (const [id, dom] of idomRaw) {
    if (id === SUPER_EXIT) continue;
    idom.set(id, dom === SUPER_EXIT ? null : (dom ?? null));
  }

  const children = buildDomChildren(idom);
  const df = computeDominanceFrontier(reverseBlocks, idomRaw);

  // RPO on reversed graph (without super-exit)
  const rpoFull = computeRPO(reverseBlocks, SUPER_EXIT);
  const rpo = rpoFull.filter(id => id !== SUPER_EXIT);

  return { idom, children, df, rpo };
}
