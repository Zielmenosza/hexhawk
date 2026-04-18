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

export type IRValue =
  | { kind: 'reg'; name: string }
  | { kind: 'const'; value: number }
  | { kind: 'mem'; base: string; index?: string; scale?: number; offset: number; size: MemSize }
  | { kind: 'expr'; text: string };

export type IRStmt =
  | { op: 'assign'; address: number; dest: IRValue; src: IRValue }
  | { op: 'binop'; address: number; dest: IRValue; operator: string; left: IRValue; right: IRValue }
  | { op: 'uop'; address: number; dest: IRValue; operator: string; operand: IRValue }
  | { op: 'cmp'; address: number; left: IRValue; right: IRValue }
  | { op: 'test'; address: number; left: IRValue; right: IRValue }
  | { op: 'cjmp'; address: number; cond: string; trueTarget: number; falseTarget: number }
  | { op: 'jmp'; address: number; target: number | null }
  | { op: 'call'; address: number; target: number | null; name?: string }
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
  | { kind: 'block'; irBlock: IRBlock }
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

export type DecompileResult = {
  functionName: string;
  startAddress: number;
  lines: PseudoLine[];
  varMap: Map<string, string>;   // IR key → friendly name
  irBlocks: IRBlock[];
  warnings: string[];
  instrCount: number;
};

// ─────────────────────────────────────────────────────────
// PHASE 1 — OPERAND PARSING
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
    return { op: 'call', address, target, name };
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
const ARG_REGS_64 = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9'];
// x86-32 arguments are on the stack at [ebp+8], [ebp+12], …
const RETURN_REGS = new Set(['rax', 'eax', 'al', 'ax', 'rdx:rax']);
const FRAME_REGS = new Set(['rbp', 'ebp']);
const STACK_REGS = new Set(['rsp', 'esp']);

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

function collectVars(stmts: IRStmt[]): VarCollector {
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
      const idx = ARG_REGS_64.indexOf(stmt.src.name);
      if (idx >= 0 && !col.argRegs.has(stmt.src.name)) {
        col.argRegs.set(stmt.src.name, `param_${idx}`);
      }
    }
  }

  return col;
}

function buildVarMap(stmts: IRStmt[]): VarMap {
  const col = collectVars(stmts);
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

  return map;
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
      if (stmt.target !== null) {
        return { text: `goto 0x${stmt.target.toString(16)};`, uncertain: true };
      }
      return { text: `goto *indirect;`, uncertain: true };

    case 'call': {
      const target = stmt.name
        ? stmt.name
        : stmt.target !== null
        ? `sub_${stmt.target.toString(16)}`
        : '*indirect';
      return { text: `${target}();` };
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
// PHASE 4 — BLOCK BUILDING
// ─────────────────────────────────────────────────────────

function buildIRBlocks(
  instructions: DisassembledInstruction[],
  cfg: CfgGraph | null
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
    const stmts: IRStmt[] = [];

    for (let i = 0; i < blockInsns.length; i++) {
      const ins = blockInsns[i];
      const nextAddr = blockInsns[i + 1]?.address ?? (range.end + 1);
      const ctx: LiftContext = {
        lastCmpLeft, lastCmpRight, lastTestLeft, lastTestRight, nextAddress: nextAddr
      };
      const stmt = liftInstruction(ins, ctx);
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

  return irBlocks;
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

const MAX_STRUCT_DEPTH = 24;

function structureBlock(
  blockId: string,
  blockMap: Map<string, IRBlock>,
  backEdges: Set<string>,
  topoOrder: string[],
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

  // ── LOOP DETECTION: back edge from this block → header ──
  if (backSuccs.length > 0 && hasCjmp(block)) {
    const loopHeader = backSuccs[0];
    // The block just before the back edge is the loop tail
    // Forward successor (if any) is the loop exit
    const exitSucc = fwdSuccs[0] ?? null;
    const cond = extractCondFromBlock(block);

    // Determine if this is a loop header itself (has a back edge coming IN)
    // For simplicity, treat the current block as the while header
    // Body = from loopHeader to this block
    const bodyVisited = new Set(visited);
    bodyVisited.delete(blockId); // allow re-entry for body

    // Build loop body: from loop header to this (tail) block
    const bodyNode = structureBlock(loopHeader, blockMap, backEdges, topoOrder,
                                    bodyVisited, blockId, depth + 1);

    const whileNode: StructuredNode = { kind: 'while', cond, address: block.stmts.find(s => s.op === 'cjmp')?.address ?? block.start, body: bodyNode };

    const rest = exitSucc
      ? structureBlock(exitSucc, blockMap, backEdges, topoOrder, visited, stopAt, depth + 1)
      : { kind: 'seq' as const, nodes: [] };

    return { kind: 'seq', nodes: [blockNode, whileNode, rest] };
  }

  // ── SIMPLE SEQUENCE (single forward successor) ──────
  if (fwdSuccs.length === 0) {
    return blockNode;
  }

  if (fwdSuccs.length === 1) {
    const rest = structureBlock(fwdSuccs[0], blockMap, backEdges, topoOrder, visited, stopAt, depth + 1);
    return { kind: 'seq', nodes: [blockNode, rest] };
  }

  // ── IF / ELSE (two forward successors) ──────────────
  if (fwdSuccs.length === 2 && hasCjmp(block)) {
    const cjmpStmt = [...block.stmts].reverse().find((s): s is Extract<IRStmt, { op: 'cjmp' }> => s.op === 'cjmp');
    const cond = cjmpStmt?.cond ?? '?';
    const trueSucc  = cjmpStmt
      ? fwdSuccs.find(s => blockMap.get(s)?.start === cjmpStmt.trueTarget) ?? fwdSuccs[0]
      : fwdSuccs[0];
    const falseSucc = fwdSuccs.find(s => s !== trueSucc) ?? fwdSuccs[1];

    const joinId = findJoinPoint(trueSucc, falseSucc, blockMap, backEdges, topoOrder);

    const thenVisited = new Set(visited);
    const elseVisited = new Set(visited);
    const thenNode = structureBlock(trueSucc, blockMap, backEdges, topoOrder, thenVisited, joinId, depth + 1);
    const elseNode = structureBlock(falseSucc, blockMap, backEdges, topoOrder, elseVisited, joinId, depth + 1);

    const cjmpAddr = cjmpStmt?.address ?? block.start;
    const ifNode: StructuredNode = {
      kind: 'if',
      cond,
      address: cjmpAddr,
      then: thenNode,
      else: isEmptySeq(elseNode) ? undefined : elseNode,
    };

    const rest = joinId
      ? structureBlock(joinId, blockMap, backEdges, topoOrder, visited, stopAt, depth + 1)
      : { kind: 'seq' as const, nodes: [] };

    return { kind: 'seq', nodes: [blockNode, ifNode, rest] };
  }

  // ── FALLBACK: multi-successor, can't structure cleanly ──
  const nodes: StructuredNode[] = [blockNode];
  for (const s of fwdSuccs) {
    const child = structureBlock(s, blockMap, backEdges, topoOrder, visited, stopAt, depth + 1);
    nodes.push(child);
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

    case 'goto': {
      lines.push({
        indent,
        text: `goto block_${node.target};`,
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
    return {
      functionName: options.functionName ?? 'sub_unknown',
      startAddress: options.startAddress ?? 0,
      lines: [{ indent: 0, text: '// No instructions in range', kind: 'comment' }],
      varMap: new Map(),
      irBlocks: [],
      warnings: ['No instructions to decompile'],
      instrCount: 0,
    };
  }

  const startAddress = options.startAddress ?? insns[0].address;
  const funcName = options.functionName ?? `sub_${startAddress.toString(16)}`;

  // Phase 3+4: Build IR blocks
  const irBlocks = buildIRBlocks(insns, cfg);

  if (!irBlocks.length) {
    return {
      functionName: funcName,
      startAddress,
      lines: [{ indent: 0, text: '// Could not build basic blocks', kind: 'comment' }],
      varMap: new Map(),
      irBlocks: [],
      warnings: ['No basic blocks built'],
      instrCount: insns.length,
    };
  }

  // Phase 3: Build variable map
  const allStmts = collectAllStmts(irBlocks);
  const varMap = buildVarMap(allStmts);

  // Detect return register
  const hasRetVal = allStmts.some(s =>
    s.op === 'assign' && s.dest.kind === 'reg' && RETURN_REGS.has(s.dest.name)
  );

  // Build parameter list from detected arg regs / stack args
  const paramNames: string[] = [];
  for (const reg of ARG_REGS_64) {
    if (varMap.has(`reg:${reg}`)) paramNames.push(varMap.get(`reg:${reg}`)!);
  }
  // Also check stack args
  for (const [key, name] of varMap) {
    if (name.startsWith('arg_')) paramNames.push(name);
  }
  const uniqueParams = [...new Set(paramNames)].sort();

  if (irBlocks.length > 32) {
    warnings.push(`Large function (${irBlocks.length} blocks) — control flow may be simplified.`);
  }

  // Phase 5: Structure control flow
  const blockMap = new Map(irBlocks.map(b => [b.id, b]));
  const backEdges = computeBackEdges(irBlocks);
  const topo = topoSort(irBlocks, backEdges);
  const entry = findEntryBlock(irBlocks);

  let structured: StructuredNode;
  if (entry) {
    structured = structureBlock(entry.id, blockMap, backEdges, topo, new Set(), null, 0);
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
    const locals = [...varMap.values()].filter(v => v.startsWith('local_'));
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

  return { functionName: funcName, startAddress, lines, varMap, irBlocks, warnings, instrCount: insns.length };
}
