/**
 * talonPasses.test.ts — Vitest unit tests for talonPasses.ts
 *
 * Coverage:
 *   canonicalizeLoops          — 7 tests
 *   inferTypes                 — 10 tests
 *   detectSwitchPatternsEnhanced — 8 tests
 */

import { describe, it, expect } from 'vitest';
import {
  canonicalizeLoops,
  inferTypes,
  detectSwitchPatternsEnhanced,
  type CanonLoopKind,
  type TypeMap,
  type EnhancedSwitchStatement,
} from '../utils/talonPasses';
import type { NaturalLoop } from '../utils/cfgSignalExtractor';
import type { TalonLine } from '../utils/talonEngine';
import type { IRBlock, IRStmt, IRValue } from '../utils/decompilerEngine';
import type { TransformRecord } from '../utils/talonAdvanced';

// ─── Shared helpers ────────────────────────────────────────────────────────────

/** Build a minimal TalonLine. `kind` defaults to 'control'. */
function makeLine(
  text: string,
  kind: TalonLine['kind'] = 'control',
  address = 0x1000,
): TalonLine {
  return { kind, text, address, lineConfidence: 80, indent: 0 } as unknown as TalonLine;
}

function makeStmt(text: string, address = 0x1000): TalonLine {
  return makeLine(text, 'stmt', address);
}

/** Build a minimal NaturalLoop at the given header address. */
function makeLoop(
  headerAddress: number,
  classification: NaturalLoop['classification'],
): NaturalLoop {
  return {
    header: 'b0',
    latch:  'b1',
    body:   new Set(['b0', 'b1']),
    depth:  1,
    backEdgeKey: 'b1->b0',
    classification,
    headerAddress,
  };
}

// ─── IR construction helpers ──────────────────────────────────────────────────

function reg(name: string): IRValue  { return { kind: 'reg',   name }; }
function cnst(value: number): IRValue { return { kind: 'const', value }; }
function memBase(base: string, offset = 0): IRValue {
  return { kind: 'mem', base, offset, size: 'qword' } as IRValue;
}
function memIdx(base: string, index: string, scale: number, offset = 0): IRValue {
  return { kind: 'mem', base, index, scale, offset, size: 'qword' } as IRValue;
}

function mkAssign(dest: string, src: IRValue, address: number): IRStmt {
  return { op: 'assign', dest: reg(dest), src, address } as IRStmt;
}
function mkBinop(
  dest: string, left: IRValue, right: IRValue, op: string, address: number,
): IRStmt {
  return { op: 'binop', dest: reg(dest), left, right, operator: op, address } as IRStmt;
}
function mkTest(left: string, right: string, address: number): IRStmt {
  return { op: 'test', left: reg(left), right: reg(right), address } as IRStmt;
}
function mkCall(name: string, address: number): IRStmt {
  return { op: 'call', target: null, name, address } as IRStmt;
}

function makeBlock(id: string, stmts: IRStmt[]): IRBlock {
  return { id, start: 0, end: 0x40, stmts, successors: [], allSuccessors: [] };
}

// ─── canonicalizeLoops ────────────────────────────────────────────────────────

describe('canonicalizeLoops', () => {
  it('returns a copy of lines unchanged when loops array is empty', () => {
    const lines = [makeLine('while (i < 10) {'), makeStmt('i++;')];
    const log: TransformRecord[] = [];
    const out = canonicalizeLoops(lines, [], log);
    expect(out).toHaveLength(2);
    expect(out[0].text).toBe('while (i < 10) {');
    expect(log).toHaveLength(0);
  });

  it('rewrites infinite loop: while (1) { → for (;;) {', () => {
    const headerAddr = 0x2000;
    const lines = [makeLine('  while (1) {', 'control', headerAddr)];
    const log: TransformRecord[] = [];
    const out = canonicalizeLoops(lines, [makeLoop(headerAddr, 'infinite')], log);

    expect(out).toHaveLength(1);
    expect(out[0].text).toContain('for (;;) {');
    expect(out[0].text).not.toContain('while (1)');
    expect(log).toHaveLength(1);
    expect(log[0].kind).toBe('loop-unroll-hint');
    expect(log[0].confidence).toBe(90);
  });

  it('rewrites any while condition to for(;;) when classification is infinite', () => {
    const addr = 0x3000;
    const lines = [makeLine('while (flag != 0) {', 'control', addr)];
    const log: TransformRecord[] = [];
    const out = canonicalizeLoops(lines, [makeLoop(addr, 'infinite')], log);
    expect(out[0].text).toBe('for (;;) {');
  });

  it('reconstructs for-loop: detects init + while + increment', () => {
    const headerAddr = 0x4000;
    const lines = [
      makeStmt('i = 0;',            0x3ffc),  // init
      makeLine('while (i < 10) {', 'control', headerAddr),
      makeStmt('doWork(i);',        0x4010),
      makeStmt('i++;',              0x4020),  // increment
    ];
    const log: TransformRecord[] = [];
    const out = canonicalizeLoops(lines, [makeLoop(headerAddr, 'for')], log);

    // The control line should become a for-loop
    const forLine = out.find(l => l.address === headerAddr);
    expect(forLine?.text).toMatch(/for\s*\(\s*i\s*=\s*0\s*;\s*i\s*<\s*10\s*;\s*i\+\+\s*\)/);
    expect(log[0].kind).toBe('loop-unroll-hint');
    expect(log[0].confidence).toBe(82);
  });

  it('inserts do-while annotation comment before the header line', () => {
    const addr = 0x5000;
    const lines = [makeLine('while (c != 0) {', 'control', addr)];
    const log: TransformRecord[] = [];
    const out = canonicalizeLoops(lines, [makeLoop(addr, 'do-while')], log);

    // Two lines emitted: annotation + original
    expect(out).toHaveLength(2);
    expect(out[0].kind).toBe('intent-comment');
    expect(out[0].text).toContain('do-while pattern');
    expect(out[1].text).toBe('while (c != 0) {');  // header text unchanged
    expect(log[0].kind).toBe('loop-unroll-hint');
  });

  it('leaves while-classified loop lines unchanged', () => {
    const addr = 0x6000;
    const lines = [makeLine('while (x < 100) {', 'control', addr)];
    const log: TransformRecord[] = [];
    const out = canonicalizeLoops(lines, [makeLoop(addr, 'while')], log);
    expect(out[0].text).toBe('while (x < 100) {');
    expect(log).toHaveLength(0);
  });

  it('does not rewrite non-control lines even if address matches a loop header', () => {
    const addr = 0x7000;
    const lines = [makeStmt('x = 1;', addr)];
    const log: TransformRecord[] = [];
    const out = canonicalizeLoops(lines, [makeLoop(addr, 'infinite')], log);
    expect(out[0].text).toBe('x = 1;');
    expect(log).toHaveLength(0);
  });
});

// ─── inferTypes ───────────────────────────────────────────────────────────────

describe('inferTypes', () => {
  it('returns empty map for empty block list', () => {
    expect(inferTypes([])).toHaveLength(0);
  });

  it('infers pointer for a register used as mem.base', () => {
    // assign rax, [rcx+0]  → rcx is the base
    const block = makeBlock('b0', [
      mkAssign('rax', memBase('rcx', 0), 0x10),
    ]);
    const map = inferTypes([block]);
    const ann = map.get('rcx');
    expect(ann?.kind).toBe('pointer');
    expect(ann?.confidence).toBe(90);
  });

  it('infers int32 for a register used as a scaled array index', () => {
    // assign rax, [rbx + rsi*4]  → rsi is the index with scale 4
    const block = makeBlock('b0', [
      mkAssign('rax', memIdx('rbx', 'rsi', 4, 0), 0x10),
    ]);
    const map = inferTypes([block]);
    const ann = map.get('rsi');
    expect(ann?.kind).toBe('int32');
    expect(ann?.confidence).toBe(88);
  });

  it('infers pointer from test reg,reg null-check pattern', () => {
    const block = makeBlock('b0', [mkTest('rax', 'rax', 0x20)]);
    const map = inferTypes([block]);
    const ann = map.get('rax');
    expect(ann?.kind).toBe('pointer');
    expect(ann?.confidence).toBe(92);
  });

  it('does NOT infer from test when both regs are different', () => {
    const block = makeBlock('b0', [mkTest('rax', 'rbx', 0x20)]);
    const map = inferTypes([block]);
    // Neither rax nor rbx triggered the null-check rule (confidence < 92)
    // They may get other lower-confidence annotations, but not the 92-conf pointer
    const raxAnn = map.get('rax');
    const rbxAnn = map.get('rbx');
    expect(raxAnn?.confidence ?? 0).toBeLessThan(92);
    expect(rbxAnn?.confidence ?? 0).toBeLessThan(92);
  });

  it('infers uint8 for dest of AND with 0xFF', () => {
    // rcx = rax & 0xFF
    const block = makeBlock('b0', [
      mkBinop('rcx', reg('rax'), cnst(0xFF), '&', 0x30),
    ]);
    const map = inferTypes([block]);
    expect(map.get('rcx')?.kind).toBe('uint8');
    expect(map.get('rcx')?.confidence).toBe(85);
    // Source also gets a lower-confidence uint8
    expect(map.get('rax')?.kind).toBe('uint8');
    expect(map.get('rax')?.confidence).toBe(83);
  });

  it('infers uint16 for dest of AND with 0xFFFF', () => {
    const block = makeBlock('b0', [
      mkBinop('rdx', reg('rbx'), cnst(0xFFFF), '&', 0x40),
    ]);
    expect(inferTypes([block]).get('rdx')?.kind).toBe('uint16');
  });

  it('infers int32 for a register incremented by 1 (loop counter)', () => {
    // rcx = rcx + 1
    const block = makeBlock('b0', [
      mkBinop('rcx', reg('rcx'), cnst(1), '+', 0x50),
    ]);
    const map = inferTypes([block]);
    expect(map.get('rcx')?.kind).toBe('int32');
    expect(map.get('rcx')?.confidence).toBe(87);
  });

  it('infers size_t for register shifted left by 3 (×8, 64-bit index)', () => {
    // rdi = rsi << 3
    const block = makeBlock('b0', [
      mkBinop('rdi', reg('rsi'), cnst(3), '<<', 0x60),
    ]);
    const map = inferTypes([block]);
    expect(map.get('rdi')?.kind).toBe('size_t');
    expect(map.get('rdi')?.confidence).toBe(91);
    expect(map.get('rsi')?.kind).toBe('size_t');
    expect(map.get('rsi')?.confidence).toBe(90);
  });

  it('infers char_ptr for rcx when strlen is called', () => {
    const block = makeBlock('b0', [mkCall('strlen', 0x70)]);
    const map = inferTypes([block]);
    expect(map.get('rcx')?.kind).toBe('char_ptr');
    expect(map.get('rcx')?.confidence).toBe(89);
  });

  it('higher-confidence rule wins over lower when both fire on the same var', () => {
    // rcx: test rcx,rcx (conf 92) AND assign rcx = [rcx+0] base (conf 90)
    // Both propose 'pointer' but test wins; if a weak rule fires first, test still wins.
    const block = makeBlock('b0', [
      mkAssign('rax', memBase('rcx', 0), 0x10),  // rcx → pointer conf 90
      mkTest('rcx', 'rcx', 0x14),                 // rcx → pointer conf 92
    ]);
    const map = inferTypes([block]);
    expect(map.get('rcx')?.confidence).toBe(92);
  });
});

// ─── detectSwitchPatternsEnhanced ────────────────────────────────────────────

describe('detectSwitchPatternsEnhanced', () => {
  it('returns empty array for empty line list', () => {
    const log: TransformRecord[] = [];
    expect(detectSwitchPatternsEnhanced([], new Map(), log)).toHaveLength(0);
    expect(log).toHaveLength(0);
  });

  it('detects indirect jump pattern (jmp table[eax*4])', () => {
    const lines = [
      makeLine('if (eax > 4) goto default', 'control', 0x100),
      makeLine('jmp table[eax*4]', 'stmt', 0x108),
    ];
    const log: TransformRecord[] = [];
    const result = detectSwitchPatternsEnhanced(lines, new Map(), log);

    expect(result).toHaveLength(1);
    expect(result[0].switchVar).toBe('eax');
    expect(result[0].cases.length).toBeGreaterThan(0);
    expect(result[0].hasDefault).toBe(true);
    expect(result[0].fromIfElseChain).toBe(false);
    expect(log[0].kind).toBe('switch-reconstruct');
  });

  it('boosts confidence by +15 when switch var has int32 type annotation', () => {
    const typeMap: TypeMap = new Map([
      ['ecx', { varBase: 'ecx', kind: 'int32', confidence: 87, reason: 'loop counter' }],
    ]);
    const lines = [
      makeLine('if (ecx > 3) goto def', 'control', 0x200),
      makeLine('jmp tbl[ecx*4]', 'stmt', 0x210),
    ];
    const log: TransformRecord[] = [];
    const result = detectSwitchPatternsEnhanced(lines, typeMap, log);

    expect(result[0].confidence).toBeGreaterThanOrEqual(87); // 72 + 15 = 87
    expect(result[0].switchVarType).toBe('int32');
    expect(log[0].reason).toContain('+15 conf');
  });

  it('collects explicit case_N: labels from subsequent lines', () => {
    const lines = [
      makeLine('if (rax > 2) goto def', 'control', 0x300),
      makeLine('jmp table[rax*8]', 'stmt', 0x308),
      makeLine('case_0:', 'stmt', 0x400),
      makeLine('  return 10;', 'stmt', 0x404),
      makeLine('case_1:', 'stmt', 0x410),
      makeLine('  return 20;', 'stmt', 0x414),
      makeLine('case_2:', 'stmt', 0x420),
    ];
    const log: TransformRecord[] = [];
    const result = detectSwitchPatternsEnhanced(lines, new Map(), log);

    expect(result[0].casesFromLabels).toBe(true);
    expect(result[0].cases.map(c => c.value)).toEqual([0, 1, 2]);
    // Real addresses from the line stream, not synthetic
    expect(result[0].cases[0].targetAddress).toBe(0x400);
    expect(result[0].confidence).toBeGreaterThanOrEqual(80); // 72 + 8 label boost
    expect(log[0].reason).toContain('explicit case labels');
  });

  it('detects if-else equality chain of ≥3 as switch-like dispatch', () => {
    const lines = [
      makeStmt('if (cmd == 1) doA();', 0x500),
      makeStmt('else if (cmd == 2) doB();', 0x510),
      makeStmt('else if (cmd == 3) doC();', 0x520),
    ];
    const log: TransformRecord[] = [];
    const result = detectSwitchPatternsEnhanced(lines, new Map(), log);

    const chain = result.find(s => s.fromIfElseChain);
    expect(chain).toBeDefined();
    expect(chain!.switchVar).toBe('cmd');
    expect(chain!.cases).toHaveLength(3);
    expect(chain!.cases.map(c => c.value)).toEqual([1, 2, 3]);
    expect(log.some(r => r.reason.includes('consecutive equality'))).toBe(true);
  });

  it('does NOT detect if-else chain of only 2 equalities', () => {
    const lines = [
      makeStmt('if (x == 0) a();', 0x600),
      makeStmt('else if (x == 1) b();', 0x610),
    ];
    const log: TransformRecord[] = [];
    const result = detectSwitchPatternsEnhanced(lines, new Map(), log);
    expect(result.filter(s => s.fromIfElseChain)).toHaveLength(0);
  });

  it('gives higher confidence to if-else chain when var has a type annotation', () => {
    const typeMap: TypeMap = new Map([
      ['code', { varBase: 'code', kind: 'uint32', confidence: 82, reason: '32-bit mask' }],
    ]);
    const lines = [
      makeStmt('if (code == 10) handle10();', 0x700),
      makeStmt('else if (code == 20) handle20();', 0x710),
      makeStmt('else if (code == 30) handle30();', 0x720),
    ];
    const log: TransformRecord[] = [];
    const result = detectSwitchPatternsEnhanced(lines, typeMap, log);

    const chain = result.find(s => s.fromIfElseChain);
    expect(chain).toBeDefined();
    expect(chain!.switchVarType).toBe('uint32');
    // With typeBoost=10: 62 + 10 + min(3*2,16) = 78
    expect(chain!.confidence).toBeGreaterThanOrEqual(78);
    expect(log.some(r => r.reason.includes('+10 conf'))).toBe(true);
  });

  it('does not produce false positives for plain if statements', () => {
    const lines = [
      makeLine('if (x > 0) {', 'control', 0x800),
      makeStmt('doSomething();', 0x810),
    ];
    const log: TransformRecord[] = [];
    const result = detectSwitchPatternsEnhanced(lines, new Map(), log);
    expect(result).toHaveLength(0);
    expect(log).toHaveLength(0);
  });

  it('indirect-jump and if-else passes are independent — both can fire on same input', () => {
    const lines = [
      // Indirect jump section
      makeLine('if (eax > 2) goto def', 'control', 0x900),
      makeLine('jmp tbl[eax*4]', 'stmt', 0x908),
      // Completely separate equality chain
      makeStmt('if (mode == 0) modeA();', 0xa00),
      makeStmt('else if (mode == 1) modeB();', 0xa10),
      makeStmt('else if (mode == 2) modeC();', 0xa20),
    ];
    const log: TransformRecord[] = [];
    const result = detectSwitchPatternsEnhanced(lines, new Map(), log);

    const indirect = result.filter(s => !s.fromIfElseChain);
    const chain    = result.filter(s =>  s.fromIfElseChain);
    expect(indirect).toHaveLength(1);
    expect(chain).toHaveLength(1);
    expect(log).toHaveLength(2);
  });
});
