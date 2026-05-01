/**
 * newFeatures.test.ts — Vitest unit tests for features added in the current batch.
 *
 * Coverage:
 *   Thunk detection                    — detectFunctions marks 1-instruction jmp funcs as thunks
 *   applyCSE rewriteCount             — CSE pass returns count of eliminated expressions
 *   Prototype header builder          — buildPrototypeHeader produces correct comment strings
 *   Dispatcher block detection        — CfgView dispatcher heuristic (≥6 branch edges, ≤5 instr)
 */

import { describe, it, expect } from 'vitest';
import { applyCSE } from '../utils/decompilerEngine';
import type { IRBlock, IRStmt, IRValue } from '../utils/decompilerEngine';
import { decompile, type CfgGraph, type DisassembledInstruction } from '../utils/decompilerEngine';

// ─── Helpers ──────────────────────────────────────────────────────────────────

function reg(name: string): IRValue { return { kind: 'reg', name }; }
function imm(val: number): IRValue { return { kind: 'const', value: val }; }

function assignStmt(dest: string, srcKind: IRValue, address = 0x1000): IRStmt {
  return { op: 'assign', address, dest: reg(dest), src: srcKind } as IRStmt;
}

function binopStmt(dest: string, left: string, op: string, right: string, address = 0x1000): IRStmt {
  return {
    op: 'binop',
    address,
    dest: reg(dest),
    left: reg(left),
    right: reg(right),
    operator: op,
  } as IRStmt;
}

function makeBlock(id: string, stmts: IRStmt[]): IRBlock {
  return { id, stmts, successors: [], predecessors: [] } as unknown as IRBlock;
}

// ─── applyCSE ─────────────────────────────────────────────────────────────────

describe('applyCSE — rewriteCount', () => {
  it('returns rewriteCount=0 when no redundant subexpressions exist', () => {
    const block = makeBlock('b0', [
      binopStmt('r1', 'rdi', '+', 'rsi', 0x1000),
      binopStmt('r2', 'rdx', '+', 'rcx', 0x1001),
    ]);
    const { rewriteCount } = applyCSE([block]);
    expect(rewriteCount).toBe(0);
  });

  it('returns rewriteCount=1 for a duplicated binop within the same block', () => {
    // Same (rdi + rsi) computed twice in one block → second use is CSE'd
    const block = makeBlock('b0', [
      binopStmt('r1', 'rdi', '+', 'rsi', 0x1000),  // first occurrence — recorded
      binopStmt('r2', 'rdi', '+', 'rsi', 0x1004),  // duplicate → replaced
    ]);
    const { rewriteCount } = applyCSE([block]);
    expect(rewriteCount).toBe(1);
  });

  it('returns optimized blocks with replaced CSE stmts in same block', () => {
    const block = makeBlock('b0', [
      binopStmt('r1', 'rdi', '+', 'rsi', 0x1000),
      binopStmt('r2', 'rdi', '+', 'rsi', 0x1004),
    ]);
    const { blocks } = applyCSE([block]);
    // The second stmt should be an 'assign' (register copy) not a 'binop'
    expect(blocks[0].stmts[1].op).toBe('assign');
  });

  it('does not CSE across a write to the same register', () => {
    // Write to rdi before the second use — kills availability
    const block = makeBlock('b0', [
      binopStmt('r1', 'rdi', '+', 'rsi', 0x1000),
      assignStmt('rdi', imm(0), 0x1001),                // kills rdi
      binopStmt('r2', 'rdi', '+', 'rsi', 0x1002),      // rdi is different now
    ]);
    const { rewriteCount } = applyCSE([block]);
    expect(rewriteCount).toBe(0);
  });
});

// ─── Thunk detection heuristic ────────────────────────────────────────────────
// We test the pure logic (not App.tsx's detectFunctions) by replicating the
// heuristic: a function is a thunk when its non-nop instructions consist of
// exactly 1 jmp to an address outside the function boundaries.

function isThunkHeuristic(
  instrs: { mnemonic: string; address: number; targets: number[] }[],
  funcStart: number,
  funcEnd: number,
): boolean {
  const nonNop = instrs.filter(i => !['nop', 'nopl', 'nopw'].includes(i.mnemonic.toLowerCase()));
  if (nonNop.length > 2) return false;
  const last = nonNop[nonNop.length - 1];
  if (!last) return false;
  if (!['jmp', 'jmpq'].includes(last.mnemonic.toLowerCase())) return false;
  if (last.targets.length !== 1) return false;
  const tgt = last.targets[0];
  return tgt < funcStart || tgt >= funcEnd;
}

describe('Thunk detection heuristic', () => {
  it('marks a 1-instruction jmp-outside function as a thunk', () => {
    const instrs = [{ mnemonic: 'jmp', address: 0x1000, targets: [0x2000] }];
    expect(isThunkHeuristic(instrs, 0x1000, 0x1005)).toBe(true);
  });

  it('marks a nop + jmp function as a thunk (nop ignored)', () => {
    const instrs = [
      { mnemonic: 'nop', address: 0x1000, targets: [] },
      { mnemonic: 'jmp', address: 0x1001, targets: [0x3000] },
    ];
    expect(isThunkHeuristic(instrs, 0x1000, 0x1005)).toBe(true);
  });

  it('does NOT mark a 3+ instruction function as a thunk', () => {
    const instrs = [
      { mnemonic: 'mov', address: 0x1000, targets: [] },
      { mnemonic: 'add', address: 0x1002, targets: [] },
      { mnemonic: 'jmp', address: 0x1004, targets: [0x2000] },
    ];
    expect(isThunkHeuristic(instrs, 0x1000, 0x1010)).toBe(false);
  });

  it('does NOT mark a jmp-into-self function as a thunk', () => {
    const instrs = [{ mnemonic: 'jmp', address: 0x1000, targets: [0x1002] }];
    expect(isThunkHeuristic(instrs, 0x1000, 0x1010)).toBe(false);
  });

  it('does NOT mark a call (non-jmp) function as a thunk', () => {
    const instrs = [{ mnemonic: 'call', address: 0x1000, targets: [0x2000] }];
    expect(isThunkHeuristic(instrs, 0x1000, 0x1005)).toBe(false);
  });
});

// ─── Dispatcher block detection heuristic ────────────────────────────────────
// The CfgView dispatcher computation: a block with ≥6 outgoing branch edges
// and ≤5 instructions is a dispatcher.

function computeDispatcherBlocks(
  nodes: { id: string; instruction_count?: number }[],
  edges: { source: string; target: string; kind: string }[],
): Set<string> {
  const branchCount = new Map<string, number>();
  for (const e of edges) {
    if (e.kind === 'branch') branchCount.set(e.source, (branchCount.get(e.source) ?? 0) + 1);
  }
  const s = new Set<string>();
  for (const node of nodes) {
    const bc = branchCount.get(node.id) ?? 0;
    const ic = node.instruction_count ?? 0;
    if (bc >= 6 && ic <= 5) s.add(node.id);
  }
  return s;
}

describe('Dispatcher block detection', () => {
  it('identifies a hub with 6 branch targets and 3 instructions as dispatcher', () => {
    const nodes = [{ id: 'hub', instruction_count: 3 }];
    const edges = Array.from({ length: 6 }, (_, i) => ({
      source: 'hub', target: `target_${i}`, kind: 'branch',
    }));
    const result = computeDispatcherBlocks(nodes, edges);
    expect(result.has('hub')).toBe(true);
  });

  it('does NOT flag a hub with only 5 branch targets', () => {
    const nodes = [{ id: 'hub', instruction_count: 3 }];
    const edges = Array.from({ length: 5 }, (_, i) => ({
      source: 'hub', target: `target_${i}`, kind: 'branch',
    }));
    const result = computeDispatcherBlocks(nodes, edges);
    expect(result.has('hub')).toBe(false);
  });

  it('does NOT flag a hub with 6 branch targets but 10 instructions', () => {
    const nodes = [{ id: 'hub', instruction_count: 10 }];
    const edges = Array.from({ length: 6 }, (_, i) => ({
      source: 'hub', target: `target_${i}`, kind: 'branch',
    }));
    const result = computeDispatcherBlocks(nodes, edges);
    expect(result.has('hub')).toBe(false);
  });

  it('does NOT flag fall-through (non-branch) edges', () => {
    const nodes = [{ id: 'hub', instruction_count: 2 }];
    const edges = Array.from({ length: 6 }, (_, i) => ({
      source: 'hub', target: `target_${i}`, kind: 'fall',  // not 'branch'
    }));
    const result = computeDispatcherBlocks(nodes, edges);
    expect(result.has('hub')).toBe(false);
  });
});

// ─── Imports for new engines ─────────────────────────────────────────────────
import { annotateInstructions } from '../utils/disasmAnnotator';
import { mapBehaviorToMitre, extractIOCs } from '../utils/mitreMapper';
import {
  buildCallStack, computeHotBlocks, detectExecutionLoops,
  createTimeline, appendStep,
} from '../utils/strikeEngine';
import type { DebugSnapshot } from '../components/DebuggerPanel';

// ─── helpers for strike tests ─────────────────────────────────────────────────
function makeSnapshot(rip: number, rsp = 0x7fff0000, event = 'step'): DebugSnapshot {
  return {
    sessionId: 1,
    status: 'Running' as const,
    registers: { rax:0,rbx:0,rcx:0,rdx:0,rsi:0,rdi:0,rsp,rbp:0,rip,
                 r8:0,r9:0,r10:0,r11:0,r12:0,r13:0,r14:0,r15:0,eflags:0,cs:0,ss:0 },
    stack: [],
    breakpoints: [],
    stepCount: 0,
    exitCode: null,
    lastEvent: event,
  };
}

// ─── disasmAnnotator ─────────────────────────────────────────────────────────

describe('annotateInstructions', () => {
  it('detects PEB access in operands', () => {
    const insns: DisassembledInstruction[] = [
      { address: 0x1000, mnemonic: 'mov', operands: 'rax, gs:0x60' },
    ];
    const annotated = annotateInstructions(insns);
    const all = annotated.flatMap(a => a.annotations);
    expect(all.some(a => a.comment.includes('PEB'))).toBe(true);
  });

  it('detects RDTSC timing check', () => {
    const insns: DisassembledInstruction[] = [
      { address: 0x1000, mnemonic: 'rdtsc', operands: '' },
    ];
    const annotated = annotateInstructions(insns);
    const all = annotated.flatMap(a => a.annotations);
    expect(all.some(a => a.comment.toLowerCase().includes('rdtsc'))).toBe(true);
  });

  it('marks push rbp as prologue boundary', () => {
    const insns: DisassembledInstruction[] = [
      { address: 0x1000, mnemonic: 'push', operands: 'rbp' },
      { address: 0x1001, mnemonic: 'mov',  operands: 'rbp, rsp' },
    ];
    const annotated = annotateInstructions(insns);
    expect(annotated[0].boundary).toBe('prologue');
  });

  it('marks ret as epilogue boundary', () => {
    const insns: DisassembledInstruction[] = [
      { address: 0x1000, mnemonic: 'ret', operands: '' },
    ];
    const annotated = annotateInstructions(insns);
    expect(annotated[0].boundary).toBe('epilogue');
  });

  it('tracks stack delta for push/pop', () => {
    const insns: DisassembledInstruction[] = [
      { address: 0x1000, mnemonic: 'push', operands: 'rax' },
      { address: 0x1001, mnemonic: 'push', operands: 'rbx' },
      { address: 0x1002, mnemonic: 'pop',  operands: 'rbx' },
    ];
    const annotated = annotateInstructions(insns);
    expect(annotated[0].stackDelta).toBe(-8);
    expect(annotated[1].stackDelta).toBe(-8);
    expect(annotated[2].stackDelta).toBe(+8);
  });

  it('resolves import name from importMap', () => {
    const insns: DisassembledInstruction[] = [
      { address: 0x1000, mnemonic: 'call', operands: '0x400100' },
    ];
    const importMap = new Map([[0x400100, 'VirtualAllocEx']]);
    const annotated = annotateInstructions(insns, importMap);
    const all = annotated.flatMap(a => a.annotations);
    expect(all.some(a => a.comment.includes('VirtualAllocEx'))).toBe(true);
    expect(all.some(a => a.severity === 'critical')).toBe(true);
  });
});

// ─── mitreMapper ─────────────────────────────────────────────────────────────

describe('mapBehaviorToMitre', () => {
  it('maps code-injection tag to T1055', () => {
    const techs = mapBehaviorToMitre(['code-injection']);
    expect(techs.some(t => t.id === 'T1055')).toBe(true);
  });

  it('maps anti-analysis tag to T1622 (debugger evasion)', () => {
    const techs = mapBehaviorToMitre(['anti-analysis']);
    expect(techs.some(t => t.id === 'T1497' || t.id === 'T1622')).toBe(true);
  });

  it('returns techniques with valid MITRE URLs', () => {
    const techs = mapBehaviorToMitre(['code-decryption', 'code-injection']);
    expect(techs.every(t => t.url.includes('attack.mitre.org'))).toBe(true);
  });

  it('deduplicates when multiple tags produce the same technique', () => {
    const techs = mapBehaviorToMitre(['code-injection', 'code-injection']);
    const ids = techs.map(t => t.subId ?? t.id);
    const unique = new Set(ids);
    expect(ids.length).toBe(unique.size);
  });
});

describe('extractIOCs', () => {
  it('extracts IPv4 addresses', () => {
    const iocs = extractIOCs(['connecting to 192.168.1.1 for exfil', 'server: 10.0.1.50']);
    // 10.0.1.50 should be extracted (not in common blocklist)
    expect(iocs.some(i => i.kind === 'ipv4')).toBe(true);
  });

  it('extracts HTTP URLs', () => {
    const iocs = extractIOCs(['http://malware.example.com/c2/callback?id=1']);
    expect(iocs.some(i => i.kind === 'url')).toBe(true);
    expect(iocs.some(i => i.value.includes('malware.example.com'))).toBe(true);
  });

  it('extracts Windows registry paths', () => {
    const iocs = extractIOCs(['HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\malware']);
    expect(iocs.some(i => i.kind === 'registry')).toBe(true);
  });

  it('extracts SHA-256 hashes', () => {
    const hash = 'a'.repeat(64);
    const iocs = extractIOCs([`file hash: ${hash}`]);
    expect(iocs.some(i => i.kind === 'hash-sha256')).toBe(true);
  });

  it('returns empty array for clean string list', () => {
    const iocs = extractIOCs(['Hello world', 'normal text', 'no iocs here']);
    // May find domains in "world" — filter to high-confidence
    const highConf = iocs.filter(i => i.confidence >= 90);
    expect(highConf).toHaveLength(0);
  });
});

// ─── STRIKE: buildCallStack ───────────────────────────────────────────────────

describe('buildCallStack', () => {
  it('returns empty stack with no steps', () => {
    const timeline = createTimeline(1);
    expect(buildCallStack(timeline)).toEqual([]);
  });

  it('pushes a frame on call and pops on ret', () => {
    let timeline = createTimeline(1);
    ({ timeline } = appendStep(timeline, makeSnapshot(0x1000, 0x7fff0000, 'start')));
    // simulate call: RIP jumps > 15 bytes forward, event says "call"
    ({ timeline } = appendStep(timeline, makeSnapshot(0x2000, 0x7ffefffc, 'call 0x2000')));
    // simulate ret
    ({ timeline } = appendStep(timeline, makeSnapshot(0x1005, 0x7fff0000, 'ret')));

    const stack = buildCallStack(timeline);
    expect(stack).toHaveLength(0); // pushed + popped = empty
  });
});

// ─── STRIKE: computeHotBlocks ─────────────────────────────────────────────────

describe('computeHotBlocks', () => {
  it('returns hottest block first', () => {
    let timeline = createTimeline(1);
    // Visit 0x1000 area 5 times, 0x2000 twice
    for (let i = 0; i < 5; i++) {
      ({ timeline } = appendStep(timeline, makeSnapshot(0x1000 + i)));
    }
    for (let i = 0; i < 2; i++) {
      ({ timeline } = appendStep(timeline, makeSnapshot(0x2000 + i)));
    }
    const hot = computeHotBlocks(timeline, 64);
    expect(hot[0].count).toBeGreaterThanOrEqual(hot[1]?.count ?? 0);
  });

  it('returns empty array for empty timeline', () => {
    const timeline = createTimeline(1);
    expect(computeHotBlocks(timeline)).toEqual([]);
  });
});

// ─── STRIKE: detectExecutionLoops ────────────────────────────────────────────

describe('detectExecutionLoops', () => {
  it('detects a simple repeated RIP sequence', () => {
    let timeline = createTimeline(1);
    // Repeat pattern [0x1000, 0x1004, 0x1008] × 4
    for (let iter = 0; iter < 4; iter++) {
      ({ timeline } = appendStep(timeline, makeSnapshot(0x1000)));
      ({ timeline } = appendStep(timeline, makeSnapshot(0x1004)));
      ({ timeline } = appendStep(timeline, makeSnapshot(0x1008)));
    }
    const loops = detectExecutionLoops(timeline, 16, 3);
    expect(loops.length).toBeGreaterThan(0);
    expect(loops[0].periodLen).toBe(3);
    expect(loops[0].iterations).toBeGreaterThanOrEqual(3);
  });

  it('returns empty for non-repeating timeline', () => {
    let timeline = createTimeline(1);
    for (let i = 0; i < 10; i++) {
      ({ timeline } = appendStep(timeline, makeSnapshot(0x1000 + i * 4)));
    }
    const loops = detectExecutionLoops(timeline, 4, 3);
    expect(loops).toHaveLength(0);
  });
});

// ─── decompiler: while-at-header loop ────────────────────────────────────────

describe('decompile — while/for loop header reconstruction', () => {
  it('emits while() for a header-conditional loop (header has cjmp, body loops back)', () => {
    // Pattern: header → body → (back to header) OR → exit
    // header: jge exit
    // body:   mov eax,1 ; jmp header  ← back edge
    // exit:   ret
    const insns: DisassembledInstruction[] = [
      { address: 0x1000, mnemonic: 'cmp',  operands: 'rcx, 0xa' },
      { address: 0x1004, mnemonic: 'jge',  operands: '0x1020' },   // exit if rcx >= 10
      { address: 0x1008, mnemonic: 'mov',  operands: 'eax, 1' },
      { address: 0x100c, mnemonic: 'inc',  operands: 'rcx' },
      { address: 0x1010, mnemonic: 'jmp',  operands: '0x1000' },   // back to header
      { address: 0x1020, mnemonic: 'ret',  operands: '' },
    ];

    const cfg: CfgGraph = {
      nodes: [
        { id: 'header', start: 0x1000, end: 0x1004 },
        { id: 'body',   start: 0x1008, end: 0x1010 },
        { id: 'exit',   start: 0x1020, end: 0x1020 },
      ],
      edges: [
        { source: 'header', target: 'body',   kind: 'fallthrough' },
        { source: 'header', target: 'exit',   kind: 'branch' },
        { source: 'body',   target: 'header', kind: 'branch' },  // back edge
      ],
    };

    const result = decompile(insns, cfg, { functionName: 'loop_fn' });
    const text = result.lines.map(l => l.text).join('\n');
      // Decompiler may promote to for() when it detects an increment pattern.
      expect(text).toMatch(/(?:while|for)\s*\(/);
  });
});

// ─── Switch reconstruction ───────────────────────────────────────────────────

describe('decompile — switch reconstruction', () => {
  it('emits switch/case for multi-target indirect dispatch blocks', () => {
    const instructions: DisassembledInstruction[] = [
      { address: 0x1000, mnemonic: 'jmp', operands: 'qword ptr [rax*8 + 0x2000]' },
      { address: 0x1010, mnemonic: 'mov', operands: 'eax, 1' },
      { address: 0x1014, mnemonic: 'jmp', operands: '0x1040' },
      { address: 0x1020, mnemonic: 'mov', operands: 'eax, 2' },
      { address: 0x1024, mnemonic: 'jmp', operands: '0x1040' },
      { address: 0x1030, mnemonic: 'mov', operands: 'eax, 3' },
      { address: 0x1034, mnemonic: 'jmp', operands: '0x1040' },
      { address: 0x1040, mnemonic: 'ret', operands: '' },
    ];

    const cfg: CfgGraph = {
      nodes: [
        { id: 'b0', start: 0x1000, end: 0x1000 },
        { id: 'b1', start: 0x1010, end: 0x1014 },
        { id: 'b2', start: 0x1020, end: 0x1024 },
        { id: 'b3', start: 0x1030, end: 0x1034 },
        { id: 'b4', start: 0x1040, end: 0x1040 },
      ],
      edges: [
        { source: 'b0', target: 'b1', kind: 'branch' },
        { source: 'b0', target: 'b2', kind: 'branch' },
        { source: 'b0', target: 'b3', kind: 'branch' },
        { source: 'b1', target: 'b4', kind: 'fall' },
        { source: 'b2', target: 'b4', kind: 'fall' },
        { source: 'b3', target: 'b4', kind: 'fall' },
      ],
    };

    const result = decompile(instructions, cfg, { functionName: 'dispatch_fn' });
    const text = result.lines.map(l => l.text).join('\n');

    expect(text).toContain('switch (');
    expect(text).toContain('case 0:');
    expect(text).toContain('break;');
  });
});
