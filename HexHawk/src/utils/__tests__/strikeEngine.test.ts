import { describe, it, expect } from 'vitest';
import {
  createTimeline,
  appendStep,
  clearStrikeHooksForTests,
  createStrikeQuerySurface,
  registerHook,
  resolveImportPrototype,
  runStrikePostAnalysisHooks,
  strike,
  MAX_STRIKE_TIMELINE_STEPS,
} from '../strikeEngine';
import type { DebugSnapshot, RegisterState } from '../../components/DebuggerPanel';
import type { DecompilerIrNode } from '../decompilerTypes';

function makeRegisters(rip: number): RegisterState {
  return {
    rax: 0,
    rbx: 0,
    rcx: 0,
    rdx: 0,
    rsi: 0,
    rdi: 0,
    rsp: 0x1000,
    rbp: 0x2000,
    rip,
    r8: 0,
    r9: 0,
    r10: 0,
    r11: 0,
    r12: 0,
    r13: 0,
    r14: 0,
    r15: 0,
    eflags: 0,
    cs: 0,
    ss: 0,
  };
}

function makeSnapshot(stepCount: number, rip: number): DebugSnapshot {
  return {
    sessionId: 7,
    status: 'Paused',
    registers: makeRegisters(rip),
    stack: [],
    breakpoints: [],
    stepCount,
    exitCode: null,
    lastEvent: 'step',
  };
}

describe('strikeEngine appendStep', () => {
  it('caps timeline steps and reindexes when over limit', () => {
    let timeline = createTimeline(7);

    const total = MAX_STRIKE_TIMELINE_STEPS + 20;
    for (let i = 0; i < total; i++) {
      timeline = appendStep(timeline, makeSnapshot(i, 0x401000 + i)).timeline;
    }

    expect(timeline.steps).toHaveLength(MAX_STRIKE_TIMELINE_STEPS);
    expect(timeline.playheadIndex).toBe(MAX_STRIKE_TIMELINE_STEPS - 1);

    expect(timeline.steps[0].index).toBe(0);
    expect(timeline.steps[MAX_STRIKE_TIMELINE_STEPS - 1].index).toBe(MAX_STRIKE_TIMELINE_STEPS - 1);

    expect(timeline.steps[0].snapshot.stepCount).toBe(20);
    expect(timeline.steps[MAX_STRIKE_TIMELINE_STEPS - 1].snapshot.stepCount).toBe(total - 1);
  });
});


describe('strikeEngine recovered structs', () => {
  const load = (address: number, destination: string, base: string, offset: number): DecompilerIrNode => ({
    kind: 'load',
    address,
    destination: { kind: 'register', name: destination },
    source: { kind: 'memory', text: `[${base} + 0x${offset.toString(16)}]`, base, offset },
    confidence: 'medium',
  });

  it('exposes recovered structs through the STRIKE query surface', () => {
    const strike = createStrikeQuerySurface([
      load(0x1000, 'rax', 'rcx', 0x08),
      load(0x1004, 'rbx', 'rcx', 0x10),
      load(0x1008, 'rdx', 'rcx', 0x18),
    ]);

    expect(strike.getRecoveredStructs()).toEqual([
      {
        name: 'struct_rcx',
        base: 'rcx',
        fields: [
          { offset: 0x08, name: 'field_08', type: 'u64' },
          { offset: 0x10, name: 'field_10', type: 'u64' },
          { offset: 0x18, name: 'field_18', type: 'u64' },
        ],
        evidenceAddresses: [0x1000, 0x1004, 0x1008],
        advisoryOnly: true,
        authority: 'nest_type_recovery_not_gyre_verdict',
      },
    ]);
  });
});


describe('STRIKE xref query surface', () => {
  it('exposes buildXRefIndex for ProgramAnalysis callersOf queries', () => {
    const analysis = {
      schema: 'hexhawk.disassembly_program.v1' as const,
      advisoryOnly: true as const,
      authority: 'analysis_evidence_not_gyre_verdict' as const,
      arch: 'x86-64' as const,
      instructions: [],
      functions: [],
      basicBlocks: [],
      xrefs: [
        { kind: 'call' as const, from: 0x401020, to: 0x401000, confidence: 'high' as const, evidence: 'synthetic call' },
      ],
      importCalls: [],
      dataReferences: [],
      stringReferences: [],
      jumpTableCandidates: [],
      callGraph: { nodes: [], edges: [] },
      warnings: [],
    };

    expect(strike.buildXRefIndex(analysis).callersOf(0x401000)).toEqual([
      expect.objectContaining({ from: 0x401020, to: 0x401000, kind: 'call' }),
    ]);
  });
});


describe('STRIKE plugin hooks', () => {
  it('post-analysis hook receives analysis result', () => {
    clearStrikeHooksForTests();
    const seen: unknown[] = [];
    const result = { verdict: { classification: 'clean', confidence: 'high' }, marker: 1 };
    registerHook('post-analysis', context => seen.push((context as { result: unknown }).result));

    runStrikePostAnalysisHooks(result);

    expect(seen).toEqual([result]);
  });

  it('throwing hook does not prevent subsequent hooks from running', () => {
    clearStrikeHooksForTests();
    const seen: string[] = [];
    registerHook('post-analysis', () => { throw new Error('boom'); });
    registerHook('post-analysis', () => { seen.push('after'); });

    runStrikePostAnalysisHooks({ verdict: { classification: 'clean', confidence: 'high' } });

    expect(seen).toEqual(['after']);
  });

  it('custom-resolver hook override is called before built-in resolution', () => {
    clearStrikeHooksForTests();
    registerHook('custom-resolver', context => ({
      library: 'kernel32',
      name: (context as { importName: string }).importName,
      returnType: 'BOOL',
      parameters: [{ name: 'customPath', type: 'LPCWSTR' }],
      callingConvention: 'winapi',
    }));

    const proto = resolveImportPrototype('CreateFileW');

    expect(proto?.parameters[0]).toEqual({ name: 'customPath', type: 'LPCWSTR' });
  });

  it('hooks cannot modify GYRE verdict fields', () => {
    clearStrikeHooksForTests();
    const result = { verdict: { classification: 'clean', confidence: 'high' } };
    registerHook('post-analysis', context => {
      const r = (context as { result: typeof result }).result;
      r.verdict.classification = 'malicious';
      r.verdict.confidence = 'low';
    });

    runStrikePostAnalysisHooks(result);

    expect(result.verdict).toEqual({ classification: 'clean', confidence: 'high' });
  });
});
