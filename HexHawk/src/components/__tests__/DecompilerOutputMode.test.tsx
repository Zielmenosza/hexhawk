import { describe, expect, it, beforeEach } from 'vitest';
import {
  DECOMPILER_OUTPUT_MODE_STORAGE_KEY,
  buildDeepDecompilerNextSteps,
  loadDecompilerOutputMode,
  persistDecompilerOutputMode,
} from '../DecompilerView';

describe('DecompilerView output-mode preference', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it('defaults to compact mode', () => {
    expect(loadDecompilerOutputMode()).toBe('compact');
  });

  it('persists annotated mode across a simulated reload', () => {
    persistDecompilerOutputMode('annotated');
    expect(localStorage.getItem(DECOMPILER_OUTPUT_MODE_STORAGE_KEY)).toBe('annotated');
    expect(loadDecompilerOutputMode()).toBe('annotated');
  });
});


describe('buildDeepDecompilerNextSteps', () => {
  const baseResult = {
    logicRegions: [],
    recoveredStructs: [],
    maturity: {
      instructionSummary: { total: 10, lifted: 10, unknown: 0, unknownAddresses: [], failedDecodeRanges: [] },
      cfgSummary: { blockCount: 2, edgeCount: 1, backEdgeCount: 0, unreachableBlockCount: 0, unreachableBlocks: [], fallbackPartitioningUsed: false },
      callArgumentRecovery: { callCount: 0, recoveredCallCount: 0, unresolvedCallCount: 0, recoveredArgumentCount: 0, registerWindowCount: 0, stackWindowCount: 0, registerStackWindowCount: 0 },
      stackFrameSummary: { localCount: 0, stackArgCount: 0, registerParamCount: 0, localNames: [], stackArgNames: [], registerParamNames: [] },
      pseudocodeQuality: { uncertainLineCount: 0, warningCount: 0, conservativeRewriteCount: 0, logicRegionCount: 0 },
      explicitIrSummary: { unknownInstructionCount: 0 },
    },
  } as any;

  it('prioritizes unknown opcodes, unresolved calls, and live-step CFG reconciliation', () => {
    const steps = buildDeepDecompilerNextSteps({
      ...baseResult,
      logicRegions: [{ address: 0x401020 }],
      recoveredStructs: [{ name: 'struct_rcx' }],
      maturity: {
        ...baseResult.maturity,
        instructionSummary: { ...baseResult.maturity.instructionSummary, unknown: 2, unknownAddresses: [0x401000, 0x401010] },
        cfgSummary: { ...baseResult.maturity.cfgSummary, backEdgeCount: 1, fallbackPartitioningUsed: true },
        callArgumentRecovery: { ...baseResult.maturity.callArgumentRecovery, callCount: 3, recoveredCallCount: 1, unresolvedCallCount: 2 },
        explicitIrSummary: { unknownInstructionCount: 2 },
      },
    });

    expect(steps.join('\n')).toContain('Prioritize unknown-opcode lift at 0x401000, 0x401010');
    expect(steps.join('\n')).toContain('Recover call arguments for 2/3 unresolved call(s)');
    expect(steps.join('\n')).toContain('live STRIKE stepping');
    expect(steps.join('\n')).toContain('recovered struct candidates');
  });
});
