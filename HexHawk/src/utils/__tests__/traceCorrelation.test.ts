import { describe, expect, it } from 'vitest';
import { buildProgramAnalysis } from '../disassemblyAnalysis';
import type { Instruction } from '../disassemblyModel';
import { parseHexHawkTraceJson } from '../traceModel';
import { correlateTraceSession } from '../traceCorrelation';

function fixtureProgram() {
  const instructions: Instruction[] = [
    { address: 0x140001000, mnemonic: 'push', operands: 'rbp' },
    { address: 0x140001001, mnemonic: 'mov', operands: 'rbp, rsp' },
    { address: 0x140001010, mnemonic: 'call', operands: '0x140001050' },
    { address: 0x140001018, mnemonic: 'jne', operands: '0x140001030' },
    { address: 0x140001020, mnemonic: 'call', operands: 'qword ptr [VirtualAlloc]' },
    { address: 0x140001030, mnemonic: 'ret', operands: '' },
    { address: 0x140001050, mnemonic: 'push', operands: 'rbp' },
    { address: 0x140001051, mnemonic: 'mov', operands: 'rbp, rsp' },
    { address: 0x140001060, mnemonic: 'ret', operands: '' },
  ];
  return buildProgramAnalysis(instructions);
}

describe('traceCorrelation', () => {
  it('correlates trace addresses to instructions, functions, and basic blocks', () => {
    const session = parseHexHawkTraceJson(JSON.stringify({
      schema: 'hexhawk.trace.v1',
      events: [
        { kind: 'call', address: '0x140001010', targetAddress: '0x140001050' },
        { kind: 'branch', address: '0x140001018', targetAddress: '0x140001030', taken: true },
      ],
    }));

    const report = correlateTraceSession(session, fixtureProgram());

    expect(report.advisoryOnly).toBe(true);
    expect(report.authority).toBe('runtime_trace_correlation_not_gyre_verdict');
    expect(report.summary.eventCount).toBe(2);
    expect(report.summary.resolvedAddressCount).toBe(2);
    expect(report.summary.functionCoverageCount).toBe(1);
    expect(report.summary.basicBlockCoverageCount).toBeGreaterThanOrEqual(1);
    expect(report.eventCorrelations[0].instruction?.address).toBe(0x140001010);
    expect(report.eventCorrelations[0].function?.startAddress).toBe(0x140001000);
    expect(report.eventCorrelations[0].basicBlock?.startAddress).toBe(0x140001000);
  });

  it('matches API call events to known imports when available', () => {
    const session = parseHexHawkTraceJson(JSON.stringify({
      schema: 'hexhawk.trace.v1',
      events: [
        { kind: 'api-call', address: '0x140001020', moduleName: 'kernel32.dll', apiName: 'VirtualAlloc' },
      ],
    }));

    const report = correlateTraceSession(session, fixtureProgram(), [
      { name: 'VirtualAlloc', library: 'kernel32.dll' },
    ]);

    expect(report.summary.apiCallCount).toBe(1);
    expect(report.summary.resolvedApiCallCount).toBe(1);
    expect(report.eventCorrelations[0].apiImport).toMatchObject({ name: 'VirtualAlloc' });
  });

  it('emits unresolved address warnings for trace addresses outside the program model', () => {
    const session = parseHexHawkTraceJson(JSON.stringify({
      schema: 'hexhawk.trace.v1',
      events: [
        { kind: 'branch', address: '0x150000000', targetAddress: '0x150000100' },
      ],
    }));

    const report = correlateTraceSession(session, fixtureProgram());

    expect(report.summary.unresolvedAddressCount).toBe(1);
    expect(report.warnings.some(warning => warning.message.includes('0x150000000'))).toBe(true);
    expect(report.eventCorrelations[0].resolved).toBe(false);
  });

  it('does not expose or mutate GYRE verdict authority fields', () => {
    const verdict = { classification: 'clean', confidence: 91 };
    const before = { ...verdict };
    const session = parseHexHawkTraceJson(JSON.stringify({
      schema: 'hexhawk.trace.v1',
      events: [{ kind: 'api-call', address: '0x140001020', apiName: 'VirtualAlloc' }],
    }));

    const report = correlateTraceSession(session, fixtureProgram(), [{ name: 'VirtualAlloc', library: 'kernel32.dll' }]);

    expect(verdict).toEqual(before);
    expect(report).not.toHaveProperty('classification');
    expect(report).not.toHaveProperty('confidence');
    expect(report.session.authority).toBe('runtime_trace_evidence_not_gyre_verdict');
  });
});
