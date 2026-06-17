import { describe, expect, it } from 'vitest';
import {
  classifyRawTraceEvent,
  parseHexHawkTraceJson,
  parseTraceAddress,
  TraceParseError,
} from '../traceModel';

describe('traceModel imported HexHawk JSON traces', () => {
  it('parses a valid documented HexHawk trace schema as advisory evidence', () => {
    const session = parseHexHawkTraceJson(JSON.stringify({
      schema: 'hexhawk.trace.v1',
      tool: 'unit-test-fixture',
      target: 'sample.exe',
      events: [
        { kind: 'module-load', moduleName: 'sample.exe', baseAddress: '0x140000000' },
        { kind: 'thread-event', action: 'start', threadId: 1 },
        { kind: 'breakpoint-hit', address: '0x140001000' },
        { kind: 'call', address: '0x140001010', targetAddress: '0x140001050', targetName: 'sub_140001050' },
        { kind: 'branch', address: '0x140001018', targetAddress: '0x140001030', taken: true },
        { kind: 'api-call', address: '0x140001020', moduleName: 'kernel32.dll', apiName: 'VirtualAlloc' },
        { kind: 'memory-access', address: '0x140001028', memoryAddress: '0x20000000', access: 'write', size: 8 },
      ],
    }));

    expect(session.schema).toBe('hexhawk.trace.v1');
    expect(session.advisoryOnly).toBe(true);
    expect(session.authority).toBe('runtime_trace_evidence_not_gyre_verdict');
    expect(session.events.map(event => event.kind)).toEqual([
      'module-load',
      'thread-event',
      'breakpoint-hit',
      'call',
      'branch',
      'api-call',
      'memory-access',
    ]);
    expect(session.warnings).toEqual([]);
  });

  it('rejects malformed JSON with a parse warning', () => {
    expect(() => parseHexHawkTraceJson('{not valid json')).toThrow(TraceParseError);
    try {
      parseHexHawkTraceJson('{not valid json');
    } catch (error) {
      expect(error).toBeInstanceOf(TraceParseError);
      expect((error as TraceParseError).warnings[0].kind).toBe('malformed-json');
    }
  });

  it('rejects unsupported schemas instead of rendering false timeline rows', () => {
    expect(() => parseHexHawkTraceJson(JSON.stringify({ trace: [] }))).toThrow(TraceParseError);
  });

  it('classifies event shapes without requiring full live debugger state', () => {
    expect(classifyRawTraceEvent({ apiName: 'VirtualAlloc' })).toBe('api-call');
    expect(classifyRawTraceEvent({ instruction: 'call qword ptr [VirtualAlloc]' })).toBe('call');
    expect(classifyRawTraceEvent({ text: 'jne 0x140001020' })).toBe('branch');
    expect(classifyRawTraceEvent({ label: 'INT3 breakpoint' })).toBe('breakpoint-hit');
  });

  it('parses stable address forms used by JSON fixtures', () => {
    expect(parseTraceAddress('0x140001010')).toBe(0x140001010);
    expect(parseTraceAddress('1400010A0')).toBe(0x1400010a0);
    expect(parseTraceAddress('42')).toBe(42);
  });
});
