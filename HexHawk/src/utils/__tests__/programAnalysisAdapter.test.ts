import { describe, expect, it } from 'vitest';
import {
  buildAddressToBlockMap,
  buildProgramAnalysisAdapter,
  toProgramInstructions,
  xrefMapsFromProgramAnalysis,
  type AppDisassembledInstruction,
  type AdapterCfgGraph,
} from '../programAnalysisAdapter';

const fixture: AppDisassembledInstruction[] = [
  { address: 0x1000, mnemonic: 'push', operands: 'rbp' },
  { address: 0x1001, mnemonic: 'mov', operands: 'rbp, rsp' },
  { address: 0x1004, mnemonic: 'call', operands: '0x2000' },
  { address: 0x1009, mnemonic: 'cmp', operands: 'eax, 0' },
  { address: 0x100c, mnemonic: 'jne', operands: '0x1018' },
  { address: 0x1010, mnemonic: 'mov', operands: 'eax, 1' },
  { address: 0x1015, mnemonic: 'jmp', operands: '0x101c' },
  { address: 0x1018, mnemonic: 'xor', operands: 'eax, eax' },
  { address: 0x101c, mnemonic: 'ret', operands: '' },
  { address: 0x2000, mnemonic: 'push', operands: 'rbp' },
  { address: 0x2001, mnemonic: 'mov', operands: 'rbp, rsp' },
  { address: 0x2004, mnemonic: 'ret', operands: '' },
];

const cfg: AdapterCfgGraph = {
  nodes: [
    { id: 'entry', start: 0x1000, end: 0x100c, block_type: 'entry' },
    { id: 'then', start: 0x1010, end: 0x1015, block_type: 'normal' },
    { id: 'else', start: 0x1018, end: 0x101c, block_type: 'normal' },
  ],
  edges: [
    { source: 'entry', target: 'then', kind: 'fallthrough' },
    { source: 'entry', target: 'else', kind: 'branch' },
  ],
};

function mapToObject<K, V>(map: Map<K, V>): Record<string, unknown> {
  const entries: Array<[string, unknown]> = [];
  Array.from(map.entries()).forEach(([key, value]) => {
    entries.push([
      String(key),
      value instanceof Set ? Array.from(value).sort() : value,
    ]);
  });
  return Object.fromEntries(entries.sort(([a], [b]) => a.localeCompare(b)));
}

function serializeAdapterForBoundaryCheck(adapter: ReturnType<typeof buildProgramAnalysisAdapter>): string {
  return JSON.stringify({
    programAnalysis: adapter.programAnalysis,
    legacyFunctions: mapToObject(adapter.legacyAnalysis.functions),
    legacyBlockAnalysis: mapToObject(adapter.legacyAnalysis.blockAnalysis),
    referenceStrength: mapToObject(adapter.legacyAnalysis.referenceStrength),
    referencesMap: mapToObject(adapter.referencesMap),
    jumpTargetsMap: mapToObject(adapter.jumpTargetsMap),
    xrefTypes: mapToObject(adapter.xrefTypes),
    addressToBlockMap: mapToObject(adapter.addressToBlockMap),
    warnings: adapter.warnings,
  });
}

describe('ProgramAnalysis adapter for legacy static-analysis UI', () => {
  it('normalizes App disassembly into advisory ProgramAnalysis instructions', () => {
    const instructions = toProgramInstructions(fixture);

    expect(instructions).toHaveLength(fixture.length);
    expect(instructions[0]).toMatchObject({ address: 0x1000, mnemonic: 'push', operands: 'rbp', source: 'backend' });
  });

  it('builds ProgramAnalysis with advisory authority and no verdict fields', () => {
    const adapter = buildProgramAnalysisAdapter(fixture, cfg);
    const json = serializeAdapterForBoundaryCheck(adapter);

    expect(adapter.programAnalysis.schema).toBe('hexhawk.disassembly_program.v1');
    expect(adapter.programAnalysis.advisoryOnly).toBe(true);
    expect(adapter.programAnalysis.authority).toBe('analysis_evidence_not_gyre_verdict');
    expect(json).not.toContain('classification');
    expect(json).not.toContain('threatScore');
    expect(json).not.toContain('finalVerdict');
    expect(json).not.toContain('setVerdict');
  });

  it('proves ProgramAnalysis function ranges preserve legacy function discovery for the shared fixture', () => {
    const adapter = buildProgramAnalysisAdapter(fixture, cfg);
    const programFunctions = new Map(adapter.programAnalysis.functions.map(fn => [fn.startAddress, fn]));

    expect(Array.from(adapter.legacyAnalysis.functions.keys()).sort()).toEqual([0x1000, 0x2000]);
    expect(Array.from(programFunctions.keys()).sort()).toEqual([0x1000, 0x2000]);

    Array.from(adapter.legacyAnalysis.functions.entries()).forEach(([startAddress, legacyFunction]) => {
      const programFunction = programFunctions.get(startAddress);
      expect(programFunction, `missing ProgramAnalysis function ${startAddress.toString(16)}`).toBeDefined();
      expect(programFunction?.startAddress).toBe(legacyFunction.startAddress);
      expect(programFunction?.endAddress).toBe(legacyFunction.endAddress);
      expect(programFunction?.instructions).toHaveLength(
        fixture.filter(instruction => instruction.address >= legacyFunction.startAddress && instruction.address <= legacyFunction.endAddress).length,
      );
    });

    expect(programFunctions.get(0x1000)?.startReasons).toEqual(expect.arrayContaining(['entrypoint', 'prologue']));
    expect(programFunctions.get(0x2000)?.startReasons).toContain('known-call-target');
    expect(adapter.programAnalysis.callGraph.edges).toContainEqual(expect.objectContaining({ from: 0x1000, to: 0x2000, callsite: 0x1004 }));
  });

  it('keeps direct xrefs available through ProgramAnalysis and legacy XRefPanel maps', () => {
    const adapter = buildProgramAnalysisAdapter(fixture, cfg);
    const fromProgram = xrefMapsFromProgramAnalysis(adapter.programAnalysis);

    expect(adapter.programAnalysis.xrefs).toContainEqual(expect.objectContaining({ kind: 'call', from: 0x1004, to: 0x2000 }));
    expect(adapter.programAnalysis.xrefs).toContainEqual(expect.objectContaining({ kind: 'conditional-jump', from: 0x100c, to: 0x1018 }));
    expect(adapter.programAnalysis.xrefs).toContainEqual(expect.objectContaining({ kind: 'jump', from: 0x1015, to: 0x101c }));

    expect(adapter.referencesMap.get(0x2000)?.has(0x1004)).toBe(true);
    expect(adapter.jumpTargetsMap.get(0x1004)?.has(0x2000)).toBe(true);
    expect(adapter.xrefTypes.get(`${0x1004}:${0x2000}`)).toBe('CALL');

    expect(fromProgram.referencesMap.get(0x2000)?.has(0x1004)).toBe(true);
    expect(fromProgram.xrefTypes.get(`${0x100c}:${0x1018}`)).toBe('JMP_COND');
  });

  it('preserves legacy DATA and RIP_REL xrefs while ProgramAnalysis remains verdict-neutral', () => {
    const adapter = buildProgramAnalysisAdapter([
      { address: 0x3000, mnemonic: 'lea', operands: 'rax, [rip+0x20]' },
      { address: 0x3007, mnemonic: 'mov', operands: 'rcx, [0x401000]' },
    ], null);

    expect(adapter.xrefTypes.get(`${0x3000}:${0x3027}`)).toBe('RIP_REL');
    expect(adapter.xrefTypes.get(`${0x3007}:${0x401000}`)).toBe('DATA');
    expect(serializeAdapterForBoundaryCheck(adapter)).not.toContain('threatScore');
    expect(serializeAdapterForBoundaryCheck(adapter)).not.toContain('classification');
  });

  it('proves ProgramAnalysis basicBlocks improve on legacy CFG helpers without replacing visible CFG shape', () => {
    const adapter = buildProgramAnalysisAdapter(fixture, cfg);
    const addressToBlock = buildAddressToBlockMap(cfg);
    const programBlockStarts = adapter.programAnalysis.basicBlocks.map(block => block.startAddress);

    expect(adapter.legacyAnalysis.blockAnalysis.get('entry')).toMatchObject({ blockId: 'entry', blockType: 'entry', branchingComplexity: 2 });
    expect(Array.from(adapter.legacyAnalysis.blockAnalysis.keys()).sort()).toEqual(['else', 'entry', 'then']);
    expect(addressToBlock.get(0x1000)).toEqual({ blockId: 'entry', start: 0x1000, end: 0x100c });
    expect(addressToBlock.get(0x100b)).toEqual({ blockId: 'entry', start: 0x1000, end: 0x100c });
    expect(addressToBlock.has(0x100c)).toBe(false);

    expect(programBlockStarts).toEqual([0x1000, 0x1010, 0x1018, 0x101c, 0x2000]);
    expect(adapter.programAnalysis.basicBlocks.find(block => block.startAddress === 0x1000)?.successors).toEqual([0x1010, 0x1018]);
    expect(adapter.programAnalysis.basicBlocks.find(block => block.startAddress === 0x1010)?.successors).toEqual([0x101c]);
  });

  it('preserves warning and uncertainty records from ProgramAnalysis instead of silently dropping them', () => {
    const adapter = buildProgramAnalysisAdapter([
      { address: 0x4000, mnemonic: 'nop', operands: '' },
      { address: 0x4001, mnemonic: 'add', operands: 'eax, 1' },
    ], null);

    expect(adapter.programAnalysis.functions[0]?.confidence).toBe('low');
    expect(adapter.programAnalysis.functions[0]?.warnings.map(warning => warning.kind)).toEqual(
      expect.arrayContaining(['uncertain-function-start', 'uncertain-function-end']),
    );
    expect(adapter.warnings.map(warning => warning.kind)).toEqual(
      expect.arrayContaining(['uncertain-function-start', 'uncertain-function-end']),
    );
    expect(adapter.warnings).toEqual(adapter.programAnalysis.warnings);
  });

  it('keeps adapter outputs advisory-only with explicit authority markers and no verdict mutation surface', () => {
    const adapter = buildProgramAnalysisAdapter(fixture, cfg);

    expect(Object.keys(adapter).sort()).toEqual([
      'addressToBlockMap',
      'jumpTargetsMap',
      'legacyAnalysis',
      'programAnalysis',
      'referencesMap',
      'warnings',
      'xrefTypes',
    ]);
    expect(adapter.programAnalysis).toMatchObject({
      advisoryOnly: true,
      authority: 'analysis_evidence_not_gyre_verdict',
    });
    expect('classification' in adapter.programAnalysis).toBe(false);
    expect('threatScore' in adapter.programAnalysis).toBe(false);
    expect('verdict' in adapter).toBe(false);
    expect('setVerdict' in adapter).toBe(false);
  });

  it('populates ProgramAnalysis importCalls from backend PE import table before xref symbols', () => {
    const adapter = buildProgramAnalysisAdapter([
      { address: 0x4000, mnemonic: 'push', operands: 'rbp' },
      { address: 0x4001, mnemonic: 'mov', operands: 'rbp, rsp' },
      { address: 0x4004, mnemonic: 'ret', operands: '' },
    ], null, [
      { name: 'CreateFileW', dll: 'KERNEL32.dll', thunk_va: 0x140002300 },
    ]);

    expect(adapter.programAnalysis.importCalls).toContainEqual(expect.objectContaining({
      callAddress: 0x140002300,
      targetAddress: 0x140002300,
      importName: 'CreateFileW',
      moduleName: 'KERNEL32.dll',
      confidence: 'high',
    }));
    expect(adapter.programAnalysis.importCalls[0]?.evidence).toContain('PE import table KERNEL32.dll!CreateFileW');
  });

  it('deduplicates matching PE table imports and xref-detected import calls', () => {
    const adapter = buildProgramAnalysisAdapter([
      { address: 0x4000, mnemonic: 'push', operands: 'rbp' },
      { address: 0x4001, mnemonic: 'mov', operands: 'rbp, rsp' },
      { address: 0x4004, mnemonic: 'call', operands: '0x5000' },
      { address: 0x4009, mnemonic: 'ret', operands: '' },
      { address: 0x5000, mnemonic: 'jmp', operands: '0x6000', symbol: 'KERNEL32.dll!CreateFileW' },
    ], null, [
      { name: 'CreateFileW', dll: 'KERNEL32.dll', thunk_va: 0x5000 },
    ]);

    const matches = adapter.programAnalysis.importCalls.filter(
      call => call.targetAddress === 0x5000 && call.importName === 'CreateFileW' && call.moduleName === 'KERNEL32.dll',
    );
    expect(matches).toHaveLength(1);
    expect(matches[0].evidence).toContain('PE import table');
  });


  it('does not require callingConvention to be present on ProgramAnalysis functions', () => {
    const adapter = buildProgramAnalysisAdapter(fixture, cfg);
    const withoutConvention = {
      ...adapter.programAnalysis,
      functions: adapter.programAnalysis.functions.map(({ callingConvention: _callingConvention, ...fn }) => fn),
    };

    expect(() => JSON.stringify(withoutConvention.functions)).not.toThrow();
    expect(withoutConvention.functions[0]).not.toHaveProperty('callingConvention');
    expect(JSON.stringify(withoutConvention)).not.toContain('threatScore');
  });

});
