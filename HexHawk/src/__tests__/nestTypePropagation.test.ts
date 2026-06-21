import { describe, expect, it } from 'vitest';
import { decompile, type DisassembledInstruction } from '../utils/decompilerEngine';

const ins = (address: number, mnemonic: string, operands: string): DisassembledInstruction => ({ address, mnemonic, operands });

describe('NEST import prototype type propagation into TALON output', () => {
  it('annotates a variable passed as CreateFileW lpFileName with LPCWSTR metadata', () => {
    const result = decompile([
      ins(0x1000, 'mov', 'rcx, rdx'),
      ins(0x1005, 'call', 'CreateFileW'),
      ins(0x100a, 'ret', ''),
    ], null, { functionName: 'open_file' });

    const call = result.irBlocks.flatMap(block => block.stmts).find(stmt => stmt.op === 'call' && stmt.name === 'CreateFileW');
    expect(call?.op).toBe('call');
    if (call?.op !== 'call') throw new Error('expected CreateFileW call');
    expect(call.args?.[0]).toMatchObject({ inferredType: 'LPCWSTR', inferredName: 'fileName' });
  });

  it('does not annotate variables passed to unknown imports and does not crash', () => {
    const result = decompile([
      ins(0x2000, 'mov', 'rcx, 0x401000'),
      ins(0x2005, 'call', 'UnknownVendorApi'),
      ins(0x200a, 'ret', ''),
    ], null, { functionName: 'unknown_api' });

    const call = result.irBlocks.flatMap(block => block.stmts).find(stmt => stmt.op === 'call' && stmt.name === 'UnknownVendorApi');
    expect(call?.op).toBe('call');
    if (call?.op !== 'call') throw new Error('expected unknown call');
    expect(call.args?.[0]).not.toHaveProperty('inferredType');
  });

  it('uses type-informed names in TALON output for annotated call arguments', () => {
    const result = decompile([
      ins(0x3000, 'mov', 'rcx, rdx'),
      ins(0x3005, 'call', 'CreateFileW'),
      ins(0x300a, 'ret', ''),
    ], null, { functionName: 'open_file' });

    const text = result.lines.map(line => line.text).join('\n');
    expect(text).toContain('lpFileName: fileName');
    expect(text).not.toContain('lpFileName: param_0');
  });
});
