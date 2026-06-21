import { describe, expect, it } from 'vitest';
import { decompile, type DisassembledInstruction } from '../utils/decompilerEngine';

const ins = (address: number, mnemonic: string, operands: string): DisassembledInstruction => ({ address, mnemonic, operands });

describe('NEST struct recovery from repeated offset accesses', () => {
  it('synthesizes a struct for 3 accesses to the same base at different offsets', () => {
    const result = decompile([
      ins(0x1000, 'mov', 'rax, [rcx + 0x08]'),
      ins(0x1004, 'mov', 'rbx, [rcx + 0x10]'),
      ins(0x1008, 'mov', 'rdx, [rcx + 0x18]'),
      ins(0x100c, 'ret', ''),
    ], null, { functionName: 'read_struct' });

    expect(result.recoveredStructs).toHaveLength(1);
    expect(result.recoveredStructs[0]).toMatchObject({
      name: 'struct_rcx',
      base: 'rcx',
      advisoryOnly: true,
      authority: 'nest_type_recovery_not_gyre_verdict',
    });
    expect(result.recoveredStructs[0].fields).toEqual([
      { offset: 0x08, name: 'field_08', type: 'u64' },
      { offset: 0x10, name: 'field_10', type: 'u64' },
      { offset: 0x18, name: 'field_18', type: 'u64' },
    ]);
  });

  it('does not synthesize a struct below the 3-offset threshold', () => {
    const result = decompile([
      ins(0x2000, 'mov', 'rax, [rcx + 0x08]'),
      ins(0x2004, 'mov', 'rbx, [rcx + 0x10]'),
      ins(0x2008, 'ret', ''),
    ], null, { functionName: 'not_struct' });

    expect(result.recoveredStructs).toEqual([]);
  });

  it('synthesizes separate structs for mixed base registers', () => {
    const result = decompile([
      ins(0x3000, 'mov', 'rax, [rcx + 0x08]'),
      ins(0x3004, 'mov', 'rbx, [rcx + 0x10]'),
      ins(0x3008, 'mov', 'rdx, [rcx + 0x18]'),
      ins(0x300c, 'mov', 'r8, [rsi + 0x20]'),
      ins(0x3010, 'mov', 'r9, [rsi + 0x28]'),
      ins(0x3014, 'mov', 'r10, [rsi + 0x30]'),
      ins(0x3018, 'ret', ''),
    ], null, { functionName: 'mixed_structs' });

    expect(result.recoveredStructs.map(s => s.base)).toEqual(['rcx', 'rsi']);
    expect(result.recoveredStructs[0].fields.map(f => f.name)).toEqual(['field_08', 'field_10', 'field_18']);
    expect(result.recoveredStructs[1].fields.map(f => f.name)).toEqual(['field_20', 'field_28', 'field_30']);
  });

  it('does not crash on functions with no pointer dereferences', () => {
    const result = decompile([
      ins(0x4000, 'xor', 'eax, eax'),
      ins(0x4004, 'ret', ''),
    ], null, { functionName: 'no_pointers' });

    expect(result.recoveredStructs).toEqual([]);
  });
});
