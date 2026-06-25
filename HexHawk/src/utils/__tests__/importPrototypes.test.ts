import { describe, expect, it } from 'vitest';
import { liftInstructionToDecompilerIr } from '../decompilerIr';
import { decompile, type DisassembledInstruction } from '../decompilerEngine';
import { formatImportPrototype, resolveConstantAnnotation, resolveImportPrototype } from '../strikeEngine';

describe('import prototype resolution', () => {
  it('resolves CreateFileW with named Win32 parameters', () => {
    const call = liftInstructionToDecompilerIr({ address: 0x1000, mnemonic: 'call', operands: 'CreateFileW' })[0];

    expect(call.kind).toBe('call');
    if (call.kind !== 'call') return;
    expect(call.resolvedPrototype?.name).toBe('CreateFileW');
    expect(call.resolvedPrototype?.parameters.map(p => p.name)).toEqual([
      'lpFileName',
      'dwDesiredAccess',
      'dwShareMode',
      'lpSecurityAttributes',
      'dwCreationDisposition',
      'dwFlagsAndAttributes',
      'hTemplateFile',
    ]);
  });

  it('returns undefined for unknown imports without throwing', () => {
    const call = liftInstructionToDecompilerIr({ address: 0x1000, mnemonic: 'call', operands: 'MysteryImport' })[0];

    expect(call.kind).toBe('call');
    if (call.kind !== 'call') return;
    expect(call.resolvedPrototype).toBeUndefined();
  });

  it('TALON formats CreateFileW calls with parameter names in annotated mode', () => {
    const instructions: DisassembledInstruction[] = [
      { address: 0x2000, mnemonic: 'mov', operands: 'rcx, 0x1000' },
      { address: 0x2004, mnemonic: 'mov', operands: 'rdx, 0x80000000' },
      { address: 0x2008, mnemonic: 'mov', operands: 'r8, 1' },
      { address: 0x200c, mnemonic: 'mov', operands: 'r9, 0' },
      { address: 0x2010, mnemonic: 'mov', operands: 'qword ptr [rsp + 0x20], 3' },
      { address: 0x2014, mnemonic: 'mov', operands: 'qword ptr [rsp + 0x28], 0x80' },
      { address: 0x2018, mnemonic: 'mov', operands: 'qword ptr [rsp + 0x30], 0' },
      { address: 0x201c, mnemonic: 'call', operands: 'CreateFileW' },
      { address: 0x2021, mnemonic: 'ret', operands: '' },
    ];

    const result = decompile(instructions, null, { functionName: 'create_file_call', outputMode: 'annotated' });
    const text = result.lines.map(l => l.text).join('\n');
    const call = result.irBlocks.flatMap(b => b.stmts).find(s => s.op === 'call');

    expect(call?.op === 'call' ? call.resolvedPrototype?.name : undefined).toBe('CreateFileW');
    expect(text).toContain('/* HANDLE */ CreateFileW(');
    expect(text).toContain('/* LPCWSTR lpFileName */ 0x1000');
    expect(text).toContain('/* DWORD dwCreationDisposition */ OPEN_EXISTING /* 0x3 */');
    expect(text).not.toContain('rN_M');
  });

  it('exposes prototype lookup through the STRIKE query surface exports', () => {
    const proto = resolveImportPrototype('kernel32.CreateFileW');

    expect(proto?.name).toBe('CreateFileW');
    expect(formatImportPrototype(proto!)).toContain('HANDLE CreateFileW');
  });

  it('resolves Win32 constant annotations and bitmasks for known API parameters', () => {
    expect(resolveConstantAnnotation('CreateFileW', 1, 0x80000000)).toBe('GENERIC_READ');
    expect(resolveConstantAnnotation('CreateFileW', 2, 3)).toBe('FILE_SHARE_READ | FILE_SHARE_WRITE');
    expect(resolveConstantAnnotation('VirtualAlloc', 2, 0x3000)).toBe('MEM_COMMIT | MEM_RESERVE');
    expect(resolveConstantAnnotation('VirtualAlloc', 3, 0x40)).toBe('PAGE_EXECUTE_READWRITE');
    expect(resolveConstantAnnotation('UnknownFunction', 1, 0x80000000)).toBeUndefined();
  });

  it('TALON formats CreateFileW call constants with semantic Win32 names', () => {
    const instructions: DisassembledInstruction[] = [
      { address: 0x3000, mnemonic: 'mov', operands: 'rcx, 0x1000' },
      { address: 0x3004, mnemonic: 'mov', operands: 'rdx, 0x80000000' },
      { address: 0x3008, mnemonic: 'mov', operands: 'r8, 3' },
      { address: 0x300c, mnemonic: 'mov', operands: 'r9, 0' },
      { address: 0x3010, mnemonic: 'mov', operands: 'qword ptr [rsp + 0x20], 3' },
      { address: 0x3014, mnemonic: 'mov', operands: 'qword ptr [rsp + 0x28], 0x80' },
      { address: 0x3018, mnemonic: 'mov', operands: 'qword ptr [rsp + 0x30], 0' },
      { address: 0x301c, mnemonic: 'call', operands: 'CreateFileW' },
      { address: 0x3021, mnemonic: 'ret', operands: '' },
    ];

    const result = decompile(instructions, null, { functionName: 'create_file_constants', outputMode: 'annotated' });
    const text = result.lines.map(l => l.text).join('\n');

    expect(text).toContain('GENERIC_READ /* 0x80000000 */');
    expect(text).toContain('FILE_SHARE_READ | FILE_SHARE_WRITE /* 0x3 */');
    expect(text).toContain('OPEN_EXISTING /* 0x3 */');
    expect(text).toContain('FILE_ATTRIBUTE_NORMAL /* 0x80 */');
  });

});
