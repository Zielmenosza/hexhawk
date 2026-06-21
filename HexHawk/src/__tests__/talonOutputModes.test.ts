import { describe, expect, it } from 'vitest';
import { decompile, type DisassembledInstruction } from '../utils/decompilerEngine';

const ins = (address: number, mnemonic: string, operands: string): DisassembledInstruction => ({ address, mnemonic, operands });

const CREATE_FILE_CALL: DisassembledInstruction[] = [
  ins(0x1000, 'mov', 'rcx, rdx'),
  ins(0x1004, 'mov', 'rdx, 0x80000000'),
  ins(0x1008, 'call', 'CreateFileW'),
  ins(0x100d, 'ret', ''),
];

describe('TALON compact and annotated output modes', () => {
  it('formats known import calls compactly by default with no type comments', () => {
    const result = decompile(CREATE_FILE_CALL, null, { functionName: 'open_file' });
    const text = result.lines.map(line => line.text).join('\n');

    expect(text).toContain('CreateFileW(fileName, 0x80000000');
    expect(text).not.toContain('/* LPCWSTR lpFileName */');
    expect(text).not.toContain('/* HANDLE */');
  });

  it('formats known import calls with parameter type/name comments in annotated mode', () => {
    const result = decompile(CREATE_FILE_CALL, null, { functionName: 'open_file', outputMode: 'annotated' });
    const text = result.lines.map(line => line.text).join('\n');

    expect(text).toContain('/* HANDLE */ CreateFileW(');
    expect(text).toContain('/* LPCWSTR lpFileName */ fileName');
    expect(text).toContain('/* DWORD dwDesiredAccess */ 0x80000000');
  });
});
