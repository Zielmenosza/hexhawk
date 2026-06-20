import { describe, expect, it } from 'vitest';
import { decompile, type DisassembledInstruction } from '../decompilerEngine';
import { liftInstructionToDecompilerIr, liftInstructionsToDecompilerIr } from '../decompilerIr';
import { computeDecompilerMaturitySummary } from '../decompilerMaturity';

describe('explicit decompiler IR foundation', () => {
  it('lifts common instructions into advisory IR nodes', () => {
    expect(liftInstructionToDecompilerIr({ address: 0x1000, mnemonic: 'mov', operands: 'rax, rcx' })[0])
      .toEqual(expect.objectContaining({ kind: 'assignment', address: 0x1000, confidence: 'high' }));

    expect(liftInstructionToDecompilerIr({ address: 0x1004, mnemonic: 'mov', operands: 'rax, [rbp - 0x8]' })[0])
      .toEqual(expect.objectContaining({ kind: 'load', address: 0x1004 }));

    expect(liftInstructionToDecompilerIr({ address: 0x1008, mnemonic: 'mov', operands: '[rbp - 0x10], rcx' })[0])
      .toEqual(expect.objectContaining({ kind: 'store', address: 0x1008 }));

    expect(liftInstructionToDecompilerIr({ address: 0x100c, mnemonic: 'add', operands: 'rax, 4' })[0])
      .toEqual(expect.objectContaining({ kind: 'arithmetic', operator: '+', address: 0x100c }));

    expect(liftInstructionToDecompilerIr({ address: 0x1010, mnemonic: 'cmp', operands: 'rax, 0' })[0])
      .toEqual(expect.objectContaining({ kind: 'compare', operator: 'cmp', address: 0x1010 }));

    expect(liftInstructionToDecompilerIr({ address: 0x1014, mnemonic: 'jne', operands: '0x1020' }, 0x1018)[0])
      .toEqual(expect.objectContaining({ kind: 'conditional-branch', target: 0x1020, fallthrough: 0x1018 }));
  });

  it('keeps unknown instructions visible as warning nodes', () => {
    const nodes = liftInstructionToDecompilerIr({ address: 0x2000, mnemonic: 'ud2', operands: '' });

    expect(nodes[0]).toEqual(expect.objectContaining({
      kind: 'unknown',
      address: 0x2000,
      confidence: 'unknown',
    }));
    expect(nodes[0]).toHaveProperty('warning');
  });

  it('recovers call arguments from recent Windows x64 argument-register setup', () => {
    const instructions: DisassembledInstruction[] = [
      { address: 0x3100, mnemonic: 'mov', operands: 'rcx, [rbp - 0x8]' },
      { address: 0x3104, mnemonic: 'mov', operands: 'rdx, 0x20' },
      { address: 0x3108, mnemonic: 'call', operands: '0x401000' },
    ];

    const call = liftInstructionsToDecompilerIr(instructions).find(
      (node): node is Extract<ReturnType<typeof liftInstructionsToDecompilerIr>[number], { kind: 'call' }> => node.kind === 'call',
    );

    expect(call?.args).toHaveLength(2);
    expect(call?.args[0]).toEqual(expect.objectContaining({ kind: 'stack-variable-candidate', name: 'local_8' }));
    expect(call?.args[1]).toEqual(expect.objectContaining({ kind: 'constant', value: 0x20 }));
  });

  it('recovers call arguments from recent System V argument-register setup', () => {
    const instructions: DisassembledInstruction[] = [
      { address: 0x3200, mnemonic: 'mov', operands: 'rdi, rax' },
      { address: 0x3204, mnemonic: 'mov', operands: 'rsi, [rbp - 0x10]' },
      { address: 0x3208, mnemonic: 'call', operands: 'puts' },
    ];

    const call = liftInstructionsToDecompilerIr(instructions).find(
      (node): node is Extract<ReturnType<typeof liftInstructionsToDecompilerIr>[number], { kind: 'call' }> => node.kind === 'call',
    );

    expect(call?.unresolved).toBe(true);
    expect(call?.args).toHaveLength(2);
    expect(call?.args[0]).toEqual(expect.objectContaining({ kind: 'register', name: 'rax' }));
    expect(call?.args[1]).toEqual(expect.objectContaining({ kind: 'stack-variable-candidate', name: 'local_10' }));
  });

  it('represents direct and unresolved call nodes honestly', () => {
    const direct = liftInstructionToDecompilerIr({ address: 0x3000, mnemonic: 'call', operands: '0x401000' })[0];
    const indirect = liftInstructionToDecompilerIr({ address: 0x3005, mnemonic: 'call', operands: 'rax' })[0];

    expect(direct).toEqual(expect.objectContaining({ kind: 'call', target: 0x401000, unresolved: false, confidence: 'high' }));
    expect(indirect).toEqual(expect.objectContaining({ kind: 'call', target: null, name: 'rax', unresolved: true, confidence: 'medium' }));
  });

  it('scores maturity with fallback mode, confidence, warnings, and proof limits', () => {
    const instructions: DisassembledInstruction[] = [
      { address: 0x4000, mnemonic: 'mov', operands: '[rbp - 0x8], rcx' },
      { address: 0x4004, mnemonic: 'call', operands: 'rax' },
      { address: 0x4009, mnemonic: 'jmp', operands: 'rax' },
      { address: 0x400d, mnemonic: 'ud2', operands: '' },
    ];
    const irNodes = liftInstructionsToDecompilerIr(instructions);
    const maturity = computeDecompilerMaturitySummary({
      instructions,
      irNodes,
      irBlocks: [],
      lines: [],
      warnings: ['manual test warning'],
    });

    expect(maturity.advisoryOnly).toBe(true);
    expect(maturity.authority).toBe('talon_decompiler_advisory_not_gyre_verdict');
    expect(maturity.fallbackMode).toBe('instruction-fallback');
    expect(maturity.confidence).toBe('low');
    expect(maturity.unknownInstructionCount).toBeGreaterThanOrEqual(2);
    expect(maturity.unresolvedCalls).toBe(1);
    expect(maturity.unresolvedIndirectJumps).toBe(1);
    expect(maturity.recoveredVariablesCount).toBeGreaterThanOrEqual(1);
    expect(maturity.warnings.join(' ')).toContain('manual test warning');
    expect(maturity.proofLimits.join(' ')).toContain('Pseudo-C is a readable analyst aid');
    expect(JSON.stringify(maturity)).not.toContain('classification');
    expect(JSON.stringify(maturity)).not.toContain('source_engine');
  });

  it('attaches explicit IR maturity to existing decompile output without changing verdict authority', () => {
    const instructions: DisassembledInstruction[] = [
      { address: 0x5000, mnemonic: 'mov', operands: '[rbp - 0x8], rcx' },
      { address: 0x5004, mnemonic: 'mov', operands: 'rax, [rbp - 0x8]' },
      { address: 0x5008, mnemonic: 'call', operands: '0x7000' },
      { address: 0x500d, mnemonic: 'ret', operands: '' },
    ];

    const result = decompile(instructions, null, { startAddress: 0x5000, endAddress: 0x500d, functionName: 'explicit_ir_fixture' });

    expect(result.maturity.explicitIrSummary.schema).toBe('hexhawk.decompiler_maturity.explicit_ir.v1');
    expect(result.maturity.explicitIrSummary.liftedInstructionCount).toBeGreaterThanOrEqual(3);
    expect(result.maturity.explicitIrSummary.recoveredCallsCount).toBe(1);
    expect(result.maturity.explicitIrSummary.recoveredVariablesCount).toBeGreaterThanOrEqual(1);
    expect(result.maturity.explicitIrSummary.proofLimits.join(' ')).toContain('does not change GYRE final decisions');
    expect(JSON.stringify(result.maturity.explicitIrSummary)).not.toContain('malwareFamily');
    expect(JSON.stringify(result.maturity.explicitIrSummary)).not.toContain('source_engine');
  });
});
