import { describe, expect, it } from 'vitest';
import { buildProgramAnalysis } from '../utils/disassemblyAnalysis';
import type { Instruction } from '../utils/disassemblyModel';

function generateSyntheticInstructions(count: number): Instruction[] {
  const instructions: Instruction[] = [];
  const base = 0x401000;
  for (let index = 0; index < count; index += 1) {
    const address = base + index * 4;
    const bucket = index % 20;
    if (bucket < 12) {
      instructions.push({
        address,
        mnemonic: bucket % 3 === 0 ? 'mov' : bucket % 3 === 1 ? 'add' : 'xor',
        operands: bucket % 3 === 0 ? 'rax, rcx' : bucket % 3 === 1 ? 'rax, 1' : 'edx, edx',
        byteLength: 4,
        source: 'synthetic-test',
      });
      continue;
    }
    if (bucket < 15) {
      const target = base + Math.min(count - 1, index + 16) * 4;
      instructions.push({ address, mnemonic: 'call', operands: `0x${target.toString(16)}`, byteLength: 4, source: 'synthetic-test' });
      continue;
    }
    if (bucket < 18) {
      const target = base + Math.min(count - 1, index + 8) * 4;
      instructions.push({ address, mnemonic: bucket % 2 === 0 ? 'jmp' : 'jne', operands: `0x${target.toString(16)}`, byteLength: 4, source: 'synthetic-test' });
      continue;
    }
    instructions.push({
      address,
      mnemonic: bucket === 18 ? 'push' : 'ret',
      operands: bucket === 18 ? 'rbp' : '',
      byteLength: 4,
      source: 'synthetic-test',
    });
  }
  return instructions;
}

describe('disassembly performance baseline', () => {
  it('buildProgramAnalysis on 5000-instruction synthetic binary completes within 3000ms', () => {
    const instructions = generateSyntheticInstructions(5000);
    const start = performance.now();
    buildProgramAnalysis(instructions);
    const elapsed = performance.now() - start;

    expect(elapsed).toBeLessThan(3000);
  });
});
