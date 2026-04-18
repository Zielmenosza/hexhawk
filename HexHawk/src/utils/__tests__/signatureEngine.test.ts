import { describe, it, expect } from 'vitest';
import { normalizeInstruction, scanSignatures } from '../../utils/signatureEngine';
import type { DisassembledInstruction } from '../../utils/decompilerEngine';

// ── normalizeInstruction ──────────────────────────────────────────────────────

describe('normalizeInstruction', () => {
  it('lowercases mnemonic', () => {
    expect(normalizeInstruction('PUSH', 'RBP')).toContain('push');
  });

  it('abstracts 64-bit registers to %r', () => {
    const norm = normalizeInstruction('mov', 'rax, rbx');
    expect(norm).toContain('%r');
    expect(norm).not.toContain('rax');
    expect(norm).not.toContain('rbx');
  });

  it('abstracts 32-bit registers to %r', () => {
    const norm = normalizeInstruction('mov', 'eax, ecx');
    expect(norm).toContain('%r');
    expect(norm).not.toContain('eax');
  });

  it('replaces large hex immediates with %addr', () => {
    const norm = normalizeInstruction('mov', 'rax, 0x7ffe0300');
    expect(norm).toContain('%addr');
  });

  it('keeps small hex immediates below 0xa intact', () => {
    const norm = normalizeInstruction('add', 'rax, 0x8');
    expect(norm).toContain('0x8');
  });

  it('replaces decimal numbers >= 10 with %imm', () => {
    const norm = normalizeInstruction('sub', 'rsp, 40');
    expect(norm).toContain('%imm');
  });

  it('removes size prefixes like dword ptr', () => {
    const norm = normalizeInstruction('mov', 'dword ptr [rsp+4], eax');
    expect(norm).not.toContain('dword ptr');
    expect(norm).toContain('%sz');
  });

  it('handles empty operands', () => {
    const norm = normalizeInstruction('ret', '');
    expect(norm).toBe('ret');
  });
});

// ── scanSignatures ────────────────────────────────────────────────────────────

describe('scanSignatures', () => {
  const prologue: DisassembledInstruction[] = [
    { address: 0x1000, mnemonic: 'push', operands: 'rbp' },
    { address: 0x1001, mnemonic: 'mov', operands: 'rbp, rsp' },
    { address: 0x1002, mnemonic: 'sub', operands: 'rsp, 40' },
    { address: 0x1003, mnemonic: 'push', operands: 'rbx' },
    { address: 0x1004, mnemonic: 'push', operands: 'rdi' },
    { address: 0x1005, mnemonic: 'push', operands: 'rsi' },
    { address: 0x1006, mnemonic: 'mov', operands: 'eax, 0' },
    { address: 0x1007, mnemonic: 'ret', operands: '' },
  ];

  it('returns a result with required fields', () => {
    const result = scanSignatures(prologue);
    expect(result).toHaveProperty('matches');
    expect(result).toHaveProperty('scannedFunctions');
    expect(result).toHaveProperty('scannedInstructions');
    expect(Array.isArray(result.matches)).toBe(true);
  });

  it('scannedInstructions equals instruction count when no function map', () => {
    const result = scanSignatures(prologue);
    expect(result.scannedInstructions).toBe(prologue.length);
  });

  it('returns empty matches for empty instruction list', () => {
    const result = scanSignatures([]);
    expect(result.matches).toHaveLength(0);
  });

  it('match scores are in range 0–100', () => {
    const result = scanSignatures(prologue);
    for (const m of result.matches) {
      expect(m.score).toBeGreaterThanOrEqual(0);
      expect(m.score).toBeLessThanOrEqual(100);
    }
  });
});
