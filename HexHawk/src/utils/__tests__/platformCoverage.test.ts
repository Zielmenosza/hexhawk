import { describe, expect, it } from 'vitest';
import {
  PLATFORM_COVERAGE_TARGETS,
  findCoverageTargets,
  getPlatformCoverageInventory,
  hasUnsupportedClaim,
  summarizeEraCoverage,
} from '../platformCoverage';

describe('platformCoverage', () => {
  it('covers every decade from the 1970s through the 2020s', () => {
    const summary = summarizeEraCoverage();

    expect(summary['1970s']).toBeGreaterThan(0);
    expect(summary['1980s']).toBeGreaterThan(0);
    expect(summary['1990s']).toBeGreaterThan(0);
    expect(summary['2000s']).toBeGreaterThan(0);
    expect(summary['2010s']).toBeGreaterThan(0);
    expect(summary['2020s']).toBeGreaterThan(0);
  });

  it('tracks legacy and modern architecture families without flattening them into x86-only support', () => {
    const inventory = getPlatformCoverageInventory();
    const architectures = new Set(inventory.flatMap((target) => target.architectures));

    for (const expected of [
      'Intel 8080',
      'MOS 6502',
      'Zilog Z80',
      'PDP-11',
      'VAX',
      'Motorola 68000',
      'MIPS I',
      'PowerPC',
      'SPARC',
      'ARM',
      'AArch64',
      'RISC-V',
      'WebAssembly',
      'eBPF',
    ]) {
      expect(architectures.has(expected)).toBe(true);
    }
  });

  it('supports analyst queries for file families and architecture targets', () => {
    expect(findCoverageTargets('pcapng').map((target) => target.id)).toContain('documents-archives-network-1990s-present');
    expect(findCoverageTargets('UEFI').map((target) => target.id)).toContain('firmware-uefi-iot-2000s-present');
    expect(findCoverageTargets('6502').map((target) => target.id)).toContain('intel-hex-srec-1970s-microcontrollers');
    expect(findCoverageTargets('WASM').map((target) => target.id)).toContain('modern-cloud-runtime-2010s-2020s');
  });

  it('keeps planned support honest rather than claiming release-ready parser/decompiler coverage', () => {
    const nonProofBacked = PLATFORM_COVERAGE_TARGETS.filter((target) => target.status !== 'proof-backed');

    expect(nonProofBacked.length).toBeGreaterThan(0);
    expect(nonProofBacked.every((target) => target.authorityBoundary.includes('does not claim full parser'))).toBe(true);
    expect(nonProofBacked.every((target) => !hasUnsupportedClaim(target))).toBe(true);
  });
});
