import { describe, it, expect } from 'vitest';
import {
  talonDecompile,
  extractCorrelationSignals,
} from '../utils/talonEngine';
import type { TalonFunctionSummary } from '../utils/talonEngine';
import type { DisassembledInstruction } from '../utils/decompilerEngine';

// ── Helpers ───────────────────────────────────────────────────────────────────

function ins(
  address: number,
  mnemonic: string,
  operands: string,
): DisassembledInstruction {
  return { address, mnemonic, operands };
}

function makeSummary(
  overrides: Partial<TalonFunctionSummary> = {},
): TalonFunctionSummary {
  return {
    name: 'fn',
    startAddress: 0x1000,
    overallConfidence: 75,
    liftingCoverage: 90,
    intents: [],
    behavioralTags: [],
    uncertainStatements: 0,
    totalStatements: 5,
    complexityScore: 2,
    warningCount: 0,
    ssaVarCount: 3,
    loopNestingDepth: 0,
    naturalLoops: [],
    ...overrides,
  };
}

/** Minimal 5-instruction function: frame setup → xor-zero → teardown → ret */
const MINIMAL_FUNC: DisassembledInstruction[] = [
  ins(0x1000, 'push', 'rbp'),
  ins(0x1001, 'mov',  'rbp, rsp'),
  ins(0x1004, 'xor',  'eax, eax'),
  ins(0x1007, 'pop',  'rbp'),
  ins(0x1008, 'ret',  ''),
];

/** Function with anti-debug + crypto API names */
const THREAT_FUNC: DisassembledInstruction[] = [
  ins(0x2000, 'push', 'rbp'),
  ins(0x2001, 'sub',  'rsp, 0x28'),
  ins(0x2005, 'call', 'IsDebuggerPresent'),
  ins(0x200a, 'test', 'eax, eax'),
  ins(0x200c, 'je',   '0x2015'),
  ins(0x200e, 'call', 'CryptEncrypt'),
  ins(0x2013, 'jmp',  '0x2016'),
  ins(0x2015, 'nop',  ''),
  ins(0x2016, 'add',  'rsp, 0x28'),
  ins(0x201a, 'pop',  'rbp'),
  ins(0x201b, 'ret',  ''),
];

/** Function with process-injection API calls */
const INJECT_FUNC: DisassembledInstruction[] = [
  ins(0x3000, 'push', 'rbp'),
  ins(0x3001, 'mov',  'rbp, rsp'),
  ins(0x3004, 'sub',  'rsp, 0x40'),
  ins(0x3008, 'call', 'VirtualAllocEx'),
  ins(0x300d, 'call', 'WriteProcessMemory'),
  ins(0x3012, 'call', 'CreateRemoteThread'),
  ins(0x3017, 'add',  'rsp, 0x40'),
  ins(0x301b, 'pop',  'rbp'),
  ins(0x301c, 'ret',  ''),
];

// ── extractCorrelationSignals ─────────────────────────────────────────────────

describe('extractCorrelationSignals', () => {
  it('returns all-false for empty summary list', () => {
    const sig = extractCorrelationSignals([]);
    expect(sig.hasAntiDebug).toBe(false);
    expect(sig.hasCrypto).toBe(false);
    expect(sig.hasNetworkOps).toBe(false);
    expect(sig.hasInjection).toBe(false);
    expect(sig.hasExec).toBe(false);
    expect(sig.hasPersistence).toBe(false);
    expect(sig.hasDynamicResolution).toBe(false);
    expect(sig.overallConfidence).toBe(0);
    expect(sig.uncertainRatio).toBe(0);
    expect(sig.functionCount).toBe(0);
  });

  it('detects anti-analysis tag', () => {
    const sig = extractCorrelationSignals([
      makeSummary({ behavioralTags: ['anti-analysis'], overallConfidence: 80 }),
    ]);
    expect(sig.hasAntiDebug).toBe(true);
    expect(sig.functionCount).toBe(1);
    expect(sig.overallConfidence).toBe(80);
  });

  it('detects data-encryption as crypto', () => {
    const sig = extractCorrelationSignals([
      makeSummary({ behavioralTags: ['data-encryption'] }),
    ]);
    expect(sig.hasCrypto).toBe(true);
  });

  it('detects code-decryption as crypto', () => {
    const sig = extractCorrelationSignals([
      makeSummary({ behavioralTags: ['code-decryption'] }),
    ]);
    expect(sig.hasCrypto).toBe(true);
  });

  it('detects c2-communication as network ops', () => {
    const sig = extractCorrelationSignals([
      makeSummary({ behavioralTags: ['c2-communication'] }),
    ]);
    expect(sig.hasNetworkOps).toBe(true);
  });

  it('detects code-injection', () => {
    const sig = extractCorrelationSignals([
      makeSummary({ behavioralTags: ['code-injection'] }),
    ]);
    expect(sig.hasInjection).toBe(true);
  });

  it('detects process-execution', () => {
    const sig = extractCorrelationSignals([
      makeSummary({ behavioralTags: ['process-execution'] }),
    ]);
    expect(sig.hasExec).toBe(true);
  });

  it('detects persistence', () => {
    const sig = extractCorrelationSignals([
      makeSummary({ behavioralTags: ['persistence'] }),
    ]);
    expect(sig.hasPersistence).toBe(true);
  });

  it('detects dynamic-resolution', () => {
    const sig = extractCorrelationSignals([
      makeSummary({ behavioralTags: ['dynamic-resolution'] }),
    ]);
    expect(sig.hasDynamicResolution).toBe(true);
  });

  it('computes uncertainty ratio correctly', () => {
    const sig = extractCorrelationSignals([
      makeSummary({ uncertainStatements: 4, totalStatements: 10 }),
    ]);
    expect(sig.uncertainRatio).toBeCloseTo(0.4);
  });

  it('uncertainty ratio is 0 when totalStatements is 0', () => {
    const sig = extractCorrelationSignals([
      makeSummary({ uncertainStatements: 0, totalStatements: 0 }),
    ]);
    expect(sig.uncertainRatio).toBe(0);
  });

  it('averages confidence across multiple functions', () => {
    const sig = extractCorrelationSignals([
      makeSummary({ overallConfidence: 60 }),
      makeSummary({ overallConfidence: 80 }),
    ]);
    expect(sig.overallConfidence).toBe(70);
    expect(sig.functionCount).toBe(2);
  });

  it('unions tags from multiple functions', () => {
    const sig = extractCorrelationSignals([
      makeSummary({ behavioralTags: ['c2-communication'] }),
      makeSummary({ behavioralTags: ['persistence', 'dynamic-resolution'] }),
    ]);
    expect(sig.hasNetworkOps).toBe(true);
    expect(sig.hasPersistence).toBe(true);
    expect(sig.hasDynamicResolution).toBe(true);
  });
});

// ── talonDecompile — structural ───────────────────────────────────────────────

describe('talonDecompile', () => {
  it('returns TalonResult with non-empty lines for minimal function', () => {
    const result = talonDecompile(MINIMAL_FUNC, null);
    expect(result.lines.length).toBeGreaterThan(0);
  });

  it('summary startAddress equals first instruction address', () => {
    const result = talonDecompile(MINIMAL_FUNC, null);
    expect(result.summary.startAddress).toBe(0x1000);
  });

  it('all lineConfidence values are in [0, 100]', () => {
    const result = talonDecompile(MINIMAL_FUNC, null);
    for (const line of result.lines) {
      expect(line.lineConfidence).toBeGreaterThanOrEqual(0);
      expect(line.lineConfidence).toBeLessThanOrEqual(100);
    }
  });

  it('overallConfidence is in [0, 100]', () => {
    const result = talonDecompile(MINIMAL_FUNC, null);
    expect(result.summary.overallConfidence).toBeGreaterThanOrEqual(0);
    expect(result.summary.overallConfidence).toBeLessThanOrEqual(100);
  });

  it('liftingCoverage is in [0, 100]', () => {
    const result = talonDecompile(MINIMAL_FUNC, null);
    expect(result.summary.liftingCoverage).toBeGreaterThanOrEqual(0);
    expect(result.summary.liftingCoverage).toBeLessThanOrEqual(100);
  });

  it('ssaVarCount is a non-negative integer', () => {
    const result = talonDecompile(MINIMAL_FUNC, null);
    expect(result.summary.ssaVarCount).toBeGreaterThanOrEqual(0);
    expect(Number.isInteger(result.summary.ssaVarCount)).toBe(true);
  });

  it('returns at least one stmt or uncertain line', () => {
    const result = talonDecompile(MINIMAL_FUNC, null);
    const hasCode = result.lines.some(l => l.kind === 'stmt' || l.kind === 'uncertain');
    expect(hasCode).toBe(true);
  });

  it('THREAT_FUNC produces at least one intent-comment line', () => {
    const result = talonDecompile(THREAT_FUNC, null);
    const hasIntent = result.lines.some(l => l.kind === 'intent-comment');
    expect(hasIntent).toBe(true);
  });

  it('THREAT_FUNC summary has at least one behavioral tag', () => {
    const result = talonDecompile(THREAT_FUNC, null);
    expect(result.summary.behavioralTags.length).toBeGreaterThan(0);
  });

  it('INJECT_FUNC summary behavioralTags includes code-injection', () => {
    const result = talonDecompile(INJECT_FUNC, null);
    expect(result.summary.behavioralTags).toContain('code-injection');
  });

  it('empty instruction list returns a result without stmt lines', () => {
    const result = talonDecompile([], null);
    const stmtLines = result.lines.filter(l => l.kind === 'stmt' || l.kind === 'uncertain');
    expect(stmtLines.length).toBe(0);
  });
});

// ── talonDecompile — snapshot ─────────────────────────────────────────────────

describe('talonDecompile — snapshot', () => {
  it('minimal function line texts match snapshot', () => {
    const result = talonDecompile(MINIMAL_FUNC, null);
    expect(result.lines.map(l => l.text)).toMatchSnapshot();
  });

  it('minimal function summary fields match snapshot', () => {
    const { summary } = talonDecompile(MINIMAL_FUNC, null);
    expect({
      liftingCoverage:    summary.liftingCoverage,
      complexityScore:    summary.complexityScore,
      behavioralTags:     summary.behavioralTags,
      loopNestingDepth:   summary.loopNestingDepth,
      naturalLoops:       summary.naturalLoops,
    }).toMatchSnapshot();
  });

  it('inject function intent-comment texts match snapshot', () => {
    const result = talonDecompile(INJECT_FUNC, null);
    const intents = result.lines
      .filter(l => l.kind === 'intent-comment')
      .map(l => l.text);
    expect(intents).toMatchSnapshot();
  });
});

// ── talonDecompile — behavioral regression ────────────────────────────────────

describe('talonDecompile — behavioral regression', () => {
  it('is deterministic: same input always produces identical line texts', () => {
    const r1 = talonDecompile(MINIMAL_FUNC, null);
    const r2 = talonDecompile(MINIMAL_FUNC, null);
    expect(r1.lines.map(l => l.text)).toEqual(r2.lines.map(l => l.text));
  });

  it('is deterministic: confidence never varies between runs', () => {
    const r1 = talonDecompile(MINIMAL_FUNC, null);
    const r2 = talonDecompile(MINIMAL_FUNC, null);
    expect(r1.summary.overallConfidence).toBe(r2.summary.overallConfidence);
  });

  it('is deterministic: behavioralTags are stable across runs', () => {
    const r1 = talonDecompile(INJECT_FUNC, null);
    const r2 = talonDecompile(INJECT_FUNC, null);
    expect(r1.summary.behavioralTags.sort()).toEqual(r2.summary.behavioralTags.sort());
  });

  it('INJECT_FUNC always produces code-injection tag (verdict stability)', () => {
    for (let i = 0; i < 3; i++) {
      const result = talonDecompile(INJECT_FUNC, null);
      expect(result.summary.behavioralTags).toContain('code-injection');
    }
  });

  it('overallConfidence never drops below 50 for a well-formed function', () => {
    expect(talonDecompile(MINIMAL_FUNC, null).summary.overallConfidence).toBeGreaterThanOrEqual(50);
    expect(talonDecompile(INJECT_FUNC, null).summary.overallConfidence).toBeGreaterThanOrEqual(50);
  });

  it('INJECT_FUNC startAddress is always 0x3000', () => {
    const result = talonDecompile(INJECT_FUNC, null);
    expect(result.summary.startAddress).toBe(0x3000);
  });
});

// ── ARM32 / AArch64 — Milestone 3 ────────────────────────────────────────────

/** Minimal ARM32 function: push lr, add r0,r0,r1, pop pc */
const ARM32_MINIMAL: DisassembledInstruction[] = [
  ins(0x8000, 'push', '{r4, lr}'),
  ins(0x8002, 'add',  'r0, r0, r1'),
  ins(0x8004, 'cmp',  'r0, #0'),
  ins(0x8006, 'beq',  '0x800c'),
  ins(0x8008, 'sub',  'r0, r0, #1'),
  ins(0x800a, 'pop',  '{r4, pc}'),
  ins(0x800c, 'mov',  'r0, #0'),
  ins(0x800e, 'pop',  '{r4, pc}'),
];

/** Minimal AArch64 function: stp x29,x30 prologue + add + ret */
const AARCH64_MINIMAL: DisassembledInstruction[] = [
  ins(0x9000, 'stp',  'x29, x30, [sp, #-16]!'),
  ins(0x9004, 'mov',  'x29, sp'),
  ins(0x9008, 'add',  'x0, x0, x1'),
  ins(0x900c, 'cmp',  'x0, #0'),
  ins(0x9010, 'b.eq', '0x9018'),
  ins(0x9014, 'sub',  'x0, x0, #1'),
  ins(0x9018, 'ldp',  'x29, x30, [sp], #16'),
  ins(0x901c, 'ret',  ''),
];

describe('talonDecompile — ARM32 (Milestone 3)', () => {
  it('ARM32 minimal function returns non-empty lines', () => {
    const result = talonDecompile(ARM32_MINIMAL, null);
    expect(result.lines.length).toBeGreaterThan(0);
  });

  it('ARM32 minimal function has at least one stmt or uncertain line', () => {
    const result = talonDecompile(ARM32_MINIMAL, null);
    expect(result.lines.some(l => l.kind === 'stmt' || l.kind === 'uncertain')).toBe(true);
  });

  it('ARM32 prologue produces intent-comment with ARM32 label', () => {
    const result = talonDecompile(ARM32_MINIMAL, null);
    const intentLines = result.lines.filter(l => l.kind === 'intent-comment');
    const hasArmPrologue = intentLines.some(l => l.text.includes('ARM32'));
    expect(hasArmPrologue).toBe(true);
  });

  it('ARM32 function is deterministic', () => {
    const r1 = talonDecompile(ARM32_MINIMAL, null);
    const r2 = talonDecompile(ARM32_MINIMAL, null);
    expect(r1.lines.map(l => l.text)).toEqual(r2.lines.map(l => l.text));
  });

  it('ARM32 all lineConfidence values are in [0, 100]', () => {
    const result = talonDecompile(ARM32_MINIMAL, null);
    for (const line of result.lines) {
      expect(line.lineConfidence).toBeGreaterThanOrEqual(0);
      expect(line.lineConfidence).toBeLessThanOrEqual(100);
    }
  });

  it('ARM32 startAddress equals first instruction address', () => {
    const result = talonDecompile(ARM32_MINIMAL, null);
    expect(result.summary.startAddress).toBe(0x8000);
  });
});

describe('talonDecompile — AArch64 (Milestone 3)', () => {
  it('AArch64 minimal function returns non-empty lines', () => {
    const result = talonDecompile(AARCH64_MINIMAL, null);
    expect(result.lines.length).toBeGreaterThan(0);
  });

  it('AArch64 minimal function has at least one stmt or uncertain line', () => {
    const result = talonDecompile(AARCH64_MINIMAL, null);
    expect(result.lines.some(l => l.kind === 'stmt' || l.kind === 'uncertain')).toBe(true);
  });

  it('AArch64 prologue produces intent-comment with AArch64 label', () => {
    const result = talonDecompile(AARCH64_MINIMAL, null);
    const intentLines = result.lines.filter(l => l.kind === 'intent-comment');
    const hasA64Prologue = intentLines.some(l => l.text.includes('AArch64'));
    expect(hasA64Prologue).toBe(true);
  });

  it('AArch64 function is deterministic', () => {
    const r1 = talonDecompile(AARCH64_MINIMAL, null);
    const r2 = talonDecompile(AARCH64_MINIMAL, null);
    expect(r1.lines.map(l => l.text)).toEqual(r2.lines.map(l => l.text));
  });

  it('AArch64 all lineConfidence values are in [0, 100]', () => {
    const result = talonDecompile(AARCH64_MINIMAL, null);
    for (const line of result.lines) {
      expect(line.lineConfidence).toBeGreaterThanOrEqual(0);
      expect(line.lineConfidence).toBeLessThanOrEqual(100);
    }
  });

  it('AArch64 startAddress equals first instruction address', () => {
    const result = talonDecompile(AARCH64_MINIMAL, null);
    expect(result.summary.startAddress).toBe(0x9000);
  });
});
