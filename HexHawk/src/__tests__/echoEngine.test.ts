import { describe, it, expect } from 'vitest';
import {
  echoScan,
  groupEchoByCategory,
  extractCorrelationSignals,
  ECHO_DB,
} from '../utils/echoEngine';
import type {
  EchoContext,
  EchoMatch,
  EchoPattern,
  EchoScanResult,
} from '../utils/echoEngine';
import type { DisassembledInstruction } from '../utils/decompilerEngine';

// ── Helpers ───────────────────────────────────────────────────────────────────

function ins(
  address: number,
  mnemonic: string,
  operands: string,
): DisassembledInstruction {
  return { address, mnemonic, operands };
}

const EMPTY_CTX: EchoContext = {
  imports: [],
  strings: [],
  knownSigMatches: [],
};

function makeMockMatch(
  overrides: Partial<EchoMatch> = {},
): EchoMatch {
  const pattern: EchoPattern = ECHO_DB[0];
  return {
    pattern,
    functionAddress: 0x1000,
    similarity: 0.8,
    score: 75,
    matchOffset: 0,
    windowSize: 2,
    contextBoost: 0,
    method: 'fuzzy',
    ...overrides,
  };
}

function makeResult(matches: EchoMatch[]): EchoScanResult {
  return {
    matches,
    scannedFunctions: 1,
    scannedInstructions: 10,
    fuzzyMatchCount: matches.filter(m => m.method === 'fuzzy').length,
    exactMatchCount: matches.filter(m => m.method === 'exact').length,
    wildcardMatchCount: matches.filter(m => m.method === 'wildcard').length,
    contextBoostCount: matches.filter(m => m.contextBoost > 0).length,
  };
}

// ── echoScan ──────────────────────────────────────────────────────────────────

describe('echoScan', () => {
  it('returns a valid EchoScanResult for empty instruction list', () => {
    const result = echoScan([], EMPTY_CTX);
    expect(result.matches).toEqual([]);
    expect(result.scannedFunctions).toBe(1);
    expect(result.scannedInstructions).toBe(0);
    expect(result.fuzzyMatchCount).toBe(0);
    expect(result.exactMatchCount).toBe(0);
    expect(result.wildcardMatchCount).toBe(0);
    expect(result.contextBoostCount).toBe(0);
  });

  it('returns correct scannedInstructions count', () => {
    const instrs: DisassembledInstruction[] = [
      ins(0x1000, 'nop', ''),
      ins(0x1001, 'nop', ''),
      ins(0x1002, 'ret', ''),
    ];
    const result = echoScan(instrs, EMPTY_CTX);
    expect(result.scannedInstructions).toBe(3);
  });

  it('matches are sorted by score descending', () => {
    // Run on a real input; even if no matches, the invariant must hold
    const instrs: DisassembledInstruction[] = [
      ins(0x1000, 'push', 'rbp'),
      ins(0x1001, 'mov',  'rbp, rsp'),
      ins(0x1004, 'sub',  'rsp, 0x20'),
      ins(0x1008, 'mov',  'eax, 0'),
      ins(0x100d, 'add',  'rsp, 0x20'),
      ins(0x1011, 'pop',  'rbp'),
      ins(0x1012, 'ret',  ''),
    ];
    const result = echoScan(instrs, EMPTY_CTX);
    for (let i = 1; i < result.matches.length; i++) {
      expect(result.matches[i - 1].score).toBeGreaterThanOrEqual(result.matches[i].score);
    }
  });

  it('all match scores are in [0, 100]', () => {
    const instrs: DisassembledInstruction[] = [
      ins(0x1000, 'push', 'rbp'),
      ins(0x1001, 'mov',  'rbp, rsp'),
      ins(0x1004, 'xor',  'eax, eax'),
      ins(0x1007, 'pop',  'rbp'),
      ins(0x1008, 'ret',  ''),
    ];
    const result = echoScan(instrs, EMPTY_CTX);
    for (const m of result.matches) {
      expect(m.score).toBeGreaterThanOrEqual(0);
      expect(m.score).toBeLessThanOrEqual(100);
    }
  });

  it('context boost from import names raises score', () => {
    // echo-malloc-wrapper needs HeapAlloc in imports to get context boost
    const allocInstrs: DisassembledInstruction[] = [
      ins(0x1000, 'push', 'rbx'),
      ins(0x1001, 'mov',  'rcx, 0x100'),
      ins(0x1006, 'sub',  'rsp, 0x20'),
      ins(0x100a, 'call', 'HeapAlloc'),
      ins(0x100f, 'add',  'rsp, 0x20'),
      ins(0x1013, 'test', 'rax, rax'),
      ins(0x1016, 'jz',   '0x1020'),
      ins(0x1018, 'pop',  'rbx'),
      ins(0x1019, 'ret',  ''),
    ];
    const withBoost = echoScan(allocInstrs, {
      ...EMPTY_CTX,
      imports: ['HeapAlloc'],
    });
    const withoutBoost = echoScan(allocInstrs, EMPTY_CTX);
    // The boosted result should have a higher or equal max score
    const maxWith    = withBoost.matches.reduce((m, x) => Math.max(m, x.score), 0);
    const maxWithout = withoutBoost.matches.reduce((m, x) => Math.max(m, x.score), 0);
    expect(maxWith).toBeGreaterThanOrEqual(maxWithout);
  });

  it('rep movsb instruction triggers libc-memory match', () => {
    // echo-memcpy-repmovsb pattern: ['??', 'rep movsb %sz [%r], %sz [%r]']
    const instrs: DisassembledInstruction[] = [
      ins(0x1000, 'mov', 'rcx, rdx'),
      ins(0x1003, 'rep movsb', 'qword ptr [rdi], qword ptr [rsi]'),
    ];
    const result = echoScan(instrs, EMPTY_CTX);
    const hasMemcpy = result.matches.some(
      m => m.pattern.category === 'libc-memory',
    );
    expect(hasMemcpy).toBe(true);
  });

  it('is deterministic — identical input produces identical result', () => {
    const instrs: DisassembledInstruction[] = [
      ins(0x1000, 'push', 'rbp'),
      ins(0x1001, 'mov',  'rbp, rsp'),
      ins(0x1004, 'xor',  'eax, eax'),
      ins(0x1007, 'pop',  'rbp'),
      ins(0x1008, 'ret',  ''),
    ];
    const r1 = echoScan(instrs, EMPTY_CTX);
    const r2 = echoScan(instrs, EMPTY_CTX);
    expect(r1.matches.map(m => m.pattern.id)).toEqual(r2.matches.map(m => m.pattern.id));
    expect(r1.matches.map(m => m.score)).toEqual(r2.matches.map(m => m.score));
  });

  it('scans per-function when function map provided', () => {
    const instrs: DisassembledInstruction[] = [
      ins(0x1000, 'push', 'rbp'),
      ins(0x1001, 'ret',  ''),
      ins(0x2000, 'push', 'rbp'),
      ins(0x2001, 'ret',  ''),
    ];
    const functions = new Map([
      [0x1000, { startAddress: 0x1000, endAddress: 0x1001, name: 'fn1', size: 2, instructionCount: 2, isEntryPoint: false, calledFunctions: [] }],
      [0x2000, { startAddress: 0x2000, endAddress: 0x2001, name: 'fn2', size: 2, instructionCount: 2, isEntryPoint: false, calledFunctions: [] }],
    ]);
    const result = echoScan(instrs, EMPTY_CTX, functions);
    expect(result.scannedFunctions).toBe(2);
  });
});

// ── groupEchoByCategory ────────────────────────────────────────────────────────

describe('groupEchoByCategory', () => {
  it('returns empty map for empty matches', () => {
    const grouped = groupEchoByCategory([]);
    expect(grouped.size).toBe(0);
  });

  it('groups matches by category', () => {
    const antiDebugPattern = ECHO_DB.find(p => p.category === 'anti-debug');
    const compilerPattern  = ECHO_DB.find(p => p.category === 'compiler-runtime');
    if (!antiDebugPattern || !compilerPattern) return; // skip if DB is empty

    const matches: EchoMatch[] = [
      makeMockMatch({ pattern: antiDebugPattern }),
      makeMockMatch({ pattern: compilerPattern }),
      makeMockMatch({ pattern: antiDebugPattern, functionAddress: 0x2000 }),
    ];
    const grouped = groupEchoByCategory(matches);
    expect(grouped.get('anti-debug')?.length).toBe(2);
    expect(grouped.get('compiler-runtime')?.length).toBe(1);
  });

  it('preserves all matches in their respective categories', () => {
    const matches: EchoMatch[] = ECHO_DB.slice(0, 5).map((pattern, i) =>
      makeMockMatch({ pattern, functionAddress: i * 0x100 }),
    );
    const grouped = groupEchoByCategory(matches);
    const total = [...grouped.values()].reduce((s, arr) => s + arr.length, 0);
    expect(total).toBe(matches.length);
  });
});

// ── extractCorrelationSignals ─────────────────────────────────────────────────

describe('extractCorrelationSignals', () => {
  it('returns all-false for empty scan result', () => {
    const sig = extractCorrelationSignals(makeResult([]));
    expect(sig.hasLibcFunctions).toBe(false);
    expect(sig.hasCryptoAlgorithm).toBe(false);
    expect(sig.hasNetworkPattern).toBe(false);
    expect(sig.hasInjectionPattern).toBe(false);
    expect(sig.hasAntiDebugPattern).toBe(false);
    expect(sig.hasCompilerArtifacts).toBe(false);
    expect(sig.hasDynamicLoad).toBe(false);
    expect(sig.hasPersistence).toBe(false);
    expect(sig.averageConfidence).toBe(0);
    expect(sig.patternDiversity).toBe(0);
    expect(sig.behavioralTags).toEqual([]);
    expect(sig.topMatchNames).toEqual([]);
  });

  it('detects libc-memory category', () => {
    const pattern = ECHO_DB.find(p => p.category === 'libc-memory');
    if (!pattern) return;
    const sig = extractCorrelationSignals(makeResult([makeMockMatch({ pattern })]));
    expect(sig.hasLibcFunctions).toBe(true);
  });

  it('detects libc-string category', () => {
    const pattern = ECHO_DB.find(p => p.category === 'libc-string');
    if (!pattern) return;
    const sig = extractCorrelationSignals(makeResult([makeMockMatch({ pattern })]));
    expect(sig.hasLibcFunctions).toBe(true);
  });

  it('detects crypto-hash category', () => {
    const pattern = ECHO_DB.find(p => p.category === 'crypto-hash');
    if (!pattern) return;
    const sig = extractCorrelationSignals(makeResult([makeMockMatch({ pattern })]));
    expect(sig.hasCryptoAlgorithm).toBe(true);
  });

  it('detects crypto-cipher category', () => {
    const pattern = ECHO_DB.find(p => p.category === 'crypto-cipher');
    if (!pattern) return;
    const sig = extractCorrelationSignals(makeResult([makeMockMatch({ pattern })]));
    expect(sig.hasCryptoAlgorithm).toBe(true);
  });

  it('detects anti-debug category', () => {
    const pattern = ECHO_DB.find(p => p.category === 'anti-debug');
    if (!pattern) return;
    const sig = extractCorrelationSignals(makeResult([makeMockMatch({ pattern })]));
    expect(sig.hasAntiDebugPattern).toBe(true);
  });

  it('detects network-io category', () => {
    const pattern = ECHO_DB.find(p => p.category === 'network-io');
    if (!pattern) return;
    const sig = extractCorrelationSignals(makeResult([makeMockMatch({ pattern })]));
    expect(sig.hasNetworkPattern).toBe(true);
  });

  it('detects code-injection category', () => {
    const pattern = ECHO_DB.find(p => p.category === 'code-injection');
    if (!pattern) return;
    const sig = extractCorrelationSignals(makeResult([makeMockMatch({ pattern })]));
    expect(sig.hasInjectionPattern).toBe(true);
  });

  it('detects compiler-runtime category', () => {
    const pattern = ECHO_DB.find(p => p.category === 'compiler-runtime');
    if (!pattern) return;
    const sig = extractCorrelationSignals(makeResult([makeMockMatch({ pattern })]));
    expect(sig.hasCompilerArtifacts).toBe(true);
  });

  it('detects dynamic-load category', () => {
    const pattern = ECHO_DB.find(p => p.category === 'dynamic-load');
    if (!pattern) return;
    const sig = extractCorrelationSignals(makeResult([makeMockMatch({ pattern })]));
    expect(sig.hasDynamicLoad).toBe(true);
  });

  it('detects persistence category', () => {
    const pattern = ECHO_DB.find(p => p.category === 'persistence');
    if (!pattern) return;
    const sig = extractCorrelationSignals(makeResult([makeMockMatch({ pattern })]));
    expect(sig.hasPersistence).toBe(true);
  });

  it('computes average confidence correctly', () => {
    const matches: EchoMatch[] = [
      makeMockMatch({ score: 60 }),
      makeMockMatch({ score: 80, functionAddress: 0x2000 }),
    ];
    const sig = extractCorrelationSignals(makeResult(matches));
    expect(sig.averageConfidence).toBe(70);
  });

  it('counts unique categories as patternDiversity', () => {
    const libc    = ECHO_DB.find(p => p.category === 'libc-memory');
    const antid   = ECHO_DB.find(p => p.category === 'anti-debug');
    const compiler = ECHO_DB.find(p => p.category === 'compiler-runtime');
    if (!libc || !antid || !compiler) return;
    const matches: EchoMatch[] = [
      makeMockMatch({ pattern: libc }),
      makeMockMatch({ pattern: antid }),
      makeMockMatch({ pattern: compiler }),
    ];
    const sig = extractCorrelationSignals(makeResult(matches));
    expect(sig.patternDiversity).toBe(3);
  });

  it('topMatchNames contains at most 5 entries', () => {
    const matches: EchoMatch[] = ECHO_DB.slice(0, 8).map((pattern, i) =>
      makeMockMatch({ pattern, score: 90 - i, functionAddress: i * 0x100 }),
    );
    const sig = extractCorrelationSignals(makeResult(matches));
    expect(sig.topMatchNames.length).toBeLessThanOrEqual(5);
  });

  it('collects behavioralTags from matched patterns', () => {
    const injPattern = ECHO_DB.find(p => p.behaviors.includes('code-decryption'));
    if (!injPattern) return;
    const sig = extractCorrelationSignals(makeResult([makeMockMatch({ pattern: injPattern })]));
    expect(sig.behavioralTags).toContain('code-decryption');
  });
});

// ── Behavioral regression ─────────────────────────────────────────────────────

describe('echoScan — behavioral regression', () => {
  /** Fixed memcpy-like input that must always produce a libc-memory match */
  const MEMCPY_INPUT: DisassembledInstruction[] = [
    ins(0x1000, 'mov',      'rcx, rdx'),
    ins(0x1003, 'rep movsb', 'qword ptr [rdi], qword ptr [rsi]'),
  ];

  it('memcpy pattern always recognized as libc-memory', () => {
    const result = echoScan(MEMCPY_INPUT, EMPTY_CTX);
    const categories = result.matches.map(m => m.pattern.category);
    expect(categories).toContain('libc-memory');
  });

  it('memcpy match always has score >= 50', () => {
    const result = echoScan(MEMCPY_INPUT, EMPTY_CTX);
    const memMatch = result.matches.find(m => m.pattern.category === 'libc-memory');
    expect(memMatch).toBeDefined();
    expect(memMatch!.score).toBeGreaterThanOrEqual(50);
  });

  it('memcpy result is stable across three runs', () => {
    const r1 = echoScan(MEMCPY_INPUT, EMPTY_CTX);
    const r2 = echoScan(MEMCPY_INPUT, EMPTY_CTX);
    const r3 = echoScan(MEMCPY_INPUT, EMPTY_CTX);
    expect(r1.matches.map(m => m.pattern.id)).toEqual(r2.matches.map(m => m.pattern.id));
    expect(r2.matches.map(m => m.pattern.id)).toEqual(r3.matches.map(m => m.pattern.id));
  });
});
