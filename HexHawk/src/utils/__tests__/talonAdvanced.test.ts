/**
 * talonAdvanced.test.ts — WS9 tests for the TALON advanced analysis pass
 */
import { describe, it, expect } from 'vitest';
import {
  detectSwitchPatterns,
  simplifyExpressions,
  buildInterproceduralHints,
  applyAdvancedPass,
  type TransformRecord,
  type CalleeHint,
} from '../talonAdvanced';
import type { TalonLine, TalonIntent } from '../talonEngine';

// ─── Helpers ──────────────────────────────────────────────────────────────────

function makeLine(text: string, address = 0x1000): TalonLine {
  return {
    kind: 'stmt',
    text,
    address,
    lineConfidence: 80,
    indent: 0,
  } as unknown as TalonLine;
}

// ─── detectSwitchPatterns ──────────────────────────────────────────────────────

describe('detectSwitchPatterns', () => {
  it('detects indirect jmp with scaled index', () => {
    const lines: TalonLine[] = [
      makeLine('if (eax > 4) goto default', 0x100),
      makeLine('jmp table[eax*4]', 0x108),
      makeLine('case_0:', 0x200),
    ];
    const log: TransformRecord[] = [];
    const result = detectSwitchPatterns(lines, log);

    expect(result.length).toBe(1);
    expect(result[0].switchVar).toBe('eax');
    expect(result[0].cases.length).toBeGreaterThan(0);
    expect(result[0].hasDefault).toBe(true);
    expect(log.length).toBeGreaterThan(0);
    expect(log[0].kind).toBe('switch-reconstruct');
  });

  it('returns empty array for code without indirect jumps', () => {
    const lines: TalonLine[] = [
      makeLine('mov eax, 1', 0x100),
      makeLine('add ecx, eax', 0x104),
    ];
    const log: TransformRecord[] = [];
    expect(detectSwitchPatterns(lines, log)).toHaveLength(0);
    expect(log).toHaveLength(0);
  });

  it('records transform log entry with correct fields', () => {
    const lines: TalonLine[] = [
      makeLine('if (ecx > 2) goto def', 0x400),
      makeLine('jmp tbl[ecx*8]', 0x410),
    ];
    const log: TransformRecord[] = [];
    detectSwitchPatterns(lines, log);

    expect(log[0]).toMatchObject({
      kind: 'switch-reconstruct',
      confidence: expect.any(Number),
      address: 0x410,
    });
    expect(log[0].outputExpr).toContain('switch');
  });
});

// ─── simplifyExpressions ──────────────────────────────────────────────────────

describe('simplifyExpressions', () => {
  it('strength-reduces multiplication by power of 2 to left shift', () => {
    const lines = [makeLine('result = x * 8', 0x200)];
    const log: TransformRecord[] = [];
    const out = simplifyExpressions(lines, log);

    expect(out[0].text).toContain('<< 3');
    expect(log[0].kind).toBe('strength-reduce');
    expect(log[0].inputExpr).toContain('* 8');
  });

  it('strength-reduces division by power of 2 to right shift', () => {
    const lines = [makeLine('y = val / 4', 0x300)];
    const log: TransformRecord[] = [];
    const out = simplifyExpressions(lines, log);

    expect(out[0].text).toContain('>> 2');
    expect(log[0].kind).toBe('strength-reduce');
  });

  it('folds constant arithmetic expressions', () => {
    const lines = [makeLine('mov eax, 3 + 7', 0x100)];
    const log: TransformRecord[] = [];
    const out = simplifyExpressions(lines, log);

    // 3 + 7 = 10
    expect(out[0].text).toContain('10');
    expect(log[0].kind).toBe('constant-fold');
  });

  it('does not alter lines without simplifiable patterns', () => {
    const lines = [makeLine('push ebp', 0x100)];
    const log: TransformRecord[] = [];
    const out = simplifyExpressions(lines, log);

    expect(out[0].text).toBe('push ebp');
    expect(log).toHaveLength(0);
  });

  it('does not simplify mul by non-power-of-2', () => {
    const lines = [makeLine('val = x * 3', 0x100)];
    const log: TransformRecord[] = [];
    const out = simplifyExpressions(lines, log);

    expect(out[0].text).toContain('* 3');
    expect(log).toHaveLength(0);
  });
});

// ─── buildInterproceduralHints ────────────────────────────────────────────────

describe('buildInterproceduralHints', () => {
  it('attaches hint for a known callee', () => {
    const lines = [makeLine('call IsDebuggerPresent', 0x500)];
    const intent: TalonIntent = {
      label: 'anti-debug check',
      confidence: 95,
      category: 'security',
      address: 0,
    };
    const callees = new Map([
      ['IsDebuggerPresent', { name: 'IsDebuggerPresent', primaryIntent: intent, confidence: 95 }],
    ]);
    const log: TransformRecord[] = [];
    const hints: CalleeHint[] = buildInterproceduralHints(lines, callees, log);

    expect(hints).toHaveLength(1);
    expect(hints[0].calleeName).toBe('IsDebuggerPresent');
    expect(hints[0].calleeCategory).toBe('security');
    expect(log[0].kind).toBe('interprocedural-hint');
  });

  it('returns no hints when callees map is empty', () => {
    const lines = [makeLine('call UnknownFunc', 0x600)];
    const log: TransformRecord[] = [];
    const hints = buildInterproceduralHints(lines, new Map(), log);

    expect(hints).toHaveLength(0);
    expect(log).toHaveLength(0);
  });
});

// ─── applyAdvancedPass (integration) ──────────────────────────────────────────

describe('applyAdvancedPass', () => {
  it('returns enriched summary with all advanced fields', () => {
    const lines = [
      makeLine('if (eax > 3) goto def', 0x100),
      makeLine('jmp table[eax*4]', 0x108),
      makeLine('call malloc', 0x200),
      makeLine('n = size * 4', 0x210),
    ];
    const callees = new Map([
      ['malloc', { name: 'malloc', primaryIntent: { label: 'heap allocation', confidence: 90, category: 'memory' as const, address: 0 }, confidence: 90 }],
    ]);

    const baseSummary = {
      name: 'test_func',
      startAddress: 0x100,
      overallConfidence: 80,
      liftingCoverage: 90,
      intents: [],
      behavioralTags: [],
      uncertainStatements: 0,
      totalStatements: 4,
      complexityScore: 1,
      warningCount: 0,
      ssaVarCount: 0,
      loopNestingDepth: 0,
      naturalLoops: [],
    };

    const result = applyAdvancedPass(lines, baseSummary, { callees });

    expect(result.summary.switchStatements).toBeDefined();
    expect(result.summary.transformLog).toBeDefined();
    expect(result.summary.calleeHints).toHaveLength(1);
    expect(result.summary.transformLog.length).toBeGreaterThan(0);
    // size * 4 should be strength-reduced
    const simplifiedLine = result.lines.find(l => l.text?.includes('<<'));
    expect(simplifiedLine).toBeDefined();
  });
});
