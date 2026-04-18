/**
 * iterationLearningAdvanced.test.ts — WS11 tests for pattern promotion,
 * regression detection, and stability scoring.
 */
import { describe, it, expect } from 'vitest';
import {
  evaluatePatternPromotion,
  detectRegressions,
  computeStabilityScore,
  type PatternPromotionRule,
  type LearningDecision,
  type ImprovementBreakdown,
} from '../iterationLearning';

// ─── Helpers ──────────────────────────────────────────────────────────────────

function makeDecision(
  iteration: number,
  level: LearningDecision['improvementLevel'],
  reinforceSignals: string[] = [],
  deprioritise: string[] = [],
  promote: string[] = []
): LearningDecision {
  const breakdown: ImprovementBreakdown = {
    confidenceDelta: level === 'high' ? 5 : level === 'negative' ? -3 : 1,
    contradictionReduction: 0,
    clarityGain: 0,
    uncorroboratedDelta: 0,
    composite: level === 'high' ? 15 : level === 'medium' ? 6 : level === 'low' ? 2 : -5,
  };

  return {
    iteration,
    improvementLevel: level,
    breakdown,
    diagnosis: 'test',
    signalLearning: [],
    strategyAdjustments: [],
    shouldPivot: level === 'negative',
    shouldReinforce: level === 'high',
    reinforceSignals,
    deprioritise,
    promote,
  };
}

function makePattern(id: string, score = 0): PatternPromotionRule {
  return {
    patternId: id,
    globalBenefitScore: score,
    promotionCount: 0,
    demotionCount: 0,
    isActive: true,
    conditions: `Pattern ${id} fires on test condition`,
  };
}

// ─── evaluatePatternPromotion ─────────────────────────────────────────────────

describe('evaluatePatternPromotion', () => {
  it('increases benefit score when pattern is reinforced in high-improvement iteration', () => {
    const decisions = [makeDecision(0, 'high', ['pat-a'])];
    const patterns  = [makePattern('pat-a', 0)];
    const result    = evaluatePatternPromotion(decisions, patterns);

    expect(result[0].globalBenefitScore).toBeGreaterThan(0);
    expect(result[0].promotionCount).toBe(1);
  });

  it('decreases benefit score when pattern is in deprioritise list', () => {
    const decisions = [makeDecision(0, 'negative', [], ['pat-b'])];
    const patterns  = [makePattern('pat-b', 5)];
    const result    = evaluatePatternPromotion(decisions, patterns);

    expect(result[0].globalBenefitScore).toBeLessThan(5);
    expect(result[0].demotionCount).toBe(1);
  });

  it('marks pattern as inactive when demotionCount far exceeds promotionCount', () => {
    const decisions = [
      makeDecision(0, 'negative', [], ['pat-c']),
      makeDecision(1, 'negative', [], ['pat-c']),
      makeDecision(2, 'negative', [], ['pat-c']),
      makeDecision(3, 'negative', [], ['pat-c']),
    ];
    const patterns = [makePattern('pat-c', 0)];
    const result   = evaluatePatternPromotion(decisions, patterns);

    expect(result[0].isActive).toBe(false);
  });

  it('returns unchanged patterns when no decisions affect them', () => {
    const decisions = [makeDecision(0, 'medium', ['pat-other'])];
    const patterns  = [makePattern('pat-unrelated', 10)];
    const result    = evaluatePatternPromotion(decisions, patterns);

    expect(result[0].globalBenefitScore).toBe(10);
    expect(result[0].promotionCount).toBe(0);
  });

  it('handles empty decisions array', () => {
    const patterns = [makePattern('p', 5)];
    const result   = evaluatePatternPromotion([], patterns);
    expect(result[0].globalBenefitScore).toBe(5);
  });
});

// ─── detectRegressions ────────────────────────────────────────────────────────

describe('detectRegressions', () => {
  it('detects critical regression when high-performing pattern degrades', () => {
    const history = [
      makeDecision(0, 'high', ['pat-x']),
      makeDecision(1, 'high', ['pat-x']),
      makeDecision(2, 'high', ['pat-x']),
      makeDecision(3, 'high', ['pat-x']),
      makeDecision(4, 'high', ['pat-x']),
    ];
    const current = makeDecision(5, 'negative', [], ['pat-x']);

    const results = detectRegressions(current, history);
    expect(results.length).toBeGreaterThan(0);
    const r = results.find(r => r.patternId === 'pat-x');
    expect(r).toBeDefined();
    expect(r!.regressionSeverity).toBe('critical');
    expect(r!.rollbackRecommended).toBe(true);
  });

  it('returns no regressions when history is too short', () => {
    const history = [makeDecision(0, 'high', ['pat-y'])];
    const current = makeDecision(1, 'negative', [], ['pat-y']);

    const results = detectRegressions(current, history);
    expect(results).toHaveLength(0);
  });

  it('returns no regressions for patterns with mixed history', () => {
    const history = [
      makeDecision(0, 'high', ['pat-z']),
      makeDecision(1, 'low',  ['pat-z']),
      makeDecision(2, 'high', ['pat-z']),
    ];
    const current = makeDecision(3, 'low', [], ['pat-z']);

    const results = detectRegressions(current, history);
    // High rate < 0.6, so no regression flagged
    expect(results.every(r => r.patternId !== 'pat-z')).toBe(true);
  });
});

// ─── computeStabilityScore ────────────────────────────────────────────────────

describe('computeStabilityScore', () => {
  it('returns 100% consistency when all runs give same level', () => {
    const snapshots = [
      { binaryHash: 'abc', finalLevel: 'high' as const, runId: 'r1' },
      { binaryHash: 'abc', finalLevel: 'high' as const, runId: 'r2' },
      { binaryHash: 'abc', finalLevel: 'high' as const, runId: 'r3' },
    ];
    const [score] = computeStabilityScore(snapshots);

    expect(score.consistencyPct).toBe(100);
    expect(score.flipCount).toBe(0);
    expect(score.runCount).toBe(3);
  });

  it('counts flips between alternating classifications', () => {
    const snapshots = [
      { binaryHash: 'def', finalLevel: 'high'     as const, runId: 'r1' },
      { binaryHash: 'def', finalLevel: 'negative' as const, runId: 'r2' },
      { binaryHash: 'def', finalLevel: 'high'     as const, runId: 'r3' },
      { binaryHash: 'def', finalLevel: 'negative' as const, runId: 'r4' },
    ];
    const [score] = computeStabilityScore(snapshots);

    expect(score.flipCount).toBe(3);
  });

  it('groups results by binaryHash', () => {
    const snapshots = [
      { binaryHash: 'aaa', finalLevel: 'high' as const, runId: 'r1' },
      { binaryHash: 'bbb', finalLevel: 'low'  as const, runId: 'r2' },
    ];
    const results = computeStabilityScore(snapshots);

    expect(results).toHaveLength(2);
  });

  it('handles single-run binary', () => {
    const snapshots = [{ binaryHash: 'single', finalLevel: 'medium' as const, runId: 'r1' }];
    const [score]   = computeStabilityScore(snapshots);

    expect(score.runCount).toBe(1);
    expect(score.flipCount).toBe(0);
    expect(score.consistencyPct).toBe(100);
  });
});
