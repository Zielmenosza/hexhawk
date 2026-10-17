import { describe, expect, it } from 'vitest';
import { computeVerdict } from '../correlationEngine';
import { runYaraRules } from '../yaraEngine';
import { computeCorpusMetrics, type BinaryRunRecord } from '../corpusPipeline';

const base = { sections: [{ name: '.text', entropy: 4.5, file_size: 4096 }], imports: [], strings: [], patterns: [] };
function record(groundTruth: BinaryRunRecord['groundTruth'], finalVerdict: string, errorMessage: string | null = null): BinaryRunRecord {
  return { sha256: 'a'.repeat(64), path: 'authored-feature-control', filename: 'control', label: 'CHALLENGE',
    groundTruth, finalVerdict, finalConfidence: 80, convergenceIterations: 1, convergenceReason: null,
    confidenceDeltas: [], signalsFired: [], durationMs: 1, pass: true, errorMessage };
}

describe('verdict provenance reliability — authored feature controls, not malware accuracy', () => {
  it.each([false, true])('preserves literal YARA observation despite Composite rule suffix (corroborated=%s)', corroborated => {
    const bytes = new TextEncoder().encode('HH_LITERAL_42');
    const matches = runYaraRules(bytes, 'rule Example_Composite : c2 { meta: threat_class = "c2" strings: $marker = "HH_LITERAL_42" condition: $marker }');
    expect(matches.some(match => match.ruleName === 'Example_Composite')).toBe(true);
    const verdict = computeVerdict({ ...base, imports: corroborated ? [{ name: 'WSAStartup', library: 'WS2_32' }] : [], yaraMatches: matches });
    expect(verdict.signals.find(signal => signal.id === 'yara-example-composite')).toMatchObject({ certainty: 'observed' });
  });
  it('keeps literal imports observed but the RAT composite conclusion inferred', () => {
    const input = { ...base, imports: ['WSAStartup', 'GetSystemInfo', 'GetVersionExA', 'GlobalMemoryStatusEx'].map(name => ({ name, library: 'authored-control' })) };
    const verdict = computeVerdict(input);
    expect(verdict.signals.find(signal => signal.id === 'rat-composite')).toMatchObject({ certainty: 'inferred' });
    expect(verdict.signals.find(signal => signal.id === 'network-imports')).toMatchObject({ certainty: 'observed' });
  });
  it('does not turn absence of signals into a clean/safe certificate', () => {
    const verdict = computeVerdict(base);
    expect(verdict.threatScore).toBe(0);
    expect(verdict.confidence).toBe(15);
    expect(verdict.uncertaintyFlags.length).toBeGreaterThan(0);
    expect(verdict.signals).toHaveLength(0);
  });
});

describe('explicit labelled-quality metrics beside unchanged legacy diagnostics', () => {
  it('reports absent class support as unmeasured, not measured zero error', () => {
    const q = computeCorpusMetrics([]).qualityEvaluation;
    expect(q).toMatchObject({ labelledCount: 0, unlabelledCount: 0, skippedCount: 0,
      strictAccuracyPct: null, definitiveCoveragePct: null,
      falsePositiveRateAmongDefinitivePct: null, falseNegativeRateAmongDefinitivePct: null });
  });
  it('does not count unlabelled or challenge observations as accuracy successes', () => {
    const q = computeCorpusMetrics([record('unknown', 'dropper'), record('challenge', 'clean'), record('clean', 'dropper')]).qualityEvaluation;
    expect(q).toMatchObject({ labelledCount: 1, unlabelledCount: 2, correctCount: 0,
      strictAccuracyPct: 0, confusion: { truePositive: 0, trueNegative: 0, falsePositive: 1, falseNegative: 0 } });
  });
  it('treats suspicious and unknown predictions as explicit abstentions for both label classes', () => {
    const q = computeCorpusMetrics([record('clean', 'suspicious'), record('malicious', 'unknown')]).qualityEvaluation;
    expect(q).toMatchObject({ labelledCount: 2, abstainedCount: 2, correctCount: 0,
      strictAccuracyPct: 0, definitiveCoveragePct: 0,
      falsePositiveRateAmongDefinitivePct: null, falseNegativeRateAmongDefinitivePct: null });
  });
  it('does not trust legacy pass flags or treat unsupported verdict strings as malicious', () => {
    const q = computeCorpusMetrics([record('clean', 'dropper'), record('malicious', 'clean'), record('clean', 'invented-verdict')]).qualityEvaluation;
    expect(q).toMatchObject({ correctCount: 0, abstainedCount: 1, confusion: { falsePositive: 1, falseNegative: 1 } });
  });
  it('separates skipped runs and publishes the support behind measured rates', () => {
    const q = computeCorpusMetrics([record('clean', 'clean'), record('malicious', 'dropper'), record('clean', 'unknown', 'skipped')]).qualityEvaluation;
    expect(q).toMatchObject({ labelledCount: 2, skippedCount: 1, correctCount: 2, strictAccuracyPct: 100,
      definitiveCoveragePct: 100, support: { clean: 1, malicious: 1 },
      falsePositiveRateAmongDefinitivePct: 0, falseNegativeRateAmongDefinitivePct: 0 });
    expect(q!.proofLimit).toMatch(/supplied labels.*not.*independently|not.*independently.*supplied labels/i);
  });
});
