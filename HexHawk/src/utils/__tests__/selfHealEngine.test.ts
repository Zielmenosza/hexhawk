/**
 * selfHealEngine tests — unit tests for gap detection and prescription logic
 */

import { describe, it, expect } from 'vitest';
import { diagnose } from '../../utils/selfHealEngine';
import type { PipelineState } from '../../utils/selfHealEngine';
import type { BinaryVerdictResult } from '../../utils/correlationEngine';

// ─── Fixtures ─────────────────────────────────────────────────────────────────

function makeVerdict(overrides: Partial<BinaryVerdictResult> = {}): BinaryVerdictResult {
  return {
    classification: 'clean',
    threatScore: 5,
    confidence: 88,
    summary: 'No threats detected.',
    signals: [{ id: 's1', source: 'struct', finding: 'low entropy', weight: 1, corroboratedBy: [] }, { id: 's2', source: 'string', finding: 'no suspicious strings', weight: 1, corroboratedBy: [] }, { id: 's3', source: 'import', finding: 'benign imports', weight: 1, corroboratedBy: [] }],
    negativeSignals: [],
    behaviors: [],
    reasoningChain: [],
    contradictions: [],
    alternatives: [],
    nextSteps: [],
    iocs: [],
    signalCount: 3,
    ...overrides,
  } as unknown as BinaryVerdictResult;
}

function makeState(overrides: Partial<PipelineState> = {}): PipelineState {
  return {
    hasMetadata: true,
    disassemblyCount: 500,
    stringCount: 200,
    hasCfg: true,
    hasStrike: false,
    hasNest: false,
    verdict: makeVerdict(),
    ...overrides,
  };
}

// ─── Tests ────────────────────────────────────────────────────────────────────

describe('selfHealEngine.diagnose', () => {
  it('returns needed=false when pipeline is healthy', () => {
    const result = diagnose(makeState());
    expect(result.needed).toBe(false);
    expect(result.prescriptions).toHaveLength(0);
  });

  it('returns needed=false when no binary is loaded', () => {
    const result = diagnose(makeState({ hasMetadata: false, verdict: null }));
    expect(result.needed).toBe(false);
  });

  it('prescribes scan_strings when strings have not been run', () => {
    const result = diagnose(makeState({ stringCount: 0 }));
    expect(result.needed).toBe(true);
    const p = result.prescriptions.find(p => p.action === 'scan_strings');
    expect(p).toBeDefined();
    expect(p!.estimatedGain).toBeGreaterThan(0);
  });

  it('prescribes disassemble when disassembly has not been run', () => {
    const result = diagnose(makeState({ disassemblyCount: 0 }));
    expect(result.needed).toBe(true);
    const p = result.prescriptions.find(p => p.action === 'disassemble');
    expect(p).toBeDefined();
    expect(p!.estimatedGain).toBeGreaterThan(0);
  });

  it('prescribes build_cfg when disassembly exists but CFG does not', () => {
    const result = diagnose(makeState({ hasCfg: false, disassemblyCount: 500 }));
    expect(result.needed).toBe(true);
    const p = result.prescriptions.find(p => p.action === 'build_cfg');
    expect(p).toBeDefined();
  });

  it('prescribes run_nest when confidence is below warning threshold and NEST not run', () => {
    const result = diagnose(makeState({ verdict: makeVerdict({ confidence: 40, classification: 'suspicious' }) }));
    expect(result.needed).toBe(true);
    const p = result.prescriptions.find(p => p.action === 'run_nest');
    expect(p).toBeDefined();
  });

  it('severity is critical when confidence is below critical threshold', () => {
    const result = diagnose(makeState({ verdict: makeVerdict({ confidence: 20, classification: 'unknown' }) }));
    expect(result.severity).toBe('critical');
  });

  it('severity is warning when confidence is between warning and critical', () => {
    const result = diagnose(makeState({ verdict: makeVerdict({ confidence: 45 }) }));
    expect(result.severity).toBe('warning');
  });

  it('suggests LLM when contradiction count is high', () => {
    const verdict = makeVerdict({
      confidence: 25,
      contradictions: [
        { id: 'c1', severity: 'high', observation: 'A', conflict: 'B', resolution: '' },
        { id: 'c2', severity: 'high', observation: 'C', conflict: 'D', resolution: '' },
        { id: 'c3', severity: 'medium', observation: 'E', conflict: 'F', resolution: '' },
        { id: 'c4', severity: 'low', observation: 'G', conflict: 'H', resolution: '' },
      ],
    });
    const result = diagnose(makeState({ verdict }));
    expect(result.suggestLlm).toBe(true);
  });

  it('prescriptions are sorted with highest estimated gain first', () => {
    const result = diagnose(makeState({ stringCount: 0, disassemblyCount: 0, hasCfg: false, verdict: makeVerdict({ confidence: 40 }) }));
    const gains = result.prescriptions.map(p => p.estimatedGain);
    for (let i = 1; i < gains.length; i++) {
      expect(gains[i]).toBeLessThanOrEqual(gains[i - 1]);
    }
  });

  it('does not prescribe run_nest if NEST has already been run and confidence is adequate', () => {
    const result = diagnose(makeState({ hasNest: true, verdict: makeVerdict({ confidence: 88 }) }));
    const p = result.prescriptions.find(p => p.action === 'run_nest');
    expect(p).toBeUndefined();
  });

  it('includes summary text when healing is needed', () => {
    const result = diagnose(makeState({ stringCount: 0, disassemblyCount: 0 }));
    expect(result.summary.length).toBeGreaterThan(0);
    expect(result.conditions.length).toBeGreaterThan(0);
  });
});
