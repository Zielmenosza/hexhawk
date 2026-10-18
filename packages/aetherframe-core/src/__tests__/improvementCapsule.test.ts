import { describe, expect, it } from 'vitest';
import {
  loadImprovementCapsuleFile,
  negotiateSchemaVersion,
  scoreImprovementCapsule,
  validateImprovementCapsule,
  type AetherFrameImprovementCapsule,
} from '../index';

const capsule: AetherFrameImprovementCapsule = {
  schemaVersion: 'aetherframe.improvement_capsule.v1',
  capsuleId: 'hexhawk.native-evidence-contract.v1',
  title: 'Native evidence contract',
  product: 'HexHawk',
  objective: 'Make native, simulated, imported, and advisory evidence visibly distinct.',
  hypothesis: 'Typed provenance will prevent silent simulation fallback and make GUI claims traceable.',
  status: 'approved',
  authorityBoundary: {
    protectedFields: ['classification', 'base_confidence', 'source_engine', 'nest_evidence_selection'],
    forbiddenActions: ['mutate GYRE verdict fields', 'replace NEST evidence selection', 'deploy or publish'],
    requiredApprovals: ['human approval before staging, committing, pushing, or deployment'],
  },
  scope: {
    targetPaths: [
      'HexHawk/src/utils/analysisProvenance.ts',
      'HexHawk/src/utils/__tests__/analysisProvenance.test.ts',
    ],
    maxFilesChanged: 2,
    maxChangedLines: 240,
    allowedChangeKinds: ['code', 'tests'],
  },
  budget: {
    maxDurationMinutes: 120,
    maxIterations: 4,
    maxTestCommands: 3,
  },
  evidence: [
    {
      id: 'repo-provenance-module',
      kind: 'repo_state',
      reference: 'HexHawk/src/utils/analysisProvenance.ts',
      claim: 'A provenance utility exists and distinguishes browser simulation from the real backend.',
      capturedAt: '2026-07-23T20:00:00.000Z',
      reproducible: true,
    },
    {
      id: 'baseline-af-tests',
      kind: 'test_result',
      reference: 'yarn workspace @hexhawk/aetherframe-core test',
      claim: 'AetherFrame core baseline passes before this capsule is applied.',
      capturedAt: '2026-07-23T20:01:00.000Z',
      reproducible: true,
    },
  ],
  uncertainty: {
    level: 'medium',
    unresolvedQuestions: ['The current provenance utility is untracked and may belong to concurrent work.'],
    proofLimits: ['This capsule governs an implementation attempt; it does not prove GUI/native parity by itself.'],
  },
  verification: {
    requiredCommands: ['yarn workspace hexhawk-ui test analysisProvenance'],
    successCriteria: ['Native and simulated sessions produce distinct typed provenance.', 'No GYRE or NEST authority field is mutated.'],
    failureSignals: ['Simulation is represented as native evidence.', 'A protected authority field becomes mutable.'],
    evidenceRefs: ['baseline-af-tests'],
  },
  reviewCheckpoints: ['before editing', 'after red test', 'after green test', 'before any external side effect'],
  stopConditions: ['scope collision with concurrent work', 'unexpected tracked-file dirt', 'authority-boundary violation'],
  rollbackPlan: 'Restore only the capsule allowlist to its pre-capsule content; preserve unrelated worktree state.',
  approval: {
    grantedBy: 'user',
    scope: 'Begin bounded HexHawk and AetherFrame upgrades without staging, committing, pushing, or deploying.',
    grantedAt: '2026-07-23T20:00:00.000Z',
  },
};

describe('AetherFrame improvement capsules', () => {
  it('validates a bounded, evidence-backed, approval-aware capsule', () => {
    expect(validateImprovementCapsule(capsule)).toEqual({ valid: true, errors: [] });
    expect(negotiateSchemaVersion(capsule.schemaVersion, 'improvement_capsule')).toMatchObject({ valid: true, major: 1 });
    const score = scoreImprovementCapsule(capsule);
    expect(score.executionEligible).toBe(true);
    expect(score.score).toBeGreaterThanOrEqual(80);
    expect(score.blockers).toEqual([]);
  });

  it('blocks execution when evidence is external context only', () => {
    const externalOnly: AetherFrameImprovementCapsule = {
      ...capsule,
      evidence: [{
        id: 'external-advice',
        kind: 'external_context',
        reference: 'ChatGPT strategy response',
        claim: 'External advice recommends a provenance envelope.',
        capturedAt: '2026-07-23T20:00:00.000Z',
        reproducible: false,
      }],
      verification: { ...capsule.verification, evidenceRefs: [] },
    };
    const score = scoreImprovementCapsule(externalOnly);
    expect(score.executionEligible).toBe(false);
    expect(score.blockers.join(' ')).toMatch(/repo-local|reproducible/i);
    expect(score.score).toBeLessThan(80);
  });

  it('rejects verified status without verification evidence', () => {
    const invalid: AetherFrameImprovementCapsule = {
      ...capsule,
      status: 'verified',
      verification: { ...capsule.verification, evidenceRefs: [] },
    };
    const result = validateImprovementCapsule(invalid);
    expect(result.valid).toBe(false);
    expect(result.errors.join(' ')).toMatch(/verified.*evidence/i);
  });

  it('rejects scopes that exceed their declared file budget', () => {
    const invalid: AetherFrameImprovementCapsule = {
      ...capsule,
      scope: { ...capsule.scope, maxFilesChanged: 1 },
    };
    const result = validateImprovementCapsule(invalid);
    expect(result.valid).toBe(false);
    expect(result.errors.join(' ')).toMatch(/maxFilesChanged/i);
  });

  it('rejects wildcard repository scopes instead of treating them as bounded', () => {
    const invalid: AetherFrameImprovementCapsule = {
      ...capsule,
      scope: { ...capsule.scope, targetPaths: ['HexHawk/**'], maxFilesChanged: 1 },
    };
    const result = validateImprovementCapsule(invalid);
    expect(result.valid).toBe(false);
    expect(result.errors.join(' ')).toMatch(/too broad/i);
  });

  it('loads the HexHawk native-evidence capsule fixture through the versioned schema', () => {
    const loaded = loadImprovementCapsuleFile(new URL('../../fixtures/hexhawk_native_evidence_capsule.json', import.meta.url));
    expect(loaded.valid).toBe(true);
    expect(loaded.value.schemaVersion).toBe('aetherframe.improvement_capsule.v1');
    expect(scoreImprovementCapsule(loaded.value).executionEligible).toBe(true);
  });
});
