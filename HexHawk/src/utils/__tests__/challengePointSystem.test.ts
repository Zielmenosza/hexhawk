import {
  buildChallengePointManifest,
  scoreChallengePointManifest,
  summarizeChallengePointScore,
  validateChallengePointManifest,
  type ChallengePointInventoryEntry,
} from '../challengePointSystem';
import { describe, expect, it } from 'vitest';

const baseEntries: ChallengePointInventoryEntry[] = [
  {
    path: 'Challenges/ch76/keygenme.exe',
    sha256: 'beb23342145c78dc0f3301eaf5c6af7a7909be0b69d32018ea739a562b0e3c77',
    sizeBytes: 2_804_697,
    kind: 'pe-executable',
    safety: 'authorized-challenge',
    evidenceState: 'native-proven',
    coverage: {
      metadata: true,
      strings: true,
      disassembly: true,
      cfg: true,
      referenceGraph: true,
      crestBundle: true,
      replayCommand: true,
      guiSmoke: true,
    },
    limits: {
      fileSizeClass: 'medium',
      cfgTruncated: false,
      artifactBudgeted: true,
    },
    cAccuracy: {
      attempted: true,
      mode: 'talon-annotated',
      functionsReviewed: 4,
      cLikeLines: 42,
      typedVariables: 8,
      recoveredBranches: 5,
      recoveredLoops: 1,
      unresolvedInstructions: 12,
      unresolvedCalls: 3,
      compileChecked: false,
      roundTripChecked: false,
      authoritySafe: true,
    },
    proofArtifacts: {
      replayCommand: 'nest_cli inspect "Challenges/ch76/keygenme.exe"',
      crestBundlePath: 'work/challenge-proof/keygenme/crest.json',
      guiSmokePath: 'work/challenge-proof/keygenme/gui.json',
      backendInspectPath: 'work/challenge-proof/keygenme/inspect.json',
      backendStringsPath: 'work/challenge-proof/keygenme/strings.json',
      backendDisassemblyPath: 'work/challenge-proof/keygenme/disassembly.json',
      backendCfgPath: 'work/challenge-proof/keygenme/cfg.json',
      cAccuracyProofPath: 'work/challenge-proof/keygenme/c-accuracy.json',
    },
  },
  {
    path: 'Challenges/3 - pretty_devilish_file/pretty_devilish_file.pdf',
    sha256: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    sizeBytes: 1_485,
    kind: 'document',
    safety: 'authorized-challenge',
    evidenceState: 'inventoried',
    coverage: {
      metadata: true,
      strings: false,
      disassembly: false,
      cfg: false,
      referenceGraph: false,
      crestBundle: false,
      replayCommand: false,
      guiSmoke: false,
    },
    limits: {
      fileSizeClass: 'tiny',
      cfgTruncated: false,
      artifactBudgeted: true,
    },
  },
  {
    path: 'Challenges/9 - 10000/10000.exe',
    sha256: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    sizeBytes: 1_156_786_688,
    kind: 'oversized-binary',
    safety: 'authorized-challenge',
    evidenceState: 'inventoried',
    coverage: {
      metadata: true,
      strings: false,
      disassembly: false,
      cfg: false,
      referenceGraph: false,
      crestBundle: false,
      replayCommand: false,
      guiSmoke: false,
    },
    limits: {
      fileSizeClass: 'huge',
      cfgTruncated: true,
      artifactBudgeted: true,
    },
    cAccuracy: {
      attempted: true,
      mode: 'static-heuristic',
      functionsReviewed: 1,
      cLikeLines: 80,
      typedVariables: 14,
      recoveredBranches: 8,
      recoveredLoops: 0,
      unresolvedInstructions: 10,
      unresolvedCalls: 2,
      compileChecked: false,
      roundTripChecked: false,
      authoritySafe: true,
    },
  },
  {
    path: 'Challenges/DDB/Unconfirmed 567992.crdownload',
    sha256: 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
    sizeBytes: 136_704,
    kind: 'partial-download',
    safety: 'quarantine-required',
    evidenceState: 'quarantined',
    coverage: {
      metadata: false,
      strings: false,
      disassembly: false,
      cfg: false,
      referenceGraph: false,
      crestBundle: false,
      replayCommand: false,
      guiSmoke: false,
    },
    limits: {
      fileSizeClass: 'small',
      cfgTruncated: false,
      artifactBudgeted: false,
    },
  },
];

describe('challengePointSystem', () => {
  it('builds a deterministic authority-safe corpus manifest', () => {
    const manifest = buildChallengePointManifest({
      generatedAt: '2026-07-25T21:55:00.000Z',
      sourceRoot: 'D:/Project/HexHawk/Challenges',
      entries: [...baseEntries].reverse(),
      custodyActions: [
        { action: 'quarantine-note', path: 'Challenges/DDB/Unconfirmed 567992.crdownload', reason: 'partial browser download', destructive: false },
      ],
    });

    expect(manifest.schema).toBe('hexhawk.challenge_point_system.v1');
    expect(manifest.entries.map((entry) => entry.path)).toEqual([
      'Challenges/3 - pretty_devilish_file/pretty_devilish_file.pdf',
      'Challenges/9 - 10000/10000.exe',
      'Challenges/ch76/keygenme.exe',
      'Challenges/DDB/Unconfirmed 567992.crdownload',
    ]);
    expect(manifest.authorityBoundary).toContain('GYRE remains sole verdict authority');
    expect(JSON.stringify(manifest)).not.toMatch(/verdict correctness is proven|release-ready/i);
  });

  it('validates hashes, custody actions, safety labels, and challenge diversity', () => {
    const manifest = buildChallengePointManifest({
      generatedAt: '2026-07-25T21:55:00.000Z',
      sourceRoot: 'D:/Project/HexHawk/Challenges',
      entries: baseEntries,
      custodyActions: [
        { action: 'delete', path: 'D:/Project/random', reason: 'too broad', destructive: true },
      ],
    });

    const validation = validateChallengePointManifest(manifest);
    expect(validation.ok).toBe(false);
    expect(validation.errors).toContain('destructive cleanup actions are not allowed in challenge point manifests');
    expect(validation.warnings).toContain('partial downloads must stay quarantined or be excluded from scoring');
  });

  it('scores difficult full-corpus progress without making hype claims', () => {
    const manifest = buildChallengePointManifest({
      generatedAt: '2026-07-25T21:55:00.000Z',
      sourceRoot: 'D:/Project/HexHawk/Challenges',
      entries: baseEntries,
      custodyActions: [
        { action: 'quarantine-note', path: 'Challenges/DDB/Unconfirmed 567992.crdownload', reason: 'partial browser download', destructive: false },
      ],
    });

    const score = scoreChallengePointManifest(manifest);
    expect(score.total).toBeGreaterThanOrEqual(60);
    expect(score.total).toBeLessThan(100);
    expect(score.categories.identity.available).toBe(20);
    expect(score.categories.challengeDiversity.points).toBeGreaterThan(0);
    expect(score.categories.integrity.points).toBeLessThan(score.categories.integrity.available);
    expect(score.penalties.some((penalty) => penalty.reason.includes('quarantine'))).toBe(true);
    expect(score.claims.releaseReady).toBe(false);
    expect(score.claims.verdictCorrectnessProven).toBe(false);
  });

  it('summarizes the score for UI/report handoff with exact next steps', () => {
    const manifest = buildChallengePointManifest({
      generatedAt: '2026-07-25T21:55:00.000Z',
      sourceRoot: 'D:/Project/HexHawk/Challenges',
      entries: baseEntries,
      custodyActions: [],
    });
    const summary = summarizeChallengePointScore(scoreChallengePointManifest(manifest));

    expect(summary).toContain('Challenge Point System');
    expect(summary).toContain('Not release-ready');
    expect(summary).toContain('Next highest-value work');
    expect(summary).toContain('partial-download');
    expect(summary).not.toMatch(/perfect|fully automated reverse engineering/i);
  });
});
