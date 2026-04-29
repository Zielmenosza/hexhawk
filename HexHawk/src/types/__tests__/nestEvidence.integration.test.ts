import { describe, it, expect } from 'vitest';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { NestSession, NestSummary } from '../../utils/nestEngine';
import type { BinaryVerdictResult } from '../../utils/correlationEngine';
import {
  buildNestEvidenceBundleFromSession,
  toNestEvidenceFileMap,
  parseNestEvidenceFileMap,
  validateBuiltNestEvidenceBundle,
} from '../../utils/nestEvidenceIntegration';
import { validateNestEvidenceBundle } from '../nestEvidence';
import { makeFullBundle } from '../../test/fixtures/nestEvidenceFixtures';

function makeSimulatedVerdict(): BinaryVerdictResult {
  return {
    classification: 'likely-malware',
    threatScore: 82,
    confidence: 82,
    signals: [
      {
        source: 'strings',
        id: 'sig-c2-url',
        finding: 'Suspicious C2 URL pattern found in string table',
        weight: 8,
        corroboratedBy: ['sig-imp-winhttp'],
      },
    ],
    negativeSignals: [],
    amplifiers: ['cross-signal corroboration'],
    dismissals: [],
    summary: 'Likely malware due to C2-like string patterns and suspicious API profile.',
    explainability: [
      { factor: 'C2 pattern strings', contribution: 'increases', detail: 'Multiple URL and beacon-like tokens found.' },
    ],
    nextSteps: [
      { priority: 'high', action: 'Inspect C2 strings in context', rationale: 'May reveal campaign family.', tab: 'strings' },
    ],
    signalCount: 1,
    behaviors: ['c2-communication'],
    reasoningChain: [
      { stage: 1, name: 'Signals', findings: ['c2-url pattern'], conclusion: 'Suspicious network intent', confidence: 78 },
      { stage: 2, name: 'Correlation', findings: ['import corroboration'], conclusion: 'Likely active beacon path', confidence: 82 },
      { stage: 3, name: 'Verdict', findings: ['malicious indicators'], conclusion: 'likely-malware', confidence: 82 },
    ],
    contradictions: [],
    alternatives: [
      { classification: 'suspicious', label: 'Benign tool with remote updates', probability: 25, reasoning: 'Could be updater behavior', requiredEvidence: ['signed updater metadata'] },
    ],
    uncertaintyFlags: [],
    heuristicSignalIds: [],
  };
}

function makeSimulatedSession(): { session: NestSession; summary: NestSummary } {
  const verdict1 = makeSimulatedVerdict();
  const verdict2 = { ...makeSimulatedVerdict(), confidence: 87, threatScore: 87, summary: 'Malicious confidence increased after refinement.' };

  const now = Date.now();
  const session = {
    id: 'nest-simulated-session',
    binaryPath: 'D:/Challenges/FlareAuthenticator/FlareAuthenticator.exe',
    config: {
      maxIterations: 5,
      minIterations: 2,
      confidenceThreshold: 80,
      plateauThreshold: 3,
      disasmExpansion: 512,
      aggressiveness: 'balanced',
      enableTalon: true,
      enableStrike: false,
      enableEcho: true,
      autoAdvance: true,
      autoAdvanceDelay: 0,
    },
    iterations: [
      {
        iteration: 0,
        timestamp: now,
        input: {
          disasmOffset: 0,
          disasmLength: 4096,
          instructionCount: 300,
          sections: [],
          imports: [],
          strings: [{ text: 'http://mal.example/c2' }],
          patterns: [],
          signatureMatches: [],
          iterationIndex: 0,
        },
        verdict: verdict1,
        confidence: 82,
        refinementPlan: {
          actions: [
            {
              type: 'expand-disasm-forward',
              priority: 'high',
              offset: 4096,
              length: 4096,
              reason: 'Need more code context',
              signal: 'sig-c2-url',
            },
          ],
          rationale: 'Expand around suspicious strings',
          expectedBoost: 5,
          primaryAction: {
            type: 'expand-disasm-forward',
            priority: 'high',
            offset: 4096,
            length: 4096,
            reason: 'Need more code context',
            signal: 'sig-c2-url',
          },
        },
        delta: null,
        annotations: ['continue'],
        durationMs: 1200,
        stabilityReport: {
          score: 0.62,
          grade: 'unstable',
          classificationConsistency: 1,
          signalSetStability: 0.6,
          confidenceStdDev: 2,
          classificationFlips: 0,
          convergenceReliable: false,
          diagnosis: 'Early iteration, keep iterating',
        },
        reasoningChain: {
          verdict: 'likely-malware',
          confidence: 82,
          iteration: 0,
          topSignals: [],
          steps: [],
          narrative: 'Initial suspicious indicators observed.',
          nextSteps: [],
        },
      },
      {
        iteration: 1,
        timestamp: now + 1500,
        input: {
          disasmOffset: 4096,
          disasmLength: 4096,
          instructionCount: 380,
          sections: [],
          imports: [],
          strings: [{ text: 'WinHttpOpen' }],
          patterns: [],
          signatureMatches: [],
          iterationIndex: 1,
        },
        verdict: verdict2,
        confidence: 87,
        refinementPlan: {
          actions: [],
          rationale: 'Converged confidence',
          expectedBoost: 0,
          primaryAction: null,
        },
        delta: {
          confidenceDelta: 5,
          newSignals: ['sig-imp-winhttp'],
          removedSignals: [],
          verdictChanged: false,
          behaviorsAdded: [],
          behaviorsRemoved: [],
          corroborationsAdded: 1,
          significantChange: true,
          summary: 'Added API corroboration and raised confidence.',
        },
        annotations: ['confidence-threshold'],
        durationMs: 900,
        stabilityReport: {
          score: 0.9,
          grade: 'stable',
          classificationConsistency: 1,
          signalSetStability: 0.95,
          confidenceStdDev: 1,
          classificationFlips: 0,
          convergenceReliable: true,
          diagnosis: 'Stable and converged',
        },
        reasoningChain: {
          verdict: 'likely-malware',
          confidence: 87,
          iteration: 1,
          topSignals: [],
          steps: [],
          narrative: 'Corroboration increased confidence.',
          nextSteps: [],
        },
      },
    ],
    status: 'converged',
    finalVerdict: verdict2,
    startTime: now - 3000,
    endTime: now + 2000,
    convergedAt: 1,
    errorMessage: null,
  } as unknown as NestSession;

  const summary: NestSummary = {
    totalIterations: 2,
    finalConfidence: 87,
    finalVerdict: 'likely-malware',
    totalDurationMs: 3000,
    confidenceProgression: [82, 87],
    convergedReason: 'confidence-threshold',
    keyFindings: ['Iter 2: Added API corroboration and raised confidence.'],
    improvementTotal: 5,
  };

  return { session, summary };
}

function writeBundleToDir(dir: string, bundle: ReturnType<typeof buildNestEvidenceBundleFromSession>) {
  const files = toNestEvidenceFileMap(bundle);
  for (const [name, value] of Object.entries(files)) {
    writeFileSync(join(dir, name), JSON.stringify(value, null, 2), 'utf8');
  }
}

describe('NEST evidence integration', () => {
  it('generates, validates, writes, and reads back bundle from simulated session', () => {
    const { session, summary } = makeSimulatedSession();
    const bundle = buildNestEvidenceBundleFromSession({
      binaryPath: session.binaryPath,
      binarySha256: 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2',
      fileSizeBytes: 184320,
      format: 'PE/MZ',
      architecture: 'x86_64',
      session,
      summary,
      actorId: 'system:test',
      actorType: 'system',
      executionMode: 'cli',
      exportMode: 'local-tauri',
    });

    const buildValidation = validateBuiltNestEvidenceBundle(bundle);
    expect(buildValidation.ok).toBe(true);
    expect(bundle.final_verdict_snapshot.source_engine).toBe('gyre');
    expect(bundle.session.gyre_linkage.gyre_is_sole_verdict_source).toBe(true);
    expect(bundle.final_verdict_snapshot.nest_linkage.gyre_is_sole_verdict_source).toBe(true);
    expect(bundle.binary_identity.file_bound_proof.binary_sha256).toBe(bundle.binary_identity.binary_sha256);

    const tmp = mkdtempSync(join(tmpdir(), 'nest-evidence-it-'));
    try {
      writeBundleToDir(tmp, bundle);
      const loaded = {
        'manifest.json': JSON.parse(readFileSync(join(tmp, 'manifest.json'), 'utf8')),
        'binary_identity.json': JSON.parse(readFileSync(join(tmp, 'binary_identity.json'), 'utf8')),
        'session.json': JSON.parse(readFileSync(join(tmp, 'session.json'), 'utf8')),
        'iterations.json': JSON.parse(readFileSync(join(tmp, 'iterations.json'), 'utf8')),
        'deltas.json': JSON.parse(readFileSync(join(tmp, 'deltas.json'), 'utf8')),
        'final_verdict_snapshot.json': JSON.parse(readFileSync(join(tmp, 'final_verdict_snapshot.json'), 'utf8')),
        'audit_refs.json': JSON.parse(readFileSync(join(tmp, 'audit_refs.json'), 'utf8')),
      } as Record<string, unknown>;

      const parsed = parseNestEvidenceFileMap(loaded);
      expect(parsed.ok).toBe(true);
      if (parsed.ok) {
        expect(parsed.value.session.iteration_count).toBe(2);
        expect(parsed.value.final_verdict_snapshot.source_engine).toBe('gyre');
      }
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('rejects malformed bundle content through parseNestEvidenceFileMap', () => {
    const bundle = makeFullBundle();
    const files = {
      'manifest.json': bundle.manifest,
      'binary_identity.json': bundle.binary_identity,
      'session.json': bundle.session,
      'iterations.json': bundle.iterations,
      'deltas.json': bundle.deltas,
      'final_verdict_snapshot.json': { ...bundle.final_verdict_snapshot, source_engine: 'nest' },
      'audit_refs.json': bundle.audit_refs,
      'runtime_proof.json': bundle.runtime_proof,
    };

    const parsed = parseNestEvidenceFileMap(files);
    expect(parsed.ok).toBe(false);
    if (!parsed.ok) {
      expect(parsed.issues.some((i) => i.code === 'replay-critical-error')).toBe(true);
    }
  });

  it('rejects schema major mismatch on load', () => {
    const bundle = makeFullBundle();
    const files = {
      'manifest.json': { ...bundle.manifest, schema_version: '2.0.0' },
      'binary_identity.json': bundle.binary_identity,
      'session.json': bundle.session,
      'iterations.json': bundle.iterations,
      'deltas.json': bundle.deltas,
      'final_verdict_snapshot.json': bundle.final_verdict_snapshot,
      'audit_refs.json': bundle.audit_refs,
      'runtime_proof.json': bundle.runtime_proof,
    };

    const parsed = parseNestEvidenceFileMap(files);
    expect(parsed.ok).toBe(false);
    if (!parsed.ok) {
      expect(parsed.issues.some((i) => i.code === 'unsupported-schema-version')).toBe(true);
    }
  });

  it('preserves replay-critical fields in generated bundle', () => {
    const { session, summary } = makeSimulatedSession();
    const bundle = buildNestEvidenceBundleFromSession({
      binaryPath: session.binaryPath,
      binarySha256: 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2',
      fileSizeBytes: 184320,
      format: 'PE/MZ',
      architecture: 'x86_64',
      session,
      summary,
      actorId: 'system:test',
      actorType: 'system',
      executionMode: 'cli',
      exportMode: 'local-tauri',
    });

    const issues = validateNestEvidenceBundle(bundle);
    expect(issues).toHaveLength(0);
    expect(bundle.final_verdict_snapshot.source_engine).toBe('gyre');
    expect(bundle.session.gyre_linkage.gyre_is_sole_verdict_source).toBe(true);
    expect(bundle.binary_identity.file_bound_proof.file_size_bytes).toBe(bundle.binary_identity.file_size_bytes);
  });

  it('accepts golden fixture bundles through new file-map parser', () => {
    const fixture = makeFullBundle();
    const parsed = parseNestEvidenceFileMap({
      'manifest.json': fixture.manifest,
      'binary_identity.json': fixture.binary_identity,
      'session.json': fixture.session,
      'iterations.json': fixture.iterations,
      'deltas.json': fixture.deltas,
      'final_verdict_snapshot.json': fixture.final_verdict_snapshot,
      'audit_refs.json': fixture.audit_refs,
      'runtime_proof.json': fixture.runtime_proof,
    });

    expect(parsed.ok).toBe(true);
    if (parsed.ok) {
      expect(parsed.value.runtime_proof?.proof_status).toBe('proven');
    }
  });
});
