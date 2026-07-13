import { describe, expect, it } from 'vitest';
import {
  verdictFromResolvedProject,
  type ResolvedProject,
} from '../projectPersistenceClient';

function resolvedProjectFixture(): ResolvedProject {
  const binarySha256 = 'a'.repeat(64);

  return {
    manifest: {
      schemaName: 'hexhawk.project',
      schemaVersion: '1.0.0',
      projectId: 'hhproj_hydration1',
      name: 'Hydration fixture',
      createdAt: '2026-07-13T17:00:00.000Z',
      updatedAt: '2026-07-13T17:00:00.000Z',
      binary: {
        originalPath: 'C:\\fixtures\\sample.exe',
        fileName: 'sample.exe',
        sizeBytes: 4096,
        sha256: binarySha256,
        partialSha256: binarySha256,
      },
      gyre: {
        snapshotId: 'gyresnap_0123456789ABCDEFGHJKMNPQRS',
        binarySha256,
        gyreBuildId: '1.0.0+renderer-gyre',
        gyreSchemaVersion: '1.0.0',
      },
      nest: null,
      verdictAuthority: 'GYRE',
      nestRole: 'advisory',
    },
    resolvedBinaryPath: 'C:\\fixtures\\sample.exe',
    binaryWasReselected: false,
    gyreSnapshot: {
      schemaName: 'gyre.recorded_verdict_snapshot',
      schemaVersion: '1.0.0',
      snapshotId: 'gyresnap_0123456789ABCDEFGHJKMNPQRS',
      provenance: 'renderer_gyre_backend_recorded',
      binarySha256,
      classification: 'rat',
      baseConfidence: 91,
      threatScore: 88,
      summary: 'Persisted authoritative GYRE verdict.',
      signalCount: 7,
      contradictionCount: 2,
      reasoningChainHash: 'b'.repeat(64),
      gyreBuildId: '1.0.0+renderer-gyre',
      gyreSchemaVersion: '1.0.0',
      createdAt: '2026-07-13T17:00:00.000Z',
    },
    nest: null,
    verdictAuthority: 'GYRE',
    nestRole: 'advisory',
  };
}

describe('persisted GYRE verdict hydration', () => {
  it('creates a complete non-fabricated BinaryVerdictResult from the immutable snapshot', () => {
    const project = resolvedProjectFixture();
    const verdict = verdictFromResolvedProject(project);

    expect(verdict.classification).toBe('rat');
    expect(verdict.confidence).toBe(91);
    expect(verdict.threatScore).toBe(88);
    expect(verdict.summary).toBe('Persisted authoritative GYRE verdict.');
    expect(verdict.signalCount).toBe(7);

    expect(verdict.signals).toEqual([]);
    expect(verdict.negativeSignals).toEqual([]);
    expect(verdict.behaviors).toEqual([]);
    expect(verdict.reasoningChain).toEqual([]);
    expect(verdict.contradictions).toEqual([]);
    expect(verdict.alternatives).toEqual([]);
    expect(verdict.nextSteps).toEqual([]);
    expect(verdict.heuristicSignalIds).toEqual([]);

    expect(verdict.explainability[0]?.detail).toContain(
      project.gyreSnapshot.snapshotId,
    );
    expect(verdict.explainability[0]?.detail).toContain(
      project.gyreSnapshot.reasoningChainHash,
    );
    expect(verdict.uncertaintyFlags[0]).toContain(
      project.gyreSnapshot.snapshotId,
    );
  });
});
