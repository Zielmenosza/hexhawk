import { invoke } from '@tauri-apps/api/core';
import type { BinaryVerdictResult } from './correlationEngine';
import type { GyreRecordedVerdictSnapshot, NestProjectLinkage } from './gyreSnapshotClient';

export type { NestProjectLinkage } from './gyreSnapshotClient';
export interface ProjectManifest {
  schemaName: 'hexhawk.project'; schemaVersion: string; projectId: string; name: string;
  createdAt: string; updatedAt: string;
  binary: { originalPath: string; fileName: string; sizeBytes: number; sha256: string; partialSha256: string };
  gyre: { snapshotId: string; binarySha256: string; gyreBuildId: string; gyreSchemaVersion: string };
  nest: NestProjectLinkage | null; verdictAuthority: 'GYRE'; nestRole: 'advisory';
}
export interface ResolvedProject {
  manifest: ProjectManifest; resolvedBinaryPath: string; binaryWasReselected: boolean;
  gyreSnapshot: GyreRecordedVerdictSnapshot; nest: NestProjectLinkage | null;
  verdictAuthority: 'GYRE'; nestRole: 'advisory';
}
export interface SaveProjectInput { projectId: string; name: string; binaryPath: string; gyreSnapshotId: string; nest?: NestProjectLinkage | null }
export const saveProject = (request: SaveProjectInput) => invoke<ProjectManifest>('save_project', { request: { ...request, nest: request.nest ?? null } });
export const openProject = (projectId: string, selectedBinaryPath?: string | null) => invoke<ResolvedProject>('open_project', { request: { projectId, selectedBinaryPath: selectedBinaryPath ?? null } });

/** Deduplicates StrictMode/re-render saves and rejects stale open responses. */
export class ProjectPersistenceCoordinator {
  private saves = new Map<string, Promise<ProjectManifest>>();
  private openGeneration = 0;
  constructor(private readonly saveFn = saveProject, private readonly openFn = openProject) {}
  save(request: SaveProjectInput): Promise<ProjectManifest> {
    const key = JSON.stringify(request);
    const existing = this.saves.get(key); if (existing) return existing;
    const pending = this.saveFn(request).finally(() => { if (this.saves.get(key) === pending) this.saves.delete(key); });
    this.saves.set(key, pending); return pending;
  }
  async open(projectId: string, selectedBinaryPath?: string | null): Promise<ResolvedProject | null> {
    const generation = ++this.openGeneration;
    const result = await this.openFn(projectId, selectedBinaryPath);
    return generation === this.openGeneration ? result : null;
  }
  invalidateOpen(): void { this.openGeneration += 1; }
}

export function verdictFromResolvedProject(project: ResolvedProject): BinaryVerdictResult {
  const snapshot = project.gyreSnapshot;

  return {
    classification: snapshot.classification as BinaryVerdictResult['classification'],
    threatScore: snapshot.threatScore,
    confidence: snapshot.baseConfidence,
    signals: [],
    negativeSignals: [],
    amplifiers: [],
    dismissals: [],
    summary: snapshot.summary,
    explainability: [
      {
        factor: 'Persisted immutable GYRE snapshot',
        contribution: 'neutral',
        detail: `Hydrated from ${snapshot.snapshotId}; detailed reasoning remains bound by hash ${snapshot.reasoningChainHash}.`,
      },
    ],
    nextSteps: [],
    signalCount: snapshot.signalCount,
    behaviors: [],
    reasoningChain: [],
    contradictions: [],
    alternatives: [],
    uncertaintyFlags: [
      `Uncertain: persisted snapshot ${snapshot.snapshotId} preserves the authoritative verdict summary but does not embed detailed signal objects.`,
    ],
    heuristicSignalIds: [],
  };
}
