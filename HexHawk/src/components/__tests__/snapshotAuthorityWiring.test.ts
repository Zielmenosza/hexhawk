/** @vitest-environment node */
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const appSource = readFileSync(
  new URL('../../App.tsx', import.meta.url),
  'utf8',
);
const nestViewSource = readFileSync(
  new URL('../NestView.tsx', import.meta.url),
  'utf8',
);

describe('snapshot authority production wiring', () => {
  it('routes App snapshot recording through the production hook', () => {
    expect(appSource).toContain('useGyreSnapshotRecording({');
    expect(appSource).toMatch(
      /useGyreSnapshotRecording\(\{[\s\S]*?binaryPath,[\s\S]*?binarySha256:[\s\S]*?verdict,[\s\S]*?\}\)/,
    );
    expect(appSource).not.toContain('recordGyreVerdictSnapshot(');
    expect(appSource).toContain(
      'gyreSnapshotId={authorityGyreSnapshotId}',
    );
  });

  it('hydrates persisted GYRE authority without recording a replacement snapshot', () => {
    expect(appSource).toContain('const persistedAuthorityProject =');
    expect(appSource).toContain(
      'verdictFromResolvedProject(persistedAuthorityProject)',
    );
    expect(appSource).toContain(
      'browserMode: browserMode || persistedAuthorityProject !== null',
    );
    expect(appSource).toContain('const authorityGyreSnapshotId =');
    expect(appSource).toMatch(/<BinaryVerdict\s+verdict=\{authorityVerdict\}/);
    expect(appSource).toMatch(/<AnalysisGraph[\s\S]*?verdict=\{authorityVerdict\}/);
    expect(appSource).toMatch(/<IntelligenceReport[\s\S]*?verdict=\{authorityVerdict\}/);
    expect(appSource).toContain('baseVerdict={authorityVerdict}');
    expect(appSource).toContain('verdict: authorityVerdict');
    expect(appSource).toContain('gyreSnapshotId={authorityGyreSnapshotId}');
    expect(appSource).not.toContain('nestEnrichedVerdict ?? verdict');
    expect(appSource).toContain('NEST advisory:');
    expect(appSource).toContain('GYRE base confidence remains');
  });

  it('routes NestView lifecycle work through the production coordinator', () => {
    expect(nestViewSource).toContain(
      'new NestLifecycleCoordinator<NestStepResult>()',
    );
    expect(nestViewSource).toContain(
      'lifecycleCoordinatorRef.current.processNext(',
    );
    expect(nestViewSource).not.toContain(
      "invoke('nest_append_iteration'",
    );
    expect(nestViewSource).not.toContain(
      "invoke('nest_finalize_session'",
    );
  });

  it('passes only canonical finalized NEST linkage into project persistence', () => {
    expect(nestViewSource).toContain(
      'onProjectLinkageReady?: (linkage: NestProjectLinkage) => void;',
    );
    expect(nestViewSource).toContain(
      'projectLinkage = lifecycleResult.projectLinkage;',
    );
    expect(nestViewSource).toContain(
      'onProjectLinkageReady?.(projectLinkage);',
    );
    expect(appSource).toContain(
      'onProjectLinkageReady={setNestProjectLinkage}',
    );
    expect(appSource).toContain(
      'nestProjectLinkage?.finalVerdictSnapshotId === authorityGyreSnapshotId',
    );
    expect(appSource).toContain('setNestProjectLinkage(resolved.nest);');
  });
});
