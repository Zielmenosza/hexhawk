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
      'gyreSnapshotId={activeGyreSnapshotBinding?.snapshotId ?? null}',
    );
  });

  it('keeps authority-bearing App consumers on the ordinary GYRE verdict', () => {
    expect(appSource).toMatch(/<BinaryVerdict\s+verdict=\{verdict\}/);
    expect(appSource).toMatch(/<AnalysisGraph[\s\S]*?verdict=\{verdict\}/);
    expect(appSource).toMatch(/<IntelligenceReport[\s\S]*?verdict=\{verdict\}/);
    expect(appSource).toContain('baseVerdict={verdict}');
    expect(appSource).toContain('verdict: verdict');
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
});
