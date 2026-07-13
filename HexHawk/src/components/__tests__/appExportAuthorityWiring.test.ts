import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const appSource = readFileSync(resolve(process.cwd(), 'src/App.tsx'), 'utf8');

const exportMatch = appSource.match(
  /function exportAnalysis\(\) \{[\s\S]*?\r?\n  \}\r?\n\r?\n  function setAndPersistTab/,
);

if (!exportMatch) {
  throw new Error('App exportAnalysis source block was not found.');
}

const exportSource = exportMatch[0];

describe('App analysis export authority wiring', () => {
  it('uses immutable provenance and redacts unavailable persisted detail', () => {
    expect(appSource).toContain(
      "import { buildFinalVerdictSnapshotExport } from './utils/reportAuthorityProvenance';",
    );

    expect(exportSource).toContain('buildFinalVerdictSnapshotExport(');
    expect(exportSource).toContain('authorityVerdict,');
    expect(exportSource).toContain(
      'persistedAuthorityProject?.gyreSnapshot ?? null',
    );
    expect(exportSource).toContain(
      'final_verdict_snapshot: finalVerdictSnapshot',
    );
    expect(exportSource).toContain(
      "detail_availability === 'summary-only'",
    );

    expect(exportSource).toMatch(
      /signals:\s*summaryOnlyVerdictDetail\s*\?\s*null\s*:\s*authorityVerdict\.signals/,
    );
    expect(exportSource).toMatch(
      /negativeSignals:\s*summaryOnlyVerdictDetail\s*\?\s*null\s*:\s*authorityVerdict\.negativeSignals/,
    );
    expect(exportSource).toMatch(
      /amplifiers:\s*summaryOnlyVerdictDetail\s*\?\s*null\s*:\s*authorityVerdict\.amplifiers/,
    );
    expect(exportSource).toMatch(
      /dismissals:\s*summaryOnlyVerdictDetail\s*\?\s*null\s*:\s*authorityVerdict\.dismissals/,
    );

    expect(exportSource).not.toContain(
      'classification: verdict.classification',
    );
    expect(exportSource).not.toContain('signals: verdict.signals');
  });
});