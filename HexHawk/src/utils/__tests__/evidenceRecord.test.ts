import { describe, expect, it } from 'vitest';
import { buildAnalysisProvenance } from '../analysisProvenance';
import {
  buildCapabilityMatrix,
  buildEvidenceRecordsFromProvenance,
  buildSelectedAnalysisProvider,
  validateEvidenceRecords,
} from '../evidenceRecord';

const binaryPath = 'D:/Project/HexHawk/work/vm-smoke/functional-fixtures/safe_hello.srec';
const sha256 = '4160787cc3ace20df9363672690d6d147216fda609f0b946e4cfd81877335d35';

describe('EvidenceRecord v1', () => {
  it('turns native provenance into operation-bound evidence records with fixed provider identity', () => {
    const provenance = buildAnalysisProvenance({
      browserMode: false,
      binaryPath,
      binarySha256: sha256,
      metadataLoaded: true,
      stringsCount: 3,
      disassemblyCount: 0,
      cfgNodes: 0,
      cfgEdges: 0,
      pluginResultCount: 0,
    });

    const records = buildEvidenceRecordsFromProvenance(provenance);
    const validation = validateEvidenceRecords(records);
    const provider = buildSelectedAnalysisProvider(provenance);

    expect(validation).toEqual({ ok: true, errors: [] });
    expect(provider).toMatchObject({
      schema: 'hexhawk.selected_analysis_provider.v1',
      provider: 'hexhawk-native',
      fixedForRun: true,
      silentFallbackAllowed: false,
      failurePolicy: 'fail-closed-no-substitution',
    });
    expect(records.map((record) => record.operation)).toContain('inspect_file_metadata');
    expect(records.map((record) => record.operation)).toContain('find_strings');
    expect(records.every((record) => record.sourceSha256 === sha256)).toBe(true);
    expect(records.every((record) => record.authority.gyreVerdictAuthorityUnaffected)).toBe(true);
    expect(JSON.stringify(records)).not.toContain('threatScore');
    expect(JSON.stringify(records)).not.toContain('classification');
  });

  it('marks browser evidence as simulation-only and advisory, never native proof', () => {
    const provenance = buildAnalysisProvenance({
      browserMode: true,
      binaryPath,
      metadataLoaded: true,
      stringsCount: 2,
      disassemblyCount: 2,
      cfgNodes: 1,
      cfgEdges: 1,
      pluginResultCount: 0,
    });

    const records = buildEvidenceRecordsFromProvenance(provenance);
    const provider = buildSelectedAnalysisProvider(provenance);
    const matrix = buildCapabilityMatrix(provenance, records);

    expect(validateEvidenceRecords(records).ok).toBe(true);
    expect(provider.provider).toBe('browser-simulation');
    expect(provider.limitations.join(' ')).toMatch(/must not be replaced by mock evidence/i);
    expect(records.every((record) => record.evidenceMode === 'simulation')).toBe(true);
    expect(records.every((record) => record.authority.advisoryOnly)).toBe(true);
    expect(matrix.entries.find((entry) => entry.capability === 'File identity / inspect')).toMatchObject({
      availability: 'simulation-only',
    });
  });

  it('makes unavailable and partial capability states explicit', () => {
    const provenance = buildAnalysisProvenance({
      browserMode: false,
      binaryPath,
      binarySha256: sha256,
      metadataLoaded: true,
      stringsCount: 0,
      disassemblyCount: 0,
      cfgNodes: 2000,
      cfgEdges: 4000,
      cfgTruncated: true,
      pluginResultCount: 0,
    });
    const matrix = buildCapabilityMatrix(provenance);

    expect(matrix.schema).toBe('hexhawk.capability_matrix.v1');
    expect(matrix.entries.find((entry) => entry.capability === 'Control-flow graph')).toMatchObject({
      availability: 'partial',
      reason: expect.stringMatching(/truncation|budget/i),
    });
    expect(matrix.entries.find((entry) => entry.capability === 'Readable strings')).toMatchObject({
      availability: 'unavailable',
      remediation: expect.stringMatching(/Scan Strings/i),
    });
  });
});
