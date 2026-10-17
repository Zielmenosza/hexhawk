import { describe, expect, it } from 'vitest';
import { buildAnalysisProvenance } from '../analysisProvenance';
import { appendEvidenceJournalEntry, buildReplayManifestFromProvenance } from '../evidenceJournal';

const sha = 'a'.repeat(64);
const base = {
  browserMode: false, binaryPath: 'C:/fixtures/safe.exe', binarySha256: sha,
  metadataLoaded: true, stringsCount: 0, disassemblyCount: 0,
  cfgNodes: 0, cfgEdges: 0, pluginResultCount: 0,
};

describe('recorded-operation provenance custody', () => {
  it('preserves the actual range, command and operation time for a successful empty result', () => {
    const operationJournal = appendEvidenceJournalEntry([], {
      action: 'strings', binaryPath: base.binaryPath, binarySha256: sha,
      command: 'invoke("find_strings", {"offset":8192,"length":128,"minLength":12})',
      timestamp: '2026-10-13T17:00:00.000Z', artifactSource: 'tauri.find_strings',
      analysisLimits: { offset: 8192, length: 128 },
    });
    const provenance = buildAnalysisProvenance({ ...base, operationJournal });
    const replay = buildReplayManifestFromProvenance(provenance, '2026-10-13T18:00:00.000Z');
    expect(replay.entries).toHaveLength(1);
    expect(replay.entries[0]).toMatchObject({
      action: 'strings', command: operationJournal[0].command,
      timestamp: operationJournal[0].timestamp, binarySha256: sha,
      analysisLimits: { offset: 8192, length: 128 },
    });
    expect(provenance.artifacts.find(a => a.kind === 'strings')).toMatchObject({ count: 0 });
    expect(replay.replayable).toBe(true);
  });

  it('does not fabricate replay timestamps and parameters from UI counts', () => {
    const provenance = buildAnalysisProvenance({ ...base, stringsCount: 4, disassemblyCount: 8 });
    const replay = buildReplayManifestFromProvenance(provenance, '2026-10-13T18:00:00.000Z');
    expect(replay.replayable).toBe(false);
    expect(replay.entries).toEqual([]);
    expect(replay.proofLimits.join(' ')).toMatch(/no operation receipts|no recorded operations/i);
  });

  it('does not bind operation receipts from a different selected file or hash', () => {
    const operationJournal = appendEvidenceJournalEntry([], {
      action: 'strings', binaryPath: 'C:/fixtures/other.exe', binarySha256: 'b'.repeat(64),
      command: 'invoke("find_strings", {})', timestamp: '2026-10-13T17:00:00.000Z',
      artifactSource: 'tauri.find_strings', analysisLimits: {},
    });
    const provenance = buildAnalysisProvenance({ ...base, operationJournal });
    const replay = buildReplayManifestFromProvenance(provenance);
    expect(replay.entries).toEqual([]);
    expect(replay.replayable).toBe(false);
    expect(provenance.warnings.join(' ')).toMatch(/identity|different file/i);
  });
});
