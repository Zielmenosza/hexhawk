import { describe, expect, it } from 'vitest';
import { appendEvidenceJournalEntry, buildReplayManifest } from '../evidenceJournal';

describe('append-only evidence journal and replay manifest', () => {
  it('appends major actions in order with replayable identity fields', () => {
    const first = appendEvidenceJournalEntry([], {
      action: 'inspect',
      binaryPath: 'sample.exe',
      binarySha256: 'a'.repeat(64),
      command: 'nest_cli inspect "sample.exe"',
      artifactSource: 'tauri.inspect_file_metadata',
      timestamp: '2026-07-24T00:00:00.000Z',
      analysisLimits: { maxBytesRead: 4096 },
    });
    const second = appendEvidenceJournalEntry(first, {
      action: 'cfg',
      binaryPath: 'sample.exe',
      binarySha256: 'a'.repeat(64),
      command: 'nest_cli cfg "sample.exe" 0 1024',
      artifactSource: 'tauri.build_cfg',
      timestamp: '2026-07-24T00:01:00.000Z',
      analysisLimits: { nodeBudget: 2000, edgeBudget: 4000, truncated: true, omittedNodes: 12, omittedEdges: 20 },
    });

    expect(first).toHaveLength(1);
    expect(second).toHaveLength(2);
    expect(second[0].sequence).toBe(1);
    expect(second[1].sequence).toBe(2);
    expect(first).not.toBe(second);
    expect(second[1]).toMatchObject({ action: 'cfg', artifactSource: 'tauri.build_cfg', replayable: true });
  });

  it('builds a replay manifest without verdict authority fields', () => {
    const journal = appendEvidenceJournalEntry([], {
      action: 'inspect',
      binaryPath: 'sample.exe',
      binarySha256: 'b'.repeat(64),
      command: 'nest_cli inspect "sample.exe"',
      artifactSource: 'tauri.inspect_file_metadata',
      timestamp: '2026-07-24T00:00:00.000Z',
      analysisLimits: { maxBytesRead: 8192 },
    });

    const manifest = buildReplayManifest(journal);
    expect(manifest.schema).toBe('hexhawk.evidence_replay_manifest.v1');
    expect(manifest.entries).toHaveLength(1);
    expect(manifest.entries[0]).toMatchObject({ binaryPath: 'sample.exe', binarySha256: 'b'.repeat(64), command: 'nest_cli inspect "sample.exe"' });
    expect(JSON.stringify(manifest)).not.toContain('classification');
    expect(JSON.stringify(manifest)).not.toContain('threatScore');
  });
});
