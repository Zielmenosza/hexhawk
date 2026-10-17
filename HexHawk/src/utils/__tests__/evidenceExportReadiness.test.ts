import { describe, expect, it } from 'vitest';
import { assessEvidenceExportReadiness } from '../evidenceExportReadiness';

const SHA256 = 'a'.repeat(64);

describe('assessEvidenceExportReadiness', () => {
  it('allows native export only when the selected file has a valid SHA-256 identity', () => {
    expect(assessEvidenceExportReadiness({
      runtime: 'tauri-native',
      binaryPath: 'C:\\samples\\safe.srec',
      sourceSha256: SHA256,
    })).toEqual({ ok: true });
  });

  it('fails closed when a restored native session has no current file identity', () => {
    expect(assessEvidenceExportReadiness({
      runtime: 'tauri-native',
      binaryPath: 'C:\\samples\\safe.srec',
      sourceSha256: null,
    })).toEqual({
      ok: false,
      reason: 'File identity is missing for this native session. Run Inspect File again before exporting.',
    });
  });

  it('fails closed when no native file is selected', () => {
    expect(assessEvidenceExportReadiness({
      runtime: 'tauri-native',
      binaryPath: '',
      sourceSha256: null,
    }).ok).toBe(false);
  });

  it('preserves explicitly simulation-only browser exports', () => {
    expect(assessEvidenceExportReadiness({
      runtime: 'browser-simulation',
      binaryPath: 'demo.bin',
      sourceSha256: null,
    })).toEqual({ ok: true });
  });
});
