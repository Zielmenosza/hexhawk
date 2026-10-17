export type EvidenceExportReadinessInput = {
  runtime: 'tauri-native' | 'browser-simulation';
  binaryPath: string;
  sourceSha256: string | null | undefined;
};

export type EvidenceExportReadiness = {
  ok: boolean;
  reason?: string;
};

const SHA256_RE = /^[a-f0-9]{64}$/i;

/**
 * Native evidence exports must fail closed when the current session no longer
 * carries the inspected file identity. This can happen after restoring a file
 * path or analysis UI state across an application restart without rerunning
 * Inspect File.
 */
export function assessEvidenceExportReadiness(input: EvidenceExportReadinessInput): EvidenceExportReadiness {
  if (input.runtime === 'browser-simulation') return { ok: true };
  if (!input.binaryPath.trim()) {
    return {
      ok: false,
      reason: 'Select and inspect a file before exporting native evidence.',
    };
  }
  if (!input.sourceSha256 || !SHA256_RE.test(input.sourceSha256)) {
    return {
      ok: false,
      reason: 'File identity is missing for this native session. Run Inspect File again before exporting.',
    };
  }
  return { ok: true };
}
