import { describe, expect, it } from 'vitest';
import { buildTesterHandoffKit } from '../testerHandoffKit';
import type { CrestEvidenceBundle } from '../crestEvidenceBundle';

const bundle = {
  schema: 'hexhawk.crest_evidence_bundle.v1',
  bundle_id: 'crest-676807a587aa-2',
  exported_at: '2026-07-24T00:00:00.000Z',
  file_identity: { path: 'HexHawk/package.json', sha256: '676807a587aaed5e3c070e7595f5fb1480790b8312c53e202bf6830dd7789251', size: 2247 },
  native_evidence_contract: { kind: 'native', label: 'Native backend evidence', native: true, canClaimFileBackedEvidence: true },
  replay_manifest: { entries: [{ command: 'nest_cli inspect "HexHawk/package.json"', artifactSource: 'tauri.inspect_file_metadata' }] },
  cfg_budget: { truncated: false },
  proof_limits: ['does not prove verdict correctness'],
} as unknown as CrestEvidenceBundle;

describe('tester handoff kit', () => {
  it('creates README, hashes, unsigned warning, and proves/does-not-prove copy', () => {
    const kit = buildTesterHandoffKit({
      generatedAt: '2026-07-24T00:00:00.000Z',
      signingStatus: 'unsigned technical preview',
      bundle,
      artifactHashes: [{ path: 'hexhawk-report.json', sha256: 'a'.repeat(64) }],
    });

    expect(kit.files['README.md']).toContain('unsigned technical preview');
    expect(kit.files['README.md']).toContain('What this build proves');
    expect(kit.files['README.md']).toContain('What this build does not prove');
    expect(kit.files['README.md']).toContain('crest-676807a587aa-2');
    expect(kit.files['SHA256SUMS.txt']).toContain('hexhawk-report.json');
    expect(kit.files['UNSIGNED-WARNING.txt']).toMatch(/unsigned/i);
    expect(JSON.stringify(kit)).not.toContain('threatScore');
  });
});
