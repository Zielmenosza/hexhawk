import { describe, expect, it } from 'vitest';
import { validateNestManifest, validateNestEvidenceBundle } from '../nestEvidence';
import { makeMinimalBundle, makeManifest } from '../../test/fixtures/nestEvidenceFixtures';

function payloadManifest() {
  const manifest = makeManifest({ bundle_format_version: '1.1.0' });
  manifest.files = manifest.files.filter(file => file.name !== 'manifest.json');
  return manifest;
}

describe('NEST 1.1 noncircular manifest custody', () => {
  it('validates all required payloads without demanding a self-hash', () => {
    const bundle = makeMinimalBundle();
    bundle.manifest = payloadManifest();
    expect(validateNestEvidenceBundle(bundle)).toEqual([]);
  });
  it.each(['manifest.json', 'manifest.sha256'])('rejects circular custody entry %s', (name) => {
    const manifest = payloadManifest();
    manifest.files.push({ ...manifest.files[0], name: name as never });
    expect(validateNestManifest(manifest).some(issue => issue.path.startsWith('manifest.files') && issue.code === 'invalid-value')).toBe(true);
  });
  it.each(['binary_identity.json', 'session.json', 'iterations.json', 'deltas.json', 'final_verdict_snapshot.json', 'audit_refs.json'])('still requires payload %s', (name) => {
    const manifest = payloadManifest();
    manifest.files = manifest.files.filter(file => file.name !== name);
    expect(validateNestManifest(manifest).some(issue => issue.code === 'missing-field' && issue.message.includes(name))).toBe(true);
  });
  it('retains legacy 1.0 validation, including its required manifest entry (not disk-integrity proof)', () => {
    expect(validateNestManifest(makeManifest())).toEqual([]);
    const manifest = makeManifest();
    manifest.files = manifest.files.filter(file => file.name !== 'manifest.json');
    expect(validateNestManifest(manifest).some(issue => issue.code === 'missing-field' && issue.message.includes('manifest.json'))).toBe(true);
  });
});
