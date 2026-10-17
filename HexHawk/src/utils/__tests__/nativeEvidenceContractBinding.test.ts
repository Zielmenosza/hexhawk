import { describe, expect, it } from 'vitest';
import { enforceNativeEvidenceContract, type EvidenceContractInput } from '../nativeEvidenceContract';

const labels: EvidenceContractInput = { runtime: 'tauri-native', source: 'real-backend', artifactOrigin: 'tauri.inspect_file_metadata', artifactKind: 'metadata' };
const sha = 'a'.repeat(64);
// Structural inputs allow this regression to execute against the old contract before optional fields exist.
const bound = { ...labels, binaryPath: 'C:\\samples\\sample.exe', sourceSha256: sha, boundSha256: sha, identityBindingSucceeded: true };
describe('file-backed evidence requires successful SHA identity binding', () => {
  it('does not grant file-backed proof to legacy native source labels', () => {
    const result = enforceNativeEvidenceContract(labels);
    expect(result.kind).toBe('native');
    expect(result.canClaimFileBackedEvidence).toBe(false);
    expect(result.warnings.join(' ')).toMatch(/identity|SHA/i);
  });
  it.each([
    { ...bound, binaryPath: '' },
    { ...bound, sourceSha256: undefined },
    { ...bound, sourceSha256: 'not-a-sha' },
    { ...bound, boundSha256: 'b'.repeat(64) },
    { ...bound, identityBindingSucceeded: false },
  ])('rejects missing, malformed, mismatched or unsuccessful identity: %j', input => {
    expect(enforceNativeEvidenceContract(input).canClaimFileBackedEvidence).toBe(false);
  });
  it('grants only native, successfully bound valid identity without verdict authority', () => {
    const result = enforceNativeEvidenceContract(bound);
    expect(result.canClaimFileBackedEvidence).toBe(true);
    expect(result.authority.gyreVerdictAuthorityUnaffected).toBe(true);
    expect(JSON.stringify(result)).not.toContain('classification');
    expect(JSON.stringify(result)).not.toContain('threatScore');
    expect(enforceNativeEvidenceContract({ ...bound, source: 'simulation' }).canClaimFileBackedEvidence).toBe(false);
  });
});
