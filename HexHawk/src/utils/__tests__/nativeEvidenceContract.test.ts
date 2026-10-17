import { describe, expect, it } from 'vitest';
import { classifyEvidenceSource, enforceNativeEvidenceContract } from '../nativeEvidenceContract';

describe('native evidence contract', () => {
  it('accepts only tauri-native real-backend tauri-origin evidence as native', () => {
    const contract = enforceNativeEvidenceContract({
      runtime: 'tauri-native',
      source: 'real-backend',
      artifactOrigin: 'tauri.inspect_file_metadata',
      artifactKind: 'metadata',
      binaryPath: 'C:\\samples\\sample.exe',
      sourceSha256: 'a'.repeat(64),
      boundSha256: 'a'.repeat(64),
      identityBindingSucceeded: true,
    });

    expect(contract.kind).toBe('native');
    expect(contract.native).toBe(true);
    expect(contract.canClaimFileBackedEvidence).toBe(true);
    expect(contract.label).toBe('Native backend evidence');
  });

  it('rejects browser simulation as non-native even when the UI has values', () => {
    const contract = enforceNativeEvidenceContract({
      runtime: 'browser-simulation',
      source: 'simulation',
      artifactOrigin: 'browser.mock_metadata',
      artifactKind: 'metadata',
    });

    expect(contract.kind).toBe('simulation');
    expect(contract.native).toBe(false);
    expect(contract.canClaimFileBackedEvidence).toBe(false);
    expect(contract.label).toBe('Browser simulation');
    expect(contract.warnings.join(' ')).toMatch(/must not be presented as native/i);
  });

  it('fails closed for inconsistent runtime/source/origin combinations', () => {
    expect(classifyEvidenceSource({ runtime: 'tauri-native', source: 'simulation', artifactOrigin: 'tauri.inspect_file_metadata' })).toBe('invalid');
    expect(classifyEvidenceSource({ runtime: 'browser-simulation', source: 'real-backend', artifactOrigin: 'browser.mock_metadata' })).toBe('invalid');
  });

  it('does not create verdict authority fields', () => {
    const contract = enforceNativeEvidenceContract({ runtime: 'tauri-native', source: 'real-backend', artifactOrigin: 'tauri.find_strings', artifactKind: 'strings' });
    expect(JSON.stringify(contract)).not.toContain('classification');
    expect(JSON.stringify(contract)).not.toContain('threatScore');
  });
});
