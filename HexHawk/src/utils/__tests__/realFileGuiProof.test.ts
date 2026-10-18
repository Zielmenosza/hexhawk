import { describe, expect, it } from 'vitest';
import { buildRealFileGuiProof, type RealFileGuiProofInput } from '../realFileGuiProof';

const sha256 = '676807a587aaed5e3c070e7595f5fb1480790b8312c53e202bf6830dd7789251';

function input(overrides: Partial<RealFileGuiProofInput> = {}): RealFileGuiProofInput {
  return {
    filePath: 'D:/Project/HexHawk/HexHawk/package.json',
    directFileSha256: sha256,
    cliSha256: sha256,
    guiSha256: sha256,
    exportSha256: sha256,
    guiArtifactOrigin: 'tauri.inspect_file_metadata',
    exportArtifactOrigin: 'tauri.inspect_file_metadata',
    runtime: 'tauri-native',
    source: 'real-backend',
    ...overrides,
  };
}

describe('real file GUI proof harness', () => {
  it('proves a real file identity when direct hash, CLI/backend, GUI, and export all match', () => {
    const proof = buildRealFileGuiProof(input());

    expect(proof.status).toBe('proved');
    expect(proof.filePath).toBe('D:/Project/HexHawk/HexHawk/package.json');
    expect(proof.sha256).toBe(sha256);
    expect(proof.artifactOrigin).toBe('tauri.inspect_file_metadata');
    expect(proof.checks).toEqual(expect.arrayContaining([
      expect.objectContaining({ id: 'direct-vs-cli', passed: true }),
      expect.objectContaining({ id: 'cli-vs-gui', passed: true }),
      expect.objectContaining({ id: 'gui-vs-export', passed: true }),
      expect.objectContaining({ id: 'origin-gui-vs-export', passed: true }),
      expect.objectContaining({ id: 'native-runtime', passed: true }),
    ]));
    expect(proof.warnings).toHaveLength(0);
    expect(JSON.stringify(proof)).not.toContain('classification');
    expect(JSON.stringify(proof)).not.toContain('threatScore');
  });

  it('fails closed when GUI SHA-256 differs from backend/CLI identity', () => {
    const proof = buildRealFileGuiProof(input({ guiSha256: '0'.repeat(64) }));

    expect(proof.status).toBe('failed');
    expect(proof.checks.find((check) => check.id === 'cli-vs-gui')).toMatchObject({ passed: false });
    expect(proof.warnings.join(' ')).toMatch(/GUI SHA-256 does not match/i);
  });

  it('does not prove browser simulation as native evidence even when hashes match', () => {
    const proof = buildRealFileGuiProof(input({
      runtime: 'browser-simulation',
      source: 'simulation',
      guiArtifactOrigin: 'browser.mock_metadata',
      exportArtifactOrigin: 'browser.mock_metadata',
    }));

    expect(proof.status).toBe('not-native');
    expect(proof.checks.find((check) => check.id === 'native-runtime')).toMatchObject({ passed: false });
    expect(proof.warnings.join(' ')).toMatch(/browser simulation/i);
  });
});
