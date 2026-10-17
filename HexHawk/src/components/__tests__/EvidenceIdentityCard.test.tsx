import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import EvidenceIdentityCard from '../EvidenceIdentityCard';
import type { AnalysisSessionProvenance } from '../../utils/analysisProvenance';

const sha256 = '676807a587aaed5e3c070e7595f5fb1480790b8312c53e202bf6830dd7789251';

function nativeProvenance(): AnalysisSessionProvenance {
  return {
    schema: 'hexhawk.analysis.provenance.v1',
    runtime: 'tauri-native',
    binaryPath: 'D:/Project/HexHawk/HexHawk/package.json',
    binarySha256: sha256,
    dataSource: 'real-backend',
    binaryIdentity: {
      path: 'D:/Project/HexHawk/HexHawk/package.json',
      sha256,
      source: 'real-backend',
      artifactOrigin: 'tauri.inspect_file_metadata',
      tauriCommand: 'inspect_file_metadata',
      cliCommand: 'nest_cli inspect "D:/Project/HexHawk/HexHawk/package.json"',
    },
    commands: ['nest_cli inspect "D:/Project/HexHawk/HexHawk/package.json"'],
    artifacts: [{
      kind: 'metadata',
      source: 'real-backend',
      binarySha256: sha256,
      artifactOrigin: 'tauri.inspect_file_metadata',
      tauriCommand: 'inspect_file_metadata',
      cliCommand: 'nest_cli inspect "D:/Project/HexHawk/HexHawk/package.json"',
      count: 1,
    }],
    warnings: [],
  };
}

describe('EvidenceIdentityCard', () => {
  it('renders a native evidence identity card with same SHA-256 and origin fields used by exports', () => {
    render(<EvidenceIdentityCard provenance={nativeProvenance()} exportSha256={sha256} exportArtifactOrigin="tauri.inspect_file_metadata" />);

    expect(screen.getByText('Evidence Identity Card')).toBeTruthy();
    expect(screen.getByText('Native backend evidence')).toBeTruthy();
    expect(screen.getByText('tauri.inspect_file_metadata')).toBeTruthy();
    expect(screen.getByText('inspect_file_metadata')).toBeTruthy();
    expect(screen.getByText(/nest_cli inspect/)).toBeTruthy();
    expect(screen.getAllByText(sha256).length).toBeGreaterThan(0);
    expect(screen.getByText('GUI/export identity match')).toBeTruthy();
  });

  it('labels browser simulation as non-native and does not claim export/native proof', () => {
    const provenance = nativeProvenance();
    provenance.runtime = 'browser-simulation';
    provenance.dataSource = 'simulation';
    provenance.binarySha256 = null;
    provenance.binaryIdentity = {
      path: provenance.binaryPath,
      sha256: null,
      source: 'simulation',
      artifactOrigin: 'browser.mock_metadata',
      cliCommand: 'nest_cli inspect "D:/Project/HexHawk/HexHawk/package.json"',
    };
    provenance.artifacts = [{ kind: 'metadata', source: 'simulation', binarySha256: null, artifactOrigin: 'browser.mock_metadata', count: 1 }];

    render(<EvidenceIdentityCard provenance={provenance} exportSha256={null} exportArtifactOrigin="browser.mock_metadata" />);

    expect(screen.getByText('Browser simulation')).toBeTruthy();
    expect(screen.getByText('browser.mock_metadata')).toBeTruthy();
    expect(screen.getByText(/not native backend evidence/i)).toBeTruthy();
    expect(screen.queryByText('Native backend evidence')).toBeNull();
  });
});
