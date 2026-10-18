import { describe, expect, it } from 'vitest';
import { buildAnalysisProvenance } from '../analysisProvenance';

const path = 'work/recreate_challenges/bin/pwn110_recreated';

describe('analysis provenance', () => {
  it('records native backend command provenance for challenge-backed sessions', () => {
    const provenance = buildAnalysisProvenance({
      browserMode: false,
      binaryPath: path,
      binarySha256: '7b4a27599f48bc7edcbe52e7cad688c92b1a0241b0e5e95b94355a2d50607b28',
      metadataLoaded: true,
      stringsCount: 5556,
      disassemblyCount: 256,
      cfgNodes: 2000,
      cfgEdges: 4000,
      cfgTruncated: true,
      pluginResultCount: 0,
    });

    expect(provenance.schema).toBe('hexhawk.analysis.provenance.v1');
    expect(provenance.runtime).toBe('tauri-native');
    expect(provenance.dataSource).toBe('real-backend');
    expect(provenance.binaryIdentity).toMatchObject({
      path,
      sha256: '7b4a27599f48bc7edcbe52e7cad688c92b1a0241b0e5e95b94355a2d50607b28',
      artifactOrigin: 'tauri.inspect_file_metadata',
      tauriCommand: 'inspect_file_metadata',
      cliCommand: `nest_cli inspect ${JSON.stringify(path)}`,
      source: 'real-backend',
    });
    expect(provenance.artifacts.find((artifact) => artifact.kind === 'metadata')).toMatchObject({
      source: 'real-backend',
      binarySha256: '7b4a27599f48bc7edcbe52e7cad688c92b1a0241b0e5e95b94355a2d50607b28',
      artifactOrigin: 'tauri.inspect_file_metadata',
      tauriCommand: 'inspect_file_metadata',
      cliCommand: `nest_cli inspect ${JSON.stringify(path)}`,
    });
    expect(provenance.commands).toContain(`nest_cli inspect ${JSON.stringify(path)}`);
    expect(provenance.commands).toContain(`nest_cli cfg ${JSON.stringify(path)} 0 1024`);
    expect(provenance.artifacts.find((artifact) => artifact.kind === 'cfg')).toMatchObject({
      source: 'real-backend',
      count: 2000,
      truncated: true,
    });
    expect(provenance.warnings).toContain('CFG exceeded UI safety budget and was truncated before renderer consumption.');
  });

  it('labels browser sessions as simulation-backed instead of backend evidence', () => {
    const provenance = buildAnalysisProvenance({
      browserMode: true,
      binaryPath: path,
      metadataLoaded: true,
      stringsCount: 5,
      disassemblyCount: 3,
      cfgNodes: 2,
      cfgEdges: 1,
      pluginResultCount: 0,
    });

    expect(provenance.runtime).toBe('browser-simulation');
    expect(provenance.dataSource).toBe('simulation');
    expect(provenance.binaryIdentity).toMatchObject({
      path,
      sha256: null,
      artifactOrigin: 'browser.mock_metadata',
      source: 'simulation',
    });
    expect(provenance.artifacts.find((artifact) => artifact.kind === 'metadata')).toMatchObject({
      source: 'simulation',
      artifactOrigin: 'browser.mock_metadata',
      binarySha256: null,
    });
    expect(provenance.warnings.join(' ')).toMatch(/simulation-backed/i);
  });
});
