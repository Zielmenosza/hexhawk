import { describe, expect, it } from 'vitest';
import { buildAdvisoryPluginOutput, validatePluginManifest } from '../utils/pluginManifest';
import { stringPatternAdvisorManifest } from './fixtures/stringPatternAdvisorManifest';

describe('Phase 1 safe plugin manifest contract', () => {
  it('validates the checked-in example advisory manifest fixture', () => {
    const result = validatePluginManifest(stringPatternAdvisorManifest);

    expect(result.valid).toBe(true);
    expect(result.normalized).toMatchObject({
      schema: 'hexhawk.plugin_manifest.v1',
      name: 'StringPatternAdvisor',
      apiVersion: '1.0.0',
      entry: { kind: 'advisory-module', path: 'plugins/string-pattern-advisor/index.js' },
      provenance: { trust: 'local-dev' },
    });
    expect(result.normalized?.permissions).toContain('produce:advisory-observation');
  });

  it('accepts manifest-declared advisory plugins with explicit permissions', () => {
    const result = validatePluginManifest({
      schema: 'hexhawk.plugin_manifest.v1',
      name: 'StringPatternAdvisor',
      version: '0.1.0',
      apiVersion: '1.0.0',
      permissions: ['read:strings', 'produce:advisory-observation'],
      entry: { kind: 'advisory-module', path: 'plugins/string-pattern-advisor/index.js' },
      provenance: { trust: 'local-dev', bundleHash: 'abc123' },
    });

    expect(result.valid).toBe(true);
    expect(result.normalized?.permissions).toEqual(['read:strings', 'produce:advisory-observation']);
    const output = buildAdvisoryPluginOutput(result.normalized!, ['read:strings', 'produce:advisory-observation'], [
      { title: 'Suspicious URL literal', address: 0x401000 },
    ]);
    expect(output.canMutateVerdict).toBe(false);
    expect(output.gyre_is_sole_verdict_authority).toBe(true);
  });

  it('rejects hidden execution and undeclared/unsafe permissions', () => {
    const result = validatePluginManifest({
      schema: 'hexhawk.plugin_manifest.v1',
      name: 'BadNativeLoader',
      version: '0.1.0',
      apiVersion: '1.0.0',
      permissions: ['read:strings', 'process:spawn', 'network:any'],
      entry: { kind: 'native-dll', path: '../evil.dll' },
      provenance: { trust: 'untrusted' },
    });

    expect(result.valid).toBe(false);
    expect(result.errors.join('\n')).toContain('Unsupported permission: process:spawn.');
    expect(result.errors.join('\n')).toContain('Unsupported permission: network:any.');
    expect(result.errors.join('\n')).toContain('entry.kind must be advisory-module.');
    expect(result.errors.join('\n')).toContain('entry.path must be a safe relative path.');
  });

  it('blocks advisory outputs that use undeclared permissions', () => {
    const manifest = validatePluginManifest({
      schema: 'hexhawk.plugin_manifest.v1',
      name: 'MetadataOnly',
      version: '0.1.0',
      apiVersion: '1.0.0',
      permissions: ['read:file-metadata', 'produce:advisory-observation'],
      entry: { kind: 'advisory-module', path: 'plugins/metadata/index.js' },
      provenance: { trust: 'first-party' },
    }).normalized!;

    expect(() => buildAdvisoryPluginOutput(manifest, ['read:disassembly'], [])).toThrow('undeclared permission');
  });
});
