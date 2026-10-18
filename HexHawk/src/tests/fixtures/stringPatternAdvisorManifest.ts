import type { SafePluginManifest } from '../../utils/pluginManifest';

export const stringPatternAdvisorManifest: SafePluginManifest = {
  schema: 'hexhawk.plugin_manifest.v1',
  name: 'StringPatternAdvisor',
  version: '0.1.0',
  author: 'HexHawk',
  description: 'Example Phase 1 advisory plugin manifest. Reads strings and emits advisory observations only.',
  apiVersion: '1.0.0',
  permissions: [
    'read:file-metadata',
    'read:strings',
    'produce:advisory-observation',
    'produce:report-section',
  ],
  entry: {
    kind: 'advisory-module',
    path: 'plugins/string-pattern-advisor/index.js',
  },
  provenance: {
    trust: 'local-dev',
    bundleHash: 'example-not-a-real-hash',
  },
};
