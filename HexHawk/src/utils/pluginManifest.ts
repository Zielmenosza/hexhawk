export const SAFE_PLUGIN_PERMISSIONS = [
  'read:file-metadata',
  'read:strings',
  'read:disassembly',
  'read:cfg',
  'produce:advisory-observation',
  'produce:report-section',
] as const;

export type SafePluginPermission = typeof SAFE_PLUGIN_PERMISSIONS[number];

export interface SafePluginManifest {
  schema: 'hexhawk.plugin_manifest.v1';
  name: string;
  version: string;
  author?: string;
  description?: string;
  apiVersion: '1.0.0';
  permissions: SafePluginPermission[];
  entry: {
    kind: 'advisory-module';
    path: string;
  };
  provenance: {
    bundleHash?: string;
    trust: 'first-party' | 'local-dev' | 'explicitly-trusted' | 'untrusted';
  };
}

export interface PluginManifestValidationResult {
  valid: boolean;
  errors: string[];
  normalized?: SafePluginManifest;
}

export interface AdvisoryPluginOutput<T = unknown> {
  schema: 'hexhawk.plugin_advisory_output.v1';
  plugin: {
    name: string;
    version: string;
    bundleHash?: string;
    trust: SafePluginManifest['provenance']['trust'];
  };
  permissionsUsed: SafePluginPermission[];
  advisoryOnly: true;
  gyre_is_sole_verdict_authority: true;
  canMutateVerdict: false;
  observations: T[];
}

const SAFE_PLUGIN_PERMISSION_SET = new Set<string>(SAFE_PLUGIN_PERMISSIONS);
const FORBIDDEN_PATH_SEGMENTS = ['..', '~'];

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function stringField(value: unknown): string | null {
  return typeof value === 'string' && value.trim().length > 0 ? value.trim() : null;
}

function safeEntryPath(path: string): boolean {
  if (path.startsWith('/') || /^[a-z]:/i.test(path) || path.includes('\\')) return false;
  const parts = path.split('/').filter(Boolean);
  return parts.length > 0 && parts.every(part => !FORBIDDEN_PATH_SEGMENTS.includes(part));
}

export function validatePluginManifest(input: unknown): PluginManifestValidationResult {
  const errors: string[] = [];
  if (!isPlainObject(input)) return { valid: false, errors: ['Manifest must be a JSON object.'] };

  const schema = input.schema;
  if (schema !== 'hexhawk.plugin_manifest.v1') errors.push('schema must be hexhawk.plugin_manifest.v1.');
  const name = stringField(input.name);
  if (!name) errors.push('name is required.');
  const version = stringField(input.version);
  if (!version) errors.push('version is required.');
  if (input.apiVersion !== '1.0.0') errors.push('apiVersion must be 1.0.0 for Phase 1 plugins.');

  const permissions = Array.isArray(input.permissions) ? input.permissions : [];
  if (!Array.isArray(input.permissions)) errors.push('permissions must be an array.');
  const normalizedPermissions: SafePluginPermission[] = [];
  for (const permission of permissions) {
    if (typeof permission !== 'string' || !SAFE_PLUGIN_PERMISSION_SET.has(permission)) {
      errors.push(`Unsupported permission: ${String(permission)}.`);
    } else if (!normalizedPermissions.includes(permission as SafePluginPermission)) {
      normalizedPermissions.push(permission as SafePluginPermission);
    }
  }
  if (!normalizedPermissions.includes('produce:advisory-observation')) {
    errors.push('Phase 1 plugins must declare produce:advisory-observation.');
  }

  const entry = input.entry;
  if (!isPlainObject(entry)) {
    errors.push('entry must be an object.');
  }
  const entryKind = isPlainObject(entry) ? entry.kind : undefined;
  const entryPath = isPlainObject(entry) ? stringField(entry.path) : null;
  if (entryKind !== 'advisory-module') errors.push('entry.kind must be advisory-module.');
  if (!entryPath || !safeEntryPath(entryPath)) errors.push('entry.path must be a safe relative path.');

  const provenance = input.provenance;
  if (!isPlainObject(provenance)) errors.push('provenance must be an object.');
  const trust = isPlainObject(provenance) ? provenance.trust : undefined;
  const allowedTrust = new Set(['first-party', 'local-dev', 'explicitly-trusted', 'untrusted']);
  if (typeof trust !== 'string' || !allowedTrust.has(trust)) errors.push('provenance.trust is required and must be recognized.');
  const bundleHash = isPlainObject(provenance) && typeof provenance.bundleHash === 'string'
    ? provenance.bundleHash
    : undefined;

  if (errors.length || !name || !version || !entryPath || typeof trust !== 'string') {
    return { valid: false, errors };
  }

  return {
    valid: true,
    errors: [],
    normalized: {
      schema: 'hexhawk.plugin_manifest.v1',
      name,
      version,
      author: stringField(input.author) ?? undefined,
      description: stringField(input.description) ?? undefined,
      apiVersion: '1.0.0',
      permissions: normalizedPermissions,
      entry: { kind: 'advisory-module', path: entryPath },
      provenance: { bundleHash, trust: trust as SafePluginManifest['provenance']['trust'] },
    },
  };
}

export function buildAdvisoryPluginOutput<T>(
  manifest: SafePluginManifest,
  permissionsUsed: SafePluginPermission[],
  observations: T[],
): AdvisoryPluginOutput<T> {
  for (const permission of permissionsUsed) {
    if (!manifest.permissions.includes(permission)) {
      throw new Error(`Plugin ${manifest.name} used undeclared permission ${permission}.`);
    }
  }
  return {
    schema: 'hexhawk.plugin_advisory_output.v1',
    plugin: {
      name: manifest.name,
      version: manifest.version,
      bundleHash: manifest.provenance.bundleHash,
      trust: manifest.provenance.trust,
    },
    permissionsUsed,
    advisoryOnly: true,
    gyre_is_sole_verdict_authority: true,
    canMutateVerdict: false,
    observations,
  };
}
