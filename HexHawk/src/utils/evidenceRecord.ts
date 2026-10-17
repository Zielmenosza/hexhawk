import type { AnalysisArtifactSummary, AnalysisSessionProvenance } from './analysisProvenance';
import type { SubsystemSource } from './qaUx';

export type EvidenceProducer = 'hexhawk-native' | 'browser-simulation' | 'ui' | 'imported' | 'manual' | 'ai-advisory' | 'gyre';
export type EvidenceMode = 'native' | 'simulation' | 'ui-only' | 'imported' | 'manual' | 'advisory' | 'verdict';
export type ConfidenceKind = 'observed' | 'derived' | 'inferred' | 'advisory';
export type CapabilityAvailability = 'available' | 'partial' | 'unavailable' | 'blocked' | 'simulation-only';

export type EvidenceLocation = {
  kind: 'file' | 'address' | 'range' | 'function' | 'export' | 'ui-panel';
  path?: string;
  address?: number;
  start?: number;
  end?: number;
  panel?: string;
  label?: string;
};

export type EvidenceRecordV1 = {
  schemaVersion: 1;
  evidenceId: string;
  caseId: string;
  artifactId: string;
  sourceSha256: string | null;
  producer: EvidenceProducer;
  producerVersion: string;
  operation: string;
  parameters: Record<string, unknown>;
  result: Record<string, unknown>;
  evidenceMode: EvidenceMode;
  confidenceKind: ConfidenceKind;
  limitations: string[];
  locations: EvidenceLocation[];
  links: string[];
  authority: {
    evidenceRecordOnly: true;
    advisoryOnly: boolean;
    gyreVerdictAuthorityUnaffected: true;
    nestEvidenceLifecycleUnaffected: true;
  };
};

export type SelectedAnalysisProviderV1 = {
  schema: 'hexhawk.selected_analysis_provider.v1';
  runtime: AnalysisSessionProvenance['runtime'];
  provider: EvidenceProducer;
  providerVersion: string;
  selectionSource: 'tauri-runtime' | 'browser-runtime' | 'manual-import' | 'unknown';
  analysisProfile: 'native-local' | 'browser-simulation' | 'imported-evidence' | 'unknown';
  fixedForRun: true;
  silentFallbackAllowed: false;
  failurePolicy: 'fail-closed-no-substitution';
  limitations: string[];
};

export type CapabilityMatrixEntry = {
  capability: string;
  availability: CapabilityAvailability;
  reason: string;
  remediation?: string;
  evidenceRecordIds: string[];
};

export type CapabilityMatrixV1 = {
  schema: 'hexhawk.capability_matrix.v1';
  generatedForArtifactId: string;
  generatedFromRuntime: AnalysisSessionProvenance['runtime'];
  entries: CapabilityMatrixEntry[];
  proofLimits: string[];
};

const VERSION = 'hexhawk-ui@1.0.0';
const SHA256_RE = /^[a-f0-9]{64}$/;

function stableHash(text: string): string {
  let h1 = 0x811c9dc5;
  let h2 = 0x01000193;
  for (let i = 0; i < text.length; i += 1) {
    const code = text.charCodeAt(i);
    h1 ^= code;
    h1 = Math.imul(h1, 0x01000193) >>> 0;
    h2 = Math.imul(h2 ^ code, 0x85ebca6b) >>> 0;
  }
  return `${h1.toString(16).padStart(8, '0')}${h2.toString(16).padStart(8, '0')}`;
}

function artifactIdFor(provenance: AnalysisSessionProvenance): string {
  const sha = provenance.binarySha256 ?? provenance.binaryIdentity.sha256;
  return sha ? `artifact-${sha.slice(0, 16)}` : `artifact-${stableHash(provenance.binaryPath)}`;
}

function caseIdFor(provenance: AnalysisSessionProvenance): string {
  return `case-${stableHash(`${provenance.runtime}|${provenance.binaryPath}|${provenance.binarySha256 ?? 'unknown'}`)}`;
}

function producerForSource(source: SubsystemSource): EvidenceProducer {
  if (source === 'real-backend') return 'hexhawk-native';
  if (source === 'simulation') return 'browser-simulation';
  return 'ui';
}

function modeForArtifact(artifact: AnalysisArtifactSummary): EvidenceMode {
  if (artifact.artifactOrigin?.startsWith('tauri.')) return 'native';
  if (artifact.artifactOrigin?.startsWith('browser.')) return 'simulation';
  if (artifact.source === 'ui-only') return 'ui-only';
  return 'imported';
}

function confidenceForArtifact(artifact: AnalysisArtifactSummary): ConfidenceKind {
  if (artifact.source === 'real-backend') return 'observed';
  if (artifact.source === 'simulation') return 'advisory';
  return 'derived';
}

function limitationsForArtifact(artifact: AnalysisArtifactSummary, provenance: AnalysisSessionProvenance): string[] {
  const limitations = [
    'Evidence records identify producer, operation, parameters, result summary, locations, and limits; they do not prove verdict correctness.',
  ];
  if (provenance.runtime === 'browser-simulation' || artifact.source === 'simulation') {
    limitations.push('Browser simulation is not native file-backed evidence and must not be substituted for failed backend analysis.');
  }
  if (artifact.truncated) {
    limitations.push('Artifact was truncated or budgeted; completeness must not be claimed without the exported limits.');
  }
  if (artifact.contract && !artifact.contract.canClaimFileBackedEvidence) {
    limitations.push(...artifact.contract.warnings);
  }
  return Array.from(new Set(limitations));
}

function recordId(input: {
  artifactId: string;
  operation: string;
  origin?: string;
  sourceSha256: string | null;
  count?: number;
}): string {
  return `evidence-${stableHash(JSON.stringify(input))}`;
}

export function buildEvidenceRecordsFromProvenance(provenance: AnalysisSessionProvenance): EvidenceRecordV1[] {
  const artifactId = artifactIdFor(provenance);
  const caseId = caseIdFor(provenance);
  return provenance.artifacts.map((artifact) => {
    const operation = artifact.tauriCommand ?? artifact.artifactOrigin ?? artifact.kind;
    const sourceSha256 = artifact.binarySha256 ?? provenance.binarySha256 ?? provenance.binaryIdentity.sha256 ?? null;
    return {
      schemaVersion: 1,
      evidenceId: recordId({ artifactId, operation, origin: artifact.artifactOrigin, sourceSha256, count: artifact.count }),
      caseId,
      artifactId,
      sourceSha256,
      producer: producerForSource(artifact.source),
      producerVersion: VERSION,
      operation,
      parameters: {
        binaryPath: provenance.binaryPath,
        artifactKind: artifact.kind,
        cliCommand: artifact.cliCommand ?? artifact.command ?? null,
      },
      result: {
        count: artifact.count ?? null,
        truncated: artifact.truncated ?? false,
        warning: artifact.warning ?? null,
        artifactOrigin: artifact.artifactOrigin ?? null,
      },
      evidenceMode: modeForArtifact(artifact),
      confidenceKind: confidenceForArtifact(artifact),
      limitations: limitationsForArtifact(artifact, provenance),
      locations: [{ kind: 'file', path: provenance.binaryPath, label: artifact.kind }],
      links: artifact.cliCommand ? [`command:${artifact.cliCommand}`] : [],
      authority: {
        evidenceRecordOnly: true,
        advisoryOnly: artifact.source !== 'real-backend',
        gyreVerdictAuthorityUnaffected: true,
        nestEvidenceLifecycleUnaffected: true,
      },
    };
  });
}

export function buildSelectedAnalysisProvider(provenance: AnalysisSessionProvenance): SelectedAnalysisProviderV1 {
  const native = provenance.runtime === 'tauri-native' && provenance.dataSource === 'real-backend';
  const simulation = provenance.runtime === 'browser-simulation' || provenance.dataSource === 'simulation';
  return {
    schema: 'hexhawk.selected_analysis_provider.v1',
    runtime: provenance.runtime,
    provider: native ? 'hexhawk-native' : simulation ? 'browser-simulation' : 'imported',
    providerVersion: VERSION,
    selectionSource: native ? 'tauri-runtime' : simulation ? 'browser-runtime' : 'unknown',
    analysisProfile: native ? 'native-local' : simulation ? 'browser-simulation' : 'unknown',
    fixedForRun: true,
    silentFallbackAllowed: false,
    failurePolicy: 'fail-closed-no-substitution',
    limitations: simulation
      ? ['Browser simulation may support UI QA only; failed native analysis must remain failed and must not be replaced by mock evidence.']
      : ['Provider identity is fixed for this analysis run; runtime failures must be shown as failures rather than silently substituting another provider.'],
  };
}

function entryForKind(kind: string, label: string, records: EvidenceRecordV1[], unavailableReason: string): CapabilityMatrixEntry {
  const matching = records.filter((record) => record.parameters.artifactKind === kind);
  if (matching.length === 0) {
    return { capability: label, availability: 'unavailable', reason: unavailableReason, remediation: unavailableReason, evidenceRecordIds: [] };
  }
  const hasNative = matching.some((record) => record.evidenceMode === 'native');
  const truncated = matching.some((record) => Boolean(record.result.truncated));
  return {
    capability: label,
    availability: hasNative ? truncated ? 'partial' : 'available' : 'simulation-only',
    reason: hasNative
      ? truncated
        ? 'Native evidence exists but declares truncation or budget limits.'
        : 'Native evidence record exists for this operation.'
      : 'Only browser-simulation or non-native evidence records exist for this operation.',
    remediation: hasNative ? undefined : 'Run in the installed desktop app and rerun the relevant analysis action.',
    evidenceRecordIds: matching.map((record) => record.evidenceId),
  };
}

export function buildCapabilityMatrix(provenance: AnalysisSessionProvenance, records = buildEvidenceRecordsFromProvenance(provenance)): CapabilityMatrixV1 {
  const artifactId = artifactIdFor(provenance);
  const entries: CapabilityMatrixEntry[] = [
    entryForKind('metadata', 'File identity / inspect', records, 'Run Inspect File to create file identity evidence.'),
    entryForKind('strings', 'Readable strings', records, 'Run Scan Strings to create string evidence.'),
    entryForKind('disassembly', 'Disassembly', records, 'Run Disassemble to create instruction evidence.'),
    entryForKind('cfg', 'Control-flow graph', records, 'Run Build CFG to create graph evidence.'),
    entryForKind('plugins', 'Plugin results', records, 'Run plugin analysis to create plugin evidence.'),
  ];
  return {
    schema: 'hexhawk.capability_matrix.v1',
    generatedForArtifactId: artifactId,
    generatedFromRuntime: provenance.runtime,
    entries,
    proofLimits: [
      'Capability matrix availability is derived from evidence records in this GUI/export session only.',
      'Unavailable and partial states are first-class proof states; they must not be hidden or described as complete.',
      'Simulation-only capabilities are useful for browser QA but are not native file-backed evidence.',
    ],
  };
}

export function validateEvidenceRecords(records: EvidenceRecordV1[]): { ok: boolean; errors: string[] } {
  const errors: string[] = [];
  const ids = new Set<string>();
  for (const record of records) {
    if (record.schemaVersion !== 1) errors.push(`${record.evidenceId || '<missing>'}: schemaVersion must be 1.`);
    if (!record.evidenceId) errors.push('evidenceId is required.');
    if (ids.has(record.evidenceId)) errors.push(`${record.evidenceId}: evidenceId must be unique.`);
    ids.add(record.evidenceId);
    if (!record.caseId) errors.push(`${record.evidenceId}: caseId is required.`);
    if (!record.artifactId) errors.push(`${record.evidenceId}: artifactId is required.`);
    if (record.sourceSha256 !== null && !SHA256_RE.test(record.sourceSha256)) errors.push(`${record.evidenceId}: sourceSha256 must be null or lowercase SHA-256.`);
    if (record.evidenceMode === 'native' && record.producer !== 'hexhawk-native') errors.push(`${record.evidenceId}: native evidence must be produced by hexhawk-native.`);
    if (record.evidenceMode === 'simulation' && record.authority.advisoryOnly !== true) errors.push(`${record.evidenceId}: simulation evidence must be advisory-only.`);
    const serialized = JSON.stringify(record);
    if (serialized.includes('threatScore')) errors.push(`${record.evidenceId}: evidence record must not carry threatScore authority fields.`);
    if (serialized.includes('classification')) errors.push(`${record.evidenceId}: evidence record must not carry classification authority fields.`);
  }
  return { ok: errors.length === 0, errors };
}
