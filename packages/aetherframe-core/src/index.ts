import { createHmac } from 'node:crypto';
import { appendFileSync, existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';

export { makeHexHawkAdapterContract, makeHexHawkAdapterFrame } from './adapters/hexhawk.js';

export type AetherFrameOperatingMode =
  | 'observe_only'
  | 'package_only'
  | 'advisory'
  | 'guided_mutation'
  | 'bounded_auto_mutation'
  | 'high_assurance'
  | 'research_debug';

export type AetherFrameBoundaryOperation =
  | 'read'
  | 'summarize'
  | 'refine'
  | 'mutate'
  | 'attach_metadata'
  | 'export';

export type AetherFrameBoundaryDecisionKind =
  | 'allowed'
  | 'blocked'
  | 'allowed_with_review'
  | 'allowed_package_only'
  | 'allowed_metadata_only'
  | 'escalated';

export type AetherFrameTransformationKind = 'deterministic' | 'heuristic' | 'statistical' | 'manual' | 'model_assisted';

export type AetherFrameNodeKind =
  | 'EvidenceNode'
  | 'ClaimNode'
  | 'MeasurementNode'
  | 'SourceNode'
  | 'DerivedInferenceNode'
  | 'ContradictionNode'
  | 'PolicyGateNode'
  | 'MutationProposalNode'
  | 'MutationAppliedNode'
  | 'MutationBlockedNode'
  | 'ReviewCheckpointNode'
  | 'UncertaintyNode'
  | 'OutcomeNode'
  | 'RollbackNode'
  | 'ExportNode';

export type AetherFrameMutationType =
  | 'text_refinement'
  | 'code_edit'
  | 'plan_revision'
  | 'recommendation_ranking'
  | 'evidence_packaging'
  | 'report_annotation'
  | 'prompt_rewrite'
  | 'configuration_suggestion'
  | 'workflow_action'
  | 'external_side_effect_proposal';

export type AetherFrameAuthorityModel = {
  soleAuthorityFields: string[];
  advisoryFields: string[];
  derivedFields: string[];
  inheritedFields: string[];
  blockedFields: string[];
  humanReviewRequiredFields: string[];
};

export type AetherFrameFrame = {
  schemaVersion: 'aetherframe.frame.v1';
  frameId: string;
  frameName: string;
  frameVersion: string;
  domain: string;
  objective: string;
  operatingMode: AetherFrameOperatingMode;
  adapterKind: 'core' | string;
  authorityModel: AetherFrameAuthorityModel;
  protectedFields: string[];
  mutableFields: string[];
  evidenceRequirements: string[];
  confidencePolicy: {
    maximumAllowedDelta: number;
    contradictionBlockThreshold: number;
    highUncertaintyClampThreshold: number;
    staleEvidenceHalfLifeDays: number;
  };
  uncertaintyPolicy: {
    requireExplicitUncertainty: boolean;
    unknownSourceReliability: 'conservative';
  };
  mutationPolicy: {
    allowMutation: boolean;
    requireRollbackForDestructiveChange: boolean;
    allowExternalSideEffects: boolean;
  };
  reviewPolicy: {
    humanReviewRequiredForProtectedFields: boolean;
    exportBlocksOnCriticalReview: boolean;
  };
  replayPolicy: {
    strictReplayRequired: boolean;
    allowedGeneratedFields: string[];
  };
  exportPolicy: {
    packageOnly: boolean;
    includeProofLimits: boolean;
    includeBlockedLineage: boolean;
  };
  stopConditions: string[];
  proofLimitTemplate: string[];
};

export type AetherFrameEvidenceNode = {
  id: string;
  kind: AetherFrameNodeKind;
  timestamp: string;
  source: string;
  sourceReliability: number | 'unknown';
  rawValue: unknown;
  normalizedValue: unknown;
  confidence: number;
  uncertaintyInterval?: { low: number; high: number };
  provenance: string[];
  redactionLevel: 'none' | 'low' | 'moderate' | 'high' | 'secret';
  replaySafe: boolean;
  reportable: boolean;
  protectedFieldInteraction: string[];
  frameId: string;
  proofLimits: string[];
  modelMetadata?: {
    provider?: string;
    model?: string;
    promptId?: string;
    contextDigest?: string;
  };
};

export type AetherFrameLineageEdge = {
  id: string;
  fromNodeIds: string[];
  toNodeId: string;
  relationshipType: string;
  transformationName: string;
  transformationVersion: string;
  transformationKind: AetherFrameTransformationKind;
  confidenceContribution: number;
  proofLimits: string[];
};

export type AetherFrameEvidenceGraph = {
  schemaVersion: 'aetherframe.evidence_graph.v1';
  graphId: string;
  frameId: string;
  nodes: AetherFrameEvidenceNode[];
  edges: AetherFrameLineageEdge[];
};

export type AetherFrameBoundaryRequest = {
  field: string;
  operation: AetherFrameBoundaryOperation;
  reason: string;
};

export type AetherFrameBoundaryDecision = {
  decision: AetherFrameBoundaryDecisionKind;
  field: string;
  operation: AetherFrameBoundaryOperation;
  owner: 'sole_authority' | 'advisory' | 'derived' | 'inherited' | 'blocked' | 'human_review_required' | 'unclaimed';
  requiresReview: boolean;
  mustPreserveOriginal: boolean;
  reason: string;
  proofLimits: string[];
  lineageNode: AetherFrameEvidenceNode;
};

export type AetherFrameConfidenceInput = {
  baseAuthorityConfidence: number;
  evidenceSupport: number;
  sourceReliability: number | 'unknown';
  measurementQuality: number;
  reproducibility: number;
  contradictionBurden: number;
  recencyDays: number;
  consensusStrength: number;
  modelUncertainty: number;
  humanReviewStatus: 'not_reviewed' | 'reviewed' | 'approved' | 'rejected';
  domainRisk: number;
  mutationRisk: number;
  rollbackConfidence: number;
  maximumAllowedDelta?: number;
};

export type AetherFrameConfidenceBreakdown = {
  baseConfidence: number;
  posteriorConfidence: number;
  allowedConfidence: number;
  upliftDelta: number;
  maximumAllowedDelta: number;
  uncertaintyPenalty: number;
  contradictionPenalty: number;
  sourceReliabilityAdjustment: number;
  reproducibilityAdjustment: number;
  recencyAdjustment: number;
  reviewAdjustment: number;
  policyClampReason: string;
  requiredNextEvidence: string[];
  proofLimits: string[];
};

export type AetherFrameMutationProposal = {
  mutationId: string;
  frameId: string;
  target: string;
  mutationType: AetherFrameMutationType;
  proposedChange: string;
  rationale: string;
  evidenceUsed: string[];
  protectedFieldsTouched: string[];
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  reversibility: 'full' | 'partial' | 'manual' | 'none';
  rollbackPlan: string | null;
  requiredApproval: 'none' | 'human' | 'authority_owner';
  stopConditions: string[];
  expectedOutcome: string;
  failureSignal: string;
};

export type AetherFrameMutationPlan = {
  proposal: AetherFrameMutationProposal;
  policyDecision: AetherFrameBoundaryDecision;
  approved: boolean;
  blockedLineage: AetherFrameEvidenceNode;
};

export type AetherFrameAppliedMutation = {
  mutationId: string;
  frameId: string;
  target: string;
  beforeSnapshot: unknown;
  afterSnapshot: unknown;
  diff: string;
  actor: string;
  approvalSource: string;
  verificationResult: {
    passed: boolean;
    command?: string;
    evidenceNodeIds: string[];
    proofLimits: string[];
  };
  rollbackStatus: 'not_required' | 'available' | 'executed' | 'failed' | 'manual_required';
  proofLimits: string[];
};

export type AetherFrameReplayBundle = {
  schemaVersion: 'aetherframe.replay_bundle.v1';
  replayId: string;
  generatedAt: string;
  frame: AetherFrameFrame;
  evidenceGraph: AetherFrameEvidenceGraph;
  mutationLog: AetherFrameMutationProposal[];
};

export type AetherFrameReplayResult = {
  replayId: string;
  stableDigest: string;
  boundaryDecisions: Array<Pick<AetherFrameBoundaryDecision, 'decision' | 'field' | 'operation' | 'owner'>>;
  lineage: {
    frameId: string;
    operatingMode: AetherFrameOperatingMode;
    protectedFields: string[];
    proofLimits: string[];
  };
};

export type AetherFrameValidationResult = {
  valid: boolean;
  errors: string[];
};

export type AetherFrameReviewItemKind =
  | 'contradiction_map'
  | 'missing_evidence'
  | 'weakest_assumption'
  | 'highest_risk_mutation'
  | 'authority_boundary_warning'
  | 'uncertainty_hotspot'
  | 'stop_condition_trigger'
  | 'human_review_queue';

export type AetherFrameReviewItem = {
  kind: AetherFrameReviewItemKind;
  severity: 'low' | 'medium' | 'high' | 'critical';
  rationale: string;
  affectedNodeIds: string[];
  affectedFields: string[];
  recommendedAction: string;
  blocksExport: boolean;
  blocksMutation: boolean;
  requiresHumanReview: boolean;
};

export type AetherFrameDriftResult = {
  driftDetected: boolean;
  priorDigest: string;
  currentDigest: string;
  changedSections: Array<'frame' | 'evidenceGraph' | 'mutationLog' | 'boundaryDecisions' | 'lineage'>;
  proofLimits: string[];
};

export type AetherFrameLoadResult<T> = AetherFrameValidationResult & {
  value: T;
  schemaPath: string;
};

export type AetherFrameMutationLedger = {
  schemaVersion: 'aetherframe.mutation_ledger.v1';
  ledgerId: string;
  frameId: string;
  mutations: AetherFrameMutationProposal[];
  appliedMutations: AetherFrameAppliedMutation[];
};

export type AetherFrameReplayMode = 'strict_replay' | 'explain_replay' | 'drift_detection' | 'counterfactual_replay';

export type AetherFrameExplainReplayResult = {
  mode: 'explain_replay';
  strict: AetherFrameReplayResult;
  commentary: string[];
  proofLimits: string[];
};

export type AetherFrameCounterfactualReplayResult = {
  mode: 'counterfactual_replay';
  baseline: AetherFrameReplayResult;
  counterfactual: AetherFrameReplayResult;
  counterfactualFrame: AetherFrameFrame;
  changedSections: AetherFrameDriftResult['changedSections'];
  proofLimits: string[];
};

export type AetherFrameAdapterContract = {
  schemaVersion: 'aetherframe.adapter_contract.v1';
  adapterKind: string;
  adapterVersion: string;
  authorityModel: AetherFrameAuthorityModel;
  evidenceSources: string[];
  protectedFields: string[];
  mutationTypes: AetherFrameMutationType[];
  validationCommands: string[];
  exportFormat: string;
  proofLimitLanguage: string[];
  stopConditions: string[];
};

export type AetherFrameAdapterRegistry = {
  contracts: Map<string, AetherFrameAdapterContract>;
};

export type AetherFrameCliResult = {
  exitCode: number;
  stdout: Record<string, unknown>;
  stderr: string;
};

export type AetherFrameSchemaKind = 'frame' | 'evidence_graph' | 'mutation_ledger' | 'replay_bundle' | 'adapter_contract';

export type AetherFrameSchemaNegotiationResult = AetherFrameValidationResult & {
  schemaVersion: string;
  expectedPrefix: string;
  major: number | null;
  supportedMajor: number;
  needsMigration: boolean;
  proofLimits: string[];
};

export type AetherFrameMigrationResult<T = unknown> = AetherFrameValidationResult & {
  value: T;
  migrated: boolean;
  fromSchemaVersion: string | null;
  toSchemaVersion: string;
  proofLimits: string[];
};

export type AetherFramePersistentReplayEnvelope = {
  schemaVersion: 'aetherframe.persisted_replay_bundle.v1';
  replayBundle: AetherFrameReplayBundle;
  stableDigest: string;
  savedAt: string;
  proofLimits: string[];
};

export type AetherFrameReplaySaveResult = AetherFrameValidationResult & {
  path: string;
  stableDigest: string;
  proofLimits: string[];
};

export type AetherFrameReplayLoadResult = AetherFrameValidationResult & {
  value: AetherFrameReplayBundle;
  persistedDigest: string;
  recomputedDigest: string;
  digestMatches: boolean;
  proofLimits: string[];
};

export type AetherFrameAuditLogEntryInput = {
  eventType: string;
  actor: string;
  replayId?: string;
  stableDigest?: string;
  proofLimits: string[];
  details?: Record<string, unknown>;
  signingKey?: string;
};

export type AetherFrameAuditLogEntry = Omit<AetherFrameAuditLogEntryInput, 'signingKey'> & {
  schemaVersion: 'aetherframe.audit_log_entry.v1';
  sequence: number;
  timestamp: string;
  previousEntryDigest: string | null;
  previous_entry_digest: string | null;
  entryDigest: string;
  entry_digest: string;
  signatureAlgorithm?: 'hmac-sha256';
  auditSignature?: string;
  audit_signature?: string;
};

export type AetherFrameReplayBundleListItem = {
  replayId: string;
  path: string;
  stableDigest: string;
  generatedAt: string;
  savedAt?: string;
};

export type AetherFrameReplayBundleStoreLoadResult = AetherFrameReplayLoadResult & {
  path: string;
};

export type AetherFrameReplayBundleAuditSummary = {
  bundleCount: number;
  replayIds: string[];
  bundles: AetherFrameReplayBundleListItem[];
  proofLimits: string[];
};

export type AetherFrameReplayBundleStore = {
  rootDir: string;
  save: (bundle: AetherFrameReplayBundle) => AetherFrameReplaySaveResult;
  listBundles: () => AetherFrameReplayBundleListItem[];
  loadByReplayId: (replayId: string) => AetherFrameReplayBundleStoreLoadResult;
  verifyDigest: (path: string) => AetherFrameReplayLoadResult;
  compareVersions: (firstPath: string, secondPath: string) => AetherFrameDriftResult;
  exportAuditSummary: () => AetherFrameReplayBundleAuditSummary;
};

export type AetherFrameAuditLogVerificationResult = AetherFrameValidationResult & {
  entryCount: number;
  proofLimits: string[];
};

export type AetherFrameMigrationFunction = (artifact: unknown) => unknown;

export type AetherFrameMigrationRegistry = {
  migrations: Map<string, AetherFrameMigrationFunction>;
};

export type AetherFrameDryRunMigrationResult<T = unknown> = AetherFrameMigrationResult<T> & {
  dryRun: true;
  blockedDiagnostics: string[];
};

export type AetherFrameAdapterManifestDiscovery = {
  path: string;
  contract: AetherFrameAdapterContract | null;
  validation: AetherFrameValidationResult;
};

export type AetherFrameAdapterCompatibilityReport = {
  validManifests: number;
  invalidManifests: number;
  diagnostics: string[];
  proofLimits: string[];
};

export type AetherFrameAdapterManifestDiscoveryResult = {
  manifests: AetherFrameAdapterManifestDiscovery[];
  compatibilityReport: AetherFrameAdapterCompatibilityReport;
};

export type AetherFrameAdapterRegistryLoadResult = AetherFrameValidationResult & {
  registry: AetherFrameAdapterRegistry;
  compatibilityReport: AetherFrameAdapterCompatibilityReport;
};

export type AetherFrameReplayReport = {
  replayId: string;
  stableDigest: string;
  boundaryDecisions: AetherFrameReplayResult['boundaryDecisions'];
  blockedActions: AetherFrameReplayResult['boundaryDecisions'];
  proofLimits: string[];
};

function clamp(value: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, value));
}

function stableStringify(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map(stableStringify).join(',')}]`;
  }
  if (value && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record)
      .sort()
      .filter(key => key !== 'generatedAt' && key !== 'timestamp')
      .map(key => `${JSON.stringify(key)}:${stableStringify(record[key])}`)
      .join(',')}}`;
  }
  return JSON.stringify(value);
}

function simpleDigest(value: unknown): string {
  const text = stableStringify(value);
  let hash = 2166136261;
  for (let i = 0; i < text.length; i += 1) {
    hash ^= text.charCodeAt(i);
    hash = Math.imul(hash, 16777619);
  }
  return `fnv1a32:${(hash >>> 0).toString(16).padStart(8, '0')}`;
}

const OPERATING_MODES: AetherFrameOperatingMode[] = [
  'observe_only',
  'package_only',
  'advisory',
  'guided_mutation',
  'bounded_auto_mutation',
  'high_assurance',
  'research_debug',
];

const SCHEMA_PREFIX_BY_KIND: Record<AetherFrameSchemaKind, string> = {
  frame: 'aetherframe.frame',
  evidence_graph: 'aetherframe.evidence_graph',
  mutation_ledger: 'aetherframe.mutation_ledger',
  replay_bundle: 'aetherframe.replay_bundle',
  adapter_contract: 'aetherframe.adapter_contract',
};

const SUPPORTED_SCHEMA_MAJOR_BY_KIND: Record<AetherFrameSchemaKind, number> = {
  frame: 1,
  evidence_graph: 1,
  mutation_ledger: 1,
  replay_bundle: 1,
  adapter_contract: 1,
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every(item => typeof item === 'string');
}

function schemaKindForVersion(schemaVersion: string): AetherFrameSchemaKind | null {
  for (const [kind, prefix] of Object.entries(SCHEMA_PREFIX_BY_KIND) as Array<[AetherFrameSchemaKind, string]>) {
    if (schemaVersion.startsWith(`${prefix}.v`)) return kind;
  }
  return null;
}

function schemaVersionOf(value: unknown): string | null {
  return isRecord(value) && typeof value.schemaVersion === 'string' ? value.schemaVersion : null;
}

export function negotiateSchemaVersion(schemaVersion: string, kind?: AetherFrameSchemaKind): AetherFrameSchemaNegotiationResult {
  const resolvedKind = kind ?? schemaKindForVersion(schemaVersion);
  const expectedPrefix = resolvedKind ? SCHEMA_PREFIX_BY_KIND[resolvedKind] : 'aetherframe.<known_artifact>';
  const supportedMajor = resolvedKind ? SUPPORTED_SCHEMA_MAJOR_BY_KIND[resolvedKind] : 1;
  const match = schemaVersion.match(/^(aetherframe\.[a-z_]+)\.v(\d+)$/);
  const major = match ? Number(match[2]) : null;
  const errors: string[] = [];

  if (!resolvedKind) errors.push(`unsupported schema family for ${schemaVersion}`);
  if (!schemaVersion.startsWith(`${expectedPrefix}.v`)) errors.push(`schemaVersion ${schemaVersion} does not match expected prefix ${expectedPrefix}`);
  if (major === null) errors.push(`schemaVersion ${schemaVersion} must end with .v<major>`);
  if (major !== null && major > supportedMajor) errors.push(`unsupported major schema version ${schemaVersion}; supported ${expectedPrefix}.v${supportedMajor}`);

  return {
    valid: errors.length === 0,
    errors,
    schemaVersion,
    expectedPrefix,
    major,
    supportedMajor,
    needsMigration: errors.length === 0 && major !== null && major < supportedMajor,
    proofLimits: [
      'Schema negotiation only validates AetherFrame artifact schema compatibility; it does not prove external-world truth.',
      'Unknown major schema versions are rejected until an explicit reviewed migration exists.',
    ],
  };
}

export function migrateAetherFrameArtifact<T = unknown>(artifact: T, toSchemaVersion: string): AetherFrameMigrationResult<T> {
  const fromSchemaVersion = schemaVersionOf(artifact);
  const kind = fromSchemaVersion ? schemaKindForVersion(fromSchemaVersion) : schemaKindForVersion(toSchemaVersion);
  const negotiation = fromSchemaVersion ? negotiateSchemaVersion(fromSchemaVersion, kind ?? undefined) : { valid: false, errors: ['artifact schemaVersion is required for migration'] } as AetherFrameValidationResult;
  if (!negotiation.valid) {
    return {
      valid: false,
      errors: negotiation.errors,
      value: artifact,
      migrated: false,
      fromSchemaVersion,
      toSchemaVersion,
      proofLimits: ['Migration is blocked because source schema negotiation failed.'],
    };
  }
  if (fromSchemaVersion === toSchemaVersion) {
    return {
      valid: true,
      errors: [],
      value: artifact,
      migrated: false,
      fromSchemaVersion,
      toSchemaVersion,
      proofLimits: ['AetherFrame migration stub: source and target schema versions match; no migration was applied.'],
    };
  }
  return {
    valid: false,
    errors: [`migration stub has no reviewed migration path from ${fromSchemaVersion} to ${toSchemaVersion}`],
    value: artifact,
    migrated: false,
    fromSchemaVersion,
    toSchemaVersion,
    proofLimits: ['AetherFrame migration stub exists explicitly to avoid silent schema rewriting.'],
  };
}

const moduleDir = dirname(fileURLToPath(import.meta.url));
const schemaRootCandidates = [join(moduleDir, '..', 'schemas'), join(moduleDir, '..', '..', 'schemas')];
const ajv = new Ajv2020({ allErrors: true, strict: false });
const schemaValidatorCache = new Map<string, ReturnType<Ajv2020['compile']>>();

function schemaPath(name: string): string {
  for (const root of schemaRootCandidates) {
    const candidate = join(root, name);
    try {
      readFileSync(candidate, 'utf8');
      return candidate;
    } catch {
      // Try the next source/build layout candidate.
    }
  }
  return join(schemaRootCandidates[0], name);
}

function validateWithSchema(schemaFileName: string, value: unknown): AetherFrameValidationResult {
  let validate = schemaValidatorCache.get(schemaFileName);
  if (!validate) {
    validate = ajv.compile(JSON.parse(readFileSync(schemaPath(schemaFileName), 'utf8')));
    schemaValidatorCache.set(schemaFileName, validate);
  }
  const valid = Boolean(validate(value));
  return {
    valid,
    errors: valid ? [] : (validate.errors ?? []).map(error => {
      const path = error.instancePath || '/';
      return `${path} ${error.message ?? 'failed schema validation'}`.trim();
    }),
  };
}

function mergeValidation(primary: AetherFrameValidationResult, extraErrors: string[]): AetherFrameValidationResult {
  const errors = [...primary.errors, ...extraErrors];
  return { valid: errors.length === 0, errors };
}

export function validateFrame(value: unknown): AetherFrameValidationResult {
  const schemaValidation = validateWithSchema('frame.schema.json', value);
  const extraErrors: string[] = [];
  if (isRecord(value) && typeof value.schemaVersion === 'string') {
    extraErrors.push(...negotiateSchemaVersion(value.schemaVersion, 'frame').errors);
  }
  if (isRecord(value) && typeof value.operatingMode === 'string' && !OPERATING_MODES.includes(value.operatingMode as AetherFrameOperatingMode)) {
    extraErrors.push(`/operatingMode is unknown or unsupported: ${value.operatingMode}`);
  }
  return mergeValidation(schemaValidation, extraErrors);
}

function parseJsonFile(path: string): unknown {
  return JSON.parse(readFileSync(path, 'utf8')) as unknown;
}

function extractPayload(value: unknown, key: string): unknown {
  if (isRecord(value) && key in value) return value[key];
  return value;
}

export function validateEvidenceGraph(value: unknown): AetherFrameValidationResult {
  const graph = extractPayload(value, 'evidenceGraph');
  const schemaValidation = validateWithSchema('evidence_graph.schema.json', graph);
  const extraErrors = isRecord(graph) && typeof graph.schemaVersion === 'string' ? negotiateSchemaVersion(graph.schemaVersion, 'evidence_graph').errors : [];
  return mergeValidation(schemaValidation, extraErrors);
}

function unsafeProtectedMutationWithoutRollback(mutation: unknown): boolean {
  if (!isRecord(mutation)) return false;
  return Array.isArray(mutation.protectedFieldsTouched)
    && mutation.protectedFieldsTouched.length > 0
    && mutation.reversibility === 'none'
    && mutation.rollbackPlan === null;
}

export function validateMutationLedger(value: unknown): AetherFrameValidationResult {
  const schemaValidation = validateWithSchema('mutation_ledger.schema.json', value);
  const extraErrors: string[] = [];
  if (isRecord(value) && typeof value.schemaVersion === 'string') {
    extraErrors.push(...negotiateSchemaVersion(value.schemaVersion, 'mutation_ledger').errors);
  }
  if (isRecord(value) && Array.isArray(value.mutations)) {
    value.mutations.forEach((mutation, index) => {
      if (unsafeProtectedMutationWithoutRollback(mutation)) {
        extraErrors.push(`/mutations/${index} protected-field mutation with reversibility none requires rollback plan before it can be ledgered as safe`);
      }
    });
  }
  return mergeValidation(schemaValidation, extraErrors);
}

export function validateReplayBundle(value: unknown): AetherFrameValidationResult {
  const schemaValidation = validateWithSchema('replay_bundle.schema.json', value);
  const extraErrors: string[] = [];
  if (isRecord(value) && typeof value.schemaVersion === 'string') {
    extraErrors.push(...negotiateSchemaVersion(value.schemaVersion, 'replay_bundle').errors);
  }
  if (isRecord(value) && isRecord(value.frame) && isRecord(value.evidenceGraph)) {
    const frameRecord = value.frame;
    const graphRecord = value.evidenceGraph;
    if (graphRecord.frameId !== frameRecord.frameId) {
      extraErrors.push('evidenceGraph.frameId must match frame.frameId');
    }
    if (Array.isArray(graphRecord.nodes)) {
      graphRecord.nodes.forEach((node, index) => {
        if (isRecord(node) && node.frameId !== frameRecord.frameId) {
          extraErrors.push(`/evidenceGraph/nodes/${index}/frameId must match frame.frameId`);
        }
      });
    }
  }
  return mergeValidation(schemaValidation, extraErrors);
}

export function validateAdapterContract(value: unknown): AetherFrameValidationResult {
  const errors: string[] = [];
  if (!isRecord(value)) return { valid: false, errors: ['adapter contract must be an object'] };
  if (typeof value.schemaVersion === 'string') errors.push(...negotiateSchemaVersion(value.schemaVersion, 'adapter_contract').errors);
  if (value.schemaVersion !== 'aetherframe.adapter_contract.v1') errors.push('schemaVersion must be aetherframe.adapter_contract.v1');
  if (typeof value.adapterKind !== 'string') errors.push('adapterKind is required');
  if (typeof value.adapterVersion !== 'string') errors.push('adapterVersion is required');
  if (!isStringArray(value.evidenceSources)) errors.push('evidenceSources must be a string array');
  if (!isStringArray(value.protectedFields) || value.protectedFields.length === 0) errors.push('protectedFields must be a non-empty string array');
  if (!Array.isArray(value.mutationTypes)) errors.push('mutationTypes must be an array');
  if (!isStringArray(value.validationCommands)) errors.push('validationCommands must be a string array');
  if (typeof value.exportFormat !== 'string') errors.push('exportFormat is required');
  if (!isStringArray(value.proofLimitLanguage)) errors.push('proofLimitLanguage must be a string array');
  if (!isStringArray(value.stopConditions)) errors.push('stopConditions must be a string array');
  const authority = value.authorityModel;
  if (!isRecord(authority) || !isStringArray(authority.soleAuthorityFields) || authority.soleAuthorityFields.length === 0) {
    errors.push('authorityModel.soleAuthorityFields must be a non-empty string array');
  }
  return { valid: errors.length === 0, errors };
}

export function loadFrameFile(path: string): AetherFrameLoadResult<AetherFrameFrame> {
  const raw = parseJsonFile(path);
  const value = extractPayload(raw, 'frame') as AetherFrameFrame;
  return { ...validateFrame(value), value, schemaPath: 'schemas/frame.schema.json' };
}

export function loadEvidenceGraphFile(path: string): AetherFrameLoadResult<AetherFrameEvidenceGraph> {
  const raw = parseJsonFile(path);
  const value = extractPayload(raw, 'evidenceGraph') as AetherFrameEvidenceGraph;
  return { ...validateEvidenceGraph(value), value, schemaPath: 'schemas/evidence_graph.schema.json' };
}

export function loadMutationLedgerFile(path: string): AetherFrameLoadResult<AetherFrameMutationLedger> {
  const value = parseJsonFile(path) as AetherFrameMutationLedger;
  return { ...validateMutationLedger(value), value, schemaPath: 'schemas/mutation_ledger.schema.json' };
}

export function loadReplayBundleFile(path: string): AetherFrameLoadResult<AetherFrameReplayBundle> {
  const value = parseJsonFile(path) as AetherFrameReplayBundle;
  return { ...validateReplayBundle(value), value, schemaPath: 'schemas/replay_bundle.schema.json' };
}

export function makeFrame(input: {
  frameId: string;
  frameName: string;
  domain: string;
  objective: string;
  operatingMode: AetherFrameOperatingMode;
  authorityModel: AetherFrameAuthorityModel;
  protectedFields: string[];
  mutableFields: string[];
  frameVersion?: string;
  adapterKind?: string;
  evidenceRequirements?: string[];
  stopConditions?: string[];
  proofLimitTemplate?: string[];
}): AetherFrameFrame {
  const packageOnly = input.operatingMode === 'package_only' || input.operatingMode === 'high_assurance';
  return {
    schemaVersion: 'aetherframe.frame.v1',
    frameId: input.frameId,
    frameName: input.frameName,
    frameVersion: input.frameVersion ?? '0.1.0',
    domain: input.domain,
    objective: input.objective,
    operatingMode: input.operatingMode,
    adapterKind: input.adapterKind ?? 'core',
    authorityModel: input.authorityModel,
    protectedFields: [...input.protectedFields],
    mutableFields: [...input.mutableFields],
    evidenceRequirements: input.evidenceRequirements ?? ['explicit evidence source', 'proof-limit disclosure'],
    confidencePolicy: {
      maximumAllowedDelta: input.operatingMode === 'high_assurance' ? 0 : 8,
      contradictionBlockThreshold: 0.6,
      highUncertaintyClampThreshold: 0.5,
      staleEvidenceHalfLifeDays: 30,
    },
    uncertaintyPolicy: {
      requireExplicitUncertainty: true,
      unknownSourceReliability: 'conservative',
    },
    mutationPolicy: {
      allowMutation: ['guided_mutation', 'bounded_auto_mutation', 'research_debug'].includes(input.operatingMode),
      requireRollbackForDestructiveChange: true,
      allowExternalSideEffects: input.operatingMode === 'research_debug',
    },
    reviewPolicy: {
      humanReviewRequiredForProtectedFields: true,
      exportBlocksOnCriticalReview: true,
    },
    replayPolicy: {
      strictReplayRequired: true,
      allowedGeneratedFields: ['generatedAt', 'timestamp'],
    },
    exportPolicy: {
      packageOnly,
      includeProofLimits: true,
      includeBlockedLineage: true,
    },
    stopConditions: input.stopConditions ?? ['protected authority mutation attempted', 'critical contradiction unresolved'],
    proofLimitTemplate: input.proofLimitTemplate ?? [
      'AetherFrame is advisory unless the frame delegates authority explicitly.',
      'Protected authoritative fields remain owned by their declared authority source.',
      'Replay proves deterministic boundary logic, not external-world truth.',
    ],
  };
}

function ownerForField(frame: AetherFrameFrame, field: string): AetherFrameBoundaryDecision['owner'] {
  if (frame.authorityModel.soleAuthorityFields.includes(field)) return 'sole_authority';
  if (frame.authorityModel.advisoryFields.includes(field)) return 'advisory';
  if (frame.authorityModel.derivedFields.includes(field)) return 'derived';
  if (frame.authorityModel.inheritedFields.includes(field)) return 'inherited';
  if (frame.authorityModel.blockedFields.includes(field)) return 'blocked';
  if (frame.authorityModel.humanReviewRequiredFields.includes(field)) return 'human_review_required';
  return 'unclaimed';
}

export function decideBoundary(frame: AetherFrameFrame, request: AetherFrameBoundaryRequest): AetherFrameBoundaryDecision {
  const owner = ownerForField(frame, request.field);
  const protectedField = frame.protectedFields.includes(request.field) || owner === 'sole_authority' || owner === 'blocked';
  const mutableField = frame.mutableFields.includes(request.field);
  let decision: AetherFrameBoundaryDecisionKind = 'allowed';
  let requiresReview = owner === 'human_review_required';
  let mustPreserveOriginal = protectedField;
  const proofLimits: string[] = [];

  if (request.operation === 'mutate' && protectedField) {
    decision = 'blocked';
    proofLimits.push(`Field ${request.field} is protected by the frame authority model.`);
  } else if (frame.operatingMode === 'observe_only' && request.operation !== 'read' && request.operation !== 'summarize') {
    decision = 'blocked';
    proofLimits.push('observe_only mode cannot refine, mutate, attach metadata, or export as instructions.');
  } else if (frame.operatingMode === 'package_only') {
    if (request.operation === 'attach_metadata' && mutableField) {
      decision = 'allowed_metadata_only';
    } else if (request.operation === 'export') {
      decision = 'allowed_package_only';
    } else if (request.operation === 'mutate' || request.operation === 'refine') {
      decision = 'blocked';
      proofLimits.push('package_only mode may append lineage but must not alter core content.');
    }
  } else if (frame.operatingMode === 'high_assurance' && request.operation === 'mutate') {
    decision = 'blocked';
    proofLimits.push('high_assurance mode blocks mutation unless a future frame delegates explicit authority.');
  } else if (requiresReview) {
    decision = 'allowed_with_review';
  }

  if (proofLimits.length === 0) {
    proofLimits.push('Decision is bounded by the active frame policy and does not transfer authority.');
  }

  const lineageNode: AetherFrameEvidenceNode = {
    id: `policy-${request.operation}-${request.field}`,
    kind: 'PolicyGateNode',
    timestamp: 'generated',
    source: 'aetherframe.boundary-engine',
    sourceReliability: 1,
    rawValue: request,
    normalizedValue: decision,
    confidence: 1,
    uncertaintyInterval: { low: 1, high: 1 },
    provenance: [frame.frameId],
    redactionLevel: 'none',
    replaySafe: true,
    reportable: true,
    protectedFieldInteraction: protectedField ? [request.field] : [],
    frameId: frame.frameId,
    proofLimits,
  };

  return {
    decision,
    field: request.field,
    operation: request.operation,
    owner,
    requiresReview,
    mustPreserveOriginal,
    reason: request.reason,
    proofLimits,
    lineageNode,
  };
}

export function evaluateConfidence(
  frame: AetherFrameFrame,
  graph: AetherFrameEvidenceGraph,
  input: AetherFrameConfidenceInput,
): AetherFrameConfidenceBreakdown {
  const baseConfidence = clamp(input.baseAuthorityConfidence, 0, 100);
  const maximumAllowedDelta = Math.min(
    frame.confidencePolicy.maximumAllowedDelta,
    input.maximumAllowedDelta ?? frame.confidencePolicy.maximumAllowedDelta,
  );
  const sourceReliability = input.sourceReliability === 'unknown' ? 0.45 : input.sourceReliability;
  const uncertaintyPenalty = Math.round(clamp(input.modelUncertainty * 24 + (1 - input.measurementQuality) * 10, 0, 30));
  const contradictionPenalty = Math.round(clamp(input.contradictionBurden * 45, 0, 40));
  const sourceReliabilityAdjustment = Math.round((sourceReliability - 0.5) * 10);
  const reproducibilityAdjustment = Math.round((input.reproducibility - 0.5) * 8);
  const recencyAdjustment = -Math.round(clamp(input.recencyDays / frame.confidencePolicy.staleEvidenceHalfLifeDays, 0, 3) * 4);
  const reviewAdjustment = input.humanReviewStatus === 'approved' ? 4 : input.humanReviewStatus === 'reviewed' ? 2 : input.humanReviewStatus === 'rejected' ? -20 : -2;
  const support = clamp(input.evidenceSupport, 0, 30) * 0.35 + input.consensusStrength * 8;
  const riskPenalty = input.domainRisk * 6 + input.mutationRisk * 5 + (1 - input.rollbackConfidence) * 4;
  const rawDelta = support + sourceReliabilityAdjustment + reproducibilityAdjustment + recencyAdjustment + reviewAdjustment - uncertaintyPenalty - contradictionPenalty - riskPenalty;

  let policyClampReason = 'within frame confidence policy';
  let allowedDelta = clamp(rawDelta, -100, maximumAllowedDelta);
  if (input.contradictionBurden >= frame.confidencePolicy.contradictionBlockThreshold) {
    allowedDelta = Math.min(allowedDelta, 0);
    policyClampReason = `contradiction burden exceeded threshold for ${frame.operatingMode}`;
  }
  if (input.modelUncertainty >= frame.confidencePolicy.highUncertaintyClampThreshold) {
    allowedDelta = Math.min(allowedDelta, 0);
    policyClampReason = `high uncertainty clamp for ${frame.operatingMode}`;
  }
  if (frame.operatingMode === 'package_only' || frame.operatingMode === 'observe_only' || frame.operatingMode === 'high_assurance') {
    allowedDelta = Math.min(allowedDelta, 0);
    policyClampReason = `${frame.operatingMode} mode does not permit advisory uplift of authoritative confidence`;
  }

  const posteriorConfidence = clamp(baseConfidence + rawDelta, 0, 100);
  const allowedConfidence = clamp(baseConfidence + allowedDelta, 0, 100);
  const requiredNextEvidence = [];
  if (graph.nodes.length === 0) requiredNextEvidence.push('Add at least one replay-safe evidence node.');
  if (input.contradictionBurden > 0.3) requiredNextEvidence.push('Resolve or explain contradictions before uplift.');
  if (input.modelUncertainty > 0.25) requiredNextEvidence.push('Reduce model uncertainty with deterministic validation or human review.');
  if (input.sourceReliability === 'unknown') requiredNextEvidence.push('Establish source reliability.');

  return {
    baseConfidence,
    posteriorConfidence,
    allowedConfidence,
    upliftDelta: Math.round((allowedConfidence - baseConfidence) * 100) / 100,
    maximumAllowedDelta,
    uncertaintyPenalty,
    contradictionPenalty,
    sourceReliabilityAdjustment,
    reproducibilityAdjustment,
    recencyAdjustment,
    reviewAdjustment,
    policyClampReason,
    requiredNextEvidence,
    proofLimits: [
      'Confidence is advisory unless the frame authority model delegates truth ownership.',
      'Contradictions and uncertainty can clamp uplift to zero or below.',
      'AetherFrame confidence decomposition does not replace authoritative validation.',
    ],
  };
}

export function planMutation(frame: AetherFrameFrame, proposal: AetherFrameMutationProposal): AetherFrameMutationPlan {
  const field = proposal.protectedFieldsTouched[0] ?? proposal.target;
  const policyDecision = decideBoundary(frame, {
    field,
    operation: 'mutate',
    reason: proposal.rationale,
  });
  const lacksRollback = frame.mutationPolicy.requireRollbackForDestructiveChange && proposal.reversibility === 'none' && !proposal.rollbackPlan;
  const blocked = policyDecision.decision === 'blocked' || lacksRollback || !frame.mutationPolicy.allowMutation;
  const proofLimits = [
    ...policyDecision.proofLimits,
    ...(lacksRollback ? ['Mutation lacks rollback and is blocked by mutation governance.'] : []),
    ...(!frame.mutationPolicy.allowMutation ? [`${frame.operatingMode} mode does not allow content mutation.`] : []),
  ];
  const blockedLineage: AetherFrameEvidenceNode = {
    id: `mutation-blocked-${proposal.mutationId}`,
    kind: 'MutationBlockedNode',
    timestamp: 'generated',
    source: 'aetherframe.mutation-governance',
    sourceReliability: 1,
    rawValue: proposal,
    normalizedValue: blocked ? 'blocked' : 'approved',
    confidence: 1,
    uncertaintyInterval: { low: 1, high: 1 },
    provenance: proposal.evidenceUsed,
    redactionLevel: 'none',
    replaySafe: true,
    reportable: true,
    protectedFieldInteraction: proposal.protectedFieldsTouched,
    frameId: frame.frameId,
    proofLimits,
  };
  return {
    proposal,
    policyDecision: blocked ? { ...policyDecision, decision: 'blocked', proofLimits } : policyDecision,
    approved: !blocked,
    blockedLineage,
  };
}

export function exportPackageOnlyLineage(frame: AetherFrameFrame, graph: AetherFrameEvidenceGraph, content: string) {
  return {
    content,
    lineage: {
      schemaVersion: 'aetherframe.export_lineage.v1',
      frameId: frame.frameId,
      frameVersion: frame.frameVersion,
      operatingMode: frame.operatingMode,
      authorityBoundaries: frame.authorityModel,
      protectedFields: [...frame.protectedFields],
      evidenceSummary: {
        graphId: graph.graphId,
        nodeCount: graph.nodes.length,
        edgeCount: graph.edges.length,
      },
      mutationsApplied: [] as string[],
      mutationsBlocked: [...frame.protectedFields],
      proofLimits: [...frame.proofLimitTemplate],
      replayId: `replay-${graph.graphId}`,
    },
  };
}

export function makeReplayBundle(input: {
  replayId: string;
  frame: AetherFrameFrame;
  evidenceGraph: AetherFrameEvidenceGraph;
  generatedAt: string;
  mutationLog?: AetherFrameMutationProposal[];
}): AetherFrameReplayBundle {
  return {
    schemaVersion: 'aetherframe.replay_bundle.v1',
    replayId: input.replayId,
    generatedAt: input.generatedAt,
    frame: input.frame,
    evidenceGraph: input.evidenceGraph,
    mutationLog: input.mutationLog ?? [],
  };
}

export function generateReviewQueue(
  frame: AetherFrameFrame,
  graph: AetherFrameEvidenceGraph,
  mutationProposals: AetherFrameMutationProposal[] = [],
): AetherFrameReviewItem[] {
  const items: AetherFrameReviewItem[] = [];
  const contradictionNodes = graph.nodes.filter(node => node.kind === 'ContradictionNode');
  if (contradictionNodes.length > 0) {
    items.push({
      kind: 'contradiction_map',
      severity: 'high',
      rationale: 'Contradiction nodes exist and must dominate weak supporting evidence before confidence uplift or mutation.',
      affectedNodeIds: contradictionNodes.map(node => node.id),
      affectedFields: Array.from(new Set(contradictionNodes.flatMap(node => node.protectedFieldInteraction))),
      recommendedAction: 'Resolve, explain, or explicitly carry each contradiction into export proof limits.',
      blocksExport: frame.reviewPolicy.exportBlocksOnCriticalReview && contradictionNodes.some(node => node.confidence >= frame.confidencePolicy.contradictionBlockThreshold),
      blocksMutation: true,
      requiresHumanReview: true,
    });
  }

  const uncertaintyNodes = graph.nodes.filter(node => {
    const interval = node.uncertaintyInterval;
    return interval ? interval.high - interval.low >= frame.confidencePolicy.highUncertaintyClampThreshold : node.kind === 'UncertaintyNode';
  });
  if (uncertaintyNodes.length > 0) {
    items.push({
      kind: 'uncertainty_hotspot',
      severity: 'medium',
      rationale: 'Wide uncertainty intervals or explicit uncertainty nodes clamp confidence and require next evidence.',
      affectedNodeIds: uncertaintyNodes.map(node => node.id),
      affectedFields: Array.from(new Set(uncertaintyNodes.flatMap(node => node.protectedFieldInteraction))),
      recommendedAction: 'Add reproducible measurements, primary sources, or human review before presenting uplift.',
      blocksExport: false,
      blocksMutation: true,
      requiresHumanReview: false,
    });
  }

  if (graph.nodes.length === 0) {
    items.push({
      kind: 'missing_evidence',
      severity: 'critical',
      rationale: 'The evidence graph is empty; claims cannot be replayed or challenged.',
      affectedNodeIds: [],
      affectedFields: frame.protectedFields,
      recommendedAction: 'Collect at least one replay-safe evidence node before export.',
      blocksExport: true,
      blocksMutation: true,
      requiresHumanReview: true,
    });
  }

  for (const proposal of mutationProposals) {
    const touchesProtected = proposal.protectedFieldsTouched.some(field => frame.protectedFields.includes(field));
    if (proposal.riskLevel === 'high' || proposal.riskLevel === 'critical' || touchesProtected) {
      items.push({
        kind: 'highest_risk_mutation',
        severity: proposal.riskLevel === 'critical' ? 'critical' : 'high',
        rationale: `Mutation ${proposal.mutationId} touches protected or high-risk scope and cannot be silent.`,
        affectedNodeIds: proposal.evidenceUsed,
        affectedFields: proposal.protectedFieldsTouched.length > 0 ? proposal.protectedFieldsTouched : [proposal.target],
        recommendedAction: 'Require explicit approval, rollback plan, and preserved before/after lineage before applying.',
        blocksExport: false,
        blocksMutation: true,
        requiresHumanReview: proposal.requiredApproval !== 'none' || touchesProtected,
      });
    }
  }

  const protectedAuthorityFields = frame.protectedFields.filter(field =>
    frame.authorityModel.soleAuthorityFields.includes(field) || frame.authorityModel.blockedFields.includes(field),
  );
  if (protectedAuthorityFields.length > 0) {
    items.push({
      kind: 'authority_boundary_warning',
      severity: 'high',
      rationale: 'The frame contains protected authority fields that AetherFrame may read/package but not silently mutate.',
      affectedNodeIds: graph.nodes.filter(node => node.protectedFieldInteraction.some(field => protectedAuthorityFields.includes(field))).map(node => node.id),
      affectedFields: protectedAuthorityFields,
      recommendedAction: 'Preserve originals, record blocked actions, and route any contradiction or mutation attempt to review.',
      blocksExport: false,
      blocksMutation: true,
      requiresHumanReview: true,
    });
  }

  return items;
}

export function replayStrict(bundle: AetherFrameReplayBundle): AetherFrameReplayResult {
  const boundaryDecisions = [
    ...bundle.frame.protectedFields.map(field => decideBoundary(bundle.frame, { field, operation: 'mutate', reason: 'strict replay protected-field check' })),
    ...bundle.frame.mutableFields.map(field => decideBoundary(bundle.frame, { field, operation: 'attach_metadata', reason: 'strict replay mutable-field check' })),
  ].map(({ decision, field, operation, owner }) => ({ decision, field, operation, owner }));
  const lineage = {
    frameId: bundle.frame.frameId,
    operatingMode: bundle.frame.operatingMode,
    protectedFields: [...bundle.frame.protectedFields],
    proofLimits: [...bundle.frame.proofLimitTemplate],
  };
  return {
    replayId: bundle.replayId,
    stableDigest: simpleDigest({ frame: bundle.frame, evidenceGraph: bundle.evidenceGraph, mutationLog: bundle.mutationLog, boundaryDecisions, lineage }),
    boundaryDecisions,
    lineage,
  };
}

export function saveReplayBundleFile(bundle: AetherFrameReplayBundle, path: string): AetherFrameReplaySaveResult {
  const validation = validateReplayBundle(bundle);
  const stableDigest = validation.valid ? replayStrict(bundle).stableDigest : '';
  if (!validation.valid) {
    return { ...validation, path, stableDigest, proofLimits: ['Replay bundle was not persisted because validation failed.'] };
  }
  mkdirSync(dirname(path), { recursive: true });
  const envelope: AetherFramePersistentReplayEnvelope = {
    schemaVersion: 'aetherframe.persisted_replay_bundle.v1',
    replayBundle: bundle,
    stableDigest,
    savedAt: new Date().toISOString(),
    proofLimits: [
      'Persisted replay bundle stores deterministic inputs and digest; it does not prove external-world truth.',
      'Generated save timestamp is excluded from replay digest semantics.',
    ],
  };
  writeFileSync(path, `${JSON.stringify(envelope, null, 2)}\n`, 'utf8');
  return { valid: true, errors: [], path, stableDigest, proofLimits: envelope.proofLimits };
}

export function loadPersistentReplayBundleFile(path: string): AetherFrameReplayLoadResult {
  const parsed = parseJsonFile(path);
  const envelope = isRecord(parsed) && parsed.schemaVersion === 'aetherframe.persisted_replay_bundle.v1'
    ? parsed as unknown as AetherFramePersistentReplayEnvelope
    : { replayBundle: parsed as AetherFrameReplayBundle, stableDigest: '' } as AetherFramePersistentReplayEnvelope;
  const validation = validateReplayBundle(envelope.replayBundle);
  const recomputedDigest = validation.valid ? replayStrict(envelope.replayBundle).stableDigest : '';
  const persistedDigest = envelope.stableDigest || recomputedDigest;
  const digestMatches = validation.valid && persistedDigest === recomputedDigest;
  return {
    ...validation,
    valid: validation.valid && digestMatches,
    errors: [...validation.errors, ...(validation.valid && !digestMatches ? ['persisted replay digest does not match recomputed digest'] : [])],
    value: envelope.replayBundle,
    persistedDigest,
    recomputedDigest,
    digestMatches,
    proofLimits: [
      'Load verification proves persisted replay digest stability after save/load, not external-world factual truth.',
      'Persistent replay storage is local-first JSON in this prototype.',
    ],
  };
}

export function readAuditLogFile(path: string): AetherFrameAuditLogEntry[] {
  if (!existsSync(path)) return [];
  const text = readFileSync(path, 'utf8').trim();
  if (!text) return [];
  return text.split('\n').map(line => JSON.parse(line) as AetherFrameAuditLogEntry);
}

type AuditLogEntryDigestMaterial = Omit<
  AetherFrameAuditLogEntry,
  'entryDigest' | 'entry_digest' | 'auditSignature' | 'audit_signature' | 'signatureAlgorithm'
>;

function digestAuditEntry(entry: AuditLogEntryDigestMaterial): string {
  return simpleDigest(entry);
}

function signAuditDigest(entryDigest: string, signingKey: string): string {
  return `hmac-sha256:${createHmac('sha256', signingKey).update(entryDigest).digest('hex')}`;
}

export function appendAuditLogEntry(path: string, input: AetherFrameAuditLogEntryInput): AetherFrameAuditLogEntry {
  mkdirSync(dirname(path), { recursive: true });
  const existing = readAuditLogFile(path);
  const sequence = existing.length + 1;
  const previousEntryDigest = existing.length > 0 ? existing[existing.length - 1].entryDigest : null;
  const { signingKey, ...persistedInput } = input;
  const entryWithoutDigest: AuditLogEntryDigestMaterial = {
    schemaVersion: 'aetherframe.audit_log_entry.v1',
    sequence,
    timestamp: new Date().toISOString(),
    previousEntryDigest,
    previous_entry_digest: previousEntryDigest,
    ...persistedInput,
    proofLimits: [
      ...input.proofLimits,
      'Append-only audit log prototype records local JSONL entries; it is not tamper-proof storage.',
      signingKey ? 'Audit entry includes an HMAC-SHA256 signature over entry_digest; key custody is outside this local prototype.' : 'Audit entry is hash-chained but unsigned because no signing key was provided.',
    ],
  };
  const entryDigest = digestAuditEntry(entryWithoutDigest);
  const signature = signingKey ? signAuditDigest(entryDigest, signingKey) : undefined;
  const entry: AetherFrameAuditLogEntry = {
    ...entryWithoutDigest,
    entryDigest,
    entry_digest: entryDigest,
    ...(signature ? { signatureAlgorithm: 'hmac-sha256' as const, auditSignature: signature, audit_signature: signature } : {}),
  };
  appendFileSync(path, `${JSON.stringify(entry)}\n`, 'utf8');
  return entry;
}

export function verifyAuditLogChain(path: string, signingKey?: string): AetherFrameAuditLogVerificationResult {
  const entries = readAuditLogFile(path);
  const errors: string[] = [];
  let previousDigest: string | null = null;
  entries.forEach((entry, index) => {
    const canonicalPreviousDigest = entry.previousEntryDigest ?? entry.previous_entry_digest ?? null;
    const canonicalEntryDigest = entry.entryDigest ?? entry.entry_digest;
    if (entry.sequence !== index + 1) errors.push(`entry ${index + 1} sequence mismatch`);
    if (canonicalPreviousDigest !== previousDigest) errors.push(`entry ${entry.sequence} previous_entry_digest mismatch`);
    if (entry.previousEntryDigest !== entry.previous_entry_digest) errors.push(`entry ${entry.sequence} previous_entry_digest alias mismatch`);
    if (entry.entryDigest !== entry.entry_digest) errors.push(`entry ${entry.sequence} entry_digest alias mismatch`);
    const {
      entryDigest: _entryDigest,
      entry_digest: _entry_digest,
      auditSignature: _auditSignature,
      audit_signature: _audit_signature,
      signatureAlgorithm: _signatureAlgorithm,
      ...entryWithoutDigest
    } = entry;
    const expectedDigest = digestAuditEntry(entryWithoutDigest);
    if (canonicalEntryDigest !== expectedDigest) errors.push(`entry ${entry.sequence} entry_digest mismatch`);
    if (entry.auditSignature !== entry.audit_signature) errors.push(`entry ${entry.sequence} audit_signature alias mismatch`);
    if (entry.auditSignature && !signingKey) errors.push(`entry ${entry.sequence} audit_signature present but no verification key was provided`);
    if (entry.auditSignature && signingKey && entry.auditSignature !== signAuditDigest(canonicalEntryDigest, signingKey)) {
      errors.push(`entry ${entry.sequence} audit_signature mismatch`);
    }
    previousDigest = canonicalEntryDigest;
  });
  return {
    valid: errors.length === 0,
    errors,
    entryCount: entries.length,
    proofLimits: [
      'Hash-chain verification detects local JSONL entry edits, deletion, reordering, and broken previous-entry links visible in the file.',
      signingKey ? 'HMAC signature verification proves entries match the provided local verification key, not external key custody or notarization.' : 'Unsigned verification checks hash-chain integrity only; signed entries require a verification key.',
      'This prototype does not provide external notarization, hardware-backed signing, or custody proof.',
    ],
  };
}

function replayStoreFileName(bundle: AetherFrameReplayBundle): string {
  const digest = replayStrict(bundle).stableDigest.replace(/[^a-zA-Z0-9_-]/g, '-');
  return `${bundle.replayId}.${digest}.replay.json`;
}

function listReplayBundleFiles(rootDir: string): string[] {
  if (!existsSync(rootDir)) return [];
  return readdirSync(rootDir)
    .filter(name => name.endsWith('.replay.json'))
    .sort()
    .map(name => join(rootDir, name));
}

function replayListItem(path: string): AetherFrameReplayBundleListItem | null {
  const loaded = loadPersistentReplayBundleFile(path);
  if (!loaded.valid) return null;
  const parsed = parseJsonFile(path) as Partial<AetherFramePersistentReplayEnvelope>;
  return {
    replayId: loaded.value.replayId,
    path,
    stableDigest: loaded.recomputedDigest,
    generatedAt: loaded.value.generatedAt,
    savedAt: typeof parsed.savedAt === 'string' ? parsed.savedAt : undefined,
  };
}

export function createReplayBundleStore(rootDir: string): AetherFrameReplayBundleStore {
  const listBundles = (): AetherFrameReplayBundleListItem[] => listReplayBundleFiles(rootDir)
    .map(replayListItem)
    .filter((item): item is AetherFrameReplayBundleListItem => item !== null);

  return {
    rootDir,
    save(bundle) {
      mkdirSync(rootDir, { recursive: true });
      return saveReplayBundleFile(bundle, join(rootDir, replayStoreFileName(bundle)));
    },
    listBundles,
    loadByReplayId(replayId) {
      const match = listBundles().filter(item => item.replayId === replayId).at(-1);
      if (!match) {
        return {
          valid: false,
          errors: [`replay bundle not found for replay id ${replayId}`],
          value: undefined as unknown as AetherFrameReplayBundle,
          persistedDigest: '',
          recomputedDigest: '',
          digestMatches: false,
          proofLimits: ['Replay bundle store lookup only searches local persisted replay JSON files.'],
          path: '',
        };
      }
      return { ...loadPersistentReplayBundleFile(match.path), path: match.path };
    },
    verifyDigest(path) {
      return loadPersistentReplayBundleFile(path);
    },
    compareVersions(firstPath, secondPath) {
      const first = loadPersistentReplayBundleFile(firstPath);
      const second = loadPersistentReplayBundleFile(secondPath);
      if (!first.valid || !second.valid) {
        return {
          driftDetected: true,
          priorDigest: first.recomputedDigest,
          currentDigest: second.recomputedDigest,
          changedSections: [],
          proofLimits: ['Version comparison is blocked or degraded because one or both replay bundles failed validation.'],
        };
      }
      return detectReplayDrift(first.value, second.value);
    },
    exportAuditSummary() {
      const bundles = listBundles();
      return {
        bundleCount: bundles.length,
        replayIds: Array.from(new Set(bundles.map(item => item.replayId))).sort(),
        bundles,
        proofLimits: [
          'Replay bundle store audit summary covers local persisted replay artifacts only and does not prove external-world truth.',
          'Digest checks prove deterministic AetherFrame replay input stability, not source authority truth.',
        ],
      };
    },
  };
}

function migrationKey(from: string, to: string): string {
  return `${from}->${to}`;
}

export function createMigrationRegistry(): AetherFrameMigrationRegistry {
  return { migrations: new Map<string, AetherFrameMigrationFunction>() };
}

export function registerMigration(
  registry: AetherFrameMigrationRegistry,
  from: string,
  to: string,
  fn: AetherFrameMigrationFunction,
): AetherFrameValidationResult {
  const errors: string[] = [];
  const fromKind = schemaKindForVersion(from);
  const toKind = schemaKindForVersion(to);
  if (!fromKind || !toKind || fromKind !== toKind) errors.push(`migration schema family mismatch from ${from} to ${to}`);
  if (registry.migrations.has(migrationKey(from, to))) errors.push(`migration already registered from ${from} to ${to}`);
  if (errors.length === 0) registry.migrations.set(migrationKey(from, to), fn);
  return { valid: errors.length === 0, errors };
}

export function dryRunMigration<T = unknown>(
  registry: AetherFrameMigrationRegistry,
  artifact: T,
  toSchemaVersion: string,
): AetherFrameDryRunMigrationResult<T> {
  const fromSchemaVersion = schemaVersionOf(artifact);
  const blockedDiagnostics: string[] = [];
  if (!fromSchemaVersion) blockedDiagnostics.push('artifact schemaVersion is required');
  const key = fromSchemaVersion ? migrationKey(fromSchemaVersion, toSchemaVersion) : '';
  const migration = key ? registry.migrations.get(key) : undefined;
  if (!migration) blockedDiagnostics.push(`no registered migration from ${fromSchemaVersion ?? '<missing>'} to ${toSchemaVersion}`);
  const targetNegotiation = negotiateSchemaVersion(toSchemaVersion, fromSchemaVersion ? schemaKindForVersion(fromSchemaVersion) ?? undefined : undefined);
  if (!targetNegotiation.valid) blockedDiagnostics.push(...targetNegotiation.errors);
  if (blockedDiagnostics.length > 0) {
    return {
      valid: false,
      errors: blockedDiagnostics,
      value: artifact,
      migrated: false,
      fromSchemaVersion,
      toSchemaVersion,
      dryRun: true,
      blockedDiagnostics,
      proofLimits: ['Migration dry-run was blocked; no artifact mutation was applied.'],
    };
  }
  return {
    valid: true,
    errors: [],
    value: artifact,
    migrated: fromSchemaVersion !== toSchemaVersion,
    fromSchemaVersion,
    toSchemaVersion,
    dryRun: true,
    blockedDiagnostics: [],
    proofLimits: ['AetherFrame migration dry-run validates registry availability only; it does not mutate the artifact.'],
  };
}

export function discoverAdapterManifests(rootDir: string): AetherFrameAdapterManifestDiscoveryResult {
  const paths = existsSync(rootDir)
    ? readdirSync(rootDir).filter(name => name.endsWith('.adapter.json')).sort().map(name => join(rootDir, name))
    : [];
  const manifests = paths.map(path => {
    try {
      const contract = parseJsonFile(path) as AetherFrameAdapterContract;
      const validation = validateAdapterContract(contract);
      return { path, contract: validation.valid ? contract : null, validation };
    } catch (error) {
      return { path, contract: null, validation: { valid: false, errors: [error instanceof Error ? error.message : String(error)] } };
    }
  });
  const diagnostics = manifests.flatMap(manifest => manifest.validation.errors.map(error => `${manifest.path}: ${error}`));
  const validManifests = manifests.filter(manifest => manifest.validation.valid).length;
  return {
    manifests,
    compatibilityReport: {
      validManifests,
      invalidManifests: manifests.length - validManifests,
      diagnostics,
      proofLimits: [
        'Adapter manifest discovery validates local adapter contract JSON only; it does not execute adapter code.',
        'Compatibility reports do not transfer domain authority to AetherFrame core.',
      ],
    },
  };
}

export function loadAdapterRegistryFromManifests(rootDir: string): AetherFrameAdapterRegistryLoadResult {
  const discovery = discoverAdapterManifests(rootDir);
  const registry = createAdapterRegistry();
  const errors = [...discovery.compatibilityReport.diagnostics];
  for (const manifest of discovery.manifests) {
    if (!manifest.contract) continue;
    const registered = registerAdapterContract(registry, manifest.contract);
    errors.push(...registered.errors.map(error => `${manifest.path}: ${error}`));
  }
  return {
    valid: errors.length === 0,
    errors,
    registry,
    compatibilityReport: { ...discovery.compatibilityReport, diagnostics: errors },
  };
}

export function makeReplayReport(bundle: AetherFrameReplayBundle): AetherFrameReplayReport {
  const replay = replayStrict(bundle);
  return {
    replayId: replay.replayId,
    stableDigest: replay.stableDigest,
    boundaryDecisions: replay.boundaryDecisions,
    blockedActions: replay.boundaryDecisions.filter(decision => decision.decision === 'blocked'),
    proofLimits: [
      ...replay.lineage.proofLimits,
      'Replay report is a non-UI JSON summary of deterministic AetherFrame replay artifacts only; it does not prove external-world truth.',
    ],
  };
}

export function detectReplayDrift(prior: AetherFrameReplayBundle, current: AetherFrameReplayBundle): AetherFrameDriftResult {
  const priorReplay = replayStrict(prior);
  const currentReplay = replayStrict(current);
  const changedSections: AetherFrameDriftResult['changedSections'] = [];
  if (simpleDigest(prior.frame) !== simpleDigest(current.frame)) changedSections.push('frame');
  if (simpleDigest(prior.evidenceGraph) !== simpleDigest(current.evidenceGraph)) changedSections.push('evidenceGraph');
  if (simpleDigest(prior.mutationLog) !== simpleDigest(current.mutationLog)) changedSections.push('mutationLog');
  if (simpleDigest(priorReplay.boundaryDecisions) !== simpleDigest(currentReplay.boundaryDecisions)) changedSections.push('boundaryDecisions');
  if (simpleDigest(priorReplay.lineage) !== simpleDigest(currentReplay.lineage)) changedSections.push('lineage');

  return {
    driftDetected: priorReplay.stableDigest !== currentReplay.stableDigest,
    priorDigest: priorReplay.stableDigest,
    currentDigest: currentReplay.stableDigest,
    changedSections,
    proofLimits: [
      'Drift detection ignores generated timestamp fields but treats frame, evidence, mutation, boundary, and lineage changes as replay-relevant.',
      'A matching digest proves deterministic AetherFrame replay inputs are stable, not that external-world facts are true.',
    ],
  };
}

export function explainReplay(bundle: AetherFrameReplayBundle): AetherFrameExplainReplayResult {
  const strict = replayStrict(bundle);
  return {
    mode: 'explain_replay',
    strict,
    commentary: [
      `Replay ${bundle.replayId} regenerated ${strict.boundaryDecisions.length} boundary decisions.`,
      `Frame ${bundle.frame.frameId} ran in ${bundle.frame.operatingMode} mode with ${bundle.frame.protectedFields.length} protected fields.`,
      'Strict replay is deterministic over frame, evidence graph, mutation log, boundary decisions, and lineage, but does not prove external-world truth.',
    ],
    proofLimits: [
      'Explain replay comments on deterministic replay artifacts only.',
      'Generated commentary must not be treated as an authoritative evidence source.',
    ],
  };
}

export function counterfactualReplay(
  bundle: AetherFrameReplayBundle,
  framePatch: Partial<AetherFrameFrame>,
): AetherFrameCounterfactualReplayResult {
  const counterfactualFrame: AetherFrameFrame = {
    ...bundle.frame,
    ...framePatch,
    authorityModel: framePatch.authorityModel ?? bundle.frame.authorityModel,
    confidencePolicy: framePatch.confidencePolicy ?? bundle.frame.confidencePolicy,
    uncertaintyPolicy: framePatch.uncertaintyPolicy ?? bundle.frame.uncertaintyPolicy,
    mutationPolicy: framePatch.mutationPolicy ?? bundle.frame.mutationPolicy,
    reviewPolicy: framePatch.reviewPolicy ?? bundle.frame.reviewPolicy,
    replayPolicy: framePatch.replayPolicy ?? bundle.frame.replayPolicy,
    exportPolicy: framePatch.exportPolicy ?? bundle.frame.exportPolicy,
  };
  const counterfactualBundle = { ...bundle, frame: counterfactualFrame };
  const drift = detectReplayDrift(bundle, counterfactualBundle);
  return {
    mode: 'counterfactual_replay',
    baseline: replayStrict(bundle),
    counterfactual: replayStrict(counterfactualBundle),
    counterfactualFrame,
    changedSections: drift.changedSections,
    proofLimits: [
      'This is a counterfactual policy replay; it does not rewrite the original replay bundle or transfer authority.',
      'Counterfactual results identify what would change under a different frame policy, not what is true in the external world.',
    ],
  };
}

export function createAdapterRegistry(): AetherFrameAdapterRegistry {
  return { contracts: new Map<string, AetherFrameAdapterContract>() };
}

export function registerAdapterContract(registry: AetherFrameAdapterRegistry, contract: AetherFrameAdapterContract): AetherFrameValidationResult {
  const validation = validateAdapterContract(contract);
  const errors = [...validation.errors];
  if (registry.contracts.has(contract.adapterKind)) {
    errors.push(`adapter contract already registered for ${contract.adapterKind}`);
  }
  if (errors.length === 0) registry.contracts.set(contract.adapterKind, contract);
  return { valid: errors.length === 0, errors };
}

function semverMajor(version: string): number | null {
  const match = version.match(/^(\d+)\./);
  return match ? Number(match[1]) : null;
}

export function validateAdapterFrameAgainstContract(registry: AetherFrameAdapterRegistry, frame: AetherFrameFrame): AetherFrameValidationResult {
  const errors: string[] = [];
  const contract = registry.contracts.get(frame.adapterKind);
  if (!contract) return { valid: false, errors: [`adapter contract not registered for ${frame.adapterKind}`] };

  const contractMajor = semverMajor(contract.adapterVersion);
  const frameMajor = semverMajor(frame.frameVersion);
  if (contractMajor === null || frameMajor === null || contractMajor !== frameMajor) {
    errors.push(`adapter frame version ${frame.frameVersion} is incompatible with contract version ${contract.adapterVersion}`);
  }

  const missingProtectedFields = contract.protectedFields.filter(field => !frame.protectedFields.includes(field));
  if (missingProtectedFields.length > 0) errors.push(`missing protected contract fields: ${missingProtectedFields.join(', ')}`);
  for (const field of contract.protectedFields) {
    if (frame.mutableFields.includes(field)) errors.push(`adapter frame must not list protected contract field ${field} as mutable`);
  }
  for (const field of contract.authorityModel.soleAuthorityFields) {
    if (!frame.authorityModel.soleAuthorityFields.includes(field)) errors.push(`adapter frame must preserve sole authority field ${field}`);
  }
  for (const field of contract.authorityModel.blockedFields) {
    if (!frame.authorityModel.blockedFields.includes(field)) errors.push(`adapter frame must preserve blocked field ${field}`);
  }
  if (frame.operatingMode === 'bounded_auto_mutation' && contract.protectedFields.length > 0) {
    errors.push('bounded_auto_mutation adapter frames require explicit additional high-assurance review before registration validation can pass');
  }
  return { valid: errors.length === 0, errors };
}

function cliUsage(): string {
  return [
    'Usage:',
    '  aetherframe validate-frame <frame-or-fixture.json>',
    '  aetherframe replay-strict <replay_bundle.json>',
    '  aetherframe replay-report <replay_bundle.json>',
    '  aetherframe save-replay-bundle <replay_bundle.json> <persisted_replay_bundle.json>',
    '  aetherframe detect-drift <replay_drift_fixture.json>',
    '  aetherframe detect-drift <prior_replay_bundle.json> <current_replay_bundle.json>',
    '  aetherframe review <frame-or-fixture.json> <evidence-graph-or-fixture.json>',
  ].join('\n') + '\n';
}

export function runAetherFrameCli(args: string[]): AetherFrameCliResult {
  const [command, first, second] = args;
  const usage = (): AetherFrameCliResult => ({ exitCode: 1, stdout: {}, stderr: cliUsage() });
  if (!command) return usage();

  try {
    if (command === 'validate-frame') {
      if (!first) return usage();
      const result = loadFrameFile(first);
      return { exitCode: result.valid ? 0 : 2, stderr: '', stdout: { command, valid: result.valid, errors: result.errors, schemaPath: result.schemaPath, frameId: result.value.frameId } };
    }

    if (command === 'replay-strict') {
      if (!first) return usage();
      const loaded = loadReplayBundleFile(first);
      if (!loaded.valid) return { exitCode: 2, stderr: '', stdout: { command, valid: false, errors: loaded.errors } };
      return { exitCode: 0, stderr: '', stdout: { command, valid: true, result: replayStrict(loaded.value) } };
    }

    if (command === 'replay-report') {
      if (!first) return usage();
      const loaded = loadReplayBundleFile(first);
      if (!loaded.valid) return { exitCode: 2, stderr: '', stdout: { command, valid: false, errors: loaded.errors } };
      return { exitCode: 0, stderr: '', stdout: { command, valid: true, report: makeReplayReport(loaded.value) } };
    }

    if (command === 'save-replay-bundle') {
      if (!first || !second) return usage();
      const loaded = loadReplayBundleFile(first);
      if (!loaded.valid) return { exitCode: 2, stderr: '', stdout: { command, valid: false, errors: loaded.errors } };
      const saved = saveReplayBundleFile(loaded.value, second);
      return { exitCode: saved.valid ? 0 : 2, stderr: '', stdout: { command, valid: saved.valid, errors: saved.errors, path: saved.path, stableDigest: saved.stableDigest, proofLimits: saved.proofLimits } };
    }

    if (command === 'detect-drift') {
      if (!first) return usage();
      let prior: AetherFrameReplayBundle;
      let current: AetherFrameReplayBundle;
      if (second) {
        const priorLoad = loadReplayBundleFile(first);
        const currentLoad = loadReplayBundleFile(second);
        if (!priorLoad.valid || !currentLoad.valid) return { exitCode: 2, stderr: '', stdout: { command, valid: false, errors: [...priorLoad.errors, ...currentLoad.errors] } };
        prior = priorLoad.value;
        current = currentLoad.value;
      } else {
        const fixture = parseJsonFile(first) as { prior?: AetherFrameReplayBundle; current?: AetherFrameReplayBundle };
        if (!fixture.prior || !fixture.current) throw new Error('single-file detect-drift input must contain prior and current replay bundles');
        prior = fixture.prior;
        current = fixture.current;
      }
      return { exitCode: 0, stderr: '', stdout: { command, valid: true, result: detectReplayDrift(prior, current) } };
    }

    if (command === 'review') {
      if (!first || !second) return usage();
      const frameLoad = loadFrameFile(first);
      const graphLoad = loadEvidenceGraphFile(second);
      if (!frameLoad.valid || !graphLoad.valid) return { exitCode: 2, stderr: '', stdout: { command, valid: false, errors: [...frameLoad.errors, ...graphLoad.errors] } };
      return { exitCode: 0, stderr: '', stdout: { command, valid: true, reviewItems: generateReviewQueue(frameLoad.value, graphLoad.value) } };
    }

    return usage();
  } catch (error) {
    return { exitCode: 2, stderr: '', stdout: { command, valid: false, errors: [error instanceof Error ? error.message : String(error)] } };
  }
}
