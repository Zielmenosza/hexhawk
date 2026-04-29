/**
 * NEST evidence-plane contracts.
 *
 * These types intentionally preserve the schema semantics documented in
 * docs/nest_evidence_schema_spec.md while staying practical for local Tauri
 * mode and future service/API import-export paths.
 */

export const NEST_EVIDENCE_SCHEMA_MAJOR = 1;
export const NEST_EVIDENCE_DEFAULT_SCHEMA_VERSION = '1.0.0';
export const NEST_EVIDENCE_BUNDLE_FORMAT_VERSION = '1.0.0';
export const NEST_EVIDENCE_REQUIRED_FILES = [
  'manifest.json',
  'binary_identity.json',
  'session.json',
  'iterations.json',
  'deltas.json',
  'final_verdict_snapshot.json',
  'audit_refs.json',
] as const;

export type RequiredNestEvidenceFileName = (typeof NEST_EVIDENCE_REQUIRED_FILES)[number];
export type OptionalNestEvidenceFileName = 'runtime_proof.json' | 'review_summary.md';
export type NestEvidenceFileName = RequiredNestEvidenceFileName | OptionalNestEvidenceFileName;

export const NEST_EVIDENCE_SCHEMA_NAMES = {
  manifest: 'nest.manifest',
  binaryIdentity: 'nest.binary_identity',
  session: 'nest.session',
  iterations: 'nest.iterations',
  deltas: 'nest.deltas',
  finalVerdictSnapshot: 'nest.final_verdict_snapshot',
  runtimeProof: 'nest.runtime_proof',
  auditRefs: 'nest.audit_refs',
} as const;

export type JsonValue = string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue };
export type JsonObject = { [key: string]: JsonValue };

export type ActorType = 'user' | 'reviewer' | 'approver' | 'service-account' | 'system';
export type ExportMode = 'local-tauri' | 'api' | 'service' | 'cli';
export type IdentitySource = 'local-path' | 'dropped-file' | 'imported-object' | 'api-upload' | 'corpus-entry';
export type FileBoundProofStatus = 'proven' | 'partial' | 'not-available';
export type SessionStatus = 'created' | 'running' | 'completed' | 'failed' | 'cancelled';
export type ExecutionMode = 'local-tauri' | 'cli' | 'api' | 'service';
export type RuntimeMode = 'tauri-runtime' | 'api-runtime' | 'service-runtime';
export type RuntimeProofStatus = 'proven' | 'partial' | 'failed';

export interface NestActor {
  id: string;
  type: ActorType;
  display_name?: string;
  tenant_id?: string;
  team_id?: string;
  auth_subject?: string;
}

export interface NestTimestamps {
  created_at: string;
  started_at?: string;
  completed_at?: string;
  exported_at?: string;
  reviewed_at?: string;
}

export interface NestEvidenceFileEntry {
  name: NestEvidenceFileName;
  required: boolean;
  sha256: string;
  bytes: number;
  schema_name: string;
  schema_version: string;
  content_type?: string;
  optional_reason?: string;
}

export interface NestImmutability {
  bundle_locked: boolean;
  locked_at: string;
  mutation_policy: string;
}

export interface NestReplayMetadata {
  replayable: boolean;
  mode_supported: string[];
  requires_binary_bytes: boolean;
}

export interface NestManifest {
  schema_name: typeof NEST_EVIDENCE_SCHEMA_NAMES.manifest;
  schema_version: string;
  bundle_schema_version: string;
  bundle_format_version: string;
  bundle_id: string;
  session_id: string;
  binary_id: string;
  binary_sha256: string;
  engine_build_id: string;
  policy_version: string;
  actor: NestActor;
  timestamps: NestTimestamps;
  files: NestEvidenceFileEntry[];
  immutability: NestImmutability;
  replay: NestReplayMetadata;
  derived_from_bundle_id?: string;
  export_mode?: ExportMode;
  notes?: string;
}

export interface BinaryHashes {
  sha256: string;
  sha1: string;
  md5: string;
}

export interface FileBoundProof {
  proof_status: FileBoundProofStatus;
  proof_basis: string[];
  binary_sha256: string;
  file_size_bytes: number;
  runtime_proof_present?: boolean;
  session_hash_lock?: boolean;
  validation_notes?: string[];
}

export interface NestBinaryIdentity {
  schema_name: typeof NEST_EVIDENCE_SCHEMA_NAMES.binaryIdentity;
  schema_version: string;
  bundle_id: string;
  session_id: string;
  binary_id: string;
  binary_sha256: string;
  hashes: BinaryHashes;
  file_size_bytes: number;
  format: string;
  architecture: string;
  first_seen_at: string;
  identity_source: IdentitySource;
  file_bound_proof: FileBoundProof;
  original_path?: string;
  normalized_path?: string;
  corpus_entry_id?: string;
  import_object_id?: string;
  file_name?: string;
  source_host?: string;
}

export interface NestSessionConfig {
  config_version: string;
  max_iterations: number;
  min_iterations: number;
  confidence_threshold: number;
  plateau_threshold: number;
  disasm_expansion: number;
  aggressiveness: string;
  enable_talon: boolean;
  enable_strike: boolean;
  enable_echo: boolean;
  auto_advance: boolean;
  auto_advance_delay_ms: number;
}

export interface NestSessionConvergence {
  has_converged: boolean;
  reason: string;
  confidence: number;
  classification_stable: boolean;
  signal_delta: number;
  contradiction_burden: number;
  stability_score: number;
  projected_loss?: number;
  confidence_variance?: number;
  diagnosis?: string;
}

export interface NestGyreLinkage {
  verdict_snapshot_id: string;
  gyre_schema_version: string;
  gyre_build_id: string;
  gyre_is_sole_verdict_source: true;
  nest_role: string;
  gyre_summary?: string;
  linked_reasoning_chain_hash?: string;
}

export interface NestSessionRecord {
  schema_name: typeof NEST_EVIDENCE_SCHEMA_NAMES.session;
  schema_version: string;
  bundle_id: string;
  session_id: string;
  binary_id: string;
  binary_sha256: string;
  engine_build_id: string;
  policy_version: string;
  actor: NestActor;
  timestamps: NestTimestamps;
  status: SessionStatus;
  execution_mode: ExecutionMode;
  config: NestSessionConfig;
  iteration_count: number;
  delta_count: number;
  final_iteration_index: number | null;
  convergence: NestSessionConvergence;
  gyre_linkage: NestGyreLinkage;
  error?: JsonObject;
  review_state?: JsonObject;
  notes?: string[];
  runtime_proof_required?: boolean;
}

export interface NestInputWindow {
  offset: number;
  length: number;
}

export interface NestExecutedAction {
  type: string;
  priority: string;
  reason: string;
  offset?: number;
  length?: number;
  signal?: string;
}

export interface NestIterationVerdictSnapshot {
  classification: string;
  confidence: number;
  threat_score: number;
  signal_count: number;
  contradiction_count: number;
  reasoning_chain_hash: string;
  summary?: string;
  behavior_tags?: string[];
  negative_signal_count?: number;
}

export interface NestIterationConvergenceSnapshot {
  reason: string;
  has_converged: boolean;
  stability_score: number;
  classification_stable: boolean;
  signal_delta: number;
  contradiction_burden: number;
}

export interface NestIterationItem {
  iteration_id: string;
  iteration_index: number;
  session_id: string;
  binary_sha256: string;
  started_at: string;
  completed_at: string;
  duration_ms: number;
  input_window: NestInputWindow;
  executed_actions: NestExecutedAction[];
  verdict_snapshot: NestIterationVerdictSnapshot;
  convergence_snapshot: NestIterationConvergenceSnapshot;
  file_identity_locked: boolean;
  annotations?: JsonValue[];
  warnings?: string[];
  tool_inputs?: JsonObject;
  runtime_context_ref?: string;
}

export interface NestIterationsFile {
  schema_name: typeof NEST_EVIDENCE_SCHEMA_NAMES.iterations;
  schema_version: string;
  bundle_id: string;
  session_id: string;
  binary_id: string;
  binary_sha256: string;
  count: number;
  items: NestIterationItem[];
}

export interface NestSignalDeltaSummary {
  added_count: number;
  removed_count: number;
  unchanged_count: number;
}

export interface NestRefinementExecution {
  action_types: string[];
  primary_action_type: string | null;
  executed: boolean;
  primary_action_reason?: string;
  target_offsets?: number[];
}

export interface NestDeltaItem {
  delta_id: string;
  from_iteration_id: string;
  to_iteration_id: string;
  from_iteration_index: number;
  to_iteration_index: number;
  binary_sha256: string;
  confidence_delta: number;
  classification_changed: boolean;
  signal_delta_summary: NestSignalDeltaSummary;
  contradiction_delta: number;
  refinement_execution: NestRefinementExecution;
  projected_gain: number;
  actual_gain: number;
  new_signal_ids?: string[];
  removed_signal_ids?: string[];
  new_behavior_tags?: string[];
  warnings?: string[];
  tool_runtime_inputs?: JsonObject;
}

export interface NestDeltasFile {
  schema_name: typeof NEST_EVIDENCE_SCHEMA_NAMES.deltas;
  schema_version: string;
  bundle_id: string;
  session_id: string;
  binary_id: string;
  binary_sha256: string;
  count: number;
  items: NestDeltaItem[];
}

export interface NestLinkage {
  session_id: string;
  final_iteration_id: string;
  nest_enrichment_applied: boolean;
  gyre_is_sole_verdict_source: true;
  nest_summary?: string;
  enriched_signal_ids?: string[];
}

export interface NestFinalVerdictSnapshot {
  schema_name: typeof NEST_EVIDENCE_SCHEMA_NAMES.finalVerdictSnapshot;
  schema_version: string;
  bundle_id: string;
  session_id: string;
  binary_id: string;
  binary_sha256: string;
  verdict_snapshot_id: string;
  source_engine: 'gyre';
  gyre_build_id: string;
  gyre_schema_version: string;
  classification: string;
  confidence: number;
  threat_score: number;
  summary: string;
  signal_count: number;
  contradiction_count: number;
  reasoning_chain_hash: string;
  linked_iteration_id: string;
  nest_linkage: NestLinkage;
  behaviors?: JsonValue[];
  negative_signals?: JsonValue[];
  amplifiers?: JsonValue[];
  dismissals?: JsonValue[];
  contradictions?: JsonValue[];
  alternatives?: JsonValue[];
  certainty_profile?: JsonObject;
}

export interface NestSourceFidelity {
  panel_fidelity_source: string;
  qa_subsystem_statuses: string[];
}

export interface NestRuntimeArtifactRef {
  path: string;
  artifact_type: string;
}

export interface NestRuntimeProof {
  schema_name: typeof NEST_EVIDENCE_SCHEMA_NAMES.runtimeProof;
  schema_version: string;
  bundle_id: string;
  session_id: string;
  binary_id: string;
  binary_sha256: string;
  runtime_mode: RuntimeMode;
  proof_status: RuntimeProofStatus;
  has_tauri_runtime: boolean;
  browser_mode: boolean;
  source_fidelity: NestSourceFidelity;
  linked_runtime_artifacts: NestRuntimeArtifactRef[];
  run_id?: string;
  page_url?: string;
  notes?: string[];
  nest_runtime_fields?: JsonObject;
}

export interface NestAuditEvent {
  event_id: string;
  event_type: string;
  timestamp: string;
  actor_id: string;
  actor_type: string;
  session_id: string;
  external_ref?: string;
  hash?: string;
  summary?: string;
}

export interface NestAuditRefs {
  schema_name: typeof NEST_EVIDENCE_SCHEMA_NAMES.auditRefs;
  schema_version: string;
  bundle_id: string;
  session_id: string;
  binary_id: string;
  binary_sha256: string;
  actor: NestActor;
  policy_version: string;
  audit_backend: string;
  events: NestAuditEvent[];
  log_stream_id?: string;
  tenant_id?: string;
  retention_policy_id?: string;
  integrity_proof?: JsonObject;
}

export interface NestEvidenceBundle {
  manifest: NestManifest;
  binary_identity: NestBinaryIdentity;
  session: NestSessionRecord;
  iterations: NestIterationsFile;
  deltas: NestDeltasFile;
  final_verdict_snapshot: NestFinalVerdictSnapshot;
  audit_refs: NestAuditRefs;
  runtime_proof?: NestRuntimeProof;
}

export interface NestValidationIssue {
  path: string;
  code:
    | 'missing-field'
    | 'invalid-type'
    | 'invalid-value'
    | 'invalid-schema-name'
    | 'unsupported-schema-version'
    | 'consistency-error'
    | 'replay-critical-error';
  message: string;
}

export type NestValidationResult<T> =
  | { ok: true; value: T }
  | { ok: false; issues: NestValidationIssue[] };

const BUNDLE_ID_RE = /^nestbundle_[0-9A-HJKMNP-TV-Z]{26}$/;
const SESSION_ID_RE = /^nestsession_[0-9A-HJKMNP-TV-Z]{26}$/;
const ITERATION_ID_RE = /^nestiter_[0-9A-HJKMNP-TV-Z]{26}_[0-9]{4}$/;
const DELTA_ID_RE = /^nestdelta_[0-9A-HJKMNP-TV-Z]{26}_[0-9]{4}_[0-9]{4}$/;
const VERDICT_SNAPSHOT_ID_RE = /^gyresnap_[0-9A-HJKMNP-TV-Z]{26}$/;
const SHA256_RE = /^[0-9a-f]{64}$/;
const SHA1_RE = /^[0-9a-f]{40}$/;
const MD5_RE = /^[0-9a-f]{32}$/;
const RFC3339_UTC_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/;
const SEMVER_RE = /^\d+\.\d+\.\d+$/;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function pushIssue(issues: NestValidationIssue[], path: string, code: NestValidationIssue['code'], message: string): void {
  issues.push({ path, code, message });
}

function requireFields(value: unknown, name: string, fields: string[], issues: NestValidationIssue[]): asserts value is Record<string, unknown> {
  if (!isRecord(value)) {
    pushIssue(issues, name, 'invalid-type', 'Expected object.');
    return;
  }
  for (const field of fields) {
    if (!(field in value) || value[field] === undefined || value[field] === null) {
      pushIssue(issues, `${name}.${field}`, 'missing-field', 'Required field is missing.');
    }
  }
}

function validateString(value: unknown, path: string, issues: NestValidationIssue[]): value is string {
  if (typeof value !== 'string' || value.length === 0) {
    pushIssue(issues, path, 'invalid-type', 'Expected non-empty string.');
    return false;
  }
  return true;
}

function validateBoolean(value: unknown, path: string, issues: NestValidationIssue[]): value is boolean {
  if (typeof value !== 'boolean') {
    pushIssue(issues, path, 'invalid-type', 'Expected boolean.');
    return false;
  }
  return true;
}

function validateNumber(value: unknown, path: string, issues: NestValidationIssue[], integer = false): value is number {
  if (typeof value !== 'number' || Number.isNaN(value)) {
    pushIssue(issues, path, 'invalid-type', 'Expected number.');
    return false;
  }
  if (integer && !Number.isInteger(value)) {
    pushIssue(issues, path, 'invalid-type', 'Expected integer.');
    return false;
  }
  return true;
}

function validateArray(value: unknown, path: string, issues: NestValidationIssue[]): value is unknown[] {
  if (!Array.isArray(value)) {
    pushIssue(issues, path, 'invalid-type', 'Expected array.');
    return false;
  }
  return true;
}

function validatePattern(value: unknown, path: string, pattern: RegExp, label: string, issues: NestValidationIssue[]): void {
  if (!validateString(value, path, issues)) {
    return;
  }
  if (!pattern.test(value)) {
    pushIssue(issues, path, 'invalid-value', `Expected ${label}.`);
  }
}

function validateRfc3339Utc(value: unknown, path: string, issues: NestValidationIssue[]): void {
  validatePattern(value, path, RFC3339_UTC_RE, 'RFC3339 UTC timestamp', issues);
}

function validateSemver(value: unknown, path: string, issues: NestValidationIssue[]): void {
  if (!validateString(value, path, issues)) {
    return;
  }
  if (!SEMVER_RE.test(value)) {
    pushIssue(issues, path, 'invalid-value', 'Expected semantic version x.y.z.');
  }
}

function validateSchemaEnvelope(
  value: Record<string, unknown>,
  expectedSchemaName: string,
  path: string,
  issues: NestValidationIssue[],
): void {
  requireFields(value, path, ['schema_name', 'schema_version'], issues);
  if (value.schema_name !== expectedSchemaName) {
    pushIssue(issues, `${path}.schema_name`, 'invalid-schema-name', `Expected ${expectedSchemaName}.`);
  }
  validateSupportedSchemaVersion(value.schema_version, `${path}.schema_version`, issues);
}

export function validateSupportedSchemaVersion(value: unknown, path: string, issues: NestValidationIssue[]): void {
  if (!validateString(value, path, issues)) {
    return;
  }
  if (!SEMVER_RE.test(value)) {
    pushIssue(issues, path, 'invalid-value', 'Expected semantic version x.y.z.');
    return;
  }
  const major = Number(value.split('.')[0]);
  if (major !== NEST_EVIDENCE_SCHEMA_MAJOR) {
    pushIssue(issues, path, 'unsupported-schema-version', `Unsupported schema major ${major}; expected ${NEST_EVIDENCE_SCHEMA_MAJOR}.`);
  }
}

function validateActor(actor: unknown, path: string, issues: NestValidationIssue[]): void {
  requireFields(actor, path, ['id', 'type'], issues);
  if (!isRecord(actor)) {
    return;
  }
  validateString(actor.id, `${path}.id`, issues);
  if (!validateString(actor.type, `${path}.type`, issues)) {
    return;
  }
  if (!['user', 'reviewer', 'approver', 'service-account', 'system'].includes(actor.type)) {
    pushIssue(issues, `${path}.type`, 'invalid-value', 'Invalid actor type.');
  }
}

function validateTimestamps(timestamps: unknown, path: string, issues: NestValidationIssue[]): void {
  requireFields(timestamps, path, ['created_at'], issues);
  if (!isRecord(timestamps)) {
    return;
  }
  validateRfc3339Utc(timestamps.created_at, `${path}.created_at`, issues);
  for (const key of ['started_at', 'completed_at', 'exported_at', 'reviewed_at'] as const) {
    if (key in timestamps && timestamps[key] !== undefined) {
      validateRfc3339Utc(timestamps[key], `${path}.${key}`, issues);
    }
  }
}

function validateCommonIdentityFields(value: Record<string, unknown>, path: string, issues: NestValidationIssue[]): void {
  validatePattern(value.bundle_id, `${path}.bundle_id`, BUNDLE_ID_RE, 'bundle id', issues);
  validatePattern(value.session_id, `${path}.session_id`, SESSION_ID_RE, 'session id', issues);
  validatePattern(value.binary_id, `${path}.binary_id`, /^binary_sha256_[0-9a-f]{64}$/, 'binary id', issues);
  validatePattern(value.binary_sha256, `${path}.binary_sha256`, SHA256_RE, 'lowercase sha256', issues);
}

export function validateNestManifest(manifest: NestManifest): NestValidationIssue[] {
  const issues: NestValidationIssue[] = [];
  requireFields(manifest, 'manifest', [
    'schema_name',
    'schema_version',
    'bundle_schema_version',
    'bundle_format_version',
    'bundle_id',
    'session_id',
    'binary_id',
    'binary_sha256',
    'engine_build_id',
    'policy_version',
    'actor',
    'timestamps',
    'files',
    'immutability',
    'replay',
  ], issues);
  if (!isRecord(manifest)) {
    return issues;
  }
  validateSchemaEnvelope(manifest, NEST_EVIDENCE_SCHEMA_NAMES.manifest, 'manifest', issues);
  validateSemver(manifest.bundle_schema_version, 'manifest.bundle_schema_version', issues);
  validateSemver(manifest.bundle_format_version, 'manifest.bundle_format_version', issues);
  validateCommonIdentityFields(manifest, 'manifest', issues);
  validateString(manifest.engine_build_id, 'manifest.engine_build_id', issues);
  validateString(manifest.policy_version, 'manifest.policy_version', issues);
  validateActor(manifest.actor, 'manifest.actor', issues);
  validateTimestamps(manifest.timestamps, 'manifest.timestamps', issues);

  if (validateArray(manifest.files, 'manifest.files', issues)) {
    const seen = new Set<string>();
    for (const [index, file] of manifest.files.entries()) {
      requireFields(file, `manifest.files[${index}]`, ['name', 'required', 'sha256', 'bytes', 'schema_name', 'schema_version'], issues);
      if (!isRecord(file)) {
        continue;
      }
      validateString(file.name, `manifest.files[${index}].name`, issues);
      validateBoolean(file.required, `manifest.files[${index}].required`, issues);
      validatePattern(file.sha256, `manifest.files[${index}].sha256`, SHA256_RE, 'lowercase sha256', issues);
      validateNumber(file.bytes, `manifest.files[${index}].bytes`, issues, true);
      validateString(file.schema_name, `manifest.files[${index}].schema_name`, issues);
      validateSupportedSchemaVersion(file.schema_version, `manifest.files[${index}].schema_version`, issues);
      if (typeof file.name === 'string') {
        seen.add(file.name);
      }
    }
    for (const requiredFile of NEST_EVIDENCE_REQUIRED_FILES) {
      if (!seen.has(requiredFile)) {
        pushIssue(issues, 'manifest.files', 'missing-field', `Missing required bundle file ${requiredFile}.`);
      }
    }
  }

  requireFields(manifest.immutability, 'manifest.immutability', ['bundle_locked', 'locked_at', 'mutation_policy'], issues);
  if (isRecord(manifest.immutability)) {
    validateBoolean(manifest.immutability.bundle_locked, 'manifest.immutability.bundle_locked', issues);
    validateRfc3339Utc(manifest.immutability.locked_at, 'manifest.immutability.locked_at', issues);
    validateString(manifest.immutability.mutation_policy, 'manifest.immutability.mutation_policy', issues);
  }

  requireFields(manifest.replay, 'manifest.replay', ['replayable', 'mode_supported', 'requires_binary_bytes'], issues);
  if (isRecord(manifest.replay)) {
    validateBoolean(manifest.replay.replayable, 'manifest.replay.replayable', issues);
    validateArray(manifest.replay.mode_supported, 'manifest.replay.mode_supported', issues);
    validateBoolean(manifest.replay.requires_binary_bytes, 'manifest.replay.requires_binary_bytes', issues);
  }

  return issues;
}

export function validateNestBinaryIdentity(binaryIdentity: NestBinaryIdentity): NestValidationIssue[] {
  const issues: NestValidationIssue[] = [];
  requireFields(binaryIdentity, 'binary_identity', [
    'schema_name', 'schema_version', 'bundle_id', 'session_id', 'binary_id', 'binary_sha256',
    'hashes', 'file_size_bytes', 'format', 'architecture', 'first_seen_at', 'identity_source', 'file_bound_proof',
  ], issues);
  if (!isRecord(binaryIdentity)) {
    return issues;
  }
  validateSchemaEnvelope(binaryIdentity, NEST_EVIDENCE_SCHEMA_NAMES.binaryIdentity, 'binary_identity', issues);
  validateCommonIdentityFields(binaryIdentity, 'binary_identity', issues);
  validateNumber(binaryIdentity.file_size_bytes, 'binary_identity.file_size_bytes', issues, true);
  validateString(binaryIdentity.format, 'binary_identity.format', issues);
  validateString(binaryIdentity.architecture, 'binary_identity.architecture', issues);
  validateRfc3339Utc(binaryIdentity.first_seen_at, 'binary_identity.first_seen_at', issues);
  if (!validateString(binaryIdentity.identity_source, 'binary_identity.identity_source', issues) ||
      !['local-path', 'dropped-file', 'imported-object', 'api-upload', 'corpus-entry'].includes(binaryIdentity.identity_source)) {
    pushIssue(issues, 'binary_identity.identity_source', 'invalid-value', 'Invalid identity source.');
  }

  requireFields(binaryIdentity.hashes, 'binary_identity.hashes', ['sha256', 'sha1', 'md5'], issues);
  if (isRecord(binaryIdentity.hashes)) {
    validatePattern(binaryIdentity.hashes.sha256, 'binary_identity.hashes.sha256', SHA256_RE, 'lowercase sha256', issues);
    validatePattern(binaryIdentity.hashes.sha1, 'binary_identity.hashes.sha1', SHA1_RE, 'lowercase sha1', issues);
    validatePattern(binaryIdentity.hashes.md5, 'binary_identity.hashes.md5', MD5_RE, 'lowercase md5', issues);
    if (binaryIdentity.hashes.sha256 !== binaryIdentity.binary_sha256) {
      pushIssue(issues, 'binary_identity.hashes.sha256', 'consistency-error', 'hashes.sha256 must match binary_sha256.');
    }
  }

  requireFields(binaryIdentity.file_bound_proof, 'binary_identity.file_bound_proof', ['proof_status', 'proof_basis', 'binary_sha256', 'file_size_bytes'], issues);
  if (isRecord(binaryIdentity.file_bound_proof)) {
    if (!validateString(binaryIdentity.file_bound_proof.proof_status, 'binary_identity.file_bound_proof.proof_status', issues) ||
        !['proven', 'partial', 'not-available'].includes(binaryIdentity.file_bound_proof.proof_status)) {
      pushIssue(issues, 'binary_identity.file_bound_proof.proof_status', 'invalid-value', 'Invalid file-bound proof status.');
    }
    validateArray(binaryIdentity.file_bound_proof.proof_basis, 'binary_identity.file_bound_proof.proof_basis', issues);
    validatePattern(binaryIdentity.file_bound_proof.binary_sha256, 'binary_identity.file_bound_proof.binary_sha256', SHA256_RE, 'lowercase sha256', issues);
    validateNumber(binaryIdentity.file_bound_proof.file_size_bytes, 'binary_identity.file_bound_proof.file_size_bytes', issues, true);
    if (binaryIdentity.file_bound_proof.binary_sha256 !== binaryIdentity.binary_sha256) {
      pushIssue(issues, 'binary_identity.file_bound_proof.binary_sha256', 'replay-critical-error', 'file_bound_proof.binary_sha256 must match binary_sha256.');
    }
    if (binaryIdentity.file_bound_proof.file_size_bytes !== binaryIdentity.file_size_bytes) {
      pushIssue(issues, 'binary_identity.file_bound_proof.file_size_bytes', 'replay-critical-error', 'file_bound_proof.file_size_bytes must match file_size_bytes.');
    }
  }

  return issues;
}

export function validateNestSessionRecord(session: NestSessionRecord): NestValidationIssue[] {
  const issues: NestValidationIssue[] = [];
  requireFields(session, 'session', [
    'schema_name', 'schema_version', 'bundle_id', 'session_id', 'binary_id', 'binary_sha256', 'engine_build_id',
    'policy_version', 'actor', 'timestamps', 'status', 'execution_mode', 'config', 'iteration_count', 'delta_count',
    'final_iteration_index', 'convergence', 'gyre_linkage',
  ], issues);
  if (!isRecord(session)) {
    return issues;
  }
  validateSchemaEnvelope(session, NEST_EVIDENCE_SCHEMA_NAMES.session, 'session', issues);
  validateCommonIdentityFields(session, 'session', issues);
  validateString(session.engine_build_id, 'session.engine_build_id', issues);
  validateString(session.policy_version, 'session.policy_version', issues);
  validateActor(session.actor, 'session.actor', issues);
  validateTimestamps(session.timestamps, 'session.timestamps', issues);
  validateString(session.status, 'session.status', issues);
  validateString(session.execution_mode, 'session.execution_mode', issues);
  validateNumber(session.iteration_count, 'session.iteration_count', issues, true);
  validateNumber(session.delta_count, 'session.delta_count', issues, true);
  if (session.final_iteration_index !== null) {
    validateNumber(session.final_iteration_index, 'session.final_iteration_index', issues, true);
  }

  requireFields(session.config, 'session.config', [
    'config_version', 'max_iterations', 'min_iterations', 'confidence_threshold', 'plateau_threshold', 'disasm_expansion',
    'aggressiveness', 'enable_talon', 'enable_strike', 'enable_echo', 'auto_advance', 'auto_advance_delay_ms',
  ], issues);
  if (isRecord(session.config)) {
    validateString(session.config.config_version, 'session.config.config_version', issues);
    for (const intField of ['max_iterations', 'min_iterations', 'disasm_expansion', 'auto_advance_delay_ms'] as const) {
      validateNumber(session.config[intField], `session.config.${intField}`, issues, true);
    }
    for (const numberField of ['confidence_threshold', 'plateau_threshold'] as const) {
      validateNumber(session.config[numberField], `session.config.${numberField}`, issues);
    }
    for (const boolField of ['enable_talon', 'enable_strike', 'enable_echo', 'auto_advance'] as const) {
      validateBoolean(session.config[boolField], `session.config.${boolField}`, issues);
    }
    validateString(session.config.aggressiveness, 'session.config.aggressiveness', issues);
  }

  requireFields(session.convergence, 'session.convergence', [
    'has_converged', 'reason', 'confidence', 'classification_stable', 'signal_delta', 'contradiction_burden', 'stability_score',
  ], issues);
  if (isRecord(session.convergence)) {
    validateBoolean(session.convergence.has_converged, 'session.convergence.has_converged', issues);
    validateString(session.convergence.reason, 'session.convergence.reason', issues);
    validateNumber(session.convergence.confidence, 'session.convergence.confidence', issues);
    validateBoolean(session.convergence.classification_stable, 'session.convergence.classification_stable', issues);
    validateNumber(session.convergence.signal_delta, 'session.convergence.signal_delta', issues, true);
    validateNumber(session.convergence.contradiction_burden, 'session.convergence.contradiction_burden', issues, true);
    validateNumber(session.convergence.stability_score, 'session.convergence.stability_score', issues);
  }

  requireFields(session.gyre_linkage, 'session.gyre_linkage', [
    'verdict_snapshot_id', 'gyre_schema_version', 'gyre_build_id', 'gyre_is_sole_verdict_source', 'nest_role',
  ], issues);
  if (isRecord(session.gyre_linkage)) {
    validatePattern(session.gyre_linkage.verdict_snapshot_id, 'session.gyre_linkage.verdict_snapshot_id', VERDICT_SNAPSHOT_ID_RE, 'GYRE snapshot id', issues);
    validateSemver(session.gyre_linkage.gyre_schema_version, 'session.gyre_linkage.gyre_schema_version', issues);
    validateString(session.gyre_linkage.gyre_build_id, 'session.gyre_linkage.gyre_build_id', issues);
    validateBoolean(session.gyre_linkage.gyre_is_sole_verdict_source, 'session.gyre_linkage.gyre_is_sole_verdict_source', issues);
    if (session.gyre_linkage.gyre_is_sole_verdict_source !== true) {
      pushIssue(issues, 'session.gyre_linkage.gyre_is_sole_verdict_source', 'replay-critical-error', 'GYRE must remain the sole verdict source.');
    }
    if (validateString(session.gyre_linkage.nest_role, 'session.gyre_linkage.nest_role', issues) && !session.gyre_linkage.nest_role.toLowerCase().includes('enrich')) {
      pushIssue(issues, 'session.gyre_linkage.nest_role', 'invalid-value', 'nest_role must describe enrichment only.');
    }
  }

  return issues;
}

export function validateNestIterationsFile(iterations: NestIterationsFile): NestValidationIssue[] {
  const issues: NestValidationIssue[] = [];
  requireFields(iterations, 'iterations', ['schema_name', 'schema_version', 'bundle_id', 'session_id', 'binary_id', 'binary_sha256', 'count', 'items'], issues);
  if (!isRecord(iterations)) {
    return issues;
  }
  validateSchemaEnvelope(iterations, NEST_EVIDENCE_SCHEMA_NAMES.iterations, 'iterations', issues);
  validateCommonIdentityFields(iterations, 'iterations', issues);
  validateNumber(iterations.count, 'iterations.count', issues, true);
  if (validateArray(iterations.items, 'iterations.items', issues)) {
    const seenIds = new Set<string>();
    for (const [index, item] of iterations.items.entries()) {
      requireFields(item, `iterations.items[${index}]`, [
        'iteration_id', 'iteration_index', 'session_id', 'binary_sha256', 'started_at', 'completed_at', 'duration_ms',
        'input_window', 'executed_actions', 'verdict_snapshot', 'convergence_snapshot', 'file_identity_locked',
      ], issues);
      if (!isRecord(item)) {
        continue;
      }
      validatePattern(item.iteration_id, `iterations.items[${index}].iteration_id`, ITERATION_ID_RE, 'iteration id', issues);
      validateNumber(item.iteration_index, `iterations.items[${index}].iteration_index`, issues, true);
      validatePattern(item.session_id, `iterations.items[${index}].session_id`, SESSION_ID_RE, 'session id', issues);
      validatePattern(item.binary_sha256, `iterations.items[${index}].binary_sha256`, SHA256_RE, 'lowercase sha256', issues);
      validateRfc3339Utc(item.started_at, `iterations.items[${index}].started_at`, issues);
      validateRfc3339Utc(item.completed_at, `iterations.items[${index}].completed_at`, issues);
      validateNumber(item.duration_ms, `iterations.items[${index}].duration_ms`, issues, true);
      validateBoolean(item.file_identity_locked, `iterations.items[${index}].file_identity_locked`, issues);
      if (typeof item.iteration_id === 'string') {
        if (seenIds.has(item.iteration_id)) {
          pushIssue(issues, `iterations.items[${index}].iteration_id`, 'consistency-error', 'iteration_id must be unique.');
        }
        seenIds.add(item.iteration_id);
      }
    }
    if (iterations.items.length !== iterations.count) {
      pushIssue(issues, 'iterations.count', 'consistency-error', 'count must match items length.');
    }
  }
  return issues;
}

export function validateNestDeltasFile(deltas: NestDeltasFile): NestValidationIssue[] {
  const issues: NestValidationIssue[] = [];
  requireFields(deltas, 'deltas', ['schema_name', 'schema_version', 'bundle_id', 'session_id', 'binary_id', 'binary_sha256', 'count', 'items'], issues);
  if (!isRecord(deltas)) {
    return issues;
  }
  validateSchemaEnvelope(deltas, NEST_EVIDENCE_SCHEMA_NAMES.deltas, 'deltas', issues);
  validateCommonIdentityFields(deltas, 'deltas', issues);
  validateNumber(deltas.count, 'deltas.count', issues, true);
  if (validateArray(deltas.items, 'deltas.items', issues)) {
    const seenIds = new Set<string>();
    for (const [index, item] of deltas.items.entries()) {
      requireFields(item, `deltas.items[${index}]`, [
        'delta_id', 'from_iteration_id', 'to_iteration_id', 'from_iteration_index', 'to_iteration_index', 'binary_sha256', 'confidence_delta',
        'classification_changed', 'signal_delta_summary', 'contradiction_delta', 'refinement_execution', 'projected_gain', 'actual_gain',
      ], issues);
      if (!isRecord(item)) {
        continue;
      }
      validatePattern(item.delta_id, `deltas.items[${index}].delta_id`, DELTA_ID_RE, 'delta id', issues);
      validatePattern(item.from_iteration_id, `deltas.items[${index}].from_iteration_id`, ITERATION_ID_RE, 'iteration id', issues);
      validatePattern(item.to_iteration_id, `deltas.items[${index}].to_iteration_id`, ITERATION_ID_RE, 'iteration id', issues);
      validateNumber(item.from_iteration_index, `deltas.items[${index}].from_iteration_index`, issues, true);
      validateNumber(item.to_iteration_index, `deltas.items[${index}].to_iteration_index`, issues, true);
      validatePattern(item.binary_sha256, `deltas.items[${index}].binary_sha256`, SHA256_RE, 'lowercase sha256', issues);
      validateNumber(item.confidence_delta, `deltas.items[${index}].confidence_delta`, issues);
      validateBoolean(item.classification_changed, `deltas.items[${index}].classification_changed`, issues);
      validateNumber(item.contradiction_delta, `deltas.items[${index}].contradiction_delta`, issues, true);
      validateNumber(item.projected_gain, `deltas.items[${index}].projected_gain`, issues);
      validateNumber(item.actual_gain, `deltas.items[${index}].actual_gain`, issues);
      if (typeof item.delta_id === 'string') {
        if (seenIds.has(item.delta_id)) {
          pushIssue(issues, `deltas.items[${index}].delta_id`, 'consistency-error', 'delta_id must be unique.');
        }
        seenIds.add(item.delta_id);
      }
      if (typeof item.from_iteration_index === 'number' && typeof item.to_iteration_index === 'number' &&
          item.from_iteration_index >= item.to_iteration_index) {
        pushIssue(issues, `deltas.items[${index}]`, 'invalid-value', 'Delta iteration indexes must move forward.');
      }
    }
    if (deltas.items.length !== deltas.count) {
      pushIssue(issues, 'deltas.count', 'consistency-error', 'count must match items length.');
    }
  }
  return issues;
}

export function validateNestFinalVerdictSnapshot(finalVerdict: NestFinalVerdictSnapshot): NestValidationIssue[] {
  const issues: NestValidationIssue[] = [];
  requireFields(finalVerdict, 'final_verdict_snapshot', [
    'schema_name', 'schema_version', 'bundle_id', 'session_id', 'binary_id', 'binary_sha256', 'verdict_snapshot_id',
    'source_engine', 'gyre_build_id', 'gyre_schema_version', 'classification', 'confidence', 'threat_score', 'summary',
    'signal_count', 'contradiction_count', 'reasoning_chain_hash', 'linked_iteration_id', 'nest_linkage',
  ], issues);
  if (!isRecord(finalVerdict)) {
    return issues;
  }
  validateSchemaEnvelope(finalVerdict, NEST_EVIDENCE_SCHEMA_NAMES.finalVerdictSnapshot, 'final_verdict_snapshot', issues);
  validateCommonIdentityFields(finalVerdict, 'final_verdict_snapshot', issues);
  validatePattern(finalVerdict.verdict_snapshot_id, 'final_verdict_snapshot.verdict_snapshot_id', VERDICT_SNAPSHOT_ID_RE, 'GYRE snapshot id', issues);
  if (finalVerdict.source_engine !== 'gyre') {
    pushIssue(issues, 'final_verdict_snapshot.source_engine', 'replay-critical-error', 'source_engine must be gyre.');
  }
  validateSemver(finalVerdict.gyre_schema_version, 'final_verdict_snapshot.gyre_schema_version', issues);
  validateString(finalVerdict.gyre_build_id, 'final_verdict_snapshot.gyre_build_id', issues);
  validateString(finalVerdict.classification, 'final_verdict_snapshot.classification', issues);
  validateNumber(finalVerdict.confidence, 'final_verdict_snapshot.confidence', issues);
  validateNumber(finalVerdict.threat_score, 'final_verdict_snapshot.threat_score', issues);
  validateString(finalVerdict.summary, 'final_verdict_snapshot.summary', issues);
  validateNumber(finalVerdict.signal_count, 'final_verdict_snapshot.signal_count', issues, true);
  validateNumber(finalVerdict.contradiction_count, 'final_verdict_snapshot.contradiction_count', issues, true);
  validatePattern(finalVerdict.linked_iteration_id, 'final_verdict_snapshot.linked_iteration_id', ITERATION_ID_RE, 'iteration id', issues);

  requireFields(finalVerdict.nest_linkage, 'final_verdict_snapshot.nest_linkage', ['session_id', 'final_iteration_id', 'nest_enrichment_applied', 'gyre_is_sole_verdict_source'], issues);
  if (isRecord(finalVerdict.nest_linkage)) {
    validatePattern(finalVerdict.nest_linkage.session_id, 'final_verdict_snapshot.nest_linkage.session_id', SESSION_ID_RE, 'session id', issues);
    validatePattern(finalVerdict.nest_linkage.final_iteration_id, 'final_verdict_snapshot.nest_linkage.final_iteration_id', ITERATION_ID_RE, 'iteration id', issues);
    validateBoolean(finalVerdict.nest_linkage.nest_enrichment_applied, 'final_verdict_snapshot.nest_linkage.nest_enrichment_applied', issues);
    validateBoolean(finalVerdict.nest_linkage.gyre_is_sole_verdict_source, 'final_verdict_snapshot.nest_linkage.gyre_is_sole_verdict_source', issues);
    if (finalVerdict.nest_linkage.gyre_is_sole_verdict_source !== true) {
      pushIssue(issues, 'final_verdict_snapshot.nest_linkage.gyre_is_sole_verdict_source', 'replay-critical-error', 'GYRE must remain the sole verdict source.');
    }
  }

  return issues;
}

export function validateNestRuntimeProof(runtimeProof: NestRuntimeProof): NestValidationIssue[] {
  const issues: NestValidationIssue[] = [];
  requireFields(runtimeProof, 'runtime_proof', [
    'schema_name', 'schema_version', 'bundle_id', 'session_id', 'binary_id', 'binary_sha256', 'runtime_mode', 'proof_status',
    'has_tauri_runtime', 'browser_mode', 'source_fidelity', 'linked_runtime_artifacts',
  ], issues);
  if (!isRecord(runtimeProof)) {
    return issues;
  }
  validateSchemaEnvelope(runtimeProof, NEST_EVIDENCE_SCHEMA_NAMES.runtimeProof, 'runtime_proof', issues);
  validateCommonIdentityFields(runtimeProof, 'runtime_proof', issues);
  validateString(runtimeProof.runtime_mode, 'runtime_proof.runtime_mode', issues);
  validateString(runtimeProof.proof_status, 'runtime_proof.proof_status', issues);
  validateBoolean(runtimeProof.has_tauri_runtime, 'runtime_proof.has_tauri_runtime', issues);
  validateBoolean(runtimeProof.browser_mode, 'runtime_proof.browser_mode', issues);
  requireFields(runtimeProof.source_fidelity, 'runtime_proof.source_fidelity', ['panel_fidelity_source', 'qa_subsystem_statuses'], issues);
  if (isRecord(runtimeProof.source_fidelity)) {
    validateString(runtimeProof.source_fidelity.panel_fidelity_source, 'runtime_proof.source_fidelity.panel_fidelity_source', issues);
    validateArray(runtimeProof.source_fidelity.qa_subsystem_statuses, 'runtime_proof.source_fidelity.qa_subsystem_statuses', issues);
  }
  if (validateArray(runtimeProof.linked_runtime_artifacts, 'runtime_proof.linked_runtime_artifacts', issues)) {
    for (const [index, artifact] of runtimeProof.linked_runtime_artifacts.entries()) {
      requireFields(artifact, `runtime_proof.linked_runtime_artifacts[${index}]`, ['path', 'artifact_type'], issues);
      if (!isRecord(artifact)) {
        continue;
      }
      validateString(artifact.path, `runtime_proof.linked_runtime_artifacts[${index}].path`, issues);
      validateString(artifact.artifact_type, `runtime_proof.linked_runtime_artifacts[${index}].artifact_type`, issues);
    }
  }
  return issues;
}

export function validateNestAuditRefs(auditRefs: NestAuditRefs): NestValidationIssue[] {
  const issues: NestValidationIssue[] = [];
  requireFields(auditRefs, 'audit_refs', [
    'schema_name', 'schema_version', 'bundle_id', 'session_id', 'binary_id', 'binary_sha256', 'actor', 'policy_version', 'audit_backend', 'events',
  ], issues);
  if (!isRecord(auditRefs)) {
    return issues;
  }
  validateSchemaEnvelope(auditRefs, NEST_EVIDENCE_SCHEMA_NAMES.auditRefs, 'audit_refs', issues);
  validateCommonIdentityFields(auditRefs, 'audit_refs', issues);
  validateActor(auditRefs.actor, 'audit_refs.actor', issues);
  validateString(auditRefs.policy_version, 'audit_refs.policy_version', issues);
  validateString(auditRefs.audit_backend, 'audit_refs.audit_backend', issues);
  if (validateArray(auditRefs.events, 'audit_refs.events', issues)) {
    for (const [index, event] of auditRefs.events.entries()) {
      requireFields(event, `audit_refs.events[${index}]`, ['event_id', 'event_type', 'timestamp', 'actor_id', 'actor_type', 'session_id'], issues);
      if (!isRecord(event)) {
        continue;
      }
      validateString(event.event_id, `audit_refs.events[${index}].event_id`, issues);
      validateString(event.event_type, `audit_refs.events[${index}].event_type`, issues);
      validateRfc3339Utc(event.timestamp, `audit_refs.events[${index}].timestamp`, issues);
      validateString(event.actor_id, `audit_refs.events[${index}].actor_id`, issues);
      validateString(event.actor_type, `audit_refs.events[${index}].actor_type`, issues);
      validatePattern(event.session_id, `audit_refs.events[${index}].session_id`, SESSION_ID_RE, 'session id', issues);
      if (event.hash !== undefined) {
        validatePattern(event.hash, `audit_refs.events[${index}].hash`, SHA256_RE, 'lowercase sha256', issues);
      }
    }
  }
  return issues;
}

export function validateNestEvidenceBundle(bundle: NestEvidenceBundle): NestValidationIssue[] {
  const issues = [
    ...validateNestManifest(bundle.manifest),
    ...validateNestBinaryIdentity(bundle.binary_identity),
    ...validateNestSessionRecord(bundle.session),
    ...validateNestIterationsFile(bundle.iterations),
    ...validateNestDeltasFile(bundle.deltas),
    ...validateNestFinalVerdictSnapshot(bundle.final_verdict_snapshot),
    ...validateNestAuditRefs(bundle.audit_refs),
    ...(bundle.runtime_proof ? validateNestRuntimeProof(bundle.runtime_proof) : []),
  ];

  const expectedBundleId = bundle.binary_identity.bundle_id;
  const expectedSessionId = bundle.binary_identity.session_id;
  const expectedBinaryId = bundle.binary_identity.binary_id;
  const expectedBinarySha256 = bundle.binary_identity.binary_sha256;

  const consistentFiles: Array<[string, { bundle_id: string; session_id: string; binary_id: string; binary_sha256: string }]> = [
    ['manifest', bundle.manifest],
    ['binary_identity', bundle.binary_identity],
    ['session', bundle.session],
    ['iterations', bundle.iterations],
    ['deltas', bundle.deltas],
    ['final_verdict_snapshot', bundle.final_verdict_snapshot],
    ['audit_refs', bundle.audit_refs],
  ];
  if (bundle.runtime_proof) {
    consistentFiles.push(['runtime_proof', bundle.runtime_proof]);
  }

  for (const [name, value] of consistentFiles) {
    if (value.bundle_id !== expectedBundleId) {
      pushIssue(issues, `${name}.bundle_id`, 'consistency-error', 'bundle_id must match binary_identity.bundle_id.');
    }
    if (value.session_id !== expectedSessionId) {
      pushIssue(issues, `${name}.session_id`, 'consistency-error', 'session_id must match binary_identity.session_id.');
    }
    if (value.binary_id !== expectedBinaryId) {
      pushIssue(issues, `${name}.binary_id`, 'consistency-error', 'binary_id must match binary_identity.binary_id.');
    }
    if (value.binary_sha256 !== expectedBinarySha256) {
      pushIssue(issues, `${name}.binary_sha256`, 'replay-critical-error', 'binary_sha256 must match binary_identity.binary_sha256.');
    }
  }

  if (bundle.session.gyre_linkage.verdict_snapshot_id !== bundle.final_verdict_snapshot.verdict_snapshot_id) {
    pushIssue(issues, 'session.gyre_linkage.verdict_snapshot_id', 'consistency-error', 'Session verdict snapshot id must match final verdict snapshot.');
  }
  if (bundle.final_verdict_snapshot.nest_linkage.session_id !== bundle.session.session_id) {
    pushIssue(issues, 'final_verdict_snapshot.nest_linkage.session_id', 'consistency-error', 'Final verdict linkage session_id must match session.session_id.');
  }
  if (bundle.final_verdict_snapshot.linked_iteration_id !== bundle.final_verdict_snapshot.nest_linkage.final_iteration_id) {
    pushIssue(issues, 'final_verdict_snapshot.linked_iteration_id', 'consistency-error', 'linked_iteration_id must match nest_linkage.final_iteration_id.');
  }
  if (bundle.session.runtime_proof_required && !bundle.runtime_proof) {
    pushIssue(issues, 'runtime_proof', 'missing-field', 'runtime_proof.json is required for this session.');
  }

  const iterationIds = new Set(bundle.iterations.items.map((item) => item.iteration_id));
  for (const [index, item] of bundle.iterations.items.entries()) {
    if (item.session_id !== expectedSessionId) {
      pushIssue(issues, `iterations.items[${index}].session_id`, 'consistency-error', 'Iteration session_id must match bundle session_id.');
    }
    if (item.binary_sha256 !== expectedBinarySha256) {
      pushIssue(issues, `iterations.items[${index}].binary_sha256`, 'replay-critical-error', 'Iteration binary_sha256 must match bundle binary_sha256.');
    }
  }

  for (const [index, item] of bundle.deltas.items.entries()) {
    if (item.binary_sha256 !== expectedBinarySha256) {
      pushIssue(issues, `deltas.items[${index}].binary_sha256`, 'replay-critical-error', 'Delta binary_sha256 must match bundle binary_sha256.');
    }
    if (!iterationIds.has(item.from_iteration_id)) {
      pushIssue(issues, `deltas.items[${index}].from_iteration_id`, 'consistency-error', 'Delta references missing from_iteration_id.');
    }
    if (!iterationIds.has(item.to_iteration_id)) {
      pushIssue(issues, `deltas.items[${index}].to_iteration_id`, 'consistency-error', 'Delta references missing to_iteration_id.');
    }
    if (item.from_iteration_index >= item.to_iteration_index) {
      pushIssue(issues, `deltas.items[${index}]`, 'invalid-value', 'Delta iteration indexes must move forward.');
    }
  }

  return issues;
}

function finishValidation<T>(value: T, issues: NestValidationIssue[]): NestValidationResult<T> {
  if (issues.length > 0) {
    return { ok: false, issues };
  }
  return { ok: true, value };
}

export function parseNestManifest(raw: unknown): NestValidationResult<NestManifest> {
  if (!isRecord(raw)) {
    return { ok: false, issues: [{ path: 'manifest', code: 'invalid-type', message: 'Expected object.' }] };
  }
  return finishValidation(raw as NestManifest, validateNestManifest(raw as NestManifest));
}

export function parseNestBinaryIdentity(raw: unknown): NestValidationResult<NestBinaryIdentity> {
  if (!isRecord(raw)) {
    return { ok: false, issues: [{ path: 'binary_identity', code: 'invalid-type', message: 'Expected object.' }] };
  }
  return finishValidation(raw as NestBinaryIdentity, validateNestBinaryIdentity(raw as NestBinaryIdentity));
}

export function parseNestSessionRecord(raw: unknown): NestValidationResult<NestSessionRecord> {
  if (!isRecord(raw)) {
    return { ok: false, issues: [{ path: 'session', code: 'invalid-type', message: 'Expected object.' }] };
  }
  return finishValidation(raw as NestSessionRecord, validateNestSessionRecord(raw as NestSessionRecord));
}

export function parseNestIterationsFile(raw: unknown): NestValidationResult<NestIterationsFile> {
  if (!isRecord(raw)) {
    return { ok: false, issues: [{ path: 'iterations', code: 'invalid-type', message: 'Expected object.' }] };
  }
  return finishValidation(raw as NestIterationsFile, validateNestIterationsFile(raw as NestIterationsFile));
}

export function parseNestDeltasFile(raw: unknown): NestValidationResult<NestDeltasFile> {
  if (!isRecord(raw)) {
    return { ok: false, issues: [{ path: 'deltas', code: 'invalid-type', message: 'Expected object.' }] };
  }
  return finishValidation(raw as NestDeltasFile, validateNestDeltasFile(raw as NestDeltasFile));
}

export function parseNestFinalVerdictSnapshot(raw: unknown): NestValidationResult<NestFinalVerdictSnapshot> {
  if (!isRecord(raw)) {
    return { ok: false, issues: [{ path: 'final_verdict_snapshot', code: 'invalid-type', message: 'Expected object.' }] };
  }
  return finishValidation(raw as NestFinalVerdictSnapshot, validateNestFinalVerdictSnapshot(raw as NestFinalVerdictSnapshot));
}

export function parseNestRuntimeProof(raw: unknown): NestValidationResult<NestRuntimeProof> {
  if (!isRecord(raw)) {
    return { ok: false, issues: [{ path: 'runtime_proof', code: 'invalid-type', message: 'Expected object.' }] };
  }
  return finishValidation(raw as NestRuntimeProof, validateNestRuntimeProof(raw as NestRuntimeProof));
}

export function parseNestAuditRefs(raw: unknown): NestValidationResult<NestAuditRefs> {
  if (!isRecord(raw)) {
    return { ok: false, issues: [{ path: 'audit_refs', code: 'invalid-type', message: 'Expected object.' }] };
  }
  return finishValidation(raw as NestAuditRefs, validateNestAuditRefs(raw as NestAuditRefs));
}
