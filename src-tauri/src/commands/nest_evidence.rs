// src-tauri/src/commands/nest_evidence.rs
//
// NEST Evidence Bundle — Rust DTO definitions and validation.
//
// These types mirror the TypeScript contracts in HexHawk/src/types/nestEvidence.ts.
// Serde round-trips must be lossless for all required fields.
//
// Validation is not performed by serde; call `validate_bundle` explicitly after
// deserialization.  `#[serde(deny_unknown_fields)]` is only applied on the 8 outer
// file structs and the bundle wrapper, so additive schema evolution (new optional
// fields) is forward-compatible for sub-objects.

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::collections::HashSet;

// ── Schema constants ──────────────────────────────────────────────────────────

pub const NEST_EVIDENCE_SCHEMA_MAJOR: u64 = 1;

// ── Enums ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ActorType {
    User,
    Reviewer,
    Approver,
    ServiceAccount,
    System,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExportMode {
    LocalTauri,
    BrowserExport,
    ApiExport,
    CorpusImport,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IdentitySource {
    LocalPath,
    DroppedFile,
    ImportedObject,
    ApiUpload,
    CorpusEntry,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SessionStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
    Paused,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExecutionMode {
    LocalTauri,
    ApiRun,
    CliRun,
    CorpusRun,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeMode {
    TauriRuntime,
    BrowserRuntime,
    CliRuntime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeProofStatus {
    Proven,
    Unproven,
    NotApplicable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FileBoundProofStatus {
    Proven,
    Partial,
    Unproven,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MutationPolicy {
    ImmutableAfterExport,
    MutableUnderReview,
}

// ── Validation types ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NestValidationCode {
    MissingField,
    InvalidType,
    InvalidValue,
    InvalidSchemaName,
    UnsupportedSchemaVersion,
    ConsistencyError,
    ReplayCriticalError,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NestValidationIssue {
    pub path:    String,
    pub code:    NestValidationCode,
    pub message: String,
}

impl NestValidationIssue {
    fn new(path: impl Into<String>, code: NestValidationCode, message: impl Into<String>) -> Self {
        Self { path: path.into(), code, message: message.into() }
    }
}

// ── Sub-structs ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NestActor {
    pub id:           String,
    #[serde(rename = "type")]
    pub actor_type:   ActorType,
    pub display_name: String,
    pub tenant_id:    Option<String>,
    pub team_id:      Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NestTimestamps {
    pub created_at:   String,
    pub started_at:   Option<String>,
    pub completed_at: Option<String>,
    pub exported_at:  Option<String>,
}

/// Gyre linkage block — present on `NestSessionRecord`.
/// GYRE invariant: `gyre_is_sole_verdict_source` MUST be `true`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NestGyreLinkage {
    pub verdict_snapshot_id:         String,
    pub gyre_schema_version:         String,
    pub gyre_build_id:               String,
    /// Must always be `true`; `false` is a replay-critical violation.
    pub gyre_is_sole_verdict_source: bool,
    pub nest_role:                   String,
}

/// Nest linkage block — present on `NestFinalVerdictSnapshot`.
/// GYRE invariant: `gyre_is_sole_verdict_source` MUST be `true`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NestFinalVerdictNestLinkage {
    pub session_id:                  String,
    pub final_iteration_id:          String,
    pub nest_enrichment_applied:     bool,
    /// Must always be `true`; `false` is a replay-critical violation.
    pub gyre_is_sole_verdict_source: bool,
    pub nest_summary:                Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NestBinaryHashes {
    pub sha256: String,
    pub sha1:   String,
    pub md5:    String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NestFileBoundProof {
    pub proof_status:         FileBoundProofStatus,
    pub proof_basis:          Vec<String>,
    pub binary_sha256:        String,
    pub file_size_bytes:      u64,
    pub session_hash_lock:    Option<bool>,
    pub runtime_proof_present: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NestManifestFile {
    pub name:           String,
    pub required:       bool,
    pub sha256:         String,
    pub bytes:          u64,
    pub schema_name:    String,
    pub schema_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NestImmutability {
    pub bundle_locked:   bool,
    pub locked_at:       Option<String>,
    pub mutation_policy: MutationPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NestReplayInfo {
    pub replayable:            bool,
    pub mode_supported:        Vec<String>,
    pub requires_binary_bytes: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NestConvergence {
    pub has_converged:         bool,
    pub reason:                String,
    pub confidence:            u32,
    pub classification_stable: bool,
    pub signal_delta:          i64,
    pub contradiction_burden:  i64,
    pub stability_score:       f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NestSessionConfig {
    pub config_version:       String,
    pub max_iterations:       u32,
    pub min_iterations:       u32,
    pub confidence_threshold: u32,
    pub plateau_threshold:    u32,
    pub disasm_expansion:     u32,
    pub aggressiveness:       String,
    pub enable_talon:         bool,
    pub enable_strike:        bool,
    pub enable_echo:          bool,
    pub auto_advance:         bool,
    pub auto_advance_delay_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NestInputWindow {
    pub offset: u64,
    pub length: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NestIterationVerdictSnapshot {
    pub classification:      String,
    pub confidence:          u32,
    pub threat_score:        u32,
    pub signal_count:        u64,
    pub contradiction_count: u64,
    pub reasoning_chain_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NestConvergenceSnapshot {
    pub has_converged:         bool,
    pub reason:                String,
    pub stability_score:       f64,
    pub classification_stable: bool,
    pub signal_delta:          i64,
    pub contradiction_burden:  i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NestIterationItem {
    pub iteration_id:          String,
    pub iteration_index:       u32,
    pub session_id:            String,
    pub binary_sha256:         String,
    pub started_at:            String,
    pub completed_at:          Option<String>,
    pub duration_ms:           Option<u64>,
    pub input_window:          Option<NestInputWindow>,
    pub executed_actions:      Option<Vec<JsonValue>>,
    pub verdict_snapshot:      NestIterationVerdictSnapshot,
    pub convergence_snapshot:  NestConvergenceSnapshot,
    pub file_identity_locked:  bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NestSignalDeltaSummary {
    pub added_count:     u64,
    pub removed_count:   u64,
    pub unchanged_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NestRefinementExecution {
    pub action_types:          Vec<String>,
    pub primary_action_type:   String,
    pub executed:              bool,
    pub primary_action_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NestDeltaItem {
    pub delta_id:               String,
    pub from_iteration_id:      String,
    pub to_iteration_id:        String,
    pub from_iteration_index:   u32,
    pub to_iteration_index:     u32,
    pub binary_sha256:          String,
    pub confidence_delta:       i64,
    pub classification_changed: bool,
    pub signal_delta_summary:   Option<NestSignalDeltaSummary>,
    pub contradiction_delta:    Option<i64>,
    pub refinement_execution:   Option<NestRefinementExecution>,
    pub projected_gain:         Option<i64>,
    pub actual_gain:            Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NestSourceFidelity {
    pub panel_fidelity_source: String,
    pub qa_subsystem_statuses: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NestRuntimeArtifact {
    pub path:          String,
    pub artifact_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NestAuditEvent {
    pub event_id:   String,
    pub event_type: String,
    pub timestamp:  String,
    pub actor_id:   String,
    pub actor_type: String,
    pub session_id: String,
    pub summary:    String,
    pub details:    Option<JsonValue>,
}

// ── Outer file structs ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NestManifest {
    pub schema_name:           String,
    pub schema_version:        String,
    pub bundle_schema_version: String,
    pub bundle_format_version: String,
    pub bundle_id:             String,
    pub session_id:            String,
    pub binary_id:             String,
    pub binary_sha256:         String,
    pub engine_build_id:       String,
    pub policy_version:        String,
    pub actor:                 NestActor,
    pub timestamps:            NestTimestamps,
    pub files:                 Vec<NestManifestFile>,
    pub immutability:          NestImmutability,
    pub replay:                NestReplayInfo,
    pub export_mode:           Option<ExportMode>,
    pub notes:                 Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NestBinaryIdentity {
    pub schema_name:      String,
    pub schema_version:   String,
    pub bundle_id:        String,
    pub session_id:       String,
    pub binary_id:        String,
    pub binary_sha256:    String,
    pub hashes:           NestBinaryHashes,
    pub file_size_bytes:  u64,
    pub format:           String,
    pub architecture:     String,
    pub first_seen_at:    String,
    pub identity_source:  IdentitySource,
    pub file_bound_proof: NestFileBoundProof,
    pub original_path:    Option<String>,
    pub file_name:        String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NestSessionRecord {
    pub schema_name:             String,
    pub schema_version:          String,
    pub bundle_id:               String,
    pub session_id:              String,
    pub binary_id:               String,
    pub binary_sha256:           String,
    pub engine_build_id:         String,
    pub policy_version:          String,
    pub actor:                   NestActor,
    pub timestamps:              NestTimestamps,
    pub status:                  SessionStatus,
    pub execution_mode:          ExecutionMode,
    pub config:                  NestSessionConfig,
    pub iteration_count:         u32,
    pub delta_count:             u32,
    pub final_iteration_index:   u32,
    pub convergence:             NestConvergence,
    pub gyre_linkage:            NestGyreLinkage,
    pub runtime_proof_required:  Option<bool>,
    pub notes:                   Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NestIterationsFile {
    pub schema_name:   String,
    pub schema_version: String,
    pub bundle_id:     String,
    pub session_id:    String,
    pub binary_id:     String,
    pub binary_sha256: String,
    pub count:         usize,
    pub items:         Vec<NestIterationItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NestDeltasFile {
    pub schema_name:   String,
    pub schema_version: String,
    pub bundle_id:     String,
    pub session_id:    String,
    pub binary_id:     String,
    pub binary_sha256: String,
    pub count:         usize,
    pub items:         Vec<NestDeltaItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NestFinalVerdictSnapshot {
    pub schema_name:          String,
    pub schema_version:       String,
    pub bundle_id:            String,
    pub session_id:           String,
    pub binary_id:            String,
    pub binary_sha256:        String,
    pub verdict_snapshot_id:  String,
    pub source_engine:        String,
    pub gyre_build_id:        String,
    pub gyre_schema_version:  String,
    pub classification:       String,
    pub confidence:           u32,
    pub threat_score:         u32,
    pub summary:              String,
    pub signal_count:         u64,
    pub contradiction_count:  u64,
    pub reasoning_chain_hash: String,
    pub linked_iteration_id:  String,
    pub nest_linkage:         NestFinalVerdictNestLinkage,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NestRuntimeProof {
    pub schema_name:              String,
    pub schema_version:           String,
    pub bundle_id:                String,
    pub session_id:               String,
    pub binary_id:                String,
    pub binary_sha256:            String,
    pub runtime_mode:             RuntimeMode,
    pub proof_status:             RuntimeProofStatus,
    pub has_tauri_runtime:        bool,
    pub browser_mode:             bool,
    pub source_fidelity:          Option<NestSourceFidelity>,
    pub linked_runtime_artifacts: Option<Vec<NestRuntimeArtifact>>,
    pub run_id:                   Option<String>,
    pub page_url:                 Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NestAuditRefs {
    pub schema_name:   String,
    pub schema_version: String,
    pub bundle_id:     String,
    pub session_id:    String,
    pub binary_id:     String,
    pub binary_sha256: String,
    pub actor:         NestActor,
    pub policy_version: String,
    pub audit_backend: String,
    pub events:        Vec<NestAuditEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NestEvidenceBundle {
    pub manifest:               NestManifest,
    pub binary_identity:        NestBinaryIdentity,
    pub session:                NestSessionRecord,
    pub iterations:             NestIterationsFile,
    pub deltas:                 NestDeltasFile,
    pub final_verdict_snapshot: NestFinalVerdictSnapshot,
    pub audit_refs:             NestAuditRefs,
    pub runtime_proof:          Option<NestRuntimeProof>,
}

// ── ID and hash validation helpers ────────────────────────────────────────────

/// Returns true if all characters are in the Crockford base-32 alphabet.
fn is_crockford(s: &str) -> bool {
    s.chars().all(|c| matches!(c,
        '0'..='9' | 'A'..='H' | 'J' | 'K' | 'M' | 'N' | 'P'..='T' | 'V'..='Z'
    ))
}

/// Returns true if all characters are lowercase hexadecimal.
fn is_lowercase_hex(s: &str) -> bool {
    s.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f'))
}

fn valid_ulid(s: &str) -> bool {
    s.len() == 26 && is_crockford(s)
}

fn valid_bundle_id(id: &str) -> bool {
    id.starts_with("nestbundle_") && valid_ulid(&id["nestbundle_".len()..])
}

fn valid_session_id(id: &str) -> bool {
    id.starts_with("nestsession_") && valid_ulid(&id["nestsession_".len()..])
}

fn valid_iteration_id(id: &str) -> bool {
    // nestiter_<26>_NNNN
    if !id.starts_with("nestiter_") { return false; }
    let rest = &id["nestiter_".len()..];
    if rest.len() != 26 + 1 + 4 { return false; }
    let (ulid, suffix) = rest.split_at(26);
    is_crockford(ulid) && suffix.starts_with('_') && suffix[1..].chars().all(|c| c.is_ascii_digit())
}

fn valid_delta_id(id: &str) -> bool {
    // nestdelta_<26>_NNNN_NNNN
    if !id.starts_with("nestdelta_") { return false; }
    let rest = &id["nestdelta_".len()..];
    if rest.len() != 26 + 1 + 4 + 1 + 4 { return false; }
    let (ulid, suffix) = rest.split_at(26);
    if !is_crockford(ulid) { return false; }
    let parts: Vec<&str> = suffix[1..].splitn(2, '_').collect();
    parts.len() == 2
        && parts[0].len() == 4 && parts[0].chars().all(|c| c.is_ascii_digit())
        && parts[1].len() == 4 && parts[1].chars().all(|c| c.is_ascii_digit())
}

fn valid_verdict_snapshot_id(id: &str) -> bool {
    id.starts_with("gyresnap_") && valid_ulid(&id["gyresnap_".len()..])
}

fn valid_binary_id(id: &str) -> bool {
    // binary_sha256_<64 lowercase hex>
    if !id.starts_with("binary_sha256_") { return false; }
    let hash = &id["binary_sha256_".len()..];
    hash.len() == 64 && is_lowercase_hex(hash)
}

fn valid_sha256(h: &str) -> bool { h.len() == 64 && is_lowercase_hex(h) }
fn valid_sha1(h: &str)   -> bool { h.len() == 40 && is_lowercase_hex(h) }
fn valid_md5(h: &str)    -> bool { h.len() == 32 && is_lowercase_hex(h) }

/// Very lightweight RFC3339 UTC check: ends with Z, has T at position 10, length ≥ 20.
fn valid_rfc3339_utc(s: &str) -> bool {
    s.len() >= 20 && s.ends_with('Z') && s.as_bytes().get(10) == Some(&b'T')
}

fn valid_semver_major(ver: &str, required_major: u64) -> bool {
    let parts: Vec<&str> = ver.splitn(3, '.').collect();
    if parts.len() != 3 { return false; }
    if let Ok(major) = parts[0].parse::<u64>() {
        return major == required_major;
    }
    false
}

// ── Bundle-level validation ───────────────────────────────────────────────────

/// Validates a deserialized `NestEvidenceBundle`.
///
/// Returns an empty `Vec` when the bundle is valid.
/// Issues are non-exhaustive — multiple violations may appear in one call.
pub fn validate_bundle(bundle: &NestEvidenceBundle) -> Vec<NestValidationIssue> {
    let mut issues: Vec<NestValidationIssue> = Vec::new();
    let add = |issues: &mut Vec<NestValidationIssue>, path: &str, code: NestValidationCode, msg: &str| {
        issues.push(NestValidationIssue::new(path, code, msg));
    };

    // Convenience aliases
    let m   = &bundle.manifest;
    let bi  = &bundle.binary_identity;
    let s   = &bundle.session;
    let it  = &bundle.iterations;
    let dl  = &bundle.deltas;
    let fv  = &bundle.final_verdict_snapshot;
    let ar  = &bundle.audit_refs;

    // 1. Schema version major == 1 for all outer files
    for (path, ver) in [
        ("manifest",               m.schema_version.as_str()),
        ("binary_identity",        bi.schema_version.as_str()),
        ("session",                s.schema_version.as_str()),
        ("iterations",             it.schema_version.as_str()),
        ("deltas",                 dl.schema_version.as_str()),
        ("final_verdict_snapshot", fv.schema_version.as_str()),
        ("audit_refs",             ar.schema_version.as_str()),
    ] {
        if !valid_semver_major(ver, NEST_EVIDENCE_SCHEMA_MAJOR) {
            add(&mut issues, path, NestValidationCode::UnsupportedSchemaVersion,
                &format!("schema_version major must be {NEST_EVIDENCE_SCHEMA_MAJOR}, got '{ver}'"));
        }
    }

    // 2. ID format validation
    if !valid_bundle_id(&m.bundle_id) {
        add(&mut issues, "manifest.bundle_id", NestValidationCode::InvalidValue,
            "bundle_id must match nestbundle_<ULID>");
    }
    if !valid_session_id(&m.session_id) {
        add(&mut issues, "manifest.session_id", NestValidationCode::InvalidValue,
            "session_id must match nestsession_<ULID>");
    }
    if !valid_binary_id(&m.binary_id) {
        add(&mut issues, "manifest.binary_id", NestValidationCode::InvalidValue,
            "binary_id must match binary_sha256_<sha256>");
    }
    if !valid_sha256(&m.binary_sha256) {
        add(&mut issues, "manifest.binary_sha256", NestValidationCode::InvalidValue,
            "binary_sha256 must be 64 lowercase hex chars");
    }

    // 3. Cross-file bundle_id consistency
    for (file, id) in [
        ("binary_identity", bi.bundle_id.as_str()),
        ("session",         s.bundle_id.as_str()),
        ("iterations",      it.bundle_id.as_str()),
        ("deltas",          dl.bundle_id.as_str()),
        ("final_verdict_snapshot", fv.bundle_id.as_str()),
        ("audit_refs",      ar.bundle_id.as_str()),
    ] {
        if id != m.bundle_id {
            add(&mut issues, file, NestValidationCode::ConsistencyError,
                &format!("{file}.bundle_id does not match manifest.bundle_id"));
        }
    }
    if let Some(rp) = &bundle.runtime_proof {
        if rp.bundle_id != m.bundle_id {
            add(&mut issues, "runtime_proof", NestValidationCode::ConsistencyError,
                "runtime_proof.bundle_id does not match manifest.bundle_id");
        }
    }

    // 4. Cross-file session_id consistency
    for (file, id) in [
        ("binary_identity", bi.session_id.as_str()),
        ("session",         s.session_id.as_str()),
        ("iterations",      it.session_id.as_str()),
        ("deltas",          dl.session_id.as_str()),
        ("final_verdict_snapshot", fv.session_id.as_str()),
        ("audit_refs",      ar.session_id.as_str()),
    ] {
        if id != m.session_id {
            add(&mut issues, file, NestValidationCode::ConsistencyError,
                &format!("{file}.session_id does not match manifest.session_id"));
        }
    }
    if let Some(rp) = &bundle.runtime_proof {
        if rp.session_id != m.session_id {
            add(&mut issues, "runtime_proof", NestValidationCode::ConsistencyError,
                "runtime_proof.session_id does not match manifest.session_id");
        }
    }

    // 5. Cross-file binary_sha256 consistency
    let root_sha256 = m.binary_sha256.as_str();
    for (file, sha) in [
        ("binary_identity", bi.binary_sha256.as_str()),
        ("session",         s.binary_sha256.as_str()),
        ("iterations",      it.binary_sha256.as_str()),
        ("deltas",          dl.binary_sha256.as_str()),
        ("final_verdict_snapshot", fv.binary_sha256.as_str()),
        ("audit_refs",      ar.binary_sha256.as_str()),
    ] {
        if sha != root_sha256 {
            add(&mut issues, file, NestValidationCode::ReplayCriticalError,
                &format!("{file}.binary_sha256 does not match manifest.binary_sha256"));
        }
    }
    if let Some(rp) = &bundle.runtime_proof {
        if rp.binary_sha256 != root_sha256 {
            add(&mut issues, "runtime_proof", NestValidationCode::ReplayCriticalError,
                "runtime_proof.binary_sha256 does not match manifest.binary_sha256");
        }
    }
    for (idx, item) in it.items.iter().enumerate() {
        if item.binary_sha256 != root_sha256 {
            add(&mut issues, &format!("iterations.items[{idx}].binary_sha256"),
                NestValidationCode::ReplayCriticalError,
                "Iteration binary_sha256 does not match bundle binary_sha256");
        }
    }
    for (idx, item) in dl.items.iter().enumerate() {
        if item.binary_sha256 != root_sha256 {
            add(&mut issues, &format!("deltas.items[{idx}].binary_sha256"),
                NestValidationCode::ReplayCriticalError,
                "Delta binary_sha256 does not match bundle binary_sha256");
        }
    }

    // 6. file_bound_proof consistency
    if bi.file_bound_proof.binary_sha256 != root_sha256 {
        add(&mut issues, "binary_identity.file_bound_proof.binary_sha256",
            NestValidationCode::ReplayCriticalError,
            "file_bound_proof.binary_sha256 does not match binary_identity.binary_sha256");
    }
    if bi.file_bound_proof.file_size_bytes != bi.file_size_bytes {
        add(&mut issues, "binary_identity.file_bound_proof.file_size_bytes",
            NestValidationCode::ReplayCriticalError,
            "file_bound_proof.file_size_bytes does not match binary_identity.file_size_bytes");
    }
    if bi.hashes.sha256 != root_sha256 {
        add(&mut issues, "binary_identity.hashes.sha256",
            NestValidationCode::ReplayCriticalError,
            "hashes.sha256 does not match binary_sha256");
    }

    // 7. Hash format validation
    if !valid_sha1(&bi.hashes.sha1) {
        add(&mut issues, "binary_identity.hashes.sha1", NestValidationCode::InvalidValue,
            "sha1 must be 40 lowercase hex chars");
    }
    if !valid_md5(&bi.hashes.md5) {
        add(&mut issues, "binary_identity.hashes.md5", NestValidationCode::InvalidValue,
            "md5 must be 32 lowercase hex chars");
    }

    // 8. GYRE sole-verdict-source invariants
    if !s.gyre_linkage.gyre_is_sole_verdict_source {
        add(&mut issues, "session.gyre_linkage.gyre_is_sole_verdict_source",
            NestValidationCode::ReplayCriticalError,
            "gyre_is_sole_verdict_source must be true — GYRE is the sole verdict authority");
    }
    if fv.source_engine != "gyre" {
        add(&mut issues, "final_verdict_snapshot.source_engine",
            NestValidationCode::ReplayCriticalError,
            "source_engine must be 'gyre' — GYRE is the sole verdict authority");
    }
    if !fv.nest_linkage.gyre_is_sole_verdict_source {
        add(&mut issues, "final_verdict_snapshot.nest_linkage.gyre_is_sole_verdict_source",
            NestValidationCode::ReplayCriticalError,
            "gyre_is_sole_verdict_source must be true — GYRE is the sole verdict authority");
    }

    // 9. verdict_snapshot_id cross-file consistency
    let snap_id = s.gyre_linkage.verdict_snapshot_id.as_str();
    if fv.verdict_snapshot_id != snap_id {
        add(&mut issues, "final_verdict_snapshot.verdict_snapshot_id",
            NestValidationCode::ConsistencyError,
            "verdict_snapshot_id does not match session.gyre_linkage.verdict_snapshot_id");
    }
    if !valid_verdict_snapshot_id(&fv.verdict_snapshot_id) {
        add(&mut issues, "final_verdict_snapshot.verdict_snapshot_id",
            NestValidationCode::InvalidValue,
            "verdict_snapshot_id must match gyresnap_<ULID>");
    }

    // 10. nest_role must contain "enrich"
    if !s.gyre_linkage.nest_role.contains("enrich") {
        add(&mut issues, "session.gyre_linkage.nest_role",
            NestValidationCode::InvalidValue,
            "nest_role must indicate enrichment-only (must contain 'enrich')");
    }

    // 11. linked_iteration_id vs nest_linkage.final_iteration_id
    if fv.linked_iteration_id != fv.nest_linkage.final_iteration_id {
        add(&mut issues, "final_verdict_snapshot.nest_linkage.final_iteration_id",
            NestValidationCode::ConsistencyError,
            "final_iteration_id does not match linked_iteration_id");
    }

    // 12. Iteration ID uniqueness and format
    {
        let mut seen: HashSet<&str> = HashSet::new();
        for (idx, item) in it.items.iter().enumerate() {
            if !valid_iteration_id(&item.iteration_id) {
                add(&mut issues, &format!("iterations.items[{idx}].iteration_id"),
                    NestValidationCode::InvalidValue,
                    "iteration_id must match nestiter_<ULID>_NNNN");
            }
            if seen.contains(item.iteration_id.as_str()) {
                add(&mut issues, &format!("iterations.items[{idx}].iteration_id"),
                    NestValidationCode::ConsistencyError,
                    "duplicate iteration_id");
            }
            seen.insert(&item.iteration_id);
        }
        if it.items.len() != it.count {
            add(&mut issues, "iterations.count", NestValidationCode::ConsistencyError,
                &format!("iterations.count={} but items.len()={}", it.count, it.items.len()));
        }
    }

    // 13. Delta ID uniqueness, format, and iteration references
    {
        let iter_ids: HashSet<&str> = it.items.iter().map(|i| i.iteration_id.as_str()).collect();
        let mut seen: HashSet<&str> = HashSet::new();
        for (idx, item) in dl.items.iter().enumerate() {
            if !valid_delta_id(&item.delta_id) {
                add(&mut issues, &format!("deltas.items[{idx}].delta_id"),
                    NestValidationCode::InvalidValue,
                    "delta_id must match nestdelta_<ULID>_NNNN_NNNN");
            }
            if seen.contains(item.delta_id.as_str()) {
                add(&mut issues, &format!("deltas.items[{idx}].delta_id"),
                    NestValidationCode::ConsistencyError,
                    "duplicate delta_id");
            }
            seen.insert(&item.delta_id);
            if !iter_ids.contains(item.from_iteration_id.as_str()) {
                add(&mut issues, &format!("deltas.items[{idx}].from_iteration_id"),
                    NestValidationCode::ConsistencyError,
                    "from_iteration_id not found in iterations");
            }
            if !iter_ids.contains(item.to_iteration_id.as_str()) {
                add(&mut issues, &format!("deltas.items[{idx}].to_iteration_id"),
                    NestValidationCode::ConsistencyError,
                    "to_iteration_id not found in iterations");
            }
            if item.from_iteration_index >= item.to_iteration_index {
                add(&mut issues, &format!("deltas.items[{idx}]"),
                    NestValidationCode::InvalidValue,
                    "Delta iteration indexes must move forward");
            }
        }
        if dl.items.len() != dl.count {
            add(&mut issues, "deltas.count", NestValidationCode::ConsistencyError,
                &format!("deltas.count={} but items.len()={}", dl.count, dl.items.len()));
        }
    }

    // 14. runtime_proof_required implies runtime_proof present
    if s.runtime_proof_required == Some(true) && bundle.runtime_proof.is_none() {
        add(&mut issues, "runtime_proof", NestValidationCode::MissingField,
            "session.runtime_proof_required=true but runtime_proof is absent");
    }

    // 15. Required files present in manifest.files
    const REQUIRED_FILES: &[&str] = &[
        "manifest.json",
        "binary_identity.json",
        "session.json",
        "iterations.json",
        "deltas.json",
        "final_verdict_snapshot.json",
        "audit_refs.json",
    ];
    let present: HashSet<&str> = m.files.iter().map(|f| f.name.as_str()).collect();
    for required in REQUIRED_FILES {
        if !present.contains(required) {
            add(&mut issues, "manifest.files", NestValidationCode::MissingField,
                &format!("Required file '{required}' missing from manifest.files"));
        }
    }

    // 16. File entry schema version major
    for (idx, f) in m.files.iter().enumerate() {
        if !valid_semver_major(&f.schema_version, NEST_EVIDENCE_SCHEMA_MAJOR) {
            add(&mut issues, &format!("manifest.files[{idx}].schema_version"),
                NestValidationCode::UnsupportedSchemaVersion,
                &format!("File '{}' schema_version major must be {NEST_EVIDENCE_SCHEMA_MAJOR}", f.name));
        }
    }

    issues
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── Fixture factory ───────────────────────────────────────────────────────

    const ULID: &str = "ABCDE12345FGHJKMNPQRST0123";

    fn bundle_id()    -> String { format!("nestbundle_{ULID}") }
    fn session_id()   -> String { format!("nestsession_{ULID}") }
    fn iter_id(n: u32)  -> String { format!("nestiter_{ULID}_{n:04}") }
    fn delta_id(a: u32, b: u32) -> String { format!("nestdelta_{ULID}_{a:04}_{b:04}") }
    fn snap_id()      -> String { format!("gyresnap_{ULID}") }
    fn sha256_a()     -> String { "a1b2c3d4e5f6".repeat(5) + "a1b2" }
    fn sha256_b()     -> String { "b2c3d4e5f6a1".repeat(5) + "b2c3" }
    fn sha1_a()       -> String { "a1b2c3d4e5f6".repeat(3) + "a1b2" }
    fn md5_a()        -> String { "a1b2c3d4e5f6".repeat(2) + "a1b2c3d4" }
    fn binary_id()    -> String { format!("binary_sha256_{}", sha256_a()) }

    fn make_actor() -> NestActor {
        NestActor {
            id:           "user:alice".into(),
            actor_type:   ActorType::User,
            display_name: "Alice".into(),
            tenant_id:    None,
            team_id:      None,
        }
    }

    fn make_timestamps() -> NestTimestamps {
        NestTimestamps {
            created_at:   "2026-04-29T16:49:00Z".into(),
            started_at:   Some("2026-04-29T16:49:02Z".into()),
            completed_at: Some("2026-04-29T16:50:12Z".into()),
            exported_at:  Some("2026-04-29T16:51:00Z".into()),
        }
    }

    fn make_gyre_linkage() -> NestGyreLinkage {
        NestGyreLinkage {
            verdict_snapshot_id:         snap_id(),
            gyre_schema_version:         "1.0.0".into(),
            gyre_build_id:               "1.0.0+abc123def456".into(),
            gyre_is_sole_verdict_source: true,
            nest_role:                   "iterative-enrichment-only".into(),
        }
    }

    fn make_config() -> NestSessionConfig {
        NestSessionConfig {
            config_version:        "1.0.0".into(),
            max_iterations:        5,
            min_iterations:        3,
            confidence_threshold:  80,
            plateau_threshold:     3,
            disasm_expansion:      512,
            aggressiveness:        "balanced".into(),
            enable_talon:          true,
            enable_strike:         false,
            enable_echo:           true,
            auto_advance:          true,
            auto_advance_delay_ms: 600,
        }
    }

    fn make_manifest() -> NestManifest {
        NestManifest {
            schema_name:           "nest.manifest".into(),
            schema_version:        "1.0.0".into(),
            bundle_schema_version: "1.0.0".into(),
            bundle_format_version: "1.0.0".into(),
            bundle_id:             bundle_id(),
            session_id:            session_id(),
            binary_id:             binary_id(),
            binary_sha256:         sha256_a(),
            engine_build_id:       "1.0.0+abc123def456".into(),
            policy_version:        "2026-04-29.1".into(),
            actor:                 make_actor(),
            timestamps:            NestTimestamps {
                created_at:   "2026-04-29T16:49:00Z".into(),
                started_at:   None,
                completed_at: None,
                exported_at:  Some("2026-04-29T16:51:00Z".into()),
            },
            files: vec![
                NestManifestFile { name: "manifest.json".into(),              required: true, sha256: sha256_a(), bytes: 1024, schema_name: "nest.manifest".into(),              schema_version: "1.0.0".into() },
                NestManifestFile { name: "binary_identity.json".into(),       required: true, sha256: sha256_a(), bytes: 512,  schema_name: "nest.binary_identity".into(),       schema_version: "1.0.0".into() },
                NestManifestFile { name: "session.json".into(),               required: true, sha256: sha256_a(), bytes: 2048, schema_name: "nest.session".into(),               schema_version: "1.0.0".into() },
                NestManifestFile { name: "iterations.json".into(),            required: true, sha256: sha256_a(), bytes: 4096, schema_name: "nest.iterations".into(),            schema_version: "1.0.0".into() },
                NestManifestFile { name: "deltas.json".into(),                required: true, sha256: sha256_a(), bytes: 2048, schema_name: "nest.deltas".into(),                schema_version: "1.0.0".into() },
                NestManifestFile { name: "final_verdict_snapshot.json".into(),required: true, sha256: sha256_a(), bytes: 1024, schema_name: "nest.final_verdict_snapshot".into(),schema_version: "1.0.0".into() },
                NestManifestFile { name: "audit_refs.json".into(),            required: true, sha256: sha256_a(), bytes: 512,  schema_name: "nest.audit_refs".into(),            schema_version: "1.0.0".into() },
            ],
            immutability: NestImmutability {
                bundle_locked:   true,
                locked_at:       Some("2026-04-29T16:51:00Z".into()),
                mutation_policy: MutationPolicy::ImmutableAfterExport,
            },
            replay: NestReplayInfo {
                replayable:            true,
                mode_supported:        vec!["local".into()],
                requires_binary_bytes: true,
            },
            export_mode: None,
            notes:       None,
        }
    }

    fn make_binary_identity() -> NestBinaryIdentity {
        NestBinaryIdentity {
            schema_name:     "nest.binary_identity".into(),
            schema_version:  "1.0.0".into(),
            bundle_id:       bundle_id(),
            session_id:      session_id(),
            binary_id:       binary_id(),
            binary_sha256:   sha256_a(),
            hashes:          NestBinaryHashes { sha256: sha256_a(), sha1: sha1_a(), md5: md5_a() },
            file_size_bytes: 184320,
            format:          "PE/MZ".into(),
            architecture:    "x86_64".into(),
            first_seen_at:   "2026-04-29T16:49:00Z".into(),
            identity_source: IdentitySource::LocalPath,
            file_bound_proof: NestFileBoundProof {
                proof_status:         FileBoundProofStatus::Proven,
                proof_basis:          vec!["sha256-match".into(), "file-size-match".into()],
                binary_sha256:        sha256_a(),
                file_size_bytes:      184320,
                session_hash_lock:    Some(true),
                runtime_proof_present: None,
            },
            original_path: Some("D:\\Challenges\\FlareAuthenticator\\FlareAuthenticator.exe".into()),
            file_name:     "FlareAuthenticator.exe".into(),
        }
    }

    fn make_session() -> NestSessionRecord {
        NestSessionRecord {
            schema_name:            "nest.session".into(),
            schema_version:         "1.0.0".into(),
            bundle_id:              bundle_id(),
            session_id:             session_id(),
            binary_id:              binary_id(),
            binary_sha256:          sha256_a(),
            engine_build_id:        "1.0.0+abc123def456".into(),
            policy_version:         "2026-04-29.1".into(),
            actor:                  make_actor(),
            timestamps:             make_timestamps(),
            status:                 SessionStatus::Completed,
            execution_mode:         ExecutionMode::LocalTauri,
            config:                 make_config(),
            iteration_count:        2,
            delta_count:            1,
            final_iteration_index:  2,
            convergence:            NestConvergence {
                has_converged:         true,
                reason:                "confidence-threshold".into(),
                confidence:            87,
                classification_stable: true,
                signal_delta:          3,
                contradiction_burden:  0,
                stability_score:       0.91,
            },
            gyre_linkage:           make_gyre_linkage(),
            runtime_proof_required: None,
            notes:                  None,
        }
    }

    fn make_iter_item(index: u32, sha: &str) -> NestIterationItem {
        NestIterationItem {
            iteration_id:         iter_id(index),
            iteration_index:      index,
            session_id:           session_id(),
            binary_sha256:        sha.to_owned(),
            started_at:           "2026-04-29T16:49:02Z".into(),
            completed_at:         Some("2026-04-29T16:49:25Z".into()),
            duration_ms:          Some(23000),
            input_window:         Some(NestInputWindow { offset: 0, length: 4096 }),
            executed_actions:     None,
            verdict_snapshot:     NestIterationVerdictSnapshot {
                classification:       "malicious".into(),
                confidence:           87,
                threat_score:         87,
                signal_count:         10,
                contradiction_count:  0,
                reasoning_chain_hash: sha256_a(),
            },
            convergence_snapshot: NestConvergenceSnapshot {
                has_converged:         true,
                reason:                "confidence-threshold".into(),
                stability_score:       0.91,
                classification_stable: true,
                signal_delta:          3,
                contradiction_burden:  0,
            },
            file_identity_locked: true,
        }
    }

    fn make_iterations() -> NestIterationsFile {
        NestIterationsFile {
            schema_name:   "nest.iterations".into(),
            schema_version: "1.0.0".into(),
            bundle_id:     bundle_id(),
            session_id:    session_id(),
            binary_id:     binary_id(),
            binary_sha256: sha256_a(),
            count:         2,
            items:         vec![
                make_iter_item(1, &sha256_a()),
                make_iter_item(2, &sha256_a()),
            ],
        }
    }

    fn make_deltas() -> NestDeltasFile {
        NestDeltasFile {
            schema_name:   "nest.deltas".into(),
            schema_version: "1.0.0".into(),
            bundle_id:     bundle_id(),
            session_id:    session_id(),
            binary_id:     binary_id(),
            binary_sha256: sha256_a(),
            count:         1,
            items:         vec![NestDeltaItem {
                delta_id:               delta_id(1, 2),
                from_iteration_id:      iter_id(1),
                to_iteration_id:        iter_id(2),
                from_iteration_index:   1,
                to_iteration_index:     2,
                binary_sha256:          sha256_a(),
                confidence_delta:       23,
                classification_changed: true,
                signal_delta_summary:   None,
                contradiction_delta:    Some(-1),
                refinement_execution:   None,
                projected_gain:         None,
                actual_gain:            None,
            }],
        }
    }

    fn make_final_verdict() -> NestFinalVerdictSnapshot {
        NestFinalVerdictSnapshot {
            schema_name:          "nest.final_verdict_snapshot".into(),
            schema_version:       "1.0.0".into(),
            bundle_id:            bundle_id(),
            session_id:           session_id(),
            binary_id:            binary_id(),
            binary_sha256:        sha256_a(),
            verdict_snapshot_id:  snap_id(),
            source_engine:        "gyre".into(),
            gyre_build_id:        "1.0.0+abc123def456".into(),
            gyre_schema_version:  "1.0.0".into(),
            classification:       "malicious".into(),
            confidence:           87,
            threat_score:         87,
            summary:              "Test summary.".into(),
            signal_count:         10,
            contradiction_count:  0,
            reasoning_chain_hash: sha256_a(),
            linked_iteration_id:  iter_id(2),
            nest_linkage:         NestFinalVerdictNestLinkage {
                session_id:              session_id(),
                final_iteration_id:      iter_id(2),
                nest_enrichment_applied: true,
                gyre_is_sole_verdict_source: true,
                nest_summary:            None,
            },
        }
    }

    fn make_audit_refs() -> NestAuditRefs {
        NestAuditRefs {
            schema_name:   "nest.audit_refs".into(),
            schema_version: "1.0.0".into(),
            bundle_id:     bundle_id(),
            session_id:    session_id(),
            binary_id:     binary_id(),
            binary_sha256: sha256_a(),
            actor:         make_actor(),
            policy_version: "2026-04-29.1".into(),
            audit_backend: "local-append-log".into(),
            events:        vec![NestAuditEvent {
                event_id:   "evt_0001".into(),
                event_type: "nest.session.created".into(),
                timestamp:  "2026-04-29T16:49:00Z".into(),
                actor_id:   "user:alice".into(),
                actor_type: "user".into(),
                session_id: session_id(),
                summary:    "Session created.".into(),
                details:    None,
            }],
        }
    }

    fn make_bundle() -> NestEvidenceBundle {
        NestEvidenceBundle {
            manifest:               make_manifest(),
            binary_identity:        make_binary_identity(),
            session:                make_session(),
            iterations:             make_iterations(),
            deltas:                 make_deltas(),
            final_verdict_snapshot: make_final_verdict(),
            audit_refs:             make_audit_refs(),
            runtime_proof:          None,
        }
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    #[test]
    fn valid_bundle_produces_no_issues() {
        let bundle = make_bundle();
        let issues = validate_bundle(&bundle);
        assert!(issues.is_empty(), "Expected no issues, got: {issues:?}");
    }

    #[test]
    fn serde_round_trip_preserves_ids() {
        let bundle = make_bundle();
        let json = serde_json::to_string(&bundle).expect("serialize");
        let restored: NestEvidenceBundle = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored.manifest.bundle_id, bundle_id());
        assert_eq!(restored.session.gyre_linkage.verdict_snapshot_id, snap_id());
        assert_eq!(restored.final_verdict_snapshot.source_engine, "gyre");
        assert!(restored.final_verdict_snapshot.nest_linkage.gyre_is_sole_verdict_source);
    }

    #[test]
    fn missing_required_field_fails_serde() {
        // A NestManifest JSON missing 'bundle_id' must fail to deserialize
        // (deny_unknown_fields only, required fields enforced by Rust struct absence of Option).
        let json = json!({
            "schema_name":           "nest.manifest",
            "schema_version":        "1.0.0",
            "bundle_schema_version": "1.0.0",
            "bundle_format_version": "1.0.0",
            // bundle_id intentionally omitted
            "session_id":    format!("nestsession_{ULID}"),
            "binary_id":     format!("binary_sha256_{}", sha256_a()),
            "binary_sha256": sha256_a(),
            "engine_build_id": "1.0.0+abc123def456",
            "policy_version": "2026-04-29.1",
            "actor":         { "id": "user:alice", "type": "user", "display_name": "Alice" },
            "timestamps":    { "created_at": "2026-04-29T16:49:00Z" },
            "files":         [],
            "immutability":  { "bundle_locked": true, "mutation_policy": "immutable-after-export" },
            "replay":        { "replayable": true, "mode_supported": ["local"], "requires_binary_bytes": true }
        });
        let result: Result<NestManifest, _> = serde_json::from_value(json);
        assert!(result.is_err(), "Expected deserialization to fail for missing bundle_id");
    }

    #[test]
    fn gyre_sole_verdict_violation_is_caught() {
        let mut bundle = make_bundle();
        bundle.session.gyre_linkage.gyre_is_sole_verdict_source = false;
        let issues = validate_bundle(&bundle);
        let critical: Vec<_> = issues.iter()
            .filter(|i| i.code == NestValidationCode::ReplayCriticalError)
            .collect();
        assert!(!critical.is_empty(), "Expected replay-critical-error for gyre violation");
    }

    #[test]
    fn source_engine_not_gyre_is_caught() {
        let mut bundle = make_bundle();
        bundle.final_verdict_snapshot.source_engine = "nest".into();
        let issues = validate_bundle(&bundle);
        let critical: Vec<_> = issues.iter()
            .filter(|i| i.code == NestValidationCode::ReplayCriticalError)
            .collect();
        assert!(!critical.is_empty(), "Expected replay-critical-error for source_engine != gyre");
    }

    #[test]
    fn binary_sha256_mismatch_produces_replay_critical() {
        let mut bundle = make_bundle();
        bundle.session.binary_sha256 = sha256_b();
        let issues = validate_bundle(&bundle);
        let critical: Vec<_> = issues.iter()
            .filter(|i| i.code == NestValidationCode::ReplayCriticalError)
            .collect();
        assert!(!critical.is_empty());
    }

    #[test]
    fn verdict_snap_mismatch_produces_consistency_error() {
        let mut bundle = make_bundle();
        bundle.session.gyre_linkage.verdict_snapshot_id = format!("gyresnap_DIFFERENT12345FGHJKMNPQR");
        let issues = validate_bundle(&bundle);
        let consistency: Vec<_> = issues.iter()
            .filter(|i| i.code == NestValidationCode::ConsistencyError)
            .collect();
        assert!(!consistency.is_empty());
    }

    #[test]
    fn duplicate_iteration_id_produces_consistency_error() {
        let mut bundle = make_bundle();
        bundle.iterations.items[1].iteration_id = iter_id(1); // duplicate of item 0
        let issues = validate_bundle(&bundle);
        let consistency: Vec<_> = issues.iter()
            .filter(|i| i.code == NestValidationCode::ConsistencyError)
            .collect();
        assert!(!consistency.is_empty());
    }

    #[test]
    fn delta_referencing_missing_iteration_produces_consistency_error() {
        let mut bundle = make_bundle();
        bundle.deltas.items[0].from_iteration_id = iter_id(99);
        let issues = validate_bundle(&bundle);
        let consistency: Vec<_> = issues.iter()
            .filter(|i| i.code == NestValidationCode::ConsistencyError)
            .collect();
        assert!(!consistency.is_empty());
    }

    #[test]
    fn reverse_delta_indexes_produce_invalid_value() {
        let mut bundle = make_bundle();
        bundle.deltas.items[0].from_iteration_index = 3;
        bundle.deltas.items[0].to_iteration_index   = 1;
        let issues = validate_bundle(&bundle);
        let inv_val: Vec<_> = issues.iter()
            .filter(|i| i.code == NestValidationCode::InvalidValue)
            .collect();
        assert!(!inv_val.is_empty());
    }

    #[test]
    fn runtime_proof_required_but_absent_produces_missing_field() {
        let mut bundle = make_bundle();
        bundle.session.runtime_proof_required = Some(true);
        // runtime_proof is None
        let issues = validate_bundle(&bundle);
        let missing: Vec<_> = issues.iter()
            .filter(|i| i.code == NestValidationCode::MissingField)
            .collect();
        assert!(!missing.is_empty());
    }

    #[test]
    fn unsupported_schema_major_produces_unsupported_version() {
        let mut bundle = make_bundle();
        bundle.manifest.schema_version = "2.0.0".into();
        let issues = validate_bundle(&bundle);
        let unsupported: Vec<_> = issues.iter()
            .filter(|i| i.code == NestValidationCode::UnsupportedSchemaVersion)
            .collect();
        assert!(!unsupported.is_empty());
    }

    #[test]
    fn helper_valid_bundle_id_accepts_correct_format() {
        assert!(valid_bundle_id(&bundle_id()));
        assert!(!valid_bundle_id("nestbundle_short"));
        assert!(!valid_bundle_id("wrongprefix_ABCDE12345FGHJKMNPQRST0123"));
        assert!(!valid_bundle_id(&format!("nestbundle_{}L", &ULID[..25]))); // L invalid in Crockford
    }

    #[test]
    fn helper_valid_iteration_id_accepts_correct_format() {
        assert!(valid_iteration_id(&iter_id(1)));
        assert!(valid_iteration_id(&iter_id(9999)));
        assert!(!valid_iteration_id("nestiter_ABCDE12345FGHJKMNPQRST0123_01")); // 2 digits not 4
        assert!(!valid_iteration_id("nestiter_ABCDE12345FGHJKMNPQRST0123"));    // no suffix
    }

    #[test]
    fn helper_valid_delta_id_accepts_correct_format() {
        assert!(valid_delta_id(&delta_id(1, 2)));
        assert!(!valid_delta_id("nestdelta_ABCDE12345FGHJKMNPQRST0123_1_2")); // not 4-digit
    }

    #[test]
    fn helper_valid_sha256_rejects_uppercase() {
        let upper = sha256_a().to_uppercase();
        assert!(!valid_sha256(&upper));
        assert!(valid_sha256(&sha256_a()));
    }
}
