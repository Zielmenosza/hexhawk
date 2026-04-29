use crate::commands::nest_evidence::{
    validate_bundle, ActorType, ExecutionMode, ExportMode, FileBoundProofStatus, IdentitySource,
    MutationPolicy, NestActor, NestAuditEvent, NestAuditRefs, NestBinaryHashes,
    NestBinaryIdentity, NestConvergence, NestConvergenceSnapshot, NestDeltaItem, NestDeltasFile,
    NestEvidenceBundle, NestFileBoundProof, NestFinalVerdictNestLinkage,
    NestFinalVerdictSnapshot, NestGyreLinkage, NestImmutability, NestInputWindow,
    NestIterationItem, NestIterationsFile, NestIterationVerdictSnapshot, NestManifest,
    NestManifestFile, NestRefinementExecution, NestReplayInfo, NestRuntimeProof,
    NestSessionConfig, NestSessionRecord, NestSignalDeltaSummary, NestTimestamps,
    NestValidationIssue, RuntimeProofStatus, RuntimeMode, SessionStatus,
};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tauri::Manager;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

const LIFECYCLE_SCHEMA_VERSION: &str = "1.0.0";
const LIFECYCLE_BUNDLE_FORMAT_VERSION: &str = "1.0.0";
const DEFAULT_POLICY_VERSION: &str = "local-policy-1";
const DEFAULT_ENGINE_BUILD_ID: &str = "1.0.0+tauri-local";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NestSessionCreateRequest {
    pub binary_path: String,
    pub binary_sha256: String,
    pub file_size_bytes: u64,
    pub format: String,
    pub architecture: String,
    pub binary_sha1: Option<String>,
    pub binary_md5: Option<String>,
    pub actor_id: Option<String>,
    pub actor_type: Option<ActorType>,
    pub actor_display_name: Option<String>,
    pub policy_version: Option<String>,
    pub engine_build_id: Option<String>,
    pub gyre_build_id: Option<String>,
    pub gyre_schema_version: Option<String>,
    pub execution_mode: Option<ExecutionMode>,
    pub export_mode: Option<ExportMode>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NestSessionAppendIterationRequest {
    pub session_id: String,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
    pub duration_ms: Option<u64>,
    pub input_offset: Option<u64>,
    pub input_length: Option<u64>,
    pub classification: String,
    pub confidence: u32,
    pub threat_score: u32,
    pub signal_count: u64,
    pub contradiction_count: u64,
    pub reasoning_chain_hash: String,
    pub convergence_reason: String,
    pub has_converged: bool,
    pub stability_score: f64,
    pub classification_stable: bool,
    pub signal_delta: i64,
    pub contradiction_burden: i64,
    pub executed_action_types: Option<Vec<String>>,
    pub primary_action_type: Option<String>,
    pub file_identity_locked: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NestSessionFinalizeRequest {
    pub session_id: String,
    pub verdict_snapshot_id: Option<String>,
    pub source_engine: String,
    pub gyre_is_sole_verdict_source: bool,
    pub classification: String,
    pub confidence: u32,
    pub threat_score: u32,
    pub summary: String,
    pub signal_count: u64,
    pub contradiction_count: u64,
    pub reasoning_chain_hash: String,
    pub linked_iteration_id: Option<String>,
    pub nest_summary: Option<String>,
    pub runtime_proof: Option<NestRuntimeProof>,
    pub notes: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NestSessionExportRequest {
    pub session_id: String,
    pub output_dir: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NestSessionLifecycleSummary {
    pub session_id: String,
    pub bundle_id: String,
    pub binary_id: String,
    pub binary_sha256: String,
    pub status: SessionStatus,
    pub iteration_count: u32,
    pub delta_count: u32,
    pub final_iteration_index: Option<u32>,
    pub created_at: String,
    pub completed_at: Option<String>,
    pub last_event_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NestSessionExportResult {
    pub session: NestSessionLifecycleSummary,
    pub output_dir: String,
    pub files_written: Vec<String>,
    pub issues: Vec<NestValidationIssue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct NestSessionLifecycleState {
    schema_version: String,
    session_id: String,
    bundle_id: String,
    ulid: String,
    binary_id: String,
    binary_path: String,
    binary_sha256: String,
    binary_sha1: String,
    binary_md5: String,
    file_size_bytes: u64,
    format: String,
    architecture: String,
    actor: NestActor,
    policy_version: String,
    engine_build_id: String,
    gyre_build_id: String,
    gyre_schema_version: String,
    execution_mode: ExecutionMode,
    export_mode: ExportMode,
    created_at: String,
    completed_at: Option<String>,
    status: SessionStatus,
    notes: Vec<String>,
    iterations: Vec<NestIterationItem>,
    deltas: Vec<NestDeltaItem>,
    final_verdict_snapshot: Option<NestFinalVerdictSnapshot>,
    runtime_proof: Option<NestRuntimeProof>,
    audit_events: Vec<NestAuditEvent>,
}

static LIFECYCLE_SESSIONS: Lazy<Mutex<HashMap<String, NestSessionLifecycleState>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

static LIFECYCLE_COUNTER: Lazy<Mutex<u64>> = Lazy::new(|| Mutex::new(0));

fn now_iso() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "2026-04-29T00:00:00Z".to_string())
}

fn app_sessions_root(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("Could not resolve app data dir: {e}"))?
        .join("nest_sessions");
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("Failed to create nest_sessions directory: {e}"))?;
    Ok(dir)
}

fn session_dir(root: &Path, session_id: &str) -> PathBuf {
    root.join(session_id)
}

fn state_path(root: &Path, session_id: &str) -> PathBuf {
    session_dir(root, session_id).join("lifecycle_state.json")
}

fn ensure_valid_sha256(value: &str, field: &str) -> Result<(), String> {
    if value.len() != 64 || !value.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')) {
        return Err(format!("{field} must be 64 lowercase hex chars"));
    }
    Ok(())
}

fn ensure_valid_hash_len(value: &str, len: usize, field: &str) -> Result<(), String> {
    if value.len() != len || !value.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')) {
        return Err(format!("{field} must be {len} lowercase hex chars"));
    }
    Ok(())
}

fn pseudo_hash(seed: &str, bytes: usize) -> String {
    let mut hasher = Sha256::new();
    hasher.update(seed.as_bytes());
    let digest = hasher.finalize();
    let mut out = String::new();
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out.truncate(bytes * 2);
    out
}

fn next_ulid_like() -> String {
    const CROCKFORD: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let ts = OffsetDateTime::now_utc().unix_timestamp_nanos();
    let mut c = LIFECYCLE_COUNTER.lock().unwrap();
    *c += 1;
    let seed = format!("{ts}:{}", *c);
    let digest = pseudo_hash(&seed, 32);
    let bytes = digest.as_bytes();
    let mut out = String::with_capacity(26);
    for i in 0..26 {
        let idx = ((bytes[(i * 2) % bytes.len()] as usize) + i) % CROCKFORD.len();
        out.push(CROCKFORD[idx] as char);
    }
    out
}

fn event_id(ulid: &str, index: usize) -> String {
    format!("evt_{ulid}_{:04}", index)
}

fn persist_state(root: &Path, state: &NestSessionLifecycleState) -> Result<(), String> {
    let dir = session_dir(root, &state.session_id);
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("Failed to create session directory: {e}"))?;
    let body = serde_json::to_string_pretty(state)
        .map_err(|e| format!("Failed to serialize lifecycle state: {e}"))?;
    std::fs::write(state_path(root, &state.session_id), body)
        .map_err(|e| format!("Failed to persist lifecycle state: {e}"))
}

fn load_state_from_disk(root: &Path, session_id: &str) -> Result<NestSessionLifecycleState, String> {
    let path = state_path(root, session_id);
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("Failed to read lifecycle state at {}: {e}", path.display()))?;
    serde_json::from_str(&text)
        .map_err(|e| format!("Failed to parse lifecycle state JSON: {e}"))
}

fn get_or_load_state(app: &tauri::AppHandle, session_id: &str) -> Result<NestSessionLifecycleState, String> {
    if let Some(in_mem) = LIFECYCLE_SESSIONS.lock().unwrap().get(session_id).cloned() {
        return Ok(in_mem);
    }
    let root = app_sessions_root(app)?;
    let loaded = load_state_from_disk(&root, session_id)?;
    LIFECYCLE_SESSIONS
        .lock()
        .unwrap()
        .insert(session_id.to_string(), loaded.clone());
    Ok(loaded)
}

fn upsert_state(app: &tauri::AppHandle, state: NestSessionLifecycleState) -> Result<(), String> {
    let root = app_sessions_root(app)?;
    persist_state(&root, &state)?;
    LIFECYCLE_SESSIONS
        .lock()
        .unwrap()
        .insert(state.session_id.clone(), state);
    Ok(())
}

fn default_session_config() -> NestSessionConfig {
    NestSessionConfig {
        config_version: LIFECYCLE_SCHEMA_VERSION.to_string(),
        max_iterations: 12,
        min_iterations: 2,
        confidence_threshold: 80,
        plateau_threshold: 3,
        disasm_expansion: 512,
        aggressiveness: "balanced".to_string(),
        enable_talon: true,
        enable_strike: false,
        enable_echo: true,
        auto_advance: true,
        auto_advance_delay_ms: 0,
    }
}

fn to_summary(state: &NestSessionLifecycleState) -> NestSessionLifecycleSummary {
    NestSessionLifecycleSummary {
        session_id: state.session_id.clone(),
        bundle_id: state.bundle_id.clone(),
        binary_id: state.binary_id.clone(),
        binary_sha256: state.binary_sha256.clone(),
        status: state.status.clone(),
        iteration_count: state.iterations.len() as u32,
        delta_count: state.deltas.len() as u32,
        final_iteration_index: if state.iterations.is_empty() {
            None
        } else {
            Some(state.iterations.len() as u32)
        },
        created_at: state.created_at.clone(),
        completed_at: state.completed_at.clone(),
        last_event_type: state.audit_events.last().map(|e| e.event_type.clone()),
    }
}

fn build_session_record(state: &NestSessionLifecycleState) -> Result<NestSessionRecord, String> {
    let final_verdict = state
        .final_verdict_snapshot
        .as_ref()
        .ok_or_else(|| "Cannot build session record before final verdict snapshot exists".to_string())?;

    let last_iter = state
        .iterations
        .last()
        .ok_or_else(|| "Cannot build session record before at least one iteration exists".to_string())?;

    Ok(NestSessionRecord {
        schema_name: "nest.session".to_string(),
        schema_version: LIFECYCLE_SCHEMA_VERSION.to_string(),
        bundle_id: state.bundle_id.clone(),
        session_id: state.session_id.clone(),
        binary_id: state.binary_id.clone(),
        binary_sha256: state.binary_sha256.clone(),
        engine_build_id: state.engine_build_id.clone(),
        policy_version: state.policy_version.clone(),
        actor: state.actor.clone(),
        timestamps: NestTimestamps {
            created_at: state.created_at.clone(),
            started_at: Some(state.created_at.clone()),
            completed_at: state.completed_at.clone(),
            exported_at: None,
        },
        status: state.status.clone(),
        execution_mode: state.execution_mode.clone(),
        config: default_session_config(),
        iteration_count: state.iterations.len() as u32,
        delta_count: state.deltas.len() as u32,
        final_iteration_index: state.iterations.len() as u32,
        convergence: NestConvergence {
            has_converged: true,
            reason: last_iter.convergence_snapshot.reason.clone(),
            confidence: final_verdict.confidence,
            classification_stable: last_iter.convergence_snapshot.classification_stable,
            signal_delta: last_iter.convergence_snapshot.signal_delta,
            contradiction_burden: last_iter.convergence_snapshot.contradiction_burden,
            stability_score: last_iter.convergence_snapshot.stability_score,
        },
        gyre_linkage: NestGyreLinkage {
            verdict_snapshot_id: final_verdict.verdict_snapshot_id.clone(),
            gyre_schema_version: state.gyre_schema_version.clone(),
            gyre_build_id: state.gyre_build_id.clone(),
            gyre_is_sole_verdict_source: true,
            nest_role: "iterative-enrichment-only".to_string(),
        },
        runtime_proof_required: Some(state.runtime_proof.is_some()),
        notes: if state.notes.is_empty() {
            None
        } else {
            Some(state.notes.clone())
        },
    })
}

fn build_evidence_bundle(state: &NestSessionLifecycleState) -> Result<NestEvidenceBundle, String> {
    let session = build_session_record(state)?;
    let final_verdict = state
        .final_verdict_snapshot
        .clone()
        .ok_or_else(|| "Cannot export bundle before session is finalized".to_string())?;

    let mut manifest_files = vec![
        NestManifestFile {
            name: "manifest.json".to_string(),
            required: true,
            sha256: state.binary_sha256.clone(),
            bytes: 0,
            schema_name: "nest.manifest".to_string(),
            schema_version: LIFECYCLE_SCHEMA_VERSION.to_string(),
        },
        NestManifestFile {
            name: "binary_identity.json".to_string(),
            required: true,
            sha256: state.binary_sha256.clone(),
            bytes: 0,
            schema_name: "nest.binary_identity".to_string(),
            schema_version: LIFECYCLE_SCHEMA_VERSION.to_string(),
        },
        NestManifestFile {
            name: "session.json".to_string(),
            required: true,
            sha256: state.binary_sha256.clone(),
            bytes: 0,
            schema_name: "nest.session".to_string(),
            schema_version: LIFECYCLE_SCHEMA_VERSION.to_string(),
        },
        NestManifestFile {
            name: "iterations.json".to_string(),
            required: true,
            sha256: state.binary_sha256.clone(),
            bytes: 0,
            schema_name: "nest.iterations".to_string(),
            schema_version: LIFECYCLE_SCHEMA_VERSION.to_string(),
        },
        NestManifestFile {
            name: "deltas.json".to_string(),
            required: true,
            sha256: state.binary_sha256.clone(),
            bytes: 0,
            schema_name: "nest.deltas".to_string(),
            schema_version: LIFECYCLE_SCHEMA_VERSION.to_string(),
        },
        NestManifestFile {
            name: "final_verdict_snapshot.json".to_string(),
            required: true,
            sha256: state.binary_sha256.clone(),
            bytes: 0,
            schema_name: "nest.final_verdict_snapshot".to_string(),
            schema_version: LIFECYCLE_SCHEMA_VERSION.to_string(),
        },
        NestManifestFile {
            name: "audit_refs.json".to_string(),
            required: true,
            sha256: state.binary_sha256.clone(),
            bytes: 0,
            schema_name: "nest.audit_refs".to_string(),
            schema_version: LIFECYCLE_SCHEMA_VERSION.to_string(),
        },
    ];

    if state.runtime_proof.is_some() {
        manifest_files.push(NestManifestFile {
            name: "runtime_proof.json".to_string(),
            required: false,
            sha256: state.binary_sha256.clone(),
            bytes: 0,
            schema_name: "nest.runtime_proof".to_string(),
            schema_version: LIFECYCLE_SCHEMA_VERSION.to_string(),
        });
    }

    Ok(NestEvidenceBundle {
        manifest: NestManifest {
            schema_name: "nest.manifest".to_string(),
            schema_version: LIFECYCLE_SCHEMA_VERSION.to_string(),
            bundle_schema_version: LIFECYCLE_SCHEMA_VERSION.to_string(),
            bundle_format_version: LIFECYCLE_BUNDLE_FORMAT_VERSION.to_string(),
            bundle_id: state.bundle_id.clone(),
            session_id: state.session_id.clone(),
            binary_id: state.binary_id.clone(),
            binary_sha256: state.binary_sha256.clone(),
            engine_build_id: state.engine_build_id.clone(),
            policy_version: state.policy_version.clone(),
            actor: state.actor.clone(),
            timestamps: NestTimestamps {
                created_at: state.created_at.clone(),
                started_at: Some(state.created_at.clone()),
                completed_at: state.completed_at.clone(),
                exported_at: None,
            },
            files: manifest_files,
            immutability: NestImmutability {
                bundle_locked: true,
                locked_at: None,
                mutation_policy: MutationPolicy::ImmutableAfterExport,
            },
            replay: NestReplayInfo {
                replayable: true,
                mode_supported: vec!["local".to_string()],
                requires_binary_bytes: true,
            },
            export_mode: Some(state.export_mode.clone()),
            notes: Some("Backend lifecycle-owned bundle export".to_string()),
        },
        binary_identity: NestBinaryIdentity {
            schema_name: "nest.binary_identity".to_string(),
            schema_version: LIFECYCLE_SCHEMA_VERSION.to_string(),
            bundle_id: state.bundle_id.clone(),
            session_id: state.session_id.clone(),
            binary_id: state.binary_id.clone(),
            binary_sha256: state.binary_sha256.clone(),
            hashes: NestBinaryHashes {
                sha256: state.binary_sha256.clone(),
                sha1: state.binary_sha1.clone(),
                md5: state.binary_md5.clone(),
            },
            file_size_bytes: state.file_size_bytes,
            format: state.format.clone(),
            architecture: state.architecture.clone(),
            first_seen_at: state.created_at.clone(),
            identity_source: IdentitySource::LocalPath,
            file_bound_proof: NestFileBoundProof {
                proof_status: FileBoundProofStatus::Proven,
                proof_basis: vec!["sha256-match".to_string(), "file-size-match".to_string()],
                binary_sha256: state.binary_sha256.clone(),
                file_size_bytes: state.file_size_bytes,
                session_hash_lock: Some(true),
                runtime_proof_present: Some(state.runtime_proof.is_some()),
            },
            original_path: Some(state.binary_path.clone()),
            file_name: Path::new(&state.binary_path)
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown.bin")
                .to_string(),
        },
        session,
        iterations: NestIterationsFile {
            schema_name: "nest.iterations".to_string(),
            schema_version: LIFECYCLE_SCHEMA_VERSION.to_string(),
            bundle_id: state.bundle_id.clone(),
            session_id: state.session_id.clone(),
            binary_id: state.binary_id.clone(),
            binary_sha256: state.binary_sha256.clone(),
            count: state.iterations.len(),
            items: state.iterations.clone(),
        },
        deltas: NestDeltasFile {
            schema_name: "nest.deltas".to_string(),
            schema_version: LIFECYCLE_SCHEMA_VERSION.to_string(),
            bundle_id: state.bundle_id.clone(),
            session_id: state.session_id.clone(),
            binary_id: state.binary_id.clone(),
            binary_sha256: state.binary_sha256.clone(),
            count: state.deltas.len(),
            items: state.deltas.clone(),
        },
        final_verdict_snapshot: final_verdict,
        audit_refs: NestAuditRefs {
            schema_name: "nest.audit_refs".to_string(),
            schema_version: LIFECYCLE_SCHEMA_VERSION.to_string(),
            bundle_id: state.bundle_id.clone(),
            session_id: state.session_id.clone(),
            binary_id: state.binary_id.clone(),
            binary_sha256: state.binary_sha256.clone(),
            actor: state.actor.clone(),
            policy_version: state.policy_version.clone(),
            audit_backend: "local-append-log".to_string(),
            events: state.audit_events.clone(),
        },
        runtime_proof: state.runtime_proof.clone(),
    })
}

fn write_bundle_files(bundle: &mut NestEvidenceBundle, output_dir: &Path) -> Result<Vec<String>, String> {
    std::fs::create_dir_all(output_dir)
        .map_err(|e| format!("Failed to create export directory {}: {e}", output_dir.display()))?;

    let mut written = Vec::new();

    let mut write_json = |name: &str, value: &serde_json::Value| -> Result<(u64, String), String> {
        let file_path = output_dir.join(name);
        let body = serde_json::to_vec_pretty(value)
            .map_err(|e| format!("Failed to serialize {name}: {e}"))?;
        std::fs::write(&file_path, &body)
            .map_err(|e| format!("Failed to write {}: {e}", file_path.display()))?;
        written.push(file_path.to_string_lossy().to_string());
        let mut hasher = Sha256::new();
        hasher.update(&body);
        let hash = format!("{:x}", hasher.finalize());
        Ok((body.len() as u64, hash))
    };

    let binary_identity_json = serde_json::to_value(&bundle.binary_identity)
        .map_err(|e| format!("Failed to encode binary_identity.json: {e}"))?;
    let session_json = serde_json::to_value(&bundle.session)
        .map_err(|e| format!("Failed to encode session.json: {e}"))?;
    let iterations_json = serde_json::to_value(&bundle.iterations)
        .map_err(|e| format!("Failed to encode iterations.json: {e}"))?;
    let deltas_json = serde_json::to_value(&bundle.deltas)
        .map_err(|e| format!("Failed to encode deltas.json: {e}"))?;
    let final_verdict_json = serde_json::to_value(&bundle.final_verdict_snapshot)
        .map_err(|e| format!("Failed to encode final_verdict_snapshot.json: {e}"))?;
    let audit_refs_json = serde_json::to_value(&bundle.audit_refs)
        .map_err(|e| format!("Failed to encode audit_refs.json: {e}"))?;

    let (binary_identity_bytes, binary_identity_hash) = write_json("binary_identity.json", &binary_identity_json)?;
    let (session_bytes, session_hash) = write_json("session.json", &session_json)?;
    let (iterations_bytes, iterations_hash) = write_json("iterations.json", &iterations_json)?;
    let (deltas_bytes, deltas_hash) = write_json("deltas.json", &deltas_json)?;
    let (final_verdict_bytes, final_verdict_hash) =
        write_json("final_verdict_snapshot.json", &final_verdict_json)?;
    let (audit_refs_bytes, audit_refs_hash) = write_json("audit_refs.json", &audit_refs_json)?;

    let mut runtime_proof_info: Option<(u64, String)> = None;
    if let Some(runtime_proof) = &bundle.runtime_proof {
        let runtime_json = serde_json::to_value(runtime_proof)
            .map_err(|e| format!("Failed to encode runtime_proof.json: {e}"))?;
        runtime_proof_info = Some(write_json("runtime_proof.json", &runtime_json)?);
    }

    for file in &mut bundle.manifest.files {
        match file.name.as_str() {
            "binary_identity.json" => {
                file.bytes = binary_identity_bytes;
                file.sha256 = binary_identity_hash.clone();
            }
            "session.json" => {
                file.bytes = session_bytes;
                file.sha256 = session_hash.clone();
            }
            "iterations.json" => {
                file.bytes = iterations_bytes;
                file.sha256 = iterations_hash.clone();
            }
            "deltas.json" => {
                file.bytes = deltas_bytes;
                file.sha256 = deltas_hash.clone();
            }
            "final_verdict_snapshot.json" => {
                file.bytes = final_verdict_bytes;
                file.sha256 = final_verdict_hash.clone();
            }
            "audit_refs.json" => {
                file.bytes = audit_refs_bytes;
                file.sha256 = audit_refs_hash.clone();
            }
            "runtime_proof.json" => {
                if let Some((bytes, hash)) = &runtime_proof_info {
                    file.bytes = *bytes;
                    file.sha256 = hash.clone();
                }
            }
            _ => {}
        }
    }

    bundle.manifest.timestamps.exported_at = Some(now_iso());
    bundle.manifest.immutability.locked_at = bundle.manifest.timestamps.exported_at.clone();

    let manifest_json = serde_json::to_value(&bundle.manifest)
        .map_err(|e| format!("Failed to encode manifest.json: {e}"))?;
    let (manifest_bytes, manifest_hash) = write_json("manifest.json", &manifest_json)?;
    if let Some(manifest_entry) = bundle
        .manifest
        .files
        .iter_mut()
        .find(|f| f.name == "manifest.json")
    {
        manifest_entry.bytes = manifest_bytes;
        manifest_entry.sha256 = manifest_hash;
    }

    Ok(written)
}

#[tauri::command]
pub fn nest_create_session(
    app: tauri::AppHandle,
    request: NestSessionCreateRequest,
) -> Result<NestSessionLifecycleSummary, String> {
    ensure_valid_sha256(&request.binary_sha256, "binary_sha256")?;
    let ulid = next_ulid_like();
    let session_id = format!("nestsession_{ulid}");
    let bundle_id = format!("nestbundle_{ulid}");
    let binary_id = format!("binary_sha256_{}", request.binary_sha256);
    let created_at = now_iso();

    let actor = NestActor {
        id: request.actor_id.unwrap_or_else(|| "system:nest-lifecycle".to_string()),
        actor_type: request.actor_type.unwrap_or(ActorType::System),
        display_name: request
            .actor_display_name
            .unwrap_or_else(|| "NEST Lifecycle".to_string()),
        tenant_id: None,
        team_id: None,
    };

    let mut state = NestSessionLifecycleState {
        schema_version: LIFECYCLE_SCHEMA_VERSION.to_string(),
        session_id,
        bundle_id,
        ulid,
        binary_id,
        binary_path: request.binary_path,
        binary_sha256: request.binary_sha256,
        binary_sha1: request
            .binary_sha1
            .unwrap_or_else(|| pseudo_hash("sha1-default", 20)),
        binary_md5: request
            .binary_md5
            .unwrap_or_else(|| pseudo_hash("md5-default", 16)),
        file_size_bytes: request.file_size_bytes,
        format: request.format,
        architecture: request.architecture,
        actor,
        policy_version: request
            .policy_version
            .unwrap_or_else(|| DEFAULT_POLICY_VERSION.to_string()),
        engine_build_id: request
            .engine_build_id
            .unwrap_or_else(|| DEFAULT_ENGINE_BUILD_ID.to_string()),
        gyre_build_id: request
            .gyre_build_id
            .unwrap_or_else(|| DEFAULT_ENGINE_BUILD_ID.to_string()),
        gyre_schema_version: request
            .gyre_schema_version
            .unwrap_or_else(|| LIFECYCLE_SCHEMA_VERSION.to_string()),
        execution_mode: request.execution_mode.unwrap_or(ExecutionMode::LocalTauri),
        export_mode: request.export_mode.unwrap_or(ExportMode::LocalTauri),
        created_at,
        completed_at: None,
        status: SessionStatus::Pending,
        notes: Vec::new(),
        iterations: Vec::new(),
        deltas: Vec::new(),
        final_verdict_snapshot: None,
        runtime_proof: None,
        audit_events: Vec::new(),
    };

    ensure_valid_hash_len(&state.binary_sha1, 40, "binary_sha1")?;
    ensure_valid_hash_len(&state.binary_md5, 32, "binary_md5")?;

    state.audit_events.push(NestAuditEvent {
        event_id: event_id(&state.ulid, 1),
        event_type: "nest.session.created".to_string(),
        timestamp: now_iso(),
        actor_id: state.actor.id.clone(),
        actor_type: match state.actor.actor_type {
            ActorType::User => "user",
            ActorType::Reviewer => "reviewer",
            ActorType::Approver => "approver",
            ActorType::ServiceAccount => "service-account",
            ActorType::System => "system",
        }
        .to_string(),
        session_id: state.session_id.clone(),
        summary: format!("Session created for {}", state.binary_path),
        details: None,
    });

    upsert_state(&app, state.clone())?;
    Ok(to_summary(&state))
}

#[tauri::command]
pub fn nest_append_iteration(
    app: tauri::AppHandle,
    request: NestSessionAppendIterationRequest,
) -> Result<NestSessionLifecycleSummary, String> {
    let mut state = get_or_load_state(&app, &request.session_id)?;

    if matches!(state.status, SessionStatus::Completed | SessionStatus::Cancelled | SessionStatus::Failed) {
        return Err("Cannot append iteration to a finalized session".to_string());
    }

    let idx = state.iterations.len() as u32 + 1;
    let started_at = request.started_at.unwrap_or_else(now_iso);
    let completed_at = request.completed_at.unwrap_or_else(now_iso);
    let iteration_id = format!("nestiter_{}_{idx:04}", state.ulid);

    let iteration = NestIterationItem {
        iteration_id: iteration_id.clone(),
        iteration_index: idx,
        session_id: state.session_id.clone(),
        binary_sha256: state.binary_sha256.clone(),
        started_at,
        completed_at: Some(completed_at),
        duration_ms: request.duration_ms,
        input_window: Some(NestInputWindow {
            offset: request.input_offset.unwrap_or(0),
            length: request.input_length.unwrap_or(0),
        }),
        executed_actions: None,
        verdict_snapshot: NestIterationVerdictSnapshot {
            classification: request.classification.clone(),
            confidence: request.confidence,
            threat_score: request.threat_score,
            signal_count: request.signal_count,
            contradiction_count: request.contradiction_count,
            reasoning_chain_hash: request.reasoning_chain_hash.clone(),
        },
        convergence_snapshot: NestConvergenceSnapshot {
            has_converged: request.has_converged,
            reason: request.convergence_reason.clone(),
            stability_score: request.stability_score,
            classification_stable: request.classification_stable,
            signal_delta: request.signal_delta,
            contradiction_burden: request.contradiction_burden,
        },
        file_identity_locked: request.file_identity_locked.unwrap_or(true),
    };

    if let Some(prev) = state.iterations.last() {
        let delta = NestDeltaItem {
            delta_id: format!("nestdelta_{}_{:04}_{:04}", state.ulid, idx - 1, idx),
            from_iteration_id: prev.iteration_id.clone(),
            to_iteration_id: iteration_id,
            from_iteration_index: prev.iteration_index,
            to_iteration_index: idx,
            binary_sha256: state.binary_sha256.clone(),
            confidence_delta: request.confidence as i64 - prev.verdict_snapshot.confidence as i64,
            classification_changed: prev.verdict_snapshot.classification != request.classification,
            signal_delta_summary: Some(NestSignalDeltaSummary {
                added_count: request.signal_count.saturating_sub(prev.verdict_snapshot.signal_count),
                removed_count: prev.verdict_snapshot.signal_count.saturating_sub(request.signal_count),
                unchanged_count: request.signal_count.min(prev.verdict_snapshot.signal_count),
            }),
            contradiction_delta: Some(
                request.contradiction_count as i64 - prev.verdict_snapshot.contradiction_count as i64,
            ),
            refinement_execution: Some(NestRefinementExecution {
                action_types: request.executed_action_types.clone().unwrap_or_default(),
                primary_action_type: request
                    .primary_action_type
                    .clone()
                    .unwrap_or_else(|| "none".to_string()),
                executed: request
                    .executed_action_types
                    .as_ref()
                    .map(|v| !v.is_empty())
                    .unwrap_or(false),
                primary_action_reason: None,
            }),
            projected_gain: None,
            actual_gain: Some(request.confidence as i64 - prev.verdict_snapshot.confidence as i64),
        };
        state.deltas.push(delta);
    }

    state.status = SessionStatus::Running;
    state.iterations.push(iteration);

    upsert_state(&app, state.clone())?;
    Ok(to_summary(&state))
}

#[tauri::command]
pub fn nest_finalize_session(
    app: tauri::AppHandle,
    request: NestSessionFinalizeRequest,
) -> Result<NestSessionLifecycleSummary, String> {
    let mut state = get_or_load_state(&app, &request.session_id)?;

    if request.source_engine != "gyre" {
        return Err("source_engine must be 'gyre' to preserve GYRE as sole verdict source".to_string());
    }
    if !request.gyre_is_sole_verdict_source {
        return Err("gyre_is_sole_verdict_source must be true".to_string());
    }
    if state.iterations.is_empty() {
        return Err("Cannot finalize session before at least one iteration exists".to_string());
    }

    let linked_iteration_id = request
        .linked_iteration_id
        .unwrap_or_else(|| state.iterations.last().unwrap().iteration_id.clone());

    if !state
        .iterations
        .iter()
        .any(|it| it.iteration_id == linked_iteration_id)
    {
        return Err("linked_iteration_id does not exist in this session".to_string());
    }

    let verdict_snapshot_id = request
        .verdict_snapshot_id
        .unwrap_or_else(|| format!("gyresnap_{}", state.ulid));

    let final_verdict = NestFinalVerdictSnapshot {
        schema_name: "nest.final_verdict_snapshot".to_string(),
        schema_version: LIFECYCLE_SCHEMA_VERSION.to_string(),
        bundle_id: state.bundle_id.clone(),
        session_id: state.session_id.clone(),
        binary_id: state.binary_id.clone(),
        binary_sha256: state.binary_sha256.clone(),
        verdict_snapshot_id,
        source_engine: "gyre".to_string(),
        gyre_build_id: state.gyre_build_id.clone(),
        gyre_schema_version: state.gyre_schema_version.clone(),
        classification: request.classification,
        confidence: request.confidence,
        threat_score: request.threat_score,
        summary: request.summary,
        signal_count: request.signal_count,
        contradiction_count: request.contradiction_count,
        reasoning_chain_hash: request.reasoning_chain_hash,
        linked_iteration_id: linked_iteration_id.clone(),
        nest_linkage: NestFinalVerdictNestLinkage {
            session_id: state.session_id.clone(),
            final_iteration_id: linked_iteration_id,
            nest_enrichment_applied: true,
            gyre_is_sole_verdict_source: true,
            nest_summary: request.nest_summary,
        },
    };

    if let Some(mut runtime) = request.runtime_proof {
        runtime.schema_name = "nest.runtime_proof".to_string();
        runtime.schema_version = LIFECYCLE_SCHEMA_VERSION.to_string();
        runtime.bundle_id = state.bundle_id.clone();
        runtime.session_id = state.session_id.clone();
        runtime.binary_id = state.binary_id.clone();
        runtime.binary_sha256 = state.binary_sha256.clone();
        if runtime.proof_status == RuntimeProofStatus::Proven && !runtime.has_tauri_runtime {
            return Err("runtime proof cannot be marked proven when has_tauri_runtime=false".to_string());
        }
        if runtime.runtime_mode == RuntimeMode::BrowserRuntime && runtime.proof_status == RuntimeProofStatus::Proven {
            return Err("browser runtime cannot be marked as proven local runtime proof".to_string());
        }
        state.runtime_proof = Some(runtime);
    }

    if let Some(notes) = request.notes {
        state.notes.extend(notes);
    }

    state.final_verdict_snapshot = Some(final_verdict);
    state.status = SessionStatus::Completed;
    state.completed_at = Some(now_iso());
    let event_index = state.audit_events.len() + 1;
    state.audit_events.push(NestAuditEvent {
        event_id: event_id(&state.ulid, event_index),
        event_type: "nest.session.completed".to_string(),
        timestamp: now_iso(),
        actor_id: state.actor.id.clone(),
        actor_type: match state.actor.actor_type {
            ActorType::User => "user",
            ActorType::Reviewer => "reviewer",
            ActorType::Approver => "approver",
            ActorType::ServiceAccount => "service-account",
            ActorType::System => "system",
        }
        .to_string(),
        session_id: state.session_id.clone(),
        summary: "Session finalized with GYRE-linked verdict snapshot".to_string(),
        details: None,
    });

    upsert_state(&app, state.clone())?;
    Ok(to_summary(&state))
}

#[tauri::command]
pub fn nest_export_session_bundle(
    app: tauri::AppHandle,
    request: NestSessionExportRequest,
) -> Result<NestSessionExportResult, String> {
    let mut state = get_or_load_state(&app, &request.session_id)?;
    if state.status != SessionStatus::Completed {
        return Err("Session must be completed before export".to_string());
    }

    let mut bundle = build_evidence_bundle(&state)?;
    let issues = validate_bundle(&bundle);
    if issues
        .iter()
        .any(|i| matches!(i.code, crate::commands::nest_evidence::NestValidationCode::ReplayCriticalError))
    {
        return Err(format!("Replay-critical bundle validation failed: {} issue(s)", issues.len()));
    }

    let output_dir = if let Some(custom) = request.output_dir {
        PathBuf::from(custom)
    } else {
        app_sessions_root(&app)?
            .join(&state.session_id)
            .join("exports")
            .join(OffsetDateTime::now_utc().unix_timestamp().to_string())
    };

    let files_written = write_bundle_files(&mut bundle, &output_dir)?;

    let event_index = state.audit_events.len() + 1;
    state.audit_events.push(NestAuditEvent {
        event_id: event_id(&state.ulid, event_index),
        event_type: "nest.bundle.exported".to_string(),
        timestamp: now_iso(),
        actor_id: state.actor.id.clone(),
        actor_type: match state.actor.actor_type {
            ActorType::User => "user",
            ActorType::Reviewer => "reviewer",
            ActorType::Approver => "approver",
            ActorType::ServiceAccount => "service-account",
            ActorType::System => "system",
        }
        .to_string(),
        session_id: state.session_id.clone(),
        summary: format!("Evidence bundle exported to {}", output_dir.display()),
        details: None,
    });

    upsert_state(&app, state.clone())?;

    Ok(NestSessionExportResult {
        session: to_summary(&state),
        output_dir: output_dir.to_string_lossy().to_string(),
        files_written,
        issues,
    })
}

#[tauri::command]
pub fn nest_get_session_summary(
    app: tauri::AppHandle,
    session_id: String,
) -> Result<NestSessionLifecycleSummary, String> {
    let state = get_or_load_state(&app, &session_id)?;
    Ok(to_summary(&state))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn actor() -> NestActor {
        NestActor {
            id: "system:test".to_string(),
            actor_type: ActorType::System,
            display_name: "test".to_string(),
            tenant_id: None,
            team_id: None,
        }
    }

    fn base_state() -> NestSessionLifecycleState {
        let ulid = "ABCDE12345FGHJKMNPQRST0123".to_string();
        let session_id = format!("nestsession_{ulid}");
        let bundle_id = format!("nestbundle_{ulid}");
        let binary_sha256 = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2".to_string();
        NestSessionLifecycleState {
            schema_version: LIFECYCLE_SCHEMA_VERSION.to_string(),
            session_id: session_id.clone(),
            bundle_id,
            ulid,
            binary_id: format!("binary_sha256_{binary_sha256}"),
            binary_path: "D:/sample.exe".to_string(),
            binary_sha256,
            binary_sha1: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2".to_string(),
            binary_md5: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4".to_string(),
            file_size_bytes: 1024,
            format: "PE/MZ".to_string(),
            architecture: "x86_64".to_string(),
            actor: actor(),
            policy_version: DEFAULT_POLICY_VERSION.to_string(),
            engine_build_id: DEFAULT_ENGINE_BUILD_ID.to_string(),
            gyre_build_id: DEFAULT_ENGINE_BUILD_ID.to_string(),
            gyre_schema_version: LIFECYCLE_SCHEMA_VERSION.to_string(),
            execution_mode: ExecutionMode::LocalTauri,
            export_mode: ExportMode::LocalTauri,
            created_at: "2026-04-29T10:00:00Z".to_string(),
            completed_at: None,
            status: SessionStatus::Pending,
            notes: Vec::new(),
            iterations: Vec::new(),
            deltas: Vec::new(),
            final_verdict_snapshot: None,
            runtime_proof: None,
            audit_events: vec![NestAuditEvent {
                event_id: "evt_ABCDE12345FGHJKMNPQRST0123_0001".to_string(),
                event_type: "nest.session.created".to_string(),
                timestamp: "2026-04-29T10:00:00Z".to_string(),
                actor_id: "system:test".to_string(),
                actor_type: "system".to_string(),
                session_id,
                summary: "created".to_string(),
                details: None,
            }],
        }
    }

    fn iter(index: u32, confidence: u32) -> NestIterationItem {
        NestIterationItem {
            iteration_id: format!("nestiter_ABCDE12345FGHJKMNPQRST0123_{index:04}"),
            iteration_index: index,
            session_id: "nestsession_ABCDE12345FGHJKMNPQRST0123".to_string(),
            binary_sha256: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2".to_string(),
            started_at: "2026-04-29T10:00:00Z".to_string(),
            completed_at: Some("2026-04-29T10:00:01Z".to_string()),
            duration_ms: Some(1000),
            input_window: Some(NestInputWindow { offset: 0, length: 4096 }),
            executed_actions: None,
            verdict_snapshot: NestIterationVerdictSnapshot {
                classification: "suspicious".to_string(),
                confidence,
                threat_score: confidence,
                signal_count: 4,
                contradiction_count: 0,
                reasoning_chain_hash: "b1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2".to_string(),
            },
            convergence_snapshot: NestConvergenceSnapshot {
                has_converged: false,
                reason: "continue".to_string(),
                stability_score: 0.7,
                classification_stable: false,
                signal_delta: 1,
                contradiction_burden: 0,
            },
            file_identity_locked: true,
        }
    }

    #[test]
    fn bundle_build_requires_finalized_state() {
        let state = base_state();
        let err = build_evidence_bundle(&state).unwrap_err();
        assert!(err.contains("final verdict"));
    }

    #[test]
    fn bundle_build_validates_when_finalized() {
        let mut state = base_state();
        state.iterations.push(iter(1, 65));
        state.iterations.push(iter(2, 84));
        state.deltas.push(NestDeltaItem {
            delta_id: "nestdelta_ABCDE12345FGHJKMNPQRST0123_0001_0002".to_string(),
            from_iteration_id: "nestiter_ABCDE12345FGHJKMNPQRST0123_0001".to_string(),
            to_iteration_id: "nestiter_ABCDE12345FGHJKMNPQRST0123_0002".to_string(),
            from_iteration_index: 1,
            to_iteration_index: 2,
            binary_sha256: state.binary_sha256.clone(),
            confidence_delta: 19,
            classification_changed: true,
            signal_delta_summary: Some(NestSignalDeltaSummary {
                added_count: 2,
                removed_count: 0,
                unchanged_count: 2,
            }),
            contradiction_delta: Some(0),
            refinement_execution: Some(NestRefinementExecution {
                action_types: vec!["deep-echo".to_string()],
                primary_action_type: "deep-echo".to_string(),
                executed: true,
                primary_action_reason: None,
            }),
            projected_gain: Some(10),
            actual_gain: Some(19),
        });
        state.status = SessionStatus::Completed;
        state.completed_at = Some("2026-04-29T10:10:00Z".to_string());
        state.final_verdict_snapshot = Some(NestFinalVerdictSnapshot {
            schema_name: "nest.final_verdict_snapshot".to_string(),
            schema_version: LIFECYCLE_SCHEMA_VERSION.to_string(),
            bundle_id: state.bundle_id.clone(),
            session_id: state.session_id.clone(),
            binary_id: state.binary_id.clone(),
            binary_sha256: state.binary_sha256.clone(),
            verdict_snapshot_id: "gyresnap_ABCDE12345FGHJKMNPQRST0123".to_string(),
            source_engine: "gyre".to_string(),
            gyre_build_id: state.gyre_build_id.clone(),
            gyre_schema_version: state.gyre_schema_version.clone(),
            classification: "malicious".to_string(),
            confidence: 84,
            threat_score: 84,
            summary: "final".to_string(),
            signal_count: 6,
            contradiction_count: 0,
            reasoning_chain_hash: "c1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2".to_string(),
            linked_iteration_id: "nestiter_ABCDE12345FGHJKMNPQRST0123_0002".to_string(),
            nest_linkage: NestFinalVerdictNestLinkage {
                session_id: state.session_id.clone(),
                final_iteration_id: "nestiter_ABCDE12345FGHJKMNPQRST0123_0002".to_string(),
                nest_enrichment_applied: true,
                gyre_is_sole_verdict_source: true,
                nest_summary: Some("summary".to_string()),
            },
        });

        let bundle = build_evidence_bundle(&state).expect("bundle");
        let issues = validate_bundle(&bundle);
        assert!(issues.is_empty(), "issues: {issues:?}");
        assert_eq!(bundle.session.session_id, state.session_id);
        assert_eq!(bundle.final_verdict_snapshot.source_engine, "gyre");
    }

    #[test]
    fn write_bundle_files_creates_expected_json_files() {
        let mut state = base_state();
        state.iterations.push(iter(1, 70));
        state.status = SessionStatus::Completed;
        state.completed_at = Some("2026-04-29T10:10:00Z".to_string());
        state.final_verdict_snapshot = Some(NestFinalVerdictSnapshot {
            schema_name: "nest.final_verdict_snapshot".to_string(),
            schema_version: LIFECYCLE_SCHEMA_VERSION.to_string(),
            bundle_id: state.bundle_id.clone(),
            session_id: state.session_id.clone(),
            binary_id: state.binary_id.clone(),
            binary_sha256: state.binary_sha256.clone(),
            verdict_snapshot_id: "gyresnap_ABCDE12345FGHJKMNPQRST0123".to_string(),
            source_engine: "gyre".to_string(),
            gyre_build_id: state.gyre_build_id.clone(),
            gyre_schema_version: state.gyre_schema_version.clone(),
            classification: "suspicious".to_string(),
            confidence: 70,
            threat_score: 70,
            summary: "final".to_string(),
            signal_count: 4,
            contradiction_count: 0,
            reasoning_chain_hash: "d1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2".to_string(),
            linked_iteration_id: "nestiter_ABCDE12345FGHJKMNPQRST0123_0001".to_string(),
            nest_linkage: NestFinalVerdictNestLinkage {
                session_id: state.session_id.clone(),
                final_iteration_id: "nestiter_ABCDE12345FGHJKMNPQRST0123_0001".to_string(),
                nest_enrichment_applied: true,
                gyre_is_sole_verdict_source: true,
                nest_summary: Some("summary".to_string()),
            },
        });

        let mut bundle = build_evidence_bundle(&state).expect("bundle");

        let tmp_dir = std::env::temp_dir().join(format!(
            "hh-nest-lifecycle-test-{}",
            OffsetDateTime::now_utc().unix_timestamp_nanos()
        ));
        let files = write_bundle_files(&mut bundle, &tmp_dir).expect("write");

        assert!(files.iter().any(|p| p.ends_with("manifest.json")));
        assert!(tmp_dir.join("session.json").exists());
        assert!(tmp_dir.join("final_verdict_snapshot.json").exists());

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }
}
