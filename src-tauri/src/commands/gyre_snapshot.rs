//! Backend recording boundary for renderer-computed GYRE verdicts.
//!
//! Trust model: the main renderer is inside HexHawk's trusted application boundary.
//! Rust does not recompute or cryptographically prove these verdict fields. It records
//! the original renderer GYRE result once, binds it to a binary SHA-256, assigns the
//! snapshot ID, and prevents later NEST/report code from replacing the recorded value.

use once_cell::sync::Lazy;
#[cfg(test)]
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tauri::Manager;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

pub const GYRE_SNAPSHOT_SCHEMA_VERSION: &str = "1.0.0";
pub const GYRE_SNAPSHOT_PROVENANCE: &str = "renderer_gyre_backend_recorded";
pub const SUPPORTED_GYRE_BUILD_ID: &str = "1.0.0+renderer-gyre";
pub const SUPPORTED_GYRE_SCHEMA_VERSION: &str = "1.0.0";
const MAX_SUMMARY_BYTES: usize = 16 * 1024;
const MAX_REASONING_HASH_BYTES: usize = 256;
const MAX_BUILD_ID_BYTES: usize = 128;
const MAX_SCHEMA_VERSION_BYTES: usize = 32;
const MAX_CLIENT_RECORD_KEY_BYTES: usize = 128;
const MAX_SIGNAL_COUNT: u64 = 1_000_000;
const MAX_CONTRADICTION_COUNT: u64 = 1_000_000;
const SNAPSHOT_ID_PREFIX: &str = "gyresnap_";
const SNAPSHOT_ID_SUFFIX_LEN: usize = 26;
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

const CLASSIFICATIONS: &[&str] = &[
    "clean",
    "suspicious",
    "packer",
    "dropper",
    "ransomware-like",
    "info-stealer",
    "rat",
    "loader",
    "wiper",
    "likely-malware",
    "unknown",
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GyreRecordVerdictSnapshotRequest {
    pub client_record_key: String,
    pub binary_sha256: String,
    pub classification: String,
    pub base_confidence: u32,
    pub threat_score: u32,
    pub summary: String,
    pub signal_count: u64,
    pub contradiction_count: u64,
    pub reasoning_chain_hash: String,
    pub gyre_build_id: String,
    pub gyre_schema_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GyreRecordedVerdictSnapshot {
    pub schema_name: String,
    pub schema_version: String,
    pub snapshot_id: String,
    pub provenance: String,
    pub binary_sha256: String,
    pub classification: String,
    pub base_confidence: u32,
    pub threat_score: u32,
    pub summary: String,
    pub signal_count: u64,
    pub contradiction_count: u64,
    pub reasoning_chain_hash: String,
    pub gyre_build_id: String,
    pub gyre_schema_version: String,
    pub created_at: String,
}

type SnapshotCacheKey = (PathBuf, String);

static GYRE_SNAPSHOTS: Lazy<Mutex<HashMap<SnapshotCacheKey, GyreRecordedVerdictSnapshot>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

fn snapshot_cache_key(root: &Path, snapshot_id: &str) -> SnapshotCacheKey {
    (root.to_path_buf(), snapshot_id.to_string())
}

fn now_iso() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

pub(crate) fn snapshot_root(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    Ok(app
        .path()
        .app_data_dir()
        .map_err(|e| format!("Failed to resolve app data directory: {e}"))?
        .join("gyre_snapshots"))
}

fn validate_snapshot_id(snapshot_id: &str) -> Result<(), String> {
    let suffix = snapshot_id
        .strip_prefix(SNAPSHOT_ID_PREFIX)
        .ok_or_else(|| {
            format!(
                "GYRE snapshot ID must match {SNAPSHOT_ID_PREFIX}<26 Crockford Base32 characters>"
            )
        })?;
    if suffix.len() != SNAPSHOT_ID_SUFFIX_LEN
        || !suffix.bytes().all(|byte| CROCKFORD.contains(&byte))
    {
        return Err(format!(
            "GYRE snapshot ID must match {SNAPSHOT_ID_PREFIX}<26 Crockford Base32 characters>"
        ));
    }
    Ok(())
}

fn snapshot_path(root: &Path, snapshot_id: &str) -> Result<PathBuf, String> {
    validate_snapshot_id(snapshot_id)?;
    Ok(root.join(format!("{snapshot_id}.json")))
}

fn valid_lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn ensure_nonempty_bounded(value: &str, max: usize, field: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("{field} must not be empty"));
    }
    if value.len() > max {
        return Err(format!("{field} exceeds {max} bytes"));
    }
    Ok(())
}

fn validate_client_record_key(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > MAX_CLIENT_RECORD_KEY_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return Err(format!(
            "client_record_key must be 1..={MAX_CLIENT_RECORD_KEY_BYTES} ASCII letters, digits, '_' or '-'"
        ));
    }
    Ok(())
}

pub fn validate_record_request(request: &GyreRecordVerdictSnapshotRequest) -> Result<(), String> {
    validate_client_record_key(&request.client_record_key)?;
    if !valid_lower_hex(&request.binary_sha256, 64) {
        return Err(
            "binary_sha256 must be exactly 64 lowercase hexadecimal characters".to_string(),
        );
    }
    if !CLASSIFICATIONS.contains(&request.classification.as_str()) {
        return Err("classification is not a supported BinaryClassification value".to_string());
    }
    if request.base_confidence > 100 {
        return Err("base_confidence must be within 0..=100".to_string());
    }
    if request.threat_score > 100 {
        return Err("threat_score must be within 0..=100".to_string());
    }
    ensure_nonempty_bounded(&request.summary, MAX_SUMMARY_BYTES, "summary")?;
    ensure_nonempty_bounded(
        &request.reasoning_chain_hash,
        MAX_REASONING_HASH_BYTES,
        "reasoning_chain_hash",
    )?;
    if request.signal_count > MAX_SIGNAL_COUNT {
        return Err(format!("signal_count exceeds {MAX_SIGNAL_COUNT}"));
    }
    if request.contradiction_count > MAX_CONTRADICTION_COUNT {
        return Err(format!(
            "contradiction_count exceeds {MAX_CONTRADICTION_COUNT}"
        ));
    }
    ensure_nonempty_bounded(&request.gyre_build_id, MAX_BUILD_ID_BYTES, "gyre_build_id")?;
    ensure_nonempty_bounded(
        &request.gyre_schema_version,
        MAX_SCHEMA_VERSION_BYTES,
        "gyre_schema_version",
    )?;
    Ok(())
}

fn validate_recorded_snapshot(snapshot: &GyreRecordedVerdictSnapshot) -> Result<(), String> {
    validate_snapshot_id(&snapshot.snapshot_id)?;
    if snapshot.schema_name != "gyre.recorded_verdict_snapshot" {
        return Err("Recorded GYRE snapshot schema_name is unsupported".to_string());
    }
    if snapshot.schema_version != GYRE_SNAPSHOT_SCHEMA_VERSION {
        return Err("Recorded GYRE snapshot schema_version is unsupported".to_string());
    }
    if snapshot.provenance != GYRE_SNAPSHOT_PROVENANCE {
        return Err("Recorded GYRE snapshot provenance is unsupported".to_string());
    }
    OffsetDateTime::parse(&snapshot.created_at, &Rfc3339)
        .map_err(|e| format!("Recorded GYRE snapshot created_at is invalid: {e}"))?;
    validate_record_request(&GyreRecordVerdictSnapshotRequest {
        client_record_key: "persisted_snapshot_validation".to_string(),
        binary_sha256: snapshot.binary_sha256.clone(),
        classification: snapshot.classification.clone(),
        base_confidence: snapshot.base_confidence,
        threat_score: snapshot.threat_score,
        summary: snapshot.summary.clone(),
        signal_count: snapshot.signal_count,
        contradiction_count: snapshot.contradiction_count,
        reasoning_chain_hash: snapshot.reasoning_chain_hash.clone(),
        gyre_build_id: snapshot.gyre_build_id.clone(),
        gyre_schema_version: snapshot.gyre_schema_version.clone(),
    })
}

fn snapshot_id_from_bytes(bytes: [u8; 16]) -> String {
    let mut value = u128::from_be_bytes(bytes);
    let mut encoded = [b'0'; 26];
    for index in (0..26).rev() {
        encoded[index] = CROCKFORD[(value & 31) as usize];
        value >>= 5;
    }
    encoded[0] = CROCKFORD[(bytes[0] >> 5) as usize];
    format!("gyresnap_{}", String::from_utf8_lossy(&encoded))
}

fn snapshot_id_for_client_record_key(client_record_key: &str) -> String {
    let digest = Sha256::digest(client_record_key.as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    snapshot_id_from_bytes(bytes)
}

#[cfg(test)]
fn generate_snapshot_id() -> String {
    let mut bytes = [0_u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    snapshot_id_from_bytes(bytes)
}

pub fn build_recorded_snapshot(
    request: GyreRecordVerdictSnapshotRequest,
    snapshot_id: String,
    created_at: String,
) -> Result<GyreRecordedVerdictSnapshot, String> {
    validate_record_request(&request)?;
    let snapshot = GyreRecordedVerdictSnapshot {
        schema_name: "gyre.recorded_verdict_snapshot".to_string(),
        schema_version: GYRE_SNAPSHOT_SCHEMA_VERSION.to_string(),
        snapshot_id,
        provenance: GYRE_SNAPSHOT_PROVENANCE.to_string(),
        binary_sha256: request.binary_sha256,
        classification: request.classification,
        base_confidence: request.base_confidence,
        threat_score: request.threat_score,
        summary: request.summary,
        signal_count: request.signal_count,
        contradiction_count: request.contradiction_count,
        reasoning_chain_hash: request.reasoning_chain_hash,
        gyre_build_id: request.gyre_build_id,
        gyre_schema_version: request.gyre_schema_version,
        created_at,
    };
    validate_recorded_snapshot(&snapshot)?;
    Ok(snapshot)
}

fn snapshot_matches_request(
    snapshot: &GyreRecordedVerdictSnapshot,
    request: &GyreRecordVerdictSnapshotRequest,
) -> bool {
    snapshot.binary_sha256 == request.binary_sha256
        && snapshot.classification == request.classification
        && snapshot.base_confidence == request.base_confidence
        && snapshot.threat_score == request.threat_score
        && snapshot.summary == request.summary
        && snapshot.signal_count == request.signal_count
        && snapshot.contradiction_count == request.contradiction_count
        && snapshot.reasoning_chain_hash == request.reasoning_chain_hash
        && snapshot.gyre_build_id == request.gyre_build_id
        && snapshot.gyre_schema_version == request.gyre_schema_version
}

fn replay_or_conflict(
    existing: GyreRecordedVerdictSnapshot,
    request: &GyreRecordVerdictSnapshotRequest,
) -> Result<GyreRecordedVerdictSnapshot, String> {
    validate_recorded_snapshot(&existing)?;
    if snapshot_matches_request(&existing, request) {
        return Ok(existing);
    }
    Err("client_record_key conflicts with a different persisted GYRE snapshot payload".to_string())
}

#[derive(Debug)]
enum PersistSnapshotError {
    AlreadyExists,
    Other(String),
}

fn persist_snapshot(
    root: &Path,
    snapshot: &GyreRecordedVerdictSnapshot,
) -> Result<(), PersistSnapshotError> {
    validate_recorded_snapshot(snapshot).map_err(PersistSnapshotError::Other)?;
    std::fs::create_dir_all(root).map_err(|e| {
        PersistSnapshotError::Other(format!("Failed to create GYRE snapshot directory: {e}"))
    })?;
    let path = snapshot_path(root, &snapshot.snapshot_id).map_err(PersistSnapshotError::Other)?;
    let body = serde_json::to_vec_pretty(snapshot).map_err(|e| {
        PersistSnapshotError::Other(format!("Failed to serialize GYRE snapshot: {e}"))
    })?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    let mut file = match options.open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(PersistSnapshotError::AlreadyExists);
        }
        Err(error) => {
            return Err(PersistSnapshotError::Other(format!(
                "Failed to create immutable GYRE snapshot {}: {error}",
                path.display()
            )));
        }
    };
    use std::io::Write;
    file.write_all(&body).map_err(|e| {
        PersistSnapshotError::Other(format!(
            "Failed to persist GYRE snapshot {}: {e}",
            path.display()
        ))
    })
}

fn insert_snapshot_in_memory_at_root(
    root: &Path,
    snapshot: GyreRecordedVerdictSnapshot,
) -> Result<(), String> {
    validate_recorded_snapshot(&snapshot)?;
    let key = snapshot_cache_key(root, &snapshot.snapshot_id);
    let mut snapshots = GYRE_SNAPSHOTS.lock().unwrap();
    if let Some(existing) = snapshots.get(&key) {
        if existing == &snapshot {
            return Ok(());
        }
        return Err(
            "GYRE snapshot ID already exists; recorded snapshots are immutable".to_string(),
        );
    }
    snapshots.insert(key, snapshot);
    Ok(())
}

pub fn insert_snapshot_in_memory(snapshot: GyreRecordedVerdictSnapshot) -> Result<(), String> {
    insert_snapshot_in_memory_at_root(Path::new(""), snapshot)
}

pub(crate) fn resolve_recorded_snapshot_at_root(
    root: &Path,
    snapshot_id: &str,
) -> Result<GyreRecordedVerdictSnapshot, String> {
    validate_snapshot_id(snapshot_id)?;
    let key = snapshot_cache_key(root, snapshot_id);
    if let Some(snapshot) = GYRE_SNAPSHOTS.lock().unwrap().get(&key).cloned() {
        validate_recorded_snapshot(&snapshot)?;
        return Ok(snapshot);
    }
    let path = snapshot_path(root, snapshot_id)?;
    let text = std::fs::read_to_string(&path)
        .map_err(|_| format!("Unknown GYRE snapshot ID: {snapshot_id}"))?;
    let snapshot: GyreRecordedVerdictSnapshot = serde_json::from_str(&text)
        .map_err(|e| format!("Failed to parse recorded GYRE snapshot: {e}"))?;
    if snapshot.snapshot_id != snapshot_id {
        return Err("Recorded GYRE snapshot ID does not match its storage key".to_string());
    }
    validate_recorded_snapshot(&snapshot)?;
    insert_snapshot_in_memory_at_root(root, snapshot.clone())?;
    Ok(snapshot)
}

pub fn resolve_recorded_snapshot(
    app: &tauri::AppHandle,
    snapshot_id: &str,
) -> Result<GyreRecordedVerdictSnapshot, String> {
    resolve_recorded_snapshot_at_root(&snapshot_root(app)?, snapshot_id)
}

pub(crate) fn record_verdict_snapshot_at_root(
    root: &Path,
    request: GyreRecordVerdictSnapshotRequest,
) -> Result<GyreRecordedVerdictSnapshot, String> {
    validate_record_request(&request)?;
    let snapshot_id = snapshot_id_for_client_record_key(&request.client_record_key);
    let key = snapshot_cache_key(root, &snapshot_id);

    if let Some(existing) = GYRE_SNAPSHOTS.lock().unwrap().get(&key).cloned() {
        return replay_or_conflict(existing, &request);
    }

    let snapshot = build_recorded_snapshot(request.clone(), snapshot_id.clone(), now_iso())?;
    match persist_snapshot(root, &snapshot) {
        Ok(()) => {
            insert_snapshot_in_memory_at_root(root, snapshot.clone())?;
            Ok(snapshot)
        }
        Err(PersistSnapshotError::AlreadyExists) => {
            let existing = resolve_recorded_snapshot_at_root(root, &snapshot_id)?;
            replay_or_conflict(existing, &request)
        }
        Err(PersistSnapshotError::Other(error)) => Err(error),
    }
}

#[tauri::command]
pub fn gyre_record_verdict_snapshot(
    app: tauri::AppHandle,
    request: GyreRecordVerdictSnapshotRequest,
) -> Result<GyreRecordedVerdictSnapshot, String> {
    record_verdict_snapshot_at_root(&snapshot_root(&app)?, request)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_request() -> GyreRecordVerdictSnapshotRequest {
        GyreRecordVerdictSnapshotRequest {
            client_record_key: "gyrerecord_test".to_string(),
            binary_sha256: "a".repeat(64),
            classification: "suspicious".to_string(),
            base_confidence: 67,
            threat_score: 42,
            summary: "Renderer-computed GYRE summary".to_string(),
            signal_count: 7,
            contradiction_count: 1,
            reasoning_chain_hash: "b".repeat(64),
            gyre_build_id: "1.0.0+renderer-gyre".to_string(),
            gyre_schema_version: "1.0.0".to_string(),
        }
    }

    #[test]
    fn recording_builds_backend_owned_snapshot_id_and_explicit_provenance() {
        let snapshot = build_recorded_snapshot(
            valid_request(),
            generate_snapshot_id(),
            "2026-07-11T00:00:00Z".to_string(),
        )
        .unwrap();
        assert!(snapshot.snapshot_id.starts_with("gyresnap_"));
        assert_eq!(snapshot.snapshot_id.len(), "gyresnap_".len() + 26);
        assert_eq!(snapshot.provenance, "renderer_gyre_backend_recorded");
        assert_eq!(snapshot.binary_sha256, "a".repeat(64));
    }

    #[test]
    fn recorded_snapshot_cannot_be_overwritten() {
        let snapshot_id = generate_snapshot_id();
        let first = build_recorded_snapshot(
            valid_request(),
            snapshot_id.clone(),
            "2026-07-11T00:00:00Z".to_string(),
        )
        .unwrap();
        insert_snapshot_in_memory(first).unwrap();

        let mut replacement_request = valid_request();
        replacement_request.classification = "clean".to_string();
        let replacement = build_recorded_snapshot(
            replacement_request,
            snapshot_id,
            "2026-07-11T00:00:01Z".to_string(),
        )
        .unwrap();
        let error = insert_snapshot_in_memory(replacement).unwrap_err();
        assert!(error.contains("immutable"));
    }

    #[test]
    fn invalid_classification_and_ranges_are_rejected() {
        let mut request = valid_request();
        request.classification = "made-up".to_string();
        assert!(validate_record_request(&request)
            .unwrap_err()
            .contains("BinaryClassification"));

        let mut request = valid_request();
        request.base_confidence = 101;
        assert!(validate_record_request(&request)
            .unwrap_err()
            .contains("base_confidence"));

        let mut request = valid_request();
        request.threat_score = 101;
        assert!(validate_record_request(&request)
            .unwrap_err()
            .contains("threat_score"));

        for invalid in ["", "has space", "slash/key", "dot.key", "percent%key"] {
            let mut request = valid_request();
            request.client_record_key = invalid.to_string();
            assert!(validate_record_request(&request)
                .unwrap_err()
                .contains("client_record_key"));
        }

        let mut request = valid_request();
        request.client_record_key = "a".repeat(MAX_CLIENT_RECORD_KEY_BYTES + 1);
        assert!(validate_record_request(&request)
            .unwrap_err()
            .contains("client_record_key"));
    }

    fn temp_root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "hexhawk-gyre-{label}-{}",
            OffsetDateTime::now_utc().unix_timestamp_nanos()
        ))
    }

    fn remove_from_memory(root: &Path, snapshot_id: &str) {
        GYRE_SNAPSHOTS
            .lock()
            .unwrap()
            .remove(&snapshot_cache_key(root, snapshot_id));
    }

    fn is_cached(root: &Path, snapshot_id: &str) -> bool {
        GYRE_SNAPSHOTS
            .lock()
            .unwrap()
            .contains_key(&snapshot_cache_key(root, snapshot_id))
    }

    fn write_raw_snapshot(root: &Path, storage_id: &str, snapshot: &GyreRecordedVerdictSnapshot) {
        std::fs::create_dir_all(root).unwrap();
        let path = snapshot_path(root, storage_id).unwrap();
        std::fs::write(path, serde_json::to_vec_pretty(snapshot).unwrap()).unwrap();
    }

    #[test]
    fn snapshot_id_validator_accepts_only_generated_grammar() {
        let valid = generate_snapshot_id();
        validate_snapshot_id(&valid).unwrap();
        for invalid in [
            "",
            "snapshot_0123456789ABCDEFGHJKMNPQRS",
            "gyresnap_0123456789ABCDEFGHJKMNPQR",
            "gyresnap_0123456789ABCDEFGHJKMNPQRST",
            "gyresnap_0123456789abcdefghjkmnpqrs",
            "gyresnap_../0123456789ABCDEFGHJKMN",
            "gyresnap_\\0123456789ABCDEFGHJKMNP",
            "gyresnap_0123456789ABCDEFGHJKMNP.R",
            "gyresnap_0123456789ABCDEFGHJKMNP%R",
            "gyresnap_0123456789ABCDEFGHJKMNPQRS.json",
            "gyresnap_0123456789ABCDEFGHJKMNPQR ",
            "gyresnap_0123456789ABCDEFGHJKMNPQ\n",
        ] {
            assert!(
                validate_snapshot_id(invalid).is_err(),
                "accepted {invalid:?}"
            );
        }
    }

    #[test]
    fn recording_persists_and_resolves_after_memory_is_cleared() {
        let root = temp_root("record-resolve");
        let snapshot = record_verdict_snapshot_at_root(&root, valid_request()).unwrap();
        validate_snapshot_id(&snapshot.snapshot_id).unwrap();
        assert!(snapshot_path(&root, &snapshot.snapshot_id)
            .unwrap()
            .exists());
        remove_from_memory(&root, &snapshot.snapshot_id);

        let resolved = resolve_recorded_snapshot_at_root(&root, &snapshot.snapshot_id).unwrap();
        assert_eq!(resolved, snapshot);
        remove_from_memory(&root, &snapshot.snapshot_id);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn persisted_malformed_verdict_fields_are_rejected() {
        for (label, mutate, expected) in [
            (
                "classification",
                (|snapshot: &mut GyreRecordedVerdictSnapshot| {
                    snapshot.classification = "made-up".to_string();
                }) as fn(&mut GyreRecordedVerdictSnapshot),
                "BinaryClassification",
            ),
            (
                "confidence",
                (|snapshot: &mut GyreRecordedVerdictSnapshot| snapshot.base_confidence = 101)
                    as fn(&mut GyreRecordedVerdictSnapshot),
                "base_confidence",
            ),
            (
                "threat-score",
                (|snapshot: &mut GyreRecordedVerdictSnapshot| snapshot.threat_score = 101)
                    as fn(&mut GyreRecordedVerdictSnapshot),
                "threat_score",
            ),
            (
                "provenance",
                (|snapshot: &mut GyreRecordedVerdictSnapshot| {
                    snapshot.provenance = "backend_computed".to_string();
                }) as fn(&mut GyreRecordedVerdictSnapshot),
                "provenance",
            ),
            (
                "sha256",
                (|snapshot: &mut GyreRecordedVerdictSnapshot| {
                    snapshot.binary_sha256 = "not-a-sha256".to_string();
                }) as fn(&mut GyreRecordedVerdictSnapshot),
                "binary_sha256",
            ),
        ] {
            let root = temp_root(label);
            let mut snapshot = build_recorded_snapshot(
                valid_request(),
                generate_snapshot_id(),
                "2026-07-11T00:00:00Z".to_string(),
            )
            .unwrap();
            mutate(&mut snapshot);
            write_raw_snapshot(&root, &snapshot.snapshot_id, &snapshot);
            let error =
                resolve_recorded_snapshot_at_root(&root, &snapshot.snapshot_id).unwrap_err();
            assert!(error.contains(expected), "{label}: {error}");
            assert!(!is_cached(&root, &snapshot.snapshot_id));
            let _ = std::fs::remove_dir_all(root);
        }
    }

    #[test]
    fn invalid_persisted_json_is_rejected_without_caching() {
        let root = temp_root("invalid-json");
        let snapshot_id = generate_snapshot_id();
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            snapshot_path(&root, &snapshot_id).unwrap(),
            b"{not valid json",
        )
        .unwrap();

        let error = resolve_recorded_snapshot_at_root(&root, &snapshot_id).unwrap_err();
        assert!(error.contains("Failed to parse recorded GYRE snapshot"));
        assert!(!is_cached(&root, &snapshot_id));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn persisted_snapshot_id_must_match_storage_key() {
        let root = temp_root("id-mismatch");
        let requested_id = generate_snapshot_id();
        let stored = build_recorded_snapshot(
            valid_request(),
            generate_snapshot_id(),
            "2026-07-11T00:00:00Z".to_string(),
        )
        .unwrap();
        assert_ne!(requested_id, stored.snapshot_id);
        write_raw_snapshot(&root, &requested_id, &stored);

        let error = resolve_recorded_snapshot_at_root(&root, &requested_id).unwrap_err();
        assert!(error.contains("does not match its storage key"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn traversal_id_is_rejected_before_filesystem_access() {
        let root = temp_root("must-not-be-created");
        let error = resolve_recorded_snapshot_at_root(&root, "gyresnap_../../outside").unwrap_err();
        assert!(error.contains("must match"));
        assert!(!root.exists());
    }

    #[test]
    fn existing_snapshot_file_cannot_be_overwritten() {
        let root = temp_root("overwrite");
        let snapshot = build_recorded_snapshot(
            valid_request(),
            generate_snapshot_id(),
            "2026-07-11T00:00:00Z".to_string(),
        )
        .unwrap();
        persist_snapshot(&root, &snapshot).unwrap();
        assert!(matches!(
            persist_snapshot(&root, &snapshot),
            Err(PersistSnapshotError::AlreadyExists)
        ));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn recording_replay_returns_same_snapshot_after_memory_is_cleared() {
        let root = temp_root("idempotent-replay");
        let request = valid_request();
        let first = record_verdict_snapshot_at_root(&root, request.clone()).unwrap();
        remove_from_memory(&root, &first.snapshot_id);

        let replay = record_verdict_snapshot_at_root(&root, request).unwrap();
        assert_eq!(replay, first);

        let json_count = std::fs::read_dir(&root)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry.path().extension().and_then(|value| value.to_str()) == Some("json")
            })
            .count();
        assert_eq!(json_count, 1);

        remove_from_memory(&root, &first.snapshot_id);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn same_deterministic_snapshot_id_is_independent_across_roots() {
        let first_root = temp_root("root-scope-first");
        let second_root = temp_root("root-scope-second");
        let first = record_verdict_snapshot_at_root(&first_root, valid_request()).unwrap();

        let mut second_request = valid_request();
        second_request.threat_score = 99;
        let second = record_verdict_snapshot_at_root(&second_root, second_request).unwrap();

        assert_eq!(second.snapshot_id, first.snapshot_id);
        assert_ne!(second.threat_score, first.threat_score);
        assert!(is_cached(&first_root, &first.snapshot_id));
        assert!(is_cached(&second_root, &second.snapshot_id));
        assert_eq!(
            resolve_recorded_snapshot_at_root(&first_root, &first.snapshot_id).unwrap(),
            first
        );
        assert_eq!(
            resolve_recorded_snapshot_at_root(&second_root, &second.snapshot_id).unwrap(),
            second
        );

        remove_from_memory(&first_root, &first.snapshot_id);
        remove_from_memory(&second_root, &second.snapshot_id);
        let _ = std::fs::remove_dir_all(first_root);
        let _ = std::fs::remove_dir_all(second_root);
    }

    #[test]
    fn reused_client_record_key_with_different_payload_is_rejected() {
        let root = temp_root("idempotent-conflict");
        let first = record_verdict_snapshot_at_root(&root, valid_request()).unwrap();

        let mut conflict = valid_request();
        conflict.threat_score = 99;
        let error = record_verdict_snapshot_at_root(&root, conflict).unwrap_err();
        assert!(error.contains("client_record_key conflicts"));

        remove_from_memory(&root, &first.snapshot_id);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn unknown_valid_snapshot_id_is_rejected() {
        let root = temp_root("unknown");
        let snapshot_id = generate_snapshot_id();
        let error = resolve_recorded_snapshot_at_root(&root, &snapshot_id).unwrap_err();
        assert!(error.contains("Unknown GYRE snapshot ID"));
        assert!(!is_cached(&root, &snapshot_id));
    }
}
