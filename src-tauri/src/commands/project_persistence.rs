//! Versioned project manifests which reference the authoritative GYRE snapshot and
//! optional advisory NEST lifecycle stores. Verdict fields are never copied into a
//! project manifest: opening always resolves the immutable GYRE snapshot.
use crate::commands::gyre_snapshot::{
    resolve_recorded_snapshot_at_root, snapshot_root, GyreRecordedVerdictSnapshot,
    SUPPORTED_GYRE_BUILD_ID, SUPPORTED_GYRE_SCHEMA_VERSION,
};
use crate::commands::nest_session_lifecycle::{
    resolve_project_nest_linkage_at_root, NestProjectLinkage,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use tauri::Manager;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

pub const PROJECT_SCHEMA_VERSION: &str = "1.0.0";
const MAX_MANIFEST_BYTES: u64 = 256 * 1024;
const MAX_ERROR_BYTES: usize = 500;
const MAX_NAME_BYTES: usize = 256;
const PROJECT_PREFIX: &str = "hhproj_";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProjectBinaryIdentity {
    pub original_path: String,
    pub file_name: String,
    pub size_bytes: u64,
    pub sha256: String,
    pub partial_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProjectGyreLinkage {
    pub snapshot_id: String,
    pub binary_sha256: String,
    pub gyre_build_id: String,
    pub gyre_schema_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProjectManifest {
    pub schema_name: String,
    pub schema_version: String,
    pub project_id: String,
    pub name: String,
    pub created_at: String,
    pub updated_at: String,
    pub binary: ProjectBinaryIdentity,
    pub gyre: ProjectGyreLinkage,
    pub nest: Option<NestProjectLinkage>,
    pub verdict_authority: String,
    pub nest_role: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SaveProjectRequest {
    pub project_id: String,
    pub name: String,
    pub binary_path: String,
    pub gyre_snapshot_id: String,
    pub nest: Option<NestProjectLinkage>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenProjectRequest {
    pub project_id: String,
    pub selected_binary_path: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolvedProject {
    pub manifest: ProjectManifest,
    pub resolved_binary_path: String,
    pub binary_was_reselected: bool,
    pub gyre_snapshot: GyreRecordedVerdictSnapshot,
    pub nest: Option<NestProjectLinkage>,
    pub verdict_authority: String,
    pub nest_role: String,
}

fn bounded(context: &str, error: impl std::fmt::Display) -> String {
    let value = format!("{context}: {error}").replace(['\r', '\n', '\t'], " ");
    if value.len() <= MAX_ERROR_BYTES {
        value
    } else {
        format!("{}…", &value[..MAX_ERROR_BYTES])
    }
}

fn valid_id(id: &str) -> bool {
    id.strip_prefix(PROJECT_PREFIX).is_some_and(|tail| {
        (8..=64).contains(&tail.len())
            && tail
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    })
}

fn validate_project_id(id: &str) -> Result<(), String> {
    if valid_id(id) {
        Ok(())
    } else {
        Err("project_id must match hhproj_<8..64 ASCII letters, digits, '_' or '-'>".into())
    }
}

fn valid_sha(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn projects_root(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    Ok(app
        .path()
        .app_data_dir()
        .map_err(|e| bounded("Failed to resolve app data directory", e))?
        .join("projects"))
}

fn project_path(root: &Path, id: &str) -> Result<PathBuf, String> {
    validate_project_id(id)?; // must precede all path use
    Ok(root.join(format!("{id}.json")))
}

fn now() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into())
}

fn hash_file(path: &Path) -> Result<ProjectBinaryIdentity, String> {
    let mut file = fs::File::open(path).map_err(|e| bounded("Failed to read project binary", e))?;
    let size = file
        .metadata()
        .map_err(|e| bounded("Failed to inspect project binary", e))?
        .len();
    let mut full = Sha256::new();
    let mut first = Vec::new();
    let mut last = Vec::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|e| bounded("Failed to hash project binary", e))?;
        if count == 0 {
            break;
        }
        full.update(&buffer[..count]);
        if first.len() < 64 * 1024 {
            first.extend_from_slice(&buffer[..count.min(64 * 1024 - first.len())]);
        }
        last.extend_from_slice(&buffer[..count]);
        if last.len() > 64 * 1024 {
            last.drain(..last.len() - 64 * 1024);
        }
    }
    let mut partial = Sha256::new();
    partial.update(size.to_le_bytes());
    partial.update(&first);
    partial.update(&last);
    Ok(ProjectBinaryIdentity {
        original_path: path.to_string_lossy().to_string(),
        file_name: path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("binary")
            .to_string(),
        size_bytes: size,
        sha256: format!("{:x}", full.finalize()),
        partial_sha256: format!("{:x}", partial.finalize()),
    })
}

fn validate_manifest(manifest: &ProjectManifest) -> Result<(), String> {
    validate_project_id(&manifest.project_id)?;
    if manifest.schema_name != "hexhawk.project" {
        return Err("Unsupported project schema_name".into());
    }
    if manifest.schema_version != PROJECT_SCHEMA_VERSION {
        return Err("Unsupported project schema_version".into());
    }
    if manifest.name.trim().is_empty() || manifest.name.len() > MAX_NAME_BYTES {
        return Err("Project name must be 1..=256 bytes".into());
    }
    OffsetDateTime::parse(&manifest.created_at, &Rfc3339)
        .map_err(|e| bounded("Invalid project created_at", e))?;
    OffsetDateTime::parse(&manifest.updated_at, &Rfc3339)
        .map_err(|e| bounded("Invalid project updated_at", e))?;
    if !valid_sha(&manifest.binary.sha256)
        || !valid_sha(&manifest.binary.partial_sha256)
        || !valid_sha(&manifest.gyre.binary_sha256)
    {
        return Err("Project hash fields must be lowercase SHA-256".into());
    }
    if manifest.binary.sha256 != manifest.gyre.binary_sha256 {
        return Err("Project binary/GYRE hash linkage mismatch".into());
    }
    if manifest.gyre.gyre_build_id != SUPPORTED_GYRE_BUILD_ID
        || manifest.gyre.gyre_schema_version != SUPPORTED_GYRE_SCHEMA_VERSION
    {
        return Err("Unsupported project GYRE build or schema".into());
    }
    if manifest.verdict_authority != "GYRE" || manifest.nest_role != "advisory" {
        return Err("Project authority declaration is invalid".into());
    }
    Ok(())
}

#[cfg(windows)]
fn replace_file_atomically(temp: &Path, path: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };

    let temp_wide: Vec<u16> = temp.as_os_str().encode_wide().chain(Some(0)).collect();

    let path_wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();

    let flags = MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH;
    let result = unsafe { MoveFileExW(temp_wide.as_ptr(), path_wide.as_ptr(), flags) };

    if result == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
fn replace_file_atomically(temp: &Path, path: &Path) -> std::io::Result<()> {
    fs::rename(temp, path)
}

fn atomic_replace(path: &Path, body: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "Project path has no parent".to_string())?;

    fs::create_dir_all(parent).map_err(|e| bounded("Failed to create project directory", e))?;

    let temp = parent.join(format!(
        ".{}.tmp",
        path.file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("project")
    ));

    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)
            .map_err(|e| bounded("Failed to create atomic project temporary file", e))?;

        file.write_all(body)
            .map_err(|e| bounded("Failed to write project", e))?;

        file.sync_all()
            .map_err(|e| bounded("Failed to sync project", e))?;

        drop(file);

        replace_file_atomically(&temp, path)
            .map_err(|e| bounded("Failed to atomically replace project", e))?;

        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }

    result
}

pub(crate) fn save_project_at_roots(
    project_root: &Path,
    gyre_root: &Path,
    nest_root: &Path,
    request: SaveProjectRequest,
) -> Result<ProjectManifest, String> {
    validate_project_id(&request.project_id)?;
    let path = project_path(project_root, &request.project_id)?;
    let binary = hash_file(Path::new(&request.binary_path))?;
    let gyre = resolve_recorded_snapshot_at_root(gyre_root, &request.gyre_snapshot_id)?;
    if gyre.binary_sha256 != binary.sha256 {
        return Err("Selected binary does not match the persisted GYRE snapshot SHA-256".into());
    }
    if gyre.gyre_build_id != SUPPORTED_GYRE_BUILD_ID
        || gyre.gyre_schema_version != SUPPORTED_GYRE_SCHEMA_VERSION
    {
        return Err("Persisted GYRE snapshot build or schema is unsupported".into());
    }
    let nest = match request.nest {
        Some(link) => Some(resolve_project_nest_linkage_at_root(
            nest_root,
            &link,
            &binary.sha256,
            &gyre.snapshot_id,
        )?),
        None => None,
    };
    let timestamp = now();
    let created_at = if path.exists() {
        read_manifest(&path)?.created_at
    } else {
        timestamp.clone()
    };
    let manifest = ProjectManifest {
        schema_name: "hexhawk.project".into(),
        schema_version: PROJECT_SCHEMA_VERSION.into(),
        project_id: request.project_id,
        name: request.name,
        created_at,
        updated_at: timestamp,
        binary,
        gyre: ProjectGyreLinkage {
            snapshot_id: gyre.snapshot_id,
            binary_sha256: gyre.binary_sha256,
            gyre_build_id: gyre.gyre_build_id,
            gyre_schema_version: gyre.gyre_schema_version,
        },
        nest,
        verdict_authority: "GYRE".into(),
        nest_role: "advisory".into(),
    };
    validate_manifest(&manifest)?;
    let body = serde_json::to_vec_pretty(&manifest)
        .map_err(|e| bounded("Failed to serialize project", e))?;
    atomic_replace(&path, &body)?;
    Ok(manifest)
}

fn read_manifest(path: &Path) -> Result<ProjectManifest, String> {
    let metadata = fs::metadata(path).map_err(|e| bounded("Project manifest is missing", e))?;
    if metadata.len() > MAX_MANIFEST_BYTES {
        return Err("Project manifest exceeds 262144 bytes".into());
    }
    let bytes = fs::read(path).map_err(|e| bounded("Failed to read project manifest", e))?;
    let manifest: ProjectManifest =
        serde_json::from_slice(&bytes).map_err(|e| bounded("Project manifest is malformed", e))?;
    validate_manifest(&manifest)?;
    Ok(manifest)
}

pub(crate) fn open_project_at_roots(
    project_root: &Path,
    gyre_root: &Path,
    nest_root: &Path,
    request: OpenProjectRequest,
) -> Result<ResolvedProject, String> {
    validate_project_id(&request.project_id)?;
    let manifest = read_manifest(&project_path(project_root, &request.project_id)?)?;
    if manifest.project_id != request.project_id {
        return Err("Project manifest ID does not match its storage key".into());
    }
    let original = PathBuf::from(&manifest.binary.original_path);
    let selected = request.selected_binary_path.as_ref().map(PathBuf::from);
    let candidate = selected.as_deref().unwrap_or(&original);
    let identity = hash_file(candidate)?;
    if identity.size_bytes != manifest.binary.size_bytes
        || identity.partial_sha256 != manifest.binary.partial_sha256
        || identity.sha256 != manifest.binary.sha256
    {
        return Err("Project binary identity changed; opening is blocked".into());
    }
    let gyre = resolve_recorded_snapshot_at_root(gyre_root, &manifest.gyre.snapshot_id)?;
    if gyre.binary_sha256 != manifest.binary.sha256
        || gyre.binary_sha256 != manifest.gyre.binary_sha256
        || gyre.gyre_build_id != manifest.gyre.gyre_build_id
        || gyre.gyre_schema_version != manifest.gyre.gyre_schema_version
    {
        return Err("Persisted GYRE snapshot does not match project linkage".into());
    }
    let nest = match &manifest.nest {
        Some(link) => Some(resolve_project_nest_linkage_at_root(
            nest_root,
            link,
            &manifest.binary.sha256,
            &gyre.snapshot_id,
        )?),
        None => None,
    };
    Ok(ResolvedProject {
        binary_was_reselected: selected.is_some() && candidate != original,
        resolved_binary_path: candidate.to_string_lossy().to_string(),
        nest,
        gyre_snapshot: gyre,
        verdict_authority: "GYRE".into(),
        nest_role: "advisory".into(),
        manifest,
    })
}

#[tauri::command]
pub fn save_project(
    app: tauri::AppHandle,
    request: SaveProjectRequest,
) -> Result<ProjectManifest, String> {
    let app_data = app
        .path()
        .app_data_dir()
        .map_err(|e| bounded("Failed to resolve app data directory", e))?;
    save_project_at_roots(
        &projects_root(&app)?,
        &snapshot_root(&app)?,
        &app_data.join("nest_sessions"),
        request,
    )
}

#[tauri::command]
pub fn open_project(
    app: tauri::AppHandle,
    request: OpenProjectRequest,
) -> Result<ResolvedProject, String> {
    let app_data = app
        .path()
        .app_data_dir()
        .map_err(|e| bounded("Failed to resolve app data directory", e))?;
    open_project_at_roots(
        &projects_root(&app)?,
        &snapshot_root(&app)?,
        &app_data.join("nest_sessions"),
        request,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::gyre_snapshot::{
        clear_snapshot_cache_for_tests, record_verdict_snapshot_at_root,
        GyreRecordVerdictSnapshotRequest,
    };
    fn root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "hh-project-{label}-{}",
            OffsetDateTime::now_utc().unix_timestamp_nanos()
        ))
    }
    fn snapshot(root: &Path, hash: &str) -> GyreRecordedVerdictSnapshot {
        record_verdict_snapshot_at_root(
            root,
            GyreRecordVerdictSnapshotRequest {
                client_record_key: "shared_record_key".into(),
                binary_sha256: hash.into(),
                classification: "suspicious".into(),
                base_confidence: 70,
                threat_score: 60,
                summary: "authoritative".into(),
                signal_count: 2,
                contradiction_count: 0,
                reasoning_chain_hash: "b".repeat(64),
                gyre_build_id: SUPPORTED_GYRE_BUILD_ID.into(),
                gyre_schema_version: SUPPORTED_GYRE_SCHEMA_VERSION.into(),
            },
        )
        .unwrap()
    }
    fn setup(
        label: &str,
    ) -> (
        PathBuf,
        PathBuf,
        PathBuf,
        PathBuf,
        GyreRecordedVerdictSnapshot,
    ) {
        let p = root(label);
        let g = root(&format!("{label}-g"));
        let n = root(&format!("{label}-n"));
        fs::create_dir_all(&p).unwrap();
        let bin = p.join("sample.bin");
        fs::write(&bin, b"identical binary bytes").unwrap();
        let id = hash_file(&bin).unwrap();
        let snap = snapshot(&g, &id.sha256);
        (p, g, n, bin, snap)
    }
    fn request(bin: &Path, snap: &GyreRecordedVerdictSnapshot) -> SaveProjectRequest {
        SaveProjectRequest {
            project_id: "hhproj_12345678".into(),
            name: "Test project".into(),
            binary_path: bin.to_string_lossy().into(),
            gyre_snapshot_id: snap.snapshot_id.clone(),
            nest: None,
        }
    }
    #[test]
    fn save_open_survives_cache_clear_and_uses_resolved_snapshot() {
        let (p, g, n, b, s) = setup("restart");
        save_project_at_roots(&p, &g, &n, request(&b, &s)).unwrap();
        clear_snapshot_cache_for_tests();
        let opened = open_project_at_roots(
            &p,
            &g,
            &n,
            OpenProjectRequest {
                project_id: "hhproj_12345678".into(),
                selected_binary_path: None,
            },
        )
        .unwrap();
        assert_eq!(opened.gyre_snapshot, s);
        assert_eq!(opened.verdict_authority, "GYRE");
    }
    #[test]
    fn moved_identical_reselection_is_allowed_but_changed_file_is_rejected() {
        let (p, g, n, b, s) = setup("move");
        save_project_at_roots(&p, &g, &n, request(&b, &s)).unwrap();
        let moved = p.join("moved.bin");
        fs::copy(&b, &moved).unwrap();
        fs::remove_file(&b).unwrap();
        let opened = open_project_at_roots(
            &p,
            &g,
            &n,
            OpenProjectRequest {
                project_id: "hhproj_12345678".into(),
                selected_binary_path: Some(moved.to_string_lossy().into()),
            },
        )
        .unwrap();
        assert!(opened.binary_was_reselected);
        fs::write(&moved, b"changed").unwrap();
        assert!(open_project_at_roots(
            &p,
            &g,
            &n,
            OpenProjectRequest {
                project_id: "hhproj_12345678".into(),
                selected_binary_path: Some(moved.to_string_lossy().into())
            }
        )
        .unwrap_err()
        .contains("identity changed"));
    }
    #[test]
    fn traversal_and_malformed_missing_unsupported_and_tamper_are_rejected() {
        let (p, g, n, b, s) = setup("invalid");
        for id in ["../outside", "hhproj_../../bad", "hhproj_short"] {
            assert!(open_project_at_roots(
                &p,
                &g,
                &n,
                OpenProjectRequest {
                    project_id: id.into(),
                    selected_binary_path: None
                }
            )
            .is_err());
        }
        let malformed_path = p.join("hhproj_12345678.json");
        fs::write(&malformed_path, b"{bad").unwrap();

        assert!(open_project_at_roots(
            &p,
            &g,
            &n,
            OpenProjectRequest {
                project_id: "hhproj_12345678".into(),
                selected_binary_path: None
            }
        )
        .unwrap_err()
        .contains("malformed"));

        assert!(save_project_at_roots(&p, &g, &n, request(&b, &s))
            .unwrap_err()
            .contains("malformed"));

        fs::remove_file(&malformed_path).unwrap();
        save_project_at_roots(&p, &g, &n, request(&b, &s)).unwrap();
        let path = p.join("hhproj_12345678.json");
        let mut m = read_manifest(&path).unwrap();
        m.schema_version = "99.0.0".into();
        fs::write(&path, serde_json::to_vec(&m).unwrap()).unwrap();
        assert!(open_project_at_roots(
            &p,
            &g,
            &n,
            OpenProjectRequest {
                project_id: "hhproj_12345678".into(),
                selected_binary_path: None
            }
        )
        .unwrap_err()
        .contains("Unsupported"));
        fs::remove_file(path).unwrap();
        assert!(open_project_at_roots(
            &p,
            &g,
            &n,
            OpenProjectRequest {
                project_id: "hhproj_12345678".into(),
                selected_binary_path: None
            }
        )
        .unwrap_err()
        .contains("missing"));
    }
    #[test]
    fn two_projects_can_share_one_snapshot() {
        let (p, g, n, b, s) = setup("shared");
        let mut a = request(&b, &s);
        save_project_at_roots(&p, &g, &n, a.clone()).unwrap();
        a.project_id = "hhproj_87654321".into();
        save_project_at_roots(&p, &g, &n, a).unwrap();
        assert_eq!(
            open_project_at_roots(
                &p,
                &g,
                &n,
                OpenProjectRequest {
                    project_id: "hhproj_12345678".into(),
                    selected_binary_path: None
                }
            )
            .unwrap()
            .gyre_snapshot
            .snapshot_id,
            open_project_at_roots(
                &p,
                &g,
                &n,
                OpenProjectRequest {
                    project_id: "hhproj_87654321".into(),
                    selected_binary_path: None
                }
            )
            .unwrap()
            .gyre_snapshot
            .snapshot_id
        );
    }
    #[test]
    fn interrupted_temp_and_failed_destination_do_not_destroy_existing_manifest() {
        let (p, g, n, b, s) = setup("atomic");
        let first = save_project_at_roots(&p, &g, &n, request(&b, &s)).unwrap();
        fs::write(p.join(".hhproj_12345678.json.tmp"), b"interrupted").unwrap();
        assert!(save_project_at_roots(&p, &g, &n, request(&b, &s))
            .unwrap_err()
            .contains("temporary"));
        assert_eq!(
            read_manifest(&p.join("hhproj_12345678.json"))
                .unwrap()
                .created_at,
            first.created_at
        );
    }

    #[test]
    fn two_distinct_binaries_survive_cache_clear_without_identity_crossover() {
        let project_root = root("multi-binary");
        let gyre_root = root("multi-binary-g");
        let nest_root = root("multi-binary-n");
        fs::create_dir_all(&project_root).unwrap();

        let first_binary = project_root.join("first.bin");
        let second_binary = project_root.join("second.bin");
        fs::write(&first_binary, b"first independent binary").unwrap();
        fs::write(&second_binary, b"second independent binary").unwrap();

        let first_identity = hash_file(&first_binary).unwrap();
        let second_identity = hash_file(&second_binary).unwrap();

        assert_ne!(first_identity.sha256, second_identity.sha256);

        let first_snapshot = record_verdict_snapshot_at_root(
            &gyre_root,
            GyreRecordVerdictSnapshotRequest {
                client_record_key: "multi_binary_first_record".into(),
                binary_sha256: first_identity.sha256.clone(),
                classification: "suspicious".into(),
                base_confidence: 81,
                threat_score: 35,
                summary: "First binary authoritative verdict".into(),
                signal_count: 3,
                contradiction_count: 0,
                reasoning_chain_hash: "c".repeat(64),
                gyre_build_id: SUPPORTED_GYRE_BUILD_ID.into(),
                gyre_schema_version: SUPPORTED_GYRE_SCHEMA_VERSION.into(),
            },
        )
        .unwrap();

        let second_snapshot = record_verdict_snapshot_at_root(
            &gyre_root,
            GyreRecordVerdictSnapshotRequest {
                client_record_key: "multi_binary_second_record".into(),
                binary_sha256: second_identity.sha256.clone(),
                classification: "likely-malware".into(),
                base_confidence: 92,
                threat_score: 84,
                summary: "Second binary authoritative verdict".into(),
                signal_count: 8,
                contradiction_count: 1,
                reasoning_chain_hash: "d".repeat(64),
                gyre_build_id: SUPPORTED_GYRE_BUILD_ID.into(),
                gyre_schema_version: SUPPORTED_GYRE_SCHEMA_VERSION.into(),
            },
        )
        .unwrap();

        assert_ne!(first_snapshot.snapshot_id, second_snapshot.snapshot_id);

        let first_manifest = save_project_at_roots(
            &project_root,
            &gyre_root,
            &nest_root,
            SaveProjectRequest {
                project_id: "hhproj_multibin_a1".into(),
                name: "First binary project".into(),
                binary_path: first_binary.to_string_lossy().into_owned(),
                gyre_snapshot_id: first_snapshot.snapshot_id.clone(),
                nest: None,
            },
        )
        .unwrap();

        let second_manifest = save_project_at_roots(
            &project_root,
            &gyre_root,
            &nest_root,
            SaveProjectRequest {
                project_id: "hhproj_multibin_b2".into(),
                name: "Second binary project".into(),
                binary_path: second_binary.to_string_lossy().into_owned(),
                gyre_snapshot_id: second_snapshot.snapshot_id.clone(),
                nest: None,
            },
        )
        .unwrap();

        clear_snapshot_cache_for_tests();

        let first_opened = open_project_at_roots(
            &project_root,
            &gyre_root,
            &nest_root,
            OpenProjectRequest {
                project_id: "hhproj_multibin_a1".into(),
                selected_binary_path: None,
            },
        )
        .unwrap();

        let second_opened = open_project_at_roots(
            &project_root,
            &gyre_root,
            &nest_root,
            OpenProjectRequest {
                project_id: "hhproj_multibin_b2".into(),
                selected_binary_path: None,
            },
        )
        .unwrap();

        assert_eq!(first_opened.manifest, first_manifest);
        assert_eq!(second_opened.manifest, second_manifest);
        assert_eq!(first_opened.gyre_snapshot, first_snapshot);
        assert_eq!(second_opened.gyre_snapshot, second_snapshot);

        assert_eq!(first_opened.manifest.binary.sha256, first_identity.sha256);

        assert_eq!(second_opened.manifest.binary.sha256, second_identity.sha256);

        assert_ne!(
            first_opened.gyre_snapshot.snapshot_id,
            second_opened.gyre_snapshot.snapshot_id
        );

        assert_eq!(first_opened.verdict_authority, "GYRE");
        assert_eq!(second_opened.verdict_authority, "GYRE");
        assert_eq!(first_opened.nest_role, "advisory");
        assert_eq!(second_opened.nest_role, "advisory");

        let crossover_error = open_project_at_roots(
            &project_root,
            &gyre_root,
            &nest_root,
            OpenProjectRequest {
                project_id: "hhproj_multibin_a1".into(),
                selected_binary_path: Some(second_binary.to_string_lossy().into_owned()),
            },
        )
        .unwrap_err();

        assert!(crossover_error.contains("identity changed"));
    }
}
