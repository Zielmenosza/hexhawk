// src-tauri/src/commands/license.rs
//
// Offline license activation boundary.
//
// HexHawk used to accept short HKHK-... keys verified by a client-held HMAC
// secret. That made the client the issuer of its own commercial entitlements:
// anyone who reversed the binary could recover the signing material and mint
// keys. Legacy HKHK client-signed keys therefore remain disabled. This client
// does not contain a universal bypass key; future activation must verify an
// issuer-signed public-key entitlement.

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

// ── Public types ──────────────────────────────────────────────────────────────
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LicenseInfo {
    pub tier: String,     // "pro" | "enterprise"
    pub expiry_year: u16, // 0 = perpetual
    pub expiry_month: u8, // 0 = perpetual
    pub is_perpetual: bool,
    pub is_expired: bool,
    pub is_trial: bool,
}

// ── Build-info command (differs between full and trial builds) ────────────────

/// Returns the current day number since Unix epoch (truncated to whole days).
fn current_day() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        / 86400
}

/// Reads the stored install day, or writes today's date on first launch.
/// The file is placed in the app data directory so it survives updates.
#[cfg(feature = "trial")]
fn get_or_create_install_day(app: &tauri::AppHandle) -> u64 {
    let install_file = app
        .path()
        .app_data_dir()
        .ok()
        .map(|d| d.join("trial_install.dat"));

    if let Some(ref path) = install_file {
        if let Ok(content) = std::fs::read_to_string(path) {
            if let Ok(day) = content.trim().parse::<u64>() {
                return day;
            }
        }
        // First run — persist install day
        let day = current_day();
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(path, day.to_string());
        return day;
    }

    current_day()
}

#[tauri::command]
pub fn get_build_info(app: tauri::AppHandle) -> serde_json::Value {
    #[cfg(feature = "trial")]
    {
        let install_day = get_or_create_install_day(&app);
        let days_elapsed = current_day().saturating_sub(install_day);
        // After 15 days Enterprise is locked; after 30 days Pro is also locked.
        let enterprise_locked = days_elapsed > 15;
        let pro_locked = days_elapsed > 30;
        return serde_json::json!({
            "is_trial":          true,
            "version":           env!("CARGO_PKG_VERSION"),
            "days_elapsed":      days_elapsed,
            "enterprise_locked": enterprise_locked,
            "pro_locked":        pro_locked,
        });
    }
    #[cfg(not(feature = "trial"))]
    {
        let _ = app; // unused in full builds
        return serde_json::json!({ "is_trial": false, "version": env!("CARGO_PKG_VERSION") });
    }
}

// ── License verification command ─────────────────────────────────────────────

#[tauri::command]
pub fn verify_license(_key: String) -> Result<LicenseInfo, String> {
    // Trial builds cannot activate a license
    #[cfg(feature = "trial")]
    return Err("License activation is not available in the Trial edition.".to_string());

    #[cfg(not(feature = "trial"))]
    {
        Err("License activation is unavailable in this build. Legacy offline HKHK keys are disabled because the old verifier embedded issuer signing material in the client; a public-key entitlement verifier is required.".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(not(feature = "trial"))]
    fn full_build_fails_closed_instead_of_accepting_client_signed_legacy_keys() {
        let err = verify_license("HKHK-00000-00000-00000-00000".to_string()).unwrap_err();
        assert!(err.contains("Legacy offline HKHK keys are disabled"));
        assert!(err.contains("public-key entitlement verifier"));
    }

    #[test]
    #[cfg(not(feature = "trial"))]
    fn no_universal_owner_bypass_is_embedded() {
        let err = verify_license("owner-bypass-candidate".to_string()).unwrap_err();
        assert!(err.contains("activation is unavailable"));
    }
}
