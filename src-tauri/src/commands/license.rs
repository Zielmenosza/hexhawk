// src-tauri/src/commands/license.rs
//
// Offline license verification using HMAC-SHA256.
//
// Key format: HKHK-XXXXX-XXXXX-XXXXX-XXXXX  (Crockford Base32, 20 data chars)
//
// Payload layout (12 bytes total):
//   [0]      tier      — 1 = Pro, 2 = Enterprise
//   [1..2]   expiry year (u16 big-endian; 0 = perpetual)
//   [3]      expiry month (1-12; 0 = perpetual)
//   [4..7]   random nonce (4 bytes)
//   [8..11]  HMAC-SHA256(secret, payload[0..8]) first 4 bytes
//
// The 32-byte secret is split across four constants so that a plain
// strings/hexdump scan cannot extract it in one pass.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

// ── Secret (split into four 8-byte halves) ────────────────────────────────────
const K0: [u8; 8] = [0x4A, 0x7F, 0x3C, 0x8E, 0x2D, 0x91, 0xB5, 0x6A];
const K1: [u8; 8] = [0x0F, 0x4E, 0x7B, 0x3D, 0x82, 0x15, 0x96, 0xC7];
const K2: [u8; 8] = [0xD4, 0x50, 0x2B, 0x8F, 0x1E, 0x6A, 0x93, 0x4C];
const K3: [u8; 8] = [0x75, 0xB0, 0x2E, 0x5D, 0x88, 0x3F, 0x1A, 0x6C];

fn hmac_secret() -> [u8; 32] {
    let mut s = [0u8; 32];
    s[0..8].copy_from_slice(&K0);
    s[8..16].copy_from_slice(&K1);
    s[16..24].copy_from_slice(&K2);
    s[24..32].copy_from_slice(&K3);
    s
}

// ── Crockford Base32 ──────────────────────────────────────────────────────────
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

fn crockford_decode(input: &str) -> Option<Vec<u8>> {
    // Strip dashes / spaces, uppercase
    let clean: String = input
        .chars()
        .filter(|c| *c != '-' && *c != ' ')
        .map(|c| c.to_ascii_uppercase())
        // Map visually-similar characters to canonical Crockford equivalents
        .map(|c| match c {
            'O' => '0',
            'I' | 'L' => '1',
            _ => c,
        })
        .collect();

    let mut bits: u64 = 0;
    let mut bit_count: u32 = 0;
    let mut result: Vec<u8> = Vec::new();

    for ch in clean.chars() {
        let val = CROCKFORD.iter().position(|&b| b == ch as u8)? as u64;
        bits = (bits << 5) | val;
        bit_count += 5;
        if bit_count >= 8 {
            bit_count -= 8;
            result.push((bits >> bit_count) as u8);
            bits &= (1u64 << bit_count) - 1;
        }
    }
    Some(result)
}

// ── Public types ──────────────────────────────────────────────────────────────
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LicenseInfo {
    pub tier: String,        // "pro" | "enterprise"
    pub expiry_year: u16,    // 0 = perpetual
    pub expiry_month: u8,    // 0 = perpetual
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
        let install_day   = get_or_create_install_day(&app);
        let days_elapsed  = current_day().saturating_sub(install_day);
        // After 15 days Enterprise is locked; after 30 days Pro is also locked.
        let enterprise_locked = days_elapsed > 15;
        let pro_locked        = days_elapsed > 30;
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
pub fn verify_license(key: String) -> Result<LicenseInfo, String> {
    // Trial builds cannot activate a license
    #[cfg(feature = "trial")]
    return Err("License activation is not available in the Trial edition.".to_string());

    #[cfg(not(feature = "trial"))]
    {
        // 1. Must begin with the product prefix
        let key_trimmed = key.trim().to_uppercase();
        if !key_trimmed.starts_with("HKHK-") {
            return Err("License key must start with HKHK-.".to_string());
        }
        let data_part = &key_trimmed["HKHK-".len()..];

        // 2. Decode Crockford Base32
        let bytes = crockford_decode(data_part)
            .ok_or_else(|| "License key contains invalid characters.".to_string())?;

        if bytes.len() != 12 {
            return Err(format!(
                "License key has wrong length (expected 12 decoded bytes, got {}).",
                bytes.len()
            ));
        }

        // 3. Verify HMAC-SHA256
        let secret = hmac_secret();
        let mut mac = HmacSha256::new_from_slice(&secret)
            .map_err(|e| format!("HMAC initialisation failed: {e}"))?;
        mac.update(&bytes[0..8]);
        let tag = mac.finalize().into_bytes();

        // Constant-time comparison of the 4-byte truncated HMAC
        let valid = (0..4).fold(0u8, |acc, i| acc | (tag[i] ^ bytes[8 + i])) == 0;
        if !valid {
            return Err(
                "Invalid license key. The key may be corrupt or was not issued by HexHawk."
                    .to_string(),
            );
        }

        // 4. Decode payload fields
        let tier_byte  = bytes[0];
        let expiry_year  = u16::from_be_bytes([bytes[1], bytes[2]]);
        let expiry_month = bytes[3];

        let tier = match tier_byte {
            1 => "pro",
            2 => "enterprise",
            _ => return Err(format!("Unknown tier byte ({tier_byte}) in license key.")),
        };

        // 5. Check expiry
        let is_perpetual = expiry_year == 0 && expiry_month == 0;
        let is_expired = if is_perpetual {
            false
        } else {
            let secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let approx_year  = (1970u64 + secs / 31_557_600) as u16;
            let approx_month = ((secs % 31_557_600) / 2_629_800) as u8 + 1;

            approx_year > expiry_year
                || (approx_year == expiry_year && approx_month > expiry_month)
        };

        if is_expired {
            return Err(format!(
                "License expired ({expiry_year}/{expiry_month:02}). Please renew."
            ));
        }

        Ok(LicenseInfo {
            tier: tier.to_string(),
            expiry_year,
            expiry_month,
            is_perpetual,
            is_expired: false,
            is_trial: false,
        })
    }
}
