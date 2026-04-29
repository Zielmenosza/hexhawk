// HexHawk/src/utils/tauriLicense.ts
// Thin wrappers around the Tauri license commands.

import { invoke } from '@tauri-apps/api/core';

export interface LicenseInfo {
  tier: 'pro' | 'enterprise';
  expiry_year: number;
  expiry_month: number;
  is_perpetual: boolean;
  is_expired: boolean;
  is_trial: boolean;
}

export interface BuildInfo {
  is_trial: boolean;
  version: string;
  /** Only present on trial builds — days since first install */
  days_elapsed?: number;
  /** Trial: Enterprise features locked (days_elapsed > 15) */
  enterprise_locked?: boolean;
  /** Trial: Pro features locked (days_elapsed > 30) */
  pro_locked?: boolean;
}

/** Verify a raw license key string (HKHK-…).
 *  Resolves with LicenseInfo on success; rejects with an error string. */
export async function verifyLicense(key: string): Promise<LicenseInfo> {
  return invoke<LicenseInfo>('verify_license', { key });
}

/** Returns build metadata — specifically whether this is a Trial binary. */
export async function getBuildInfo(): Promise<BuildInfo> {
  return invoke<BuildInfo>('get_build_info');
}
