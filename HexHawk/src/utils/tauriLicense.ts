// HexHawk/src/utils/tauriLicense.ts
// Thin wrappers around the Tauri license commands.

import { invoke } from '@tauri-apps/api/core';

function hasTauriRuntime(): boolean {
  return typeof window !== 'undefined' && typeof (window as { __TAURI_INTERNALS__?: unknown }).__TAURI_INTERNALS__ !== 'undefined';
}

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

/** Verify a raw license entitlement string. Activation currently rejects
 *  fail-closed until an issuer-signed public-key verifier is implemented. */
export async function verifyLicense(key: string): Promise<LicenseInfo> {
  if (!hasTauriRuntime()) {
    void key;
    throw new Error('License activation requires the native HexHawk app. Legacy HKHK keys are disabled because the old verifier embedded issuer signing material in the client.');
  }
  return invoke<LicenseInfo>('verify_license', { key });
}

/** Returns build metadata — specifically whether this is a Trial binary. */
export async function getBuildInfo(): Promise<BuildInfo> {
  if (!hasTauriRuntime()) {
    return { is_trial: false, version: '1.0.0-web' };
  }
  return invoke<BuildInfo>('get_build_info');
}
