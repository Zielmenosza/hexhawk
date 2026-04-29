// HexHawk/src/components/LicensePanel.tsx
// License activation modal — enter a HKHK-… key to unlock Pro/Enterprise tier.

import React, { useState } from 'react';
import type { LicenseInfo } from '../utils/tauriLicense';
import { verifyLicense } from '../utils/tauriLicense';
import { saveLicenseKey, clearLicenseKey, TIER_DISPLAY } from '../utils/tierConfig';
import type { Tier } from '../utils/tierConfig';

interface LicensePanelProps {
  isTrial: boolean;
  currentTier: Tier;
  activeLicense: LicenseInfo | null;
  onLicenseActivated: (info: LicenseInfo) => void;
  onLicenseCleared: () => void;
  onClose: () => void;
}

const LicensePanel: React.FC<LicensePanelProps> = ({
  isTrial,
  currentTier,
  activeLicense,
  onLicenseActivated,
  onLicenseCleared,
  onClose,
}) => {
  const [keyInput, setKeyInput] = useState('');
  const [status, setStatus] = useState<'idle' | 'checking' | 'ok' | 'error'>('idle');
  const [message, setMessage] = useState('');

  const handleActivate = async () => {
    const trimmed = keyInput.trim();
    if (!trimmed) return;
    setStatus('checking');
    setMessage('');
    try {
      const info = await verifyLicense(trimmed);
      saveLicenseKey(trimmed);
      setStatus('ok');
      setMessage(`License activated: ${info.tier.toUpperCase()}${info.is_perpetual ? ' (perpetual)' : ` — expires ${info.expiry_year}/${String(info.expiry_month).padStart(2, '0')}`}`);
      onLicenseActivated(info);
    } catch (err: unknown) {
      setStatus('error');
      setMessage(typeof err === 'string' ? err : String(err));
    }
  };

  const handleDeactivate = () => {
    clearLicenseKey();
    setKeyInput('');
    setStatus('idle');
    setMessage('');
    onLicenseCleared();
  };

  const formatExpiry = (info: LicenseInfo) => {
    if (info.is_perpetual) return 'Perpetual — never expires';
    return `Expires ${info.expiry_year}/${String(info.expiry_month).padStart(2, '0')}`;
  };

  return (
    <div className="license-panel-overlay" onClick={onClose}>
      <div
        className="license-panel"
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-label="License activation"
      >
        {/* ── Header ── */}
        <div className="license-panel-header">
          <span className="license-panel-icon">🔑</span>
          <h2 className="license-panel-title">License Activation</h2>
          <button className="license-panel-close" onClick={onClose} aria-label="Close">✕</button>
        </div>

        {/* ── Current status ── */}
        <div className="license-status-section">
          <div className="license-status-row">
            <span className="license-status-label">Edition</span>
            <span
              className="license-status-value tier-badge"
              style={{
                borderColor: TIER_DISPLAY[currentTier].borderColor,
                background:  TIER_DISPLAY[currentTier].bg,
                color:       TIER_DISPLAY[currentTier].color,
              }}
            >
              {TIER_DISPLAY[currentTier].badge} {TIER_DISPLAY[currentTier].label}
            </span>
          </div>

          {isTrial && (
            <div className="license-trial-notice">
              This is a <strong>Trial Edition</strong> binary. License activation is disabled.
              Download the full installer to activate a license.
            </div>
          )}

          {activeLicense && !isTrial && (
            <>
              <div className="license-status-row">
                <span className="license-status-label">Tier</span>
                <span className="license-status-value">{activeLicense.tier.toUpperCase()}</span>
              </div>
              <div className="license-status-row">
                <span className="license-status-label">Validity</span>
                <span className="license-status-value">{formatExpiry(activeLicense)}</span>
              </div>
              <div className="license-status-row">
                <span className="license-status-label">Status</span>
                <span className="license-status-value license-status-active">✔ Active</span>
              </div>
              <button className="license-deactivate-btn" onClick={handleDeactivate}>
                Deactivate License
              </button>
            </>
          )}

          {!activeLicense && !isTrial && (
            <div className="license-none-notice">
              No license key activated. Running with manually-selected tier.
            </div>
          )}
        </div>

        {/* ── Activation form ── */}
        {!isTrial && (
          <div className="license-activate-section">
            <label className="license-input-label" htmlFor="license-key-input">
              Enter License Key
            </label>
            <div className="license-input-row">
              <input
                id="license-key-input"
                className="license-key-input"
                type="text"
                placeholder="HKHK-XXXXX-XXXXX-XXXXX-XXXXX"
                value={keyInput}
                onChange={(e) => {
                  setKeyInput(e.target.value.toUpperCase());
                  setStatus('idle');
                  setMessage('');
                }}
                onKeyDown={(e) => { if (e.key === 'Enter') handleActivate(); }}
                spellCheck={false}
                autoComplete="off"
                maxLength={32}
              />
              <button
                className={`license-activate-btn${status === 'checking' ? ' license-activate-btn--loading' : ''}`}
                onClick={handleActivate}
                disabled={status === 'checking' || !keyInput.trim()}
              >
                {status === 'checking' ? 'Verifying…' : 'Activate'}
              </button>
            </div>

            {message && (
              <div className={`license-message license-message--${status === 'ok' ? 'ok' : 'error'}`}>
                {status === 'ok' ? '✔ ' : '✖ '}{message}
              </div>
            )}

            <p className="license-help-text">
              Keys are validated offline. Format: <code>HKHK-XXXXX-XXXXX-XXXXX-XXXXX</code>
            </p>
          </div>
        )}

        {/* ── Tier comparison footer ── */}
        <div className="license-tier-summary">
          <div className="license-tier-col">
            <div className="license-tier-col-name" style={{ color: TIER_DISPLAY.free.color }}>🟢 Free</div>
            <div className="license-tier-col-desc">Inspect · Hex · Strings · CFG · Decompile</div>
          </div>
          <div className="license-tier-col">
            <div className="license-tier-col-name" style={{ color: TIER_DISPLAY.pro.color }}>🔵 Pro</div>
            <div className="license-tier-col-desc">+ TALON · STRIKE · ECHO · IMP · Debugger · Console</div>
          </div>
          <div className="license-tier-col">
            <div className="license-tier-col-name" style={{ color: TIER_DISPLAY.enterprise.color }}>🔴 Enterprise</div>
            <div className="license-tier-col-desc">+ NEST convergence · API automation · Team sharing</div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default LicensePanel;
