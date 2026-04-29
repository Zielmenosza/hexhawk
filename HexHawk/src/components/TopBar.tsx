import React from 'react';
import { TIER_DISPLAY } from '../utils/tierConfig';
import type { Tier } from '../utils/tierConfig';

interface TopBarProps {
  tier: Tier;
  isTrial: boolean;
  consoleQuery: string;
  onConsoleQueryChange: (v: string) => void;
  onConsoleSubmit: () => void;
  onUpgradeClick: () => void;
  onLicenseClick: () => void;
}

export default function TopBar({
  tier,
  isTrial,
  consoleQuery,
  onConsoleQueryChange,
  onConsoleSubmit,
  onUpgradeClick,
  onLicenseClick,
}: TopBarProps) {
  const td = TIER_DISPLAY[tier];

  return (
    <header className="wf-topbar">
      <div className="wf-topbar-brand">
        <span className="wf-topbar-logo">HexHawk</span>
      </div>

      <div className="wf-topbar-console">
        <input
          type="text"
          className="wf-topbar-console-input"
          placeholder="Search intents (network, injection, persistence)…"
          value={consoleQuery}
          onChange={(e) => onConsoleQueryChange(e.target.value)}
          onKeyDown={(e) => { if (e.key === 'Enter') onConsoleSubmit(); }}
        />
        <button
          type="button"
          className="wf-topbar-console-btn"
          onClick={onConsoleSubmit}
          title="Submit query"
        >
          ↵
        </button>
      </div>

      <div className="wf-topbar-right">
        <div
          className="wf-tier-badge"
          style={{ borderColor: td.borderColor, background: td.bg, color: td.color }}
          title={`${td.label} — ${td.tagline}`}
        >
          {td.badge} {isTrial ? 'TRIAL' : td.label}
        </div>
        {tier === 'free' && !isTrial && (
          <button type="button" className="wf-upgrade-btn" onClick={onUpgradeClick}>
            Upgrade ↑
          </button>
        )}
        {!isTrial && (
          <button type="button" className="wf-license-btn" onClick={onLicenseClick} title="Activate license key">
            🔑
          </button>
        )}
      </div>
    </header>
  );
}
