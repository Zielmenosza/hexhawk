/**
 * TierGate.tsx — Upgrade wall shown when a tab requires a higher tier.
 *
 * Renders an inline locked-feature screen with:
 *   - The required tier badge
 *   - Feature description
 *   - Tier comparison for the three tiers
 *   - A tier switcher (dev / demo mode — no server required)
 */

import React from 'react';
import {
  type Tier,
  TIER_DISPLAY,
  TIER_ORDER,
  saveTier,
  TAB_FEATURE_DESC,
} from '../utils/tierConfig';

// ─── Types ────────────────────────────────────────────────────────────────────

interface TierGateProps {
  tab:          string;
  tabLabel:     string;
  requiredTier: Tier;
  currentTier:  Tier;
  onTierChange: (tier: Tier) => void;
}

// ─── Tier feature bullets ─────────────────────────────────────────────────────

const TIER_BULLETS: Record<Tier, string[]> = {
  free: [
    'Metadata, hex, strings, CFG',
    'Basic decompilation',
    'Plugin results',
    'Files up to 50 MB',
    '5 console queries / session',
  ],
  pro: [
    'Everything in Free',
    'Full TALON (SSA, data-flow, LLM)',
    'STRIKE, ECHO, Debugger',
    'IMP patch intelligence',
    'GYRE explainability chain',
    'KITE graph, CREST report',
    'Bookmarks, logs, history',
    'Unlimited console queries',
    'Unlimited file size',
  ],
  enterprise: [
    'Everything in Pro',
    'NEST iterative convergence analysis',
    'Corpus training & MalwareBazaar import',
    'API & automation (roadmap)',
    'Batch console queries (roadmap)',
    'Team intelligence sharing (roadmap)',
    'SOC integration (roadmap)',
  ],
};

// ─── Component ────────────────────────────────────────────────────────────────

export default function TierGate({
  tab,
  tabLabel,
  requiredTier,
  currentTier,
  onTierChange,
}: TierGateProps) {
  const req  = TIER_DISPLAY[requiredTier];
  const curr = TIER_DISPLAY[currentTier];
  const tiers: Tier[] = ['free', 'pro', 'enterprise'];
  const featureDesc = TAB_FEATURE_DESC[tab] ?? `${tabLabel} is not available on the ${curr.label} tier.`;

  function handleSwitch(tier: Tier) {
    saveTier(tier);
    onTierChange(tier);
  }

  return (
    <div className="tier-gate-root">
      {/* Lock header */}
      <div className="tier-gate-header">
        <div className="tier-gate-lock">🔒</div>
        <div>
          <div className="tier-gate-title">
            <span className="tier-badge" style={{ color: req.color, borderColor: req.borderColor, background: req.bg }}>
              {req.badge} {req.label}
            </span>
            &nbsp;feature
          </div>
          <div className="tier-gate-tab-name">{tabLabel}</div>
        </div>
      </div>

      {/* Feature description */}
      <div className="tier-gate-desc">{featureDesc}</div>

      {/* Current tier */}
      <div className="tier-gate-current">
        You are on the&nbsp;
        <span className="tier-badge" style={{ color: curr.color, borderColor: curr.borderColor, background: curr.bg }}>
          {curr.badge} {curr.label}
        </span>
        &nbsp;tier.
      </div>

      {/* Tier cards */}
      <div className="tier-gate-cards">
        {tiers.map((t) => {
          const d       = TIER_DISPLAY[t];
          const isCurr  = t === currentTier;
          const isReq   = t === requiredTier;
          const unlocks = TIER_ORDER[t] >= TIER_ORDER[requiredTier];
          return (
            <div
              key={t}
              className={`tier-card ${isCurr ? 'tier-card--current' : ''} ${isReq ? 'tier-card--required' : ''}`}
              style={{
                borderColor: isCurr ? d.borderColor : 'rgba(255,255,255,0.1)',
                background:  isCurr ? d.bg : 'rgba(255,255,255,0.03)',
              }}
            >
              <div className="tier-card-header" style={{ color: d.color }}>
                {d.badge} {d.label}
                {isCurr && <span className="tier-card-tag">current</span>}
                {isReq && !isCurr && <span className="tier-card-tag tier-card-tag--unlock">unlocks this</span>}
              </div>
              <div className="tier-card-tagline">{d.tagline}</div>
              <ul className="tier-card-bullets">
                {TIER_BULLETS[t].map((b) => (
                  <li key={b} className={unlocks && b !== 'Everything in Free' && b !== 'Everything in Pro' ? 'tier-bullet--highlight' : ''}>
                    {b}
                  </li>
                ))}
              </ul>
              {!isCurr && (
                <button
                  type="button"
                  className="tier-card-switch-btn"
                  style={{ borderColor: d.borderColor, color: d.color }}
                  onClick={() => handleSwitch(t)}
                >
                  Switch to {d.label}
                </button>
              )}
            </div>
          );
        })}
      </div>

      <div className="tier-gate-note">
        Tier switching is available locally for evaluation purposes.
      </div>
    </div>
  );
}
