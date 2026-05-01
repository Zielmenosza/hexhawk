/**
 * AutoHealBanner — Self-Healing Analysis Remediation UI
 *
 * Appears automatically on the Verdict screen when selfHealEngine detects that
 * the pipeline is incomplete or the verdict confidence is too low to be reliable.
 *
 * Shows:
 *   - Severity-coded headline (critical / warning / info)
 *   - Detected conditions as a concise list
 *   - One-click action buttons for each prescription
 *   - Optional "Ask AI" button to get a narrative diagnosis
 */

import React, { useState } from 'react';
import type { HealDiagnosis, HealPrescription } from '../utils/selfHealEngine';

interface AutoHealBannerProps {
  diagnosis: HealDiagnosis;
  onHeal: (action: HealPrescription['action']) => void;
  /** Called when analyst dismisses the banner for this session */
  onDismiss?: () => void;
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#ef4444',
  warning:  '#f97316',
  info:     '#00e5ff',
};

const SEVERITY_BG: Record<string, string> = {
  critical: 'rgba(239,68,68,0.08)',
  warning:  'rgba(249,115,22,0.08)',
  info:     'rgba(0,229,255,0.06)',
};

const SEVERITY_ICON: Record<string, string> = {
  critical: '🔴',
  warning:  '🟡',
  info:     '🔵',
};

export function AutoHealBanner({ diagnosis, onHeal, onDismiss }: AutoHealBannerProps) {
  const [expanded, setExpanded] = useState(false);

  if (!diagnosis.needed) return null;

  const color = SEVERITY_COLORS[diagnosis.severity];
  const bg    = SEVERITY_BG[diagnosis.severity];
  const icon  = SEVERITY_ICON[diagnosis.severity];

  return (
    <div
      className="autoheal-banner"
      style={{
        border: `1px solid ${color}`,
        background: bg,
        borderRadius: '0.5rem',
        padding: '0.85rem 1rem',
        marginBottom: '1rem',
        fontFamily: "'Segoe UI', system-ui, sans-serif",
      }}
      data-testid="autoheal-banner"
      data-severity={diagnosis.severity}
    >
      {/* ── Header row ── */}
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.6rem' }}>
        <span style={{ fontSize: '1rem', flexShrink: 0, marginTop: '0.05rem' }}>{icon}</span>
        <div style={{ flex: 1 }}>
          <div style={{ fontWeight: 600, color, fontSize: '0.9rem', lineHeight: 1.3 }}>
            Self-Healing Analysis
            {diagnosis.currentConfidence !== null && (
              <span style={{ fontWeight: 400, color: '#8b949e', marginLeft: '0.5rem' }}>
                — {diagnosis.currentConfidence}% confidence
              </span>
            )}
          </div>
          <div style={{ color: '#e6edf3', fontSize: '0.85rem', marginTop: '0.2rem' }}>
            {diagnosis.summary}
          </div>
        </div>
        <div style={{ display: 'flex', gap: '0.4rem', flexShrink: 0 }}>
          <button
            type="button"
            onClick={() => setExpanded(e => !e)}
            style={{
              background: 'none', border: 'none', color: '#8b949e',
              cursor: 'pointer', fontSize: '0.75rem', padding: '0.15rem 0.4rem',
              borderRadius: '0.25rem',
            }}
          >
            {expanded ? 'Less ▲' : 'Details ▼'}
          </button>
          {onDismiss && (
            <button
              type="button"
              onClick={onDismiss}
              style={{
                background: 'none', border: 'none', color: '#8b949e',
                cursor: 'pointer', fontSize: '0.8rem', padding: '0.15rem 0.35rem',
                borderRadius: '0.25rem',
              }}
              title="Dismiss until next analysis"
            >
              ✕
            </button>
          )}
        </div>
      </div>

      {/* ── Expanded: condition list + prescription buttons ── */}
      {expanded && (
        <>
          {diagnosis.conditions.length > 0 && (
            <ul style={{
              margin: '0.75rem 0 0 1.6rem',
              padding: 0,
              listStyle: 'disc',
              color: '#8b949e',
              fontSize: '0.8rem',
              lineHeight: 1.6,
            }}>
              {diagnosis.conditions.map((c, i) => (
                <li key={i}>{c}</li>
              ))}
            </ul>
          )}

          {diagnosis.prescriptions.length > 0 && (
            <div style={{
              display: 'flex',
              flexWrap: 'wrap',
              gap: '0.5rem',
              marginTop: '0.75rem',
              paddingLeft: '1.6rem',
            }}>
              {diagnosis.prescriptions.map((p) => (
                <button
                  key={p.action}
                  type="button"
                  onClick={() => onHeal(p.action)}
                  title={p.reason}
                  style={{
                    background: p.action === 'ask_llm'
                      ? 'rgba(0,229,255,0.12)'
                      : `${color}22`,
                    border: `1px solid ${p.action === 'ask_llm' ? '#00e5ff55' : `${color}66`}`,
                    color: p.action === 'ask_llm' ? '#00e5ff' : color,
                    borderRadius: '0.3rem',
                    padding: '0.3rem 0.7rem',
                    fontSize: '0.8rem',
                    fontWeight: 600,
                    cursor: 'pointer',
                  }}
                  data-testid={`heal-btn-${p.action}`}
                >
                  {p.action === 'ask_llm' ? '✨ ' : '▶ '}
                  {p.label}
                  {p.estimatedGain > 0 && (
                    <span style={{ opacity: 0.65, marginLeft: '0.35rem', fontWeight: 400 }}>
                      +{p.estimatedGain}%
                    </span>
                  )}
                </button>
              ))}
            </div>
          )}
        </>
      )}
    </div>
  );
}
