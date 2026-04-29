/**
 * WorkSavedPanel — Prompt 9
 *
 * Visualises the "Work Saved" metrics computed by computeWorkSaved() in
 * nestEngine.ts.  Answers: "how much manual reverse-engineering did HexHawk
 * replace?"
 *
 * Layout
 * ──────
 *   ┌─────────────────────────────────────────────────────────────────┐
 *   │ WORK SAVED  [score ring]  narrative                             │
 *   ├──────────┬──────────────────────────────────────────────────────┤
 *   │ Speed    │ Category breakdown table                             │
 *   │ estimate │                                                      │
 *   ├──────────┴──────────────────────────────────────────────────────┤
 *   │ Key logic regions identified                                    │
 *   │ Hidden signals (blind spots)                                    │
 *   └─────────────────────────────────────────────────────────────────┘
 */

import React from 'react';
import type { WorkSavedMetrics } from '../utils/nestEngine';

// ─── Colour helpers ───────────────────────────────────────────────────────────

function scoreColor(score: number): string {
  if (score >= 75) return '#4caf50';  // green
  if (score >= 45) return '#ffc107';  // amber
  return '#f44336';                    // red
}

const CATEGORY_COLORS: Record<string, string> = {
  structure:    '#64b5f6',
  imports:      '#ff8a65',
  strings:      '#81c784',
  disassembly:  '#ba68c8',
  signatures:   '#f06292',
};

// ─── Sub-components ───────────────────────────────────────────────────────────

function ScoreRing({ score }: { score: number }) {
  const r = 34;
  const circ = 2 * Math.PI * r;
  const dash = circ * (score / 100);
  const color = scoreColor(score);
  return (
    <svg width={84} height={84} style={{ flexShrink: 0 }}>
      <circle cx={42} cy={42} r={r} fill="none" stroke="#222" strokeWidth={7} />
      <circle
        cx={42} cy={42} r={r}
        fill="none"
        stroke={color}
        strokeWidth={7}
        strokeDasharray={`${dash} ${circ - dash}`}
        strokeLinecap="round"
        transform="rotate(-90 42 42)"
        style={{ transition: 'stroke-dasharray 0.6s ease' }}
      />
      <text x={42} y={47} textAnchor="middle" fill={color} fontSize={16} fontWeight={700}>
        {score}
      </text>
    </svg>
  );
}

function BarCell({ value, max }: { value: number; max: number }) {
  const pct = max > 0 ? Math.min(1, value / max) * 100 : 0;
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
      <div style={{
        flex: 1, height: 6, background: '#1a1a2e', borderRadius: 3, overflow: 'hidden',
      }}>
        <div style={{ width: `${pct}%`, height: '100%', background: '#64b5f6', borderRadius: 3 }} />
      </div>
      <span style={{ fontSize: 11, color: '#aaa', minWidth: 26, textAlign: 'right' }}>
        {value}/{max}
      </span>
    </div>
  );
}

// ─── Main component ───────────────────────────────────────────────────────────

interface Props {
  metrics: WorkSavedMetrics;
}

export function WorkSavedPanel({ metrics }: Props) {
  const color = scoreColor(metrics.workSavedScore);

  return (
    <div style={{
      background: '#0d0d1a',
      border: '1px solid #1e1e3a',
      borderRadius: 8,
      padding: 16,
      fontFamily: 'monospace',
      fontSize: 13,
      color: '#ccc',
    }}>
      {/* ── Header ─────────────────────────────────────────────────── */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 16, marginBottom: 14 }}>
        <ScoreRing score={metrics.workSavedScore} />
        <div>
          <div style={{ fontSize: 11, color: '#888', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 2 }}>
            Work Saved Score
          </div>
          <div style={{ fontSize: 20, fontWeight: 700, color, marginBottom: 4 }}>
            {metrics.workSavedScore}<span style={{ fontSize: 12, fontWeight: 400, color: '#888' }}>/100</span>
          </div>
          <div style={{ fontSize: 11, color: '#888' }}>
            {metrics.computedAtIteration} iteration{metrics.computedAtIteration !== 1 ? 's' : ''}
            {' · '}
            {metrics.signalsSurfaced} signals surfaced
            {' · '}
            {Math.round(metrics.signalCoverage * 100)}% coverage
          </div>
        </div>
      </div>

      <div style={{ fontSize: 12, color: '#888', marginBottom: 14, lineHeight: 1.5 }}>
        {metrics.narrative}
      </div>

      {/* ── Two-column row: speed + category table ──────────────────── */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 14 }}>
        {/* Speed card */}
        <div style={{ background: '#111127', borderRadius: 6, padding: '10px 12px' }}>
          <div style={{ fontSize: 11, color: '#888', marginBottom: 8, textTransform: 'uppercase', letterSpacing: 0.8 }}>
            Effort Estimate
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: '#888' }}>Manual</span>
              <span style={{ color: '#ffc107' }}>{metrics.estimatedManualMinutes} min</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: '#888' }}>Tool</span>
              <span style={{ color: '#4caf50' }}>{metrics.estimatedToolMinutes} min</span>
            </div>
            <div style={{ borderTop: '1px solid #1e1e3a', marginTop: 4, paddingTop: 4, display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: '#888' }}>Speed factor</span>
              <span style={{ color, fontWeight: 700 }}>{metrics.speedFactor}×</span>
            </div>
          </div>
        </div>

        {/* Category coverage table */}
        <div style={{ background: '#111127', borderRadius: 6, padding: '10px 12px' }}>
          <div style={{ fontSize: 11, color: '#888', marginBottom: 8, textTransform: 'uppercase', letterSpacing: 0.8 }}>
            Signal Coverage by Category
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {metrics.categoryBreakdown.map(cat => (
              <div key={cat.category}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 2 }}>
                  <span style={{ color: CATEGORY_COLORS[cat.category] ?? '#aaa', fontSize: 11 }}>
                    {cat.category}
                  </span>
                  <span style={{ fontSize: 11, color: '#888' }}>
                    {cat.minutesSaved > 0 ? `~${cat.minutesSaved} min saved` : '–'}
                  </span>
                </div>
                <BarCell value={cat.signalsFired} max={cat.signalsTotal} />
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ── Path reduction ───────────────────────────────────────────── */}
      {metrics.cfgBlocksCovered > 0 && (
        <div style={{ background: '#111127', borderRadius: 6, padding: '10px 12px', marginBottom: 12 }}>
          <div style={{ fontSize: 11, color: '#888', marginBottom: 6, textTransform: 'uppercase', letterSpacing: 0.8 }}>
            CFG Path Reduction
          </div>
          <BarCell value={metrics.cfgBlocksCovered} max={metrics.cfgBlocksEstimated} />
          <div style={{ fontSize: 11, color: '#888', marginTop: 4 }}>
            {Math.round(metrics.pathReductionRate * 100)}% of CFG paths narrowed to relevant subgraph
          </div>
        </div>
      )}

      {/* ── Key logic regions ────────────────────────────────────────── */}
      {metrics.keyLogicSummaries.length > 0 && (
        <div style={{ background: '#111127', borderRadius: 6, padding: '10px 12px', marginBottom: 12 }}>
          <div style={{ fontSize: 11, color: '#888', marginBottom: 6, textTransform: 'uppercase', letterSpacing: 0.8 }}>
            Key Logic Identified ({metrics.keyLogicRegionsIdentified})
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
            {metrics.keyLogicSummaries.map((s, i) => (
              <span key={i} style={{
                fontSize: 11, background: '#1a1a3e', color: '#90caf9',
                borderRadius: 4, padding: '2px 7px',
              }}>
                {s}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* ── Hidden signals (blind spots) ─────────────────────────────── */}
      {metrics.hiddenSignalIds.length > 0 && (
        <div style={{ background: '#1a1000', border: '1px solid #3a2800', borderRadius: 6, padding: '10px 12px' }}>
          <div style={{ fontSize: 11, color: '#888', marginBottom: 6, textTransform: 'uppercase', letterSpacing: 0.8 }}>
            Blind Spots — {metrics.hiddenSignalIds.length} signal{metrics.hiddenSignalIds.length !== 1 ? 's' : ''} not yet collected
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5 }}>
            {metrics.hiddenSignalIds.slice(0, 16).map(id => (
              <span key={id} style={{
                fontSize: 10, background: '#2a1800', color: '#ffc107',
                borderRadius: 3, padding: '1px 6px', opacity: 0.85,
              }}>
                {id}
              </span>
            ))}
            {metrics.hiddenSignalIds.length > 16 && (
              <span style={{ fontSize: 10, color: '#666', padding: '1px 4px' }}>
                +{metrics.hiddenSignalIds.length - 16} more
              </span>
            )}
          </div>
          <div style={{ fontSize: 11, color: '#666', marginTop: 6 }}>
            These would require manual investigation. Run additional NEST iterations to surface more.
          </div>
        </div>
      )}
    </div>
  );
}
