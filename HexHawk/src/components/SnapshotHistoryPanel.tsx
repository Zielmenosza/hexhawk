/**
 * SnapshotHistoryPanel — Cross-file Snapshot History Browser
 *
 * Reads all report snapshots from localStorage and surfaces them grouped by
 * binary, allowing analysts to select any two snapshots (across different files)
 * for side-by-side comparison using compareReportSnapshots().
 */

import React, { useMemo, useState } from 'react';
import {
  compareReportSnapshots,
  formatDiffMarkdown,
  REPORT_SNAPSHOTS_STORAGE_KEY,
} from './IntelligenceReport';
import type { ReportSnapshot, ReportComparison } from './IntelligenceReport';

// ─── Helpers ──────────────────────────────────────────────────────────────────

function loadAllSnapshots(): ReportSnapshot[] {
  if (typeof window === 'undefined') return [];
  try {
    const raw = window.localStorage.getItem(REPORT_SNAPSHOTS_STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as ReportSnapshot[];
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function downloadText(content: string, filename: string, mimeType: string) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function formatDelta(value: number): string {
  return value > 0 ? `+${value}` : `${value}`;
}

// ─── Delta badge ──────────────────────────────────────────────────────────────

function DeltaBadge({ value }: { value: number }) {
  const cls = value > 0 ? 'history-delta--up' : value < 0 ? 'history-delta--down' : 'history-delta--neutral';
  return <span className={`history-delta ${cls}`}>{formatDelta(value)}</span>;
}

// ─── Comparison card ─────────────────────────────────────────────────────────

interface ComparisonCardProps {
  current: ReportSnapshot;
  baseline: ReportSnapshot;
  comparison: ReportComparison;
}

function ComparisonCard({ current, baseline, comparison }: ComparisonCardProps) {
  const handleExportMd = () => {
    const md = formatDiffMarkdown(comparison, current, baseline);
    const safeName = current.binaryName.replace(/[^a-zA-Z0-9_-]/g, '_');
    downloadText(md, `hexhawk-diff-${safeName}.md`, 'text/markdown');
  };

  const handleExportJson = () => {
    const payload = { generatedAt: new Date().toISOString(), current, baseline, comparison };
    const safeName = current.binaryName.replace(/[^a-zA-Z0-9_-]/g, '_');
    downloadText(JSON.stringify(payload, null, 2), `hexhawk-diff-${safeName}.json`, 'application/json');
  };

  return (
    <div className="history-compare-card">
      <div className="history-compare-header">
        <div className="history-compare-title">Comparison</div>
        <div className="history-compare-actions">
          <button className="report-btn report-btn--sm" type="button" onClick={handleExportMd}>↓ Diff MD</button>
          <button className="report-btn report-btn--sm" type="button" onClick={handleExportJson}>↓ Diff JSON</button>
        </div>
      </div>

      <div className="history-compare-binaries">
        <div className="history-compare-side history-compare-side--baseline">
          <div className="history-compare-side-label">Baseline</div>
          <div className="history-compare-binary-name">{baseline.binaryName}</div>
          <div className="history-compare-class">{baseline.classification}</div>
          <div className="history-compare-score">{baseline.threatScore}<span>/100</span></div>
          <div className="history-compare-date">{new Date(baseline.generatedAt).toLocaleString()}</div>
          {baseline.notes && <div className="history-compare-notes">📝 {baseline.notes}</div>}
        </div>

        <div className="history-compare-arrow">→</div>

        <div className="history-compare-side history-compare-side--current">
          <div className="history-compare-side-label">Current</div>
          <div className="history-compare-binary-name">{current.binaryName}</div>
          <div className="history-compare-class">{current.classification}</div>
          <div className="history-compare-score">{current.threatScore}<span>/100</span></div>
          <div className="history-compare-date">{new Date(current.generatedAt).toLocaleString()}</div>
          {current.notes && <div className="history-compare-notes">📝 {current.notes}</div>}
        </div>
      </div>

      <div className="history-compare-grid">
        <div className="history-compare-metric">
          <span className="report-compare-label">Threat score</span>
          <DeltaBadge value={comparison.threatScoreDelta} />
        </div>
        <div className="history-compare-metric">
          <span className="report-compare-label">Confidence</span>
          <DeltaBadge value={comparison.confidenceDelta} />
        </div>
        <div className="history-compare-metric">
          <span className="report-compare-label">Signals</span>
          <DeltaBadge value={comparison.signalCountDelta} />
        </div>
        <div className="history-compare-metric">
          <span className="report-compare-label">IOCs</span>
          <DeltaBadge value={comparison.iocCountDelta} />
        </div>
      </div>

      {comparison.classificationChanged && (
        <div className="history-compare-drift">
          Classification drift: <strong>{baseline.classification}</strong> → <strong>{current.classification}</strong>
        </div>
      )}
      {comparison.behaviorsAdded.length > 0 && (
        <div className="history-compare-behaviors history-compare-behaviors--added">
          Behaviors added: {comparison.behaviorsAdded.join(', ')}
        </div>
      )}
      {comparison.behaviorsRemoved.length > 0 && (
        <div className="history-compare-behaviors history-compare-behaviors--removed">
          Behaviors removed: {comparison.behaviorsRemoved.join(', ')}
        </div>
      )}
    </div>
  );
}

// ─── Main Component ───────────────────────────────────────────────────────────

export function SnapshotHistoryPanel() {
  const [snapshots] = useState<ReportSnapshot[]>(() => loadAllSnapshots());
  const [selectedA, setSelectedA] = useState<string>('');
  const [selectedB, setSelectedB] = useState<string>('');

  const grouped = useMemo(() => {
    const map = new Map<string, ReportSnapshot[]>();
    for (const s of snapshots) {
      const key = s.binaryName;
      if (!map.has(key)) map.set(key, []);
      map.get(key)!.push(s);
    }
    return map;
  }, [snapshots]);

  const snapshotA = useMemo(() => snapshots.find(s => s.id === selectedA) ?? null, [snapshots, selectedA]);
  const snapshotB = useMemo(() => snapshots.find(s => s.id === selectedB) ?? null, [snapshots, selectedB]);

  const comparison = useMemo<ReportComparison | null>(() => {
    if (!snapshotA || !snapshotB || snapshotA.id === snapshotB.id) return null;
    return compareReportSnapshots(snapshotA, snapshotB);
  }, [snapshotA, snapshotB]);

  if (snapshots.length === 0) {
    return (
      <div className="history-panel-empty">
        <div className="history-panel-empty-icon">🕐</div>
        <div className="history-panel-empty-title">No Snapshots Yet</div>
        <div className="history-panel-empty-subtitle">
          Open a binary, run analysis, then use the Intelligence Report tab to save a snapshot checkpoint.
        </div>
      </div>
    );
  }

  return (
    <div className="history-panel">
      <div className="history-panel-header">
        <div className="history-panel-title">Snapshot History</div>
        <div className="history-panel-subtitle">
          {snapshots.length} snapshot{snapshots.length !== 1 ? 's' : ''} across {grouped.size} binary file{grouped.size !== 1 ? 's' : ''}
        </div>
      </div>

      {/* ── Selector row ─────────────────────────────────────── */}
      <div className="history-selector-row">
        <div className="history-selector">
          <label className="history-selector-label">Snapshot A (current)</label>
          <select
            className="history-selector-select"
            value={selectedA}
            onChange={(e) => setSelectedA(e.target.value)}
          >
            <option value="">— Select snapshot —</option>
            {[...grouped.entries()].map(([binaryName, snaps]) => (
              <optgroup key={binaryName} label={binaryName}>
                {snaps.map(s => (
                  <option key={s.id} value={s.id}>
                    {new Date(s.generatedAt).toLocaleString()} · {s.classification} · {s.threatScore}
                    {s.notes ? ` · "${s.notes.slice(0, 30)}${s.notes.length > 30 ? '…' : ''}"` : ''}
                  </option>
                ))}
              </optgroup>
            ))}
          </select>
        </div>

        <div className="history-selector-vs">vs</div>

        <div className="history-selector">
          <label className="history-selector-label">Snapshot B (baseline)</label>
          <select
            className="history-selector-select"
            value={selectedB}
            onChange={(e) => setSelectedB(e.target.value)}
          >
            <option value="">— Select snapshot —</option>
            {[...grouped.entries()].map(([binaryName, snaps]) => (
              <optgroup key={binaryName} label={binaryName}>
                {snaps.map(s => (
                  <option key={s.id} value={s.id} disabled={s.id === selectedA}>
                    {new Date(s.generatedAt).toLocaleString()} · {s.classification} · {s.threatScore}
                    {s.notes ? ` · "${s.notes.slice(0, 30)}${s.notes.length > 30 ? '…' : ''}"` : ''}
                  </option>
                ))}
              </optgroup>
            ))}
          </select>
        </div>
      </div>

      {/* ── Comparison ────────────────────────────────────────── */}
      {snapshotA && snapshotB && comparison && (
        <ComparisonCard current={snapshotA} baseline={snapshotB} comparison={comparison} />
      )}

      {/* ── Full snapshot index ───────────────────────────────── */}
      <div className="history-index">
        {[...grouped.entries()].map(([binaryName, snaps]) => (
          <div key={binaryName} className="history-binary-group">
            <div className="history-binary-name">{binaryName}</div>
            <div className="history-binary-snapshots">
              {snaps.map(s => (
                <div key={s.id} className="history-snapshot-row">
                  <button
                    type="button"
                    className={`history-snapshot-select-btn${selectedA === s.id ? ' selected-a' : selectedB === s.id ? ' selected-b' : ''}`}
                    onClick={() => {
                      if (selectedA === s.id) {
                        setSelectedA('');
                      } else if (selectedB === s.id) {
                        setSelectedB('');
                      } else if (!selectedA) {
                        setSelectedA(s.id);
                      } else if (!selectedB) {
                        setSelectedB(s.id);
                      } else {
                        setSelectedA(s.id);
                      }
                    }}
                    title={selectedA === s.id ? 'Snapshot A (click to deselect)' : selectedB === s.id ? 'Snapshot B (click to deselect)' : 'Click to select for comparison'}
                  >
                    <span className="history-snapshot-score">{s.threatScore}</span>
                    <span className="history-snapshot-class">{s.classification}</span>
                    <span className="history-snapshot-date">{new Date(s.generatedAt).toLocaleString()}</span>
                    {s.notes && <span className="history-snapshot-notes">📝 {s.notes}</span>}
                    {selectedA === s.id && <span className="history-snapshot-badge history-snapshot-badge--a">A</span>}
                    {selectedB === s.id && <span className="history-snapshot-badge history-snapshot-badge--b">B</span>}
                  </button>
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
