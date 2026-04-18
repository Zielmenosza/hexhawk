/**
 * CorpusBenchmarkPanel — Corpus management and benchmark history UI
 *
 * Provides:
 *   - Quick add of the current binary to the corpus with ground-truth label
 *   - Corpus statistics overview (total entries, classification breakdown)
 *   - Benchmark run history with pass rates
 *   - Export / import corpus as JSON
 */

import React, { useState, useEffect, useCallback } from 'react';
import {
  addToCorpus,
  removeFromCorpus,
  getCorpusStats,
  queryCorpus,
  exportCorpus,
  importCorpus,
  clearCorpus,
  type CorpusEntry,
  type CorpusLabel,
} from '../utils/corpusManager';
import {
  loadBenchmarkHistory,
  deleteBenchmarkRun,
  type BenchmarkRun,
} from '../utils/benchmarkHarness';

// ── Helpers ───────────────────────────────────────────────────────────────────

function shortPath(p: string): string {
  return p.replace(/\\/g, '/').split('/').pop() ?? p;
}

function fmtDate(iso: string): string {
  try {
    return new Date(iso).toLocaleString(undefined, {
      month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
    });
  } catch {
    return iso;
  }
}

function passRateColor(rate: number): string {
  if (rate >= 0.8) return '#4ade80';
  if (rate >= 0.5) return '#facc15';
  return '#f87171';
}

// ── Sub-components ────────────────────────────────────────────────────────────

interface AddEntryFormProps {
  binaryPath: string | null;
  onAdded: () => void;
}

function AddEntryForm({ binaryPath, onAdded }: AddEntryFormProps) {
  const [groundTruth, setGroundTruth] = useState<CorpusLabel>('unknown');
  const [expectedClass, setExpectedClass] = useState('');
  const [notes, setNotes] = useState('');
  const [added, setAdded] = useState(false);

  const handleAdd = useCallback(() => {
    if (!binaryPath) return;
    // Derive a simple sha256-like key from path+timestamp for offline use
    const pseudo = btoa(binaryPath).replace(/[^a-z0-9]/gi, '').slice(0, 40) || 'unknown';
    addToCorpus({
      sha256: pseudo,
      binaryPath,
      groundTruth,
      expectedClassification: (expectedClass || null) as any,
      tags: [],
      lastNestSummary: null,
      lastSessionId: null,
      notes,
    });
    setAdded(true);
    onAdded();
    setTimeout(() => setAdded(false), 2000);
  }, [binaryPath, groundTruth, expectedClass, notes, onAdded]);

  return (
    <div className="cbp-add-form">
      <div className="cbp-add-title">Add Current Binary to Corpus</div>
      {binaryPath ? (
        <div className="cbp-add-path" title={binaryPath}>📄 {shortPath(binaryPath)}</div>
      ) : (
        <div className="cbp-add-no-binary">No binary loaded — open a file first.</div>
      )}
      <div className="cbp-add-row">
        <label className="cbp-add-label">Ground Truth</label>
        <select
          className="cbp-add-select"
          value={groundTruth}
          onChange={e => setGroundTruth(e.target.value as CorpusLabel)}
        >
          <option value="clean">Clean</option>
          <option value="malicious">Malicious</option>
          <option value="unknown">Unknown</option>
        </select>
      </div>
      <div className="cbp-add-row">
        <label className="cbp-add-label">Expected Class <span className="cbp-opt">(optional)</span></label>
        <input
          className="cbp-add-input"
          placeholder="e.g. clean, dropper, rat…"
          value={expectedClass}
          onChange={e => setExpectedClass(e.target.value)}
        />
      </div>
      <div className="cbp-add-row">
        <label className="cbp-add-label">Notes <span className="cbp-opt">(optional)</span></label>
        <input
          className="cbp-add-input"
          placeholder="Analyst notes…"
          value={notes}
          onChange={e => setNotes(e.target.value)}
        />
      </div>
      <button
        className={`nest-btn ${added ? 'success' : 'primary'} cbp-add-btn`}
        onClick={handleAdd}
        disabled={!binaryPath || added}
      >
        {added ? '✓ Added to Corpus' : '+ Add to Corpus'}
      </button>
    </div>
  );
}

// ── Corpus entry list ─────────────────────────────────────────────────────────

interface CorpusListProps {
  entries: CorpusEntry[];
  onRemove: (sha256: string) => void;
}

function CorpusList({ entries, onRemove }: CorpusListProps) {
  if (entries.length === 0) {
    return <div className="cbp-empty">No corpus entries yet. Add binaries above.</div>;
  }
  return (
    <div className="cbp-corpus-list">
      {entries.map(e => (
        <div key={e.sha256} className={`cbp-corpus-row cbp-gt-${e.groundTruth}`}>
          <div className="cbp-corpus-left">
            <span className="cbp-corpus-label">{e.label}</span>
            {e.expectedClassification && (
              <span className="cbp-corpus-cls">{e.expectedClassification}</span>
            )}
            <span className={`cbp-corpus-gt cbp-gt-badge-${e.groundTruth}`}>{e.groundTruth}</span>
          </div>
          <div className="cbp-corpus-right">
            {e.lastNestSummary && (
              <span
                className="cbp-corpus-conf"
                style={{ color: e.lastNestSummary.finalConfidence >= 85 ? '#4ade80' : '#facc15' }}
              >
                {e.lastNestSummary.finalConfidence}%
              </span>
            )}
            <button
              className="cbp-remove-btn"
              title="Remove from corpus"
              onClick={() => onRemove(e.sha256)}
            >
              ✕
            </button>
          </div>
        </div>
      ))}
    </div>
  );
}

// ── Benchmark history ─────────────────────────────────────────────────────────

interface BenchmarkHistoryProps {
  runs: BenchmarkRun[];
  onDelete: (id: string) => void;
}

function BenchmarkHistory({ runs, onDelete }: BenchmarkHistoryProps) {
  if (runs.length === 0) {
    return (
      <div className="cbp-empty">
        No benchmark runs yet. Benchmark runs are created by the NEST engine
        when analysing corpus entries.
      </div>
    );
  }

  return (
    <div className="cbp-bm-list">
      {runs.map(run => {
        const s = run.summary;
        return (
          <div key={run.id} className={`cbp-bm-row cbp-bm-${run.status}`}>
            <div className="cbp-bm-header">
              <span className="cbp-bm-name">{run.name}</span>
              <span className={`cbp-bm-status cbp-bm-status-${run.status}`}>{run.status}</span>
              <button
                className="cbp-remove-btn"
                title="Delete run"
                onClick={() => onDelete(run.id)}
              >
                ✕
              </button>
            </div>
            <div className="cbp-bm-meta">
              <span className="cbp-bm-date">{fmtDate(run.createdAt)}</span>
              <span className="cbp-bm-entries">{run.entries.length} entries</span>
            </div>
            {s && (
              <div className="cbp-bm-stats">
                <div className="cbp-bm-stat">
                  <span className="cbp-bm-stat-lbl">Pass Rate</span>
                  <span className="cbp-bm-stat-val" style={{ color: passRateColor(s.passRate) }}>
                    {Math.round(s.passRate * 100)}%
                  </span>
                </div>
                <div className="cbp-bm-stat">
                  <span className="cbp-bm-stat-lbl">Passed</span>
                  <span className="cbp-bm-stat-val">{s.passed}/{s.totalEntries}</span>
                </div>
                {s.avgConfidence !== null && (
                  <div className="cbp-bm-stat">
                    <span className="cbp-bm-stat-lbl">Avg Conf</span>
                    <span className="cbp-bm-stat-val">{s.avgConfidence.toFixed(0)}%</span>
                  </div>
                )}
                {s.macroF1 !== null && (
                  <div className="cbp-bm-stat">
                    <span className="cbp-bm-stat-lbl">Macro F1</span>
                    <span className="cbp-bm-stat-val">{(s.macroF1 * 100).toFixed(0)}%</span>
                  </div>
                )}
                {s.avgConfidenceDelta !== null && (
                  <div className="cbp-bm-stat">
                    <span className="cbp-bm-stat-lbl">Δ Conf</span>
                    <span
                      className="cbp-bm-stat-val"
                      style={{ color: s.avgConfidenceDelta >= 0 ? '#4ade80' : '#f87171' }}
                    >
                      {s.avgConfidenceDelta >= 0 ? '+' : ''}{s.avgConfidenceDelta.toFixed(1)}%
                    </span>
                  </div>
                )}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

// ── Export / import controls ──────────────────────────────────────────────────

interface ExportImportProps {
  onImported: () => void;
}

function ExportImportControls({ onImported }: ExportImportProps) {
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  const handleExport = useCallback(() => {
    const json = exportCorpus();
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `hexhawk-corpus-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }, []);

  const handleImport = useCallback(() => {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.json';
    input.onchange = (e) => {
      const file = (e.target as HTMLInputElement).files?.[0];
      if (!file) return;
      const reader = new FileReader();
      reader.onload = () => {
        try {
          const count = importCorpus(reader.result as string);
          setSuccess(`Imported ${count} entries.`);
          setError(null);
          onImported();
          setTimeout(() => setSuccess(null), 3000);
        } catch (err) {
          setError(err instanceof Error ? err.message : String(err));
        }
      };
      reader.readAsText(file);
    };
    input.click();
  }, [onImported]);

  return (
    <div className="cbp-export-row">
      <button className="nest-btn ghost small" onClick={handleExport}>⬇ Export JSON</button>
      <button className="nest-btn ghost small" onClick={handleImport}>⬆ Import JSON</button>
      {error   && <span className="cbp-io-error">{error}</span>}
      {success && <span className="cbp-io-success">{success}</span>}
    </div>
  );
}

// ── Main panel ────────────────────────────────────────────────────────────────

export interface CorpusBenchmarkPanelProps {
  binaryPath: string | null;
  onClose: () => void;
}

export default function CorpusBenchmarkPanel({ binaryPath, onClose }: CorpusBenchmarkPanelProps) {
  const [tab, setTab] = useState<'corpus' | 'benchmarks'>('corpus');
  const [entries, setEntries] = useState<CorpusEntry[]>([]);
  const [runs, setRuns] = useState<BenchmarkRun[]>([]);
  const [showAdd, setShowAdd] = useState(false);

  const refresh = useCallback(() => {
    setEntries(queryCorpus());
    setRuns(loadBenchmarkHistory());
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  const stats = getCorpusStats();

  return (
    <div className="cbp-overlay">
      <div className="cbp-panel">

        {/* Header */}
        <div className="cbp-header">
          <span className="cbp-icon">📦</span>
          <div className="cbp-titles">
            <span className="cbp-title">Corpus &amp; Benchmarks</span>
            <span className="cbp-sub">Manage ground-truth labels and track verdict quality over time</span>
          </div>
          <button className="cbp-close" onClick={onClose}>✕</button>
        </div>

        {/* Tabs */}
        <div className="cbp-tabs">
          <button
            className={`cbp-tab ${tab === 'corpus' ? 'active' : ''}`}
            onClick={() => setTab('corpus')}
          >
            Corpus
            <span className="cbp-tab-count">{stats.totalEntries}</span>
          </button>
          <button
            className={`cbp-tab ${tab === 'benchmarks' ? 'active' : ''}`}
            onClick={() => setTab('benchmarks')}
          >
            Benchmark Runs
            <span className="cbp-tab-count">{runs.length}</span>
          </button>
        </div>

        {/* Corpus tab */}
        {tab === 'corpus' && (
          <div className="cbp-body">
            {/* Stats bar */}
            <div className="cbp-stats-bar">
              <div className="cbp-stat">
                <span className="cbp-stat-lbl">Total</span>
                <span className="cbp-stat-val">{stats.totalEntries}</span>
              </div>
              <div className="cbp-stat">
                <span className="cbp-stat-lbl cbp-gt-clean">Clean</span>
                <span className="cbp-stat-val">{stats.byGroundTruth.clean}</span>
              </div>
              <div className="cbp-stat">
                <span className="cbp-stat-lbl cbp-gt-malicious">Malicious</span>
                <span className="cbp-stat-val">{stats.byGroundTruth.malicious}</span>
              </div>
              <div className="cbp-stat">
                <span className="cbp-stat-lbl">With NEST</span>
                <span className="cbp-stat-val">{stats.withNestResults}</span>
              </div>
              {stats.avgConfidence !== null && (
                <div className="cbp-stat">
                  <span className="cbp-stat-lbl">Avg Conf</span>
                  <span className="cbp-stat-val">{stats.avgConfidence.toFixed(0)}%</span>
                </div>
              )}
            </div>

            {/* Add form toggle */}
            <div className="cbp-add-row-top">
              <button
                className={`nest-btn ${showAdd ? 'ghost' : 'primary'} small`}
                onClick={() => setShowAdd(v => !v)}
              >
                {showAdd ? '▲ Hide' : '+ Add Current Binary'}
              </button>
              <ExportImportControls onImported={refresh} />
            </div>

            {showAdd && (
              <AddEntryForm binaryPath={binaryPath} onAdded={refresh} />
            )}

            {/* Entry list */}
            <CorpusList
              entries={entries}
              onRemove={(sha256) => { removeFromCorpus(sha256); refresh(); }}
            />
          </div>
        )}

        {/* Benchmarks tab */}
        {tab === 'benchmarks' && (
          <div className="cbp-body">
            <div className="cbp-bm-info">
              Benchmark runs are created programmatically via{' '}
              <code>createBenchmarkRun</code> and <code>runBenchmark</code> from{' '}
              <code>benchmarkHarness.ts</code>. Results are stored locally and
              displayed here for regression tracking.
            </div>
            <BenchmarkHistory
              runs={runs}
              onDelete={(id) => { deleteBenchmarkRun(id); refresh(); }}
            />
          </div>
        )}
      </div>
    </div>
  );
}
