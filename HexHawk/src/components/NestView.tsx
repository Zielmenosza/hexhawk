/**
 * NestView — NEST Self-Improving Analysis Loop UI
 *
 * Orchestrates the NEST engine:
 *   - Drives iteration loop: invoke Tauri, run ECHO+signatures, run correlation pass
 *   - Evaluates convergence after each iteration
 *   - Generates and displays the refinement plan
 *   - Renders a timeline of iteration snapshots with delta highlighting
 *   - Shows a live confidence convergence chart
 */

import React, { useState, useCallback, useRef, useEffect } from 'react';
import {
  summarizeSession,
  computeWorkSaved,
  DEFAULT_NEST_CONFIG,
  type NestConfig,
  type NestSession,
  type NestIterationSnapshot,
  type NestRefinementAction,
  type NestSummary,
} from '../utils/nestEngine';
import {
  getReadyActions,
  summarisePlan,
  type AnalysisPlan,
  type StrategyAction,
  type StrategyClass,
} from '../utils/strategyEngine';
import {
  getLearningRecord,
  getLearningBoosts,
  getEchoEnhancements,
  getStrategyReliability,
  type BinaryLearningRecord,
  type LearningBoosts,
  type SimilarBinary,
} from '../utils/learningStore';
import {
  type LearningSession,
  type LearningDecision,
  type ImprovementLevel,
} from '../utils/iterationLearning';
import {
  loadDominanceAssessment,
  type DominanceAssessment,
} from '../utils/dominanceEngine';
import {
  buildCrossBinaryReport,
  computeSignalWeightAdjustments,
  type CrossBinaryReport,
} from '../utils/crossBinaryAdvisor';
import {
  createBatchRun,
  markItemRunning,
  completeItem as completeBatchItem,
  failItem as failBatchItem,
  finalizeBatch,
  computeStabilityScore,
  computeConvergenceSpeed,
  type BatchRunState,
  type BatchQueueItem,
  type BatchItemResult,
  type BatchMetrics,
} from '../utils/multiBinaryRunner';
import type {
  FileMetadata,
  StringMatch,
  DisassembledInstruction,
  DisassemblyAnalysis,
} from '../App';
import { WorkSavedPanel } from './WorkSavedPanel';
import type { BinaryVerdictResult } from '../utils/correlationEngine';
import type { StrikeCorrelationSignal } from '../utils/strikeEngine';
import {
  CURATED_TRAINING_BINARIES,
  DEFAULT_TRAINING_BINARY,
  TEST_SUBJECT_SUITE,
  TIER_META,
  getDefaultSubject,
  formatSize,
  type TrainingCandidate,
  type TestSubject,
  type TestSubjectTier,
  type TierStatus,
} from '../utils/trainingBinaryEvaluator';
import {
  type TrainingRecord,
  type TrainingStats,
} from '../utils/nestTrainingStore';
import { checkRegressionWarning, type HealResult } from '../utils/nestAdaptiveHealer';
import {
  type NestDiagnosticsReport,
  type DiagnosticOutcome,
  type DiagnosticDimension,
} from '../utils/nestDiagnostics';
// ── Engine — all execution logic lives here ───────────────────────────────────
import {
  NestSessionRunner,
  runNestSession,
  type NestStepResult,
  type NestSessionResult,
  type NestPostProcessingResult,
} from '../engines/nest/NestSessionRunner';
import CorpusBenchmarkPanel from './CorpusBenchmarkPanel';


// ── TrainingBinaryPicker ──────────────────────────────────────────────────────

const SCORE_BAR: Record<number, string> = {
  10: '██████████', 9: '█████████░', 8: '████████░░',
  7: '███████░░░', 6: '██████░░░░', 5: '█████░░░░░',
};

function TrainingBinaryPicker({
  onLoad,
}: {
  onLoad: (path: string) => void;
}) {
  const [selected, setSelected] = React.useState<string>(DEFAULT_TRAINING_BINARY.path);

  return (
    <div className="nest-tbp">
      <div className="nest-tbp-header">
        <span className="nest-tbp-icon">🎯</span>
        <span className="nest-tbp-title">Suggested Training Binaries</span>
        <span className="nest-tbp-sub">Stable, well-structured executables ideal for NEST learning</span>
      </div>
      <div className="nest-tbp-list">
        {CURATED_TRAINING_BINARIES.map((c: TrainingCandidate) => (
          <div
            key={c.path}
            className={`nest-tbp-row${selected === c.path ? ' sel' : ''}`}
            onClick={() => setSelected(c.path)}
          >
            <div className="nest-tbp-row-left">
              <div className="nest-tbp-row-name">{c.label}</div>
              <div className="nest-tbp-row-desc">{c.description}</div>
              <div className="nest-tbp-row-tags">
                {c.tags.map(t => (
                  <span key={t} className="nest-tbp-tag">{t}</span>
                ))}
              </div>
            </div>
            <div className="nest-tbp-row-right">
              <div className="nest-tbp-score">
                <span className="nest-tbp-score-bar">{SCORE_BAR[c.score] ?? '░░░░░░░░░░'}</span>
                <span className="nest-tbp-score-num">{c.score}/10</span>
              </div>
              <div className="nest-tbp-size">{formatSize(c.sizeBytes)}</div>
            </div>
          </div>
        ))}
      </div>
      <div className="nest-tbp-actions">
        <span className="nest-tbp-path">{selected}</span>
        <button
          className="nest-btn primary nest-tbp-load"
          onClick={() => onLoad(selected)}
        >
          Load as Training Binary
        </button>
      </div>
    </div>
  );
}

// ── SuiteResultsPanel ─────────────────────────────────────────────────────────

interface SuiteResultsPanelProps {
  batchRun:   BatchRunState;
  onClose:    () => void;
  onStop:     () => void;
}

function SuiteResultsPanel({ batchRun, onClose, onStop }: SuiteResultsPanelProps) {
  const isRunning = batchRun.status === 'running';
  const isDone    = batchRun.status === 'complete';
  const m         = batchRun.metrics;

  // Map each batch item back to its tier metadata for display
  function subjectForItem(item: BatchQueueItem) {
    return TEST_SUBJECT_SUITE.find(s => s.path === item.path);
  }

  // Derive a pass/fail grade from a completed item
  function grade(item: BatchQueueItem): { pass: boolean; reason: string } {
    const r = item.result;
    if (!r) return { pass: false, reason: 'Did not complete' };
    const subj = subjectForItem(item);
    if (!subj) return { pass: true, reason: 'No expected outcome defined' };

    if (r.verdict !== subj.expectedClassification)
      return { pass: false, reason: `Misclassified: got '${r.verdict}', expected '${subj.expectedClassification}'` };
    if (r.weaknessFlags.includes('contradiction-heavy'))
      return { pass: subj.tier === 'challenge', reason: subj.tier === 'challenge' ? 'Contradictions acceptable at challenge tier' : 'Unresolved contradictions' };
    if (subj.tier === 'baseline' && r.dominanceStatus !== 'DOMINATED')
      return { pass: false, reason: 'Baseline must reach DOMINATED — confirm all pipeline steps ran' };
    if (r.weaknessFlags.includes('negative-improvement'))
      return { pass: false, reason: 'Confidence regressed across iterations' };
    return { pass: true, reason: '' };
  }

  // Format stop reason to short label
  function stopLabel(r: BatchItemResult['convergenceSpeed']['stopReason'] | undefined): string {
    if (!r) return '—';
    const m: Record<string, string> = {
      converged: 'CONVERGED', plateau: 'PLATEAU', 'max-reached': 'MAX ITER', error: 'ERROR', unknown: '—',
    };
    return m[r] ?? r;
  }

  // Compute "loss" proxy: remaining uncertainty at convergence
  function lossProxy(item: BatchQueueItem): string {
    if (!item.result) return '—';
    const remaining = 100 - item.result.finalConfidence;
    const gain = item.result.convergenceSpeed.gainPerIteration.toFixed(1);
    return `${remaining}% (${gain} pts/iter)`;
  }

  // Count contradiction-heavy flag
  function contradictionNote(item: BatchQueueItem): string {
    if (!item.result) return '—';
    return item.result.weaknessFlags.includes('contradiction-heavy') ? 'Heavy' : 'None';
  }

  const passCount = batchRun.items.filter(it => it.status === 'completed' && grade(it).pass).length;
  const doneCount = batchRun.items.filter(it => it.status === 'completed').length;

  return (
    <div className="nest-srs">

      {/* Header */}
      <div className="nest-srs-header">
        <span className="nest-srs-icon">⬡</span>
        <div className="nest-srs-titles">
          <span className="nest-srs-title">Suite Benchmark</span>
          <span className="nest-srs-sub">3-tier progressive NEST performance measurement</span>
        </div>
        <div className="nest-srs-header-right">
          {isRunning && (
            <button className="nest-btn ghost" onClick={onStop}>
              Stop
            </button>
          )}
          {isDone && (
            <span className={`nest-srs-score-badge ${passCount === 3 ? 'all-pass' : passCount === 0 ? 'all-fail' : 'partial'}`}>
              {passCount}/{doneCount} passed
            </span>
          )}
          <button className="nest-tss-expand-btn" onClick={onClose} title="Close results">✕</button>
        </div>
      </div>

      {/* Per-tier result rows */}
      <div className="nest-srs-tiers">
        {batchRun.items.map((item) => {
          const subj   = subjectForItem(item);
          const tier   = subj?.tier;
          const meta   = tier ? TIER_META[tier] : null;
          const g      = item.status === 'completed' ? grade(item) : null;
          const r      = item.result;

          return (
            <div
              key={item.id}
              className={`nest-srs-row nest-srs-row--${tier ?? 'unknown'}${item.status === 'running' ? ' running' : ''}${item.status === 'completed' ? (g?.pass ? ' pass' : ' fail') : ''}`}
            >
              {/* Tier badge */}
              <div className="nest-srs-tier-col">
                {meta ? (
                  <span className="nest-srs-tier-badge" style={{ color: meta.color, borderColor: meta.color }}>
                    {meta.icon} {meta.shortLabel}
                  </span>
                ) : (
                  <span className="nest-srs-tier-badge">?</span>
                )}
              </div>

              {/* Label + status */}
              <div className="nest-srs-label-col">
                <span className="nest-srs-label">{item.label}</span>
                <span className={`nest-srs-status nest-srs-status--${item.status}`}>
                  {item.status === 'running' ? 'Running…' :
                   item.status === 'pending' ? 'Queued' :
                   item.status === 'error'   ? `Error: ${item.errorMessage ?? ''}` :
                   item.status === 'completed' ? (g?.pass ? '✓ Pass' : `✗ Fail`) : item.status}
                </span>
                {g && !g.pass && g.reason && (
                  <span className="nest-srs-fail-reason">{g.reason}</span>
                )}
              </div>

              {/* Metrics grid */}
              {r ? (
                <div className="nest-srs-metrics">
                  <div className="nest-srs-metric">
                    <span className="nest-srs-m-lbl">Verdict</span>
                    <span className={`nest-srs-m-val verdict-${r.verdict}`}>{r.verdict}</span>
                  </div>
                  <div className="nest-srs-metric">
                    <span className="nest-srs-m-lbl">Confidence</span>
                    <span className="nest-srs-m-val" style={{ color: r.finalConfidence >= 85 ? '#4ade80' : r.finalConfidence >= 65 ? '#facc15' : '#f87171' }}>
                      {r.finalConfidence}%
                    </span>
                  </div>
                  <div className="nest-srs-metric">
                    <span className="nest-srs-m-lbl">Iterations</span>
                    <span className="nest-srs-m-val">{r.iterationCount}</span>
                  </div>
                  <div className="nest-srs-metric">
                    <span className="nest-srs-m-lbl">Stop</span>
                    <span className={`nest-srs-m-val stop-${r.convergenceSpeed.stopReason}`}>{stopLabel(r.convergenceSpeed.stopReason)}</span>
                  </div>
                  <div className="nest-srs-metric">
                    <span className="nest-srs-m-lbl">Loss / Gain</span>
                    <span className="nest-srs-m-val">{lossProxy(item)}</span>
                  </div>
                  <div className="nest-srs-metric">
                    <span className="nest-srs-m-lbl">Contradictions</span>
                    <span className={`nest-srs-m-val ${contradictionNote(item) === 'Heavy' ? 'contra-heavy' : ''}`}>{contradictionNote(item)}</span>
                  </div>
                  <div className="nest-srs-metric">
                    <span className="nest-srs-m-lbl">Stability</span>
                    <span className="nest-srs-m-val">{r.stabilityScore}/100</span>
                  </div>
                  <div className="nest-srs-metric">
                    <span className="nest-srs-m-lbl">Dominance</span>
                    <span className={`nest-srs-m-val dom-${r.dominanceStatus.toLowerCase()}`}>{r.dominanceStatus}</span>
                  </div>
                </div>
              ) : item.status === 'running' ? (
                <div className="nest-srs-running-pulse">Analysing…</div>
              ) : (
                <div className="nest-srs-metrics nest-srs-metrics--empty">
                  {['Verdict','Confidence','Iterations','Stop','Loss / Gain','Contradictions','Stability','Dominance'].map(l => (
                    <div key={l} className="nest-srs-metric">
                      <span className="nest-srs-m-lbl">{l}</span>
                      <span className="nest-srs-m-val nest-srs-m-pending">—</span>
                    </div>
                  ))}
                </div>
              )}

              {/* Weakness flags */}
              {r && r.weaknessFlags.length > 0 && (
                <div className="nest-srs-flags">
                  {r.weaknessFlags.map(f => (
                    <span key={f} className="nest-srs-flag">{f}</span>
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Summary bar — shown when complete */}
      {isDone && (
        <div className="nest-srs-summary">
          <div className="nest-srs-summary-stat">
            <span className="nest-srs-summary-lbl">Avg Confidence</span>
            <span className="nest-srs-summary-val">{m.avgFinalConfidence.toFixed(0)}%</span>
          </div>
          <div className="nest-srs-summary-stat">
            <span className="nest-srs-summary-lbl">Avg Iterations</span>
            <span className="nest-srs-summary-val">{m.avgIterations.toFixed(1)}</span>
          </div>
          <div className="nest-srs-summary-stat">
            <span className="nest-srs-summary-lbl">Convergence Rate</span>
            <span className="nest-srs-summary-val">{Math.round(m.convergenceRate * 100)}%</span>
          </div>
          <div className="nest-srs-summary-stat">
            <span className="nest-srs-summary-lbl">Stable Rate</span>
            <span className="nest-srs-summary-val">{Math.round(m.stableRate * 100)}%</span>
          </div>
          <div className="nest-srs-summary-stat">
            <span className="nest-srs-summary-lbl">Suite Score</span>
            <span className={`nest-srs-summary-val nest-srs-suite-score ${passCount === 3 ? 'all-pass' : passCount === 0 ? 'all-fail' : 'partial'}`}>
              {passCount}/3
            </span>
          </div>
        </div>
      )}
    </div>
  );
}

// ── DiagnosticsPanel ─────────────────────────────────────────────────────────

const OUTCOME_META: Record<DiagnosticOutcome, { color: string; bg: string; border: string; icon: string }> = {
  SUCCESS:          { color: '#4ade80', bg: '#4ade8012', border: '#4ade8040', icon: '✓' },
  UNDERFITTING:     { color: '#facc15', bg: '#facc1512', border: '#facc1540', icon: '⬇' },
  OVERFITTING:      { color: '#fb923c', bg: '#fb923c12', border: '#fb923c40', icon: '⬆' },
  MISCLASSIFICATION:{ color: '#f87171', bg: '#f8717112', border: '#f8717140', icon: '✗' },
};

function DiagDimensionCard({ dim }: { dim: DiagnosticDimension }) {
  const [open, setOpen] = React.useState(false);
  const statusColor = dim.status === 'healthy' ? '#4ade80' : dim.status === 'warning' ? '#facc15' : '#f87171';
  const barWidth = `${dim.score}%`;

  return (
    <div className={`nest-diag-dim nest-diag-dim--${dim.status}`}>
      <button className="nest-diag-dim-header" onClick={() => setOpen(o => !o)}>
        <span className="nest-diag-dim-icon">{dim.icon}</span>
        <span className="nest-diag-dim-label">{dim.label}</span>
        <div className="nest-diag-dim-bar-wrap">
          <div className="nest-diag-dim-bar" style={{ width: barWidth, background: statusColor }} />
        </div>
        <span className="nest-diag-dim-score" style={{ color: statusColor }}>{dim.score}</span>
        <span className="nest-diag-dim-chevron">{open ? '▲' : '▼'}</span>
      </button>

      {open && (
        <div className="nest-diag-dim-body">
          {dim.observations.length > 0 && (
            <ul className="nest-diag-obs-list">
              {dim.observations.map((o, i) => (
                <li key={i} className="nest-diag-obs">{o}</li>
              ))}
            </ul>
          )}
          <div className="nest-diag-checks">
            {dim.checks.map(c => (
              <div key={c.id} className={`nest-diag-check ${c.pass ? 'pass' : `fail--${c.severity}`}`}>
                <span className="nest-diag-check-icon">{c.pass ? '✓' : c.severity === 'critical' ? '✗' : '!'}</span>
                <div className="nest-diag-check-body">
                  <span className="nest-diag-check-label">{c.label}</span>
                  <span className="nest-diag-check-value">{c.value}</span>
                </div>
                <span className="nest-diag-check-detail">{c.detail}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function DiagnosticsSparkline({ values, color }: { values: number[]; color: string }) {
  if (values.length < 2) return null;
  const min = Math.min(...values);
  const max = Math.max(...values);
  const range = max - min || 1;
  const W = 120, H = 30, pad = 3;
  const pts = values.map((v, i) => {
    const x = pad + (i / (values.length - 1)) * (W - pad * 2);
    const y = H - pad - ((v - min) / range) * (H - pad * 2);
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(' ');
  return (
    <svg width={W} height={H} className="nest-diag-spark">
      <polyline points={pts} fill="none" stroke={color} strokeWidth="1.5" strokeLinejoin="round" />
    </svg>
  );
}

interface DiagnosticsPanelProps {
  report:   NestDiagnosticsReport;
  onClose?: () => void;
}

function DiagnosticsPanel({ report, onClose }: DiagnosticsPanelProps) {
  const [expanded, setExpanded] = React.useState(true);
  const meta    = OUTCOME_META[report.outcome];
  const { summary } = report;

  const confValues  = report.trace.map(t => t.confidence);
  const contraValues= report.trace.map(t => t.contradictions);

  return (
    <div className="nest-diag" style={{ borderColor: meta.border, background: meta.bg }}>
      {/* ── Header ── */}
      <div className="nest-diag-header" style={{ borderBottomColor: meta.border }}>
        <span className="nest-diag-outcome-badge" style={{ color: meta.color, borderColor: meta.border }}>
          {meta.icon} {report.outcomeLabel.toUpperCase()}
        </span>
        <div className="nest-diag-title-wrap">
          <span className="nest-diag-title">NEST Diagnostics</span>
          <span className="nest-diag-subtitle">{report.outcomeReason}</span>
        </div>
        <div className="nest-diag-header-right">
          <span className="nest-diag-conf-badge">
            {report.diagnosticConfidence}% certain
          </span>
          <button className="nest-diag-toggle" onClick={() => setExpanded(o => !o)}>
            {expanded ? '▲' : '▼'}
          </button>
          {onClose && (
            <button className="nest-diag-close" onClick={onClose}>✕</button>
          )}
        </div>
      </div>

      {expanded && (
        <>
          {/* ── Summary metrics ── */}
          <div className="nest-diag-summary-bar">
            {[
              { l: 'Iters',         v: summary.totalIterations },
              { l: 'First Conf',    v: `${summary.firstConfidence}%` },
              { l: 'Final Conf',    v: `${summary.finalConfidence}%`, color: summary.finalConfidence >= 80 ? '#4ade80' : summary.finalConfidence >= 65 ? '#facc15' : '#f87171' },
              { l: 'Total Gain',    v: `${summary.totalGain >= 0 ? '+' : ''}${summary.totalGain.toFixed(0)}%`, color: summary.totalGain >= 5 ? '#4ade80' : summary.totalGain < 0 ? '#f87171' : '#facc15' },
              { l: 'Avg/Iter',      v: `${summary.avgGainPerIter.toFixed(1)} pts` },
              { l: 'Contradictions',v: summary.finalContradictions, color: summary.finalContradictions === 0 ? '#4ade80' : summary.finalContradictions >= 2 ? '#f87171' : '#facc15' },
              { l: 'Stop',          v: summary.stopReason },
              { l: 'Stability',     v: `${summary.stabilityScore}%`, color: summary.stabilityScore >= 80 ? '#4ade80' : '#facc15' },
            ].map(({ l, v, color }) => (
              <div key={l} className="nest-diag-stat">
                <span className="nest-diag-stat-lbl">{l}</span>
                <span className="nest-diag-stat-val" style={color ? { color } : undefined}>{v}</span>
              </div>
            ))}
          </div>

          {/* ── Sparklines ── */}
          {report.trace.length >= 2 && (
            <div className="nest-diag-sparks">
              <div className="nest-diag-spark-item">
                <span className="nest-diag-spark-lbl">Confidence</span>
                <DiagnosticsSparkline values={confValues} color="#7c6af5" />
              </div>
              <div className="nest-diag-spark-item">
                <span className="nest-diag-spark-lbl">Contradictions</span>
                <DiagnosticsSparkline values={contraValues} color="#f87171" />
              </div>
            </div>
          )}

          {/* ── Four dimensions ── */}
          <div className="nest-diag-dims">
            {Object.values(report.dimensions).map(dim => (
              <DiagDimensionCard key={dim.id} dim={dim} />
            ))}
          </div>

          {/* ── Actionable insights ── */}
          {report.actionableInsights.length > 0 && (
            <div className="nest-diag-insights">
              <div className="nest-diag-insights-title">Actionable Insights</div>
              <ul className="nest-diag-insights-list">
                {report.actionableInsights.map((ins, i) => (
                  <li key={i} className="nest-diag-insight">{ins}</li>
                ))}
              </ul>
            </div>
          )}
        </>
      )}
    </div>
  );
}

// ── HealerBanner ──────────────────────────────────────────────────────────────

function HealerBanner({ result, onDismiss, regression }: {
  result:     HealResult;
  onDismiss:  () => void;
  regression: string | null;
}) {
  const [open, setOpen] = React.useState(false);

  if (!result.changed && !regression) return null;

  return (
    <div className={`nest-healer-banner ${result.changed ? 'changed' : 'noop'} ${regression ? 'regression' : ''}`}>
      <div className="nest-healer-banner-header">
        <span className="nest-healer-banner-icon">{result.changed ? '⚙' : 'ℹ'}</span>
        <div className="nest-healer-banner-text">
          {regression && (
            <span className="nest-healer-regression">{regression}</span>
          )}
          <span className="nest-healer-summary">{result.summary}</span>
        </div>
        {result.fixes.length > 0 && (
          <button className="nest-healer-expand" onClick={() => setOpen(o => !o)}>
            {result.fixes.length} fix{result.fixes.length > 1 ? 'es' : ''} {open ? '▲' : '▼'}
          </button>
        )}
        <button className="nest-healer-dismiss" onClick={onDismiss}>✕</button>
      </div>
      {open && result.fixes.length > 0 && (
        <div className="nest-healer-fixes">
          {result.fixes.map((f, i) => (
            <div key={i} className="nest-healer-fix">
              <span className="nest-healer-fix-field">{String(f.field)}</span>
              <span className="nest-healer-fix-arrow">→</span>
              <span className="nest-healer-fix-old">{String(f.oldValue)}</span>
              <span className="nest-healer-fix-arrow">⇒</span>
              <span className="nest-healer-fix-new">{String(f.newValue)}</span>
              <span className="nest-healer-fix-reason">{f.reason}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── TrainingHistoryPanel ──────────────────────────────────────────────────────

const OUTCOME_COLOR: Record<string, string> = {
  SUCCESS:          '#4ade80',
  UNDERFITTING:     '#facc15',
  OVERFITTING:      '#fb923c',
  MISCLASSIFICATION:'#f87171',
};

function TrainingHistoryPanel({ records, stats, onClose }: {
  records: TrainingRecord[];
  stats:   TrainingStats | null;
  onClose: () => void;
}) {
  return (
    <div className="nest-training-panel">
      <div className="nest-training-header">
        <span className="nest-training-title">Training History</span>
        <span className="nest-training-sub">{records.length} session{records.length !== 1 ? 's' : ''} stored</span>
        <button className="nest-training-close" onClick={onClose}>✕</button>
      </div>

      {/* Aggregate stats */}
      {stats && stats.totalSessions > 0 && (
        <div className="nest-training-stats">
          {([
            { l: 'Total',    v: stats.totalSessions },
            { l: 'Success',  v: `${Math.round(stats.successRate * 100)}%`,  color: '#4ade80' },
            { l: 'Healed',   v: `${Math.round(stats.healRate * 100)}%`,     color: '#7c6af5' },
            { l: 'Avg Conf', v: `${stats.avgFinalConfidence.toFixed(0)}%` },
            { l: 'Avg Gain', v: `${stats.avgTotalGain >= 0 ? '+' : ''}${stats.avgTotalGain.toFixed(1)}%` },
          ] as { l: string; v: string | number; color?: string }[]).map(({ l, v, color }) => (
            <div key={l} className="nest-training-stat">
              <span className="nest-training-stat-lbl">{l}</span>
              <span className="nest-training-stat-val" style={color ? { color } : undefined}>{v}</span>
            </div>
          ))}
          {/* Outcome breakdown bar */}
          <div className="nest-training-breakdown">
            {(['SUCCESS', 'UNDERFITTING', 'OVERFITTING', 'MISCLASSIFICATION'] as const).map(o => {
              const count = stats.outcomeBreakdown[o];
              if (count === 0) return null;
              const pct   = (count / stats.totalSessions) * 100;
              return (
                <div
                  key={o}
                  className="nest-training-breakdown-seg"
                  style={{ width: `${pct}%`, background: OUTCOME_COLOR[o] }}
                  title={`${o}: ${count}`}
                />
              );
            })}
          </div>
        </div>
      )}

      {/* Record list */}
      <div className="nest-training-list">
        {records.length === 0 && (
          <div className="nest-training-empty">No training records yet. Run a session to begin.</div>
        )}
        {records.map(r => (
          <div key={r.id} className={`nest-training-row outcome-${r.outcome.toLowerCase()}`}>
            <div className="nest-training-row-top">
              <span
                className="nest-training-row-outcome"
                style={{ color: OUTCOME_COLOR[r.outcome] }}
              >
                {r.outcome}
              </span>
              <span className="nest-training-row-label">{r.binaryLabel}</span>
              <span className="nest-training-row-conf">{r.finalConfidence}%</span>
              <span className="nest-training-row-gain">
                {r.totalGain >= 0 ? '+' : ''}{r.totalGain.toFixed(0)}pts
              </span>
              <span className="nest-training-row-iters">{r.iterationHistory.length} iter</span>
              <span className="nest-training-row-ts">
                {new Date(r.timestamp).toLocaleTimeString()}
              </span>
            </div>
            <div className="nest-training-row-reason">{r.outcomeReason}</div>
            {r.fixesApplied.length > 0 && (
              <div className="nest-training-row-fixes">
                {r.fixesApplied.map((f, i) => (
                  <span key={i} className="nest-training-row-fix">
                    {String(f.field)} {String(f.oldValue)}→{String(f.newValue)}
                  </span>
                ))}
              </div>
            )}
            {/* Mini loss-progression bar */}
            {r.lossProgression.length >= 2 && (
              <div className="nest-training-row-loss">
                {r.lossProgression.map((l, i) => (
                  <div
                    key={i}
                    className="nest-training-loss-seg"
                    style={{ height: `${Math.max(2, (l / 100) * 20)}px` }}
                    title={`iter ${i}: loss ${l.toFixed(0)}`}
                  />
                ))}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Props ─────────────────────────────────────────────────────────────────────

interface NestViewProps {
  binaryPath:           string;
  metadata:             FileMetadata | null;
  disassembly:          DisassembledInstruction[];
  strings:              StringMatch[];
  disassemblyAnalysis:  DisassemblyAnalysis;
  /** Initial disassembly byte offset in the file */
  disasmOffset:         number;
  /** Initial disassembly byte length requested */
  disasmLength:         number;
  /** Optional STRIKE runtime signals if a session is active */
  strikeSignals?:       StrikeCorrelationSignal;
  onAddressSelect:      (addr: number) => void;
  /** Called when user picks a training binary from the picker — parent should set binary path */
  onLoadTrainingBinary?: (path: string) => void;
  /** Called when a NEST session completes — provides the final enriched verdict */
  onNestComplete?: (verdict: BinaryVerdictResult) => void;
}

// ── Helper: format ms ─────────────────────────────────────────────────────────

function fmtMs(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

function fmtHex(n: number): string {
  return `0x${n.toString(16).toUpperCase()}`;
}

// ── NestTestSubjectSelector ───────────────────────────────────────────────────

const DIFFICULTY_BAR = (score: number) =>
  Array.from({ length: 10 }, (_, i) => (i < score ? '█' : '░')).join('');

const TIER_ORDER: TestSubjectTier[] = ['baseline', 'intermediate', 'challenge'];

function NestTestSubjectSelector({
  onLoad,
  onRunSuite,
}: {
  onLoad:       (path: string) => void;
  onRunSuite?:  () => void;
}) {
  const [slotStatus, setSlotStatus] = React.useState<Record<TestSubjectTier, TierStatus>>({
    baseline:     'ready',
    intermediate: 'ready',
    challenge:    'ready',
  });
  const [activeTier, setActiveTier] = React.useState<TestSubjectTier>('baseline');
  const [showDetails, setShowDetails] = React.useState<TestSubjectTier | null>(null);

  function loadSubject(subject: TestSubject) {
    setSlotStatus(prev => ({ ...prev, [subject.tier]: 'active' }));
    setActiveTier(subject.tier);
    onLoad(subject.path);
  }

  function markDone(tier: TestSubjectTier) {
    setSlotStatus(prev => ({ ...prev, [tier]: 'done' }));
    // Auto-advance active indicator to next tier
    const idx = TIER_ORDER.indexOf(tier);
    if (idx < TIER_ORDER.length - 1) setActiveTier(TIER_ORDER[idx + 1]);
  }

  const allDone = TIER_ORDER.every(t => slotStatus[t] === 'done');

  return (
    <div className="nest-tss">

      {/* Header */}
      <div className="nest-tss-header">
        <span className="nest-tss-icon">⬡</span>
        <div className="nest-tss-titles">
          <span className="nest-tss-title">Test Subject Selector</span>
          <span className="nest-tss-sub">
            Progressive 3-tier training suite — deterministic, no randomness
          </span>
        </div>
        {allDone && (
          <span className="nest-tss-complete-badge">✓ Suite Complete</span>
        )}
      </div>

      {/* Progression ladder */}
      <div className="nest-tss-ladder">
        {TIER_ORDER.map((tier, idx) => {
          const subject = getDefaultSubject(tier);
          const meta    = TIER_META[tier];
          const status  = slotStatus[tier];
          const isOpen  = showDetails === tier;
          const isLocked = idx > 0 && slotStatus[TIER_ORDER[idx - 1]] === 'ready';

          return (
            <div
              key={tier}
              className={`nest-tss-slot nest-tss-slot--${tier}${status === 'active' ? ' active' : ''}${status === 'done' ? ' done' : ''}${isLocked ? ' locked' : ''}`}
            >
              {/* Connector line between cards */}
              {idx > 0 && (
                <div className={`nest-tss-connector${slotStatus[TIER_ORDER[idx - 1]] === 'done' ? ' lit' : ''}`} />
              )}

              {/* Tier badge row */}
              <div className="nest-tss-slot-top">
                <div className="nest-tss-tier-badge" style={{ borderColor: meta.color, color: meta.color }}>
                  <span className="nest-tss-tier-icon">{meta.icon}</span>
                  <span className="nest-tss-tier-label">{meta.shortLabel}</span>
                </div>

                <div className="nest-tss-slot-info">
                  <div className="nest-tss-slot-name">{subject.label}</div>
                  <div className="nest-tss-slot-path">{subject.path}</div>
                </div>

                <div className="nest-tss-slot-meta">
                  <div className="nest-tss-diff">
                    <span className="nest-tss-diff-bar"
                      style={{ color: meta.color }}>{DIFFICULTY_BAR(subject.difficultyScore)}</span>
                    <span className="nest-tss-diff-num">{subject.difficultyScore}/10</span>
                  </div>
                  <div className="nest-tss-slot-size">{formatSize(subject.sizeBytes)}</div>
                </div>

                <div className="nest-tss-slot-actions">
                  {status === 'done' ? (
                    <span className="nest-tss-status-done">✓ Done</span>
                  ) : (
                    <button
                      className={`nest-btn${status === 'active' ? ' primary' : ' ghost'} nest-tss-load-btn`}
                      disabled={isLocked}
                      title={isLocked ? 'Complete the previous tier first' : `Load ${subject.label}`}
                      onClick={() => loadSubject(subject)}
                    >
                      {status === 'active' ? 'Loaded' : 'Load'}
                    </button>
                  )}
                  {status === 'active' && (
                    <button
                      className="nest-btn ghost nest-tss-done-btn"
                      onClick={() => markDone(tier)}
                      title="Mark this tier as complete and advance"
                    >
                      Mark Done
                    </button>
                  )}
                  <button
                    className="nest-tss-expand-btn"
                    onClick={() => setShowDetails(isOpen ? null : tier)}
                    title={isOpen ? 'Hide details' : 'Show expected signals and learning goal'}
                  >
                    {isOpen ? '▲' : '▼'}
                  </button>
                </div>
              </div>

              {/* Description */}
              <div className="nest-tss-slot-desc">{subject.description}</div>

              {/* Tags */}
              <div className="nest-tss-tags">
                {subject.tags.map(t => (
                  <span key={t} className="nest-tbp-tag">{t}</span>
                ))}
              </div>

              {/* Expanded detail panel */}
              {isOpen && (
                <div className="nest-tss-detail">
                  <div className="nest-tss-detail-row">
                    <span className="nest-tss-detail-lbl">Learning goal</span>
                    <span className="nest-tss-detail-val">{subject.learningGoal}</span>
                  </div>
                  <div className="nest-tss-detail-row">
                    <span className="nest-tss-detail-lbl">Tier rationale</span>
                    <span className="nest-tss-detail-val">{subject.tierRationale}</span>
                  </div>
                  <div className="nest-tss-detail-row">
                    <span className="nest-tss-detail-lbl">Expected signals</span>
                    <span className="nest-tss-detail-signals">
                      {subject.expectedSignals.map(s => (
                        <span key={s} className="nest-tss-signal-chip">{s}</span>
                      ))}
                    </span>
                  </div>
                  <div className="nest-tss-detail-row">
                    <span className="nest-tss-detail-lbl">Expected verdict</span>
                    <span className="nest-tss-verdict-chip">{subject.expectedClassification}</span>
                  </div>
                  <div className="nest-tss-detail-row">
                    <span className="nest-tss-detail-lbl">Recommended iterations</span>
                    <span className="nest-tss-detail-val">≤{subject.recommendedIterations}</span>
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Footer hint */}
      <div className="nest-tss-footer">
        <span className="nest-tss-footer-rule">Size: 200 KB – 5 MB</span>
        <span className="nest-tss-footer-sep">·</span>
        <span className="nest-tss-footer-rule">Valid .exe / .dll</span>
        <span className="nest-tss-footer-sep">·</span>
        <span className="nest-tss-footer-rule">Microsoft-signed, no packing</span>
        <span className="nest-tss-footer-sep">·</span>
        <span className="nest-tss-footer-rule">Progressive difficulty — not random</span>
        {onRunSuite && (
          <>
            <span className="nest-tss-footer-sep" style={{ marginLeft: 'auto' }}>·</span>
            <button className="nest-btn primary nest-tss-run-suite-btn" onClick={onRunSuite}>
              ▶ Run Full Suite
            </button>
          </>
        )}
      </div>
    </div>
  );
}



function confidenceColor(c: number): string {
  if (c >= 85) return '#4caf50';
  if (c >= 65) return '#ff9800';
  if (c >= 40) return '#f44336';
  return '#9e9e9e';
}

function verdictColor(v: string): string {
  const l = v.toLowerCase();
  if (l.includes('malicious')) return '#f44336';
  if (l.includes('suspicious')) return '#ff9800';
  if (l.includes('clean') || l.includes('safe')) return '#4caf50';
  return '#90a4ae';
}

// ── Sub-components ────────────────────────────────────────────────────────────

const ActionBadge: React.FC<{ action: NestRefinementAction }> = ({ action }) => {
  const colors: Record<string, string> = {
    high: '#f44336', medium: '#ff9800', low: '#4caf50',
  };
  const icons: Partial<Record<string, string>> = {
    'expand-disasm-forward':  '→',
    'expand-disasm-backward': '←',
    'focus-high-entropy':     '🌡',
    'follow-cfg-path':        '⬡',
    'deep-echo':              '◎',
    'talon-focus':            '⟁',
    'string-context':         '"',
    'import-context':         '⚠',
  };
  return (
    <span className="nest-action-badge" style={{ borderColor: colors[action.priority] }}>
      <span className="nest-action-icon">{icons[action.type] ?? '•'}</span>
      <span className="nest-action-type">{action.type}</span>
      <span className="nest-action-prio" style={{ color: colors[action.priority] }}>
        {action.priority}
      </span>
    </span>
  );
};

const ConfidenceBar: React.FC<{ value: number; prev?: number; compact?: boolean }> = ({
  value, prev, compact,
}) => {
  const delta = prev != null ? value - prev : null;
  return (
    <div className={`nest-conf-bar-wrap${compact ? ' compact' : ''}`}>
      <div className="nest-conf-track">
        <div
          className="nest-conf-fill"
          style={{ width: `${value}%`, background: confidenceColor(value) }}
        />
        {prev != null && (
          <div
            className="nest-conf-prev-marker"
            style={{ left: `${prev}%` }}
          />
        )}
      </div>
      <span className="nest-conf-label" style={{ color: confidenceColor(value) }}>
        {value}%
      </span>
      {delta != null && delta !== 0 && (
        <span className={`nest-conf-delta ${delta > 0 ? 'positive' : 'negative'}`}>
          {delta > 0 ? `+${delta.toFixed(0)}` : delta.toFixed(0)}
        </span>
      )}
    </div>
  );
};

// ── LearningMeter ─────────────────────────────────────────────────────────────
// Compact improvement indicator shown inside each IterationCard.

const LEVEL_COLOR: Record<string, string> = {
  high:     '#4ade80',
  medium:   '#facc15',
  low:      '#f97316',
  negative: '#f87171',
};
const LEVEL_ICON: Record<string, string> = {
  high: '▲', medium: '►', low: '▼', negative: '✕',
};

function LearningMeter({ decision }: { decision: LearningDecision }) {
  const { improvementLevel: level, breakdown: b } = decision;
  const color = LEVEL_COLOR[level] ?? '#888';
  const icon  = LEVEL_ICON[level]  ?? '·';
  return (
    <div className="nest-learn-meter" style={{ borderColor: color }}>
      <span className="nest-learn-level" style={{ color }}>{icon} {level}</span>
      <span className="nest-learn-score">{b.composite > 0 ? '+' : ''}{b.composite.toFixed(1)}</span>
      {decision.shouldPivot && <span className="nest-learn-pivot">↺ pivot</span>}
      {decision.shouldReinforce && <span className="nest-learn-reinforce">★ reinforce</span>}
    </div>
  );
}

const IterationCard: React.FC<{
  snap:      NestIterationSnapshot;
  prev?:     NestIterationSnapshot;
  selected:  boolean;
  onClick:   () => void;
  decision?: LearningDecision;
}> = ({ snap, prev, selected, onClick, decision }) => {
  const primaryPlan  = snap.refinementPlan?.primaryAction;
  const newSigCount  = snap.delta?.newSignals.length ?? 0;
  const newBehaviors = snap.delta?.behaviorsAdded ?? [];

  return (
    <div
      className={`nest-iter-card${selected ? ' selected' : ''}${snap.delta?.significantChange ? ' significant' : ''}`}
      onClick={onClick}
      role="button"
      tabIndex={0}
      onKeyDown={e => e.key === 'Enter' && onClick()}
    >
      <div className="nest-iter-header">
        <span className="nest-iter-num">#{snap.iteration + 1}</span>
        <span className="nest-iter-verdict" style={{ color: verdictColor(snap.verdict.classification) }}>
          {snap.verdict.classification}
        </span>
        <span className="nest-iter-time">{fmtMs(snap.durationMs)}</span>
      </div>
      <ConfidenceBar value={snap.confidence} prev={prev?.confidence} compact />
      {/* Discovered insights */}
      <div className="nest-iter-insights">
        {newSigCount > 0 && (
          <span className="nest-insight-chip signals">+{newSigCount} signal{newSigCount !== 1 ? 's' : ''}</span>
        )}
        {newBehaviors.slice(0, 2).map(b => (
          <span key={b} className="nest-insight-chip behavior">{b}</span>
        ))}
        {snap.delta != null && snap.delta.corroborationsAdded > 0 && (
          <span className="nest-insight-chip corr">+{snap.delta.corroborationsAdded} corr.</span>
        )}
      </div>
      {snap.delta && (
        <div className={`nest-iter-delta ${snap.delta.significantChange ? 'sig' : 'minor'}`}>
          {snap.delta.summary}
        </div>
      )}
      {/* Strategy used next */}
      {primaryPlan && (
        <div className="nest-iter-strategy">
          <span className="nest-iter-strat-icon">⟳</span>
          <span className="nest-iter-strat-label">{primaryPlan.type.replace(/-/g, ' ')}</span>
        </div>
      )}
      {decision && <LearningMeter decision={decision} />}
      <div className="nest-iter-coverage">
        {snap.input.instructionCount} instr · {fmtHex(snap.input.disasmOffset)}+{fmtHex(snap.input.disasmLength)}
      </div>
    </div>
  );
};

const ConvergenceChart: React.FC<{
  progression: number[];
  threshold:   number;
  width?:      number;
  height?:     number;
}> = ({ progression, threshold, width = 360, height = 110 }) => {
  const w = width, h = height, padL = 28, padR = 36, padT = 10, padB = 22;
  const chartW = w - padL - padR;
  const chartH = h - padT - padB;

  if (progression.length === 0) return null;

  // With a single point render a stub line
  const pts = progression.length === 1
    ? [{ x: padL, y: padT + chartH - progression[0] / 100 * chartH }]
    : progression.map((c, i) => ({
        x: padL + (i / (progression.length - 1)) * chartW,
        y: padT + chartH - (c / 100) * chartH,
      }));

  const thresholdY = padT + chartH - (threshold / 100) * chartH;
  const pathD = pts.map((p, i) => `${i === 0 ? 'M' : 'L'} ${p.x.toFixed(1)} ${p.y.toFixed(1)}`).join(' ');

  // Area fill path
  const areaD = progression.length >= 2
    ? `${pathD} L ${pts[pts.length - 1].x.toFixed(1)} ${(padT + chartH).toFixed(1)} L ${padL} ${(padT + chartH).toFixed(1)} Z`
    : '';

  return (
    <svg className="nest-chart" width={w} height={h} viewBox={`0 0 ${w} ${h}`}>
      <defs>
        <linearGradient id="confGrad" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="#7c4dff" stopOpacity="0.3" />
          <stop offset="100%" stopColor="#7c4dff" stopOpacity="0.02" />
        </linearGradient>
      </defs>

      {/* Horizontal grid lines at 25 / 50 / 75 */}
      {[25, 50, 75].map(v => {
        const gy = padT + chartH - (v / 100) * chartH;
        return (
          <g key={v}>
            <line x1={padL} y1={gy} x2={padL + chartW} y2={gy}
              stroke="#ffffff08" strokeWidth="1" />
            <text x={padL - 4} y={gy + 4} fill="#444466"
              fontSize="8" textAnchor="end">{v}</text>
          </g>
        );
      })}

      {/* Threshold line */}
      <line x1={padL} y1={thresholdY} x2={padL + chartW} y2={thresholdY}
        stroke="#4caf5066" strokeWidth="1" strokeDasharray="4 3" />
      <text x={padL + chartW + 3} y={thresholdY + 4}
        fill="#4caf50" fontSize="9">{threshold}%</text>

      {/* Area fill */}
      {areaD && <path d={areaD} fill="url(#confGrad)" />}

      {/* Confidence line */}
      {progression.length >= 2 && (
        <path d={pathD} fill="none" stroke="#7c4dff" strokeWidth="2" strokeLinejoin="round" />
      )}

      {/* Data points + iteration labels */}
      {pts.map((p, i) => (
        <g key={i}>
          <circle cx={p.x} cy={p.y} r={4}
            fill={confidenceColor(progression[i])}
            stroke="#10101c" strokeWidth="1.5" />
          <text x={p.x} y={padT + chartH + 13}
            fill="#556688" fontSize="8.5" textAnchor="middle">
            #{i + 1}
          </text>
          {/* Tooltip-style label on last point */}
          {i === pts.length - 1 && (
            <text x={p.x} y={p.y - 7}
              fill={confidenceColor(progression[i])} fontSize="9" textAnchor="middle"
              fontWeight="700">
              {progression[i]}%
            </text>
          )}
        </g>
      ))}
    </svg>
  );
};

// ── Convergence Banner ────────────────────────────────────────────────────────

const CONVERGENCE_LABELS: Record<string, string> = {
  'converged':    'Converged',
  'plateau':      'Plateau',
  'max-reached':  'Max Iterations',
  'paused':       'Paused',
  'error':        'Error',
};

const ConvergenceBanner: React.FC<{ summary: NestSummary; status: string }> = ({ summary, status }) => {
  const label     = CONVERGENCE_LABELS[status] ?? status;
  const colorMap: Record<string, string> = {
    'converged':   '#4caf50',
    'plateau':     '#ff9800',
    'max-reached': '#90a4ae',
    'error':       '#f44336',
    'paused':      '#7c4dff',
  };
  const accent = colorMap[status] ?? '#7c4dff';
  const first  = summary.confidenceProgression[0] ?? 0;
  const last   = summary.finalConfidence;
  const gain   = last - first;

  return (
    <div className="nest-convergence-banner" style={{ borderColor: accent + '66' }}>
      <div className="nest-conv-left">
        <span className="nest-conv-state" style={{ color: accent }}>{label}</span>
        <span className="nest-conv-reason">
          {summary.convergedReason === 'confidence-threshold' && `Reached ${last}% confidence`}
          {summary.convergedReason === 'plateau' && 'Confidence plateaued'}
          {summary.convergedReason === 'max-iterations' && `All ${summary.totalIterations} iterations used`}
          {!summary.convergedReason && `Stopped after ${summary.totalIterations} iteration${summary.totalIterations !== 1 ? 's' : ''}`}
        </span>
      </div>
      <div className="nest-conv-stats">
        <div className="nest-conv-stat">
          <span className="nest-conv-val" style={{ color: confidenceColor(last) }}>{last}%</span>
          <span className="nest-conv-lbl">confidence</span>
        </div>
        <div className="nest-conv-stat">
          <span className="nest-conv-val" style={{ color: gain > 0 ? '#4caf50' : '#90a4ae' }}>
            {gain > 0 ? `+${gain}` : gain}%
          </span>
          <span className="nest-conv-lbl">total gain</span>
        </div>
        <div className="nest-conv-stat">
          <span className="nest-conv-val">{summary.totalIterations}</span>
          <span className="nest-conv-lbl">iterations</span>
        </div>
        <div className="nest-conv-stat">
          <span className="nest-conv-val" style={{ color: verdictColor(summary.finalVerdict) }}>
            {summary.finalVerdict}
          </span>
          <span className="nest-conv-lbl">verdict</span>
        </div>
      </div>
      {/* Confidence path */}
      {summary.confidenceProgression.length > 0 && (
        <div className="nest-conv-path">
          {summary.confidenceProgression.map((c, i) => (
            <React.Fragment key={i}>
              <span className="nest-conv-path-node" style={{ color: confidenceColor(c) }}>{c}%</span>
              {i < summary.confidenceProgression.length - 1 && (
                <span className="nest-conv-path-arrow">→</span>
              )}
            </React.Fragment>
          ))}
        </div>
      )}
      {summary.keyFindings.length > 0 && (
        <div className="nest-conv-findings">
          {summary.keyFindings.slice(0, 3).map((f, i) => (
            <div key={i} className="nest-conv-finding">⬡ {f}</div>
          ))}
        </div>
      )}
    </div>
  );
};

// ── Evolution Strip ───────────────────────────────────────────────────────────
// Compact horizontal row summarising all iterations, sits above the timeline.

const EvolutionStrip: React.FC<{
  iters:    NestIterationSnapshot[];
  selected: number | null;
  onSelect: (i: number) => void;
}> = ({ iters, selected, onSelect }) => (
  <div className="nest-evo-strip">
    {iters.map((snap, i) => {
      const prev   = iters[i - 1];
      const delta  = prev != null ? snap.confidence - prev.confidence : null;
      const isSelected = selected === i || (selected == null && i === iters.length - 1);
      return (
        <button
          key={i}
          className={`nest-evo-node${isSelected ? ' sel' : ''}${snap.delta?.significantChange ? ' sig' : ''}`}
          onClick={() => onSelect(i)}
          title={`Iteration ${i + 1}: ${snap.confidence}% confidence\n${snap.delta?.summary ?? ''}`}
        >
          <span className="nest-evo-num">#{i + 1}</span>
          <span className="nest-evo-conf" style={{ color: confidenceColor(snap.confidence) }}>
            {snap.confidence}%
          </span>
          {delta != null && (
            <span className={`nest-evo-delta ${delta >= 0 ? 'pos' : 'neg'}`}>
              {delta >= 0 ? `+${delta.toFixed(0)}` : delta.toFixed(0)}
            </span>
          )}
        </button>
      );
    })}
  </div>
);

// ── Learning panel ────────────────────────────────────────────────────────────

const LearningPanel: React.FC<{
  record:   BinaryLearningRecord | null;
  boosts:   LearningBoosts | null;
  similar:  SimilarBinary[];
}> = ({ record, boosts, similar }) => {
  const [open, setOpen] = React.useState(true);
  const hasData = record || (boosts && boosts.confidenceBonus > 0) || similar.length > 0;
  if (!hasData) return null;

  return (
    <div className="learn-panel">
      <button
        className="learn-header"
        onClick={() => setOpen(v => !v)}
        aria-expanded={open}
      >
        <span className="learn-icon">💡</span>
        <span className="learn-title">Learning Context</span>
        {record && (
          <span className="learn-badge">{record.sessionCount} session{record.sessionCount !== 1 ? 's' : ''}</span>
        )}
        {boosts && boosts.confidenceBonus > 0 && (
          <span className="learn-boost-badge">+{boosts.confidenceBonus}%</span>
        )}
        <span className="learn-chevron">{open ? '▲' : '▼'}</span>
      </button>

      {open && (
        <div className="learn-body">
          {/* Previous sessions for this binary */}
          {record && (
            <div className="learn-section">
              <div className="learn-section-title">This Binary</div>
              <div className="learn-stat-row">
                <span className="learn-stat">
                  <span className="learn-stat-val">{record.sessionCount}</span>
                  <span className="learn-stat-lbl">Sessions</span>
                </span>
                <span className="learn-stat">
                  <span className="learn-stat-val">{record.confirmedPatterns.length}</span>
                  <span className="learn-stat-lbl">Confirmed patterns</span>
                </span>
                <span className="learn-stat">
                  <span className="learn-stat-val">{record.bestConfidence}%</span>
                  <span className="learn-stat-lbl">Best confidence</span>
                </span>
                <span className="learn-stat">
                  <span className="learn-stat-val" style={{ textTransform: 'capitalize' }}>
                    {record.bestClassification}
                  </span>
                  <span className="learn-stat-lbl">Best verdict</span>
                </span>
              </div>
              {record.confirmedPatterns.length > 0 && (
                <div className="learn-patterns">
                  {record.confirmedPatterns.slice(0, 6).map(p => (
                    <span key={p} className="learn-pattern-chip confirmed">{p}</span>
                  ))}
                  {record.confirmedPatterns.length > 6 && (
                    <span className="learn-pattern-more">+{record.confirmedPatterns.length - 6} confirmed</span>
                  )}
                </div>
              )}
              {record.observedBehaviors.length > 0 && (
                <div className="learn-behaviors">
                  Previously detected: {record.observedBehaviors.map(b => (
                    <span key={b} className="learn-behavior-chip">{b}</span>
                  ))}
                </div>
              )}
              {record.verdictHistory.length >= 2 && (() => {
                const first = record.verdictHistory[0];
                const last  = record.verdictHistory[record.verdictHistory.length - 1];
                const delta = last.confidence - first.confidence;
                return (
                  <div className="learn-evolution">
                    Verdict evolution: {first.classification} ({first.confidence}%)
                    {' → '}
                    {last.classification} ({last.confidence}%)
                    {delta !== 0 && (
                      <span className={`learn-delta ${delta > 0 ? 'pos' : 'neg'}`}>
                        {delta > 0 ? `+${delta}` : delta}%
                      </span>
                    )}
                  </div>
                );
              })()}
            </div>
          )}

          {/* Active boosts */}
          {boosts && boosts.confidenceBonus > 0 && (
            <div className="learn-section">
              <div className="learn-section-title">
                Active Boosts
                <span className="learn-total-boost">+{boosts.confidenceBonus}% confidence</span>
              </div>
              {boosts.boostReasons.map((r, i) => (
                <div key={i} className="learn-boost-row">
                  <span className="learn-boost-dot">◆</span>{r}
                </div>
              ))}
              {boosts.heuristicFired && (
                <div className="learn-heuristic-fired">⚡ Known heuristic fired</div>
              )}
            </div>
          )}

          {/* Similar binaries */}
          {similar.length > 0 && (
            <div className="learn-section">
              <div className="learn-section-title">Similar Binaries ({similar.length})</div>
              <div className="learn-similar-list">
                {similar.map(s => (
                  <div key={s.hash} className="learn-similar-row">
                    <span className="learn-sim-pct">{s.similarity}%</span>
                    <span className="learn-sim-name">{s.fileName || s.hash.slice(0, 12)}</span>
                    <span className="learn-sim-verdict" style={{ textTransform: 'capitalize' }}>
                      {s.classification}
                    </span>
                    <span className="learn-sim-conf">{s.bestConfidence}%</span>
                    {s.sharedSignals.length > 0 && (
                      <span className="learn-sim-shared">
                        shared: {s.sharedSignals.slice(0, 3).join(', ')}
                        {s.sharedSignals.length > 3 && ` +${s.sharedSignals.length - 3}`}
                      </span>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

// ── DominanceBanner ───────────────────────────────────────────────────────────

const RESISTANCE_ICON: Record<string, string> = {
  'low-confidence':           '📉',
  'unresolved-contradictions':'⚡',
  'unstable-verdict':         '🔄',
  'weak-reasoning-chain':     '🧩',
  'missing-signals':          '🔍',
  'unclear-logic':            '❓',
  'weak-heuristics':          '⚠️',
};

function DominanceBanner({ assessment }: { assessment: DominanceAssessment }) {
  const [open, setOpen] = React.useState(true);
  const dominated = assessment.status === 'DOMINATED';

  return (
    <div className={`nest-dominance-banner ${dominated ? 'dominated' : 'resistant'}`}>
      {/* Header row */}
      <button
        className="nest-dom-header"
        onClick={() => setOpen(v => !v)}
        aria-expanded={open}
      >
        <span className="nest-dom-emblem">{dominated ? '⚔️' : '🛡️'}</span>
        <span className="nest-dom-status">{assessment.status}</span>
        <span className="nest-dom-conf">{assessment.finalConfidence}% confidence</span>
        {assessment.contradictionCount > 0 && (
          <span className="nest-dom-contra">
            {assessment.contradictionCount} contradiction{assessment.contradictionCount !== 1 ? 's' : ''}
          </span>
        )}
        <span className="nest-dom-chevron">{open ? '▲' : '▼'}</span>
      </button>

      {/* Summary line */}
      <div className="nest-dom-summary">{assessment.summary}</div>

      {/* Failure log — only when RESISTANT and panel is open */}
      {!dominated && open && assessment.failures.length > 0 && (
        <div className="nest-dom-failures">
          {assessment.failures.map((f, i) => (
            <div key={i} className={`nest-dom-failure sev-${f.severity}`}>
              <span className="nest-dom-failure-icon">{RESISTANCE_ICON[f.reason] ?? '⚠️'}</span>
              <div className="nest-dom-failure-body">
                <span className="nest-dom-failure-reason">{f.reason.replace(/-/g, ' ')}</span>
                <span className="nest-dom-failure-desc">{f.description}</span>
              </div>
              <span className={`nest-dom-sev-badge sev-${f.severity}`}>{f.severity}</span>
            </div>
          ))}
        </div>
      )}

      {/* Gates checklist — visible when open */}
      {open && (
        <div className="nest-dom-gates">
          {[
            { label: `Confidence ≥ 90%`,          pass: assessment.finalConfidence >= 90 },
            { label: `Contradictions resolved`,    pass: assessment.contradictionCount === 0 },
            { label: `Stable verdict`,             pass: assessment.verdictStable },
            { label: `Clear reasoning chain`,      pass: assessment.reasoningChainClear },
          ].map((g, i) => (
            <div key={i} className={`nest-dom-gate ${g.pass ? 'pass' : 'fail'}`}>
              <span className="nest-dom-gate-icon">{g.pass ? '✓' : '✗'}</span>
              <span className="nest-dom-gate-label">{g.label}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── CrossBinaryAdvisorPanel ───────────────────────────────────────────────────

const WEAKNESS_ICON: Record<string, string> = {
  'low-iteration-depth':       '🔁',
  'strategy-underperformance': '📉',
  'signal-instability':        '🔄',
  'overconfidence':            '🎯',
  'contradiction-stall':       '⚡',
  'shallow-coverage':          '🔍',
  'signal-weight-imbalance':   '⚖️',
};

const ADJUSTMENT_ICON: Record<string, string> = {
  'increase-max-iterations':        '➕',
  'decrease-max-iterations':        '➖',
  'lower-confidence-threshold':     '⬇',
  'raise-confidence-threshold':     '⬆',
  'set-aggressiveness-aggressive':  '🔥',
  'set-aggressiveness-conservative':'🧊',
  'enable-talon':                   '🦅',
  'enable-echo':                    '📡',
  'enable-autoadvance':             '▶',
  'increase-plateau-sensitivity':   '📊',
};

function CrossBinaryAdvisorPanel({
  report,
  onApply,
}: {
  report:   import('../utils/crossBinaryAdvisor').CrossBinaryReport;
  onApply:  (cfg: import('../utils/nestEngine').NestConfig) => void;
}) {
  const [tab, setTab] = React.useState<'overview' | 'weaknesses' | 'adjustments'>('overview');
  const [applied, setApplied] = React.useState(false);

  const handleApply = () => {
    onApply(report.recommendedConfig);
    setApplied(true);
  };

  return (
    <div className="nest-cba-panel">
      {/* Header */}
      <div className="nest-cba-header">
        <span className="nest-cba-icon">🧠</span>
        <div className="nest-cba-title-wrap">
          <span className="nest-cba-title">Cross-Binary Advisor</span>
          <span className="nest-cba-subtitle">{report.binaryCount} session{report.binaryCount !== 1 ? 's' : ''} analysed</span>
        </div>
        {report.sufficientData && report.adjustments.length > 0 && (
          <button
            className={`nest-cba-apply-btn ${applied ? 'applied' : ''}`}
            onClick={handleApply}
            disabled={applied}
            title="Apply all recommended config adjustments"
          >
            {applied ? '✓ Applied' : 'Apply Recommendations'}
          </button>
        )}
      </div>

      {/* Overall assessment */}
      <div className="nest-cba-assessment">{report.overallAssessment}</div>

      {/* Not enough data yet */}
      {!report.sufficientData && (
        <div className="nest-cba-nodata">
          <span className="nest-cba-nodata-icon">⏳</span>
          <span className="nest-cba-nodata-text">{report.insufficientDataReason}</span>
        </div>
      )}

      {/* Tabs */}
      {report.sufficientData && (
        <>
          <div className="nest-cba-tabs">
            {(['overview', 'weaknesses', 'adjustments'] as const).map(t => (
              <button
                key={t}
                className={`nest-cba-tab ${tab === t ? 'active' : ''}`}
                onClick={() => setTab(t)}
              >
                {t === 'overview'     ? `Overview` :
                 t === 'weaknesses'   ? `Weaknesses (${report.weaknesses.length})` :
                                        `Adjustments (${report.adjustments.length})`}
              </button>
            ))}
          </div>

          {/* Overview tab */}
          {tab === 'overview' && (
            <div className="nest-cba-overview">
              <div className="nest-cba-metrics-grid">
                {[
                  { label: 'Binaries',      val: report.metrics.totalBinaries },
                  { label: 'Dominated',     val: `${Math.round(report.metrics.dominanceRate * 100)}%` },
                  { label: 'Avg Confidence',val: `${report.metrics.avgFinalConfidence}%` },
                  { label: 'Avg Iterations',val: report.metrics.avgIterations },
                  { label: 'Instability',   val: `${Math.round(report.metrics.instabilityRate * 100)}%` },
                  { label: 'Contradictions',val: `${Math.round(report.metrics.contradictionRate * 100)}%` },
                ].map(m => (
                  <div key={m.label} className="nest-cba-metric">
                    <span className="nest-cba-metric-val">{m.val}</span>
                    <span className="nest-cba-metric-lbl">{m.label}</span>
                  </div>
                ))}
              </div>
              {report.metrics.topFailureReasons.length > 0 && (
                <div className="nest-cba-failure-chart">
                  <div className="nest-cba-section-title">Top Failure Reasons</div>
                  {report.metrics.topFailureReasons.slice(0, 5).map(fr => (
                    <div key={fr.reason} className="nest-cba-failure-row">
                      <span className="nest-cba-failure-name">{fr.reason.replace(/-/g, ' ')}</span>
                      <div className="nest-cba-failure-bar-wrap">
                        <div
                          className="nest-cba-failure-bar"
                          style={{ width: `${Math.round(fr.fraction * 100)}%` }}
                        />
                      </div>
                      <span className="nest-cba-failure-pct">{Math.round(fr.fraction * 100)}%</span>
                    </div>
                  ))}
                </div>
              )}
              {report.metrics.strategyReliability.length > 0 && (
                <div className="nest-cba-strategy-table">
                  <div className="nest-cba-section-title">Strategy Reliability</div>
                  {report.metrics.strategyReliability.map(s => (
                    <div key={s.strategy} className="nest-cba-strategy-row">
                      <span className="nest-cba-strategy-name">{s.strategy}</span>
                      <div className="nest-cba-rel-bar-wrap">
                        <div
                          className={`nest-cba-rel-bar ${s.reliability >= 0.7 ? 'good' : s.reliability >= 0.4 ? 'ok' : 'bad'}`}
                          style={{ width: `${Math.round(s.reliability * 100)}%` }}
                        />
                      </div>
                      <span className="nest-cba-rel-pct">{Math.round(s.reliability * 100)}%</span>
                      <span className="nest-cba-rel-uses">×{s.uses}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Weaknesses tab */}
          {tab === 'weaknesses' && (
            <div className="nest-cba-weaknesses">
              {report.weaknesses.length === 0 ? (
                <div className="nest-cba-empty">No systemic weaknesses detected — NEST is performing well.</div>
              ) : (
                report.weaknesses.map((w, i) => (
                  <div key={i} className={`nest-cba-weakness sev-${w.severity}`}>
                    <div className="nest-cba-weakness-header">
                      <span className="nest-cba-weakness-icon">{WEAKNESS_ICON[w.category] ?? '⚠️'}</span>
                      <span className="nest-cba-weakness-title">{w.title}</span>
                      <span className={`nest-cba-sev-badge sev-${w.severity}`}>{w.severity}</span>
                    </div>
                    <div className="nest-cba-weakness-desc">{w.description}</div>
                    <div className="nest-cba-weakness-evidence">
                      {w.evidence.map((e, j) => (
                        <span key={j} className="nest-cba-evidence-item">▸ {e}</span>
                      ))}
                    </div>
                  </div>
                ))
              )}
            </div>
          )}

          {/* Adjustments tab */}
          {tab === 'adjustments' && (
            <div className="nest-cba-adjustments">
              {report.adjustments.length === 0 ? (
                <div className="nest-cba-empty">No adjustments recommended.</div>
              ) : (
                report.adjustments.map((a, i) => (
                  <div key={i} className={`nest-cba-adjustment pri-${a.priority}`}>
                    <div className="nest-cba-adj-header">
                      <span className="nest-cba-adj-icon">{ADJUSTMENT_ICON[a.type] ?? '🔧'}</span>
                      <span className="nest-cba-adj-title">{a.title}</span>
                      <span className="nest-cba-adj-gain">+{a.expectedGain}%</span>
                    </div>
                    <div className="nest-cba-adj-rationale">{a.rationale}</div>
                  </div>
                ))
              )}
            </div>
          )}
        </>
      )}
    </div>
  );
}

// ── MultiBinaryPanel ──────────────────────────────────────────────────────────

const WEAKNESS_FLAG_LABEL: Record<string, string> = {
  'unstable-reasoning':   '🔄 Unstable Reasoning',
  'overconfident':        '🎯 Overconfident',
  'strategy-stall':       '📉 Strategy Stall',
  'low-coverage':         '🔍 Low Coverage',
  'contradiction-heavy':  '⚡ Contradiction Heavy',
  'negative-improvement': '⬇ Negative Improvement',
};

function MultiBinaryPanel({
  batchRun,
  onStop,
}: {
  batchRun:  BatchRunState;
  onStop:    () => void;
}) {
  const [tab, setTab] = React.useState<'queue' | 'metrics' | 'patterns'>('queue');
  const m = batchRun.metrics;
  const isDone = batchRun.status === 'complete';

  return (
    <div className="nest-mb-panel">
      {/* Header */}
      <div className="nest-mb-header">
        <span className="nest-mb-icon">⬡</span>
        <div className="nest-mb-title-wrap">
          <span className="nest-mb-title">Multi-Binary Run</span>
          <span className="nest-mb-subtitle">
            {m.completedCount}/{m.totalCount} binaries analysed
          </span>
        </div>
        <span className={`nest-mb-status ${isDone ? 'done' : 'running'}`}>
          {isDone ? '✓ Complete' : '⟳ Running'}
        </span>
        {!isDone && (
          <button className="nest-btn danger small" onClick={onStop}>⏹ Stop</button>
        )}
      </div>

      {/* Config changes */}
      {batchRun.configHistory.length > 0 && (
        <div className="nest-mb-config-changes">
          {batchRun.configHistory.map((ch, i) => (
            <div key={i} className="nest-mb-config-change">
              <span className="nest-mb-config-change-label">Before binary #{ch.appliedBeforeIndex + 1}:</span>
              <span className="nest-mb-config-change-summary">{ch.summary}</span>
            </div>
          ))}
        </div>
      )}

      {/* Tabs */}
      <div className="nest-mb-tabs">
        {(['queue', 'metrics', 'patterns'] as const).map(t => (
          <button
            key={t}
            className={`nest-mb-tab ${tab === t ? 'active' : ''}`}
            onClick={() => setTab(t)}
          >
            {t === 'queue' ? 'Queue' : t === 'metrics' ? 'Metrics' : 'Patterns'}
          </button>
        ))}
      </div>

      {/* Queue tab */}
      {tab === 'queue' && (
        <div className="nest-mb-queue">
          {batchRun.items.map((item, idx) => (
            <div key={item.id} className={`nest-mb-item status-${item.status}`}>
              <div className="nest-mb-item-header">
                <span className="nest-mb-item-num">#{idx + 1}</span>
                <span className="nest-mb-item-label">{item.label}</span>
                <span className={`nest-mb-item-status ${item.status}`}>
                  {item.status === 'completed' ? '✓'
                    : item.status === 'running'   ? '⟳'
                    : item.status === 'error'     ? '✕'
                    : item.status === 'pending'   ? '…'
                    : '—'}
                </span>
              </div>
              {item.result && (
                <div className="nest-mb-item-result">
                  <span style={{ color: confidenceColor(item.result.finalConfidence) }}>
                    {item.result.finalConfidence}%
                  </span>
                  <span style={{ color: verdictColor(item.result.verdict) }}>
                    {item.result.verdict}
                  </span>
                  <span className="nest-mb-item-iters">
                    {item.result.iterationCount} iters
                  </span>
                  <span
                    className={`nest-mb-item-stab ${item.result.stabilityScore >= 75 ? 'stable' : 'unstable'}`}
                    title="Stability score"
                  >
                    ⚖ {item.result.stabilityScore}%
                  </span>
                  <span className={`nest-mb-dom ${item.result.dominanceStatus === 'DOMINATED' ? 'dominated' : 'resistant'}`}>
                    {item.result.dominanceStatus === 'DOMINATED' ? '⚔ DOM' : '🛡 RES'}
                  </span>
                  {item.result.weaknessFlags.length > 0 && (
                    <div className="nest-mb-item-flags">
                      {item.result.weaknessFlags.map(f => (
                        <span key={f} className="nest-mb-flag">{WEAKNESS_FLAG_LABEL[f] ?? f}</span>
                      ))}
                    </div>
                  )}
                  {item.result.configAdjustmentsApplied.length > 0 && (
                    <div className="nest-mb-item-cfgadj">
                      ⚙ {item.result.configAdjustmentsApplied[0]}
                    </div>
                  )}
                </div>
              )}
              {item.errorMessage && (
                <div className="nest-mb-item-error">{item.errorMessage}</div>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Metrics tab */}
      {tab === 'metrics' && m.completedCount > 0 && (
        <div className="nest-mb-metrics">
          <div className="nest-mb-metrics-grid">
            {[
              { label: 'Avg Confidence',  val: `${m.avgFinalConfidence}%` },
              { label: 'Avg Iterations',  val: m.avgIterations },
              { label: 'Convergence Rate',val: `${Math.round(m.convergenceRate * 100)}%` },
              { label: 'Stable Rate',     val: `${Math.round(m.stableRate * 100)}%` },
              { label: 'Avg Stability',   val: `${m.avgStabilityScore}%` },
              { label: 'Config Changes',  val: m.configAdjustmentsMade },
            ].map(stat => (
              <div key={stat.label} className="nest-mb-metric">
                <span className="nest-mb-metric-val">{stat.val}</span>
                <span className="nest-mb-metric-lbl">{stat.label}</span>
              </div>
            ))}
          </div>

          {/* Weakness summary */}
          {m.weaknessSummary.length > 0 && (
            <div className="nest-mb-weakness-summary">
              <div className="nest-mb-section-title">Weakness Frequency</div>
              {m.weaknessSummary.map(w => (
                <div key={w.flag} className="nest-mb-weakness-row">
                  <span className="nest-mb-weakness-name">{WEAKNESS_FLAG_LABEL[w.flag] ?? w.flag}</span>
                  <div className="nest-mb-weakness-bar-wrap">
                    <div
                      className="nest-mb-weakness-bar"
                      style={{ width: `${Math.round(w.fraction * 100)}%` }}
                    />
                  </div>
                  <span className="nest-mb-weakness-pct">{w.count}/{m.completedCount}</span>
                </div>
              ))}
            </div>
          )}

          {/* Overconfidence cases */}
          {m.overconfidenceCases.length > 0 && (
            <div className="nest-mb-oc-cases">
              <div className="nest-mb-section-title">Overconfidence Cases</div>
              {m.overconfidenceCases.map((c, i) => (
                <div key={i} className="nest-mb-oc-row">
                  <span className="nest-mb-oc-path">{c.path.split(/[\\/]/).pop()}</span>
                  <span style={{ color: confidenceColor(c.confidence) }}>{c.confidence}%</span>
                  <span className="nest-mb-oc-verdict">{c.verdict}</span>
                  <span className="nest-mb-oc-badge">RESISTANT</span>
                </div>
              ))}
            </div>
          )}

          {/* Unstable reasoning cases */}
          {m.unstableReasoningCases.length > 0 && (
            <div className="nest-mb-ur-cases">
              <div className="nest-mb-section-title">Unstable Reasoning Cases</div>
              {m.unstableReasoningCases.map((c, i) => (
                <div key={i} className="nest-mb-ur-row">
                  <span className="nest-mb-ur-path">{c.path.split(/[\\/]/).pop()}</span>
                  <span className="nest-mb-ur-flips">{c.verdictFlips} flips</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Patterns tab */}
      {tab === 'patterns' && (
        <div className="nest-mb-patterns">
          {m.repeatedPatterns.length === 0 ? (
            <div className="nest-mb-empty">
              {m.completedCount < 2
                ? 'Complete ≥ 2 binaries to see repeated patterns.'
                : 'No repeated signal patterns found yet.'}
            </div>
          ) : (
            <>
              <div className="nest-mb-section-title">
                Repeated Patterns ({m.repeatedPatterns.length} found in ≥ 2 binaries)
              </div>
              {m.repeatedPatterns.slice(0, 15).map(p => (
                <div key={p.signalId} className="nest-mb-pattern-row">
                  <span className="nest-mb-pattern-id">{p.signalId}</span>
                  <div className="nest-mb-pattern-bar-wrap">
                    <div
                      className="nest-mb-pattern-bar"
                      style={{ width: `${Math.round(p.fraction * 100)}%` }}
                    />
                  </div>
                  <span className="nest-mb-pattern-count">{p.count}/{m.completedCount}</span>
                </div>
              ))}
            </>
          )}
        </div>
      )}
    </div>
  );
}

const SummaryPanel: React.FC<{ summary: NestSummary }> = ({ summary }) => (  <div className="nest-summary">
    <div className="nest-summary-title">Session Summary</div>
    <div className="nest-summary-grid">
      <div className="nest-summary-cell">
        <span className="nest-summary-val" style={{ color: confidenceColor(summary.finalConfidence) }}>
          {summary.finalConfidence}%
        </span>
        <span className="nest-summary-lbl">Final Confidence</span>
      </div>
      <div className="nest-summary-cell">
        <span className="nest-summary-val" style={{ color: verdictColor(summary.finalVerdict) }}>
          {summary.finalVerdict}
        </span>
        <span className="nest-summary-lbl">Verdict</span>
      </div>
      <div className="nest-summary-cell">
        <span className="nest-summary-val">{summary.totalIterations}</span>
        <span className="nest-summary-lbl">Iterations</span>
      </div>
      <div className="nest-summary-cell">
        <span
          className="nest-summary-val"
          style={{ color: summary.improvementTotal > 0 ? '#4caf50' : '#90a4ae' }}
        >
          {summary.improvementTotal > 0 ? `+${summary.improvementTotal}` : summary.improvementTotal}%
        </span>
        <span className="nest-summary-lbl">Improvement</span>
      </div>
    </div>
    {summary.convergedReason && (
      <div className="nest-summary-reason">
        Stopped: {summary.convergedReason.replace(/-/g, ' ')}
      </div>
    )}
    {summary.keyFindings.length > 0 && (
      <div className="nest-summary-findings">
        {summary.keyFindings.map((f, i) => (
          <div key={i} className="nest-summary-finding">⬡ {f}</div>
        ))}
      </div>
    )}
  </div>
);

// ── LearningSessionPanel ──────────────────────────────────────────────────────

const IMPROVEMENT_LABEL: Record<ImprovementLevel, string> = {
  high:     '▲ High',
  medium:   '► Medium',
  low:      '▼ Low',
  negative: '✕ Negative',
};

function LearningSessionPanel({ session }: { session: LearningSession }) {
  const [open, setOpen] = React.useState(true);
  if (session.decisions.length === 0) return null;
  const avg = session.decisions.length > 0
    ? (session.totalImprovement / session.decisions.length).toFixed(1)
    : '—';

  return (
    <div className="nest-lsess">
      <button className="nest-lsess-header" onClick={() => setOpen(v => !v)}>
        <span className="nest-lsess-icon">🧠</span>
        <span className="nest-lsess-title">Meta-Learning</span>
        <span className="nest-lsess-avg" style={{
          color: parseFloat(avg) >= 12 ? '#4ade80' : parseFloat(avg) >= 4 ? '#facc15' : '#f97316',
        }}>avg {avg > '0' ? '+' : ''}{avg}</span>
        <span className="nest-lsess-chevron">{open ? '▲' : '▼'}</span>
      </button>
      {open && (
        <div className="nest-lsess-body">
          {/* Stats row */}
          <div className="nest-lsess-stats">
            <div className="nest-lsess-stat">
              <span className="nest-lsess-val">{session.highImprovementCount}</span>
              <span className="nest-lsess-lbl">High</span>
            </div>
            <div className="nest-lsess-stat">
              <span className="nest-lsess-val">{session.lowImprovementCount}</span>
              <span className="nest-lsess-lbl">Low/Neg</span>
            </div>
            <div className="nest-lsess-stat">
              <span className="nest-lsess-val">{session.reinforcedSignals.length}</span>
              <span className="nest-lsess-lbl">Reinforced</span>
            </div>
          </div>

          {/* Decisions list */}
          <div className="nest-lsess-decisions">
            {session.decisions.map(d => (
              <div key={d.iteration} className={`nest-lsess-row level-${d.improvementLevel}`}>
                <span className="nest-lsess-row-iter">#{d.iteration + 1}</span>
                <span className="nest-lsess-row-level" style={{ color: LEVEL_COLOR[d.improvementLevel] }}>
                  {IMPROVEMENT_LABEL[d.improvementLevel]}
                </span>
                <span className="nest-lsess-row-score">
                  {d.breakdown.composite > 0 ? '+' : ''}{d.breakdown.composite.toFixed(1)}
                </span>
                <div className="nest-lsess-row-diagnosis">{d.diagnosis}</div>
                {d.shouldPivot && (
                  <div className="nest-lsess-pivot">↺ Pivoting: {d.deprioritise.join(', ') || 'strategy change'}</div>
                )}
                {d.shouldReinforce && d.reinforceSignals.length > 0 && (
                  <div className="nest-lsess-reinforce">
                    ★ Reinforced: {d.reinforceSignals.slice(0, 3).join(', ')}
                  </div>
                )}
              </div>
            ))}
          </div>

          {/* Effective / ineffective strategies */}
          {(session.effectiveStrategies.length > 0 || session.ineffectiveStrategies.length > 0) && (
            <div className="nest-lsess-strategies">
              {session.effectiveStrategies.length > 0 && (
                <div className="nest-lsess-strat-row effective">
                  <span className="nest-lsess-strat-lbl">Effective:</span>
                  {session.effectiveStrategies.map(s => (
                    <span key={s} className="nest-lsess-strat-chip effective">{s.replace(/-/g, ' ')}</span>
                  ))}
                </div>
              )}
              {session.ineffectiveStrategies.length > 0 && (
                <div className="nest-lsess-strat-row ineffective">
                  <span className="nest-lsess-strat-lbl">Avoid:</span>
                  {session.ineffectiveStrategies.map(s => (
                    <span key={s} className="nest-lsess-strat-chip ineffective">{s.replace(/-/g, ' ')}</span>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Final assessment */}
          {session.finalAssessment && (
            <div className="nest-lsess-assessment">{session.finalAssessment}</div>
          )}
        </div>
      )}
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

const NestView: React.FC<NestViewProps> = ({
  onLoadTrainingBinary,
  onNestComplete,
  binaryPath,
  metadata,
  disassembly: initialDisassembly,
  strings,
  disassemblyAnalysis,
  disasmOffset: initialOffset,
  disasmLength: initialLength,
  strikeSignals,
  onAddressSelect,
}) => {
  const [session,           setSession]           = useState<NestSession | null>(null);
  const [isRunning,         setIsRunning]         = useState(false);
  const [selectedIter,      setSelectedIter]      = useState<number | null>(null);
  const [error,             setError]             = useState<string | null>(null);
  const [config,            setConfig]            = useState<NestConfig>({ ...DEFAULT_NEST_CONFIG });
  const [showConfig,        setShowConfig]        = useState(false);
  const [summary,           setSummary]           = useState<NestSummary | null>(null);
  // Dominance assessment — computed after session ends
  const [dominance,         setDominance]         = useState<DominanceAssessment | null>(null);
  const [crossBinaryReport, setCrossBinaryReport] = useState<CrossBinaryReport | null>(null);
  // Learning state
  const [learningRecord,    setLearningRecord]    = useState<BinaryLearningRecord | null>(null);
  const [lastBoosts,        setLastBoosts]        = useState<LearningBoosts | null>(null);
  const [similarBinaries,      setSimilarBinaries]      = useState<SimilarBinary[]>([]);
  const [currentStrategyPlan,  setCurrentStrategyPlan]  = useState<AnalysisPlan | null>(null);
  // Meta-learning state
  const [learningSession,      setLearningSession]      = useState<LearningSession | null>(null);
  const [iterDecisions,        setIterDecisions]        = useState<LearningDecision[]>([]);
  const learningSessionRef = useRef<LearningSession | null>(null);
  /** Historical strategy reliability scores from learningStore */
  const strategyReliabilityRef = useRef<Partial<Record<StrategyClass, number>>>({}); 
  const sessRef    = useRef<NestSession | null>(null);
  const disasmRef  = useRef<DisassembledInstruction[]>(initialDisassembly);
  const offsetRef  = useRef<number>(initialOffset);
  const lengthRef  = useRef<number>(initialLength);
  const stopRef    = useRef<boolean>(false);
  // Learning refs (stable across re-renders)
  const echoHintsRef = useRef<string[]>([]);
  // Runner ref — holds the current NestSessionRunner instance
  const runnerRef  = useRef<NestSessionRunner | null>(null);

  // ── Multi-binary batch state ───────────────────────────────────────────────
  const [showBatchPanel,  setShowBatchPanel]  = useState(false);
  const [batchRun,        setBatchRun]        = useState<BatchRunState | null>(null);
  const [batchQueueInput, setBatchQueueInput] = useState('');
  const batchRunRef  = useRef<BatchRunState | null>(null);
  const batchStopRef = useRef<boolean>(false);
  /** When true, batchRun is driven by the 3-tier test suite — shows SuiteResultsPanel */
  const [suiteMode,      setSuiteMode]       = useState(false);
  const [diagReport,     setDiagReport]      = useState<NestDiagnosticsReport | null>(null);
  const [diagVisible,    setDiagVisible]     = useState(false);
  const [healResult,     setHealResult]      = useState<HealResult | null>(null);
  const [trainingStats,  setTrainingStats]   = useState<TrainingStats | null>(null);
  const [trainingRecords,setTrainingRecords] = useState<TrainingRecord[]>([]);
  const [trainingHistoryVisible, setTrainingHistoryVisible] = useState(false);
  const [corpusPanelVisible,     setCorpusPanelVisible]     = useState(false);

  // Keep disasm ref in sync with prop changes (new binary loaded)
  useEffect(() => {
    disasmRef.current = initialDisassembly;
    offsetRef.current = initialOffset;
    lengthRef.current = initialLength;
  }, [initialDisassembly, initialOffset, initialLength]);

  // Load learning record whenever the binary hash changes
  useEffect(() => {
    const hash = metadata?.sha256;
    if (hash) {
      setLearningRecord(getLearningRecord(hash));
      echoHintsRef.current = getEchoEnhancements(hash);
      strategyReliabilityRef.current = getStrategyReliability();
      setDominance(loadDominanceAssessment(hash));
    } else {
      setLearningRecord(null);
      echoHintsRef.current = [];
      strategyReliabilityRef.current = {};
      setDominance(null);
    }
    // Always (re-)compute cross-binary report when binary changes —
    // prior sessions for other binaries may already be stored
    setCrossBinaryReport(buildCrossBinaryReport(config));
  }, [metadata?.sha256]); // eslint-disable-line react-hooks/exhaustive-deps

  // ── Single iteration pass ───────────────────────────────────────────────

  const handleStep = useCallback(async (): Promise<boolean> => {
    const runner = runnerRef.current;
    if (!runner || !binaryPath) return false;

    const step: NestStepResult = await runner.step();

    // Sync mutable refs
    sessRef.current   = step.session;
    disasmRef.current = runner.disassembly;
    offsetRef.current = runner.currentOffset;
    lengthRef.current = runner.currentLength;

    // Stream iteration state into React UI
    // Keep status='running' while the loop continues (the runner's internal
    // session starts as 'idle' and is only finalized when shouldContinue=false)
    setSession(step.shouldContinue ? { ...step.session, status: 'running' } : { ...step.session });
    setSelectedIter(step.snapshot.iteration);
    learningSessionRef.current = step.learningSession;
    setLearningSession({ ...step.learningSession });
    setIterDecisions(runner.decisions);
    setCurrentStrategyPlan(step.analysisPlan);
    if (step.boosts) setLastBoosts(step.boosts);

    if (!step.shouldContinue) {
      setSummary(summarizeSession(step.session));
      learningSessionRef.current = step.learningSession;
      setLearningSession({ ...step.learningSession });

      const pp = step.postProcessing;
      if (pp) {
        setLearningRecord(pp.learningRecord);
        setSimilarBinaries(pp.similarBinaries);
        echoHintsRef.current        = pp.echoHints;
        strategyReliabilityRef.current = pp.strategyReliability;
        setDominance(pp.dominance);
        setCrossBinaryReport(pp.crossBinaryReport);
        if (pp.diagReport) { setDiagReport(pp.diagReport); setDiagVisible(true); }
        setHealResult(pp.healResult);
        if (pp.healResult.changed) setConfig(pp.healedConfig);
        setTrainingRecords(pp.trainingRecords);
        setTrainingStats(pp.trainingStats);
      }

      // Propagate NEST-enriched verdict to the parent (Verdict panel)
      if (step.session.finalVerdict) {
        onNestComplete?.(step.session.finalVerdict);
      }

      return false; // stop
    }

    return true; // keep going
  }, [binaryPath]);

  // ── Start a new session ─────────────────────────────────────────────────

  const startSession = useCallback(async () => {
    if (!binaryPath) return;
    stopRef.current = false;
    setError(null);
    setSummary(null);
    setSelectedIter(null);
    setIterDecisions([]);

    // NestSessionRunner (engines/) handles all iteration logic and post-processing
    runnerRef.current = new NestSessionRunner({
      filePath:            binaryPath,
      config,
      metadata,
      initialDisassembly,
      initialOffset,
      initialLength,
      strings,
      disassemblyAnalysis,
      strikeSignals,
      echoHints:           echoHintsRef.current,
      strategyReliability: strategyReliabilityRef.current,
      // Apply ownership: start from the best previously achieved confidence
      // and use stored learning patterns as confidence boosts each iteration.
      seedConfidence:      learningRecord?.bestConfidence ?? 0,
      getBoosts: (hash, signalIds) => {
        const b = getLearningBoosts(hash ?? undefined, signalIds);
        return b.confidenceBonus > 0 ? b : null;
      },
      shouldStop:          () => stopRef.current,
    });

    // Sync initial state from the freshly created runner
    disasmRef.current = [...initialDisassembly];
    offsetRef.current = initialOffset;
    lengthRef.current = initialLength;
    learningSessionRef.current = runnerRef.current.learningSession;
    const initSess = { ...runnerRef.current.session, status: 'running' as const };
    sessRef.current = initSess;
    setSession(initSess);
    setLearningSession({ ...runnerRef.current.learningSession });
    setIsRunning(true);

    try {
      if (config.autoAdvance) {
        let keepGoing = true;
        while (keepGoing && !stopRef.current) {
          keepGoing = await handleStep();
          if (keepGoing && config.autoAdvanceDelay > 0) {
            await new Promise<void>(r => setTimeout(r, config.autoAdvanceDelay));
          }
        }
      } else {
        await handleStep();
      }
    } catch (e) {
      setError(String(e));
    }

    setIsRunning(false);
  }, [binaryPath, config, metadata, initialDisassembly, initialOffset, initialLength, strings, disassemblyAnalysis, strikeSignals, handleStep]);

  // ── Next iteration (manual advance) ─────────────────────────────────────

  const advanceIteration = useCallback(async () => {
    if (!sessRef.current || isRunning) return;
    setIsRunning(true);
    setError(null);
    try {
      await handleStep();
    } catch (e) {
      setError(String(e));
    }
    setIsRunning(false);
  }, [isRunning, handleStep]);

  // ── Pause / stop ─────────────────────────────────────────────────────────

  const pauseSession = useCallback(() => {
    stopRef.current = true;
    if (sessRef.current) {
      const paused = { ...sessRef.current, status: 'paused' as const };
      sessRef.current = paused;
      setSession({ ...paused });
    }
    setIsRunning(false);
  }, []);

  const resetSession = useCallback(() => {
    stopRef.current = true;
    runnerRef.current = null;
    sessRef.current = null;
    learningSessionRef.current = null;
    disasmRef.current = initialDisassembly;
    offsetRef.current = initialOffset;
    lengthRef.current = initialLength;
    setSession(null);
    setSummary(null);
    setSelectedIter(null);
    setIsRunning(false);
    setError(null);
    setLastBoosts(null);
    setSimilarBinaries([]);
    setCurrentStrategyPlan(null);
    setLearningSession(null);
    setIterDecisions([]);
    setDominance(null);
  }, [initialDisassembly, initialOffset, initialLength]);

  // ── Multi-binary batch runner ─────────────────────────────────────────────

  /**
   * Run a full NEST session on a single binary path using the supplied config.
   * Returns a BatchItemResult once the session concludes (any stop reason).
   * The session feeds into the existing per-binary learning store just like
   * a normal single-binary session.
   */
  const runBatchItemSession = useCallback(async (
    path:   string,
    cfg:    NestConfig,
    configAdjustmentsApplied: string[],
  ): Promise<BatchItemResult> => {
    const primaryStrategies: StrategyClass[] = [];

    // runNestSession handles metadata fetch, disassembly, analysis loop, and all
    // post-processing (learning store, dominance, diagnostics, healer, training)
    const result = await runNestSession(path, cfg, {
      strategyReliability: strategyReliabilityRef.current,
      shouldStop:          () => batchStopRef.current,
      delay:               cfg.autoAdvanceDelay,
      onIteration:         (step) => {
        if (step.analysisPlan?.primaryStrategy) {
          primaryStrategies.push(step.analysisPlan.primaryStrategy);
        }
      },
    });

    // Propagate updated reliability scores to subsequent batch items
    strategyReliabilityRef.current = result.strategyReliability;

    const snaps = result.session.iterations;
    const last  = snaps[snaps.length - 1];

    const stopReasonRaw: string = result.session.status;
    const stopReason: BatchItemResult['convergenceSpeed']['stopReason'] =
      stopReasonRaw === 'converged'    ? 'converged'
      : stopReasonRaw === 'plateau'    ? 'plateau'
      : stopReasonRaw === 'max-reached'? 'max-reached'
      : stopReasonRaw === 'error'      ? 'error'
      : 'unknown';

    return {
      finalConfidence:          last?.confidence ?? 0,
      verdict:                  last?.verdict.classification ?? 'unknown',
      iterationCount:           snaps.length,
      convergenceSpeed:         computeConvergenceSpeed(snaps, cfg, stopReason),
      stabilityScore:           computeStabilityScore(snaps),
      weaknessFlags:            result.weaknessFlags,
      signalIds:                last?.verdict.signals.map(s => s.id) ?? [],
      dominanceStatus:          result.dominance?.status ?? 'unknown',
      verdictFlipCount:         result.verdictFlipCount,
      configAdjustmentsApplied,
      primaryStrategies,
    };
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  /** Start the multi-binary batch run */
  const startBatchRun = useCallback(async (paths: Array<{ path: string; label?: string }>) => {
    if (paths.length < 2) return;
    batchStopRef.current = false;

    const run: BatchRunState = createBatchRun(paths, config);
    batchRunRef.current = run;
    setBatchRun({ ...run });

    let state: BatchRunState = { ...run, status: 'running' as const };
    batchRunRef.current = state;
    setBatchRun({ ...state });

    // Compute initial signal-weight adjustments from stored cross-binary data
    const signalWeights = computeSignalWeightAdjustments([]);

    for (let i = 0; i < state.items.length; i++) {
      if (batchStopRef.current) break;

      state = markItemRunning(state as Parameters<typeof markItemRunning>[0], i);
      batchRunRef.current = state;
      setBatchRun({ ...state });

      const item = state.items[i];
      // Config changes recorded for this item
      const cfgChanges = state.configHistory
        .filter(ch => ch.appliedBeforeIndex === i)
        .map(ch => ch.summary);

      try {
        const result = await runBatchItemSession(item.path, state.activeConfig, cfgChanges);
        state = completeBatchItem(state as Parameters<typeof completeBatchItem>[0], i, result);
      } catch (e) {
        state = failBatchItem(state as Parameters<typeof failBatchItem>[0], i, String(e));
      }

      batchRunRef.current = state;
      setBatchRun({ ...state });

      // Recompute signal weights using any new overconfidence cases
      const overconfIds = state.metrics.overconfidenceCases.flatMap(c =>
        state.items.find(it => it.path === c.path)?.result?.signalIds ?? []
      );
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const _updatedWeights = computeSignalWeightAdjustments(overconfIds);

      // Refresh cross-binary report
      setCrossBinaryReport(buildCrossBinaryReport(state.activeConfig));
    }

    state = finalizeBatch(state as Parameters<typeof finalizeBatch>[0]);
    batchRunRef.current = state;
    setBatchRun({ ...state });
    setCrossBinaryReport(buildCrossBinaryReport(state.activeConfig));
  }, [config, runBatchItemSession]);

  // ── Derived view state ────────────────────────────────────────────────────

  const iters        = session?.iterations ?? [];
  const selectedSnap = selectedIter != null ? iters[selectedIter] : iters[iters.length - 1];
  const isIdle       = !session || session.status === 'idle';
  const isDone       = session && ['converged', 'max-reached', 'plateau', 'error'].includes(session.status);
  const canAdvance   = !config.autoAdvance && session?.status === 'running' && !isRunning;
  const progression  = iters.map(i => i.confidence);

  // ── Render ────────────────────────────────────────────────────────────────

  return (
    <div className="nest-root">
      {/* Header bar */}
      <div className="nest-header">
        <div className="nest-header-left">
          <span className="nest-logo">⟳</span>
          <span className="nest-title">NEST</span>
          <span className="nest-subtitle">Self-Improving Analysis Loop</span>
          {session && (
            <span className={`nest-status-badge status-${session.status}`}>
              {session.status.replace('-', ' ').toUpperCase()}
            </span>
          )}
          {!session && learningRecord && learningRecord.sessionCount > 0 && (
            <span className="nest-owned-badge" title={`${learningRecord.sessionCount} previous session(s) — resuming from ${learningRecord.bestConfidence}%`}>
              📌 Owned · {learningRecord.bestConfidence}%
            </span>
          )}
        </div>

        <div className="nest-header-right">
          {iters.length > 0 && (
            <span className="nest-iter-count">
              {iters.length}/{config.maxIterations} iterations
            </span>
          )}
          <button
            className={`nest-btn-icon${showBatchPanel ? ' active' : ''}`}
            title="Multi-binary batch run"
            onClick={() => setShowBatchPanel(v => !v)}
          >⬡</button>
          <button
            className={`nest-btn-icon${trainingHistoryVisible ? ' active' : ''}`}
            title="Training History"
            onClick={() => setTrainingHistoryVisible(v => !v)}
          >📋</button>
          <button
            className={`nest-btn-icon${corpusPanelVisible ? ' active' : ''}`}
            title="Corpus &amp; Benchmarks"
            onClick={() => setCorpusPanelVisible(v => !v)}
          >📦</button>
          <button
            className="nest-btn-icon"
            title="Configure NEST"
            onClick={() => setShowConfig(v => !v)}
          >⚙</button>
        </div>
      </div>

      {/* Config panel */}
      {showConfig && (        <div className="nest-config-panel">
          <div className="nest-config-row">
            <label>Max iterations</label>
            <input
              type="number" min={1} max={20} value={config.maxIterations}
              onChange={e => setConfig(c => ({ ...c, maxIterations: Number(e.target.value) }))}
            />
          </div>
          <div className="nest-config-row">
            <label>Confidence threshold (%)</label>
            <input
              type="number" min={50} max={99} value={config.confidenceThreshold}
              onChange={e => setConfig(c => ({ ...c, confidenceThreshold: Number(e.target.value) }))}
            />
          </div>
          <div className="nest-config-row">
            <label>Disasm expansion (bytes)</label>
            <input
              type="number" min={128} max={4096} step={128} value={config.disasmExpansion}
              onChange={e => setConfig(c => ({ ...c, disasmExpansion: Number(e.target.value) }))}
            />
          </div>
          <div className="nest-config-row">
            <label>
              <input
                type="checkbox" checked={config.autoAdvance}
                onChange={e => setConfig(c => ({ ...c, autoAdvance: e.target.checked }))}
              />
              Auto-advance iterations
            </label>
          </div>
          {config.autoAdvance && (
            <div className="nest-config-row">
              <label>Delay between iterations (ms)</label>
              <input
                type="number" min={0} max={5000} step={100} value={config.autoAdvanceDelay}
                onChange={e => setConfig(c => ({ ...c, autoAdvanceDelay: Number(e.target.value) }))}
              />
            </div>
          )}
          <div className="nest-config-row nest-config-aggr">
            <label>Aggressiveness</label>
            <div className="nest-aggr-group">
              {(['conservative', 'balanced', 'aggressive'] as const).map(lvl => (
                <button
                  key={lvl}
                  className={`nest-aggr-btn${config.aggressiveness === lvl ? ' active' : ''}`}
                  onClick={() => setConfig(c => ({ ...c, aggressiveness: lvl }))}
                >
                  {lvl === 'conservative' ? '🛡 Conservative' : lvl === 'aggressive' ? '⚡ Aggressive' : '⚖ Balanced'}
                </button>
              ))}
            </div>
            <div className="nest-aggr-desc">
              {config.aggressiveness === 'conservative' && 'Minimal expansion · cheap ops only · faster'}
              {config.aggressiveness === 'balanced'     && 'Moderate expansion · TALON + ECHO enabled'}
              {config.aggressiveness === 'aggressive'   && '2× expansion · triggers STRIKE · all ops · deeper'}
            </div>
          </div>
          <div className="nest-config-row">
            <label>
              <input
                type="checkbox" checked={config.enableTalon}
                onChange={e => setConfig(c => ({ ...c, enableTalon: e.target.checked }))}
              />
              Enable TALON signals
            </label>
          </div>
          <div className="nest-config-row">
            <label>
              <input
                type="checkbox" checked={config.enableEcho}
                onChange={e => setConfig(c => ({ ...c, enableEcho: e.target.checked }))}
              />
              Enable ECHO signals
            </label>
          </div>
          <div className="nest-config-row">
            <label>
              <input
                type="checkbox" checked={config.enableStrike}
                onChange={e => setConfig(c => ({ ...c, enableStrike: e.target.checked }))}
              />
              Include STRIKE runtime signals
            </label>
          </div>
        </div>
      )}

      {/* Multi-binary batch panel */}
      {showBatchPanel && (
        <div className="nest-mb-config-panel">
          <div className="nest-mb-config-title">
            <span>⬡ Multi-Binary NEST Run</span>
            <span className="nest-mb-config-sub">Analyse 3–5 binaries in sequence to improve cross-binary learning</span>
          </div>
          <div className="nest-mb-config-desc">
            Enter binary paths — one per line. NEST will run full sessions on each,
            track convergence and stability, detect repeated patterns, and adapt the
            configuration between binaries.
          </div>
          <textarea
            className="nest-mb-path-input"
            rows={5}
            placeholder="C:\binaries\sample1.exe&#10;C:\binaries\sample2.dll&#10;C:\binaries\sample3.exe"
            value={batchQueueInput}
            onChange={e => setBatchQueueInput(e.target.value)}
            disabled={batchRun?.status === 'running'}
          />
          <div className="nest-mb-config-actions">
            <button
              className="nest-btn primary"
              disabled={batchQueueInput.trim().length === 0 || batchRun?.status === 'running'}
              onClick={() => {
                const paths = batchQueueInput
                  .split('\n')
                  .map(l => l.trim())
                  .filter(l => l.length > 0)
                  .map(p => ({ path: p }));
                if (paths.length >= 2) {
                  startBatchRun(paths);
                }
              }}
            >
              ⬡ Start Batch Run
            </button>
            {batchRun?.status === 'running' && (
              <button className="nest-btn danger" onClick={() => { batchStopRef.current = true; }}>
                ⏹ Stop Batch
              </button>
            )}
            {batchRun && batchRun.status !== 'running' && (
              <button
                className="nest-btn"
                onClick={() => { setBatchRun(null); batchRunRef.current = null; setBatchQueueInput(''); }}
              >
                ↺ Clear
              </button>
            )}
          </div>
          {batchRun && (
            <MultiBinaryPanel
              batchRun={batchRun}
              onStop={() => { batchStopRef.current = true; }}
            />
          )}
        </div>
      )}

      {/* Controls */}
      <div className="nest-controls">
        {isIdle && (
          <button className="nest-btn primary" onClick={startSession} disabled={!binaryPath}>
            ⟳ Start NEST Session
          </button>
        )}
        {isDone && (
          <button className="nest-btn" onClick={resetSession}>↺ New Session</button>
        )}
        {session?.status === 'running' && !isDone && (
          <>
            {!config.autoAdvance && (
              <button className="nest-btn primary" onClick={advanceIteration} disabled={!canAdvance}>
                → Next Iteration
              </button>
            )}
            <button className="nest-btn danger stop-early" onClick={pauseSession}>
              ⏹ Stop Early
            </button>
          </>
        )}
        {session?.status === 'paused' && (
          <>
            <button className="nest-btn primary" onClick={advanceIteration}>→ Resume</button>
            <button className="nest-btn" onClick={resetSession}>↺ Reset</button>
          </>
        )}
        {isRunning && (
          <span className="nest-spinner">
            <span className="nest-spinner-dot" />
            Analysing…
          </span>
        )}
      </div>

      {/* Progress bar — visible while session is active */}
      {session && !isDone && (
        <div className="nest-progress-wrap">
          <div className="nest-progress-label">
            <span>
              {isRunning ? 'Running iteration…' : session.status === 'paused' ? 'Paused' : 'Ready'}
              {iters.length > 0 && ` — iteration ${iters.length} of ${config.maxIterations}`}
            </span>
            <span>{iters.length > 0 ? `${Math.round(iters[iters.length - 1]?.confidence ?? 0)}% confidence` : ''}</span>
          </div>
          <div className="nest-progress-bar">
            <div
              className="nest-progress-fill"
              style={{ width: `${Math.min(100, (iters.length / config.maxIterations) * 100)}%` }}
            />
          </div>
        </div>
      )}

      {/* Error banner */}
      {error && (
        <div className="nest-error">{error}</div>
      )}

      {/* Training History panel — overlay when toggled */}
      {trainingHistoryVisible && (
        <TrainingHistoryPanel
          records={trainingRecords}
          stats={trainingStats}
          onClose={() => setTrainingHistoryVisible(false)}
        />
      )}

      {/* Corpus & Benchmark panel — overlay when toggled */}
      {corpusPanelVisible && (
        <CorpusBenchmarkPanel
          binaryPath={binaryPath ?? null}
          onClose={() => setCorpusPanelVisible(false)}
        />
      )}

      {/* Empty state */}
      {!session && !error && !trainingHistoryVisible && (
        <div className="nest-empty">
          <div className="nest-empty-icon">⟳</div>
          <div className="nest-empty-title">NEST — Self-Improving Analysis</div>
          <div className="nest-empty-desc">
            Each iteration expands disassembly coverage and refines the verdict.
            The loop converges when confidence reaches {config.confidenceThreshold}%
            or plateaus.
          </div>
          <div className="nest-empty-steps">
            <div className="nest-empty-step">1 · Run full pipeline (signatures, ECHO, TALON)</div>
            <div className="nest-empty-step">2 · Compute verdict via correlation engine</div>
            <div className="nest-empty-step">3 · Evaluate uncertainty → converge or plan</div>
            <div className="nest-empty-step">4 · Generate refinement plan</div>
            <div className="nest-empty-step">5 · Expand disassembly, re-run targeted analysis</div>
            <div className="nest-empty-step">6 · Compare deltas, store snapshot</div>
          </div>
          {/* Test Subject Selector — shown when no binary is loaded yet */}
          {(!binaryPath || binaryPath === 'sample.bin') && onLoadTrainingBinary && (
            <NestTestSubjectSelector
              onLoad={onLoadTrainingBinary}
              onRunSuite={() => {
                setSuiteMode(true);
                startBatchRun(TEST_SUBJECT_SUITE.map(s => ({ path: s.path, label: s.label })));
              }}
            />
          )}
          {/* Suite results panel — shown when a suite run is active or complete */}
          {suiteMode && batchRun && (
            <SuiteResultsPanel
              batchRun={batchRun}
              onClose={() => setSuiteMode(false)}
              onStop={() => { batchStopRef.current = true; }}
            />
          )}
          {/* Show learning context even before session starts */}
          <div className="nest-empty-learning">
            <LearningPanel
              record={learningRecord}
              boosts={null}
              similar={similarBinaries}
            />
          </div>
        </div>
      )}

      {/* Main layout — timeline + detail */}
      {session && iters.length > 0 && (
        <div className="nest-body">

          {/* Convergence banner — shown when done */}
          {isDone && summary && (
            <ConvergenceBanner summary={summary} status={session.status} />
          )}

          {/* Dominance verdict — shown when done */}
          {isDone && dominance && (
            <DominanceBanner assessment={dominance} />
          )}

          {/* Diagnostics panel — shown when done and report is available */}
          {isDone && diagVisible && diagReport && (
            <DiagnosticsPanel
              report={diagReport}
              onClose={() => setDiagVisible(false)}
            />
          )}

          {/* Healer banner — shown when done and healer produced output */}
          {isDone && healResult && (
            <HealerBanner
              result={healResult}
              regression={checkRegressionWarning(trainingRecords)}
              onDismiss={() => setHealResult(null)}
            />
          )}

          {/* Evolution strip + chart — always visible once any iteration is done */}
          <div className="nest-evolution-wrap">
            <EvolutionStrip
              iters={iters}
              selected={selectedIter}
              onSelect={setSelectedIter}
            />
            <ConvergenceChart
              progression={progression}
              threshold={config.confidenceThreshold}
              width={Math.max(280, iters.length * 60 + 64)}
            />
          </div>

          {/* Left: iteration timeline */}
          <div className="nest-timeline">
            <div className="nest-timeline-title">Iterations</div>
            <div className="nest-timeline-list">
              {iters.map((snap, i) => (
                <IterationCard
                  key={snap.iteration}
                  snap={snap}
                  prev={i > 0 ? iters[i - 1] : undefined}
                  selected={selectedIter === i}
                  onClick={() => setSelectedIter(i)}
                  decision={iterDecisions.find(d => d.iteration === snap.iteration)}
                />
              ))}
              {isRunning && (
                <div className="nest-iter-card pending">
                  <div className="nest-iter-header">
                    <span className="nest-iter-num">#{iters.length + 1}</span>
                    <span className="nest-iter-pending">Analysing…</span>
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Right: detail panel */}
          <div className="nest-detail">
            {/* Learning context — always visible once session starts */}
            <LearningPanel
              record={learningRecord}
              boosts={lastBoosts}
              similar={similarBinaries}
            />
            {/* Meta-learning session panel */}
            {learningSession && learningSession.decisions.length > 0 && (
              <LearningSessionPanel session={learningSession} />
            )}
            {selectedSnap ? (
              <>
                <div className="nest-detail-header">
                  <span className="nest-detail-title">Iteration #{selectedSnap.iteration + 1}</span>
                  <span className="nest-detail-ts">
                    {new Date(selectedSnap.timestamp).toLocaleTimeString()} · {fmtMs(selectedSnap.durationMs)}
                  </span>
                </div>

                {/* Verdict */}
                <div className="nest-verdict-row">
                  <span
                    className="nest-verdict-badge"
                    style={{ background: verdictColor(selectedSnap.verdict.classification) + '22',
                             borderColor: verdictColor(selectedSnap.verdict.classification) }}
                  >
                    {selectedSnap.verdict.classification}
                  </span>
                  <ConfidenceBar
                    value={selectedSnap.confidence}
                    prev={selectedSnap.iteration > 0
                      ? iters[selectedSnap.iteration - 1]?.confidence
                      : undefined}
                  />
                </div>

                {/* Delta */}
                {selectedSnap.delta && (
                  <div className={`nest-delta-block ${selectedSnap.delta.significantChange ? 'significant' : ''}`}>
                    <div className="nest-delta-title">
                      {selectedSnap.delta.significantChange ? '▲ Significant Change' : '△ Change'}
                    </div>
                    <div className="nest-delta-summary">{selectedSnap.delta.summary}</div>
                    {selectedSnap.delta.newSignals.length > 0 && (
                      <div className="nest-delta-signals">
                        + {selectedSnap.delta.newSignals.map(s => (
                          <span key={s} className="nest-signal-chip new">{s}</span>
                        ))}
                      </div>
                    )}
                    {selectedSnap.delta.removedSignals.length > 0 && (
                      <div className="nest-delta-signals">
                        − {selectedSnap.delta.removedSignals.map(s => (
                          <span key={s} className="nest-signal-chip removed">{s}</span>
                        ))}
                      </div>
                    )}
                    {selectedSnap.delta.behaviorsAdded.length > 0 && (
                      <div className="nest-delta-behaviors">
                        Behaviors detected: {selectedSnap.delta.behaviorsAdded.map(b => (
                          <span key={b} className="nest-behavior-chip">{b}</span>
                        ))}
                      </div>
                    )}
                  </div>
                )}

                {/* Coverage */}
                <div className="nest-section">
                  <div className="nest-section-title">Coverage</div>
                  <div className="nest-coverage-row">
                    <span>{selectedSnap.input.instructionCount} instructions</span>
                    <span>{fmtHex(selectedSnap.input.disasmOffset)} + {fmtHex(selectedSnap.input.disasmLength)} bytes</span>
                    <span>{selectedSnap.input.signatureMatches.length} signature match(es)</span>
                  </div>
                </div>

                {/* Signals */}
                {selectedSnap.verdict.signals.length > 0 && (
                  <div className="nest-section">
                    <div className="nest-section-title">
                      Active Signals ({selectedSnap.verdict.signals.length})
                    </div>
                    <div className="nest-signals-list">
                      {selectedSnap.verdict.signals.slice(0, 8).map(sig => (
                        <div key={sig.id} className="nest-signal-row">
                          <span className="nest-signal-id">{sig.id}</span>
                          <span className="nest-signal-weight">w{sig.weight}</span>
                          {sig.tier && (
                            <span className={`nest-signal-tier nest-tier-${sig.tier.toLowerCase()}`}>
                              {sig.tier}
                            </span>
                          )}
                          {sig.corroboratedBy.length > 0 && (
                            <span className="nest-signal-corr">
                              ✓ {sig.corroboratedBy.join(', ')}
                            </span>
                          )}
                        </div>
                      ))}
                      {selectedSnap.verdict.signals.length > 8 && (
                        <div className="nest-signals-more">
                          +{selectedSnap.verdict.signals.length - 8} more
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {/* Evidence-tier confidence breakdown */}
                {selectedSnap.verdict.evidenceTierBreakdown && (() => {
                  const etb = selectedSnap.verdict.evidenceTierBreakdown!;
                  const total = etb.direct.contribution + etb.strong.contribution + etb.weak.contribution;
                  const tierRows: Array<{ label: string; key: keyof typeof etb; color: string; cap: number }> = [
                    { label: 'DIRECT',  key: 'direct', color: '#4ade80', cap: 40 },
                    { label: 'STRONG',  key: 'strong', color: '#60a5fa', cap: 35 },
                    { label: 'WEAK',    key: 'weak',   color: '#a3a3a3', cap: 10 },
                  ];
                  return (
                    <div className="nest-section">
                      <div className="nest-section-title">Confidence Tier Breakdown</div>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.45rem', marginTop: '0.4rem' }}>
                        {tierRows.map(({ label, key, color, cap }) => {
                          const row = etb[key] as { signalCount: number; contribution: number; signals: string[] };
                          const pct = cap > 0 ? (row.contribution / cap) * 100 : 0;
                          return (
                            <div key={label} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.78rem' }}>
                              <span style={{
                                minWidth: '52px', fontWeight: 700, fontSize: '0.7rem',
                                color, fontFamily: 'monospace', letterSpacing: '0.04em',
                              }}>{label}</span>
                              <div style={{
                                flex: 1, height: '6px', background: '#2a2a2a',
                                borderRadius: '3px', overflow: 'hidden',
                              }}>
                                <div style={{
                                  width: `${pct}%`, height: '100%',
                                  background: color, borderRadius: '3px',
                                  opacity: row.signalCount === 0 ? 0.2 : 1,
                                }} />
                              </div>
                              <span style={{ minWidth: '36px', textAlign: 'right', color, fontWeight: 600 }}>
                                {row.contribution}<span style={{ color: '#555', fontWeight: 400 }}>/{cap}</span>
                              </span>
                              <span style={{ color: '#666', minWidth: '70px' }}>
                                {row.signalCount} signal{row.signalCount !== 1 ? 's' : ''}
                              </span>
                            </div>
                          );
                        })}
                        <div style={{ fontSize: '0.72rem', color: '#555', borderTop: '1px solid #2a2a2a', paddingTop: '0.3rem', marginTop: '0.1rem' }}>
                          Tier contribution: {total} pts
                          {etb.preDampenConfidence !== selectedSnap.confidence && (
                            <span> · pre-dampen {etb.preDampenConfidence}%</span>
                          )}
                        </div>
                      </div>
                    </div>
                  );
                })()}

                {/* Strategy Plan */}
                {(currentStrategyPlan || selectedSnap.refinementPlan) && (() => {
                  // Use live strategy plan for the latest iteration, snapshot plan for history
                  const isLatest = selectedIter === iters.length - 1 || selectedIter == null;
                  const plan = isLatest && currentStrategyPlan ? currentStrategyPlan : null;
                  const fallback = selectedSnap.refinementPlan;
                  return (
                    <div className="nest-section">
                      <div className="nest-section-title">
                        Analysis Strategy
                        {plan && (
                          <span className="nest-plan-boost">
                            est. +{plan.totalExpectedGain}%
                          </span>
                        )}
                        {!plan && fallback && (
                          <span className="nest-plan-boost">
                            est. +{fallback.expectedBoost}%
                          </span>
                        )}
                      </div>
                      {plan ? (
                        <>
                          <div className="nest-plan-rationale">{plan.rationale}</div>
                          {plan.lowConfidenceAreas.length > 0 && (
                            <div className="nest-strategy-areas">
                              {plan.lowConfidenceAreas.slice(0, 4).map((area, i) => (
                                <div key={i} className={`nest-area-chip sev-${area.severity}`}>
                                  <span className="nest-area-cause">{area.cause}</span>
                                  <span className="nest-area-penalty">−{area.confidencePenalty}%</span>
                                </div>
                              ))}
                            </div>
                          )}
                          <div className="nest-strategy-summary">
                            {summarisePlan(plan).map((line, i) => (
                              <div key={i} className="nest-strategy-line">⟳ {line}</div>
                            ))}
                          </div>
                          <div className="nest-plan-actions">
                            {getReadyActions(plan).slice(0, 5).map((action, i) => (
                              <div key={i} className={`nest-plan-action cost-${action.cost}`}>
                                <span className={`nest-strategy-badge s-${action.strategy}`}>
                                  {action.strategy}
                                </span>
                                <span className="nest-plan-reason">{action.label}</span>
                                {action.expectedGain > 0 && (
                                  <span className="nest-plan-gain">+{action.expectedGain}%</span>
                                )}
                              </div>
                            ))}
                          </div>
                          {plan.requestStrike && (
                            <div className="nest-strike-request">
                              ⚡ STRIKE execution trace requested
                            </div>
                          )}
                        </>
                      ) : fallback ? (
                        <>
                          <div className="nest-plan-rationale">{fallback.rationale}</div>
                          <div className="nest-plan-actions">
                            {fallback.actions.slice(0, 5).map((action, i) => (
                              <div key={i} className="nest-plan-action">
                                <ActionBadge action={action} />
                                <span className="nest-plan-reason">{action.reason}</span>
                              </div>
                            ))}
                          </div>
                        </>
                      ) : null}
                    </div>
                  );
                })()}

                {/* Annotations */}
                {selectedSnap.annotations.length > 0 && (
                  <div className="nest-section">
                    <div className="nest-section-title">Notes</div>
                    {selectedSnap.annotations.map((note, i) => (
                      <div key={i} className="nest-annotation">⟳ {note}</div>
                    ))}
                  </div>
                )}

                {/* Navigate to top signal address */}
                {selectedSnap.verdict.signals.length > 0 && (
                  <div className="nest-nav-row">
                    <button
                      className="nest-btn small"
                      onClick={() => {
                        const firstAddr = selectedSnap.input.disasmOffset;
                        if (firstAddr) onAddressSelect(firstAddr);
                      }}
                    >
                      → View in Disassembly
                    </button>
                  </div>
                )}
              </>
            ) : (
              <div className="nest-detail-empty">Select an iteration to view details</div>
            )}
          </div>
        </div>
      )}

      {/* Summary panel when done */}
      {summary && isDone && (
        <div className="nest-summary-wrap">
          <SummaryPanel summary={summary} />
          {dominance && <DominanceBanner assessment={dominance} />}
          {session && (() => {
            const wsm = computeWorkSaved(session);
            return wsm.computedAtIteration > 0 ? <WorkSavedPanel metrics={wsm} /> : null;
          })()}
        </div>
      )}
    </div>
  );
};

export default NestView;
