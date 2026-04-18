import React, { useState } from 'react';
import type {
  BinaryVerdictResult,
  BinaryClassification,
  CorrelatedSignal,
  NegativeSignal,
  ExplainabilityEntry,
  WorkflowStep,
} from '../utils/correlationEngine';

// ─── Classification styling ───────────────────────────────────────────────────

const CLASS_STYLE: Record<BinaryClassification, { color: string; bg: string; icon: string; border: string }> = {
  clean:             { color: '#4caf50', bg: 'rgba(76,175,80,0.08)',  icon: '✓', border: '#4caf5044' },
  suspicious:        { color: '#ffc107', bg: 'rgba(255,193,7,0.08)',  icon: '⚑', border: '#ffc10744' },
  packer:            { color: '#ff9800', bg: 'rgba(255,152,0,0.08)',  icon: '📦', border: '#ff980044' },
  dropper:           { color: '#f44336', bg: 'rgba(244,67,54,0.10)',  icon: '💉', border: '#f4433644' },
  'ransomware-like': { color: '#e91e63', bg: 'rgba(233,30,99,0.10)',  icon: '🔒', border: '#e91e6344' },
  'info-stealer':    { color: '#9c27b0', bg: 'rgba(156,39,176,0.10)', icon: '🕵', border: '#9c27b044' },
  rat:               { color: '#f44336', bg: 'rgba(244,67,54,0.10)',  icon: '🐀', border: '#f4433644' },
  loader:            { color: '#ff9800', bg: 'rgba(255,152,0,0.08)',  icon: '⬇', border: '#ff980044' },
  'likely-malware':  { color: '#f44336', bg: 'rgba(244,67,54,0.10)',  icon: '☣', border: '#f4433644' },
  unknown:           { color: '#888',    bg: 'rgba(128,128,128,0.05)',icon: '?', border: '#88888833' },
};

const SOURCE_COLORS: Record<string, string> = {
  structure:   '#64b5f6',
  imports:     '#ff8a65',
  strings:     '#81c784',
  disassembly: '#ba68c8',
};

const SOURCE_LABELS: Record<string, string> = {
  structure:   'Structure',
  imports:     'Imports',
  strings:     'Strings',
  disassembly: 'Disassembly',
};

const PRIORITY_COLOR: Record<string, string> = {
  critical: '#f44336',
  high:     '#ff9800',
  medium:   '#ffc107',
  low:      '#4fc3f7',
};

const CLASS_LABEL: Record<BinaryClassification, string> = {
  clean:             'Clean',
  suspicious:        'Suspicious',
  packer:            'Packer',
  dropper:           'Dropper',
  'ransomware-like': 'Ransomware-like',
  'info-stealer':    'Info Stealer',
  rat:               'RAT / Backdoor',
  loader:            'Loader',
  'likely-malware':  'Likely Malware',
  unknown:           'Unknown',
};

// ─── Component ────────────────────────────────────────────────────────────────

interface Props {
  verdict: BinaryVerdictResult;
  onNavigateTab?: (tab: string) => void;
}

export default function BinaryVerdict({ verdict, onNavigateTab }: Props) {
  const [expanded, setExpanded] = useState(false);
  const [activeStep, setActiveStep] = useState<number | null>(null);

  const style = CLASS_STYLE[verdict.classification];
  const label = CLASS_LABEL[verdict.classification];

  const hasData = verdict.signalCount > 0;

  return (
    <div className="binary-verdict" style={{ borderColor: style.border, background: style.bg }}>

      {/* Header row: classification + score */}
      <div className="verdict-header" onClick={() => setExpanded(e => !e)}>
        <div className="verdict-badge" style={{ color: style.color, borderColor: style.border }}>
          <span className="verdict-icon">{style.icon}</span>
          <span className="verdict-label">{label}</span>
        </div>

        <div className="verdict-scores">
          <div className="verdict-score-item">
            <span className="verdict-score-num" style={{ color: scoreColor(verdict.threatScore) }}>
              {verdict.threatScore}
            </span>
            <span className="verdict-score-sub">/ 100</span>
          </div>
          <div className="verdict-score-divider" />
          <div className="verdict-score-item">
            <span className="verdict-score-num" style={{ color: '#888' }}>{verdict.confidence}%</span>
            <span className="verdict-score-sub">conf</span>
          </div>
        </div>

        {/* Signal source badges */}
        <div className="verdict-sources">
          {(['structure', 'imports', 'strings', 'disassembly'] as const).map(src => {
            const count = verdict.signals.filter(s => s.source === src).length;
            return (
              <span
                key={src}
                className={`verdict-source-badge ${count === 0 ? 'verdict-source-empty' : ''}`}
                style={count > 0 ? { color: SOURCE_COLORS[src], borderColor: SOURCE_COLORS[src] + '44' } : {}}
                title={`${SOURCE_LABELS[src]}: ${count} signal(s)`}
              >
                {SOURCE_LABELS[src][0]} {count > 0 ? count : '—'}
              </span>
            );
          })}
        </div>

        <button className="verdict-expand-btn" type="button" title={expanded ? 'Collapse' : 'Expand'}>
          {expanded ? '▲' : '▼'}
        </button>
      </div>

      {/* Summary line */}
      <p className="verdict-summary">{verdict.summary}</p>

      {/* Expanded detail */}
      {expanded && hasData && (
        <div className="verdict-detail">

          {/* Correlated signals */}
          {verdict.signals.length > 0 && (
            <section className="verdict-section">
              <div className="verdict-section-title">Evidence Chain</div>
              <div className="verdict-signals">
                {[...verdict.signals]
                  .sort((a, b) => b.weight - a.weight)
                  .map(sig => (
                    <SignalRow key={sig.id} signal={sig} />
                  ))}
              </div>
            </section>
          )}

          {/* Amplifiers */}
          {verdict.amplifiers.length > 0 && (
            <section className="verdict-section">
              <div className="verdict-section-title">🔗 Cross-Signal Amplifiers</div>
              {verdict.amplifiers.map((amp, i) => (
                <div key={i} className="verdict-amplifier">{amp}</div>
              ))}
            </section>
          )}

          {/* Dismissals */}
          {verdict.dismissals.length > 0 && (
            <section className="verdict-section">
              <div className="verdict-section-title">✓ Mitigating Factors</div>
              {verdict.dismissals.map((d, i) => (
                <div key={i} className="verdict-dismissal">{d}</div>
              ))}
            </section>
          )}

          {/* Negative signals */}
          {verdict.negativeSignals.length > 0 && (
            <section className="verdict-section">
              <div className="verdict-section-title">🟢 Clean Indicators</div>
              {verdict.negativeSignals.map((ns) => (
                <div key={ns.id} className="verdict-negative-signal">
                  <span className="verdict-neg-finding">{ns.finding}</span>
                  <span className="verdict-neg-reduction">−{ns.reduction}pts</span>
                </div>
              ))}
            </section>
          )}

          {/* Explainability */}
          {verdict.explainability.length > 0 && (
            <section className="verdict-section">
              <div className="verdict-section-title">🔍 Why This Classification</div>
              <div className="verdict-explain-list">
                {verdict.explainability.map((e, i) => (
                  <div key={i} className={`verdict-explain-row verdict-explain-${e.contribution}`}>
                    <span className="verdict-explain-icon">
                      {e.contribution === 'increases' ? '▲' : e.contribution === 'decreases' ? '▼' : '—'}
                    </span>
                    <div className="verdict-explain-content">
                      <span className="verdict-explain-factor">{e.factor}</span>
                      <span className="verdict-explain-detail">{e.detail}</span>
                    </div>
                  </div>
                ))}
              </div>
            </section>
          )}

          {/* Workflow steps */}
          {verdict.nextSteps.length > 0 && (
            <section className="verdict-section">
              <div className="verdict-section-title">🧭 Next Steps</div>
              <div className="verdict-steps">
                {verdict.nextSteps.map((step, i) => (
                  <WorkflowStepRow
                    key={i}
                    step={step}
                    index={i + 1}
                    open={activeStep === i}
                    onToggle={() => setActiveStep(activeStep === i ? null : i)}
                    onNavigate={onNavigateTab}
                  />
                ))}
              </div>
            </section>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function SignalRow({ signal }: { signal: CorrelatedSignal }) {
  const color = SOURCE_COLORS[signal.source] ?? '#aaa';
  const barWidth = `${Math.round((signal.weight / 10) * 100)}%`;
  return (
    <div className="verdict-signal-row">
      <span className="verdict-signal-source" style={{ color, borderColor: color + '44' }}>
        {SOURCE_LABELS[signal.source]}
      </span>
      <span className="verdict-signal-finding">{signal.finding}</span>
      <div className="verdict-signal-bar-track" title={`Weight: ${signal.weight}/10`}>
        <div className="verdict-signal-bar-fill" style={{ width: barWidth, background: color }} />
      </div>
    </div>
  );
}

function WorkflowStepRow({
  step,
  index,
  open,
  onToggle,
  onNavigate,
}: {
  step: WorkflowStep;
  index: number;
  open: boolean;
  onToggle: () => void;
  onNavigate?: (tab: string) => void;
}) {
  const color = PRIORITY_COLOR[step.priority];
  return (
    <div className={`verdict-step ${open ? 'verdict-step-open' : ''}`} style={{ borderLeftColor: color }}>
      <div className="verdict-step-header" onClick={onToggle}>
        <span className="verdict-step-num" style={{ background: color + '33', color }}>
          {index}
        </span>
        <span className="verdict-step-action">{step.action}</span>
        <span className="verdict-step-priority" style={{ color }}>{step.priority.toUpperCase()}</span>
        <span className="verdict-step-toggle">{open ? '▲' : '▼'}</span>
      </div>
      {open && (
        <div className="verdict-step-detail">
          <p className="verdict-step-rationale">{step.rationale}</p>
          {step.tab && onNavigate && (
            <button
              type="button"
              className="verdict-step-goto"
              onClick={() => onNavigate(step.tab!)}
            >
              Go to {step.tab.charAt(0).toUpperCase() + step.tab.slice(1)} tab →
            </button>
          )}
        </div>
      )}
    </div>
  );
}

function scoreColor(score: number): string {
  if (score >= 70) return '#f44336';
  if (score >= 40) return '#ff9800';
  if (score >= 20) return '#ffc107';
  return '#4caf50';
}
