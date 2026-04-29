import React, { useState } from 'react';
import type {
  BinaryVerdictResult,
  BinaryClassification,
  CorrelatedSignal,
  NegativeSignal,
  ExplainabilityEntry,
  WorkflowStep,
  SignalLocation,
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
  wiper:             { color: '#e91e63', bg: 'rgba(233,30,99,0.10)',  icon: '🗑', border: '#e91e6344' },
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
  wiper:             'Wiper',
  'likely-malware':  'Likely Malware',
  unknown:           'Unknown',
};

// ─── Component ────────────────────────────────────────────────────────────────

interface Props {
  verdict: BinaryVerdictResult;
  onNavigateTab?: (tab: string) => void;
  /** Called when user clicks a navigable location chip — address > 0 */
  onJumpToAddress?: (address: number) => void;
}

export default function BinaryVerdict({ verdict, onNavigateTab, onJumpToAddress }: Props) {
  const [expanded, setExpanded] = useState(false);
  const [activeStep, setActiveStep] = useState<number | null>(null);

  const signals = (verdict.signals ?? []).map((signal) => {
    const legacy = signal as CorrelatedSignal & {
      description?: string;
      corroborations?: number;
      priority?: string;
    };
    return {
      ...legacy,
      finding: legacy.finding ?? legacy.description ?? 'Signal',
      corroboratedBy: legacy.corroboratedBy ?? Array.from({ length: legacy.corroborations ?? 0 }, (_, i) => `legacy-${i}`),
    };
  });
  const amplifiers = (verdict as BinaryVerdictResult & { amplifiers?: string[] }).amplifiers ?? [];
  const dismissals = (verdict as BinaryVerdictResult & { dismissals?: string[] }).dismissals ?? [];
  const negativeSignals = verdict.negativeSignals ?? [];
  const explainability = verdict.explainability ?? [];
  const nextSteps = (
    (verdict as BinaryVerdictResult & { nextSteps?: WorkflowStep[]; workflowSteps?: Array<WorkflowStep & { label?: string; description?: string }> }).nextSteps
    ?? (verdict as BinaryVerdictResult & { workflowSteps?: Array<WorkflowStep & { label?: string; description?: string }> }).workflowSteps
    ?? []
  ).map((step) => {
    const legacyStep = step as WorkflowStep & { label?: string; description?: string };
    return {
      ...legacyStep,
      action: legacyStep.action ?? legacyStep.label ?? 'Review step',
      rationale: legacyStep.rationale ?? legacyStep.description ?? 'Follow this investigation step.',
      priority: legacyStep.priority ?? 'medium',
    };
  });
  const contradictions = (verdict as BinaryVerdictResult & { contradictions?: unknown[] }).contradictions ?? [];
  const behavioralTags = (
    (verdict as BinaryVerdictResult & { behaviors?: string[]; behavioralTags?: string[] }).behaviors
    ?? (verdict as BinaryVerdictResult & { behavioralTags?: string[] }).behavioralTags
    ?? []
  );

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
            const count = signals.filter(s => s.source === src).length;
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

      {/* Uncertainty flags — Prompt 10 (Trusted Acceleration) */}
      {verdict.uncertaintyFlags?.length > 0 && (
        <div style={{ margin: '6px 0 2px', display: 'flex', flexDirection: 'column', gap: 4 }}>
          {verdict.uncertaintyFlags.map((flag, i) => (
            <div key={i} style={{
              display: 'flex', alignItems: 'flex-start', gap: 8,
              background: 'rgba(255,193,7,0.07)', border: '1px solid rgba(255,193,7,0.25)',
              borderRadius: 5, padding: '5px 8px', fontSize: 11, color: '#ffc107',
            }}>
              <span style={{ fontWeight: 700, flexShrink: 0 }}>⚠</span>
              <span>{flag}</span>
            </div>
          ))}
        </div>
      )}

      {/* Summary line */}
      <p className="verdict-summary">{verdict.summary}</p>

      {behavioralTags.length > 0 && (
        <div className="verdict-tags-inline" style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginBottom: 8 }}>
          {behavioralTags.map((tag, i) => (
            <span key={`inline-${tag}-${i}`} className="verdict-tag-chip">{tag}</span>
          ))}
        </div>
      )}

      {/* Expanded detail */}
      {expanded && hasData && (
        <div className="verdict-detail">

          {/* Correlated signals */}
          {signals.length > 0 && (
            <section className="verdict-section">
              <div className="verdict-section-title">Evidence Chain</div>
              <div className="verdict-signals">
                {[...signals]
                  .sort((a, b) => b.weight - a.weight)
                  .map(sig => (
                    <SignalRow key={sig.id} signal={sig} onJumpToAddress={onJumpToAddress} />
                  ))}
              </div>
            </section>
          )}

          {/* Amplifiers */}
          {amplifiers.length > 0 && (
            <section className="verdict-section">
              <div className="verdict-section-title">🔗 Cross-Signal Amplifiers</div>
              {amplifiers.map((amp, i) => (
                <div key={i} className="verdict-amplifier">{amp}</div>
              ))}
            </section>
          )}

          {/* Dismissals */}
          {dismissals.length > 0 && (
            <section className="verdict-section">
              <div className="verdict-section-title">✓ Mitigating Factors</div>
              {dismissals.map((d, i) => (
                <div key={i} className="verdict-dismissal">{d}</div>
              ))}
            </section>
          )}

          {/* Negative signals */}
          {negativeSignals.length > 0 && (
            <section className="verdict-section">
              <div className="verdict-section-title">🟢 Clean Indicators</div>
              {negativeSignals.map((ns) => (
                <div key={ns.id} className="verdict-negative-signal">
                  <span className="verdict-neg-finding">{ns.finding}</span>
                  <span className="verdict-neg-reduction">−{ns.reduction}pts</span>
                </div>
              ))}
            </section>
          )}

          {/* Explainability */}
          {explainability.length > 0 && (
            <section className="verdict-section">
              <div className="verdict-section-title">🔍 Why This Classification</div>
              <div className="verdict-explain-list">
                {explainability.map((e, i) => (
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
          {nextSteps.length > 0 && (
            <section className="verdict-section">
              <div className="verdict-section-title">🧭 Next Steps</div>
              <div className="verdict-steps">
                {nextSteps.map((step, i) => (
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

// Certainty badge styling — Prompt 10 (Trusted Acceleration)
const CERTAINTY_STYLE: Record<string, { label: string; bg: string; color: string; title: string }> = {
  observed:  { label: 'OBS', bg: 'rgba(76,175,80,0.15)',   color: '#4caf50', title: 'Observed: directly present in the binary — high trust' },
  inferred:  { label: 'INF', bg: 'rgba(255,193,7,0.15)',   color: '#ffc107', title: 'Inferred: derived by combining multiple observed facts — moderate trust' },
  heuristic: { label: 'HEU', bg: 'rgba(120,120,120,0.15)', color: '#999',    title: 'Heuristic: pattern-matched rule — needs human confirmation' },
};

// Kind icons for location chips
const LOC_KIND_ICON: Record<SignalLocation['kind'], string> = {
  import:      '⚙️',
  string:      '"',
  instruction: '▶',
  function:    'ƒ',
  section:     '▤',
  pattern:     '~',
};

// Signal engine prefix → display label for the finding prefix chip
const ENGINE_PREFIX_LABEL: Record<string, { label: string; color: string }> = {
  'YARA/':   { label: 'YARA',   color: '#ab47bc' },
  'MYTHOS/': { label: 'MYTHOS', color: '#26a69a' },
  'TALON:':  { label: 'TALON',  color: '#42a5f5' },
  'ECHO:':   { label: 'ECHO',   color: '#66bb6a' },
  'STRIKE:': { label: 'STRIKE', color: '#ef5350' },
};

function getEngineChip(finding?: string): { label: string; color: string } | null {
  if (!finding) return null;
  for (const [prefix, chip] of Object.entries(ENGINE_PREFIX_LABEL)) {
    if (finding.startsWith(prefix)) return chip;
  }
  return null;
}

function SignalRow({
  signal,
  onJumpToAddress,
}: {
  signal: CorrelatedSignal;
  onJumpToAddress?: (address: number) => void;
}) {
  const [open, setOpen] = useState(false);

  const color    = SOURCE_COLORS[signal.source] ?? '#aaa';
  const barWidth = `${Math.round((signal.weight / 10) * 100)}%`;
  const cert     = signal.certainty ? CERTAINTY_STYLE[signal.certainty] : null;
  const engine   = getEngineChip(signal.finding);

  const hasDetail = (signal.locations && signal.locations.length > 0) ||
                    (signal.evidence  && signal.evidence.length  > 0);

  // Strip the engine prefix from the displayed finding text (it's shown as a chip)
  const findingText = signal.finding ?? 'Signal';
  const displayFinding = engine
    ? findingText.replace(/^(YARA|MYTHOS|TALON|ECHO|STRIKE)[:/]\s*/, '')
    : findingText;

  return (
    <div className="verdict-signal-row" style={{ flexDirection: 'column', alignItems: 'stretch', gap: 0 }}>
      {/* ── Header row */}
      <div
        style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: hasDetail ? 'pointer' : 'default' }}
        onClick={() => hasDetail && setOpen(o => !o)}
        title={hasDetail ? (open ? 'Collapse detail' : 'Expand: locations + evidence') : undefined}
      >
        <span className="verdict-signal-source" style={{ color, borderColor: color + '44' }}>
          {SOURCE_LABELS[signal.source]}
        </span>

        {/* Engine chip: YARA / MYTHOS / TALON / etc. */}
        {engine && (
          <span style={{
            fontSize: 10, fontWeight: 700, padding: '1px 5px',
            borderRadius: 3, background: engine.color + '22', color: engine.color,
            border: `1px solid ${engine.color}44`, flexShrink: 0,
          }}>
            {engine.label}
          </span>
        )}

        {/* Certainty badge */}
        {cert && (
          <span
            title={cert.title}
            style={{
              fontSize: 10, fontWeight: 700, padding: '0 5px',
              borderRadius: 3, background: cert.bg, color: cert.color,
              fontFamily: 'monospace', flexShrink: 0,
            }}
          >
            {cert.label}
          </span>
        )}

        <span className="verdict-signal-finding" style={{ flex: 1 }}>{displayFinding}</span>

        <div className="verdict-signal-bar-track" title={`Weight: ${signal.weight}/10`}>
          <div className="verdict-signal-bar-fill" style={{ width: barWidth, background: color }} />
        </div>

        {/* Expand toggle when there is detail */}
        {hasDetail && (
          <span style={{ fontSize: 10, color: '#666', flexShrink: 0, userSelect: 'none' }}>
            {open ? '▲' : '▼'}
          </span>
        )}
      </div>

      {/* ── Expanded detail: locations + evidence */}
      {open && hasDetail && (
        <div style={{
          marginTop: 6, paddingLeft: 8,
          borderLeft: `2px solid ${color}44`,
          display: 'flex', flexDirection: 'column', gap: 8,
        }}>

          {/* Location chips */}
          {signal.locations && signal.locations.length > 0 && (
            <div>
              <div style={{ fontSize: 10, color: '#777', marginBottom: 4, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                Code Locations
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5 }}>
                {signal.locations.map((loc, i) => (
                  <LocationChip
                    key={i}
                    loc={loc}
                    onJumpToAddress={onJumpToAddress}
                  />
                ))}
              </div>
            </div>
          )}

          {/* Evidence sentences */}
          {signal.evidence && signal.evidence.length > 0 && (
            <div>
              <div style={{ fontSize: 10, color: '#777', marginBottom: 4, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                Why This Fired
              </div>
              <ul style={{ margin: 0, padding: '0 0 0 14px', listStyle: 'disc' }}>
                {signal.evidence.map((ev, i) => (
                  <li key={i} style={{ fontSize: 11, color: '#ccc', lineHeight: 1.5 }}>{ev}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function LocationChip({
  loc,
  onJumpToAddress,
}: {
  loc: SignalLocation;
  onJumpToAddress?: (address: number) => void;
}) {
  const isNavigable = loc.address > 0 && !!onJumpToAddress;
  const icon        = LOC_KIND_ICON[loc.kind] ?? '●';

  const chipStyle: React.CSSProperties = {
    display:       'inline-flex',
    alignItems:    'center',
    gap:           4,
    padding:       '2px 7px',
    borderRadius:  4,
    fontSize:      11,
    fontFamily:    'monospace',
    border:        '1px solid',
    cursor:        isNavigable ? 'pointer' : 'default',
    userSelect:    'none',
    background:    isNavigable ? 'rgba(66,165,245,0.10)' : 'rgba(120,120,120,0.08)',
    color:         isNavigable ? '#64b5f6' : '#999',
    borderColor:   isNavigable ? '#64b5f644' : '#55555544',
    transition:    'background 0.12s',
    whiteSpace:    'nowrap',
    maxWidth:      260,
    overflow:      'hidden',
    textOverflow:  'ellipsis',
  };

  return (
    <span
      style={chipStyle}
      title={loc.context ?? loc.label}
      onClick={() => isNavigable && onJumpToAddress!(loc.address)}
    >
      <span style={{ opacity: 0.7 }}>{icon}</span>
      <span style={{ overflow: 'hidden', textOverflow: 'ellipsis' }}>{loc.label}</span>
      {isNavigable && (
        <span style={{ fontSize: 9, opacity: 0.6, flexShrink: 0 }}>→</span>
      )}
    </span>
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
  const priority = step.priority ?? 'medium';
  const color = PRIORITY_COLOR[priority] ?? PRIORITY_COLOR.medium;
  return (
    <div
      className={`verdict-step verdict-workflow-step ${open ? 'verdict-step-open' : ''}`}
      style={{ borderLeftColor: color }}
      onClick={() => {
        onToggle();
        if (step.tab && onNavigate) onNavigate(step.tab);
      }}
    >
      <div className="verdict-step-header">
        <span className="verdict-step-num" style={{ background: color + '33', color }}>
          {index}
        </span>
        <span className="verdict-step-action">{step.action ?? 'Review step'}</span>
        <span className="verdict-step-priority" style={{ color }}>{priority.toUpperCase()}</span>
        <span className="verdict-step-toggle">{open ? '▲' : '▼'}</span>
      </div>
      {open && (
        <div className="verdict-step-detail">
          <p className="verdict-step-rationale">{step.rationale ?? 'Follow this investigation step.'}</p>
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
