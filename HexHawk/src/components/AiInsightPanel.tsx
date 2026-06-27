import React from 'react';
import type { AiObservation, AiObservationSource } from '../types/aiObservation';

interface AiInsightPanelProps {
  observations: AiObservation[];
  onObservationChange?: (observation: AiObservation) => void;
  onAcceptAsNote?: (observation: AiObservation) => void;
  onDismiss?: (observation: AiObservation) => void;
  onRequestSummary?: () => void;
}

const SOURCE_LABELS: Record<AiObservationSource, string> = {
  'aetherframe-static': 'AETHERFRAME static pattern',
  'aetherframe-llm': 'AETHERFRAME LLM',
  'nexus-llm': 'NEXUS LLM',
  'talon-llm-pass': 'TALON LLM pass',
  'user-accepted': 'Analyst accepted note',
};

const KIND_LABELS: Record<AiObservation['kind'], string> = {
  'likely-purpose': 'Likely purpose',
  'suspicious-pattern': 'Suspicious pattern',
  'technique-hint': 'Technique hint',
  'decompiler-note': 'Decompiler note',
  'coverage-gap': 'Coverage gap',
  'analyst-suggestion': 'Analyst suggestion',
};

function isLlmSource(source: AiObservationSource): boolean {
  return source === 'aetherframe-llm' || source === 'nexus-llm' || source === 'talon-llm-pass';
}

function cardClassName(observation: AiObservation): string {
  return [
    'ai-observation-card',
    isLlmSource(observation.source) ? 'ai-observation-card--llm' : 'ai-observation-card--static',
  ].join(' ');
}

function formatAddress(address?: number): string | null {
  if (typeof address !== 'number') return null;
  return `0x${address.toString(16).toUpperCase()}`;
}

export function AiInsightPanel({
  observations,
  onObservationChange,
  onAcceptAsNote,
  onDismiss,
  onRequestSummary,
}: AiInsightPanelProps) {
  const visibleObservations = observations.filter(observation => !observation.accepted && !observation.dismissed);

  function accept(observation: AiObservation) {
    const next: AiObservation = {
      ...observation,
      accepted: true,
      dismissed: false,
      gyre_is_sole_verdict_authority: true,
      advisory_only: true,
    };
    onObservationChange?.(next);
    onAcceptAsNote?.(next);
  }

  function dismiss(observation: AiObservation) {
    const next: AiObservation = {
      ...observation,
      accepted: false,
      dismissed: true,
      gyre_is_sole_verdict_authority: true,
      advisory_only: true,
    };
    onObservationChange?.(next);
    onDismiss?.(next);
  }

  return (
    <section className="panel ai-insight-panel" data-testid="ai-insight-panel" aria-labelledby="ai-insight-heading">
      <header className="ai-insight-header">
        <div>
          <h2 id="ai-insight-heading">AI Observations</h2>
          <p className="ai-insight-subtitle">AETHERFRAME — advisory</p>
        </div>
        <span className="ai-insight-authority-badge">Not GYRE</span>
      </header>

      <div className="ai-insight-explainer" role="note">
        <strong>What this panel shows</strong>
        <p>
          AI-generated interpretations of static analysis. These are suggestions, not facts.
          GYRE remains the sole verdict authority.
        </p>
      </div>

      {visibleObservations.length === 0 ? (
        <div className="ai-insight-empty" data-testid="ai-insight-empty">
          Run analysis to generate AI observations.
        </div>
      ) : (
        <div className="ai-observation-list" aria-label="AI observation cards">
          {visibleObservations.map(observation => {
            const address = formatAddress(observation.address);
            const needsNotVerdict = observation.kind === 'suspicious-pattern' || observation.kind === 'technique-hint';
            return (
              <article
                key={observation.id}
                className={cardClassName(observation)}
                data-testid={`ai-observation-${observation.id}`}
                data-source={observation.source}
              >
                <div className="ai-observation-topline">
                  <span className="ai-observation-kind">{KIND_LABELS[observation.kind]}</span>
                  <span className="ai-observation-source">Source: {SOURCE_LABELS[observation.source]}</span>
                </div>
                <h3>{observation.title}</h3>
                <p>{observation.body}</p>
                <dl className="ai-observation-meta">
                  <div>
                    <dt>Evidence basis</dt>
                    <dd>{observation.evidenceBasis}</dd>
                  </div>
                  <div>
                    <dt>Confidence</dt>
                    <dd>{observation.analysisConfidence}</dd>
                  </div>
                  {observation.functionId && (
                    <div>
                      <dt>Function</dt>
                      <dd>{observation.functionId}</dd>
                    </div>
                  )}
                  {address && (
                    <div>
                      <dt>Address</dt>
                      <dd>{address}</dd>
                    </div>
                  )}
                </dl>
                <p className="ai-observation-authority">
                  Advisory only. GYRE remains the sole verdict authority.
                  {needsNotVerdict ? ' Not a verdict. GYRE decides verdicts.' : ''}
                </p>
                <div className="ai-observation-actions">
                  <button type="button" onClick={() => accept(observation)}>Accept as note</button>
                  <button type="button" onClick={() => dismiss(observation)}>Dismiss</button>
                </div>
              </article>
            );
          })}
        </div>
      )}

      <footer className="ai-insight-footer">
        <button type="button" onClick={onRequestSummary}>Request AI summary of loaded binary</button>
      </footer>
    </section>
  );
}

export default AiInsightPanel;
