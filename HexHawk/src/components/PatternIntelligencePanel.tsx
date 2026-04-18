import React from 'react';
import type { DisassemblyAnalysis } from '../App';
import {
  buildPatternIntelligence,
  PatternIntelligenceData,
} from '../utils/patternIntelligence';

interface PatternIntelligencePanelProps {
  analysis: DisassemblyAnalysis | null;
  selectedAddress: number;
  disassembly: Array<{ mnemonic: string; operands: string }>;
  onNavigate: (address: number) => void;
}

const PatternIntelligencePanel = React.memo(function PatternIntelligencePanel({
  analysis,
  selectedAddress,
  disassembly,
  onNavigate,
}: PatternIntelligencePanelProps) {
  // Find pattern at selected address
  const pattern = analysis?.suspiciousPatterns.find(
    (p) => p.address === selectedAddress
  );

  if (!pattern || !analysis) {
    return (
      <div className="pattern-intelligence-panel">
        <div className="pi-empty">
          <div className="pi-empty-icon">📊</div>
          <div className="pi-empty-text">Select an instruction to see pattern analysis</div>
        </div>
      </div>
    );
  }

  const intelligence = buildPatternIntelligence(pattern, analysis, disassembly);

  const getThreatIcon = (threatLevel: string): string => {
    switch (threatLevel) {
      case 'critical':
        return '🔴';
      case 'high':
        return '🟠';
      case 'medium':
        return '🟡';
      case 'low':
        return '🟢';
      default:
        return '⚪';
    }
  };

  const getThreatColor = (threatLevel: string): string => {
    switch (threatLevel) {
      case 'critical':
        return '#F44336';
      case 'high':
        return '#FF9800';
      case 'medium':
        return '#FFC107';
      case 'low':
        return '#2196F3';
      default:
        return '#9E9E9E';
    }
  };

  return (
    <div className="pattern-intelligence-panel">
      <div className="pi-header">
        <div className="pi-title">
          <span className="pi-threat-icon">
            {getThreatIcon(intelligence.interpretation.threatLevel)}
          </span>
          <span className="pi-name">{intelligence.interpretation.name}</span>
        </div>
        <div
          className="pi-threat-badge"
          style={{
            backgroundColor: getThreatColor(intelligence.interpretation.threatLevel),
          }}
        >
          {intelligence.interpretation.threatLevel.toUpperCase()}
        </div>
      </div>

      <div className="pi-section">
        <div className="pi-section-header">What Is This?</div>
        <div className="pi-description">{intelligence.interpretation.description}</div>
      </div>

      <div className="pi-section">
        <div className="pi-section-header">Why It Matters</div>
        <div className="pi-why-matters">{intelligence.interpretation.whyItMatters}</div>
      </div>

      {intelligence.similarPatternCount > 0 && (
        <div className="pi-section">
          <div className="pi-section-header">Frequency</div>
          <div className="pi-frequency">
            Found{' '}
            <strong>
              {intelligence.similarPatternCount} similar pattern
              {intelligence.similarPatternCount > 1 ? 's' : ''}
            </strong>{' '}
            in this binary
            <button
              className="pi-action-btn"
              onClick={() => {
                // Could trigger showing all similar patterns
              }}
            >
              Show All
            </button>
          </div>
        </div>
      )}

      {intelligence.chainedWith.length > 0 && (
        <div className="pi-section">
          <div className="pi-section-header">Related Patterns</div>
          <div className="pi-chained">
            <div className="pi-chained-count">
              Chained with {intelligence.chainedWith.length} other pattern
              {intelligence.chainedWith.length > 1 ? 's' : ''}
            </div>
            <div className="pi-chained-addresses">
              {intelligence.chainedWith.map((addr) => (
                <button
                  key={addr}
                  className="pi-addr-btn"
                  onClick={() => onNavigate(addr)}
                >
                  0x{addr.toString(16).toUpperCase()}
                </button>
              ))}
            </div>
          </div>
        </div>
      )}

      <div className="pi-section">
        <div className="pi-section-header">Likely Next Steps</div>
        <div className="pi-insights">
          {intelligence.interpretation.actionableInsights.map(
            (insight, idx) => (
              <div key={idx} className="pi-insight">
                <span className="insight-bullet">→</span>
                <span className="insight-text">{insight}</span>
              </div>
            )
          )}
        </div>
      </div>

      <div className="pi-footer">
        <div className="pi-confidence">
          <span className="confidence-label">Analysis Confidence:</span>
          <span className="confidence-value">
            {intelligence.interpretation.confidence}%
          </span>
        </div>
      </div>
    </div>
  );
});

export default PatternIntelligencePanel;
