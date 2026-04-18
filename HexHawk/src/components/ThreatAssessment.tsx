import React, { useState } from 'react';
import type { DisassemblyAnalysis } from '../App';
import {
  calculateDetailedThreatScore,
  generateBinaryProfile,
  calculateThreatScoreWithExplanation,
} from '../utils/patternIntelligence';

interface ThreatAssessmentProps {
  analysis: DisassemblyAnalysis;
}

const ThreatAssessment = React.memo(function ThreatAssessment({
  analysis,
}: ThreatAssessmentProps) {
  const [showDetailed, setShowDetailed] = useState(false);
  const [showExplanation, setShowExplanation] = useState(false);

  // Get Phase 7 breakdown
  const scoreBreakdown = calculateDetailedThreatScore(analysis);
  const profile = generateBinaryProfile(analysis);

  // NEW Phase 1: Get detailed explanation with confidence factors
  const threatExplanation = calculateThreatScoreWithExplanation(analysis);

  const getThreatColor = (score: number): string => {
    if (score >= 70) return '#F44336'; // red - critical
    if (score >= 50) return '#FF9800'; // orange - high
    if (score >= 30) return '#FFC107'; // amber - medium
    if (score >= 10) return '#2196F3'; // blue - low
    return '#4CAF50'; // green - none
  };

  const getThreatLabel = (score: number): string => {
    if (score >= 70) return 'CRITICAL';
    if (score >= 50) return 'HIGH';
    if (score >= 30) return 'MEDIUM';
    if (score >= 10) return 'LOW';
    return 'CLEAN';
  };

  const threatColor = getThreatColor(scoreBreakdown.overall);
  const threatLabel = getThreatLabel(scoreBreakdown.overall);


  return (
    <div className="threat-assessment">
      {/* Header with Score */}
      <div className="threat-header">
        <div className="threat-score-display">
          <div
            className="threat-score-circle"
            style={{
              borderColor: threatColor,
              color: threatColor,
            }}
          >
            {scoreBreakdown.overall}
          </div>
          <div className="threat-score-label">
            <div className="score-value">{threatLabel}</div>
            <div className="score-subtext">
              Threat Level (
              <span style={{ fontSize: '11px', opacity: 0.7 }}>
                {scoreBreakdown.confidence}% confidence
              </span>
              )
            </div>
          </div>
        </div>
      </div>

      {/* Breakdown */}
      <div className="threat-breakdown">
        <div className="threat-row critical">
          <span className="threat-label">🔴 Critical</span>
          <span className="threat-count">{scoreBreakdown.critical}</span>
        </div>
        {scoreBreakdown.critical > 0 && (
          <div className="threat-indicator critical-indicator" />
        )}

        <div className="threat-row high">
          <span className="threat-label">🟠 High Risk</span>
          <span className="threat-count">{scoreBreakdown.high}</span>
        </div>
        {scoreBreakdown.high > 0 && <div className="threat-indicator high-indicator" />}

        <div className="threat-row medium">
          <span className="threat-label">🟡 Medium</span>
          <span className="threat-count">{scoreBreakdown.medium}</span>
        </div>

        <div className="threat-row low">
          <span className="threat-label">🟢 Low Risk</span>
          <span className="threat-count">{scoreBreakdown.low}</span>
        </div>
      </div>

      {/* Phase 1: Confidence Factors */}
      <div className="confidence-factors">
        <div className="factors-title">Confidence Factors</div>
        <div className="factor-row">
          <span className="factor-label">Pattern Count:</span>
          <span className="factor-value">{threatExplanation.confidenceFactors.patternCount}</span>
        </div>
        <div className="factor-row">
          <span className="factor-label">Quality:</span>
          <span className="factor-value">
            {threatExplanation.confidenceFactors.patternQuality}%
          </span>
        </div>
        <div className="factor-row">
          <span className="factor-label">Consistency:</span>
          <span className="factor-value">
            {threatExplanation.confidenceFactors.patternConsistency}%
          </span>
        </div>
        <div className="factor-row">
          <span className="factor-label">Analysis Depth:</span>
          <span className="factor-value">
            {threatExplanation.confidenceFactors.analysisDepth}%
          </span>
        </div>
      </div>

      {/* Reasoning (Explainability) */}
      {scoreBreakdown.reasoning.length > 0 && (
        <div className="threat-reasoning">
          <div className="reasoning-title">Score Breakdown</div>
          <div className="reasoning-items">
            {scoreBreakdown.reasoning.map((reason, i) => (
              <div key={i} className="reasoning-item">
                {reason}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Edge Case Warnings (Phase 1) */}
      {threatExplanation.edgeCasesDetected.length > 0 && (
        <div className="edge-case-warnings">
          <div className="warning-title">⚠️ Edge Cases Detected</div>
          {threatExplanation.edgeCasesDetected.map((warning, i) => (
            <div key={i} className={`edge-case-warning edge-case-${warning.edgeCase.type}`}>
              <div className="case-type">{warning.edgeCase.type.replace(/-/g, ' ')}</div>
              <div className="case-description">{warning.edgeCase.description}</div>
              <div className="case-recommendation">→ {warning.edgeCase.recommendation}</div>
            </div>
          ))}
        </div>
      )}

      {/* Likely Behaviors */}
      {profile.likelyBehaviors.length > 0 &&
        !profile.likelyBehaviors.includes('normal') && (
          <div className="threat-behaviors">
            <div className="behaviors-title">Detected Behaviors</div>
            <div className="behaviors-list">
              {profile.likelyBehaviors.map((behavior) => (
                <div key={behavior} className="behavior-tag">
                  {behavior
                    .split('-')
                    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
                    .join(' ')}
                </div>
              ))}
            </div>
          </div>
        )}

      {/* Phase 1: Explanation Toggle */}
      <button
        className="explanation-toggle"
        onClick={() => setShowExplanation(!showExplanation)}
        title="Show detailed threat analysis explanation"
      >
        {showExplanation ? '▼' : '▶'} Detailed Explanation
      </button>
      {showExplanation && (
        <div className="explanation-detail">
          <div className="explanation-text">{threatExplanation.reasoning}</div>
          <div className="explanation-summary">{threatExplanation.summary}</div>
        </div>
      )}

      {/* Binary Summary */}
      <div className="threat-summary">
        <button
          className="summary-toggle"
          onClick={() => setShowDetailed(!showDetailed)}
          title="Toggle detailed summary"
        >
          {showDetailed ? '▼' : '▶'} Binary Summary
        </button>
        {showDetailed && (
          <div className="summary-text">
            <p>{profile.summary}</p>
            <div className="summary-stats">
              <div className="stat">
                <span className="stat-label">Obfuscation:</span>
                <span className="stat-value">
                  {profile.obfuscationLevel.charAt(0).toUpperCase() +
                    profile.obfuscationLevel.slice(1)}
                </span>
              </div>
              {profile.packedLikelihood > 0 && (
                <div className="stat">
                  <span className="stat-label">Packed Likelihood:</span>
                  <span className="stat-value">{profile.packedLikelihood}%</span>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
});

export default ThreatAssessment;
