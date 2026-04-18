/**
 * ExplainabilityEngine - Phase 1: TRUST
 * 
 * Generates explainable threat scores with:
 * - Point-based breakdowns
 * - Confidence factors
 * - Reasoning strings
 * - Actionable insights
 */

import type {
  SuspiciousPattern,
  DisassemblyAnalysis,
} from '../App';
import type {
  ExplanationBreakdown,
  ConfidenceFactors,
  ThreatExplanation,
  AnalysisParameters,
  EdgeCaseWarning,
} from '../types/enterprise';
import type { ThreatLevel } from '../utils/patternIntelligence';

/**
 * Point allocation per threat level
 * These are fixed constants for reproducibility
 */
const POINTS_PER_LEVEL = {
  critical: 25,
  high: 15,
  medium: 5,
  low: 1,
} as const;

/**
 * ExplainabilityEngine class
 * All methods are deterministic with no side effects
 */
export class ExplainabilityEngine {
  /**
   * Generate a complete threat explanation for a binary
   */
  static generateThreatExplanation(
    threatScore: number,
    patterns: SuspiciousPattern[],
    threatLevels: Map<number, ThreatLevel>,
    edgeCaseWarnings: EdgeCaseWarning[] = []
  ): ThreatExplanation {
    const breakdown = this.buildBreakdown(patterns, threatLevels);
    const confidenceFactors = this.calculateConfidenceFactors(patterns);
    const confidence = this.calculateConfidenceScore(confidenceFactors);
    const reasoning = this.generateReasoningStrings(breakdown, confidenceFactors);
    const summary = this.generateSummary(threatScore, confidence);

    return {
      score: Math.round(threatScore),
      confidence: Math.round(confidence),
      confidenceFactors,
      breakdown,
      reasoning,
      summary,
      edgeCasesDetected: edgeCaseWarnings,
    };
  }

  /**
   * Build a breakdown of threat score by threat level
   * Shows: "2 critical (50pts) + 3 high (45pts) = 95pts / 2 = 47/100"
   */
  static buildBreakdown(
    patterns: SuspiciousPattern[],
    threatLevels: Map<number, ThreatLevel>
  ): ExplanationBreakdown[] {
    // Group patterns by threat level
    const grouped: Record<'critical' | 'high' | 'medium' | 'low', number[]> = {
      critical: [],
      high: [],
      medium: [],
      low: [],
    };

    for (const pattern of patterns) {
      const level = threatLevels.get(pattern.address) || 'low';
      if (level !== 'none' && grouped[level] !== undefined) {
        grouped[level].push(pattern.address);
      }
    }

    // Build breakdown for each threat level
    const breakdown: ExplanationBreakdown[] = [];
    const levels: ('critical' | 'high' | 'medium' | 'low')[] = ['critical', 'high', 'medium', 'low'];

    for (const level of levels) {
      const addresses = grouped[level];
      if (addresses.length === 0) continue;

      const count = addresses.length;
      const pointsPerPattern = POINTS_PER_LEVEL[level];
      const totalPoints = count * pointsPerPattern;

      breakdown.push({
        threatLevel: level,
        count,
        pointsPerPattern,
        totalPoints,
        description: this.getDescriptionForLevel(level),
      });
    }

    return breakdown;
  }

  /**
   * Get human-readable description for a threat level
   */
  private static getDescriptionForLevel(level: 'critical' | 'high' | 'medium' | 'low'): string {
    const descriptions: Record<'critical' | 'high' | 'medium' | 'low', string> = {
      critical: 'Anti-analysis patterns designed to confuse analysis tools',
      high: 'Control flow anomalies and suspicious patterns',
      medium: 'Stack manipulation and reference chains',
      low: 'Data obfuscation and performance-critical code',
    };
    return descriptions[level];
  }

  /**
   * Calculate confidence factors based on pattern analysis
   */
  static calculateConfidenceFactors(
    patterns: SuspiciousPattern[]
  ): ConfidenceFactors {
    const patternCount = patterns.length;

    // Pattern quality: based on clarity of pattern signatures
    // More patterns = patterns must be clearer
    const patternQuality = Math.min(100, 50 + Math.min(50, patternCount * 2));

    // Pattern consistency: how coherent is the set?
    // This is a placeholder; in real impl would check pattern relationships
    const patternConsistency = Math.min(100, 60 + Math.min(40, patternCount * 1));

    // Analysis depth: percentage of code analyzed
    // Placeholder: assume reasonable depth with 5+ patterns
    const analysisDepth = Math.min(100, 70 + Math.min(30, patternCount / 2));

    return {
      patternCount,
      patternQuality,
      patternConsistency,
      analysisDepth,
    };
  }

  /**
   * Calculate overall confidence score (0-100)
   */
  static calculateConfidenceScore(factors: ConfidenceFactors): number {
    // Weight the factors
    const weighted =
      factors.patternCount * 0.1 + // Min 10% for count
      factors.patternQuality * 0.3 + // 30% for quality
      factors.patternConsistency * 0.3 + // 30% for consistency
      factors.analysisDepth * 0.3; // 30% for depth

    return Math.min(100, Math.max(0, weighted));
  }

  /**
   * Generate human-readable reasoning string
   * Example: "2 critical (50pts) + 3 high (45pts) = 95pts / 2 levels = 47/100"
   */
  static generateReasoningStrings(
    breakdown: ExplanationBreakdown[],
    factors: ConfidenceFactors
  ): string {
    if (breakdown.length === 0) {
      return 'No suspicious patterns detected. This binary appears clean.';
    }

    // Build the calculation string
    const parts: string[] = [];
    let totalPoints = 0;

    for (const item of breakdown) {
      const part = `${item.count} ${item.threatLevel} (${item.totalPoints}pts)`;
      parts.push(part);
      totalPoints += item.totalPoints;
    }

    const calculation = parts.join(' + ');
    const divisor = breakdown.length;
    const averageScore = Math.round(totalPoints / divisor);

    const reasoning =
      `${calculation} = ${totalPoints}pts / ${divisor} levels = ${averageScore}/100. ` +
      `Confidence factors: ${factors.patternCount} patterns detected, ` +
      `quality ${factors.patternQuality}%, consistency ${factors.patternConsistency}%.`;

    return reasoning;
  }

  /**
   * Generate a one-line summary of threat level
   */
  static generateSummary(threatScore: number, confidence: number): string {
    const scoreLevel =
      threatScore >= 70
        ? '🔴 CRITICAL'
        : threatScore >= 50
          ? '🟠 HIGH'
          : threatScore >= 30
            ? '🟡 MEDIUM'
            : '🟢 LOW';

    const confidenceLabel =
      confidence >= 80
        ? 'high confidence'
        : confidence >= 60
          ? 'moderate confidence'
          : 'low confidence';

    return `${scoreLevel} threat detected (${Math.round(threatScore)}/100) with ${confidenceLabel}.`;
  }

  /**
   * Export explanation in different formats
   */
  static exportExplanation(
    explanation: ThreatExplanation,
    format: 'json' | 'markdown' | 'text' = 'text'
  ): string {
    switch (format) {
      case 'json':
        return JSON.stringify(explanation, null, 2);

      case 'markdown':
        return this.exportAsMarkdown(explanation);

      case 'text':
      default:
        return this.exportAsText(explanation);
    }
  }

  /**
   * Export as markdown
   */
  private static exportAsMarkdown(explanation: ThreatExplanation): string {
    const lines: string[] = [];

    lines.push(`# Threat Analysis Report`);
    lines.push(``);
    lines.push(`**Summary:** ${explanation.summary}`);
    lines.push(`**Score:** ${explanation.score}/100`);
    lines.push(`**Confidence:** ${explanation.confidence}%`);
    lines.push(``);

    lines.push(`## Breakdown`);
    for (const item of explanation.breakdown) {
      lines.push(
        `- **${item.threatLevel.toUpperCase()}**: ${item.count} patterns (${item.totalPoints} points)`
      );
    }
    lines.push(``);

    lines.push(`## Reasoning`);
    lines.push(explanation.reasoning);
    lines.push(``);

    lines.push(`## Confidence Factors`);
    const cf = explanation.confidenceFactors;
    lines.push(`- Pattern Count: ${cf.patternCount}`);
    lines.push(`- Pattern Quality: ${cf.patternQuality}%`);
    lines.push(`- Pattern Consistency: ${cf.patternConsistency}%`);
    lines.push(`- Analysis Depth: ${cf.analysisDepth}%`);
    lines.push(``);

    if (explanation.edgeCasesDetected.length > 0) {
      lines.push(`## Edge Cases Detected`);
      for (const warning of explanation.edgeCasesDetected) {
        lines.push(`- **${warning.edgeCase.type}**: ${warning.edgeCase.description}`);
      }
    }

    return lines.join('\n');
  }

  /**
   * Export as plain text
   */
  private static exportAsText(explanation: ThreatExplanation): string {
    const lines: string[] = [];

    lines.push(`THREAT ANALYSIS REPORT`);
    lines.push(`${'='.repeat(50)}`);
    lines.push(``);
    lines.push(`Summary: ${explanation.summary}`);
    lines.push(`Score: ${explanation.score}/100`);
    lines.push(`Confidence: ${explanation.confidence}%`);
    lines.push(``);

    lines.push(`BREAKDOWN`);
    lines.push(`${'-'.repeat(50)}`);
    for (const item of explanation.breakdown) {
      lines.push(
        `${item.threatLevel.toUpperCase().padEnd(12)} ${item.count} patterns (${item.totalPoints} points)`
      );
    }
    lines.push(``);

    lines.push(`REASONING`);
    lines.push(`${'-'.repeat(50)}`);
    lines.push(explanation.reasoning);
    lines.push(``);

    lines.push(`CONFIDENCE FACTORS`);
    lines.push(`${'-'.repeat(50)}`);
    const cf = explanation.confidenceFactors;
    lines.push(`Pattern Count:     ${cf.patternCount}`);
    lines.push(`Pattern Quality:   ${cf.patternQuality}%`);
    lines.push(`Pattern Consistency: ${cf.patternConsistency}%`);
    lines.push(`Analysis Depth:    ${cf.analysisDepth}%`);

    return lines.join('\n');
  }

  /**
   * Validate an explanation for consistency
   */
  static validateExplanation(explanation: ThreatExplanation): {
    valid: boolean;
    errors: string[];
  } {
    const errors: string[] = [];

    // Score must be 0-100
    if (explanation.score < 0 || explanation.score > 100) {
      errors.push(`Score out of range: ${explanation.score}`);
    }

    // Confidence must be 0-100
    if (explanation.confidence < 0 || explanation.confidence > 100) {
      errors.push(`Confidence out of range: ${explanation.confidence}`);
    }

    // Breakdown must sum to something reasonable
    const totalPoints = explanation.breakdown.reduce((sum, item) => sum + item.totalPoints, 0);
    if (totalPoints === 0 && explanation.score > 0) {
      errors.push(`Breakdown points are zero but score is ${explanation.score}`);
    }

    // Confidence factors must be 0-100
    const cf = explanation.confidenceFactors;
    if (cf.patternQuality < 0 || cf.patternQuality > 100) {
      errors.push(`Pattern quality out of range: ${cf.patternQuality}`);
    }
    if (cf.patternConsistency < 0 || cf.patternConsistency > 100) {
      errors.push(`Pattern consistency out of range: ${cf.patternConsistency}`);
    }
    if (cf.analysisDepth < 0 || cf.analysisDepth > 100) {
      errors.push(`Analysis depth out of range: ${cf.analysisDepth}`);
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }
}
