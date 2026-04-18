/**
 * EdgeCaseEngine - Phase 1: TRUST
 * 
 * Detects and handles edge cases in binary analysis:
 * - Benign-complex: Many patterns but actually clean (e.g., compiler optimizations)
 * - Packed-clean: Packed binary that scans clean (e.g., UPX with legitimate content)
 * - Mixed-signals: Conflicting threat signals (e.g., anti-analysis but also benign patterns)
 */

import type {
  SuspiciousPattern,
  DisassemblyAnalysis,
} from '../App';
import type {
  EdgeCaseDetection,
  EdgeCaseAnalysisResult,
} from '../types/enterprise';
import type { ThreatLevel, PatternCategory } from '../utils/patternIntelligence';

/**
 * EdgeCaseEngine class
 * Detects special cases that need special handling
 */
export class EdgeCaseEngine {
  /**
   * Detect if a binary has edge cases
   */
  static detectEdgeCases(
    patterns: SuspiciousPattern[],
    threatLevels: Map<number, ThreatLevel>,
    threatScore: number,
    analysis: DisassemblyAnalysis
  ): EdgeCaseAnalysisResult {
    const detectedCases: EdgeCaseDetection[] = [];
    let scoreAdjustment = 0;

    // Check each edge case type
    if (this.isBenignComplex(patterns, threatScore)) {
      const detection = {
        type: 'benign-complex' as const,
        severity: 'low' as const,
        confidence: 75,
        description:
          'Binary has many suspicious patterns but low overall threat score. ' +
          'Often caused by compiler optimizations, standard library code, or legitimate obfuscation.',
        recommendation:
          'Verify with static and dynamic analysis. Check if patterns are related to known libraries or compiler behavior.',
      };
      detectedCases.push(detection);
      // Reduce confidence in threat score slightly
      scoreAdjustment = Math.max(-5, scoreAdjustment - 5);
    }

    if (this.isPackedButClean(patterns, threatScore, analysis)) {
      const detection = {
        type: 'packed-clean' as const,
        severity: 'medium' as const,
        confidence: 85,
        description:
          'Binary appears packed but scans as clean. ' +
          'May be legitimately packed executable (e.g., UPX) or intentional protection.',
        recommendation:
          'Unpack the binary using appropriate tools and re-analyze. ' +
          'Check digital signatures for legitimacy.',
      };
      detectedCases.push(detection);
      // Slightly increase skepticism
      scoreAdjustment = Math.max(-3, scoreAdjustment - 3);
    }

    if (this.isMixedSignals(patterns, threatLevels)) {
      const detection = {
        type: 'mixed-signals' as const,
        severity: 'high' as const,
        confidence: 80,
        description:
          'Binary has conflicting threat signals (e.g., anti-analysis patterns alongside benign patterns). ' +
          'May indicate sophisticated packing, polymorphism, or intentional obfuscation.',
        recommendation:
          'Manual review required. Use dynamic analysis to understand actual behavior. ' +
          'Treat with higher suspicion until verified.',
      };
      detectedCases.push(detection);
      // Increase threat score slightly for mixed signals
      scoreAdjustment = Math.max(5, scoreAdjustment + 5);
    }

    const warnings = detectedCases.map((ec) => ({
      edgeCase: ec,
      impacts: this.getImpacts(ec.type),
      adjustedScore: threatScore + scoreAdjustment,
    }));

    return {
      detectedCases,
      scoreAdjustment,
      warnings,
    };
  }

  /**
   * Detect benign-complex edge case
   * Many patterns but low threat score suggests compiler artifacts or standard library
   */
  static isBenignComplex(patterns: SuspiciousPattern[], threatScore: number): boolean {
    // Heuristic: High pattern count but low threat = benign complex
    const PATTERN_THRESHOLD = 15;
    const THREAT_THRESHOLD = 25;

    if (
      patterns.length >= PATTERN_THRESHOLD &&
      threatScore < THREAT_THRESHOLD
    ) {
      // Additional check: are most patterns low-threat?
      const lowThreatCount = patterns.filter(
        (p) => !p.description?.includes('anti') && !p.description?.includes('critical')
      ).length;

      return lowThreatCount > patterns.length * 0.7; // 70%+ are low threat
    }

    return false;
  }

  /**
   * Detect packed-clean edge case
   * Binary has high entropy/size variance but low threat score
   */
  static isPackedButClean(
    patterns: SuspiciousPattern[],
    threatScore: number,
    analysis: DisassemblyAnalysis
  ): boolean {
    // Check for packing indicators
    const packedIndicators =
      patterns.some((p) => p.description?.includes('packed') || p.description?.includes('entropy'));

    // But threat score is low
    const cleanScore = threatScore < 30;

    return packedIndicators && cleanScore;
  }

  /**
   * Detect mixed-signals edge case
   * Binary has both critical and benign patterns
   */
  static isMixedSignals(
    patterns: SuspiciousPattern[],
    threatLevels: Map<number, ThreatLevel>
  ): boolean {
    // Check for both critical AND benign patterns
    const hasCritical = Array.from(threatLevels.values()).includes('critical');
    const hasLow = Array.from(threatLevels.values()).includes('low');
    const hasMedium = Array.from(threatLevels.values()).includes('medium');

    // Mixed signals: critical + benign, or critical + medium + benign
    const hasConflict = hasCritical && (hasLow || (hasMedium && hasLow));

    // Also check for anti-analysis + standard patterns
    const hasAntiAnalysis = patterns.some(
      (p) => p.description?.includes('anti') || p.description?.includes('vm')
    );
    const hasStandard = patterns.some(
      (p) => p.description?.includes('standard') || p.description?.includes('optimize')
    );

    return hasConflict || (hasAntiAnalysis && hasStandard);
  }

  /**
   * Get what aspects of analysis this edge case impacts
   */
  private static getImpacts(type: string): string[] {
    switch (type) {
      case 'benign-complex':
        return [
          'threat-score',
          'pattern-detection',
          'false-positive-rate',
        ];

      case 'packed-clean':
        return [
          'threat-score',
          'behavior-detection',
          'full-analysis-coverage',
        ];

      case 'mixed-signals':
        return [
          'confidence-score',
          'threat-assessment',
          'recommendation-generation',
        ];

      default:
        return ['unknown'];
    }
  }

  /**
   * Adjust threat score based on edge cases
   */
  static adjustThreatScoreForEdgeCases(
    threatScore: number,
    edgeCaseResult: EdgeCaseAnalysisResult
  ): number {
    const adjusted = threatScore + edgeCaseResult.scoreAdjustment;
    return Math.max(0, Math.min(100, adjusted));
  }

  /**
   * Generate explanation of edge cases for user
   */
  static generateEdgeCaseExplanation(
    detectedCases: EdgeCaseDetection[]
  ): string {
    if (detectedCases.length === 0) {
      return '';
    }

    const lines: string[] = [];
    lines.push('⚠️ EDGE CASES DETECTED:');

    for (const edgeCase of detectedCases) {
      lines.push(`\n  ${edgeCase.type.toUpperCase()}`);
      lines.push(`  Confidence: ${edgeCase.confidence}%`);
      lines.push(`  Severity: ${edgeCase.severity.toUpperCase()}`);
      lines.push(`  ${edgeCase.description}`);
      lines.push(`  → ${edgeCase.recommendation}`);
    }

    return lines.join('\n');
  }

  /**
   * Check if analysis is reliable given edge cases
   */
  static isAnalysisReliable(
    edgeCases: EdgeCaseDetection[],
    threatScore: number
  ): {
    reliable: boolean;
    reliability: number; // 0-100
    warnings: string[];
  } {
    const warnings: string[] = [];
    let reliabilityPenalty = 0;

    for (const edgeCase of edgeCases) {
      switch (edgeCase.type) {
        case 'benign-complex':
          warnings.push('High pattern count with low threat score. May be false positives.');
          reliabilityPenalty += 10;
          break;

        case 'packed-clean':
          warnings.push('Binary is packed. Full analysis may not be possible without unpacking.');
          reliabilityPenalty += 20;
          break;

        case 'mixed-signals':
          warnings.push('Conflicting threat signals detected. Manual review recommended.');
          reliabilityPenalty += 15;
          break;
      }
    }

    const reliability = Math.max(0, 100 - reliabilityPenalty);
    const reliable = reliability >= 75;

    return {
      reliable,
      reliability,
      warnings,
    };
  }

  /**
   * Recommend next steps based on edge cases
   */
  static recommendNextSteps(
    detectedCases: EdgeCaseDetection[],
    threatScore: number
  ): string[] {
    const steps: string[] = [];

    for (const edgeCase of detectedCases) {
      switch (edgeCase.type) {
        case 'benign-complex':
          steps.push('Check if binary links against standard C runtime libraries');
          steps.push('Analyze compiler optimization settings (e.g., -O2, -O3)');
          steps.push('Compare against known clean binaries in same category');
          break;

        case 'packed-clean':
          steps.push('Attempt to unpack using common packing tools (UPX, ASPack, etc)');
          steps.push('Verify digital signatures and certificates');
          steps.push('Check for legitimate code signing');
          break;

        case 'mixed-signals':
          steps.push('Run dynamic analysis to observe actual runtime behavior');
          steps.push('Check for polymorphic or encrypted code');
          steps.push('Perform manual code review of critical sections');
          break;
      }
    }

    // Based on threat score
    if (threatScore >= 70) {
      steps.push('⚠️ HIGH THREAT: Isolate and quarantine until verified');
    }

    if (threatScore >= 50) {
      steps.push('🟠 MEDIUM THREAT: Further investigation required before execution');
    }

    // Remove duplicates while preserving order
    return [...new Set(steps)];
  }

  /**
   * Score confidence based on edge cases
   * Edge cases reduce our confidence in the analysis
   */
  static adjustConfidenceForEdgeCases(
    baseConfidence: number,
    edgeCases: EdgeCaseDetection[]
  ): number {
    let adjusted = baseConfidence;

    for (const edgeCase of edgeCases) {
      // Each edge case reduces confidence
      const penalty =
        edgeCase.severity === 'high'
          ? 15
          : edgeCase.severity === 'medium'
            ? 10
            : 5;

      adjusted -= penalty;
    }

    return Math.max(0, Math.min(100, adjusted));
  }

  /**
   * Validate edge case detection
   */
  static validateEdgeCaseDetection(
    detectedCases: EdgeCaseDetection[]
  ): {
    valid: boolean;
    errors: string[];
  } {
    const errors: string[] = [];

    for (const edgeCase of detectedCases) {
      if (edgeCase.confidence < 0 || edgeCase.confidence > 100) {
        errors.push(`Invalid confidence for ${edgeCase.type}: ${edgeCase.confidence}`);
      }

      if (!['low', 'medium', 'high'].includes(edgeCase.severity)) {
        errors.push(`Invalid severity for ${edgeCase.type}: ${edgeCase.severity}`);
      }

      if (!edgeCase.description || edgeCase.description.length === 0) {
        errors.push(`Missing description for ${edgeCase.type}`);
      }

      if (!edgeCase.recommendation || edgeCase.recommendation.length === 0) {
        errors.push(`Missing recommendation for ${edgeCase.type}`);
      }
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }
}
