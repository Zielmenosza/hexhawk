/**
 * DeterminismEngine - Phase 1: TRUST
 * 
 * Ensures all analysis results are reproducible:
 * - Fixed thresholds (no randomness)
 * - Sorted outputs (no ordering variance)
 * - Deterministic behavior detection
 * - Reproducible threat scoring
 */

import type {
  SuspiciousPattern,
  DisassemblyAnalysis,
} from '../App';
import type {
  NormalizedPattern,
  BehaviorDetectionResult,
  DeterminismResult,
  AnalysisParameters,
} from '../types/enterprise';
import type { ThreatLevel } from '../utils/patternIntelligence';

/**
 * Fixed thresholds for deterministic behavior detection
 * THESE MUST NOT CHANGE - they define reproducibility
 */
const DETERMINISTIC_THRESHOLDS = {
  // Proximity: patterns within N bytes are considered related
  PATTERN_PROXIMITY_BYTES: 512,

  // Anti-analysis: if we see N+ anti-analysis patterns, binary is likely anti-analysis
  ANTI_ANALYSIS_THRESHOLD: 2,

  // Packing: entropy threshold for packed detection
  PACKED_ENTROPY_THRESHOLD: 7.5,

  // Obfuscation: pattern count threshold
  OBFUSCATION_PATTERN_THRESHOLD: 5,

  // Control flow: unusual jump patterns threshold
  CONTROL_FLOW_ANOMALY_THRESHOLD: 3,

  // Stack manipulation: stack operations threshold
  STACK_MANIPULATION_THRESHOLD: 4,

  // Reference chain: call patterns threshold
  REFERENCE_CHAIN_THRESHOLD: 6,

  // Performance critical: optimization pattern threshold
  PERFORMANCE_CRITICAL_THRESHOLD: 8,
} as const;

/**
 * DeterminismEngine class
 * All methods are pure functions with no side effects
 */
export class DeterminismEngine {
  /**
   * Get analysis parameters that were used
   * Used for reproducibility tracking
   */
  static getAnalysisParameters(): AnalysisParameters {
    return {
      thresholdPatternProximity: DETERMINISTIC_THRESHOLDS.PATTERN_PROXIMITY_BYTES,
      thresholdSimilarityScore: 0.7,
      thresholdAntiAnalysisCount: DETERMINISTIC_THRESHOLDS.ANTI_ANALYSIS_THRESHOLD,
      thresholdPackedLikelihood: DETERMINISTIC_THRESHOLDS.PACKED_ENTROPY_THRESHOLD,
      versionAnalysisEngine: '1.0.0',
    };
  }

  /**
   * Normalize suspicious patterns for deterministic comparison
   * Sorting ensures same patterns always in same order
   */
  static normalizeSuspiciousPatterns(
    patterns: SuspiciousPattern[]
  ): NormalizedPattern[] {
    // First, convert to normalized format
    const normalized = patterns.map((p) => ({
      address: p.address,
      type: p.description || 'unknown',
      normalized: true,
      originalValues: {
        description: p.description,
      },
    }));

    // CRITICAL: Sort by address first, then by type
    // This ensures deterministic ordering regardless of input order
    normalized.sort((a, b) => {
      if (a.address !== b.address) {
        return a.address - b.address;
      }
      return a.type.localeCompare(b.type);
    });

    return normalized;
  }

  /**
   * Detect behaviors deterministically (no randomness)
   */
  static detectBehaviorsDeterministic(
    patterns: SuspiciousPattern[],
    threatLevels: Map<number, ThreatLevel>
  ): BehaviorDetectionResult {
    const behaviors: string[] = [];
    const normalized = this.normalizeSuspiciousPatterns(patterns);

    // Count patterns by threat level
    const levelCounts: Record<'critical' | 'high' | 'medium' | 'low', number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
    };

    for (const pattern of patterns) {
      const level = threatLevels.get(pattern.address) || 'low';
      if (level !== 'none' && levelCounts[level] !== undefined) {
        levelCounts[level]++;
      }
    }

    // DETERMINISTIC: These thresholds are fixed
    if (levelCounts.critical > 0) {
      behaviors.push('Critical Threat Detected');
    }

    if (levelCounts.high >= DETERMINISTIC_THRESHOLDS.ANTI_ANALYSIS_THRESHOLD) {
      behaviors.push('Anti-Analysis Patterns');
    }

    if (levelCounts.medium >= DETERMINISTIC_THRESHOLDS.CONTROL_FLOW_ANOMALY_THRESHOLD) {
      behaviors.push('Control Flow Anomalies');
    }

    if (levelCounts.low >= DETERMINISTIC_THRESHOLDS.OBFUSCATION_PATTERN_THRESHOLD) {
      behaviors.push('Obfuscation Detected');
    }

    if (patterns.length >= DETERMINISTIC_THRESHOLDS.PERFORMANCE_CRITICAL_THRESHOLD) {
      behaviors.push('Performance Optimization');
    }

    // Sort behaviors alphabetically for deterministic output
    behaviors.sort();

    const confidence = this.calculateDeterminismConfidence(patterns.length);

    return {
      behaviors,
      detectionMethod: 'deterministic',
      confidence,
    };
  }

  /**
   * Calculate threat score deterministically
   */
  static calculateThreatScoreDeterministic(
    patterns: SuspiciousPattern[],
    threatLevels: Map<number, ThreatLevel>
  ): number {
    if (patterns.length === 0) {
      return 0;
    }

    // DETERMINISTIC: Fixed point allocation
    const POINTS: Record<'critical' | 'high' | 'medium' | 'low', number> = {
      critical: 25,
      high: 15,
      medium: 5,
      low: 1,
    };

    let totalPoints = 0;
    const levelCounts: Record<'critical' | 'high' | 'medium' | 'low', number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
    };

    for (const pattern of patterns) {
      const level = threatLevels.get(pattern.address) || 'low';
      if (level !== 'none' && levelCounts[level] !== undefined) {
        levelCounts[level]++;
        totalPoints += POINTS[level];
      }
    }

    // Normalize to 0-100 scale
    // Maximum score: if all patterns were critical
    const maxPossibleScore = patterns.length * POINTS.critical;
    const normalizedScore = (totalPoints / maxPossibleScore) * 100;

    // Cap at 100, floor at 0
    return Math.max(0, Math.min(100, Math.round(normalizedScore)));
  }

  /**
   * Check if this binary can be reproducibly analyzed
   */
  static canReproduceAnalysis(
    patterns: SuspiciousPattern[],
    threatLevels: Map<number, ThreatLevel>
  ): DeterminismResult {
    const normalized = this.normalizeSuspiciousPatterns(patterns);

    // All conditions for reproducibility
    const isSeedable =
      patterns.length > 0 &&
      normalized.every((p) => p.address !== undefined) &&
      normalized.every((p) => p.type !== undefined);

    const reproducibilityScore = isSeedable ? 100 : 50;

    return {
      isSeedable,
      reproducibilityScore,
      expectedVariance: ['timing', 'system-state'],
      fixedThresholds: { ...DETERMINISTIC_THRESHOLDS },
    };
  }

  /**
   * Calculate confidence in deterministic detection
   */
  private static calculateDeterminismConfidence(patternCount: number): number {
    // More patterns = higher confidence
    if (patternCount >= 10) return 95;
    if (patternCount >= 5) return 85;
    if (patternCount >= 3) return 75;
    if (patternCount >= 1) return 65;
    return 50;
  }

  /**
   * Verify reproducibility: analyze same patterns twice, get same result
   */
  static verifyReproducibility(
    patterns: SuspiciousPattern[],
    threatLevels: Map<number, ThreatLevel>,
    iterations: number = 5
  ): { reproducible: boolean; variance: number } {
    // Run analysis multiple times
    const scores: number[] = [];

    for (let i = 0; i < iterations; i++) {
      const score = this.calculateThreatScoreDeterministic(patterns, threatLevels);
      scores.push(score);
    }

    // Check all scores are identical
    const firstScore = scores[0];
    const allIdentical = scores.every((s) => s === firstScore);

    // Calculate variance (should be 0)
    const variance = Math.max(...scores) - Math.min(...scores);

    return {
      reproducible: allIdentical && variance === 0,
      variance,
    };
  }

  /**
   * Create a seed for reproducible analysis
   * This can be used to replay the same analysis
   */
  static createAnalysisSeed(
    patterns: SuspiciousPattern[],
    threatLevels: Map<number, ThreatLevel>
  ): string {
    const normalized = this.normalizeSuspiciousPatterns(patterns);
    const seed = {
      patternCount: normalized.length,
      addresses: normalized.map((p) => p.address),
      types: normalized.map((p) => p.type),
      threats: normalized.map((p) => threatLevels.get(p.address) || 'low'),
      thresholds: DETERMINISTIC_THRESHOLDS,
    };

    // Create a deterministic JSON representation
    return JSON.stringify(seed);
  }

  /**
   * Parse an analysis seed to reproduce the analysis
   */
  static parseAnalysisSeed(
    seed: string
  ): {
    patternCount: number;
    addresses: number[];
    types: string[];
    threats: ThreatLevel[];
  } {
    const parsed = JSON.parse(seed);
    return {
      patternCount: parsed.patternCount,
      addresses: parsed.addresses,
      types: parsed.types,
      threats: parsed.threats,
    };
  }

  /**
   * Ensure deterministic sorting of any array
   */
  static sortDeterministically<T>(
    items: T[],
    getKey: (item: T) => string | number
  ): T[] {
    const copy = [...items];
    copy.sort((a, b) => {
      const keyA = getKey(a);
      const keyB = getKey(b);
      if (typeof keyA === 'number' && typeof keyB === 'number') {
        return keyA - keyB;
      }
      return String(keyA).localeCompare(String(keyB));
    });
    return copy;
  }

  /**
   * Hash patterns deterministically
   * Same patterns always produce same hash
   */
  static hashPatterns(patterns: SuspiciousPattern[]): string {
    const normalized = this.normalizeSuspiciousPatterns(patterns);
    const hashInput = normalized.map((p) => `${p.address}:${p.type}`).join('|');

    // Simple hash function (in production, use crypto)
    let hash = 0;
    for (let i = 0; i < hashInput.length; i++) {
      const char = hashInput.charCodeAt(i);
      hash = (hash << 5) - hash + char;
      hash = hash & hash; // Convert to 32-bit integer
    }
    return Math.abs(hash).toString(16);
  }
}
