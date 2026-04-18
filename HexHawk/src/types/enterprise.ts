/**
 * Enterprise Architecture Types - Phase 1: TRUST
 * Provides type definitions for explainability, determinism, and edge case detection
 */

// ===== EXPLAINABILITY TYPES =====

/**
 * Represents a single component of the threat score breakdown
 * Example: "2 critical patterns (50 points)"
 */
export interface ExplanationBreakdown {
  threatLevel: 'critical' | 'high' | 'medium' | 'low';
  count: number;
  pointsPerPattern: number;
  totalPoints: number;
  description: string; // e.g., "Anti-analysis pattern"
}

/**
 * Confidence factors that explain why we have a certain confidence in the score
 */
export interface ConfidenceFactors {
  patternCount: number; // How many patterns (more = higher confidence)
  patternQuality: number; // 0-100: How clear/strong are the patterns
  patternConsistency: number; // 0-100: How coherent is the pattern set
  analysisDepth: number; // 0-100: How deep is our analysis
}

/**
 * Complete explanation of a threat score
 * Instead of just showing "42/100", show the reasoning
 */
export interface ThreatExplanation {
  score: number; // 0-100
  confidence: number; // 0-100: How confident in this score
  confidenceFactors: ConfidenceFactors;
  breakdown: ExplanationBreakdown[]; // Per-level breakdown
  reasoning: string; // Human-readable explanation
  summary: string; // One-line summary
  edgeCasesDetected: EdgeCaseWarning[];
}

// ===== DETERMINISM TYPES =====

/**
 * Result of analyzing a binary for consistent behavior detection
 */
export interface DeterminismResult {
  isSeedable: boolean; // Can we reproduce this result?
  reproducibilityScore: number; // 0-100: How reproducible
  expectedVariance: string[]; // Things that might vary (filesystem, etc)
  fixedThresholds: Record<string, number>; // Thresholds used
}

/**
 * Track analysis parameters for reproducibility
 */
export interface AnalysisParameters {
  thresholdPatternProximity: number; // Patterns within N bytes considered related
  thresholdSimilarityScore: number; // Minimum score for similarity
  thresholdAntiAnalysisCount: number; // Patterns needed to detect anti-analysis
  thresholdPackedLikelihood: number; // Entropy threshold for packed detection
  versionAnalysisEngine: string; // Track which version analyzed this
}

// ===== EDGE CASE TYPES =====

/**
 * Represents detection of an edge case in binary analysis
 * Edge cases are binaries that don't fit normal threat patterns
 */
export interface EdgeCaseDetection {
  type: 'benign-complex' | 'packed-clean' | 'mixed-signals';
  severity: 'low' | 'medium' | 'high'; // How much it affects threat score
  confidence: number; // 0-100: How confident in detection
  description: string; // What the edge case is
  recommendation: string; // What to do about it
}

/**
 * Warning about an edge case that affects interpretation
 */
export interface EdgeCaseWarning {
  edgeCase: EdgeCaseDetection;
  impacts: string[]; // What this changes (e.g., "threat-score", "pattern-detection")
  adjustedScore?: number; // If score was adjusted due to edge case
}

// ===== BINARY THREAT PROFILE =====

/**
 * Complete threat profile for a binary (enhanced from Phase 7)
 */
export interface BinaryThreatProfile {
  binaryHash: string; // SHA256 of binary
  threatScore: number; // 0-100
  threatExplanation: ThreatExplanation;
  edgeCases: EdgeCaseDetection[];
  determinismResult: DeterminismResult;
  analyzedAt: number; // Unix timestamp
  analysisParameters: AnalysisParameters;
}

// ===== BATCH PROCESSING TYPES =====

/**
 * Represents a batch of binaries to analyze
 */
export interface BatchJob {
  jobId: string;
  status: 'pending' | 'processing' | 'completed' | 'failed';
  priority: 'high' | 'medium' | 'low';
  createdAt: number;
  startedAt?: number;
  completedAt?: number;
  filesTotal: number;
  filesProcessed: number;
  filesFailed: number;
  error?: string;
}

/**
 * Single analysis result from a batch job
 */
export interface AnalysisResult {
  filePath: string;
  binaryHash: string;
  threatScore: number;
  threatExplanation: ThreatExplanation;
  status: 'success' | 'error';
  error?: string;
  duration: number; // Milliseconds
}

/**
 * Persisted analysis record for history/comparison
 */
export interface AnalysisRecord {
  recordId: string;
  filePath: string;
  binaryHash: string;
  threatScore: number;
  threatExplanation: ThreatExplanation;
  analysisParameters: AnalysisParameters;
  analyzedAt: number;
  tags?: string[];
  notes?: string;
}

/**
 * Comparison between two analyses of the same binary
 */
export interface AnalysisComparison {
  previousRecord: AnalysisRecord;
  currentRecord: AnalysisRecord;
  scoreChange: number; // Positive = increased threat
  scoreChangePercent: number;
  parametersChanged: boolean;
  newPatternsDetected: number;
  patternsResolved: number;
  timestamp: number;
}

// ===== EXPORT/REPORT TYPES =====

/**
 * Exportable report format
 */
export interface AnalysisReport {
  version: string;
  generatedAt: number;
  format: 'json' | 'csv' | 'markdown';
  analyses: AnalysisRecord[];
  summary: {
    totalFiles: number;
    averageThreatScore: number;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
  };
}

// ===== FEATURE FLAGS =====

/**
 * Enterprise feature configuration
 */
export interface EnterpriseConfig {
  enableExplainability: boolean;
  enableDeterminism: boolean;
  enableEdgeCaseDetection: boolean;
  enableBatchProcessing: boolean;
  enableReporting: boolean;
  enableHistory: boolean;
  enableRBAC: boolean;
  explainabilityThreshold: number; // Only explain scores above this
  determinismCheckInterval: number; // How often to verify reproducibility
  edgeCaseCheckInterval: number; // How often to check for edge cases
}

// ===== INTERNAL COMPUTATION TYPES =====

/**
 * Internal: Pattern analysis for determinism engine
 */
export interface NormalizedPattern {
  address: number;
  type: string;
  normalized: boolean; // Whether we normalized this
  originalValues: Record<string, unknown>;
}

/**
 * Internal: Behavior detection result
 */
export interface BehaviorDetectionResult {
  behaviors: string[];
  detectionMethod: 'deterministic' | 'heuristic';
  confidence: number;
}

/**
 * Internal: Confidence calculation result
 */
export interface ConfidenceCalculation {
  factors: ConfidenceFactors;
  reasoning: string;
  score: number; // 0-100
}

/**
 * Internal: Edge case analysis result
 */
export interface EdgeCaseAnalysisResult {
  detectedCases: EdgeCaseDetection[];
  scoreAdjustment: number; // Adjustment to apply to threat score
  warnings: EdgeCaseWarning[];
}

// ===== ERROR TYPES =====

/**
 * Enterprise operation error with context
 */
export interface EnterpriseError extends Error {
  code: string;
  context: Record<string, unknown>;
  severity: 'fatal' | 'error' | 'warning' | 'info';
  timestamp: number;
}

/**
 * Batch job error with file context
 */
export interface BatchJobError extends EnterpriseError {
  jobId: string;
  fileIndex: number;
  filePath: string;
}

// ===== AUDIT TYPES (Phase 4, included for reference) =====

/**
 * Audit log entry (for future RBAC implementation)
 */
export interface AuditLogEntry {
  timestamp: number;
  userId: string;
  action: string;
  resource: string;
  result: 'success' | 'failure';
  details: Record<string, unknown>;
}
