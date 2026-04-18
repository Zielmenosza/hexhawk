import type {
  SuspiciousPattern,
  DisassemblyAnalysis,
  FunctionMetadata,
  LoopInfo,
} from '../App';
import type {
  ThreatExplanation,
  EdgeCaseAnalysisResult,
  BinaryThreatProfile,
  AnalysisParameters,
} from '../types/enterprise';
import { ExplainabilityEngine } from './explainabilityEngine';
import { DeterminismEngine } from './determinismEngine';
import { EdgeCaseEngine } from './edgeCaseEngine';

// ===== Pattern Intelligence Types =====

export type PatternCategory =
  | 'stack-manipulation'
  | 'control-flow-anomaly'
  | 'reference-chain'
  | 'data-obfuscation'
  | 'anti-analysis'
  | 'performance-critical';

export type ThreatLevel = 'critical' | 'high' | 'medium' | 'low' | 'none';

export interface PatternInterpretation {
  category: PatternCategory;
  name: string;
  description: string;
  whyItMatters: string;
  threatLevel: ThreatLevel;
  confidence: number; // 0-100
  actionableInsights: string[];
}

export interface PatternIntelligenceData {
  address: number;
  interpretation: PatternInterpretation;
  similarPatternCount: number;
  chainedWith: number[];
}

// ===== Categorization Logic =====

/**
 * Categorize a pattern based on its characteristics
 */
export function categorizePattern(
  pattern: SuspiciousPattern,
  analysis: DisassemblyAnalysis,
  disassembly: Array<{ mnemonic: string; operands: string }>
): PatternCategory {
  // Analyze pattern characteristics
  if (isStackManipulation(pattern, disassembly)) {
    return 'stack-manipulation';
  }
  if (isControlFlowAnomaly(pattern, disassembly)) {
    return 'control-flow-anomaly';
  }
  if (isReferenceChain(pattern, analysis)) {
    return 'reference-chain';
  }
  if (isDataObfuscation(pattern, disassembly)) {
    return 'data-obfuscation';
  }
  if (isAntiAnalysis(pattern, disassembly)) {
    return 'anti-analysis';
  }
  return 'performance-critical';
}

/**
 * Assign threat level to a pattern category
 */
export function getThreatLevel(category: PatternCategory): ThreatLevel {
  const threatMap: Record<PatternCategory, ThreatLevel> = {
    'anti-analysis': 'critical',
    'control-flow-anomaly': 'high',
    'reference-chain': 'medium',
    'stack-manipulation': 'medium',
    'data-obfuscation': 'low',
    'performance-critical': 'low',
  };
  return threatMap[category];
}

/**
 * Generate interpretation for a pattern
 */
export function interpretPattern(
  pattern: SuspiciousPattern,
  category: PatternCategory,
  analysis: DisassemblyAnalysis,
  similarCount: number
): PatternInterpretation {
  const threatLevel = getThreatLevel(category);
  const confidence = calculateConfidence(pattern, category);

  const interpretations: Record<PatternCategory, () => PatternInterpretation> = {
    'stack-manipulation': () => ({
      category: 'stack-manipulation',
      name: 'Stack Manipulation Chain',
      description:
        'Unusual pattern of stack operations (push/pop pairs, pointer arithmetic)',
      whyItMatters:
        'Often used for obfuscation, ROP chain construction, or exploit payload delivery',
      threatLevel,
      confidence,
      actionableInsights: [
        `Found ${similarCount} similar patterns in binary`,
        'Check if patterns chain together for ROP gadgets',
        'Look for xor operations that may decode stack values',
        'Compare stack layout with function prologue',
      ],
    }),
    'control-flow-anomaly': () => ({
      category: 'control-flow-anomaly',
      name: 'Control Flow Anomaly',
      description: 'Unusual branching pattern (jump chains, indirect jumps, abnormal conditionals)',
      whyItMatters:
        'Indicates packed/obfuscated code, anti-analysis measures, or uncommon control structures',
      threatLevel,
      confidence,
      actionableInsights: [
        `Found ${similarCount} similar patterns`,
        'Check for packing headers and unpacking loops',
        'Look for trampoline functions or tail calls',
        'Analyze if branches always take same path (dead code)',
      ],
    }),
    'reference-chain': () => ({
      category: 'reference-chain',
      name: 'Heavy Reference Chain',
      description:
        'Multiple functions heavily dependent on this location (circular references, API trampolines)',
      whyItMatters: 'Could indicate API hooking, core framework functions, or business logic hubs',
      threatLevel,
      confidence,
      actionableInsights: [
        `Found ${similarCount} similar reference patterns`,
        'Check which functions are callers',
        'Look for common patterns in all callers',
        'Compare with known malware hooking patterns',
      ],
    }),
    'data-obfuscation': () => ({
      category: 'data-obfuscation',
      name: 'Data Obfuscation Pattern',
      description: 'Complex bitwise operations (xor chains, lookup tables, encoded data)',
      whyItMatters: 'Used to protect sensitive data, algorithms, or strings from static analysis',
      threatLevel,
      confidence,
      actionableInsights: [
        'Look for constant xor keys in nearby instructions',
        'Check if same pattern repeats for data decoding',
        'Try to identify protected data (strings, keys, configs)',
        'Look for runtime decryption routines',
      ],
    }),
    'anti-analysis': () => ({
      category: 'anti-analysis',
      name: 'Anti-Analysis Pattern',
      description:
        'Code designed to evade or confuse analysis tools (junk code, fake functions, timing checks)',
      whyItMatters:
        'Intentional obfuscation to prevent reverse engineering — indicates deliberate protection',
      threatLevel,
      confidence,
      actionableInsights: [
        `Found ${similarCount} similar anti-analysis patterns`,
        'Check if code is actually executed or dead',
        'Look for debugger/VM detection patterns',
        'Identify and remove junk code to clarify real logic',
      ],
    }),
    'performance-critical': () => ({
      category: 'performance-critical',
      name: 'Performance-Optimized Code',
      description: 'Code optimized for performance (tight loops, cache optimization, SIMD)',
      whyItMatters: 'Usually legitimate optimization or cryptographic operations',
      threatLevel,
      confidence,
      actionableInsights: [
        'Check for cryptographic library patterns (AES, SHA, etc.)',
        'Look for loop unrolling and inline optimization',
        'Verify this is core business logic, not obfuscation',
      ],
    }),
  };

  return interpretations[category]();
}

/**
 * Find similar patterns in the analysis
 */
export function findSimilarPatterns(
  pattern: SuspiciousPattern,
  category: PatternCategory,
  analysis: DisassemblyAnalysis
): number[] {
  // Find patterns of same category within function distance
  const similar = Array.from(analysis.suspiciousPatterns)
    .filter((p) => {
      if (p.address === pattern.address) return false;
      // Rough similarity: same type, within 1000 bytes
      return (
        categorizePattern(p, analysis, []) === category &&
        Math.abs(p.address - pattern.address) < 1000
      );
    })
    .map((p) => p.address)
    .slice(0, 5); // Return top 5

  return similar;
}

/**
 * Build comprehensive pattern intelligence
 */
export function buildPatternIntelligence(
  pattern: SuspiciousPattern,
  analysis: DisassemblyAnalysis,
  disassembly: Array<{ mnemonic: string; operands: string }>
): PatternIntelligenceData {
  const category = categorizePattern(pattern, analysis, disassembly);
  const interpretation = interpretPattern(pattern, category, analysis, 0);
  const similar = findSimilarPatterns(pattern, category, analysis);

  return {
    address: pattern.address,
    interpretation: {
      ...interpretation,
      confidence: calculateConfidence(pattern, category),
    },
    similarPatternCount: similar.length,
    chainedWith: findChainedPatterns(pattern, analysis),
  };
}

/**
 * Get threat score for entire binary (0-100)
 */
export function calculateBinaryThreatScore(analysis: DisassemblyAnalysis): {
  overall: number;
  byLevel: Record<ThreatLevel, number>;
} {
  const byLevel: Record<ThreatLevel, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    none: 0,
  };

  const weights: Record<ThreatLevel, number> = {
    critical: 25,
    high: 15,
    medium: 5,
    low: 1,
    none: 0,
  };

  // Score each pattern
  let totalScore = 0;
  analysis.suspiciousPatterns.forEach((pattern) => {
    const category = categorizePattern(pattern, analysis, []);
    const threatLevel = getThreatLevel(category);
    byLevel[threatLevel]++;
    totalScore += weights[threatLevel];
  });

  // Normalize to 0-100
  const overall = Math.min(100, Math.round(totalScore / 2));

  return { overall, byLevel };
}

/**
 * Generate personalized suggestion with personality
 */
export function generatePersonalizedSuggestion(
  base: string,
  analysis: DisassemblyAnalysis,
  selectedAddress: number,
  category?: PatternCategory
): string {
  const threatLevel = category ? getThreatLevel(category) : 'low';
  const threat = threatLevel === 'critical' ? ' (🔴 critical)' : threatLevel === 'high' ? ' (🟠 high risk)' : '';

  const suggestionMap: Record<string, string> = {
    'go-to-start': `Jump to function start${threat}`,
    'follow-call': `Jump into callee — likely next step${threat}`,
    'follow-jump': `Follow this jump${threat}`,
    'show-callers': `See who depends on this (helps understand usage)`,
    'highlight-loop': `Show loop structure — helps understand iteration`,
    'view-patterns': `Analyze patterns here${threat}`,
  };

  return suggestionMap[base] || base;
}

/**
 * Helper: Check if pattern looks like stack manipulation
 */
function isStackManipulation(
  pattern: SuspiciousPattern,
  disassembly: Array<{ mnemonic: string; operands: string }>
): boolean {
  // Heuristic: contains push/pop/stack ops in close proximity
  const stackOps = ['push', 'pop', 'add rsp', 'sub rsp', 'mov rsp', 'xchg'];
  return stackOps.some((op) =>
    disassembly.slice(pattern.address, pattern.address + 20).some((instr) =>
      instr.mnemonic.toLowerCase().includes(op.split(' ')[0])
    )
  );
}

/**
 * Helper: Check if pattern looks like control flow anomaly
 */
function isControlFlowAnomaly(
  pattern: SuspiciousPattern,
  disassembly: Array<{ mnemonic: string; operands: string }>
): boolean {
  // Heuristic: multiple jumps in short distance
  const jumpOps = ['jmp', 'jz', 'jnz', 'je', 'jne', 'jl', 'jg', 'ja', 'jb', 'jo', 'jno', 'js'];
  const jumpCount = disassembly
    .slice(pattern.address, pattern.address + 50)
    .filter((instr) =>
      jumpOps.some((op) => instr.mnemonic.toLowerCase().startsWith(op))
    ).length;
  return jumpCount >= 3;
}

/**
 * Helper: Check if pattern looks like reference chain
 */
function isReferenceChain(pattern: SuspiciousPattern, analysis: DisassemblyAnalysis): boolean {
  // Heuristic: instruction with many callers
  const func = Array.from(analysis.functions.values()).find(
    (f) => pattern.address >= f.startAddress && pattern.address < f.endAddress
  );
  return func ? func.incomingCalls.size >= 3 : false;
}

/**
 * Helper: Check if pattern looks like data obfuscation
 */
function isDataObfuscation(
  pattern: SuspiciousPattern,
  disassembly: Array<{ mnemonic: string; operands: string }>
): boolean {
  // Heuristic: xor/and/or operations clustered
  const bitOps = ['xor', 'and', 'or', 'not', 'shl', 'shr', 'rol', 'ror'];
  const bitOpCount = disassembly
    .slice(pattern.address, pattern.address + 30)
    .filter((instr) => bitOps.some((op) => instr.mnemonic.toLowerCase().startsWith(op)))
    .length;
  return bitOpCount >= 4;
}

/**
 * Helper: Check if pattern looks like anti-analysis
 */
function isAntiAnalysis(
  pattern: SuspiciousPattern,
  disassembly: Array<{ mnemonic: string; operands: string }>
): boolean {
  // Heuristic: junk code sequences, call to suspicious functions
  const suspiciousOps = ['nop', 'int3', 'ud2', 'call', 'ret'];
  const sequence = disassembly.slice(pattern.address, pattern.address + 20);
  const hasNops = sequence.filter((i) => i.mnemonic.toLowerCase() === 'nop').length >= 3;
  const callsToUnknown = sequence.filter(
    (i) => i.mnemonic.toLowerCase() === 'call' && i.operands.includes('0x')
  ).length;
  return hasNops || callsToUnknown >= 2;
}

/**
 * Helper: Calculate confidence of categorization
 */
function calculateConfidence(pattern: SuspiciousPattern, category: PatternCategory): number {
  // Simple heuristic: most patterns are 70-90% confident
  const baseConfidence: Record<PatternCategory, number> = {
    'anti-analysis': 85,
    'control-flow-anomaly': 75,
    'stack-manipulation': 70,
    'reference-chain': 80,
    'data-obfuscation': 75,
    'performance-critical': 60,
  };
  return baseConfidence[category];
}

/**
 * Helper: Find patterns that chain together
 */
function findChainedPatterns(pattern: SuspiciousPattern, analysis: DisassemblyAnalysis): number[] {
  // Heuristic: patterns within 200 bytes that are related
  const nearby = Array.from(analysis.suspiciousPatterns)
    .filter((p) => {
      const distance = Math.abs(p.address - pattern.address);
      return distance > 0 && distance < 200;
    })
    .map((p) => p.address)
    .slice(0, 3);

  return nearby;
}

// ===== Enhanced Threat Scoring with Explainability =====

export type LikelyBehavior =
  | 'packed-executable'
  | 'heavily-obfuscated'
  | 'control-flow-flattened'
  | 'anti-analysis-measures'
  | 'performance-optimized'
  | 'normal';

export interface ThreatScoreBreakdown {
  overall: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  confidence: number;
  reasoning: string[];
}

export interface BinaryBehaviorProfile {
  likelyBehaviors: LikelyBehavior[];
  obfuscationLevel: 'low' | 'medium' | 'high' | 'extreme';
  antiAnalysisDetected: boolean;
  packedLikelihood: number; // 0-100
  summary: string; // 3-sentence assessment
}

/**
 * Calculate detailed threat score with reasoning
 */
export function calculateDetailedThreatScore(
  analysis: DisassemblyAnalysis
): ThreatScoreBreakdown {
  const byLevel: Record<ThreatLevel, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    none: 0,
  };

  const weights: Record<ThreatLevel, number> = {
    critical: 25,
    high: 15,
    medium: 5,
    low: 1,
    none: 0,
  };

  const reasoning: string[] = [];
  let totalScore = 0;

  analysis.suspiciousPatterns.forEach((pattern) => {
    const category = categorizePattern(pattern, analysis, []);
    const threatLevel = getThreatLevel(category);
    byLevel[threatLevel]++;
    totalScore += weights[threatLevel];
  });

  // Generate reasoning
  if (byLevel.critical > 0) {
    reasoning.push(`${byLevel.critical} critical pattern${byLevel.critical > 1 ? 's' : ''} (anti-analysis measures)`);
  }
  if (byLevel.high > 0) {
    reasoning.push(`${byLevel.high} high-risk pattern${byLevel.high > 1 ? 's' : ''} (control flow anomalies)`);
  }
  if (byLevel.medium > 0) {
    reasoning.push(`${byLevel.medium} medium-threat pattern${byLevel.medium > 1 ? 's' : ''} (obfuscation)`);
  }

  const overall = Math.min(100, Math.round(totalScore / 2));
  const confidence = calculateScoreConfidence(byLevel, overall);

  return {
    overall,
    critical: byLevel.critical,
    high: byLevel.high,
    medium: byLevel.medium,
    low: byLevel.low,
    confidence,
    reasoning,
  };
}

/**
 * Calculate confidence in threat score (0-100)
 */
function calculateScoreConfidence(byLevel: Record<ThreatLevel, number>, score: number): number {
  const totalPatterns = Object.values(byLevel).reduce((a, b) => a + b, 0);
  if (totalPatterns === 0) return 100; // No patterns = confidently safe
  if (totalPatterns < 3) return 70; // Few patterns = lower confidence
  if (totalPatterns < 10) return 80; // Some patterns = medium confidence
  if (totalPatterns < 30) return 90; // Many patterns = high confidence
  return 95; // Very many patterns = very high confidence
}

/**
 * Detect likely binary behaviors based on pattern distribution
 */
export function detectLikelyBehaviors(analysis: DisassemblyAnalysis): LikelyBehavior[] {
  const behaviors: LikelyBehavior[] = [];
  const categoryCount: Record<PatternCategory, number> = {
    'stack-manipulation': 0,
    'control-flow-anomaly': 0,
    'reference-chain': 0,
    'data-obfuscation': 0,
    'anti-analysis': 0,
    'performance-critical': 0,
  };

  // Count patterns by category
  analysis.suspiciousPatterns.forEach((pattern) => {
    const category = categorizePattern(pattern, analysis, []);
    categoryCount[category]++;
  });

  const total = Object.values(categoryCount).reduce((a, b) => a + b, 0);
  if (total === 0) return ['normal'];

  // Detect behaviors
  if (categoryCount['anti-analysis'] >= 2) {
    behaviors.push('anti-analysis-measures');
  }

  if (categoryCount['control-flow-anomaly'] >= 3) {
    behaviors.push('control-flow-flattened');
  }

  if (
    categoryCount['stack-manipulation'] >= 3 ||
    (categoryCount['data-obfuscation'] >= 3 && categoryCount['stack-manipulation'] >= 1)
  ) {
    behaviors.push('heavily-obfuscated');
  }

  if (
    categoryCount['stack-manipulation'] >= 5 &&
    categoryCount['control-flow-anomaly'] >= 2 &&
    categoryCount['anti-analysis'] >= 1
  ) {
    behaviors.push('packed-executable');
  }

  if (categoryCount['performance-critical'] >= 5 && behaviors.length === 0) {
    behaviors.push('performance-optimized');
  }

  return behaviors.length > 0 ? behaviors : ['normal'];
}

/**
 * Determine obfuscation level
 */
export function getObfuscationLevel(
  analysis: DisassemblyAnalysis
): 'low' | 'medium' | 'high' | 'extreme' {
  const categoryCount: Record<PatternCategory, number> = {
    'stack-manipulation': 0,
    'control-flow-anomaly': 0,
    'reference-chain': 0,
    'data-obfuscation': 0,
    'anti-analysis': 0,
    'performance-critical': 0,
  };

  analysis.suspiciousPatterns.forEach((pattern) => {
    const category = categorizePattern(pattern, analysis, []);
    categoryCount[category]++;
  });

  const obfuscationPatterns =
    categoryCount['stack-manipulation'] +
    categoryCount['control-flow-anomaly'] +
    categoryCount['data-obfuscation'];
  const ratio = obfuscationPatterns / Math.max(1, analysis.suspiciousPatterns.length);

  if (ratio >= 0.8) return 'extreme';
  if (ratio >= 0.5) return 'high';
  if (ratio >= 0.25) return 'medium';
  return 'low';
}

/**
 * Estimate packed binary likelihood (0-100)
 */
export function estimatePackedLikelihood(analysis: DisassemblyAnalysis): number {
  const categoryCount: Record<PatternCategory, number> = {
    'stack-manipulation': 0,
    'control-flow-anomaly': 0,
    'reference-chain': 0,
    'data-obfuscation': 0,
    'anti-analysis': 0,
    'performance-critical': 0,
  };

  analysis.suspiciousPatterns.forEach((pattern) => {
    const category = categorizePattern(pattern, analysis, []);
    categoryCount[category]++;
  });

  let score = 0;

  // Stack manipulation often indicates packing/ROP
  score += Math.min(categoryCount['stack-manipulation'] * 8, 40);

  // Control flow anomalies indicate packing
  score += Math.min(categoryCount['control-flow-anomaly'] * 10, 35);

  // Anti-analysis measures indicate packing
  score += categoryCount['anti-analysis'] * 15;

  // Few reference chains suggest code may be packed
  const avgReferences = analysis.functions.size > 0
    ? analysis.referenceStrength.size / analysis.functions.size
    : 0;
  if (avgReferences < 2) score += 15;

  return Math.min(100, score);
}

/**
 * Generate binary behavior profile
 */
export function generateBinaryProfile(analysis: DisassemblyAnalysis): BinaryBehaviorProfile {
  const scoreBreakdown = calculateDetailedThreatScore(analysis);
  const behaviors = detectLikelyBehaviors(analysis);
  const obfuscation = getObfuscationLevel(analysis);
  const packedLikelihood = estimatePackedLikelihood(analysis);
  const antiAnalysis = behaviors.includes('anti-analysis-measures');

  // Generate 3-sentence summary
  const patternCount = analysis.suspiciousPatterns.length;
  let summary = '';

  if (patternCount === 0) {
    summary = 'This binary contains no suspicious patterns. It appears to be straightforward compiled code without obfuscation or anti-analysis measures.';
  } else {
    const behaviorStr = behaviors
      .filter((b) => b !== 'normal')
      .map((b) => b.replace(/-/g, ' '))
      .join(', ');

    const threat = scoreBreakdown.overall > 70 ? 'highly suspicious' : scoreBreakdown.overall > 40 ? 'moderately suspicious' : 'slightly suspicious';

    summary = `This binary contains ${patternCount} suspicious patterns and appears ${threat}. `;

    if (behaviorStr) {
      summary += `Analysis suggests: ${behaviorStr}. `;
    }

    if (packedLikelihood > 60) {
      summary += 'Strong indicators suggest this binary may be packed or significantly obfuscated.';
    } else if (antiAnalysis) {
      summary += 'Detected anti-analysis measures designed to evade reverse engineering tools.';
    } else if (obfuscation !== 'low') {
      summary += `The code shows ${obfuscation} levels of obfuscation.`;
    } else {
      summary += 'Investigate flagged patterns to understand intended functionality.';
    }
  }

  return {
    likelyBehaviors: behaviors,
    obfuscationLevel: obfuscation,
    antiAnalysisDetected: antiAnalysis,
    packedLikelihood,
    summary,
  };
}

// ===== Phase 1: Enterprise Extensions =====

/**
 * Calculate threat score with full explanation (Phase 1: TRUST)
 * Returns: Score + Breakdown + Confidence + Reasoning
 */
export function calculateThreatScoreWithExplanation(
  analysis: DisassemblyAnalysis
): ThreatExplanation {
  // Map patterns to threat levels
  const threatLevels = new Map<number, ThreatLevel>();
  analysis.suspiciousPatterns.forEach((pattern) => {
    const category = categorizePattern(pattern, analysis, []);
    const level = getThreatLevel(category);
    threatLevels.set(pattern.address, level);
  });

  // Use determinism engine for reproducible score
  const deterministicScore = DeterminismEngine.calculateThreatScoreDeterministic(
    Array.from(analysis.suspiciousPatterns),
    threatLevels
  );

  // Detect edge cases
  const edgeCaseResult = EdgeCaseEngine.detectEdgeCases(
    Array.from(analysis.suspiciousPatterns),
    threatLevels,
    deterministicScore,
    analysis
  );

  // Adjust score for edge cases
  const adjustedScore = EdgeCaseEngine.adjustThreatScoreForEdgeCases(
    deterministicScore,
    edgeCaseResult
  );

  // Generate explanation using explainability engine
  return ExplainabilityEngine.generateThreatExplanation(
    adjustedScore,
    Array.from(analysis.suspiciousPatterns),
    threatLevels,
    edgeCaseResult.warnings
  );
}

/**
 * Generate enhanced binary threat profile with edge case awareness
 */
export function generateBinaryProfileEnhanced(
  analysis: DisassemblyAnalysis
): BinaryThreatProfile & { threatExplanation: ThreatExplanation } {
  const threatExplanation = calculateThreatScoreWithExplanation(analysis);

  // Map patterns to threat levels
  const threatLevels = new Map<number, ThreatLevel>();
  analysis.suspiciousPatterns.forEach((pattern) => {
    const category = categorizePattern(pattern, analysis, []);
    const level = getThreatLevel(category);
    threatLevels.set(pattern.address, level);
  });

  // Get edge case analysis
  const edgeCases = EdgeCaseEngine.detectEdgeCases(
    Array.from(analysis.suspiciousPatterns),
    threatLevels,
    threatExplanation.score,
    analysis
  );

  // Get reproducibility info
  const determinismResult = DeterminismEngine.canReproduceAnalysis(
    Array.from(analysis.suspiciousPatterns),
    threatLevels
  );

  return {
    binaryHash: 'generated',
    threatScore: threatExplanation.score,
    threatExplanation,
    edgeCases: edgeCases.detectedCases,
    determinismResult,
    analyzedAt: Date.now(),
    analysisParameters: DeterminismEngine.getAnalysisParameters(),
  };
}

/**
 * Verify analysis reproducibility (for testing)
 * Runs the same analysis N times and checks for consistency
 */
export function verifyAnalysisReproducibility(
  analysis: DisassemblyAnalysis,
  iterations: number = 5
): {
  reproducible: boolean;
  variance: number;
  scores: number[];
} {
  const threatLevels = new Map<number, ThreatLevel>();
  analysis.suspiciousPatterns.forEach((pattern) => {
    const category = categorizePattern(pattern, analysis, []);
    const level = getThreatLevel(category);
    threatLevels.set(pattern.address, level);
  });

  const result = DeterminismEngine.verifyReproducibility(
    Array.from(analysis.suspiciousPatterns),
    threatLevels,
    iterations
  );

  // DeterminismEngine.verifyReproducibility returns { reproducible, variance }
  // We need to compute scores ourselves
  const scores: number[] = [];
  for (let i = 0; i < iterations; i++) {
    const score = DeterminismEngine.calculateThreatScoreDeterministic(
      Array.from(analysis.suspiciousPatterns),
      threatLevels
    );
    scores.push(score);
  }

  return {
    reproducible: result.reproducible,
    variance: result.variance,
    scores,
  };
}

/**
 * Get analysis parameters used (for audit trail)
 */
export function getAnalysisParameters(): AnalysisParameters {
  return DeterminismEngine.getAnalysisParameters();
}

/**
 * Export threat explanation in various formats
 */
export function exportThreatExplanation(
  explanation: ThreatExplanation,
  format: 'json' | 'markdown' | 'text' = 'text'
): string {
  return ExplainabilityEngine.exportExplanation(explanation, format);
}

