/**
 * Training Binary Evaluator
 * Defines rules, scoring, and curated recommendations for NEST MODE "food" selection.
 * A training binary must be complex enough to challenge the analysis engine, but
 * stable and well-understood enough to produce consistent learning signals.
 */

export type BinaryFormat = 'exe' | 'dll' | 'elf' | 'bin';

export interface TrainingCandidate {
  /** Display name */
  label: string;
  /** Absolute path to the binary */
  path: string;
  /** Detected format */
  format: BinaryFormat;
  /** File size in bytes */
  sizeBytes: number;
  /** Short description of what makes this binary interesting for training */
  description: string;
  /** Tags describing the kinds of patterns this binary exercises */
  tags: string[];
  /** 1–10 score (higher = better training signal) */
  score: number;
  /** Why this binary was scored this way */
  scoreReason: string;
}

export interface EvaluationResult {
  accepted: boolean;
  reason: string;
  /** Estimated training signal quality 0–1 */
  quality: number;
  /** Suggested number of NEST iterations for this binary */
  suggestedIterations: number;
}

// ─────────────────────────────────────────────────────────────────────────────
// Size constraints (bytes)
// ─────────────────────────────────────────────────────────────────────────────
export const TRAINING_SIZE_MIN = 200 * 1024;       // 200 KB
export const TRAINING_SIZE_MAX = 5 * 1024 * 1024;  // 5 MB
export const TRAINING_SIZE_HARD_REJECT = 10 * 1024 * 1024; // 10 MB — hard reject

// ─────────────────────────────────────────────────────────────────────────────
// Curated recommendations
// Listed in descending preference order.
// ─────────────────────────────────────────────────────────────────────────────
export const CURATED_TRAINING_BINARIES: TrainingCandidate[] = [
  {
    label: 'notepad.exe',
    path: 'C:\\Windows\\System32\\notepad.exe',
    format: 'exe',
    sizeBytes: 360_448,   // ~352 KB (actual size may vary by OS build)
    description: 'Windows text editor — optimal size, rich import table, file I/O and string APIs, no packing or obfuscation.',
    tags: ['file-io', 'ui-api', 'strings', 'pe-standard', 'microsoft-signed'],
    score: 10,
    scoreReason: 'Explicitly preferred in training criteria. Stable across Windows versions, well-documented structure, ideal size for coverage without overload.',
  },
  {
    label: 'cmd.exe',
    path: 'C:\\Windows\\System32\\cmd.exe',
    format: 'exe',
    sizeBytes: 344_064,   // ~336 KB
    description: 'Windows command interpreter — complex control flow, process spawning, string parsing, and env-var access patterns.',
    tags: ['process-spawn', 'control-flow', 'string-parsing', 'env-vars', 'microsoft-signed'],
    score: 8,
    scoreReason: 'More complex control flow than notepad; good for testing NEST control-flow graph analysis. Slightly harder to converge.',
  },
  {
    label: 'regedit.exe',
    path: 'C:\\Windows\\regedit.exe',
    format: 'exe',
    sizeBytes: 577_536,   // ~564 KB
    description: 'Registry editor — diverse API surface including registry I/O, UI, and search patterns.',
    tags: ['registry', 'ui-api', 'tree-walk', 'microsoft-signed'],
    score: 7,
    scoreReason: 'Good signal diversity from registry APIs. Slightly larger; useful when notepad has been exhausted.',
  },
  {
    label: 'bitsadmin.exe',
    path: 'C:\\Windows\\System32\\bitsadmin.exe',
    format: 'exe',
    sizeBytes: 241_664,   // ~236 KB
    description: 'BITS transfer tool — network I/O, COM interfaces, and async job patterns. Good for threat-detection training.',
    tags: ['network', 'com', 'async', 'microsoft-signed'],
    score: 6,
    scoreReason: 'Network and COM patterns improve threat-detection coverage. Compact size but complex import table.',
  },
  {
    label: 'schtasks.exe',
    path: 'C:\\Windows\\System32\\schtasks.exe',
    format: 'exe',
    sizeBytes: 253_952,   // ~248 KB
    description: 'Task scheduler CLI — XML parsing, scheduled execution patterns, persistence-related APIs.',
    tags: ['scheduler', 'xml', 'persistence', 'microsoft-signed'],
    score: 6,
    scoreReason: 'Persistence-related patterns are high-value for threat scoring. Compact and stable.',
  },
];

// The single recommended default
export const DEFAULT_TRAINING_BINARY = CURATED_TRAINING_BINARIES[0];

// ─────────────────────────────────────────────────────────────────────────────
// Evaluation logic — used for user-supplied paths
// ─────────────────────────────────────────────────────────────────────────────

/** Derive format from file extension */
export function detectFormat(filePath: string): BinaryFormat | null {
  const ext = filePath.split('.').pop()?.toLowerCase();
  if (ext === 'exe') return 'exe';
  if (ext === 'dll') return 'dll';
  if (ext === 'elf') return 'elf';
  if (ext === 'bin') return 'bin';
  return null;
}

/** Evaluate a user-supplied binary path + size against the training rules */
export function evaluateTrainingCandidate(
  filePath: string,
  sizeBytes: number,
): EvaluationResult {
  const format = detectFormat(filePath);

  if (!format) {
    return {
      accepted: false,
      reason: 'Unsupported format. Must be .exe, .dll, .elf, or .bin.',
      quality: 0,
      suggestedIterations: 0,
    };
  }

  if (sizeBytes > TRAINING_SIZE_HARD_REJECT) {
    return {
      accepted: false,
      reason: `File too large (${(sizeBytes / 1024 / 1024).toFixed(1)} MB). Hard limit is 10 MB.`,
      quality: 0,
      suggestedIterations: 0,
    };
  }

  if (sizeBytes > TRAINING_SIZE_MAX) {
    return {
      accepted: false,
      reason: `File too large (${(sizeBytes / 1024 / 1024).toFixed(1)} MB). Maximum is 5 MB for stable training.`,
      quality: 0,
      suggestedIterations: 0,
    };
  }

  if (sizeBytes < TRAINING_SIZE_MIN) {
    return {
      accepted: false,
      reason: `File too small (${(sizeBytes / 1024).toFixed(0)} KB). Minimum is 200 KB for meaningful learning.`,
      quality: 0,
      suggestedIterations: 0,
    };
  }

  // Size score: peaks at ~1MB, falls off at edges
  const normalizedSize = sizeBytes / (1024 * 1024); // MB
  const sizeScore = Math.min(1, 1 - Math.abs(normalizedSize - 1) / 4);

  // Format bonus
  const formatBonus = format === 'exe' ? 0.15 : format === 'dll' ? 0.1 : 0;

  const quality = Math.min(1, sizeScore + formatBonus);

  // Suggest iterations proportional to size
  const suggestedIterations = sizeBytes < 500 * 1024 ? 3
    : sizeBytes < 1024 * 1024 ? 5
    : 8;

  return {
    accepted: true,
    reason: `Accepted: ${format.toUpperCase()}, ${(sizeBytes / 1024).toFixed(0)} KB. Good training candidate.`,
    quality,
    suggestedIterations,
  };
}

/** Format byte count for display */
export function formatSize(bytes: number): string {
  if (bytes >= 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  return `${Math.round(bytes / 1024)} KB`;
}

// ─────────────────────────────────────────────────────────────────────────────
// NEST Test Subject Selector — 3-tier progressive suite
// ─────────────────────────────────────────────────────────────────────────────

export type TestSubjectTier = 'baseline' | 'intermediate' | 'challenge';

/**
 * A single test subject — extends TrainingCandidate with tier metadata and
 * expected NEST outcomes to enable progressive difficulty training.
 */
export interface TestSubject extends TrainingCandidate {
  tier: TestSubjectTier;
  /** Relative difficulty: 1 (easiest) → 10 (hardest) */
  difficultyScore: number;
  /** Classification NEST should converge on for this binary */
  expectedClassification: 'clean' | 'suspicious' | 'packer' | 'likely-malware';
  /** What the NEST engine should learn from this subject */
  learningGoal: string;
  /** Why this binary fits this tier */
  tierRationale: string;
  /** Signal IDs the correlation engine is expected to emit */
  expectedSignals: string[];
  /** Recommended max iterations for this tier */
  recommendedIterations: number;
}

export interface TierMeta {
  tier: TestSubjectTier;
  label: string;
  shortLabel: string;
  /** CSS color token */
  color: string;
  icon: string;
  description: string;
}

export const TIER_META: Record<TestSubjectTier, TierMeta> = {
  baseline: {
    tier: 'baseline',
    label: 'Baseline',
    shortLabel: 'BASE',
    color: '#4ade80',
    icon: '○',
    description: 'Clean reference — establishes the Win32 clean fingerprint and dominance gate baseline.',
  },
  intermediate: {
    tier: 'intermediate',
    label: 'Intermediate',
    shortLabel: 'MID',
    color: '#facc15',
    icon: '◑',
    description: 'System utility with richer imports — tests signal diversity and contradiction handling.',
  },
  challenge: {
    tier: 'challenge',
    label: 'Challenge',
    shortLabel: 'HARD',
    color: '#f87171',
    icon: '●',
    description: 'Validation-heavy binary with crypto routines — stress-tests classification under ambiguity.',
  },
};

/**
 * The curated 3-tier progressive test suite.
 * Listed in progressive order: baseline → intermediate → challenge.
 *
 * Selection criteria:
 *   - All are Microsoft-signed Windows system binaries (no malware risk)
 *   - All fall within 200 KB – 5 MB size envelope
 *   - Each introduces strictly more signal complexity than the previous tier
 *   - The challenge tier contains real validation / crypto routines
 */
export const TEST_SUBJECT_SUITE: TestSubject[] = [
  {
    // ── TIER 1: BASELINE ──────────────────────────────────────────────────────
    tier: 'baseline',
    difficultyScore: 1,
    label: 'notepad.exe',
    path: 'C:\\Windows\\System32\\notepad.exe',
    format: 'exe',
    sizeBytes: 360_448,
    description:
      'Windows text editor — canonical clean binary. Rich import table, file I/O and string APIs, ' +
      'standard PE structure, no obfuscation. Establishes the Win32 clean fingerprint.',
    tags: ['file-io', 'ui-api', 'win32-clean', 'strings', 'microsoft-signed'],
    score: 10,
    scoreReason: 'Ideal baseline. Consistently classified as clean, minimal contradictions, fast convergence.',
    expectedClassification: 'clean',
    learningGoal:
      'Establish Win32 clean binary fingerprint. NEST should converge in ≤3 iterations ' +
      'at ≥85% confidence with 0 HIGH contradictions.',
    tierRationale:
      'Most predictable clean binary in any Windows installation. ' +
      'Zero false-positive risk. The gold standard reference point.',
    expectedSignals: ['gui-imports', 'win32-standard-app', 'file-io-imports', 'normal-section-count'],
    recommendedIterations: 3,
  },
  {
    // ── TIER 2: INTERMEDIATE ─────────────────────────────────────────────────
    tier: 'intermediate',
    difficultyScore: 5,
    label: 'mstsc.exe',
    path: 'C:\\Windows\\System32\\mstsc.exe',
    format: 'exe',
    sizeBytes: 534_528,
    description:
      'Remote Desktop Client — richer API surface with TLS, certificate, network, and UI patterns. ' +
      'Network imports alongside GUI create a more ambiguous signal profile than notepad.',
    tags: ['network', 'tls', 'ui-api', 'certificate', 'win32-clean', 'microsoft-signed'],
    score: 8,
    scoreReason:
      'Network + crypto imports may superficially resemble a threat. ' +
      'Tests whether NEST correctly weighs clean indicators over surface-level threat signals.',
    expectedClassification: 'clean',
    learningGoal:
      'Prove that network + TLS imports in a GUI-bearing signed binary do not cause misclassification. ' +
      'Moderate convergence expected (4–5 iterations).',
    tierRationale:
      'Larger import surface with TLS patterns challenges contradiction detection. ' +
      'Correct handling proves clean-binary recognition generalises beyond the simplest case.',
    expectedSignals: ['network-imports', 'gui-imports', 'win32-standard-app', 'shell-dialog-imports'],
    recommendedIterations: 5,
  },
  {
    // ── TIER 3: CHALLENGE ─────────────────────────────────────────────────────
    tier: 'challenge',
    difficultyScore: 8,
    label: 'certutil.exe',
    path: 'C:\\Windows\\System32\\certutil.exe',
    format: 'exe',
    sizeBytes: 1_572_864,
    description:
      'Certificate utility — ASN.1 parsing, certificate chain validation, cryptographic operations, ' +
      'and network I/O. Contains real validation logic that superficially resembles threat behaviors.',
    tags: ['crypto', 'validation-routines', 'asn1', 'certificate-chain', 'network', 'microsoft-signed'],
    score: 9,
    scoreReason:
      'Crypto + network co-presence is the hardest clean-binary pattern to classify correctly. ' +
      'Tests the full contradiction resolution pipeline under deliberate ambiguity.',
    expectedClassification: 'clean',
    learningGoal:
      'Resolve crypto + network co-presence without misclassification. ' +
      'Validate that absence of injection / process-execution / anti-debug weighs correctly. ' +
      'Expect 5–8 iterations, possibly with LOW-severity contradictions that self-resolve.',
    tierRationale:
      'certutil contains the most complex validation routines of any common Windows utility. ' +
      'BCrypt + network calls alongside a large import table are the hardest clean pattern to verify.',
    expectedSignals: ['crypto-imports', 'network-imports', 'win32-standard-app'],
    recommendedIterations: 7,
  },
];

/** Status of a single test-subject slot */
export type TierStatus = 'ready' | 'active' | 'done' | 'skipped';

/**
 * Validate a user-supplied binary against the size and format requirements
 * for a specific tier. Does NOT require file system access — call with
 * metadata obtained from a Tauri file-open dialog or OS API.
 */
export function validateForTier(
  tier: TestSubjectTier,
  filePath: string,
  sizeBytes: number,
): { valid: boolean; message: string } {
  if (sizeBytes < TRAINING_SIZE_MIN)
    return {
      valid: false,
      message: `Too small (${formatSize(sizeBytes)}) — minimum ${formatSize(TRAINING_SIZE_MIN)}`,
    };
  if (sizeBytes > TRAINING_SIZE_MAX)
    return {
      valid: false,
      message: `Too large (${formatSize(sizeBytes)}) — maximum ${formatSize(TRAINING_SIZE_MAX)}`,
    };

  const ext = filePath.split('.').pop()?.toLowerCase();
  if (ext !== 'exe' && ext !== 'dll')
    return { valid: false, message: 'Must be a .exe or .dll file' };

  // Challenge tier requires enough code mass for meaningful validation logic
  if (tier === 'challenge' && sizeBytes < 400 * 1024)
    return {
      valid: false,
      message: `Challenge tier requires ≥400 KB — need sufficient code mass for validation routines`,
    };

  return {
    valid: true,
    message: `Valid ${tier} candidate — ${formatSize(sizeBytes)}`,
  };
}

/**
 * Return the default curated subject for a tier.
 * Convenience helper for initialising UI state.
 */
export function getDefaultSubject(tier: TestSubjectTier): TestSubject {
  return TEST_SUBJECT_SUITE.find(s => s.tier === tier) ?? TEST_SUBJECT_SUITE[0];
}
