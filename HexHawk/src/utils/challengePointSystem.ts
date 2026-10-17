export type ChallengeArtifactKind =
  | 'pe-executable'
  | 'elf-executable'
  | 'document'
  | 'archive'
  | 'pcap'
  | 'script'
  | 'text-or-config'
  | 'challenge-data'
  | 'oversized-binary'
  | 'partial-download'
  | 'unknown';

export type ChallengeSafetyLabel =
  | 'authorized-challenge'
  | 'quarantine-required'
  | 'unknown-needs-review';

export type ChallengeEvidenceState =
  | 'inventoried'
  | 'native-proven'
  | 'gui-smoked'
  | 'quarantined';

export type ChallengeFileSizeClass = 'tiny' | 'small' | 'medium' | 'large' | 'huge';

export type ChallengeCoverage = {
  metadata: boolean;
  strings: boolean;
  disassembly: boolean;
  cfg: boolean;
  referenceGraph: boolean;
  crestBundle: boolean;
  replayCommand: boolean;
  guiSmoke: boolean;
};

export type ChallengePointInventoryEntry = {
  path: string;
  sha256: string;
  sizeBytes: number;
  kind: ChallengeArtifactKind;
  safety: ChallengeSafetyLabel;
  evidenceState: ChallengeEvidenceState;
  coverage: ChallengeCoverage;
  limits: {
    fileSizeClass: ChallengeFileSizeClass;
    cfgTruncated: boolean;
    artifactBudgeted: boolean;
  };
  cAccuracy?: ChallengeCAccuracyEvidence;
  proofArtifacts?: ChallengeProofArtifacts;
};

export type ChallengeCAccuracyEvidence = {
  attempted: boolean;
  mode: 'not-run' | 'static-heuristic' | 'talon-annotated' | 'native-assisted';
  functionsReviewed: number;
  cLikeLines: number;
  typedVariables: number;
  recoveredBranches: number;
  recoveredLoops: number;
  unresolvedInstructions: number;
  unresolvedCalls: number;
  compileChecked: boolean;
  roundTripChecked: boolean;
  authoritySafe: boolean;
};

export type ChallengeProofArtifacts = {
  replayCommand?: string;
  crestBundlePath?: string;
  guiSmokePath?: string;
  backendInspectPath?: string;
  backendStringsPath?: string;
  backendDisassemblyPath?: string;
  backendCfgPath?: string;
  cAccuracyProofPath?: string;
  sanitizedCPath?: string;
  cCompileProofPath?: string;
};

export type ChallengeCustodyAction = {
  action: 'move-into-work' | 'quarantine-note' | 'delete' | 'exclude-from-score';
  path: string;
  reason: string;
  destructive: boolean;
};

export type ChallengePointManifest = {
  schema: 'hexhawk.challenge_point_system.v1';
  generatedAt: string;
  sourceRoot: string;
  entries: ChallengePointInventoryEntry[];
  custodyActions: ChallengeCustodyAction[];
  authorityBoundary: string[];
  proofLimits: string[];
};

export type ChallengeScoreCategory = {
  points: number;
  available: number;
  reason: string;
};

export type ChallengePointPenalty = {
  points: number;
  reason: string;
};

export type ChallengePointScore = {
  schema: 'hexhawk.challenge_point_score.v1';
  total: number;
  available: 100;
  grade: 'blocked' | 'starter' | 'credible' | 'strong' | 'exceptional-but-not-release-ready';
  categories: {
    identity: ChallengeScoreCategory;
    challengeDiversity: ChallengeScoreCategory;
    evidenceCoverage: ChallengeScoreCategory;
    cAccuracy: ChallengeScoreCategory;
    guiAndReplay: ChallengeScoreCategory;
    integrity: ChallengeScoreCategory;
  };
  penalties: ChallengePointPenalty[];
  claims: {
    releaseReady: false;
    verdictCorrectnessProven: false;
    fullAutomationClaimed: false;
  };
  nextHighestValueWork: string[];
};

export type ChallengePointValidation = { ok: boolean; errors: string[]; warnings: string[] };

const SHA_RE = /^[a-f0-9]{64}$/;

function clamp(n: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, n));
}

function unique<T>(items: T[]): T[] {
  return Array.from(new Set(items));
}

function normalisePath(path: string): string {
  return path.replace(/\\/g, '/').replace(/^\.\//, '');
}

function countCoverage(entry: ChallengePointInventoryEntry): number {
  return Object.values(entry.coverage).filter(Boolean).length;
}

export function sizeClassForBytes(sizeBytes: number): ChallengeFileSizeClass {
  if (sizeBytes < 16 * 1024) return 'tiny';
  if (sizeBytes < 1 * 1024 * 1024) return 'small';
  if (sizeBytes < 32 * 1024 * 1024) return 'medium';
  if (sizeBytes < 512 * 1024 * 1024) return 'large';
  return 'huge';
}

export function classifyChallengeKind(path: string, sizeBytes: number): ChallengeArtifactKind {
  const lower = path.toLowerCase();
  if (lower.endsWith('.crdownload') || lower.includes('unconfirmed ')) return 'partial-download';
  if (sizeBytes >= 512 * 1024 * 1024) return 'oversized-binary';
  if (lower.endsWith('.exe') || lower.endsWith('.dll')) return 'pe-executable';
  if (lower.endsWith('.pcap') || lower.endsWith('.pcapng')) return 'pcap';
  if (lower.endsWith('.txt') || lower.endsWith('.md') || lower.endsWith('.eng') || lower.endsWith('.ddf')) return 'text-or-config';
  if (/\.pwn\d+$/i.test(lower)) return 'challenge-data';
  if (lower.endsWith('.pdf') || lower.endsWith('.doc') || lower.endsWith('.docx')) return 'document';
  if (lower.endsWith('.7z') || lower.endsWith('.zip') || lower.endsWith('.rar')) return 'archive';
  if (lower.endsWith('.py') || lower.endsWith('.bat') || lower.endsWith('.sh')) return 'script';
  if (!lower.includes('.') || lower.endsWith('.so')) return 'elf-executable';
  return 'unknown';
}

export function buildChallengePointManifest(input: {
  generatedAt: string;
  sourceRoot: string;
  entries: ChallengePointInventoryEntry[];
  custodyActions: ChallengeCustodyAction[];
}): ChallengePointManifest {
  const entries = input.entries
    .map((entry) => ({
      ...entry,
      path: normalisePath(entry.path),
      sha256: entry.sha256.toLowerCase(),
      coverage: { ...entry.coverage },
      limits: { ...entry.limits },
      cAccuracy: entry.cAccuracy ? { ...entry.cAccuracy } : undefined,
      proofArtifacts: entry.proofArtifacts ? { ...entry.proofArtifacts } : undefined,
    }))
    .sort((a, b) => a.path.toLowerCase().localeCompare(b.path.toLowerCase()));

  return {
    schema: 'hexhawk.challenge_point_system.v1',
    generatedAt: input.generatedAt,
    sourceRoot: normalisePath(input.sourceRoot),
    entries,
    custodyActions: input.custodyActions.map((action) => ({
      ...action,
      path: normalisePath(action.path),
    })),
    authorityBoundary: [
      'GYRE remains sole verdict authority',
      'GYRE remains sole verdict authority; challenge points cannot change verdict fields or base confidence by themselves.',
      'NEST remains evidence lifecycle authority; this point system grades corpus readiness and proof completeness only.',
      'AETHERFRAME, TALON, STRIKE, ECHO, plugins, and C-like pseudocode are advisory evidence surfaces, not hidden verdict authority.',
    ],
    proofLimits: [
      'Challenge points do not prove verdict correctness, malware family truth, exploitability, or release readiness.',
      'Large challenge files may require budgets, truncation, or staged analysis; bounded coverage must be shown instead of hidden.',
      'C-like output accuracy is scored by recoverability, uncertainty, and checks; it is not claimed as original source recovery.',
      'Cleanup actions are recorded as custody notes and must not silently delete unrelated project artifacts.',
    ],
  };
}

export function validateChallengePointManifest(manifest: ChallengePointManifest): ChallengePointValidation {
  const errors: string[] = [];
  const warnings: string[] = [];

  if (manifest.schema !== 'hexhawk.challenge_point_system.v1') errors.push('schema must be hexhawk.challenge_point_system.v1');
  if (!manifest.generatedAt) errors.push('generatedAt is required');
  if (!manifest.sourceRoot) errors.push('sourceRoot is required');
  if (manifest.entries.length === 0) errors.push('at least one challenge entry is required');

  const seenPaths = new Set<string>();
  for (const entry of manifest.entries) {
    if (seenPaths.has(entry.path)) errors.push(`duplicate challenge path: ${entry.path}`);
    seenPaths.add(entry.path);
    if (!SHA_RE.test(entry.sha256)) errors.push(`invalid sha256 for ${entry.path}`);
    if (!Number.isFinite(entry.sizeBytes) || entry.sizeBytes < 0) errors.push(`invalid sizeBytes for ${entry.path}`);
    if (entry.safety === 'quarantine-required' && entry.evidenceState !== 'quarantined') {
      errors.push(`quarantine-required entry must be marked quarantined: ${entry.path}`);
    }
    if (entry.kind === 'partial-download') {
      warnings.push('partial downloads must stay quarantined or be excluded from scoring');
    }
    if (entry.limits.fileSizeClass === 'huge' && !entry.limits.artifactBudgeted) {
      errors.push(`huge entry must declare artifactBudgeted: ${entry.path}`);
    }
    if (entry.cAccuracy && !entry.cAccuracy.authoritySafe) {
      errors.push(`C-output evidence must be authority-safe: ${entry.path}`);
    }
    if (entry.coverage.replayCommand && !entry.proofArtifacts?.replayCommand) {
      errors.push(`replayCommand coverage requires a replay command artifact: ${entry.path}`);
    }
    if (entry.coverage.crestBundle && !entry.proofArtifacts?.crestBundlePath) {
      errors.push(`crestBundle coverage requires a CREST bundle path: ${entry.path}`);
    }
    if (entry.coverage.guiSmoke && !entry.proofArtifacts?.guiSmokePath) {
      errors.push(`guiSmoke coverage requires a GUI smoke artifact path: ${entry.path}`);
    }
  }

  for (const action of manifest.custodyActions) {
    if (action.destructive || action.action === 'delete') {
      errors.push('destructive cleanup actions are not allowed in challenge point manifests');
    }
    if (!action.reason.trim()) errors.push(`custody action reason is required for ${action.path}`);
  }

  const kinds = unique(manifest.entries.filter(e => e.safety === 'authorized-challenge').map(e => e.kind));
  if (kinds.length < 3) warnings.push('challenge diversity is low; use more artifact kinds from the Challenges folder');

  return { ok: errors.length === 0, errors, warnings: unique(warnings) };
}

function scoreIdentity(entries: ChallengePointInventoryEntry[]): ChallengeScoreCategory {
  const available = 20;
  if (entries.length === 0) return { points: 0, available, reason: 'no challenge files inventoried' };
  const validHashes = entries.filter(e => SHA_RE.test(e.sha256)).length;
  const points = Math.round((validHashes / entries.length) * available);
  return { points, available, reason: `${validHashes}/${entries.length} files have valid SHA-256 identity` };
}

function scoreDiversity(entries: ChallengePointInventoryEntry[]): ChallengeScoreCategory {
  const available = 15;
  const authorized = entries.filter(e => e.safety === 'authorized-challenge');
  const kinds = unique(authorized.map(e => e.kind));
  const sizeClasses = unique(authorized.map(e => e.limits.fileSizeClass));
  const raw = (Math.min(kinds.length, 6) / 6) * 9 + (Math.min(sizeClasses.length, 5) / 5) * 6;
  return { points: Math.round(raw), available, reason: `${kinds.length} artifact kinds and ${sizeClasses.length} size classes covered` };
}

function scoreEvidenceCoverage(entries: ChallengePointInventoryEntry[]): ChallengeScoreCategory {
  const available = 20;
  const scorable = entries.filter(e => e.safety === 'authorized-challenge');
  if (scorable.length === 0) return { points: 0, available, reason: 'no authorized challenge entries' };
  const possible = scorable.length * 8;
  const achieved = scorable.reduce((sum, entry) => sum + countCoverage(entry), 0);
  return { points: Math.round((achieved / possible) * available), available, reason: `${achieved}/${possible} coverage checks present` };
}

export function scoreCAccuracyEvidence(evidence: ChallengeCAccuracyEvidence | undefined): number {
  if (!evidence || !evidence.attempted || evidence.mode === 'not-run') return 0;
  let score = 0;
  score += clamp(evidence.functionsReviewed, 0, 10) * 1.2;
  score += clamp(evidence.cLikeLines, 0, 120) / 12;
  score += clamp(evidence.typedVariables, 0, 24) / 4;
  score += clamp(evidence.recoveredBranches, 0, 20) / 3;
  score += clamp(evidence.recoveredLoops, 0, 12) / 3;
  score -= clamp(evidence.unresolvedInstructions, 0, 80) / 10;
  score -= clamp(evidence.unresolvedCalls, 0, 30) / 6;
  if (evidence.compileChecked) score += 4;
  if (evidence.roundTripChecked) score += 4;
  if (evidence.mode === 'native-assisted') score += 3;
  if (evidence.mode === 'talon-annotated') score += 2;
  if (!evidence.authoritySafe) score = 0;
  return clamp(Math.round(score), 0, 20);
}

function scoreCAccuracy(entries: ChallengePointInventoryEntry[]): ChallengeScoreCategory {
  const available = 15;
  const executableEntries = entries.filter(e => e.kind === 'pe-executable' || e.kind === 'elf-executable' || e.kind === 'oversized-binary');
  if (executableEntries.length === 0) return { points: 0, available, reason: 'no executable challenge entries for C-output scoring' };
  const raw = executableEntries.reduce((sum, entry) => sum + scoreCAccuracyEvidence(entry.cAccuracy), 0);
  const possible = executableEntries.length * 20;
  const compileChecked = executableEntries.filter(entry => entry.cAccuracy?.compileChecked).length;
  const roundTripChecked = executableEntries.filter(entry => entry.cAccuracy?.roundTripChecked).length;
  const uncapped = Math.round((raw / possible) * available);
  const maxWithoutCompileChecks = 13;
  const points = compileChecked === 0 ? Math.min(uncapped, maxWithoutCompileChecks) : uncapped;
  const capNote = compileChecked === 0
    ? '; capped below maximum because no executable challenge has compile-checked C output'
    : `; ${compileChecked}/${executableEntries.length} compile-checked, ${roundTripChecked}/${executableEntries.length} round-trip checked`;
  return { points, available, reason: `${raw}/${possible} C-output accuracy evidence points across executable challenges${capNote}` };
}

function scoreGuiReplay(entries: ChallengePointInventoryEntry[]): ChallengeScoreCategory {
  const available = 15;
  const authorized = entries.filter(e => e.safety === 'authorized-challenge');
  if (authorized.length === 0) return { points: 0, available, reason: 'no authorized entries for GUI/replay scoring' };
  const perEntry = authorized.map(e => (e.coverage.guiSmoke ? 1 : 0) + (e.coverage.replayCommand ? 1 : 0) + (e.coverage.crestBundle ? 1 : 0));
  const achieved = perEntry.reduce((a, b) => a + b, 0);
  return { points: Math.round((achieved / (authorized.length * 3)) * available), available, reason: `${achieved}/${authorized.length * 3} GUI/replay/CREST checks present` };
}

function scoreIntegrity(manifest: ChallengePointManifest): ChallengeScoreCategory {
  const available = 15;
  let points = available;
  const quarantined = manifest.entries.filter(e => e.safety === 'quarantine-required').length;
  const unknown = manifest.entries.filter(e => e.safety === 'unknown-needs-review').length;
  const destructive = manifest.custodyActions.filter(a => a.destructive || a.action === 'delete').length;
  points -= quarantined * 2;
  points -= unknown * 3;
  points -= destructive * 10;
  const unbudgetedHuge = manifest.entries.filter(e => e.limits.fileSizeClass === 'huge' && !e.limits.artifactBudgeted).length;
  points -= unbudgetedHuge * 5;
  return { points: clamp(points, 0, available), available, reason: `${quarantined} quarantine, ${unknown} unknown, ${destructive} destructive actions, ${unbudgetedHuge} unbudgeted huge files` };
}

function grade(total: number): ChallengePointScore['grade'] {
  if (total < 30) return 'blocked';
  if (total < 50) return 'starter';
  if (total < 72) return 'credible';
  if (total < 90) return 'strong';
  return 'exceptional-but-not-release-ready';
}

export function scoreChallengePointManifest(manifest: ChallengePointManifest): ChallengePointScore {
  const categories = {
    identity: scoreIdentity(manifest.entries),
    challengeDiversity: scoreDiversity(manifest.entries),
    evidenceCoverage: scoreEvidenceCoverage(manifest.entries),
    cAccuracy: scoreCAccuracy(manifest.entries),
    guiAndReplay: scoreGuiReplay(manifest.entries),
    integrity: scoreIntegrity(manifest),
  };

  const penalties: ChallengePointPenalty[] = [];
  const partials = manifest.entries.filter(e => e.kind === 'partial-download').length;
  if (partials) penalties.push({ points: partials * 2, reason: `${partials} partial-download artifact(s) require quarantine/exclusion` });
  const unknowns = manifest.entries.filter(e => e.kind === 'unknown' || e.safety === 'unknown-needs-review').length;
  if (unknowns) penalties.push({ points: unknowns * 2, reason: `${unknowns} unknown artifact(s) need review before scoring` });
  const destructive = manifest.custodyActions.filter(a => a.destructive || a.action === 'delete').length;
  if (destructive) penalties.push({ points: destructive * 10, reason: 'destructive cleanup is outside the challenge point-system guardrail' });

  const categoryTotal = Object.values(categories).reduce((sum, category) => sum + category.points, 0);
  const total = clamp(categoryTotal - penalties.reduce((sum, penalty) => sum + penalty.points, 0), 0, 100);

  return {
    schema: 'hexhawk.challenge_point_score.v1',
    total,
    available: 100,
    grade: grade(total),
    categories,
    penalties,
    claims: {
      releaseReady: false,
      verdictCorrectnessProven: false,
      fullAutomationClaimed: false,
    },
    nextHighestValueWork: [
      'Move from direct native release-binary smoke to explicitly approved installer install/uninstall smoke for the next tester handoff.',
      'Add deeper executable semantic checks beyond sanitized structural probes, including input/output behavior where safe challenge semantics are known.',
      'Keep huge-file CFG/decompile budgets visible and add resumable deeper passes instead of pretending full coverage.',
      'Attach score-gated proof manifests to the next tester handoff only after rebuilding and installer smoke approval.',
    ],
  };
}

export function summarizeChallengePointScore(score: ChallengePointScore): string {
  const categoryLines = Object.entries(score.categories)
    .map(([name, category]) => `- ${name}: ${category.points}/${category.available} — ${category.reason}`)
    .join('\n');
  const penaltyLines = score.penalties.length
    ? score.penalties.map(p => `- -${p.points}: ${p.reason}`).join('\n')
    : '- none';
  return `# Challenge Point System\n\nScore: ${score.total}/${score.available} (${score.grade})\n\nNot release-ready. Verdict correctness is not proven. Full automation is not claimed.\n\n## Categories\n${categoryLines}\n\n## Penalties\n${penaltyLines}\n\n## Next highest-value work\n${score.nextHighestValueWork.map(item => `- ${item}`).join('\n')}`;
}
