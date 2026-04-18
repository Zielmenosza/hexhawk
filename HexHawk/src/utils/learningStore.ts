/**
 * learningStore — Persistent Binary Learning System
 *
 * Stores per-binary analysis history and cross-binary pattern intelligence
 * in localStorage so HexHawk remembers and improves between sessions.
 *
 * Capabilities:
 *   - Per-binary: hash, verdict evolution, confirmed patterns, successful heuristics
 *   - Cross-binary: global pattern corroboration rates, heuristic discovery
 *   - Confidence boost for repeated / historically reliable patterns
 *   - Similarity search: find previously analysed binaries that share signal sets
 *   - ECHO enhancement: surface historically reliable patterns as hints
 *
 * Storage key: 'hexhawk.learningStore'
 * All data lives in the browser's localStorage (~5–10 MB budget).
 * Records are pruned (oldest first) when the budget is exceeded.
 */

import type {
  BinaryClassification,
  BinaryVerdictResult,
  BehavioralTag,
  CorrelatedSignal,
} from './correlationEngine';
import type { StrategyClass } from './strategyEngine';

// ── Storage ───────────────────────────────────────────────────────────────────

const STORE_KEY     = 'hexhawk.learningStore';
const STORE_VERSION = 3;
/** Maximum number of binary records to keep. Oldest are pruned. */
const MAX_RECORDS   = 200;
/** Maximum verdict history entries per binary */
const MAX_VERDICT_HISTORY = 20;

// ── Types ─────────────────────────────────────────────────────────────────────

export interface VerdictSnapshot {
  timestamp:      number;
  classification: BinaryClassification;
  confidence:     number;
  /** NEST iteration index that produced this snapshot */
  iteration:      number;
  /** Signal IDs active at this snapshot */
  signalIds:      string[];
}

/**
 * Everything HexHawk knows about a previously-analysed binary,
 * keyed by its SHA-256 hash.
 */
export interface BinaryLearningRecord {
  hash:          string;
  /** File name hint (last seen name, informational only) */
  fileName:      string;
  firstSeen:     number;
  lastSeen:      number;
  sessionCount:  number;
  /**
   * Signal IDs that appeared in every single session for this binary.
   * These are "confirmed" — very high confidence they belong to this file.
   */
  confirmedPatterns: string[];
  /**
   * Signal IDs that appeared in at least one session.
   * Union of all seen signals.
   */
  observedPatterns: string[];
  /** Full verdict history (capped at MAX_VERDICT_HISTORY) */
  verdictHistory: VerdictSnapshot[];
  /**
   * Signal IDs that corroborated other signals in at least one session.
   * "Successful heuristics" — these actively improved the verdict.
   */
  successfulHeuristics: string[];
  /** All behavioral tags ever observed */
  observedBehaviors: BehavioralTag[];
  /** Best confidence achieved across all sessions */
  bestConfidence:    number;
  /** Classification at best confidence */
  bestClassification: BinaryClassification;
}

/**
 * Cross-binary pattern intelligence.
 * Tracks how often each signal ID appeared, and how often it was corroborated.
 */
export interface GlobalPattern {
  /** Signal ID as produced by correlationEngine */
  signalId:          string;
  /** Total number of binaries where this signal appeared */
  observedInCount:   number;
  /** How many times it was corroborated by another signal across all occurrences */
  corroborationHits: number;
  /** Classifications associated with this pattern across all binaries */
  classifications:   Partial<Record<BinaryClassification, number>>;
  /** Average confidence of verdicts that included this signal */
  avgConfidenceWhenPresent: number;
  /** Running sum for avgConfidenceWhenPresent calculation */
  _confidenceSum:    number;
}

/**
 * A cross-binary heuristic: a co-occurring set of signals that reliably
 * predicts a classification or behavior.
 */
export interface GlobalHeuristic {
  id:          string;
  /** Signal IDs that compose this heuristic */
  signalIds:   string[];
  /** Observed trigger count (all signals present simultaneously) */
  triggerCount: number;
  /** Times this heuristic was associated with the dominant classification */
  successCount: number;
  /** Average confidence boost observed when this heuristic fired */
  avgBoost:    number;
  _boostSum:   number;
  /** Most common classification when this heuristic fires */
  dominantClassification: BinaryClassification | null;
  lastSeen:    number;
}

/**
 * Per-strategy-class performance across ALL sessions.
 * Tells HexHawk which strategies reliably improved confidence.
 */
export interface GlobalStrategyStats {
  strategyClass:    StrategyClass;
  /** Total times this strategy was the primary action in an iteration */
  uses:             number;
  /** Iterations that resulted in HIGH improvement */
  highImprovCount:  number;
  /** Iterations that resulted in LOW or NEGATIVE improvement */
  lowImprovCount:   number;
  /** Running sum of composite improvement scores (for avg calculation) */
  _improvSum:       number;
  /** Average composite improvement score when this strategy was used */
  avgImprovement:   number;
  /** Reliability: highImprovCount / uses (0–1). null until 3+ uses. */
  reliability:      number | null;
}

export interface LearningStore {
  version:          number;
  lastUpdated:      number;
  /** Per-binary records, keyed by SHA-256 hash */
  binaryRecords:    Record<string, BinaryLearningRecord>;
  /** Cross-binary pattern frequency and corroboration stats */
  globalPatterns:   Record<string, GlobalPattern>;
  /** Discovered cross-binary heuristics (co-occurring signal sets) */
  globalHeuristics: GlobalHeuristic[];
  /** Cross-binary strategy effectiveness (keyed by StrategyClass) */
  strategyStats:    Partial<Record<StrategyClass, GlobalStrategyStats>>;
}

// ── Boosts / outputs ──────────────────────────────────────────────────────────

export interface LearningBoosts {
  /** Confidence bonus to add (0–15) */
  confidenceBonus: number;
  /** Human-readable reasons for the bonus */
  boostReasons:    string[];
  /**
   * Signal IDs that are pre-corroborated by history.
   * These can be injected as `corroboratedBy` hints to correlationEngine
   * (currently used as annotation hints in NestView).
   */
  preCorroboratedSignals: string[];
  /** Was a known heuristic triggered? */
  heuristicFired: boolean;
}

export interface SimilarBinary {
  hash:               string;
  fileName:           string;
  /** Jaccard similarity of signal ID sets (0–1) */
  similarity:         number;
  classification:     BinaryClassification;
  bestConfidence:     number;
  sessionCount:       number;
  sharedSignals:      string[];
}

// ── Default empty store ────────────────────────────────────────────────────────

function emptyStore(): LearningStore {
  return {
    version:          STORE_VERSION,
    lastUpdated:      Date.now(),
    binaryRecords:    {},
    globalPatterns:   {},
    globalHeuristics: [],
    strategyStats:    {},
  };
}

// ── Persistence ───────────────────────────────────────────────────────────────

export function loadStore(): LearningStore {
  try {
    const raw = localStorage.getItem(STORE_KEY);
    if (!raw) return emptyStore();
    const parsed = JSON.parse(raw) as LearningStore;
    // Migrate from older versions
    if (!parsed.version || parsed.version < STORE_VERSION) {
      return migrateStore(parsed);
    }
    return parsed;
  } catch {
    return emptyStore();
  }
}

export function saveStore(store: LearningStore): void {
  try {
    store.lastUpdated = Date.now();
    // Prune oldest records if over budget
    const hashes = Object.keys(store.binaryRecords);
    if (hashes.length > MAX_RECORDS) {
      const sorted = hashes.sort(
        (a, b) => store.binaryRecords[a].lastSeen - store.binaryRecords[b].lastSeen,
      );
      const toRemove = sorted.slice(0, sorted.length - MAX_RECORDS);
      for (const h of toRemove) delete store.binaryRecords[h];
    }
    localStorage.setItem(STORE_KEY, JSON.stringify(store));
  } catch {
    // localStorage may be full; try to remove the oldest record and retry once
    try {
      const store2 = loadStore();
      const oldest = Object.values(store2.binaryRecords).sort(
        (a, b) => a.lastSeen - b.lastSeen,
      )[0];
      if (oldest) {
        delete store2.binaryRecords[oldest.hash];
        localStorage.setItem(STORE_KEY, JSON.stringify(store));
      }
    } catch {
      // Silent fail — learning is non-critical
    }
  }
}

function migrateStore(old: Partial<LearningStore>): LearningStore {
  // Preserve any records that exist, fill gaps with defaults
  return {
    ...emptyStore(),
    binaryRecords:    old.binaryRecords    ?? {},
    globalPatterns:   old.globalPatterns   ?? {},
    globalHeuristics: old.globalHeuristics ?? [],
    strategyStats:    old.strategyStats    ?? {},
  };
}

export function clearStore(): void {
  localStorage.removeItem(STORE_KEY);
}

// ── Record access ─────────────────────────────────────────────────────────────

export function getLearningRecord(hash: string): BinaryLearningRecord | null {
  if (!hash) return null;
  const store = loadStore();
  return store.binaryRecords[hash] ?? null;
}

export function getStoreStats(): {
  totalBinaries: number;
  totalPatterns:  number;
  totalHeuristics: number;
  oldestRecord:   number | null;
} {
  const store = loadStore();
  const records = Object.values(store.binaryRecords);
  return {
    totalBinaries:   records.length,
    totalPatterns:   Object.keys(store.globalPatterns).length,
    totalHeuristics: store.globalHeuristics.length,
    oldestRecord:    records.length > 0
      ? Math.min(...records.map(r => r.firstSeen))
      : null,
  };
}

// ── Record a completed binary session ─────────────────────────────────────────

export interface SessionData {
  /** SHA-256 hash of the binary */
  hash:         string;
  /** Suggested file name for display (e.g. path basename) */
  fileName:     string;
  classification: BinaryClassification;
  confidence:   number;
  signals:      CorrelatedSignal[];
  behaviors:    BehavioralTag[];
  /** Ordered verdict history from NEST iterations */
  verdictHistory: VerdictSnapshot[];
}

export function recordBinarySession(data: SessionData): void {
  if (!data.hash) return;

  const store     = loadStore();
  const signalIds = data.signals.map(s => s.id);
  const corroboratedIds = data.signals
    .filter(s => s.corroboratedBy.length > 0)
    .map(s => s.id);

  // ── Update / create binary record ──────────────────────────────────────
  const existing = store.binaryRecords[data.hash];

  if (existing) {
    // Update confirmed patterns: intersection of all sessions
    existing.confirmedPatterns = existing.confirmedPatterns.length === 0
      ? signalIds
      : existing.confirmedPatterns.filter(id => signalIds.includes(id));

    // Observed: union
    for (const id of signalIds) {
      if (!existing.observedPatterns.includes(id)) existing.observedPatterns.push(id);
    }

    // Successful heuristics: add newly corroborated signals
    for (const id of corroboratedIds) {
      if (!existing.successfulHeuristics.includes(id)) existing.successfulHeuristics.push(id);
    }

    // Behaviors: union
    for (const b of data.behaviors) {
      if (!existing.observedBehaviors.includes(b)) existing.observedBehaviors.push(b);
    }

    // Verdict history (capped)
    const newEntries = data.verdictHistory.filter(
      v => !existing.verdictHistory.some(e => e.timestamp === v.timestamp),
    );
    existing.verdictHistory = [
      ...existing.verdictHistory,
      ...newEntries,
    ].slice(-MAX_VERDICT_HISTORY);

    if (data.confidence > existing.bestConfidence) {
      existing.bestConfidence     = data.confidence;
      existing.bestClassification = data.classification;
    }
    existing.sessionCount++;
    existing.lastSeen   = Date.now();
    existing.fileName   = data.fileName || existing.fileName;

    store.binaryRecords[data.hash] = existing;
  } else {
    store.binaryRecords[data.hash] = {
      hash:                 data.hash,
      fileName:             data.fileName,
      firstSeen:            Date.now(),
      lastSeen:             Date.now(),
      sessionCount:         1,
      confirmedPatterns:    signalIds,
      observedPatterns:     signalIds,
      verdictHistory:       data.verdictHistory.slice(-MAX_VERDICT_HISTORY),
      successfulHeuristics: corroboratedIds,
      observedBehaviors:    data.behaviors,
      bestConfidence:       data.confidence,
      bestClassification:   data.classification,
    };
  }

  // ── Update global patterns ──────────────────────────────────────────────
  for (const sig of data.signals) {
    const gp = store.globalPatterns[sig.id] ?? {
      signalId:                 sig.id,
      observedInCount:          0,
      corroborationHits:        0,
      classifications:          {},
      avgConfidenceWhenPresent: 0,
      _confidenceSum:           0,
    };

    gp.observedInCount++;
    if (sig.corroboratedBy.length > 0) gp.corroborationHits++;

    const cls = data.classification;
    gp.classifications[cls] = (gp.classifications[cls] ?? 0) + 1;

    gp._confidenceSum += data.confidence;
    gp.avgConfidenceWhenPresent = gp._confidenceSum / gp.observedInCount;

    store.globalPatterns[sig.id] = gp;
  }

  // ── Discover / update global heuristics ────────────────────────────────
  // A heuristic is a pair of co-occurring corroborated signals
  if (corroboratedIds.length >= 2) {
    for (let i = 0; i < corroboratedIds.length; i++) {
      for (let j = i + 1; j < corroboratedIds.length; j++) {
        const key = [corroboratedIds[i], corroboratedIds[j]].sort().join('||');
        const existing_h = store.globalHeuristics.find(h => h.id === key);
        const prevConf   = existing_h?.avgBoost ?? 0;
        const boost      = Math.max(0, data.confidence - 50); // rough boost estimate

        if (existing_h) {
          existing_h.triggerCount++;
          existing_h.successCount++;
          existing_h._boostSum += boost;
          existing_h.avgBoost    = existing_h._boostSum / existing_h.triggerCount;
          existing_h.dominantClassification = data.classification;
          existing_h.lastSeen    = Date.now();
        } else {
          store.globalHeuristics.push({
            id:                     key,
            signalIds:              [corroboratedIds[i], corroboratedIds[j]],
            triggerCount:           1,
            successCount:           1,
            avgBoost:               boost,
            _boostSum:              boost,
            dominantClassification: data.classification,
            lastSeen:               Date.now(),
          });
        }

        void prevConf; // suppress unused warning
      }
    }

    // Cap heuristics list — prune least-triggered
    if (store.globalHeuristics.length > 500) {
      store.globalHeuristics.sort((a, b) => b.triggerCount - a.triggerCount);
      store.globalHeuristics.length = 400;
    }
  }

  saveStore(store);
}

// ── Confidence boosts ─────────────────────────────────────────────────────────

/**
 * Compute learning-based confidence boosts for a set of current signal IDs.
 *
 * Sources of boost:
 *   1. Previously-seen binary (same hash): +5 if confirmed patterns match
 *   2. Globally high-corroboration patterns: +1–3 per signal
 *   3. Known heuristic fired (co-occurring pair): +3–5
 *
 * Total capped at +15 to avoid inflating confidence beyond what the
 * underlying evidence supports.
 */
export function getLearningBoosts(
  hash:             string | undefined,
  currentSignalIds: string[],
): LearningBoosts {
  const store  = loadStore();
  const sigSet = new Set(currentSignalIds);
  let bonus    = 0;
  const reasons: string[] = [];
  const preCorroborated: string[] = [];

  // 1. Previously-seen binary
  if (hash) {
    const rec = store.binaryRecords[hash];
    if (rec && rec.sessionCount > 0) {
      const confirmedHits = rec.confirmedPatterns.filter(id => sigSet.has(id));
      if (confirmedHits.length > 0) {
        const b = Math.min(5, confirmedHits.length * 2);
        bonus += b;
        reasons.push(
          `${confirmedHits.length} confirmed pattern(s) from ${rec.sessionCount} previous session(s) (+${b}%)`,
        );
        preCorroborated.push(...confirmedHits);
      }
      if (rec.successfulHeuristics.length > 0) {
        const heurHits = rec.successfulHeuristics.filter(id => sigSet.has(id));
        if (heurHits.length > 0) {
          const b = Math.min(3, heurHits.length);
          bonus += b;
          reasons.push(`${heurHits.length} successful heuristic(s) re-activated (+${b}%)`);
        }
      }
    }
  }

  // 2. Globally reliable patterns (corroboration rate > 70%, seen in 3+ binaries)
  let globalBonus = 0;
  for (const id of currentSignalIds) {
    const gp = store.globalPatterns[id];
    if (!gp || gp.observedInCount < 3) continue;
    const rate = gp.corroborationHits / gp.observedInCount;
    if (rate >= 0.7) {
      globalBonus += 1;
      preCorroborated.push(id);
    }
  }
  if (globalBonus > 0) {
    const capped = Math.min(4, globalBonus);
    bonus += capped;
    reasons.push(`${globalBonus} globally-reliable signal(s) detected (+${capped}%)`);
  }

  // 3. Known heuristic pair fired
  let heuristicFired = false;
  const sortedSigs = [...currentSignalIds].sort();
  for (let i = 0; i < sortedSigs.length; i++) {
    for (let j = i + 1; j < sortedSigs.length; j++) {
      const key = `${sortedSigs[i]}||${sortedSigs[j]}`;
      const h   = store.globalHeuristics.find(x => x.id === key);
      if (h && h.triggerCount >= 2) {
        const b = Math.min(5, Math.round(h.avgBoost * 0.1));
        if (b > 0) {
          bonus += b;
          reasons.push(
            `Known heuristic (${h.signalIds.join(' + ')}, ${h.triggerCount}× observed) (+${b}%)`,
          );
          heuristicFired = true;
          break;
        }
      }
    }
    if (heuristicFired) break;
  }

  return {
    confidenceBonus:        Math.min(15, bonus),
    boostReasons:           reasons,
    preCorroboratedSignals: [...new Set(preCorroborated)],
    heuristicFired,
  };
}

// ── Similarity search ─────────────────────────────────────────────────────────

/**
 * Find binaries in the store with similar signal sets to the current analysis.
 * Uses Jaccard similarity on signal ID sets.
 * Returns up to `limit` results sorted by similarity descending.
 */
export function getSimilarBinaries(
  currentSignalIds: string[],
  excludeHash?:     string,
  limit = 5,
): SimilarBinary[] {
  const store    = loadStore();
  const current  = new Set(currentSignalIds);
  if (current.size === 0) return [];

  const results: SimilarBinary[] = [];

  for (const rec of Object.values(store.binaryRecords)) {
    if (rec.hash === excludeHash) continue;

    const observed  = new Set(rec.observedPatterns);
    const unionSize = new Set([...current, ...observed]).size;
    if (unionSize === 0) continue;

    let intersectCount = 0;
    const shared: string[] = [];
    for (const id of current) {
      if (observed.has(id)) {
        intersectCount++;
        shared.push(id);
      }
    }

    const jaccard = intersectCount / unionSize;
    if (jaccard >= 0.2) {   // at least 20% similarity to be listed
      results.push({
        hash:           rec.hash,
        fileName:       rec.fileName,
        similarity:     Math.round(jaccard * 100),
        classification: rec.bestClassification,
        bestConfidence: rec.bestConfidence,
        sessionCount:   rec.sessionCount,
        sharedSignals:  shared.slice(0, 6),
      });
    }
  }

  return results.sort((a, b) => b.similarity - a.similarity).slice(0, limit);
}

// ── ECHO enhancements ─────────────────────────────────────────────────────────

/**
 * Returns a list of signal IDs to pre-populate `knownSigMatches` when
 * calling echoScan. These are patterns that have proven reliable for this
 * binary (confirmed) or globally (high corroboration rate).
 */
export function getEchoEnhancements(hash: string | undefined): string[] {
  const store = loadStore();
  const hints = new Set<string>();

  // From binary record: confirmed + successful heuristics
  if (hash) {
    const rec = store.binaryRecords[hash];
    if (rec) {
      for (const id of rec.confirmedPatterns)    hints.add(id);
      for (const id of rec.successfulHeuristics) hints.add(id);
    }
  }

  // Globally high-corroboration patterns (top 10 by corroboration rate)
  const globals = Object.values(store.globalPatterns)
    .filter(gp => gp.observedInCount >= 3)
    .map(gp => ({
      id:   gp.signalId,
      rate: gp.corroborationHits / gp.observedInCount,
    }))
    .filter(x => x.rate >= 0.75)
    .sort((a, b) => b.rate - a.rate)
    .slice(0, 10);

  for (const g of globals) hints.add(g.id);

  return [...hints];
}

// ── Apply learning boost to a verdict's confidence ────────────────────────────

/**
 * Returns a shallow copy of `verdict` with `confidence` bumped by `boosts.confidenceBonus`.
 * Use this before calling `evaluateUncertainty` so the learning context influences
 * the convergence decision.
 */
export function applyLearningBoost(
  verdict: BinaryVerdictResult,
  boosts:  LearningBoosts,
): BinaryVerdictResult {
  if (boosts.confidenceBonus === 0) return verdict;
  return {
    ...verdict,
    confidence: Math.min(100, verdict.confidence + boosts.confidenceBonus),
  };
}

// ── Build verdict history entries from NEST iteration snapshots ───────────────

/**
 * Convenience: convert an array of `{ iteration, timestamp, confidence, classification, signalIds }`
 * to `VerdictSnapshot[]` for use in `recordBinarySession`.
 */
export function buildVerdictHistory(
  snapshots: Array<{
    iteration:      number;
    timestamp:      number;
    confidence:     number;
    classification: BinaryClassification;
    signalIds:      string[];
  }>,
): VerdictSnapshot[] {
  return snapshots.map(s => ({
    timestamp:      s.timestamp,
    classification: s.classification,
    confidence:     s.confidence,
    iteration:      s.iteration,
    signalIds:      s.signalIds,
  }));
}

// ── LearningSession persistence ───────────────────────────────────────────────

const SESSION_KEY_PREFIX = 'hexhawk.learningSession.';
/** Max sessions to keep in localStorage per binary (oldest pruned) */
const MAX_SESSIONS_PER_BINARY = 5;

import type { LearningSession } from './iterationLearning';
export type { LearningSession };

/**
 * Persist a completed (or in-progress) learning session keyed by fileHash.
 * Keeps up to MAX_SESSIONS_PER_BINARY sessions per binary (oldest pruned).
 */
export function saveLearningSession(session: LearningSession): void {
  if (!session.fileHash) return;
  try {
    const key = `${SESSION_KEY_PREFIX}${session.fileHash}`;
    const existing: LearningSession[] = (() => {
      try {
        return JSON.parse(localStorage.getItem(key) ?? '[]') as LearningSession[];
      } catch {
        return [];
      }
    })();

    // Replace in-progress session or append
    const idx = existing.findIndex(
      s => s.startTime === session.startTime,
    );
    if (idx >= 0) {
      existing[idx] = session;
    } else {
      existing.push(session);
    }

    // Prune oldest if over budget
    const pruned = existing
      .sort((a, b) => b.startTime - a.startTime)
      .slice(0, MAX_SESSIONS_PER_BINARY);

    localStorage.setItem(key, JSON.stringify(pruned));
  } catch {
    // Non-critical
  }
}

/**
 * Load all learning sessions for a binary hash.
 * Returns newest-first.
 */
export function getLearningSessionsForHash(
  fileHash: string,
): LearningSession[] {
  if (!fileHash) return [];
  try {
    const key = `${SESSION_KEY_PREFIX}${fileHash}`;
    return JSON.parse(localStorage.getItem(key) ?? '[]') as LearningSession[];
  } catch {
    return [];
  }
}

/**
 * Load the most recent completed (endTime != null) session for a binary.
 */
export function getLastLearningSession(fileHash: string): LearningSession | null {
  const sessions = getLearningSessionsForHash(fileHash);
  return sessions.find(s => s.endTime !== null) ?? sessions[0] ?? null;
}

// ── Strategy outcome recording ─────────────────────────────────────────────

export interface StrategyOutcome {
  strategyClass:    StrategyClass;
  /** Whether this strategy produced high or medium improvement */
  wasEffective:     boolean;
  /** Composite improvement score from iterationLearning */
  compositeDelta:   number;
}

/**
 * Record the outcome of strategies used in a completed session.
 * Aggregates into GlobalStrategyStats for cross-binary learning.
 */
export function recordStrategyOutcomes(outcomes: StrategyOutcome[]): void {
  if (outcomes.length === 0) return;
  try {
    const store = loadStore();
    for (const { strategyClass, wasEffective, compositeDelta } of outcomes) {
      const existing = store.strategyStats[strategyClass] ?? {
        strategyClass,
        uses:            0,
        highImprovCount: 0,
        lowImprovCount:  0,
        _improvSum:      0,
        avgImprovement:  0,
        reliability:     null,
      };
      existing.uses++;
      existing._improvSum     += compositeDelta;
      existing.avgImprovement  = existing._improvSum / existing.uses;
      if (wasEffective) {
        existing.highImprovCount++;
      } else {
        existing.lowImprovCount++;
      }
      // Reliability score available after 3+ uses
      existing.reliability = existing.uses >= 3
        ? existing.highImprovCount / existing.uses
        : null;
      store.strategyStats[strategyClass] = existing;
    }
    saveStore(store);
  } catch {
    // Non-critical
  }
}

/**
 * Return per-strategy reliability scores (0–1) for all strategies
 * with at least 3 observations. Used by strategyEngine to adjust
 * expectedGain for historically unreliable strategies.
 */
export function getStrategyReliability(): Partial<Record<StrategyClass, number>> {
  try {
    const store = loadStore();
    const result: Partial<Record<StrategyClass, number>> = {};
    for (const [cls, stats] of Object.entries(store.strategyStats)) {
      if (stats && stats.reliability !== null) {
        result[cls as StrategyClass] = stats.reliability;
      }
    }
    return result;
  } catch {
    return {};
  }
}
