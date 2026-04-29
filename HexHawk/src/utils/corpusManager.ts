/**
 * corpusManager — Analysis Corpus Persistence
 *
 * Manages a user-curated set of binaries with known (expected) classifications.
 * Each entry records what the user expects the binary to be, alongside the
 * last NEST result so the benchmark harness can score verdict accuracy.
 *
 * Storage key: 'hexhawk:corpus'
 * Entries are deduplicated by SHA-256 hash.
 * Maximum 500 entries; oldest are evicted when exceeded.
 */

import type { BinaryClassification } from './correlationEngine';
import type { NestSummary } from './nestEngine';

// ── Constants ─────────────────────────────────────────────────────────────────

const STORE_KEY     = 'hexhawk:corpus';
const STORE_VERSION = 1;
const MAX_ENTRIES   = 500;

// ── Types ─────────────────────────────────────────────────────────────────────

/** User-supplied label for the binary's ground-truth class. */
export type CorpusLabel = 'clean' | 'malicious' | 'unknown' | 'challenge';

/** Tags the user assigns to a corpus entry for filtering. */
export type CorpusTag =
  | 'system-binary'
  | 'network-active'
  | 'packer-suspected'
  | 'crypto-routines'
  | 'persistence'
  | 'dropper'
  | 'ransomware'
  | 'rat'
  | 'info-stealer'
  | 'loader'
  | 'custom';

/** A single entry in the managed corpus. */
export interface CorpusEntry {
  /** SHA-256 hash — primary key. */
  sha256: string;
  /** Absolute path as last seen on disk. */
  binaryPath: string;
  /** Display-friendly file name derived from path. */
  label: string;
  /** Ground-truth class assigned by the analyst. */
  groundTruth: CorpusLabel;
  /** More specific expected NEST classification (optional). */
  expectedClassification: BinaryClassification | null;
  /** Free-form tags for filtering. */
  tags: CorpusTag[];
  /** ISO-8601 timestamp when the entry was added. */
  addedAt: string;
  /** ISO-8601 timestamp when the entry was last updated. */
  updatedAt: string;
  /** Most recent NEST analysis summary, if a session has run. */
  lastNestSummary: NestSummary | null;
  /** Learning session ID that produced lastNestSummary. */
  lastSessionId: string | null;
  /** Optional analyst notes. */
  notes: string;
}

/** Filter criteria for queryCorpus(). All fields are optional (AND semantics). */
export interface CorpusFilter {
  groundTruth?: CorpusLabel;
  tag?: CorpusTag;
  hasNestResult?: boolean;
  expectedClassification?: BinaryClassification;
  /** Only entries whose lastNestSummary.confidence >= minConfidence. */
  minConfidence?: number;
}

/** Aggregate statistics over the current corpus. */
export interface CorpusStats {
  totalEntries: number;
  byGroundTruth: Record<CorpusLabel, number>;
  byClassification: Partial<Record<BinaryClassification, number>>;
  withNestResults: number;
  avgConfidence: number | null;
}

interface CorpusStore {
  version: number;
  updated: number;
  entries: CorpusEntry[];
}

// ── Internal helpers ──────────────────────────────────────────────────────────

function loadStore(): CorpusStore {
  try {
    const raw = localStorage.getItem(STORE_KEY);
    if (!raw) return emptyStore();
    const parsed: CorpusStore = JSON.parse(raw);
    if (parsed.version !== STORE_VERSION) return emptyStore();
    return parsed;
  } catch {
    return emptyStore();
  }
}

function emptyStore(): CorpusStore {
  return { version: STORE_VERSION, updated: Date.now(), entries: [] };
}

function saveStore(store: CorpusStore): void {
  store.updated = Date.now();
  try {
    localStorage.setItem(STORE_KEY, JSON.stringify(store));
  } catch {
    // Storage quota exceeded — prune 10% and retry once
    store.entries = store.entries.slice(Math.ceil(store.entries.length * 0.1));
    try {
      localStorage.setItem(STORE_KEY, JSON.stringify(store));
    } catch {
      // Give up silently — don't crash the UI
    }
  }
}

function evictOldest(store: CorpusStore): void {
  if (store.entries.length > MAX_ENTRIES) {
    store.entries.sort((a, b) => a.addedAt.localeCompare(b.addedAt));
    store.entries = store.entries.slice(store.entries.length - MAX_ENTRIES);
  }
}

function labelFromPath(path: string): string {
  return path.replace(/\\/g, '/').split('/').pop() ?? path;
}

// ── Public API ─────────────────────────────────────────────────────────────────

/**
 * Add a new entry or update an existing one (matched by sha256).
 * If an entry already exists its NEST summary and metadata are preserved
 * unless explicitly overwritten via updateCorpusEntry().
 * @returns The final stored entry.
 */
export function addToCorpus(
  entry: Omit<CorpusEntry, 'addedAt' | 'updatedAt' | 'label'> & { label?: string }
): CorpusEntry {
  const store = loadStore();
  const now = new Date().toISOString();
  const existing = store.entries.find(e => e.sha256 === entry.sha256);

  if (existing) {
    // Preserve add-time; update metadata
    existing.binaryPath = entry.binaryPath;
    existing.label = entry.label ?? labelFromPath(entry.binaryPath);
    existing.groundTruth = entry.groundTruth;
    existing.expectedClassification = entry.expectedClassification;
    existing.tags = entry.tags;
    existing.notes = entry.notes;
    existing.updatedAt = now;
    saveStore(store);
    return existing;
  }

  const newEntry: CorpusEntry = {
    ...entry,
    label: entry.label ?? labelFromPath(entry.binaryPath),
    addedAt: now,
    updatedAt: now,
    lastNestSummary: entry.lastNestSummary ?? null,
    lastSessionId: entry.lastSessionId ?? null,
    notes: entry.notes ?? '',
  };
  store.entries.push(newEntry);
  evictOldest(store);
  saveStore(store);
  return newEntry;
}

/**
 * Update an existing entry's NEST summary and session ID after a run.
 * No-op if the entry does not exist.
 */
export function updateNestResult(
  sha256: string,
  summary: NestSummary,
  sessionId: string
): void {
  const store = loadStore();
  const entry = store.entries.find(e => e.sha256 === sha256);
  if (!entry) return;
  entry.lastNestSummary = summary;
  entry.lastSessionId = sessionId;
  entry.updatedAt = new Date().toISOString();
  saveStore(store);
}

/**
 * Partially update any fields on an existing entry.
 */
export function updateCorpusEntry(
  sha256: string,
  patch: Partial<Omit<CorpusEntry, 'sha256' | 'addedAt'>>
): void {
  const store = loadStore();
  const entry = store.entries.find(e => e.sha256 === sha256);
  if (!entry) return;
  Object.assign(entry, patch, { updatedAt: new Date().toISOString() });
  saveStore(store);
}

/**
 * Remove an entry from the corpus by SHA-256.
 * @returns true if an entry was found and removed.
 */
export function removeFromCorpus(sha256: string): boolean {
  const store = loadStore();
  const before = store.entries.length;
  store.entries = store.entries.filter(e => e.sha256 !== sha256);
  if (store.entries.length !== before) {
    saveStore(store);
    return true;
  }
  return false;
}

/**
 * Retrieve a single corpus entry by SHA-256.
 */
export function getCorpusEntry(sha256: string): CorpusEntry | null {
  return loadStore().entries.find(e => e.sha256 === sha256) ?? null;
}

/**
 * Query the corpus with optional filters (AND semantics).
 */
export function queryCorpus(filter?: CorpusFilter): CorpusEntry[] {
  const entries = loadStore().entries;
  if (!filter) return [...entries];

  return entries.filter(e => {
    if (filter.groundTruth !== undefined && e.groundTruth !== filter.groundTruth)
      return false;
    if (filter.tag !== undefined && !e.tags.includes(filter.tag))
      return false;
    if (filter.hasNestResult !== undefined) {
      const has = e.lastNestSummary !== null;
      if (has !== filter.hasNestResult) return false;
    }
    if (filter.expectedClassification !== undefined &&
        e.expectedClassification !== filter.expectedClassification)
      return false;
    if (filter.minConfidence !== undefined) {
      if (!e.lastNestSummary) return false;
      if (e.lastNestSummary.finalConfidence < filter.minConfidence) return false;
    }
    return true;
  });
}

/**
 * Return aggregate statistics over the entire corpus.
 */
export function getCorpusStats(): CorpusStats {
  const entries = loadStore().entries;
  const byGroundTruth: Record<CorpusLabel, number> = { clean: 0, malicious: 0, unknown: 0, challenge: 0 };
  const byClassification: Partial<Record<BinaryClassification, number>> = {};
  let totalConfidence = 0;
  let withResults = 0;

  for (const e of entries) {
    byGroundTruth[e.groundTruth] = (byGroundTruth[e.groundTruth] ?? 0) + 1;
    if (e.lastNestSummary) {
      withResults++;
      totalConfidence += e.lastNestSummary.finalConfidence;
      const cls = e.lastNestSummary.finalVerdict as BinaryClassification;
      byClassification[cls] = (byClassification[cls] ?? 0) + 1;
    }
  }

  return {
    totalEntries: entries.length,
    byGroundTruth,
    byClassification,
    withNestResults: withResults,
    avgConfidence: withResults > 0 ? totalConfidence / withResults : null,
  };
}

/**
 * Export the entire corpus as a JSON string for portability.
 */
export function exportCorpus(): string {
  return JSON.stringify(loadStore(), null, 2);
}

/**
 * Replace the current corpus with imported JSON.
 * Merges by sha256 — imported entries win on conflict.
 * @returns Number of entries imported.
 */
export function importCorpus(json: string): number {
  let imported: CorpusStore;
  try {
    imported = JSON.parse(json);
  } catch {
    throw new Error('Invalid corpus JSON');
  }
  if (!Array.isArray(imported.entries)) {
    throw new Error('Corpus JSON missing "entries" array');
  }

  const store = loadStore();
  const existing = new Map(store.entries.map(e => [e.sha256, e]));
  let count = 0;

  for (const entry of imported.entries) {
    if (typeof entry.sha256 !== 'string') continue;
    existing.set(entry.sha256, entry as CorpusEntry);
    count++;
  }

  store.entries = Array.from(existing.values());
  evictOldest(store);
  saveStore(store);
  return count;
}

/**
 * Wipe the entire corpus. Irreversible.
 */
export function clearCorpus(): void {
  saveStore(emptyStore());
}

// ── Directory Ingestion ────────────────────────────────────────────────────────

/**
 * Upper-case ingestion labels used in external directory manifests.
 * Maps to the internal CorpusLabel used throughout the engine.
 *   CLEAN      → 'clean'
 *   SUSPICIOUS → 'unknown'  (ambiguous polarity — could be clean or malicious)
 *   MALICIOUS  → 'malicious'
 */
export type IngestLabel = 'CLEAN' | 'SUSPICIOUS' | 'MALICIOUS' | 'CHALLENGE';

/** One entry in a directory ingest manifest. */
export interface DirectoryIngestEntry {
  /** Absolute path to the binary on disk. */
  path: string;
  /** Pre-computed SHA-256 hash (primary key). */
  sha256: string;
  /** Analyst-assigned label. */
  label: IngestLabel;
  /** Optional more specific expected NEST classification. */
  expectedClassification?: BinaryClassification;
  /** Optional corpus tags. */
  tags?: CorpusTag[];
  /** Optional freeform analyst notes. */
  notes?: string;
}

/** A manifest describing a directory of labelled binaries. */
export interface DirectoryIngestManifest {
  /** Human-readable name for this corpus snapshot (used for display and dedup). */
  name: string;
  entries: DirectoryIngestEntry[];
}

/** Result summary returned by ingestDirectory(). */
export interface IngestResult {
  /** Number of net-new entries added to the corpus. */
  added: number;
  /** Number of existing entries whose metadata was updated. */
  updated: number;
  /** Number of entries skipped due to missing required fields. */
  skipped: number;
  /** Validation errors, one per malformed entry. */
  errors: Array<{ path: string; reason: string }>;
  /** All entries successfully ingested (added or updated), in manifest order. */
  entries: CorpusEntry[];
}

function ingestLabelToCorpusLabel(l: IngestLabel): CorpusLabel {
  if (l === 'CLEAN')     return 'clean';
  if (l === 'MALICIOUS') return 'malicious';
  if (l === 'CHALLENGE') return 'challenge';
  return 'unknown'; // SUSPICIOUS
}

/**
 * Bulk-ingest a directory manifest into the corpus.
 *
 * Entries are deduplicated by SHA-256.  Existing entries keep their NEST
 * summary but have their path/label/tags updated.
 *
 * The operation is deterministic: given the same manifest the result is
 * always the same regardless of how many times it is called.
 *
 * @returns IngestResult summarising what was added / updated / skipped.
 */
export function ingestDirectory(manifest: DirectoryIngestManifest): IngestResult {
  const result: IngestResult = { added: 0, updated: 0, skipped: 0, errors: [], entries: [] };
  const store = loadStore();
  const now = new Date().toISOString();

  for (const raw of manifest.entries) {
    if (!raw.sha256 || typeof raw.sha256 !== 'string') {
      result.errors.push({ path: raw.path ?? '(unknown)', reason: 'Missing or invalid sha256' });
      result.skipped++;
      continue;
    }
    if (!raw.path || typeof raw.path !== 'string') {
      result.errors.push({ path: raw.sha256, reason: 'Missing path' });
      result.skipped++;
      continue;
    }

    const groundTruth = ingestLabelToCorpusLabel(raw.label);
    const existing = store.entries.find(e => e.sha256 === raw.sha256);

    if (existing) {
      existing.binaryPath = raw.path;
      existing.label = labelFromPath(raw.path);
      existing.groundTruth = groundTruth;
      existing.expectedClassification = raw.expectedClassification ?? existing.expectedClassification;
      existing.tags = raw.tags ?? existing.tags;
      existing.notes = raw.notes ?? existing.notes;
      existing.updatedAt = now;
      result.updated++;
      result.entries.push(existing);
    } else {
      const entry: CorpusEntry = {
        sha256: raw.sha256,
        binaryPath: raw.path,
        label: labelFromPath(raw.path),
        groundTruth,
        expectedClassification: raw.expectedClassification ?? null,
        tags: raw.tags ?? [],
        addedAt: now,
        updatedAt: now,
        lastNestSummary: null,
        lastSessionId: null,
        notes: raw.notes ?? '',
      };
      store.entries.push(entry);
      result.added++;
      result.entries.push(entry);
    }
  }

  evictOldest(store);
  saveStore(store);
  return result;
}
