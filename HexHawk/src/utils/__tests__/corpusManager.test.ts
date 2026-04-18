import { describe, it, expect, beforeEach } from 'vitest';
import {
  addToCorpus,
  removeFromCorpus,
  getCorpusEntry,
  queryCorpus,
  getCorpusStats,
  updateNestResult,
  updateCorpusEntry,
  exportCorpus,
  importCorpus,
  clearCorpus,
  type CorpusEntry,
} from '../../utils/corpusManager';
import type { NestSummary } from '../../utils/nestEngine';

// ── Fixtures ──────────────────────────────────────────────────────────────────

function makeSummary(confidence: number, verdict: string): NestSummary {
  return {
    totalIterations: 3,
    finalConfidence: confidence,
    finalVerdict: verdict,
    totalDurationMs: 700,
    confidenceProgression: [70, 85, confidence],
    convergedReason: 'confidence-threshold',
    keyFindings: [],
    improvementTotal: confidence - 70,
  };
}

function addClean(sha256 = 'aaaa'): CorpusEntry {
  return addToCorpus({
    sha256,
    binaryPath: `C:\\Windows\\System32\\${sha256}.exe`,
    groundTruth: 'clean',
    expectedClassification: 'clean',
    tags: ['system-binary'],
    lastNestSummary: null,
    lastSessionId: null,
    notes: '',
  });
}

// ── Setup ─────────────────────────────────────────────────────────────────────

beforeEach(() => {
  clearCorpus();
});

// ── addToCorpus ───────────────────────────────────────────────────────────────

describe('addToCorpus', () => {
  it('adds an entry and retrieves it by sha256', () => {
    addClean('abc123');
    const entry = getCorpusEntry('abc123');
    expect(entry).not.toBeNull();
    expect(entry!.groundTruth).toBe('clean');
  });

  it('deduplicates by sha256 — second add updates metadata', () => {
    addClean('dupeHash');
    addToCorpus({
      sha256: 'dupeHash',
      binaryPath: 'C:\\new\\path.exe',
      groundTruth: 'malicious',
      expectedClassification: 'dropper',
      tags: [],
      lastNestSummary: null,
      lastSessionId: null,
      notes: 'updated',
    });
    expect(queryCorpus().length).toBe(1);
    const updated = getCorpusEntry('dupeHash')!;
    expect(updated.groundTruth).toBe('malicious');
    expect(updated.expectedClassification).toBe('dropper');
    expect(updated.notes).toBe('updated');
  });

  it('derives label from path when not supplied', () => {
    const entry = addToCorpus({
      sha256: 'labelTest',
      binaryPath: 'C:\\Windows\\System32\\calc.exe',
      groundTruth: 'clean',
      expectedClassification: null,
      tags: [],
      lastNestSummary: null,
      lastSessionId: null,
      notes: '',
    });
    expect(entry.label).toBe('calc.exe');
  });
});

// ── removeFromCorpus ──────────────────────────────────────────────────────────

describe('removeFromCorpus', () => {
  it('removes an existing entry and returns true', () => {
    addClean('rem1');
    expect(removeFromCorpus('rem1')).toBe(true);
    expect(getCorpusEntry('rem1')).toBeNull();
  });

  it('returns false for unknown sha256', () => {
    expect(removeFromCorpus('nonexistent')).toBe(false);
  });
});

// ── queryCorpus ───────────────────────────────────────────────────────────────

describe('queryCorpus', () => {
  beforeEach(() => {
    addToCorpus({ sha256: 'c1', binaryPath: 'clean1.exe', groundTruth: 'clean', expectedClassification: 'clean', tags: ['system-binary'], lastNestSummary: null, lastSessionId: null, notes: '' });
    addToCorpus({ sha256: 'm1', binaryPath: 'mal1.exe', groundTruth: 'malicious', expectedClassification: 'dropper', tags: ['dropper'], lastNestSummary: null, lastSessionId: null, notes: '' });
    addToCorpus({ sha256: 'u1', binaryPath: 'unk1.exe', groundTruth: 'unknown', expectedClassification: null, tags: [], lastNestSummary: null, lastSessionId: null, notes: '' });
  });

  it('returns all entries when no filter', () => {
    expect(queryCorpus().length).toBe(3);
  });

  it('filters by groundTruth', () => {
    const malicious = queryCorpus({ groundTruth: 'malicious' });
    expect(malicious.length).toBe(1);
    expect(malicious[0].sha256).toBe('m1');
  });

  it('filters by tag', () => {
    const sys = queryCorpus({ tag: 'system-binary' });
    expect(sys.length).toBe(1);
  });

  it('filters by hasNestResult', () => {
    updateNestResult('c1', makeSummary(95, 'clean'), 'sess-1');
    expect(queryCorpus({ hasNestResult: true }).length).toBe(1);
    expect(queryCorpus({ hasNestResult: false }).length).toBe(2);
  });

  it('filters by minConfidence', () => {
    updateNestResult('c1', makeSummary(95, 'clean'), 'sess-1');
    updateNestResult('m1', makeSummary(60, 'dropper'), 'sess-2');
    expect(queryCorpus({ minConfidence: 80 }).length).toBe(1);
  });
});

// ── getCorpusStats ────────────────────────────────────────────────────────────

describe('getCorpusStats', () => {
  it('returns zero stats for empty corpus', () => {
    const stats = getCorpusStats();
    expect(stats.totalEntries).toBe(0);
    expect(stats.withNestResults).toBe(0);
    expect(stats.avgConfidence).toBeNull();
  });

  it('counts by ground truth correctly', () => {
    addClean('s1');
    addClean('s2');
    addToCorpus({ sha256: 'm1', binaryPath: 'mal.exe', groundTruth: 'malicious', expectedClassification: 'dropper', tags: [], lastNestSummary: null, lastSessionId: null, notes: '' });
    const stats = getCorpusStats();
    expect(stats.byGroundTruth.clean).toBe(2);
    expect(stats.byGroundTruth.malicious).toBe(1);
    expect(stats.totalEntries).toBe(3);
  });

  it('computes avg confidence from NEST results', () => {
    addClean('s1');
    addClean('s2');
    updateNestResult('s1', makeSummary(80, 'clean'), 'sess1');
    updateNestResult('s2', makeSummary(100, 'clean'), 'sess2');
    const stats = getCorpusStats();
    expect(stats.avgConfidence).toBe(90);
  });
});

// ── export / import ───────────────────────────────────────────────────────────

describe('exportCorpus / importCorpus', () => {
  it('round-trips corpus entries', () => {
    addClean('exp1');
    addClean('exp2');
    const json = exportCorpus();
    clearCorpus();
    expect(queryCorpus().length).toBe(0);
    const count = importCorpus(json);
    expect(count).toBe(2);
    expect(getCorpusEntry('exp1')).not.toBeNull();
  });

  it('throws on invalid JSON', () => {
    expect(() => importCorpus('not json')).toThrow('Invalid corpus JSON');
  });

  it('throws when entries array is missing', () => {
    expect(() => importCorpus(JSON.stringify({ version: 1 }))).toThrow('Corpus JSON missing "entries" array');
  });

  it('merges imported entries — imported wins on conflict', () => {
    addClean('merge1');
    const json = JSON.stringify({
      version: 1, updated: Date.now(),
      entries: [{
        sha256: 'merge1', binaryPath: 'new.exe', label: 'new.exe',
        groundTruth: 'malicious', expectedClassification: 'rat', tags: [],
        addedAt: new Date().toISOString(), updatedAt: new Date().toISOString(),
        lastNestSummary: null, lastSessionId: null, notes: 'imported',
      }],
    });
    importCorpus(json);
    const entry = getCorpusEntry('merge1')!;
    expect(entry.groundTruth).toBe('malicious');
    expect(entry.notes).toBe('imported');
  });
});
