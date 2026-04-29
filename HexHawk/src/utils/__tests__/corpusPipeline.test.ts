import { describe, it, expect } from 'vitest';
import {
  scanCorpusDir,
  buildCorpusManifest,
  runCorpusBenchmark,
  computeCorpusMetrics,
  checkRegressionGuard,
  computeConfidenceDeltas,
  verdictPolarity,
  verdictMatchesGroundTruth,
  filenameFromPath,
  ingestLabelToCorpusLabel,
  RegressionError,
  type ScannedBinary,
  type BinaryRunRecord,
  type CorpusBenchmarkMetrics,
  type PipelineIoFns,
} from '../../utils/corpusPipeline';
import type { NestSummary, NestConfig } from '../../utils/nestEngine';

// ── Shared fixtures ────────────────────────────────────────────────────────────

function makeSummary(overrides: Partial<NestSummary> = {}): NestSummary {
  return {
    totalIterations:       3,
    finalConfidence:       85,
    finalVerdict:          'clean',
    totalDurationMs:       1500,
    confidenceProgression: [60, 75, 85],
    convergedReason:       'confidence-threshold',
    keyFindings:           ['Iter 2: No malicious signals found'],
    improvementTotal:      25,
    ...overrides,
  };
}

/**
 * Build a minimal PipelineIoFns mock.
 *   files  — mapping from directory path → list of absolute file paths
 *   hashes — mapping from file path → SHA-256 hex string
 */
function makeIo(
  files:  Record<string, string[]>,
  hashes: Record<string, string>,
): Pick<PipelineIoFns, 'listFiles' | 'hashFile'> {
  return {
    listFiles: async (dir: string) => files[dir] ?? [],
    hashFile:  async (path: string) => hashes[path] ?? 'deadbeef00000000',
  };
}

// ── Test 1: scanCorpusDir ──────────────────────────────────────────────────────

describe('scanCorpusDir', () => {
  it('returns correctly labelled ScannedBinary records for each file', async () => {
    const io = makeIo(
      {
        '/corpus/clean': [
          '/corpus/clean/notepad.exe',
          '/corpus/clean/calc.exe',
        ],
      },
      {
        '/corpus/clean/notepad.exe': 'aaabbb111',
        '/corpus/clean/calc.exe':    'cccddd222',
      },
    );

    const results = await scanCorpusDir('/corpus/clean', 'CLEAN', io);

    expect(results).toHaveLength(2);
    expect(results[0]).toMatchObject({
      path:        '/corpus/clean/notepad.exe',
      sha256:      'aaabbb111',
      filename:    'notepad.exe',
      label:       'CLEAN',
      groundTruth: 'clean',
    });
    expect(results[1]).toMatchObject({
      sha256:      'cccddd222',
      filename:    'calc.exe',
      label:       'CLEAN',
      groundTruth: 'clean',
    });
  });

  it('returns an empty array when the directory contains no files', async () => {
    const io = makeIo({ '/corpus/empty': [] }, {});
    const results = await scanCorpusDir('/corpus/empty', 'MALICIOUS', io);
    expect(results).toHaveLength(0);
  });

  it('assigns MALICIOUS label and malicious groundTruth for the malicious subdir', async () => {
    const io = makeIo(
      { '/corpus/malicious': ['/corpus/malicious/dropper.exe'] },
      { '/corpus/malicious/dropper.exe': 'evil0001' },
    );
    const [record] = await scanCorpusDir('/corpus/malicious', 'MALICIOUS', io);
    expect(record.label).toBe('MALICIOUS');
    expect(record.groundTruth).toBe('malicious');
  });

  it('assigns SUSPICIOUS label and unknown groundTruth for the suspicious subdir', async () => {
    const io = makeIo(
      { '/corpus/suspicious': ['/corpus/suspicious/crackme.exe'] },
      { '/corpus/suspicious/crackme.exe': 'susp0001' },
    );
    const [record] = await scanCorpusDir('/corpus/suspicious', 'SUSPICIOUS', io);
    expect(record.label).toBe('SUSPICIOUS');
    expect(record.groundTruth).toBe('unknown');
  });
});

// ── Test 2: buildCorpusManifest ────────────────────────────────────────────────

describe('buildCorpusManifest', () => {
  it('assigns CLEAN/SUSPICIOUS/MALICIOUS labels from the correct subdirectories', async () => {
    const io = makeIo(
      {
        '/corpus/clean':      ['/corpus/clean/a.exe'],
        '/corpus/suspicious': ['/corpus/suspicious/b.exe'],
        '/corpus/malicious':  ['/corpus/malicious/c.exe'],
      },
      {
        '/corpus/clean/a.exe':      'hash-a',
        '/corpus/suspicious/b.exe': 'hash-b',
        '/corpus/malicious/c.exe':  'hash-c',
      },
    );

    const manifest = await buildCorpusManifest('/corpus', io);

    expect(manifest.entries).toHaveLength(3);
    const byHash = Object.fromEntries(
      manifest.entries.map(e => [e.sha256, e.label]),
    );
    expect(byHash['hash-a']).toBe('CLEAN');
    expect(byHash['hash-b']).toBe('SUSPICIOUS');
    expect(byHash['hash-c']).toBe('MALICIOUS');
  });

  it('produces a manifest with a non-empty name and path entries', async () => {
    const io = makeIo(
      { '/corpus/clean': ['/corpus/clean/x.dll'] },
      { '/corpus/clean/x.dll': 'hash-x' },
    );
    const manifest = await buildCorpusManifest('/corpus', io);
    expect(typeof manifest.name).toBe('string');
    expect(manifest.name.length).toBeGreaterThan(0);
    expect(manifest.entries[0].path).toBe('/corpus/clean/x.dll');
  });

  it('handles a corpus root with a trailing slash without duplicating separators', async () => {
    const io = makeIo(
      { '/corpus/clean': ['/corpus/clean/a.exe'] },
      { '/corpus/clean/a.exe': 'hash-trail' },
    );
    // Both baseDir variants must produce the same result
    const manifestNoSlash   = await buildCorpusManifest('/corpus',  io);
    const manifestWithSlash = await buildCorpusManifest('/corpus/', io);
    expect(manifestNoSlash.entries[0].sha256).toBe(manifestWithSlash.entries[0].sha256);
  });
});

// ── Test 3: runCorpusBenchmark ─────────────────────────────────────────────────

describe('runCorpusBenchmark', () => {
  it('maps NestSummary fields onto BinaryRunRecord with correct confidence deltas', async () => {
    const scanned: ScannedBinary[] = [
      {
        path:        '/corpus/clean/a.exe',
        sha256:      'hash-a',
        filename:    'a.exe',
        label:       'CLEAN',
        groundTruth: 'clean',
      },
    ];

    const nestRunFn = async (
      _path: string,
      _cfg:  NestConfig,
    ): Promise<NestSummary | null> =>
      makeSummary({
        finalVerdict:          'clean',
        finalConfidence:       90,
        confidenceProgression: [60, 80, 90],
        totalIterations:       3,
        convergedReason:       'confidence-threshold',
        keyFindings:           ['Iter 2: clean imports confirmed'],
      });

    const records = await runCorpusBenchmark(scanned, nestRunFn);

    expect(records).toHaveLength(1);
    const r = records[0];
    expect(r.sha256).toBe('hash-a');
    expect(r.filename).toBe('a.exe');
    expect(r.finalVerdict).toBe('clean');
    expect(r.finalConfidence).toBe(90);
    expect(r.convergenceIterations).toBe(3);
    expect(r.convergenceReason).toBe('confidence-threshold');
    // Deltas: [80-60, 90-80] = [20, 10]
    expect(r.confidenceDeltas).toEqual([20, 10]);
    expect(r.signalsFired).toEqual(['Iter 2: clean imports confirmed']);
    expect(r.pass).toBe(true);
    expect(r.errorMessage).toBeNull();
  });

  it('creates a skipped record when nestRunFn returns null', async () => {
    const scanned: ScannedBinary[] = [
      {
        path:        '/corpus/malicious/x.exe',
        sha256:      'hash-x',
        filename:    'x.exe',
        label:       'MALICIOUS',
        groundTruth: 'malicious',
      },
    ];

    const nestRunFn = async (): Promise<NestSummary | null> => null;

    const records = await runCorpusBenchmark(scanned, nestRunFn);

    expect(records).toHaveLength(1);
    const r = records[0];
    expect(r.errorMessage).not.toBeNull();
    expect(r.convergenceIterations).toBe(0);
    expect(r.confidenceDeltas).toEqual([]);
    expect(r.finalVerdict).toBe('unknown');
  });

  it('sets pass=false for a malicious binary that receives a clean verdict', async () => {
    const scanned: ScannedBinary[] = [
      {
        path:        '/corpus/malicious/rat.exe',
        sha256:      'hash-rat',
        filename:    'rat.exe',
        label:       'MALICIOUS',
        groundTruth: 'malicious',
      },
    ];

    // nestRunFn returns a 'clean' verdict — this is a false negative
    const nestRunFn = async (): Promise<NestSummary | null> =>
      makeSummary({ finalVerdict: 'clean', finalConfidence: 80 });

    const records = await runCorpusBenchmark(scanned, nestRunFn);
    expect(records[0].pass).toBe(false);
  });
});

// ── Test 4: checkRegressionGuard ──────────────────────────────────────────────

describe('checkRegressionGuard', () => {
  /** Build a minimal CorpusBenchmarkMetrics with the given accuracy. */
  function makeMetrics(
    accuracyPct: number,
    records: BinaryRunRecord[] = [],
  ): CorpusBenchmarkMetrics {
    const nonSkipped = records.filter(r => r.errorMessage === null);
    return {
      generatedAt:              new Date().toISOString(),
      totalBinaries:            records.length,
      passCount:                nonSkipped.filter(r => r.pass).length,
      failCount:                nonSkipped.filter(r => !r.pass).length,
      skipCount:                records.length - nonSkipped.length,
      accuracyPct,
      falsePositiveRate:        0,
      falseNegativeRate:        0,
      avgConvergenceIterations: 3,
      records,
    };
  }

  it('does not throw when accuracy equals the threshold', () => {
    expect(() => checkRegressionGuard(makeMetrics(80))).not.toThrow();
  });

  it('does not throw when accuracy exceeds the threshold', () => {
    expect(() => checkRegressionGuard(makeMetrics(95))).not.toThrow();
    expect(() => checkRegressionGuard(makeMetrics(100))).not.toThrow();
  });

  it('throws RegressionError when accuracy is one point below the threshold', () => {
    expect(() => checkRegressionGuard(makeMetrics(79))).toThrow(RegressionError);
  });

  it('attaches the observed accuracy to the thrown RegressionError', () => {
    try {
      checkRegressionGuard(makeMetrics(55));
      throw new Error('Expected RegressionError to be thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(RegressionError);
      expect((err as RegressionError).accuracyPct).toBe(55);
    }
  });

  it('uses a custom threshold when supplied', () => {
    expect(() => checkRegressionGuard(makeMetrics(70), 70)).not.toThrow();
    expect(() => checkRegressionGuard(makeMetrics(69), 70)).toThrow(RegressionError);
  });

  it('highlights only new regressions when priorMetrics is provided', () => {
    const failRecord: BinaryRunRecord = {
      sha256:                'fail-hash',
      path:                  '/corpus/clean/fail.exe',
      filename:              'fail.exe',
      label:                 'CLEAN',
      groundTruth:           'clean',
      finalVerdict:          'dropper',
      finalConfidence:       85,
      convergenceIterations: 3,
      convergenceReason:     'confidence-threshold',
      confidenceDeltas:      [10, 5],
      signalsFired:          [],
      durationMs:            1000,
      pass:                  false,
      errorMessage:          null,
    };

    const priorPass: BinaryRunRecord = { ...failRecord, pass: true };

    const priorMetrics  = makeMetrics(90, [priorPass]);
    const currentMetrics = makeMetrics(10, [failRecord]);

    let caught: RegressionError | null = null;
    try {
      checkRegressionGuard(currentMetrics, 80, priorMetrics);
    } catch (err) {
      caught = err as RegressionError;
    }

    expect(caught).not.toBeNull();
    expect(caught!.regressedBinaries).toHaveLength(1);
    expect(caught!.regressedBinaries[0]).toContain('fail.exe');
    expect(caught!.regressedBinaries[0]).toContain('was passing');
  });
});

// ── Test 5: computeCorpusMetrics ──────────────────────────────────────────────

describe('computeCorpusMetrics', () => {
  function makeRecord(
    sha256:       string,
    groundTruth:  'clean' | 'malicious' | 'unknown',
    finalVerdict: string,
    pass:         boolean,
    errorMessage: string | null = null,
  ): BinaryRunRecord {
    return {
      sha256,
      path:                  `/test/${sha256}.exe`,
      filename:              `${sha256}.exe`,
      label:                 groundTruth === 'clean' ? 'CLEAN'
                           : groundTruth === 'malicious' ? 'MALICIOUS'
                           : 'SUSPICIOUS',
      groundTruth,
      finalVerdict,
      finalConfidence:       80,
      convergenceIterations: 3,
      convergenceReason:     'confidence-threshold',
      confidenceDeltas:      [10, 5],
      signalsFired:          [],
      durationMs:            1000,
      pass,
      errorMessage,
    };
  }

  it('computes correct accuracy, FP rate, and FN rate for a mixed corpus', () => {
    const records = [
      makeRecord('c1', 'clean',     'clean',    true),   // correct clean
      makeRecord('c2', 'clean',     'dropper',  false),  // FP: clean → malicious
      makeRecord('m1', 'malicious', 'dropper',  true),   // correct malicious
      makeRecord('m2', 'malicious', 'clean',    false),  // FN: malicious → clean
    ];

    const metrics = computeCorpusMetrics(records);

    expect(metrics.totalBinaries).toBe(4);
    expect(metrics.passCount).toBe(2);
    expect(metrics.failCount).toBe(2);
    expect(metrics.skipCount).toBe(0);
    expect(metrics.accuracyPct).toBe(50);         // 2/4
    expect(metrics.falsePositiveRate).toBe(50);   // 1 FP / 2 clean
    expect(metrics.falseNegativeRate).toBe(50);   // 1 FN / 2 malicious
  });

  it('excludes skipped records from accuracy and rate calculations', () => {
    const records = [
      makeRecord('ok1',   'clean', 'clean', true),
      makeRecord('skip1', 'clean', 'unknown', false, 'NEST run returned no summary (skipped)'),
    ];

    const metrics = computeCorpusMetrics(records);

    expect(metrics.skipCount).toBe(1);
    expect(metrics.totalBinaries).toBe(2);
    // Only 1 non-skipped record — 1 pass → 100 %
    expect(metrics.accuracyPct).toBe(100);
  });

  it('returns 0 for FP and FN rates when the relevant ground-truth classes are absent', () => {
    // All records are 'unknown' groundTruth — no clean or malicious entries
    const records = [
      makeRecord('u1', 'unknown', 'suspicious', true),
      makeRecord('u2', 'unknown', 'suspicious', true),
    ];
    const metrics = computeCorpusMetrics(records);
    expect(metrics.falsePositiveRate).toBe(0);
    expect(metrics.falseNegativeRate).toBe(0);
  });

  it('computes avgConvergenceIterations as the mean over non-skipped records', () => {
    const records = [
      makeRecord('a', 'clean', 'clean', true),
      makeRecord('b', 'clean', 'clean', true),
    ];
    // Both have convergenceIterations = 3 (from makeRecord default)
    const metrics = computeCorpusMetrics(records);
    expect(metrics.avgConvergenceIterations).toBe(3);
  });
});

// ── Unit tests: pure helpers ───────────────────────────────────────────────────

describe('computeConfidenceDeltas', () => {
  it('computes consecutive deltas correctly', () => {
    expect(computeConfidenceDeltas([60, 75, 85])).toEqual([15, 10]);
    expect(computeConfidenceDeltas([50, 60, 70, 80])).toEqual([10, 10, 10]);
  });

  it('returns empty array for progressions with fewer than 2 entries', () => {
    expect(computeConfidenceDeltas([])).toEqual([]);
    expect(computeConfidenceDeltas([85])).toEqual([]);
  });
});

describe('verdictPolarity', () => {
  it.each([
    ['clean',          'clean'   ],
    ['unknown',        'clean'   ],
    ['suspicious',     'clean'   ],
    ['dropper',        'malicious'],
    ['ransomware-like','malicious'],
    ['info-stealer',   'malicious'],
    ['rat',            'malicious'],
    ['loader',         'malicious'],
    ['likely-malware', 'malicious'],
    ['packer',         'malicious'],
  ] as [string, 'clean' | 'malicious'][])('"%s" → %s', (verdict, expected) => {
    expect(verdictPolarity(verdict)).toBe(expected);
  });
});

describe('verdictMatchesGroundTruth', () => {
  it('returns true for unknown ground truth regardless of verdict', () => {
    expect(verdictMatchesGroundTruth('dropper', 'unknown')).toBe(true);
    expect(verdictMatchesGroundTruth('clean',   'unknown')).toBe(true);
  });

  it('matches clean verdict to clean ground truth', () => {
    expect(verdictMatchesGroundTruth('clean', 'clean')).toBe(true);
  });

  it('mismatches malicious verdict for clean ground truth', () => {
    expect(verdictMatchesGroundTruth('dropper', 'clean')).toBe(false);
  });
});

describe('filenameFromPath', () => {
  it('handles forward-slash paths', () => {
    expect(filenameFromPath('/corpus/clean/notepad.exe')).toBe('notepad.exe');
  });

  it('handles backslash paths (Windows)', () => {
    expect(filenameFromPath('C:\\Windows\\System32\\calc.exe')).toBe('calc.exe');
  });
});

describe('ingestLabelToCorpusLabel', () => {
  it('maps CLEAN → clean, MALICIOUS → malicious, SUSPICIOUS → unknown', () => {
    expect(ingestLabelToCorpusLabel('CLEAN')).toBe('clean');
    expect(ingestLabelToCorpusLabel('MALICIOUS')).toBe('malicious');
    expect(ingestLabelToCorpusLabel('SUSPICIOUS')).toBe('unknown');
  });
});
