/**
 * ingest-challenges — Corpus Ingest Script for FLARE Challenge Binaries
 *
 * Scans D:\Project\HexHawk\Challenges recursively, hashes every binary
 * (≤ SIZE_LIMIT_BYTES), labels each as 'CHALLENGE', and writes a corpus
 * manifest to:
 *   HexHawk/corpus/results.json
 *
 * Usage:
 *   npx tsx scripts/ingest-challenges.ts
 *   npx tsx scripts/ingest-challenges.ts [challenges-dir] [output-file]
 *
 * Binaries larger than SIZE_LIMIT_BYTES (default 512 MB) are recorded without
 * a hash (sha256: null) and tagged as 'analysis-skipped'.
 *
 * Output schema:
 *   {
 *     version: 1,
 *     generatedAt: ISO-8601,
 *     source: string,
 *     totalEntries: number,
 *     entries: ChallengeEntry[]
 *   }
 */

import * as fs   from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);

// ── Config ────────────────────────────────────────────────────────────────────

const SIZE_LIMIT_BYTES = 512 * 1024 * 1024; // 512 MB

/** File extensions considered binaries. Empty string = no extension (e.g. ELF). */
const BINARY_EXTS = new Set(['.exe', '.dll', '.bin', '.elf', '']);

/** Extensions that are definitely not binaries — skip unconditionally. */
const SKIP_EXTS = new Set(['.txt', '.md', '.json', '.bat', '.ps1', '.sh', '.py', '.pcapng', '.log']);

// ── Known companion DLLs from the FlareAuthenticator challenge folder.
//   These are Microsoft/Qt runtime libraries bundled with the challenge, not
//   the challenge binary itself.  They are still ingested but flagged.
const KNOWN_RUNTIME_DLLS = new Set([
  'msvcp140.dll', 'msvcp140_1.dll', 'msvcp140_2.dll',
  'vcruntime140.dll', 'vcruntime140_1.dll',
  'qt6core.dll', 'qt6gui.dll', 'qt6widgets.dll', 'qwindows.dll',
]);

// ── Known analysis metadata from NEST/TALON/STRIKE sessions.
//   Keyed by lower-cased filename; used to enrich output with pre-computed
//   verdicts and signal sets.
const KNOWN_METADATA: Record<string, {
  nestVerdict:     string;
  nestConfidence:  number | null;
  strikeSignals:   string[];
  talonQuality:    string;
  notes:           string;
  tags:            string[];
  expectedClass:   string | null;
}> = {
  'crackme_shroud.exe': {
    nestVerdict:    'SUSPICIOUS',
    nestConfidence: 68,
    strikeSignals:  ['anti-debug', 'dynamic-load', 'timing-check', 'exception-handling', 'seh-unwind'],
    talonQuality:   'low-packed',
    notes:          'Shroud packer. EP near end of .text (9.3 MB). All imports from KERNEL32 only. IsDebuggerPresent, GetProcAddress, LoadLibraryExW, QueryPerformanceCounter. Anti-debug + timing checks. Unpacking required before TALON analysis.',
    tags:           ['packer-suspected', 'custom'],
    expectedClass:  null,
  },
  'unholydragon-150.exe': {
    nestVerdict:    'UNKNOWN',
    nestConfidence: null,
    strikeSignals:  [],
    talonQuality:   'n/a-parse-failure',
    notes:          'nest_cli returned "Unknown file magic". Not a valid PE/MZ binary. Possible 16-bit DOS/NE, .NET with malformed headers, custom format, or ELF with .exe extension.',
    tags:           ['custom'],
    expectedClass:  null,
  },
  'ntfsm.exe': {
    nestVerdict:    'SUSPICIOUS',
    nestConfidence: 77,
    strikeSignals:  ['crypto-cipher', 'crypto-hash', 'process-exec', 'shell-execute', 'system-reboot', 'anti-debug', 'timing'],
    talonQuality:   'medium',
    notes:          'BCryptOpenAlgorithmProvider + BCryptDecrypt + CreateProcessA + ShellExecuteA + ExitWindowsEx + IsDebuggerPresent. 20 MB binary; 41,964 exception records. Potential dropper/wiper with anti-analysis.',
    tags:           ['crypto-routines', 'custom'],
    expectedClass:  null,
  },
  'chat_client': {
    nestVerdict:    'UNKNOWN',
    nestConfidence: null,
    strikeSignals:  [],
    talonQuality:   'n/a-elf',
    notes:          'No file extension; likely Linux ELF. Chain of Demands challenge. Not analysable by HexHawk PE backend.',
    tags:           ['custom'],
    expectedClass:  null,
  },
  'hopeanddreams.exe': {
    nestVerdict:    'SUSPICIOUS',
    nestConfidence: 72,
    strikeSignals:  ['system-enum', 'anti-debug', 'os-fingerprint', 'timing-check', 'threading', 'network'],
    talonQuality:   'medium',
    notes:          'GetComputerNameA + GetUserNameA + GetSystemInfo + GlobalMemoryStatusEx + GetVersionExW + IsDebuggerPresent. C++ STL (MSVCP140). Confirmed network activity via companion packets.pcapng. RAT/info-stealer pattern.',
    tags:           ['rat', 'info-stealer', 'network-active', 'custom'],
    expectedClass:  'rat',
  },
  'flareauth.exe': {   // matched as prefix below
    nestVerdict:    'SUSPICIOUS',
    nestConfidence: 61,
    strikeSignals:  ['encrypted-payload', 'tls-callback', 'high-entropy-rdata', 'anti-debug'],
    talonQuality:   'medium',
    notes:          '.data entropy 7.997/8.0 (effectively maximum — encrypted/compressed blob 174 KB). .tls section present. Qt6 UI. FLARE-On authenticator challenge.',
    tags:           ['packer-suspected', 'crypto-routines', 'custom'],
    expectedClass:  null,
  },
  'flareauth': {       // fallback without .exe
    nestVerdict:    'SUSPICIOUS',
    nestConfidence: 61,
    strikeSignals:  ['encrypted-payload', 'tls-callback', 'high-entropy-rdata'],
    talonQuality:   'medium',
    notes:          'See flareauth.exe',
    tags:           ['packer-suspected', 'crypto-routines', 'custom'],
    expectedClass:  null,
  },
  '10000.exe': {
    nestVerdict:    'UNKNOWN',
    nestConfidence: null,
    strikeSignals:  [],
    talonQuality:   'n/a-size-exceeded',
    notes:          '1.1 GB — exceeds 512 MB nest_cli size limit. Likely padded CTF binary. SHA-256 not computed.',
    tags:           ['custom'],
    expectedClass:  null,
  },
  'keygenme.exe': {
    nestVerdict:    'MALICIOUS',
    nestConfidence: 88,
    strikeSignals:  ['code-injection-triad', 'process-hollowing', 'process-memory-read', 'resource-extraction', 'dynamic-load', 'target-creation', 'persistence-adjacent', 'protect-change'],
    talonQuality:   'medium-high',
    notes:          'VirtualAllocEx + WriteProcessMemory + CreateRemoteThread (injection triad). GetThreadContext + SetThreadContext + ResumeThread (process hollowing). 2.74 MB .rsrc encrypted payload. GCC/MinGW with 1045 debug symbols. Attack chain: CreateProcessA (suspended) → extract .rsrc → GetProcAddress → VirtualAllocEx → WriteProcessMemory → SetThreadContext → ResumeThread.',
    tags:           ['dropper', 'loader', 'custom'],
    expectedClass:  'malicious',
  },
};

// ── Types ──────────────────────────────────────────────────────────────────────

interface ChallengeEntry {
  sha256:             string | null;
  binaryPath:         string;
  filename:           string;
  label:              'CHALLENGE';
  groundTruth:        'challenge';
  sizeBytes:          number;
  sizeLimitExceeded:  boolean;
  isRuntimeCompanion: boolean;
  nestVerdict:        string | null;
  nestConfidence:     number | null;
  strikeSignals:      string[];
  talonQuality:       string | null;
  expectedClass:      string | null;
  tags:               string[];
  notes:              string;
  addedAt:            string;
}

interface CorpusResults {
  version:      1;
  generatedAt:  string;
  source:       string;
  totalEntries: number;
  entries:      ChallengeEntry[];
}

// ── Helpers ────────────────────────────────────────────────────────────────────

function sha256File(filePath: string): string {
  const hash = crypto.createHash('sha256');
  const data = fs.readFileSync(filePath);
  hash.update(data);
  return hash.digest('hex');
}

function scanDir(dir: string): string[] {
  const results: string[] = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      results.push(...scanDir(full));
    } else if (entry.isFile()) {
      const ext = path.extname(entry.name).toLowerCase();
      if (SKIP_EXTS.has(ext)) continue;
      if (BINARY_EXTS.has(ext)) results.push(full);
    }
  }
  return results;
}

function lookupMeta(filename: string) {
  const lower = filename.toLowerCase();
  if (KNOWN_METADATA[lower]) return KNOWN_METADATA[lower];
  // Fuzzy match: 'FlareAuthenticator.exe' → 'flareauth.exe' prefix
  if (lower.startsWith('flareauth')) return KNOWN_METADATA['flareauth.exe'];
  return null;
}

// ── Main ───────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const challengesDir = process.argv[2] ?? 'D:\\Project\\HexHawk\\Challenges';
  const outputPath    = process.argv[3] ??
    path.join(path.dirname(__dirname), 'corpus', 'results.json');

  // Ensure output directory exists
  const outputDir = path.dirname(outputPath);
  if (!fs.existsSync(outputDir)) fs.mkdirSync(outputDir, { recursive: true });

  console.log(`Scanning: ${challengesDir}`);
  const files = scanDir(challengesDir);
  console.log(`Found ${files.length} binary file(s)`);

  const now = new Date().toISOString();
  const entries: ChallengeEntry[] = [];

  for (const filePath of files) {
    const filename = path.basename(filePath);
    const lower    = filename.toLowerCase();
    const stat     = fs.statSync(filePath);
    const isCompanion = KNOWN_RUNTIME_DLLS.has(lower);
    const tooLarge    = stat.size > SIZE_LIMIT_BYTES;

    let sha: string | null = null;
    if (!tooLarge) {
      process.stdout.write(`  Hashing ${filename} (${(stat.size / 1024 / 1024).toFixed(1)} MB)… `);
      try {
        sha = sha256File(filePath);
        console.log(sha.slice(0, 16) + '…');
      } catch (e) {
        console.log(`FAILED: ${(e as Error).message}`);
      }
    } else {
      console.log(`  Skipping hash for ${filename} (${(stat.size / 1024 / 1024).toFixed(0)} MB > limit)`);
    }

    const meta = lookupMeta(filename);

    entries.push({
      sha256:             sha,
      binaryPath:         filePath,
      filename,
      label:              'CHALLENGE',
      groundTruth:        'challenge',
      sizeBytes:          stat.size,
      sizeLimitExceeded:  tooLarge,
      isRuntimeCompanion: isCompanion,
      nestVerdict:        isCompanion ? 'CLEAN' : (meta?.nestVerdict ?? null),
      nestConfidence:     isCompanion ? 100 : (meta?.nestConfidence ?? null),
      strikeSignals:      isCompanion ? [] : (meta?.strikeSignals ?? []),
      talonQuality:       isCompanion ? 'n/a-runtime-dll' : (meta?.talonQuality ?? null),
      expectedClass:      isCompanion ? 'clean' : (meta?.expectedClass ?? null),
      tags:               isCompanion
        ? ['system-binary', 'custom']
        : (meta?.tags ?? ['custom']),
      notes: isCompanion
        ? `Known runtime companion DLL (${filename}). Bundled with FlareAuthenticator challenge; not the challenge target.`
        : (meta?.notes ?? ''),
      addedAt: now,
    });
  }

  const results: CorpusResults = {
    version:      1,
    generatedAt:  now,
    source:       challengesDir,
    totalEntries: entries.length,
    entries,
  };

  fs.writeFileSync(outputPath, JSON.stringify(results, null, 2), 'utf8');

  const analysable = entries.filter(e => !e.sizeLimitExceeded && !e.isRuntimeCompanion);
  const withHash   = entries.filter(e => e.sha256 !== null);
  console.log(`\nWrote ${entries.length} entries → ${outputPath}`);
  console.log(`  ${withHash.length} hashed, ${entries.length - withHash.length} skipped (size limit)`);
  console.log(`  ${analysable.length} primary challenge binaries, ${entries.length - analysable.length} companion/skipped`);
}

main().catch(err => {
  console.error('ingest-challenges failed:', err);
  process.exit(1);
});
