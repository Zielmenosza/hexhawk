/**
 * binaryDiffEngine — Binary Version Comparison & Diff Engine
 *
 * Compares two binary analysis snapshots and surfaces semantic differences:
 *
 *   - Function changes: added, removed, modified (size, complexity, patterns)
 *   - CFG changes: added/removed basic blocks, edge mutations
 *   - String changes: added, removed
 *   - Import changes: added, removed
 *   - Signal/capability changes: new threats, resolved threats, weight shifts
 *
 * Design: pure TypeScript — no Tauri calls. All data is fed in as snapshots
 * collected by BinaryDiffPanel via the standard invoke() path.
 *
 * Function matching algorithm (priority order):
 *   1. Exact address match (same entry-point VA in both binaries)
 *   2. Size + complexity match within 10% (structural similarity)
 *
 * This intentionally does NOT do byte-level diffing (that's a hex tool job).
 * The goal is semantic diff: what capabilities appeared, what logic changed,
 * what new threat signals fire in the patched version.
 */

import type { BinaryVerdictResult, CorrelatedSignal } from './correlationEngine';

// ─── Snapshot types ────────────────────────────────────────────────────────────

/**
 * A snapshot of all analysis data for one binary.
 * BinaryDiffPanel collects these from Tauri before calling diffSnapshots().
 */
export interface BinarySnapshot {
  /** Absolute path to the binary (for display) */
  path: string;
  /** User-provided label, e.g. "v1.2.3" or "Original" */
  label: string;

  // ── From inspect_file_metadata
  fileSize:     number;
  fileType:     string;
  architecture: string;
  sha256:       string;
  sections:     Array<{ name: string; file_size: number; virtual_address: number; entropy: number }>;
  imports:      Array<{ name: string; library: string }>;
  exports:      Array<{ name: string; address: number }>;

  // ── From find_strings
  strings:      Array<{ text: string; offset: number; kind: string }>;

  // ── From disassemble_file_range — reduced to function map
  functions:    FunctionSnapshot[];

  // ── From build_cfg
  cfgBlocks:    CfgBlockSnapshot[];

  // ── Computed by GYRE correlationEngine
  verdict:      BinaryVerdictResult;
}

export interface FunctionSnapshot {
  /** Entry-point virtual address */
  address:         number;
  /** Optional symbol name (from exports or debug info) */
  name?:           string;
  /** Size in bytes */
  size:            number;
  /** Number of instructions */
  instructionCount: number;
  /** Cyclomatic-style complexity (branch count + 1) */
  complexity:      number;
  /** Mnemonic histogram key e.g. "call:3,jne:2,mov:12" — used for similarity */
  mnemonicKey:     string;
  /** Suspicious pattern types present in this function */
  patterns:        string[];
  /** Whether this function contains any loop */
  hasLoops:        boolean;
}

export interface CfgBlockSnapshot {
  id:            string;
  start:         number;
  end:           number;
  instructionCount: number;
  blockType:     string;  // 'entry' | 'normal' | 'exit' | 'loop' | 'external'
  outEdges:      number;  // number of outgoing edges
}

// ─── Diff result types ─────────────────────────────────────────────────────────

export type DiffStatus = 'added' | 'removed' | 'modified' | 'unchanged';

export interface FunctionDiff {
  status:              DiffStatus;
  /** Address in whichever binary has it (base if removed, target if added) */
  address:             number;
  baseAddress?:        number;
  targetAddress?:      number;
  name?:               string;
  sizeChange:          number;  // target - base (bytes); 0 if not modified
  complexityChange:    number;  // target - base
  instructionDelta:    number;  // target - base
  /** New suspicious pattern types that appear in target but not base */
  addedPatterns:       string[];
  /** Suspicious pattern types present in base but gone in target */
  removedPatterns:     string[];
  /** Structural similarity score 0–1 (1 = identical mnemonics) */
  similarity:          number;
  /** Was a new loop added? */
  loopAdded:           boolean;
  /** Was an existing loop removed? */
  loopRemoved:         boolean;
}

export interface StringDiff {
  status:        'added' | 'removed' | 'unchanged';
  text:          string;
  kind:          string;
  baseOffset?:   number;
  targetOffset?: number;
}

export interface ImportDiff {
  status:  'added' | 'removed' | 'unchanged';
  name:    string;
  library: string;
}

export interface SignalDiff {
  status:       'added' | 'removed' | 'modified';
  signalId:     string;
  finding:      string;
  baseWeight?:  number;
  targetWeight?: number;
  /** Positive = more threatening; negative = less threatening */
  weightChange: number;
}

export interface CfgBlockDiff {
  status:       DiffStatus;
  blockId:      string;
  start:        number;
  end:          number;
  blockType:    string;
  sizeChange:   number;  // instruction delta
  edgeChange:   number;  // outEdge delta
}

export interface BinaryDiffSummary {
  addedFunctions:    number;
  removedFunctions:  number;
  modifiedFunctions: number;
  unchangedFunctions: number;

  addedStrings:      number;
  removedStrings:    number;

  addedImports:      number;
  removedImports:    number;

  addedCfgBlocks:    number;
  removedCfgBlocks:  number;
  modifiedCfgBlocks: number;

  addedSignals:      number;
  removedSignals:    number;
  modifiedSignals:   number;

  threatScoreChange: number;  // target.threatScore - base.threatScore
  confidenceChange:  number;

  newCapabilities:   string[];   // Mythos/YARA signal IDs added
  resolvedCapabilities: string[];  // signal IDs removed
}

export type DiffRiskAssessment =
  | 'escalated'   // threat score increased ≥ 5 or new critical signals
  | 'reduced'     // threat score decreased ≥ 5 and no new critical signals
  | 'neutral';    // small change

export interface BinaryDiffResult {
  base:   { path: string; label: string; sha256: string; threatScore: number; fileSize: number };
  target: { path: string; label: string; sha256: string; threatScore: number; fileSize: number };

  summary:      BinaryDiffSummary;
  risk:         DiffRiskAssessment;

  functionDiffs:  FunctionDiff[];
  stringDiffs:    StringDiff[];
  importDiffs:    ImportDiff[];
  signalDiffs:    SignalDiff[];
  cfgBlockDiffs:  CfgBlockDiff[];

  /** Functions most likely to contain the interesting change, sorted by |weightedDelta| */
  hotspots:     HotspotFunction[];
}

export interface HotspotFunction {
  address:        number;
  name?:          string;
  reason:         string;  // "new patterns: tight_loop, indirect_call" etc.
  severity:       'critical' | 'high' | 'medium' | 'low';
  addedPatterns:  string[];
}

// ─── Core diff algorithm ───────────────────────────────────────────────────────

/**
 * Compare two snapshots and produce a full diff result.
 *
 * @param base   — the "before" binary (original / old version)
 * @param target — the "after"  binary (patched / new version)
 */
export function diffSnapshots(base: BinarySnapshot, target: BinarySnapshot): BinaryDiffResult {
  const functionDiffs  = diffFunctions(base.functions, target.functions);
  const stringDiffs    = diffStrings(base.strings, target.strings);
  const importDiffs    = diffImports(base.imports, target.imports);
  const signalDiffs    = diffSignals(base.verdict.signals, target.verdict.signals);
  const cfgBlockDiffs  = diffCfgBlocks(base.cfgBlocks, target.cfgBlocks);

  const threatScoreChange = target.verdict.threatScore - base.verdict.threatScore;
  const confidenceChange  = (target.verdict.confidence ?? 0) - (base.verdict.confidence ?? 0);

  const newCaps      = signalDiffs.filter(s => s.status === 'added').map(s => s.signalId);
  const resolvedCaps = signalDiffs.filter(s => s.status === 'removed').map(s => s.signalId);

  const summary: BinaryDiffSummary = {
    addedFunctions:    functionDiffs.filter(f => f.status === 'added').length,
    removedFunctions:  functionDiffs.filter(f => f.status === 'removed').length,
    modifiedFunctions: functionDiffs.filter(f => f.status === 'modified').length,
    unchangedFunctions:functionDiffs.filter(f => f.status === 'unchanged').length,
    addedStrings:      stringDiffs.filter(s => s.status === 'added').length,
    removedStrings:    stringDiffs.filter(s => s.status === 'removed').length,
    addedImports:      importDiffs.filter(i => i.status === 'added').length,
    removedImports:    importDiffs.filter(i => i.status === 'removed').length,
    addedCfgBlocks:    cfgBlockDiffs.filter(b => b.status === 'added').length,
    removedCfgBlocks:  cfgBlockDiffs.filter(b => b.status === 'removed').length,
    modifiedCfgBlocks: cfgBlockDiffs.filter(b => b.status === 'modified').length,
    addedSignals:      signalDiffs.filter(s => s.status === 'added').length,
    removedSignals:    signalDiffs.filter(s => s.status === 'removed').length,
    modifiedSignals:   signalDiffs.filter(s => s.status === 'modified').length,
    threatScoreChange,
    confidenceChange,
    newCapabilities:      newCaps,
    resolvedCapabilities: resolvedCaps,
  };

  const risk = assessRisk(summary, signalDiffs);
  const hotspots = buildHotspots(functionDiffs);

  return {
    base:   { path: base.path,   label: base.label,   sha256: base.sha256,   threatScore: base.verdict.threatScore,   fileSize: base.fileSize },
    target: { path: target.path, label: target.label, sha256: target.sha256, threatScore: target.verdict.threatScore, fileSize: target.fileSize },
    summary,
    risk,
    functionDiffs,
    stringDiffs,
    importDiffs,
    signalDiffs,
    cfgBlockDiffs,
    hotspots,
  };
}

// ─── Function diff ─────────────────────────────────────────────────────────────

function diffFunctions(base: FunctionSnapshot[], target: FunctionSnapshot[]): FunctionDiff[] {
  const results: FunctionDiff[] = [];

  // Build lookup maps
  const baseByAddr  = new Map(base.map(f  => [f.address, f]));
  const targetByAddr = new Map(target.map(f => [f.address, f]));
  const baseMatched = new Set<number>();
  const targetMatched = new Set<number>();

  // Pass 1: exact address matches
  for (const [addr, tf] of targetByAddr) {
    const bf = baseByAddr.get(addr);
    if (bf) {
      baseMatched.add(addr);
      targetMatched.add(addr);
      const diff = buildFunctionDiff(bf, tf);
      results.push(diff);
    }
  }

  // Pass 2: structural similarity for unmatched functions
  const unmatchedBase   = base.filter(f => !baseMatched.has(f.address));
  const unmatchedTarget = target.filter(f => !targetMatched.has(f.address));

  for (const tf of unmatchedTarget) {
    let bestMatch: FunctionSnapshot | null = null;
    let bestScore = 0;

    for (const bf of unmatchedBase) {
      if (baseMatched.has(bf.address)) continue;
      const score = structuralSimilarity(bf, tf);
      if (score > bestScore && score >= 0.70) {
        bestScore = score;
        bestMatch = bf;
      }
    }

    if (bestMatch) {
      baseMatched.add(bestMatch.address);
      targetMatched.add(tf.address);
      const diff = buildFunctionDiff(bestMatch, tf);
      // Override addresses since they didn't match exactly
      diff.baseAddress   = bestMatch.address;
      diff.targetAddress = tf.address;
      diff.address       = tf.address;
      results.push(diff);
    } else {
      // No match → added function
      results.push({
        status:           'added',
        address:          tf.address,
        targetAddress:    tf.address,
        name:             tf.name,
        sizeChange:       tf.size,
        complexityChange: tf.complexity,
        instructionDelta: tf.instructionCount,
        addedPatterns:    tf.patterns,
        removedPatterns:  [],
        similarity:       0,
        loopAdded:        tf.hasLoops,
        loopRemoved:      false,
      });
    }
  }

  // Pass 3: remaining base functions are removed
  for (const bf of base) {
    if (!baseMatched.has(bf.address)) {
      results.push({
        status:           'removed',
        address:          bf.address,
        baseAddress:      bf.address,
        name:             bf.name,
        sizeChange:       -bf.size,
        complexityChange: -bf.complexity,
        instructionDelta: -bf.instructionCount,
        addedPatterns:    [],
        removedPatterns:  bf.patterns,
        similarity:       0,
        loopAdded:        false,
        loopRemoved:      bf.hasLoops,
      });
    }
  }

  // Sort: modified + added first, then unchanged, then removed
  const ORDER: Record<DiffStatus, number> = { added: 0, modified: 1, removed: 3, unchanged: 4 };
  results.sort((a, b) => ORDER[a.status] - ORDER[b.status]);
  return results;
}

function buildFunctionDiff(base: FunctionSnapshot, target: FunctionSnapshot): FunctionDiff {
  const sim           = structuralSimilarity(base, target);
  const addedPatterns = target.patterns.filter(p => !base.patterns.includes(p));
  const removedPatterns = base.patterns.filter(p => !target.patterns.includes(p));
  const sizeChange    = target.size            - base.size;
  const complexityChange = target.complexity   - base.complexity;
  const instructionDelta = target.instructionCount - base.instructionCount;
  const loopAdded     = !base.hasLoops && target.hasLoops;
  const loopRemoved   = base.hasLoops && !target.hasLoops;

  const isModified = sizeChange !== 0 || complexityChange !== 0 ||
                     addedPatterns.length > 0 || removedPatterns.length > 0 ||
                     loopAdded || loopRemoved;

  return {
    status:           isModified ? 'modified' : 'unchanged',
    address:          target.address,
    baseAddress:      base.address,
    targetAddress:    target.address,
    name:             target.name ?? base.name,
    sizeChange,
    complexityChange,
    instructionDelta,
    addedPatterns,
    removedPatterns,
    similarity:       sim,
    loopAdded,
    loopRemoved,
  };
}

/**
 * Structural similarity: 0–1 score.
 * Weights: size (30%), complexity (20%), mnemonic histogram (50%).
 */
function structuralSimilarity(a: FunctionSnapshot, b: FunctionSnapshot): number {
  // Size proximity
  const maxSize = Math.max(a.size, b.size, 1);
  const sizeSim = 1 - Math.abs(a.size - b.size) / maxSize;

  // Complexity proximity
  const maxCx = Math.max(a.complexity, b.complexity, 1);
  const cxSim = 1 - Math.abs(a.complexity - b.complexity) / maxCx;

  // Mnemonic histogram similarity (Jaccard over tokens)
  const aTokens = parseMnemonicKey(a.mnemonicKey);
  const bTokens = parseMnemonicKey(b.mnemonicKey);
  const mnemonicSim = jaccardSimilarity(aTokens, bTokens);

  return sizeSim * 0.30 + cxSim * 0.20 + mnemonicSim * 0.50;
}

function parseMnemonicKey(key: string): Map<string, number> {
  const m = new Map<string, number>();
  if (!key) return m;
  for (const part of key.split(',')) {
    const [mnemonic, countStr] = part.split(':');
    if (mnemonic) m.set(mnemonic.trim(), parseInt(countStr ?? '1', 10));
  }
  return m;
}

function jaccardSimilarity(a: Map<string, number>, b: Map<string, number>): number {
  if (a.size === 0 && b.size === 0) return 1;
  const allKeys = new Set([...a.keys(), ...b.keys()]);
  let intersection = 0;
  let union = 0;
  for (const k of allKeys) {
    const av = a.get(k) ?? 0;
    const bv = b.get(k) ?? 0;
    intersection += Math.min(av, bv);
    union += Math.max(av, bv);
  }
  return union === 0 ? 1 : intersection / union;
}

// ─── String diff ───────────────────────────────────────────────────────────────

function diffStrings(
  base:   Array<{ text: string; offset: number; kind: string }>,
  target: Array<{ text: string; offset: number; kind: string }>,
): StringDiff[] {
  const baseTexts   = new Map(base.map(s   => [s.text, s]));
  const targetTexts = new Map(target.map(s => [s.text, s]));
  const results: StringDiff[] = [];

  // Added strings
  for (const [text, s] of targetTexts) {
    if (!baseTexts.has(text)) {
      results.push({ status: 'added', text, kind: s.kind, targetOffset: s.offset });
    } else {
      results.push({ status: 'unchanged', text, kind: s.kind, baseOffset: baseTexts.get(text)!.offset, targetOffset: s.offset });
    }
  }

  // Removed strings
  for (const [text, s] of baseTexts) {
    if (!targetTexts.has(text)) {
      results.push({ status: 'removed', text, kind: s.kind, baseOffset: s.offset });
    }
  }

  // Sort: added first, then removed, then unchanged
  const ORDER = { added: 0, removed: 1, unchanged: 2 };
  results.sort((a, b) => ORDER[a.status] - ORDER[b.status]);
  return results;
}

// ─── Import diff ───────────────────────────────────────────────────────────────

function diffImports(
  base:   Array<{ name: string; library: string }>,
  target: Array<{ name: string; library: string }>,
): ImportDiff[] {
  const baseSet   = new Set(base.map(i   => `${i.library}::${i.name}`));
  const targetSet = new Set(target.map(i => `${i.library}::${i.name}`));
  const results: ImportDiff[] = [];

  const targetByKey = new Map(target.map(i => [`${i.library}::${i.name}`, i]));
  const baseByKey   = new Map(base.map(i   => [`${i.library}::${i.name}`, i]));

  for (const [key, i] of targetByKey) {
    if (!baseSet.has(key)) {
      results.push({ status: 'added', name: i.name, library: i.library });
    } else {
      results.push({ status: 'unchanged', name: i.name, library: i.library });
    }
  }
  for (const [key, i] of baseByKey) {
    if (!targetSet.has(key)) {
      results.push({ status: 'removed', name: i.name, library: i.library });
    }
  }

  const ORDER = { added: 0, removed: 1, unchanged: 2 };
  results.sort((a, b) => ORDER[a.status] - ORDER[b.status]);
  return results;
}

// ─── Signal diff ───────────────────────────────────────────────────────────────

function diffSignals(base: CorrelatedSignal[], target: CorrelatedSignal[]): SignalDiff[] {
  const baseById   = new Map(base.map(s   => [s.id, s]));
  const targetById = new Map(target.map(s => [s.id, s]));
  const results: SignalDiff[] = [];

  for (const [id, ts] of targetById) {
    const bs = baseById.get(id);
    if (!bs) {
      results.push({ status: 'added', signalId: id, finding: ts.finding, targetWeight: ts.weight, weightChange: ts.weight });
    } else {
      const weightChange = ts.weight - bs.weight;
      if (weightChange !== 0) {
        results.push({ status: 'modified', signalId: id, finding: ts.finding, baseWeight: bs.weight, targetWeight: ts.weight, weightChange });
      }
    }
  }
  for (const [id, bs] of baseById) {
    if (!targetById.has(id)) {
      results.push({ status: 'removed', signalId: id, finding: bs.finding, baseWeight: bs.weight, weightChange: -bs.weight });
    }
  }

  // Sort by |weightChange| descending
  results.sort((a, b) => Math.abs(b.weightChange) - Math.abs(a.weightChange));
  return results;
}

// ─── CFG block diff ────────────────────────────────────────────────────────────

function diffCfgBlocks(base: CfgBlockSnapshot[], target: CfgBlockSnapshot[]): CfgBlockDiff[] {
  const baseByStart   = new Map(base.map(b   => [b.start, b]));
  const targetByStart = new Map(target.map(b => [b.start, b]));
  const results: CfgBlockDiff[] = [];

  for (const [start, tb] of targetByStart) {
    const bb = baseByStart.get(start);
    if (!bb) {
      results.push({ status: 'added', blockId: tb.id, start: tb.start, end: tb.end, blockType: tb.blockType, sizeChange: tb.instructionCount, edgeChange: tb.outEdges });
    } else {
      const sizeChange = tb.instructionCount - bb.instructionCount;
      const edgeChange = tb.outEdges - bb.outEdges;
      const isModified = sizeChange !== 0 || edgeChange !== 0 || tb.blockType !== bb.blockType;
      results.push({ status: isModified ? 'modified' : 'unchanged', blockId: tb.id, start: tb.start, end: tb.end, blockType: tb.blockType, sizeChange, edgeChange });
    }
  }
  for (const [start, bb] of baseByStart) {
    if (!targetByStart.has(start)) {
      results.push({ status: 'removed', blockId: bb.id, start: bb.start, end: bb.end, blockType: bb.blockType, sizeChange: -bb.instructionCount, edgeChange: -bb.outEdges });
    }
  }

  const ORDER: Record<DiffStatus, number> = { added: 0, modified: 1, removed: 2, unchanged: 3 };
  results.sort((a, b) => ORDER[a.status] - ORDER[b.status]);
  return results;
}

// ─── Risk assessment ───────────────────────────────────────────────────────────

function assessRisk(summary: BinaryDiffSummary, signalDiffs: SignalDiff[]): DiffRiskAssessment {
  const hasCriticalNewSignal = signalDiffs.some(
    s => s.status === 'added' && (s.targetWeight ?? 0) >= 7
  );
  if (hasCriticalNewSignal || summary.threatScoreChange >= 5) return 'escalated';
  if (summary.threatScoreChange <= -5 && !hasCriticalNewSignal) return 'reduced';
  return 'neutral';
}

// ─── Hotspot detection ─────────────────────────────────────────────────────────

function buildHotspots(functionDiffs: FunctionDiff[]): HotspotFunction[] {
  const hotspots: HotspotFunction[] = [];

  for (const fd of functionDiffs) {
    if (fd.status === 'unchanged') continue;
    if (fd.addedPatterns.length === 0 && fd.status !== 'added') continue;

    const severity = fd.addedPatterns.some(p => ['indirect_call', 'obfuscation', 'tight_loop'].includes(p))
      ? 'critical'
      : fd.addedPatterns.length > 0 || fd.complexityChange > 5
        ? 'high'
        : fd.complexityChange > 2
          ? 'medium'
          : 'low';

    const reasons: string[] = [];
    if (fd.addedPatterns.length > 0) reasons.push(`new patterns: ${fd.addedPatterns.join(', ')}`);
    if (fd.loopAdded) reasons.push('loop introduced');
    if (fd.complexityChange > 3) reasons.push(`complexity +${fd.complexityChange}`);
    if (fd.status === 'added') reasons.push('new function');

    hotspots.push({
      address:       fd.address,
      name:          fd.name,
      reason:        reasons.join('; ') || 'code changed',
      severity,
      addedPatterns: fd.addedPatterns,
    });
  }

  const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
  hotspots.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
  return hotspots.slice(0, 20); // top 20
}

// ─── Snapshot builder helpers ──────────────────────────────────────────────────

/**
 * Build a FunctionSnapshot from disassembled instructions for one function.
 * Called by BinaryDiffPanel after collecting disassembly from Tauri.
 */
export function buildFunctionSnapshot(
  address: number,
  instructions: Array<{ address: number; mnemonic: string; operands: string }>,
  name?: string,
): FunctionSnapshot {
  if (instructions.length === 0) {
    return { address, name, size: 0, instructionCount: 0, complexity: 1, mnemonicKey: '', patterns: [], hasLoops: false };
  }

  const mnemonicCounts = new Map<string, number>();
  let complexity = 1;
  let hasLoops = false;

  for (const instr of instructions) {
    const m = instr.mnemonic.toLowerCase();
    mnemonicCounts.set(m, (mnemonicCounts.get(m) ?? 0) + 1);
    if (/^j[a-z]+$/.test(m) && m !== 'jmp') complexity++;
    if (m === 'jmp') {
      // Back-edge heuristic: if target < current address, likely a loop
      const target = parseInt(instr.operands.replace('0x', ''), 16);
      if (!isNaN(target) && target < instr.address) hasLoops = true;
    }
  }

  const mnemonicKey = [...mnemonicCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 15)
    .map(([m, c]) => `${m}:${c}`)
    .join(',');

  const first = instructions[0];
  const last  = instructions[instructions.length - 1];
  const size  = last.address - first.address + 1; // approximate

  // Simple pattern detection
  const patterns: string[] = [];
  const indirectCalls = instructions.filter(i => i.mnemonic === 'call' && /\[/.test(i.operands));
  if (indirectCalls.length > 0) patterns.push('indirect_call');
  if (hasLoops) patterns.push('tight_loop');

  return { address, name, size, instructionCount: instructions.length, complexity, mnemonicKey, patterns, hasLoops };
}

/**
 * Extract function boundaries from a flat disassembly list.
 * Groups consecutive instructions into functions using prologue detection.
 * Returns one entry per detected function boundary.
 */
export function extractFunctions(
  instructions: Array<{ address: number; mnemonic: string; operands: string }>,
  exports: Array<{ name: string; address: number }>,
): FunctionSnapshot[] {
  if (instructions.length === 0) return [];

  const exportByAddr = new Map(exports.map(e => [e.address, e.name]));
  const functions: FunctionSnapshot[] = [];
  let currentStart = 0;
  const prologues = new Set(['push', 'sub', 'mov', 'endbr64', 'endbr32']);

  for (let i = 0; i < instructions.length; i++) {
    const instr = instructions[i];
    const isPrologue = prologues.has(instr.mnemonic.toLowerCase()) && exportByAddr.has(instr.address);
    const isReturn   = ['ret', 'retn', 'retf'].includes(instr.mnemonic.toLowerCase());

    if ((isPrologue && i > currentStart) || (isReturn && i + 1 < instructions.length)) {
      const slice = instructions.slice(currentStart, isReturn ? i + 1 : i);
      if (slice.length >= 2) {
        const name = exportByAddr.get(slice[0].address);
        functions.push(buildFunctionSnapshot(slice[0].address, slice, name));
      }
      if (!isReturn) currentStart = i;
      else currentStart = i + 1;
    }
  }

  // Remaining instructions
  const remaining = instructions.slice(currentStart);
  if (remaining.length >= 2) {
    const name = exportByAddr.get(remaining[0].address);
    functions.push(buildFunctionSnapshot(remaining[0].address, remaining, name));
  }

  return functions;
}

/**
 * Build CfgBlockSnapshot array from a Tauri CFG response.
 */
export function buildCfgBlockSnapshots(
  nodes: Array<{ id: string; start?: number; end?: number; instruction_count?: number; block_type?: string }>,
  edges: Array<{ source: string; target: string }>,
): CfgBlockSnapshot[] {
  const edgesBySource = new Map<string, number>();
  for (const e of edges) {
    edgesBySource.set(e.source, (edgesBySource.get(e.source) ?? 0) + 1);
  }

  return nodes
    .filter(n => n.start !== undefined)
    .map(n => ({
      id:               n.id,
      start:            n.start!,
      end:              n.end ?? n.start!,
      instructionCount: n.instruction_count ?? 0,
      blockType:        n.block_type ?? 'normal',
      outEdges:         edgesBySource.get(n.id) ?? 0,
    }));
}
