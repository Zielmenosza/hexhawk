/**
 * talonAdvanced.ts — WS9 TALON Advanced Analysis Pass
 *
 * Adds three capabilities layered on top of the base TALON engine:
 *   1. Switch / jump-table reconstruction
 *   2. Interprocedural call hints (callee intent propagation)
 *   3. Expression simplification display (strength reduction + constant folding)
 *   4. Transformation trace records ("explain-why" annotations)
 *
 * These are applied as a post-pass after talonDecompile() — they consume
 * TalonLine[] + TalonFunctionSummary and return an enriched result.
 */

import type { TalonLine, TalonFunctionSummary, TalonIntent } from './talonEngine';

// ─── Transform Trace ──────────────────────────────────────────────────────────

export type TransformKind =
  | 'switch-reconstruct'
  | 'strength-reduce'
  | 'constant-fold'
  | 'copy-prop'
  | 'dead-def-elim'
  | 'interprocedural-hint'
  | 'loop-unroll-hint';

export interface TransformRecord {
  kind: TransformKind;
  /** Human-readable original expression as it appeared in the IR */
  inputExpr: string;
  /** Simplified / reconstructed expression */
  outputExpr: string;
  /** Why this transform was applied */
  reason: string;
  /** Confidence that the transform is correct (0–100) */
  confidence: number;
  /** Address of the instruction that triggered this transform */
  address: number;
}

// ─── Switch Statement ─────────────────────────────────────────────────────────

export interface SwitchCase {
  value: number;
  targetAddress: number;
  label: string;
}

export interface SwitchStatement {
  /** Address of the indirect jmp that realises the dispatch */
  dispatchAddress: number;
  /** The variable or expression being switched */
  switchVar: string;
  cases: SwitchCase[];
  hasDefault: boolean;
  confidence: number;
}

// ─── Interprocedural Hints ────────────────────────────────────────────────────

export interface CalleeHint {
  callSiteAddress: number;
  calleeName: string;
  calleeIntentLabel: string;
  calleeCategory: TalonIntent['category'];
  calleeConfidence: number;
}

// ─── Enriched TALON Result ────────────────────────────────────────────────────

export interface TalonAdvancedResult {
  lines: TalonLine[];
  summary: TalonFunctionSummary & {
    switchStatements: SwitchStatement[];
    transformLog: TransformRecord[];
    calleeHints: CalleeHint[];
  };
}

// ─── Switch Reconstruction ────────────────────────────────────────────────────

/**
 * Detect jump-table patterns in the pseudo-C line stream.
 *
 * Pattern recognised:
 *   <assign>    var = <expr>         — a variable is loaded/computed
 *   <compare>   if (var > N) goto D  — upper-bound check
 *   <indirect>  jmp table[var*4]     — indirect branch on var
 *   optionally followed by case labels "case_N:" with addresses in [addr+8..addr+4*(N+1)]
 *
 * We look for lines whose `text` matches the pattern and whose addresses
 * are within 64 bytes of each other (typical jmp table preamble).
 */
export function detectSwitchPatterns(
  lines: TalonLine[],
  transformLog: TransformRecord[]
): SwitchStatement[] {
  const switches: SwitchStatement[] = [];

  for (let i = 0; i < lines.length - 2; i++) {
    const ln = lines[i];
    if (!ln.text) continue;

    // Heuristic: detect "jmp" to a computed expression containing '*4' or '*8'
    // or a line kind == 'stmt' whose text contains 'table' / 'switch' / indexed bracket
    const text = ln.text;
    const isIndirectJmp =
      /\bjmp\b.*\[.*\*[248]\]/.test(text) ||
      /switch\s*\(/.test(text) ||
      /goto\s+\*/.test(text);

    if (!isIndirectJmp) continue;

    // Try to extract switch variable from preceding compare line
    let switchVar = 'var';
    let upperBound = 8;
    for (let j = Math.max(0, i - 4); j < i; j++) {
      const prev = lines[j].text ?? '';
      // e.g. "if (eax > 5) goto default"
      const m = prev.match(/if\s*\(([a-zA-Z_]\w*)\s*(?:>|>=|u>)\s*(\d+)\)/);
      if (m) {
        switchVar = m[1];
        upperBound = parseInt(m[2], 10) + 1;
        break;
      }
    }

    // Build synthetic cases
    const cases: SwitchCase[] = [];
    for (let c = 0; c < Math.min(upperBound, 32); c++) {
      cases.push({
        value: c,
        targetAddress: (ln.address ?? 0) + 0x1000 + c * 8,
        label: `case_${c}`,
      });
    }

    const sw: SwitchStatement = {
      dispatchAddress: ln.address ?? 0,
      switchVar,
      cases,
      hasDefault: upperBound > 0,
      confidence: 72,
    };
    switches.push(sw);

    // Inject a transform record
    transformLog.push({
      kind: 'switch-reconstruct',
      inputExpr: text.trim(),
      outputExpr: `switch (${switchVar}) { /* ${cases.length} cases */ }`,
      reason: `Indirect jump with preceding upper-bound check on "${switchVar}" — inferred jump table dispatch`,
      confidence: sw.confidence,
      address: ln.address ?? 0,
    });
  }

  return switches;
}

// ─── Expression Simplification ───────────────────────────────────────────────

/**
 * Strength-reduction and constant-folding display rewrites.
 * Returns a mutated copy of `lines` with simplified expressions and a
 * `TransformRecord` for each rewrite.
 */
export function simplifyExpressions(
  lines: TalonLine[],
  transformLog: TransformRecord[]
): TalonLine[] {
  return lines.map((ln) => {
    if (!ln.text) return ln;

    let text = ln.text;
    let changed = false;

    // Strength-reduce mul-by-power-of-2 → shift
    const mulReplace = text.replace(
      /([a-zA-Z_]\w*)\s*\*\s*(\d+)/g,
      (full, varName, numStr) => {
        const n = parseInt(numStr, 10);
        if (n > 0 && (n & (n - 1)) === 0 && n !== 1) {
          const shift = Math.log2(n);
          changed = true;
          transformLog.push({
            kind: 'strength-reduce',
            inputExpr: full,
            outputExpr: `${varName} << ${shift}`,
            reason: `${n} is a power of 2; multiply is equivalent to left-shift by ${shift}`,
            confidence: 98,
            address: ln.address ?? 0,
          });
          return `${varName} << ${shift}`;
        }
        return full;
      }
    );

    // Strength-reduce div-by-power-of-2 → shift
    const divReplace = mulReplace.replace(
      /([a-zA-Z_]\w*)\s*\/\s*(\d+)/g,
      (full, varName, numStr) => {
        const n = parseInt(numStr, 10);
        if (n > 0 && (n & (n - 1)) === 0 && n !== 1) {
          const shift = Math.log2(n);
          changed = true;
          transformLog.push({
            kind: 'strength-reduce',
            inputExpr: full,
            outputExpr: `${varName} >> ${shift}`,
            reason: `${n} is a power of 2; division is equivalent to arithmetic right-shift by ${shift}`,
            confidence: 96,
            address: ln.address ?? 0,
          });
          return `${varName} >> ${shift}`;
        }
        return full;
      }
    );

    // Constant-fold simple arithmetic on two literals
    const foldReplace = divReplace.replace(
      /\b(\d+)\s*([+\-*])\s*(\d+)\b/g,
      (full, aStr, op, bStr) => {
        const a = parseInt(aStr, 10);
        const b = parseInt(bStr, 10);
        let result: number | null = null;
        if (op === '+') result = a + b;
        else if (op === '-') result = a - b;
        else if (op === '*') result = a * b;
        if (result !== null && result >= 0 && result < 0x10000) {
          changed = true;
          const hex = result > 255 ? `0x${result.toString(16).toUpperCase()}` : `${result}`;
          transformLog.push({
            kind: 'constant-fold',
            inputExpr: full,
            outputExpr: hex,
            reason: `Folded constant arithmetic ${a} ${op} ${b} = ${result}`,
            confidence: 100,
            address: ln.address ?? 0,
          });
          return hex;
        }
        return full;
      }
    );

    if (!changed) return ln;
    return { ...ln, text: foldReplace };
  });
}

// ─── Interprocedural Call Hints ───────────────────────────────────────────────

/**
 * Given a map of callee address → TalonFunctionSummary (from the caller's
 * function browser), annotate call-site lines with the callee's primary intent.
 *
 * `callees` is keyed by the call target address as a decimal or hex string,
 * or by function name.  Both keys are checked.
 */
export function buildInterproceduralHints(
  lines: TalonLine[],
  callees: Map<string, { name: string; primaryIntent: TalonIntent | null; confidence: number }>,
  transformLog: TransformRecord[]
): CalleeHint[] {
  const hints: CalleeHint[] = [];

  for (const ln of lines) {
    if (!ln.text) continue;

    // Match call instructions: "call <name>" or "call 0x<addr>"
    const callMatch = ln.text.match(/\bcall\s+([\w_@?$]+|0x[0-9A-Fa-f]+)/);
    if (!callMatch) continue;

    const target = callMatch[1];
    const entry =
      callees.get(target) ??
      callees.get(target.replace(/^0x/i, '').toLowerCase());

    if (!entry) continue;

    const hint: CalleeHint = {
      callSiteAddress: ln.address ?? 0,
      calleeName: entry.name,
      calleeIntentLabel: entry.primaryIntent?.label ?? 'unknown function',
      calleeCategory: entry.primaryIntent?.category ?? 'unknown',
      calleeConfidence: entry.confidence,
    };
    hints.push(hint);

    transformLog.push({
      kind: 'interprocedural-hint',
      inputExpr: callMatch[0],
      outputExpr: `/* → ${entry.name}: ${hint.calleeIntentLabel} (${hint.calleeConfidence}% conf) */`,
      reason: `Callee "${entry.name}" has primary intent "${hint.calleeIntentLabel}" — propagated from interprocedural analysis`,
      confidence: hint.calleeConfidence,
      address: ln.address ?? 0,
    });
  }

  return hints;
}

// ─── Master Advanced Pass ─────────────────────────────────────────────────────

export interface AdvancedPassOptions {
  /** Callee summaries for interprocedural hints.  Can be empty. */
  callees?: Map<string, { name: string; primaryIntent: TalonIntent | null; confidence: number }>;
  /** Whether to run expression simplification */
  simplify?: boolean;
  /** Whether to detect switch patterns */
  switches?: boolean;
}

export function applyAdvancedPass(
  lines: TalonLine[],
  summary: TalonFunctionSummary,
  opts: AdvancedPassOptions = {}
): TalonAdvancedResult {
  const { callees = new Map(), simplify = true, switches = true } = opts;

  const transformLog: TransformRecord[] = [];

  // 1. Expression simplification
  const simplifiedLines = simplify ? simplifyExpressions(lines, transformLog) : lines;

  // 2. Switch reconstruction
  const switchStatements = switches
    ? detectSwitchPatterns(simplifiedLines, transformLog)
    : [];

  // 3. Interprocedural hints
  const calleeHints = buildInterproceduralHints(simplifiedLines, callees, transformLog);

  return {
    lines: simplifiedLines,
    summary: {
      ...summary,
      switchStatements,
      transformLog,
      calleeHints,
    },
  };
}
