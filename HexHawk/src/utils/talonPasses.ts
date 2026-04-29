/**
 * talonPasses.ts — TALON Pseudo-C Quality Improvement Passes
 *
 * Three pure post-passes layered on top of talonEngine / talonAdvanced:
 *
 *   1. canonicalizeLoops            — normalize while/do-while/for patterns from CFG back-edges
 *   2. inferTypes                   — infer int/pointer/array/char from SSA usage patterns
 *   3. detectSwitchPatternsEnhanced — switch reconstruction improved with type hints
 *
 * Design:
 *   • All functions are pure — no side effects, no module-level mutable state.
 *   • Input arrays / objects are never mutated; copies are returned.
 *   • All exported types are available for downstream consumers (including correlationEngine).
 *   • The correlationEngine signal integration in talonEngine.ts is not altered by these passes;
 *     they operate as optional post-passes on TalonLine[] / IRBlock[].
 */

import type { IRBlock, IRValue } from './decompilerEngine';
import type { SSAForm } from './ssaTransform';
import type { TalonLine } from './talonEngine';
import type { NaturalLoop } from './cfgSignalExtractor';
import type { TransformRecord, SwitchStatement, SwitchCase } from './talonAdvanced';

// ─── Pass 1: Loop Canonicalization ────────────────────────────────────────────

/** The canonical form a loop was normalized into. */
export type CanonLoopKind = 'for' | 'while' | 'do-while' | 'infinite' | 'unchanged';

/**
 * Records one loop canonicalization rewrite for audit / display purposes.
 * Emitted into the TransformRecord log as `kind: 'loop-unroll-hint'`.
 */
export interface LoopCanonRecord {
  /** Start address of the loop header block. */
  headerAddress: number;
  /** The NaturalLoop classification that triggered the rewrite. */
  classification: NaturalLoop['classification'];
  /** The resulting canonical form. */
  canonKind: CanonLoopKind;
  /** Original text of the control line before rewriting. */
  originalText: string;
  /** Rewritten text (equals originalText when canonKind === 'unchanged' or 'do-while'). */
  rewrittenText: string;
}

/**
 * Normalize loop shapes in the pseudo-C line stream using NaturalLoop metadata.
 *
 * Rewrites applied:
 *   - `infinite`  : `while (…)` at the header → `for (;;)` when the loop
 *                   classifier determined it is unbounded.
 *   - `for`       : detect adjacent init assignment + `while (var OP bound)` header
 *                   + trailing `var++`/`var += N` → `for (var = init; cond; incr)`.
 *   - `do-while`  : prepend a `// [do-while pattern]` intent-comment before the header line.
 *   - `while`     : no change (already the correct form).
 *   - `unknown`   : no change.
 *
 * A `TransformRecord` (kind `'loop-unroll-hint'`) is appended to `transformLog`
 * for every rewrite (infinite and for) or annotation (do-while).
 *
 * @param lines        TalonLine[] from talonDecompile — not mutated.
 * @param loops        NaturalLoop[] from computeNaturalLoops.
 * @param transformLog mutable TransformRecord[] — entries are appended.
 * @returns new TalonLine[] with canonicalized loop shapes.
 */
export function canonicalizeLoops(
  lines: TalonLine[],
  loops: NaturalLoop[],
  transformLog: TransformRecord[],
): TalonLine[] {
  if (loops.length === 0) return lines.slice();

  // Build headerAddress → NaturalLoop lookup (skip loops with no address info)
  const loopByAddr = new Map<number, NaturalLoop>();
  for (const loop of loops) {
    if (loop.headerAddress > 0) {
      loopByAddr.set(loop.headerAddress, loop);
    }
  }

  const result: TalonLine[] = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Only rewrite control lines that sit at a known loop header address
    if (line.kind !== 'control' || line.address === undefined) {
      result.push(line);
      continue;
    }

    const loop = loopByAddr.get(line.address);
    if (!loop) {
      result.push(line);
      continue;
    }

    const originalText = line.text ?? '';
    let rewrittenText = originalText;
    let canonKind: CanonLoopKind = 'unchanged';

    switch (loop.classification) {
      case 'infinite': {
        // Replace the entire `while (…) {` substring with `for (;;) {`
        const m = originalText.match(/while\s*\([^)]*\)\s*\{/);
        if (m) {
          rewrittenText = originalText.replace(m[0], 'for (;;) {');
          canonKind = 'infinite';
        }
        break;
      }

      case 'for': {
        // Try to detect: init-stmt before header + while (var OP bound) + trailing incr
        const condMatch = originalText.match(
          /while\s*\(\s*([a-zA-Z_]\w*)\s*([<>]=?|!=)\s*([^)]+?)\s*\)\s*\{/,
        );
        if (condMatch) {
          const [wholeMatch, loopVar, op, bound] = condMatch;
          const initLine = findInitLine(lines, i, loopVar, 3);
          if (initLine !== null) {
            const initMatch = (initLine.text ?? '').match(
              new RegExp(`\\b${loopVar}\\s*=\\s*([^=+\\-;][^;]*)\\s*;`),
            );
            if (initMatch) {
              const initVal = initMatch[1].trim();
              const incrText = findIncrementText(lines, i + 1, loopVar, 20);
              if (incrText !== null) {
                const newHeader =
                  `for (${loopVar} = ${initVal}; ${loopVar} ${op} ${bound.trim()}; ${incrText}) {`;
                rewrittenText = originalText.replace(wholeMatch, newHeader);
                canonKind = 'for';
              }
            }
          }
        }
        break;
      }

      case 'do-while': {
        // Inject an annotation comment line before the header; keep header text unchanged
        result.push({
          ...line,
          kind: 'intent-comment' as TalonLine['kind'],
          text: '// [do-while pattern — condition is rechecked at the back-edge]',
          lineConfidence: 72,
        });
        rewrittenText = originalText;
        canonKind = 'do-while';
        break;
      }

      default:
        // 'while' and 'unknown': no change
        break;
    }

    // Append a TransformRecord for any recognised rewrite or annotation
    if (canonKind !== 'unchanged') {
      transformLog.push({
        kind: 'loop-unroll-hint',
        inputExpr: originalText.trim(),
        outputExpr:
          canonKind === 'do-while'
            ? `/* do-while */ ${originalText.trim()}`
            : rewrittenText.trim(),
        reason: `Loop classified as "${loop.classification}" — canonicalized to ${canonKind} form`,
        confidence: canonKind === 'infinite' ? 90 : canonKind === 'for' ? 82 : 72,
        address: line.address,
      });
    }

    result.push({ ...line, text: rewrittenText });
  }

  return result;
}

// ── Loop helpers ──────────────────────────────────────────────────────────────

/**
 * Scan backward from `lines[i]` (exclusive) up to `window` positions for a
 * stmt line that assigns `loopVar` (e.g. `i = 0;`).
 */
function findInitLine(
  lines: TalonLine[],
  i: number,
  loopVar: string,
  window: number,
): TalonLine | null {
  for (let j = Math.max(0, i - window); j < i; j++) {
    const ln = lines[j];
    if (ln.kind !== 'stmt') continue;
    // Matches `loopVar = expr;` but NOT `==`, `+=`, `-=`, etc.
    if (new RegExp(`\\b${loopVar}\\s*=[^=+\\-*&|^!<>]`).test(ln.text ?? '')) {
      return ln;
    }
  }
  return null;
}

/**
 * Scan forward up to `limit` lines from `start` for an increment or
 * decrement of `varName`.  Returns a canonical increment string such as
 * `i++`, `i--`, `i += 2`, or `i -= 1`.
 */
function findIncrementText(
  lines: TalonLine[],
  start: number,
  varName: string,
  limit: number,
): string | null {
  const end = Math.min(lines.length, start + limit);
  for (let j = start; j < end; j++) {
    const text = lines[j].text ?? '';
    if (new RegExp(`\\b${varName}\\+\\+`).test(text) || new RegExp(`\\+\\+${varName}\\b`).test(text)) {
      return `${varName}++`;
    }
    if (new RegExp(`\\b${varName}--`).test(text) || new RegExp(`--${varName}\\b`).test(text)) {
      return `${varName}--`;
    }
    const addAssign = text.match(new RegExp(`\\b${varName}\\s*\\+=\\s*(\\d+)`));
    if (addAssign) return `${varName} += ${addAssign[1]}`;
    const subAssign = text.match(new RegExp(`\\b${varName}\\s*-=\\s*(\\d+)`));
    if (subAssign) return `${varName} -= ${subAssign[1]}`;
    // `i = i + N` form
    const addForm = text.match(new RegExp(`\\b${varName}\\s*=\\s*${varName}\\s*\\+\\s*(\\d+)`));
    if (addForm) return `${varName} += ${addForm[1]}`;
  }
  return null;
}

// ─── Pass 2: Basic Type Inference ─────────────────────────────────────────────

/** Possible inferred types for tracked IR variables. */
export type InferredTypeKind =
  | 'bool'
  | 'int8' | 'int16' | 'int32' | 'int64'
  | 'uint8' | 'uint16' | 'uint32' | 'uint64'
  | 'pointer'
  | 'char_ptr'
  | 'array_ptr'
  | 'size_t'
  | 'unknown';

/** A single inferred type annotation for one tracked variable. */
export interface TypeAnnotation {
  /** Variable base name (e.g. "rax", "rbp-8"). */
  varBase: string;
  /** Inferred type kind. */
  kind: InferredTypeKind;
  /** Confidence 0–100.  Higher value overwrites a prior annotation for the same var. */
  confidence: number;
  /** Human-readable justification for this inference. */
  reason: string;
}

/**
 * Map from varBase → best (highest-confidence) TypeAnnotation.
 * Only the winning annotation per variable is retained.
 */
export type TypeMap = Map<string, TypeAnnotation>;

/** String-operation APIs whose first Win64 argument (rcx) is a `char *`. */
const STRING_PTR_APIS = new Set([
  'strlen', 'strcpy', 'strncpy', 'strcat', 'strncat', 'strcmp', 'strncmp',
  'strstr', 'strchr', 'sprintf', 'snprintf', 'lstrcpyA', 'lstrcpyW',
  'lstrlenA', 'lstrlenW', 'wcscpy', 'wcslen',
]);

/**
 * Infer variable types from usage patterns in the IR.
 *
 * Rules (listed by descending priority / confidence):
 *   92 — `test reg, reg` same register      → pointer  (null-check pattern)
 *   91 — shift left/right by 3 (×8)         → size_t   (64-bit array index calc)
 *   90 — used as `mem.base`                 → pointer  (memory dereference)
 *   89 — first arg (rcx) of string API      → char_ptr
 *   88 — used as scaled `mem.index` (×N>1)  → int32    (array index)
 *   87 — binop ±1 on dest register          → int32    (loop counter)
 *   85 — AND mask 0xFF on dest              → uint8    (byte extraction)
 *   84 — AND mask 0xFFFF on dest            → uint16   (16-bit)
 *   83 — source operand of AND 0xFF         → uint8
 *   82 — AND mask 0xFFFFFFFF on dest        → uint32   (32-bit mask)
 *   78 — assigned small literal 0–255       → int32    (weak signal)
 *
 * @param blocks    IRBlock[] to analyse — not mutated.
 * @param _ssaForm  Optional SSAForm reserved for future use (phi-node propagation).
 * @returns TypeMap — one annotation per variable, highest confidence wins.
 */
export function inferTypes(blocks: IRBlock[], _ssaForm?: SSAForm): TypeMap {
  const map: TypeMap = new Map();

  /** Accept an annotation only if its confidence beats any existing one for the same var. */
  function propose(
    varBase: string,
    kind: InferredTypeKind,
    confidence: number,
    reason: string,
  ): void {
    const existing = map.get(varBase);
    if (!existing || existing.confidence < confidence) {
      map.set(varBase, { varBase, kind, confidence, reason });
    }
  }

  /** Extract a register name from an IRValue, or null if not a plain register. */
  function regName(v: IRValue): string | null {
    return v.kind === 'reg' ? v.name : null;
  }

  /**
   * Check a single IRValue for memory-access patterns:
   *   - The base register is proposed as `pointer`.
   *   - A scaled index register is proposed as `int32`.
   */
  function checkMemVal(v: IRValue): void {
    if (v.kind !== 'mem') return;
    propose(v.base, 'pointer', 90, `Used as memory dereference base ([${v.base}+…])`);
    if (v.index !== undefined && (v.scale ?? 1) > 1) {
      propose(v.index, 'int32', 88, `Used as scaled array index ([…+${v.index}×${v.scale}])`);
    }
  }

  for (const block of blocks) {
    for (const stmt of block.stmts) {

      if (stmt.op === 'assign') {
        // Rules 1 & 2: memory accesses on both sides
        checkMemVal(stmt.dest);
        checkMemVal(stmt.src);
        // Rule 9: assigned small literal
        if (stmt.src.kind === 'const' && stmt.src.value >= 0 && stmt.src.value <= 255) {
          const dest = regName(stmt.dest);
          if (dest) propose(dest, 'int32', 78, `Assigned small literal ${stmt.src.value}`);
        }

      } else if (stmt.op === 'binop') {
        // Rules 1 & 2: memory accesses
        checkMemVal(stmt.left);
        checkMemVal(stmt.right);

        // Rules 4, 5, 6: AND mask width inference
        if (stmt.operator === '&' && stmt.right.kind === 'const') {
          const dest = regName(stmt.dest);
          const src  = regName(stmt.left);
          const mask = stmt.right.value >>> 0;
          if (mask === 0xFF) {
            if (dest) propose(dest, 'uint8',  85, `AND with 0xFF — byte extraction`);
            if (src)  propose(src,  'uint8',  83, `Source of byte-extraction AND 0xFF`);
          } else if (mask === 0xFFFF) {
            if (dest) propose(dest, 'uint16', 84, `AND with 0xFFFF — 16-bit extraction`);
          } else if (mask === 0xFFFFFFFF) {
            if (dest) propose(dest, 'uint32', 82, `AND with 0xFFFFFFFF — 32-bit mask`);
          }
        }

        // Rule 7: ±1 on result register → loop counter
        if (
          (stmt.operator === '+' || stmt.operator === '-') &&
          stmt.right.kind === 'const' &&
          Math.abs(stmt.right.value) === 1
        ) {
          const dest = regName(stmt.dest);
          if (dest) propose(dest, 'int32', 87, `Increment/decrement by 1 — loop counter`);
        }

        // Rule 10: shift by 3 (×8) → 64-bit array index calculation
        if (
          (stmt.operator === '<<' || stmt.operator === '>>') &&
          stmt.right.kind === 'const' &&
          stmt.right.value === 3
        ) {
          const dest = regName(stmt.dest);
          const src  = regName(stmt.left);
          if (dest) propose(dest, 'size_t', 91, `Shift by 3 (×8) — 64-bit array index result`);
          if (src)  propose(src,  'size_t', 90, `Source of shift-by-3 — 64-bit array index`);
        }

      } else if (stmt.op === 'test') {
        // Rule 3: `test reg, reg` with the same register — canonical null-check
        const l = regName(stmt.left);
        const r = regName(stmt.right);
        if (l && r && l === r) {
          propose(l, 'pointer', 92, `Null-check pattern: test ${l}, ${l}`);
        }

      } else if (stmt.op === 'call') {
        // Rule 8: Win64 first argument (rcx) of a known string API → char_ptr
        if (stmt.name && STRING_PTR_APIS.has(stmt.name)) {
          propose('rcx', 'char_ptr', 89, `First argument (rcx) of string API "${stmt.name}"`);
        }
      }
    }
  }

  return map;
}

// ─── Pass 3: Enhanced Switch Reconstruction ───────────────────────────────────

/**
 * Extended SwitchStatement with additional metadata produced by the enhanced pass.
 * Extends `SwitchStatement` from talonAdvanced.ts — fully backwards compatible.
 */
export interface EnhancedSwitchStatement extends SwitchStatement {
  /** Inferred type of the switch variable, or `'unknown'` if not in the TypeMap. */
  switchVarType: InferredTypeKind;
  /**
   * True when at least one SwitchCase came from an explicit `case_N:` / `case N:` label
   * found in the line stream rather than being synthetically generated.
   */
  casesFromLabels: boolean;
  /**
   * True when the switch was detected from a consecutive `if (var == N)` equality chain
   * rather than from an indirect jump instruction.
   */
  fromIfElseChain: boolean;
}

/**
 * Enhanced switch statement reconstruction.
 *
 * Improvements over `detectSwitchPatterns` in talonAdvanced.ts:
 *   1. **Type-driven confidence boost**: +15 when the switch variable is inferred as
 *      `int32` or `uint32`; +8 when explicit `case_N:` labels are present.
 *   2. **Explicit case label collection**: scans up to 48 lines after the indirect
 *      jump for `case_N:` or `case N:` labels and uses their real addresses.
 *   3. **If-else chain detection**: ≥3 consecutive `if (var == N)` / `else if (var == N)`
 *      equalities on the same variable are recognised as switch-like dispatch.
 *   4. **Type propagation**: the inferred type is stored on the result for downstream use.
 *
 * Pure function — input arrays and the typeMap are never mutated.
 *
 * @param lines        TalonLine[] from talonDecompile (or canonicalizeLoops output).
 * @param typeMap      TypeMap from inferTypes (may be an empty Map).
 * @param transformLog mutable TransformRecord[] — entries are appended.
 * @returns EnhancedSwitchStatement[]
 */
export function detectSwitchPatternsEnhanced(
  lines: TalonLine[],
  typeMap: TypeMap,
  transformLog: TransformRecord[],
): EnhancedSwitchStatement[] {
  return [
    ...detectIndirectJumpSwitches(lines, typeMap, transformLog),
    ...detectIfElseChainSwitches(lines, typeMap, transformLog),
  ];
}

// ── Sub-pass A: indirect-jump dispatch ────────────────────────────────────────

function detectIndirectJumpSwitches(
  lines: TalonLine[],
  typeMap: TypeMap,
  transformLog: TransformRecord[],
): EnhancedSwitchStatement[] {
  const result: EnhancedSwitchStatement[] = [];

  for (let i = 0; i < lines.length; i++) {
    const ln   = lines[i];
    const text = ln.text ?? '';
    if (!text) continue;

    const isIndirectJmp =
      /\bjmp\b.*\[.*\*[248]\]/.test(text) ||
      /\bswitch\s*\(/.test(text)          ||
      /\bgoto\s+\*/.test(text);
    if (!isIndirectJmp) continue;

    // Find switch variable and upper bound from a preceding comparison
    let switchVar   = 'var';
    let upperBound  = 8;
    for (let j = Math.max(0, i - 5); j < i; j++) {
      const prev = lines[j].text ?? '';
      const m1 = prev.match(/if\s*\(([a-zA-Z_]\w*)\s*(?:>|>=)\s*(\d+)\)/);
      if (m1) { switchVar = m1[1]; upperBound = parseInt(m1[2], 10) + 1; break; }
      const m2 = prev.match(/if\s*\((\d+)\s*(?:<|<=)\s*([a-zA-Z_]\w*)\)/);
      if (m2) { switchVar = m2[2]; upperBound = parseInt(m2[1], 10) + 1; break; }
    }

    // Collect explicit case labels from the next 48 lines
    const cases: SwitchCase[] = [];
    let casesFromLabels = false;
    for (let k = i + 1; k < Math.min(lines.length, i + 48); k++) {
      const lt = lines[k].text ?? '';
      const cm =
        lt.match(/^(?:case_(\d+)|case\s+(\d+))\s*:/) ??
        lt.match(/\/\/\s*case\s+(\d+)\b/);
      if (cm) {
        const val = parseInt(cm[1] ?? cm[2] ?? '0', 10);
        cases.push({ value: val, targetAddress: lines[k].address ?? 0, label: `case_${val}` });
        casesFromLabels = true;
      }
    }

    // Fall back to synthetic cases if no labels found
    if (cases.length === 0) {
      for (let c = 0; c < Math.min(upperBound, 32); c++) {
        cases.push({
          value: c,
          targetAddress: (ln.address ?? 0) + 0x1000 + c * 8,
          label: `case_${c}`,
        });
      }
    }

    // Confidence with optional boosts
    const typeAnnotation = typeMap.get(switchVar);
    const typeBoost  = typeAnnotation &&
      (typeAnnotation.kind === 'int32' || typeAnnotation.kind === 'uint32') ? 15 : 0;
    const labelBoost = casesFromLabels ? 8 : 0;
    const confidence = Math.min(92, 72 + typeBoost + labelBoost);

    const sw: EnhancedSwitchStatement = {
      dispatchAddress: ln.address ?? 0,
      switchVar,
      cases,
      hasDefault: upperBound > 0,
      confidence,
      switchVarType: typeAnnotation?.kind ?? 'unknown',
      casesFromLabels,
      fromIfElseChain: false,
    };
    result.push(sw);

    transformLog.push({
      kind: 'switch-reconstruct',
      inputExpr:  text.trim(),
      outputExpr: `switch (${switchVar}) { /* ${cases.length} cases */ }`,
      reason:
        `Indirect jump with preceding upper-bound check on "${switchVar}"` +
        (typeBoost  > 0 ? ` (type: ${typeAnnotation!.kind}, +${typeBoost} conf)` : '') +
        (casesFromLabels ? ` + ${cases.length} explicit case labels (+${labelBoost} conf)` : ''),
      confidence,
      address: ln.address ?? 0,
    });
  }

  return result;
}

// ── Sub-pass B: if-else equality chain ────────────────────────────────────────

/**
 * Detect a run of ≥3 consecutive `if (var == N)` / `else if (var == N)` statements
 * on the same variable and emit them as a switch-like dispatch.
 */
function detectIfElseChainSwitches(
  lines: TalonLine[],
  typeMap: TypeMap,
  transformLog: TransformRecord[],
): EnhancedSwitchStatement[] {
  const result: EnhancedSwitchStatement[] = [];
  let i = 0;

  while (i < lines.length) {
    const text = lines[i].text ?? '';
    const m = text.match(/if\s*\(([a-zA-Z_]\w*)\s*==\s*(\d+)\)/);
    if (!m) { i++; continue; }

    const chainVar = m[1];
    const chainCases: SwitchCase[] = [
      { value: parseInt(m[2], 10), targetAddress: lines[i].address ?? 0, label: `case_${m[2]}` },
    ];

    let j = i + 1;
    while (j < lines.length && j < i + 80) {
      const lt = lines[j].text ?? '';
      const cont = lt.match(
        new RegExp(`(?:else\\s+)?if\\s*\\(${chainVar}\\s*==\\s*(\\d+)\\)`),
      );
      if (cont) {
        chainCases.push({
          value: parseInt(cont[1], 10),
          targetAddress: lines[j].address ?? 0,
          label: `case_${cont[1]}`,
        });
        j++;
      } else if (/^\s*(else\s*[\{\n]?|\/\/)/.test(lt) || lt.trim() === '') {
        j++; // skip plain else / comment / blank line
      } else {
        break;
      }
    }

    if (chainCases.length >= 3) {
      const typeAnnotation = typeMap.get(chainVar);
      const typeBoost  = typeAnnotation ? 10 : 0;
      // confidence grows with chain length (up to +16 for 8+ cases)
      const confidence = Math.min(88, 62 + typeBoost + Math.min(chainCases.length * 2, 16));

      const sw: EnhancedSwitchStatement = {
        dispatchAddress: lines[i].address ?? 0,
        switchVar:       chainVar,
        cases:           chainCases,
        hasDefault:      false,
        confidence,
        switchVarType:   typeAnnotation?.kind ?? 'unknown',
        casesFromLabels: false,
        fromIfElseChain: true,
      };
      result.push(sw);

      transformLog.push({
        kind:       'switch-reconstruct',
        inputExpr:  `if (${chainVar} == …) else-if chain`,
        outputExpr: `switch (${chainVar}) { /* ${chainCases.length} cases */ }`,
        reason:
          `${chainCases.length} consecutive equality checks on "${chainVar}" ` +
          `— inferred as switch-like dispatch` +
          (typeBoost > 0 ? ` (type: ${typeAnnotation!.kind}, +${typeBoost} conf)` : ''),
        confidence,
        address: lines[i].address ?? 0,
      });

      i = j;
    } else {
      i++;
    }
  }

  return result;
}
