/**
 * yaraEngine — Pure TypeScript YARA-compatible rule engine
 *
 * Supports a practical subset of the YARA 4.x rule language:
 *
 *   String types:
 *     "literal"             — ASCII text, with optional modifiers
 *     { DE AD ?? EF 0? }    — hex byte pattern with wildcard nibbles/bytes
 *     /regex/[flags]        — PCRE-compatible regular expression
 *
 *   String modifiers:
 *     nocase, wide, ascii, fullword
 *
 *   Condition expressions:
 *     any of them           any of ($s1, $s2, ...)
 *     all of them           all of ($s1, $s2, ...)
 *     none of them
 *     N of them             N of ($s1*, $s2)   — prefix wildcard
 *     $name                 boolean: matched?
 *     $name at N            matched at exact byte offset N
 *     #name                 count of matches (numeric)
 *     #name > N, >= N…      count comparison
 *     not, and, or          boolean operators (standard precedence)
 *     (expr)                grouping
 *
 *   Meta fields (all optional):
 *     description           human-readable text → CorrelatedSignal.finding
 *     severity              critical / high / medium / low → default weight
 *     threat_class          maps to existing GYRE signal IDs for corroboration
 *     weight                0–10, overrides severity-derived weight
 *     behaviors             comma-separated BehavioralTag list
 *     author, reference     informational
 *
 * Limitations vs. full YARA 4.x:
 *   - No pe.*, math.*, hash.* modules
 *   - No `at entrypoint`, `in (N..M)`, or jump ranges { [N-M] } in hex
 *   - No `for` loop expressions
 *   - Private / global rules not differentiated
 *   - Rule imports not supported
 *
 * Signals produced here are consumed by correlationEngine.computeVerdict() as
 * section §16.5, alongside the existing signatureEngine (§16), TALON (§17),
 * STRIKE (§18), and ECHO (§19) signal sources.
 */

import type { BehavioralTag } from './correlationEngine';

// ── Internal types ────────────────────────────────────────────────────────────

type YaraStringType = 'text' | 'hex' | 'regex';

interface YaraStringModifiers {
  nocase:   boolean;
  wide:     boolean;
  ascii:    boolean;
  fullword: boolean;
}

interface YaraStringEntry {
  identifier: string;          // "$s1", "$hex1", etc.
  type:       YaraStringType;
  value:      string;          // raw pattern content (without delimiters)
  modifiers:  YaraStringModifiers;
}

interface ParsedYaraRule {
  ruleName:     string;
  namespace:    string;
  tags:         string[];
  meta:         YaraRuleMeta;
  strings:      YaraStringEntry[];
  conditionRaw: string;
}

// ── Public types ─────────────────────────────────────────────────────────────

/**
 * Metadata extracted from a YARA rule's `meta:` section.
 * All fields are optional — rules need only declare the fields relevant to them.
 */
export interface YaraRuleMeta {
  /** Human-readable rule description — becomes the CorrelatedSignal finding text */
  description?:  string;
  /** How severe this rule is; drives weight when `weight` is not set */
  severity?:     'critical' | 'high' | 'medium' | 'low';
  /**
   * Threat class this rule belongs to — used to corroborate existing GYRE signals.
   * Examples: "packer", "ransomware", "injection", "anti-debug", "c2", "crypto",
   *           "dropper", "persistence", "rat"
   */
  threat_class?: string;
  /**
   * Explicit 0–10 weight for the generated CorrelatedSignal.
   * Overrides the severity-derived weight when present.
   */
  weight?:       number;
  /**
   * Behavioral capabilities this rule implies.
   * Comma-separated in rule source; parsed into a string array.
   */
  behaviors?:    BehavioralTag[];
  /** Rule author — informational only */
  author?:       string;
  /** Reference URL or identifier — informational only */
  reference?:    string;
}

/**
 * One string pattern that matched within the binary.
 * Multiple `YaraMatchedString` entries can be present for a single rule
 * when several of its patterns fired (or a single pattern fired multiple times).
 */
export interface YaraMatchedString {
  /** Identifier of the matching pattern, e.g. "$s1" */
  identifier: string;
  /** Byte offset of the first matching occurrence */
  offset:     number;
  /**
   * Hex-encoded excerpt of the matched bytes, e.g. "4D 5A 90 00 …".
   * Capped at 16 bytes for readability.
   */
  data:       string;
  /** Length of the matched sequence in bytes */
  length:     number;
  /** Original pattern value as written in the YARA rule */
  value:      string;
  /** All byte offsets where this identifier matched (for counting and `at` checks) */
  allOffsets: number[];
}

/**
 * A YARA rule that fired on the scanned binary — the unit of output from
 * `matchRules()` / `runYaraRules()`.
 */
export interface YaraRuleMatch {
  /** Rule name exactly as declared in the YARA source */
  ruleName:       string;
  /** Namespace prefix (empty string when absent) */
  namespace:      string;
  /** Tags declared after the colon in the rule header */
  tags:           string[];
  /** Parsed meta fields */
  meta:           YaraRuleMeta;
  /**
   * The string patterns that fired.
   * One entry per matching identifier (with offset = first match).
   * For conditions like `any of them`, only the identifiers that actually
   * contributed to the rule firing are included.
   */
  matchedStrings: YaraMatchedString[];
}

// ── YARA Rule Parser ──────────────────────────────────────────────────────────

function stripYaraComments(text: string): string {
  // Block comments: /* ... */
  let result = text.replace(/\/\*[\s\S]*?\*\//g, ' ');
  // Line comments:  // ...
  result = result.replace(/\/\/[^\n]*/g, '');
  return result;
}

function parseMeta(section: string): YaraRuleMeta {
  const meta: YaraRuleMeta = {};
  // Matches: key = "string" | integer | true | false
  const kvPat = /(\w+)\s*=\s*(?:"([^"]*)"|(-?\d+)|(true|false))/g;
  let m: RegExpExecArray | null;
  while ((m = kvPat.exec(section)) !== null) {
    const key    = m[1];
    const strVal = m[2];   // quoted string value
    const numVal = m[3];   // integer literal
    switch (key) {
      case 'description':  if (strVal !== undefined) meta.description  = strVal;               break;
      case 'severity':     if (strVal !== undefined) meta.severity     = strVal as YaraRuleMeta['severity']; break;
      case 'threat_class': if (strVal !== undefined) meta.threat_class = strVal;               break;
      case 'weight':       if (numVal !== undefined) meta.weight       = parseInt(numVal, 10); break;
      case 'behaviors':
        if (strVal !== undefined)
          meta.behaviors = strVal.split(',').map(b => b.trim() as BehavioralTag).filter(Boolean);
        break;
      case 'author':    if (strVal !== undefined) meta.author    = strVal; break;
      case 'reference': if (strVal !== undefined) meta.reference = strVal; break;
    }
  }
  return meta;
}

function parseStringModifiers(modStr: string): YaraStringModifiers {
  const s = modStr.toLowerCase();
  const wide   = /\bwide\b/.test(s);
  const ascii  = !wide || /\bascii\b/.test(s);
  return {
    nocase:   /\bnocase\b/.test(s),
    wide,
    ascii,
    fullword: /\bfullword\b/.test(s),
  };
}

function parseStringsSection(section: string): YaraStringEntry[] {
  const entries: YaraStringEntry[] = [];
  let i = 0;
  while (i < section.length) {
    // Skip whitespace
    while (i < section.length && /\s/.test(section[i])) i++;
    // We need a '$' to start a string entry
    if (i >= section.length || section[i] !== '$') { i++; continue; }

    // Collect identifier: everything up to the '='
    let idEnd = i;
    while (idEnd < section.length && section[idEnd] !== '=' && section[idEnd] !== '\n') idEnd++;
    if (idEnd >= section.length || section[idEnd] !== '=') { i = idEnd + 1; continue; }

    const identifier = section.slice(i, idEnd).trim();
    i = idEnd + 1;

    // Skip whitespace after '='
    while (i < section.length && section[i] === ' ') i++;

    if (i >= section.length) break;

    const defaultMods: YaraStringModifiers = { nocase: false, wide: false, ascii: true, fullword: false };

    if (section[i] === '"') {
      // ── Text string ───────────────────────────────────────────────────────
      i++; // skip opening quote
      let value = '';
      while (i < section.length && section[i] !== '"') {
        if (section[i] === '\\' && i + 1 < section.length) {
          const next = section[i + 1];
          if      (next === 'n')  { value += '\n'; i += 2; }
          else if (next === 'r')  { value += '\r'; i += 2; }
          else if (next === 't')  { value += '\t'; i += 2; }
          else if (next === '\\') { value += '\\'; i += 2; }
          else if (next === '"')  { value += '"';  i += 2; }
          else                    { value += next; i += 2; }
        } else {
          value += section[i++];
        }
      }
      if (i < section.length) i++; // skip closing quote
      // Collect modifiers until end of line
      const lineEnd = section.indexOf('\n', i);
      const modStr = lineEnd < 0 ? section.slice(i) : section.slice(i, lineEnd);
      entries.push({ identifier, type: 'text', value, modifiers: parseStringModifiers(modStr) });
      i = lineEnd < 0 ? section.length : lineEnd + 1;

    } else if (section[i] === '{') {
      // ── Hex string ────────────────────────────────────────────────────────
      // Hex patterns may span multiple lines — scan to matching '}'
      i++;
      let depth = 1;
      let value = '';
      while (i < section.length && depth > 0) {
        if (section[i] === '{') { depth++; value += section[i]; }
        else if (section[i] === '}') { depth--; if (depth > 0) value += section[i]; }
        else { value += section[i]; }
        i++;
      }
      entries.push({ identifier, type: 'hex', value: value.trim(), modifiers: defaultMods });

    } else if (section[i] === '/') {
      // ── Regex string ──────────────────────────────────────────────────────
      i++; // skip opening '/'
      let value = '';
      // Scan to closing '/' — account for escaped slashes
      while (i < section.length && section[i] !== '/') {
        if (section[i] === '\\' && i + 1 < section.length) {
          value += section[i] + section[i + 1];
          i += 2;
        } else {
          value += section[i++];
        }
      }
      if (i < section.length) i++; // skip closing '/'
      // Collect flags (e.g. "i", "s") until whitespace/newline
      let flags = '';
      while (i < section.length && /[gims]/.test(section[i])) flags += section[i++];
      const mods: YaraStringModifiers = {
        nocase: flags.includes('i'),
        wide:   false,
        ascii:  true,
        fullword: false,
      };
      entries.push({ identifier, type: 'regex', value, modifiers: mods });
    } else {
      i++;
    }
  }
  return entries;
}

/**
 * Parse a string of YARA rules into internal `ParsedYaraRule[]`.
 * Accepts multiple rules per string.
 */
export function parseYaraRules(text: string): ParsedYaraRule[] {
  const clean = stripYaraComments(text);
  const rules: ParsedYaraRule[] = [];

  // Rule header: [namespace:]rule RuleName [: tag1 tag2] {
  const ruleHeaderPat = /(?:(\w+)\s*:\s*)?rule\s+(\w+)(?:\s*:\s*([\w\s]+?))?\s*\{/g;
  let hm: RegExpExecArray | null;

  while ((hm = ruleHeaderPat.exec(clean)) !== null) {
    const namespace = hm[1] ?? '';
    const ruleName  = hm[2];
    const tagsStr   = hm[3]?.trim() ?? '';
    const tags      = tagsStr ? tagsStr.split(/\s+/).filter(Boolean) : [];

    // Find the matching closing brace using depth counting
    const bodyStart = hm.index + hm[0].length;
    let depth = 1;
    let pos   = bodyStart;
    while (pos < clean.length && depth > 0) {
      if (clean[pos] === '{') depth++;
      else if (clean[pos] === '}') depth--;
      pos++;
    }
    const body = clean.slice(bodyStart, pos - 1);

    // ── Parse sections ──────────────────────────────────────────────────────
    const metaMatch    = /\bmeta\s*:([\s\S]*?)(?=\bstrings\b|\bcondition\b|$)/i.exec(body);
    const stringsMatch = /\bstrings\s*:([\s\S]*?)(?=\bcondition\b|$)/i.exec(body);
    const condMatch    = /\bcondition\s*:([\s\S]+)$/i.exec(body);

    const meta      = metaMatch    ? parseMeta(metaMatch[1])          : {};
    const strings   = stringsMatch ? parseStringsSection(stringsMatch[1]) : [];
    const conditionRaw = condMatch ? condMatch[1].trim()              : '';

    if (conditionRaw) {
      rules.push({ ruleName, namespace, tags, meta, strings, conditionRaw });
    }
  }

  return rules;
}

// ── Binary Matching ───────────────────────────────────────────────────────────

function findBytes(haystack: Uint8Array, needle: Uint8Array): number[] {
  const offsets: number[] = [];
  if (needle.length === 0) return offsets;
  const limit = haystack.length - needle.length;
  outer:
  for (let i = 0; i <= limit; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (haystack[i + j] !== needle[j]) continue outer;
    }
    offsets.push(i);
  }
  return offsets;
}

function findBytesNocase(haystack: Uint8Array, needle: Uint8Array): number[] {
  // Lower-case the needle (ASCII only: A–Z → a–z)
  const nl = needle.map(b => (b >= 0x41 && b <= 0x5A) ? b + 0x20 : b);
  const offsets: number[] = [];
  const limit = haystack.length - needle.length;
  outer:
  for (let i = 0; i <= limit; i++) {
    for (let j = 0; j < needle.length; j++) {
      const b = haystack[i + j];
      const bl = (b >= 0x41 && b <= 0x5A) ? b + 0x20 : b;
      if (bl !== nl[j]) continue outer;
    }
    offsets.push(i);
  }
  return offsets;
}

function encodeAscii(s: string): Uint8Array {
  const buf = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) buf[i] = s.charCodeAt(i) & 0xFF;
  return buf;
}

function encodeWide(s: string): Uint8Array {
  const buf = new Uint8Array(s.length * 2);
  for (let i = 0; i < s.length; i++) {
    buf[i * 2]     = s.charCodeAt(i) & 0xFF;
    buf[i * 2 + 1] = (s.charCodeAt(i) >> 8) & 0xFF;
  }
  return buf;
}

/**
 * Parse a YARA hex pattern into an array of byte values or `null` for wildcards.
 * Supports: `??` (full byte wildcard), `?X` / `X?` (nibble wildcard → treated as full wildcard).
 * Unsupported jumps `[N-M]` are replaced with a single wildcard byte.
 */
function parseHexPattern(hex: string): Array<number | null> {
  // Replace jump expressions [N], [N-M], [-] with a single wildcard placeholder
  const simplified = hex.replace(/\[[^\]]*\]/g, '?? ').trim();
  const tokens = simplified.split(/\s+/).filter(Boolean);
  const bytes: Array<number | null> = [];
  for (const tok of tokens) {
    if (tok === '??' || tok === '?') {
      bytes.push(null);
    } else if (/^[0-9A-Fa-f]{2}$/.test(tok)) {
      bytes.push(parseInt(tok, 16));
    } else if (/^[0-9A-Fa-f]\?$/.test(tok) || /^\?[0-9A-Fa-f]$/.test(tok)) {
      // Nibble wildcard — treat as full wildcard
      bytes.push(null);
    }
    // Unknown tokens silently ignored
  }
  return bytes;
}

function findHexPattern(haystack: Uint8Array, pattern: Array<number | null>): number[] {
  const offsets: number[] = [];
  if (pattern.length === 0) return offsets;
  const limit = haystack.length - pattern.length;
  outer:
  for (let i = 0; i <= limit; i++) {
    for (let j = 0; j < pattern.length; j++) {
      if (pattern[j] !== null && haystack[i + j] !== pattern[j]) continue outer;
    }
    offsets.push(i);
  }
  return offsets;
}

/**
 * Match a regex against binary data decoded as Latin-1.
 * Returns [offset, length] pairs for each match.
 */
function findRegexPattern(haystack: Uint8Array, pattern: string, nocase: boolean): Array<[number, number]> {
  // Decode binary as Latin-1 for regex matching (safe — no code execution)
  let latin1 = '';
  for (let i = 0; i < haystack.length; i++) latin1 += String.fromCharCode(haystack[i]);

  const flags = 'g' + (nocase ? 'i' : '');
  try {
    const re = new RegExp(pattern, flags);
    const results: Array<[number, number]> = [];
    let m: RegExpExecArray | null;
    while ((m = re.exec(latin1)) !== null) {
      results.push([m.index, m[0].length]);
      if (re.lastIndex === m.index) re.lastIndex++; // avoid infinite loop on zero-length match
    }
    return results;
  } catch {
    return [];
  }
}

function toHexExcerpt(binary: Uint8Array, offset: number, length: number): string {
  const end = Math.min(offset + length, binary.length, offset + 16); // cap at 16 bytes
  const parts: string[] = [];
  for (let i = offset; i < end; i++) {
    parts.push(binary[i].toString(16).padStart(2, '0').toUpperCase());
  }
  if (offset + length > offset + 16) parts.push('…');
  return parts.join(' ');
}

function matchStringEntry(entry: YaraStringEntry, binary: Uint8Array): number[] {
  // Returns all byte offsets where this pattern matched.
  const offsets: number[] = [];

  if (entry.type === 'text') {
    if (entry.modifiers.ascii) {
      const needle = encodeAscii(entry.value);
      const found  = entry.modifiers.nocase
        ? findBytesNocase(binary, needle)
        : findBytes(binary, needle);
      offsets.push(...found);
    }
    if (entry.modifiers.wide) {
      const needle = encodeWide(entry.value);
      const found  = entry.modifiers.nocase
        ? findBytesNocase(binary, needle)
        : findBytes(binary, needle);
      offsets.push(...found);
    }
  } else if (entry.type === 'hex') {
    const pattern = parseHexPattern(entry.value);
    offsets.push(...findHexPattern(binary, pattern));
  } else if (entry.type === 'regex') {
    const found = findRegexPattern(binary, entry.value, entry.modifiers.nocase);
    offsets.push(...found.map(([off]) => off));
  }

  // Deduplicate and sort ascending
  return [...new Set(offsets)].sort((a, b) => a - b);
}

function matchLengthFor(entry: YaraStringEntry): number {
  // Approximate match length for excerpt generation when we don't track length per-hit
  if (entry.type === 'text') {
    return entry.modifiers.wide ? entry.value.length * 2 : entry.value.length;
  }
  if (entry.type === 'hex') {
    return parseHexPattern(entry.value).length;
  }
  return entry.value.length; // regex: approximate
}

// ── Condition Evaluator ───────────────────────────────────────────────────────

type CondToken =
  | { t: 'id';  v: string }   // $name, #name, any, all, none, of, them, and, or, not, true, false
  | { t: 'num'; v: number }
  | { t: 'cmp'; v: string }   // >, >=, <, <=, ==, =, !=
  | { t: 'sym'; v: string };  // ( ) ,

function tokenizeCond(expr: string): CondToken[] {
  const tokens: CondToken[] = [];
  let i = 0;
  while (i < expr.length) {
    if (/\s/.test(expr[i])) { i++; continue; }

    // Comparison operators (must check 2-char before 1-char)
    if ((expr[i] === '>' || expr[i] === '<' || expr[i] === '!') &&
        i + 1 < expr.length && expr[i + 1] === '=') {
      tokens.push({ t: 'cmp', v: expr[i] + '=' }); i += 2; continue;
    }
    if (expr[i] === '=' && i + 1 < expr.length && expr[i + 1] === '=') {
      tokens.push({ t: 'cmp', v: '==' }); i += 2; continue;
    }
    if (expr[i] === '>' || expr[i] === '<') {
      tokens.push({ t: 'cmp', v: expr[i++] }); continue;
    }
    if (expr[i] === '=' && (i === 0 || expr[i - 1] !== '!' && expr[i - 1] !== '<' && expr[i - 1] !== '>')) {
      tokens.push({ t: 'cmp', v: '=' }); i++; continue;
    }

    if (expr[i] === '(') { tokens.push({ t: 'sym', v: '(' }); i++; continue; }
    if (expr[i] === ')') { tokens.push({ t: 'sym', v: ')' }); i++; continue; }
    if (expr[i] === ',') { tokens.push({ t: 'sym', v: ',' }); i++; continue; }

    if (/\d/.test(expr[i])) {
      let num = '';
      while (i < expr.length && /\d/.test(expr[i])) num += expr[i++];
      tokens.push({ t: 'num', v: parseInt(num, 10) }); continue;
    }

    // Identifiers: $name, #name, keywords
    if (/[$#\w]/.test(expr[i])) {
      let word = '';
      while (i < expr.length && /[$#\w*]/.test(expr[i])) word += expr[i++];
      tokens.push({ t: 'id', v: word.toLowerCase() }); continue;
    }

    i++; // skip unknown character
  }
  return tokens;
}

class ConditionEvaluator {
  private pos = 0;
  constructor(
    private readonly tokens: CondToken[],
    private readonly matchedIds:    Set<string>,   // lowercased identifier set
    private readonly matchCounts:   Map<string, number>,  // '#name' → count
    private readonly matchOffsets:  Map<string, number[]>,// '$name' → offsets
    private readonly allIdentifiers: string[],             // all $names in rule (lowercase)
  ) {}

  private peek(): CondToken | undefined { return this.tokens[this.pos]; }
  private consume(): CondToken | undefined { return this.tokens[this.pos++]; }

  private matchId(value: string): boolean {
    const t = this.peek();
    if (t?.t === 'id' && t.v === value) { this.pos++; return true; }
    return false;
  }

  evaluate(): boolean {
    const v = this.parseOr();
    return v;
  }

  private parseOr(): boolean {
    let left = this.parseAnd();
    while (this.matchId('or')) {
      const right = this.parseAnd();
      left = left || right;
    }
    return left;
  }

  private parseAnd(): boolean {
    let left = this.parseNot();
    while (this.matchId('and')) {
      const right = this.parseNot();
      left = left && right;
    }
    return left;
  }

  private parseNot(): boolean {
    if (this.matchId('not')) return !this.parseAtom();
    return this.parseAtom();
  }

  private parseAtom(): boolean {
    const t = this.peek();
    if (!t) return false;

    // Grouped expression
    if (t.t === 'sym' && t.v === '(') {
      this.consume();
      const v = this.parseOr();
      if (this.peek()?.t === 'sym' && this.peek()?.v === ')') this.consume();
      return v;
    }

    // Numeric literal — likely the N in "N of them"
    if (t.t === 'num') {
      this.consume();
      if (this.matchId('of')) {
        const ids = this.parseOfTarget();
        const hit = ids.filter(id => this.matchedIds.has(id)).length;
        return hit >= t.v;
      }
      return t.v > 0;
    }

    if (t.t === 'id') {
      // ── "any of ..."  ──────────────────────────────────────────────────────
      if (t.v === 'any') {
        this.consume();
        if (!this.matchId('of')) return false;
        const ids = this.parseOfTarget();
        return ids.some(id => this.matchedIds.has(id));
      }

      // ── "all of ..."  ──────────────────────────────────────────────────────
      if (t.v === 'all') {
        this.consume();
        if (!this.matchId('of')) return false;
        const ids = this.parseOfTarget();
        return ids.length > 0 && ids.every(id => this.matchedIds.has(id));
      }

      // ── "none of ..." ──────────────────────────────────────────────────────
      if (t.v === 'none') {
        this.consume();
        if (!this.matchId('of')) return false;
        const ids = this.parseOfTarget();
        return ids.every(id => !this.matchedIds.has(id));
      }

      // ── Boolean literals ───────────────────────────────────────────────────
      if (t.v === 'true')  { this.consume(); return true;  }
      if (t.v === 'false') { this.consume(); return false; }

      // ── "$name [at N]" ─────────────────────────────────────────────────────
      if (t.v.startsWith('$')) {
        this.consume();
        const id = t.v; // lowercase identifier
        if (this.matchId('at')) {
          const numTok = this.peek();
          if (numTok?.t === 'num') {
            const targetOffset = numTok.v;
            this.consume();
            return (this.matchOffsets.get(id) ?? []).includes(targetOffset);
          }
        }
        return this.matchedIds.has(id);
      }

      // ── "#name [op N]" ─────────────────────────────────────────────────────
      if (t.v.startsWith('#')) {
        this.consume();
        const count = this.matchCounts.get(t.v) ?? 0;
        const cmpTok = this.peek();
        if (cmpTok?.t === 'cmp') {
          this.consume();
          const numTok = this.peek();
          if (numTok?.t === 'num') {
            this.consume();
            const n = numTok.v;
            switch (cmpTok.v) {
              case '>':  return count > n;
              case '>=': return count >= n;
              case '<':  return count < n;
              case '<=': return count <= n;
              case '=':
              case '==': return count === n;
              case '!=': return count !== n;
            }
          }
        }
        return count > 0;
      }
    }

    this.consume(); // skip unknown token
    return false;
  }

  /**
   * Parse the target of an "of" expression:
   *   "them"        → all string identifiers
   *   "($s1, $s2)"  → named identifiers (with prefix wildcards like "$s*")
   */
  private parseOfTarget(): string[] {
    const t = this.peek();
    if (!t) return [];

    if (t.t === 'id' && t.v === 'them') {
      this.consume();
      return this.allIdentifiers;
    }

    if (t.t === 'sym' && t.v === '(') {
      this.consume();
      const ids: string[] = [];
      while (this.peek() && !(this.peek()?.t === 'sym' && this.peek()?.v === ')')) {
        const tok = this.peek();
        if (tok?.t === 'id' && tok.v.startsWith('$')) {
          this.consume();
          if (tok.v.endsWith('*')) {
            // Prefix wildcard — expand to all matching identifiers
            const prefix = tok.v.slice(0, -1);
            ids.push(...this.allIdentifiers.filter(id => id.startsWith(prefix)));
          } else {
            ids.push(tok.v);
          }
        } else if (tok?.t === 'sym' && tok.v === ',') {
          this.consume();
        } else {
          this.consume(); // skip unexpected token
        }
      }
      if (this.peek()?.t === 'sym' && this.peek()?.v === ')') this.consume();
      return ids;
    }

    return this.allIdentifiers; // fallback: treat unknown as "them"
  }
}

function evaluateCondition(
  condRaw:        string,
  allEntries:     YaraStringEntry[],
  matchedIds:     Set<string>,
  matchCounts:    Map<string, number>,
  matchOffsets:   Map<string, number[]>,
): boolean {
  const tokens         = tokenizeCond(condRaw);
  const allIdentifiers = allEntries.map(e => e.identifier.toLowerCase());
  const evaluator      = new ConditionEvaluator(
    tokens, matchedIds, matchCounts, matchOffsets, allIdentifiers,
  );
  try {
    return evaluator.evaluate();
  } catch {
    // Parse failure — fall back to "any of them" so we don't silently drop results
    return matchedIds.size > 0;
  }
}

// ── Rule Execution ────────────────────────────────────────────────────────────

/**
 * Run all parsed YARA rules against a binary blob.
 *
 * @param rules       Rules returned by `parseYaraRules()`
 * @param binary      Raw binary data to scan
 * @param maxBytes    Maximum bytes to scan (default 64 MB — prevents browser freeze)
 */
export function matchRules(
  rules:    ParsedYaraRule[],
  binary:   Uint8Array,
  maxBytes  = 64 * 1024 * 1024,
): YaraRuleMatch[] {
  const data    = binary.length > maxBytes ? binary.subarray(0, maxBytes) : binary;
  const results: YaraRuleMatch[] = [];

  for (const rule of rules) {
    // ── Match all string patterns ─────────────────────────────────────────
    const matchedIds:   Set<string>             = new Set();
    const matchCounts:  Map<string, number>     = new Map();
    const matchOffsets: Map<string, number[]>   = new Map();

    // hitsByIdentifier collects all offset hits per pattern
    const hitsByIdentifier = new Map<string, number[]>();

    for (const entry of rule.strings) {
      const id      = entry.identifier.toLowerCase();
      const offsets = matchStringEntry(entry, data);
      hitsByIdentifier.set(id, offsets);
      if (offsets.length > 0) {
        matchedIds.add(id);
        matchCounts.set('#' + id.slice(1), offsets.length); // #s1 → count
        matchOffsets.set(id, offsets);
      }
    }

    // ── Evaluate condition ────────────────────────────────────────────────
    const fired = evaluateCondition(
      rule.conditionRaw,
      rule.strings,
      matchedIds,
      matchCounts,
      matchOffsets,
    );

    if (!fired) continue;

    // ── Build YaraMatchedString list (first match per identifier) ─────────
    const matchedStrings: YaraMatchedString[] = [];

    for (const entry of rule.strings) {
      const id      = entry.identifier.toLowerCase();
      const offsets = hitsByIdentifier.get(id) ?? [];
      if (offsets.length === 0) continue;

      const offset = offsets[0];
      const length = matchLengthFor(entry);

      matchedStrings.push({
        identifier: entry.identifier,
        offset,
        data:       toHexExcerpt(data, offset, length),
        length,
        value:      entry.value,
        allOffsets: offsets.slice(0, 20), // cap at 20 for readability
      });
    }

    results.push({
      ruleName:       rule.ruleName,
      namespace:      rule.namespace,
      tags:           rule.tags,
      meta:           rule.meta,
      matchedStrings,
    });
  }

  return results;
}

// ── Built-in Rules ────────────────────────────────────────────────────────────

/**
 * Default YARA rule set bundled with HexHawk.
 * Covers the most common threat patterns encountered in CTF and malware analysis.
 * Users can extend with custom rules via the YARA panel or by passing extra
 * rule text to `runYaraRules()`.
 */
export const BUILTIN_YARA_RULES_TEXT = `
rule UpxPacker : packer {
    meta:
        description = "UPX packer stub — compressed executable"
        threat_class = "packer"
        severity = "medium"
        weight = 6
        behaviors = "code-decryption"
    strings:
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
        $upx2 = "UPX!" ascii
    condition:
        any of them
}

rule RansomwareNote : ransomware {
    meta:
        description = "Ransomware extortion note keywords"
        threat_class = "ransomware"
        severity = "high"
        weight = 8
        behaviors = "data-encryption,file-destruction"
    strings:
        $n1 = "your files have been encrypted" nocase
        $n2 = "decrypt your files" nocase
        $n3 = "bitcoin" nocase
        $n4 = "ransom" nocase
        $n5 = ".onion" nocase
        $n6 = "pay to recover" nocase
    condition:
        2 of them
}

rule AntiDebugAPIs : anti_debug {
    meta:
        description = "Anti-debugging Win32 API strings found"
        threat_class = "anti-debug"
        severity = "medium"
        weight = 6
        behaviors = "anti-analysis"
    strings:
        $ad1 = "IsDebuggerPresent" ascii
        $ad2 = "CheckRemoteDebuggerPresent" ascii
        $ad3 = "NtQueryInformationProcess" ascii
        $ad4 = "OutputDebugStringA" ascii
        $ad5 = "BlockInput" ascii
        $ad6 = "SetUnhandledExceptionFilter" ascii
    condition:
        2 of them
}

rule ProcessInjectionAPIs : injection {
    meta:
        description = "Process injection Win32 API sequence"
        threat_class = "injection"
        severity = "high"
        weight = 8
        behaviors = "code-injection"
    strings:
        $i1 = "VirtualAllocEx" ascii
        $i2 = "WriteProcessMemory" ascii
        $i3 = "CreateRemoteThread" ascii
        $i4 = "NtCreateThreadEx" ascii
        $i5 = "QueueUserAPC" ascii
    condition:
        2 of them
}

rule NetworkC2 : network {
    meta:
        description = "Network C2 communication Win32 API"
        threat_class = "c2"
        severity = "high"
        weight = 7
        behaviors = "c2-communication"
    strings:
        $n1 = "InternetOpen" ascii
        $n2 = "HttpSendRequest" ascii
        $n3 = "WinHttpOpen" ascii
        $n4 = "URLDownloadToFile" ascii
        $n5 = "WSAStartup" ascii
        $n6 = "curl_easy_perform" ascii
    condition:
        2 of them
}

rule EmbeddedPE : dropper {
    meta:
        description = "Embedded PE executable (MZ header) found in binary"
        threat_class = "dropper"
        severity = "medium"
        weight = 6
        behaviors = "code-injection"
    strings:
        $mz = { 4D 5A }
    condition:
        $mz at 0 or #mz > 1
}

rule RegistryPersistence : persistence {
    meta:
        description = "Registry-based persistence (Run/RunOnce keys)"
        threat_class = "persistence"
        severity = "high"
        weight = 7
        behaviors = "persistence"
    strings:
        $r1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $r2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" nocase
        $r3 = "CurrentVersion\\Run" nocase
    condition:
        any of them
}

rule AesConstants : crypto {
    meta:
        description = "AES S-box constants — AES encryption implementation"
        threat_class = "crypto"
        severity = "medium"
        weight = 5
        behaviors = "data-encryption"
    strings:
        // AES forward S-box first 16 bytes
        $aes_sbox = { 63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76 }
        // AES key expansion constant
        $aes_rcon = { 01 00 00 00 02 00 00 00 04 00 00 00 08 00 00 00 }
    condition:
        any of them
}

rule PebDirectAccess : rat {
    meta:
        description = "Direct PEB/TEB access — API-less dynamic resolution"
        threat_class = "rat"
        severity = "high"
        weight = 7
        behaviors = "dynamic-resolution,anti-analysis"
    strings:
        // mov eax, fs:[30h] — x86 PEB
        $peb32 = { 64 A1 30 00 00 00 }
        // mov rax, gs:[60h] — x64 PEB
        $peb64 = { 65 48 8B 04 25 60 00 00 00 }
        // mov eax, fs:[18h] — x86 TEB
        $teb32 = { 64 A1 18 00 00 00 }
    condition:
        any of them
}

rule Base64EncodedPE : dropper {
    meta:
        description = "Base64-encoded PE header — embedded executable payload"
        threat_class = "dropper"
        severity = "medium"
        weight = 6
    strings:
        // base64("MZ") — TVQAAA (padded) or TVo (raw)
        $mz_b64a = "TVQAAA" ascii
        $mz_b64b = "TVo" ascii
    condition:
        any of them
}

rule SuspiciousScheduledTask : persistence {
    meta:
        description = "Scheduled task creation for persistence"
        threat_class = "persistence"
        severity = "high"
        weight = 7
        behaviors = "persistence"
    strings:
        $t1 = "schtasks" nocase
        $t2 = "TaskScheduler" ascii
        $t3 = "ITaskScheduler" ascii
        $t4 = "/create" nocase
        $t5 = "SYSTEM32\\Tasks" nocase
    condition:
        2 of them
}

rule CryptoMiningStrings : cryptominer {
    meta:
        description = "Cryptocurrency mining pool / Monero references"
        threat_class = "cryptominer"
        severity = "high"
        weight = 8
    strings:
        $m1 = "stratum+tcp://" nocase
        $m2 = "xmrig" nocase
        $m3 = "monero" nocase
        $m4 = "cryptonight" nocase
        $m5 = "pool.supportxmr.com" nocase
        $m6 = "nicehash" nocase
    condition:
        2 of them
}

rule SelfDeletingBinary : rat {
    meta:
        description = "Self-deletion pattern — binary removes itself after execution"
        threat_class = "rat"
        severity = "medium"
        weight = 5
        behaviors = "anti-analysis"
    strings:
        $sd1 = "cmd.exe /c del " nocase
        $sd2 = "COMSPEC" ascii
        $sd3 = "ping 127.0.0.1 -n" nocase
        $sd4 = "/c timeout" nocase
    condition:
        2 of them
}
`;

let _builtinRules: ParsedYaraRule[] | null = null;

/** Return the built-in YARA rules, parsing them lazily on first call. */
export function getBuiltinRules(): ParsedYaraRule[] {
  if (!_builtinRules) _builtinRules = parseYaraRules(BUILTIN_YARA_RULES_TEXT);
  return _builtinRules;
}

/**
 * Run all built-in rules plus any user-supplied rule text against a binary.
 *
 * @param binary          Raw binary bytes (e.g. from a Tauri file-read command)
 * @param extraRulesText  Optional additional YARA rule text to run alongside built-ins
 * @param maxBytes        Scan limit (default 64 MB)
 */
export function runYaraRules(
  binary:         Uint8Array,
  extraRulesText?: string,
  maxBytes        = 64 * 1024 * 1024,
): YaraRuleMatch[] {
  const rules: ParsedYaraRule[] = [
    ...getBuiltinRules(),
    ...(extraRulesText ? parseYaraRules(extraRulesText) : []),
  ];
  return matchRules(rules, binary, maxBytes);
}
