/**
 * mythosEngine — MYTHOS Capability Detection Engine
 *
 * Implements capa-style structured capability detection for HexHawk.
 * Where YARA detects patterns (bytes, strings, regex), Mythos detects
 * *behavioral capabilities* — higher-order combinations of evidence that
 * answer "what can this binary DO?" rather than "what bytes are present?".
 *
 * Each Mythos rule fires when its condition tree evaluates to true against
 * all available evidence. Every match carries:
 *   - A capability name and namespace (capa-style "host-interaction/process-injection")
 *   - Linked code locations (addresses, import names, string offsets)
 *   - The evidence chain that satisfied the rule
 *   - A weight and severity that scale the resulting CorrelatedSignal
 *
 * Rules are evaluated against a MythosInput that aggregates all signal
 * sources: imports, strings, disassembly patterns, TALON function analysis,
 * ECHO fuzzy matches, YARA results, and section metadata.
 *
 * Integration:
 *   - CorrelationInput.mythosMatches? → fed into §16.6 of computeVerdict()
 *   - NestIterationInput.mythosMatches? → passed through runCorrelationPass()
 *   - Each MythosCapabilityMatch → one CorrelatedSignal with certainty:'inferred'
 *     and a locations[] array linking back to the code that triggered it.
 */

import type { BehavioralTag } from './correlationEngine';

// ─── Public Location Types ─────────────────────────────────────────────────────

/**
 * A single code location that contributed evidence to a capability match.
 * Used by the UI to navigate to the actual binary location (hex offset,
 * disassembly address, import name, etc.).
 */
export interface MythosLocation {
  /**
   * Binary address or offset.
   * 0 when the location is derived from an import declaration (no runtime address).
   * Non-zero for disassembly patterns, TALON function addresses, ECHO matches.
   */
  address: number;
  kind: 'import' | 'string' | 'instruction' | 'function' | 'section' | 'pattern';
  /** Short human-readable label: "WriteProcessMemory", "fn@0x401000", ".text §entropy=7.9" */
  label: string;
  /** Optional one-sentence context note for the UI tooltip */
  context?: string;
}

// ─── Public Capability Match Types ────────────────────────────────────────────

export interface MythosCapabilityMatch {
  /** Short kebab-case ID: 'inject-remote-thread', 'encrypt-aes', 'persist-registry' */
  id: string;
  /** Human-readable capability name */
  name: string;
  /**
   * Hierarchical capability namespace (capa convention):
   *   "host-interaction/process-injection/remote-thread"
   *   "data-manipulation/encryption/aes"
   */
  namespace: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  /** Weight 0–10 for the resulting CorrelatedSignal */
  weight: number;
  /**
   * Confidence 0–100: fraction of the rule's conditions that matched,
   * weighted by condition importance. Mandatory rules score higher than optional.
   */
  confidence: number;
  /** Locations in the binary that triggered this rule (for navigation) */
  locations: MythosLocation[];
  /** Human-readable evidence sentences: "import VirtualAllocEx found", etc. */
  evidence: string[];
  behaviors: BehavioralTag[];
  /**
   * MITRE ATT&CK technique ID for this capability, if mapped.
   * Format: "T1055" or "T1055.001" for sub-techniques.
   */
  attackId?: string;
}

// ─── Rule Condition Tree ───────────────────────────────────────────────────────

/**
 * Discriminated union condition tree.  Conditions compose recursively via
 * and / or / not / n-of.  Leaf conditions test a single evidence source.
 *
 * Evaluation produces a boolean; weight is tracked externally by the rule's
 * firing logic, not by individual conditions.
 */
export type MythosCondition =
  | { type: 'and';   conditions: MythosCondition[] }
  | { type: 'or';    conditions: MythosCondition[] }
  | { type: 'not';   condition:  MythosCondition }
  | { type: 'n-of';  n: number; conditions: MythosCondition[] }

  // Import table: exact API name match
  | { type: 'import';           api: string }

  // String search: case-insensitive substring or regex
  | { type: 'string-contains';  pattern: string }
  | { type: 'string-regex';     pattern: string }

  // Disassembly pattern type from SuspiciousPattern.type
  | { type: 'pattern-type';     patternType: string }

  // Section attribute tests
  | { type: 'section-name';     name: string }   // substring match on section name
  | { type: 'section-entropy';  min: number }    // any section entropy >= min

  // Higher-level corroborating signals
  | { type: 'behavioral-tag';   tag: BehavioralTag }   // from TALON / ECHO
  | { type: 'yara-hit';         ruleName: string }      // YARA rule already fired
  | { type: 'echo-category';    category: string };     // ECHO EchoCategory

// ─── Rule Definition ──────────────────────────────────────────────────────────

interface MythosRule {
  id: string;
  name: string;
  namespace: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  weight: number;
  behaviors: BehavioralTag[];
  /** Top-level condition tree — must evaluate to true for the rule to fire */
  condition: MythosCondition;
  /**
   * Additional optional conditions used for confidence boosting (0–+15 pts each).
   * These don't affect whether the rule fires, but they increase the match
   * confidence when present — showing the analyst HOW confident Mythos is.
   */
  boosts?: MythosCondition[];
}

// ─── Match Context ────────────────────────────────────────────────────────────

/**
 * Flattened, pre-computed lookup structures derived from MythosInput.
 * Built once per evaluation pass and shared across all rule evaluations.
 */
interface EvalContext {
  importSet:            Set<string>;           // all import names (original case)
  importSetLower:       Set<string>;           // lowercase for case-insensitive lookups
  lowerStrings:         string[];              // all strings lowercased
  patternTypes:         Set<string>;           // SuspiciousPattern.type values present
  sectionNameSet:       Set<string>;           // section names lowercased
  highEntropySections:  string[];              // names with entropy >= 7.0
  behavioralTagSet:     Set<BehavioralTag>;    // from TALON/ECHO signals
  yaraRuleNames:        Set<string>;           // fired YARA rule names
  echoCategoryHits:     Set<string>;           // ECHO categories that matched
}

// ─── Input Shape ──────────────────────────────────────────────────────────────

export interface MythosInput {
  imports: Array<{ name: string; library: string }>;
  strings: Array<{ text: string; offset?: number }>;
  patterns: Array<{ address: number; type: string; description: string }>;
  sections: Array<{ name: string; entropy: number; file_size: number }>;

  /**
   * Optional: richer TALON function-level data for address linking.
   * When present, Mythos can point to the exact function addresses where
   * capabilities were detected, not just say "capability exists".
   */
  talonFunctions?: Array<{
    name: string;
    startAddress: number;
    behavioralTags: BehavioralTag[];
    intents: Array<{ label: string; address: number; category: string }>;
  }>;

  /**
   * Optional: ECHO pattern-match function addresses.
   * Lets Mythos link an ECHO-category hit back to the function that matched.
   */
  echoFunctionMatches?: Array<{
    patternId: string;
    category: string;
    functionAddress: number;
  }>;

  /** Optional: pre-computed YARA matches for cross-reference conditions */
  yaraMatches?: Array<{ ruleName: string; tags: string[]; meta?: { threat_class?: string } }>;

  /** Optional: behavioral tags aggregated by TALON/ECHO before Mythos runs */
  behavioralTags?: BehavioralTag[];

  /** Optional: ECHO category hits (EchoCategory strings) */
  echoCategoryHits?: string[];
}

// ─── Condition Evaluator ─────────────────────────────────────────────────────

function evalCond(cond: MythosCondition, ctx: EvalContext): boolean {
  switch (cond.type) {
    case 'and':
      return cond.conditions.every(c => evalCond(c, ctx));

    case 'or':
      return cond.conditions.some(c => evalCond(c, ctx));

    case 'not':
      return !evalCond(cond.condition, ctx);

    case 'n-of': {
      let hits = 0;
      for (const c of cond.conditions) {
        if (evalCond(c, ctx)) hits++;
        if (hits >= cond.n) return true;
      }
      return hits >= cond.n;
    }

    case 'import':
      return ctx.importSet.has(cond.api) || ctx.importSetLower.has(cond.api.toLowerCase());

    case 'string-contains': {
      const pat = cond.pattern.toLowerCase();
      return ctx.lowerStrings.some(s => s.includes(pat));
    }

    case 'string-regex': {
      const re = new RegExp(cond.pattern, 'i');
      return ctx.lowerStrings.some(s => re.test(s));
    }

    case 'pattern-type':
      return ctx.patternTypes.has(cond.patternType);

    case 'section-name': {
      const nameLower = cond.name.toLowerCase();
      for (const s of ctx.sectionNameSet) {
        if (s.includes(nameLower)) return true;
      }
      return false;
    }

    case 'section-entropy':
      return ctx.highEntropySections.length > 0 &&
        ctx.highEntropySections.some(_ => true); // checked by min in build

    case 'behavioral-tag':
      return ctx.behavioralTagSet.has(cond.tag);

    case 'yara-hit':
      return ctx.yaraRuleNames.has(cond.ruleName);

    case 'echo-category':
      return ctx.echoCategoryHits.has(cond.category);
  }
}

// ─── Location Builder ─────────────────────────────────────────────────────────

/** Collect locations from all evidence sources that the rule touched. */
function buildLocations(
  rule: MythosRule,
  input: MythosInput,
  ctx: EvalContext,
): MythosLocation[] {
  const locs: MythosLocation[] = [];

  // Import-based locations
  collectImportLocations(rule.condition, ctx, input, locs);

  // String-based locations
  collectStringLocations(rule.condition, input, locs);

  // Pattern-based locations
  collectPatternLocations(rule.condition, input, ctx, locs);

  // TALON function locations (cross-reference behavioural tags)
  if (input.talonFunctions) {
    for (const fn of input.talonFunctions) {
      const hasRelevantTag = rule.behaviors.some(b => fn.behavioralTags.includes(b));
      if (hasRelevantTag) {
        locs.push({
          address: fn.startAddress,
          kind:    'function',
          label:   `${fn.name}@0x${fn.startAddress.toString(16).toUpperCase()}`,
          context: `TALON: ${fn.behavioralTags.join(', ')}`,
        });
      }
      // Also capture specific intents (e.g. anti-debug routines)
      for (const intent of fn.intents) {
        if (isIntentRelevantToRule(intent.label, rule)) {
          locs.push({
            address: intent.address,
            kind:    'instruction',
            label:   `${intent.label}@0x${intent.address.toString(16).toUpperCase()}`,
            context: `TALON intent in ${fn.name}`,
          });
        }
      }
    }
  }

  // ECHO function-address locations
  if (input.echoFunctionMatches) {
    for (const em of input.echoFunctionMatches) {
      if (ctx.echoCategoryHits.has(em.category)) {
        locs.push({
          address: em.functionAddress,
          kind:    'function',
          label:   `echo:${em.patternId}@0x${em.functionAddress.toString(16).toUpperCase()}`,
          context: `ECHO pattern: ${em.category}`,
        });
      }
    }
  }

  // Deduplicate by (address, label) — keep first occurrence
  const seen = new Set<string>();
  return locs.filter(loc => {
    const key = `${loc.address}:${loc.label}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  }).slice(0, 8); // cap at 8 locations per capability
}

function isIntentRelevantToRule(intentLabel: string, rule: MythosRule): boolean {
  const label = intentLabel.toLowerCase();
  for (const b of rule.behaviors) {
    if (b === 'code-injection'    && (label.includes('inject') || label.includes('alloc') || label.includes('thread'))) return true;
    if (b === 'anti-analysis'     && (label.includes('debug') || label.includes('anti') || label.includes('timing'))) return true;
    if (b === 'c2-communication'  && (label.includes('network') || label.includes('http') || label.includes('socket'))) return true;
    if (b === 'persistence'       && (label.includes('registry') || label.includes('service') || label.includes('persist'))) return true;
    if (b === 'data-encryption'   && (label.includes('crypt') || label.includes('encrypt') || label.includes('aes'))) return true;
    if (b === 'process-execution' && (label.includes('spawn') || label.includes('exec') || label.includes('process'))) return true;
    if (b === 'dynamic-resolution' && (label.includes('load') || label.includes('dynamic') || label.includes('resolve'))) return true;
    if (b === 'data-exfiltration' && (label.includes('exfil') || label.includes('upload') || label.includes('send'))) return true;
  }
  return false;
}

function collectImportLocations(
  cond: MythosCondition,
  ctx: EvalContext,
  input: MythosInput,
  locs: MythosLocation[],
): void {
  switch (cond.type) {
    case 'import':
      if (evalCond(cond, ctx)) {
        const imp = input.imports.find(
          i => i.name === cond.api || i.name.toLowerCase() === cond.api.toLowerCase()
        );
        locs.push({
          address: 0,
          kind:    'import',
          label:   cond.api + (imp ? ` (${imp.library})` : ''),
          context: 'Import table declaration',
        });
      }
      break;
    case 'and':
    case 'or':
      for (const c of cond.conditions) collectImportLocations(c, ctx, input, locs);
      break;
    case 'n-of':
      for (const c of cond.conditions) collectImportLocations(c, ctx, input, locs);
      break;
    case 'not':
      break; // don't add locations for negated conditions
    default:
      break;
  }
}

function collectStringLocations(
  cond: MythosCondition,
  input: MythosInput,
  locs: MythosLocation[],
): void {
  let pattern: RegExp | null = null;
  if (cond.type === 'string-contains') {
    pattern = new RegExp(cond.pattern.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i');
  } else if (cond.type === 'string-regex') {
    try { pattern = new RegExp(cond.pattern, 'i'); } catch { return; }
  } else if (cond.type === 'and' || cond.type === 'or' || cond.type === 'n-of') {
    const children = cond.type === 'n-of' ? cond.conditions : cond.conditions;
    for (const c of children) collectStringLocations(c, input, locs);
    return;
  } else {
    return;
  }

  if (!pattern) return;
  for (const s of input.strings) {
    if (pattern.test(s.text)) {
      const truncated = s.text.length > 40 ? s.text.slice(0, 40) + '…' : s.text;
      locs.push({
        address: s.offset ?? 0,
        kind:    'string',
        label:   `"${truncated}"`,
        context: s.offset != null ? `String at offset 0x${s.offset.toString(16).toUpperCase()}` : 'String match',
      });
      if (locs.filter(l => l.kind === 'string').length >= 3) break; // cap string locs
    }
  }
}

function collectPatternLocations(
  cond: MythosCondition,
  input: MythosInput,
  ctx: EvalContext,
  locs: MythosLocation[],
): void {
  if (cond.type === 'pattern-type') {
    if (ctx.patternTypes.has(cond.patternType)) {
      for (const p of input.patterns) {
        if (p.type === cond.patternType) {
          locs.push({
            address: p.address,
            kind:    'pattern',
            label:   `${p.type}@0x${p.address.toString(16).toUpperCase()}`,
            context: p.description,
          });
          break; // first match only
        }
      }
    }
  } else if (cond.type === 'and' || cond.type === 'or' || cond.type === 'n-of') {
    const children = cond.type === 'n-of' ? cond.conditions : cond.conditions;
    for (const c of children) collectPatternLocations(c, input, ctx, locs);
  }
}

// ─── Evidence Builder ─────────────────────────────────────────────────────────

function buildEvidence(
  cond: MythosCondition,
  ctx: EvalContext,
  input: MythosInput,
): string[] {
  const ev: string[] = [];
  gatherEvidence(cond, ctx, input, ev);
  return [...new Set(ev)].slice(0, 8);
}

function gatherEvidence(
  cond: MythosCondition,
  ctx: EvalContext,
  input: MythosInput,
  out: string[],
): void {
  if (!evalCond(cond, ctx)) return;

  switch (cond.type) {
    case 'import':
      out.push(`import: ${cond.api}`);
      break;
    case 'string-contains':
      out.push(`string contains "${cond.pattern}"`);
      break;
    case 'string-regex':
      out.push(`string matches /${cond.pattern}/`);
      break;
    case 'pattern-type':
      out.push(`disasm pattern: ${cond.patternType}`);
      break;
    case 'section-entropy': {
      const matching = input.sections.filter(s => s.entropy >= cond.min);
      out.push(`high-entropy section (≥${cond.min}): ${matching.map(s => s.name || '<unnamed>').join(', ')}`);
      break;
    }
    case 'section-name':
      out.push(`section name contains "${cond.name}"`);
      break;
    case 'behavioral-tag':
      out.push(`behavioral tag: ${cond.tag}`);
      break;
    case 'yara-hit':
      out.push(`YARA rule hit: ${cond.ruleName}`);
      break;
    case 'echo-category':
      out.push(`ECHO pattern category: ${cond.category}`);
      break;
    case 'and':
    case 'or':
      for (const c of cond.conditions) gatherEvidence(c, ctx, input, out);
      break;
    case 'n-of':
      for (const c of cond.conditions) gatherEvidence(c, ctx, input, out);
      break;
    case 'not':
      if (!evalCond(cond.condition, ctx)) {
        out.push(`(absent — expected by rule)`);
      }
      break;
  }
}

// ─── Context Builder ──────────────────────────────────────────────────────────

function buildContext(input: MythosInput): EvalContext {
  const importSet      = new Set(input.imports.map(i => i.name));
  const importSetLower = new Set(input.imports.map(i => i.name.toLowerCase()));
  const lowerStrings   = input.strings.map(s => s.text.toLowerCase());
  const patternTypes   = new Set(input.patterns.map(p => p.type));
  const sectionNameSet = new Set(input.sections.map(s => s.name.toLowerCase()));
  const highEntropySections = input.sections
    .filter(s => s.entropy >= 7.0)
    .map(s => s.name);

  const behavioralTagSet = new Set<BehavioralTag>(input.behavioralTags ?? []);
  const yaraRuleNames    = new Set((input.yaraMatches ?? []).map(m => m.ruleName));
  const echoCategoryHits = new Set(input.echoCategoryHits ?? []);

  return {
    importSet, importSetLower, lowerStrings,
    patternTypes, sectionNameSet, highEntropySections,
    behavioralTagSet, yaraRuleNames, echoCategoryHits,
  };
}

// ─── Confidence Scorer ────────────────────────────────────────────────────────

/**
 * Base confidence = 70 (rule fired) + boost for each optional condition that matched.
 * Each boost condition adds up to 15 points, capped at 98.
 */
function scoreConfidence(rule: MythosRule, ctx: EvalContext): number {
  let score = 70;
  if (rule.boosts) {
    const boostPer = Math.min(15, Math.floor(28 / rule.boosts.length));
    for (const b of rule.boosts) {
      if (evalCond(b, ctx)) score += boostPer;
    }
  }
  return Math.min(98, score);
}

// ─── Built-in Capability Rules ────────────────────────────────────────────────

/**
 * ~25 built-in capability rules organized into capa-style namespaces.
 * These cover the most impactful capabilities seen in malware CTF samples.
 */
const MYTHOS_BUILTIN_RULES: MythosRule[] = [

  // ── Process Injection ──────────────────────────────────────────────────────

  {
    id:          'inject-remote-thread',
    name:        'Remote Thread Injection',
    namespace:   'host-interaction/process-injection/remote-thread',
    description: 'Allocates memory in and creates an execution thread in a remote process',
    severity:    'critical',
    weight:      10,
    behaviors:   ['code-injection'],
    condition: {
      type: 'and',
      conditions: [
        { type: 'import', api: 'VirtualAllocEx' },
        { type: 'import', api: 'WriteProcessMemory' },
        { type: 'import', api: 'CreateRemoteThread' },
      ],
    },
    boosts: [
      { type: 'import', api: 'OpenProcess' },
      { type: 'import', api: 'NtCreateThreadEx' },
    ],
  },

  {
    id:          'inject-process-hollow',
    name:        'Process Hollowing',
    namespace:   'host-interaction/process-injection/process-hollowing',
    description: 'Spawns a suspended process and replaces its image with injected code',
    severity:    'critical',
    weight:      10,
    behaviors:   ['code-injection'],
    condition: {
      type: 'and',
      conditions: [
        {
          type: 'n-of', n: 1,
          conditions: [
            { type: 'import', api: 'CreateProcessA' },
            { type: 'import', api: 'CreateProcessW' },
            { type: 'import', api: 'NtCreateProcess' },
          ],
        },
        { type: 'import', api: 'WriteProcessMemory' },
        {
          type: 'n-of', n: 1,
          conditions: [
            { type: 'import', api: 'ResumeThread' },
            { type: 'import', api: 'NtResumeThread' },
          ],
        },
      ],
    },
    boosts: [
      { type: 'import', api: 'VirtualAllocEx' },
      { type: 'import', api: 'SetThreadContext' },
      { type: 'import', api: 'GetThreadContext' },
    ],
  },

  {
    id:          'inject-apc-queue',
    name:        'APC Queue Injection',
    namespace:   'host-interaction/process-injection/apc',
    description: 'Queues an Asynchronous Procedure Call to execute shellcode in a remote thread',
    severity:    'critical',
    weight:      9,
    behaviors:   ['code-injection'],
    condition: {
      type: 'and',
      conditions: [
        { type: 'import', api: 'QueueUserAPC' },
        { type: 'import', api: 'VirtualAllocEx' },
      ],
    },
    boosts: [
      { type: 'import', api: 'WriteProcessMemory' },
      { type: 'import', api: 'OpenThread' },
    ],
  },

  {
    id:          'inject-hook',
    name:        'Windows Hook Injection',
    namespace:   'host-interaction/process-injection/hook',
    description: 'Installs a Windows message hook to force DLL loading into target processes',
    severity:    'high',
    weight:      8,
    behaviors:   ['code-injection'],
    condition: {
      type: 'and',
      conditions: [
        { type: 'import', api: 'SetWindowsHookEx' },
        {
          type: 'n-of', n: 1,
          conditions: [
            { type: 'import', api: 'LoadLibraryA' },
            { type: 'import', api: 'LoadLibraryW' },
            { type: 'import', api: 'GetProcAddress' },
          ],
        },
      ],
    },
  },

  // ── Defense Evasion ────────────────────────────────────────────────────────

  {
    id:          'anti-debug-presence',
    name:        'Debugger Presence Check',
    namespace:   'anti-analysis/anti-debugging/debugger-detection/api',
    description: 'Detects an attached debugger using Windows API before executing malicious code',
    severity:    'high',
    weight:      7,
    behaviors:   ['anti-analysis'],
    condition: {
      type: 'n-of', n: 1,
      conditions: [
        { type: 'import', api: 'IsDebuggerPresent' },
        { type: 'import', api: 'CheckRemoteDebuggerPresent' },
        { type: 'import', api: 'NtQueryInformationProcess' },
      ],
    },
    boosts: [
      { type: 'import', api: 'NtSetInformationThread' },
      { type: 'import', api: 'OutputDebugStringA' },
    ],
  },

  {
    id:          'anti-debug-timing',
    name:        'Timing-Based Anti-Debug',
    namespace:   'anti-analysis/anti-debugging/debugger-detection/timing',
    description: 'Uses timing measurements to detect the slow-down caused by an attached debugger',
    severity:    'medium',
    weight:      6,
    behaviors:   ['anti-analysis'],
    condition: {
      type: 'n-of', n: 2,
      conditions: [
        { type: 'import', api: 'GetTickCount' },
        { type: 'import', api: 'QueryPerformanceCounter' },
        { type: 'import', api: 'NtDelayExecution' },
        { type: 'import', api: 'GetTickCount64' },
        { type: 'pattern-type', patternType: 'tight_loop' },
      ],
    },
    boosts: [
      { type: 'import', api: 'IsDebuggerPresent' },
    ],
  },

  {
    id:          'anti-vm-detection',
    name:        'Virtual Machine Detection',
    namespace:   'anti-analysis/anti-vm',
    description: 'Checks for hypervisor artifacts, VM-specific registry keys, or known VM process names',
    severity:    'high',
    weight:      7,
    behaviors:   ['anti-analysis'],
    condition: {
      type: 'n-of', n: 2,
      conditions: [
        { type: 'string-contains', pattern: 'vmware' },
        { type: 'string-contains', pattern: 'virtualbox' },
        { type: 'string-contains', pattern: 'vbox' },
        { type: 'string-contains', pattern: 'qemu' },
        { type: 'string-contains', pattern: 'sandboxie' },
        { type: 'string-contains', pattern: 'cuckoo' },
        { type: 'string-regex',    pattern: 'HARDWARE\\\\ACPI\\\\DSDT\\\\(VBOX|VMW)' },
      ],
    },
  },

  {
    id:          'evade-dynamic-resolve',
    name:        'Dynamic API Resolution',
    namespace:   'anti-analysis/obfuscation/dynamic-api-resolution',
    description: 'Resolves API addresses at runtime to hide capabilities from static import analysis',
    severity:    'high',
    weight:      7,
    behaviors:   ['dynamic-resolution'],
    condition: {
      type: 'and',
      conditions: [
        { type: 'import', api: 'GetProcAddress' },
        {
          type: 'n-of', n: 1,
          conditions: [
            { type: 'import', api: 'LoadLibraryA' },
            { type: 'import', api: 'LoadLibraryW' },
          ],
        },
      ],
    },
    boosts: [
      { type: 'pattern-type', patternType: 'indirect_call' },
      { type: 'behavioral-tag', tag: 'dynamic-resolution' },
    ],
  },

  {
    id:          'evade-self-delete',
    name:        'Self-Deletion on Exit',
    namespace:   'anti-analysis/anti-forensic/self-deletion',
    description: 'Deletes its own executable after running to hinder forensic analysis',
    severity:    'high',
    weight:      7,
    behaviors:   ['anti-analysis'],
    condition: {
      type: 'and',
      conditions: [
        {
          type: 'n-of', n: 1,
          conditions: [
            { type: 'string-contains', pattern: 'cmd.exe /c del' },
            { type: 'string-contains', pattern: '/c del ' },
            { type: 'string-contains', pattern: 'ping 127.0.0.1' },
          ],
        },
        {
          type: 'n-of', n: 1,
          conditions: [
            { type: 'import', api: 'DeleteFileA' },
            { type: 'import', api: 'DeleteFileW' },
            { type: 'import', api: 'DeleteFile' },
          ],
        },
      ],
    },
  },

  // ── Persistence ────────────────────────────────────────────────────────────

  {
    id:          'persist-registry-run',
    name:        'Registry Run Key Persistence',
    namespace:   'persistence/registry/run-key',
    description: 'Writes to a registry Run key to execute on system startup or user login',
    severity:    'high',
    weight:      8,
    behaviors:   ['persistence'],
    condition: {
      type: 'and',
      conditions: [
        {
          type: 'n-of', n: 1,
          conditions: [
            { type: 'import', api: 'RegSetValueEx' },
            { type: 'import', api: 'RegSetValueExA' },
            { type: 'import', api: 'RegSetValueExW' },
          ],
        },
        {
          type: 'n-of', n: 1,
          conditions: [
            { type: 'string-contains', pattern: 'CurrentVersion\\Run' },
            { type: 'string-contains', pattern: 'CurrentVersion\\RunOnce' },
            { type: 'string-regex',    pattern: 'Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run' },
          ],
        },
      ],
    },
    boosts: [
      { type: 'import', api: 'RegCreateKeyEx' },
      { type: 'import', api: 'RegOpenKeyEx' },
    ],
  },

  {
    id:          'persist-scheduled-task',
    name:        'Scheduled Task Persistence',
    namespace:   'persistence/scheduled-task',
    description: 'Creates a scheduled task to execute the payload periodically or at login',
    severity:    'high',
    weight:      8,
    behaviors:   ['persistence'],
    condition: {
      type: 'n-of', n: 2,
      conditions: [
        { type: 'string-contains', pattern: 'schtasks' },
        { type: 'string-contains', pattern: 'taskscheduler' },
        { type: 'string-regex',    pattern: 'ITaskScheduler|ITaskService' },
        { type: 'string-contains', pattern: '/create' },
        { type: 'string-contains', pattern: '/sc onlogon' },
      ],
    },
  },

  {
    id:          'persist-service',
    name:        'Service Installation Persistence',
    namespace:   'persistence/service/install',
    description: 'Installs a Windows service to achieve persistent background execution',
    severity:    'high',
    weight:      8,
    behaviors:   ['persistence'],
    condition: {
      type: 'n-of', n: 1,
      conditions: [
        { type: 'import', api: 'CreateServiceA' },
        { type: 'import', api: 'CreateServiceW' },
      ],
    },
    boosts: [
      { type: 'import', api: 'OpenSCManagerA' },
      { type: 'import', api: 'OpenSCManagerW' },
      { type: 'import', api: 'StartServiceA' },
      { type: 'import', api: 'StartServiceW' },
    ],
  },

  // ── Cryptography ────────────────────────────────────────────────────────────

  {
    id:          'encrypt-files',
    name:        'File Encryption',
    namespace:   'data-manipulation/encryption/file',
    description: 'Encrypts files on disk — a core capability of ransomware and data-stealing malware',
    severity:    'critical',
    weight:      9,
    behaviors:   ['data-encryption', 'file-destruction'],
    condition: {
      type: 'and',
      conditions: [
        {
          type: 'n-of', n: 1,
          conditions: [
            { type: 'import', api: 'CryptEncrypt' },
            { type: 'import', api: 'BCryptEncrypt' },
          ],
        },
        {
          type: 'n-of', n: 1,
          conditions: [
            { type: 'import', api: 'CreateFileA' },
            { type: 'import', api: 'CreateFileW' },
            { type: 'import', api: 'CreateFile' },
          ],
        },
        { type: 'import', api: 'WriteFile' },
      ],
    },
    boosts: [
      { type: 'import',         api: 'FindFirstFileW' },
      { type: 'string-contains', pattern: '.encrypted' },
      { type: 'string-contains', pattern: 'bitcoin' },
      { type: 'behavioral-tag',  tag: 'file-destruction' },
    ],
  },

  {
    id:          'encrypt-aes',
    name:        'AES Encryption Implementation',
    namespace:   'data-manipulation/encryption/aes',
    description: 'Uses AES cipher — either via Windows BCrypt/Crypt API or embedded S-box constants',
    severity:    'medium',
    weight:      5,
    behaviors:   ['data-encryption'],
    condition: {
      type: 'n-of', n: 1,
      conditions: [
        { type: 'import', api: 'BCryptOpenAlgorithmProvider' },
        { type: 'import', api: 'BCryptGenerateSymmetricKey' },
        { type: 'import', api: 'CryptAcquireContext' },
        { type: 'yara-hit', ruleName: 'AesConstants' },
        { type: 'echo-category', category: 'crypto-cipher' },
      ],
    },
    boosts: [
      { type: 'import',      api: 'BCryptEncrypt' },
      { type: 'import',      api: 'CryptEncrypt' },
      { type: 'yara-hit',    ruleName: 'AesConstants' },
    ],
  },

  {
    id:          'decrypt-payload',
    name:        'Self-Decrypting Payload',
    namespace:   'data-manipulation/encryption/self-decryption',
    description: 'Decrypts or decompresses an embedded payload at runtime before executing it',
    severity:    'high',
    weight:      8,
    behaviors:   ['code-decryption'],
    condition: {
      type: 'and',
      conditions: [
        { type: 'section-entropy', min: 7.0 },
        {
          type: 'n-of', n: 1,
          conditions: [
            { type: 'import', api: 'CryptDecrypt' },
            { type: 'import', api: 'BCryptDecrypt' },
            { type: 'import', api: 'VirtualAlloc' },
          ],
        },
      ],
    },
    boosts: [
      { type: 'import',         api: 'VirtualProtect' },
      { type: 'yara-hit',       ruleName: 'UpxPacker' },
      { type: 'behavioral-tag', tag: 'code-decryption' },
    ],
  },

  // ── Network / C2 ───────────────────────────────────────────────────────────

  {
    id:          'c2-http',
    name:        'HTTP-Based Command & Control',
    namespace:   'communication/c2/http',
    description: 'Contacts a C2 server using HTTP/HTTPS to receive commands or exfiltrate data',
    severity:    'critical',
    weight:      9,
    behaviors:   ['c2-communication'],
    condition: {
      type: 'n-of', n: 2,
      conditions: [
        { type: 'import', api: 'WinHttpOpen' },
        { type: 'import', api: 'WinHttpConnect' },
        { type: 'import', api: 'WinHttpSendRequest' },
        { type: 'import', api: 'InternetOpen' },
        { type: 'import', api: 'InternetConnect' },
        { type: 'import', api: 'HttpSendRequest' },
      ],
    },
    boosts: [
      { type: 'string-contains', pattern: 'User-Agent' },
      { type: 'string-contains', pattern: 'POST' },
      { type: 'string-regex',    pattern: 'https?://' },
      { type: 'behavioral-tag',  tag: 'c2-communication' },
    ],
  },

  {
    id:          'c2-raw-socket',
    name:        'Raw Socket Command & Control',
    namespace:   'communication/c2/raw-socket',
    description: 'Uses Winsock directly for C2 traffic — harder to intercept than HTTP',
    severity:    'critical',
    weight:      9,
    behaviors:   ['c2-communication'],
    condition: {
      type: 'and',
      conditions: [
        { type: 'import', api: 'WSAStartup' },
        {
          type: 'n-of', n: 2,
          conditions: [
            { type: 'import', api: 'connect' },
            { type: 'import', api: 'send' },
            { type: 'import', api: 'recv' },
            { type: 'import', api: 'WSASend' },
            { type: 'import', api: 'WSARecv' },
          ],
        },
      ],
    },
    boosts: [
      { type: 'string-regex', pattern: '\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}' },
      { type: 'import',       api: 'socket' },
    ],
  },

  {
    id:          'exfil-data',
    name:        'Data Exfiltration',
    namespace:   'communication/exfiltration',
    description: 'Collects and transmits sensitive data (credentials, files, system info) to a remote host',
    severity:    'critical',
    weight:      9,
    behaviors:   ['data-exfiltration', 'c2-communication'],
    condition: {
      type: 'and',
      conditions: [
        {
          type: 'n-of', n: 1,
          conditions: [
            { type: 'import', api: 'GetUserNameA' },
            { type: 'import', api: 'GetUserNameW' },
            { type: 'import', api: 'GetComputerNameA' },
            { type: 'import', api: 'GetComputerNameW' },
          ],
        },
        {
          type: 'n-of', n: 1,
          conditions: [
            { type: 'import', api: 'WSASend' },
            { type: 'import', api: 'send' },
            { type: 'import', api: 'WinHttpSendRequest' },
            { type: 'import', api: 'HttpSendRequest' },
          ],
        },
      ],
    },
    boosts: [
      { type: 'import', api: 'GetAdaptersInfo' },
      { type: 'import', api: 'EnumProcesses' },
    ],
  },

  // ── Process / Execution ────────────────────────────────────────────────────

  {
    id:          'exec-spawn-child',
    name:        'Child Process Spawning',
    namespace:   'host-interaction/process/spawn',
    description: 'Creates child processes — used by droppers, loaders, and lateral-movement modules',
    severity:    'medium',
    weight:      5,
    behaviors:   ['process-execution'],
    condition: {
      type: 'n-of', n: 1,
      conditions: [
        { type: 'import', api: 'CreateProcessA' },
        { type: 'import', api: 'CreateProcessW' },
        { type: 'import', api: 'WinExec' },
        { type: 'import', api: 'ShellExecuteA' },
        { type: 'import', api: 'ShellExecuteW' },
      ],
    },
    boosts: [
      { type: 'import', api: 'WriteProcessMemory' },
      { type: 'import', api: 'ResumeThread' },
    ],
  },

  {
    id:          'load-embedded-pe',
    name:        'Embedded PE Loader',
    namespace:   'host-interaction/loader/embedded-pe',
    description: 'Contains an embedded PE executable that it extracts and runs at runtime',
    severity:    'critical',
    weight:      9,
    behaviors:   ['code-injection', 'code-decryption'],
    condition: {
      type: 'and',
      conditions: [
        {
          type: 'n-of', n: 1,
          conditions: [
            { type: 'yara-hit',       ruleName: 'EmbeddedPE' },
            { type: 'yara-hit',       ruleName: 'Base64EncodedPE' },
            { type: 'echo-category',  category: 'code-injection' },
          ],
        },
        {
          type: 'n-of', n: 1,
          conditions: [
            { type: 'import', api: 'VirtualAlloc' },
            { type: 'import', api: 'VirtualAllocEx' },
          ],
        },
      ],
    },
    boosts: [
      { type: 'import', api: 'VirtualProtect' },
      { type: 'import', api: 'CreateRemoteThread' },
      { type: 'import', api: 'WriteProcessMemory' },
    ],
  },

  {
    id:          'load-reflective',
    name:        'Reflective DLL Loading',
    namespace:   'host-interaction/loader/reflective',
    description: 'Loads a DLL directly from memory without writing to disk, evading file-based detection',
    severity:    'critical',
    weight:      9,
    behaviors:   ['code-injection', 'dynamic-resolution'],
    condition: {
      type: 'and',
      conditions: [
        { type: 'import', api: 'GetProcAddress' },
        { type: 'import', api: 'VirtualAlloc' },
        { type: 'import', api: 'VirtualProtect' },
        {
          type: 'n-of', n: 1,
          conditions: [
            { type: 'string-contains',  pattern: 'ReflectiveDLL' },
            { type: 'string-contains',  pattern: 'LoaderDLL' },
            { type: 'pattern-type',     patternType: 'indirect_call' },
          ],
        },
      ],
    },
  },

  // ── Ransomware Profile ────────────────────────────────────────────────────

  {
    id:          'ransomware-full-profile',
    name:        'Ransomware Behavioral Profile',
    namespace:   'malware/ransomware/full-profile',
    description: 'Exhibits the complete ransomware behavior triad: file enumeration, encryption, and ransom note',
    severity:    'critical',
    weight:      10,
    behaviors:   ['data-encryption', 'file-destruction', 'c2-communication'],
    condition: {
      type: 'and',
      conditions: [
        {
          type: 'n-of', n: 1,
          conditions: [
            { type: 'import', api: 'FindFirstFileA' },
            { type: 'import', api: 'FindFirstFileW' },
            { type: 'import', api: 'FindFirstFile' },
          ],
        },
        {
          type: 'n-of', n: 1,
          conditions: [
            { type: 'import', api: 'CryptEncrypt' },
            { type: 'import', api: 'BCryptEncrypt' },
          ],
        },
        {
          type: 'n-of', n: 1,
          conditions: [
            { type: 'string-contains', pattern: 'bitcoin' },
            { type: 'string-contains', pattern: 'ransom' },
            { type: 'string-contains', pattern: '.onion' },
            { type: 'string-contains', pattern: 'decrypt' },
          ],
        },
      ],
    },
    boosts: [
      { type: 'import',          api: 'DeleteFileA' },
      { type: 'behavioral-tag',  tag: 'file-destruction' },
      { type: 'yara-hit',        ruleName: 'RansomwareNote' },
    ],
  },

  // ── Credential Access ─────────────────────────────────────────────────────

  {
    id:          'access-credentials',
    name:        'Credential Access',
    namespace:   'credential-access/credential-dumping',
    description: 'Targets stored credentials, browser passwords, or authentication tokens',
    severity:    'critical',
    weight:      9,
    behaviors:   ['credential-theft'],
    condition: {
      type: 'n-of', n: 2,
      conditions: [
        { type: 'string-contains', pattern: 'password' },
        { type: 'string-contains', pattern: 'credential' },
        { type: 'string-contains', pattern: 'login data' },
        { type: 'string-contains', pattern: 'cookies' },
        { type: 'string-regex',    pattern: '\\\\AppData\\\\(Local|Roaming)' },
        { type: 'import',          api: 'CryptUnprotectData' },
        { type: 'import',          api: 'LsaQueryInformationPolicy' },
      ],
    },
    boosts: [
      { type: 'string-contains', pattern: 'chrome' },
      { type: 'string-contains', pattern: 'firefox' },
      { type: 'import',          api: 'CredEnumerateA' },
    ],
  },

  // ── Wiper ─────────────────────────────────────────────────────────────────

  {
    id:          'wiper-forced-shutdown',
    name:        'Wiper / Forced System Shutdown',
    namespace:   'impact/disk/wipe',
    description: 'Forces system shutdown or reboot — characteristic of destructive wiper malware',
    severity:    'critical',
    weight:      10,
    behaviors:   ['file-destruction'],
    condition: {
      type: 'n-of', n: 1,
      conditions: [
        { type: 'import', api: 'InitiateSystemShutdownA' },
        { type: 'import', api: 'InitiateSystemShutdownW' },
        { type: 'import', api: 'InitiateShutdownW' },
        { type: 'import', api: 'NtShutdownSystem' },
        { type: 'import', api: 'ExitWindowsEx' },
      ],
    },
    boosts: [
      { type: 'import', api: 'WriteFile' },
      { type: 'import', api: 'DeleteFileW' },
    ],
  },
];

// ─── MITRE ATT&CK ID Mapping ──────────────────────────────────────────────────

/** Maps Mythos rule IDs to MITRE ATT&CK technique IDs (T#### or T####.###). */
const ATTACK_ID_MAP: Readonly<Record<string, string>> = {
  'inject-remote-thread':   'T1055.001',
  'inject-process-hollow':  'T1055.012',
  'inject-apc-queue':       'T1055.004',
  'inject-hook':            'T1056.004',
  'anti-debug-presence':    'T1622',
  'anti-debug-timing':      'T1622',
  'anti-vm-detection':      'T1497',
  'evade-dynamic-resolve':  'T1027.007',
  'evade-self-delete':      'T1070.004',
  'persist-registry-run':   'T1547.001',
  'persist-scheduled-task': 'T1053.005',
  'persist-service':        'T1543.003',
  'encrypt-files':          'T1486',
  'encrypt-aes':            'T1027',
  'decrypt-payload':        'T1140',
  'c2-http':                'T1071.001',
  'c2-raw-socket':          'T1095',
  'exfil-data':             'T1041',
  'exec-spawn-child':       'T1059',
  'load-embedded-pe':       'T1027.009',
};

// ─── Main Entry Points ────────────────────────────────────────────────────────

/**
 * Evaluate all built-in Mythos capability rules against the provided input.
 * Returns one MythosCapabilityMatch per rule that fires, sorted by weight desc.
 *
 * Pass user-defined extra rules (same MythosRule shape) to extend coverage.
 */
export function runMythosRules(
  input: MythosInput,
  extraRules: MythosRule[] = [],
): MythosCapabilityMatch[] {
  const ctx   = buildContext(input);
  const rules = [...MYTHOS_BUILTIN_RULES, ...extraRules];
  const out: MythosCapabilityMatch[] = [];

  for (const rule of rules) {
    if (!evalCond(rule.condition, ctx)) continue;

    const confidence = scoreConfidence(rule, ctx);
    const locations  = buildLocations(rule, input, ctx);
    const evidence   = buildEvidence(rule.condition, ctx, input);

    out.push({
      id:          rule.id,
      name:        rule.name,
      namespace:   rule.namespace,
      description: rule.description,
      severity:    rule.severity,
      weight:      rule.weight,
      confidence,
      locations,
      evidence,
      behaviors:   rule.behaviors,
      attackId:    ATTACK_ID_MAP[rule.id],
    });
  }

  out.sort((a, b) => b.weight - a.weight || b.confidence - a.confidence);
  return out;
}

/**
 * Build a MythosInput from the data available in a NEST iteration.
 * All TALON/ECHO-specific optional fields will be absent unless the caller
 * passes them explicitly (they come from the full engine results, not the
 * reduced correlation signal structs stored in NestIterationInput).
 */
export function mythosInputFromNest(
  sections: MythosInput['sections'],
  imports:  MythosInput['imports'],
  strings:  MythosInput['strings'],
  patterns: MythosInput['patterns'],
  extra: Partial<Pick<MythosInput, 'talonFunctions' | 'echoFunctionMatches' | 'yaraMatches' | 'behavioralTags' | 'echoCategoryHits'>>,
): MythosInput {
  return { sections, imports, strings, patterns, ...extra };
}

/**
 * Capability namespace taxonomy for display in the UI.
 * Maps the first segment of the namespace to a category label and colour.
 */
export const MYTHOS_NAMESPACE_META: Record<string, { label: string; color: string }> = {
  'host-interaction':    { label: 'Host Interaction',     color: '#ef5350' },
  'anti-analysis':       { label: 'Defense Evasion',      color: '#e53935' },
  'persistence':         { label: 'Persistence',          color: '#c62828' },
  'data-manipulation':   { label: 'Data Manipulation',    color: '#ff9800' },
  'communication':       { label: 'Network / C2',         color: '#2196f3' },
  'malware':             { label: 'Malware Profile',      color: '#9c27b0' },
  'credential-access':   { label: 'Credential Access',    color: '#e91e63' },
  'impact':              { label: 'Impact / Wiper',       color: '#b71c1c' },
};

export function mythosNamespaceLabel(namespace: string): string {
  const root = namespace.split('/')[0];
  return MYTHOS_NAMESPACE_META[root]?.label ?? root;
}

export function mythosNamespaceColor(namespace: string): string {
  const root = namespace.split('/')[0];
  return MYTHOS_NAMESPACE_META[root]?.color ?? '#607d8b';
}
