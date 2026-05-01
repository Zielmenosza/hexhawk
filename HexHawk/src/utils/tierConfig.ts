/**
 * tierConfig.ts — Market Tier System
 *
 * Three tiers:
 *   FREE       🟢  Adoption layer: basic TALON, limited console, ≤50 MB files
 *   PRO        🔵  Core users: full engines, patch intelligence, explainability
 *   ENTERPRISE 🔴  Scale layer: NEST (ultimate Enterprise feature), API, automation
 */

// ─── Tier type ────────────────────────────────────────────────────────────────

export type Tier = 'free' | 'pro' | 'enterprise';

export const TIER_ORDER: Record<Tier, number> = {
  free:       0,
  pro:        1,
  enterprise: 2,
};

/** Returns true when the user's current tier meets or exceeds the required tier. */
export function tierAtLeast(current: Tier, required: Tier): boolean {
  return TIER_ORDER[current] >= TIER_ORDER[required];
}

// ─── Display metadata ─────────────────────────────────────────────────────────

export const TIER_DISPLAY: Record<Tier, {
  label:       string;
  badge:       string;
  tagline:     string;
  color:       string;
  borderColor: string;
  bg:          string;
}> = {
  free: {
    label:       'FREE',
    badge:       '🟢',
    tagline:     'Adoption Layer',
    color:       '#4caf50',
    borderColor: 'rgba(76,175,80,0.45)',
    bg:          'rgba(76,175,80,0.10)',
  },
  pro: {
    label:       'PRO',
    badge:       '🔵',
    tagline:     'Core Users',
    color:       '#2196f3',
    borderColor: 'rgba(33,150,243,0.45)',
    bg:          'rgba(33,150,243,0.10)',
  },
  enterprise: {
    label:       'ENTERPRISE',
    badge:       '🔴',
    tagline:     'Scale Layer',
    color:       '#e53935',
    borderColor: 'rgba(229,57,53,0.45)',
    bg:          'rgba(229,57,53,0.10)',
  },
};

// ─── Feature gate: minimum tier per app tab ───────────────────────────────────

export const TAB_MIN_TIER: Record<string, Tier> = {
  // ── FREE ──────────────────────────────────────────────────────────────────
  metadata:    'free',
  hex:         'free',
  strings:     'free',
  cfg:         'free',
  plugins:     'free',
  disassembly: 'free',
  decompile:   'free',   // basic decompilation (no SSA, no LLM)

  // ── PRO ───────────────────────────────────────────────────────────────────
  talon:       'pro',    // full TALON: SSA, data-flow, LLM pass
  constraint:  'pro',    // constraint solver (taint + Z3)
  sandbox:     'pro',    // script sandbox execution
  document:    'pro',    // document analysis (PDF, Office)
  debugger:    'pro',    // native debugger panel
  strike:      'pro',    // STRIKE runtime intelligence
  signatures:  'pro',    // signature matching
  echo:        'pro',    // ECHO fuzzy signatures
  bookmarks:   'pro',    // bookmarks & session history
  logs:        'pro',    // activity logs
  graph:       'pro',    // KITE intelligence graph
  report:      'pro',    // CREST intelligence report
  console:     'pro',    // AERIE operator console (unlimited)

  // ── ENTERPRISE ────────────────────────────────────────────────────────────
  nest:        'enterprise',  // NEST: the ultimate enterprise feature

  // ── PRO (binary diff / version tracking) ─────────────────────────────────
  diff:        'pro',         // Binary Diff: compare two binaries, track version changes
  agent:       'pro',         // Agent Gate: MCP agent signal approval and action log
};

/** Human-readable description of each gated tab shown in the upgrade wall. */
export const TAB_FEATURE_DESC: Record<string, string> = {
  talon:      'Full TALON IR decompiler — SSA passes, data-flow analysis, LLM-assisted decompilation',
  constraint: 'Constraint engine — forward taint propagation, keygen shape detection, Z3 solve',
  sandbox:    'Script sandbox — subprocess execution with memory cap and behaviour signal derivation',
  document:   'Document analysis — PDF content and Office macro parsing',
  debugger:   'Native debugger panel with breakpoints and register inspection',
  strike:     'STRIKE runtime intelligence — cross-platform debug loop, behavioral delta analysis',
  signatures: 'Signature matching — custom YARA-style rule engine',
  echo:       'ECHO fuzzy signature matching — FLARE-derived crypto and obfuscation patterns',
  bookmarks:  'Bookmarks, annotations, and full session history with back/forward navigation',
  logs:       'Activity log — full audit trail of every analysis operation',
  graph:      'KITE knowledge graph — ReactFlow visualisation of signal-to-verdict reasoning',
  report:     'CREST intelligence report — JSON and Markdown export with full reasoning chain',
  console:    'AERIE Operator Console — intent-driven workflow engine with unlimited queries',
  nest:       'NEST iterative convergence analysis — multi-pass dampening, contradiction detection, corpus training, MalwareBazaar integration',
};

/** What to upgrade to in order to unlock each tab. */
export function requiredTierForTab(tab: string): Tier {
  return TAB_MIN_TIER[tab] ?? 'free';
}

// ─── Free-tier limits ─────────────────────────────────────────────────────────

/** Files larger than this trigger a warning banner in Free tier (bytes). */
export const FREE_FILE_SIZE_LIMIT = 50 * 1024 * 1024; // 50 MB

/** Number of console queries allowed per session in Free tier. */
export const FREE_CONSOLE_QUERY_LIMIT = 5;

// ─── Persistence helpers ──────────────────────────────────────────────────────

const LS_KEY = 'hexhawk.tier';
const SS_KEY = 'hexhawk.consoleQueriesUsed';

export function loadTier(): Tier {
  const stored = localStorage.getItem(LS_KEY) as Tier | null;
  if (stored && stored in TIER_ORDER) return stored;
  return 'free';
}

export function saveTier(tier: Tier): void {
  localStorage.setItem(LS_KEY, tier);
}

export function loadConsoleQueriesUsed(): number {
  return Number(sessionStorage.getItem(SS_KEY) ?? '0');
}

export function incrementConsoleQueriesUsed(): number {
  const next = loadConsoleQueriesUsed() + 1;
  sessionStorage.setItem(SS_KEY, String(next));
  return next;
}

// ─── License key storage ──────────────────────────────────────────────────────

const LS_LICENSE_KEY = 'hexhawk.license_key';

/** Persist a validated license key string so it survives app restarts. */
export function saveLicenseKey(key: string): void {
  localStorage.setItem(LS_LICENSE_KEY, key);
}

/** Load the stored license key string, or null if none. */
export function loadLicenseKey(): string | null {
  return localStorage.getItem(LS_LICENSE_KEY);
}

/** Remove the stored license key (deactivate). */
export function clearLicenseKey(): void {
  localStorage.removeItem(LS_LICENSE_KEY);
}
