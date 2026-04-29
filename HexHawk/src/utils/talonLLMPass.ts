/**
 * talonLLMPass.ts — Optional LLM Decompilation Refinement Pass for TALON
 *
 * Architecture:
 *   - Pure function: takes TalonFunctionSummary + TalonLine[], returns LLMPassResult
 *   - Calls a configurable LLM endpoint (Ollama by default, OpenAI-compatible fallback)
 *   - All LLM output is advisory — any error produces a safe fallback (used=false)
 *   - Injectable fetch function for testability
 *
 * Prompt strategy (per architecture-notes.md §3):
 *   - Feed already-structured pseudo-C (Ref-mode, not End-mode)
 *   - Focus on uncertain lines (lineConfidence < 58) to bound token usage
 *   - Include behavioralTags + intent comments as pre-computed hints
 *   - Ask for JSON output: renamed variables, inferred types, refined pseudo-C
 */

import type { TalonFunctionSummary, TalonLine } from './talonEngine';
import { invoke } from '@tauri-apps/api/core';

// ─── Configuration ────────────────────────────────────────────────────────────

export interface LLMPassConfig {
  /** Provider selected for this request. */
  provider: 'open_ai' | 'anthropic' | 'ollama';
  /** Feature action emitted to backend for advisory routing. */
  action: 'signal_explainer' | 'aerie_mode' | 'talon_narrate' | 'crest_narration' | 'binary_diff_insight';
  /** Enable state per provider. */
  providerEnabled: Record<'open_ai' | 'anthropic' | 'ollama', boolean>;
  /** Enable state per AI feature. */
  featureEnabled: Record<'signal_explainer' | 'aerie_mode' | 'talon_narrate' | 'crest_narration' | 'binary_diff_insight', boolean>;
  /** Privacy disclosure must be acknowledged before any model call. */
  privacyDisclosureAccepted: boolean;
  /** Hard cap for aggregate token usage in this session. */
  sessionTokenCap: number;
  /** Current consumed token estimate in this session. */
  sessionTokensUsed: number;
  /** LLM endpoint URL.
   *  Ollama:  http://localhost:11434/api/chat  (default)
   *  OpenAI-compat: any /v1/chat/completions URL */
  endpointUrl: string;
  /** Model name passed to the endpoint. */
  modelName: string;
  /** API key — when set, OpenAI-compatible request format is used. */
  apiKey?: string;
  /** Use keychain-backed API key from backend instead of sending raw key from renderer. */
  useKeychain: boolean;
  /** Key alias for keychain storage lookup. */
  keyAlias: string;
  /** Hard cap for prompt size before transport. */
  maxPromptChars: number;
  /** Token budget for prompt + completion request guardrails. */
  tokenBudget: number;
  /** Require explicit per-request approval from the UI call site. */
  approvalGranted: boolean;
  /** Allow non-local model endpoints; defaults to false. */
  allowRemoteEndpoints: boolean;
  /** Allow tool directives in AI outputs; defaults to false. */
  allowAgentTools: boolean;
  /** Request timeout in milliseconds. */
  timeoutMs: number;
  /** Maximum number of pseudo-C lines included in the prompt. */
  maxPromptLines: number;
}

export const DEFAULT_LLM_CONFIG: Readonly<LLMPassConfig> = {
  provider:      'ollama',
  action:        'talon_narrate',
  providerEnabled: {
    open_ai:   true,
    anthropic: true,
    ollama:    true,
  },
  featureEnabled: {
    signal_explainer:   false,
    aerie_mode:         false,
    talon_narrate:      true,
    crest_narration:    false,
    binary_diff_insight:false,
  },
  privacyDisclosureAccepted: false,
  sessionTokenCap: 20_000,
  sessionTokensUsed: 0,
  endpointUrl:    'http://localhost:11434/api/chat',
  modelName:      'codellama:7b',
  apiKey:         undefined,
  useKeychain:    false,
  keyAlias:       'talon.default',
  maxPromptChars: 24_000,
  tokenBudget:    4_096,
  approvalGranted: true,
  allowRemoteEndpoints: false,
  allowAgentTools: false,
  timeoutMs:      30_000,
  maxPromptLines: 100,
};

interface LlmQueryResponse {
  content: string;
  redactionCount: number;
  promptChars: number;
  tokenEstimate: number;
  endpointHost: string;
  modelName: string;
}

// ─── Result Types ─────────────────────────────────────────────────────────────

/** Mapping from the SSA/IR variable name found in TALON output → suggested human name. */
export type VariableRenameMap = Record<string, string>;

/** Mapping from variable name → inferred C type string. */
export type InferredTypeMap = Record<string, string>;

export interface LLMPassResult {
  /** Proposed variable renames: original_name → human_readable_name. */
  renamedVariables: VariableRenameMap;
  /** Proposed type annotations: variable_name → C type string. */
  inferredTypes: InferredTypeMap;
  /** Full refined pseudo-C as returned (or cleaned) by the model. */
  refinedPseudoC: string;
  /** true when the LLM was successfully called and parsed. */
  used: boolean;
  /** Model that produced this result. */
  modelUsed: string;
  /** Non-null when the pass failed (used will be false). */
  errorMessage: string | null;
}

/** Injectable fetch replacement — allows tests to inject mocks without patching globals. */
export type LLMFetchFn = (url: string, init: RequestInit) => Promise<Response>;

export function redactSensitivePrompt(input: string): { redacted: string; redactionCount: number } {
  const patterns: Array<{ re: RegExp; replacement: string }> = [
    { re: /authorization\s*:\s*bearer\s+[^\s"']+/gi, replacement: 'Authorization: Bearer [REDACTED]' },
    { re: /\bsk-[A-Za-z0-9_-]{12,}\b/g, replacement: '[REDACTED]' },
    { re: /(api[_-]?key\s*[:=]\s*)[^\s"'`]+/gi, replacement: '$1[REDACTED]' },
    { re: /(x-api-key\s*[:=]\s*)[^\s"'`]+/gi, replacement: '$1[REDACTED]' },
  ];

  let redacted = input;
  let redactionCount = 0;
  for (const { re, replacement } of patterns) {
    const matches = redacted.match(re)?.length ?? 0;
    if (matches > 0) {
      redactionCount += matches;
      redacted = redacted.replace(re, replacement);
    }
  }
  return { redacted, redactionCount };
}

function containsToolDirective(content: string): boolean {
  const s = content.toLowerCase();
  return s.includes('"tool_calls"') || s.includes('"function_call"') || s.includes('<tool') || s.includes('tool:');
}

function hasTauriBridge(): boolean {
  return typeof window !== 'undefined' && '__TAURI_INTERNALS__' in (window as unknown as Record<string, unknown>);
}

function estimateTokensFromChars(chars: number): number {
  return Math.ceil(chars / 4);
}

function looksLikeValidApiKey(provider: LLMPassConfig['provider'], apiKey: string): boolean {
  const key = apiKey.trim();
  if (!key) return false;
  if (provider === 'open_ai') return /^sk-[A-Za-z0-9_-]{8,}$/.test(key);
  if (provider === 'anthropic') return /^sk-ant-[A-Za-z0-9_-]{8,}$/.test(key);
  return true;
}

// ─── Prompt Builder ───────────────────────────────────────────────────────────

/**
 * Build a deterministic, structured prompt for the LLM refinement pass.
 *
 * Exported for unit testing.
 */
export function buildLLMPrompt(
  summary:    TalonFunctionSummary,
  lines:      TalonLine[],
  maxLines = DEFAULT_LLM_CONFIG.maxPromptLines,
): string {
  const addr  = `0x${summary.startAddress.toString(16).toUpperCase()}`;
  const conf  = summary.overallConfidence;
  const tags  = summary.behavioralTags.join(', ') || 'none';
  const uncertCount = summary.uncertainStatements;
  const ssaCount    = summary.ssaVarCount;

  // Collect the pseudo-C skeleton.  Only include code/comment/control lines —
  // skip blank lines beyond the first and trim to maxLines to bound tokens.
  const codeLines: string[] = [];
  let blankRun = 0;
  for (const line of lines) {
    if (codeLines.length >= maxLines) break;
    if (line.kind === 'blank') {
      if (blankRun < 1) { codeLines.push(''); blankRun++; }
      continue;
    }
    blankRun = 0;
    const indent = '  '.repeat(line.indent);
    const uncertain = line.lineConfidence < 58 &&
      line.kind !== 'comment' &&
      line.kind !== 'intent-comment' &&
      line.kind !== 'brace' ? ' /* ?? */' : '';
    codeLines.push(`${indent}${line.text}${uncertain}`);
  }
  const pseudoC = codeLines.join('\n');

  return [
    `// Function: ${summary.name} @ ${addr}`,
    `// Confidence: ${conf}%  |  SSA variables: ${ssaCount}  |  Uncertain statements: ${uncertCount}`,
    `// Behavioral hints: ${tags}`,
    `//`,
    `// Pseudo-C (TALON structural pass):`,
    `// ─────────────────────────────────────────────`,
    pseudoC,
    `// ─────────────────────────────────────────────`,
    `//`,
    `// Task:`,
    `//   1. Rename generic variables (rax₀, rbp-8₀, …) to meaningful names.`,
    `//   2. Infer C types for each renamed variable.`,
    `//   3. Rewrite the pseudo-C above with your renames and type annotations.`,
    `//`,
    `// Return ONLY a JSON object in this exact shape (no markdown, no prose):`,
    `// {`,
    `//   "renamedVariables": { "<original>": "<humanName>", … },`,
    `//   "inferredTypes":    { "<humanName>": "<cType>", … },`,
    `//   "refinedPseudoC":   "<full rewritten pseudo-C string>"`,
    `// }`,
  ].join('\n');
}

// ─── Response Parser ──────────────────────────────────────────────────────────

/**
 * Parse and validate the raw JSON string returned by the LLM.
 *
 * Exported for unit testing.
 *
 * @param rawContent - The `message.content` string from the LLM response.
 * @param modelName  - Model name to embed in the result.
 */
export function parseLLMResponse(rawContent: string, modelName: string): LLMPassResult {
  // Strip markdown code-fences if the model wrapped its JSON
  const stripped = rawContent
    .replace(/^```(?:json)?\s*/i, '')
    .replace(/\s*```\s*$/, '')
    .trim();

  let parsed: unknown;
  try {
    parsed = JSON.parse(stripped);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return makeFallback(`LLM returned non-JSON content: ${msg}`, modelName);
  }

  if (typeof parsed !== 'object' || parsed === null) {
    return makeFallback('LLM response is not a JSON object', modelName);
  }

  const obj = parsed as Record<string, unknown>;

  const renamedVariables = isStringRecord(obj['renamedVariables'])
    ? (obj['renamedVariables'] as VariableRenameMap)
    : {};

  const inferredTypes = isStringRecord(obj['inferredTypes'])
    ? (obj['inferredTypes'] as InferredTypeMap)
    : {};

  const refinedPseudoC = typeof obj['refinedPseudoC'] === 'string'
    ? obj['refinedPseudoC']
    : '';

  return {
    renamedVariables,
    inferredTypes,
    refinedPseudoC,
    used:         true,
    modelUsed:    modelName,
    errorMessage: null,
  };
}

function isStringRecord(v: unknown): v is Record<string, string> {
  if (typeof v !== 'object' || v === null) return false;
  return Object.values(v).every(val => typeof val === 'string');
}

function makeFallback(errorMessage: string, modelName = ''): LLMPassResult {
  return {
    renamedVariables: {},
    inferredTypes:    {},
    refinedPseudoC:   '',
    used:             false,
    modelUsed:        modelName,
    errorMessage,
  };
}

// ─── HTTP Helpers ─────────────────────────────────────────────────────────────

/**
 * Extract the assistant message content string from a raw LLM HTTP response.
 * Handles both Ollama and OpenAI-compatible response shapes.
 */
async function extractContent(response: Response): Promise<string> {
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
  }
  const body = (await response.json()) as Record<string, unknown>;

  // OpenAI-compatible: { choices: [{ message: { content: "..." } }] }
  if (Array.isArray(body['choices'])) {
    const first = (body['choices'] as Record<string, unknown>[])[0];
    const msg = first?.['message'] as Record<string, unknown> | undefined;
    const content = msg?.['content'];
    if (typeof content === 'string') return content;
  }

  // Ollama: { message: { content: "..." } }
  const ollamaMsg = body['message'] as Record<string, unknown> | undefined;
  const content   = ollamaMsg?.['content'];
  if (typeof content === 'string') return content;

  // Anthropic: { content: [{ type: "text", text: "..." }] }
  if (Array.isArray(body['content'])) {
    for (const part of body['content'] as Array<Record<string, unknown>>) {
      if (part.type === 'text' && typeof part.text === 'string') {
        return part.text;
      }
    }
  }

  throw new Error('Unexpected LLM response shape — could not locate message content');
}

// ─── Public API: runLLMPass ───────────────────────────────────────────────────

/**
 * Run the LLM decompilation refinement pass.
 *
 * - Never throws: any error produces a safe fallback result (used=false).
 * - Uses AbortController for the configured timeout.
 * - fetchFn is injectable for unit tests.
 */
export async function runLLMPass(
  summary:   TalonFunctionSummary,
  lines:     TalonLine[],
  config:    Partial<LLMPassConfig> = {},
  fetchFn:   LLMFetchFn = (url, init) => fetch(url, init),
): Promise<LLMPassResult> {
  const cfg: LLMPassConfig = { ...DEFAULT_LLM_CONFIG, ...config };

  if (!cfg.privacyDisclosureAccepted) {
    return makeFallback('LLM request blocked: privacy disclosure acknowledgement is required.', cfg.modelName);
  }

  if (!cfg.providerEnabled[cfg.provider]) {
    return makeFallback(`LLM request blocked: provider ${cfg.provider} is disabled.`, cfg.modelName);
  }

  if (!cfg.featureEnabled[cfg.action]) {
    return makeFallback(`LLM request blocked: feature ${cfg.action} is disabled.`, cfg.modelName);
  }

  if (!cfg.approvalGranted) {
    return makeFallback('LLM request blocked: explicit user approval not granted.', cfg.modelName);
  }

  const prompt = buildLLMPrompt(summary, lines, cfg.maxPromptLines);
  const estimatedPromptTokens = estimateTokensFromChars(prompt.length);
  if (cfg.sessionTokensUsed + estimatedPromptTokens > cfg.sessionTokenCap) {
    return makeFallback(
      `LLM request blocked: session token cap exceeded (${cfg.sessionTokensUsed + estimatedPromptTokens}/${cfg.sessionTokenCap}).`,
      cfg.modelName,
    );
  }
  if (prompt.length > cfg.maxPromptChars) {
    return makeFallback(
      `LLM request blocked: prompt too large (${prompt.length} chars, max ${cfg.maxPromptChars}).`,
      cfg.modelName,
    );
  }

  const { redacted: redactedPrompt } = redactSensitivePrompt(prompt);

  if (cfg.provider !== 'ollama') {
    const hasInlineKey = Boolean(cfg.apiKey?.trim());
    if (!cfg.useKeychain && !hasInlineKey) {
      return makeFallback(
        'LLM unavailable offline: no API key configured for selected provider. Add a key in BYOK settings.',
        cfg.modelName,
      );
    }
    if (hasInlineKey && !looksLikeValidApiKey(cfg.provider, cfg.apiKey!)) {
      return makeFallback(
        `LLM request blocked: API key format for ${cfg.provider} appears invalid.`,
        cfg.modelName,
      );
    }
  }

  if (hasTauriBridge()) {
    try {
      if (cfg.provider !== 'ollama' && cfg.useKeychain) {
        const hasStored = await invoke<boolean>('has_llm_provider_key', {
          provider: cfg.provider,
          keyAlias: cfg.keyAlias,
        });
        if (!hasStored) {
          return makeFallback(
            'LLM unavailable offline: no stored API key found for selected provider alias.',
            cfg.modelName,
          );
        }
      }

      const response = await invoke<LlmQueryResponse>('llm_query', {
        request: {
          provider: cfg.provider,
          action: cfg.action,
          endpointUrl: cfg.endpointUrl,
          modelName: cfg.modelName,
          prompt: redactedPrompt,
          timeoutMs: cfg.timeoutMs,
          maxPromptChars: cfg.maxPromptChars,
          tokenBudget: cfg.tokenBudget,
          approvalGranted: cfg.approvalGranted,
          allowRemoteEndpoint: cfg.allowRemoteEndpoints,
          allowAgentTools: cfg.allowAgentTools,
          apiKey: cfg.useKeychain ? undefined : cfg.apiKey,
          useKeychainKey: cfg.useKeychain,
          keyAlias: cfg.keyAlias,
        },
      });

      if (!cfg.allowAgentTools && containsToolDirective(response.content)) {
        return makeFallback('LLM response contained tool directives but tool execution is not approved.', cfg.modelName);
      }

      return parseLLMResponse(response.content, cfg.modelName);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (cfg.provider === 'ollama') {
        return makeFallback(`LLM request failed: local Ollama unavailable (${msg}).`, cfg.modelName);
      }
      return makeFallback(`LLM request failed: ${msg}`, cfg.modelName);
    }
  }

  if (cfg.provider !== 'ollama' && cfg.useKeychain && !cfg.apiKey?.trim()) {
    return makeFallback(
      'LLM unavailable offline: keychain lookup requires desktop bridge; add a temporary API key or run in desktop mode.',
      cfg.modelName,
    );
  }

  const isOpenAI = cfg.provider === 'open_ai';
  const isAnthropic = cfg.provider === 'anthropic';

  const body = isOpenAI
    ? JSON.stringify({
        model:           cfg.modelName,
        messages:        [{ role: 'user', content: redactedPrompt }],
        response_format: { type: 'json_object' },
        tool_choice:     'none',
        parallel_tool_calls: false,
        max_tokens: Math.max(64, Math.min(2048, Math.floor(cfg.tokenBudget / 2))),
      })
    : isAnthropic
    ? JSON.stringify({
        model:      cfg.modelName,
        max_tokens: Math.max(64, Math.min(2048, Math.floor(cfg.tokenBudget / 2))),
        messages:   [{ role: 'user', content: redactedPrompt }],
      })
    : JSON.stringify({
        model:    cfg.modelName,
        messages: [{ role: 'user', content: redactedPrompt }],
        stream:   false,
        format:   'json',
        options:  { num_predict: Math.max(64, Math.min(2048, Math.floor(cfg.tokenBudget / 2))) },
      });

  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (cfg.provider === 'open_ai' && cfg.apiKey) {
    headers['Authorization'] = `Bearer ${cfg.apiKey}`;
  }
  if (cfg.provider === 'anthropic' && cfg.apiKey) {
    headers['x-api-key'] = cfg.apiKey;
    headers['anthropic-version'] = '2023-06-01';
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), cfg.timeoutMs);

  try {
    const response = await fetchFn(cfg.endpointUrl, {
      method:  'POST',
      headers,
      body,
      signal:  controller.signal,
    });
    const content = await extractContent(response);
    if (!cfg.allowAgentTools && containsToolDirective(content)) {
      return makeFallback('LLM response contained tool directives but tool execution is not approved.', cfg.modelName);
    }
    return parseLLMResponse(content, cfg.modelName);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (cfg.provider === 'ollama') {
      return makeFallback(`LLM request failed: local Ollama unavailable (${msg})`, cfg.modelName);
    }
    return makeFallback(
      msg.includes('aborted') || msg.includes('abort')
        ? `LLM request timed out after ${cfg.timeoutMs}ms`
        : `LLM request failed: ${msg}`,
      cfg.modelName,
    );
  } finally {
    clearTimeout(timer);
  }
}

// ─── Line Applicator ──────────────────────────────────────────────────────────

/**
 * Apply variable renames from an LLMPassResult to a TalonLine[].
 *
 * Pure function — returns a new array with renamed text; does not mutate inputs.
 * Only lines whose `text` contains at least one mapped variable are touched.
 */
export function applyLLMRenames(
  lines:  TalonLine[],
  result: LLMPassResult,
): TalonLine[] {
  if (!result.used || Object.keys(result.renamedVariables).length === 0) {
    return lines;
  }

  // Build a single-pass regex that replaces all known SSA names.
  // Sort longer names first to avoid partial substitution.
  const origNames = Object.keys(result.renamedVariables).sort(
    (a, b) => b.length - a.length,
  );
  // Escape special regex chars in variable names (subscript digits are fine)
  const pattern = new RegExp(
    origNames.map(n => n.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|'),
    'g',
  );

  return lines.map(line => {
    if (line.kind === 'blank' || line.kind === 'brace') return line;
    const newText = line.text.replace(pattern, m => result.renamedVariables[m] ?? m);
    if (newText === line.text) return line;          // no change — skip allocation
    return { ...line, text: newText };
  });
}
