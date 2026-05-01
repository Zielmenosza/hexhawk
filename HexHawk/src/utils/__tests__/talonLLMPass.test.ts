/**
 * talonLLMPass.test.ts — Vitest tests for the TALON LLM decompilation pass.
 *
 * All tests use injected mock fetch functions — no real network calls are made.
 */

import { describe, it, expect, vi } from 'vitest';
import {
  buildLLMPrompt,
  parseLLMResponse,
  runLLMPass,
  redactSensitivePrompt,
  applyLLMRenames,
  DEFAULT_LLM_CONFIG,
  type LLMPassResult,
  type LLMFetchFn,
} from '../../utils/talonLLMPass';

const BYOK_BASE = {
  privacyDisclosureAccepted: true,
  provider: 'ollama' as const,
  action: 'talon_narrate' as const,
  providerEnabled: {
    open_ai: true,
    anthropic: true,
    ollama: true,
  },
  featureEnabled: {
    signal_explainer: false,
    aerie_mode: false,
    talon_narrate: true,
    crest_narration: false,
    binary_diff_insight: false,
  },
  sessionTokenCap: 20_000,
  sessionTokensUsed: 0,
};
import type { TalonFunctionSummary, TalonLine } from '../../utils/talonEngine';

// ── Fixtures ───────────────────────────────────────────────────────────────────

function makeSummary(overrides: Partial<TalonFunctionSummary> = {}): TalonFunctionSummary {
  return {
    name:                 'sub_1000',
    startAddress:         0x1000,
    overallConfidence:    72,
    liftingCoverage:      88,
    intents:              [],
    behavioralTags:       ['anti-analysis', 'data-encryption'],
    uncertainStatements:  3,
    totalStatements:      12,
    complexityScore:      4,
    warningCount:         0,
    ssaVarCount:          7,
    loopNestingDepth:     1,
    naturalLoops:         [],
    ...overrides,
  };
}

function makeLine(
  text:            string,
  kind:            TalonLine['kind'] = 'stmt',
  lineConfidence = 80,
  indent         = 0,
): TalonLine {
  return { text, kind, lineConfidence, indent };
}

/** Build a minimal mock Response from a JSON-serialisable body. */
function mockResponse(body: unknown, status = 200): Response {
  return {
    ok:   status >= 200 && status < 300,
    status,
    statusText: status === 200 ? 'OK' : 'Error',
    json: async () => body,
  } as unknown as Response;
}

/** Build a mock fetch that returns an Ollama-style response. */
function ollamaFetch(content: string, status = 200): LLMFetchFn {
  return async () => mockResponse(
    { message: { role: 'assistant', content }, done: true },
    status,
  );
}

/** Build a mock fetch that returns an OpenAI-style response. */
function openAIFetch(content: string): LLMFetchFn {
  return async () => mockResponse({
    choices: [{ message: { role: 'assistant', content } }],
  });
}

// ── Test 1: buildLLMPrompt ─────────────────────────────────────────────────────

describe('buildLLMPrompt', () => {
  it('includes behavioral tags and function address in the prompt header', () => {
    const summary = makeSummary();
    const lines: TalonLine[] = [
      makeLine('rax₀ = IsDebuggerPresent();', 'stmt',    90),
      makeLine('if (rax₀ != 0) {',           'control',   85),
      makeLine('  rax₁ = CryptEncrypt();',    'stmt',      35),  // uncertain
    ];

    const prompt = buildLLMPrompt(summary, lines);

    expect(prompt).toContain('sub_1000');
    expect(prompt).toContain('0x1000');
    expect(prompt).toContain('anti-analysis');
    expect(prompt).toContain('data-encryption');
    expect(prompt).toContain('72%');             // overallConfidence
    expect(prompt).toContain('SSA variables: 7');
  });

  it('marks uncertain lines (lineConfidence < 58) with /* ?? */ annotation', () => {
    const summary = makeSummary({ uncertainStatements: 1 });
    const lines: TalonLine[] = [
      makeLine('rax₂ = unknown_api();', 'stmt', 40),  // uncertain
      makeLine('return rax₂;',          'stmt', 90),  // certain
    ];

    const prompt = buildLLMPrompt(summary, lines);

    const uncertainLine = prompt
      .split('\n')
      .find(l => l.includes('unknown_api'));

    expect(uncertainLine).toBeDefined();
    expect(uncertainLine).toContain('/* ?? */');

    const certainLine = prompt
      .split('\n')
      .find(l => l.includes('return rax₂'));

    expect(certainLine).toBeDefined();
    expect(certainLine).not.toContain('/* ?? */');
  });

  it('respects maxLines to cap prompt size', () => {
    const summary  = makeSummary();
    const manyLines = Array.from({ length: 200 }, (_, i) =>
      makeLine(`var_${i} = ${i};`, 'stmt', 80),
    );

    const full     = buildLLMPrompt(summary, manyLines, 200);
    const capped   = buildLLMPrompt(summary, manyLines, 10);

    // Count how many `var_N = N;` entries appear in each
    const fullCount  = (full.match(/var_\d+ = \d+/g) ?? []).length;
    const cappedCount = (capped.match(/var_\d+ = \d+/g) ?? []).length;

    expect(fullCount).toBeGreaterThan(cappedCount);
    expect(cappedCount).toBeLessThanOrEqual(10);
  });

  it('includes the JSON schema description in the prompt', () => {
    const prompt = buildLLMPrompt(makeSummary(), []);
    expect(prompt).toContain('renamedVariables');
    expect(prompt).toContain('inferredTypes');
    expect(prompt).toContain('refinedPseudoC');
  });
});

// ── Test 2: parseLLMResponse ───────────────────────────────────────────────────

describe('parseLLMResponse', () => {
  it('correctly parses a well-formed JSON response', () => {
    const content = JSON.stringify({
      renamedVariables: { 'rax₀': 'isDebugged', 'rbp-8₀': 'encryptedBuf' },
      inferredTypes:    { 'isDebugged': 'BOOL', 'encryptedBuf': 'LPVOID' },
      refinedPseudoC:   'BOOL isDebugged = IsDebuggerPresent();\nif (isDebugged) { ... }',
    });

    const result = parseLLMResponse(content, 'codellama:7b');

    expect(result.used).toBe(true);
    expect(result.modelUsed).toBe('codellama:7b');
    expect(result.errorMessage).toBeNull();
    expect(result.renamedVariables['rax₀']).toBe('isDebugged');
    expect(result.inferredTypes['isDebugged']).toBe('BOOL');
    expect(result.refinedPseudoC).toContain('IsDebuggerPresent');
  });

  it('strips markdown code-fences before parsing', () => {
    const fenced = '```json\n{"renamedVariables":{},"inferredTypes":{},"refinedPseudoC":""}\n```';
    const result = parseLLMResponse(fenced, 'test-model');
    expect(result.used).toBe(true);
    expect(result.errorMessage).toBeNull();
  });

  it('returns fallback (used=false) for non-JSON content', () => {
    const result = parseLLMResponse('Sorry, I cannot help with that.', 'test-model');
    expect(result.used).toBe(false);
    expect(result.errorMessage).not.toBeNull();
    expect(result.renamedVariables).toEqual({});
  });

  it('returns empty maps for missing keys without throwing', () => {
    const result = parseLLMResponse('{"refinedPseudoC":"void f(){}"}', 'test-model');
    expect(result.used).toBe(true);
    expect(result.renamedVariables).toEqual({});
    expect(result.inferredTypes).toEqual({});
    expect(result.refinedPseudoC).toBe('void f(){}');
  });
});

// ── Test 3: runLLMPass — success path ─────────────────────────────────────────

describe('runLLMPass (success)', () => {
  it('returns parsed renames when the Ollama endpoint responds correctly', async () => {
    const responseContent = JSON.stringify({
      renamedVariables: { 'rax₀': 'debugHandle', 'rbp-0x10₀': 'bufferPtr' },
      inferredTypes:    { 'debugHandle': 'HANDLE', 'bufferPtr': 'LPBYTE' },
      refinedPseudoC:   'HANDLE debugHandle = IsDebuggerPresent();',
    });

    const summary = makeSummary();
    const lines: TalonLine[] = [makeLine('rax₀ = IsDebuggerPresent();')];

    const result = await runLLMPass(summary, lines, BYOK_BASE, ollamaFetch(responseContent));

    expect(result.used).toBe(true);
    expect(result.errorMessage).toBeNull();
    expect(result.renamedVariables['rax₀']).toBe('debugHandle');
    expect(result.inferredTypes['debugHandle']).toBe('HANDLE');
    expect(result.modelUsed).toBe(DEFAULT_LLM_CONFIG.modelName);
  });

  it('uses OpenAI response format when apiKey is provided', async () => {
    const content = JSON.stringify({
      renamedVariables: { 'rax₀': 'retVal' },
      inferredTypes:    { 'retVal': 'DWORD' },
      refinedPseudoC:   'DWORD retVal = 0;',
    });

    const summary = makeSummary();
    const lines: TalonLine[] = [makeLine('rax₀ = 0;')];

    const result = await runLLMPass(
      summary,
      lines,
      {
        ...BYOK_BASE,
        provider: 'open_ai',
        apiKey: 'sk-test-key',
        endpointUrl: 'https://api.openai.com/v1/chat/completions',
      },
      openAIFetch(content),
    );

    expect(result.used).toBe(true);
    expect(result.renamedVariables['rax₀']).toBe('retVal');
  });

  it('passes the correct model name to the request body', async () => {
    const capturedBodies: string[] = [];
    const spyFetch: LLMFetchFn = async (_url, init) => {
      capturedBodies.push(init.body as string);
      return ollamaFetch(
        JSON.stringify({ renamedVariables: {}, inferredTypes: {}, refinedPseudoC: '' }),
      )(_url, init);
    };

    await runLLMPass(
      makeSummary(),
      [],
      { ...BYOK_BASE, modelName: 'mistral:7b' },
      spyFetch,
    );

    expect(capturedBodies).toHaveLength(1);
    const body = JSON.parse(capturedBodies[0]);
    expect(body.model).toBe('mistral:7b');
  });
});

// ── Test 4: runLLMPass — failure / fallback path ───────────────────────────────

describe('runLLMPass (failure fallback)', () => {
  it('blocks request when explicit approval is not granted', async () => {
    const result = await runLLMPass(
      makeSummary(),
      [],
      { ...BYOK_BASE, approvalGranted: false },
      ollamaFetch('{"renamedVariables":{},"inferredTypes":{},"refinedPseudoC":""}'),
    );

    expect(result.used).toBe(false);
    expect(result.errorMessage).toContain('approval');
  });

  it('returns used=false when fetch throws a network error', async () => {
    const failFetch: LLMFetchFn = async () => {
      throw new Error('Network unreachable');
    };

    const result = await runLLMPass(makeSummary(), [], BYOK_BASE, failFetch);

    expect(result.used).toBe(false);
    expect(result.errorMessage).toContain('Network unreachable');
    expect(result.renamedVariables).toEqual({});
    expect(result.refinedPseudoC).toBe('');
  });

  it('returns used=false when the HTTP status is not ok (e.g. 503)', async () => {
    const errorFetch: LLMFetchFn = async () => mockResponse({ error: 'service unavailable' }, 503);

    const result = await runLLMPass(makeSummary(), [], BYOK_BASE, errorFetch);

    expect(result.used).toBe(false);
    expect(result.errorMessage).toContain('503');
  });

  it('returns used=false when the LLM returns malformed JSON', async () => {
    const result = await runLLMPass(
      makeSummary(),
      [],
      BYOK_BASE,
      ollamaFetch('Sure! Here are some variable names...'),
    );

    expect(result.used).toBe(false);
    expect(result.errorMessage).not.toBeNull();
  });

  it('never throws regardless of failure mode', async () => {
    const alwaysThrows: LLMFetchFn = async () => { throw new TypeError('Fatal'); };

    // Must resolve, not reject
    await expect(runLLMPass(makeSummary(), [], BYOK_BASE, alwaysThrows)).resolves.toBeDefined();
  });

  it('clears timeout timer in request finally path', async () => {
    const clearSpy = vi.spyOn(globalThis, 'clearTimeout');
    const hangingFetch: LLMFetchFn = async () => {
      throw new Error('aborted');
    };

    await runLLMPass(makeSummary(), [], { ...BYOK_BASE, timeoutMs: 10 }, hangingFetch);

    expect(clearSpy).toHaveBeenCalled();
  });
});

describe('redactSensitivePrompt', () => {
  it('redacts inline API-key-like values before transport', () => {
    const text = 'Authorization: Bearer sk-ABCDEF1234567890\napi_key=super_secret';
    const out = redactSensitivePrompt(text);
    expect(out.redactionCount).toBeGreaterThanOrEqual(2);
    expect(out.redacted).toContain('[REDACTED]');
    expect(out.redacted).not.toContain('super_secret');
  });

  it('missing key: blocks remote provider call with graceful fallback', async () => {
    const fetchSpy = vi.fn(ollamaFetch('{"renamedVariables":{},"inferredTypes":{},"refinedPseudoC":""}'));
    const result = await runLLMPass(
      makeSummary(),
      [makeLine('rax = 1;')],
      {
        ...BYOK_BASE,
        provider: 'open_ai',
        useKeychain: false,
        apiKey: '',
      },
      fetchSpy,
    );

    expect(result.used).toBe(false);
    expect(result.errorMessage).toContain('no API key configured');
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('invalid key: rejects malformed provider key and does not call model', async () => {
    const fetchSpy = vi.fn(ollamaFetch('{"renamedVariables":{},"inferredTypes":{},"refinedPseudoC":""}'));
    const result = await runLLMPass(
      makeSummary(),
      [makeLine('rax = 1;')],
      {
        ...BYOK_BASE,
        provider: 'open_ai',
        useKeychain: false,
        apiKey: 'bad',
      },
      fetchSpy,
    );

    expect(result.used).toBe(false);
    expect(result.errorMessage).toContain('invalid');
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('disabled feature: blocks call when talon_narrate feature toggle is off', async () => {
    const fetchSpy = vi.fn(ollamaFetch('{"renamedVariables":{},"inferredTypes":{},"refinedPseudoC":""}'));
    const result = await runLLMPass(
      makeSummary(),
      [makeLine('rax = 1;')],
      {
        ...BYOK_BASE,
        featureEnabled: {
          ...BYOK_BASE.featureEnabled,
          talon_narrate: false,
        },
      },
      fetchSpy,
    );

    expect(result.used).toBe(false);
    expect(result.errorMessage).toContain('feature');
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('cap exceeded: blocks call when per-session cap would be exceeded', async () => {
    const fetchSpy = vi.fn(ollamaFetch('{"renamedVariables":{},"inferredTypes":{},"refinedPseudoC":""}'));
    const result = await runLLMPass(
      makeSummary(),
      [makeLine('x = y + z;')],
      {
        ...BYOK_BASE,
        sessionTokenCap: 10,
        sessionTokensUsed: 9,
      },
      fetchSpy,
    );

    expect(result.used).toBe(false);
    expect(result.errorMessage).toContain('cap exceeded');
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('provider disabled: blocks call for disabled provider', async () => {
    const fetchSpy = vi.fn(ollamaFetch('{"renamedVariables":{},"inferredTypes":{},"refinedPseudoC":""}'));
    const result = await runLLMPass(
      makeSummary(),
      [makeLine('rax = 1;')],
      {
        ...BYOK_BASE,
        provider: 'anthropic',
        providerEnabled: {
          ...BYOK_BASE.providerEnabled,
          anthropic: false,
        },
      },
      fetchSpy,
    );

    expect(result.used).toBe(false);
    expect(result.errorMessage).toContain('provider');
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('local Ollama unavailable: reports graceful local fallback message', async () => {
    const unavailableFetch: LLMFetchFn = async () => {
      throw new Error('ECONNREFUSED 127.0.0.1:11434');
    };

    const result = await runLLMPass(
      makeSummary(),
      [makeLine('rax = 1;')],
      {
        ...BYOK_BASE,
        provider: 'ollama',
      },
      unavailableFetch,
    );

    expect(result.used).toBe(false);
    expect(result.errorMessage).toContain('Ollama unavailable');
  });
});

// ── Test 5: applyLLMRenames ────────────────────────────────────────────────────

describe('applyLLMRenames', () => {
  function makeResult(renames: Record<string, string>): LLMPassResult {
    return {
      renamedVariables: renames,
      inferredTypes:    {},
      refinedPseudoC:   '',
      used:             true,
      modelUsed:        'test',
      errorMessage:     null,
    };
  }

  it('substitutes known SSA names in line text', () => {
    const lines: TalonLine[] = [
      makeLine('rax₀ = IsDebuggerPresent();'),
      makeLine('if (rax₀ != 0) {', 'control'),
    ];

    const result = applyLLMRenames(lines, makeResult({ 'rax₀': 'isDebugged' }));

    expect(result[0].text).toBe('isDebugged = IsDebuggerPresent();');
    expect(result[1].text).toBe('if (isDebugged != 0) {');
  });

  it('does not mutate the original lines array', () => {
    const original: TalonLine[] = [makeLine('rax₀ = 0;')];
    const copy = original[0].text;

    applyLLMRenames(original, makeResult({ 'rax₀': 'counter' }));

    expect(original[0].text).toBe(copy);
  });

  it('returns the original array unchanged when used=false', () => {
    const lines: TalonLine[] = [makeLine('rax₀ = 0;')];
    const notUsed: LLMPassResult = { ...makeResult({}), used: false };

    const out = applyLLMRenames(lines, notUsed);
    expect(out).toBe(lines);
  });

  it('handles multiple renames in the same line', () => {
    const lines: TalonLine[] = [
      makeLine('rbp-8₀ = rax₀ + rcx₀;'),
    ];
    const out = applyLLMRenames(lines, makeResult({
      'rax₀':   'srcPtr',
      'rcx₀':   'count',
      'rbp-8₀': 'result',
    }));

    expect(out[0].text).toBe('result = srcPtr + count;');
  });
});
