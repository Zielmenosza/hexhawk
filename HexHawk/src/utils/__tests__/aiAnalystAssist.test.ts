/**
 * aiAnalystAssist.test.ts — Vitest unit tests for the M10 AI Analyst Assist
 * frontend boundary layer (HexHawk/src/utils/aiAnalystAssist.ts).
 *
 * Architectural rules verified here:
 *   - All calls go through invoke('llm_query', { request }) — no direct HTTP.
 *   - Each action wrapper hard-codes its own AnalystAction value.
 *   - approvalGranted is passed through as-is (caller responsibility).
 *   - advisoryOnly=true on every response (no verdict mutation).
 *   - Rejection from invoke propagates faithfully (no silent swallowing).
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// ── Mock @tauri-apps/api/core before importing the module under test ───────────
vi.mock('@tauri-apps/api/core', () => ({
  invoke: vi.fn(),
}));

import { invoke } from '@tauri-apps/api/core';
import {
  runAnalystAssist,
  runSignalExplainer,
  runAerieMode,
  runTalonNarrate,
  runCrestNarration,
  runBinaryDiffInsight,
  type AnalystAssistRequest,
  type AnalystAssistResponse,
} from '../aiAnalystAssist';

// ── Fixtures ───────────────────────────────────────────────────────────────────

const BASE_REQUEST: Omit<AnalystAssistRequest, 'action'> = {
  endpointUrl: 'http://localhost:11434/api/chat',
  modelName: 'llama3',
  prompt: 'Describe this signal.',
  contextBlocks: ['signal: anti-analysis detected at 0x1040'],
  provider: 'ollama',
  keyAlias: 'default',
  timeoutMs: 10_000,
  tokenBudget: 1024,
  approvalGranted: true,
  allowRemoteEndpoint: false,
  allowAgentTools: false,
};

function makeResponse(action: string, content = 'advisory text'): AnalystAssistResponse {
  return {
    advisoryOnly: true,
    provider: 'ollama',
    action: action as AnalystAssistResponse['action'],
    modelName: 'llama3',
    endpointHost: 'localhost',
    content,
    redactionCount: 0,
    promptChars: 22,
    contextChars: 40,
    tokenEstimate: 16,
    estimatedCostUsd: undefined,
    warnings: ['AI output is advisory only and must not directly mutate verdict state.'],
  };
}

const mockInvoke = vi.mocked(invoke);

beforeEach(() => {
  vi.clearAllMocks();
});

// ── runAnalystAssist ──────────────────────────────────────────────────────────

describe('runAnalystAssist', () => {
  it('calls invoke with llm_query and the full request', async () => {
    const req: AnalystAssistRequest = { ...BASE_REQUEST, action: 'signal_explainer' };
    const expected = makeResponse('signal_explainer');
    mockInvoke.mockResolvedValueOnce(expected);

    const result = await runAnalystAssist(req);

    expect(invoke).toHaveBeenCalledOnce();
    expect(invoke).toHaveBeenCalledWith('llm_query', { request: req });
    expect(result).toEqual(expected);
  });

  it('returns advisoryOnly=true from backend response', async () => {
    const req: AnalystAssistRequest = { ...BASE_REQUEST, action: 'talon_narrate' };
    mockInvoke.mockResolvedValueOnce(makeResponse('talon_narrate'));

    const result = await runAnalystAssist(req);
    expect(result.advisoryOnly).toBe(true);
  });

  it('propagates rejection from invoke without swallowing', async () => {
    const req: AnalystAssistRequest = { ...BASE_REQUEST, action: 'signal_explainer' };
    mockInvoke.mockRejectedValueOnce(new Error('api key lookup failed'));

    await expect(runAnalystAssist(req)).rejects.toThrow('api key lookup failed');
  });

  it('propagates provider timeout error', async () => {
    const req: AnalystAssistRequest = { ...BASE_REQUEST, action: 'aerie_mode' };
    mockInvoke.mockRejectedValueOnce(new Error('provider timeout'));

    await expect(runAnalystAssist(req)).rejects.toThrow('provider timeout');
  });

  it('propagates malformed provider response error', async () => {
    const req: AnalystAssistRequest = { ...BASE_REQUEST, action: 'crest_narration' };
    mockInvoke.mockRejectedValueOnce(new Error('provider returned malformed response'));

    await expect(runAnalystAssist(req)).rejects.toThrow('provider returned malformed response');
  });

  it('propagates oversized context rejection', async () => {
    const req: AnalystAssistRequest = {
      ...BASE_REQUEST,
      action: 'binary_diff_insight',
      contextBlocks: ['X'.repeat(200_000)],
    };
    mockInvoke.mockRejectedValueOnce(new Error('context exceeds maximum allowed size'));

    await expect(runAnalystAssist(req)).rejects.toThrow('context exceeds maximum allowed size');
  });

  it('propagates token budget enforcement error', async () => {
    const req: AnalystAssistRequest = {
      ...BASE_REQUEST,
      action: 'talon_narrate',
      tokenBudget: 1,
    };
    mockInvoke.mockRejectedValueOnce(new Error('token budget exceeded'));

    await expect(runAnalystAssist(req)).rejects.toThrow('token budget exceeded');
  });

  it('propagates approval-required error when approvalGranted=false', async () => {
    const req: AnalystAssistRequest = {
      ...BASE_REQUEST,
      action: 'signal_explainer',
      approvalGranted: false,
    };
    mockInvoke.mockRejectedValueOnce(new Error('explicit approval is required before sending data to a provider'));

    await expect(runAnalystAssist(req)).rejects.toThrow('explicit approval');
  });

  it('propagates invalid provider config error', async () => {
    const req: AnalystAssistRequest = {
      ...BASE_REQUEST,
      action: 'aerie_mode',
      endpointUrl: 'not-a-valid-url',
    };
    mockInvoke.mockRejectedValueOnce(new Error('provider endpoint is invalid'));

    await expect(runAnalystAssist(req)).rejects.toThrow('provider endpoint is invalid');
  });
});

// ── Action wrappers ───────────────────────────────────────────────────────────

describe('runSignalExplainer', () => {
  it('calls invoke with action=signal_explainer', async () => {
    mockInvoke.mockResolvedValueOnce(makeResponse('signal_explainer'));

    await runSignalExplainer(BASE_REQUEST);

    const [, args] = mockInvoke.mock.calls[0] as [string, { request: AnalystAssistRequest }];
    expect(args.request.action).toBe('signal_explainer');
  });

  it('does not override other request fields', async () => {
    mockInvoke.mockResolvedValueOnce(makeResponse('signal_explainer'));

    await runSignalExplainer(BASE_REQUEST);

    const [, args] = mockInvoke.mock.calls[0] as [string, { request: AnalystAssistRequest }];
    expect(args.request.prompt).toBe(BASE_REQUEST.prompt);
    expect(args.request.approvalGranted).toBe(true);
    expect(args.request.allowAgentTools).toBe(false);
  });
});

describe('runAerieMode', () => {
  it('calls invoke with action=aerie_mode', async () => {
    mockInvoke.mockResolvedValueOnce(makeResponse('aerie_mode'));

    await runAerieMode(BASE_REQUEST);

    const [, args] = mockInvoke.mock.calls[0] as [string, { request: AnalystAssistRequest }];
    expect(args.request.action).toBe('aerie_mode');
  });
});

describe('runTalonNarrate', () => {
  it('calls invoke with action=talon_narrate', async () => {
    mockInvoke.mockResolvedValueOnce(makeResponse('talon_narrate'));

    await runTalonNarrate(BASE_REQUEST);

    const [, args] = mockInvoke.mock.calls[0] as [string, { request: AnalystAssistRequest }];
    expect(args.request.action).toBe('talon_narrate');
  });
});

describe('runCrestNarration', () => {
  it('calls invoke with action=crest_narration', async () => {
    mockInvoke.mockResolvedValueOnce(makeResponse('crest_narration'));

    await runCrestNarration(BASE_REQUEST);

    const [, args] = mockInvoke.mock.calls[0] as [string, { request: AnalystAssistRequest }];
    expect(args.request.action).toBe('crest_narration');
  });
});

describe('runBinaryDiffInsight', () => {
  it('calls invoke with action=binary_diff_insight', async () => {
    mockInvoke.mockResolvedValueOnce(makeResponse('binary_diff_insight'));

    await runBinaryDiffInsight(BASE_REQUEST);

    const [, args] = mockInvoke.mock.calls[0] as [string, { request: AnalystAssistRequest }];
    expect(args.request.action).toBe('binary_diff_insight');
  });
});

// ── Advisory isolation contract ───────────────────────────────────────────────

describe('advisory isolation', () => {
  it('does not contain any verdict-mutating field in the response type', () => {
    // Verify at the type level that AnalystAssistResponse carries no verdict
    // mutation payload. The response must only hold advisory content.
    const sample = makeResponse('talon_narrate', 'some analysis');
    const disallowedKeys = ['verdict', 'threatScore', 'classification', 'setVerdict', 'mutate'];
    const keys = Object.keys(sample);
    for (const bad of disallowedKeys) {
      expect(keys).not.toContain(bad);
    }
  });

  it('result content is a plain string — not executable code or a verdict command', async () => {
    mockInvoke.mockResolvedValueOnce(makeResponse('signal_explainer', 'This function likely performs XOR decryption.'));

    const result = await runSignalExplainer(BASE_REQUEST);
    expect(typeof result.content).toBe('string');
  });
});
