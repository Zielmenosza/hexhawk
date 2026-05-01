import { invoke } from '@tauri-apps/api/core';

export type AnalystAction =
  | 'signal_explainer'
  | 'aerie_mode'
  | 'talon_narrate'
  | 'crest_narration'
  | 'binary_diff_insight'
  | 'self_heal';

export interface AnalystAssistRequest {
  action: AnalystAction;
  endpointUrl: string;
  modelName: string;
  prompt: string;
  contextBlocks?: string[];
  provider?: 'open_ai' | 'anthropic' | 'ollama';
  keyAlias?: string;
  timeoutMs?: number;
  tokenBudget?: number;
  approvalGranted: boolean;
  allowRemoteEndpoint: boolean;
  allowAgentTools: boolean;
}

export interface AnalystAssistResponse {
  advisoryOnly: boolean;
  provider: 'open_ai' | 'anthropic' | 'ollama';
  action: AnalystAction;
  modelName: string;
  endpointHost: string;
  content: string;
  redactionCount: number;
  promptChars: number;
  contextChars: number;
  tokenEstimate: number;
  estimatedCostUsd?: number;
  warnings: string[];
}

export async function runAnalystAssist(request: AnalystAssistRequest): Promise<AnalystAssistResponse> {
  const response = await invoke<AnalystAssistResponse>('llm_query', { request });
  return response;
}

export function runSignalExplainer(request: Omit<AnalystAssistRequest, 'action'>) {
  return runAnalystAssist({ ...request, action: 'signal_explainer' });
}

export function runAerieMode(request: Omit<AnalystAssistRequest, 'action'>) {
  return runAnalystAssist({ ...request, action: 'aerie_mode' });
}

export function runTalonNarrate(request: Omit<AnalystAssistRequest, 'action'>) {
  return runAnalystAssist({ ...request, action: 'talon_narrate' });
}

export function runCrestNarration(request: Omit<AnalystAssistRequest, 'action'>) {
  return runAnalystAssist({ ...request, action: 'crest_narration' });
}

export function runBinaryDiffInsight(request: Omit<AnalystAssistRequest, 'action'>) {
  return runAnalystAssist({ ...request, action: 'binary_diff_insight' });
}

export function runSelfHeal(request: Omit<AnalystAssistRequest, 'action'>) {
  return runAnalystAssist({ ...request, action: 'self_heal' });
}
