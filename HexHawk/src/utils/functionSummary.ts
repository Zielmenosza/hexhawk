import type { AiObservation } from '../types/aiObservation';
import type { FunctionIntelligence } from './functionIntelligence';
import { runAetherframePatterns } from './aetherframePatterns';

export interface FunctionSummary {
  oneLiner: string;
  paragraphSummary: string;
  keyOperations: string[];
  analystQuestions: string[];
  confidence: 'high' | 'medium' | 'low';
  basis: string;
  generatedBy: 'aetherframe-llm' | 'aetherframe-static-only';
  gyre_is_sole_verdict_authority: true;
  advisory_only: true;
  not_a_verdict: true;
}

const FORBIDDEN_OUTPUT_RE = /\b(malware|classified|classification|confirmed|confirmed malware|proven)\b|verdict:?/gi;

function sanitizeSummaryText(text: string): string {
  return text.replace(FORBIDDEN_OUTPUT_RE, 'advisory assessment').replace(/\s+/g, ' ').trim();
}

function compactList(values: string[], limit: number): string[] {
  return values.map(sanitizeSummaryText).filter(Boolean).slice(0, limit);
}

function confidenceFromObservations(observations: AiObservation[]): FunctionSummary['confidence'] {
  if (observations.some(observation => observation.analysisConfidence === 'high')) return 'high';
  if (observations.some(observation => observation.analysisConfidence === 'medium')) return 'medium';
  return 'low';
}

function operationsFromFi(fi: FunctionIntelligence, observations: AiObservation[]): string[] {
  const operations: string[] = [];
  for (const entry of fi.importCalls.slice(0, 5)) {
    const constants = entry.constantAnnotations.length ? ` (${entry.constantAnnotations.join(', ')})` : '';
    operations.push(`Uses ${entry.importName}${constants}`);
  }
  for (const observation of observations.slice(0, 3)) {
    operations.push(observation.title);
  }
  if (operations.length === 0 && fi.callees.length > 0) {
    operations.push(`Calls ${fi.callees.length} recovered callee${fi.callees.length === 1 ? '' : 's'}`);
  }
  return compactList(operations.length ? operations : ['Review pseudocode and import calls manually'], 6);
}

function analystQuestions(fi: FunctionIntelligence, observations: AiObservation[]): string[] {
  const questions: string[] = [];
  if (fi.callers.length > 0) questions.push('Who calls this function, and what arguments are passed?');
  if (fi.importCalls.length > 0) questions.push('Which imported API arguments control this behavior?');
  if (observations.some(observation => observation.kind === 'suspicious-pattern')) questions.push('Where does control flow continue after the highlighted pattern?');
  if (fi.callers.length === 0) questions.push('Is this function an entry point, callback, or indirect target?');
  questions.push('What evidence would confirm or weaken this interpretation?');
  return compactList(Array.from(new Set(questions)), 3);
}

function makeSummary(input: {
  oneLiner: string;
  paragraphSummary: string;
  keyOperations: string[];
  analystQuestions: string[];
  confidence: FunctionSummary['confidence'];
  basis: string;
  generatedBy: FunctionSummary['generatedBy'];
}): FunctionSummary {
  return {
    oneLiner: sanitizeSummaryText(input.oneLiner),
    paragraphSummary: sanitizeSummaryText(input.paragraphSummary),
    keyOperations: compactList(input.keyOperations, 8),
    analystQuestions: compactList(input.analystQuestions, 4),
    confidence: input.confidence,
    basis: sanitizeSummaryText(input.basis),
    generatedBy: input.generatedBy,
    gyre_is_sole_verdict_authority: true,
    advisory_only: true,
    not_a_verdict: true,
  };
}

export function buildFunctionSummaryPrompt(fi: FunctionIntelligence, observations: AiObservation[]): string {
  const imports = fi.importCalls
    .map(entry => `${entry.importName}${entry.constantAnnotations.length ? ` [${entry.constantAnnotations.join(', ')}]` : ''}`)
    .join('; ') || 'none observed';
  const callees = fi.callees.map(edge => edge.targetName ?? edge.importName ?? `0x${edge.targetAddress.toString(16)}`).join(', ') || 'none observed';
  const pseudocode = (fi.pseudocode ?? '').slice(0, 800) || 'none observed';
  const obs = observations.map(observation => `${observation.title}: ${observation.body}`).join('\n') || 'none observed';
  return [
    'System: Your output is advisory analysis only. GYRE is the sole verdict authority in HexHawk. Never contradict this.',
    'You are a reverse engineering assistant. Describe what this function appears to do based on the evidence provided. Be specific about API calls and constants. Do not produce a malware verdict. Do not use the words malware, classified, verdict, confirmed, proven. Use hedged language: appears to, suggests, likely, may be. If the evidence is insufficient, say so.',
    `Function: ${fi.name}`,
    `Calling convention: ${fi.callingConvention?.abi ?? 'unknown'}`,
    `Import calls: ${imports}`,
    `Callees: ${callees}`,
    `Caller count: ${fi.callers.length}`,
    `Pseudocode compact: ${pseudocode}`,
    `AETHERFRAME observations:\n${obs}`,
  ].join('\n');
}

export async function generateFunctionSummary(
  fi: FunctionIntelligence,
  observations: AiObservation[] = runAetherframePatterns(fi),
): Promise<FunctionSummary> {
  const matched = observations.filter(observation => !observation.dismissed);
  const first = matched[0];
  if (matched.length === 0) {
    return makeSummary({
      oneLiner: 'No patterns matched',
      paragraphSummary: 'Insufficient data to generate a plain-English summary. Review the pseudocode and import calls manually.',
      keyOperations: operationsFromFi(fi, matched),
      analystQuestions: analystQuestions(fi, matched),
      confidence: 'low',
      basis: `0 pattern matches, ${fi.importCalls.length} import calls, ${fi.callees.length} callees`,
      generatedBy: 'aetherframe-static-only',
    });
  }

  return makeSummary({
    oneLiner: first.title,
    paragraphSummary: matched.map(observation => observation.body).join(' '),
    keyOperations: operationsFromFi(fi, matched),
    analystQuestions: analystQuestions(fi, matched),
    confidence: confidenceFromObservations(matched),
    basis: `${fi.importCalls.length} import calls, ${matched.length} pattern matches`,
    generatedBy: 'aetherframe-static-only',
  });
}
