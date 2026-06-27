export type AiObservationKind =
  | 'likely-purpose'
  | 'suspicious-pattern'
  | 'technique-hint'
  | 'decompiler-note'
  | 'coverage-gap'
  | 'analyst-suggestion';

export type AiObservationSource =
  | 'aetherframe-static'
  | 'aetherframe-llm'
  | 'nexus-llm'
  | 'talon-llm-pass'
  | 'user-accepted';

export type AiObservationConfidence = 'high' | 'medium' | 'low';

export interface AiObservation {
  id: string;
  kind: AiObservationKind;
  title: string;
  body: string;
  evidenceBasis: string;
  source: AiObservationSource;
  analysisConfidence: AiObservationConfidence;
  functionId?: string;
  address?: number;
  accepted: boolean;
  dismissed: boolean;
  generatedAt: string;
  gyre_is_sole_verdict_authority: true;
  advisory_only: true;
}

export function withAiObservationAuthorityEnvelope(
  observation: Omit<AiObservation, 'gyre_is_sole_verdict_authority' | 'advisory_only'>,
): AiObservation {
  return {
    ...observation,
    gyre_is_sole_verdict_authority: true,
    advisory_only: true,
  };
}
