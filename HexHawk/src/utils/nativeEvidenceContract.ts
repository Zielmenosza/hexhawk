import type { SubsystemSource } from './qaUx';
import type { AnalysisArtifactOrigin } from './analysisProvenance';

export type EvidenceContractKind = 'native' | 'simulation' | 'ui-only' | 'invalid';

export type EvidenceContractInput = {
  runtime: 'tauri-native' | 'browser-simulation';
  source: SubsystemSource;
  artifactOrigin: AnalysisArtifactOrigin;
  artifactKind: string;
  /** Explicit successful binding; legacy runtime/source/origin labels alone are not file proof. */
  binaryPath?: string;
  sourceSha256?: string | null;
  boundSha256?: string | null;
  identityBindingSucceeded?: boolean;
};

export type NativeEvidenceContract = {
  schema: 'hexhawk.native_evidence_contract.v1';
  kind: EvidenceContractKind;
  label: 'Native backend evidence' | 'Browser simulation' | 'UI-only evidence' | 'Invalid evidence source';
  native: boolean;
  canClaimFileBackedEvidence: boolean;
  artifactKind: string;
  artifactOrigin: AnalysisArtifactOrigin;
  warnings: string[];
  authority: {
    evidenceContractOnly: true;
    gyreVerdictAuthorityUnaffected: true;
    nestEvidenceSelectionUnaffected: true;
  };
};

export function classifyEvidenceSource(input: Omit<EvidenceContractInput, 'artifactKind'>): EvidenceContractKind {
  const tauriOrigin = input.artifactOrigin.startsWith('tauri.');
  const browserOrigin = input.artifactOrigin.startsWith('browser.');

  if (input.runtime === 'tauri-native' && input.source === 'real-backend' && tauriOrigin) return 'native';
  if (input.runtime === 'browser-simulation' && input.source === 'simulation' && browserOrigin) return 'simulation';
  if (input.source === 'ui-only' && !tauriOrigin) return 'ui-only';
  return 'invalid';
}

export function enforceNativeEvidenceContract(input: EvidenceContractInput): NativeEvidenceContract {
  const kind = classifyEvidenceSource(input);
  const warnings: string[] = [];
  const validSha = (value: string | null | undefined): value is string => typeof value === 'string' && /^[a-f0-9]{64}$/i.test(value);
  const identityBound = input.identityBindingSucceeded === true
    && Boolean(input.binaryPath?.trim())
    && validSha(input.sourceSha256)
    && validSha(input.boundSha256)
    && input.sourceSha256!.toLowerCase() === input.boundSha256!.toLowerCase();
  if (kind === 'native' && !identityBound) {
    warnings.push('Native source labels do not prove file identity. A successfully bound path and matching valid SHA-256 are required for file-backed evidence.');
  }

  if (kind === 'simulation') {
    warnings.push('Browser simulation must not be presented as native file-backed evidence.');
  }
  if (kind === 'ui-only') {
    warnings.push('UI-only evidence may describe presentation state, not backend file analysis.');
  }
  if (kind === 'invalid') {
    warnings.push('Inconsistent runtime/source/origin combination; fail closed and do not claim native evidence.');
  }

  const label: NativeEvidenceContract['label'] = kind === 'native'
    ? 'Native backend evidence'
    : kind === 'simulation'
      ? 'Browser simulation'
      : kind === 'ui-only'
        ? 'UI-only evidence'
        : 'Invalid evidence source';

  return {
    schema: 'hexhawk.native_evidence_contract.v1',
    kind,
    label,
    native: kind === 'native',
    canClaimFileBackedEvidence: kind === 'native' && identityBound,
    artifactKind: input.artifactKind,
    artifactOrigin: input.artifactOrigin,
    warnings,
    authority: {
      evidenceContractOnly: true,
      gyreVerdictAuthorityUnaffected: true,
      nestEvidenceSelectionUnaffected: true,
    },
  };
}
