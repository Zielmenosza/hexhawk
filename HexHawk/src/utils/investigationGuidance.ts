import type { AnalysisSessionProvenance } from './analysisProvenance';

export type InvestigationTarget = 'load' | 'inspect' | 'strings' | 'disassembly' | 'verdict';
export type InvestigationStep = {
  action: 'inspect' | 'strings' | 'disassembly';
  label: string;
  status: 'missing' | 'recorded' | 'limited';
  detail: string;
};
export type InvestigationGuidance = {
  schema: 'hexhawk.investigation-guidance.v1';
  title: string;
  steps: InvestigationStep[];
  next: { target: InvestigationTarget; label: string } | null;
  exportReady: boolean;
  authority: 'navigation-only; GYRE verdict unchanged';
  proofLimit: string;
};

/** Presentation only. The caller supplies the existing shared report export gate;
 * this checklist never replaces that gate or infers success from result counts. */
export function buildInvestigationGuidance(input: {
  binaryPath?: string;
  provenance?: AnalysisSessionProvenance;
  nativeRuntime: boolean;
  exportGate: { ok: boolean; reason?: string };
  hasVerdict: boolean;
}): InvestigationGuidance {
  const definitions = [
    { action: 'inspect', label: 'Inspect', origin: 'tauri.inspect_file_metadata', kind: 'metadata' },
    { action: 'strings', label: 'Strings', origin: 'tauri.find_strings', kind: 'strings' },
    { action: 'disassembly', label: 'Disassembly', origin: 'tauri.disassemble_file_range', kind: 'disassembly' },
  ] as const;
  const native = input.nativeRuntime || input.provenance?.runtime === 'tauri-native';
  const admitted = native && input.exportGate.ok;
  const p = input.provenance;
  const sha = p?.binaryIdentity.sha256;
  const steps: InvestigationStep[] = definitions.map(definition => {
    const matching = admitted ? (p?.operationJournal ?? []).filter(entry =>
      entry.schema === 'hexhawk.evidence_journal_entry.v1' && entry.replayable === true
      && entry.authority?.evidenceRecordOnly === true && entry.authority.gyreVerdictAuthorityUnaffected === true
      && entry.action === definition.action && entry.artifactSource === definition.origin
      && entry.binaryPath === input.binaryPath && typeof sha === 'string'
      && entry.binarySha256?.toLowerCase() === sha.toLowerCase()) : [];
    const limited = matching.some(entry => entry.analysisLimits.truncated === true)
      || (admitted && (p?.artifacts ?? []).some(artifact => artifact.kind === definition.kind
        && artifact.artifactOrigin === definition.origin && artifact.binarySha256?.toLowerCase() === sha?.toLowerCase()
        && artifact.truncated === true));
    const status = matching.length === 0 ? 'missing' : limited ? 'limited' : 'recorded';
    return { action: definition.action, label: definition.label, status,
      detail: status === 'missing' ? 'No recorded completion' : status === 'limited' ? 'Recorded — limited' : 'Recorded' };
  });
  const result: InvestigationGuidance = {
    schema: 'hexhawk.investigation-guidance.v1', steps,
    title: 'Evidence checklist', next: null,
    exportReady: admitted && input.hasVerdict,
    authority: 'navigation-only; GYRE verdict unchanged',
    proofLimit: 'Recorded steps are not a safety certificate or proof of whole-file or whole-program coverage. Missing receipts do not prove a check was never attempted or that a behavior is absent.',
  };
  if (!input.binaryPath) {
    result.title = 'Choose a file';
    result.next = { target: 'load', label: 'Open a File' };
  } else if (!native) {
    result.title = 'Demo only';
    result.proofLimit = 'Browser demonstration results are not native file-backed evidence. Use the desktop app to inspect an authorized local file. ' + result.proofLimit;
  } else if (!admitted) {
    result.title = 'Repair evidence identity';
    result.next = { target: 'inspect', label: 'Open Inspect' };
  } else {
    result.title = 'Recorded evidence for this file';
    const missing = steps.find(step => step.status === 'missing');
    result.next = missing
      ? { target: missing.action, label: `Open ${missing.label}` }
      : { target: 'verdict', label: 'Review Verdict' };
  }
  return result;
}
