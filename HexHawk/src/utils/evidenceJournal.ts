import type { AnalysisArtifactOrigin, AnalysisSessionProvenance } from './analysisProvenance';

export type EvidenceJournalAction = 'inspect' | 'hex' | 'strings' | 'disassembly' | 'cfg' | 'plugins' | 'report-export';

export type EvidenceAnalysisLimits = {
  maxBytesRead?: number;
  offset?: number;
  length?: number;
  minLength?: number;
  maxInstructions?: number;
  nodeBudget?: number;
  edgeBudget?: number;
  truncated?: boolean;
  omittedNodes?: number;
  omittedEdges?: number;
};

export type EvidenceJournalEntryInput = {
  action: EvidenceJournalAction;
  binaryPath: string;
  binarySha256: string | null;
  command: string;
  timestamp: string;
  artifactSource: AnalysisArtifactOrigin;
  analysisLimits: EvidenceAnalysisLimits;
};

export type EvidenceJournalEntry = EvidenceJournalEntryInput & {
  schema: 'hexhawk.evidence_journal_entry.v1';
  sequence: number;
  replayable: true;
  authority: {
    evidenceRecordOnly: true;
    gyreVerdictAuthorityUnaffected: true;
    nestEvidenceSelectionUnaffected: true;
  };
};

export type EvidenceReplayManifest = {
  schema: 'hexhawk.evidence_replay_manifest.v1';
  generatedAt: string;
  replayable: boolean;
  entries: EvidenceJournalEntry[];
  proofLimits: string[];
};

export function appendEvidenceJournalEntry(
  journal: readonly EvidenceJournalEntry[],
  input: EvidenceJournalEntryInput,
): EvidenceJournalEntry[] {
  const entry: EvidenceJournalEntry = {
    schema: 'hexhawk.evidence_journal_entry.v1',
    sequence: journal.length + 1,
    replayable: true,
    ...input,
    authority: {
      evidenceRecordOnly: true,
      gyreVerdictAuthorityUnaffected: true,
      nestEvidenceSelectionUnaffected: true,
    },
  };
  return [...journal, entry];
}

export function buildReplayManifest(
  journal: readonly EvidenceJournalEntry[],
  generatedAt = new Date().toISOString(),
): EvidenceReplayManifest {
  return {
    schema: 'hexhawk.evidence_replay_manifest.v1',
    generatedAt,
    replayable: true,
    entries: journal.map((entry) => ({ ...entry })),
    proofLimits: [
      'Replay manifests record commands, identity, artifact source, timestamps, and analysis limits; they do not prove verdict correctness.',
      'Commands are replay instructions for authorized local files only; analysts must confirm files are still present and unchanged by SHA-256.',
      'GYRE remains the sole verdict authority; NEST remains evidence lifecycle authority.',
    ],
  };
}

export function buildReplayManifestFromProvenance(
  provenance: AnalysisSessionProvenance,
  generatedAt = new Date().toISOString(),
): EvidenceReplayManifest {
  const journal = provenance.operationJournal ?? [];
  const manifest = buildReplayManifest(journal, generatedAt);
  if (journal.length === 0) {
    manifest.replayable = false;
    manifest.proofLimits.push('No operation receipts were recorded; no execution timestamps, ranges or replay proof can be inferred from UI counts.');
  } else {
    manifest.proofLimits.push('Recorded Tauri invocations require this application command API; they are not interchangeable with CLI implementations. GUI receipts do not independently verify backend file snapshots.');
  }
  return manifest;
}
