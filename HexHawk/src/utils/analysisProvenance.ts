import type { SubsystemSource } from './qaUx';
import type { EvidenceJournalEntry } from './evidenceJournal';
import { enforceNativeEvidenceContract, type NativeEvidenceContract } from './nativeEvidenceContract';

export type AnalysisArtifactSummary = {
  kind: string;
  source: SubsystemSource;
  command?: string;
  binarySha256?: string | null;
  artifactOrigin?: AnalysisArtifactOrigin;
  tauriCommand?: string;
  cliCommand?: string;
  contract?: NativeEvidenceContract;
  count?: number;
  truncated?: boolean;
  warning?: string;
};

export type AnalysisArtifactOrigin =
  | 'tauri.inspect_file_metadata'
  | 'tauri.find_strings'
  | 'tauri.disassemble_file_range'
  | 'tauri.build_cfg'
  | 'tauri.run_plugins_on_file'
  | 'browser.mock_metadata'
  | 'browser.mock_strings'
  | 'browser.mock_disassembly'
  | 'browser.mock_cfg'
  | 'browser.mock_plugins';

export type BinaryEvidenceIdentity = {
  path: string;
  sha256: string | null;
  source: SubsystemSource;
  artifactOrigin: AnalysisArtifactOrigin;
  tauriCommand?: string;
  cliCommand?: string;
  contract?: NativeEvidenceContract;
};

export type AnalysisSessionProvenance = {
  schema: 'hexhawk.analysis.provenance.v1';
  runtime: 'tauri-native' | 'browser-simulation';
  binaryPath: string;
  binarySha256: string | null;
  dataSource: SubsystemSource;
  binaryIdentity: BinaryEvidenceIdentity;
  commands: string[];
  artifacts: AnalysisArtifactSummary[];
  operationJournal?: EvidenceJournalEntry[];
  warnings: string[];
};

export type BuildAnalysisProvenanceInput = {
  browserMode: boolean;
  binaryPath: string;
  binarySha256?: string | null;
  metadataLoaded: boolean;
  stringsCount: number;
  disassemblyCount: number;
  cfgNodes: number;
  cfgEdges: number;
  cfgTruncated?: boolean;
  pluginResultCount: number;
  operationJournal?: readonly EvidenceJournalEntry[];
};

function backendCommand(tool: string, binaryPath: string, args = ''): string {
  const suffix = args ? ` ${args}` : '';
  return `nest_cli ${tool} ${JSON.stringify(binaryPath)}${suffix}`;
}

function artifactOrigin(
  browserMode: boolean,
  nativeCommand: Exclude<AnalysisArtifactOrigin, `browser.${string}`>,
  browserOrigin: Extract<AnalysisArtifactOrigin, `browser.${string}`>,
): AnalysisArtifactOrigin {
  return browserMode ? browserOrigin : nativeCommand;
}

function tauriCommandForOrigin(origin: AnalysisArtifactOrigin): string | undefined {
  return origin.startsWith('tauri.') ? origin.slice('tauri.'.length) : undefined;
}

function artifactSummary(input: {
  kind: string;
  source: SubsystemSource;
  runtime: 'tauri-native' | 'browser-simulation';
  binarySha256: string | null;
  artifactOrigin: AnalysisArtifactOrigin;
  cliCommand?: string;
  count?: number;
  truncated?: boolean;
  warning?: string;
}): AnalysisArtifactSummary {
  const tauriCommand = tauriCommandForOrigin(input.artifactOrigin);
  const contract = enforceNativeEvidenceContract({
    runtime: input.runtime,
    source: input.source,
    artifactOrigin: input.artifactOrigin,
    artifactKind: input.kind,
  });
  return {
    kind: input.kind,
    source: input.source,
    command: input.cliCommand,
    binarySha256: input.binarySha256,
    artifactOrigin: input.artifactOrigin,
    tauriCommand,
    cliCommand: input.cliCommand,
    contract,
    count: input.count,
    truncated: input.truncated,
    warning: input.warning,
  };
}

export function buildAnalysisProvenance(input: BuildAnalysisProvenanceInput): AnalysisSessionProvenance {
  const dataSource: SubsystemSource = input.browserMode ? 'simulation' : 'real-backend';
  const runtime = input.browserMode ? 'browser-simulation' : 'tauri-native';
  const commands: string[] = [];
  const artifacts: AnalysisArtifactSummary[] = [];
  const warnings: string[] = [];
  const binarySha256 = input.binarySha256 ?? null;
  const identityOrigin = artifactOrigin(input.browserMode, 'tauri.inspect_file_metadata', 'browser.mock_metadata');
  const identityCliCommand = backendCommand('inspect', input.binaryPath);
  const binaryIdentity: BinaryEvidenceIdentity = {
    path: input.binaryPath,
    sha256: binarySha256,
    source: dataSource,
    artifactOrigin: identityOrigin,
    tauriCommand: tauriCommandForOrigin(identityOrigin),
    cliCommand: identityCliCommand,
    contract: enforceNativeEvidenceContract({
      runtime,
      source: dataSource,
      artifactOrigin: identityOrigin,
      artifactKind: 'metadata',
      binaryPath: input.binaryPath,
      sourceSha256: binarySha256,
      boundSha256: binarySha256,
      identityBindingSucceeded: input.metadataLoaded,
    }),
  };

  if (input.metadataLoaded) {
    commands.push(identityCliCommand);
    artifacts.push(artifactSummary({
      kind: 'metadata',
      source: dataSource,
      runtime,
      binarySha256,
      artifactOrigin: identityOrigin,
      cliCommand: identityCliCommand,
      count: 1,
    }));
  }
  if (input.stringsCount > 0) {
    const cliCommand = backendCommand('strings', input.binaryPath);
    commands.push(cliCommand);
    artifacts.push(artifactSummary({
      kind: 'strings',
      source: dataSource,
      runtime,
      binarySha256,
      artifactOrigin: artifactOrigin(input.browserMode, 'tauri.find_strings', 'browser.mock_strings'),
      cliCommand,
      count: input.stringsCount,
    }));
  }
  if (input.disassemblyCount > 0) {
    const cliCommand = backendCommand('disassemble', input.binaryPath, '0 1024');
    commands.push(cliCommand);
    artifacts.push(artifactSummary({
      kind: 'disassembly',
      source: dataSource,
      runtime,
      binarySha256,
      artifactOrigin: artifactOrigin(input.browserMode, 'tauri.disassemble_file_range', 'browser.mock_disassembly'),
      cliCommand,
      count: input.disassemblyCount,
    }));
  }
  if (input.cfgNodes > 0 || input.cfgEdges > 0) {
    const cliCommand = backendCommand('cfg', input.binaryPath, '0 1024');
    commands.push(cliCommand);
    artifacts.push(artifactSummary({
      kind: 'cfg',
      source: dataSource,
      runtime,
      binarySha256,
      artifactOrigin: artifactOrigin(input.browserMode, 'tauri.build_cfg', 'browser.mock_cfg'),
      cliCommand,
      count: input.cfgNodes,
      truncated: input.cfgTruncated,
      warning: input.cfgTruncated ? `CFG was truncated to ${input.cfgNodes} nodes / ${input.cfgEdges} edges for UI safety.` : undefined,
    }));
  }
  if (input.pluginResultCount > 0) {
    artifacts.push(artifactSummary({
      kind: 'plugins',
      source: dataSource,
      runtime,
      binarySha256,
      artifactOrigin: artifactOrigin(input.browserMode, 'tauri.run_plugins_on_file', 'browser.mock_plugins'),
      count: input.pluginResultCount,
    }));
  }

  if (input.browserMode) {
    warnings.push('Browser runtime is simulation-backed; native Tauri backend commands were not invoked by this GUI session.');
  }
  if (input.cfgTruncated) {
    warnings.push('CFG exceeded UI safety budget and was truncated before renderer consumption.');
  }

  let operationJournal: EvidenceJournalEntry[] | undefined;
  if (input.operationJournal !== undefined) {
    const matchesIdentity = input.operationJournal.every(entry =>
      entry.binaryPath === input.binaryPath
      && !!binarySha256
      && entry.binarySha256?.toLowerCase() === binarySha256.toLowerCase());
    operationJournal = matchesIdentity ? input.operationJournal.map(entry => ({
      ...entry, analysisLimits: { ...entry.analysisLimits }, authority: { ...entry.authority },
    })) : [];
    if (!matchesIdentity) warnings.push('Operation receipts refer to a different file identity; replay is blocked.');
    const kindForAction = (action: EvidenceJournalEntry['action']) => action === 'inspect' ? 'metadata' : action;
    const recordedKinds = new Set<string>(operationJournal.map(entry => kindForAction(entry.action)));
    for (let i = artifacts.length - 1; i >= 0; i -= 1) {
      if (!recordedKinds.has(artifacts[i].kind)) artifacts.splice(i, 1);
    }
    for (const entry of operationJournal) {
      const kind = kindForAction(entry.action);
      let artifact = artifacts.find(candidate => candidate.kind === kind);
      if (!artifact) {
        artifact = { kind, source: dataSource, count: 0, binarySha256 };
        artifacts.push(artifact);
      }
      artifact.command = entry.command;
      artifact.cliCommand = entry.command.startsWith('nest_cli ') ? entry.command : undefined;
      artifact.artifactOrigin = entry.artifactSource;
      artifact.tauriCommand = tauriCommandForOrigin(entry.artifactSource);
    }
    commands.splice(0, commands.length, ...operationJournal.map(entry => entry.command));
    warnings.push('Operation receipts record successful GUI invokes, not independently signed backend execution or unchanged-file proof for every operation.');
  } else {
    warnings.push('No operation receipts were recorded; UI counts and CLI recipes are not execution or replay proof.');
  }
  for (const artifact of artifacts) {
    if (!artifact.artifactOrigin) continue;
    artifact.contract = enforceNativeEvidenceContract({
      runtime, source: artifact.source, artifactOrigin: artifact.artifactOrigin, artifactKind: artifact.kind,
      binaryPath: input.binaryPath, sourceSha256: artifact.binarySha256, boundSha256: binarySha256,
      identityBindingSucceeded: input.metadataLoaded,
    });
  }

  return {
    schema: 'hexhawk.analysis.provenance.v1',
    runtime,
    binaryPath: input.binaryPath,
    binarySha256,
    dataSource,
    binaryIdentity,
    commands,
    artifacts,
    operationJournal,
    warnings,
  };
}
