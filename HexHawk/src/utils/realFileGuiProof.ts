import type { SubsystemSource } from './qaUx';
import type { AnalysisArtifactOrigin } from './analysisProvenance';

export type RealFileGuiProofStatus = 'proved' | 'failed' | 'not-native';

export type RealFileGuiProofCheck = {
  id: 'direct-vs-cli' | 'cli-vs-gui' | 'gui-vs-export' | 'origin-gui-vs-export' | 'native-runtime';
  label: string;
  passed: boolean;
  expected?: string | null;
  actual?: string | null;
};

export type RealFileGuiProofInput = {
  filePath: string;
  directFileSha256: string | null;
  cliSha256: string | null;
  guiSha256: string | null;
  exportSha256: string | null;
  guiArtifactOrigin: AnalysisArtifactOrigin;
  exportArtifactOrigin: AnalysisArtifactOrigin;
  runtime: 'tauri-native' | 'browser-simulation';
  source: SubsystemSource;
};

export type RealFileGuiProof = {
  schema: 'hexhawk.real_file_gui_proof.v1';
  status: RealFileGuiProofStatus;
  filePath: string;
  sha256: string | null;
  artifactOrigin: AnalysisArtifactOrigin;
  checks: RealFileGuiProofCheck[];
  warnings: string[];
  authority: {
    evidenceIdentityOnly: true;
    gyreVerdictAuthorityUnaffected: true;
    nestEvidenceSelectionUnaffected: true;
  };
};

function check(
  id: RealFileGuiProofCheck['id'],
  label: string,
  expected: string | null,
  actual: string | null,
): RealFileGuiProofCheck {
  return { id, label, expected, actual, passed: expected !== null && actual !== null && expected === actual };
}

export function buildRealFileGuiProof(input: RealFileGuiProofInput): RealFileGuiProof {
  const checks: RealFileGuiProofCheck[] = [
    check('direct-vs-cli', 'Direct file hash matches CLI/backend inspection', input.directFileSha256, input.cliSha256),
    check('cli-vs-gui', 'CLI/backend SHA-256 matches GUI evidence identity', input.cliSha256, input.guiSha256),
    check('gui-vs-export', 'GUI SHA-256 matches exported report SHA-256', input.guiSha256, input.exportSha256),
    check('origin-gui-vs-export', 'GUI artifact origin matches exported artifact origin', input.guiArtifactOrigin, input.exportArtifactOrigin),
    {
      id: 'native-runtime',
      label: 'Runtime is native Tauri backend evidence, not browser simulation',
      expected: 'tauri-native:real-backend',
      actual: `${input.runtime}:${input.source}`,
      passed: input.runtime === 'tauri-native' && input.source === 'real-backend' && input.guiArtifactOrigin.startsWith('tauri.'),
    },
  ];

  const warnings: string[] = [];
  if (!checks.find((c) => c.id === 'direct-vs-cli')?.passed) warnings.push('CLI/backend SHA-256 does not match the direct file hash.');
  if (!checks.find((c) => c.id === 'cli-vs-gui')?.passed) warnings.push('GUI SHA-256 does not match CLI/backend identity.');
  if (!checks.find((c) => c.id === 'gui-vs-export')?.passed) warnings.push('Export SHA-256 does not match the GUI identity card.');
  if (!checks.find((c) => c.id === 'origin-gui-vs-export')?.passed) warnings.push('Export artifact origin does not match the GUI identity card.');
  if (!checks.find((c) => c.id === 'native-runtime')?.passed) warnings.push('This proof is not native backend evidence; browser simulation or non-native source cannot satisfy the real-file GUI proof.');

  const status: RealFileGuiProofStatus = checks.every((c) => c.passed)
    ? 'proved'
    : checks.find((c) => c.id === 'native-runtime')?.passed === false
      ? 'not-native'
      : 'failed';

  return {
    schema: 'hexhawk.real_file_gui_proof.v1',
    status,
    filePath: input.filePath,
    sha256: input.guiSha256,
    artifactOrigin: input.guiArtifactOrigin,
    checks,
    warnings,
    authority: {
      evidenceIdentityOnly: true,
      gyreVerdictAuthorityUnaffected: true,
      nestEvidenceSelectionUnaffected: true,
    },
  };
}
