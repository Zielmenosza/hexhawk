import type { CrestEvidenceBundle } from './crestEvidenceBundle';

export type TesterHandoffKitInput = {
  generatedAt: string;
  signingStatus: string;
  bundle: CrestEvidenceBundle;
  artifactHashes: Array<{ path: string; sha256: string }>;
};

export type TesterHandoffKit = {
  schema: 'hexhawk.tester_handoff_kit.v1';
  generatedAt: string;
  files: Record<'README.md' | 'SHA256SUMS.txt' | 'UNSIGNED-WARNING.txt', string>;
};

export function buildTesterHandoffKit(input: TesterHandoffKitInput): TesterHandoffKit {
  const bundleId = input.bundle.bundle_id ?? `${input.bundle.schema}:${input.bundle.file_identity.sha256}`;
  const shaLines = input.artifactHashes
    .map((artifact) => `${artifact.sha256.toLowerCase()}  ${artifact.path}`)
    .join('\n');
  const replayCommands = input.bundle.replay_manifest.entries
    .map((entry) => `- \`${entry.command}\` (${entry.artifactSource})`)
    .join('\n') || '- No replay commands recorded.';

  const readme = `# HexHawk Technical Preview Handoff Kit

Generated: ${input.generatedAt}
Signing status: ${input.signingStatus}
CREST evidence bundle: ${bundleId}
Primary file SHA-256: ${input.bundle.file_identity.sha256 ?? 'unknown'}

## What this build proves

- The exported report can carry a CREST evidence bundle tying file identity, provenance, replay commands, artifact origins, and CFG limits together.
- The primary file identity is SHA-256 anchored: ${input.bundle.file_identity.sha256 ?? 'unknown'}.
- Native evidence is separated from browser simulation by the typed native evidence contract.
- Replay commands are listed for authorized local reruns:
${replayCommands}

## What this build does not prove

- It does not prove verdict correctness or malware family truth.
- It does not claim full CFG coverage when CFG budgets or truncation apply.
- It does not make AI, AETHERFRAME, STRIKE, TALON, ECHO, plugins, CREST, or UI copy the verdict authority.
- It does not claim a signed production release while signing status is: ${input.signingStatus}.

## Tester handling notes

- Use only files you are authorized to inspect.
- Verify SHA256SUMS.txt before trusting artifacts.
- Treat unsigned builds as technical previews and expect operating-system warnings.
`;

  const unsignedWarning = `HexHawk unsigned technical preview warning

Signing status: ${input.signingStatus}

This handoff kit is not a signed production release. Windows or security tooling may warn about unsigned binaries or archives. Verify SHA-256 hashes, keep the sample local, and do not treat this kit as release-readiness evidence.
`;

  return {
    schema: 'hexhawk.tester_handoff_kit.v1',
    generatedAt: input.generatedAt,
    files: {
      'README.md': readme,
      'SHA256SUMS.txt': `${shaLines}\n`,
      'UNSIGNED-WARNING.txt': unsignedWarning,
    },
  };
}
