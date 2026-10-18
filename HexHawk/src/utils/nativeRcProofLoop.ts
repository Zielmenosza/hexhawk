export type NativeRcRuntime = 'tauri-native' | 'browser-simulation' | 'not-run';

export type NativeRcFixtureIdentity = {
  path: string;
  directSha256: string;
  backendSha256: string | null;
  guiSha256: string | null;
  exportedBundleSha256: string | null;
};

export type NativeRcProofLoop = {
  schema: 'hexhawk.native_rc_proof_loop.v1';
  generated_at: string;
  custody: { branch: string; head: string };
  native_app: { attempted: boolean; runtime: NativeRcRuntime; blocker: string | null };
  fixture: NativeRcFixtureIdentity;
  sha256_chain: {
    direct_matches_backend: boolean;
    direct_matches_gui: boolean;
    direct_matches_exported_bundle: boolean;
    all_match: boolean;
  };
  proof_artifacts: {
    screenshot_path: string | null;
    crest_bundle_path: string;
    crest_bundle_id: string;
    handoff_kit_path: string;
    package_candidate_path: string | null;
    package_candidate_sha256: string | null;
    signing_status: string;
  };
  release_claim: {
    release_ready: false;
    verdict_correctness_proven: false;
    improved_trust_chain: true;
  };
  required_before_release_ready: string[];
  proof_limits: string[];
};

export type NativeRcProofInput = {
  generatedAt: string;
  branch: string;
  head: string;
  fixture: NativeRcFixtureIdentity;
  nativeApp: { attempted: boolean; runtime: NativeRcRuntime; screenshotPath: string | null; blocker: string | null };
  crestBundle: { path: string; bundleId: string };
  packageCandidate: { path: string; sha256: string; signingStatus: string } | null;
  handoffKitPath: string;
};

export type NativeRcValidation = { ok: boolean; errors: string[]; warnings: string[] };

const SHA_RE = /^[a-f0-9]{64}$/;

function norm(value: string | null | undefined): string | null {
  return value ? value.toLowerCase() : null;
}

function same(a: string | null | undefined, b: string | null | undefined): boolean {
  const left = norm(a);
  const right = norm(b);
  return Boolean(left && right && left === right);
}

export function buildNativeRcProofLoop(input: NativeRcProofInput): NativeRcProofLoop {
  const direct = norm(input.fixture.directSha256) ?? input.fixture.directSha256;
  const fixture = {
    ...input.fixture,
    directSha256: direct,
    backendSha256: norm(input.fixture.backendSha256),
    guiSha256: norm(input.fixture.guiSha256),
    exportedBundleSha256: norm(input.fixture.exportedBundleSha256),
  };
  const directMatchesBackend = same(fixture.directSha256, fixture.backendSha256);
  const directMatchesGui = same(fixture.directSha256, fixture.guiSha256);
  const directMatchesExport = same(fixture.directSha256, fixture.exportedBundleSha256);

  return {
    schema: 'hexhawk.native_rc_proof_loop.v1',
    generated_at: input.generatedAt,
    custody: { branch: input.branch, head: input.head },
    native_app: { attempted: input.nativeApp.attempted, runtime: input.nativeApp.runtime, blocker: input.nativeApp.blocker },
    fixture,
    sha256_chain: {
      direct_matches_backend: directMatchesBackend,
      direct_matches_gui: directMatchesGui,
      direct_matches_exported_bundle: directMatchesExport,
      all_match: directMatchesBackend && directMatchesGui && directMatchesExport,
    },
    proof_artifacts: {
      screenshot_path: input.nativeApp.screenshotPath,
      crest_bundle_path: input.crestBundle.path,
      crest_bundle_id: input.crestBundle.bundleId,
      handoff_kit_path: input.handoffKitPath,
      package_candidate_path: input.packageCandidate?.path ?? null,
      package_candidate_sha256: norm(input.packageCandidate?.sha256),
      signing_status: input.packageCandidate?.signingStatus ?? 'unsigned technical preview',
    },
    release_claim: {
      release_ready: false,
      verdict_correctness_proven: false,
      improved_trust_chain: true,
    },
    required_before_release_ready: [
      'Clean or isolated release-candidate custody with unrelated work excluded.',
      'Fresh signed-or-explicitly-unsigned package build with installer/install/uninstall smoke proof.',
      'Native Tauri GUI run against golden safe fixtures with screenshot and exported CREST bundle hashes.',
      'Golden corpus verdict regression with expected outcomes and documented failures.',
      'Privacy/offline/license/AI egress verification matching tester-facing claims.',
    ],
    proof_limits: [
      'This proof loop can show native product evidence identity and export reproducibility; it does not make the product release-ready by itself.',
      'SHA-256 agreement proves file identity consistency, not verdict correctness or full analysis coverage.',
      'GYRE remains sole verdict authority; CREST, AETHERFRAME, reports, screenshots, and handoff kits are evidence packaging/governance only.',
    ],
  };
}

export function validateNativeRcProofLoop(proof: NativeRcProofLoop): NativeRcValidation {
  const errors: string[] = [];
  const warnings: string[] = [];
  if (proof.schema !== 'hexhawk.native_rc_proof_loop.v1') errors.push('schema must be hexhawk.native_rc_proof_loop.v1.');
  if (!proof.fixture.path) errors.push('fixture path is required.');
  if (!SHA_RE.test(proof.fixture.directSha256)) errors.push('direct fixture SHA-256 must be 64 lowercase hex characters.');
  if (!proof.sha256_chain.all_match) errors.push('SHA-256 chain must match across direct, backend, GUI, and exported bundle evidence.');
  if (proof.native_app.runtime !== 'tauri-native') errors.push('Native RC proof loop requires tauri-native runtime evidence.');
  if (proof.native_app.attempted && proof.native_app.runtime !== 'tauri-native' && !proof.native_app.blocker) errors.push('Non-native or failed native proof attempts must record a blocker.');
  if (!proof.proof_artifacts.screenshot_path) errors.push('Evidence Identity Card screenshot path is required.');
  if (!proof.proof_artifacts.crest_bundle_path || !proof.proof_artifacts.crest_bundle_id) errors.push('CREST bundle path and ID are required.');
  if (!proof.proof_artifacts.handoff_kit_path) errors.push('handoff kit path is required.');
  if (proof.release_claim.release_ready) errors.push('Native RC proof loops must not self-claim release readiness.');
  if (proof.release_claim.verdict_correctness_proven) errors.push('Native RC proof loops must not claim verdict correctness is proven.');
  if (!proof.proof_artifacts.package_candidate_path) warnings.push('No package candidate was attached to this proof loop.');
  const serialized = JSON.stringify(proof);
  if (serialized.includes('threatScore')) errors.push('Proof loop must not contain threatScore authority fields.');
  if (serialized.includes('classification')) errors.push('Proof loop must not contain classification authority fields.');
  return { ok: errors.length === 0, errors, warnings };
}

export function buildNativeRcProofReadme(input: {
  bundleId: string;
  fixturePath: string;
  sha256: string;
  signingStatus: string;
  nativeRuntime: NativeRcRuntime;
  blocker: string | null;
}): string {
  return `# Native Product Release Candidate Proof Loop

CREST bundle: ${input.bundleId}
Fixture: ${input.fixturePath}
SHA-256: ${input.sha256}
Runtime observed: ${input.nativeRuntime}
Signing status: ${input.signingStatus}
${input.blocker ? `Native proof blocker: ${input.blocker}\n` : ''}
## What this proof loop proves

- A safe fixture can be traced through native/backend, GUI, exported CREST bundle, and replay manifest SHA-256 identity checks when runtime is \`tauri-native\`.
- Evidence Identity Card screenshots and CREST bundles can be handed to testers with replay commands and proof limits.
- HexHawk's trust chain is improved because native evidence, simulation, CREST packaging, and handoff docs are separated.

## What this proof loop does not prove

- This is not release-ready evidence by itself.
- This does not prove verdict correctness on arbitrary binaries.
- This does not prove signed production release status while signing status is ${input.signingStatus}.
- This does not make AETHERFRAME, CREST, screenshots, reports, plugins, or AI output a GYRE verdict authority.
`;
}
