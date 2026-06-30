# AetherFrame/Hermes Factory Cycle 0002 — Unsigned Early Access Intake

Generated: 2026-07-01 00:40:47 SAST
Repo: D:/Project/HexHawk
Cycle target: Unsigned Early Access packaging path
Factory classification: Intake / before edits

## Mission

Create a safe, honest unsigned paid early-access release path for HexHawk. This cycle is for controlled technical testers only. It is not a public/world-ready release, not a signed release, not Microsoft verified, and not an auto-updating release.

## Current repo evidence

- Branch/status command run: `git status --short --branch`
- Starting HEAD: `f513fb6` (`f513fb619f871c7b20597e47cde05942a901e429`)
- Recent commit at start: `[DOCS] Record first AetherFrame factory cycle report`
- Current branch: `main`
- Working tree at Phase 0 audit: clean
- Tags pointing at HEAD at Phase 0 audit: none
- No deployment-candidate/public-release tag was created during intake.

## Current CI evidence

Command run:

```text
gh run list --branch main --limit 3 --json databaseId,status,conclusion,headSha,url
```

Latest main CI runs at intake:

- Run 28478161801 — success — HEAD `f513fb619f871c7b20597e47cde05942a901e429` — https://github.com/Zielmenosza/hexhawk/actions/runs/28478161801
- Run 28477520312 — success — HEAD `2f16e9657e7e25bb7fe26edce16c4c01e648f349`
- Run 28476869500 — success — HEAD `dd14c49a32a4b5a88a3ce8fd7ef6bc0902c39775`

Intake conclusion: latest CI on main is green and matches the starting HEAD.

## Existing release/artifact evidence inspected

- `docs/release-evidence/unsigned_deployment_candidate_2026-06-20_215102.json`
  - Historical unsigned deployment candidate evidence at commit `e625403a076d100237dcd2ec13a0b1d36985312f`.
  - MSI/NSIS recorded as `NotSigned`.
  - Installer smoke recorded MSI extraction and NSIS install/launch success for that historical candidate.
  - Limits explicitly say the artifacts are unsigned, updater metadata was not regenerated/published, and GUI smoke did not prove full Open -> Inspect -> NEST -> Export parity for those exact artifacts.
- `gui-evidence/controlled_release_gate_unsigned_native_gui_probe_2026-06-02_213600.json`
  - Historical installed native AI/workflow probe evidence.
  - Confirms Tauri runtime and advisory AETHERFRAME report packaging boundaries for that historical probe.

These are useful provenance inputs only. They do not automatically prove the current HEAD package unless a fresh package/gate records exact current artifacts.

## Current candidate classification

- Source/CI state: clean main with green CI.
- Public release: NOT ALLOWED.
- Signed release: NOT PROVEN.
- Auto-updating release: NOT PROVEN / not enabled by this cycle.
- Early-access channel target: policy/script path may be defined; local package may be created only if exact local artifacts exist and the unsigned early-access gate records evidence.

## Release trust blockers

- No Authenticode signing proof for current exact artifacts.
- No public updater/signature chain proof.
- No signed exact-artifact release gate.
- No public download/trust page or publishing approval for this cycle.
- Existing June 20 artifact evidence is historical, not current-HEAD public-release proof.

## Factory machines used or planned

- Repo inspection: git status/log/tags and file reads.
- GitHub Actions status: `gh run list` for main.
- Local docs: factory docs, boundary doctrine, high-assurance guide, release evidence.
- Existing release scripts: installer smoke, release hardening, official release builder.
- PowerShell packaging script validation: planned parse/sanity checks.
- AetherFrame factory reporter: planned before/after bounded reports.
- Web research: not used in intake; official docs will be used only if needed.

## Go/no-go constraints

Go for this cycle only if:

- main remains clean before staging;
- latest CI on main remains green;
- created package path says unsigned early access only;
- Authenticode `NotSigned` is expected and recorded for this channel;
- no public/signed/Microsoft-verified/world-ready claims are introduced;
- no updater/public publishing/deployment/secrets are used;
- GYRE/NEST/TALON/STRIKE/AETHERFRAME authority boundaries remain unchanged.

Stop if:

- CI turns red;
- working tree contains unexpected product/build/generated dirt;
- docs or scripts would imply public/signed/verified status;
- package evidence cannot distinguish local unsigned early access from public release readiness.

## Authority-boundary checklist

- GYRE remains sole verdict/classification authority.
- NEST remains evidence orchestration and convergence only.
- TALON remains advisory decompiler/pseudocode reconstruction only.
- STRIKE remains runtime/debugger evidence only.
- Function Intelligence remains advisory evidence notebook only.
- AETHERFRAME remains advancement/refinement/factory orchestration only.
- NEXUS/Hermes/AI remain assistant/proposal/workflow helper only.

## Intake decision

Proceed with docs/script-only unsigned early-access release path work. Do not publish, deploy, sign, charge money, create updater metadata, or create a deployment-candidate/public-release tag in this cycle.
