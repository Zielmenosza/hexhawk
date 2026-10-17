# Reliability and evidence workflow — source update

**Status: reviewable engineering source, not release approval.**

This update improves the bounded Windows x64 static-analysis workflow for authorized PE32/x86 and PE32+/x64 EXE/DLL inputs. Files are inspected as data, not executed. GYRE remains the verdict/base-confidence authority; investigation guidance is navigation-only.

## Included improvements

- Checked, SHA-bound native reads and bounded PE parsing, strings, disassembly and CFG operations.
- Selected-file/request ownership, stale-result rejection and immutable verdict/evidence custody.
- NEST session lifecycle and learning acceptance hardening without bypassing entitlement checks.
- Receipt-driven report checklists, explicit missing/truncated evidence and JSON/Markdown disclosures.
- Suggested navigation that does not silently start analysis and rejects stale callbacks.
- Producer-owned RAT/wiper inference certainty, preserving literal import and YARA observations.
- Additive supplied-label support, abstention, confusion and error-rate metrics. Legacy regression statistics are not detection accuracy; confidence is not calibrated probability.
- Scope-aligned onboarding, documentation, native command exposure and Windows packaging support.

## Clean-checkout integration verification

The publication worktree was created from the current remote `main`, separately from the pre-existing dirty workspace. Verification on Windows returned:

| Check | Result |
| --- | --- |
| HexHawk frontend | 1,231 passed; one skipped; 120 files |
| Advisory core dependency | 41 passed; three files |
| Rust workspace/all targets | 452 passed; four existing ignored |
| Strict Clippy | Passed with `-D warnings` |
| TypeScript | Passed with `--noEmit` |
| Production frontend build | Passed |

The integration pass preserved the newer upstream `formatVarDictionaryKey` security fix and its existing tests instead of replacing it with an older snapshot implementation.

An unpublished optional golden-corpus module, its manifest and its tests are deliberately excluded together: they require local binary fixtures and historical evidence that are not suitable source dependencies for a clean checkout. They remain preserved locally. No existing remote test assertions were removed or relaxed, and no private samples or fabricated fixture outputs were substituted.

The tag-triggered signing/release workflow is unchanged. No release tag, merge, installer upload, signing operation or release publication is part of this source push.

Publication review also restored the existing Linux-only `glib` test dependency, retained Linux source tests, and explicitly disabled macOS/Linux packaging jobs that contradict the Windows-only bundle hook. Windows CI requests NSIS only. The hard-coded standalone "native smoke" HTML page is excluded from production assets; documentation image links resolve to explicitly labelled legacy browser/dev captures rather than claiming current native proof. Linux compilation is not claimed from the Windows validation run.

## Evidence limits and remaining gates

An earlier engineering snapshot produced an unsigned NSIS and passed 300 read-only checks against its exact extracted GUI across three clean cold starts. That artifact's SHA-256 is `5efed2ceb0379a9754295d47cd668fd343fc7e2d447c815897a28f9c889e7b3d`.

**That installer is not claimed to represent this publication integration.** Source integration preserves newer upstream code and excludes the non-portable corpus slice. This source must earn its own exact-artifact installation, physical JSON/Markdown export and uninstall/residue qualification before an installed-build claim.

Other open gates remain explicit:

- Legitimate Enterprise entitlement and native NEST lifecycle/export qualification.
- Security-owner disposition: the latest recorded audit retains three ZIP 8.6 advisories and 16 warnings. No waiver or security-clean claim is granted.
- First-party license intent, third-party notices and an artifact-matched packaged SBOM.
- Trusted signing and independent release approval.
- Independently adjudicated verdict evaluation and confidence calibration.

Source tests, authored controls, successful zero-result operations and checklist completion are not safety certificates, malware-accuracy proofs or whole-program coverage guarantees.
