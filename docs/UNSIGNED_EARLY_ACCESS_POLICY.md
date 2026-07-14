# HexHawk Unsigned Early Access Policy

Last updated: 2026-07-14

The current HexHawk 1.0.0 MSI and NSIS candidates are Authenticode `NotSigned` with verified hashes and metadata. They are ready only for approved controlled local installation testing. No installation or installed-artifact acceptance check has passed for the exact candidates; packaging does not establish production, procurement, updater, or public-release readiness. See [`CURRENT_STATUS.md`](CURRENT_STATUS.md) and [`EARLY_ACCESS_INSTALL_README.md`](EARLY_ACCESS_INSTALL_README.md).

Status: Active policy for controlled paid early-access technical preview
Channel name: HexHawk Early Access — Unsigned Founder Build

## Purpose

HexHawk Unsigned Early Access is a paid technical preview channel for users who understand unsigned Windows software and want to help fund HexHawk's release-trust path.

This is a commercial testing channel. It is not a public trust claim.

The goals are:

- let technical testers evaluate a local-first analysis workbench before public signing is complete;
- collect practical installation, workflow, and analysis feedback;
- generate early revenue to fund proper code signing, updater trust, release hardening, and product polish;
- keep every trust limitation visible instead of pretending the build is public-ready.

## What this channel is

- A paid early-access technical preview.
- A controlled package for technical testers.
- An unsigned Windows build unless a future exact package says otherwise.
- A manual-update channel.
- A way to fund proper Authenticode signing, updater signing, release trust, support process, and product hardening.

## What this channel is not

- Not a signed release.
- Not Microsoft verified.
- Not a public/world-ready release.
- Not an enterprise/procurement-ready release.
- Not an auto-updating release.
- Not a claim that Windows should trust the publisher yet.
- Not a reason to disable Windows security globally.

## Unsigned artifact expectations

Artifacts in this channel are expected to report Authenticode status `NotSigned`. Windows may show trust, reputation, or security warnings for unsigned installers and executables.

Users should verify SHA256 hashes from the package before installing or running anything. Hash verification proves that a file matches the package manifest. It does not make an unsigned file signed or Microsoft verified.

## Security posture for buyers

Do not disable system security globally to use HexHawk. Do not turn off Microsoft Defender, SmartScreen, endpoint protection, or browser security across the system just to run an early-access package.

If Windows or an organizational endpoint tool blocks the unsigned build, treat that as expected behavior for unsigned software. Ask for support or wait for a signed build rather than weakening system-wide protections.

## Update policy

No auto-update is included in this channel. Updates are manual until updater signing and release trust are configured and proven on exact artifacts.

A private download, payment, or buyer relationship does not prove updater readiness. Tauri updater signatures and hosted metadata must be separately configured, validated, and recorded before any auto-update claim is made.

## Authority boundaries

HexHawk's technical authority boundaries do not change for early access:

- GYRE remains the sole verdict/classification authority.
- NEST remains evidence orchestration and convergence only.
- TALON remains advisory decompiler/pseudocode reconstruction only.
- STRIKE remains runtime/debugger evidence only.
- Function Intelligence remains an advisory evidence notebook only.
- AETHERFRAME remains advancement/refinement/factory orchestration only.
- NEXUS/Hermes/AI remain assistant/proposal/workflow helpers only.

AI, AETHERFRAME, Function Intelligence, and buyer feedback may help improve the product and packaging process. They do not override GYRE verdict authority.

## Commercial boundary

Payment/private distribution must not be confused with signed or public-release readiness. A buyer is paying for early access, feedback influence, and future upgrade path — not for a Microsoft-verified or broadly trusted public release.

Every package should carry:

- package contents;
- SHA256 hashes;
- Authenticode status;
- exact commit and artifact paths;
- known limitations;
- clear unsigned early-access wording.
