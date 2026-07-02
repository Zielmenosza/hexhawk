# HexHawk Early Access Package Custody

Generated: 2026-07-02 23:22:05 +0200

Status: custody plan for local unsigned early-access package handling. This document does not publish, upload, sign, deploy, or deliver a package.

## Current local package path

- Folder: `D:/Project/HexHawk-early-access-packages`
- Current known package: `HexHawk_Early_Access_UNSIGNED_v1.0.0_20260701.zip`
- Zip path: `D:/Project/HexHawk-early-access-packages/HexHawk_Early_Access_UNSIGNED_v1.0.0_20260701.zip`
- Zip size at read-only verification: `40,638,772 bytes`
- Zip SHA256 at read-only verification: `234a96e19675fe7293786215cb1a9b7cc01af23997332734f045bf3d24f69d87`

## Package contents hash manifest

From local `SHA256SUMS.txt` inside `HexHawk_Early_Access_UNSIGNED_v1.0.0_20260701`:

- `HexHawk_1.0.0_x64_en-US.msi` — `0b6a8e885accd45b6c1633f5db79af839302d8c45311ab5d48ef4ddeefe0d14e`
- `HexHawk_1.0.0_x64-setup.exe` — `fae7b573054a3938bc38c7ae21f341b54a2772629526cbda1c829a663ce59c71`
- `nest_cli.exe` — `c4be723b6aaffafac18d04ea06928177bea0b5d46ee13f8ef65d51621225beb9`

## Custody recommendation

- Keep the local package folder for now.
- Do not public-upload the zip.
- Use private manual delivery only after payment confirmation and buyer acknowledgement of unsigned limits.
- Before sending to any tester, re-run exact package verification:
  - package exists;
  - package SHA256 matches the expected value;
  - expanded package docs are present;
  - `SHA256SUMS.txt` is present;
  - package contents match the manifest;
  - Authenticode status is recorded as expected for unsigned early access.
- Record which package was sent to whom, on what date, and with which SHA256 in private fulfillment records.
- Do not store buyer PII, payment details, or private delivery links in this repo.

## Future signed release path

Public trust/download remains blocked until:

- Authenticode signing is configured and proven on exact artifacts;
- updater signing and hosted metadata are configured and proven;
- exact-artifact release gate passes;
- public trust/download page is approved and validated;
- support, refund, and fulfillment process is settled.

Payment/private delivery does not substitute for signed release readiness.
