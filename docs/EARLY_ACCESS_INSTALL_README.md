# HexHawk Early Access Install README

Channel: HexHawk Early Access — Unsigned Founder Build
Audience: technical testers comfortable evaluating unsigned Windows software

## Package contents

A package created by `scripts/release/build_unsigned_early_access_package.ps1` should include:

- Windows MSI installer.
- Windows NSIS setup executable.
- `nest_cli.exe` when included by the package parameters.
- `WebView2Loader.dll` when included by the package parameters or relevant artifact collection.
- `SHA256SUMS.txt`.
- `EVIDENCE_MANIFEST.json`.
- `PACKAGE_CONTENTS.txt`.
- `EARLY_ACCESS_RELEASE_NOTES.md`.
- `UNSIGNED_EARLY_ACCESS_POLICY.md`.
- `EARLY_ACCESS_INSTALL_README.md`.
- `EARLY_ACCESS_BUYER_NOTE.md`.

## Verify SHA256 before installing

From PowerShell in the extracted package folder:

```powershell
Get-FileHash -Algorithm SHA256 .\HexHawk_1.0.0_x64_en-US.msi
Get-FileHash -Algorithm SHA256 .\HexHawk_1.0.0_x64-setup.exe
```

Compare the hash values with `SHA256SUMS.txt` and `EVIDENCE_MANIFEST.json`.

Hash verification confirms that the file matches the package manifest. It does not mean the artifact is signed, Microsoft verified, or public-ready.

## Install options

Use one installer path, not both at the same time:

1. MSI path: run the `.msi` installer and follow the prompts.
2. NSIS path: run the `*-setup.exe` installer and follow the prompts.

The package is unsigned. Windows may show warnings because the publisher trust chain is not established yet.

## Uninstall

Use Windows Apps & features / Installed apps to remove HexHawk, or use the uninstaller created by the NSIS installer when present.

If you installed both MSI and NSIS variants during testing, uninstall both variants separately and report that test condition in feedback.

## Known warnings

- Windows may warn that the app is from an unknown publisher.
- SmartScreen or enterprise endpoint tools may block or quarantine unsigned software.
- These warnings are expected for unsigned builds.
- Do not disable system security globally. If blocked, report the exact warning and wait for guidance or a signed build.

## Known limitations

- This is an unsigned early-access build.
- No auto-update is included yet.
- Updates are manual until signing and updater trust are complete.
- The package is for technical testers, not broad consumer deployment.
- A successful install does not prove enterprise/procurement readiness.
- Existing native workflow probes and release evidence may be historical unless the package manifest ties evidence to the exact current artifacts.

## Safe use notes

HexHawk is a local-first analysis workbench. It is intended to help inspect binary metadata, strings, disassembly, evidence, advisory function notes, reports, and related analysis surfaces on your machine.

Do not use on production malware samples unless you understand the risk and have an appropriate isolated analysis environment. HexHawk early access is not a promise that unsafe samples become safe to handle.

## Support / contact placeholder

Support channel: TBD before private distribution.

When reporting issues, include:

- package filename;
- package version/date;
- SHA256 hash of the installer used;
- Windows version;
- which installer path you used: MSI or NSIS;
- warning/error screenshots or exact text;
- steps to reproduce;
- whether you were analyzing a benign test file or a risky sample.

## Authority boundary reminder

GYRE remains the sole verdict/classification authority. Function Intelligence, AETHERFRAME, AI/NEXUS, decompiler notes, runtime notes, and report packaging are advisory/evidence surfaces only.
