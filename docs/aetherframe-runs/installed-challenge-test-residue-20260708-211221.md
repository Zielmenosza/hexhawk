# Installed HexHawk Challenge Test Residue Report

Generated: 20260708-211221
Status: post-test / pre-cleanup residue classification

## Evidence reports to keep

- `D:/Project/HexHawk/docs/aetherframe-runs/installed-challenge-test-prestate-20260708-211221.md`
- `D:/Project/HexHawk/docs/aetherframe-runs/installed-challenges-test-20260708-211221.md`
- `D:/Project/HexHawk/docs/aetherframe-runs/installed-challenge-test-residue-20260708-211221.md (this report)`

## Safe to clean after recording

- `D:/Project/HexHawk-smoke-20260708-211253` — installer smoke root created by this run; summary and key results recorded
- `D:/Project/HexHawk-installed-challenge-test-20260708-211221` — controlled NSIS install directory created for this run; should be uninstalled/removed after recording
- `D:/Project/HexHawk/work/installed_challenge_test_20260708-211221` — work/test output folder created by this run; raw outputs summarized in docs reports

## Do not clean automatically

- `D:/Project/HexHawk/Challenges`
- `D:/Project/HexHawk/target/release/bundle/msi/HexHawk_1.0.0_x64_en-US.msi`
- `D:/Project/HexHawk/target/release/bundle/nsis/HexHawk_1.0.0_x64-setup.exe`
- `D:/Project/HexHawk/target/release/hexhawk-backend.exe`
- `D:/Project/HexHawk source files and committed docs`
- `D:/Project/HexHawk/docs/aetherframe-runs/installer-smoke-plan-20260708-194641.md (pre-existing generated custody report)`
- `D:/Project/HexHawk/docs/aetherframe-runs/worktree-custody-20260701-201449.md (pre-existing generated custody report)`

## Raw inventories

- Pre-test inventory: `D:/Project/HexHawk/work/installed_challenge_test_20260708-211221/pre_residue_inventory.json`
- Post-test pre-cleanup inventory: `D:\Project\HexHawk\work\installed_challenge_test_20260708-211221\post_test_pre_cleanup_residue_inventory.json`

## Cleanup policy

Cleanup is limited to the exact safe-to-clean paths above. No wildcard/broad repo cleanup is permitted. Original challenge files, source, installers, target artifacts, package artifacts, committed docs, and unrelated untracked files remain untouched.

## Cleanup performed

- `D:/Project/HexHawk-installed-challenge-test-20260708-211221/uninstall.exe` — NSIS silent uninstall, exit code 0; install directory absent afterward.
- `D:/Project/HexHawk-smoke-20260708-211253` — exact installer smoke root created by this run; removed; absent afterward.
- `D:/Project/HexHawk-installed-challenge-test-20260708-211221` — exact controlled install directory created by this run; already absent after uninstall; absent afterward.
- `D:/Project/HexHawk/work/installed_challenge_test_20260708-211221` — exact installed challenge test work output folder created by this run; removed after markdown summaries were written; absent afterward.

No broad wildcard deletion was performed. Original Challenges files, source files, target installer outputs, package artifacts, and generated markdown custody reports were left in place.

## Remaining residue after cleanup

- `C:/Users/Ziel/AppData/Local/HexHawk` remains. It contains an `updater` folder with creation time 2026-06-02, so it was not created by this test run and was not cleaned.
- `C:/Users/Ziel/AppData/Roaming/HexHawk` remains. It contains pre-existing HexHawk user data including license key file names dated 2026-05-08. File contents were not read and the directory was not cleaned because it may contain credentials/secrets or durable user state.
- `D:/Project/HexHawk/work/recreate_challenges` remains. It predates this installed challenge test and was not cleaned because this run may not delete unrelated generated work merely because it is untracked.
