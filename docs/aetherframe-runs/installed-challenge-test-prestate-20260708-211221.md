# Installed HexHawk Challenge Test Prestate

Status: pre-test snapshot only; no deletion in this phase
Generated: 20260708-211221
Approved target machine: DESKTOP-0F2PCGU
Approved challenge folder: D:/Project/HexHawk/Challenges

## Git / CI custody

```text
## main...origin/main
?? docs/aetherframe-runs/installer-smoke-plan-20260708-194641.md
?? docs/aetherframe-runs/worktree-custody-20260701-201449.md
?? work/
HEAD: f1743740dfc238b6799cefa385452e10a92c60d9
origin/main: f1743740dfc238b6799cefa385452e10a92c60d9
```

Recent GitHub runs:

```json
[{"conclusion":"success","databaseId":28963720396,"headSha":"f1743740dfc238b6799cefa385452e10a92c60d9","status":"completed","url":"https://github.com/Zielmenosza/hexhawk/actions/runs/28963720396"},{"conclusion":"success","databaseId":28756576304,"headSha":"b4916a0ff30c46c928a0ac9d29a62ddd79d7f204","status":"completed","url":"https://github.com/Zielmenosza/hexhawk/actions/runs/28756576304"},{"conclusion":"failure","databaseId":28704207691,"headSha":"0e2a54c9ca1ebe189fa21e3fc7aae65a704a8ddc","status":"completed","url":"https://github.com/Zielmenosza/hexhawk/actions/runs/28704207691"},{"conclusion":"success","databaseId":28689569942,"headSha":"bd1bd0305c01fbb42e6c6ce7b381999b889bc729","status":"completed","url":"https://github.com/Zielmenosza/hexhawk/actions/runs/28689569942"},{"conclusion":"success","databaseId":28688926907,"headSha":"798b628edb3d771e0f04813d8ca731348ff5abcd","status":"completed","url":"https://github.com/Zielmenosza/hexhawk/actions/runs/28688926907"}]
```

Worktrees:

```text
D:/Project/HexHawk f174374 [main]
```

## Machine identity

```text
Manufacturer      : ASUS
Model             : System Product Name
Name              : DESKTOP-0F2PCGU
Domain            : WORKGROUP
HypervisorPresent : True
```

## Installer hashes

```text
18fbbead7f7cfa5fdb98ff0b7d07af83909a17e3670ed70c8238919a5def29db *target/release/bundle/msi/HexHawk_1.0.0_x64_en-US.msi
416f477b8b46014aadff522b83f2f3ba55974a196e6cd7a2f5d12091848b26dc *target/release/bundle/nsis/HexHawk_1.0.0_x64-setup.exe
6454f7ac15ad245ed1c4700d9d120e15d9f943f0af8c05e3d5f55bcbbaed5af4 *target/release/hexhawk-backend.exe
```

## Authenticode status

```text
SignerCertificate      : 
TimeStamperCertificate : 
Status                 : NotSigned
StatusMessage          : The file D:\Project\HexHawk\target\release\bundle\msi\HexHawk_1.0.0_x64_en-US.msi is not 
                         digitally signed. You cannot run this script on the current system. For more information 
                         about running scripts and setting execution policy, see about_Execution_Policies at 
                         https:/go.microsoft.com/fwlink/?LinkID=135170
Path                   : D:\Project\HexHawk\target\release\bundle\msi\HexHawk_1.0.0_x64_en-US.msi
SignatureType          : None
IsOSBinary             : False




--- NSIS ---


SignerCertificate      : 
TimeStamperCertificate : 
Status                 : NotSigned
StatusMessage          : The file D:\Project\HexHawk\target\release\bundle\nsis\HexHawk_1.0.0_x64-setup.exe is not 
                         digitally signed. You cannot run this script on the current system. For more information 
                         about running scripts and setting execution policy, see about_Execution_Policies at 
                         https:/go.microsoft.com/fwlink/?LinkID=135170
Path                   : D:\Project\HexHawk\target\release\bundle\nsis\HexHawk_1.0.0_x64-setup.exe
SignatureType          : None
IsOSBinary             : False




--- backend ---


SignerCertificate      : 
TimeStamperCertificate : 
Status                 : NotSigned
StatusMessage          : The file D:\Project\HexHawk\target\release\hexhawk-backend.exe is not digitally signed. You 
                         cannot run this script on the current system. For more information about running scripts and 
                         setting execution policy, see about_Execution_Policies at 
                         https:/go.microsoft.com/fwlink/?LinkID=135170
Path                   : D:\Project\HexHawk\target\release\hexhawk-backend.exe
SignatureType          : None
IsOSBinary             : False
```

## Known residue locations inspected before test

- Program Files / HexHawk install location: C:/Program Files/HexHawk
- Start Menu shortcuts: C:/ProgramData/Microsoft/Windows/Start Menu/Programs/HexHawk
- Desktop shortcuts: current user's Desktop/HexHawk.lnk
- AppData Local HexHawk folder: %LOCALAPPDATA%/HexHawk
- AppData Roaming HexHawk folder: %APPDATA%/HexHawk
- ProgramData HexHawk folder: C:/ProgramData/HexHawk
- Temp HexHawk-related folders: %TEMP%/*HexHawk*, %TEMP%/*hexhawk*
- Repo work/test outputs: D:/Project/HexHawk/work
- Installer smoke roots: D:/Project/HexHawk-smoke-*
- Windows uninstall entries containing HexHawk in HKLM/HKCU uninstall locations
- App logs created by HexHawk under install/AppData/temp paths if present

Raw pre-test inventory JSON:
D:/Project/HexHawk/work/installed_challenge_test_20260708-211221/pre_residue_inventory.json

## Deletion policy

No deletion was performed in Phase 0. Cleanup later is limited to exact paths created by this test run and classified safe after recording.
