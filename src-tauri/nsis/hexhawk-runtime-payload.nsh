; HexHawk NSIS runtime payload parity hook.
;
; Tauri's generated WiX bundle includes WebView2Loader.dll from the same
; release directory as hexhawk-backend.exe, but the generated NSIS install
; section only copies the main executable and external binaries. Without the
; loader beside the GUI executable, the NSIS-installed app exits at launch with
; 0xC0000135.
;
; Keep this installer-only hook path-derived and worktree-portable: this file
; lives at src-tauri/nsis/, so ../../target/release/WebView2Loader.dll points at
; the Tauri-built runtime loader in any fresh release worktree.

!define HEXHAWK_WEBVIEW2_LOADER_PATH "${__FILEDIR__}\..\..\target\release\WebView2Loader.dll"

!macro NSIS_HOOK_POSTINSTALL
  ; Keep the NSIS installed payload at parity with the MSI payload: the GUI
  ; executable requires WebView2Loader.dll in the application root directory.
  ; CI packaging may not materialize WebView2Loader.dll before NSIS generation.
  ; Keep installer creation nonfatal; exact NSIS runtime-loader parity remains a release gate.
  File /nonfatal /a "/oname=WebView2Loader.dll" "${HEXHAWK_WEBVIEW2_LOADER_PATH}"
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  ; The default NSIS template only removes files it knows about. Remove the
  ; parity loader explicitly so silent uninstall leaves no runtime DLL behind.
  Delete "$INSTDIR\WebView2Loader.dll"
!macroend
