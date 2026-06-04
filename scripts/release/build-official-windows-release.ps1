param(
  [string]$RepoRoot = ".",
  [string]$TimestampServer = "http://timestamp.digicert.com",
  [switch]$SkipBuild,
  [switch]$SkipAuthenticodeSigning
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Require-Env {
  param([string]$Name)
  $value = [Environment]::GetEnvironmentVariable($Name)
  if (-not $value) {
    throw "Missing required official release secret/environment variable: $Name"
  }
  return $value
}

$repo = Get-Item -LiteralPath (Resolve-Path -LiteralPath $RepoRoot)
Set-Location $repo.FullName

$tauriConfigPath = Join-Path $repo.FullName "src-tauri/tauri.conf.json"
if (-not (Test-Path -LiteralPath $tauriConfigPath)) {
  throw "Missing Tauri config: $tauriConfigPath"
}

Require-Env -Name "TAURI_SIGNING_PRIVATE_KEY" | Out-Null
if ($env:HEXHAWK_ALLOW_UNTRUSTED_DEV_SIGNATURE -eq "1") {
  throw "Official release build refuses HEXHAWK_ALLOW_UNTRUSTED_DEV_SIGNATURE=1. Use a real organization-trusted code-signing path or pass -SkipAuthenticodeSigning for updater-only rehearsal evidence."
}

if (-not $SkipAuthenticodeSigning) {
  if (-not $env:HEXHAWK_CODESIGN_THUMBPRINT -and -not $env:HEXHAWK_CODESIGN_PFX_PATH) {
    throw "Official Windows release signing requires HEXHAWK_CODESIGN_THUMBPRINT or HEXHAWK_CODESIGN_PFX_PATH."
  }
}

$originalConfig = Get-Content -LiteralPath $tauriConfigPath -Raw
try {
  $tauriConfig = $originalConfig | ConvertFrom-Json
  $tauriConfig.bundle.createUpdaterArtifacts = $true
  [System.IO.File]::WriteAllText($tauriConfigPath, ($tauriConfig | ConvertTo-Json -Depth 100), [System.Text.UTF8Encoding]::new($false))

  if (-not $SkipBuild) {
    & yarn tauri:build
    if ($LASTEXITCODE -ne 0) {
      throw "yarn tauri:build failed during official Windows release build."
    }
  }
} finally {
  [System.IO.File]::WriteAllText($tauriConfigPath, $originalConfig, [System.Text.UTF8Encoding]::new($false))
}

$version = [string](($originalConfig | ConvertFrom-Json).version)
$artifacts = @(
  (Join-Path $repo.FullName "target/release/hexhawk-backend.exe"),
  (Join-Path $repo.FullName "target/release/bundle/msi/HexHawk_${version}_x64_en-US.msi"),
  (Join-Path $repo.FullName "target/release/bundle/nsis/HexHawk_${version}_x64-setup.exe")
)

foreach ($artifact in $artifacts) {
  if (-not (Test-Path -LiteralPath $artifact)) {
    throw "Missing expected official Windows artifact: $artifact"
  }
}

$nsisSig = "$($artifacts[2]).sig"
if (-not (Test-Path -LiteralPath $nsisSig)) {
  throw "Missing Tauri updater signature sidecar for NSIS installer: $nsisSig. Ensure TAURI_SIGNING_PRIVATE_KEY is official custody and updater artifacts were enabled for this build."
}

if (-not $SkipAuthenticodeSigning) {
  $signScript = Join-Path $repo.FullName "scripts/release/sign-windows-artifact.ps1"
  foreach ($artifact in $artifacts) {
    & powershell -NoProfile -ExecutionPolicy Bypass -File $signScript -ArtifactPath $artifact -TimestampServer $TimestampServer
    if ($LASTEXITCODE -ne 0) {
      throw "Authenticode signing failed for $artifact"
    }
  }
}

$authenticode = foreach ($artifact in $artifacts) {
  $sig = Get-AuthenticodeSignature -FilePath $artifact
  [ordered]@{
    path = $artifact
    status = [string]$sig.Status
    statusMessage = [string]$sig.StatusMessage
    signerSubject = if ($sig.SignerCertificate) { [string]$sig.SignerCertificate.Subject } else { $null }
    signerThumbprint = if ($sig.SignerCertificate) { [string]$sig.SignerCertificate.Thumbprint } else { $null }
    timestampSubject = if ($sig.TimeStamperCertificate) { [string]$sig.TimeStamperCertificate.Subject } else { $null }
  }
}

$hashes = foreach ($artifact in $artifacts) {
  $hash = Get-FileHash -LiteralPath $artifact -Algorithm SHA256
  [ordered]@{ path = $artifact; sha256 = $hash.Hash.ToLowerInvariant() }
}

$result = [ordered]@{
  schema = "hexhawk.official_windows_release_build.v1"
  generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
  updater_key_custody = "TAURI_SIGNING_PRIVATE_KEY from official release environment secret"
  updater_artifacts_enabled_for_build = $true
  authenticode_signing_skipped = [bool]$SkipAuthenticodeSigning
  artifacts = $hashes
  authenticode = $authenticode
  nsis_updater_signature = [ordered]@{
    path = $nsisSig
    exists = $true
    bytes = (Get-Item -LiteralPath $nsisSig).Length
  }
}

$result | ConvertTo-Json -Depth 8
