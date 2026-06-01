param(
  [string]$RepoRoot = ".",
  [string]$Version,
  [string]$TimestampServer = "http://timestamp.digicert.com",
  [string]$UpdaterTarget = "windows",
  [string]$UpdaterArch = "x86_64",
  [switch]$BuildArtifacts,
  [switch]$UseSelfSignedDevCert,
  [switch]$SkipNativeProbe,
  [switch]$SkipUpdaterValidation
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Resolve-RepoPath {
  param([string]$PathFromRoot)
  return Join-Path $repo.FullName $PathFromRoot
}

function Get-TauriConfig {
  $confPath = Resolve-RepoPath "src-tauri/tauri.conf.json"
  if (-not (Test-Path -LiteralPath $confPath)) {
    throw "Missing tauri config at $confPath"
  }
  return Get-Content -LiteralPath $confPath -Raw | ConvertFrom-Json
}

function Ensure-DevCodeSigningCert {
  param([string]$SubjectName)

  $existing = Get-ChildItem "Cert:\CurrentUser\My" -CodeSigningCert -ErrorAction SilentlyContinue |
    Where-Object { $_.Subject -eq "CN=$SubjectName" } |
    Sort-Object NotAfter -Descending |
    Select-Object -First 1

  if ($existing) {
    return $existing
  }

  return New-SelfSignedCertificate `
    -Type CodeSigningCert `
    -Subject "CN=$SubjectName" `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -NotAfter (Get-Date).AddYears(1) `
    -HashAlgorithm SHA256
}

function Get-SignatureInfo {
  param([string]$FilePath)

  $sig = Get-AuthenticodeSignature -FilePath $FilePath
  return [ordered]@{
    path = $FilePath
    status = [string]$sig.Status
    statusMessage = [string]$sig.StatusMessage
    signerSubject = if ($sig.SignerCertificate) { [string]$sig.SignerCertificate.Subject } else { $null }
    signerThumbprint = if ($sig.SignerCertificate) { [string]$sig.SignerCertificate.Thumbprint } else { $null }
    signerNotAfter = if ($sig.SignerCertificate) { $sig.SignerCertificate.NotAfter.ToUniversalTime().ToString("o") } else { $null }
    timestampSubject = if ($sig.TimeStamperCertificate) { [string]$sig.TimeStamperCertificate.Subject } else { $null }
  }
}

function Get-UpdaterValidation {
  param(
    [object]$TauriConfig,
    [string]$CurrentVersion,
    [string]$Target,
    [string]$Arch
  )

  $updater = $TauriConfig.plugins.updater
  $endpointTemplate = $updater.endpoints[0]
  $resolvedUrl = [string]$endpointTemplate
  $resolvedUrl = $resolvedUrl.Replace("{{target}}", $Target)
  $resolvedUrl = $resolvedUrl.Replace("{{arch}}", $Arch)
  $resolvedUrl = $resolvedUrl.Replace("{{current_version}}", $CurrentVersion)

  $result = [ordered]@{
    endpointTemplate = $endpointTemplate
    resolvedUrl = $resolvedUrl
    pubkeyConfigured = [bool]($updater.pubkey -and $updater.pubkey.Trim().Length -gt 0)
    fetchOk = $false
    httpStatus = $null
    metadataValid = $false
    metadataChecks = @()
    error = $null
  }

  try {
    $response = Invoke-WebRequest -Uri $resolvedUrl -UseBasicParsing -TimeoutSec 30
    $result.fetchOk = $true
    $result.httpStatus = [int]$response.StatusCode

    $json = $response.Content | ConvertFrom-Json
    $checks = @()

    $checks += [ordered]@{ name = "hasVersion"; ok = [bool]($json.version); detail = $json.version }
    $checks += [ordered]@{ name = "hasPlatforms"; ok = [bool]($json.platforms); detail = if ($json.platforms) { "present" } else { "missing" } }

    $platformKey = "$Target-$Arch"
    $platformNode = if ($json.platforms) { $json.platforms.$platformKey } else { $null }
    $checks += [ordered]@{ name = "hasPlatformNode"; ok = [bool]$platformNode; detail = $platformKey }
    $checks += [ordered]@{ name = "hasPlatformUrl"; ok = [bool]($platformNode -and $platformNode.url); detail = if ($platformNode) { $platformNode.url } else { $null } }
    $checks += [ordered]@{ name = "hasPlatformSignature"; ok = [bool]($platformNode -and $platformNode.signature); detail = if ($platformNode) { $platformNode.signature } else { $null } }

    $result.metadataChecks = $checks
    $result.metadataValid = ($checks | Where-Object { -not $_.ok }).Count -eq 0
  } catch {
    $result.error = $_.Exception.Message
  }

  return $result
}

$repo = Get-Item -LiteralPath (Resolve-Path -LiteralPath $RepoRoot)
Set-Location $repo.FullName

$tauriConfig = Get-TauriConfig
if (-not $Version) {
  $Version = [string]$tauriConfig.version
}

if ($BuildArtifacts) {
  & yarn tauri:build
  if ($LASTEXITCODE -ne 0) {
    throw "yarn tauri:build failed."
  }
}

$exePath = Resolve-RepoPath "target/release/hexhawk-backend.exe"
$msiPath = Resolve-RepoPath "target/release/bundle/msi/HexHawk_${Version}_x64_en-US.msi"
$nsisPath = Resolve-RepoPath "target/release/bundle/nsis/HexHawk_${Version}_x64-setup.exe"

foreach ($required in @($exePath, $msiPath, $nsisPath)) {
  if (-not (Test-Path -LiteralPath $required)) {
    throw "Missing release artifact: $required"
  }
}

$signingIdentity = [ordered]@{
  thumbprint = $env:HEXHAWK_CODESIGN_THUMBPRINT
  pfxPath = $env:HEXHAWK_CODESIGN_PFX_PATH
  usedSelfSignedDevCert = $false
}

if (-not $signingIdentity.thumbprint -and -not $signingIdentity.pfxPath -and $UseSelfSignedDevCert) {
  $devCert = Ensure-DevCodeSigningCert -SubjectName "HexHawk Internal Dev Code Signing"
  $env:HEXHAWK_CODESIGN_THUMBPRINT = $devCert.Thumbprint
  $env:HEXHAWK_ALLOW_UNTRUSTED_DEV_SIGNATURE = "1"
  $signingIdentity.thumbprint = $devCert.Thumbprint
  $signingIdentity.usedSelfSignedDevCert = $true
}

if (-not $signingIdentity.thumbprint -and -not $signingIdentity.pfxPath) {
  throw "No code-signing identity configured. Set HEXHAWK_CODESIGN_THUMBPRINT or HEXHAWK_CODESIGN_PFX_PATH, or use -UseSelfSignedDevCert for internal-only local signing."
}

$signScript = Resolve-RepoPath "scripts/release/sign-windows-artifact.ps1"
$artifacts = @($exePath, $msiPath, $nsisPath)
$signatureResults = @()
$hashes = @()

foreach ($artifact in $artifacts) {
  & powershell -NoProfile -ExecutionPolicy Bypass -File $signScript -ArtifactPath $artifact -TimestampServer $TimestampServer
  if ($LASTEXITCODE -ne 0) {
    throw "Signing failed for $artifact"
  }

  $signatureResults += Get-SignatureInfo -FilePath $artifact
  $hash = Get-FileHash -LiteralPath $artifact -Algorithm SHA256
  $hashes += [ordered]@{
    path = $artifact
    sha256 = $hash.Hash.ToLowerInvariant()
  }
}

$updaterValidation = if ($SkipUpdaterValidation) {
  [ordered]@{ skipped = $true }
} else {
  Get-UpdaterValidation -TauriConfig $tauriConfig -CurrentVersion $Version -Target $UpdaterTarget -Arch $UpdaterArch
}

$nativeProbe = [ordered]@{ skipped = [bool]$SkipNativeProbe; ok = $null; outputPath = $null; error = $null }
if (-not $SkipNativeProbe) {
  $probeScript = Resolve-RepoPath "scripts/release/run-native-parity-probe.ps1"
  $probeOut = Resolve-RepoPath ("gui-evidence/release_hardening_native_gui_probe_{0}.json" -f (Get-Date -Format "yyyy-MM-dd_HHmmss"))
  try {
    & powershell -NoProfile -ExecutionPolicy Bypass -File $probeScript -MsiPath $msiPath -OutputPath $probeOut
    if ($LASTEXITCODE -ne 0) {
      throw "native probe failed with exit code $LASTEXITCODE"
    }
    $nativeProbe.ok = $true
    $nativeProbe.outputPath = $probeOut
  } catch {
    $nativeProbe.ok = $false
    $nativeProbe.error = $_.Exception.Message
    $nativeProbe.outputPath = $probeOut
  }
}

$evidenceDir = Resolve-RepoPath "docs/release-evidence"
New-Item -ItemType Directory -Path $evidenceDir -Force | Out-Null
$evidencePath = Join-Path $evidenceDir ("windows_release_hardening_{0}.json" -f (Get-Date -Format "yyyy-MM-dd_HHmmss"))

$report = [ordered]@{
  generatedAt = (Get-Date).ToUniversalTime().ToString("o")
  version = $Version
  signingIdentity = $signingIdentity
  artifacts = $hashes
  signatures = $signatureResults
  updaterValidation = $updaterValidation
  nativeProbe = $nativeProbe
}

($report | ConvertTo-Json -Depth 8) | Set-Content -LiteralPath $evidencePath -Encoding ascii

Write-Output "Release hardening evidence written: $evidencePath"
Write-Output ($report | ConvertTo-Json -Depth 6)
