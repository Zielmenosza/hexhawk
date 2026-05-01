param(
  [string]$Version,
  [string]$WebsiteRoot = ".\website",
  [string]$BundleRoot = ".\target\release\bundle",
  [string]$GitHubOwner = "Zielmenosza",
  [string]$GitHubRepo = "hexhawk",
  [switch]$UseLocalReleaseFiles
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Require-Path {
  param([string]$Path, [string]$Message)
  if (-not (Test-Path -LiteralPath $Path)) {
    throw $Message
  }
}

function To-ManifestEntry {
  param(
    [Parameter(Mandatory = $true)] [System.IO.FileInfo]$File,
    [Parameter(Mandatory = $true)] [string]$BaseUrl
  )

  return [ordered]@{
    name = $File.Name
    url  = "$BaseUrl/$($File.Name)"
  }
}

if (-not $Version) {
  $tauriConfigPath = Join-Path $PSScriptRoot "..\..\src-tauri\tauri.conf.json"
  Require-Path -Path $tauriConfigPath -Message "Could not find tauri.conf.json at $tauriConfigPath"
  $tauriConfig = Get-Content -Raw -LiteralPath $tauriConfigPath | ConvertFrom-Json
  $Version = [string]$tauriConfig.version
}

if (-not $Version) {
  throw "Version could not be determined. Pass -Version explicitly."
}

$websiteRootFull = (Resolve-Path $WebsiteRoot).Path
if (-not (Test-Path -LiteralPath $BundleRoot)) {
  throw "Bundle folder not found at '$BundleRoot'. Build installers first with 'yarn tauri:build'."
}
$bundleRootFull = (Resolve-Path $BundleRoot).Path

$releaseFolderName = "v$Version"
$releaseRoot = Join-Path $websiteRootFull "releases\$releaseFolderName"
$assetRoot = Join-Path $releaseRoot "assets"
$latestJsonPath = Join-Path $websiteRootFull "releases\latest.json"

New-Item -ItemType Directory -Path $assetRoot -Force | Out-Null

$extensions = @("*.msi", "*.exe", "*.dmg", "*.deb", "*.AppImage", "*.appimage", "*.rpm", "*.zip", "*.tar.gz")
$bundleFiles = Get-ChildItem -Path $bundleRootFull -Recurse -File | Where-Object {
  $name = $_.Name
  foreach ($pattern in $extensions) {
    if ($name -like $pattern) { return $true }
  }
  return $false
}

if (-not $bundleFiles) {
  throw "No installer artifacts found under $bundleRootFull. Build with 'yarn tauri:build' first."
}

foreach ($file in $bundleFiles) {
  Copy-Item -LiteralPath $file.FullName -Destination (Join-Path $assetRoot $file.Name) -Force
}

$copiedFiles = Get-ChildItem -LiteralPath $assetRoot -File
if (-not $copiedFiles) {
  throw "No artifacts copied to $assetRoot"
}

$shaFile = Join-Path $releaseRoot "SHA256SUMS.txt"
$hashLines = foreach ($file in $copiedFiles | Sort-Object Name) {
  $hash = Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256
  "$($hash.Hash.ToLowerInvariant())  $($file.Name)"
}
$hashLines | Set-Content -LiteralPath $shaFile -Encoding ascii

$releaseBaseUrl = if ($UseLocalReleaseFiles) {
  "/releases/$releaseFolderName/assets"
} else {
  "https://github.com/$GitHubOwner/$GitHubRepo/releases/download/$releaseFolderName"
}

$pick = @{}
$pick.windowsInstaller = $copiedFiles | Where-Object { $_.Name -match "(?i)setup\.exe$" } | Sort-Object Name | Select-Object -First 1
$pick.windowsMsi = $copiedFiles | Where-Object { $_.Extension -eq ".msi" } | Sort-Object Name | Select-Object -First 1
$pick.windowsExe = $copiedFiles | Where-Object { $_.Extension -eq ".exe" } | Sort-Object Name | Select-Object -First 1
$pick.windowsPortable = $copiedFiles | Where-Object { $_.Name -match "portable" -and $_.Extension -eq ".exe" } | Sort-Object Name | Select-Object -First 1
$pick.linuxAppImage = $copiedFiles | Where-Object { $_.Name -match "(?i)appimage" } | Sort-Object Name | Select-Object -First 1
$pick.linuxDeb = $copiedFiles | Where-Object { $_.Extension -eq ".deb" } | Sort-Object Name | Select-Object -First 1
$pick.linuxRpm = $copiedFiles | Where-Object { $_.Extension -eq ".rpm" } | Sort-Object Name | Select-Object -First 1
$pick.macosDmg = $copiedFiles | Where-Object { $_.Extension -eq ".dmg" } | Sort-Object Name | Select-Object -First 1

$manifest = [ordered]@{
  version = $Version
  releasedAt = (Get-Date).ToUniversalTime().ToString("o")
  notesUrl = "https://github.com/$GitHubOwner/$GitHubRepo/releases/tag/$releaseFolderName"
  checksumsUrl = "/releases/$releaseFolderName/SHA256SUMS.txt"
  downloads = [ordered]@{
    windows = [ordered]@{}
    linux = [ordered]@{}
    macos = [ordered]@{}
  }
}

if ($pick.windowsInstaller) { $manifest.downloads.windows.installer = To-ManifestEntry -File $pick.windowsInstaller -BaseUrl $releaseBaseUrl }
if ($pick.windowsMsi) { $manifest.downloads.windows.msi = To-ManifestEntry -File $pick.windowsMsi -BaseUrl $releaseBaseUrl }
if (-not $pick.windowsInstaller -and $pick.windowsExe) { $manifest.downloads.windows.installer = To-ManifestEntry -File $pick.windowsExe -BaseUrl $releaseBaseUrl }
if ($pick.windowsPortable) { $manifest.downloads.windows.portable = To-ManifestEntry -File $pick.windowsPortable -BaseUrl $releaseBaseUrl }
if ($pick.linuxAppImage) { $manifest.downloads.linux.appImage = To-ManifestEntry -File $pick.linuxAppImage -BaseUrl $releaseBaseUrl }
if ($pick.linuxDeb) { $manifest.downloads.linux.deb = To-ManifestEntry -File $pick.linuxDeb -BaseUrl $releaseBaseUrl }
if ($pick.linuxRpm) { $manifest.downloads.linux.rpm = To-ManifestEntry -File $pick.linuxRpm -BaseUrl $releaseBaseUrl }
if ($pick.macosDmg) { $manifest.downloads.macos.dmg = To-ManifestEntry -File $pick.macosDmg -BaseUrl $releaseBaseUrl }

$manifestJson = $manifest | ConvertTo-Json -Depth 8
$manifestJson | Set-Content -LiteralPath $latestJsonPath -Encoding ascii

Write-Host "Release prepared for version $Version"
Write-Host "Artifacts copied: $($copiedFiles.Count)"
Write-Host "Manifest updated: $latestJsonPath"
Write-Host "Checksums file: $shaFile"
