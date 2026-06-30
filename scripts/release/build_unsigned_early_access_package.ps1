param(
  [string]$WorktreePath = ".",
  [string]$OutputDir = "D:\Project\HexHawk-early-access-packages",
  [string]$Version,
  [string]$Stamp,
  [switch]$IncludeNestCli,
  [switch]$IncludeWebView2Loader,
  [bool]$RequireNotSigned = $true,
  [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Resolve-FullPath {
  param([string]$PathValue)
  return (Resolve-Path -LiteralPath $PathValue).Path
}

function Get-Sha256 {
  param([string]$PathValue)
  return (Get-FileHash -LiteralPath $PathValue -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-AuthenticodeInfo {
  param([string]$PathValue)
  $sig = Get-AuthenticodeSignature -FilePath $PathValue
  return [ordered]@{
    path = $PathValue
    status = [string]$sig.Status
    statusMessage = [string]$sig.StatusMessage
    signerSubject = if ($sig.SignerCertificate) { [string]$sig.SignerCertificate.Subject } else { $null }
    signerThumbprint = if ($sig.SignerCertificate) { [string]$sig.SignerCertificate.Thumbprint } else { $null }
  }
}

function Add-Artifact {
  param(
    [System.Collections.ArrayList]$List,
    [string]$Kind,
    [string]$PathValue,
    [bool]$Required = $true
  )

  $exists = Test-Path -LiteralPath $PathValue -PathType Leaf
  if ($Required -and -not $exists) {
    throw "Missing required artifact [$Kind]: $PathValue"
  }
  if ($exists) {
    [void]$List.Add([ordered]@{
      kind = $Kind
      path = $PathValue
      fileName = [IO.Path]::GetFileName($PathValue)
      bytes = (Get-Item -LiteralPath $PathValue).Length
      sha256 = Get-Sha256 -PathValue $PathValue
      authenticode = Get-AuthenticodeInfo -PathValue $PathValue
    })
  }
}

function Copy-RequiredFile {
  param(
    [string]$Source,
    [string]$DestinationDir
  )
  if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) {
    throw "Missing required package document: $Source"
  }
  Copy-Item -LiteralPath $Source -Destination (Join-Path $DestinationDir ([IO.Path]::GetFileName($Source))) -Force
}

$repo = Get-Item -LiteralPath (Resolve-FullPath $WorktreePath)
Set-Location $repo.FullName

$tauriConfigPath = Join-Path $repo.FullName "src-tauri\tauri.conf.json"
if (-not (Test-Path -LiteralPath $tauriConfigPath -PathType Leaf)) {
  throw "Missing Tauri config: $tauriConfigPath"
}

$tauriConfig = Get-Content -LiteralPath $tauriConfigPath -Raw | ConvertFrom-Json
if (-not $Version) {
  $Version = [string]$tauriConfig.version
}
if (-not $Version) {
  throw "Version was not provided and src-tauri/tauri.conf.json did not contain a version."
}

$versionForName = $Version.Trim()
if ($versionForName.StartsWith("v")) {
  $versionForName = $versionForName.Substring(1)
}

if (-not $Stamp) {
  $Stamp = Get-Date -Format "yyyyMMdd"
}
$packageName = "HexHawk_Early_Access_UNSIGNED_v{0}_{1}" -f $versionForName, $Stamp
$zipPath = Join-Path $OutputDir ($packageName + ".zip")
$stagePath = Join-Path $OutputDir $packageName

$msiPath = Join-Path $repo.FullName ("target\release\bundle\msi\HexHawk_{0}_x64_en-US.msi" -f $Version)
$nsisPath = Join-Path $repo.FullName ("target\release\bundle\nsis\HexHawk_{0}_x64-setup.exe" -f $Version)
$nestCliPath = Join-Path $repo.FullName "target\release\nest_cli.exe"
$webView2Path = Join-Path $repo.FullName "target\release\WebView2Loader.dll"

$artifacts = [System.Collections.ArrayList]::new()
Add-Artifact -List $artifacts -Kind "msi" -PathValue $msiPath -Required $true
Add-Artifact -List $artifacts -Kind "nsis" -PathValue $nsisPath -Required $true
if ($IncludeNestCli) {
  Add-Artifact -List $artifacts -Kind "nest_cli" -PathValue $nestCliPath -Required $true
}
if ($IncludeWebView2Loader) {
  Add-Artifact -List $artifacts -Kind "webview2_loader" -PathValue $webView2Path -Required $true
}

if ($RequireNotSigned) {
  foreach ($artifact in $artifacts) {
    $status = [string]$artifact.authenticode.status
    if ($status -ne "NotSigned") {
      throw "Unsigned early-access channel requires Authenticode NotSigned, but [$($artifact.kind)] is [$status]: $($artifact.path)"
    }
  }
}

$head = (git rev-parse HEAD).Trim()
$shortHead = (git rev-parse --short HEAD).Trim()
$branch = (git rev-parse --abbrev-ref HEAD).Trim()
$statusLines = @(git status --short)
$status = ($statusLines -join [Environment]::NewLine).Trim()
$ciJson = $null
try {
  $ciJson = gh run list --branch main --limit 1 --json databaseId,status,conclusion,headSha,url | ConvertFrom-Json
} catch {
  $ciJson = $null
}

$manifest = [ordered]@{
  schema = "hexhawk.unsigned_early_access_package.v1"
  generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
  channel = "HexHawk Early Access - Unsigned Founder Build"
  package_name = $packageName
  package_zip = $zipPath
  version = $Version
  stamp = $Stamp
  repo = $repo.FullName
  branch = $branch
  commit = $head
  short_commit = $shortHead
  git_status_short = $status
  ci_latest_main = if ($ciJson -and $ciJson.Count -gt 0) { $ciJson[0] } else { $null }
  classification = "Unsigned early-access local package; not published."
  signed_release = $false
  microsoft_verified = $false
  public_world_ready = $false
  auto_update_enabled_by_package = $false
  require_not_signed = [bool]$RequireNotSigned
  artifacts = @($artifacts)
  docs = @(
    "UNSIGNED_EARLY_ACCESS_POLICY.md",
    "EARLY_ACCESS_INSTALL_README.md",
    "EARLY_ACCESS_BUYER_NOTE.md"
  )
  release_notes = "EARLY_ACCESS_RELEASE_NOTES.md"
  safety = [ordered]@{
    does_not_publish = $true
    does_not_upload = $true
    does_not_deploy = $true
    does_not_charge_money = $true
    uses_no_secrets = $true
    signs_nothing = $true
    modifies_no_updater_metadata = $true
    modifies_no_product_behavior = $true
    no_public_ready_claim = $true
    no_signed_claim = $true
    no_microsoft_verified_claim = $true
  }
  authority_boundaries = [ordered]@{
    gyre = "sole verdict/classification authority"
    nest = "evidence orchestration and convergence only"
    talon = "advisory decompiler/pseudocode reconstruction only"
    strike = "runtime/debugger evidence only"
    function_intelligence = "advisory evidence notebook only"
    aetherframe = "advancement/refinement/factory orchestration only"
    nexus_hermes_ai = "assistant/proposal/workflow helper only"
  }
}

if ($DryRun) {
  Write-Output "DRY RUN: validated expected artifacts and Authenticode status. No package directory or zip was created."
  Write-Output ($manifest | ConvertTo-Json -Depth 8)
  exit 0
}

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
if (Test-Path -LiteralPath $stagePath) {
  Remove-Item -LiteralPath $stagePath -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $stagePath | Out-Null

foreach ($artifact in $artifacts) {
  Copy-Item -LiteralPath $artifact.path -Destination (Join-Path $stagePath $artifact.fileName) -Force
}

Copy-RequiredFile -Source (Join-Path $repo.FullName "docs\UNSIGNED_EARLY_ACCESS_POLICY.md") -DestinationDir $stagePath
Copy-RequiredFile -Source (Join-Path $repo.FullName "docs\EARLY_ACCESS_INSTALL_README.md") -DestinationDir $stagePath
Copy-RequiredFile -Source (Join-Path $repo.FullName "docs\EARLY_ACCESS_BUYER_NOTE.md") -DestinationDir $stagePath

$templatePath = Join-Path $repo.FullName "docs\EARLY_ACCESS_RELEASE_NOTES_TEMPLATE.md"
if (-not (Test-Path -LiteralPath $templatePath -PathType Leaf)) {
  throw "Missing release notes template: $templatePath"
}
$ciRunText = if ($manifest.ci_latest_main) { ("{0} ({1}) {2}" -f $manifest.ci_latest_main.databaseId, $manifest.ci_latest_main.conclusion, $manifest.ci_latest_main.url) } else { "not captured" }
$notes = Get-Content -LiteralPath $templatePath -Raw
$notes = $notes.Replace("{{VERSION}}", $Version)
$notes = $notes.Replace("{{DATE}}", $Stamp)
$notes = $notes.Replace("{{BRANCH}}", $branch)
$notes = $notes.Replace("{{COMMIT}}", $head)
$notes = $notes.Replace("{{CI_RUN}}", $ciRunText)
Set-Content -LiteralPath (Join-Path $stagePath "EARLY_ACCESS_RELEASE_NOTES.md") -Value $notes -Encoding utf8

$sumLines = foreach ($artifact in $artifacts) {
  "{0}  {1}" -f $artifact.sha256, $artifact.fileName
}
Set-Content -LiteralPath (Join-Path $stagePath "SHA256SUMS.txt") -Value ($sumLines -join [Environment]::NewLine) -Encoding ascii

$contentLines = @()
$contentLines += "HexHawk Early Access - Unsigned Founder Build"
$contentLines += "Package: $packageName"
$contentLines += "Classification: unsigned early-access local package; not published"
$contentLines += ""
$contentLines += "Files:"
Get-ChildItem -LiteralPath $stagePath -File | Sort-Object Name | ForEach-Object {
  $contentLines += ("- {0} ({1} bytes)" -f $_.Name, $_.Length)
}
$contentLines += ""
$contentLines += "This package is not signed, not Microsoft verified, not public/world-ready, and not auto-updating."
Set-Content -LiteralPath (Join-Path $stagePath "PACKAGE_CONTENTS.txt") -Value ($contentLines -join [Environment]::NewLine) -Encoding utf8

$manifestPath = Join-Path $stagePath "EVIDENCE_MANIFEST.json"
($manifest | ConvertTo-Json -Depth 10) | Set-Content -LiteralPath $manifestPath -Encoding utf8

if (Test-Path -LiteralPath $zipPath) {
  Remove-Item -LiteralPath $zipPath -Force
}
Get-ChildItem -LiteralPath $stagePath | Compress-Archive -DestinationPath $zipPath -Force

$zipHash = Get-Sha256 -PathValue $zipPath
Write-Output "Created unsigned early-access package: $zipPath"
Write-Output "Package SHA256: $zipHash"
Write-Output "Stage directory: $stagePath"
Write-Output "Manifest: $manifestPath"
Write-Output "No upload, deployment, publishing, charging, signing, or updater metadata change was performed."
