param(
  [Parameter(Mandatory = $true)]
  [string]$WebsiteRoot,
  [Parameter(Mandatory = $true)]
  [string]$ReleaseVersion,
  [Parameter(Mandatory = $true)]
  [string]$ReleaseFolderName,
  [Parameter(Mandatory = $true)]
  [string]$AssetRoot,
  [Parameter(Mandatory = $true)]
  [string]$TauriConfigPath,
  [string]$TrustSigningPrivateKeyPath = $env:HEXHAWK_TRUST_SIGNING_KEY_PATH,
  [string]$TrustSigningKeyId = $env:HEXHAWK_TRUST_SIGNING_KEY_ID
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Ensure-Directory {
  param([string]$Path)
  New-Item -ItemType Directory -Path $Path -Force | Out-Null
}

function ConvertTo-HashtableRecursive {
  param([Parameter(ValueFromPipeline = $true)]$InputObject)

  if ($null -eq $InputObject) {
    return $null
  }

  if ($InputObject -is [System.Collections.IDictionary]) {
    $hash = @{}
    foreach ($key in $InputObject.Keys) {
      $hash[$key] = ConvertTo-HashtableRecursive -InputObject $InputObject[$key]
    }
    return $hash
  }

  if ($InputObject -is [pscustomobject]) {
    $hash = @{}
    foreach ($prop in $InputObject.PSObject.Properties) {
      $hash[$prop.Name] = ConvertTo-HashtableRecursive -InputObject $prop.Value
    }
    return $hash
  }

  if ($InputObject -is [System.Array]) {
    $arr = @()
    foreach ($item in $InputObject) {
      $arr += ConvertTo-HashtableRecursive -InputObject $item
    }
    return ,$arr
  }

  return $InputObject
}

function Read-JsonOrDefault {
  param(
    [string]$Path,
    [hashtable]$Default
  )

  if (-not (Test-Path -LiteralPath $Path)) {
    return $Default
  }

  $obj = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
  return ConvertTo-HashtableRecursive -InputObject $obj
}

function Write-Json {
  param(
    [string]$Path,
    [hashtable]$Object
  )

  ($Object | ConvertTo-Json -Depth 10) | Set-Content -LiteralPath $Path -Encoding ascii
}

function Parse-MinisignKeyId {
  param([string]$MinisignText)

  $line = ($MinisignText -split "`n" | Select-Object -First 1).Trim()
  if ($line -match 'public key:\s*([A-Fa-f0-9]+)') {
    return $matches[1].ToUpperInvariant()
  }
  return $null
}

function Get-FileSha256 {
  param([string]$Path)
  return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Convert-ToPosixPath {
  param([string]$Path)
  return $Path.Replace('\\', '/')
}

function Ensure-Array {
  param([object]$Value)
  if ($null -eq $Value) { return @() }
  if ($Value -is [System.Array]) { return @($Value) }
  return @($Value)
}

$websiteRootFull = (Resolve-Path -LiteralPath $WebsiteRoot).Path
$assetRootFull = (Resolve-Path -LiteralPath $AssetRoot).Path

if (-not (Test-Path -LiteralPath $TauriConfigPath)) {
  throw "Missing Tauri config at '$TauriConfigPath'."
}

$tauriConfig = Get-Content -LiteralPath $TauriConfigPath -Raw | ConvertFrom-Json
$updaterPubKeyEncoded = [string]$tauriConfig.plugins.updater.pubkey
if (-not $updaterPubKeyEncoded) {
  throw "Tauri updater pubkey is missing; cannot refresh trust artifacts."
}

$updaterPubKeyText = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($updaterPubKeyEncoded))
$updaterKeyFingerprint = Parse-MinisignKeyId -MinisignText $updaterPubKeyText
if (-not $updaterKeyFingerprint) {
  throw "Could not parse updater minisign key fingerprint from tauri.conf.json pubkey."
}

$trustRoot = Join-Path $websiteRootFull "trust"
$keysDir = Join-Path $trustRoot "keys"
$signaturesRoot = Join-Path $trustRoot "signatures"
$signaturesVersionDir = Join-Path $signaturesRoot $ReleaseFolderName
$signaturesLatestDir = Join-Path $signaturesRoot "latest"
$wellKnownDir = Join-Path $websiteRootFull ".well-known"

Ensure-Directory -Path $trustRoot
Ensure-Directory -Path $keysDir
Ensure-Directory -Path $signaturesRoot
Ensure-Directory -Path $signaturesVersionDir
Ensure-Directory -Path $signaturesLatestDir
Ensure-Directory -Path $wellKnownDir

$keysJsonPath = Join-Path $trustRoot "keys.json"
$revocationsJsonPath = Join-Path $trustRoot "revocations.json"
$keyRotationsJsonPath = Join-Path $trustRoot "key-rotations.json"
$signedTimestampsJsonPath = Join-Path $trustRoot "signed-timestamps.json"
$discoveryJsonPath = Join-Path $wellKnownDir "hexhawk-trust.json"

$keysDoc = Read-JsonOrDefault -Path $keysJsonPath -Default @{
  schema = "hexhawk.trust.keys.v1"
  version = $ReleaseVersion
  generated_at = (Get-Date).ToUniversalTime().ToString("o")
  keys = @()
}
$keysDoc.keys = Ensure-Array -Value $keysDoc.keys

$revocationsDoc = Read-JsonOrDefault -Path $revocationsJsonPath -Default @{
  schema = "hexhawk.trust.revocations.v1"
  version = $ReleaseVersion
  generated_at = (Get-Date).ToUniversalTime().ToString("o")
  revocations = @()
  release_blocks = @()
}
$revocationsDoc.revocations = Ensure-Array -Value $revocationsDoc.revocations
$revocationsDoc.release_blocks = Ensure-Array -Value $revocationsDoc.release_blocks

$nowIso = (Get-Date).ToUniversalTime().ToString("o")

$updaterKey = $keysDoc.keys | Where-Object {
  $_.metadata -and $_.metadata.tauri_updater_key_id -eq $updaterKeyFingerprint
} | Select-Object -First 1

if (-not $updaterKey) {
  $updaterKeyId = "HXK-UPDATER-" + (Get-Date -Format "yyyy-MM")
  $updaterKey = [ordered]@{
    key_id = $updaterKeyId
    purpose = "updater-metadata"
    algorithm = "ed25519-minisign"
    status = "active"
    activated_at = $nowIso
    public_key_url = "/trust/keys/$updaterKeyId.minisign.pub"
    metadata = [ordered]@{ tauri_updater_key_id = $updaterKeyFingerprint }
  }
  $keysDoc.keys += $updaterKey
} else {
  $updaterKey.status = "active"
  if (-not $updaterKey.activated_at) { $updaterKey.activated_at = $nowIso }
}

$updaterPubFileName = [System.IO.Path]::GetFileName([string]$updaterKey.public_key_url)
$updaterPubFilePath = Join-Path $keysDir $updaterPubFileName
$updaterPubKeyText.TrimEnd() | Set-Content -LiteralPath $updaterPubFilePath -Encoding ascii

$signingRecords = @()
$hasOpenSsl = $null -ne (Get-Command openssl -ErrorAction SilentlyContinue)

if (-not $TrustSigningPrivateKeyPath) {
  $TrustSigningPrivateKeyPath = Join-Path $PSScriptRoot ".generated\trust_signing_private.pem"
}

if ((-not (Test-Path -LiteralPath $TrustSigningPrivateKeyPath)) -and $hasOpenSsl) {
  Ensure-Directory -Path (Split-Path -Parent $TrustSigningPrivateKeyPath)
  & openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out $TrustSigningPrivateKeyPath | Out-Null
}

if (-not $TrustSigningKeyId) {
  $TrustSigningKeyId = "HXK-REPORT-" + (Get-Date -Format "yyyy-MM")
}

if ($hasOpenSsl -and (Test-Path -LiteralPath $TrustSigningPrivateKeyPath)) {
  $publicKeyFileName = "$TrustSigningKeyId.pem"
  $publicKeyFilePath = Join-Path $keysDir $publicKeyFileName
  & openssl pkey -in $TrustSigningPrivateKeyPath -pubout -out $publicKeyFilePath | Out-Null
  $trustSigningFingerprint = (& openssl pkey -pubin -in $publicKeyFilePath -outform DER | openssl dgst -sha256) -replace '^SHA2-256\(stdin\)=\s*', ''

  $signingKey = $keysDoc.keys | Where-Object { $_.key_id -eq $TrustSigningKeyId } | Select-Object -First 1
  if (-not $signingKey) {
    $signingKey = [ordered]@{
      key_id = $TrustSigningKeyId
      purpose = "release-artifact-signatures"
      algorithm = "rsa-2048-sha256"
      status = "active"
      activated_at = $nowIso
      public_key_url = "/trust/keys/$publicKeyFileName"
      fingerprint_sha256 = $trustSigningFingerprint.Trim().ToLowerInvariant()
    }
    $keysDoc.keys += $signingKey
  } else {
    $signingKey.status = "active"
    $signingKey.public_key_url = "/trust/keys/$publicKeyFileName"
    $signingKey.fingerprint_sha256 = $trustSigningFingerprint.Trim().ToLowerInvariant()
  }

  Get-ChildItem -LiteralPath $signaturesLatestDir -File | Remove-Item -Force
  $assetFiles = Get-ChildItem -LiteralPath $assetRootFull -File
  foreach ($asset in $assetFiles) {
    $sigName = "$($asset.Name).sig"
    $sigPathVersion = Join-Path $signaturesVersionDir $sigName
    $sigPathLatest = Join-Path $signaturesLatestDir $sigName

    & openssl dgst -sha256 -sign $TrustSigningPrivateKeyPath -out $sigPathVersion $asset.FullName | Out-Null
    Copy-Item -LiteralPath $sigPathVersion -Destination $sigPathLatest -Force

    $record = [ordered]@{
      artifact = $asset.Name
      artifact_sha256 = Get-FileSha256 -Path $asset.FullName
      signature_url = "/trust/signatures/$ReleaseFolderName/$sigName"
      latest_signature_url = "/trust/signatures/latest/$sigName"
      signed_at = $nowIso
      key_id = $TrustSigningKeyId
      algorithm = "rsa-2048-sha256"
    }
    $signingRecords += $record
  }

  $checksumsPath = Join-Path (Split-Path -Parent $assetRootFull) "SHA256SUMS.txt"
  if (Test-Path -LiteralPath $checksumsPath) {
    $checksumsSigName = "SHA256SUMS.txt.sig"
    $checksumsSigVersion = Join-Path $signaturesVersionDir $checksumsSigName
    $checksumsSigLatest = Join-Path $signaturesLatestDir $checksumsSigName

    & openssl dgst -sha256 -sign $TrustSigningPrivateKeyPath -out $checksumsSigVersion $checksumsPath | Out-Null
    Copy-Item -LiteralPath $checksumsSigVersion -Destination $checksumsSigLatest -Force

    $signingRecords += [ordered]@{
      artifact = "SHA256SUMS.txt"
      artifact_sha256 = Get-FileSha256 -Path $checksumsPath
      signature_url = "/trust/signatures/$ReleaseFolderName/$checksumsSigName"
      latest_signature_url = "/trust/signatures/latest/$checksumsSigName"
      signed_at = $nowIso
      key_id = $TrustSigningKeyId
      algorithm = "rsa-2048-sha256"
    }
  }
}

$signatureManifest = [ordered]@{
  schema = "hexhawk.trust.signatures.v1"
  version = $ReleaseVersion
  generated_at = $nowIso
  release = $ReleaseFolderName
  signatures = $signingRecords
}

Write-Json -Path (Join-Path $signaturesVersionDir "signatures.json") -Object $signatureManifest
Write-Json -Path (Join-Path $signaturesLatestDir "signatures.json") -Object $signatureManifest

$keysDoc.version = $ReleaseVersion
$keysDoc.generated_at = $nowIso
Write-Json -Path $keysJsonPath -Object $keysDoc

$revocationsDoc.version = $ReleaseVersion
$revocationsDoc.generated_at = $nowIso
Write-Json -Path $revocationsJsonPath -Object $revocationsDoc

$activeByPurpose = @{}
foreach ($k in $keysDoc.keys) {
  if ($k.status -eq "active" -and $k.purpose) {
    $activeByPurpose[$k.purpose] = $k.key_id
  }
}

$keyRotations = @()
foreach ($rev in $revocationsDoc.revocations) {
  $purpose = switch ([string]$rev.scope) {
    "updater-metadata" { "updater-metadata"; break }
    "report-signatures" { "release-artifact-signatures"; break }
    "plugin-signatures" { "plugin-signatures"; break }
    default { [string]$rev.scope }
  }

  $keyRotations += [ordered]@{
    rotated_at = $rev.revoked_at
    retired_key_id = $rev.key_id
    replacement_key_id = if ($activeByPurpose.ContainsKey($purpose)) { $activeByPurpose[$purpose] } else { $null }
    scope = $rev.scope
    reason = $rev.reason
  }
}

$keyRotationsDoc = [ordered]@{
  schema = "hexhawk.trust.key_rotations.v1"
  version = $ReleaseVersion
  generated_at = $nowIso
  history = $keyRotations
}
Write-Json -Path $keyRotationsJsonPath -Object $keyRotationsDoc

$signedTimestampsDoc = [ordered]@{
  schema = "hexhawk.trust.signed_timestamps.v1"
  version = $ReleaseVersion
  generated_at = $nowIso
  records = $signingRecords
}
Write-Json -Path $signedTimestampsJsonPath -Object $signedTimestampsDoc

$discoveryDoc = [ordered]@{
  schema = "hexhawk.trust.discovery.v1"
  last_refreshed_at = $nowIso
  keys_endpoint = "/trust/keys.json"
  revocations_endpoint = "/trust/revocations.json"
  signatures_endpoint = "/trust/signatures/latest/signatures.json"
  signed_timestamps_endpoint = "/trust/signed-timestamps.json"
  key_rotation_history_endpoint = "/trust/key-rotations.json"
  checksums_endpoint = "/downloads/checksums.txt"
  trust_center = "/trust-center"
  verify_tool = "/verify-file"
  signed_timestamps = $signingRecords | Select-Object -First 10
  key_rotation_history = $keyRotations | Select-Object -First 10
}
Write-Json -Path $discoveryJsonPath -Object $discoveryDoc

Write-Output "Trust artifacts refreshed."
Write-Output "Keys endpoint: /trust/keys.json"
Write-Output "Revocations endpoint: /trust/revocations.json"
Write-Output "Signatures endpoint: /trust/signatures/latest/signatures.json"
