param(
  [Parameter(Mandatory = $true)]
  [string]$MetadataUrl,
  [string]$ExpectedVersion,
  [string]$ExpectedPlatform = "windows-x86_64",
  [string]$ExpectedArtifactSha256,
  [string]$ExpectedSignatureSha256,
  [string]$TauriConfigPath = "src-tauri/tauri.conf.json",
  [string]$OutputPath,
  [switch]$AllowLocalFileAsset
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Add-Check {
  param(
    [System.Collections.ArrayList]$Checks,
    [string]$Name,
    [bool]$Ok,
    [object]$Detail = $null
  )
  [void]$Checks.Add([ordered]@{ name = $Name; ok = $Ok; detail = $Detail })
}

function Decode-Base64Text {
  param([string]$Value)
  try {
    return [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Value))
  } catch {
    return $null
  }
}

$checks = [System.Collections.ArrayList]::new()
$started = (Get-Date).ToUniversalTime().ToString("o")
$metadata = $null
$fetch = [ordered]@{ ok = $false; status = $null; bytes = $null; sha256 = $null; finalUrl = $MetadataUrl; error = $null }

try {
  if ($MetadataUrl.StartsWith("file:///")) {
    $localMetadataPath = [Uri]::UnescapeDataString(([Uri]$MetadataUrl).LocalPath)
    $content = Get-Content -LiteralPath $localMetadataPath -Raw
    $fetch.ok = $true
    $fetch.status = 200
    $fetch.bytes = [Text.Encoding]::UTF8.GetByteCount([string]$content)
    $fetch.sha256 = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes([string]$content))).Replace("-", "").ToLowerInvariant()
    $metadata = $content | ConvertFrom-Json
  } elseif (Test-Path -LiteralPath $MetadataUrl) {
    $content = Get-Content -LiteralPath $MetadataUrl -Raw
    $fetch.ok = $true
    $fetch.status = 200
    $fetch.bytes = [Text.Encoding]::UTF8.GetByteCount([string]$content)
    $fetch.sha256 = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes([string]$content))).Replace("-", "").ToLowerInvariant()
    $metadata = $content | ConvertFrom-Json
  } else {
    $response = Invoke-WebRequest -Uri $MetadataUrl -UseBasicParsing -TimeoutSec 30
    $fetch.ok = $true
    $fetch.status = [int]$response.StatusCode
    $fetch.bytes = [Text.Encoding]::UTF8.GetByteCount([string]$response.Content)
    $fetch.sha256 = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes([string]$response.Content))).Replace("-", "").ToLowerInvariant()
    $metadata = $response.Content | ConvertFrom-Json
  }
  Add-Check -Checks $checks -Name "metadata_fetch_ok" -Ok ($fetch.status -eq 200) -Detail $fetch
} catch {
  $fetch.error = $_.Exception.Message
  Add-Check -Checks $checks -Name "metadata_fetch_ok" -Ok $false -Detail $fetch
}

if ($metadata) {
  Add-Check -Checks $checks -Name "metadata_has_version" -Ok ([bool]$metadata.version) -Detail $metadata.version
  if ($ExpectedVersion) {
    Add-Check -Checks $checks -Name "metadata_version_matches_expected" -Ok ([string]$metadata.version -eq $ExpectedVersion) -Detail ([ordered]@{ expected = $ExpectedVersion; actual = [string]$metadata.version })
  }
  Add-Check -Checks $checks -Name "metadata_has_pub_date" -Ok ([bool]$metadata.pub_date) -Detail $metadata.pub_date
  Add-Check -Checks $checks -Name "metadata_has_platforms" -Ok ([bool]$metadata.platforms) -Detail $null

  $platform = if ($metadata.platforms) { $metadata.platforms.$ExpectedPlatform } else { $null }
  Add-Check -Checks $checks -Name "metadata_has_expected_platform" -Ok ([bool]$platform) -Detail $ExpectedPlatform
  Add-Check -Checks $checks -Name "platform_has_url" -Ok ([bool]($platform -and $platform.url)) -Detail $(if ($platform) { $platform.url } else { $null })
  Add-Check -Checks $checks -Name "platform_has_signature" -Ok ([bool]($platform -and $platform.signature)) -Detail $(if ($platform -and $platform.signature) { @{ len = ([string]$platform.signature).Length } } else { $null })

  $decodedSig = if ($platform -and $platform.signature) { Decode-Base64Text -Value ([string]$platform.signature) } else { $null }
  $sigProbe = [ordered]@{
    decodes = [bool]$decodedSig
    contains_tauri_comment = [bool]($decodedSig -and $decodedSig.Contains("signature from tauri secret key"))
    contains_trusted_comment = [bool]($decodedSig -and $decodedSig.Contains("trusted comment:"))
  }
  Add-Check -Checks $checks -Name "signature_decodes_as_tauri_payload" -Ok ($sigProbe.decodes -and $sigProbe.contains_tauri_comment -and $sigProbe.contains_trusted_comment) -Detail $sigProbe

  if ($ExpectedSignatureSha256 -and $platform -and $platform.signature) {
    $actualSignatureSha256 = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes([string]$platform.signature))).Replace("-", "").ToLowerInvariant()
    Add-Check -Checks $checks -Name "signature_sha256_matches_expected" -Ok ($actualSignatureSha256 -eq $ExpectedSignatureSha256.ToLowerInvariant()) -Detail ([ordered]@{ expected = $ExpectedSignatureSha256.ToLowerInvariant(); actual = $actualSignatureSha256 })
  }

  if ($ExpectedArtifactSha256 -and $metadata.PSObject.Properties.Name -contains "hexhawk_release_truth") {
    $actualArtifactSha256 = [string]$metadata.hexhawk_release_truth.artifact_sha256
    Add-Check -Checks $checks -Name "artifact_sha256_matches_expected" -Ok ($actualArtifactSha256.ToLowerInvariant() -eq $ExpectedArtifactSha256.ToLowerInvariant()) -Detail ([ordered]@{ expected = $ExpectedArtifactSha256.ToLowerInvariant(); actual = $actualArtifactSha256 })
  } elseif ($ExpectedArtifactSha256) {
    Add-Check -Checks $checks -Name "artifact_sha256_matches_expected" -Ok $false -Detail "metadata missing hexhawk_release_truth.artifact_sha256"
  }

  if (Test-Path -LiteralPath $TauriConfigPath) {
    $tauri = Get-Content -LiteralPath $TauriConfigPath -Raw | ConvertFrom-Json
    $configuredPubkey = [string]$tauri.plugins.updater.pubkey
    $pubkeyProbe = [ordered]@{
      configured_pubkey_present = [bool]$configuredPubkey
      sha256 = if ($configuredPubkey) { [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($configuredPubkey))).Replace("-", "").ToLowerInvariant() } else { $null }
    }
    Add-Check -Checks $checks -Name "configured_pubkey_present" -Ok $pubkeyProbe.configured_pubkey_present -Detail $pubkeyProbe
  } else {
    Add-Check -Checks $checks -Name "configured_pubkey_present" -Ok $false -Detail "missing tauri config: $TauriConfigPath"
  }

  if ($platform -and $platform.url) {
    $assetUrl = [string]$platform.url
    if ($assetUrl.StartsWith("file:") -or $assetUrl.StartsWith("/")) {
      Add-Check -Checks $checks -Name "platform_asset_url_fetchable" -Ok ([bool]$AllowLocalFileAsset) -Detail "local asset URL not fetched: $assetUrl"
    } else {
      try {
        $assetResponse = Invoke-WebRequest -Uri $assetUrl -UseBasicParsing -TimeoutSec 30 -Method Head
        Add-Check -Checks $checks -Name "platform_asset_url_fetchable" -Ok ($assetResponse.StatusCode -in @(200, 206)) -Detail ([ordered]@{
          status = [int]$assetResponse.StatusCode
          content_length = $assetResponse.Headers["Content-Length"]
          content_range = $assetResponse.Headers["Content-Range"]
          content_type = $assetResponse.Headers["Content-Type"]
        })
      } catch {
        try {
          $assetResponse = Invoke-WebRequest -Uri $assetUrl -UseBasicParsing -TimeoutSec 30
          Add-Check -Checks $checks -Name "platform_asset_url_fetchable" -Ok ($assetResponse.StatusCode -in @(200, 206)) -Detail ([ordered]@{
            status = [int]$assetResponse.StatusCode
            bytes = [Text.Encoding]::UTF8.GetByteCount([string]$assetResponse.Content)
            content_type = $assetResponse.Headers["Content-Type"]
          })
        } catch {
          Add-Check -Checks $checks -Name "platform_asset_url_fetchable" -Ok $false -Detail $_.Exception.Message
        }
      }
    }
  }
}

$allOk = @($checks | Where-Object { -not $_.ok }).Count -eq 0
$report = [ordered]@{
  schema = "hexhawk.updater_metadata_validation.v1"
  generated_at_utc = $started
  metadata_url = $MetadataUrl
  expected_version = $ExpectedVersion
  expected_platform = $ExpectedPlatform
  fetch = $fetch
  checks = $checks
  all_checks_ok = $allOk
}

if ($OutputPath) {
  $parent = Split-Path -Parent $OutputPath
  if ($parent) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
  ($report | ConvertTo-Json -Depth 8) | Set-Content -LiteralPath $OutputPath -Encoding ascii
}

$report | ConvertTo-Json -Depth 8
if (-not $allOk) { exit 1 }
