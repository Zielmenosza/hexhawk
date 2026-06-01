param(
  [Parameter(Mandatory = $true)]
  [string]$ArtifactPath,
  [string]$CertThumbprint = $env:HEXHAWK_CODESIGN_THUMBPRINT,
  [string]$PfxPath = $env:HEXHAWK_CODESIGN_PFX_PATH,
  [string]$PfxPassword = $env:HEXHAWK_CODESIGN_PFX_PASSWORD,
  [string]$TimestampServer = "http://timestamp.digicert.com",
  [switch]$SkipTimestamp
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Resolve-CodeSigningCert {
  param([string]$Thumbprint)
  if (-not $Thumbprint) {
    return $null
  }

  $normalized = $Thumbprint.Replace(" ", "").ToUpperInvariant()
  $cert = Get-ChildItem "Cert:\CurrentUser\My" -CodeSigningCert -ErrorAction SilentlyContinue |
    Where-Object { $_.Thumbprint.ToUpperInvariant() -eq $normalized } |
    Select-Object -First 1

  if (-not $cert) {
    $cert = Get-ChildItem "Cert:\LocalMachine\My" -CodeSigningCert -ErrorAction SilentlyContinue |
      Where-Object { $_.Thumbprint.ToUpperInvariant() -eq $normalized } |
      Select-Object -First 1
  }

  return $cert
}

$resolvedArtifact = Resolve-Path -LiteralPath $ArtifactPath -ErrorAction Stop
$signtool = Get-Command signtool -ErrorAction SilentlyContinue

if ($signtool) {
  $args = @("sign", "/fd", "SHA256")

  if (-not $SkipTimestamp -and $TimestampServer) {
    $args += @("/tr", $TimestampServer, "/td", "SHA256")
  }

  if ($PfxPath) {
    $resolvedPfx = Resolve-Path -LiteralPath $PfxPath -ErrorAction Stop
    $args += @("/f", $resolvedPfx.Path)
    if ($PfxPassword) {
      $args += @("/p", $PfxPassword)
    }
  } elseif ($CertThumbprint) {
    $args += @("/sha1", $CertThumbprint)
  } else {
    throw "No signing identity configured. Set HEXHAWK_CODESIGN_THUMBPRINT or HEXHAWK_CODESIGN_PFX_PATH."
  }

  $args += $resolvedArtifact.Path
  & $signtool.Source @args
  if ($LASTEXITCODE -ne 0) {
    throw "signtool failed for '$($resolvedArtifact.Path)' (exit code: $LASTEXITCODE)."
  }
} else {
  $cert = $null
  if ($PfxPath) {
    $resolvedPfx = Resolve-Path -LiteralPath $PfxPath -ErrorAction Stop
    $securePassword = if ($PfxPassword) {
      ConvertTo-SecureString -String $PfxPassword -AsPlainText -Force
    } else {
      $null
    }

    $cert = if ($securePassword) {
      Get-PfxCertificate -FilePath $resolvedPfx.Path -Password $securePassword
    } else {
      Get-PfxCertificate -FilePath $resolvedPfx.Path
    }
  } else {
    $cert = Resolve-CodeSigningCert -Thumbprint $CertThumbprint
  }

  if (-not $cert) {
    throw "signtool is unavailable and no usable code-signing certificate was found."
  }

  $signatureParams = @{
    FilePath = $resolvedArtifact.Path
    Certificate = $cert
    HashAlgorithm = "SHA256"
  }

  if (-not $SkipTimestamp -and $TimestampServer) {
    $signatureParams.TimestampServer = $TimestampServer
  }

  $signature = Set-AuthenticodeSignature @signatureParams
  $allowUntrusted = $env:HEXHAWK_ALLOW_UNTRUSTED_DEV_SIGNATURE -eq "1"
  $isExpectedDevStatus = $allowUntrusted -and $signature.SignerCertificate -and $signature.Status -in @("UnknownError", "NotTrusted")
  if ($signature.Status -ne "Valid" -and -not $isExpectedDevStatus) {
    throw "Set-AuthenticodeSignature did not produce an accepted signature for '$($resolvedArtifact.Path)': $($signature.Status) - $($signature.StatusMessage)"
  }
}

Get-AuthenticodeSignature -FilePath $resolvedArtifact.Path | Select-Object `
  @{ Name = "Path"; Expression = { $resolvedArtifact.Path } },
  Status,
  StatusMessage,
  @{ Name = "SignerSubject"; Expression = { if ($_.SignerCertificate) { $_.SignerCertificate.Subject } else { $null } } },
  @{ Name = "SignerThumbprint"; Expression = { if ($_.SignerCertificate) { $_.SignerCertificate.Thumbprint } else { $null } } },
  @{ Name = "TimestampSubject"; Expression = { if ($_.TimeStamperCertificate) { $_.TimeStamperCertificate.Subject } else { $null } } } |
  ConvertTo-Json -Depth 4
