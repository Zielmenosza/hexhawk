param(
  [string]$Version,
  [string]$WebsiteRoot = ".\site-build",
  [string]$BundleRoot = ".\target\release\bundle",
  [string]$GitHubOwner = "Zielmenosza",
  [string]$GitHubRepo = "hexhawk",
  [switch]$UseLocalReleaseFiles,
  [string]$TrustSigningPrivateKeyPath = $env:HEXHAWK_TRUST_SIGNING_KEY_PATH,
  [string]$TrustSigningKeyId = $env:HEXHAWK_TRUST_SIGNING_KEY_ID
)

$scriptPath = Join-Path $PSScriptRoot "website\tools\prepare-release.ps1"
if (-not (Test-Path -LiteralPath $scriptPath)) {
  throw "Could not find release script at '$scriptPath'."
}

$params = @{
  WebsiteRoot = $WebsiteRoot
  BundleRoot = $BundleRoot
  GitHubOwner = $GitHubOwner
  GitHubRepo = $GitHubRepo
  TrustSigningPrivateKeyPath = $TrustSigningPrivateKeyPath
  TrustSigningKeyId = $TrustSigningKeyId
}

if ($PSBoundParameters.ContainsKey('Version') -and $Version) {
  $params.Version = $Version
}

if ($UseLocalReleaseFiles) {
  $params.UseLocalReleaseFiles = $true
}

& $scriptPath @params
