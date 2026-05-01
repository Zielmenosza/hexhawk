param(
  [string]$Version,
  [string]$WebsiteRoot = ".\website",
  [string]$BundleRoot = ".\target\release\bundle",
  [string]$GitHubOwner = "Zielmenosza",
  [string]$GitHubRepo = "hexhawk",
  [switch]$UseLocalReleaseFiles
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
}

if ($PSBoundParameters.ContainsKey('Version') -and $Version) {
  $params.Version = $Version
}

if ($UseLocalReleaseFiles) {
  $params.UseLocalReleaseFiles = $true
}

& $scriptPath @params
