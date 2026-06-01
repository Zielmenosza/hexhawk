param(
  [Parameter(Mandatory = $true)]
  [string]$MsiPath,
  [string]$SamplePath = "D:/Project/HexHawk/Challenges/ch76/keygenme.exe",
  [string]$ProbeScript = "scripts/native_gui_parity_probe.py",
  [string]$OutputPath,
  [int]$RemoteDebugPort = 9223,
  [int]$BootTimeoutSeconds = 90
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Wait-ForCdp {
  param(
    [int]$Port,
    [int]$TimeoutSec
  )

  $deadline = (Get-Date).AddSeconds($TimeoutSec)
  while ((Get-Date) -lt $deadline) {
    try {
      $resp = Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:$Port/json/list" -TimeoutSec 2
      if ($resp.StatusCode -eq 200) {
        return $true
      }
    } catch {
      Start-Sleep -Milliseconds 500
    }
  }

  return $false
}

$resolvedMsi = (Resolve-Path -LiteralPath $MsiPath -ErrorAction Stop).Path
$resolvedProbe = (Resolve-Path -LiteralPath $ProbeScript -ErrorAction Stop).Path

if (-not $OutputPath) {
  $OutputPath = "D:/Project/HexHawk/gui-evidence/release_hardening_native_gui_probe_$(Get-Date -Format 'yyyy-MM-dd_HHmmss').json"
}

$extractRoot = Join-Path $env:TEMP ("hexhawk_msi_extract_" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $extractRoot -Force | Out-Null

try {
  $msiArgs = @("/a", $resolvedMsi, "/qn", "TARGETDIR=$extractRoot")
  $msiProc = Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -Wait -PassThru
  if ($msiProc.ExitCode -ne 0) {
    throw "msiexec extraction failed with exit code $($msiProc.ExitCode)."
  }

  $appExe = Get-ChildItem -Path $extractRoot -Recurse -Filter "hexhawk-backend.exe" | Select-Object -First 1
  if (-not $appExe) {
    throw "Could not find hexhawk-backend.exe in extracted MSI payload."
  }

  $startInfo = New-Object System.Diagnostics.ProcessStartInfo
  $startInfo.FileName = $appExe.FullName
  $startInfo.WorkingDirectory = $appExe.DirectoryName
  $startInfo.UseShellExecute = $false
  $startInfo.EnvironmentVariables["WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS"] = "--remote-debugging-port=$RemoteDebugPort"

  $appProc = New-Object System.Diagnostics.Process
  $appProc.StartInfo = $startInfo
  [void]$appProc.Start()

  if (-not (Wait-ForCdp -Port $RemoteDebugPort -TimeoutSec $BootTimeoutSeconds)) {
    throw "Timed out waiting for WebView2 CDP endpoint on port $RemoteDebugPort."
  }

  $venvPython = Join-Path (Resolve-Path -LiteralPath ".").Path ".venv/Scripts/python.exe"
  $pythonCommand = if (Test-Path -LiteralPath $venvPython) {
    $venvPython
  } elseif (Get-Command py -ErrorAction SilentlyContinue) {
    "py"
  } elseif (Get-Command python -ErrorAction SilentlyContinue) {
    "python"
  } else {
    $null
  }
  if (-not $pythonCommand) {
    throw "Python launcher was not found (expected 'py' or 'python')."
  }

  $probeArgs = @($resolvedProbe, "--output", $OutputPath, "--sample", $SamplePath, "--port", "$RemoteDebugPort")
  $probeProc = Start-Process -FilePath $pythonCommand -ArgumentList $probeArgs -Wait -PassThru -NoNewWindow
  if ($probeProc.ExitCode -ne 0) {
    throw "native_gui_parity_probe.py failed with exit code $($probeProc.ExitCode)."
  }

  Write-Output "Native parity probe written: $OutputPath"
} finally {
  Get-Process | Where-Object { $_.ProcessName -eq "hexhawk-backend" } | ForEach-Object {
    try { $_.Kill() } catch {}
  }
}
