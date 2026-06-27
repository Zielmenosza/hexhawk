param(
  [Parameter(Mandatory=$true)][string]$Worktree,
  [string]$OutRoot,
  [int]$WindowTimeoutSeconds = 30
)

$ErrorActionPreference = 'Stop'

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
if (-not $OutRoot) {
  $OutRoot = "D:\Project\HexHawk-smoke-$stamp"
}
$root = $OutRoot
$msiExtract = Join-Path $root 'msi-admin'
$nsisInstall = Join-Path $root 'nsis-install'
New-Item -ItemType Directory -Force -Path $root,$msiExtract,$nsisInstall | Out-Null

$msi = Join-Path $Worktree 'target\release\bundle\msi\HexHawk_1.0.0_x64_en-US.msi'
$nsis = Join-Path $Worktree 'target\release\bundle\nsis\HexHawk_1.0.0_x64-setup.exe'
$releaseExe = Join-Path $Worktree 'target\release\hexhawk-backend.exe'
$releaseCli = Join-Path $Worktree 'target\release\nest_cli.exe'

$result = [ordered]@{
  schema = 'hexhawk.installer_smoke.v2'
  generated_at = (Get-Date).ToUniversalTime().ToString('o')
  stamp = $stamp
  root = $root
  worktree = $Worktree
  msi = $msi
  nsis = $nsis
  steps = @()
}

function Add-Step($name, $ok, $detail) {
  $script:result.steps += [ordered]@{ name=$name; ok=[bool]$ok; detail=$detail }
}

function Find-One($base, $name) {
  Get-ChildItem -Path $base -Recurse -Filter $name -File -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName
}

function Get-Sha256($path) {
  if (-not (Test-Path -LiteralPath $path)) { return $null }
  (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash.ToLowerInvariant()
}

function Add-Hash-Step($paths) {
  $items = @()
  foreach ($p in $paths) {
    $items += [ordered]@{ path=$p; exists=(Test-Path -LiteralPath $p); sha256=(Get-Sha256 $p) }
  }
  Add-Step 'artifact sha256' (($items | Where-Object { -not $_.exists }).Count -eq 0) @{ artifacts=$items }
}

function Add-Authenticode-Step($paths) {
  $items = @()
  foreach ($sig in Get-AuthenticodeSignature -FilePath $paths) {
    $items += [ordered]@{ path=$sig.Path; status=$sig.Status.ToString(); statusCode=[int]$sig.Status; signer=$sig.SignerCertificate.Subject }
  }
  Add-Step 'artifact authenticode' $true @{ signatures=$items }
}

Add-Type -AssemblyName System.Drawing
Add-Type @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public class HexHawkSmokeWin32 {
  public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr hWnd);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassName(IntPtr hWnd, StringBuilder lpClassName, int nMaxCount);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hWnd, out RECT rect);
  [DllImport("user32.dll")] public static extern IntPtr GetWindowLongPtr(IntPtr hWnd, int nIndex);
  [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr hwnd, IntPtr hdcBlt, uint nFlags);
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left; public int Top; public int Right; public int Bottom; }
}
'@ -ErrorAction SilentlyContinue

function Get-WindowsForPid([int]$TargetPid) {
  $items = New-Object System.Collections.ArrayList
  $callback = [HexHawkSmokeWin32+EnumWindowsProc]{ param([IntPtr]$hwnd, [IntPtr]$lparam)
    $windowPid = [uint32]0
    [void][HexHawkSmokeWin32]::GetWindowThreadProcessId($hwnd, [ref]$windowPid)
    if ($windowPid -eq [uint32]$TargetPid) {
      $titleSb = New-Object System.Text.StringBuilder 512
      [void][HexHawkSmokeWin32]::GetWindowText($hwnd, $titleSb, $titleSb.Capacity)
      $classSb = New-Object System.Text.StringBuilder 256
      [void][HexHawkSmokeWin32]::GetClassName($hwnd, $classSb, $classSb.Capacity)
      $rect = New-Object HexHawkSmokeWin32+RECT
      [void][HexHawkSmokeWin32]::GetWindowRect($hwnd, [ref]$rect)
      $style = [HexHawkSmokeWin32]::GetWindowLongPtr($hwnd, -16).ToInt64()
      $exstyle = [HexHawkSmokeWin32]::GetWindowLongPtr($hwnd, -20).ToInt64()
      [void]$items.Add([ordered]@{
        hwnd=$hwnd.ToInt64()
        visible=[HexHawkSmokeWin32]::IsWindowVisible($hwnd)
        title=$titleSb.ToString()
        class=$classSb.ToString()
        rect=[ordered]@{ left=$rect.Left; top=$rect.Top; right=$rect.Right; bottom=$rect.Bottom; width=($rect.Right-$rect.Left); height=($rect.Bottom-$rect.Top) }
        style=('0x{0:X}' -f $style)
        exstyle=('0x{0:X}' -f $exstyle)
      })
    }
    return $true
  }
  [void][HexHawkSmokeWin32]::EnumWindows($callback, [IntPtr]::Zero)
  return @($items)
}

function Capture-Window($hwnd, $path) {
  $rect = New-Object HexHawkSmokeWin32+RECT
  [void][HexHawkSmokeWin32]::GetWindowRect([IntPtr]$hwnd, [ref]$rect)
  $width = [Math]::Max(1, $rect.Right - $rect.Left)
  $height = [Math]::Max(1, $rect.Bottom - $rect.Top)
  $bitmap = New-Object System.Drawing.Bitmap $width, $height
  $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
  $hdc = $graphics.GetHdc()
  try { [void][HexHawkSmokeWin32]::PrintWindow([IntPtr]$hwnd, $hdc, 2) } finally { $graphics.ReleaseHdc($hdc); $graphics.Dispose() }
  $bitmap.Save($path, [System.Drawing.Imaging.ImageFormat]::Png)
  $bitmap.Dispose()
}

function Stop-SmokeHexHawkProcesses {
  Get-Process hexhawk-backend -ErrorAction SilentlyContinue |
    Where-Object { $_.Path -and $_.Path -like 'D:\Project\HexHawk-smoke-*' } |
    ForEach-Object { try { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue } catch {} }
  Start-Sleep -Milliseconds 750
}

function Launch-Probe($exe, $label, $port) {
  Stop-SmokeHexHawkProcesses
  $shot = Join-Path $root "$label.png"
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $exe
  $psi.WorkingDirectory = Split-Path $exe -Parent
  $psi.UseShellExecute = $false
  $psi.EnvironmentVariables['WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS'] = "--remote-debugging-port=$port --remote-allow-origins=*"
  $proc = [System.Diagnostics.Process]::Start($psi)
  $snapshots = @()
  $selected = $null
  $deadline = (Get-Date).AddSeconds($WindowTimeoutSeconds)
  while ((Get-Date) -lt $deadline) {
    Start-Sleep -Milliseconds 500
    $p = Get-Process -Id $proc.Id -ErrorAction SilentlyContinue
    if (-not $p) { break }
    $p.Refresh()
    $windows = @(Get-WindowsForPid $proc.Id)
    $candidate = $windows |
      Where-Object { $_.visible -and $_.title -like '*HexHawk*' -and $_.rect.width -ge 300 -and $_.rect.height -ge 300 -and $_.class -like '*Tauri*' } |
      Sort-Object @{Expression={$_.rect.width * $_.rect.height};Descending=$true} |
      Select-Object -First 1
    $snapshots += [ordered]@{ t=(Get-Date).ToString('o'); responding=$p.Responding; mainWindowHandle=$p.MainWindowHandle.ToInt64(); mainWindowTitle=$p.MainWindowTitle; windows=$windows }
    if ($candidate) { $selected = $candidate; break }
  }
  $alive = $null -ne (Get-Process -Id $proc.Id -ErrorAction SilentlyContinue)
  $responding = $false
  if ($alive) { $p = Get-Process -Id $proc.Id; $p.Refresh(); $responding = $p.Responding }
  $children = @()
  try { $children = @(Get-CimInstance Win32_Process | Where-Object { $_.ParentProcessId -eq $proc.Id } | Select-Object ProcessId,Name,CommandLine) } catch {}
  if ($selected) {
    try { Capture-Window $selected.hwnd $shot } catch { Add-Step "$label screenshot" $false $_.Exception.Message }
  }
  $ok = $alive -and $responding -and $null -ne $selected
  Add-Step "$label gui launch" $ok ([ordered]@{ pid=$proc.Id; alive=$alive; responding=$responding; selectedWindow=$selected; screenshot=$shot; port=$port; exe=$exe; cwd=(Split-Path $exe -Parent); snapshots=$snapshots; children=$children })
  if ($alive) { try { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue } catch {} }
  Start-Sleep -Seconds 1
  return @{ processId=$proc.Id; screenshot=$shot; port=$port; exe=$exe; ok=$ok; selectedWindow=$selected }
}

function Run-Cli($name, $exe, $cliArgs, $expectedExit, $stdoutPattern, $stderrPattern, [bool]$allowStdout, [bool]$allowStderr) {
  $safe = ($name -replace '[^A-Za-z0-9_-]', '-')
  $stdoutPath = Join-Path $root "$safe-stdout.txt"
  $stderrPath = Join-Path $root "$safe-stderr.txt"
  if ($cliArgs -and $cliArgs.Count -gt 0) {
    $p = Start-Process -FilePath $exe -ArgumentList $cliArgs -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath -Wait -PassThru
  } else {
    $p = Start-Process -FilePath $exe -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath -Wait -PassThru
  }
  $stdout = if (Test-Path $stdoutPath) { Get-Content $stdoutPath -Raw } else { '' }
  $stderr = if (Test-Path $stderrPath) { Get-Content $stderrPath -Raw } else { '' }
  $ok = $p.ExitCode -eq $expectedExit
  if ($stdoutPattern) { $ok = $ok -and (($stdout -match $stdoutPattern) -or ($stderr -match $stdoutPattern)) }
  if ($stderrPattern) { $ok = $ok -and (($stderr -match $stderrPattern) -or ($stdout -match $stderrPattern)) }
  if (-not $allowStdout) { $ok = $ok -and ([string]::IsNullOrWhiteSpace($stdout)) }
  if (-not $allowStderr) { $ok = $ok -and ([string]::IsNullOrWhiteSpace($stderr)) }
  Add-Step $name $ok ([ordered]@{ exitCode=$p.ExitCode; stdout=$stdoutPath; stderr=$stderrPath; args=$cliArgs })
}

Add-Hash-Step @($releaseExe,$releaseCli,$msi,$nsis)
Add-Authenticode-Step @($releaseExe,$releaseCli,$msi,$nsis)

$p = Start-Process -FilePath 'msiexec.exe' -ArgumentList @('/a', $msi, '/qn', "TARGETDIR=$msiExtract") -Wait -PassThru
Add-Step 'MSI admin extract' ($p.ExitCode -eq 0) @{ exitCode=$p.ExitCode; target=$msiExtract }
$msiExe = Find-One $msiExtract 'hexhawk-backend.exe'
$msiCli = Find-One $msiExtract 'nest_cli.exe'
$msiDll = Find-One $msiExtract 'WebView2Loader.dll'
Add-Step 'MSI payload files' ($msiExe -and $msiCli -and $msiDll) @{ backend=$msiExe; cli=$msiCli; webview2=$msiDll; webview2Sha256=(Get-Sha256 $msiDll) }

$p = Start-Process -FilePath $nsis -ArgumentList @('/S', "/D=$nsisInstall") -Wait -PassThru
Add-Step 'NSIS silent install' ($p.ExitCode -eq 0) @{ exitCode=$p.ExitCode; target=$nsisInstall }
$nsisExe = Find-One $nsisInstall 'hexhawk-backend.exe'
$nsisCli = Find-One $nsisInstall 'nest_cli.exe'
$nsisDll = Find-One $nsisInstall 'WebView2Loader.dll'
$uninstaller = Find-One $nsisInstall 'uninstall.exe'
Add-Step 'NSIS payload files' ($nsisExe -and $nsisCli -and $nsisDll -and $uninstaller) @{ backend=$nsisExe; cli=$nsisCli; webview2=$nsisDll; uninstall=$uninstaller; webview2Sha256=(Get-Sha256 $nsisDll) }

if ($msiExe) { $result.msiProbe = Launch-Probe $msiExe 'msi-gui' 9224 }
if ($nsisExe) { $result.nsisProbe = Launch-Probe $nsisExe 'nsis-gui' 9223 }

Run-Cli 'release nest_cli --help' $releaseCli @('--help') 0 'Usage:' $null $true $true
Run-Cli 'release nest_cli -h' $releaseCli @('-h') 0 'Usage:' $null $true $true
Run-Cli 'release nest_cli no args' $releaseCli @() 2 $null 'Usage:' $false $true

$reportJson = Join-Path $root 'headless-report.json'
$p = Start-Process -FilePath $releaseCli -ArgumentList @('strike','--headless',$releaseCli,'--out',$reportJson) -RedirectStandardOutput (Join-Path $root 'headless-stdout.txt') -RedirectStandardError (Join-Path $root 'headless-stderr.txt') -Wait -PassThru
$headlessOk = $false
$headlessDetail = [ordered]@{ exitCode=$p.ExitCode; report=$reportJson }
if ($p.ExitCode -eq 0 -and (Test-Path $reportJson)) {
  try {
    $j = Get-Content $reportJson -Raw | ConvertFrom-Json
    $top = ($j | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name)
    $headlessOk = $null -ne $j.file.sha256 -and $null -ne $j.verdict -and $null -ne $j.imports -and $null -ne $j.generated_at -and ($top -notcontains 'classification')
    $headlessDetail.keys = $top
    $headlessDetail.fileSha256 = $j.file.sha256
  } catch { $headlessDetail.error = $_.Exception.Message }
}
Add-Step 'headless batch smoke' $headlessOk $headlessDetail

if ($uninstaller) {
  $p = Start-Process -FilePath $uninstaller -ArgumentList @('/S') -Wait -PassThru
  Add-Step 'NSIS silent uninstall' ($p.ExitCode -eq 0) @{ exitCode=$p.ExitCode; uninstall=$uninstaller }
}

Stop-SmokeHexHawkProcesses
$result.paths = [ordered]@{ msiExtract=$msiExtract; nsisInstall=$nsisInstall; msiExe=$msiExe; nsisExe=$nsisExe; releaseCli=$releaseCli }
$outPath = Join-Path $root 'installer-smoke-result.json'
$result.all_ok = (($result.steps | Where-Object { -not $_.ok }).Count -eq 0)
$result | ConvertTo-Json -Depth 24 | Set-Content -Path $outPath -Encoding UTF8
Write-Output $outPath
