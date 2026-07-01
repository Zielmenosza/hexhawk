param(
    [string]$ProjectRoot = 'D:\Project',
    [string]$RepoRoot = 'D:\Project\HexHawk',
    [string]$OutDir = 'D:\Project\HexHawk\docs\aetherframe-runs'
)

$ErrorActionPreference = 'Stop'

function Get-DirectorySizeBytes {
    param([string]$Path)
    $sum = (Get-ChildItem -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum
    if ($null -eq $sum) { return 0 }
    return [int64]$sum
}

function Test-GitWorktreePath {
    param([string]$Path, [string[]]$WorktreePaths)
    $full = [System.IO.Path]::GetFullPath($Path).TrimEnd('\')
    foreach ($wt in $WorktreePaths) {
        if ([System.IO.Path]::GetFullPath($wt).TrimEnd('\') -ieq $full) { return $true }
    }
    return $false
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$outFile = Join-Path $OutDir "workspace-cleanup-plan-$stamp.md"

$worktreeRaw = git -C $RepoRoot worktree list 2>$null
$worktreePaths = @()
foreach ($line in $worktreeRaw) {
    if ($line.Trim()) { $worktreePaths += (($line -split '\s+')[0]) }
}

$candidates = Get-ChildItem -LiteralPath $ProjectRoot -Directory -Force | Where-Object {
    $_.Name -match 'HexHawk.*(smoke|release-candidate|rc|probe|ai-overhaul|gate)' -or
    $_.Name -match 'smoke|release-candidate|probe'
}

$rows = @()
foreach ($dir in $candidates) {
    $size = Get-DirectorySizeBytes -Path $dir.FullName
    $isWorktree = Test-GitWorktreePath -Path $dir.FullName -WorktreePaths $worktreePaths
    $hasDotGit = Test-Path -LiteralPath (Join-Path $dir.FullName '.git')
    $gitStatus = 'not a git worktree'
    if ($isWorktree -or $hasDotGit) {
        try {
            $statusText = git -C $dir.FullName status --short 2>$null
            if ($statusText) { $gitStatus = 'dirty' } else { $gitStatus = 'clean' }
        } catch {
            $gitStatus = 'status check failed'
        }
    }

    $files = Get-ChildItem -LiteralPath $dir.FullName -Recurse -Force -File -ErrorAction SilentlyContinue
    $evidence = $files | Where-Object { $_.Name -in @('installer-smoke-result.json','probe-result.json','function-notebook-export.json','EVIDENCE_MANIFEST.json','SHA256SUMS.txt') } | Select-Object -First 12
    $artifacts = $files | Where-Object { $_.Name -like '*.msi' -or $_.Name -like '*setup.exe' -or $_.Name -like '*.zip' } | Select-Object -First 12

    $recommendation = if ($isWorktree -and $gitStatus -eq 'dirty') {
        'do not touch - registered dirty git worktree'
    } elseif ($isWorktree) {
        'review then git worktree remove only after approval'
    } elseif ($evidence.Count -gt 0 -or $artifacts.Count -gt 0) {
        'summarize/preserve evidence, then delete only after approval'
    } else {
        'safe delete candidate after explicit approval'
    }

    $rows += [pscustomobject]@{
        Name = $dir.Name
        FullName = $dir.FullName
        SizeGB = [math]::Round(($size / 1GB), 2)
        LastWriteTime = $dir.LastWriteTime
        GitWorktree = $isWorktree
        GitStatus = $gitStatus
        EvidenceExamples = (($evidence | ForEach-Object { $_.FullName.Substring($dir.FullName.Length).TrimStart('\') }) -join '; ')
        ArtifactExamples = (($artifacts | ForEach-Object { $_.FullName.Substring($dir.FullName.Length).TrimStart('\') }) -join '; ')
        Recommendation = $recommendation
    }
}

$rows = $rows | Sort-Object SizeGB -Descending

$md = @()
$md += '# HexHawk Workspace Cleanup Dry-Run Plan'
$md += ''
$md += "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
$md += ''
$md += 'This is a dry-run report only. No folders were deleted, moved, compressed, uploaded, or unregistered as git worktrees.'
$md += ''
$md += '## Candidates'
$md += ''
$md += '| Path | Size GB | Last modified | Git worktree | Git status | Recommendation |'
$md += '|---|---:|---|---|---|---|'
foreach ($r in $rows) {
    $md += "| ``$($r.FullName)`` | $($r.SizeGB) | $($r.LastWriteTime) | $($r.GitWorktree) | $($r.GitStatus) | $($r.Recommendation) |"
}
$md += ''
$md += '## Evidence/artifact examples'
foreach ($r in $rows) {
    $md += ''
    $md += "### $($r.Name)"
    $evidenceText = if ($r.EvidenceExamples) { $r.EvidenceExamples } else { "(none)" }
    $artifactText = if ($r.ArtifactExamples) { $r.ArtifactExamples } else { "(none)" }
    $md += "- Evidence: $evidenceText"
    $md += "- Artifacts: $artifactText"
}
$md += ''
$md += '## Explicit non-actions'
$md += ''
$md += '- No Remove-Item.'
$md += '- No git worktree remove.'
$md += '- No compression.'
$md += '- No move.'
$md += '- No upload.'
$md += '- No credentials.'

$md -join "`r`n" | Set-Content -LiteralPath $outFile -Encoding UTF8
Write-Output "Cleanup dry-run report written: $outFile"
Write-Output "Candidate count: $($rows.Count)"
Write-Output "Total candidate GB: $([math]::Round((($rows | Measure-Object SizeGB -Sum).Sum),2))"
