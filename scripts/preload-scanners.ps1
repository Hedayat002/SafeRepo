# ==============================================================================
# SafeRepo Phase 09 — Scanner Image Pre-Caching Script (PowerShell)
#
# Preloads and verifies the pinned container images required by SafeRepo's
# multi-scanner analysis pipeline:
#   1. semgrep/semgrep:1.100.0 (SAST)
#   2. aquasec/trivy:0.59.1    (SCA / Vulnerabilities)
#   3. zricethezav/gitleaks:v8.24.0 (Secret Detection)
#
# Safety Invariants:
# - Read-only metadata inspection (NO scanner containers executed)
# - Exact pinned semantic version tags ONLY (no :latest, :edge, etc.)
# - Zero host filesystem or socket mounts
# - Zero repository scans or code execution
# ==============================================================================

[CmdletBinding()]
param(
    [switch]$ForcePull = $false
)

$ErrorActionPreference = 'Stop'

# Pinned scanner image registry references
$ScannerImages = @(
    "semgrep/semgrep:1.100.0",
    "aquasec/trivy:0.59.1",
    "zricethezav/gitleaks:v8.24.0"
)

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host " SafeRepo Phase 09 Scanner Image Pre-Caching (PowerShell)" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan

# 1. Verify Docker CLI availability
$dockerCmd = Get-Command docker -ErrorAction SilentlyContinue
if (-not $dockerCmd) {
    Write-Error "[FAIL] Docker CLI is not installed or not in PATH."
    exit 1
}
$dockerVer = (& docker --version).Trim()
Write-Host "[OK] Docker CLI detected: $dockerVer" -ForegroundColor Green

# 2. Verify Docker daemon responsiveness
try {
    $null = & docker info 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Docker daemon not responsive"
    }
    Write-Host "[OK] Docker daemon is reachable." -ForegroundColor Green
}
catch {
    Write-Error "[FAIL] Docker daemon is not running or unreachable."
    exit 1
}

Write-Host ""

$passedCount = 0
$failedCount = 0

foreach ($image in $ScannerImages) {
    Write-Host "────────────────────────────────────────────────────────────────" -ForegroundColor Gray
    Write-Host "Target Scanner: $image" -ForegroundColor Yellow

    # Check if image already cached locally
    $imageExists = $false
    try {
        $null = & docker image inspect $image 2>&1
        if ($LASTEXITCODE -eq 0) {
            $imageExists = $true
        }
    }
    catch {
        $imageExists = $false
    }

    if ($imageExists -and (-not $ForcePull)) {
        Write-Host "  [INFO] Image already present in local Docker cache." -ForegroundColor Gray
    }
    else {
        Write-Host "  [PULL] Pulling exact pinned tag..." -ForegroundColor Cyan
        & docker pull $image
        if ($LASTEXITCODE -ne 0) {
            Write-Host "  [FAIL] Failed to pull $image" -ForegroundColor Red
            $failedCount++
            continue
        }
    }

    # Read-only metadata inspection (safe dry-run without container execution)
    $inspectJson = & docker image inspect $image 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  [FAIL] Metadata inspection failed for $image" -ForegroundColor Red
        $failedCount++
        continue
    }

    try {
        $parsed = ($inspectJson | Out-String | ConvertFrom-Json)[0]
        $imageId = $parsed.Id
        $architecture = $parsed.Architecture
        $os = $parsed.Os
        $sizeMB = [math]::Round($parsed.Size / 1MB, 2)
        $repoTags = $parsed.RepoTags

        # Verify exact tag presence in RepoTags
        if ($repoTags -notcontains $image) {
            Write-Host "  [FAIL] RepoTags metadata does not contain exact reference: $image" -ForegroundColor Red
            $failedCount++
            continue
        }

        Write-Host "  [PASS] Verified: $image" -ForegroundColor Green
        Write-Host "         Digest:       $imageId" -ForegroundColor Gray
        Write-Host "         Architecture: $os/$architecture" -ForegroundColor Gray
        Write-Host "         Size:         $sizeMB MB" -ForegroundColor Gray
        $passedCount++
    }
    catch {
        Write-Host "  [FAIL] Could not parse metadata for $($image): $_" -ForegroundColor Red
        $failedCount++
    }
}

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host " SUMMARY: $passedCount/$($ScannerImages.Count) PASSED | $failedCount FAILED" -ForegroundColor $(if ($failedCount -eq 0) { "Green" } else { "Red" })
Write-Host "================================================================" -ForegroundColor Cyan

if ($failedCount -gt 0) {
    Write-Error "[FAIL] One or more scanner images failed validation."
    exit 1
}

Write-Host "[SUCCESS] All scanner images preloaded and verified successfully." -ForegroundColor Green
exit 0
