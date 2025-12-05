# Simple Bulk Download - Pull entire directories and filter locally
# This is more reliable than trying to filter on-device

param(
    [string]$OutputDir = "F:\repo\zerosms\analysis\device_binaries_full"
)

Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "  Bulk Device Binary Extraction" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host ""

# Check ADB
$adbDevices = adb devices 2>&1 | Select-String "device$"
if (-not $adbDevices) {
    Write-Host "[!] ERROR: No ADB device connected!" -ForegroundColor Red
    exit 1
}
Write-Host "[+] ADB device connected" -ForegroundColor Green

# Create output directory
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

# Directories to download
$directories = @(
    "/usr/bin",
    "/usr/sbin",
    "/bin",
    "/sbin",
    "/usr/lib",
    "/lib",
    "/usr/libexec"
)

Write-Host "`n[*] Downloading directories from device..." -ForegroundColor Yellow
Write-Host "    This will download ALL files, then filter for ELF binaries locally" -ForegroundColor Gray
Write-Host ""

$dirCount = 0
foreach ($dir in $directories) {
    $dirCount++
    Write-Host "[$dirCount/$($directories.Count)] Pulling: $dir" -ForegroundColor Cyan
    
    $localDir = Join-Path $OutputDir $dir.TrimStart('/')
    
    # Pull entire directory
    adb pull "$dir" "$localDir" 2>&1 | Out-Null
    
    if (Test-Path $localDir) {
        $fileCount = (Get-ChildItem -Path $localDir -Recurse -File | Measure-Object).Count
        Write-Host "    [+] Downloaded ($fileCount files)" -ForegroundColor Green
    } else {
        Write-Host "    [!] Failed or directory doesn't exist" -ForegroundColor Yellow
    }
}

# Now filter for ELF binaries locally
Write-Host "`n[*] Scanning downloaded files for ELF binaries..." -ForegroundColor Yellow

$allFiles = Get-ChildItem -Path $OutputDir -Recurse -File
$elfFiles = @()
$checked = 0

foreach ($file in $allFiles) {
    $checked++
    if ($checked % 100 -eq 0) {
        Write-Host "    Checked $checked/$($allFiles.Count) files..." -ForegroundColor Gray
    }
    
    try {
        $bytes = [System.IO.File]::ReadAllBytes($file.FullName)
        # Check for ELF magic: 0x7F 'E' 'L' 'F'
        if ($bytes.Length -gt 4 -and $bytes[0] -eq 0x7F -and $bytes[1] -eq 0x45 -and $bytes[2] -eq 0x4C -and $bytes[3] -eq 0x46) {
            $elfFiles += $file
        }
    }
    catch {
        # Ignore read errors
    }
}

Write-Host "[+] Found $($elfFiles.Count) ELF binaries" -ForegroundColor Green

# Create separate directory for ELF-only files
$elfOnlyDir = Join-Path $OutputDir "_ELF_BINARIES_ONLY"
if (-not (Test-Path $elfOnlyDir)) {
    New-Item -ItemType Directory -Path $elfOnlyDir -Force | Out-Null
}

# Copy ELF files to separate directory while preserving structure
Write-Host "`n[*] Copying ELF binaries to separate directory..." -ForegroundColor Yellow

foreach ($elf in $elfFiles) {
    $relativePath = $elf.FullName.Substring($OutputDir.Length + 1)
    $destFile = Join-Path $elfOnlyDir $relativePath
    $destDir = Split-Path $destFile -Parent
    
    if (-not (Test-Path $destDir)) {
        New-Item -ItemType Directory -Path $destDir -Force | Out-Null
    }
    
    try {
        Copy-Item -LiteralPath $elf.FullName -Destination $destFile -Force
    }
    catch {
        # Skip files with problematic names
    }
}

# Create manifest
$manifestFile = Join-Path $elfOnlyDir "MANIFEST.txt"
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

$totalSize = ($elfFiles | Measure-Object -Property Length -Sum).Sum
$manifestContent = @"
MiFi 8800L Full Binary Extraction
==================================
Date: $timestamp
Device: MiFi 8800L (SDx20ALP-1.22.11)
Total Files Downloaded: $($allFiles.Count)
Total ELF Binaries: $($elfFiles.Count)
Total ELF Size: $([Math]::Round($totalSize / 1MB, 2)) MB

Directories Downloaded:
$(($directories | ForEach-Object { "  - $_" }) -join "`n")

ELF Binaries by Size:
=====================

"@

# Sort by size and add to manifest
$sortedElf = $elfFiles | Sort-Object Length -Descending

foreach ($elf in $sortedElf) {
    $relativePath = $elf.FullName.Substring($OutputDir.Length + 1)
    $sizeMB = [Math]::Round($elf.Length / 1MB, 3)
    $sizeKB = [Math]::Round($elf.Length / 1KB, 2)
    $manifestContent += "`n$relativePath - $sizeKB KB"
}

$manifestContent | Out-File -FilePath $manifestFile -Encoding UTF8

# Summary
Write-Host "`n=====================================" -ForegroundColor Cyan
Write-Host "  Extraction Complete" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "Total files downloaded: $($allFiles.Count)" -ForegroundColor White
Write-Host "ELF binaries found: $($elfFiles.Count)" -ForegroundColor Green
Write-Host "Total ELF size: $([Math]::Round($totalSize / 1MB, 2)) MB" -ForegroundColor White
Write-Host ""
Write-Host "Output locations:" -ForegroundColor Cyan
Write-Host "  All files: $OutputDir" -ForegroundColor Gray
Write-Host "  ELF only: $elfOnlyDir" -ForegroundColor Gray
Write-Host "  Manifest: $manifestFile" -ForegroundColor Gray
Write-Host ""
Write-Host "[*] Largest binaries:" -ForegroundColor Yellow
$sortedElf | Select-Object -First 10 | ForEach-Object {
    $sizeMB = [Math]::Round($_.Length / 1MB, 3)
    Write-Host "    $($_.Name) - $sizeMB MB" -ForegroundColor White
}
Write-Host ""
