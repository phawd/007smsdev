# Complete Device Binary Download - Recursive from /
# Prioritizes /opt as requested, then covers entire filesystem

param(
    [string]$OutputDir = "F:\repo\zerosms\analysis\complete_device_dump",
    [switch]$OptOnly = $false
)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  COMPLETE DEVICE DUMP" -ForegroundColor Cyan
Write-Host "  MiFi 8800L Full Filesystem" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
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

# Define directories to download (in priority order)
$directories = @(
    "/opt",           # PRIORITY - User requested focus
    "/usr/bin",
    "/usr/sbin", 
    "/usr/lib",
    "/usr/libexec",
    "/usr/local",
    "/bin",
    "/sbin",
    "/lib",
    "/system/bin",
    "/system/lib",
    "/system/lib64",
    "/system/xbin",
    "/vendor/bin",
    "/vendor/lib",
    "/vendor/lib64",
    "/data/bin",
    "/data/lib",
    "/firmware",
    "/root",
    "/home"
)

if ($OptOnly) {
    $directories = @("/opt")
    Write-Host "[*] OPT-ONLY MODE: Downloading /opt only" -ForegroundColor Yellow
}

Write-Host "[*] Directory download plan:" -ForegroundColor Cyan
for ($i = 0; $i -lt $directories.Count; $i++) {
    Write-Host "    [$($i+1)] $($directories[$i])" -ForegroundColor Gray
}
Write-Host ""

# Check which directories actually exist
Write-Host "[*] Checking which directories exist on device..." -ForegroundColor Yellow
$existingDirs = @()
foreach ($dir in $directories) {
    $exists = adb shell "[ -d '$dir' ] && echo 'YES'" 2>$null
    if ($exists -match "YES") {
        $existingDirs += $dir
        Write-Host "    [+] $dir exists" -ForegroundColor Green
    } else {
        Write-Host "    [-] $dir not found" -ForegroundColor DarkGray
    }
}

Write-Host "`n[+] Found $($existingDirs.Count) directories to download" -ForegroundColor Green
Write-Host ""

# Download each directory
$downloadLog = Join-Path $OutputDir "download_log.txt"
"MiFi 8800L Complete Device Dump Log`n" + "=" * 50 + "`nStart: $(Get-Date)`n" | Out-File -FilePath $downloadLog -Encoding UTF8

$totalDirs = $existingDirs.Count
$dirNum = 0

foreach ($dir in $existingDirs) {
    $dirNum++
    $percentComplete = [Math]::Round(($dirNum / $totalDirs) * 100, 1)
    
    Write-Host "[$dirNum/$totalDirs] ($percentComplete%) Pulling: $dir" -ForegroundColor Cyan
    $startTime = Get-Date
    
    $localDir = Join-Path $OutputDir $dir.TrimStart('/')
    
    # Use adb pull with error handling
    $pullOutput = adb pull "$dir" "$localDir" 2>&1 | Out-String
    
    $endTime = Get-Date
    $duration = ($endTime - $startTime).TotalSeconds
    
    if (Test-Path $localDir) {
        $fileCount = (Get-ChildItem -Path $localDir -Recurse -File -ErrorAction SilentlyContinue | Measure-Object).Count
        $dirSize = (Get-ChildItem -Path $localDir -Recurse -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
        $sizeMB = [Math]::Round($dirSize / 1MB, 2)
        
        Write-Host "    [+] Downloaded: $fileCount files ($sizeMB MB) in $([Math]::Round($duration, 1))s" -ForegroundColor Green
        
        "$dir -> Downloaded $fileCount files ($sizeMB MB) in $([Math]::Round($duration, 1))s" | Out-File -FilePath $downloadLog -Append -Encoding UTF8
    } else {
        Write-Host "    [!] Failed or empty directory" -ForegroundColor Yellow
        "$dir -> FAILED or EMPTY" | Out-File -FilePath $downloadLog -Append -Encoding UTF8
    }
}

Write-Host "`n[*] Scanning for ELF binaries..." -ForegroundColor Yellow

$allFiles = Get-ChildItem -Path $OutputDir -Recurse -File -ErrorAction SilentlyContinue
Write-Host "    Total files downloaded: $($allFiles.Count)" -ForegroundColor Gray

$elfFiles = @()
$checked = 0

foreach ($file in $allFiles) {
    $checked++
    if ($checked % 200 -eq 0) {
        Write-Host "    Scanned $checked/$($allFiles.Count) files..." -ForegroundColor Gray
    }
    
    try {
        $bytes = [System.IO.File]::ReadAllBytes($file.FullName)
        if ($bytes.Length -gt 4 -and $bytes[0] -eq 0x7F -and $bytes[1] -eq 0x45 -and $bytes[2] -eq 0x4C -and $bytes[3] -eq 0x46) {
            $elfFiles += $file
        }
    }
    catch {
        # Skip unreadable files
    }
}

Write-Host "[+] Found $($elfFiles.Count) ELF binaries" -ForegroundColor Green

# Create ELF-only directory
$elfDir = Join-Path $OutputDir "_ALL_ELF_BINARIES"
if (-not (Test-Path $elfDir)) {
    New-Item -ItemType Directory -Path $elfDir -Force | Out-Null
}

Write-Host "`n[*] Copying ELF binaries to analysis directory..." -ForegroundColor Yellow

foreach ($elf in $elfFiles) {
    $relativePath = $elf.FullName.Substring($OutputDir.Length).TrimStart('\')
    $destFile = Join-Path $elfDir $relativePath
    $destDir = Split-Path $destFile -Parent
    
    if (-not (Test-Path $destDir)) {
        New-Item -ItemType Directory -Path $destDir -Force | Out-Null
    }
    
    try {
        Copy-Item -LiteralPath $elf.FullName -Destination $destFile -Force -ErrorAction SilentlyContinue
    }
    catch {
        # Skip problematic filenames
    }
}

# Create comprehensive manifest
$manifestFile = Join-Path $elfDir "DEVICE_MANIFEST.txt"
$totalSize = ($elfFiles | Measure-Object -Property Length -Sum).Sum
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

$manifestContent = @"
MiFi 8800L Complete Device Binary Manifest
==========================================
Extraction Date: $timestamp
Device: MiFi 8800L (SDx20ALP-1.22.11)
Firmware: SDx20ALP-1.22.11

Statistics:
-----------
Total Files Downloaded: $($allFiles.Count)
Total ELF Binaries Found: $($elfFiles.Count)
Total ELF Size: $([Math]::Round($totalSize / 1MB, 2)) MB

Directories Downloaded:
-----------------------
"@

foreach ($dir in $existingDirs) {
    $localDir = Join-Path $OutputDir $dir.TrimStart('/')
    if (Test-Path $localDir) {
        $dirFiles = (Get-ChildItem -Path $localDir -Recurse -File -ErrorAction SilentlyContinue | Measure-Object).Count
        $manifestContent += "`n$dir -> $dirFiles files"
    }
}

$manifestContent += "`n`nELF Binaries (sorted by size):`n" + ("=" * 50) + "`n"

# Sort ELF files by size
$sortedElf = $elfFiles | Sort-Object Length -Descending

foreach ($elf in $sortedElf) {
    $relativePath = $elf.FullName.Substring($OutputDir.Length).TrimStart('\')
    $sizeKB = [Math]::Round($elf.Length / 1KB, 2)
    $manifestContent += "`n$relativePath - $sizeKB KB"
}

$manifestContent | Out-File -FilePath $manifestFile -Encoding UTF8

# Final summary
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  DOWNLOAD COMPLETE" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Statistics:" -ForegroundColor Cyan
Write-Host "  Total files: $($allFiles.Count)" -ForegroundColor White
Write-Host "  ELF binaries: $($elfFiles.Count)" -ForegroundColor Green
Write-Host "  Total size: $([Math]::Round($totalSize / 1MB, 2)) MB" -ForegroundColor White
Write-Host ""
Write-Host "Output:" -ForegroundColor Cyan
Write-Host "  Complete dump: $OutputDir" -ForegroundColor Gray
Write-Host "  ELF binaries: $elfDir" -ForegroundColor Gray
Write-Host "  Manifest: $manifestFile" -ForegroundColor Gray
Write-Host "  Download log: $downloadLog" -ForegroundColor Gray
Write-Host ""
Write-Host "[*] Top 15 largest binaries:" -ForegroundColor Yellow
$sortedElf | Select-Object -First 15 | ForEach-Object {
    Write-Host "    $($_.Name) - $([Math]::Round($_.Length / 1MB, 3)) MB" -ForegroundColor White
}
Write-Host ""
Write-Host "[+] Ready for Rizin/Cutter and Ghidra analysis!" -ForegroundColor Green
Write-Host ""
