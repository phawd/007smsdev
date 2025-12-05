# Download All Binaries and Libraries from MiFi 8800L Device
# This script recursively finds and downloads all ELF binaries and shared libraries

param(
    [string]$OutputDir = "F:\repo\zerosms\analysis\device_binaries_full",
    [switch]$DryRun = $false
)

Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "  MiFi Device Binary Extraction" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host ""

# Check ADB connectivity
Write-Host "[*] Checking ADB connection..." -ForegroundColor Yellow
$adbDevices = adb devices 2>&1 | Select-String "device$"
if (-not $adbDevices) {
    Write-Host "[!] ERROR: No ADB device connected!" -ForegroundColor Red
    exit 1
}
Write-Host "[+] ADB device connected" -ForegroundColor Green
Write-Host ""

# Create output directory structure
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    Write-Host "[+] Created output directory: $OutputDir" -ForegroundColor Green
}

# Create manifest file
$manifestFile = Join-Path $OutputDir "MANIFEST.txt"
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
@"
MiFi 8800L Binary Extraction Manifest
========================================
Extraction Date: $timestamp
Device: MiFi 8800L (SDx20ALP-1.22.11)
Output Directory: $OutputDir

"@ | Out-File -FilePath $manifestFile -Encoding UTF8

Write-Host "[*] Finding all ELF binaries and shared libraries on device..." -ForegroundColor Yellow
Write-Host "    (This may take several minutes...)" -ForegroundColor Gray

# Find all ELF files on device
# We'll search common directories first, then expand
$searchPaths = @(
    "/usr/bin",
    "/usr/sbin",
    "/bin",
    "/sbin",
    "/usr/lib",
    "/lib",
    "/system/bin",
    "/system/lib",
    "/system/xbin",
    "/vendor/bin",
    "/vendor/lib",
    "/data/bin",
    "/data/lib"
)

$allFiles = @()
$fileCount = 0

foreach ($path in $searchPaths) {
    Write-Host "`n[*] Scanning: $path" -ForegroundColor Cyan
    
    # Check if path exists on device
    $pathExists = adb shell "[ -d '$path' ] && echo 'exists'" 2>$null
    if ($pathExists -notmatch "exists") {
        Write-Host "    [!] Path not found, skipping" -ForegroundColor DarkGray
        continue
    }
    
    # Find all files (not just ELF, we'll filter later)
    $files = adb shell "find '$path' -type f 2>/dev/null" 2>$null
    if ($files) {
        $fileList = $files -split "`n" | Where-Object { $_ -match '\S' }
        $count = ($fileList | Measure-Object).Count
        Write-Host "    [+] Found $count files" -ForegroundColor Green
        $allFiles += $fileList
        $fileCount += $count
    }
}

Write-Host "`n[+] Total files found: $fileCount" -ForegroundColor Green
Write-Host "[*] Filtering for ELF binaries and shared libraries..." -ForegroundColor Yellow

# Function to check if file is ELF
function Test-IsELF {
    param([string]$FilePath)
    
    # Read first 4 bytes from device
    $header = adb shell "od -An -tx1 -N4 '$FilePath' 2>/dev/null" 2>$null
    if ($header -match "7f\s+45\s+4c\s+46") {
        return $true
    }
    return $false
}

# Function to get file size
function Get-DeviceFileSize {
    param([string]$FilePath)
    
    $size = adb shell "stat -c%s '$FilePath' 2>/dev/null" 2>$null | Out-String
    $size = $size.Trim()
    if ($size -match '^\d+$') {
        return [int64]$size
    }
    return 0
}

# Process files in batches
$elfFiles = @()
$processed = 0
$batchSize = 50

Write-Host "[*] Processing files in batches of $batchSize..." -ForegroundColor Yellow

for ($i = 0; $i -lt $allFiles.Count; $i += $batchSize) {
    $batch = $allFiles[$i..([Math]::Min($i + $batchSize - 1, $allFiles.Count - 1))]
    
    foreach ($file in $batch) {
        $processed++
        $percentComplete = [Math]::Round(($processed / $fileCount) * 100, 1)
        
        if ($processed % 100 -eq 0) {
            Write-Host "    Progress: $processed/$fileCount ($percentComplete%)" -ForegroundColor Gray
        }
        
        # Check if ELF
        if (Test-IsELF -FilePath $file) {
            $size = Get-DeviceFileSize -FilePath $file
            $elfFiles += [PSCustomObject]@{
                Path = $file
                Size = $size
            }
        }
    }
}

Write-Host "`n[+] Found $($elfFiles.Count) ELF binaries/libraries" -ForegroundColor Green

# Sort by size (largest first) for better progress visibility
$elfFiles = $elfFiles | Sort-Object -Property Size -Descending

# Display summary
Write-Host "`n[*] Binary Summary:" -ForegroundColor Cyan
$totalSize = ($elfFiles | Measure-Object -Property Size -Sum).Sum
$totalSizeMB = [Math]::Round($totalSize / 1MB, 2)
Write-Host "    Total binaries: $($elfFiles.Count)" -ForegroundColor White
Write-Host "    Total size: $totalSizeMB MB" -ForegroundColor White

# Save manifest
"`nELF Binaries Found: $($elfFiles.Count)" | Out-File -FilePath $manifestFile -Append -Encoding UTF8
"Total Size: $totalSizeMB MB`n" | Out-File -FilePath $manifestFile -Append -Encoding UTF8
"Files:" | Out-File -FilePath $manifestFile -Append -Encoding UTF8

foreach ($elf in $elfFiles) {
    $sizeMB = [Math]::Round($elf.Size / 1MB, 3)
    "$($elf.Path) ($sizeMB MB)" | Out-File -FilePath $manifestFile -Append -Encoding UTF8
}

if ($DryRun) {
    Write-Host "`n[*] DRY RUN MODE - No files downloaded" -ForegroundColor Yellow
    Write-Host "[*] Manifest saved to: $manifestFile" -ForegroundColor Cyan
    exit 0
}

# Download all ELF files
Write-Host "`n[*] Downloading binaries..." -ForegroundColor Yellow
$downloadCount = 0
$failedCount = 0
$downloadedSize = 0

foreach ($elf in $elfFiles) {
    $downloadCount++
    $percentComplete = [Math]::Round(($downloadCount / $elfFiles.Count) * 100, 1)
    
    # Create local directory structure
    $localPath = $elf.Path.TrimStart('/')
    $localFile = Join-Path $OutputDir $localPath
    $localDir = Split-Path $localFile -Parent
    
    if (-not (Test-Path $localDir)) {
        New-Item -ItemType Directory -Path $localDir -Force | Out-Null
    }
    
    # Download file
    $sizeMB = [Math]::Round($elf.Size / 1MB, 3)
    Write-Host "[$downloadCount/$($elfFiles.Count)] ($percentComplete%) $($elf.Path) ($sizeMB MB)" -ForegroundColor Cyan
    
    $result = adb pull "$($elf.Path)" "$localFile" 2>&1
    
    if (Test-Path $localFile) {
        $downloadedSize += $elf.Size
        Write-Host "    [+] Downloaded successfully" -ForegroundColor Green
    } else {
        $failedCount++
        Write-Host "    [!] Failed to download" -ForegroundColor Red
        "FAILED: $($elf.Path)" | Out-File -FilePath $manifestFile -Append -Encoding UTF8
    }
}

# Final summary
Write-Host "`n=====================================" -ForegroundColor Cyan
Write-Host "  Extraction Complete" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "Downloaded: $($elfFiles.Count - $failedCount)/$($elfFiles.Count) binaries" -ForegroundColor Green
Write-Host "Failed: $failedCount" -ForegroundColor $(if ($failedCount -gt 0) { "Yellow" } else { "Green" })
Write-Host "Total size: $([Math]::Round($downloadedSize / 1MB, 2)) MB" -ForegroundColor White
Write-Host "Output directory: $OutputDir" -ForegroundColor Cyan
Write-Host "Manifest: $manifestFile" -ForegroundColor Cyan
Write-Host ""
