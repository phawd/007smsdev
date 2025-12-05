# Fast Binary Download - Uses single find command to locate all ELF files

param(
    [string]$OutputDir = "F:\repo\zerosms\analysis\device_binaries_full"
)

Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "  Fast MiFi Binary Extraction" -ForegroundColor Cyan
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

Write-Host "[*] Finding all ELF binaries on device (this may take 2-3 minutes)..." -ForegroundColor Yellow

# Use file command on device to find ELF files
# This is much faster than checking each file individually
$findCommand = @'
find /usr/bin /usr/sbin /bin /sbin /usr/lib /lib /usr/local 2>/dev/null | while read f; do
    if [ -f "$f" ]; then
        # Check if file starts with ELF magic bytes (7f 45 4c 46)
        od -An -tx1 -N4 "$f" 2>/dev/null | grep -q "7f 45 4c 46" && echo "$f"
    fi
done
'@

Write-Host "[*] Executing on-device ELF discovery..." -ForegroundColor Yellow
$elfFiles = adb shell $findCommand 2>$null | Out-String
$elfFileList = $elfFiles -split "`n" | Where-Object { $_ -match '\S' } | ForEach-Object { $_.Trim() }

Write-Host "[+] Found $($elfFileList.Count) ELF binaries" -ForegroundColor Green

# Get sizes for all files
Write-Host "[*] Getting file sizes..." -ForegroundColor Yellow
$elfData = @()

foreach ($file in $elfFileList) {
    $size = (adb shell "stat -c%s '$file' 2>/dev/null" | Out-String).Trim()
    if ($size -match '^\d+$') {
        $elfData += [PSCustomObject]@{
            Path = $file
            Size = [int64]$size
        }
    }
}

$totalSize = ($elfData | Measure-Object -Property Size -Sum).Sum
Write-Host "[+] Total size: $([Math]::Round($totalSize / 1MB, 2)) MB" -ForegroundColor Green

# Create manifest
$manifestFile = Join-Path $OutputDir "MANIFEST.txt"
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
@"
MiFi 8800L Full Binary Extraction
==================================
Date: $timestamp
Device: MiFi 8800L (SDx20ALP-1.22.11)
Total Binaries: $($elfData.Count)
Total Size: $([Math]::Round($totalSize / 1MB, 2)) MB

Files:
"@ | Out-File -FilePath $manifestFile -Encoding UTF8

foreach ($elf in $elfData) {
    "$($elf.Path) ($([Math]::Round($elf.Size / 1KB, 2)) KB)" | Out-File -FilePath $manifestFile -Append -Encoding UTF8
}

# Download all files
Write-Host "`n[*] Downloading binaries..." -ForegroundColor Yellow
$downloaded = 0
$failed = 0

foreach ($elf in $elfData) {
    $downloaded++
    $percent = [Math]::Round(($downloaded / $elfData.Count) * 100, 1)
    
    $localPath = $elf.Path.TrimStart('/')
    $localFile = Join-Path $OutputDir $localPath
    $localDir = Split-Path $localFile -Parent
    
    if (-not (Test-Path $localDir)) {
        New-Item -ItemType Directory -Path $localDir -Force | Out-Null
    }
    
    Write-Host "[$downloaded/$($elfData.Count)] ($percent%) $($elf.Path)" -ForegroundColor Cyan
    
    adb pull "$($elf.Path)" "$localFile" 2>&1 | Out-Null
    
    if (Test-Path $localFile) {
        Write-Host "    [+] OK" -ForegroundColor Green
    } else {
        $failed++
        Write-Host "    [!] FAILED" -ForegroundColor Red
    }
}

Write-Host "`n=====================================" -ForegroundColor Cyan
Write-Host "Downloaded: $($downloaded - $failed)/$($elfData.Count)" -ForegroundColor Green
Write-Host "Failed: $failed" -ForegroundColor $(if ($failed -gt 0) { "Yellow" } else { "Green" })
Write-Host "Output: $OutputDir" -ForegroundColor Cyan
Write-Host "Manifest: $manifestFile" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
