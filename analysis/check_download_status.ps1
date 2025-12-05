# Quick status checker for complete device download

$dumpDir = "F:\repo\zerosms\analysis\complete_device_dump"

if (-not (Test-Path $dumpDir)) {
    Write-Host "[!] Dump directory not found: $dumpDir" -ForegroundColor Red
    Write-Host "[*] Run download_complete_device.ps1 first" -ForegroundColor Yellow
    exit
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Device Dump Status" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check what's been downloaded
$directories = @(
    "opt", "usr/bin", "usr/sbin", "usr/lib", "usr/libexec",
    "bin", "sbin", "lib", "system/bin", "firmware", "root", "home"
)

Write-Host "[*] Downloaded Directories:" -ForegroundColor Yellow
foreach ($dir in $directories) {
    $fullPath = Join-Path $dumpDir $dir
    if (Test-Path $fullPath) {
        $fileCount = (Get-ChildItem -Path $fullPath -Recurse -File -ErrorAction SilentlyContinue | Measure-Object).Count
        $size = (Get-ChildItem -Path $fullPath -Recurse -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
        $sizeMB = [Math]::Round($size / 1MB, 2)
        Write-Host "  [+] /$dir - $fileCount files ($sizeMB MB)" -ForegroundColor Green
    } else {
        Write-Host "  [ ] /$dir - Not downloaded yet" -ForegroundColor Gray
    }
}

# Check for ELF directory
$elfDir = Join-Path $dumpDir "_ALL_ELF_BINARIES"
if (Test-Path $elfDir) {
    Write-Host "`n[*] ELF Binaries:" -ForegroundColor Yellow
    $elfFiles = Get-ChildItem -Path $elfDir -Recurse -File -ErrorAction SilentlyContinue
    $elfSize = ($elfFiles | Measure-Object -Property Length -Sum).Sum
    Write-Host "  [+] Found: $($elfFiles.Count) binaries" -ForegroundColor Green
    Write-Host "  [+] Total size: $([Math]::Round($elfSize / 1MB, 2)) MB" -ForegroundColor Green
    
    Write-Host "`n  Top 10 largest:" -ForegroundColor Cyan
    $elfFiles | Sort-Object Length -Descending | Select-Object -First 10 | ForEach-Object {
        Write-Host "    $($_.Name) - $([Math]::Round($_.Length / 1MB, 3)) MB" -ForegroundColor White
    }
} else {
    Write-Host "`n[!] ELF extraction not completed yet" -ForegroundColor Yellow
}

# Check for manifest
$manifest = Join-Path $elfDir "DEVICE_MANIFEST.txt"
if (Test-Path $manifest) {
    Write-Host "`n[+] Manifest available: $manifest" -ForegroundColor Green
}

Write-Host ""
