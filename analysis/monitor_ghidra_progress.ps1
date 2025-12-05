# Monitor Ghidra Analysis Progress

param(
    [string]$OutputDir = "F:\repo\zerosms\analysis\ghidra_full_analysis\reports"
)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Ghidra Analysis Monitor" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

if (-not (Test-Path $OutputDir)) {
    Write-Host "[!] Analysis not started yet - directory not found" -ForegroundColor Yellow
    Write-Host "    Expected: $OutputDir" -ForegroundColor Gray
    exit
}

# Count analysis files
$analysisFiles = Get-ChildItem -Path $OutputDir -Filter "*.analysis.txt" -Recurse -ErrorAction SilentlyContinue
$logFiles = Get-ChildItem -Path $OutputDir -Filter "*.log.txt" -Recurse -ErrorAction SilentlyContinue
$errorFiles = Get-ChildItem -Path $OutputDir -Filter "*.error.txt" -Recurse -ErrorAction SilentlyContinue

Write-Host "[*] Analysis Progress:" -ForegroundColor Yellow
Write-Host "  Completed: $($analysisFiles.Count) binaries" -ForegroundColor Green
Write-Host "  Log files: $($logFiles.Count)" -ForegroundColor Gray
Write-Host "  Errors: $($errorFiles.Count)" -ForegroundColor $(if ($errorFiles.Count -gt 0) { "Red" } else { "Gray" })
Write-Host ""

if ($analysisFiles.Count -gt 0) {
    Write-Host "[*] Recently analyzed:" -ForegroundColor Cyan
    $analysisFiles | Sort-Object LastWriteTime -Descending | Select-Object -First 5 | ForEach-Object {
        Write-Host "  $($_.Name) - $(Get-Date $_.LastWriteTime -Format 'HH:mm:ss')" -ForegroundColor White
    }
    Write-Host ""
}

if ($errorFiles.Count -gt 0) {
    Write-Host "[!] Binaries with errors:" -ForegroundColor Red
    $errorFiles | ForEach-Object {
        Write-Host "  $($_.Name)" -ForegroundColor Yellow
    }
    Write-Host ""
}

# Check summary file
$summaryFile = Join-Path $OutputDir.Replace("\reports", "") "ANALYSIS_SUMMARY.txt"
if (Test-Path $summaryFile) {
    Write-Host "[+] Summary file exists: $summaryFile" -ForegroundColor Green
    $summary = Get-Content $summaryFile -Raw
    if ($summary -match "Successfully analyzed: (\d+)") {
        Write-Host "  Analysis complete!" -ForegroundColor Green
    }
}

Write-Host ""
