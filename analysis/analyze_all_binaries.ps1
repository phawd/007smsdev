# Comprehensive Binary Analysis - All MiFi Binaries
# Analyzes all remaining binaries for QMI/NV/EFS/unlock functions

$ErrorActionPreference = "Continue"
$ghidraPath = "F:\download\ghidra_11.4.3_PUBLIC_20251203\ghidra_11.4.3_PUBLIC\support\analyzeHeadless.bat"
$projectPath = "F:\repo\zerosms\analysis\ghidra_project"
$projectName = "MiFi_Deep_Analysis"
$binariesPath = "F:\repo\zerosms\analysis\binaries"
$scriptPath = "F:\repo\zerosms\analysis"
$outputPath = "F:\repo\zerosms\analysis\decompiled"

# Binaries to analyze (excluding already analyzed ones)
$binariesToAnalyze = @(
    "libqmi_client_helper.so.1.0.0",
    "qmi_ip_multiclient",
    "qmi_test_service_test",
    "rmnetcli",
    "sms_cli",
    "gps_cli",
    "wifi_cli"
)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "MiFi 8800L - Comprehensive Binary Analysis" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Create output directory if it doesn't exist
if (-not (Test-Path $outputPath)) {
    New-Item -ItemType Directory -Path $outputPath -Force | Out-Null
}

$totalBinaries = $binariesToAnalyze.Count
$currentBinary = 0

foreach ($binary in $binariesToAnalyze) {
    $currentBinary++
    $binPath = Join-Path $binariesPath $binary
    
    if (-not (Test-Path $binPath)) {
        Write-Host "[$currentBinary/$totalBinaries] SKIPPED: $binary (file not found)" -ForegroundColor Yellow
        continue
    }
    
    Write-Host "[$currentBinary/$totalBinaries] Analyzing: $binary" -ForegroundColor Green
    Write-Host "  Path: $binPath" -ForegroundColor Gray
    
    $fileSize = (Get-Item $binPath).Length
    Write-Host "  Size: $fileSize bytes" -ForegroundColor Gray
    
    # Run Ghidra analysis
    Write-Host "  [*] Running Ghidra analysis..." -ForegroundColor Yellow
    
    try {
        $startTime = Get-Date
        
        & $ghidraPath $projectPath $projectName `
            -import $binPath `
            -processor ARM:LE:32:v7 -cspec default `
            -analysisTimeoutPerFile 600 `
            -scriptPath $scriptPath `
            -postScript ghidra_deep_analysis.py 2>&1 | Out-Null
        
        $endTime = Get-Date
        $duration = ($endTime - $startTime).TotalSeconds
        
        Write-Host "  [+] Analysis completed in $([math]::Round($duration, 1))s" -ForegroundColor Green
        
        # Check for output file
        $outputFile = Join-Path $outputPath "$($binary)_analysis.txt"
        if (Test-Path $outputFile) {
            $outputSize = (Get-Item $outputFile).Length
            Write-Host "  [+] Output: $outputSize bytes" -ForegroundColor Green
        } else {
            Write-Host "  [!] Warning: No output file generated" -ForegroundColor Yellow
        }
        
    } catch {
        Write-Host "  [!] Error during analysis: $_" -ForegroundColor Red
    }
    
    Write-Host ""
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Analysis Complete!" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Summary of output files
Write-Host "Generated Analysis Files:" -ForegroundColor Green
Get-ChildItem $outputPath -Filter "*_analysis.txt" | ForEach-Object {
    $size = [math]::Round($_.Length / 1KB, 2)
    Write-Host "  - $($_.Name) ($size KB)" -ForegroundColor Gray
}
Write-Host ""

Write-Host "Next Steps:" -ForegroundColor Cyan
Write-Host "  1. Review analysis files in: $outputPath" -ForegroundColor White
Write-Host "  2. Extract specific functions using extract_unlock_functions.py" -ForegroundColor White
Write-Host "  3. Document findings in SESSION_7_8_PART3_SUMMARY.md" -ForegroundColor White
