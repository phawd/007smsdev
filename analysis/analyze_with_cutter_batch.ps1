# Batch Analysis with Rizin/Cutter
# Analyzes all downloaded binaries using Rizin decompiler

param(
    [string]$BinaryDir = "F:\repo\zerosms\analysis\device_binaries_full",
    [string]$CutterPath = "F:\download\Cutter-v2.4.1-Windows-x86_64\Cutter-v2.4.1-Windows-x86_64\cutter.exe",
    [string]$OutputDir = "F:\repo\zerosms\analysis\cutter_analysis",
    [int]$MaxBinaries = -1  # -1 = analyze all
)

Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "  Rizin/Cutter Batch Analysis" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host ""

# Verify Cutter exists
if (-not (Test-Path $CutterPath)) {
    Write-Host "[!] ERROR: Cutter not found at: $CutterPath" -ForegroundColor Red
    exit 1
}
Write-Host "[+] Cutter found: $CutterPath" -ForegroundColor Green

# Verify binary directory
if (-not (Test-Path $BinaryDir)) {
    Write-Host "[!] ERROR: Binary directory not found: $BinaryDir" -ForegroundColor Red
    exit 1
}

# Create output directory
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

# Find all ELF binaries
Write-Host "[*] Finding binaries to analyze..." -ForegroundColor Yellow
$binaries = Get-ChildItem -Path $BinaryDir -Recurse -File | Where-Object {
    # Check if file is ELF (starts with 0x7F 'E' 'L' 'F')
    $bytes = [System.IO.File]::ReadAllBytes($_.FullName)
    $bytes.Length -gt 4 -and $bytes[0] -eq 0x7F -and $bytes[1] -eq 0x45 -and $bytes[2] -eq 0x4C -and $bytes[3] -eq 0x46
}

$totalCount = $binaries.Count
if ($MaxBinaries -gt 0 -and $totalCount -gt $MaxBinaries) {
    Write-Host "[*] Limiting analysis to first $MaxBinaries binaries" -ForegroundColor Yellow
    $binaries = $binaries | Select-Object -First $MaxBinaries
    $totalCount = $MaxBinaries
}

Write-Host "[+] Found $totalCount binaries to analyze" -ForegroundColor Green
Write-Host ""

# Create Rizin script for automated analysis
$rizinScript = @'
# Rizin automated analysis script
aa    # Analyze all
aaa   # Deeper analysis
aaaa  # Even deeper analysis
afl   # List functions
afll  # List functions with size
iz    # List strings
ii    # List imports
iE    # List exports
'@

$scriptPath = Join-Path $OutputDir "rizin_analysis.r2"
$rizinScript | Out-File -FilePath $scriptPath -Encoding ASCII

# Analysis loop
$analyzed = 0
$failed = 0
$startTime = Get-Date

foreach ($binary in $binaries) {
    $analyzed++
    $percentComplete = [Math]::Round(($analyzed / $totalCount) * 100, 1)
    
    $relativePath = $binary.FullName.Substring($BinaryDir.Length + 1)
    $outputFile = Join-Path $OutputDir "$relativePath.analysis.txt"
    $outputDir = Split-Path $outputFile -Parent
    
    if (-not (Test-Path $outputDir)) {
        New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
    }
    
    Write-Host "[$analyzed/$totalCount] ($percentComplete%) $relativePath" -ForegroundColor Cyan
    Write-Host "    Size: $([Math]::Round($binary.Length / 1KB, 2)) KB" -ForegroundColor Gray
    
    # Use rizin command-line (r2) for batch processing
    $r2Path = Join-Path (Split-Path $CutterPath -Parent) "rizin\bin\rizin.exe"
    
    if (Test-Path $r2Path) {
        try {
            # Run rizin analysis
            $output = & $r2Path -A -q -c "aaa; afl; iz; ii; iE" "$($binary.FullName)" 2>&1
            
            # Save output
            $analysisContent = @"
Rizin Analysis Report
=====================
Binary: $relativePath
Size: $($binary.Length) bytes
Analysis Date: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

FUNCTIONS:
$output

"@
            $analysisContent | Out-File -FilePath $outputFile -Encoding UTF8
            Write-Host "    [+] Analysis saved" -ForegroundColor Green
        }
        catch {
            $failed++
            Write-Host "    [!] Analysis failed: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    else {
        Write-Host "    [!] Rizin not found, skipping..." -ForegroundColor Yellow
        "NOTE: Rizin command-line tool not found. Please use Cutter GUI for manual analysis." | Out-File -FilePath $outputFile -Encoding UTF8
    }
}

$endTime = Get-Date
$duration = $endTime - $startTime

# Summary
Write-Host "`n=====================================" -ForegroundColor Cyan
Write-Host "  Analysis Complete" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "Analyzed: $($analyzed - $failed)/$totalCount binaries" -ForegroundColor Green
Write-Host "Failed: $failed" -ForegroundColor $(if ($failed -gt 0) { "Yellow" } else { "Green" })
Write-Host "Duration: $($duration.ToString('hh\:mm\:ss'))" -ForegroundColor White
Write-Host "Output directory: $OutputDir" -ForegroundColor Cyan
Write-Host ""
Write-Host "[*] To analyze manually with Cutter GUI:" -ForegroundColor Yellow
Write-Host "    1. Open Cutter: $CutterPath" -ForegroundColor Gray
Write-Host "    2. File > Open > Select binary" -ForegroundColor Gray
Write-Host "    3. Let auto-analysis complete" -ForegroundColor Gray
Write-Host "    4. Use 'Functions' panel and decompiler view" -ForegroundColor Gray
Write-Host ""
