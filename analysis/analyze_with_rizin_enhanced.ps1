# Enhanced Rizin/Cutter Analysis
# Uses Rizin from Cutter installation for comprehensive binary analysis

param(
    [string]$BinaryDir = "F:\repo\zerosms\analysis\complete_device_dump\_ALL_ELF_BINARIES",
    [string]$CutterPath = "F:\download\Cutter-v2.4.1-Windows-x86_64\Cutter-v2.4.1-Windows-x86_64",
    [string]$OutputDir = "F:\repo\zerosms\analysis\rizin_full_analysis",
    [int]$MaxBinaries = -1,
    [switch]$UseGUI = $false
)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Rizin/Cutter Binary Analysis" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Verify Cutter/Rizin installation
$rizinExe = Join-Path $CutterPath "rizin\bin\rizin.exe"
$cutterExe = Join-Path $CutterPath "cutter.exe"

if (-not (Test-Path $rizinExe) -and -not (Test-Path $cutterExe)) {
    Write-Host "[!] ERROR: Neither Rizin nor Cutter found at: $CutterPath" -ForegroundColor Red
    Write-Host "    Looking for:" -ForegroundColor Yellow
    Write-Host "      - $rizinExe" -ForegroundColor Gray
    Write-Host "      - $cutterExe" -ForegroundColor Gray
    exit 1
}

$useRizinCLI = Test-Path $rizinExe
Write-Host "[+] Found: $(if ($useRizinCLI) { 'Rizin CLI' } else { 'Cutter GUI only' })" -ForegroundColor Green

# Verify binary directory
if (-not (Test-Path $BinaryDir)) {
    Write-Host "[!] ERROR: Binary directory not found: $BinaryDir" -ForegroundColor Red
    Write-Host "[*] Run download_complete_device.ps1 first" -ForegroundColor Yellow
    exit 1
}

# Create output directory
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

# Find ELF binaries
Write-Host "[*] Finding ELF binaries..." -ForegroundColor Yellow
$binaries = Get-ChildItem -Path $BinaryDir -Recurse -File | Where-Object {
    try {
        $bytes = [System.IO.File]::ReadAllBytes($_.FullName)
        $bytes.Length -gt 4 -and $bytes[0] -eq 0x7F -and $bytes[1] -eq 0x45 -and $bytes[2] -eq 0x4C -and $bytes[3] -eq 0x46
    }
    catch { $false }
}

$totalCount = $binaries.Count
if ($totalCount -eq 0) {
    Write-Host "[!] No ELF binaries found" -ForegroundColor Red
    exit 1
}

# Sort by size (analyze largest first for important binaries)
$binaries = $binaries | Sort-Object Length -Descending

if ($MaxBinaries -gt 0 -and $totalCount -gt $MaxBinaries) {
    Write-Host "[*] Limiting to $MaxBinaries largest binaries" -ForegroundColor Yellow
    $binaries = $binaries | Select-Object -First $MaxBinaries
    $totalCount = $MaxBinaries
}

$totalSize = ($binaries | Measure-Object -Property Length -Sum).Sum
Write-Host "[+] Found $totalCount binaries ($([Math]::Round($totalSize / 1MB, 2)) MB)" -ForegroundColor Green
Write-Host ""

if ($UseGUI) {
    Write-Host "[*] GUI MODE - Opening Cutter for manual analysis" -ForegroundColor Yellow
    Write-Host "    Largest binaries to analyze:" -ForegroundColor Cyan
    $binaries | Select-Object -First 10 | ForEach-Object {
        Write-Host "      $($_.Name) - $([Math]::Round($_.Length / 1MB, 3)) MB" -ForegroundColor Gray
    }
    Write-Host ""
    Write-Host "[*] Opening Cutter..." -ForegroundColor Yellow
    Start-Process -FilePath $cutterExe
    Write-Host "[+] Cutter launched - manually open binaries from:" -ForegroundColor Green
    Write-Host "    $BinaryDir" -ForegroundColor White
    exit 0
}

if (-not $useRizinCLI) {
    Write-Host "[!] Rizin CLI not found - use -UseGUI flag for manual Cutter analysis" -ForegroundColor Yellow
    exit 1
}

# Automated CLI analysis
Write-Host "[*] Starting automated Rizin analysis..." -ForegroundColor Yellow
Write-Host ""

$analyzed = 0
$failed = 0
$startTime = Get-Date

foreach ($binary in $binaries) {
    $analyzed++
    $percentComplete = [Math]::Round(($analyzed / $totalCount) * 100, 1)
    
    $relativePath = $binary.FullName.Substring($BinaryDir.Length).TrimStart('\')
    $outputFile = Join-Path $OutputDir "$relativePath.rizin.txt"
    $outputFileDir = Split-Path $outputFile -Parent
    
    if (-not (Test-Path $outputFileDir)) {
        New-Item -ItemType Directory -Path $outputFileDir -Force | Out-Null
    }
    
    $sizeMB = [Math]::Round($binary.Length / 1MB, 3)
    Write-Host "[$analyzed/$totalCount] ($percentComplete%) $($binary.Name)" -ForegroundColor Cyan
    Write-Host "    Size: $sizeMB MB" -ForegroundColor Gray
    
    $binaryStartTime = Get-Date
    
    try {
        # Rizin commands for comprehensive analysis
        $rizinCommands = @"
e analysis.timeout=30
aaa
afl
aflm
afll
iz
izz
ii
iE
iI
pdf
"@
        
        # Run rizin with commands
        $rizinOutput = $rizinCommands | & $rizinExe -q -A -c - "$($binary.FullName)" 2>&1
        
        # Create analysis report
        $reportContent = @"
Rizin Analysis Report
=====================
Binary: $relativePath
Full Path: $($binary.FullName)
Size: $($binary.Length) bytes ($sizeMB MB)
Analysis Date: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

Analysis Output:
================

$rizinOutput

"@
        
        $reportContent | Out-File -FilePath $outputFile -Encoding UTF8
        
        $binaryEndTime = Get-Date
        $binaryDuration = ($binaryEndTime - $binaryStartTime).TotalSeconds
        
        Write-Host "    [+] Complete ($([Math]::Round($binaryDuration, 1))s)" -ForegroundColor Green
    }
    catch {
        $failed++
        Write-Host "    [!] Failed: $($_.Exception.Message)" -ForegroundColor Red
        "ERROR: $($_.Exception.Message)" | Out-File -FilePath $outputFile -Encoding UTF8
    }
}

$endTime = Get-Date
$duration = $endTime - $startTime

# Generate summary
$summaryFile = Join-Path $OutputDir "RIZIN_ANALYSIS_SUMMARY.md"
$summaryContent = @"
# Rizin Analysis Summary
## MiFi 8800L Complete Device Analysis

**Date:** $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")  
**Tool:** Rizin (from Cutter $CutterPath)  
**Binary Directory:** ``$BinaryDir``  

---

## Statistics

- **Binaries Analyzed:** $($analyzed - $failed) / $totalCount
- **Failed:** $failed
- **Total Size:** $([Math]::Round($totalSize / 1MB, 2)) MB
- **Analysis Duration:** $($duration.ToString('hh\:mm\:ss'))

---

## Largest Binaries Analyzed

"@

$binaries | Select-Object -First 20 | ForEach-Object {
    $summaryContent += "`n- **$($_.Name)** - $([Math]::Round($_.Length / 1MB, 3)) MB"
}

$summaryContent += @"


---

## Output Files

All analysis reports saved to: ``$OutputDir``

Each report contains:
- Function list (afl)
- Strings (iz/izz)
- Imports (ii)
- Exports (iE)
- Binary info (iI)

---

## Next Steps

1. Review reports in: $OutputDir
2. Open key binaries in Cutter GUI for decompilation
3. Cross-reference with Ghidra analysis
4. Extract critical functions for mifi_controller.py

---

*Generated by Rizin/Cutter Analysis Script*
"@

$summaryContent | Out-File -FilePath $summaryFile -Encoding UTF8

# Final summary
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  Rizin Analysis Complete" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Analyzed: $($analyzed - $failed)/$totalCount" -ForegroundColor Green
Write-Host "Failed: $failed" -ForegroundColor $(if ($failed -gt 0) { "Yellow" } else { "Green" })
Write-Host "Duration: $($duration.ToString('hh\:mm\:ss'))" -ForegroundColor White
Write-Host ""
Write-Host "Output:" -ForegroundColor Cyan
Write-Host "  Reports: $OutputDir" -ForegroundColor Gray
Write-Host "  Summary: $summaryFile" -ForegroundColor Gray
Write-Host ""
Write-Host "[*] To use Cutter GUI for detailed decompilation:" -ForegroundColor Yellow
Write-Host "    Run: & '$cutterExe'" -ForegroundColor Gray
Write-Host ""
