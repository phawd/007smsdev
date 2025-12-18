# Master Analysis Orchestrator
# Runs comprehensive analysis using both Rizin/Cutter and Ghidra on all downloaded binaries

param(
    [string]$BinaryDir = "F:\repo\zerosms\analysis\complete_device_dump\_ALL_ELF_BINARIES",
    [string]$CutterPath = "F:\download\Cutter-v2.4.1-Windows-x86_64\Cutter-v2.4.1-Windows-x86_64",
    [string]$GhidraPath = "F:\download\ghidra_11.2.1_PUBLIC",
    [string]$OutputDir = "F:\repo\zerosms\analysis\full_device_analysis",
    [int]$MaxBinaries = -1,  # -1 = analyze all
    [switch]$GhidraOnly = $false,
    [switch]$CutterOnly = $false,
    [switch]$SkipConfirm = $false
)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  MASTER ANALYSIS ORCHESTRATOR" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Device: MiFi 8800L (SDx20ALP-1.22.11)" -ForegroundColor White
Write-Host "  Analysis Tools: " -NoNewline
if (-not $CutterOnly) { Write-Host "Ghidra " -NoNewline -ForegroundColor Green }
if (-not $GhidraOnly) { Write-Host "Rizin/Cutter" -NoNewline -ForegroundColor Green }
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Verify binary directory
if (-not (Test-Path $BinaryDir)) {
    Write-Host "[!] ERROR: Binary directory not found: $BinaryDir" -ForegroundColor Red
    Write-Host "[*] Please run bulk_download_binaries.ps1 first" -ForegroundColor Yellow
    exit 1
}

# Find all ELF binaries
Write-Host "[*] Finding ELF binaries to analyze..." -ForegroundColor Yellow
$binaries = Get-ChildItem -Path $BinaryDir -Recurse -File | Where-Object {
    try {
        $bytes = [System.IO.File]::ReadAllBytes($_.FullName)
        $bytes.Length -gt 4 -and $bytes[0] -eq 0x7F -and $bytes[1] -eq 0x45 -and $bytes[2] -eq 0x4C -and $bytes[3] -eq 0x46
    }
    catch {
        $false
    }
}

if ($binaries.Count -eq 0) {
    Write-Host "[!] No ELF binaries found in $BinaryDir" -ForegroundColor Red
    exit 1
}

# Sort by size for better progress visibility
$binaries = $binaries | Sort-Object Length -Descending

$totalCount = $binaries.Count
if ($MaxBinaries -gt 0 -and $totalCount -gt $MaxBinaries) {
    Write-Host "[*] Limiting analysis to $MaxBinaries largest binaries" -ForegroundColor Yellow
    $binaries = $binaries | Select-Object -First $MaxBinaries
    $totalCount = $MaxBinaries
}

$totalSize = ($binaries | Measure-Object -Property Length -Sum).Sum
Write-Host "[+] Found $totalCount ELF binaries ($([Math]::Round($totalSize / 1MB, 2)) MB)" -ForegroundColor Green
Write-Host ""

# Create output structure
$ghidraOutputDir = Join-Path $OutputDir "ghidra_analysis"
$cutterOutputDir = Join-Path $OutputDir "cutter_analysis"
$comparisonDir = Join-Path $OutputDir "comparison"

New-Item -ItemType Directory -Path $ghidraOutputDir -Force | Out-Null
New-Item -ItemType Directory -Path $cutterOutputDir -Force | Out-Null
New-Item -ItemType Directory -Path $comparisonDir -Force | Out-Null

# Display plan
Write-Host "[*] Analysis Plan:" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Binaries to analyze: $totalCount" -ForegroundColor White
Write-Host "  Total size: $([Math]::Round($totalSize / 1MB, 2)) MB" -ForegroundColor White
Write-Host ""
Write-Host "  Top 10 largest binaries:" -ForegroundColor Yellow
$binaries | Select-Object -First 10 | ForEach-Object {
    Write-Host "    $($_.Name) - $([Math]::Round($_.Length / 1MB, 3)) MB" -ForegroundColor Gray
}
Write-Host ""

if (-not $CutterOnly) {
    Write-Host "  [1] Ghidra Analysis:" -ForegroundColor Cyan
    Write-Host "      - Headless batch analysis" -ForegroundColor Gray
    Write-Host "      - Function discovery" -ForegroundColor Gray
    Write-Host "      - Decompilation" -ForegroundColor Gray
    Write-Host "      - Cross-reference mapping" -ForegroundColor Gray
    Write-Host "      Output: $ghidraOutputDir" -ForegroundColor DarkGray
    Write-Host ""
}

if (-not $GhidraOnly) {
    Write-Host "  [2] Rizin/Cutter Analysis:" -ForegroundColor Cyan
    Write-Host "      - Rizin CLI analysis" -ForegroundColor Gray
    Write-Host "      - Function listing" -ForegroundColor Gray
    Write-Host "      - String extraction" -ForegroundColor Gray
    Write-Host "      - Import/Export tables" -ForegroundColor Gray
    Write-Host "      Output: $cutterOutputDir" -ForegroundColor DarkGray
    Write-Host ""
}

Write-Host "  [3] Comparison Report:" -ForegroundColor Cyan
Write-Host "      - Cross-tool validation" -ForegroundColor Gray
Write-Host "      - Confidence scoring" -ForegroundColor Gray
Write-Host "      - Unified findings" -ForegroundColor Gray
Write-Host "      Output: $comparisonDir" -ForegroundColor DarkGray
Write-Host ""

# Confirm start
if (-not $SkipConfirm) {
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  Press ENTER to start analysis..." -ForegroundColor Yellow
    Write-Host "  (This will take several hours)" -ForegroundColor Gray
    Write-Host "========================================" -ForegroundColor Cyan
    Read-Host
}

$masterStartTime = Get-Date

# Phase 1: Ghidra Analysis
if (-not $CutterOnly) {
    Write-Host "`n" + "=" * 80 -ForegroundColor Cyan
    Write-Host "  PHASE 1: GHIDRA ANALYSIS" -ForegroundColor Cyan
    Write-Host "=" * 80 -ForegroundColor Cyan
    Write-Host ""
    
    $ghidraScript = Join-Path $PSScriptRoot "analyze_with_ghidra_full.ps1"
    if (Test-Path $ghidraScript) {
        & $ghidraScript -BinaryDir $BinaryDir -GhidraPath $GhidraPath -OutputDir $ghidraOutputDir -MaxBinaries $MaxBinaries
    }
    else {
        Write-Host "[!] Ghidra analysis script not found: $ghidraScript" -ForegroundColor Red
    }
}

# Phase 2: Rizin/Cutter Analysis
if (-not $GhidraOnly) {
    Write-Host "`n" + "=" * 80 -ForegroundColor Cyan
    Write-Host "  PHASE 2: RIZIN/CUTTER ANALYSIS" -ForegroundColor Cyan
    Write-Host "=" * 80 -ForegroundColor Cyan
    Write-Host ""
    
    $cutterScript = Join-Path $PSScriptRoot "analyze_with_cutter_batch.ps1"
    if (Test-Path $cutterScript) {
        & $cutterScript -BinaryDir $BinaryDir -CutterPath (Join-Path $CutterPath "cutter.exe") -OutputDir $cutterOutputDir -MaxBinaries $MaxBinaries
    }
    else {
        Write-Host "[!] Cutter analysis script not found: $cutterScript" -ForegroundColor Red
    }
}

# Phase 3: Comparison and Unified Report
if (-not $GhidraOnly -and -not $CutterOnly) {
    Write-Host "`n" + "=" * 80 -ForegroundColor Cyan
    Write-Host "  PHASE 3: CROSS-TOOL COMPARISON" -ForegroundColor Cyan
    Write-Host "=" * 80 -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host "[*] Generating comparison report..." -ForegroundColor Yellow
    
    # Create unified report
    $reportFile = Join-Path $comparisonDir "UNIFIED_ANALYSIS_REPORT.md"
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    $reportContent = @"
# Full Device Analysis Report
## MiFi 8800L Complete Binary Decompilation

**Date:** $timestamp  
**Device:** MiFi 8800L (SDx20ALP-1.22.11)  
**Analysis Tools:** Ghidra $($GhidraPath -replace '.*ghidra_([^_]+)_.*','$1'), Rizin/Cutter  

---

## Executive Summary

This report documents the comprehensive analysis of all ELF binaries extracted from the MiFi 8800L device.

### Analysis Scope
- **Total Binaries Analyzed:** $totalCount
- **Total Size:** $([Math]::Round($totalSize / 1MB, 2)) MB
- **Analysis Duration:** $((Get-Date) - $masterStartTime | ForEach-Object { "{0:hh\:mm\:ss}" -f $_ })

### Tools Used
1. **Ghidra** - Advanced decompilation and function discovery
2. **Rizin/Cutter** - String analysis and import/export mapping

---

## Binary Inventory

### Largest Binaries
"@

    $binaries | Select-Object -First 20 | ForEach-Object {
        $reportContent += "`n- **$($_.Name)** - $([Math]::Round($_.Length / 1MB, 3)) MB"
    }
    
    $reportContent += @"


---

## Analysis Outputs

### Ghidra Analysis
- **Location:** ``$ghidraOutputDir``
- **Project:** MiFi_Full_Device.gpr
- **Reports:** Individual analysis reports per binary

### Rizin/Cutter Analysis
- **Location:** ``$cutterOutputDir``
- **Reports:** Function listings, strings, imports/exports

---

## Key Findings

[This section will be populated with manual review of Ghidra and Rizin outputs]

### Critical Binaries

"@

    # Identify binaries with unlock/security keywords
    $criticalBinaries = $binaries | Where-Object {
        $_.Name -match 'modem|qmi|unlock|security|mal|nv|efs'
    }
    
    if ($criticalBinaries) {
        $reportContent += "`n**Security-Related Binaries:**`n"
        foreach ($binary in $criticalBinaries) {
            $reportContent += "`n- **$($binary.Name)** - $([Math]::Round($binary.Length / 1KB, 2)) KB"
        }
    }
    
    $reportContent += @"


---

## Next Steps

1. Review Ghidra decompiled functions in key binaries
2. Cross-reference with Rizin string analysis
3. Document unlock algorithms and security mechanisms
4. Create function call graphs for critical paths
5. Update mifi_controller.py with new findings

---

## References

- Ghidra Project: ``$ghidraOutputDir\ghidra_project``
- Cutter Reports: ``$cutterOutputDir``
- Original Binaries: ``$BinaryDir``

---

*Report generated by SMS Test Master Analysis Orchestrator*
"@

    $reportContent | Out-File -FilePath $reportFile -Encoding UTF8
    Write-Host "[+] Unified report created: $reportFile" -ForegroundColor Green
}

$masterEndTime = Get-Date
$masterDuration = $masterEndTime - $masterStartTime

# Final Summary
Write-Host "`n" + "=" * 80 -ForegroundColor Cyan
Write-Host "  MASTER ANALYSIS COMPLETE" -ForegroundColor Cyan
Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host ""
Write-Host "  Total Duration: $($masterDuration.ToString('hh\:mm\:ss'))" -ForegroundColor White
Write-Host ""
Write-Host "  Output Directories:" -ForegroundColor Cyan
if (-not $CutterOnly) {
    Write-Host "    Ghidra: $ghidraOutputDir" -ForegroundColor Gray
}
if (-not $GhidraOnly) {
    Write-Host "    Cutter: $cutterOutputDir" -ForegroundColor Gray
}
if (-not $GhidraOnly -and -not $CutterOnly) {
    Write-Host "    Unified: $comparisonDir" -ForegroundColor Gray
}
Write-Host ""
Write-Host "  [+] All analysis complete!" -ForegroundColor Green
Write-Host "  [*] Review the unified report for combined findings" -ForegroundColor Yellow
Write-Host ""
Write-Host "=" * 80 -ForegroundColor Cyan
