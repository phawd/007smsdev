# Comprehensive Ghidra Batch Analysis for All Device Binaries
# Decompiles all binaries from the MiFi device using Ghidra headless analyzer

param(
    [string]$BinaryDir = "F:\repo\zerosms\analysis\device_binaries_full",
    [string]$GhidraPath = "F:\download\ghidra_11.2.1_PUBLIC",
    [string]$OutputDir = "F:\repo\zerosms\analysis\ghidra_full_analysis",
    [string]$ProjectName = "MiFi_Full_Device",
    [int]$MaxBinaries = -1,  # -1 = analyze all
    [switch]$FullDecompile = $false
)

Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "  Ghidra Full Device Analysis" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host ""

# Verify Ghidra installation
$ghidraHeadless = Join-Path $GhidraPath "support\analyzeHeadless.bat"
if (-not (Test-Path $ghidraHeadless)) {
    Write-Host "[!] ERROR: Ghidra not found at: $GhidraPath" -ForegroundColor Red
    Write-Host "    Looking for: $ghidraHeadless" -ForegroundColor Red
    exit 1
}
Write-Host "[+] Ghidra found: $GhidraPath" -ForegroundColor Green

# Verify binary directory
if (-not (Test-Path $BinaryDir)) {
    Write-Host "[!] ERROR: Binary directory not found: $BinaryDir" -ForegroundColor Red
    exit 1
}

# Create output directory
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

$projectDir = Join-Path $OutputDir "ghidra_project"
$decompileDir = Join-Path $OutputDir "decompiled"
$reportDir = Join-Path $OutputDir "reports"

New-Item -ItemType Directory -Path $decompileDir -Force | Out-Null
New-Item -ItemType Directory -Path $reportDir -Force | Out-Null

# Find all ELF binaries
Write-Host "[*] Finding binaries to analyze..." -ForegroundColor Yellow
$binaries = Get-ChildItem -Path $BinaryDir -Recurse -File | Where-Object {
    try {
        $bytes = [System.IO.File]::ReadAllBytes($_.FullName)
        $bytes.Length -gt 4 -and $bytes[0] -eq 0x7F -and $bytes[1] -eq 0x45 -and $bytes[2] -eq 0x4C -and $bytes[3] -eq 0x46
    }
    catch {
        $false
    }
}

# Sort by size (analyze smaller binaries first for faster initial results)
$binaries = $binaries | Sort-Object Length

$totalCount = $binaries.Count
if ($MaxBinaries -gt 0 -and $totalCount -gt $MaxBinaries) {
    Write-Host "[*] Limiting analysis to first $MaxBinaries binaries" -ForegroundColor Yellow
    $binaries = $binaries | Select-Object -First $MaxBinaries
    $totalCount = $MaxBinaries
}

Write-Host "[+] Found $totalCount binaries to analyze" -ForegroundColor Green
$totalSize = ($binaries | Measure-Object -Property Length -Sum).Sum
Write-Host "[+] Total size: $([Math]::Round($totalSize / 1MB, 2)) MB" -ForegroundColor Green
Write-Host ""

# Create comprehensive Ghidra analysis script
$ghidraScript = @'
# Comprehensive Ghidra Analysis Script - extract_all_info.py
# @category Analysis
# @author SMS Test Research

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
import json

# Initialize decompiler
decompiler = DecompInterface()
decompiler.openProgram(currentProgram)
monitor = ConsoleTaskMonitor()

output = []
output.append("=" * 80)
output.append("GHIDRA COMPREHENSIVE ANALYSIS REPORT")
output.append("=" * 80)
output.append("Binary: " + currentProgram.getName())
output.append("Base Address: " + hex(currentProgram.getImageBase().getOffset()))
output.append("")

# 1. PROGRAM INFO
output.append("\n[*] PROGRAM INFORMATION")
output.append("-" * 80)
output.append("Executable Format: " + currentProgram.getExecutableFormat())
output.append("Executable Path: " + currentProgram.getExecutablePath())
output.append("Compiler: " + str(currentProgram.getCompiler()))
output.append("Language: " + str(currentProgram.getLanguage()))
output.append("")

# 2. MEMORY LAYOUT
output.append("\n[*] MEMORY LAYOUT")
output.append("-" * 80)
for block in currentProgram.getMemory().getBlocks():
    output.append("  [{0}] {1} - {2} ({3} bytes) {4}".format(
        block.getName(),
        block.getStart(),
        block.getEnd(),
        block.getSize(),
        "R" + ("W" if block.isWrite() else "-") + ("X" if block.isExecute() else "-")
    ))
output.append("")

# 3. FUNCTIONS
output.append("\n[*] FUNCTIONS")
output.append("-" * 80)
fm = currentProgram.getFunctionManager()
functions = list(fm.getFunctions(True))
output.append("Total Functions: " + str(len(functions)))
output.append("")

# Group functions by category
imported_funcs = []
exported_funcs = []
internal_funcs = []

for func in functions:
    func_name = func.getName()
    func_addr = func.getEntryPoint()
    func_size = func.getBody().getNumAddresses()
    
    if func.isExternal():
        imported_funcs.append("  {0} @ EXTERNAL:{1}".format(func_name, func_addr))
    elif func.isThunk():
        exported_funcs.append("  {0} @ {1} (thunk)".format(func_name, func_addr))
    else:
        internal_funcs.append("  {0} @ {1} ({2} bytes)".format(func_name, func_addr, func_size))

output.append("Imported Functions ({0}):".format(len(imported_funcs)))
for f in imported_funcs[:50]:  # Limit to first 50
    output.append(f)
if len(imported_funcs) > 50:
    output.append("  ... and {0} more".format(len(imported_funcs) - 50))

output.append("\nExported Functions ({0}):".format(len(exported_funcs)))
for f in exported_funcs[:50]:
    output.append(f)
if len(exported_funcs) > 50:
    output.append("  ... and {0} more".format(len(exported_funcs) - 50))

output.append("\nInternal Functions ({0}):".format(len(internal_funcs)))
for f in internal_funcs[:50]:
    output.append(f)
if len(internal_funcs) > 50:
    output.append("  ... and {0} more".format(len(internal_funcs) - 50))

# 4. STRINGS
output.append("\n\n[*] INTERESTING STRINGS")
output.append("-" * 80)
string_count = 0
interesting_patterns = ["qmi", "nv", "efs", "unlock", "password", "key", "secret", "admin", "root", "config"]

for string in currentProgram.getListing().getDefinedData(True):
    if string.hasStringValue():
        string_val = string.getValue()
        if string_val and len(str(string_val)) > 3:
            string_str = str(string_val).lower()
            for pattern in interesting_patterns:
                if pattern in string_str:
                    output.append("  {0}: \"{1}\"".format(string.getAddress(), string_val))
                    string_count += 1
                    if string_count >= 100:  # Limit output
                        break
                    break
            if string_count >= 100:
                break

output.append("\nTotal interesting strings: " + str(string_count))

# 5. CROSS REFERENCES (for key functions)
output.append("\n\n[*] KEY FUNCTION CROSS-REFERENCES")
output.append("-" * 80)
key_funcs = ["unlock", "qmi", "nv_read", "nv_write", "validate", "check", "verify"]

for func in functions[:200]:  # Check first 200 functions
    func_name = func.getName().lower()
    for key in key_funcs:
        if key in func_name:
            output.append("\n  Function: {0} @ {1}".format(func.getName(), func.getEntryPoint()))
            refs = func.getCallingFunctions(monitor)
            if refs:
                output.append("    Called by:")
                for ref in list(refs)[:10]:  # Limit to 10 refs
                    output.append("      - {0} @ {1}".format(ref.getName(), ref.getEntryPoint()))
            break

# 6. DECOMPILE KEY FUNCTIONS (if requested)
output.append("\n\n[*] DECOMPILED FUNCTIONS (KEY FUNCTIONS ONLY)")
output.append("-" * 80)

key_functions_to_decompile = []
for func in functions:
    func_name = func.getName().lower()
    if any(keyword in func_name for keyword in ["unlock", "carrier", "validate", "spc", "nck", "otksk"]):
        if not func.isExternal() and not func.isThunk():
            key_functions_to_decompile.append(func)

output.append("Found {0} key functions to decompile".format(len(key_functions_to_decompile)))

for func in key_functions_to_decompile[:10]:  # Limit to 10 functions
    output.append("\n" + "=" * 80)
    output.append("FUNCTION: {0}".format(func.getName()))
    output.append("Address: {0}".format(func.getEntryPoint()))
    output.append("Size: {0} bytes".format(func.getBody().getNumAddresses()))
    output.append("-" * 80)
    
    try:
        results = decompiler.decompileFunction(func, 30, monitor)
        if results and results.decompileCompleted():
            decomp = results.getDecompiledFunction()
            if decomp:
                output.append(decomp.getC())
        else:
            output.append("// Decompilation failed or timed out")
    except:
        output.append("// Error during decompilation")

# Output everything
for line in output:
    println(line)

println("\n[+] Analysis complete!")
'@

$scriptPath = Join-Path $OutputDir "extract_all_info.py"
$ghidraScript | Out-File -FilePath $scriptPath -Encoding UTF8
Write-Host "[+] Created Ghidra analysis script: $scriptPath" -ForegroundColor Green

# Analysis loop
$analyzed = 0
$failed = 0
$startTime = Get-Date

Write-Host "`n[*] Starting batch analysis..." -ForegroundColor Yellow
Write-Host "    This will take a significant amount of time for large binaries" -ForegroundColor Gray
Write-Host ""

foreach ($binary in $binaries) {
    $analyzed++
    $percentComplete = [Math]::Round(($analyzed / $totalCount) * 100, 1)
    
    $relativePath = $binary.FullName.Substring($BinaryDir.Length + 1)
    $binaryName = $binary.Name
    $outputFile = Join-Path $reportDir "$relativePath.analysis.txt"
    $outputFileDir = Split-Path $outputFile -Parent
    
    if (-not (Test-Path $outputFileDir)) {
        New-Item -ItemType Directory -Path $outputFileDir -Force | Out-Null
    }
    
    $sizeMB = [Math]::Round($binary.Length / 1MB, 3)
    Write-Host "[$analyzed/$totalCount] ($percentComplete%) $relativePath" -ForegroundColor Cyan
    Write-Host "    Size: $sizeMB MB" -ForegroundColor Gray
    
    $binaryStartTime = Get-Date
    
    try {
        # Run Ghidra headless analysis
        $ghidraArgs = @(
            $projectDir,
            $ProjectName,
            "-import", $binary.FullName,
            "-overwrite",
            "-postScript", $scriptPath,
            "-scriptlog", (Join-Path $reportDir "$binaryName.scriptlog.txt"),
            "-log", (Join-Path $reportDir "$binaryName.log.txt")
        )
        
        $process = Start-Process -FilePath $ghidraHeadless `
            -ArgumentList $ghidraArgs `
            -Wait `
            -NoNewWindow `
            -PassThru `
            -RedirectStandardOutput $outputFile `
            -RedirectStandardError (Join-Path $reportDir "$binaryName.error.txt")
        
        $binaryEndTime = Get-Date
        $binaryDuration = $binaryEndTime - $binaryStartTime
        
        if ($process.ExitCode -eq 0 -and (Test-Path $outputFile)) {
            Write-Host "    [+] Analysis complete ($($binaryDuration.TotalSeconds.ToString('F1'))s)" -ForegroundColor Green
        }
        else {
            $failed++
            Write-Host "    [!] Analysis failed (exit code: $($process.ExitCode))" -ForegroundColor Red
        }
    }
    catch {
        $failed++
        Write-Host "    [!] Error: $($_.Exception.Message)" -ForegroundColor Red
    }
}

$endTime = Get-Date
$duration = $endTime - $startTime

# Generate summary report
$summaryFile = Join-Path $OutputDir "ANALYSIS_SUMMARY.txt"
$summaryContent = @"
Ghidra Full Device Analysis Summary
====================================
Analysis Date: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Device: MiFi 8800L (SDx20ALP-1.22.11)

Statistics:
-----------
Total binaries found: $totalCount
Successfully analyzed: $($analyzed - $failed)
Failed: $failed
Total size analyzed: $([Math]::Round($totalSize / 1MB, 2)) MB
Analysis duration: $($duration.ToString('hh\:mm\:ss'))

Output Locations:
-----------------
Project directory: $projectDir
Decompiled code: $decompileDir
Analysis reports: $reportDir
Summary report: $summaryFile

Analysis Script:
----------------
$scriptPath

Files Analyzed:
---------------
"@

foreach ($binary in $binaries) {
    $relativePath = $binary.FullName.Substring($BinaryDir.Length + 1)
    $summaryContent += "`n$relativePath ($([Math]::Round($binary.Length / 1KB, 2)) KB)"
}

$summaryContent | Out-File -FilePath $summaryFile -Encoding UTF8

# Final summary
Write-Host "`n=====================================" -ForegroundColor Cyan
Write-Host "  Ghidra Analysis Complete" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "Analyzed: $($analyzed - $failed)/$totalCount binaries" -ForegroundColor Green
Write-Host "Failed: $failed" -ForegroundColor $(if ($failed -gt 0) { "Yellow" } else { "Green" })
Write-Host "Duration: $($duration.ToString('hh\:mm\:ss'))" -ForegroundColor White
Write-Host ""
Write-Host "Output locations:" -ForegroundColor Cyan
Write-Host "  Project: $projectDir" -ForegroundColor Gray
Write-Host "  Reports: $reportDir" -ForegroundColor Gray
Write-Host "  Summary: $summaryFile" -ForegroundColor Gray
Write-Host ""
Write-Host "[*] To open in Ghidra GUI:" -ForegroundColor Yellow
Write-Host "    1. Open Ghidra" -ForegroundColor Gray
Write-Host "    2. File > Open Project" -ForegroundColor Gray
Write-Host "    3. Navigate to: $projectDir" -ForegroundColor Gray
Write-Host "    4. Select: $ProjectName" -ForegroundColor Gray
Write-Host ""
