# Ghidra Batch Analysis Script
# Analyzes all critical binaries for QMI/NV/EFS layer understanding

$GHIDRA_DIR = "F:\download\ghidra_11.4.3_PUBLIC_20251203\ghidra_11.4.3_PUBLIC"
$PROJECT_DIR = "F:\repo\zerosms\analysis\ghidra_project"
$PROJECT_NAME = "MiFi_QMI_NV_Analysis"
$BINARIES_DIR = "F:\repo\zerosms\analysis\binaries"

$CRITICAL_BINARIES = @(
    @{Name="libmal_qct.so"; Focus="Carrier unlock, QMI DMS"},
    @{Name="nwcli"; Focus="Network control, NV write bug"},
    @{Name="modem2_cli"; Focus="Primary modem control (196 commands)"},
    @{Name="libqmi.so.1.0.0"; Focus="QMI client library"},
    @{Name="libqmiservices.so.1.0.0"; Focus="QMI services"},
    @{Name="libqmi_client_qmux.so.1.0.0"; Focus="QMI multiplexing"},
    @{Name="sms_cli"; Focus="SMS management"},
    @{Name="gps_cli"; Focus="GPS/Location services"},
    @{Name="rmnetcli"; Focus="RmNet configuration"},
    @{Name="wifi_cli"; Focus="WiFi control"}
)

Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host "Ghidra Batch Analysis - QMI/NV/EFS Layer Investigation" -ForegroundColor Cyan
Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host ""

# Create output directory for decompiled code
$OUTPUT_DIR = "F:\repo\zerosms\analysis\decompiled"
if (-not (Test-Path $OUTPUT_DIR)) {
    New-Item -ItemType Directory -Path $OUTPUT_DIR -Force | Out-Null
}

Write-Host "[*] Output directory: $OUTPUT_DIR" -ForegroundColor Yellow
Write-Host ""

# Analyze each binary
foreach ($binary in $CRITICAL_BINARIES) {
    $binPath = Join-Path $BINARIES_DIR $binary.Name
    
    if (-not (Test-Path $binPath)) {
        Write-Host "[!] SKIP: $($binary.Name) - not found" -ForegroundColor Red
        continue
    }
    
    $fileInfo = Get-Item $binPath
    Write-Host "[*] Analyzing: $($binary.Name)" -ForegroundColor Green
    Write-Host "    Size: $($fileInfo.Length) bytes" -ForegroundColor Gray
    Write-Host "    Focus: $($binary.Focus)" -ForegroundColor Gray
    Write-Host ""
    
    # Run headless analysis
    $headlessCmd = Join-Path $GHIDRA_DIR "support\analyzeHeadless.bat"
    $args = @(
        $PROJECT_DIR,
        $PROJECT_NAME,
        "-import", $binPath,
        "-processor", "ARM:LE:32:v7",
        "-cspec", "default",
        "-analysisTimeoutPerFile", "300",
        "-deleteProject",  # Reuse project
        "-overwrite"
    )
    
    Write-Host "    [*] Running Ghidra analysis..." -ForegroundColor Yellow
    
    $output = & $headlessCmd @args 2>&1 | Out-String
    
    if ($output -match "Analysis succeeded") {
        Write-Host "    [+] Analysis complete!" -ForegroundColor Green
    } else {
        Write-Host "    [!] Analysis may have failed - check logs" -ForegroundColor Red
    }
    
    Write-Host ""
}

Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host "Batch Analysis Complete" -ForegroundColor Cyan
Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host ""
Write-Host "[+] Project: $PROJECT_DIR\$PROJECT_NAME.gpr" -ForegroundColor Green
Write-Host "[*] Open in Ghidra GUI for detailed analysis" -ForegroundColor Yellow
