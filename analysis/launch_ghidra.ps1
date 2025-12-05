# Ghidra Analysis Launcher for libmal_qct.so
# This script sets up and runs Ghidra analysis on the carrier unlock library

$GHIDRA_DIR = "F:\download\ghidra_11.4.3_PUBLIC_20251203\ghidra_11.4.3_PUBLIC"
$PROJECT_DIR = "F:\repo\zerosms\analysis\ghidra_project"
$PROJECT_NAME = "MiFi_Unlock_Analysis"
$BINARY = "F:\repo\zerosms\analysis\binaries\libmal_qct.so"

Write-Host "=" * 70 -ForegroundColor Cyan
Write-Host "Ghidra Analysis Setup - libmal_qct.so" -ForegroundColor Cyan
Write-Host "=" * 70 -ForegroundColor Cyan

# Create project directory if it doesn't exist
if (-not (Test-Path $PROJECT_DIR)) {
    Write-Host "[*] Creating project directory: $PROJECT_DIR" -ForegroundColor Yellow
    New-Item -ItemType Directory -Path $PROJECT_DIR -Force | Out-Null
}

# Check if binary exists
if (-not (Test-Path $BINARY)) {
    Write-Host "[!] ERROR: Binary not found: $BINARY" -ForegroundColor Red
    exit 1
}

Write-Host "[+] Binary found: $BINARY" -ForegroundColor Green
$fileInfo = Get-Item $BINARY
Write-Host "    Size: $($fileInfo.Length) bytes" -ForegroundColor Gray

# Display options
Write-Host ""
Write-Host "Analysis Options:" -ForegroundColor Cyan
Write-Host "  1. Launch Ghidra GUI (Interactive Analysis)" -ForegroundColor White
Write-Host "  2. Headless Analysis (Automated)" -ForegroundColor White
Write-Host "  3. Quick Info (Binary Details Only)" -ForegroundColor White
Write-Host ""

$choice = Read-Host "Select option [1-3]"

switch ($choice) {
    "1" {
        Write-Host "[*] Launching Ghidra GUI..." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Instructions:" -ForegroundColor Cyan
        Write-Host "  1. Create new project: File -> New Project -> Non-Shared" -ForegroundColor White
        Write-Host "  2. Project Directory: $PROJECT_DIR" -ForegroundColor White
        Write-Host "  3. Project Name: $PROJECT_NAME" -ForegroundColor White
        Write-Host "  4. Import File: File -> Import File" -ForegroundColor White
        Write-Host "  5. Select: $BINARY" -ForegroundColor White
        Write-Host "  6. Processor: ARM (v7, Little Endian)" -ForegroundColor White
        Write-Host "  7. Run Auto-Analysis: Yes" -ForegroundColor White
        Write-Host ""
        Write-Host "Target Functions to Analyze:" -ForegroundColor Yellow
        Write-Host "  - modem2_modem_carrier_unlock (PRIMARY)" -ForegroundColor Green
        Write-Host "  - modem2_modem_validate_spc" -ForegroundColor Green
        Write-Host "  - modem2_modem_get_carrier_unlock_status" -ForegroundColor Green
        Write-Host ""
        
        # Launch Ghidra
        Set-Location $GHIDRA_DIR
        Start-Process -FilePath "$GHIDRA_DIR\ghidraRun.bat" -WorkingDirectory $GHIDRA_DIR
        
        Write-Host "[+] Ghidra launched!" -ForegroundColor Green
    }
    
    "2" {
        Write-Host "[*] Running headless analysis..." -ForegroundColor Yellow
        Write-Host "    This may take 5-10 minutes..." -ForegroundColor Gray
        
        $headlessCmd = "$GHIDRA_DIR\support\analyzeHeadless.bat"
        $args = @(
            $PROJECT_DIR,
            $PROJECT_NAME,
            "-import", $BINARY,
            "-processor", "ARM:LE:32:v7",
            "-cspec", "default",
            "-analysisTimeoutPerFile", "600",
            "-scriptPath", "F:\repo\zerosms\analysis",
            "-postScript", "ghidra_unlock_analysis.py"
        )
        
        Write-Host "[*] Command: $headlessCmd $($args -join ' ')" -ForegroundColor Gray
        
        & $headlessCmd @args
        
        Write-Host ""
        Write-Host "[+] Analysis complete!" -ForegroundColor Green
        Write-Host "[*] Check: $PROJECT_DIR" -ForegroundColor Cyan
    }
    
    "3" {
        Write-Host "[*] Binary Information:" -ForegroundColor Yellow
        Write-Host ""
        
        # Use file command if available (via Git Bash or WSL)
        $fileCmd = Get-Command "file" -ErrorAction SilentlyContinue
        if ($fileCmd) {
            Write-Host "File Details:" -ForegroundColor Cyan
            & file $BINARY
        }
        
        Write-Host ""
        Write-Host "Strings Analysis (First 50 functions):" -ForegroundColor Cyan
        $bytes = [System.IO.File]::ReadAllBytes($BINARY)
        $text = [System.Text.Encoding]::ASCII.GetString($bytes)
        $functions = [regex]::Matches($text, 'modem2_[a-zA-Z0-9_]+|nwqmi_[a-zA-Z0-9_]+|dsm_[a-zA-Z0-9_]+')
        $uniqueFuncs = $functions.Value | Sort-Object -Unique | Select-Object -First 50
        
        $unlockFuncs = $uniqueFuncs | Where-Object { $_ -match 'unlock|carrier|spc|validate|imei' }
        
        Write-Host ""
        Write-Host "Unlock-Related Functions Found:" -ForegroundColor Green
        $unlockFuncs | ForEach-Object { Write-Host "  - $_" -ForegroundColor White }
        
        Write-Host ""
        Write-Host "Total Functions Discovered: $($uniqueFuncs.Count)" -ForegroundColor Cyan
    }
    
    default {
        Write-Host "[!] Invalid selection" -ForegroundColor Red
        exit 1
    }
}

Write-Host ""
Write-Host "=" * 70 -ForegroundColor Cyan
Write-Host "Analysis Session Complete" -ForegroundColor Cyan
Write-Host "=" * 70 -ForegroundColor Cyan
