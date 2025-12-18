# Phase 5 Device Recovery & Reconnection Guide

**Status:** Device briefly connected, filesystem extraction started, then disconnected  
**Last Known State:** Filesystem extraction script running, EFS2 extraction in progress  
**Time:** 2025-12-04 ~22:00 UTC  

---

## What Happened

1. ✅ Device connected successfully (ID: 0123456789ABCDEF)
2. ✅ Verified root access and MiFiOS2 (Linux-based)
3. ✅ Pushed filesystem extraction script to /tmp/
4. ✅ Executed script - MTD partition enumeration completed
5. ✅ EFS2 extraction started
6. ❌ Device disconnected mid-extraction

---

## Device Recovery Steps

### Step 1: Physical Device Power Cycle (CRITICAL)

```
1. Locate power button on MiFi 8800L
2. Hold for 10-15 seconds until device powers off
3. Wait 5 seconds (complete shutdown)
4. Press power button again to restart
5. Wait 30-45 seconds for full boot
6. Check LED indicators for normal operation
```

### Step 2: USB Connection Verification

```
1. Check USB cable is firmly connected to both device and computer
2. Try different USB port on computer if available
3. Look for stable LED indicators on device
4. Check Windows Device Manager for "Unknown Device" (driver issue)
```

### Step 3: ADB Connection Test

```powershell
# Reset ADB server
adb kill-server
adb start-server
Start-Sleep -Seconds 2

# Verify device appears
adb devices -l

# If device appears: Proceed to Step 4
# If "unauthorized": Approve prompt on device or adb tcpip fallback
```

### Step 4: Check Device State

```bash
adb shell id                    # Verify root access
adb shell "ls -la /tmp/phase5_backup/" 2>/dev/null  # Check for partial extraction
adb shell "df -h | grep -E '^/dev|mtd|Filesystem'"  # Check storage
```

---

## If Partial Data Was Extracted

**Location:** `/tmp/phase5_backup/phase5_filesystem_20251204_214939/`

**To verify what was extracted:**

```bash
adb shell "find /tmp/phase5_backup/ -type f | head -20"
adb shell "du -sh /tmp/phase5_backup/*"
```

**Options:**

### Option A: Resume Extraction (Faster)

```bash
# Check if backup dir still has data
adb shell "ls -la /tmp/phase5_backup/phase5_filesystem_*/"

# If data exists, continue from where it stopped:
adb shell "sh /tmp/phase5_filesystem_extraction.sh /tmp/phase5_backup"
```

### Option B: Clean Restart (Safer)

```bash
# Remove incomplete backup
adb shell "rm -rf /tmp/phase5_backup"

# Restart extraction
adb shell "sh /tmp/phase5_filesystem_extraction.sh /tmp/phase5_backup"
```

---

## Expected Extraction Output

When script runs successfully, expect:

```
=== STEP 1: MTD Partition Extraction ===
[13 MTD devices extracted to /tmp/phase5_backup/mtd_*]

=== STEP 2: EFS2 Partition (Carrier Lock Data) ===
[180 MB carrier lock data extracted]

=== STEP 3: Modem Firmware ===
[315 MB modem firmware extracted]

=== STEP 4: Carrier Configuration Files ===
[XML configuration files extracted]

=== STEP 5: FOTA Update Files ===
[Firmware update scripts extracted]

=== STEP 6: SPC & NV Items ===
[NV item dumps extracted]

=== STEP 7: Binary Metadata ===
[Library and tool metadata extracted]

=== STEP 8: Summary Report ===
[Analysis summary created]

=== STEP 9: Compressed Archive ===
[All data compressed to backup.tar.gz]
```

**Typical duration:** 10-15 minutes  
**Total size:** ~500 MB-1 GB

---

## Data Transfer After Extraction

Once extraction completes successfully on device:

### Method 1: Pull All Data (Recommended)

```bash
# Create local directory
New-Item -ItemType Directory -Force -Path "F:\repo\007smsdev\mifi_backup\filesystem" -ErrorAction SilentlyContinue

# Pull backup directory
adb pull "/tmp/phase5_backup/" "F:\repo\007smsdev\mifi_backup\filesystem\"

# Alternative: Pull compressed archive (faster)
adb shell "cd /tmp && tar -czf phase5_backup.tar.gz phase5_backup/"
adb pull "/tmp/phase5_backup.tar.gz" "F:\repo\007smsdev\mifi_backup\filesystem\"
```

### Method 2: Pull Individual Files (Selective)

```bash
# Just the critical MTD partitions
adb pull "/tmp/phase5_backup/mtd0_sbl" "F:\repo\007smsdev\mifi_backup\filesystem\"
adb pull "/tmp/phase5_backup/mtd2_efs2" "F:\repo\007smsdev\mifi_backup\filesystem\"
adb pull "/tmp/phase5_backup/mtd8_modem" "F:\repo\007smsdev\mifi_backup\filesystem\"
```

---

## Parallel Activities (While Device Extraction Runs)

**These can be done WITHOUT the device:**

1. **Download Ghidra** (Free Binary Analysis Tool)

   ```bash
   # Download from: https://ghidra-sre.org
   # Or direct: https://ghidra-sre.org/ghidra_latest_build.zip
   ```

2. **Begin Binary Analysis** (Already Have Data)

   ```
   binaries already extracted to: mifi_backup/binaries/
   - libmodem2_api.so (144 KB) ⭐ Ready for analysis
   - libmal_qct.so (307 KB) ⭐ Ready for analysis
   ```

3. **Analyze FOTA Mechanism** (Already Have Data)

   ```
   Extracted firmware available in: mifi_backup/firmware/
   Configuration files available in: mifi_backup/config/
   ```

4. **Study Phase 4 Findings**

   ```
   Reference: docs/PHASE_4_TIER_BYPASS_FINDINGS.md
   Focus: NV 60044 is writable without SPC (confirmed bypass vector)
   ```

---

## If Device Won't Reconnect

### Troubleshooting

**Scenario 1: Device shows as "offline" in ADB**

```bash
# Try soft reboot
adb reboot

# Or hard reboot (force power cycle)
adb shell su -c "reboot -f"

# Wait 30 seconds, then try reconnection
adb devices
```

**Scenario 2: Device not appearing at all**

```bash
# Check Windows Device Manager
# Look for: "Android Device" or "Unknown Device"

# If showing as Unknown:
# - Install ADB drivers (Qualcomm drivers recommended)
# - Or right-click in Device Manager → Update driver → Browse computer
```

**Scenario 3: "No devices/emulators found" error**

```powershell
# Reset ADB completely
adb kill-server
Start-Sleep -Seconds 2
adb start-server
Start-Sleep -Seconds 2
adb devices

# Try alternative: Check if device is in recovery/fastboot
adb devices
fastboot devices
```

**Scenario 4: Device powers off unexpectedly**

```
Possible causes:
- Low battery → Charge device first
- Overheating → Let cool down for 10 minutes
- USB power insufficient → Try different USB port
- Device crash → Perform power cycle (hold power 15 seconds)
```

---

## Fallback: Offline Work Plan

**If device stays disconnected:**

Proceed with offline analysis using already-extracted binaries:

### Immediate (Next 2-4 hours)

1. Download Ghidra (free tool, 300 MB)
2. Open: `mifi_backup/binaries/libmodem2_api.so`
3. Run: `arm_analysis_tools/ghidra_spc_analyzer.py`
4. Analyze: SPC validation function location and logic
5. Document: Findings in `PHASE_5_SPC_ANALYSIS.md`

### Secondary (2-3 hours)

1. Analyze FOTA mechanism using extracted firmware
2. Research carrier lock protection layers
3. Compile all findings into `PHASE_5_FINDINGS.md`
4. Begin SMS Test integration design

### Tertiary (When Device Reconnects)

1. Reconnect and resume extraction
2. Perform live device testing
3. Verify offline findings with live modem
4. Complete Phase 5 with device confirmation

---

## Reconnection Checklist

When ready to attempt device reconnection:

- [ ] Power cycle completed (15+ seconds)
- [ ] USB cable connected firmly
- [ ] ADB server restarted (`adb kill-server && adb start-server`)
- [ ] Device appears in `adb devices` output
- [ ] Device status shows "device" (not "offline")
- [ ] `adb shell id` returns uid=0(root) confirmation
- [ ] Ready to execute extraction script

---

## Quick Commands Reference

```bash
# Device status
adb devices -l                    # Detailed device list
adb shell id                      # Verify root access
adb shell "df -h"                 # Check available storage

# Restart extraction
adb shell "sh /tmp/phase5_filesystem_extraction.sh /tmp/phase5_backup"

# Monitor progress
adb shell "du -sh /tmp/phase5_backup/"
adb shell "ls -la /tmp/phase5_backup/mtd*" | wc -l

# Transfer data
adb pull "/tmp/phase5_backup/" "F:\repo\007smsdev\mifi_backup\filesystem\"

# Emergency: Remove and restart
adb shell "rm -rf /tmp/phase5_backup"
adb shell "sh /tmp/phase5_filesystem_extraction.sh /tmp/phase5_backup"
```

---

## Expected Timeline (From Now)

```
Reconnection:           5 min  (device power cycle + ADB)
Extraction check:       2 min  (ls /tmp/phase5_backup/)
Resume/restart:        15 min  (script execution with monitoring)
Data transfer:         10 min  (adb pull to local storage)
─────────────────────────────
Subtotal:             32 min

Parallel offline work: 2-4 hrs (can start immediately)
Combined time:        2-5 hrs (if device reconnects soon)
```

---

## Next Actions (Immediate)

### Action 1: Attempt Device Reconnection (DO NOW)

```bash
# Power cycle device
# Wait 30-45 seconds for boot
# Then run:
adb devices -l
```

### Action 2: If Device Reconnects

```bash
# Immediately pull any extracted data
adb shell "ls -la /tmp/phase5_backup/" 2>/dev/null

# If data exists, pull it
adb pull "/tmp/phase5_backup/" "mifi_backup/filesystem/"

# Resume/complete extraction if needed
adb shell "sh /tmp/phase5_filesystem_extraction.sh /tmp/phase5_backup"
```

### Action 3: If Device Stays Offline

```bash
# Proceed with offline binary analysis
# Download Ghidra and analyze libmodem2_api.so
# Prepare PHASE_5_SPC_ANALYSIS.md
# Can do this for 2-4 hours while awaiting reconnection
```

---

## Success Indicators

✅ **Successful Reconnection:**

- `adb devices` shows device with "device" status
- `adb shell id` returns root access
- `/tmp/phase5_backup/` directory exists with partial data
- Can resume extraction script

✅ **Successful Extraction:**

- Script completes with "STEP 9: Compressed Archive" message
- `/tmp/phase5_backup.tar.gz` file created (~500 MB)
- `adb pull` completes successfully
- Data appears in `mifi_backup/filesystem/`

✅ **Successful Parallel Analysis:**

- Ghidra successfully loads libmodem2_api.so
- ghidra_spc_analyzer.py runs without errors
- SPC validation functions identified and documented

---

**Recovery Guide Status:** Complete  
**Primary Path:** Device reconnection → Resume extraction → Data transfer  
**Fallback Path:** Offline binary analysis (no device required)  
**Expected Resolution:** 30 minutes to 2 hours

When device comes back online, execute the commands in "Action 1" above.
