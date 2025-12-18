# Phase 5: Device Extraction & Testing Guide

**CRITICAL:** Use SAFE extraction method (userspace tools, NOT dd)

## Quick Start

### Step 1: Verify Device Connection

```powershell
adb devices
```

**Expected Output:**

```
List of devices attached
0123456789ABCDEF       device
```

If no device listed → Device offline. See "Device Recovery" section below.

### Step 2: Verify Extraction Scripts

```powershell
cd f:\repo\007smsdev
ls tools/phase5_*.sh
```

Should show:

- `phase5_safe_efs2_extraction.sh` ✅
- `phase5_locking_analysis.sh` ✅
- `phase5_download_arm_tools.sh` ✅

### Step 3: Push Extraction Scripts to Device

```powershell
adb push tools/phase5_safe_efs2_extraction.sh /tmp/
adb push tools/phase5_locking_analysis.sh /tmp/
adb push tools/phase5_download_arm_tools.sh /tmp/
```

### Step 4: Make Scripts Executable

```powershell
adb shell "chmod +x /tmp/phase5_safe_efs2_extraction.sh"
adb shell "chmod +x /tmp/phase5_locking_analysis.sh"
adb shell "chmod +x /tmp/phase5_download_arm_tools.sh"
```

### Step 5: Execute Safe Extraction

```powershell
adb shell "sh /tmp/phase5_safe_efs2_extraction.sh /tmp/phase5_backup 2>&1"
```

**Watch for:**

- ✅ "Backup directory: /tmp/phase5_backup/..." → Script started
- ✅ "Device status captured" → Modem info extracted
- ✅ "NV analysis complete" → NV items extracted
- ✅ "EFS2 safe extraction" → Safe method in progress
- ✅ "Extraction Complete!" → Success! Device still online
- ❌ Device reboots → Problem with watchdog (try alternative method)

### Step 6: Pull Extracted Data

```powershell
mkdir -p phase5_extraction_local
adb pull /tmp/phase5_backup phase5_extraction_local/
```

### Step 7: Execute Locking Analysis

```powershell
adb shell "sh /tmp/phase5_locking_analysis.sh /tmp/phase5_analysis 2>&1"
adb pull /tmp/phase5_analysis phase5_extraction_local/
```

### Step 8: Verify Data

```powershell
cd phase5_extraction_local
ls -la
```

Should contain:

- `/phase5_backup/nv_items/` - NV item dumps
- `/phase5_backup/efs2_safe/` - EFS2 extracts
- `/phase5_backup/fota/` - FOTA data
- `/phase5_analysis/nv_analysis/` - NV analysis
- `/phase5_analysis/policy_analysis/` - Lock policies

---

## Device Recovery (If Offline)

### Quick Reconnection

```powershell
# Power cycle
adb reboot

# Wait 30 seconds
Start-Sleep -Seconds 30

# Check status
adb devices
```

### If Still Offline

```powershell
# Kill ADB server
adb kill-server

# Start fresh
adb start-server

# Check again
adb devices -l
```

### Force Reconnection

```powershell
# Plug device in via USB
# Verify in Device Manager that ADB device is present

# Add vendor ID if needed (MiFi 1410)
Add-Content -Path $env:USERPROFILE\.android\adb_usb.ini -Value "0x1410"

# Restart server
adb kill-server
adb start-server
adb devices
```

### Last Resort: Device Reboot

```powershell
# Software reboot (if device responsive)
adb shell "reboot"

# Wait 60 seconds
Start-Sleep -Seconds 60

# Check status
adb devices
```

---

## Expected Extraction Outputs

### NV Items (Critical)

Location: `/tmp/phase5_backup/nv_items/nv_*.txt`

**Important Items:**

```
nv_item_550.txt        -> IMEI (device identifier)
nv_item_3461.txt       -> SIM Lock Status (1 = locked)
nv_item_4399.txt       -> Subsidy Lock Status (1 = verizon only)
nv_item_60044.txt      -> PRI Version (WRITABLE!)
```

### EFS2 Extraction

Location: `/tmp/phase5_backup/efs2_safe/`

**Possible Files:**

- `qmi_read_attempt.log` - QMI method result
- `modem2_efs_attempt.log` - modem2_cli method result
- `efs2_safe_backup.tar.gz` - Full EFS2 backup (if mounted)
- `mounted_fs.txt` - Mounted filesystem info

### FOTA Data

Location: `/tmp/phase5_backup/fota/`

**Contains:**

- `config.xml` - FOTA configuration
- `update_log.txt` - Update history
- `build_cert.pem` - Verizon signature certificate
- `device.pem` - Device certificate

### Modem Info

Location: `/tmp/phase5_backup/modem_info/`

**Contains:**

- `device_info.txt` - IMEI, IMSI, ICCID, firmware version
- `modem_state.txt` - Current connection state
- `signal_strength.txt` - Signal strength and bands
- `sim_status.txt` - SIM card status

---

## Troubleshooting

### Problem: "Device did not reboot" (Expected!)

**This is GOOD!** Means safe extraction method worked.

If device rebooted instead:

- EFS2 protection was triggered by wrong method
- Never use `dd if=/dev/mtd2` on this device
- Stick with modem2_cli and nwcli only

### Problem: "adb: device offline"

**Solution:**

```powershell
adb kill-server
adb start-server
adb devices
```

Wait 10-15 seconds between commands.

### Problem: "Permission denied" errors

**Solution:** Verify root access

```powershell
adb shell "id"
```

Should show: `uid=0(root) gid=0(root)`

If not root:

```powershell
# On device: Enable developer options
# On device: Enable USB debugging
# Reconnect ADB
adb shell su  # Should not prompt
```

### Problem: "/opt/nvtl/bin/modem2_cli: not found"

**Solution:** Device is not MiFi 8800L (wrong device type)

Check device OS:

```powershell
adb shell "cat /etc/os-release"
```

Should show MiFiOS2. If shows Android → Wrong procedure.

### Problem: Script timeout

**Solution:** Increase timeout and retry

```powershell
adb shell "timeout 300 sh /tmp/phase5_safe_efs2_extraction.sh /tmp/phase5_backup"
```

30-second timeout by default. Increase to 300 (5 minutes).

---

## Safety Checklist

Before running extraction:

- [ ] Device connected via USB (`adb devices` shows device)
- [ ] Root access confirmed (`adb shell id` shows uid=0)
- [ ] Device is MiFi 8800L (`adb shell getprop ro.build.product` shows "MIFI8800L" or similar)
- [ ] Scripts are present on device (`adb shell ls /tmp/phase5_*.sh` shows all 3)
- [ ] Backup directory writable (`adb shell touch /tmp/test_write.txt` succeeds)
- [ ] Device has space (`adb shell df | grep -E /tmp` shows >100 MB free)

### Critical: DO NOT USE

❌ `dd if=/dev/mtd2 of=efs2.bin` - WILL CAUSE REBOOT  
❌ Raw `/dev/smd*` access without modem2_cli wrapper  
❌ Any low-level MTD operations during extraction  
❌ Multiple simultaneous ADB sessions  

### Critical: DO USE

✅ `modem2_cli nv read` - Safe NV access  
✅ `modem2_cli efs_read` - Safe EFS access  
✅ `nwcli qmi_idl read_file` - Safe firmware-aware access  
✅ `tar -czf` - Safe filesystem backup  

---

## Data Organization After Extraction

Once data is pulled locally:

```
phase5_extraction_local/
├── phase5_backup/
│   ├── nv_items/              ← Carrier lock data
│   │   ├── nv_3461.txt        ← SIM Lock Status
│   │   ├── nv_4399.txt        ← Subsidy Lock
│   │   ├── nv_60044.txt       ← PRI Version
│   │   └── ... (15 more)
│   ├── efs2_safe/             ← EFS2 backup attempts
│   ├── fota/                  ← FOTA mechanism data
│   ├── modem_info/            ← Device info
│   ├── carrier_config/        ← Carrier policies
│   └── EXTRACTION_SUMMARY.txt ← Summary
├── phase5_analysis/
│   ├── nv_analysis/           ← NV analysis
│   ├── config_analysis/       ← Config file analysis
│   ├── policy_analysis/       ← Lock policy breakdown
│   └── LOCKING_RESEARCH_SUMMARY.txt
```

### Next: Binary Analysis

Copy key binaries to analysis folder:

```powershell
cp mifi_backup/binaries/libmodem2_api.so phase5_extraction_local/
cp mifi_backup/binaries/libmal_qct.so phase5_extraction_local/
```

Ready for Ghidra analysis:

1. Start Ghidra
2. Import `libmodem2_api.so`
3. Run `arm_analysis_tools/ghidra_spc_analyzer.py`
4. Document findings

---

## Timeline Estimate

| Task | Time | Status |
|------|------|--------|
| Device reconnection | 2-5 min | ⏳ |
| Script push | 1 min | ⏳ |
| Safe extraction | 5-10 min | ⏳ |
| Data pull | 3-5 min | ⏳ |
| Analysis script | 5-10 min | ⏳ |
| **Total** | **20-35 min** | ⏳ |

After extraction:

| Task | Time | Status |
|------|------|--------|
| Ghidra setup | 10 min | ⏳ |
| Binary analysis | 2-4 hours | ⏳ |
| FOTA analysis | 1-2 hours | ⏳ |
| Documentation | 1-2 hours | ⏳ |
| SMS Test integration | 3-4 hours | ⏳ |
| **Total** | **7-12 hours** | ⏳ |

---

## Success Criteria

Extraction is successful when:

1. ✅ Device stays online throughout (no reboot)
2. ✅ All 18 NV items extracted (or documented as protected)
3. ✅ EFS2 data retrieved (full or partial)
4. ✅ FOTA certificates extracted
5. ✅ Carrier configuration parsed
6. ✅ Summary document generated
7. ✅ Data pulled to local machine
8. ✅ Analysis scripts completed
9. ✅ No errors in extraction logs

---

**Ready to proceed? Run: `adb devices`**

If device shows → You're ready!  
If no device → Follow Device Recovery section above.
