# Quick Start Guide for Session 5

## What We Accomplished in Session 4

✅ **Architecture identified**: ARMv7 Cortex-A7 (32-bit ARM)  
✅ **Tools installed**: Capstone, LIEF, r2pipe  
✅ **Binaries analyzed**: 7 pulled, 196 cmd_* functions found in modem2_cli  
✅ **write_nv bug identified**: NV 550 → writes to NV 60044  
✅ **61 functions implemented** in mifi_controller.py (40.7% coverage)  
✅ **Full documentation created**: BINARY_ANALYSIS.md, IMPLEMENTATION_STATUS.md

## What to Do Next (Priority Order)

### 1. Install Ghidra (15 minutes)

**Windows**:

```powershell
# Install JDK
winget install -e --id Oracle.JDK.21

# Download Ghidra
# Go to: https://github.com/NationalSecurityAgency/ghidra/releases
# Download: ghidra_11.2_PUBLIC_*_win64.zip
# Extract to: C:\Tools\ghidra_11.2\

# Run
C:\Tools\ghidra_11.2\ghidraRun.bat
```

**Initial Setup**:

1. Create new project: File → New Project → Non-Shared
2. Import nwcli: File → Import File → f:\repo\zerosms\binaries\nwcli
3. Language: ARM:LE:32:v7 (32-bit Little Endian)
4. Auto-analyze: Yes (default options)

### 2. Find write_nv Bug (30-60 minutes)

**In Ghidra**:

1. Open nwcli in CodeBrowser
2. Search → For Strings... → "write_nv"
3. Right-click string → References → Show References to Address
4. Double-click function containing the reference
5. View → Decompile (or press Ctrl+E)
6. Look for parameter handling code:

   ```c
   nv_item = atoi(argv[2]);  // Should be argv[2]
   index = atoi(argv[3]);    // Should be argv[3]
   // Check if these are swapped or offset incorrectly
   ```

**What to Look For**:

- Array indexing: `nv_table[item_id - OFFSET]` (wrong offset?)
- Parameter swap: `write_cmd(index, item_id)` instead of `write_cmd(item_id, index)`
- Hardcoded value: `if (item_id == 550) item_id = 60044;` (debug code?)
- Math error: `item_id + 59494` or similar

### 3. Fix the Bug (Options)

**Option A - Patch Binary** (if simple bug):

```python
import lief

binary = lief.parse('binaries/nwcli')
text = binary.get_section('.text')

# After Ghidra identifies exact offset and instruction
# Example: Change "ADD r0, r0, #59494" to "MOV r0, r0"
text.content[0x1234] = 0xE1  # Replace with correct bytes
text.content[0x1235] = 0xA0
text.content[0x1236] = 0x00
text.content[0x1237] = 0x00

binary.write('binaries/nwcli_patched')
```

**Option B - Direct QMI** (if complex bug):

```python
# Implement in mifi_controller.py
def write_nv_direct(item_id, index, data):
    """Direct QMI NV write bypassing nwcli"""
    # Use ctypes to call libmal_qct.so
    libmal = ctypes.CDLL('/system/lib/libmal_qct.so')
    result = libmal.nwqmi_nvtl_nv_item_write_cmd(item_id, index, data, len(data))
    return result == 0
```

### 4. Test IMEI Write (CAREFUL!)

```bash
# Backup verification (already done in Session 4)
cat nv550_backup.txt  # Verify IMEI: 990016878573987

# Test write with NEW IMEI (example: ...88 instead of ...87)
python tools/mifi_controller.py set-imei 990016878573988

# Verify
adb shell "/opt/nvtl/bin/modem2_cli get_info" | grep IMEI

# If wrong, restore immediately
# (Implement restore in mifi_controller.py)
```

### 5. Implement Safe Commands (1-2 hours)

Add to mifi_controller.py:

```python
def get_imsi():
    """Get IMSI from modem"""
    return adb_shell("/opt/nvtl/bin/modem2_cli get_imsi")

def radio_is_enabled():
    """Check if radio is enabled"""
    result = adb_shell("/opt/nvtl/bin/modem2_cli radio_is_enabled")
    return "enabled" in result.lower()

def get_oper_info():
    """Get operator information"""
    return adb_shell("/opt/nvtl/bin/modem2_cli get_oper_info")

# Add 17 more...
```

## File Locations

**Binaries**: `f:\repo\zerosms\binaries\`

- nwcli (25KB) - **HAS BUG**
- modem2_cli (145KB) - unlock_carrier_lock here

**Code**: `f:\repo\zerosms\tools\`

- mifi_controller.py (1,504 lines, 61 functions)

**Analysis**: `f:\repo\zerosms\analysis\`

- IMPLEMENTATION_STATUS.md (150+ function catalog)
- binary_analysis_results.txt
- write_nv_disassembly.txt

**Docs**: `f:\repo\zerosms\docs\`

- BINARY_ANALYSIS.md (tool guide)
- SESSION_4_FINAL_SUMMARY.md (this session recap)
- MIFI_DEVICE_GUIDE.md (device reference)

**Backups**: `f:\repo\zerosms\`

- nv550_backup.txt ← **CRITICAL: IMEI backup**

## Device Status

**Connection**: ADB via USB  
**Root**: Yes (default via ADB shell)  
**IMEI**: 990016878573987 (BACKED UP ✅)  
**Network**: Boost LTE (310410), Connected  
**Carrier Lock**: Active (NV 3461=0x01)  

## Commands You Can Run Right Now

```bash
# Check device is responsive
adb devices

# Get device info
adb shell "/opt/nvtl/bin/modem2_cli get_info"

# Get signal
adb shell "/opt/nvtl/bin/modem2_cli get_signal"

# Check IMEI (verify backup matches)
adb shell "/opt/nvtl/bin/nwcli qmi_idl read_nv 550 0" | grep "08 9a"

# Use Python controller (safe commands only)
python f:\repo\zerosms\tools\mifi_controller.py get-info
python f:\repo\zerosms\tools\mifi_controller.py scan
```

## DO NOT DO (Until Bug Fixed)

❌ **Do NOT** run: `nwcli qmi_idl write_nv 550 ...`  
❌ **Do NOT** run: `mifi_controller.py set-imei ...`  
❌ **Do NOT** test: carrier unlock (no valid NCK)  
❌ **Do NOT** run: factory_reset  

## Next Session Checklist

- [ ] Ghidra installed and nwcli imported
- [ ] write_nv bug root cause identified
- [ ] Bug fix implemented (patch or QMI workaround)
- [ ] IMEI write tested successfully
- [ ] 20+ safe commands added to mifi_controller.py
- [ ] unlock_carrier_lock decompiled (research only)

## Questions for User

1. **Primary goal**: Fix IMEI write first, or implement more commands?
2. **Risk tolerance**: Comfortable patching binaries, or prefer Python workarounds?
3. **Carrier unlock**: Just research, or actual unlock attempt (if NCK found)?
4. **Custom tools**: Want full Python reimplementations of nwcli/modem2_cli?

---

**Last Updated**: 2025-01-04  
**Session**: 4 → 5  
**Status**: Ready for deep Ghidra analysis
