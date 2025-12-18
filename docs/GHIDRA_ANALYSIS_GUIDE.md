# Ghidra Analysis Guide - libmal_qct.so & nwcli

## Overview

This guide covers the deep analysis of two critical binaries:

1. **libmal_qct.so** (307,292 bytes) - Carrier unlock library
2. **nwcli** (25,500 bytes) - Network CLI tool with write_nv bug

**Objectives**:

- Understand carrier unlock challenge-response algorithm
- Locate and fix write_nv bug in nwcli (offset 0x4404)
- Extract unlock keys/validation logic
- Document findings for safe unlock implementation

---

## Setup Instructions

### 1. Launch Ghidra

Ghidra should already be running. If not:

```powershell
Start-Process -FilePath "F:\download\ghidra_11.4.3_PUBLIC_20251203\ghidra_11.4.3_PUBLIC\ghidraRun.bat"
```

### 2. Create New Project

1. File → New Project
2. Select "Non-Shared Project"
3. Project Directory: `F:\repo\007smsdev\analysis\ghidra_projects`
4. Project Name: `mifi_8800l_analysis`
5. Click "Finish"

### 3. Import libmal_qct.so

1. File → Import File
2. Navigate to: `F:\repo\007smsdev\analysis\binaries\libmal_qct.so`
3. Format: **ELF (Executable and Linkable Format)**
4. Language: **ARM:LE:32:v7** (ARM 32-bit little-endian, ARMv7)
5. Click "OK" → "OK" (accept default options)
6. When prompted: "Would you like to analyze now?" → **YES**
7. Analysis Options:
   - ✅ Decompiler Parameter ID
   - ✅ Function Start Search
   - ✅ ARM Aggressive Instruction Finder
   - ✅ Create Address Tables
   - ✅ Embedded Media
   - ✅ Non-Returning Functions
   - ✅ Reference
   - ✅ Shared Return Calls
   - ✅ Stack
8. Click "Analyze" and wait (may take 2-5 minutes)

### 4. Import nwcli

Repeat steps 1-8 above for:

- File: `F:\repo\007smsdev\analysis\binaries\nwcli`
- Same settings: ELF, ARM:LE:32:v7

---

## Part 1: libmal_qct.so Analysis

### Target: Carrier Unlock Algorithm

#### Step 1: Search for String References

1. **Search → For Strings...**
2. Filter settings:
   - Minimum Length: 5
   - Search: Memory Block (all)
3. Look for strings containing:
   - "unlock"
   - "carrier"
   - "lock"
   - "challenge"
   - "response"
   - "validate"
   - "auth"
   - "SPC" (Service Programming Code)
   - "MSL" (Master Subsidy Lock)
   - "IMEI"
   - "MCC/MNC" (Mobile Country/Network Code)

#### Step 2: Locate Unlock Functions

**Expected function names** (search in Symbol Tree):

- `carrier_unlock_validate`
- `check_unlock_status`
- `get_unlock_challenge`
- `verify_unlock_code`
- `calculate_unlock_response`
- `imei_to_unlock_key`

**Search Strategy**:

1. Window → Functions
2. Filter: Type "unlock" in filter box
3. Double-click each function to view decompilation
4. Look for:
   - IMEI reading (likely via NV 550 or QMI DMS)
   - Challenge generation (likely uses IMEI + salt)
   - Response validation (compares input vs calculated)
   - Lock status checks (reads NV 3461, 4395, 4399)

#### Step 3: Analyze Unlock Challenge Generation

**Key algorithm patterns to look for**:

**Pattern 1: IMEI-based unlock (most common)**

```c
// Pseudocode expected
uint32_t generate_unlock_code(char* imei) {
    uint32_t hash = 0;
    for (int i = 0; i < 15; i++) {
        hash = (hash * 31) + (imei[i] - '0');
    }
    return hash ^ SECRET_XOR_KEY;  // Look for this constant
}
```

**Pattern 2: Challenge-response (Sierra style)**

```c
// Device sends challenge (random or IMEI-derived)
uint32_t challenge = generate_challenge(imei);

// User calculates response offline
uint32_t response = calculate_response(challenge, MASTER_KEY);

// Device validates
if (validate_response(challenge, response)) {
    set_unlock_status(UNLOCKED);  // Write NV 3461 = 0x00
}
```

**Pattern 3: Direct code validation (Qualcomm style)**

```c
// User enters 8-digit unlock code
bool validate_unlock_code(char* code) {
    char* imei = read_imei();  // From NV 550
    char expected[9];
    generate_unlock_code(imei, expected);  // Proprietary algorithm
    return strcmp(code, expected) == 0;
}
```

#### Step 4: Find NV Write Operations

Search for NV write calls:

1. Search → For Strings: "nv_write", "qmi_nv", "diag_nv"
2. Look for functions calling:
   - `qmi_nv_write_item()` - QMI NV service
   - `diag_nv_write()` - DIAG protocol
   - System calls to `/dev/smd*` or `/dev/diag`

**Expected unlock flow**:

```c
bool unlock_carrier(char* unlock_code) {
    if (!validate_unlock_code(unlock_code)) {
        return false;  // Invalid code
    }
    
    // Write unlock status to NV items
    nv_write(3461, 0x00);  // Clear carrier lock
    nv_write(4395, 0x00);  // Clear lock bitmask
    nv_write(4399, 0x00);  // Disable enforcement
    
    return true;
}
```

#### Step 5: Extract Constants

Look for **hardcoded constants** used in unlock algorithm:

- XOR keys (e.g., `0xDEADBEEF`, `0x12345678`)
- Hash seeds (e.g., `0x5A5A5A5A`)
- Lookup tables (arrays of magic numbers)
- Salt values appended to IMEI

**How to find**:

1. Navigate to function containing unlock algorithm
2. Right-click on constants in decompiler → "Set Equate" to label them
3. Look for repeated constants across multiple functions
4. Check `.rodata` section (read-only data) for large arrays

#### Step 6: Document Algorithm

Create Python reference implementation:

```python
def mifi_8800l_unlock_code(imei: str) -> str:
    """
    Generate carrier unlock code for MiFi 8800L
    
    Args:
        imei: 15-digit IMEI string
        
    Returns:
        8-digit unlock code
        
    Example:
        >>> mifi_8800l_unlock_code("990016878573987")
        "12345678"  # Replace with actual algorithm
    """
    # TODO: Implement based on Ghidra findings
    pass
```

---

## Part 2: nwcli write_nv Bug Analysis

### Target: Offset 0x4404 Bug

#### Step 1: Locate write_nv Function

1. Window → Functions
2. Filter: "write_nv" or "nv_write"
3. Double-click function to open in decompiler

**Alternative search**:

1. Go to address: Press "G" → Enter `0x4404`
2. View disassembly at offset 0x4404
3. Right-click → "Create Function" if not auto-detected
4. Switch to decompiler view

#### Step 2: Analyze Bug Pattern

**Expected bug patterns**:

**Bug Type 1: Buffer overflow**

```c
void write_nv(int nv_id, char* data, int len) {
    char buffer[256];
    memcpy(buffer, data, len);  // ⚠️ No bounds check!
    // If len > 256, buffer overflow
    send_to_modem(buffer, len);
}
```

**Bug Type 2: Null pointer dereference**

```c
void write_nv(int nv_id, char* data, int len) {
    if (data == NULL) {
        return ERROR;  // ⚠️ Should return here
    }
    // Missing return - continues execution
    int result = process_data(data);  // ⚠️ Crashes if data == NULL
}
```

**Bug Type 3: Integer overflow**

```c
void write_nv(int nv_id, char* data, int len) {
    if (len > MAX_NV_SIZE) {
        len = MAX_NV_SIZE;
    }
    char* buffer = malloc(len + 1);  // ⚠️ If len = 0xFFFFFFFF, wraps to 0
    memcpy(buffer, data, len);       // ⚠️ Writes beyond allocated memory
}
```

**Bug Type 4: Incorrect validation**

```c
void write_nv(int nv_id, char* data, int len) {
    if (nv_id < 0 || nv_id > 10000) {  // ⚠️ Wrong check
        return ERROR;
    }
    // Should check: if (nv_id < 0 || nv_id > 65535)
    // Bug allows invalid NV IDs 10001-65535 through
}
```

#### Step 3: Find Root Cause

1. Look for **missing validation** on line before crash
2. Check **bounds checks** on buffer operations
3. Look for **unchecked return values** from malloc/read/write
4. Check for **race conditions** in multi-threaded code

#### Step 4: Develop Workaround

**Workaround Option 1: Patch binary**

```python
# If bug is at offset 0x4404, patch with NOP or jump
import struct

def patch_nwcli(binary_path):
    with open(binary_path, 'r+b') as f:
        f.seek(0x4404)
        # Replace buggy instruction with NOP (0x00 0x00 0xA0 0xE1 for ARM)
        f.write(struct.pack('<I', 0xE1A00000))  # MOV R0, R0 (NOP)
```

**Workaround Option 2: Use QMI directly**

```python
# Bypass nwcli, use QMI NV service directly via libqmi
import subprocess

def qmi_nv_write(nv_id, data):
    """Write NV item using QMI instead of buggy nwcli"""
    hex_data = data.hex()
    cmd = f'qmicli -d /dev/cdc-wdm0 --dms-write-nv={nv_id},{hex_data}'
    result = subprocess.run(cmd, shell=True, capture_output=True)
    return result.returncode == 0
```

**Workaround Option 3: Use modem2_cli**

```python
# If modem2_cli has working NV write
def modem2_nv_write(nv_id, data):
    """Use modem2_cli write_nv function via raw command"""
    cmd = f'modem2_cli cmd_write_efs_file /nv/item_{nv_id} {data.hex()}'
    result = subprocess.run(cmd, shell=True, capture_output=True)
    return b'Success' in result.stdout
```

#### Step 5: Verify Fix

1. Test patched binary on device
2. Attempt safe NV write (non-critical item like NV 108)
3. Verify write succeeded with `nv_read`
4. Document fix in code comments

---

## Part 3: Cross-Reference Analysis

### Link libmal_qct.so → nwcli

**Goal**: Understand if libmal_qct.so uses nwcli for NV writes

#### Check Shared Libraries

1. In libmal_qct.so Symbol Tree:
   - Look for: `nv_write`, `write_nv`, `nwcli` strings
2. Check External References (Window → External Programs)
   - Does libmal_qct.so link to nwcli or its libraries?

#### Check System Calls

1. Search → For Strings: "/usr/bin/nwcli", "/opt/nvtl/bin/nwcli"
2. If found, libmal_qct.so likely calls nwcli as subprocess
3. Analyze `system()`, `popen()`, or `execve()` calls

#### Alternative NV Write Methods

If libmal_qct.so avoids nwcli:

- Look for direct QMI calls: `qmi_client_send_msg_sync()`
- Look for DIAG protocol: `/dev/diag`, `/dev/smd*`
- Look for direct file writes: `/nv/item_*` paths

**Recommendation**: If libmal_qct.so has working NV write, extract and use its method instead of buggy nwcli.

---

## Part 4: Documentation Standards

### Function Documentation Template

For each discovered function, document:

```markdown
### Function: carrier_unlock_validate

**Location**: libmal_qct.so @ 0x00012A40
**Prototype**: `bool carrier_unlock_validate(char* unlock_code)`
**Purpose**: Validates 8-digit carrier unlock code against IMEI-derived expected value

#### Algorithm
1. Read IMEI from NV 550 (via qmi_dms_get_imei)
2. Calculate hash: `hash = imei_hash(imei) ^ 0xDEADBEEF`
3. Format as 8-digit string: `sprintf(expected, "%08X", hash)`
4. Compare input code to expected
5. If match: Write NV 3461 = 0x00, NV 4395 = 0x00, NV 4399 = 0x00

#### Constants
- XOR_KEY: `0xDEADBEEF` (found @ .rodata+0x1A4C)
- HASH_SEED: `0x5A5A5A5A` (found @ .rodata+0x1A50)

#### Dependencies
- qmi_dms_get_imei() - QMI DMS service
- nv_write() - NV write function (uses QMI, not nwcli)

#### Security Analysis
- ⚠️ Weak algorithm: XOR key is static (can be reversed)
- ✅ No network validation required (offline unlock possible)
- ⚠️ No rate limiting (brute force possible if key leaked)
```

---

## Expected Outcomes

### libmal_qct.so Analysis

**Minimum findings**:

1. ✅ Unlock algorithm identified (IMEI hash + XOR key)
2. ✅ Constants extracted (XOR keys, salts, lookup tables)
3. ✅ NV write method discovered (QMI vs nwcli vs DIAG)
4. ✅ Python reference implementation created

**Stretch goals**:

- 🎯 Find alternative unlock methods (backdoor codes, OEM keys)
- 🎯 Identify carrier-specific variants (Sprint vs AT&T vs Verizon)
- 🎯 Extract firmware update validation keys

### nwcli Analysis

**Minimum findings**:

1. ✅ Bug root cause identified (buffer overflow, null deref, etc.)
2. ✅ Patch developed (binary patch or workaround)
3. ✅ Safe NV write method documented (QMI or modem2_cli)

**Stretch goals**:

- 🎯 Submit bug report to Inseego/Sierra Wireless
- 🎯 Develop automated patching tool
- 🎯ネFind other bugs in nwcli (security audit)

---

## Safety Reminders

### ⚠️ DO NOT on Production Device

- Modify binaries without backup
- Test experimental unlock codes
- Write to NV items without verification
- Flash modified firmware

### ✅ SAFE on Development Device

- Read-only analysis (Ghidra)
- NV reads (never writes)
- String extraction
- Algorithm documentation

### 🧪 Test Only on Development Device

- Patched binary testing
- Experimental NV writes (backup first!)
- Unlock code testing (backup IMEI!)

---

## Next Steps After Analysis

1. **Document findings** in `GHIDRA_FINDINGS.md`
2. **Implement unlock algorithm** in `mifi_controller.py`
3. **Test on development device** (never production!)
4. **Create backup procedure** before any unlock attempt
5. **Update implementation status** (80 remaining commands)

---

*Guide created: Session 7*  
*Binaries ready: libmal_qct.so (307KB), nwcli (25KB)*  
*Ghidra version: 11.4.3*  
*Target device: MiFi 8800L (SDx20ALP-1.22.11)*
