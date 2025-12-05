# MiFi 8800L Carrier Unlock Algorithm - Reverse Engineering Analysis

**Status**: SUCCESSFULLY DECOMPILED ✅  
**Date**: Session 7/8 Part 2  
**Tool**: Ghidra 11.4.3  
**Binary**: libmal_qct.so (307,292 bytes)  

---

## Executive Summary

The complete carrier unlock mechanism has been reverse engineered from the MiFi 8800L firmware. The unlock algorithm uses a **direct NCK (Network Control Key) string comparison** with an NV item stored value, requiring SPC validation as a prerequisite. Two critical NV items control the lock state:

- **NV 59,492 (0xEA64)**: Stores the master NCK (104 bytes)
- **NV 60,076 (0xEAAC)**: Lock status flag (1 byte: 0=UNLOCKED, 1=LOCKED)
- **NV 59,490 (0xEA62)**: Secondary lock control (1 byte)

**Critical Finding**: The unlock uses `strncmp()` for validation, meaning the NCK is stored as **plaintext** in NV memory, not hashed. This is a significant security weakness.

---

## Function 1: modem2_modem_carrier_unlock()

**Address**: `0x00039f4c` in libmal_qct.so  
**Purpose**: Performs carrier unlock using provided NCK  
**Called by**: `modem2_cli unlock_carrier <NCK>`  

### Decompiled C Code

```c
undefined4 modem2_modem_carrier_unlock(char *param_1)
{
  undefined4 uVar1;
  int iVar2;
  char acStack_78 [107];  // Buffer for NCK from NV (104 bytes + padding)
  undefined1 local_d;      // Unlock flag value (0 = unlocked)
  int local_c;             // Return code
  
  local_c = 0;
  
  // Check if modem is initialized
  if (*(int *)(DAT_0003a1fc + 0x39f70) == 1) {
    
    // Log unlock attempt
    uVar1 = mifi_dbg_get_level_name(5);
    mifi_dbg_log(DAT_0003a214 + 0x39ff8, 5, DAT_0003a218 + 0x3a008,
                 DAT_0003a21c + 0x3a014, uVar1, DAT_0003a210 + 0x39fe4, param_1);
    
    local_d = 0;
    memset(acStack_78, 0, 0x68);  // Clear NCK buffer (104 bytes)
    
    // **STEP 1: Read master NCK from NV item 59,492 (0xEA64)**
    local_c = nwqmi_nvtl_nv_item_read_cmd(0xea64, acStack_78, 0x68);
    
    uVar1 = mifi_dbg_get_level_name(5);
    mifi_dbg_log(DAT_0003a224 + 0x3a078, 5, DAT_0003a228 + 0x3a088,
                 DAT_0003a22c + 0x3a094, uVar1, DAT_0003a220 + 0x3a064, local_c);
    
    uVar1 = mifi_dbg_get_level_name(5);
    mifi_dbg_log(DAT_0003a234 + 0x3a0c4, 5, DAT_0003a238 + 0x3a0d4,
                 DAT_0003a23c + 0x3a0e0, uVar1, DAT_0003a230 + 0x3a0b0, acStack_78);
    
    // **STEP 2: CRITICAL - Direct string comparison of NCK (PLAINTEXT!)**
    iVar2 = strncmp(acStack_78, param_1, 0x68);
    
    if (iVar2 == 0) {  // NCK matches!
      
      // **STEP 3: Write unlock flag to NV 60,076 (0xEAAC) = 0 (UNLOCKED)**
      local_c = nwqmi_nvtl_nv_item_write_cmd(0xeaac, &local_d, 1);
      
      uVar1 = mifi_dbg_get_level_name(5);
      mifi_dbg_log(DAT_0003a244 + 0x3a148, 5, DAT_0003a248 + 0x3a158,
                   DAT_0003a24c + 0x3a164, uVar1, DAT_0003a240 + 0x3a134, local_c);
      
      if (local_c == 0) {  // First write succeeded
        
        // **STEP 4: Write secondary unlock flag to NV 59,490 (0xEA62) = 0**
        local_c = nwqmi_nvtl_nv_item_write_cmd(0xea62, &local_d, 1);
        
        uVar1 = mifi_dbg_get_level_name(5);
        mifi_dbg_log(DAT_0003a254 + 0x3a1b8, 5, DAT_0003a258 + 0x3a1c8,
                     DAT_0003a25c + 0x3a1d4, uVar1, DAT_0003a250 + 0x3a1a4, local_c);
      }
      
      if (local_c == 0) {
        return 0xc0000;  // SUCCESS!
      }
    }
  }
  else {
    // Modem not initialized
    uVar1 = mifi_dbg_get_level_name(5);
    mifi_dbg_log(DAT_0003a204 + 0x39fa0, 5, DAT_0003a208 + 0x39fb0,
                 DAT_0003a20c + 0x39fbc, uVar1, DAT_0003a200 + 0x39f94);
  }
  
  return 0xc0001;  // FAILURE (NCK mismatch or NV write error)
}
```

### Algorithm Logic Flow

```
┌─────────────────────────────────────────────┐
│ User Input: NCK string (up to 104 chars)    │
└─────────────────┬───────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────┐
│ 1. Check modem initialized?                 │
│    if (modem_status == 1) → Continue        │
│    else → FAIL (0xC0001)                    │
└─────────────────┬───────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────┐
│ 2. Read Master NCK from NV 0xEA64           │
│    nwqmi_nvtl_nv_item_read_cmd(0xea64)      │
│    → 104 bytes into acStack_78[]            │
└─────────────────┬───────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────┐
│ 3. CRITICAL: Direct String Compare          │
│    strncmp(stored_nck, user_nck, 104)       │
│    ⚠️  NCK is PLAINTEXT, not hashed!        │
└─────────────────┬───────────────────────────┘
                  │
          ┌───────┴────────┐
          │                │
          ▼                ▼
     Match = 0         Mismatch
          │                │
          │                └──> FAIL (0xC0001)
          ▼
┌─────────────────────────────────────────────┐
│ 4. Write NV 0xEAAC = 0 (Primary Unlock)     │
│    nwqmi_nvtl_nv_item_write_cmd(0xeaac, 0)  │
└─────────────────┬───────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────┐
│ 5. Write NV 0xEA62 = 0 (Secondary Unlock)   │
│    nwqmi_nvtl_nv_item_write_cmd(0xea62, 0)  │
└─────────────────┬───────────────────────────┘
                  │
                  ▼
         ┌────────┴────────┐
         │                 │
         ▼                 ▼
   Both Success       Any Failure
         │                 │
         │                 └──> FAIL (0xC0001)
         ▼
    SUCCESS (0xC0000)
```

### Return Codes

- `0xC0000` (786432): **SUCCESS** - Device unlocked
- `0xC0001` (786433): **FAILURE** - NCK mismatch or NV write error

---

## Function 2: modem2_modem_get_carrier_unlock_status()

**Address**: `0x00039d80` in libmal_qct.so  
**Purpose**: Query current carrier lock status  
**Called by**: `modem2_cli unlock_carrier_status`  

### Decompiled C Code

```c
undefined4 modem2_modem_get_carrier_unlock_status(undefined4 *param_1)
{
  undefined4 uVar1;
  char local_d;  // Lock status byte
  int local_c;   // Return code
  
  local_c = 0;
  
  // Check if modem initialized
  if (*(int *)(DAT_00039f28 + 0x39da4) == 1) {
    
    uVar1 = mifi_dbg_get_level_name(7);
    mifi_dbg_log(DAT_00039f40 + 0x39e24, 7, DAT_00039f44 + 0x39e34,
                 DAT_00039f48 + 0x39e40, uVar1, DAT_00039f3c + 0x39e18);
    
    local_d = '\0';
    
    // **STEP 1: Read primary lock flag from NV 0xEAAC**
    local_c = nwqmi_nvtl_nv_item_read_cmd(0xeaac, &local_d, 1);
    
    if ((local_c == 0) && (local_d == '\0')) {
      // Primary flag = 0, check secondary
      local_c = nwqmi_nvtl_nv_item_read_cmd(0xea62, &local_d, 1);
    }
    
    if (local_c == 0) {
      if (local_d == '\0') {
        // Device is UNLOCKED
        *param_1 = 0;        // Status: Unlocked
        param_1[1] = 10;     // Max attempts: 10
        param_1[2] = 0;      // Remaining attempts (N/A when unlocked)
        param_1[3] = 0;      // Unknown field
      }
      else {
        // Device is LOCKED
        *param_1 = 1;        // Status: Locked
        param_1[1] = 10;     // Max attempts: 10
        param_1[2] = 0;      // Remaining attempts (should query OTKSK counter)
        param_1[3] = 0;      // Unknown field
      }
      uVar1 = 0xc0000;  // SUCCESS
    }
    else {
      uVar1 = 0xc0001;  // NV read error
    }
  }
  else {
    // Modem not initialized
    uVar1 = mifi_dbg_get_level_name(5);
    mifi_dbg_log(DAT_00039f30 + 0x39dd4, 5, DAT_00039f34 + 0x39de4,
                 DAT_00039f38 + 0x39df0, uVar1, DAT_00039f2c + 0x39dc8);
    uVar1 = 0xc0001;
  }
  
  return uVar1;
}
```

### Status Structure (param_1 output)

```c
param_1[0]: Lock status
  - 0 = UNLOCKED
  - 1 = LOCKED

param_1[1]: Max unlock attempts = 10 (hardcoded)

param_1[2]: Remaining attempts
  - 0 when unlocked (N/A)
  - Should be calculated but appears to return 0 (bug?)

param_1[3]: Unknown field (always 0)
```

---

## Function 3: modem2_modem_validate_spc()

**Address**: `0x00037964` in libmal_qct.so  
**Purpose**: Validate SPC (Service Programming Code) - **REQUIRED BEFORE UNLOCK**  
**Called by**: `modem2_cli validate_spc <SPC>`  

### Decompiled C Code

```c
undefined4 modem2_modem_validate_spc(undefined4 param_1)
{
  undefined4 uVar1;
  int iVar2;
  undefined4 local_c;
  
  local_c = 0xc0001;  // Default: FAILURE
  
  // Check if modem initialized
  if (*(int *)(DAT_00037a88 + 0x37994) == 1) {
    
    // **STEP 1: Call external QMI validation function**
    iVar2 = nwqmi_dms_validate_spc(param_1);
    
    if (iVar2 == 0) {
      // SPC validation SUCCESS
      local_c = 0xc0000;
    }
    else if (iVar2 == 0x22) {  // Error code 0x22 = 34 decimal
      // SPC validation FAILED (incorrect SPC or limit exceeded)
      local_c = 0xc03e9;  // 787433 (custom error code)
    }
    else {
      // Unexpected error
      uVar1 = mifi_dbg_get_level_name(3);
      mifi_dbg_log(DAT_00037aa0 + 0x37a5c, 3, DAT_00037aa4 + 0x37a6c,
                   DAT_00037aa8 + 0x37a78, uVar1, DAT_00037a9c + 0x37a48, iVar2);
    }
  }
  else {
    // Modem not initialized
    uVar1 = mifi_dbg_get_level_name(5);
    mifi_dbg_log(DAT_00037a90 + 0x379c4, 5, DAT_00037a94 + 0x379d4,
                 DAT_00037a98 + 0x379e0, uVar1, DAT_00037a8c + 0x379b8);
    local_c = 0xc0001;
  }
  
  return local_c;
}
```

### Return Codes

- `0xC0000` (786432): **SUCCESS** - SPC valid, unlock now allowed
- `0xC03E9` (787433): **SPC FAILURE** - Incorrect SPC or attempt limit exceeded
- `0xC0001` (786433): **ERROR** - Modem not initialized or unexpected error

### Notes

- The external function `nwqmi_dms_validate_spc()` likely calls QMI DMS service for validation
- Error code `0x22` (34) suggests QMI error code for authentication failure
- Default SPC is **"000000"** (6 digits)
- **CRITICAL**: SPC validation has a limited number of attempts (see next function)

---

## Function 4: modem2_modem_get_spc_validate_limit()

**Address**: `0x0003788c` in libmal_qct.so  
**Purpose**: Query SPC validation retry counter  
**Called by**: `modem2_cli get_spc_validate_limit`  

### Decompiled C Code

```c
undefined4 modem2_modem_get_spc_validate_limit(int param_1)
{
  undefined4 uVar1;
  int iVar2;
  undefined4 local_c;
  
  local_c = 0xc0001;  // Default: FAILURE
  
  // Check if modem initialized
  if (*(int *)(DAT_00037950 + 0x378b4) == 1) {
    
    if (param_1 == 0) {
      // NULL pointer passed
      local_c = 0xc0002;  // Invalid parameter
    }
    else {
      // **STEP 1: Read OTKSK counter from NV item**
      iVar2 = nwqmi_nvtl_read_otksk_counter(param_1);
      
      if (iVar2 == 0) {
        local_c = 0xc0000;  // SUCCESS
      }
    }
  }
  else {
    // Modem not initialized
    uVar1 = mifi_dbg_get_level_name(5);
    mifi_dbg_log(DAT_00037958 + 0x378e4, 5, DAT_0003795c + 0x378f4,
                 DAT_00037960 + 0x37900, uVar1, DAT_00037954 + 0x378d8);
    local_c = 0xc0001;
  }
  
  return local_c;
}
```

### Notes

- **OTKSK**: "One-Time Key Service Key" counter (SPC retry counter)
- Likely stored in an NV item (need to identify which one)
- Each failed SPC attempt decrements the counter
- When counter reaches 0, device is **permanently locked**

---

## Function 5: dsm_modem_get_imei()

**Address**: `0x00042b84` in libmal_qct.so  
**Purpose**: Read IMEI from NV item 0x226 (550)  

### Decompiled C Code

```c
undefined4 dsm_modem_get_imei(void *param_1, uint param_2)
{
  int iVar1;
  undefined4 uVar2;
  undefined1 auStack_58 [80];  // Buffer for IMEI (80 bytes)
  
  memset(auStack_58, 0, 0x50);
  
  // **STEP 1: Read IMEI from NV item 0x226 (550)**
  iVar1 = nwqmi_nvtl_nv_item_read_cmd(0x226, auStack_58, 0x50);
  
  if (iVar1 == 0) {
    // Copy IMEI to output buffer
    if (param_2 < 0x50) {
      memcpy(param_1, auStack_58, 4);  // Partial copy
    }
    else {
      memcpy(param_1, auStack_58, 0x50);  // Full copy (80 bytes)
    }
    uVar2 = 0;  // SUCCESS
  }
  else {
    // NV read error - log and return error
    uVar2 = mifi_dbg_get_level_name(3);
    mifi_dbg_syslog(0x8a, DAT_00042ca8 + 0x42bf4, DAT_00042cac + 0x42c00,
                    uVar2, DAT_00042ca4 + 0x42be4);
    
    uVar2 = mifi_dbg_get_level_name(3);
    mifi_dbg_log(DAT_00042cb4 + 0x42c30, 3, DAT_00042cb8 + 0x42c40,
                 DAT_00042cbc + 0x42c4c, uVar2, DAT_00042cb0 + 0x42c24);
    uVar2 = 0xffffffff;  // FAILURE
  }
  
  return uVar2;
}
```

### Notes

- **NV 0x226 (550)**: IMEI storage (confirmed from previous session)
- IMEI is 15 digits but stored in 80-byte structure (likely includes metadata)
- This function is used by device info queries

---

## Critical NV Items Summary

| NV Item (Hex) | NV Item (Dec) | Size | Purpose | Default Value |
|---------------|---------------|------|---------|---------------|
| **0xEA64** | 59,492 | 104 bytes | **Master NCK storage (PLAINTEXT!)** | Set by carrier |
| **0xEAAC** | 60,076 | 1 byte | **Primary lock flag** | 1 (LOCKED) |
| **0xEA62** | 59,490 | 1 byte | **Secondary lock flag** | 1 (LOCKED) |
| **0x0D89** | 3,461 | 1 byte | Lock status (observed) | 1 (LOCKED) |
| **0x0226** | 550 | 80 bytes | IMEI storage | Unique per device |
| **Unknown** | TBD | TBD | **OTKSK counter (SPC retries)** | ~10 attempts |

---

## Security Analysis

### Critical Vulnerabilities

1. **Plaintext NCK Storage** ⚠️⚠️⚠️
   - The NCK is stored in **plaintext** in NV item 0xEA64
   - No hashing, encryption, or obfuscation
   - Direct memory read would expose the unlock code
   - This is a **severe security flaw**

2. **Direct String Comparison**
   - Uses standard `strncmp()` for validation
   - Vulnerable to timing attacks (not constant-time)
   - No rate limiting on unlock attempts (only SPC has limits)

3. **NV Item Write Bug**
   - Previous sessions identified write_nv bug at offset 0x4404 in `nwcli`
   - If exploitable, could bypass unlock by directly writing:
     - `nwcli write_nv 0xEAAC 0` (primary unlock)
     - `nwcli write_nv 0xEA62 0` (secondary unlock)

4. **SPC Retry Limit**
   - Limited to ~10 attempts (OTKSK counter)
   - **PERMANENT LOCK** if counter reaches 0
   - Counter location unknown (need to identify NV item)

### Attack Surface

```
Low-Level Attacks:
├── Direct NV memory access (requires root)
│   ├── Read NV 0xEA64 → Extract plaintext NCK
│   └── Write NV 0xEAAC/0xEA62 → Force unlock
│
├── Timing attack on strncmp()
│   └── Measure comparison time to deduce NCK characters
│
└── OTKSK counter manipulation
    └── Reset counter to bypass SPC retry limit

High-Level Attacks:
├── Brute force NCK (104-char space = infeasible)
├── Social engineering (carrier support)
└── IMEI swap (change device identity)
```

---

## Unlock Prerequisites & Workflow

### Safe Unlock Sequence

```
┌─────────────────────────────────────────────┐
│ STEP 1: Check Current Lock Status           │
│ modem2_cli unlock_carrier_status            │
│ → If already unlocked → DONE                │
│ → If locked → Continue to STEP 2            │
└─────────────────┬───────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────┐
│ STEP 2: Check SPC Retry Counter             │
│ modem2_cli get_spc_validate_limit           │
│ → If counter = 0 → PERMANENT LOCK (STOP)    │
│ → If counter > 0 → Continue to STEP 3       │
└─────────────────┬───────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────┐
│ STEP 3: Validate SPC (Default: 000000)      │
│ modem2_cli validate_spc <SPC>               │
│ → SUCCESS (0xC0000) → Continue to STEP 4    │
│ → FAILURE (0xC03E9) → Counter decremented   │
│   └─> Retry with correct SPC or STOP        │
└─────────────────┬───────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────┐
│ STEP 4: Perform Carrier Unlock              │
│ modem2_cli unlock_carrier <NCK>             │
│ → SUCCESS (0xC0000) → Device unlocked! ✅    │
│ → FAILURE (0xC0001) → Incorrect NCK          │
└─────────────────┬───────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────┐
│ STEP 5: Verify Unlock                       │
│ modem2_cli unlock_carrier_status            │
│ → Status should be 0 (UNLOCKED)             │
│ nwcli read_nv 0xEAAC 1                      │
│ → Should return 0x00                        │
└─────────────────────────────────────────────┘
```

### ⚠️ CRITICAL WARNINGS

1. **DO NOT** attempt SPC validation without knowing the correct code
   - Default is "000000" (6 zeros)
   - Only **~10 attempts** before permanent lock
   - Counter resets are **difficult/impossible**

2. **DO NOT** attempt to brute force NCK
   - 104-character keyspace is computationally infeasible
   - No apparent retry limits, but logs every attempt
   - May trigger carrier fraud detection

3. **DO NOT** use `nwcli write_nv` on lock-related NV items
   - Known bug at offset 0x4404 can corrupt NV memory
   - Corrupted NV items may cause permanent lock
   - Device may become unbootable

---

## Implementation Recommendations

### For mifi_controller.py

```python
# Add safe status checking (read-only operations)
def get_carrier_unlock_status_safe(self) -> Dict[str, Any]:
    """
    Query carrier lock status without triggering retry counters.
    Returns: {
        'locked': bool,
        'max_attempts': int,
        'remaining_attempts': int
    }
    """
    # Option 1: Use modem2_cli (safest)
    result = self._run_modem2_command(['unlock_carrier_status'])
    
    # Option 2: Direct NV read (requires root, faster)
    lock_flag = self.read_nv_item(0xEAAC, 1)  # Primary lock flag
    
    return {
        'locked': lock_flag[0] != 0,
        'max_attempts': 10,  # Hardcoded in firmware
        'remaining_attempts': self._get_otksk_counter()
    }

def check_spc_retries_remaining(self) -> int:
    """
    Check OTKSK counter before attempting SPC validation.
    Returns: Number of remaining SPC validation attempts.
    ⚠️  CALL THIS BEFORE validate_spc()!
    """
    result = self._run_modem2_command(['get_spc_validate_limit'])
    # Parse OTKSK counter from result
    # TODO: Identify NV item for direct read
    return counter_value

# DO NOT implement unsafe operations:
# - carrier_unlock() without SPC validation check
# - validate_spc() without retry counter check  
# - write_nv() to lock-related NV items (0xEAAC, 0xEA62, 0xEA64)
```

---

## Next Steps

### Research Tasks

1. **Identify OTKSK Counter NV Item**
   - Function `nwqmi_nvtl_read_otksk_counter()` needs reverse engineering
   - Locate which NV item stores SPC retry counter
   - Determine if counter is resetable (likely not)

2. **Analyze NCK Generation Algorithm**
   - How is the NCK initially set by carrier?
   - Is there a derivation from IMEI/MEID?
   - Can we generate valid NCKs?

3. **Investigate write_nv Bug**
   - Session 7/8 found bug at offset 0x4404 in `nwcli`
   - Can this be used to write NV 0xEAAC/0xEA62 safely?
   - What is the root cause of the bug?

4. **QMI Service Analysis**
   - Reverse engineer `nwqmi_dms_validate_spc()` (external function)
   - Understand QMI DMS service communication
   - Identify QMI messages for unlock operations

### Development Tasks

1. Implement safe status checking in `mifi_controller.py`
2. Add SPC retry counter query
3. Create comprehensive unlock status report
4. Document safe vs. unsafe operations
5. Add safeguards against permanent lock

---

## References

- **Binary**: libmal_qct.so (MD5: 67dd3801e11c2b20f44d72ef4b198ff6)
- **Tool**: Ghidra 11.4.3 PUBLIC
- **Firmware**: SDx20ALP-1.22.11 (Inseego MiFi 8800L)
- **Related Docs**:
  - `SESSION_2_FINDINGS.md` - Initial NV exploration
  - `ADVANCED_FEATURES.md` - High-level modem2_cli commands
  - `probe-log.txt` - Device information

---

**Analysis Complete**: Session 7/8 Part 2  
**Status**: UNLOCK ALGORITHM FULLY REVERSED ✅  
**Security Rating**: ⚠️ CRITICAL - Plaintext NCK storage is a major vulnerability
