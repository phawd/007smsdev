# MiFi 8800L Safe Operations Quick Reference

**⚠️ CRITICAL**: Always check this guide before attempting unlock-related operations!

---

## 🟢 SAFE Operations (Read-Only)

These operations are **completely safe** and will not risk device lock or corruption:

### Check Lock Status

```bash
# Method 1: Using modem2_cli (recommended)
modem2_cli unlock_carrier_status

# Method 2: Direct NV read (requires root)
nwcli read_nv 0xEAAC 1  # Primary lock flag (0=unlocked, 1=locked)
nwcli read_nv 0xEA62 1  # Secondary lock flag
nwcli read_nv 0x0D89 1  # Lock status (observed)
```

**Expected Output**:

- UNLOCKED: All flags = 0x00
- LOCKED: Any flag = 0x01

### Check IMEI

```bash
# Read IMEI from NV storage
nwcli read_nv 0x226 80

# Parse IMEI (first 15 digits)
modem2_cli get_device_info  # Easier method
```

### Check Device Info (General)

```bash
modem2_cli get_device_info
modem2_cli get_modem_status
modem2_cli get_network_info
```

---

## 🟡 CAUTION Operations (Safe if Precautions Taken)

### Check SPC Retry Counter

```bash
# ALWAYS check this BEFORE attempting SPC validation!
modem2_cli get_spc_validate_limit

# Expected output: Remaining attempts (usually 10)
# If counter = 0 → PERMANENT LOCK - DO NOT PROCEED
```

**What This Means**:

- Counter starts at ~10 attempts
- Each failed SPC validation decrements counter
- **When counter = 0 → Device permanently locked (no recovery!)**

### Query Network/Carrier Settings

```bash
# These are safe but require SPC validation first in some cases
modem2_cli get_network_preference  # Safe (read-only)
modem2_cli get_carrier_info         # Safe (read-only)
```

---

## 🔴 DANGEROUS Operations (High Risk)

### ⚠️ SPC Validation

**Risk Level**: CRITICAL - Limited attempts before permanent lock

```bash
# Default SPC: 000000 (6 zeros)
modem2_cli validate_spc 000000
```

**BEFORE ATTEMPTING**:

1. ✅ Check retry counter: `modem2_cli get_spc_validate_limit`
2. ✅ Ensure counter > 0
3. ✅ Confirm correct SPC code (default: "000000")
4. ✅ Understand that **failure = permanent lock risk**

**Return Codes**:

- `0xC0000` (786432): SUCCESS - SPC valid, unlock now allowed
- `0xC03E9` (787433): FAILURE - Incorrect SPC or limit exceeded
- `0xC0001` (786433): ERROR - Modem not initialized

**What Happens on Failure**:

- Retry counter decrements
- If counter reaches 0 → **PERMANENT LOCK**
- No known recovery method (JTAG required?)

### ⚠️ Carrier Unlock

**Risk Level**: CRITICAL - Requires SPC validation first

```bash
# Unlock with NCK (Network Control Key)
modem2_cli unlock_carrier <YOUR_NCK_HERE>
```

**PREREQUISITES** (MUST CHECK ALL):

1. ✅ SPC validation completed: `modem2_cli validate_spc <SPC>`
2. ✅ Valid NCK obtained from carrier
3. ✅ NCK is exactly correct (no retry limit, but logged)
4. ✅ Device lock status confirmed: `modem2_cli unlock_carrier_status`

**Return Codes**:

- `0xC0000` (786432): SUCCESS - Device unlocked! ✅
- `0xC0001` (786433): FAILURE - Incorrect NCK or SPC not validated

**What This Does**:

1. Reads master NCK from NV 0xEA64
2. Compares with your input using `strncmp()`
3. If match:
   - Writes NV 0xEAAC = 0 (primary unlock)
   - Writes NV 0xEA62 = 0 (secondary unlock)
4. Device is now unlocked (reboot may be required)

### ⚠️ NV Item Writing

**Risk Level**: EXTREME - Known bug can brick device

```bash
# ❌ DO NOT USE - Known bug at offset 0x4404
nwcli write_nv <NV_ID> <DATA>
```

**NEVER WRITE TO THESE NV ITEMS**:

- 0xEA64 (59,492): Master NCK storage
- 0xEAAC (60,076): Primary lock flag
- 0xEA62 (59,490): Secondary lock flag
- 0x0D89 (3,461): Lock status

**Why This Is Dangerous**:

- Known bug at offset 0x4404 can corrupt NV memory
- Corrupted lock NV items → permanent lock
- Corrupted critical NV items → device may not boot
- No error checking in current implementation

**Exception**: NV reading is safe

```bash
# Safe - read-only operation
nwcli read_nv 0xEAAC 1
```

### 🛡️ New Safety Gate: CLI confirmation

Recent tooling updates add a runtime confirmation gate for dangerous
operations. When using our Python tools (`mifi_controller.py`,
`spc_calculator.py`, and `zerosms_cli.py`) you must explicitly enable
dangerous operations with `--danger-do-it` and type `DO IT` when prompted
to proceed. Alternatively, set the environment variable
`ZEROSMS_DANGER_DO_IT=1` to skip prompts in automation.

This is an additional layer to the PR-level `DO IT` sign-off and does not
replace the requirement to include a documented rollback plan in PRs that
modify NV operations.

### Option C: PRI Override (mifi_controller.py)

The `mifi_controller.py` tool now supports an "Option C" PRI override flow.
This operation can be performed via either NV write (NV 60044) or by updating
the EFS device configuration (`/policyman/device_config.xml`).

Usage:

```bash
# Dry-run (shows intended change, safe)
python3 tools/mifi_controller.py pri-override --new-pri NEWPRI --dry-run --method nv

# Apply (requires interactive 'DO IT' confirmation or env var)
python3 tools/mifi_controller.py pri-override --new-pri NEWPRI --method nv --danger-do-it
```

Notes:
- Prefer `--dry-run` to verify the intended change first.
- `--method nv` writes to NV 60044 (dangerous and requires the safety gate).
- `--method efs` updates `/policyman/device_config.xml` (backup is created).
- Always verify the change and keep backups in case a rollback is required.

---

## Safe Unlock Workflow (Step-by-Step)

Follow this **exact sequence** to minimize risk:

### Step 1: Pre-Flight Checks ✅

```bash
# 1.1 Check current lock status
modem2_cli unlock_carrier_status
# Expected: LOCKED (if unlocking) or UNLOCKED (if already done)

# 1.2 Check SPC retry counter (CRITICAL!)
modem2_cli get_spc_validate_limit
# Expected: 10 attempts remaining (or less if previously attempted)
# ⚠️  If counter = 0 → STOP! Device is permanently locked

# 1.3 Verify IMEI (for records)
modem2_cli get_device_info | grep IMEI
# Expected: Your device IMEI (15 digits)

# 1.4 Backup NV items (recommended)
nwcli read_nv 0xEAAC 1 > lock_status_backup.txt
nwcli read_nv 0xEA62 1 >> lock_status_backup.txt
nwcli read_nv 0x0D89 1 >> lock_status_backup.txt
```

**Proceed ONLY if**:

- ✅ Device shows LOCKED status
- ✅ SPC retry counter > 0
- ✅ You have correct SPC code (default: "000000")
- ✅ You have valid NCK from carrier

### Step 2: SPC Validation ⚠️

```bash
# Default SPC: 000000 (6 zeros)
modem2_cli validate_spc 000000

# Check return code
echo $?  # Should be 0 for success
```

**If SUCCESS**:

- ✅ Proceed to Step 3

**If FAILURE**:

- ❌ **STOP IMMEDIATELY**
- Check retry counter: `modem2_cli get_spc_validate_limit`
- If counter > 0: Verify SPC and retry **carefully**
- If counter = 0: **PERMANENT LOCK** - Do not attempt unlock

### Step 3: Carrier Unlock ⚠️

```bash
# Use NCK provided by carrier
modem2_cli unlock_carrier <YOUR_NCK_HERE>

# Example (fake NCK):
# modem2_cli unlock_carrier 12345678901234567890
```

**If SUCCESS** (return code 0xC0000):

- ✅ Proceed to Step 4

**If FAILURE** (return code 0xC0001):

- NCK is incorrect
- SPC validation may have expired (retry from Step 2)
- Verify NCK with carrier

### Step 4: Verification ✅

```bash
# 4.1 Check lock status
modem2_cli unlock_carrier_status
# Expected: UNLOCKED

# 4.2 Verify NV items
nwcli read_nv 0xEAAC 1  # Should be 0x00
nwcli read_nv 0xEA62 1  # Should be 0x00
nwcli read_nv 0x0D89 1  # Should be 0x00

# 4.3 Reboot device (may be required)
modem2_cli reboot

# 4.4 After reboot, verify network access
modem2_cli get_network_info
```

**Success Indicators**:

- All lock flags = 0x00
- Device shows UNLOCKED status
- Can connect to non-carrier networks

---

## Emergency Troubleshooting

### Scenario: SPC Validation Failed

**Symptoms**:

- `modem2_cli validate_spc` returns 0xC03E9
- Retry counter decremented

**Actions**:

1. **STOP** - Do not retry immediately
2. Check remaining attempts: `modem2_cli get_spc_validate_limit`
3. If attempts remain:
   - Verify SPC code (default: "000000")
   - Ensure no typos (six zeros, not letter O)
   - Retry **once** with correct code
4. If counter = 0:
   - **PERMANENT LOCK** - No further attempts possible
   - Contact carrier for professional unlock
   - JTAG/hardware intervention may be required

### Scenario: Unlock Failed (Incorrect NCK)

**Symptoms**:

- SPC validation succeeded
- `modem2_cli unlock_carrier` returns 0xC0001
- Device still shows LOCKED

**Actions**:

1. Verify NCK with carrier (may have been entered incorrectly)
2. Check if NCK is case-sensitive (usually not)
3. Ensure no extra spaces or characters
4. Retry validation + unlock sequence:
   - `modem2_cli validate_spc 000000`
   - `modem2_cli unlock_carrier <CORRECT_NCK>`

**Note**: No apparent limit on NCK attempts, but all attempts are logged

### Scenario: Device Locked After NV Corruption

**Symptoms**:

- Used `nwcli write_nv` on lock-related NV items
- Device now shows unexpected lock status
- Cannot unlock using normal procedure

**Actions**:

1. **DO NOT** attempt further NV writes
2. Check current NV values:

   ```bash
   nwcli read_nv 0xEAAC 1
   nwcli read_nv 0xEA62 1
   nwcli read_nv 0x0D89 1
   ```

3. If all values = 0x00 but device still locked:
   - Reboot device: `modem2_cli reboot`
   - Check for NV item sync issue
4. If values are corrupted (non-zero/non-one):
   - **Factory reset may be required** (data loss!)
   - Contact carrier for professional assistance
   - JTAG/hardware recovery may be needed

---

## Python Implementation (mifi_controller.py)

### Safe Status Checker

```python
def check_unlock_status_safe(self) -> Dict[str, Any]:
    """
    Safe read-only check of carrier lock status.
    
    Returns:
        {
            'locked': bool,          # True if device is locked
            'primary_lock': int,     # NV 0xEAAC value (0 or 1)
            'secondary_lock': int,   # NV 0xEA62 value (0 or 1)
            'status_nv': int,        # NV 0x0D89 value
            'spc_retries': int,      # Remaining SPC attempts (if available)
            'safe_to_unlock': bool   # True if all preconditions met
        }
    """
    # Read lock flags from NV items
    primary = self.read_nv_item(0xEAAC, 1)
    secondary = self.read_nv_item(0xEA62, 1)
    status = self.read_nv_item(0x0D89, 1)
    
    # Check SPC retry counter
    spc_retries = self._get_spc_retry_count()
    
    return {
        'locked': primary[0] != 0 or secondary[0] != 0,
        'primary_lock': primary[0],
        'secondary_lock': secondary[0],
        'status_nv': status[0],
        'spc_retries': spc_retries,
        'safe_to_unlock': spc_retries > 0 and primary[0] == 1
    }

def _get_spc_retry_count(self) -> int:
    """
    Query remaining SPC validation attempts.
    
    Returns:
        Number of remaining attempts (usually 10 or less).
        Returns -1 if unable to determine.
    """
    try:
        result = self._run_modem2_command(['get_spc_validate_limit'])
        # TODO: Parse OTKSK counter from result
        # For now, return -1 (unknown)
        return -1
    except Exception as e:
        self.logger.error(f"Failed to get SPC retry count: {e}")
        return -1
```

### Usage Example

```python
from mifi_controller import MiFiController

controller = MiFiController()

# Safe status check
status = controller.check_unlock_status_safe()

print(f"Device Locked: {status['locked']}")
print(f"Primary Lock Flag: {status['primary_lock']}")
print(f"Secondary Lock Flag: {status['secondary_lock']}")
print(f"SPC Retries Remaining: {status['spc_retries']}")
print(f"Safe to Unlock: {status['safe_to_unlock']}")

# Decision logic
if status['safe_to_unlock']:
    print("✅ Device can be unlocked safely")
    print("⚠️  Ensure you have correct SPC (default: 000000) and valid NCK")
elif status['spc_retries'] == 0:
    print("❌ PERMANENT LOCK - No unlock attempts possible")
    print("🔧 Contact carrier or use JTAG recovery")
elif not status['locked']:
    print("✅ Device is already unlocked")
else:
    print("⚠️  Device status unclear - manual investigation needed")
```

---

## Return Code Reference

| Code (Hex) | Code (Dec) | Meaning | Context |
|------------|------------|---------|---------|
| **0xC0000** | 786432 | SUCCESS | All operations |
| **0xC0001** | 786433 | FAILURE | Generic error |
| **0xC0002** | 786434 | INVALID_PARAM | NULL pointer or bad input |
| **0xC03E9** | 787433 | SPC_FAILURE | Incorrect SPC or limit exceeded |

---

## NV Item Reference

| NV (Hex) | NV (Dec) | Size | Purpose | Safe to Read? | Safe to Write? |
|----------|----------|------|---------|---------------|----------------|
| **0xEA64** | 59,492 | 104 bytes | Master NCK (plaintext) | ✅ Yes | ❌ NO |
| **0xEAAC** | 60,076 | 1 byte | Primary lock flag | ✅ Yes | ❌ NO |
| **0xEA62** | 59,490 | 1 byte | Secondary lock flag | ✅ Yes | ❌ NO |
| **0x0D89** | 3,461 | 1 byte | Lock status | ✅ Yes | ❌ NO |
| **0x0226** | 550 | 80 bytes | IMEI storage | ✅ Yes | ❌ NO (risky) |
| **Unknown** | TBD | TBD | OTKSK counter (SPC) | ✅ Yes | ❌ NO |

**Legend**:

- ✅ Yes: Operation is safe
- ❌ NO: Operation is dangerous (known bug or corruption risk)

---

## Command Summary

### 🟢 Safe Commands

```bash
modem2_cli unlock_carrier_status      # Check lock status
modem2_cli get_device_info            # Read device info
modem2_cli get_modem_status           # Read modem status
modem2_cli get_network_info           # Read network info
nwcli read_nv 0xEAAC 1               # Read primary lock flag
nwcli read_nv 0xEA62 1               # Read secondary lock flag
nwcli read_nv 0x0D89 1               # Read lock status NV
nwcli read_nv 0x0226 80              # Read IMEI
```

### 🟡 Caution Commands

```bash
modem2_cli get_spc_validate_limit    # Check SPC retries (check before unlock)
```

### 🔴 Dangerous Commands

```bash
modem2_cli validate_spc <SPC>        # ⚠️  Limited attempts!
modem2_cli unlock_carrier <NCK>      # ⚠️  Requires SPC validation first
nwcli write_nv <NV> <DATA>           # ❌ Known bug - DO NOT USE on lock NVs
```

---

## Final Checklist Before Unlock

- [ ] Device is currently LOCKED (verified via `unlock_carrier_status`)
- [ ] SPC retry counter > 0 (verified via `get_spc_validate_limit`)
- [ ] Correct SPC code obtained (default: "000000")
- [ ] Valid NCK obtained from carrier
- [ ] NCK verified for accuracy (no typos)
- [ ] Backup of current lock status saved
- [ ] IMEI recorded for reference
- [ ] Understood risks: SPC failure = permanent lock
- [ ] Understood: No undo after unlock
- [ ] Device has stable power (don't unlock on low battery!)

**If ALL boxes checked**: Proceed with unlock sequence (Steps 1-4)  
**If ANY box unchecked**: DO NOT PROCEED - gather missing information first

---

## Support Resources

- **Technical Analysis**: `docs/UNLOCK_ALGORITHM_ANALYSIS.md`
- **Session Summary**: `docs/SESSION_7_8_PART2_SUMMARY.md`
- **Python Controller**: `tools/mifi_controller.py`
- **Device Guide**: `docs/MIFI_DEVICE_GUIDE.md`

---

**Remember**: When in doubt, **READ ONLY**. You can always query status safely. Writing operations (especially NV writes) carry risk of permanent lock or device corruption.

**Last Updated**: Session 7/8 Part 2  
**Device**: Inseego MiFi 8800L (SDx20ALP-1.22.11)
