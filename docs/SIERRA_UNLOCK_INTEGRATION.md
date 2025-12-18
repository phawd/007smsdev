# Sierra Wireless Unlock Integration

This document describes the integration of B.Kerler's Sierra Wireless unlock algorithms into the SMS Test toolkit for Inseego MiFi devices.

## Overview

The Sierra Wireless unlock algorithms use challenge-response cryptography to unlock carrier locks on modems. The algorithms were reverse-engineered from Sierra Wireless devices (MDM8200, MDM9200, MDM9x series, SDX55/65/75) and implement a proprietary encryption scheme.

## ⚠️ CRITICAL WARNING

**Algorithm Compatibility**: The Sierra algorithms were designed for **Sierra Wireless chipsets**, NOT Qualcomm chipsets. The Inseego MiFi 8800L uses a **Qualcomm SDX20** chipset, which may use a completely different unlock algorithm.

**Attempting unlock with wrong algorithm will:**

- Decrement the unlock retry counter
- After 0 retries remaining, device is **PERMANENTLY LOCKED**
- Potentially brick the device

**DO NOT ATTEMPT UNLOCK ON CRITICAL DEVICE!**

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│ SMS Test mifi_controller.py                                  │
├─────────────────────────────────────────────────────────────┤
│ unlock_carrier_sierra()  ← High-level unlock function       │
│ get_carrier_unlock_status() ← Check retry counter           │
└────────────────────┬────────────────────────────────────────┘
                     │ imports
┌────────────────────▼────────────────────────────────────────┐
│ sierra_adapter.py                                           │
├─────────────────────────────────────────────────────────────┤
│ calculate_unlock_response() ← MiFi-friendly wrapper         │
│ SierraGenerator.run() ← Core algorithm                      │
│ SierraGenerator.SierraKeygen() ← Challenge-response calc    │
│ SierraGenerator.SierraAlgo() ← Encryption primitive         │
└────────────────────┬────────────────────────────────────────┘
                     │ uses
┌────────────────────▼────────────────────────────────────────┐
│ Algorithm Tables (29 keys × 16 bytes)                       │
├─────────────────────────────────────────────────────────────┤
│ PRODTABLE: Device generation → algorithm parameters         │
│ KEYTABLE: 464 bytes of encryption keys                      │
│ INFOTABLE: Model name → device generation mapping           │
└─────────────────────────────────────────────────────────────┘
                     │ feeds
┌────────────────────▼────────────────────────────────────────┐
│ MiFi Device (ADB shell)                                     │
├─────────────────────────────────────────────────────────────┤
│ /opt/nvtl/bin/modem2_cli get_carrier_unlock                │
│ /opt/nvtl/bin/modem2_cli unlock_carrier_lock (get challenge)│
│ /opt/nvtl/bin/modem2_cli unlock_carrier_lock (submit NCK)   │
└─────────────────────────────────────────────────────────────┘
```

## Challenge-Response Process

### 1. Query Unlock Status

```python
from mifi_controller import get_carrier_unlock_status

success, status = get_carrier_unlock_status()
print(f"State: {status['state']}")  # 0=unlocked, 1=locked
print(f"Retry counter: {status['verify_retries']}")  # Remaining attempts
```

**Output Example:**

```
State: 1 (locked)
Retry counter: 10
```

### 2. Get Challenge from Modem

```bash
adb shell "/opt/nvtl/bin/modem2_cli unlock_carrier_lock"
# May prompt for challenge or return challenge in output
# Expected: 8-byte hex string (e.g., BE96CBBEE0829BCA)
```

### 3. Calculate Response

```python
from sierra_adapter import calculate_unlock_response

challenge = "BE96CBBEE0829BCA"  # From modem
devicegeneration = "SDX20"  # MiFi 8800L (EXPERIMENTAL!)

response = calculate_unlock_response(challenge, devicegeneration)
print(f"Response: {response}")  # e.g., "1033773720F6EE66"
```

### 4. Submit Response to Modem

```python
from mifi_controller import unlock_carrier_lock

success, output = unlock_carrier_lock(response)
if success:
    print("Device unlocked!")
else:
    print("Unlock failed - retry counter decremented")
```

## Algorithm Details

### Encryption Primitive: SierraAlgo()

The core encryption function performs:

1. Table initialization with key schedule
2. Permutation of 256-byte lookup table
3. XOR operations on challenge bytes
4. Multiple rounds of table lookups

**Parameters:**

- `challenge`: 8-byte input from modem
- `key`: 16-byte encryption key (from KEYTABLE)
- `init`: Initial register values `[7, 3, 0, 1, 5]`
- `a, b, c, d, e`: Register indices (control table lookups)

**Key Selection:**

- Each device generation has 3 key indices: `openlock`, `openmep`, `opencnd`
- MiFi 8800L (SDX20): Uses key index 11 (same as MDM9x40)
- Key index → KEYTABLE offset: `key = KEYTABLE[index * 16 : (index * 16) + 16]`

### Device Generation Mapping

| Chipset | Device Generation | Key Index | Verified |
|---------|-------------------|-----------|----------|
| MDM8200 | MDM8200 | 0 | ✓ Yes |
| MDM9200 | MDM9200 | 0 | ✓ Yes |
| MDM9x15 | MDM9x15 | 0 | ✓ Yes |
| MDM9x30 | MDM9x30 | 5 | ✓ Yes |
| MDM9x40 | MDM9x40 | 11 | ✓ Yes |
| MDM9x50 | MDM9x50 | 7 | ✓ Yes |
| SDX55 | SDX55 | 22 | ✓ Yes |
| SDX65 | SDX65 | 25 | ✓ Yes |
| **SDX20** | **SDX20** | **11** | **❌ UNVERIFIED** |

**SDX20 Note:** Using MDM9x40 algorithm (key 11) as closest match. May be incorrect!

## Usage Examples

### Safe: Check Unlock Status Only

```python
from mifi_controller import get_carrier_unlock_status

success, status = get_carrier_unlock_status()
if success:
    if status['unlocked']:
        print("✓ Device is already unlocked")
    else:
        print(f"✗ Device is locked")
        print(f"  Remaining unlock attempts: {status['verify_retries']}")
        print(f"  Carrier block: {status['carrier_block']}")
```

### Moderate Risk: Calculate Response (No Submit)

```python
from sierra_adapter import calculate_unlock_response

# Test challenge from Sierra self-test
challenge = "BE96CBBEE0829BCA"
response = calculate_unlock_response(challenge, "MDM9x40")
print(f"Response: {response}")
# Expected: 1033773720F6EE66

# Try MiFi algorithm (EXPERIMENTAL!)
response_mifi = calculate_unlock_response(challenge, "SDX20")
print(f"MiFi response: {response_mifi}")
# Output: Same as MDM9x40 (uses same key index 11)
```

### HIGH RISK: Full Unlock Workflow

```python
from mifi_controller import unlock_carrier_sierra

# ⚠️ WARNING: This will attempt unlock!
# - Check retry counter first
# - Verify device is MiFi 8800L (SDX20)
# - Backup device state
# - Test on non-critical device first

success, output = unlock_carrier_sierra(
    challenge=None,  # Will query modem
    devicegeneration="SDX20"
)

if success:
    print("✓ Device unlocked successfully!")
else:
    print("✗ Unlock failed")
    print(output)
```

## Self-Test

The adapter includes a self-test function with known challenge-response pairs:

```python
from sierra_adapter import run_selftest

all_passed, results = run_selftest()
for device, passed in results.items():
    print(f"{device}: {'PASSED' if passed else 'FAILED'}")
```

**Expected Output:**

```
MDM9x15:  ✓ PASSED
MDM9x40:  ✓ PASSED
MDM9x30:  ✓ PASSED
MDM9x50:  ✓ PASSED
MDM8200:  ✓ PASSED
MDM9200:  ✓ PASSED
SDX55:    ✓ PASSED
SDX65:    ✓ PASSED
```

## Known Test Vectors

| Challenge         | Device     | Expected Response |
|-------------------|------------|-------------------|
| 8101A18AB3C3E66A | MDM9x15    | D1E128FCA8A963ED |
| BE96CBBEE0829BCA | MDM9x40    | 1033773720F6EE66 |
| BE96CBBEE0829BCA | MDM9x30    | 1E02CE6A98B7DD2A |
| BE96CBBEE0829BCA | MDM9x50    | 32AB617DB4B1C205 |
| BE96CBBEE0829BCA | MDM8200    | EE702212D9C12FAB |
| 20E253156762DACE | SDX55      | 03940D7067145323 |
| 4B1FEF9FD43C6DAA | SDX65      | 1253C1B1E447B697 |

**No test vectors exist for SDX20 (MiFi 8800L)!**

## Research Tasks

### 1. Identify Correct SDX20 Algorithm

**Method 1: Firmware Reverse Engineering**

- Use Ghidra to decompile `/opt/nvtl/bin/modem2_cli`
- Find `unlock_carrier_lock` function (offset 0x211c0)
- Analyze unlock validation logic
- Compare with Sierra algorithms

**Method 2: Modem AT Commands**

- Check if modem supports AT!OPENLOCK? (Sierra command)
- Try AT!ENTERCND? (engineering mode)
- Probe for Qualcomm-specific unlock commands

**Method 3: NV Item Analysis**

- Read NV 3461 (SIM lock status) = 0x01 (locked)
- Read NV 4399 (subsidy lock 2) = 0x01 (locked)
- Analyze lock structure in EFS filesystem

**Method 4: Carrier Unlock Service**

- Request legitimate unlock code from carrier
- Capture challenge-response exchange via logging
- Reverse-engineer algorithm from valid unlock

### 2. Verify Key Index

Current assumption: SDX20 uses key index 11 (same as MDM9x40)

**Verification:**

- Extract encryption key from modem firmware
- Compare with KEYTABLE entries
- Test all 29 key indices with known challenge

### 3. Test on Multiple Devices

- MiFi 8800L (Verizon) - SDX20
- MiFi M2000 (T-Mobile) - SDX55
- MiFi M2100 (5G) - SDX65

Compare algorithm behavior across Inseego models.

## Safety Checklist

Before attempting unlock:

- [ ] Device is NOT critical (test device only)
- [ ] Full device backup completed (EFS, NV items, firmware)
- [ ] IMEI backed up (NV 550)
- [ ] Unlock retry counter > 5 (verify with `get_carrier_unlock_status()`)
- [ ] Self-test passed (`run_selftest()` returns all True)
- [ ] Device generation identified correctly (`detect_device_generation()`)
- [ ] Challenge obtained successfully (8-byte hex string)
- [ ] Response calculated (16 hex digits)
- [ ] User confirmed understanding of permanent lock risk
- [ ] Carrier unlock service attempted first (legitimate method)

## Alternative Unlock Methods

### 1. Carrier Unlock Request (RECOMMENDED)

Contact carrier (Verizon, AT&T, T-Mobile) and request unlock code:

- Usually free after contract ends
- No risk of bricking device
- Legitimate method

### 2. Qualcomm QPST/QXDM

Use Qualcomm tools to send unlock commands:

- Requires Qualcomm drivers
- May need SPC (Service Programming Code)
- Research Qualcomm-specific unlock NV items

### 3. Third-Party Unlock Services

Commercial services that claim to unlock devices:

- Charge $20-$100
- May use same algorithms (unknown)
- Risk of scam services

### 4. Firmware Modification

Replace locked firmware with unlocked version:

- High risk of bricking
- Requires EDL (Emergency Download) mode access
- Voids warranty

## File Structure

```
007smsdev/
├── tools/
│   ├── mifi_controller.py         (1,504 lines → 1,700+ lines)
│   │   ├── get_carrier_unlock_status()
│   │   ├── unlock_carrier_lock()  (updated with safety checks)
│   │   └── unlock_carrier_sierra() (NEW: Sierra algorithm unlock)
│   │
│   └── sierra_adapter.py          (NEW: 700+ lines)
│       ├── SierraGenerator class
│       │   ├── SierraInit()
│       │   ├── SierraAlgo()
│       │   ├── SierraKeygen()
│       │   └── run()
│       ├── calculate_unlock_response()
│       ├── detect_device_generation()
│       ├── run_selftest()
│       └── Algorithm tables (PRODTABLE, KEYTABLE, INFOTABLE)
│
└── docs/
    └── SIERRA_UNLOCK_INTEGRATION.md  (this file)
```

## Legal & Ethical Considerations

**License**: Sierra algorithms from B.Kerler's project (GPLv3)

- Original: <https://github.com/bkerler/sierrakeygen>
- Author: B.Kerler 2019-2023
- SMS Test adapter: GPLv3 compatible

**Carrier Locks**: Legal status varies by country

- USA: Unlocking is generally legal after contract ends
- Carrier must provide unlock code per FCC rules (post-2015)
- DMCA exemption for phone unlocking

**Reverse Engineering**: Educational/research purposes

- Fair use under DMCA Section 1201(f) (interoperability)
- Not intended for bypassing legitimate carrier locks
- Test on personal devices only

## References

1. **Sierra Keygen Project**
   - GitHub: <https://github.com/bkerler/sierrakeygen>
   - Author: B.Kerler
   - License: GPLv3

2. **Qualcomm DIAG Protocol**
   - Used by QPST/QXDM tools
   - Unlock commands may be device-specific

3. **MiFi 8800L Documentation**
   - Chipset: Qualcomm SDX20 (Alpine)
   - Firmware: SDx20ALP-1.22.11
   - Carrier: Verizon (VID 1410, PID B023)

4. **SMS Test Project Documentation**
   - MIFI_DEVICE_GUIDE.md: MiFi-specific commands
   - ROOT_ACCESS_GUIDE.md: AT commands and root access
   - SESSION_4_FINDINGS.md: Reverse engineering notes

## Troubleshooting

### "Algorithm compatibility uncertain" Warning

**Cause**: SDX20 (MiFi 8800L) algorithm is unknown
**Solution**: Research correct algorithm via Ghidra or carrier unlock

### "No unlock attempts remaining"

**Cause**: Retry counter reached 0
**Solution**: Device permanently locked - contact carrier for factory unlock

### "Could not parse challenge from modem"

**Cause**: modem2_cli output format unknown
**Solution**: Enter challenge manually when prompted

### Self-Test Fails

**Cause**: Implementation error or missing dependencies
**Solution**: Check sierra_adapter.py for typos, verify Python 3.7+

### "sierra_adapter.py not found"

**Cause**: Running from wrong directory
**Solution**: `cd tools/` before running mifi_controller.py

## Future Work

1. **Algorithm Research**
   - Decompile unlock_carrier_lock in modem2_cli
   - Extract challenge-response pairs from logs
   - Compare with Sierra algorithms

2. **Key Extraction**
   - Extract encryption key from firmware
   - Verify against KEYTABLE
   - Add SDX20-specific key if different

3. **Multi-Device Testing**
   - Test on MiFi M2000 (SDX55)
   - Test on MiFi M2100 (SDX65)
   - Compare algorithm behavior

4. **Automation**
   - Auto-detect device generation from firmware
   - Batch unlock for multiple devices
   - Integration with smstest_cli.py

5. **Android App Integration**
   - Add unlock UI to SMS Test app
   - Real-time unlock status display
   - Safety warnings and backup prompts

## Conclusion

The Sierra Wireless unlock algorithms have been successfully integrated into the SMS Test toolkit. However, **algorithm compatibility with Qualcomm SDX20 (MiFi 8800L) remains unverified and HIGHLY UNCERTAIN**.

**DO NOT ATTEMPT UNLOCK ON PRODUCTION DEVICE WITHOUT VERIFICATION!**

Further research via Ghidra decompilation and firmware analysis is required to identify the correct unlock algorithm for Qualcomm SDX20 chipsets.

---

**Last Updated**: Session 5
**Authors**: B.Kerler (original algorithm), SMS Test Project (adapter)
**Status**: EXPERIMENTAL - Verification Required
