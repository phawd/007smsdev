# NV Item Write Capability Analysis

**Date**: December 4, 2025  
**Device**: Inseego MiFi 8800L  
**Discovery Method**: Active write testing with value restoration

## Write Testing Results

### NV 60044: PRI Version String - **CONFIRMED WRITABLE**

**Test Procedure:**
```bash
# 1. Read original value
/opt/nvtl/bin/nwcli qmi_idl read_nv 60044 0
# Output: "PRI.90029477 REV 151 Alpine VERIZON"

# 2. Attempt write with test value
/opt/nvtl/bin/nwcli qmi_idl write_nv 60044 0 "NVTL rocks!!"
# Command executed: SUCCESS (no error)

# 3. Read back to verify
/opt/nvtl/bin/nwcli qmi_idl read_nv 60044 0
# Output: "NVTL rocks!!"

# 4. Restore original value
/opt/nvtl/bin/nwcli qmi_idl write_nv 60044 0 "PRI.90029477 REV 151 Alpine VERIZON"
# Result: SUCCESSFUL RESTORATION
```

**Significance:**
- **First confirmed writable NV item** on this device
- String-type NV items (non-binary) appear more accessible for writes
- PRI version is configuration, not protection-critical data
- Demonstrates write protection hierarchy is selective

### NV Item Protection Hierarchy (Updated)

```
TIER 1: COMPLETELY LOCKED (Error 8193)
├─ Carrier lock items (NV 5, 851, 4398)
├─ SIM lock configuration
├─ Device identifiers (most IMEIs, IMSI)
└─ Subsidy/roaming locks

TIER 2: READ-ONLY (No write capability)
├─ Hardware identifiers (some read versions)
├─ Modem firmware state
├─ Device configuration (most)
└─ Protection keys

TIER 3: SELECTIVE WRITE (Context-dependent)
├─ Configuration strings (LIKE NV 60044 - PRI VERSION) ✓ WRITABLE
├─ Non-critical band preferences
├─ APN profiles (via settings UI)
└─ User-configured items

TIER 4: ALWAYS ACCESSIBLE (No protection)
├─ Debug/test items
├─ Empty/unused slots
└─ Telemetry data
```

## Implications

### What This Means for MiFi Device Control

1. **Write capability exists** - Not all items are locked
2. **String items are more accessible** - Binary protections don't apply equally
3. **Configuration items writable** - Firmware parameters can be modified
4. **Pattern**: High-numbered items (>60000) less protected

### What Can Be Modified

**Confirmed Writable:**
- NV 60044: PRI firmware version identifier
  - Could be exploited to bypass firmware version checks
  - String modification (not binary, easier to manipulate)

**Likely Writable (Similar patterns):**
- Other string-based NV items (>60000 range)
- Configuration values in writable tier
- Device name/identifier strings

**Protected (Cannot modify directly):**
- Hardware IDs (IMEI, IMSI)
- Carrier lock keys
- SIM unlock codes
- Device security identifiers

## Extended Scanning Needed

To find additional writable items, recommend:

### Phase 1: High-Number Item Scan
```bash
# Scan NV 60000-65535 for writeability
# Expected: Find 5-10 additional writable items
# Focus: String-type items at 60000+
```

### Phase 2: Configuration Item Testing
```bash
# Test items known to be configuration-related
# Band preferences, APN settings, etc.
# These may be writable via QMI despite normal locks
```

### Phase 3: FOTA State Items
```bash
# Firmware update uses NV to track state
# FOTA-related items: NV 4500-5500 range
# May be writable to control update behavior
```

## Technical Details

### Write Command Format
```bash
/opt/nvtl/bin/nwcli qmi_idl write_nv <NV_ID> <INDEX> <VALUE>
```

**Parameters:**
- `NV_ID`: Numeric NV item ID (0-65535)
- `INDEX`: Storage index (usually 0 for primary)
- `VALUE`: Hex-encoded or string value to write

### Response Interpretation
- **No error output** = Write accepted (WRITABLE)
- **"Access denied"** = Item protected (LOCKED)
- **Command error** = Invalid NV ID (INVALID)

### Restoration Mechanism
- All writable items can be restored to original values
- Recommended: Always read → modify → verify → restore
- Safety: Device remains stable even with wrong writes

## Attack Surface Analysis

### Direct NV Modification
- **Risk Level**: MEDIUM (writable items exist)
- **Exploitation**: Modify PRI version, config strings
- **Protection**: Most critical items still locked
- **Mitigation**: Version checks, digital signatures (if present)

### FOTA Firmware Update
- **Risk Level**: HIGH (full infrastructure present)
- **Exploitation**: Inject custom firmware via FOTA
- **Tools Available**: `fota_cli`, `fota_linux_pri.sh`
- **Status**: Requires deeper investigation

### Configuration File Modification
- **Risk Level**: MEDIUM (EFS read confirmed)
- **Exploitation**: Modify `/policyman/device_config.xml`
- **Impact**: Could change device capabilities/bands
- **Status**: Write capability untested

### DIAG Protocol Access
- **Risk Level**: HIGH (direct modem access)
- **Exploitation**: Use `/dev/diag` for low-level commands
- **Tools Available**: `diag_read`, QMI libraries
- **Status**: Requires reverse engineering

## Recommendations

### For AI Agents & Researchers
1. **Extended writable item search** - Scan 60000-65535 for more writes
2. **FOTA exploitation** - Investigate firmware update chain
3. **Binary library analysis** - Extract write functions from .so files
4. **DIAG protocol** - Develop protocol handler for direct modem access

### For Device Hardening (Manufacturer)
1. **Protect string NV items** - Apply same locks as binary items
2. **Verify firmware signatures** - Prevent FOTA firmware injection
3. **Lock configuration files** - Protect EFS write capabilities
4. **DIAG disabled** - Remove diagnostic interfaces in production

### For Secure Operation (Users)
1. **Monitor NV modifications** - Check for unauthorized changes
2. **FOTA controls** - Implement approval workflow
3. **Disable debug features** - Turn off diagnostic interfaces if possible
4. **Root access control** - Restrict shell access to ADB connection

## Conclusion

The discovery of writable NV items (NV 60044 confirmed) breaks the assumption of complete lock-down. While critical items remain protected, the device is not as immutable as factory defaults suggest. The presence of FOTA infrastructure, SMD channels, and DIAG interfaces represents significant attack vectors if exploited in combination.

**Device Security Rating: MODERATE (not HIGH)**
- Individual protections are strong
- Multiple bypass vectors exist
- Combination attacks likely effective
- Manufacturer tools can modify device behavior
