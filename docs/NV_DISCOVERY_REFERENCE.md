# NV Item Discovery & Device Capabilities Documentation

## Overview

This document catalogs the results of comprehensive NV item discovery, write capability testing, and filesystem exploration on the Inseego MiFi 8800L device. It serves as a reference for future investigation and reveals patterns, constraints, and undocumented capabilities.

---

## NV Item Categories & Access Patterns

### Readable NV Items (Success Pattern)

Items that return hex data when queried via `nwcli qmi_idl read_nv`:

- **Pattern**: First byte indicates data type/length field
- **Range**: Scattered across 0-10000+ (not contiguous)
- **Common ranges**:
  - 0-50: System initialization items
  - 100-500: Carrier/network configuration
  - 550-600: Device identifiers (IMEI, SIM, etc.)
  - 946-1016: SMS/messaging configuration
  - 2954+: Advanced band/feature settings
  - 3461, 4399, 6830: Lock/carrier status

### Protected NV Items (Error 8193 - Access Denied)

Items that require SPC (Service Programming Code) or carrier-specific credentials:

- **Error Message**: "QMI error 8193"
- **Known protected items**: 5, 851, 4398, 6831, 7000+
- **Pattern**: Typically carrier/subsidy lock related
- **Workaround**: None without SPC code

### Unresponsive/Non-existent Items

Items that return generic errors or no response:

- **Common in ranges**: 11-49, 51-99, 151-199, etc.
- **Pattern**: Gaps between populated ranges
- **Likely cause**: Reserved but unallocated NV space

---

## Write Capability Analysis

### Current Findings

- **Writable items**: Limited subset of readable items
- **Known writable items**:
  - `/nv/item_files/modem/mmode/lte_bandpref` (8 bytes, bitmask)
  - EFS files via `nwcli qmi_idl write_file` (requires path knowledge)
  - Potentially: NV items controlling band preferences, tech selection

### Write Testing Methodology

```bash
# 1. Read current value
ORIG=$(nwcli qmi_idl read_nv NV_ID 0 | head -1)

# 2. Create test value
echo -n -e '\x00' > /tmp/nv_test.bin

# 3. Attempt write
nwcli qmi_idl write_nv NV_ID 0 /tmp/nv_test.bin

# 4. Verify result
# - "success" = writable
# - "8193" = protected
# - Other error = read-only or permission denied
```

### Protection Levels

| Level | Access | Items | Method |
|-------|--------|-------|--------|
| 0 | Read-Write | EFS paths, lte_bandpref | Full access |
| 1 | Read-Only | Most device identifiers | Readable but protected |
| 2 | Access Denied | Carrier lock items | Requires SPC/auth |
| 3 | Non-existent | Reserved ranges | No response |

---

## Device Identifiers (NV Items)

### Critical Read-Only Items

| NV ID | Description | Size | Value | Access |
|-------|-------------|------|-------|--------|
| 550 | IMEI (BCD encoded) | 8 | 08 9a 09 10... | Read-Only |
| 3461 | SIM Lock Status | 256 | 01 00... | Read-Only |
| 4399 | Subsidy Lock | 256 | 01 00... | Read-Only |
| 6830 | Carrier Info | 256 | 0a 00... | Read-Only |
| 60044 | PRI Version | 256 | ASCII text | Read-Only |

### Device-Level NV Items (via `nwnvitem`)

- `NW_NV_MAC_ID_I`: WiFi MAC (18:EE:86:AF:C8:74)
- `NW_NV_USB_MAC_ID_I`: USB MAC (00:15:FF:85:73:98)
- `NW_NV_PRI_INFORMATION_I`: Firmware version
- `NW_NV_LINUX_ROOT_PASSWORD_I`: Root password hash (MD5 crypt)
- `NW_NV_USB_DEFAULT_MODE_I`: USB mode (DEBUG)
- `NW_NV_LINUX_RUN_LEVEL_I`: Boot runlevel (0 3)

---

## EFS File System

### Accessible Paths

Confirmed readable/writable via `nwcli qmi_idl read_file/write_file`:

```
/nv/item_files/modem/mmode/lte_bandpref          (8 bytes, writable)
/policyman/device_config.xml                      (503 bytes, readable)
```

### Known Paths (from library strings)

Paths found in `libmal_qct.so` but may not be accessible without proper context/SPC:

```
/nv/item_files/modem/lte/rrc/csp/band_priority_list
/nv/item_files/modem/mmode/sxlte_timers
/nv/item_files/ims/qp_ims_voip_config
/nv/item_files/ims/qp_ims_sms_config
/nv/item_files/ims/ims_sip_config
/nv/item_files/ims/qipcall_enable_hd_voice
/nv/item_files/ims/qipcall_codec_mode_set
/nv/item_files/cdma/1xcp/disable_so35_so36
/nv/item_files/cne/1XDataServiceTransferTimer
```

### Access Pattern

- Most accessible via `nwcli qmi_idl read_file <output.bin> <path> <maxbytes>`
- Write via `nwcli qmi_idl write_file <input.bin> <path>`
- Failures typically silent (no output) or generic errors
- **Constraint**: Path must be known (no directory listing available)

---

## Qualcomm Utilities & Hidden Programs

### Primary Tools

| Tool | Location | Purpose | Key Commands |
|------|----------|---------|--------------|
| `nwcli qmi_idl` | `/opt/nvtl/bin/nwcli` | QMI interface | read_nv, write_nv, read_file, write_file |
| `modem2_cli` | `/opt/nvtl/bin/modem2_cli` | Modem control | 140+ subcommands |
| `modem_at_server_cli` | `/opt/nvtl/bin/modem_at_server_cli` | AT server testing | Limited (mostly test hooks) |
| `nwnvitem` | `/opt/nvtl/bin/nwnvitem` | Device NV items | -r -e (read), -w -e (write) |

### Alternative/Hidden Programs

Discovery via `/opt/nvtl/bin` enumeration reveals 100+ tools:

```
sms_cli, modem2_cli, usb_cli, wifi_cli, gps_cli, router2_cli
fota_cli, settings_cli, factory_reset_cli, omadm_cli
nvtl_*.sh (wrapper scripts)
And many more - see fs_exploration.sh output for complete list
```

### Lesser-Known Capabilities

- **diag_read**: Direct DIAG protocol logging
- **nvtl_*.sh**: Wrapper scripts for common operations
- **libqmi*.so**: Qualcomm QMI framework (dynamic linking)
- **modem_at_serverd**: Daemon for AT passthrough

---

## Access Mechanisms

### Primary Interfaces

1. **QMI (Qualcomm Messaging Interface)**
   - Via: `nwcli qmi_idl` command
   - Scope: NV item read/write, file operations
   - Limitation: Requires QMI service connection
   - **Strongest interface** - most reliable

2. **AT Commands**
   - Via: Raw `/dev/at_*` ports or `modem2_cli run_raw_command`
   - Scope: PDU encoding, SMS sending, band switching
   - Limitation: Ports often busy, interactive mode required
   - **Weaker for NV** - limited NV access via AT

3. **Device Files**
   - Via: Direct `/dev/diag`, `/dev/at_*` writes
   - Scope: DIAG protocol, AT commands
   - Limitation: Port contention, no error feedback
   - **Unreliable** - best avoided

### Protection Enforcement

- **Carrier Lock**: Enforced by modem firmware, requires SPC code
- **Subsidy Lock**: Stored in NV 4399, locks certain configurations
- **EFS Access Control**: Some paths require authorization context
- **QMI Error 8193**: Universal "access denied" response

---

## Write Capability Constraints

### Why Most Items Are Read-Only

1. **Carrier Configuration Lock**
   - Prevents unauthorized device configuration
   - Enforced at modem firmware level
   - Requires SPC (Service Programming Code) for override

2. **Device Identity Protection**
   - IMEI, SIM slot configuration immutable
   - Prevents fraud/cloning
   - Hardware-enforced at low levels

3. **Firmware Integrity**
   - PRI version, feature flags protected
   - Prevents malformed configurations
   - Modem validates all writes

### Successfully Writable Categories

1. **Band Preferences**
   - Path: `/nv/item_files/modem/mmode/lte_bandpref`
   - Method: 8-byte bitmask (FF=all bands enabled)
   - Reason: User-configurable network preference

2. **Roaming Flags**
   - Method: `modem2_cli roam_set_enabled`
   - Reason: User-configurable network behavior

3. **APN Profiles**
   - Method: `modem2_cli prof_set_pri_tech`
   - Reason: User-configurable network attachment

---

## Recommended Investigation Paths

### For Future AI/Human Investigation

1. **SPC Code Discovery**
   - Look for SPC in kernel logs, memory dumps, firmware strings
   - Try common defaults: 000000, 123456, 1234, etc.
   - May be extractable from carrier systems

2. **EFS Path Enumeration**
   - Extract all strings from `libmal_qct.so` containing '/'
   - Cross-reference with modem firmware blobs
   - Attempt access to discovered paths systematically

3. **Protected Item Analysis**
   - Map error codes to specific lock types
   - Attempt to understand lock state via read_nv
   - Look for lock bypass in QMI error handling

4. **Firmware Binary Analysis**
   - Use `strings` on `/opt/nvtl/lib/libmodem*.so`
   - Look for hardcoded NV item IDs and ranges
   - Extract QMI protocol definitions

5. **Kernel Module Investigation**
   - Check loaded modules: `cat /proc/modules`
   - Look for Qualcomm-specific drivers
   - Might expose additional capabilities

6. **Alternative Access Methods**
   - Explore DIAG protocol directly (USB mode switch possible)
   - Try EDL (Emergency Download) mode for low-level access
   - Investigate fastboot capabilities

---

## Scripts & Tools Provided

### Automated Discovery

- **`nv_discovery.sh`**: Aggressive scan of NV 0-20000, write testing
- **`fs_exploration.sh`**: Deep filesystem search for hints, configurations
- **`fast_audit.sh`**: Quick snapshot of current device state

### Operation

- **`auto_flash_sms.sh`**: Send Class 0 Flash SMS automatically
- **`auto_type0_sms.sh`**: Send Type 0 Silent SMS automatically
- **`sms_listener.sh`**: Continuous background SMS listener

---

## Known Limitations & Future Work

### Current Blockers

1. SPC code required for carrier lock modification
2. Most NV items protected by firmware
3. AT port contention makes direct access difficult
4. No directory listing for EFS filesystem

### Potential Breakthroughs

1. Discovering SPC code or bypass
2. Understanding QMI security context requirements
3. Exploiting firmware vulnerabilities
4. DIAG protocol exploitation
5. EDL mode full device dump

### Documentation Needs

- [ ] Complete NV item mapping (0-20000) with descriptions
- [ ] EFS path exhaustive catalog
- [ ] QMI protocol packet specifications
- [ ] Modem firmware disassembly
- [ ] Carrier unlock procedures

---

## Reference Commands

### NV Operations

```bash
# Read NV item
nwcli qmi_idl read_nv <ID> <INDEX>

# Write NV item
nwcli qmi_idl write_nv <ID> <INDEX> <FILE.bin>

# Read EFS file
nwcli qmi_idl read_file <OUTPUT.bin> <PATH> <MAXBYTES>

# Write EFS file
nwcli qmi_idl write_file <INPUT.bin> <PATH>

# Device NV items
nwnvitem -r -e <ITEM_NAME>
nwnvitem -w -e <ITEM_NAME> -d <DATA>
```

### Modem Operations

```bash
# Get device info
modem2_cli get_info

# Get connection state
modem2_cli get_state

# Enable roaming
modem2_cli roam_set_enabled 1

# Set APN
modem2_cli prof_set_pri_tech

# Get carrier unlock status
modem2_cli get_carrier_unlock

# All available commands
modem2_cli help
```

### SMS Operations

```bash
# List messages (0=PreInbox, 1=Inbox, 2=Outbox, 3=Sent)
sms_cli get_list <FOLDER>

# Send SMS
sms_cli send

# Read message
sms_cli read <MESSAGE_ID>

# Delete message
sms_cli delete <MESSAGE_ID>
```

---

## Document Metadata

- **Created**: 2025-12-04
- **Device**: Inseego MiFi 8800L (Verizon)
- **Firmware**: SDx20ALP-1.22.11
- **PRI**: PRI.90029477 REV 151 Alpine VERIZON
- **Status**: Unlocked, LTE connected, SMS working
- **Purpose**: Reference for future NV item investigation

---

**This document should be updated with findings from each new investigation phase to build a comprehensive reference database for AI agents and human researchers.**
