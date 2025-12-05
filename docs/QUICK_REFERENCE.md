# MiFi 8800L Reverse Engineering - Quick Reference Card

**Last Updated**: December 2025  
**Version**: Session 7/8 Part 3 Complete  
**Device**: Inseego MiFi 8800L (SDx20ALP-1.22.11)  

---

## 🎯 Critical NV Items

| NV Item | Dec | Hex | Size | Purpose | Access |
|---------|-----|-----|------|---------|--------|
| **59,492** | 0xEA64 | 59492 | 104 bytes | Master NCK (PLAINTEXT) | R/W ⚠️ |
| **60,076** | 0xEAAC | 60076 | 1 byte | Primary lock flag | R/W ⚠️ |
| **59,490** | 0xEA62 | 59490 | 1 byte | Secondary lock flag | R/W ⚠️ |
| **3,461** | 0x0D89 | 3461 | 1 byte | Lock status | R |
| **550** | 0x0226 | 550 | 80 bytes | IMEI | R |
| **???** | ??? | TBD | ??? | OTKSK counter (SPC retries) | R |

### NV Item Values

```bash
# Lock Status
0x00 = UNLOCKED ✅
0x01 = LOCKED 🔒

# NCK Format
104-byte ASCII string (null-terminated at byte 105)
Example: "ABCD1234EFGH5678..." (carrier-specific)
```

---

## 🔧 Safe Operations

### ✅ Always Safe (Read-Only)

```bash
# Check unlock status
modem2_cli unlock_carrier_status

# Read lock flags
nwcli read_nv 0xEAAC 1  # Primary lock
nwcli read_nv 0xEA62 1  # Secondary lock
nwcli read_nv 0x0D89 1  # Status

# Check SPC retries BEFORE attempting validation
modem2_cli get_spc_validate_limit

# Read IMEI
nwcli read_nv 0x0226 80
modem2_cli get_device_info
```

### ⚠️ Use With Caution (Limited Attempts)

```bash
# SPC validation (~10 attempts, PERMANENT LOCK if exhausted!)
modem2_cli validate_spc <SPC>
# Default SPC: "000000" (6 zeros)

# Carrier unlock (requires SPC validation first)
modem2_cli unlock_carrier <NCK>
# NCK is 104-byte carrier-provided string
```

### ❌ NEVER Use (High Risk)

```bash
# Direct NV writes (KNOWN BUG @ offset 0x4404)
nwcli write_nv 0xEAAC 0  # May brick device!
nwcli write_nv 0xEA62 0  # May brick device!
nwcli write_nv 0xEA64 <NCK>  # May brick device!

# Reason: write_nv has a confirmed bug that can corrupt NV memory
```

---

## 📦 Binary Inventory

### Critical Binaries

| Binary | Size | Functions | Purpose |
|--------|------|-----------|---------|
| **libmal_qct.so** | 307 KB | 353 | Primary unlock implementation ⭐ |
| libqmi.so.1.0.0 | 214 KB | 114 | QMI client interface |
| modem2_cli | 148 KB | 196 cmds | Modem control CLI |
| nwcli | 25 KB | 72 funcs | NV item access CLI (39 NV-related) |
| qmi_ip_multiclient | 112 KB | 5 QMI | Multi-client manager |

### CLI Tools

| Tool | Size | Commands | Purpose |
|------|------|----------|---------|
| modem2_cli | 148 KB | 196 | Modem operations |
| nwcli | 25 KB | 72 | NV item access |
| sms_cli | 15 KB | 14 | SMS (via AT) |
| gps_cli | 13 KB | 16 | GPS position |
| wifi_cli | 39 KB | Various | WiFi AP config |
| rmnetcli | 16 KB | Various | Mobile data routing |

---

## 🔑 Unlock Algorithm

### Function Locations (libmal_qct.so)

```c
// Primary unlock function
@ 0x00039f4c: modem2_modem_carrier_unlock(char *nck)
   ├─ Read NV 0xEA64 (master NCK)
   ├─ Compare: strncmp(stored, user, 104)  // ⚠️ INSECURE
   ├─ Write NV 0xEAAC = 0 (if match)
   └─ Write NV 0xEA62 = 0 (if match)

// Unlock status query
@ 0x00039d80: modem2_modem_get_carrier_unlock_status(uint32_t *out)
   ├─ Read NV 0xEAAC
   └─ Read NV 0xEA62

// SPC validation
@ 0x00037964: modem2_modem_validate_spc(char *spc)
   ├─ Check OTKSK counter
   └─ Call: nwqmi_dms_validate_spc() → QMI DMS 0x02

// SPC retry counter
@ 0x0003788c: modem2_modem_get_spc_validate_limit(int *out)
   └─ Call: nwqmi_nvtl_read_otksk_counter()

// IMEI getter
@ 0x00042b84: dsm_modem_get_imei(void *buf, uint size)
   └─ Read NV 0x0226
```

### Unlock Flow

```
1. SPC Validation (prerequisite):
   modem2_cli validate_spc 000000
   └─ QMI DMS 0x02 → Baseband validates SPC
   └─ ~10 attempts before PERMANENT LOCK
   
2. NCK Unlock:
   modem2_cli unlock_carrier <NCK>
   └─ Read NV 0xEA64 (master NCK)
   └─ strncmp(stored, user, 104)
   └─ If match: Write 0 to NV 0xEAAC & 0xEA62
   
3. Status Check:
   modem2_cli unlock_carrier_status
   └─ Return 0=unlocked, 1=locked
```

---

## 🌐 QMI Services

### Service IDs

| ID | Service | Purpose | Functions |
|----|---------|---------|-----------|
| 0x01 | WDS | Wireless Data | 5 |
| 0x02 | DMS | Device Mgmt | 5 (SPC validation) ⭐ |
| 0x03 | NAS | Network Access | 5 |
| 0x04 | QOS | Quality of Service | 1 |
| 0x0A | CAT2 | Card App Toolkit | 455 refs ⭐⭐⭐ |
| 0x0B | UIM | SIM Operations | 3 |
| 0x10 | LOC | GPS Location | External |

### QMI Function Categories

**DMS (Device Management - Service 0x02)**:

- nwqmi_dms_validate_spc ⭐ (SPC validation)
- nwqmi_dms_get_device_hwrev
- nwqmi_dms_get_device_revid
- nwqmi_dms_get_factory_sku
- nwqmi_dms_get_device_serial_numbers

**NV Access**:

- nwqmi_nvtl_nv_item_read_cmd (7 implementations)
- nwqmi_nvtl_nv_item_write_cmd (7 implementations)
- nwqmi_nvtl_file_read (EFS files)
- nwqmi_nvtl_file_write (EFS files)
- nwqmi_nvtl_read_otksk_counter (SPC retries)

---

## 📁 EFS Filesystem Paths

### LTE/Network Configuration

```
/nv/item_files/modem/mmode/lte_bandpref
/nv/item_files/modem/lte/rrc/csp/band_priority_list
/nv/item_files/modem/mmode/sxlte_timers
```

### IMS/VoLTE (9 files)

```
/nv/item_files/ims/qp_ims_voip_config
/nv/item_files/ims/qp_ims_sip_extended_0_config
/nv/item_files/ims/ims_sip_config
/nv/item_files/ims/qp_ims_sms_config
/nv/item_files/ims/qipcall_enable_hd_voice
/nv/item_files/ims/qipcall_codec_mode_set
/nv/item_files/ims/qipcall_codec_mode_set_amr_wb
/nv/item_files/ims/qp_ims_reg_extended_0_config
/nv/item_files/ims/qp_ims_presence_config
/nv/item_files/ims/qipcall_config_items
```

### Other

```
/nv/item_files/cne/1XDataServiceTransferTimer
/nv/item_files/cdma/1xcp/disable_so35_so36
```

---

## 🔒 Security Vulnerabilities

| Severity | Issue | Impact | CVE |
|----------|-------|--------|-----|
| 🔴 CRITICAL | Plaintext NCK (NV 0xEA64) | Root → unlock bypass | N/A |
| 🔴 CRITICAL | SPC permanent lock | ~10 attempts → brick | N/A |
| 🔴 CRITICAL | write_nv bug (offset 0x4404) | NV corruption → brick | N/A |
| 🟡 HIGH | strncmp() timing attack | NCK extraction | N/A |
| 🟡 MEDIUM | CAT2 service exposure | Malicious SIM apps | N/A |
| 🟡 MEDIUM | No NCK retry limit | Unlimited attempts | N/A |
| 🟢 LOW | QMI multi-client races | Theoretical | N/A |

### Security Best Practices

1. ✅ Always check SPC retry counter BEFORE validation
2. ✅ Obtain correct NCK from carrier (don't guess)
3. ✅ Use read-only operations for status checks
4. ❌ NEVER use write_nv on lock-related NV items
5. ⚠️ Treat SPC validation as "limited attempts" operation
6. ⚠️ Root access = full unlock capability (be careful)

---

## 🛠️ Development Tools

### Ghidra Analysis

```bash
# Batch analysis script
.\analysis\analyze_all_binaries.ps1

# Extract specific functions
.\analysis\extract_unlock_functions.py

# Detailed QMI/NV/EFS analysis
.\analysis\extract_qmi_details.py

# CLI command extraction
.\analysis\extract_cli_commands.py
```

### Python Integration (zerosms_cli.py)

```python
from tools.mifi_controller import MiFiController

mifi = MiFiController()

# Safe operations
status = mifi.get_unlock_status()
imei = mifi.get_imei()
spc_retries = mifi.get_spc_retries()

# Dangerous operations (use carefully)
result = mifi.validate_spc("000000")  # Limited attempts!
result = mifi.unlock_carrier(nck)     # Requires SPC first
```

---

## 📚 Documentation Files

### Primary Documents

| File | Size | Purpose |
|------|------|---------|
| **UNLOCK_ALGORITHM_ANALYSIS.md** | ~32 KB | Complete technical analysis |
| **SESSION_7_8_PART2_SUMMARY.md** | ~20 KB | Part 2 findings summary |
| **SESSION_7_8_PART3_SUMMARY.md** | ~40 KB | Part 3 complete analysis |
| **SAFE_OPERATIONS_GUIDE.md** | ~15 KB | Safety guidelines |
| **ARCHITECTURE_DIAGRAM.md** | ~25 KB | System architecture |
| **QUICK_REFERENCE.md** | ~10 KB | This file |

### Analysis Outputs

| File | Size | Content |
|------|------|---------|
| unlock_functions.c | 5,285 bytes | Decompiled C code (5 functions) |
| modem2_cli_analysis.txt | 3,565 bytes | CLI function mapping |
| libmal_qct_analysis.txt | 8,899 bytes | Complete binary analysis |
| *_qmi_nv_efs_detailed.txt | Varies | QMI/NV/EFS discoveries |

---

## 🚀 Common Tasks

### Check Unlock Status

```bash
# CLI method
modem2_cli unlock_carrier_status

# Direct NV read
nwcli read_nv 0xEAAC 1  # 0x00 = unlocked
nwcli read_nv 0xEA62 1  # 0x00 = unlocked

# Python method
python3 tools/zerosms_cli.py status
```

### Safe Unlock Procedure

```bash
# 1. Check SPC retry counter (IMPORTANT!)
modem2_cli get_spc_validate_limit
# Must be > 0, or device is PERMANENTLY LOCKED

# 2. Validate SPC (default: 000000)
modem2_cli validate_spc 000000
# If wrong SPC, counter decrements!

# 3. Unlock with carrier-provided NCK
modem2_cli unlock_carrier <NCK>
# NCK is 104-byte string from carrier

# 4. Verify unlock
modem2_cli unlock_carrier_status
# Should return: "Unlocked"
```

### Extract NCK (Requires Root)

```bash
# ⚠️ WARNING: This reveals the plaintext NCK
# Only use on devices you own for research

# Direct NV read (104 bytes)
nwcli read_nv 0xEA64 104

# Or via Python
python3 -c "
# SAFE example: read-only operations. Avoid extracting plaintext NCK unless you
# legally own the device and understand the risks.
from tools.mifi_controller import MiFiController
mifi = MiFiController()
print('Unlock status:', mifi.get_unlock_status())
print('IMEI:', mifi.get_imei())
print('SPC retries:', mifi.get_spc_retries())
"
```

---

## 🔬 Research Priorities

### High Priority 🔴

- [ ] Find OTKSK counter NV item ID
- [ ] Reverse NCK generation algorithm
- [ ] Investigate write_nv bug root cause
- [ ] Analyze CAT2 service (455 references)

### Medium Priority 🟡

- [ ] Document complete IMS/VoLTE config
- [ ] Reverse QMI IDL message format
- [ ] Test EFS file permission model
- [ ] Create QMI message fuzzer

### Low Priority 🟢

- [ ] Extract all CLI command structures
- [ ] Document hidden/undocumented commands
- [ ] Test SIM toolkit attack vectors
- [ ] Analyze JTAG/hardware debug interface

---

## 📞 Key Contacts & Resources

### Official Documentation

- Qualcomm QMI documentation (proprietary)
- Ghidra: <https://ghidra-sre.org/>
- MiFi firmware: SDx20ALP-1.22.11

### Project Files

- Repository: `f:\repo\zerosms`
- Documentation: `docs/`
- Analysis scripts: `analysis/`
- Python tools: `tools/`

---

## ⚡ Emergency Procedures

### Device Bricked After write_nv

1. ❌ **DO NOT** repeatedly try write_nv commands
2. ⚠️ Contact carrier for JTAG recovery (if available)
3. ⚠️ May require hardware repair/replacement
4. 📝 Document exactly what was written (for recovery)

### SPC Counter Exhausted

1. ❌ **PERMANENT LOCK** - No software recovery known
2. ⚠️ JTAG/hardware debug may be only option
3. ⚠️ Carrier may replace device under warranty
4. 📝 Always check counter BEFORE validation attempts

### General Recovery

```bash
# Check device state
modem2_cli get_device_info
modem2_cli get_modem_status

# Reboot modem (safe)
modem2_cli reset_modem

# Factory reset (nuclear option, erases all config)
modem2_cli factory_reset
```

---

**Generated**: December 2025  
**Version**: 1.0 (Session 7/8 Part 3 Complete)  
**Status**: Production Ready ✅  
**Confidence**: High (based on decompiled code analysis)
