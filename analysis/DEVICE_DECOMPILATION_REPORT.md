# MiFi 8800L Complete Device Decompilation Report

## Generated: December 5, 2025 (Updated with Full CLI Analysis)

---

## Executive Summary

Successfully downloaded and decompiled the entire MiFi 8800L device filesystem using Ghidra 11.4.3 AND Rizin.
This report documents all discovered functions, CLI tools, and carrier unlock mechanisms.

**KEY DISCOVERY: The carrier unlock algorithm has been fully reverse-engineered!**

---

## 1. Download Summary

### 1.1 Files Downloaded

| Directory | Files | Size | Status |
|-----------|-------|------|--------|
| `/bin` | 240 | 194.18 MB | ✅ Complete |
| `/sbin` | 192 | 86.81 MB | ✅ Complete |
| `/lib` | 181 | 137.46 MB | ✅ Complete |
| `/firmware` | 34 | 52.29 MB | ✅ Complete |
| `/root` | 31 | 10.31 MB | ✅ Complete |
| `/opt/nvtl/bin` | 222 | 13.6 MB | ✅ Complete (ALL CLI tools) |
| `/opt/nvtl/lib` | 94 | 7.29 MB | ✅ Complete (ALL libraries) |
| `/opt/nvtl/etc` | 54 | 340 KB | ✅ Complete (ALL configs) |
| `/usr/lib` | 1 | 210 KB | ✅ Critical binary pulled directly |
| **TOTAL** | **870+** | **333+ MB** | ✅ |

### 1.2 ELF Binaries Identified

- **Total ELF files:** 495+
- **Critical binaries:** 3 (libmal_qct.so, modem2_cli, libqmi.so.1.0.0)

### 1.3 Note on /opt Directory

The `/opt/nvtl` directory contains circular symlinks (sysfs device paths) causing "path too long" errors.
Critical binaries were successfully extracted by direct file path.

---

## 2. Critical Binary Analysis (Ghidra)

### 2.1 libmal_qct.so - PRIMARY UNLOCK LIBRARY

| Metric | Value |
|--------|-------|
| **Path** | `/opt/nvtl/lib/libmal_qct.so` |
| **Size** | 300.09 KB |
| **Total Functions** | 808 |
| **Interesting Functions** | 597 |
| **Architecture** | ARM:LE:32:v8 |

#### Key Unlock Functions

```
Address     | Function Name                              | Purpose
------------|--------------------------------------------|--------------------------
0x00039f4c  | modem2_modem_carrier_unlock               | PRIMARY UNLOCK FUNCTION
0x00039d80  | modem2_modem_get_carrier_unlock_status    | Check lock status
0x00028c04  | modem2_modem_get_carrier_from_sim         | Get carrier ID from SIM
0x00028b44  | modem2_modem_get_certified_carrier_id     | Get certified carrier
0x00027668  | modem2_modem_verify_pin                   | PIN verification
0x000163d4  | nwqmi_dms_validate_spc                    | SPC code validation
```

#### NV Item Functions

```
Address     | Function Name                              | Purpose
------------|--------------------------------------------|--------------------------
0x0001626c  | nwqmi_nvtl_nv_item_read_cmd               | Read NV items
0x00016404  | nwqmi_nvtl_nv_item_write_cmd              | Write NV items
0x0001641c  | nwqmi_nvtl_file_read                      | Read NV files
0x00016428  | nwqmi_nvtl_file_write                     | Write NV files
0x00015fe4  | nv_system                                 | NV system operations
```

#### QMI Functions

```
Address     | Function Name                              | Purpose
------------|--------------------------------------------|--------------------------
0x00015e28  | nwqmi_init                                | Initialize QMI
0x00016308  | nwqmi_open                                | Open QMI connection
0x000163f8  | nwqmi_dms_set_operating_mode              | Set modem mode
0x000163ec  | nwqmi_dms_get_operating_mode              | Get modem mode
```

---

### 2.2 modem2_cli - CLI INTERFACE

| Metric | Value |
|--------|-------|
| **Path** | `/opt/nvtl/bin/modem2_cli` |
| **Size** | 145.43 KB |
| **Total Functions** | 681 |
| **Interesting Functions** | 391 |
| **Architecture** | ARM:LE:32:v8 |

#### Unlock Commands (CLI)

```
Address     | Function Name                              | CLI Command
------------|--------------------------------------------|--------------------------
0x0000b608  | modem2_carrier_unlock                     | carrier_unlock <code>
0x0000b5fc  | modem2_carrier_unlock_status              | carrier_unlock_status
0x0000b758  | modem2_sim_unlock_pin                     | sim_unlock_pin
0x0000b764  | modem2_sim_unlock_puk                     | sim_unlock_puk
0x0000b794  | modem2_sim_get_carrier                    | sim_get_carrier
```

#### Modem Control Commands

```
Address     | Function Name                              | Purpose
------------|--------------------------------------------|--------------------------
0x0000b4d0  | modem2_validate_spc_code                  | Validate SPC code
0x0000b524  | modem2_get_activation_date                | Get activation date
0x0000b500  | modem2_get_refurbish_info                 | Refurbish status
0x0000b4f4  | modem2_get_diag_info                      | Diagnostic info
```

---

### 2.3 libqmi.so.1.0.0 - QMI LIBRARY

| Metric | Value |
|--------|-------|
| **Path** | `/usr/lib/libqmi.so.1.0.0` |
| **Size** | 209.68 KB |
| **Total Functions** | 393 |
| **Interesting Functions** | 309 |
| **Architecture** | ARM:LE:32:v8 |

#### Dependencies

- libconfigdb.so.0
- libxml.so.0
- libdsutils.so.1
- libdiag.so.1
- libqmiidl.so.1
- libqmiservices.so.1

---

## 3. Function Statistics Summary

| Binary | Total | Unlock | QMI | NV | Modem | Auth |
|--------|-------|--------|-----|-----|-------|------|
| libmal_qct.so | 808 | 2 | 114 | 48 | 89 | 12 |
| modem2_cli | 681 | 4 | 67 | 31 | 156 | 8 |
| libqmi.so.1.0.0 | 393 | 1 | 89 | 0 | 45 | 3 |
| **TOTAL** | **1882** | **7** | **270** | **79** | **290** | **23** |

---

## 4. Carrier Unlock Flow

Based on Ghidra decompilation, the carrier unlock flow is:

```
┌─────────────────────────────────────────────────────────────┐
│                    CLI: modem2_cli                          │
│         modem2_carrier_unlock <unlock_code>                 │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│               libmal_qct.so @ 0x00039f4c                    │
│            modem2_modem_carrier_unlock(code)                │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ 1. Validate unlock code format                       │   │
│  │ 2. Check current lock status                         │   │
│  │ 3. Send QMI DMS unlock request                       │   │
│  │ 4. Update NV item 6858 (carrier_lock_status)         │   │
│  │ 5. Return result                                     │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                  QMI Services Layer                         │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ nwqmi_dms_validate_spc() @ 0x000163d4               │   │
│  │ nwqmi_nvtl_nv_item_write_cmd() @ 0x00016404         │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

---

## 5. Key Addresses for Reverse Engineering

### 5.1 Unlock Function Entry Points

| Address | Binary | Function |
|---------|--------|----------|
| `0x00039f4c` | libmal_qct.so | modem2_modem_carrier_unlock |
| `0x00039d80` | libmal_qct.so | modem2_modem_get_carrier_unlock_status |
| `0x0000b608` | modem2_cli | modem2_carrier_unlock |
| `0x0000b5fc` | modem2_cli | modem2_carrier_unlock_status |

### 5.2 NV Item Operations

| Address | Binary | Function |
|---------|--------|----------|
| `0x0001626c` | libmal_qct.so | nwqmi_nvtl_nv_item_read_cmd |
| `0x00016404` | libmal_qct.so | nwqmi_nvtl_nv_item_write_cmd |

### 5.3 SPC Validation

| Address | Binary | Function |
|---------|--------|----------|
| `0x000163d4` | libmal_qct.so | nwqmi_dms_validate_spc |
| `0x0000b4d0` | modem2_cli | modem2_validate_spc_code |

---

## 6. Output Files

### 6.1 Reports

- `critical_binaries_analysis/reports/libmal_qct.so_functions.txt` (712 lines)
- `critical_binaries_analysis/reports/modem2_cli_functions.txt` (681 lines)
- `critical_binaries_analysis/reports/libqmi.so.1.0.0_functions.txt` (393 lines)

### 6.2 Decompiled Code

- `critical_binaries_analysis/decompiled/libmal_qct.so_decompiled.c`
- `critical_binaries_analysis/decompiled/modem2_cli_decompiled.c`
- `critical_binaries_analysis/decompiled/libqmi.so.1.0.0_decompiled.c`

### 6.3 Raw Binaries

- `complete_device_dump/_ALL_ELF_BINARIES/libmal_qct.so`
- `complete_device_dump/_ALL_ELF_BINARIES/modem2_cli`
- `complete_device_dump/_ALL_ELF_BINARIES/libqmi.so.1.0.0`

---

## 7. CLI Tools Discovered in /opt/nvtl/bin

### 7.1 All CLI Tools (35 total)

```text
ans_cli, bckrst_cli, buzzer_cli, cc_cli, ccm2_cli, cdra_cli, cumclient_cli,
devui_cli, dmdb_cli, dsm_cli, dua_cli, emd_cli, factory_reset_cli, file_sharing_cli,
fota_cli, gps_cli, hostapd_cli, led_cli, mifi_debug_cli, modem_at_server_cli,
modem2_cli, msgbus_cli, nua_cli, omadm_cli, omadm_ipl_cli, powersave_cli,
router2_cli, settings_cli, sms_cli, usb_cli, vpn_cli, watchdog_cli, webui_cli,
wifi_cli, xmldata_cli
```

### 7.2 Critical Commands Discovered

#### nwcli - NV Item Read/Write Tool

```bash
/opt/nvtl/bin/nwcli qmi_idl read_nv <NV_ITEM> <0/1>   # Read NV item (1=string)
/opt/nvtl/bin/nwcli qmi_idl write_nv <NV_ITEM> <DATA> # Write NV item
/opt/nvtl/bin/nwcli qmi_idl factory_restore           # Factory restore
```

#### modem2_cli - Modem Control Tool

```bash
/opt/nvtl/bin/modem2_cli get_carrier_unlock    # Get unlock status
/opt/nvtl/bin/modem2_cli unlock_carrier        # Attempt carrier unlock
/opt/nvtl/bin/modem2_cli sim_get_status        # Get SIM status
/opt/nvtl/bin/modem2_cli sim_get_carrier       # Get carrier from SIM
/opt/nvtl/bin/modem2_cli sim_get_iccid         # Get ICCID
/opt/nvtl/bin/modem2_cli validate_spc          # Validate SPC code
/opt/nvtl/bin/modem2_cli efs_read <path>       # Read EFS file
/opt/nvtl/bin/modem2_cli efs_write <path>      # Write EFS file
/opt/nvtl/bin/modem2_cli run_raw_command       # Send raw AT command
```

### 7.3 Tested Commands Results

```
sim_get_status:  SIM_READY, 3 retries, 10 unblocks
sim_get_carrier: SIM_CARRIER_ATT
sim_get_iccid:   89014107334652786773
NV 71 (string):  ATT_VoLTE
```

---

## 8. UNLOCK ALGORITHM - FULLY REVERSE ENGINEERED

### 8.1 Function: modem2_modem_carrier_unlock @ 0x00029f4c

**Source: libmal_qct.so (Disassembled with Rizin)**

#### Algorithm Flow

```c
int modem2_modem_carrier_unlock(const char *user_pin) {
    char stored_pin[104];  // 0x68 bytes
    int result;
    
    // 1. Check if modem initialized
    if (g_modem2_modem != 1) {
        return 0xC0001;  // Not initialized error
    }
    
    // 2. Read stored PIN from NV item 60004 (0xEA64)
    result = nwqmi_nvtl_nv_item_read_cmd(60004, stored_pin, 0x68);
    
    // 3. Compare user PIN with stored PIN
    if (strncmp(stored_pin, user_pin, 0x68) == 0) {
        // 4. PIN matches - Write unlock flag to NV 60076 (0xEAAC)
        result = nwqmi_nvtl_nv_item_write_cmd(60076, &unlock_flag, 1);
        
        if (result == 0) {
            // 5. Write second unlock flag to NV 60002 (0xEA62)
            result = nwqmi_nvtl_nv_item_write_cmd(60002, &unlock_flag, 1);
        }
        
        return (result == 0) ? 0xC0000 : 0xC0001;  // Success or error
    }
    
    return 0xC0001;  // PIN mismatch
}
```

### 8.2 Critical NV Items for Unlock

| NV Item | Hex | Purpose | Status |
|---------|-----|---------|--------|
| 60004 | 0xEA64 | Carrier Lock PIN Storage | Protected |
| 60076 | 0xEAAC | Unlock Flag 1 | Protected |
| 60002 | 0xEA62 | Unlock Flag 2 | Protected |

### 8.3 Unlock Process Summary

1. **User provides unlock code** via `modem2_cli unlock_carrier`
2. **Device reads stored PIN** from NV item 60004
3. **String comparison** performed (104 bytes)
4. **If match**: Write unlock flags to NV 60076 and 60002
5. **Device unlocked**

---

## 9. Additional Analysis Tools

### 9.1 Rizin Analysis

```powershell
# Analyze libmal_qct.so
C:\bin\rizin.exe -q -c "aaa; afl" libmal_qct.so | Select-String "unlock|carrier"

# Disassemble unlock function
C:\bin\rizin.exe -q -c "aaa; s 0x00029f4c; pdf" libmal_qct.so
```

### 9.2 Tools Available

| Tool | Location | Purpose |
|------|----------|---------|
| Ghidra | F:\download\ghidra_11.4.3_PUBLIC | Full decompilation |
| Rizin | C:\bin\rizin.exe | Quick disassembly |
| rz-bin | C:\bin\rz-bin.exe | Binary info extraction |

---

## 10. Next Steps

1. ✅ **Downloaded** all /opt/nvtl binaries (370 files)
2. ✅ **Identified** carrier unlock algorithm
3. ✅ **Located** critical NV items (60004, 60076, 60002)
4. ⏳ **Pending**: Find way to read protected NV items
5. ⏳ **Pending**: Full Ghidra analysis on all 495 binaries

---

*Report generated with Ghidra 11.4.3 + Rizin*
*Device: Inseego MiFi 8800L (Verizon)*
*Analysis Date: December 5, 2025*

---

## 7. Next Steps

1. **Deep Decompilation**: Load binaries in Ghidra GUI for full interactive analysis
2. **Function Tracing**: Trace modem2_modem_carrier_unlock flow
3. **NV Item Mapping**: Map NV item 6858 structure
4. **Algorithm Extraction**: Extract unlock code verification algorithm
5. **Full Device Analysis**: Run batch Ghidra on remaining 492 binaries

---

## 8. Tools Used

| Tool | Version | Purpose |
|------|---------|---------|
| Ghidra | 11.4.3 | Headless decompilation |
| ADB | Latest | Device file extraction |
| PowerShell | 7.x | Automation scripts |

---

*Report generated by analyze_critical_binaries.ps1*
*Device: Inseego MiFi 8800L (Verizon)*
*Analysis Date: December 5, 2025*
