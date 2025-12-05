# Binary Disassembly Findings - MiFi 8800L

## Session Date: 2025-01-30

## Binaries Analyzed

All binaries extracted from `/opt/nvtl/` on MiFi 8800L device.

---

## libmal_qct.so (307,292 bytes)

**Purpose:** QMI (Qualcomm MSM Interface) abstraction layer for modem communication

### Key Function Exports (from strings analysis)

#### NV Item Functions

- `nwqmi_nvtl_get_mac_index` - MAC address NV item access
- Functions reference NV write/read but symbols not explicitly exported (may be internal)

#### GPS/Location Services

- `nwqmi_gps_set_event_mask`
- `nwqmi_gps_inject_xtra_time`
- `nwqmi_gps_inject_xtra_part`
- `nwqmi_gps_start_fix_req`
- `nwqmi_gps_stop_fix_req`
- `nwqmi_gps_force_xtra_dl`

#### Network Access Service (NAS)

- `nwqmi_nas_get_3gpp2_subscription_info` - CDMA subscription
- `nwqmi_nas_get_system_info` - Network state
- `nwqmi_nas_get_device_config` - Device configuration
- `nwqmi_nas_get_sig_str` - Signal strength
- `nwqmi_nas_get_tx_rx_info` - TX/RX power
- `nwqmi_nas_get_system_selection_preference` - Network mode
- `nwqmi_nas_get_rf_band` - Active band
- `nwqmi_nas_convert_ecio` - Ec/Io calculation
- `nwqmi_nas_convert_mcc_mnc` - MCC/MNC parsing
- `nwqmi_nas_convert_sinr` - SINR calculation

#### Wireless Data Service (WDS)

- `nwqmi_wds_get_mip_mode` - Mobile IP mode
- `nwqmi_wds_get_mip_settings` - Mobile IP config
- `nwqmi_wds_get_active_mip_profile` - Active MIP profile
- `nwqmi_wds_read_mip_profile` - Read MIP profile
- `nwqmi_wds_get_dns_settings` - DNS servers
- `nwqmi_wds_get_scrm` - SCRM status
- `nwqmi_wds_get_call_dormancy_status` - Call state
- `nwqmi_wds_get_runtime_settings` - Runtime config

#### UIM (UICC Interface Module) - SIM Card

- `nwqmi_uim_get_iccid` - Read SIM ICCID

### Embedded EFS Paths (Confirmed in Binary)

#### LTE Configuration

- `/nv/item_files/modem/mmode/lte_bandpref` ✅ (we read this - all FF)
- `/nv/item_files/modem/lte/rrc/csp/band_priority_list` ⚠️ (band priority order)

#### IMS/VoLTE Configuration

- `/nv/item_files/ims/qp_ims_voip_config` - VoIP settings
- `/nv/item_files/ims/qp_ims_sip_extended_0_config` - SIP extended config
- `/nv/item_files/ims/ims_sip_config` - SIP basic config
- `/nv/item_files/ims/qp_ims_sms_config` - SMS over IMS
- `/nv/item_files/ims/qipcall_enable_hd_voice` - HD Voice toggle
- `/nv/item_files/ims/qipcall_codec_mode_set` - Audio codec config
- `/nv/item_files/ims/qipcall_codec_mode_set_amr_wb` - AMR-WB codec
- `/nv/item_files/ims/qp_ims_reg_extended_0_config` - IMS registration
- `/nv/item_files/ims/qp_ims_presence_config` - Presence service
- `/nv/item_files/ims/qipcall_config_items` - IP call config

#### CDMA/EVDO Configuration

- `/nv/item_files/cdma/1xcp/disable_so35_so36` - Service options 35/36
- `/nv/item_files/modem/mmode/sxlte_timers` - SXLTE timing
- `/nv/item_files/cne/1XDataServiceTransferTimer` - Data transfer timer

### Analysis Notes

**QMI Architecture:**

- Library uses Qualcomm's QMI protocol for all modem communication
- NV item write functions likely exist but not exported as public symbols
- GPS functionality embedded (XTRA data injection for A-GPS)
- Full IMS stack support (VoLTE, VoWiFi, SMS over IMS)

**Security:**

- No direct IMEI manipulation functions found in public exports
- NV write may be internal-only or accessed via nwcli wrapper

**Next Steps:**

- Disassemble with Ghidra to find internal nv_item_write functions
- Check for QMI command 0x002F (NV_SVC1_CMD_WRITE_NV_ITEM) references
- Analyze fota_modem_write_nv_item (mentioned in earlier docs but not in strings)

---

## libsms_encoder.so (91,848 bytes)

**Purpose:** SMS PDU encoding and CDMA SMS encoding

### Key Function Exports (pending strings extraction)

Functions expected based on documentation:

- `PDU_Encode_Sms` - 3GPP SMS PDU encoding
- `CDMA_Encode_Message_IS637` - IS-637 CDMA SMS encoding

**Next:** Extract strings on device to confirm function names

---

## modem2_cli (pending size check)

**Purpose:** User-facing CLI for modem control

### Known Commands (from PROPRIETARY_FUNCTIONS.md)

**Device Info:**

- `get_info` ✅ - IMEI, IMSI, firmware, model
- `get_signal` ✅ - RSSI, RSRP, RSRQ, SINR, bars
- `get_state` ✅ - Connection state, tech, operator

**SIM/Security:**

- `sim_get_status` ✅ - SIM card state
- `unlock_carrier` ⚠️ - NCK unlock (requires code)
- `validate_spc` ✅ - SPC validation (000000 confirmed)

**Network:**

- `mns_start_scan` ✅ - Manual network scan (45s)
- `mns_get_list` ✅ - Available networks
- `mns_set_oper` ✅ - Select network manually
- `radio_set_enabled` ✅ - Radio on/off toggle

**Configuration:**

- `roam_get_enabled` ✅ - Roaming status
- `roam_set_enabled` ✅ - Enable/disable roaming
- `enabled_tech_get` ✅ - Active tech modes (GSM/UMTS/LTE...)
- `enabled_tech_set` ✅ - Set tech modes
- `lte_band_get_enabled` ✅ - Per-band status
- `lte_band_set_enabled` ✅ - Enable/disable band
- `prof_get_pri_tech` ⚠️ - Get APN profile (TIMEOUT issue!)
- `prof_set_pri_tech` ✅ - Set APN profile
- `powersave_set` ✅ - Power save mode
- `carrier_aggregation_set` ✅ - CA enable/disable

**EFS Access:**

- `efs_read` ✅ - Interactive EFS file read
- `efs_write` ✅ - Interactive EFS file write
- `efs_read_large` ✅ - Large file via shared memory
- `efs_delete` ✅ - Delete EFS file

**Advanced:**

- `run_raw_command` ⚠️ - AT command interface (unresponsive)
- `get_carrier_unlock` ✅ - Unlock status check

**Next:** Extract command dispatch table from binary to find hidden/undocumented commands

---

## nwcli (25,500 bytes)

**Purpose:** QMI Interface CLI wrapper

### Known qmi_idl Commands

**NV Items:**

- `read_nv <item_id> <index>` ✅ - Read NV item (index 0=primary, 1=secondary)
- `write_nv <item_id> <index> <file>` ⚠️ - Write NV item from binary file

**EFS Files:**

- `read_file <dest_file> <efs_path> <max_bytes>` ✅ - Read EFS file to /tmp
- `write_file <source_file> <efs_path>` ✅ - Write binary file to EFS
- `factory_restore` - Factory reset via QMI (DANGEROUS)

**Next:** Disassemble to find QMI message structure and command codes

---

## sms_cli (15,540 bytes)

**Purpose:** SMS operations CLI

### Known Commands (from PROPRIETARY_FUNCTIONS.md)

- `send` ⚠️ - Interactive SMS send (30s timeout)
- `get_list` ⚠️ - List inbox/outbox
- `get_unread` ⚠️ - Unread count
- `read` ⚠️ - Read message by index
- `delete` ⚠️ - Delete message

**Next:** Analyze smsd daemon integration and message encoding flow

---

## libmodem2_api.so (144,888 bytes)

**Purpose:** High-level modem API abstraction

**Expected Functions:**

- Wrappers for modem2_cli commands as C library functions
- Configuration file parsing (/sysconf/settings.xml, /sysconf/features.xml)
- State machine for connection management

**Next:** Disassemble to find public API surface and internal state management

---

## libsms_api.so (20,996 bytes)

**Purpose:** SMS API abstraction

**Expected Functions:**

- SMS send/receive queue management
- Integration with smsd daemon
- PDU encoding/decoding wrappers

**Next:** Analyze smsd IPC mechanism (likely Unix domain sockets or D-Bus)

---

## Disassembly Action Plan

### Priority 1: IMEI Modification Path

**Goal:** Understand how set_imei in mifi_controller.py works and if there are alternatives

1. Disassemble `libmal_qct.so` in Ghidra
2. Search for string references to "nv_item_write", "NV_SVC1", "0x002F"
3. Trace QMI message construction for NV write command
4. Document binary format for NV 550 (IMEI) write operation
5. Compare with mifi_controller.py implementation

### Priority 2: Carrier Unlock Mechanism

**Goal:** Understand NV 3461/4399 lock bits and unlock process

1. Disassemble `modem2_cli` → find `unlock_carrier` implementation
2. Trace to QMI unlock command structure
3. Identify NCK (Network Control Key) validation logic
4. Document bypass methods (if any) or brute-force feasibility
5. Check if SPC code (000000) can override carrier locks

### Priority 3: SMS PDU Encoding

**Goal:** Enable Flash SMS (Class 0) and Silent SMS (Type 0) sending

1. Disassemble `libsms_encoder.so` → locate `PDU_Encode_Sms`
2. Understand DCS (Data Coding Scheme) byte manipulation
3. Find TP-PID (Protocol Identifier) field for Type 0 SMS
4. Implement raw PDU send via AT commands if modem2_cli won't cooperate
5. Test with mifi_controller.py send_sms function

### Priority 4: Hidden Modem Commands

**Goal:** Find undocumented commands in modem2_cli

1. Extract command dispatch table from modem2_cli
2. Compare with known commands in PROPRIETARY_FUNCTIONS.md
3. Test newly discovered commands via ADB shell
4. Document functionality and add to documentation

### Priority 5: EFS Exploration Automation

**Goal:** Systematically read all interesting NV items and EFS files

1. Create Python script to iterate NV items 0-7232 + 65337-70282
2. Classify by category (Security, RF, Data, GPS, etc.)
3. Decode binary formats for each NV item type
4. Compare with XDA NV item list for verification
5. Document in structured JSON format for future reference

---

## Tools Required for Next Phase

1. **Ghidra** (Free, open source) - Primary disassembler
   - Download: <https://ghidra-sre.org/>
   - Import ARM/ARM64 binaries (.so files, ELF executables)
   - Auto-analyze with default options

2. **Binary Ninja** (Trial available) - Control flow analysis
   - Download: <https://binary.ninja/>
   - Better for complex function graphs

3. **IDA Pro** (Commercial, or use IDA Free) - Cross-referencing
   - Download IDA Free: <https://hex-rays.com/ida-free/>
   - Excellent for finding all references to specific strings/functions

4. **Python DIAG Parser** - Direct QMI communication
   - pip install pyserial
   - Use Qualcomm DIAG protocol for raw modem access
   - Bypass CLI wrappers for advanced operations

5. **QPST/QXDM** (Windows only) - Official Qualcomm tools
   - Already attempted (QCN restore failed)
   - May still be useful for packet capture and analysis

---

## Next Session Goals

1. ✅ Complete strings extraction from all binaries
2. ⚠️ Import libmal_qct.so into Ghidra and locate nv_item_write functions
3. ⚠️ Test IMEI write with mifi_controller.py (REQUIRES USER APPROVAL!)
4. ⚠️ Systematically read all interesting NV items (3461, 4399, 441, security range 0-100)
5. ⚠️ Attempt carrier unlock via modem2_cli unlock_carrier (requires NCK code)
6. ⚠️ Explore additional EFS paths from libmal_qct.so string references

---

**Session Status:** Binaries pulled and initial strings analysis complete. Ready for deep disassembly in Ghidra.
**IMEI Write:** Implementation ready in mifi_controller.py but NOT YET TESTED (user must explicitly approve).
**Risk Assessment:** All read operations safe. NV writes (IMEI, locks) should be done with backups. Device is stable and responsive.
