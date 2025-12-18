# Phase 6B: Comprehensive Algorithm Discovery Report

## Executive Summary

Phase 6B conducted comprehensive analysis of all 50 proprietary libraries from the MiFi 8800L device, identifying **98 algorithm functions**, **272 SMS pipeline functions**, **167 carrier management functions**, and **43 NV item access functions**.

**Key Findings:**

- ✅ Device is **UNLOCKED** at modem level (State:[0], CertifiedCarrier=AUTO)
- ✅ Currently connected to **Boost (310410)** on LTE with AT&T SIM
- ✅ Full SMS encoding pipeline documented (GSM PDU + CDMA IS-637)
- ✅ 78 SMS encoding/decoding functions identified and disassembled
- ✅ NV item access verified (550=IMEI, 3461=SIM lock, 4399=subsidy lock)

---

## 1. Carrier Unlock Status

### Verification Results

```bash
# Command: modem2_cli get_carrier_unlock
State:[0]           # 0 = UNLOCKED
Carrier block:[0]   # No carrier block active
Verify retries:[0]  # No failed attempts
Unblock retries:[0]
```

### Carrier Configuration

| Setting | Value | Notes |
|---------|-------|-------|
| CertifiedCarrier | AUTO | From /sysconf/settings.xml |
| Current Network | Boost (310410) | Connected on LTE |
| Technology | LTE (tech:10) | rssi:-74, bars:3 |
| Cell ID | 56701906 | Active cell |
| Roaming | 0 | Home network |

### Carrier Change Capability

The device can operate on any carrier due to:

1. `CertifiedCarrier=AUTO` in settings
2. `State:[0]` (modem unlock)
3. All LTE bands enabled via EFS

**Tested Carriers:**

- ✅ AT&T SIM detected and connected
- ✅ Boost Mobile network (AT&T MVNO)
- Original device: Verizon

---

## 2. Library Analysis Summary

### Total Counts

| Category | Count |
|----------|-------|
| Libraries Analyzed | 50 |
| Algorithm Functions | 98 |
| Validation Functions | 55 |
| Encoding Functions | 225 |
| NV Item Functions | 43 |
| Carrier Functions | 167 |
| SMS Functions | 272 |
| Lock/Unlock Functions | 111 |

### Key Libraries by Function

| Library | Total Functions | SMS | Carrier | NV | Lock |
|---------|-----------------|-----|---------|----|----|
| libmal_qct.so | 420 | 11 | 6 | 1 | 4 |
| libsms_encoder.so | 139 | 78 | 0 | 0 | 0 |
| libsms_api.so | 32 | 17 | 0 | 0 | 0 |
| libmodem2_api.so | 269 | 0 | 8 | 0 | 4 |
| libsysintclient.so | 758 | 3 | 77 | 3 | 6 |
| libdevui_model_api.so | 490 | 20 | 45 | 0 | 2 |
| libomadm_bl.so | 1988 | 0 | 12 | 3 | 3 |

---

## 3. SMS Pipeline Analysis

### SMS Daemon (smsd) - Process 1277

Loaded libraries:

- `/opt/nvtl/lib/libsms_encoder.so` - PDU encoding
- `/opt/nvtl/lib/libsms_api.so` - API layer
- `/opt/nvtl/lib/libmodem2_api.so` - Modem control
- `/opt/nvtl/lib/libmal_qct.so` - Qualcomm MAL (QMI)

### Encoding Flow

#### GSM PDU Chain

```
SmsEncodeMessage() → EncodeSms() → PDU_Encode_Sms()
    ↓
wms_ts_encode_submit() → wms_ts_pack_gw_7_bit_chars()
    ↓
wms_ts_encode_address() → wms_ts_ascii_to_bcd()
```

#### CDMA IS-637 Chain

```
SmsEncodeMessage() → CDMA_Encode_Message_IS637()
    ↓
CDMA_Encode_Message() → wms_ts_encode_CDMA_tl()
    ↓
Encode_Address() + Encode_UserData() + Encode_MessageId()
```

### Key SMS Functions Disassembled

| Function | Address | Size | Instructions | Purpose |
|----------|---------|------|--------------|---------|
| PDU_Encode_Sms | 0x52f0 | 3120 | 780 | GSM PDU encoding |
| CDMA_Encode_Message | 0x9b48 | 1080 | 270 | CDMA message build |
| CDMA_Encode_Message_IS637 | 0xa4f4 | 224 | 56 | IS-637 wrapper |
| EncodeSms | 0x3834 | 636 | 159 | High-level encode |
| wms_ts_encode_submit | 0xce60 | 832 | 208 | Submit PDU |
| wms_ts_pack_gw_7_bit_chars | 0xb4e0 | 360 | 90 | GSM 7-bit packing |
| Encode_UserData | 0x8df0 | 1152 | 288 | User data encoding |
| wms_ts_ucs2_to_gsm | 0xa9d4 | 500 | 125 | UCS-2 to GSM |

### SMS API Functions (libsms_api.so)

| Function | Purpose |
|----------|---------|
| sms_api_send | Send SMS message |
| sms_api_get_list | Get inbox/outbox messages |
| sms_api_read | Read specific message |
| sms_api_delete | Delete message |
| sms_api_get_unread_count | Unread count |
| sms_api_set_state | Mark read/unread |
| sms_api_get_voice_mail_info | Voicemail notification |
| sms_factory_reset | Clear SMS data |

### SMS Modem Functions (libmal_qct.so)

| Function | Address | Purpose |
|----------|---------|---------|
| sms_modem_initialize | 0x2ea60 | Initialize SMS subsystem |
| sms_modem_send_sms_msg | 0x2f7d8 | Send via QMI WMS |
| sms_modem_read_sms_msg | 0x2f438 | Read via QMI WMS |
| decode_sms | 0x303bc | Decode incoming |
| modem_util_get_wms_message_mode | 0x2e9bc | Get CDMA/GW mode |

---

## 4. NV Item Analysis

### Accessible NV Items

| NV ID | Name | Sample Value | Description |
|-------|------|--------------|-------------|
| 0 | Security Code | `00 00 00 00...` | All zeros (disabled) |
| 550 | **IMEI (BCD)** | `08 9a 09 10 86 87 75 93 78` | 990016878573987 |
| 3461 | **SIM Lock Status** | `01 00...` | Value 1 |
| 4399 | **Subsidy Lock 2** | `01 00...` | Value 1 |
| 6830 | Carrier Info | `0a 00...` | Value 10 (Verizon) |
| 60044 | **PRI Version** | ASCII | "PRI.90029477 REV 151 Alpine VERIZON" |

### NV Access Functions

| Function | Library | Purpose |
|----------|---------|---------|
| nwqmi_nvtl_nv_item_read_cmd | libmal_qct.so | Read NV item via QMI |
| nwqmi_nvtl_nv_item_write_cmd | libmal_qct.so | Write NV item via QMI |
| fota_modem_write_nv_item | libmal_qct.so | FOTA NV update |
| nwqmi_nvtl_file_read | libmal_qct.so | EFS file read |
| nwqmi_nvtl_file_write | libmal_qct.so | EFS file write |
| nwqmi_nvtl_file_delete | libmal_qct.so | EFS file delete |

### EFS Paths

| Path | Size | Description |
|------|------|-------------|
| /nv/item_files/modem/mmode/lte_bandpref | 8 bytes | LTE band bitmask |
| /policyman/device_config.xml | ~503 bytes | Device config |
| /nv/item_files/ims/qp_ims_sms_config | - | IMS SMS config |

---

## 5. Carrier/Lock Functions

### Carrier Unlock Functions

| Function | Library | Address | Purpose |
|----------|---------|---------|---------|
| modem2_carrier_unlock | libmodem2_api.so | 0x6c14 | Unlock with NCK code |
| modem2_carrier_unlock_status | libmodem2_api.so | 0x6acc | Get unlock status |
| modem2_modem_carrier_unlock | libmal_qct.so | 0x29f4c | Modem-level unlock |
| modem2_modem_get_carrier_unlock_status | libmal_qct.so | 0x29d80 | Status check |

### SIM Lock Functions

| Function | Library | Purpose |
|----------|---------|---------|
| sys_getSIMLockStatus | libsysintclient.so | Get SIM lock state |
| sys_simUnlockPIN | libsysintclient.so | Unlock with PIN |
| sys_simUnlockPUK | libsysintclient.so | Unlock with PUK |
| sys_simEnablePINLock | libsysintclient.so | Enable/disable PIN |
| sys_simRemoveNetworkLock | libsysintclient.so | Remove network lock |
| sys_getNetworkSIMLockStatus | libsysintclient.so | Network lock state |

### SPC Validation (from Phase 6A)

| Function | Address | Purpose |
|----------|---------|---------|
| modem2_modem_validate_spc | 0x27964 | Validate 6-digit SPC |
| modem2_modem_get_spc_validate_limit | 0x2788c | Get retry limit |

**Default SPC: 000000** (confirmed working)

---

## 6. Discovered Algorithms

### Encoding Algorithms

| Algorithm | Function | Description |
|-----------|----------|-------------|
| GSM 7-bit Pack | wms_ts_pack_gw_7_bit_chars | GSM 03.38 character packing |
| GSM 7-bit Unpack | wms_ts_unpack_gw_7_bit_chars | GSM 03.38 unpacking |
| UCS-2 to GSM | wms_ts_ucs2_to_gsm | Unicode to GSM alphabet |
| ASCII to BCD | wms_ts_ascii_to_bcd | Phone number encoding |
| BCD to ASCII | wms_ts_bcd_to_ascii | Phone number decoding |
| PDU Timestamp | wms_ts_encode_timestamp | SCTS encoding |
| DCS Encoding | wms_ts_encode_dcs | Data coding scheme |

### Message Encoding

| Algorithm | Function | Description |
|-----------|----------|-------------|
| GSM PDU Submit | wms_ts_encode_submit | SMS-SUBMIT PDU |
| GSM PDU Deliver | wms_ts_encode_deliver | SMS-DELIVER PDU |
| CDMA Transport Layer | wms_ts_encode_CDMA_tl | CDMA TL encoding |
| CDMA Bearer Data | CDMA_Decode_BearerData | IS-637 bearer decode |
| UDH Concat 8-bit | wms_ts_encode_udh_concat_8 | Concat SMS header |
| UDH Concat 16-bit | wms_ts_encode_udh_concat16 | Long SMS header |

### Validation Algorithms

| Algorithm | Function | Library |
|-----------|----------|---------|
| SPC Validation | modem2_modem_validate_spc | libmal_qct.so |
| NCK Validation | modem2_modem_carrier_unlock | libmal_qct.so |
| PIN Validation | sys_simUnlockPIN | libsysintclient.so |
| PUK Validation | sys_simUnlockPUK | libsysintclient.so |

---

## 7. Dynamic Tracing Results

### Process Mapping (smsd PID 1277)

```
/opt/nvtl/bin/smsd                 @ 0x00008000-0x00013000
/opt/nvtl/lib/libsms_encoder.so    @ 0xb682e000-0xb6841000
/opt/nvtl/lib/libsms_api.so        @ 0xb6843000-0xb6846000
/opt/nvtl/lib/libmodem2_api.so     @ 0xb6928000-0xb6945000
/opt/nvtl/lib/libmal_qct.so        @ 0xb699e000-0xb69dc000
```

### Available Tracing Tools

- `/usr/bin/strace` - System call tracing
- `/usr/bin/ltrace` - Library call tracing

---

## 8. Files Generated

| File | Description |
|------|-------------|
| PHASE6B_ALGORITHM_DISCOVERY.json | Full library analysis (45K lines) |
| SMS_ENCODER_DISASSEMBLY.json | SMS function disassembly |
| ALL_LIBRARIES_SYMBOLS.json | Complete symbol map |
| libraries_full/lib/*.so | Extracted binary libraries |

---

## 9. Recommendations

### For SMS Testing

1. Use `sms_api_send()` via `sms_cli send` command
2. Monitor encoding via strace on smsd (PID 1277)
3. Direct PDU injection possible via `modem2_cli run_raw_command`

### For Carrier Operations

1. Device is unlocked - no further action needed
2. APN configuration via `modem2_cli prof_set_pri_tech`
3. Band selection via `modem2_cli lte_band_set_enabled`

### For NV Item Modification

1. Use `nwcli qmi_idl read_nv/write_nv` for QMI access
2. Use `modem2_cli efs_read/efs_write` for EFS files
3. Protected items (SPC-locked) require `validate_spc` first

---

## 10. Conclusion

Phase 6B successfully cataloged the complete proprietary library ecosystem of the MiFi 8800L. The device is fully unlocked and capable of carrier switching. The SMS encoding pipeline is fully documented with 78 functions available for analysis. All discovered algorithms are implementable in the SMS Test Android app for cross-platform compatibility testing.

**Next Steps:**

1. Implement GSM PDU encoder in SMS Test based on `PDU_Encode_Sms` structure
2. Add CDMA IS-637 support using `CDMA_Encode_Message_IS637` as reference
3. Test Flash SMS (Class 0) via direct AT commands
4. Validate encoding against actual device output
