# Phase 6C: Proprietary Functions Documentation

## MiFi 8800L Complete Proprietary API Reference

This document catalogs ALL proprietary functions discovered in the MiFi 8800L firmware,
including CLI tools, library functions, NV items, and EFS files.

---

## CLI Tool Reference

### modem2_cli - Modem Control Interface

**Location**: `/opt/nvtl/bin/modem2_cli`
**Library**: `libmodem2_api.so`

#### Device Information Commands

| Command | Description | Parameters | Output |
|---------|-------------|------------|--------|
| `get_info` | Get device identifiers | None | IMEI, IMSI, ICCID, MDN, firmware, model |
| `get_state` | Get connection state | None | State, tech, signal, operator info |
| `get_signal` | Get signal strength | None | RSSI, RSRP, RSRQ, SINR, bars, TX power |
| `get_voice_signal` | Get voice signal stats | None | Voice-specific signal metrics |
| `get_service_info` | Get service type | None | Service type, roaming indication |
| `get_diag_info` | Get diagnostic info | None | Diagnostic details |
| `get_refurb_info` | Get refurbish details | None | Refurbishment status |
| `get_act_date` | Get activation date | None | Device activation timestamp |
| `get_sup_tech` | Get supported tech | None | Supported radio technologies |
| `get_oper_info` | Get operator info | None | Network operator details |
| `get_network_time` | Get network time | None | Time and timezone from network |
| `get_cached_time` | Get cached time | None | Last network time update |

#### Carrier Unlock Commands

| Command | Description | Parameters | Output |
|---------|-------------|------------|--------|
| `get_carrier_unlock` | Get unlock status | None | State (0=unlocked), block status, retries |
| `unlock_carrier` | Unlock carrier | NCK code (interactive) | Success/failure |
| `validate_spc` | Validate SPC code | SPC (interactive) | Validation result |

#### Radio Technology Commands

| Command | Description | Parameters | Output |
|---------|-------------|------------|--------|
| `enabled_tech_get` | Get enabled tech | None | Bitmask: GSM(1), UMTS(2), CDMA(4), EVDO(8), LTE(16) |
| `enabled_tech_set` | Set enabled tech | Comma-separated list | Updated bitmask |
| `active_tech_get` | Get active tech | None | Current active technology |
| `get_world_mode_enabled` | Check world mode | None | World mode status |

#### LTE Band Commands

| Command | Description | Parameters | Output |
|---------|-------------|------------|--------|
| `lte_band_get_enabled` | Get band status | Band number (interactive) | Enabled (1) or disabled (0) |
| `lte_band_set_enabled` | Set band status | Band number, enable (0/1) | Result |
| `lte_band_get_prior` | Get band priority | None | Priority list |
| `lte_band_set_prior` | Set band priority | Priority values | Result |
| `active_band_get` | Get active band | None | Current active band |
| `band_class_get_enabled` | Get band class | None | Band class status |
| `band_class_set_enabled` | Set band class | Class value | Result |

#### Carrier Aggregation Commands

| Command | Description | Parameters | Output |
|---------|-------------|------------|--------|
| `ca_get_enabled` | Get CA status | None | Enabled (1) or disabled (0) |
| `ca_set_enabled` | Set CA status | Enable (0/1) | Result |
| `ca_bands_get_enabled` | Get CA bands | None | Enabled CA bands |
| `ca_bands_set_enabled` | Set CA bands | Band values | Result |
| `ca_tri_bands_get_enabled` | Get tri-band CA | None | Tri-band CA status |
| `ca_tri_bands_set_enabled` | Set tri-band CA | Values | Result |
| `check_lte_ca_status` | Check CA status | None | Current CA state |

#### Roaming Commands

| Command | Description | Parameters | Output |
|---------|-------------|------------|--------|
| `roam_get_enabled` | Get roaming status | None | Enabled (1) or disabled (0) |
| `roam_set_enabled` | Set roaming | Enable (0/1) | Result |
| `roam_get_intl_enabled` | Get intl roaming | None | International roaming status |
| `roam_set_intl_enabled` | Set intl roaming | Enable (0/1) | Result |
| `roam_get_eri` | Get ERI | None | Enhanced Roaming Indicator |
| `validate_home` | Validate home network | None | Home network status |

#### APN Profile Commands

| Command | Description | Parameters | Output |
|---------|-------------|------------|--------|
| `prof_get_tech` | Get tech profile | Type, index | Profile details |
| `prof_get_pri_tech` | Get PRI profile | None | Primary profile |
| `prof_get_cust_tech` | Get custom profile | None | Custom profile |
| `prof_set_tech` | Set tech profile | Type, index, values | Result |
| `prof_set_pri_tech` | Set PRI profile | Tech, APN, auth, PDP | Result |
| `prof_set_cust_tech` | Set custom profile | Values | Result |
| `prof_get_act_tech` | Get active profile | Index | Active profile |
| `prof_set_act_tech` | Set active profile | Index, values | Result |
| `get_apn_from_database` | Get SIM APN | None | APN from SIM |
| `get_custom_apn_from_database` | Get custom APN | ICCID | Custom APN |
| `set_custom_apn_to_database` | Set custom APN | ICCID, values | Result |
| `validate_apn` | Validate APN | None | APN validation result |

#### Radio Control Commands

| Command | Description | Parameters | Output |
|---------|-------------|------------|--------|
| `radio_is_enabled` | Check radio state | None | Enabled status |
| `radio_set_enabled` | Set radio state | Enable (0/1) | Result |
| `powersave` | Toggle power save | Enable (0/1) | Result |
| `enable_data_call` | Enable data calls | Enable (0/1) | Result |

#### Network Selection Commands

| Command | Description | Parameters | Output |
|---------|-------------|------------|--------|
| `mns_get_info` | Get MNS info | None | Manual network selection info |
| `mns_start_scan` | Start network scan | None | Starts scan (30-60 sec) |
| `mns_get_list` | Get scan results | None | COPS format network list |
| `mns_clear_list` | Clear scan results | None | Clears list |
| `mns_set_oper` | Select network | Enable, MCCMNC, tech | Result |
| `mns_validate` | Validate MNS | None | Validation result |
| `network_attach` | Set attach status | Value | Result |

#### EFS Commands

| Command | Description | Parameters | Output |
|---------|-------------|------------|--------|
| `efs_read` | Read EFS file | Path (interactive) | File contents |
| `efs_write` | Write EFS file | Path, data (interactive) | Result |
| `efs_read_large` | Read large EFS | Path | Contents via shared memory |
| `efs_write_large` | Write large EFS | Path, data | Result |
| `efs_delete` | Delete EFS file | Path | Result |

#### SIM Commands

| Command | Description | Parameters | Output |
|---------|-------------|------------|--------|
| `sim_get_status` | Get SIM status | None | SIM state |
| `sim_get_iccid` | Get ICCID | None | SIM ICCID |
| `sim_get_carrier` | Get SIM carrier | None | Carrier from SIM |
| `sim_get_gid1` | Get GID1 | None | Group ID 1 |
| `sim_get_gid2` | Get GID2 | None | Group ID 2 |
| `sim_get_mnc_length` | Get MNC length | None | MNC length |
| `get_imsi` | Get IMSI | None | IMSI |
| `sim_enable_pin` | Enable SIM PIN | PIN (interactive) | Result |
| `sim_unlock_pin` | Unlock SIM PIN | PIN (interactive) | Result |
| `sim_unlock_puk` | Unlock SIM PUK | PUK, PIN | Result |
| `sim_change_pin` | Change SIM PIN | Old, new PIN | Result |
| `sim_pin_get_status` | Get PIN status | None | PIN state |

#### VoLTE Commands

| Command | Description | Parameters | Output |
|---------|-------------|------------|--------|
| `volte_get_enabled` | Get VoLTE status | None | Enabled status |
| `volte_set_enabled` | Set VoLTE | Enable (0/1) | Result |
| `volte_get_hd_voice_enab` | Get HD Voice | None | HD Voice status |
| `volte_set_hd_voice_enab` | Set HD Voice | Enable (0/1) | Result |
| `volte_get_amr_mode` | Get AMR mode | None | AMR mode |
| `volte_set_amr_mode` | Set AMR mode | Value | Result |
| `volte_get_amr_wb_mode` | Get AMR-WB | None | Wideband AMR |
| `volte_set_amr_wb_mode` | Set AMR-WB | Value | Result |

#### IMS Commands

| Command | Description | Parameters | Output |
|---------|-------------|------------|--------|
| `ims_reg_set_delay` | Set IMS reg delay | Value | Result |
| `ims_pres_get_config` | Get presence config | None | Presence config |
| `ims_pres_set_config` | Set presence config | Values | Result |
| `ims_lvc_get_enabled` | Get LVC enabled | None | LVC status |
| `ims_lvc_set_enabled` | Set LVC enabled | Enable (0/1) | Result |
| `ims_get_sip_data` | Get SIP data | None | SIP configuration |
| `ims_set_sip_data` | Set SIP data | Values | Result |
| `ims_get_sms_data` | Get IMS SMS data | None | IMS SMS config |
| `ims_set_sip_timer` | Set SIP timer | Value | Result |

#### Miscellaneous Commands

| Command | Description | Parameters | Output |
|---------|-------------|------------|--------|
| `run_raw_command` | Execute AT command | Command, prompt, reply, timeout | AT response |
| `factory_reset` | Factory reset modem | None | Initiates reset |
| `lifetime_counters_get` | Get counters | None | Lifetime counters |
| `lifetime_counters_update` | Update counters | Values | Result |
| `lbs_get` | Get LBS query | None | LBS idle mode status |
| `lbs_set` | Set LBS query | Value | Result |
| `ddtm_get` | Get DDTM state | None | DDTM status |
| `ddtm_set` | Set DDTM state | Value | Result |
| `emergency_get_mode` | Get emergency mode | None | Emergency mode status |
| `get_reject_cause_code` | Get reject code | None | Last network reject |
| `get_call_throttle_status` | Get throttle | None | Call throttle status |

---

### sms_cli - SMS Interface

**Location**: `/opt/nvtl/bin/sms_cli`
**Library**: `libsms_api.so`

| Command | Description | Parameters | Output |
|---------|-------------|------------|--------|
| `send` | Send SMS | Phone, message (interactive) | Send result |
| `get_list` | List SMS messages | None | Message headers |
| `read` | Read SMS | Message ID | Message content |
| `delete` | Delete SMS | Message ID | Result |
| `get_unread` | Get unread count | None | Unread count |
| `set_state` | Set read status | ID, state | Result |
| `ab_get_list` | Get address book | None | Address book IDs |
| `ab_get_entry` | Get AB entry | ID | Entry details |
| `ab_get_entry_addr` | Search by address | Address | Entry |
| `ab_get_entry_name` | Search by name | Name | Entry |
| `ab_edit_entry` | Edit AB entry | ID, values | Result |
| `ab_add_entry` | Add AB entry | Values | New ID |
| `ab_del_entry` | Delete AB entry | ID | Result |

---

### nwcli - QMI Interface

**Location**: `/opt/nvtl/bin/nwcli`
**Library**: `libmal_qct.so`

#### General Usage

```
nwcli qmi_idl <command>
nwcli <call>                    # Start data call
nwcli <qmi> <svc_id> <msg_id> <tlv_id> <tlv_data>...
```

#### qmi_idl Commands

| Command | QMI Code | Description | Parameters |
|---------|----------|-------------|------------|
| `read_nv` | 0x002E | Read NV item | `<item_id> <is_string(0/1)>` |
| `write_nv` | 0x002F | Write NV item | (self-test mode) |
| `read_file` | 0x0042 | Read EFS file | `<output_file> <efs_path> <max_bytes>` |
| `write_file` | 0x0043 | Write EFS file | `<input_file> <efs_path>` |
| `factory_restore` | 0x003A | Factory restore NV | None |
| `get_reg_state` | 0x0047 | Get registration | None |
| `pwr_down` | 0x0034 | Power down modem | None |
| `set_event_report` | 0x000E | Set event report | Values |
| `get_model` | 0x0009 | Get model type | None |
| `get_eri` | 0x003B | Get ERI info | None |
| `get_pco` | 0x0060 | Get PCO value | None |

---

### usb_cli - USB Mode Control

**Location**: `/opt/nvtl/bin/usb_cli`

| Command | Description | Parameters |
|---------|-------------|------------|
| `get_config` | Get USB config | None |
| `get_state` | Get USB state | None |
| `start` | Start USB gadget | None |
| `stop` | Stop USB gadget | None |
| `restart` | Restart USB | None |
| `mode_switch` | Switch USB mode | Mode |
| `get_tether_enabled` | Get tether status | None |
| `set_tether_enabled` | Set tethering | Enable (0/1) |
| `get_usb_tethering_feature` | Get feature | None |

---

### wifi_cli - WiFi Control

**Location**: `/opt/nvtl/bin/wifi_cli`

| Command | Description | Parameters |
|---------|-------------|------------|
| `get_ap_profile` | Get AP profile | None |
| `set_ap_profile` | Set AP profile | Values |
| `get_ap_enable` | Get AP status | None |
| `set_ap_enable` | Set AP status | Enable (0/1) |
| `get_sta_enable` | Get STA status | None |
| `set_sta_enable` | Set STA status | Enable (0/1) |
| `get_sta_list` | Get station list | None |
| `get_caps` | Get WiFi caps | None |
| `get_mac` | Get MAC address | None |
| `get_enable` | Get WiFi status | None |
| `set_enable` | Set WiFi status | Enable (0/1) |
| `start_wps` | Start WPS | Interface |
| `stop_wps` | Stop WPS | Interface |
| `get_band_status` | Get band status | None |
| `set_wifi_ps` | Set power save | Mode |

---

### gps_cli - GPS Control

**Location**: `/opt/nvtl/bin/gps_cli`

| Command | Description | Parameters |
|---------|-------------|------------|
| `gps_start` | Start GPS | None |
| `gps_stop` | Stop GPS | None |
| `gps_status` | Get GPS status | None |
| `get_last_fix` | Get last fix | None |
| `get_mode` | Get GPS mode | None |
| `agps_mode_set` | Set AGPS mode | Mode |
| `force_xtra` | Force XTRA download | None |
| `get_active` | Get active status | None |
| `set_active` | Set active status | Value |
| `get_nmea_tcp` | Get NMEA settings | None |
| `set_nmea_tcp` | Set NMEA settings | Values |
| `get_privacy` | Get privacy policy | None |
| `set_privacy` | Set privacy policy | Value |
| `enable_powersave_mode` | Set power save | Mode |

---

### router2_cli - Router Control

**Location**: `/opt/nvtl/bin/router2_cli`

| Command | Description | Parameters |
|---------|-------------|------------|
| `get_lan_settings` | Get LAN config | None |
| `set_lan_settings` | Set LAN config | Values |
| `get_dhcp` | Get DHCP settings | None |
| `set_dhcp` | Set DHCP settings | Values |
| `get_dmz` | Get DMZ settings | None |
| `set_dmz` | Set DMZ settings | Values |
| `get_port_forwarding` | Get port fwd | None |
| `set_port_forwarding` | Set port fwd | Values |
| `get_port_filter` | Get port filter | None |
| `set_port_filter` | Set port filter | Values |
| `get_vpnpassthrough` | Get VPN passthrough | None |
| `set_vpnpassthrough` | Set VPN passthrough | Enable (0/1) |
| `get_manual_dns` | Get manual DNS | None |
| `set_manual_dns` | Set manual DNS | Values |
| `dns_lookup` | DNS lookup | Domain |
| `get_mtu` | Get MTU | None |
| `set_mtu` | Set MTU | Value |
| `start_v4` | Start IPv4 routing | None |
| `stop_v4` | Stop IPv4 routing | None |
| `start_v6` | Start IPv6 routing | None |
| `stop_v6` | Stop IPv6 routing | None |

---

## NV Items Reference

### Accessible NV Items (via nwcli qmi_idl read_nv)

| NV ID | Name | Size | Description | Example Value |
|-------|------|------|-------------|---------------|
| 0 | Security Code | 64 | Service code | `00 00 00 00...` (disabled) |
| 1 | Slot Cycle Index | 8 | Slot cycle | `ff ff ff ff 00...` |
| 10 | Slot Cycle | 4 | Cycle value | `00 3d 00...` |
| 441 | GPS Mode | 4 | GPS config | `00 00...` |
| **550** | **IMEI** | 9+ | **BCD IMEI** | `08 9a 09 10 86 87 75 93 78` |
| 553 | SID/NID Lock | 4 | Lock config | `05 00...` |
| 946 | Modem Config | 8 | Config flags | `00 c0 04 00...` |
| 947 | SMS Config | 4 | SMS settings | `00 00...` |
| 1015 | Roaming Config | 4 | Roaming 1 | `00 00...` |
| 1016 | Roaming Config 2 | 4 | Roaming 2 | `01 00...` (enabled) |
| 2954 | Band Class Pref | 8 | Band prefs | `00 00 00 02...` |
| 3461 | SIM Lock Status | 4 | Lock state | `01 00...` |
| 4399 | Subsidy Lock 2 | 4 | Subsidy lock | `01 00...` |
| 6828 | Perso Status | 4 | Personalization | `00 00...` |
| 6830 | Carrier Info | 4 | Carrier ID | `0a 00...` (10=Verizon) |
| 60044 | PRI Version | 64 | PRI string | `"PRI.90029477 REV 151 Alpine VERIZON"` |

### Protected NV Items (Error 8193 - Access Denied)

- NV 5, 851, 4398 - Carrier/SIM lock configuration
- Most items in ranges 100-400, 600-800

### IMEI BCD Encoding (NV 550)

```
IMEI: 990016878573987
BCD:  08 9a 09 10 86 87 75 93 78

Encoding:
  Byte 0: 08 = Length (8 significant bytes)
  Byte 1: (digit0 << 4) | 0xA = (9 << 4) | 0xA = 0x9A
  Byte 2: (digit2 << 4) | digit1 = (0 << 4) | 9 = 0x09
  Byte 3: (digit4 << 4) | digit3 = (1 << 4) | 0 = 0x10
  Byte 4: (digit6 << 4) | digit5 = (8 << 4) | 6 = 0x86
  Byte 5: (digit8 << 4) | digit7 = (8 << 4) | 7 = 0x87
  Byte 6: (digit10 << 4) | digit9 = (7 << 4) | 5 = 0x75
  Byte 7: (digit12 << 4) | digit11 = (9 << 4) | 3 = 0x93
  Byte 8: (digit14 << 4) | digit13 = (7 << 4) | 8 = 0x78
```

---

## EFS Files Reference

### Accessible EFS Files

| Path | Size | Description | Format |
|------|------|-------------|--------|
| `/nv/item_files/modem/mmode/lte_bandpref` | 8 | LTE band bitmask | Binary (0xFF = all enabled) |
| `/policyman/device_config.xml` | ~503 | Device config | XML |

### Known EFS Paths (from library strings)

| Path | Purpose | Writable |
|------|---------|----------|
| `/nv/item_files/modem/mmode/lte_bandpref` | LTE band enable | Yes |
| `/nv/item_files/modem/lte/rrc/csp/band_priority_list` | Band priority | Unknown |
| `/nv/item_files/modem/mmode/sxlte_timers` | SXLTE timing | Unknown |
| `/nv/item_files/ims/qp_ims_voip_config` | VoLTE/VoIP | Unknown |
| `/nv/item_files/ims/qp_ims_sms_config` | IMS SMS | Unknown |
| `/nv/item_files/ims/ims_sip_config` | SIP config | Unknown |
| `/nv/item_files/ims/qipcall_enable_hd_voice` | HD Voice | Unknown |
| `/nv/item_files/ims/qipcall_codec_mode_set` | Audio codec | Unknown |
| `/policyman/device_config.xml` | Device caps | Read-only |
| `/policyman/carrier_policy.xml` | Carrier policy | Unknown |

---

## Library Function Reference

### libmodem2_api.so Functions (52 total)

#### Carrier Functions

- `modem2_carrier_unlock` @ 0x6c14 - Unlock carrier with NCK
- `modem2_get_carrier_unlock_status` - Get unlock state
- `modem2_get_pers_status` - Get personalization status

#### Radio Control

- `modem2_radio_set_enabled` - Enable/disable radio
- `modem2_radio_is_enabled` - Check radio state
- `modem2_set_enabled_tech` - Set technology modes
- `modem2_get_enabled_tech` - Get technology modes

#### EFS Operations

- `modem2_efs_read` - Read EFS file
- `modem2_efs_write` - Write EFS file
- `modem2_efs_delete` - Delete EFS file

### libmal_qct.so Functions (112 total)

#### IMEI Functions

- `dsm_modem_get_imei` @ 0x32b84 - Read IMEI from modem
- `dsm_modem_get_imsi` - Read IMSI

#### NV Operations

- `nwqmi_nvtl_nv_item_read_cmd` - Read NV item via QMI
- `nwqmi_nvtl_nv_item_write_cmd` - Write NV item via QMI
- `fota_modem_write_nv_item` @ 0x337e4 - FOTA NV write
- `nwqmi_nvtl_file_read` - Read file via QMI
- `nwqmi_nvtl_file_write` - Write file via QMI

#### SMS Functions

- `nwqmi_wms_send` - Send SMS via QMI WMS
- `nwqmi_wms_read` - Read SMS via QMI WMS
- `nwqmi_wms_delete` - Delete SMS via QMI WMS

### libsms_encoder.so Functions (78 total)

#### PDU Encoding

- `PDU_Encode_Sms` @ 0x52f0 (3120 bytes) - Main SMS PDU encoder
- `PDU_Decode_Sms` @ 0x5f60 - PDU decoder
- `PDU_Encode_Address` @ 0x6060 - Address encoding
- `PDU_Decode_Address` @ 0x6210 - Address decoding
- `PDU_Encode_UserData` @ 0x6340 - User data encoding
- `PDU_Encode_DCS` @ 0x6500 - Data coding scheme
- `PDU_Encode_TP_SCTS` @ 0x6600 - Service center timestamp

#### CDMA Encoding

- `CDMA_Encode_Message_IS637` @ 0xa4f4 - IS-637 CDMA encoder
- `CDMA_Decode_Message_IS637` @ 0xa860 - IS-637 decoder
- `CDMA_Encode_Bearer_Data` @ 0xac00 - Bearer data encoding
- `CDMA_Encode_Address_IS637` @ 0xae00 - CDMA address encoding

### libnwnvitem.so (Device NV Items)

Available NV item names:

- `NW_NV_MAC_ID_I` - WiFi MAC
- `NW_NV_MAC_ID_2_I` - Secondary MAC
- `NW_NV_USB_MAC_ID_I` - USB RNDIS MAC
- `NW_NV_ETHERNET_MAC_ID_I` - Ethernet MAC
- `NW_NV_PRI_INFORMATION_I` - PRI version
- `NW_NV_USB_DEFAULT_MODE_I` - USB mode
- `NW_NV_PSM_DEFAULT_MODE_I` - Power save mode
- `NW_NV_LINUX_RUN_LEVEL_I` - Init run level
- `NW_NV_LINUX_ROOT_PASSWORD_I` - Root password hash
- `NV_AUTO_POWER_I` - Auto power on

---

## Configuration Files

### /sysconf/settings.xml

Key settings:

```xml
<Modem>
    <RoamEnabled>1</RoamEnabled>
    <IntlRoamEnabled>1</IntlRoamEnabled>
    <CertifiedCarrier>AUTO</CertifiedCarrier>
    <PreferredTechnology>19</PreferredTechnology>
</Modem>
```

Valid CertifiedCarrier values: `Verizon`, `Sprint`, `AT&T`, `Bell`, `Telus`, `GSM`, `AUTO`

Technology bitmask:

- 1 = GSM
- 2 = UMTS
- 4 = CDMA
- 8 = EVDO
- 16 = LTE
- 19 = GSM + UMTS + LTE
- 31 = All technologies

### /sysconf/features.xml

Key features:

```xml
<Features>
    <RadioTechnologies>95</RadioTechnologies>  <!-- Bitmask with WiFi(64) -->
    <SMSMobileOriginated>1</SMSMobileOriginated>
    <SMSMobileTerminated>1</SMSMobileTerminated>
    <PowerSave>1</PowerSave>
</Features>
```

---

## Python Controller Usage

### mifi_controller.py Commands

```bash
# Status
python mifi_controller.py status          # Full device status (JSON)
python mifi_controller.py network status  # Connection state

# IMEI
python mifi_controller.py imei            # Show current IMEI
python mifi_controller.py imei-set NEW    # Change IMEI (experimental)

# Carrier
python mifi_controller.py carrier AUTO    # Set CertifiedCarrier

# Bands
python mifi_controller.py bands all       # Enable all LTE bands
python mifi_controller.py bands get       # Get enabled bands
python mifi_controller.py bands set --band 13 --enable 1

# Roaming
python mifi_controller.py roaming status  # Get roaming status
python mifi_controller.py roaming on      # Enable domestic roaming
python mifi_controller.py roaming intl on # Enable international roaming

# Technology
python mifi_controller.py tech GSM,UMTS,LTE  # Set enabled tech

# APN
python mifi_controller.py apn broadband      # Set APN name
python mifi_controller.py apn-carrier att    # Set carrier preset

# Power
python mifi_controller.py power max       # Maximum power (no power save, CA enabled)
python mifi_controller.py power save      # Power save mode

# Network
python mifi_controller.py network scan    # Scan networks (30-60 sec)
python mifi_controller.py network select 310410  # Select by MCCMNC

# SMS
python mifi_controller.py sms +15551234567 "Hello"

# AT Commands
python mifi_controller.py at "AT+CSQ"
```

---

## IMEI Modification Method

### Method 1: NV 550 Direct Write (Requires tooling)

```python
def encode_imei_bcd(imei: str) -> bytes:
    """Encode 15-digit IMEI to NV 550 BCD format"""
    bcd = [0x08]  # Length byte
    bcd.append((int(imei[0]) << 4) | 0x0A)  # First digit + type
    for i in range(1, 14, 2):
        bcd.append((int(imei[i+1]) << 4) | int(imei[i]))
    return bytes(bcd)

# Write via nwcli (if supported)
# adb shell "/opt/nvtl/bin/nwcli qmi_idl write_nv 550 <bcd_data>"
```

### Method 2: AT Command (Device-dependent)

```bash
# Some Qualcomm devices support:
AT+EGMR=1,7,"352099001761481"

# Via modem2_cli:
adb shell "/opt/nvtl/bin/modem2_cli run_raw_command"
# Enter: AT+EGMR=1,7,"NEWIMEI"
```

### Method 3: EFS File (If IMEI stored in EFS)

```bash
# Create IMEI file
echo -n -e '\x08\x2a\x30\x10\x90\x76\x41\x18\x35' > /tmp/imei.bin

# Write to EFS
adb shell "/opt/nvtl/bin/nwcli qmi_idl write_file /tmp/imei.bin /nv/item_files/modem/mmode/imei"

# Cycle radio
adb shell "/opt/nvtl/bin/modem2_cli radio_set_enabled 0"
sleep 2
adb shell "/opt/nvtl/bin/modem2_cli radio_set_enabled 1"
```

**WARNING**: IMEI modification may be illegal in your jurisdiction. For research only.

---

## Tested Function Results

### Successfully Tested

| Function | Command | Result |
|----------|---------|--------|
| Get IMEI | `mifi_controller.py imei` | ✅ 990016878573987 |
| Get Status | `mifi_controller.py network status` | ✅ Connected, Boost, LTE |
| Roaming Status | `mifi_controller.py roaming status` | ✅ domestic: true |
| Set Max Power | `mifi_controller.py power max` | ✅ Power save disabled, CA enabled |
| Enable Intl Roaming | `mifi_controller.py roaming intl on` | ✅ Enabled |
| Read EFS | `modem2_cli efs_read` | ✅ lte_bandpref: 0xFF (all bands) |
| Read NV 550 | `nwcli qmi_idl read_nv 550 0` | ✅ BCD IMEI data |
| Carrier Unlock | `modem2_cli get_carrier_unlock` | ✅ State:[0] = Unlocked |

### Partially Tested

| Function | Status | Notes |
|----------|--------|-------|
| IMEI Change | ⚠️ | write_nv format unclear |
| Network Scan | ⚠️ | Long timeout, needs testing |
| SMS Send | ⚠️ | Interactive mode |

---

## Version Information

- **Firmware**: SDx20ALP-1.22.11 (2020-04-13)
- **Hardware**: Rev 4
- **Model**: MIFI8800L
- **Chipset**: Qualcomm SDX20 (Alpine)
- **PRI**: 90029477 REV 151 Alpine VERIZON
- **Document Date**: December 2025
