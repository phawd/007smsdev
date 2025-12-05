# Binary Analysis Session 4 - Implementation Status

## Analysis Results

### nwcli (25,500 bytes)

**Commands Found**: 107 total string references

**Critical Findings**:

- `write_nv` string at file offset **0x4404**
- Bug: write_nv 550 writes to NV 60044 instead
- Calls `nwqmi_nvtl_nv_item_write_cmd` from libmal_qct.so

**Key Functions**:

```
nwqmi_nvtl_nv_item_read_cmd
nwqmi_nvtl_nv_item_write_cmd  ← BUG HERE
nwqmi_nvtl_file_read
nwqmi_nvtl_file_write
nwqmi_nvtl_file_delete
nwqmi_nvtl_factory_restore
nwqmi_nvtl_get_eri
nwqmi_nvtl_get_model_number_cmd
nwqmi_nvtl_get_pco_value
nwqmi_nvtl_modem_pwr_down_cmd
nwqmi_nvtl_register_event_reporting
nwqmi_nvtl_test_cmd
nwqmi_nvtl_verify_registration_state
```

### modem2_cli (148,920 bytes)

**Commands Found**: 639 total string references

**Critical Findings**:

- `unlock_carrier` string at file offset **0x1be70**
- `unlock_carrier_lock` string at file offset **0x211c0**
- Over 100 cmd_* handler functions discovered

**Complete cmd_* Function List** (150+ functions):

#### Network & Registration

```
cmd_active_band_get
cmd_active_tech_get
cmd_get_enabled_tech
cmd_set_enabled_tech
cmd_get_oper_info
cmd_get_network_time
cmd_get_cached_time
cmd_get_service_info
cmd_get_reg_state
cmd_mns_start_scan
cmd_mns_get_list
cmd_mns_get_info
cmd_mns_clear_list
cmd_mns_set_oper
cmd_mns_validate
cmd_network_attach
```

#### Band & Carrier Aggregation

```
cmd_band_class_get_enabled
cmd_band_class_set_enabled
cmd_lte_band_get_enabled
cmd_lte_band_set_enabled
cmd_lte_band_get_prior
cmd_lte_band_set_prior
cmd_ca_get_enabled
cmd_ca_set_enabled
cmd_ca_bands_get_enabled
cmd_ca_bands_set_enabled
cmd_ca_tri_bands_get_enabled
cmd_ca_tri_bands_set_enabled
cmd_check_lte_ca_status
```

#### VoLTE & IMS

```
cmd_volte_get_enabled
cmd_volte_set_enabled
cmd_volte_get_hd_voice
cmd_volte_set_hd_voice
cmd_volte_get_amr_mode
cmd_volte_set_amr_mode
cmd_volte_get_amr_wb_mode
cmd_volte_set_amr_wb_mode
cmd_volte_get_dcmo_timer
cmd_volte_set_dcmo_timer
cmd_volte_get_dcmo_tdelay
cmd_volte_set_dcmo_tdelay
cmd_volte_get_hys
cmd_volte_set_hys
cmd_volte_get_rcl_max_entries
cmd_volte_set_rcl_max_entries
cmd_volte_get_sess_config
cmd_volte_set_sess_config
cmd_volte_get_silent_redial
cmd_volte_set_silent_redial
cmd_volte_get_src_thttle
cmd_volte_set_src_thttle
cmd_volte_get_tlte_911fail
cmd_volte_set_tlte_911fail
cmd_ims_get_sip_data
cmd_ims_set_sip_data
cmd_ims_get_sms_data
cmd_ims_set_sip_timer
cmd_ims_lvc_get_enabled
cmd_ims_pres_get_config
cmd_ims_pres_set_config
cmd_ims_reg_set_delay
```

#### SIM Management

```
cmd_sim_get_carrier
cmd_sim_get_gid1
cmd_sim_get_gid2
cmd_sim_get_mnc_length
cmd_sim_pin_get_status
cmd_sim_change_pin
cmd_sim_enable_pin
cmd_sim_unlock_pin
cmd_sim_unlock_puk
cmd_get_imsi
cmd_get_iccid
```

#### Power & Roaming

```
cmd_roam_get_enabled
cmd_roam_set_enabled
cmd_roam_get_intl_enabled
cmd_roam_set_intl_enabled
cmd_roam_get_eri
cmd_enable_powersave
cmd_get_power_mode
cmd_set_power_mode
cmd_get_tx_power
```

#### Diagnostics

```
cmd_get_info
cmd_get_signal
cmd_get_state
cmd_get_diag_info
cmd_get_activation_date
cmd_get_refurb_info
cmd_get_voice_signal
cmd_lifetime_counters_get
cmd_lifetime_counters_update
cmd_get_call_throttle_status
cmd_get_reject_cause_code
cmd_get_pco_event
```

#### APN & Profiles

```
cmd_prof_get_pri_tech
cmd_prof_set_pri_tech
cmd_prof_get_tech
cmd_prof_set_tech
cmd_prof_get_cust_tech
cmd_prof_set_cust_tech
cmd_prof_get_act_tech
cmd_prof_set_act_tech
cmd_get_apn_from_database
cmd_get_custom_apn_from_database
cmd_set_custom_apn_to_database
cmd_validate_apn
cmd_validate_home
cmd_pdn_get_ext_params
cmd_pdn_set_ext_params
```

#### EFS & NV

```
cmd_efs_read
cmd_efs_write
cmd_efs_read_large
cmd_efs_write_large
cmd_delete_efs_file
cmd_run_raw_command
```

#### CDMA & 1xRTT

```
cmd_1xrtt_get_ext_timer
cmd_1xrtt_set_ext_timer
cmd_get_cai_rev
cmd_cai_set
cmd_bsr_get_timers
cmd_bsr_set_timers
cmd_get_ddtm_state
cmd_ddtm_set
cmd_mdn_min_set
```

#### eHRPD

```
cmd_ehrpd_get_enabled
cmd_ehrpd_set_enabled
cmd_ehrpd_get_state
cmd_ehrpd_set_state
```

#### LBS (Location Based Services)

```
cmd_get_lbs_idle
cmd_lbs_set
```

#### Radio Control

```
cmd_radio_is_enabled
cmd_radio_set_enabled
cmd_get_autonomous_gap_enabled
cmd_set_autonomous_gap_enabled
```

#### MIP (Mobile IP)

```
cmd_mip_get_profile
cmd_mip_get_settings
cmd_mip_set_profile
cmd_mip_set_settings
```

#### Call Control

```
cmd_call_get_status
cmd_call_start
cmd_call_stop
cmd_enable_data_call
cmd_set_lte_wifi_coex
```

#### **CRITICAL: Unlock Functions**

```
cmd_get_carrier_unlock       ← Query lock status
cmd_unlock_carrier_lock      ← UNLOCK COMMAND - NCK required
```

#### System

```
cmd_factory_reset
cmd_get_sup_tech
cmd_get_world_mode_enabled
cmd_emergency_get_mode
cmd_sd_config_get_setting
cmd_sd_config_set_setting
```

#### Testing/Simulation (40+ update_* functions)

```
cmd_update_* (many simulation/testing commands)
```

## Implementation Status in mifi_controller.py

### ✅ Implemented (61 functions)

**Core**: adb_shell, adb_shell_interactive

**IMEI**: imei_to_bcd_bytes, encode_imei_bcd, imei_from_bcd, get_current_imei, calculate_luhn_check, set_imei

**Carrier**: get_certified_carrier, set_certified_carrier

**Bands**: get_enabled_lte_bands, enable_all_lte_bands, set_lte_band

**Roaming**: get_roaming_status, set_roaming

**Tech**: get_enabled_tech, set_enabled_tech

**APN**: get_apn_profile, set_apn_profile, set_carrier_apn

**Power**: set_power_mode, get_tx_power

**Network**: scan_networks, select_network, connect_to_network, get_connection_state

**SMS**: send_sms, get_sms_list, send_at_command

**SIM**: sim_get_carrier, sim_get_mnc_length, sim_pin_get_status, sim_change_pin, sim_enable_pin, sim_unlock_pin, sim_unlock_puk

**VoLTE/IMS**: volte_get_enabled, volte_set_enabled, volte_get_hd_voice, volte_set_hd_voice, ims_get_sip_data, ims_get_sms_data, ims_lvc_get_enabled

**CA**: ca_get_enabled, check_lte_ca_status

**Diagnostics**: get_diag_info, lifetime_counters_get, get_activation_date, get_refurb_info, get_voice_signal

**EFS**: efs_delete_file, efs_write_large_file

**MIP/PDN**: mip_get_profile, mip_get_settings, pdn_get_ext_params

**Advanced**: network_attach, factory_reset_device, mdn_min_set, unlock_carrier_lock

**Status**: get_full_status

**Main**: main (CLI handler)

### ⚠️ Missing (90+ functions)

**SIM** (2):

- sim_get_gid1, sim_get_gid2

**VoLTE Advanced** (20+):

- volte_get/set_amr_mode
- volte_get/set_amr_wb_mode  
- volte_get/set_dcmo_timer
- volte_get/set_dcmo_tdelay
- volte_get/set_hys
- volte_get/set_rcl_max_entries
- volte_get/set_sess_config
- volte_get/set_silent_redial
- volte_get/set_src_thttle
- volte_get/set_tlte_911fail

**IMS Advanced** (4):

- ims_pres_get/set_config
- ims_reg_set_delay
- ims_set_sip_timer

**Band Priority** (2):

- lte_band_get/set_prior

**CA Advanced** (5):

- ca_bands_set_enabled
- ca_tri_bands_get/set_enabled
- ca_set_enabled
- get/set_autonomous_gap_enabled

**Radio** (2):

- radio_is_enabled
- radio_set_enabled

**eHRPD** (4):

- ehrpd_get/set_enabled
- ehrpd_get/set_state

**1xRTT** (2):

- 1xrtt_get/set_ext_timer

**CDMA** (6):

- cai_get, cai_set
- bsr_get/set_timers
- get_ddtm_state, ddtm_set

**LBS** (2):

- get_lbs_idle (partially implemented)
- lbs_set

**MIP** (2):

- mip_set_profile
- mip_set_settings

**PDN** (1):

- pdn_set_ext_params

**MNS (Manual Network Selection)** (3):

- mns_get_info
- mns_clear_list
- mns_validate

**Profiles** (6):

- prof_get/set_tech
- prof_get/set_cust_tech
- prof_get/set_act_tech

**Call Control** (3):

- call_start
- call_stop
- enable_data_call

**Network Info** (5):

- get_oper_info
- get_network_time
- get_cached_time
- get_service_info
- active_tech_get

**Band Control** (2):

- band_class_get/set_enabled
- active_band_get

**Roaming** (1):

- roam_get_eri

**Diagnostics** (4):

- get_call_throttle_status
- get_reject_cause_code
- get_sup_tech
- get_world_mode_enabled

**System** (4):

- emergency_get_mode
- sd_config_get/set_setting
- get_pco_event
- lifetime_counters_update

**APN** (2):

- get_custom_apn_from_database
- set_custom_apn_to_database

**EFS** (2):

- efs_read_large (started but incomplete)
- cmd_efs_read, cmd_efs_write (low-level)

**Testing** (40+):

- All update_* simulation commands

**WiFi Coexistence** (1):

- set_lte_wifi_coex

## Next Steps

### Priority 1: Fix write_nv Bug (CRITICAL)

1. **Disassemble nwcli write_nv handler**:
   - String at 0x4404, find xrefs
   - Trace parameter parsing: argv[2]=item_id, argv[3]=index, argv[4]=file
   - Identify where 550 becomes 60044
   - Check for: array indexing error, parameter swap, remapping table

2. **Options**:
   - **A**: Patch nwcli binary with LIEF
   - **B**: Implement direct QMI via libmal_qct.so
   - **C**: Use QPST on Windows (external tool)

3. **Test on safe NV item** before IMEI write

### Priority 2: Implement Missing Commands (Medium)

Target high-value, safe commands first:

- get_imsi (tested, works, add wrapper)
- sim_get_gid1, sim_get_gid2
- radio_is_enabled (safe query)
- get_oper_info, get_network_time, get_cached_time
- active_band_get, active_tech_get
- All volte_get_* (read-only queries)
- All ims_**get** (read-only)
- roam_get_eri
- get_sup_tech, get_world_mode_enabled
- band_class_get_enabled

### Priority 3: Carrier Unlock Analysis (High Risk)

**ONLY ATTEMPT WITH FULL DEVICE BACKUP**

1. **Disassemble cmd_unlock_carrier_lock**:
   - String at 0x211c0, find handler function
   - Identify NCK parameter handling
   - Find QMI message construction
   - Check retry counter logic
   - Look for permanent lock conditions

2. **Research**:
   - NCK stored in NV 5 (protected)?
   - Retry counters in NV 3461/4399?
   - Master unlock codes exist?

3. **Tools**:
   - Ghidra decompilation for pseudocode
   - angr symbolic execution for NCK bypass discovery

### Priority 4: Complete Implementation (Long-term)

Add remaining 90+ commands to mifi_controller.py for completeness.

---

**Last Updated**: 2025-01-04
**Status**: 61/150 functions implemented (40.7%)
**Next**: Disassemble nwcli write_nv, fix bug, test IMEI write
