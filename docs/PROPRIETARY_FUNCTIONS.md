# Proprietary Functions Reference (MiFi 8800L)

Status key: ✅ tested OK · ⚠️ partial/unknown · ❌ failed · 📦 observed in binary (not callable here)

## modem2_cli (libmodem2_api.so)

- get_info ✅: IMEI/IMSI/ICCID/FW/Model snapshot.
- get_state ✅: Connection state, tech, operator, RSSI/bars/roam.
- get_signal ✅: RSSI/RSRP/RSRQ/SINR/tx power.
- get_carrier_unlock ✅: Unlock state (State 0 = unlocked).
- unlock_carrier ⚠️: Requires NCK; not tested.
- validate_spc ✅: SPC check (000000 default).
- roam_get_enabled / roam_set_enabled ✅: Domestic roaming.
- roam_get_intl_enabled / roam_set_intl_enabled ✅: International roaming.
- enabled_tech_get / enabled_tech_set ✅: Radio tech bitmask (GSM/UMTS/CDMA/EVDO/LTE).
- lte_band_get_enabled / lte_band_set_enabled ✅: Per-band enable.
- active_band_get ✅: Current active band.
- prof_get_pri_tech / prof_set_pri_tech ✅: APN profile (tech, APN, auth, PDP).
- mns_start_scan / mns_get_list / mns_set_oper ✅: Manual network scan/select.
- powersave ✅: 0=disable,1=enable.
- ca_set_enabled ✅: Carrier aggregation toggle.
- sim_get_status ✅: SIM presence/status.
- radio_set_enabled ✅: Radio toggle (used after band writes).

## nwcli qmi_idl (libmal_qct.so)

- read_nv <id> <index> ✅: NV read (e.g., 550 IMEI index 0).
- write_nv <id> <index> <file> ⚠️: Implemented in script; success depends on modem policy.
- read_file <local> <efs_path> <len> ✅: EFS read (e.g., bandpref).
- write_file <local> <efs_path> ✅: EFS write (bandpref, test file).
- QMI svc1 cmd 0x2e/0x2f 📦: nwqmi_nvtl_nv_item_read_cmd/write_cmd found in libmal_qct.so.
- fota_modem_write_nv_item 📦: NV writer symbol present; not directly exposed in CLI.

## sms_cli (libsms_api.so)

- send ⚠️: Interactive SMS send (tested for command path; modem delivery not verified).
- get_list ⚠️: Lists inbox/outbox (parsing TBD).
- get_unread ⚠️: Unread count.
- read/delete ⚠️: Per-message operations.

## usb_cli

- get_config / get_state ✅: Current composite functions.
- mode_switch ⚠️: USB mode change (not exercised here).

## wifi_cli

- config/query ⚠️: Wi-Fi AP settings (not exercised here).

## router2_cli

- routing/NAT controls ⚠️ (not exercised here).

## gps_cli

- GPS/GNSS controls ⚠️ (not exercised here).

## Notable Binary Symbols (from disassembly/strings)

- libmal_qct.so: nwqmi_nvtl_nv_item_write_cmd/read_cmd (QMI NV write/read), fota_modem_write_nv_item, dsm_modem_get_imei.
- smsd/lbsms: PDU encode/decode via libsms_encoder.so (PDU_Encode_Sms, CDMA_Encode_Message_IS637).

## Tested EFS/NV paths

- /nv/item_files/modem/mmode/lte_bandpref ✅: All-FF write enables all LTE bands (radio cycle needed).
- /nv/item_files/modem/mmode/test_file ✅: Arbitrary write/read via modem2_cli efs_write/efs_read.
- NV 550 (IMEI) ⚠️: read_nv works; write_nv path implemented in script, success depends on modem policy.

## Operational guidance

- Use 90s default timeout; keep individual commands under ~20s to avoid interactive hangs.
- After EFS band writes, cycle radio via modem2_cli radio_set_enabled 0/1 with short sleeps.
- When attempting NV writes (IMEI), push exact binary payload (length byte + BCD digits) to /tmp and invoke nwcli qmi_idl write_nv.
