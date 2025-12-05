# Inseego MiFi 8800L Device Reference

**Deep exploration conducted via ADB - comprehensive system catalog**

## Device Summary

| Property | Value |
|----------|-------|
| Model | MIFI8800L |
| Manufacturer | Inseego (Novatel Wireless) |
| Firmware | SDx20ALP-1.22.11 (2020-04-13) |
| Hardware Version | 4 |
| Factory ID | FA020922G20904 |
| VID:PID | 1410:B023 |
| OS | MiFiOS2 (PTXdist Linux 2017.04.0) |
| Kernel | Linux 3.18.71 (GCC 4.9.3) |
| CPU | Qualcomm SDX20 (ARMv7 Cortex-A7 @ 38 BogoMIPS) |
| RAM | 374MB total (~142MB free, ~108MB cached) |
| Root | YES (uid=0 by default) |

## Identifiers (Tested Device)

| ID | Value |
|----|-------|
| IMEI | 990016878573987 |
| IMSI | 310410465469221 (AT&T) |
| ICCID | 89014107334654628585 |
| MDN | 12562392208 |
| MAC (Host) | 00:15:FF:85:73:98 |
| MAC (Device) | 00:15:FF:85:73:99 |
| MAC (WiFi) | 18:EE:86:AF:C8:74 |

## Storage Partitions

| MTD | Size | Name |
|-----|------|------|
| mtd0 | 2.5MB | sbl (Secondary Bootloader) |
| mtd1 | 2.5MB | mibib |
| mtd2 | 11MB | efs2 (Modem NV items) |
| mtd3 | 2MB | tz (TrustZone) |
| mtd4 | 1MB | rpm |
| mtd5 | 2MB | aboot (Android Boot) |
| mtd6 | 20MB | boot |
| mtd7 | 512KB | scrub |
| mtd8 | 77MB | modem |
| mtd9 | 1MB | misc |
| mtd10 | 20MB | recovery |
| mtd11 | 1MB | fotacookie |
| mtd12 | 371MB | system |

**Filesystems:**

- Root: UBI0 (UBIFS, 325MB total, ~223MB free)
- Firmware: UBI1 (UBIFS, 57MB, read-only)

## Network Interfaces

| Interface | IP | Purpose |
|-----------|-----|---------|
| br0 | 192.168.11.1 | Bridge (WiFi + LAN) |
| rndis0 | 169.254.3.1 | USB Tethering |
| wlan0 | 169.254.1.1 | WiFi AP (2.4GHz) |
| wlan1 | 169.254.2.1 | WiFi AP (5GHz) |
| rmnet_ipa0 | - | LTE data (IPA) |
| lo | 127.0.0.1 | Loopback |

## Modem Device Nodes

| Device | Major:Minor | Purpose |
|--------|-------------|---------|
| /dev/at_mdm0 | 247:0 | AT commands (MDM interface) |
| /dev/at_usb0 | 240:0 | AT commands (USB interface 1) |
| /dev/at_usb1 | 240:1 | AT commands (USB interface 2) |
| /dev/diag | 243:0 | Qualcomm DIAG (QCDM) |
| /dev/smd7 | 247:7 | SMD channel 7 |
| /dev/smd8 | 247:8 | SMD channel 8 |
| /dev/smd11 | 247:9 | SMD channel 11 |
| /dev/smd21 | 247:10 | SMD channel 21 |
| /dev/smd22 | 247:5 | SMD channel 22 |
| /dev/smdcntl0 | 247:3 | SMD control 0 |
| /dev/smdcntl8 | 247:6 | SMD control 8 |
| /dev/ttyHS0 | 245:0 | UART (High-Speed) |
| /dev/ttyHSL0 | 244:0 | UART (Low-Speed) |

## USB Configuration

**USB Modes:**

| Mode | PID | Functions |
|------|-----|-----------|
| Debug (OLM) | B023 | rndis_gsi, serial, diag, ffs, acm, hid |
| Debug (OLM no tether) | B023 | serial, diag, ffs, acm, hid |
| FTM | B023 | serial, diag, ffs, acm, hid |
| LTM | B023 | rmnet_gsi, serial, diag, ffs, acm, hid |
| LPM | - | ffs, hid |
| EUM | B020 | hid, acm, mass_storage |
| EUM LPM | B010 | hid |
| Enterprise | B022 | hid, serial |

**Current Function List:** `rndis_gsi, serial, diag, ffs, acm, hid`

## Novatel CLI Tools (/opt/nvtl/bin/)

### Core Modem Tools

| Tool | Daemon | Purpose |
|------|--------|---------|
| modem2_cli | modem2d | Modem control, signal, bands, AT commands |
| sms_cli | smsd | SMS send/receive/delete |
| usb_cli | usbd | USB mode switching |
| wifi_cli | wifid | WiFi AP configuration |
| gps_cli | gpsd | GPS/GNSS location |
| router2_cli | router2d | Routing, NAT, DHCP |
| vpn_cli | vpnd | VPN tunnel management |

### System Tools

| Tool | Daemon | Purpose |
|------|--------|---------|
| settings_cli | settingsd | System settings |
| factory_reset_cli | factory_resetd | Factory reset |
| powersave_cli | powersaved | Power management |
| fota_cli | fotad | Firmware updates (OTA) |
| omadm_cli | omadmd | OMA Device Management |
| watchdog_cli | watchdogd | Watchdog timer |

### Diagnostics Tools

| Tool | Purpose |
|------|---------|
| diag_read | Qualcomm DIAG logging |
| mifi_debug_cli | Debug utilities |
| dmdb_cli | Device management DB |
| hostapd_cli | WiFi hostapd control |
| led_cli | LED control |
| buzzer_cli | Audio alerts |

### All Binaries (Exhaustive List)

```
ans_cli, ansd, bckrst.sh, bckrst_cli, bckrstd, buzzer_cli
cc.sh, cc_cli, ccd, ccm2.sh, ccm2_cli, ccm2d, cdra, cdra_cli
check_md5.sh, check_recovery_image.sh, create_device_sym_links.sh
ctrlxfer.sh, cumclient, cumclient.sh, cumclient_cli
customize_xml.sh, devui_cli, devuiappd, devuid
diag_read, diag_read.sh, dmdb.sh, dmdb_cli, dmdbd
dsm.sh, dsm_cli, dsmd, dua_cli, duad, emd, emd.sh, emd_cli
factory_reset.sh, factory_reset_cli, factory_resetd
file_sharing.sh, file_sharing_cli, file_sharingd
fix_log_files.sh, fota.sh, fota_cli, fota_interruption.sh
fota_linux_pri.sh, fota_pmode.sh, fota_pmode_watchdog.sh
fota_pmode_watchdog_init.sh, fotad
gps.sh, gps_cli, gpsd, hostapd, hostapd_cli
kernel_crash_log, kernel_crash_log.sh, led_cli, ledd
list_threads.sh, load_kernel_modules.sh, log_pub_cert.pem
low_volt_monitor.sh, lpmappd, mifi_debug_cli, mifi_debugd
mifi_debugd.sh, mifi_display_animation.sh, mifi_display_png
mifi_rootpass, mifi_rootpass.sh, mifi_sua_device, mifi_upi
mifi_upi_disp, modem2.sh, modem2_cli, modem2d
modem_at_server.sh, modem_at_server_cli, modem_at_serverd
msgbus_cli, msgbusd, nand_write_rate.sh, nbnsd
nua.sh, nua_cli, nua_upi.sh, nuad
nvtl_acm_test, nvtl_ans.sh, nvtl_avahi.sh, nvtl_cdra.sh
nvtl_check_webserver.sh, nvtl_chrt_ui.sh, nvtl_deviceui.sh
nvtl_devui.sh, nvtl_dns_resolver, nvtl_dnsd, nvtl_dua.sh
nvtl_encrypt, nvtl_fatest_ui.sh, nvtl_gpio_test, nvtl_led.sh
nvtl_log, nvtl_lpm.sh, nvtl_memusage.sh, nvtl_modfastcgi_init.sh
nvtl_msgbus.sh, nvtl_nmbd.sh, nvtl_redirect_init.sh
nvtl_runlevel.sh, nvtl_samba.sh, nvtl_smbd.sh
nvtl_usb_flash.sh, nvtl_watchdog.sh, nvtl_wdcp.sh
nvtl_webserver.sh, nvtl_xml.sh, nwcli, nwnvitem
omadm.sh, omadm_cli, omadm_ipl_cli, omadm_restore.sh
omadm_wap_proxy.sh, omadm_wap_proxyd, omadmd
powersave.sh, powersave_cli, powersaved, program_fotacookie.sh
router2.sh, router2_cli, router2d
save_var_log.sh, save_var_log_files.sh, save_var_log_files_init.sh
save_var_log_files_timer.sh, settings.sh, settings_cli, settingsd
smb_otg_off.sh, smb_usb3_ftm.sh, sms.sh, sms_cli, smsd
srtemplate.txt, stop_process.sh, storelogs.lib, storelogs.sh
sua_display_png.sh, sua_flash_device.sh, sua_start_update.sh
sysintcli, syslogd_monitor.sh, sysser.fcgi
test_touch_during_boot.sh, update_ipk.sh, uploadfile.sh
usb.sh, usb_cli, usb_start.sh, usb_start_init.sh, usbd
vpn.sh, vpn_cli, vpnd, watchdog_cli, watchdogd, wdcp
webui_cli, webuid, wifi.sh, wifi_cli, wifi_diag.sh, wifid, wl
xmldata_cli, xmlmergecust, xmlvalidate
```

## Modem2_cli Key Commands

```bash
# Information
get_info           # IMEI, IMSI, firmware, etc.
get_state          # Connection state
get_signal         # Signal strength
sim_get_status     # SIM status

# Radio Control  
radio_is_enabled
radio_set_enabled <0|1>
enabled_tech_get   # Get enabled technologies
enabled_tech_set   # Set technologies (bitmap)

# Band Control
active_band_get
lte_band_get_enabled
lte_band_set_enabled

# Network
mns_get_list       # Manual network selection
mns_select         # Select network

# Data
call_start         # Start data call
call_stop          # Stop data call
enable_data_call   # Enable/disable data

# APN
get_apn_from_database
get_custom_apn_from_database
set_custom_apn_to_database

# IMS/SMS
ims_get_sms_data
ims_set_sms_data

# Raw AT
run_raw_command    # Interactive raw AT
```

## SMS_cli Commands

```bash
get_list           # List messages (0=PreInbox, 1=Inbox, 2=Outbox, 3=Sent)
read               # Read message by ID
send               # Send SMS (interactive)
delete             # Delete message
get_unread         # Count unread
set_state          # Mark read/unread

# Address Book
ab_get_list        # List contacts
ab_get_entry       # Get contact by ID
ab_add_entry       # Add contact
ab_edit_entry      # Edit contact
ab_del_entry       # Delete contact
```

## Novatel Libraries (/opt/nvtl/lib/)

### SMS-Related

| Library | Purpose |
|---------|---------|
| libsms_api.so (21KB) | SMS API wrapper |
| libsms_encoder.so (92KB) | PDU/CDMA encoding |

### Modem-Related

| Library | Purpose |
|---------|---------|
| libmal_qct.so (307KB) | Modem Abstraction Layer (Qualcomm) |
| libmodem2_api.so (145KB) | Modem2 API |
| libmodem_at_server_api.so (14KB) | AT server API |

### System Libraries

```
libacm.so, libans_api.so, libbckrst_api.so, libbuzzer_api.so
libcc_api.so, libccm2_api.so, libcdra_api.so, libcdra_upload.so
libcumclient_api.so, libdevui_api.so, libdevui_model_api.so
libdmdb_api.so, libdsm_api.so, libdua_api.so, libemd_api.so
libfactory_reset_api.so, libfile_sharing_api.so, libfota_api.so
libfuel_gauge.so, libgpio.so, libgps_api.so, libled_api.so
liblpm_model_api.so, libMGA.so, libmifi_config.so, libmifi_debug.so
libmifi_leds.so, libmifi_mtd.so, libmifi_upi_fs.so, libmifi_upi_image.so
libmifimsgbus.so, libnua_api.so, libomadm_api.so, libomadm_bl.so (1.7MB)
libpowersave_api.so, librouter2_api.so, libsensor_api.so
libsettings_api.so, libsysintclient.so, libusb_api.so, libvpn_api.so
libwatchdog_api.so, libwebui_api.so, libwifi_api.so, libxmldata_api.so
```

## SMS Encoder Library Functions

From `libsms_encoder.so` strings:

```
IsConfiguredForGsm         # Check GSM mode
IsConfiguredForIS637       # Check CDMA mode
PDU_Encode_Sms             # Encode SMS to PDU
PDU_Decode_Sms             # Decode PDU to SMS
CDMA_Encode_Message_IS637  # CDMA IS-637 encode
CDMA_Decode_Message_IS637  # CDMA IS-637 decode
SmsMsgDataToSmsMsgDataEx   # Data conversion
UnicodeToAscii             # Character conversion
AsciiToUnicode
```

## QMI Functions (libmal_qct.so)

```
nwqmi_wms_send             # Send SMS via WMS
nwqmi_wms_read             # Read SMS
nwqmi_wms_delete_msg       # Delete SMS
nwqmi_wms_list             # List SMS
nwqmi_wms_get_routes       # Get SMS routes
nwqmi_wms_get_msg_protocol # Get message protocol
nwqmi_wms_get_message_waiting
nwqmi_wms_set_message_waiting
nwqmi_ims_get_sms_format   # IMS SMS format
nwqmi_ims_set_sms_format
nwqmi_ims_get_sms_over_ip
nwqmi_ims_set_sms_over_ip
```

## Web UI Apps (/opt/nvtl/webui/apps/)

48 web applications including:

- **Admin**: login, set_passcode, user_preferences
- **Device**: device_info, device_preferences, status_current, status_diagnostics
- **Network**: connected_devices, lan, wwan_settings, firewall, port_filtering
- **WiFi**: wifi_primary_settings, wifi_guest_settings, wifi_advanced_settings
- **SMS**: sms
- **GPS**: gps
- **VPN**: vpn
- **File**: file_sharing, backup_restore
- **Diagnostics**: field_test_info, lab_test_info, debug_logs, status_logs
- **Update**: software_update, sideload_software_update, sideload_software_install

## Feature Flags (/sysconf/features.xml)

| Feature | Enabled | Notes |
|---------|---------|-------|
| USBTethering | 1 | USB RNDIS |
| RadioTechnologies | 95 | GSM+WCDMA+CDMA+EVDO+LTE+WiFi |
| WiFiAccessPoint | 1 | |
| WiFiDualSsid | 1 | |
| WiFiStation | 0 | Client mode disabled |
| GPS | 1 | |
| PowerSave | 1 | |
| IPv6 | 1 | |
| SMSMobileTerminated | 1 | Can receive SMS |
| SMSMobileOriginated | 0 | **Cannot send SMS from UI** |
| Voice | 0 | |
| Webui | 1 | |
| Deviceui | 1 | LCD touch UI |
| VPN | 1 | |
| DNS | 1 | |
| OMADM | 1 | Device management |
| FOTA | 1 | Firmware OTA |
| LED | 1 | |
| AutoAPN | 0 | |

**Note:** `SMSMobileOriginated=0` means the web UI/device UI doesn't expose SMS sending, but `sms_cli send` and QMI API may still work.

## Kernel Modules

```
brcmfmac        # Broadcom WiFi
cfg80211        # WiFi config
brcmutil        # Broadcom util
compat          # Compat layer
ramoops         # RAM crash logs
shortcut_fe     # Shortcut Forwarding Engine
shortcut_fe_ipv6
shortcut_fe_cm
bq27520_battery_nvtl  # Battery gauge
msm_mnd_buzzer  # Buzzer/audio
cyttsp5*        # Cypress touchscreen (I2C)
fusb30x_whole   # USB Type-C controller
smb1351_charger_nvtl  # SMB1351 charger
```

## Running Processes

Key daemons:

```
init, udevd, syslogd, adbd
ipacm, ipacmdiag, ipacm_perf  # IPA (Integrated Packet Accelerator)
qti, port_bridge, netmgrd     # Qualcomm utilities
tftp_server, rngd             # System services
msgbusd, settingsd, dsmd      # Novatel core
usbd, router2d, devuid        # USB/Network/Device UI
webuid, devuiappd, sysser.fcgi, lighttpd  # Web interface
modem2d, smsd, gpsd           # Modem services
wifid, hostapd (x2)           # WiFi
omadmd, wdcp, fotad           # Management/Updates
ledd, ansd, watchdogd         # Hardware control
diag_read, modem_at_serverd   # Diagnostics
dhcpd, nvtl_dnsd              # Network services
```

## System Users

| User | UID | Purpose |
|------|-----|---------|
| root | 0 | System |
| mifi | 1001 | MiFi user |
| lighttpd | 4000 | Web server |
| twonky | 1002 | Media server |
| nobody | 99 | Unprivileged |

## Configuration Files

### Key Paths

- `/sysconf/features.xml` - Feature flags
- `/sysconf/settings.xml` - Device settings
- `/opt/nvtl/etc/modem2/config.xml` - Carrier profiles/APN
- `/opt/nvtl/etc/webui/config.xml` - Web UI config
- `/opt/nvtl/etc/webui/menu_layout.json` - UI layout
- `/etc/lighttpd/lighttpd.conf` - Web server
- `/etc/passwd` - Users
- `/etc/shadow` - Password hashes

### WiFi Configuration (from settings.xml)

```xml
<APProfile index="1">
  <Ssid>8800</Ssid>
  <SecurityType>3</SecurityType>  <!-- WPA2 -->
  <Passphrase>yoyoyoyo</Passphrase>
  <Channel>0</Channel>  <!-- Auto -->
  <Mode>1</Mode>  <!-- BGN -->
</APProfile>
```

## Environment Variables

```bash
LD_LIBRARY_PATH=:/opt/nvtl/lib
PATH=/sbin:/usr/sbin:/bin:/usr/bin:/opt/nvtl/bin
SHELL=/bin/sh
```

## Known Limitations

1. **No Python** - Shell/busybox scripting only
2. **AT ports busy** - `modem_at_serverd` holds AT devices
3. **SMS MO disabled** - UI doesn't expose SMS sending
4. **No signal** - Device searching (may need antenna/location)
5. **Clock reset** - Shows Jan 1970 (no NTP without network)

## Recovery Options

### Fastboot Mode

```bash
adb reboot bootloader
# OR hold Volume Down during power-on
fastboot devices
fastboot getvar all
```

### EDL Mode (Emergency Download)

```bash
adb reboot edl
# Look for Qualcomm 9008 device
```

## References

- Chipset: Qualcomm SDX20 (Alpine LE10)
- WiFi: Broadcom BCM4359 (brcmfmac)
- Charger: SMB1351
- Touch: Cypress CYTTSP5
- USB-PD: FUSB302
- Battery: TI BQ27520
