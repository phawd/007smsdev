# Inseego MiFi Device Guide

This guide covers Inseego MiFi device (MiFi 8800L, M2000, M2100) setup, discovery, and SMS operations. These devices run **MiFiOS2** (PTXdist Linux), NOT Android.

> **CRITICAL**: These are embedded Linux devices. Do not use Android-specific commands like `getprop`, `pm`, `am`.

## Device Overview

| Property | MiFi 8800L Value |
|----------|------------------|
| Model | MIFI8800L |
| Firmware | SDx20ALP-1.22.11 |
| Chipset | Qualcomm SDX20 (Alpine) |
| OS | MiFiOS2 (PTXdist Linux) |
| VID:PID | 1410:B023 |
| Root | Yes (uid=0 default) |
| RNDIS IP | 169.254.3.1 |
| Web UI | <http://192.168.11.1> or via RNDIS |

### Known Inseego Models

| Model | VID | PID | Chipset | Notes |
|-------|-----|-----|---------|-------|
| MiFi 8800L | 1410 | B023 | SDX20 | Verizon LTE |
| MiFi M2000 | 1410 | B024 | SDX55 | T-Mobile 5G |
| MiFi M2100 | 1410 | B025 | SDX65 | 5G mmWave |

## Device Discovery

### Step 1: Identify Device via USB

```bash
# VID 1410 = Novatel/Inseego
python3 tools/smstest_cli.py usb --json | grep -i 1410

# Windows PowerShell
Get-PnpDevice | Where-Object { $_.InstanceId -like '*1410*' }
```

### Step 2: Add Vendor ID to ADB Config

```bash
echo "0x1410" >> ~/.android/adb_usb.ini
adb kill-server
adb start-server
adb devices
```

### Step 3: Verify MiFi (Linux-based)

```bash
adb shell "cat /etc/os-release"    # Shows MiFiOS2/PTXdist
adb shell "id"                      # Should show root access
```

### Step 4: Discover Modem Paths

```bash
adb shell "ls -la /dev/at_* /dev/smd* /dev/diag /dev/ttyHS* 2>/dev/null"
# Expected: /dev/at_mdm0, /dev/at_usb0, /dev/smd7, /dev/smd11, /dev/diag
```

## Modem Device Nodes

| Path | Description |
|------|-------------|
| `/dev/at_mdm0`, `/dev/at_usb0`, `/dev/at_usb1` | AT command interfaces |
| `/dev/smd7`, `/dev/smd8`, `/dev/smd11` | SMD (Shared Memory Driver) |
| `/dev/diag` | Qualcomm DIAG (QCDM) |
| `/dev/ttyHS0`, `/dev/ttyHSL0` | UART interfaces |

## USB Composite Interfaces

| Interface | Function |
|-----------|----------|
| MI_00 | RNDIS (169.254.3.1) |
| MI_04 | ADB Interface |
| MI_05 | Mass Storage |
| MI_0C | CDC Serial/ACM |
| MI_0D | HID (touchscreen) |

**USB Composite Functions (when fully enabled):**
`rndis_gsi, serial, diag, ffs, acm, hid`

## Native CLI Tools (/opt/nvtl/bin/)

MiFi devices have **built-in CLI tools** that are more reliable than raw AT commands.

### Full CLI Tool List

| Tool | Purpose |
|------|---------|
| `sms_cli` | SMS send/receive/delete |
| `modem2_cli` | Modem control, bands, EFS, raw AT |
| `usb_cli` | USB mode switching |
| `wifi_cli` | WiFi AP configuration |
| `router2_cli` | Network routing/NAT |
| `gps_cli` | GPS/GNSS control |
| `diag_read` | Qualcomm DIAG logging |
| `fota_cli` | Firmware updates |
| `factory_reset_cli` | Factory reset |
| `nwcli` | QMI interface commands |
| `nwnvitem` | NV item read/write (limited) |

### SMS Operations

```bash
adb shell "/opt/nvtl/bin/sms_cli help"         # List SMS commands
adb shell "/opt/nvtl/bin/sms_cli send"         # Interactive SMS send
adb shell "/opt/nvtl/bin/sms_cli get_list"     # List inbox/outbox
adb shell "/opt/nvtl/bin/sms_cli get_unread"   # Unread count
adb shell "/opt/nvtl/bin/sms_cli read"         # Read message
adb shell "/opt/nvtl/bin/sms_cli delete"       # Delete message
```

### Modem Control & Info

```bash
adb shell "/opt/nvtl/bin/modem2_cli get_info"       # IMEI, IMSI, ICCID, firmware
adb shell "/opt/nvtl/bin/modem2_cli get_signal"     # Signal strength, tech, bands
adb shell "/opt/nvtl/bin/modem2_cli get_state"      # Connection state
adb shell "/opt/nvtl/bin/modem2_cli sim_get_status" # SIM status
adb shell "/opt/nvtl/bin/modem2_cli enabled_tech_get"  # LTE/UMTS/CDMA modes
```

### USB Mode Control

```bash
adb shell "/opt/nvtl/bin/usb_cli get_config"   # Current USB functions
adb shell "/opt/nvtl/bin/usb_cli get_state"    # USB gadget state
adb shell "/opt/nvtl/bin/usb_cli mode_switch"  # Switch USB modes
```

### Band Management

```bash
adb shell "/opt/nvtl/bin/modem2_cli active_band_get"
adb shell "/opt/nvtl/bin/modem2_cli lte_band_get_enabled"
adb shell "/opt/nvtl/bin/modem2_cli lte_band_set_enabled"
```

### Raw AT Commands

```bash
adb shell "/opt/nvtl/bin/modem2_cli run_raw_command"  # Interactive AT prompt
```

## EFS/NV Item Access

The MiFi 8800L provides two main tools for accessing NV (Non-Volatile) items and EFS (Embedded File System):

1. **`nwcli qmi_idl`** - QMI-based access to modem NV items and EFS files
2. **`nwnvitem`** - Access to device-specific NV items (MAC, passwords, etc.)

### QMI NV/EFS Commands (nwcli qmi_idl)

```bash
# List available QMI commands
adb shell "/opt/nvtl/bin/nwcli qmi_idl help"
# Commands: read_nv, write_nv, read_file, write_file, factory_restore, etc.

# Read NV items (index 0=primary, 1=secondary)
adb shell "/opt/nvtl/bin/nwcli qmi_idl read_nv <item_id> <index>"

# Read EFS files
adb shell "/opt/nvtl/bin/nwcli qmi_idl read_file /tmp/out.bin <efs_path> <max_bytes>"

# Write EFS files
adb shell "/opt/nvtl/bin/nwcli qmi_idl write_file /tmp/in.bin <efs_path>"

# Interactive EFS via modem2_cli
adb shell "/opt/nvtl/bin/modem2_cli efs_read"        # Interactive read
adb shell "/opt/nvtl/bin/modem2_cli efs_write"       # Interactive write
adb shell "/opt/nvtl/bin/modem2_cli efs_read_large"  # Shared memory buffer
adb shell "/opt/nvtl/bin/modem2_cli efs_delete"      # Delete file
```

### Readable NV Items (18 Total)

| NV ID | Description | Sample Data | Notes |
|-------|-------------|-------------|-------|
| 0 | Security Code | `00 00 00 00...` | All zeros (disabled) |
| 1 | Slot Cycle Index | `ff ff ff ff 00...` | |
| 2 | Unknown | `00 00...` | |
| 3 | Min Lock | `00 00...` | |
| 10 | Slot Cycle | `00 3d 00...` | |
| 441 | GPS Mode | `00 00...` | Zeros |
| 550 | **IMEI (BCD)** | `08 9a 09 10 86 87 75 93 78` | Decodes to 990016878573987 |
| 553 | SID/NID Lock | `05 00...` | Value 5 |
| 946 | Modem Config | `00 c0 04 00...` | |
| 947 | SMS Config | `00 00...` | Zeros |
| 1015 | Roaming Config | `00 00...` | Zeros |
| 1016 | Roaming Config 2 | `01 00...` | Roaming enabled |
| 2954 | Band Class Pref | `00 00 00 02...` | |
| 3461 | **SIM Lock Status** | `01 00...` | Value 1 |
| 4399 | **Subsidy Lock 2** | `01 00...` | Value 1 |
| 6828 | Perso Status | `00 00...` | Zeros |
| 6830 | Carrier Info | `0a 00...` | Value 10 (Verizon) |
| 60044 | **PRI Version** | ASCII text | "PRI.90029477 REV 151 Alpine VERIZON" |

**Protected NV Items (Error 8193 - Access Denied):**

- NV 5, 851, 4398 - Carrier/SIM lock configuration (require SPC code)
- Most items in ranges 100-400, 600-800

### Device NV Items (nwnvitem)

Separate tool for device-specific configuration:

```bash
adb shell "/opt/nvtl/bin/nwnvitem -r -e <ITEM_NAME>"   # Read
adb shell "/opt/nvtl/bin/nwnvitem -w -e <ITEM_NAME> -d <data>"  # Write
```

| Item Name | Description | Sample Value |
|-----------|-------------|--------------|
| `NW_NV_MAC_ID_I` | WiFi MAC Address | `18:EE:86:AF:C8:74` |
| `NW_NV_MAC_ID_2_I` | Secondary MAC | `18:EE:86:AF:C8:75` |
| `NW_NV_USB_MAC_ID_I` | USB RNDIS MAC | `00:15:FF:85:73:98` |
| `NW_NV_ETHERNET_MAC_ID_I` | Ethernet MAC (hex) | `LO32=0x85FF1500 HI16=0x9073` |
| `NW_NV_PRI_INFORMATION_I` | PRI Version | `PRI.90029477 REV 151 Alpine VERIZON` |
| `NW_NV_USB_DEFAULT_MODE_I` | USB Mode | `DEBUG` |
| `NW_NV_PSM_DEFAULT_MODE_I` | Power Save Mode | `0` |
| `NW_NV_LINUX_RUN_LEVEL_I` | Init Run Level | `0 3` |
| `NW_NV_LINUX_ROOT_PASSWORD_I` | Root Password Hash | `$1$lpggZbjV$...` (MD5 crypt) |
| `NV_AUTO_POWER_I` | Auto Power On | `1` (enabled) |

### Readable EFS Files

| Path | Size | Description |
|------|------|-------------|
| `/nv/item_files/modem/mmode/lte_bandpref` | 8 bytes | LTE band bitmask (`ff ff ff ff ff ff ff ff` = all bands) |
| `/policyman/device_config.xml` | ~503 bytes | Device configuration XML |

**device_config.xml Contents:**

```xml
<device_config name="MiFi" target="CHGWLT" single_sim="0" ss_toggle="0">
  <config primary="C H G W L T" />
  <feature name="Feature_Hdr" enabled="1" />
  <feature name="Feature_RF_Bands" enabled="0" />
</device_config>
```

Where: C=CDMA, H=HDR/EVDO, G=GSM, W=WCDMA, L=LTE, T=TD-SCDMA

### Known EFS Paths (from library strings)

These paths exist in firmware but may not be accessible:

| Path | Purpose |
|------|---------|
| `/nv/item_files/modem/mmode/lte_bandpref` | LTE band enable bitmask ✅ |
| `/nv/item_files/modem/lte/rrc/csp/band_priority_list` | Band priority |
| `/nv/item_files/modem/mmode/sxlte_timers` | SXLTE timing config |
| `/nv/item_files/ims/qp_ims_voip_config` | VoLTE/VoIP config |
| `/nv/item_files/ims/qp_ims_sms_config` | IMS SMS config |
| `/nv/item_files/ims/ims_sip_config` | SIP configuration |
| `/nv/item_files/ims/qipcall_enable_hd_voice` | HD Voice toggle |
| `/nv/item_files/ims/qipcall_codec_mode_set` | Audio codec config |
| `/nv/item_files/cne/1XDataServiceTransferTimer` | Data transfer timer |
| `/nv/item_files/cdma/1xcp/disable_so35_so36` | CDMA service options |
| `/policyman/device_config.xml` | Device capabilities ✅ |
| `/policyman/carrier_policy.xml` | Carrier policy |

### Modifying EFS Files - Enable All LTE Bands

```bash
# Create file with all bands enabled (8 bytes of 0xFF)
adb shell "echo -n -e '\xff\xff\xff\xff\xff\xff\xff\xff' > /tmp/lte_band_all.bin"

# Write to EFS
adb shell "/opt/nvtl/bin/nwcli qmi_idl write_file /tmp/lte_band_all.bin /nv/item_files/modem/mmode/lte_bandpref"

# Toggle radio to apply
adb shell "/opt/nvtl/bin/modem2_cli radio_set_enabled 0; sleep 2; /opt/nvtl/bin/modem2_cli radio_set_enabled 1"
```

## Network Configuration

### Network Scan Commands

```bash
# Start manual network scan
adb shell "/opt/nvtl/bin/modem2_cli mns_start_scan"

# Wait 30-45 seconds, then get results
adb shell "/opt/nvtl/bin/modem2_cli mns_get_list"
# Output: +COPS: (status,"mccmnc","name",tech)
# Status: 1=available, 2=current, 3=forbidden

# Manually select network
adb shell "/opt/nvtl/bin/modem2_cli mns_set_oper"
# Prompts: Enable MNS, MCCMNC, Access tech (GSM=0, UMTS=2, LTE=7)

# Check registration state
adb shell "/opt/nvtl/bin/modem2_cli get_state"
# States: Searching, Online, No Service, Not Activated
```

### Enable All Radio Technologies

```bash
adb shell "/opt/nvtl/bin/modem2_cli enabled_tech_set"
# Enter: GSM,UMTS,CDMA,EVDO,LTE
# Result: Enabled tech modes:[31]
```

### Enable Roaming

```bash
adb shell "/opt/nvtl/bin/modem2_cli roam_set_enabled"
# Enter: 1
```

### Set APN Profile

```bash
adb shell "/opt/nvtl/bin/modem2_cli prof_set_pri_tech"
# Technology: 0 (LTE)
# APN: broadband (for AT&T)
# Auth: 2 (CHAP)
# PDP type: 3 (v4v6)
```

### Modify EFS Band Preference

```bash
# Create all-bands file
adb shell "echo -n -e '\xff\xff\xff\xff\xff\xff\xff\xff' > /tmp/lte_band_all.bin"

# Write to EFS
adb shell "/opt/nvtl/bin/nwcli qmi_idl write_file /tmp/lte_band_all.bin /nv/item_files/modem/mmode/lte_bandpref"
```

### Toggle Radio to Apply Changes

```bash
adb shell "/opt/nvtl/bin/modem2_cli radio_set_enabled 0; sleep 2; /opt/nvtl/bin/modem2_cli radio_set_enabled 1"
```

## Cross-Carrier Setup (AT&T SIM on Verizon Device)

**Problem:** Device stuck in "Searching" state despite SIM being detected.

**Solution:**

1. **Enable all radio technologies:**

   ```bash
   adb shell "/opt/nvtl/bin/modem2_cli enabled_tech_set"
   # Enter: GSM,UMTS,CDMA,EVDO,LTE
   ```

2. **Enable roaming (critical!):**

   ```bash
   adb shell "/opt/nvtl/bin/modem2_cli roam_set_enabled"
   # Enter: 1
   ```

3. **Set correct APN:**

   ```bash
   adb shell "/opt/nvtl/bin/modem2_cli prof_set_pri_tech"
   # Technology: 0 (LTE), APN: broadband, Auth: 2, PDP: 3
   ```

4. **Modify EFS band preference:**

   ```bash
   adb shell "echo -n -e '\xff\xff\xff\xff\xff\xff\xff\xff' > /tmp/lte_band_all.bin"
   adb shell "/opt/nvtl/bin/nwcli qmi_idl write_file /tmp/lte_band_all.bin /nv/item_files/modem/mmode/lte_bandpref"
   ```

5. **Toggle radio:**

   ```bash
   adb shell "/opt/nvtl/bin/modem2_cli radio_set_enabled 0; sleep 2; /opt/nvtl/bin/modem2_cli radio_set_enabled 1"
   ```

**Successful Connection Result:**

```text
state:[Connected]
reg state:[1]
tech:[10] (LTE)
rssi:[-77]
bars:[2]
oper name:[Boost]
oper id:[310410]
cell id:[56756948]
```

## Carrier Unlock Investigation

### Check Lock Status

```bash
adb shell "/opt/nvtl/bin/modem2_cli get_carrier_unlock"
# State:[0] Carrier block:[0] Verify retries:[0] Unblock retries:[0]
# State 0 = unlocked at modem level
```

### Carrier Configuration

- `CertifiedCarrier` in `/sysconf/settings.xml` controls carrier behavior
- Valid values: `Verizon`, `Sprint`, `AT&T`, `Bell`, `Telus`, `GSM`, `AUTO`

### Configuration Files

```bash
# Enable SMS sending (was disabled)
sed -i 's/SMSMobileOriginated>0/SMSMobileOriginated>1/' /sysconf/features.xml

# Change carrier mode
sed -i 's/CertifiedCarrier>Verizon/CertifiedCarrier>AUTO/' /sysconf/settings.xml
```

### Unlock Commands (NCK code required)

```bash
/opt/nvtl/bin/modem2_cli unlock_carrier      # Needs NCK unlock code
/opt/nvtl/bin/modem2_cli get_carrier_unlock  # Check status
```

## Fastboot & Recovery

### Enter Fastboot Mode

```bash
adb reboot bootloader
# OR: Hold Volume Down while powering on
```

### Fastboot Commands (30+ second timeout!)

```bash
fastboot devices
fastboot getvar all          # Device info
fastboot oem device-info     # Lock status
fastboot oem unlock          # Unlock (wipes device)
```

## EDL (Emergency Download) Mode

If device is bricked or needs low-level access:

### Enter EDL Mode (Qualcomm 9008)

```bash
adb reboot edl               # From ADB if available
# OR: Hold Volume Up + Volume Down while connecting USB
# OR: Short test points on PCB (device-specific)
```

### Check for EDL Device

```bash
python3 tools/smstest_cli.py usb --json | grep -E "05C6|9008"
# Windows: Look for "Qualcomm HS-USB QDLoader 9008" in Device Manager
```

### EDL Tools

```bash
pip install edl
edl printgpt                 # Show partition table
edl r full_dump.bin          # Full read (if unlocked)
```

## Filesystem & Partitions

### MTD Partitions

| Partition | Size | Name |
|-----------|------|------|
| mtd0 | 2.5 MB | sbl (Secondary Boot Loader) |
| mtd1 | 2.5 MB | mibib |
| mtd2 | 11 MB | **efs2** (Carrier lock data!) |
| mtd3 | 2 MB | tz (TrustZone) |
| mtd4 | 1 MB | rpm |
| mtd5 | 2 MB | aboot (Android Boot) |
| mtd6 | 20 MB | boot |
| mtd7 | 0.5 MB | scrub |
| mtd8 | 77 MB | modem |
| mtd9 | 1 MB | misc |
| mtd10 | 20 MB | recovery |
| mtd11 | 1 MB | fotacookie |
| mtd12 | 371 MB | system |

### Backup Files (mifi_backup/)

| File | Size | Contents |
|------|------|----------|
| `firmware_backup.tar.gz` | 27.7 MB | Modem firmware, WiFi blobs, boot images |
| `opt_nvtl_backup.tar.gz` | 10.4 MB | CLI tools, libraries, configs |
| `root_backup.tar.gz` | 2.7 MB | /root including dmesg, backing_file |
| `etc_backup.tar.gz` | 0.5 MB | System configs, init scripts, SSL certs |
| `data_backup.tar.gz` | 0.1 MB | Persist data, USB configs |
| `sysconf_backup.tar.gz` | 12 KB | features.xml, settings.xml |

## SMS Architecture (Internal)

```text
sms_cli → libsms_api.so → smsd (daemon)
                ↓
        libsms_encoder.so (PDU/CDMA)
                ↓
        libmal_qct.so (QMI)
                ↓
        nwqmi_wms_send() → modem
```

### Critical Libraries

- `libsms_encoder.so` - `PDU_Encode_Sms()`, `CDMA_Encode_Message_IS637()`
- `libmal_qct.so` - `nwqmi_wms_send()`, `nwqmi_wms_read()`
- `libmodem2_api.so` - Modem control abstraction

## Troubleshooting

### Device Not Responding to ADB

```bash
adb kill-server
adb start-server
adb devices  # Retry
```

### Device Stuck - Force Reboot

```bash
adb reboot                      # Soft reboot
adb shell su -c "reboot -f"     # Force reboot (root)
# Hardware: Hold power 10-15 seconds
```

### USB Interface Issues (Windows)

```bash
pnputil /scan-devices           # Rescan (needs admin)
# Device Manager → USB device → Uninstall → Rescan
```

### RNDIS Not Getting IP

```bash
ipconfig /release "Ethernet X"  # Release DHCP
ipconfig /renew "Ethernet X"    # Renew DHCP
# Or manually set IP in same subnet as device gateway
```

### Serial/COM Port Not Appearing

- Check Device Manager for yellow ! icons
- Install Qualcomm USB drivers or use generic usbser.sys
- Try: `python3 tools/smstest_cli.py comscan --json`

## AI Agent Integration Notes

For AI agents (Gemini, Claude, GPT) working autonomously:

1. **Always use 30+ second timeouts** for device operations - modems are slow
2. **Check prerequisites first**: `adb`, `fastboot`, `python3`, pyserial installed
3. **Detect device type FIRST**: Android vs MiFiOS (Linux) requires different commands
4. **Escalate gracefully**: ADB → fastboot → EDL → web interface → manual intervention
5. **Log everything**: Use `python3 tools/smstest_cli.py probe --deep --include-response > probe-log.txt`
6. **Handle driver issues**: Windows devices may show "Unknown" status - need admin
7. **Network vs USB**: MiFi devices often prefer Wi-Fi connection over USB tethering for admin access
8. **Document findings**: Update `docs/SESSION_*_FINDINGS.md` with device-specific discoveries

### Device Type Detection Flow

```bash
# Step 1: Check if device responds to ADB
adb devices -l

# Step 2: Detect OS type
adb shell "cat /etc/os-release 2>/dev/null"       # Linux-based (MiFi)
adb shell "getprop ro.build.product 2>/dev/null"  # Android

# Step 3: Branch based on OS
# - MiFiOS2: Use /opt/nvtl/bin/* CLI tools
# - Android: Use standard Android commands, SmsManager API
```

### MiFi-Specific Agent Workflow

```bash
# 1. Gather device info
adb shell "/opt/nvtl/bin/modem2_cli get_info"
adb shell "/opt/nvtl/bin/modem2_cli sim_get_status"

# 2. Check connectivity
adb shell "/opt/nvtl/bin/modem2_cli get_state"     # Look for state:[Online]
adb shell "/opt/nvtl/bin/modem2_cli get_signal"    # Check for signal

# 3. Send SMS (if signal available)
adb shell "/opt/nvtl/bin/sms_cli send"             # Interactive

# 4. If no signal, check radio
adb shell "/opt/nvtl/bin/modem2_cli radio_is_enabled"
adb shell "/opt/nvtl/bin/modem2_cli radio_set_enabled 1"  # Enable if needed
```

## Related Documentation

- `docs/MIFI_8800L_DEVICE_REFERENCE.md` - Comprehensive hardware catalog
- `docs/SESSION_2_FINDINGS.md` - Experimental session notes
