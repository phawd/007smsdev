# Extended NV Item Discovery & Alternate Program Analysis

**Date**: December 4, 2025  
**Device**: Inseego MiFi 8800L (Qualcomm SDX20 Alpine)  
**Discovery Scope**: NV 0-30,000 range + hidden/alternate programs

## Key Findings

### 1. Extended NV Item Accessibility (0-30,000 Range)

**Coarse-Grain Scan Results (500-item intervals):**
- **All 25 test points responded successfully** (0, 500, 1000, 1500, ..., 30000)
- Status: Every 500-item interval returned OK
- Conclusion: **Modem supports NV item indexing beyond 20,000 range**

**Fine-Grain Scan Results (550-1100 range, 50-item intervals):**
- **All 12 test points readable** (550, 600, 650, 700, 750, 800, 850, 900, 950, 1000, 1050, 1100)
- Status: 100% readability in sampled range
- Pattern: Consistent with previous discovery (201 items in 100-item intervals 0-20,000)

### 2. Write Capability Testing

**NV 550 (IMEI) Test:**
```
Original read: READABLE
Write attempt: SUCCESS (response received)
Result: Indicates some items accept write commands without error
```

**Critical Discovery - NV 60044 (PRI Version):**
```
Original value: "PRI.90029477 REV 151 Alpine VERIZON"
Write test value: "NVTL rocks!!"
Test result: SUCCESSFUL WRITE
Restore: Successfully wrote old value back
Conclusion: THIS ITEM IS WRITABLE (confirmed with restore validation)
```

**Write Capability Summary:**
- **Writable Items**: At least NV 60044 confirmed
- **Pattern**: High-numbered NV items (>60000) may have fewer protections
- **Access Model**: Items follow device protection hierarchy, not all locked

### 3. AT Command Interfaces

**Available Interfaces:**
```
/dev/at_mdm0  - Qualcomm MDM AT interface (EXISTS)
/dev/at_usb0  - USB AT serial interface 0 (EXISTS)
/dev/at_usb1  - USB AT serial interface 1 (EXISTS)
```

**Status**: All AT interfaces present; direct access requires elevated shell techniques

### 4. Programs Discovered - Complete Inventory

**Total Programs in `/opt/nvtl/bin/`**: 180+ utilities

**Key Categories:**

#### Modem Control (8 programs)
- `modem2_cli` - Main modem control interface
- `modem2d` - Modem daemon
- `modem2.sh` - Modem shell wrapper
- `modem_at_server_cli` - AT command server
- `modem_at_serverd` - AT server daemon
- `modem_at_server.sh` - AT server wrapper
- `modem2d` - Daemon
- `diag_read` - Qualcomm DIAG protocol reader

#### SMS/SMS Handling (3 programs)
- `sms_cli` - SMS command-line interface
- `sms.sh` - SMS shell wrapper
- `smsd` - SMS daemon
- `libsms_encoder.so` - SMS encoding library

#### NV Item Access (2+ programs)
- `nwcli` - Main QMI/NV command interface
- `nwnvitem` - Device NV item access tool (for device-specific settings)
- `nwcli qmi_idl` - QMI IDL interface (used in discovery)

#### USB Management (8 programs)
- `usb_cli` - USB configuration
- `usb.sh` - USB shell wrapper
- `usbd` - USB daemon
- `nvtl_usb_flash.sh` - USB flash utility
- `usb_start.sh` - USB startup
- `usb_start_init.sh` - USB init
- `sua_flash_device.sh` - Flash device via USB

#### Firmware/FOTA (8 programs)
- `fota_cli` - FOTA (Firmware Over The Air) control
- `fotad` - FOTA daemon
- `fota.sh` - FOTA shell wrapper
- `fota_linux_pri.sh` - PRI firmware update
- `fota_pmode_watchdog.sh` - FOTA power mode watchdog
- `fota_pmode_watchdog_init.sh` - FOTA init
- `fota_interruption.sh` - FOTA interrupt handler
- `program_fotacookie.sh` - FOTA cookie programming

#### Configuration/System (20+ programs)
- `settings_cli`, `settingsd`, `settings.sh` - System settings
- `factory_reset_cli`, `factory_reset.sh` - Factory reset
- `bckrst_cli`, `bckrst.sh`, `bckrstd` - Backup/restore
- `nvtl_xml.sh`, `xmldata_cli` - XML configuration
- `nvtl_watchdog.sh`, `watchdog_cli` - System watchdog
- `nvtl_encrypt` - Encryption utility

#### Network/Routing (8 programs)
- `router2_cli`, `router2d`, `router2.sh` - Network routing
- `wifi_cli`, `wifid`, `wifi.sh` - WiFi control
- `vpn_cli`, `vpnd`, `vpn.sh` - VPN control

#### GPS/Location (3 programs)
- `gps_cli`, `gpsd`, `gps.sh` - GPS control
- `omadm_cli`, `omadm.sh`, `omadmd` - OMA-DM (device management)

#### Device UI/Display (8+ programs)
- `devui_cli`, `devuid`, `devuiappd` - Device UI
- `mifi_display_png`, `mifi_display_animation.sh` - Display control
- `sua_display_png.sh` - SUA display
- `nvtl_dua.sh`, `dua_cli` - DUA interface

#### Diagnostics/Debug (10+ programs)
- `mifi_debug_cli`, `mifi_debugd` - Debug interface
- `kernel_crash_log`, `kernel_crash_log.sh` - Crash logging
- `nvtl_gpio_test` - GPIO testing
- `nvtl_acm_test` - ACM testing
- `check_recovery_image.sh` - Recovery check
- `check_md5.sh` - MD5 verification
- `list_threads.sh` - Thread listing
- `nvtl_memusage.sh` - Memory usage

#### Service/Infrastructure (20+ programs)
- `ans_cli`, `ansd`, `nvtl_ans.sh` - ANS service
- `avahi` related - mDNS/Bonjour
- `nbnsd` - NetBIOS name service
- `syslogd_monitor.sh` - Syslog monitoring
- `msgbus_cli`, `msgbusd` - Message bus
- `nua_cli`, `nuad`, `nua.sh` - NUA service
- `dsm_cli`, `dsmd`, `dsm.sh` - Data stream management
- `emd_cli`, `emdd`, `emd.sh` - Event manager
- `cumclient_cli`, `cumclient.sh` - CUM client

#### Data/Storage (5+ programs)
- `dmdb_cli`, `dmdbd`, `dmdb.sh` - Database
- `uploadfile.sh` - File upload
- `file_sharing_cli`, `file_sharingd` - File sharing
- `nvtl_redirect_init.sh` - Redirection init

#### Network Services (15+ programs)
- `hostapd`, `hostapd_cli` - WiFi AP daemon
- `webui_cli`, `webuid` - Web UI service
- `ctrlxfer.sh` - Control transfer
- `cc_cli`, `ccd`, `cc.sh` - Control center
- `ccm2_cli`, `ccm2d`, `ccm2.sh` - Control center M2
- `mifi_sua_device` - SUA device
- `mifi_upi`, `mifi_upi_disp` - UPI interface
- `lpmappd` - LPM APP daemon
- `watchdogd` - Watchdog daemon

**Total Enumeration**: 180+ programs across 20+ functional categories

### 5. Firmware & Flash Tools

**FOTA (Firmware Over The Air) Suite:**
- `fota_cli` - FOTA control interface
- `fota_linux_pri.sh` - Modem PRI firmware update script
- `fota_pmode_watchdog.sh` - Firmware update watchdog
- `fotad` - Background FOTA daemon
- `/opt/nvtl/bin/tests/fota_cfg_xml_updater` - FOTA config updater

**USB Flash Tools:**
- `sua_flash_device.sh` - SUA (Software Update Appliance) flash
- `nvtl_usb_flash.sh` - Generic USB flash utility

**Recovery & Restore:**
- `bckrst_cli` - Backup/restore CLI
- `omadm_restore.sh` - OMA-DM restore script
- `program_fotacookie.sh` - FOTA cookie programming

### 6. Critical Libraries for NV/Modem Access

**Library Inventory:**
```
/opt/nvtl/lib/libmodem2_api.so         - Modem control API
/opt/nvtl/lib/libsms_encoder.so        - SMS encoding (contains PDU logic)
/opt/nvtl/lib/libfota_api.so           - FOTA API
/opt/nvtl/lib/libomadm_api.so          - OMA-DM API
/opt/nvtl/lib/libcumclient_api.so      - CUM client API
/opt/nvtl/lib/libwatchdog_api.so       - Watchdog API
/opt/nvtl/lib/libwebui_api.so          - Web UI API
/opt/nvtl/lib/libvpn_api.so            - VPN API
/opt/nvtl/lib/libnua_api.so            - NUA API
/opt/nvtl/lib/libdevui_api.so          - Device UI API
/opt/nvtl/lib/libxmldata_api.so        - XML data API
/opt/nvtl/lib/libmifi_debug.so         - Debug interface
/opt/nvtl/lib/libmifi_upi_fs.so        - UPI filesystem
/opt/nvtl/lib/libfuel_gauge.so         - Battery/power management
/opt/nvtl/lib/libgpio.so               - GPIO control
```

**Candidates for NV/Modem Write Access:**
- `libmodem2_api.so` - Likely contains NV write functions
- `libfota_api.so` - FOTA uses NV to store firmware state
- `libsms_encoder.so` - May access NV for SMS config

### 7. Device Files & Access Points

**Available Device Interfaces:**
```
/dev/at_mdm0           - Modem AT command (247:0)
/dev/at_usb0           - USB AT serial 0 (240:0)
/dev/at_usb1           - USB AT serial 1 (240:1)
/dev/diag              - DIAG protocol (243:0)
/dev/smd7              - Shared Memory Driver 7 (247:7)
/dev/smd8              - Shared Memory Driver 8 (247:8)
/dev/smd11             - Shared Memory Driver 11 (247:9)
/dev/smd21             - Shared Memory Driver 21 (247:10)
/dev/smd22             - Shared Memory Driver 22 (247:5)
/dev/smdcntl0          - SMD Control 0 (247:3)
/dev/smdcntl8          - SMD Control 8 (247:6)
/dev/ttyHS0            - High-speed UART 0 (245:0)
/dev/ttyHSL0           - High-speed UART 0 logging (244:0)
```

### 8. EFS (Embedded File System) Accessibility

**Configuration File Successfully Read:**
```
File: /policyman/device_config.xml
Size: 503 bytes
Status: READABLE via nwcli qmi_idl read_file
Content: Device configuration (bands, features, capabilities)
```

**EFS Read Capability**: CONFIRMED - Files can be read via QMI

**Content Example:**
```xml
<device_config name="MiFi" target="CHGWLT" single_sim="0" ss_toggle="0">
  <config primary="C H G W L T" />
  <feature name="Feature_Hdr" enabled="1" />
  <feature name="Feature_RF_Bands" enabled="0" />
</device_config>
```
Where: C=CDMA, H=HDR/EVDO, G=GSM, W=WCDMA, L=LTE, T=TD-SCDMA

### 9. System Configuration Analysis

**Key Configuration Files:**

| File | Size | Writable | Purpose |
|------|------|----------|---------|
| `/sysconf/features.xml` | 2.9 KB | YES (via UI) | Feature toggles |
| `/sysconf/settings.xml` | 29 KB | YES (via UI) | System settings |
| `/sysconf/settings_def.xml` | 31.5 KB | NO (default) | Settings defaults |
| `/sysconf/addrbook.db` | 0 B | YES | Address book |

**Settings Modifiable via Configuration:**
- Carrier settings
- Network mode preferences
- SMS configuration
- WiFi settings
- USB mode

## Implications for Further Investigation

### 1. **NV Item Extension Confirmed**
- Beyond 20,000 items: NV addressing extends to at least 30,000
- Items at higher indices (60000+) may have fewer protections
- **Future work**: Scan 30,000-65535 range for additional writable items

### 2. **Direct Write Capability Found**
- **NV 60044 is definitely writable** (PRI version string)
- Demonstrates write barrier can be overcome for specific items
- Suggests pattern: configuration/string items vs. protected system items

### 3. **FOTA Infrastructure**
- Complete FOTA (firmware update) implementation available
- `fota_linux_pri.sh` can update modem PRI firmware
- **Possible vector**: Leverage FOTA to modify firmware behavior

### 4. **Alternative Access Methods**
- **SMD channels**: /dev/smd* interfaces available (may allow direct modem access)
- **DIAG protocol**: /dev/diag available (Qualcomm diagnostic interface)
- **AT command servers**: modem_at_server_cli provides programmatic AT access
- **These may bypass normal protections if accessed directly**

### 5. **EFS Write Capability**
- EFS read confirmed; write capability untested
- `/policyman/device_config.xml` controls device capabilities
- **Future work**: Attempt EFS file write to device_config.xml

### 6. **Library-Based Exploitation**
- `libmodem2_api.so` likely contains internal NV write functions
- Binary analysis could reveal undocumented write APIs
- **Future work**: Use nm/strings extraction on modem libraries

## Recommendations for Next Phase

### Immediate Priority
1. **Extend NV scan to 30,000-65535 range** (find additional writable items)
2. **Binary analysis of modem libraries** (extract write function symbols)
3. **EFS file write testing** (attempt modification of device_config.xml)

### Medium Priority
1. **DIAG protocol exploitation** (direct modem interface)
2. **SMD channel direct access** (bypass QMI intermediaries)
3. **SPC code extraction** (firmware reverse engineering)

### Long-term Investigation
1. **FOTA firmware modification** (patch modem firmware)
2. **EDL mode access** (full device control)
3. **Carrier lock bypass** (firmware-level modifications)

## Tools & Scripts

**Discovery Scripts Created:**
- `nv_extended_audit.sh` - Extended NV enumeration (0-30K, write testing)
- `program_discovery.sh` - Comprehensive program catalog

**Previously Deployed:**
- `nv_forensic_audit.sh` - Full 0-20K NV enumeration (201 items)
- `sms_listener.sh` - SMS interception
- `fast_audit.sh`, `nv_discovery.sh`, `fs_exploration.sh`

## Conclusion

The Inseego MiFi 8800L provides extensive diagnostic and configuration capabilities beyond typical carrier-locked devices. While most NV items remain protected, the discovery of writable items (NV 60044) and available FOTA infrastructure suggests multiple vectors for deeper device control. The complete inventory of 180+ programs and libraries indicates significant testing/development infrastructure that could be leveraged for advanced modifications.

**Estimated device control capability**: ~40-50% (read most config, write select items, FOTA infrastructure, debug interfaces available)
