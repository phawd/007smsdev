# SMS Test Extended Discovery Documentation Index

**Last Updated**: December 4, 2025  
**Project**: SMS Test - Android SMS/MMS/RCS Testing Suite with Extended Device Research  
**Status**: Session 3 Complete - Writable NV Item Confirmed

## Quick Navigation

### 📋 Session Summaries (Start Here)

- **[SESSION_3_DISCOVERY_SUMMARY.md](SESSION_3_DISCOVERY_SUMMARY.md)** - Latest breakthrough findings (WRITABLE NV 60044 confirmed)
- **[SESSION_2_FINDINGS.md](SESSION_2_FINDINGS.md)** - Previous forensic audit results  
- **[SESSION_FORENSIC_SUMMARY.md](SESSION_FORENSIC_SUMMARY.md)** - Full forensic investigation overview

### 📊 Technical Documentation

#### NV Item Research

- **[NV_DISCOVERY_REFERENCE.md](NV_DISCOVERY_REFERENCE.md)** - Master reference (201+ readable items, extended findings)
- **[EXTENDED_NV_DISCOVERY.md](EXTENDED_NV_DISCOVERY.md)** - Extended range testing (0-30K scan results)
- **[NV_WRITE_CAPABILITY_ANALYSIS.md](NV_WRITE_CAPABILITY_ANALYSIS.md)** - Write capability details & security analysis

#### Device Guides  

- **[MIFI_DEVICE_GUIDE.md](MIFI_DEVICE_GUIDE.md)** - Complete MiFi operation guide (CLI tools, modem control)
- **[ANDROID_DEVICE_GUIDE.md](ANDROID_DEVICE_GUIDE.md)** - Android device setup and AT commands
- **[MIFI_8800L_DEVICE_REFERENCE.md](MIFI_8800L_DEVICE_REFERENCE.md)** - Comprehensive hardware catalog

#### Protocol & Compliance

- **[RFC_COMPLIANCE.md](RFC_COMPLIANCE.md)** - SMS protocol implementation details
- **[ROOT_ACCESS_GUIDE.md](ROOT_ACCESS_GUIDE.md)** - Root access and AT command reference  
- **[TESTING_GUIDE.md](TESTING_GUIDE.md)** - User testing workflows

#### Research & Development

- **[MEDIATEK_FLASH_SMS_RESEARCH.md](MEDIATEK_FLASH_SMS_RESEARCH.md)** - MediaTek device quirks
- **[ADVANCED_FEATURES.md](ADVANCED_FEATURES.md)** - Extended SMS features research
- **[DELIVERABLES.md](../DELIVERABLES.md)** - Project completion summary

### 🛠️ Tools & Scripts

**In `/tools/` Directory:**

#### Primary Discovery Tools

- `smstest_cli.py` - Main Python CLI tool (probe, sms send, diag control)
- `nv_extended_audit.sh` - Extended NV enumeration (0-30K range)
- `program_discovery.sh` - Comprehensive program discovery
- `nv_forensic_audit.sh` - Full forensic NV audit (201 items)
- `sms_listener.sh` - SMS interception listener

#### Specialized Tools

- `auto_flash_sms.sh` - Automated Flash SMS testing
- `auto_type0_sms.sh` - Automated Silent SMS (Type 0) testing  
- `nv_discovery.sh` - NV item discovery script
- `fs_exploration.sh` - Filesystem exploration utility
- `fast_audit.sh` - Rapid audit runner

### 🔑 Key Findings Summary

#### Writable NV Items (TIER 3)

| Item | Type | Original Value | Status | Significance |
|------|------|----------------|--------|--------------|
| **60044** | String | PRI.90029477... | ✅ **WRITABLE** | Firmware version identifier |
| *Additional items* | Various | *To be found* | *Under investigation* | Extended 60000-65535 range |

#### Device Programs (180+ Total)

- **Modem**: modem2_cli, modem_at_server_cli, diag_read (8 programs)
- **SMS**: sms_cli, sms.sh, smsd (3 programs)  
- **NV Access**: nwcli, nwnvitem (2 programs)
- **FOTA**: fota_cli, fota_linux_pri.sh, fotad (8 programs) ⚠️ **CRITICAL**
- **System**: settings_cli, factory_reset_cli, bckrst_cli (20+ programs)
- **Network**: router2_cli, wifi_cli, vpn_cli (8 programs)
- **Other**: USB, GPS, Debug, UI, Services (50+ programs)

#### Access Methods

- **NV Items**: QMI via `/opt/nvtl/bin/nwcli`
- **EFS Files**: QMI read_file capability confirmed
- **SMD Channels**: 7 direct modem interfaces (`/dev/smd*`)
- **DIAG Protocol**: `/dev/diag` interface available
- **AT Commands**: `/dev/at_mdm0`, `/dev/at_usb0`, `/dev/at_usb1`
- **UART**: `/dev/ttyHS0`, `/dev/ttyHSL0` for serial access

### 📈 Device Security Evolution

| Aspect | Previous | Current | Change |
|--------|----------|---------|--------|
| **NV Readability** | 201 items (0-20K) | 300+ items (0-30K+) | +50% |
| **Writable Items** | 0 (assumed locked) | 1+ confirmed (TIER 3) | **BREAKTHROUGH** |
| **Control Capability** | ~40% | ~45-55% | +5-15% |
| **Security Rating** | HIGH | **MODERATE** | Downgrade |

### 🎯 Investigation Roadmap

#### Phase 1 (Completed) ✓

- [x] Initial 0-20K NV discovery (201 items)
- [x] Filesystem exploration (2000+ lines audit)
- [x] Tool enumeration (160+ programs)
- [x] Session documentation

#### Phase 2 (Completed) ✓  

- [x] Comprehensive forensic audit
- [x] Write capability investigation started
- [x] Protocol research
- [x] Complete documentation suite

#### Phase 3 (Completed) ✓

- [x] Extended NV range (0-30K scan)
- [x] Writable item discovery (NV 60044 confirmed)
- [x] Program inventory (180+ catalogued)
- [x] FOTA infrastructure identification

#### Phase 4 (Planned) ⏳

- [ ] Extended high-number scan (60000-65535)
- [ ] Binary library analysis (extract write functions)
- [ ] EFS file write testing
- [ ] Additional TIER 3 item discovery

#### Phase 5 (Planned) ⏳

- [ ] FOTA firmware modification research
- [ ] DIAG protocol reverse engineering
- [ ] SMD channel protocol development
- [ ] SPC code extraction investigation

### 🚀 For AI Agents & Researchers

**Getting Started:**

1. Start with `SESSION_3_DISCOVERY_SUMMARY.md` for current state
2. Read `EXTENDED_NV_DISCOVERY.md` for technical details  
3. Review `NV_WRITE_CAPABILITY_ANALYSIS.md` for attack surface
4. Check `MIFI_DEVICE_GUIDE.md` for operational procedures

**Recommended Investigation Order:**

1. Extended NV scan (60000-65535) - likely to find more writable items
2. Binary library analysis (libmodem2_api.so) - extract undocumented APIs
3. EFS file write capability - test device_config.xml modification
4. FOTA firmware chain - trace update process

**Critical References:**

- NV Item write format: `nwcli qmi_idl write_nv <ID> <INDEX> <VALUE>`
- Read format: `nwcli qmi_idl read_nv <ID> <INDEX>`
- EFS read: `nwcli qmi_idl read_file /tmp/out.bin <EFS_PATH> <SIZE>`
- Status codes: 0=success, 8193=access denied, other=error

**Safety Practices:**

1. Always read original value before write
2. Document all modifications
3. Test on non-critical items first (NV 60044 is string, safe for testing)
4. Restore original values after testing
5. Use 30+ second timeouts for device operations

### 📞 Device Information

**Current Test Device:**

- Model: Inseego MiFi 8800L
- Chipset: Qualcomm SDX20 Alpine LE10
- Firmware: SDx20ALP-1.22.11
- PRI: PRI.90029477 REV 151 Alpine VERIZON
- Root: Yes (uid=0 default)
- LTE: Connected (AT&T 310410)
- Status: Fully operational

### 📝 Document Statistics

- **Total Documentation**: 15+ markdown files
- **Total Lines**: 5000+ lines of technical documentation
- **Code/Scripts**: 7+ shell/python scripts deployed
- **Commits**: 3+ containing findings and code
- **Discovery Sessions**: 3 completed, multiple phases

### ✅ Session 3 Deliverables

**Code:**

- ✅ nv_extended_audit.sh (extended NV enumeration)
- ✅ program_discovery.sh (program inventory)
- ✅ Updated documentation suite

**Documentation:**

- ✅ SESSION_3_DISCOVERY_SUMMARY.md (executive summary)
- ✅ EXTENDED_NV_DISCOVERY.md (technical report)
- ✅ NV_WRITE_CAPABILITY_ANALYSIS.md (security analysis)
- ✅ Updated NV_DISCOVERY_REFERENCE.md

**Findings:**

- ✅ NV 60044 write capability confirmed
- ✅ 180+ programs catalogued and categorized
- ✅ Extended NV range (0-30K) tested
- ✅ 4+ alternative access methods identified
- ✅ FOTA infrastructure documented

---

## Quick Reference Commands

**Device Discovery:**

```bash
adb devices                                  # List connected devices
adb shell "/opt/nvtl/bin/modem2_cli get_info"  # Device info
```

**NV Item Operations:**

```bash
/opt/nvtl/bin/nwcli qmi_idl read_nv 60044 0    # Read NV 60044
/opt/nvtl/bin/nwcli qmi_idl write_nv 60044 0 "VALUE"  # Write NV 60044
```

**Program Discovery:**

```bash
ls /opt/nvtl/bin/ | grep -E 'modem|nv|fota|usb'  # Find modem tools
find /opt /bin /usr/bin -type f -name '*fota*'   # Find FOTA tools
```

**SMS Operations:**

```bash
/opt/nvtl/bin/sms_cli send                  # Send SMS
/opt/nvtl/bin/sms_cli get_list              # List messages
```

**Script Execution:**

```bash
sh /tmp/nv_extended_audit.sh                # Run NV audit
sh /tmp/program_discovery.sh                # Run program discovery
```

---

**Last Updated**: December 4, 2025  
**Next Review**: After Session 4 investigation phase  
**Archive Status**: All findings committed to git with full history  
**Recommended Action**: Begin Phase 4 extended NV scanning (60000-65535 range)
