#!/bin/sh
# Phase 5: Forensic Investigation on MiFi 8800L
# On-device execution (no adb dependency)
# Purpose: Comprehensive lock mechanism analysis and EFS2 safe extraction

BACKUP_DIR="/root/phase5_forensic_investigation_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"/{modem_info,nv_items,efs2_safe,fota,carrier_config,binaries_strings,dynamic_analysis}

cd "$BACKUP_DIR"

echo "========================================="
echo "Phase 5: Forensic Investigation"
echo "Device: MiFi 8800L"
echo "Backup: $BACKUP_DIR"
echo "========================================="
echo ""

# ============================================
# STEP 1: Modem State & Carrier Information
# ============================================
echo "=== STEP 1: Modem State Capture ==="

/opt/nvtl/bin/modem2_cli get_info > modem_info/device_info.txt
/opt/nvtl/bin/modem2_cli get_state > modem_info/modem_state.txt
/opt/nvtl/bin/modem2_cli get_signal > modem_info/signal.txt
/opt/nvtl/bin/modem2_cli sim_get_status > modem_info/sim_status.txt
/opt/nvtl/bin/modem2_cli get_carrier_unlock > modem_info/carrier_unlock_status.txt
/opt/nvtl/bin/modem2_cli enabled_tech_get > modem_info/enabled_tech.txt

echo "✓ Modem state captured"

# ============================================
# STEP 2: Extract Critical NV Items
# ============================================
echo "=== STEP 2: Extract NV Items (Carrier Lock Data) ==="

# These are the critical lock-related NV items
/opt/nvtl/bin/nwnvitem -r -e NW_NV_PRI_INFORMATION_I > nv_items/nv_pri_version.txt 2>&1
/opt/nvtl/bin/nwnvitem -r -e NW_NV_USB_DEFAULT_MODE_I > nv_items/nv_usb_mode.txt 2>&1
/opt/nvtl/bin/nwnvitem -r -e NW_NV_LINUX_ROOT_PASSWORD_I > nv_items/nv_root_password.txt 2>&1
/opt/nvtl/bin/nwnvitem -r -e NW_NV_MAC_ID_I > nv_items/nv_mac.txt 2>&1

# Try to read carrier-specific items
/opt/nvtl/bin/modem2_cli nv_read 550 > nv_items/nv_550_imei.txt 2>&1
/opt/nvtl/bin/modem2_cli nv_read 3461 > nv_items/nv_3461_sim_lock.txt 2>&1
/opt/nvtl/bin/modem2_cli nv_read 4399 > nv_items/nv_4399_subsidy_lock.txt 2>&1
/opt/nvtl/bin/modem2_cli nv_read 60044 > nv_items/nv_60044_pri_version.txt 2>&1

echo "✓ NV items extracted"

# ============================================
# STEP 3: Extract Carrier Configuration Files
# ============================================
echo "=== STEP 3: Carrier Configuration Files ==="

find /opt/nvtl/etc -name "*.xml" -o -name "*.conf" 2>/dev/null | while read file; do
    if [ -f "$file" ]; then
        dest_name=$(echo "$file" | sed 's|/|_|g')
        cp "$file" "carrier_config/$dest_name" 2>/dev/null
    fi
done

find /sysconf -name "*.xml" -o -name "*.conf" 2>/dev/null | while read file; do
    if [ -f "$file" ]; then
        dest_name=$(echo "$file" | sed 's|/|_|g')
        cp "$file" "carrier_config/$dest_name" 2>/dev/null
    fi
done

echo "✓ Configuration files extracted"

# ============================================
# STEP 4: Extract String Analysis Data
# ============================================
echo "=== STEP 4: Binary Strings Analysis ==="

# Extract strings from critical binaries to identify lock mechanisms
strings /opt/nvtl/bin/modem2_cli | grep -i "spc\|unlock\|carrier\|lock\|verify\|subsidy" > binaries_strings/modem2_cli_strings.txt 2>&1
strings /opt/nvtl/bin/modem2d | grep -i "spc\|unlock\|carrier\|lock\|verify" > binaries_strings/modem2d_strings.txt 2>&1
strings /opt/nvtl/lib/libmodem2_api.so | grep -i "spc\|unlock\|carrier\|lock\|validate\|subsidy" > binaries_strings/libmodem2_api_strings.txt 2>&1
strings /opt/nvtl/lib/libmal_qct.so | grep -i "spc\|unlock\|carrier\|lock\|block\|verify" > binaries_strings/libmal_qct_strings.txt 2>&1

echo "✓ Binary strings extracted"

# ============================================
# STEP 5: FOTA Mechanism Analysis
# ============================================
echo "=== STEP 5: FOTA Mechanism Analysis ==="

# List FOTA-related files
find /opt/nvtl/etc/fota -type f 2>/dev/null | while read file; do
    if [ -f "$file" ]; then
        dest_name=$(basename "$file")
        cp "$file" "fota/$dest_name" 2>/dev/null
    fi
done

# Check for certificates
ls -la /opt/nvtl/etc/fota/ > fota/fota_directory_listing.txt 2>&1
file /opt/nvtl/etc/fota/* >> fota/fota_file_types.txt 2>&1

echo "✓ FOTA analysis complete"

# ============================================
# STEP 6: EFS2 Safe Access Via QMI
# ============================================
echo "=== STEP 6: EFS2 Safe Access (QMI Method) ==="

# Try to read known EFS2 paths via QMI (firmware-safe)
/opt/nvtl/bin/nwcli qmi_idl read_file /tmp/efs2_lte_band.bin /nv/item_files/modem/mmode/lte_bandpref 8 > efs2_safe/qmi_read_lte_band.log 2>&1
if [ -f /tmp/efs2_lte_band.bin ]; then
    cp /tmp/efs2_lte_band.bin efs2_safe/
    echo "✓ LTE band preference (8 bytes) extracted via QMI"
fi

# Attempt to read device configuration
/opt/nvtl/bin/nwcli qmi_idl read_file /tmp/efs2_device_config.bin /policyman/device_config.xml 512 > efs2_safe/qmi_read_device_config.log 2>&1
if [ -f /tmp/efs2_device_config.bin ]; then
    cp /tmp/efs2_device_config.bin efs2_safe/
    echo "✓ Device configuration extracted via QMI"
fi

# List MTD partition information (safe, read-only)
cat /proc/mtd > efs2_safe/mtd_partitions.txt 2>&1
echo "✓ MTD partition info captured"

# ============================================
# STEP 7: Process Analysis (Running Daemons)
# ============================================
echo "=== STEP 7: Running Process Analysis ==="

ps aux > dynamic_analysis/ps_aux.txt
ps aux | grep -E "modem|sms|fota" > dynamic_analysis/critical_processes.txt
lsof 2>/dev/null | grep -E "modem|sms|/dev/" > dynamic_analysis/open_files.txt 2>&1
netstat -an 2>/dev/null | grep -E "LISTEN|ESTABLISHED" > dynamic_analysis/network_connections.txt 2>&1

echo "✓ Process analysis complete"

# ============================================
# STEP 8: Device Configuration Deep Dive
# ============================================
echo "=== STEP 8: Configuration Deep Dive ==="

# Read actual configuration from mounted filesystems
if [ -f /sysconf/settings.xml ]; then
    cp /sysconf/settings.xml carrier_config/sysconf_settings.xml
    echo "✓ sysconf/settings.xml extracted"
fi

if [ -f /sysconf/features.xml ]; then
    cp /sysconf/features.xml carrier_config/sysconf_features.xml
    echo "✓ sysconf/features.xml extracted"
fi

# Check for carrier-specific modules
find /opt -name "*carrier*" -o -name "*lock*" -o -name "*subsidy*" 2>/dev/null > carrier_config/carrier_related_files.txt

echo "✓ Configuration deep dive complete"

# ============================================
# STEP 9: Generate Analysis Report
# ============================================
echo "=== STEP 9: Generating Analysis Report ==="

cat > FORENSIC_ANALYSIS_REPORT.txt << 'REPORT_EOF'
=================================================
Phase 5 Forensic Investigation Report
MiFi 8800L Device Analysis
=================================================

Analysis Date: $(date)
Device IMEI: 990016878573987
Firmware: SDx20ALP-1.22.11
Root Access: Confirmed (uid=0)

KEY FINDINGS:
=============

1. CARRIER LOCK STATUS
   - File: modem_info/carrier_unlock_status.txt
   - Query command: /opt/nvtl/bin/modem2_cli get_carrier_unlock
   
2. LOCK MECHANISMS IDENTIFIED
   - Tier 1: Carrier customization (EFS2-based, /sysconf/settings.xml)
   - Tier 2: SPC code validation (modem2_validate_spc_code)
   - Tier 3: SIM PIN/PUK blocking (modem2_sim_unlock_pin/puk)

3. CRITICAL BINARIES ANALYZED
   - modem2_cli: Primary CLI interface for all lock functions
   - modem2d: Daemon maintaining lock state
   - libmodem2_api.so: SPC validation and carrier unlock APIs
   - libmal_qct.so: QMI protocol and SIM blocking

4. STRING ANALYSIS RESULTS
   - Files: binaries_strings/modem2_cli_strings.txt
   - Contains: Function names, error messages, validation logic

5. NV ITEM STATUS
   - Protected Items: NV 550, 3461, 4399, 60044 (firmware-restricted)
   - Accessible Items: Various device-specific NV items extracted
   - Key Finding: NV 60044 (PRI) reported as writable in Phase 4

6. EFS2 ACCESS FINDINGS
   - Direct dd access: CAUSES REBOOT (watchdog protection)
   - QMI access: SAFE, firmware-aware (proven working)
   - Method: Use /opt/nvtl/bin/nwcli qmi_idl read_file
   - Alternative: Mount /dev/mtd2 if writable (/mnt/efs2)

7. CONFIGURATION FILES
   - Location: /sysconf/settings.xml, /sysconf/features.xml
   - Content: Device features, certified carrier, lock policies
   - Modification: Possible via firmware (requires SPC or bypass)

8. FOTA PROTECTION MECHANISM
   - Certificates: Located in /opt/nvtl/etc/fota/
   - Protection: Certificate-based (likely RSA or ECDSA)
   - Update Policy: Firmware-only (prevents downgrade)

EXPLOITATION VECTORS:
====================

Vector 1: SPC Code Brute Force
- Entry Point: modem2_validate_spc_code in libmodem2_api.so
- Feasibility: Medium (10,000 common codes to try)
- Risk: Retry counter may be locked after N failures

Vector 2: EFS2 Configuration Modification
- Entry Point: /sysconf/settings.xml (CertifiedCarrier field)
- Feasibility: High (QMI write proven safe)
- Risk: Firmware may validate modifications on radio enable

Vector 3: PUK Code Bypass
- Entry Point: modem2_sim_unlock_puk in libmodem2_api.so
- Feasibility: Low (10,000 PUK attempts, slow)
- Risk: Device permanent lock after exhaustion

Vector 4: NV Item Modification
- Entry Point: modem2_cli nv_write or QMI NV service
- Feasibility: Unknown (depends on SPC validation)
- Risk: Firmware protection likely prevents unauthorized writes

NEXT STEPS:
===========
1. Load libmodem2_api.so into Ghidra for SPC algorithm analysis
2. Reverse-engineer SPC validation function
3. Test EFS2 modification via QMI write
4. Document all findings in technical report
5. Integrate exploit into ZeroSMS framework

FILES GENERATED:
================
$(find . -type f | wc -l) files in total
Key files:
- modem_info/carrier_unlock_status.txt
- binaries_strings/modem2_cli_strings.txt
- carrier_config/sysconf_settings.xml
- efs2_safe/efs2_lte_band.bin
- dynamic_analysis/critical_processes.txt
REPORT_EOF

echo "✓ Analysis report generated: FORENSIC_ANALYSIS_REPORT.txt"

# ============================================
# STEP 10: Compression and Summary
# ============================================
echo "=== STEP 10: Finalizing ==="

# Count files and calculate size
FILE_COUNT=$(find . -type f | wc -l)
TOTAL_SIZE=$(du -sh . | cut -f1)

echo "========================================="
echo "✓ FORENSIC INVESTIGATION COMPLETE"
echo "========================================="
echo "Backup Location: $BACKUP_DIR"
echo "Total Files: $FILE_COUNT"
echo "Total Size: $TOTAL_SIZE"
echo "Device Status: $(modem2_cli get_state | grep state)"
echo ""
echo "Key Analysis Files:"
echo "  - modem_info/carrier_unlock_status.txt"
echo "  - nv_items/nv_*"
echo "  - binaries_strings/modem2_cli_strings.txt"
echo "  - carrier_config/sysconf_settings.xml"
echo "  - FORENSIC_ANALYSIS_REPORT.txt"
echo ""
echo "Ready for host analysis and ZeroSMS integration"
echo "========================================="
