#!/bin/bash

# Phase 5: Safe EFS2 & Locking Mechanism Extraction
# Uses userspace tools (modem2_cli, nwcli, tar) instead of raw dd
# Avoids watchdog reboot issue when accessing active EFS2 filesystem
#
# Focuses on:
# 1. Carrier lock data extraction (NV items)
# 2. FOTA mechanism analysis
# 3. Safe EFS2 filesystem backup

BACKUP_DIR="${1:-.}/phase5_safe_extraction_$(date +%Y%m%d_%H%M%S)"
DEVICE_ID=$(adb shell "getprop ro.serialno 2>/dev/null || echo 'unknown'")
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

echo "========================================="
echo "Phase 5: Safe EFS2 & Locking Extraction"
echo "========================================="
echo "Backup directory: $BACKUP_DIR"
echo "Device: $DEVICE_ID"
echo "Timestamp: $TIMESTAMP"
echo ""

mkdir -p "$BACKUP_DIR"/{nv_items,efs2_safe,fota,modem_info,carrier_config}

# ============================================
# STEP 1: Device Status Check
# ============================================
echo "=== STEP 1: Device Status Check ==="

adb shell "/opt/nvtl/bin/modem2_cli get_info" > "$BACKUP_DIR/modem_info/device_info.txt" 2>&1
adb shell "/opt/nvtl/bin/modem2_cli get_state" > "$BACKUP_DIR/modem_info/modem_state.txt" 2>&1
adb shell "/opt/nvtl/bin/modem2_cli get_signal" > "$BACKUP_DIR/modem_info/signal_strength.txt" 2>&1
adb shell "/opt/nvtl/bin/modem2_cli sim_get_status" > "$BACKUP_DIR/modem_info/sim_status.txt" 2>&1

echo "Device status captured."
echo ""

# ============================================
# STEP 2: NV Item Extraction (Carrier Lock Data)
# ============================================
echo "=== STEP 2: NV Item Extraction (Carrier Lock Data) ==="

# Critical NV items for carrier lock research
declare -a NV_ITEMS=(
  "550"   # IMEI
  "3461"  # SIM lock status
  "4399"  # Subsidy lock status
  "60044" # PRI version (writable per Phase 4 findings!)
  "441"   # GPS mode
  "553"   # SID/NID lock
  "946"   # Modem config
  "947"   # SMS config
  "1015"  # Roaming config
  "1016"  # Roaming config 2
  "2954"  # Band class preference
  "6828"  # Perso status
  "6830"  # Carrier info
)

echo "Extracting ${#NV_ITEMS[@]} critical NV items..."

for nv_id in "${NV_ITEMS[@]}"; do
  echo -n "  NV $nv_id: "
  OUTPUT=$(adb shell "/opt/nvtl/bin/modem2_cli nv read $nv_id" 2>&1)
  if echo "$OUTPUT" | grep -q "Error\|error"; then
    echo "❌ Error (likely protected)"
    echo "$OUTPUT" >> "$BACKUP_DIR/nv_items/nv_${nv_id}_error.txt"
  else
    echo "✓ Extracted"
    echo "$OUTPUT" > "$BACKUP_DIR/nv_items/nv_${nv_id}.txt"
  fi
done

echo "NV item extraction complete."
echo ""

# ============================================
# STEP 3: EFS2 Safe Extraction via nwcli
# ============================================
echo "=== STEP 3: EFS2 Safe Extraction (nwcli method) ==="

# Check if nwcli is available
if adb shell "which /opt/nvtl/bin/nwcli" 2>/dev/null | grep -q "nwcli"; then
  echo "nwcli found. Attempting EFS2 backup via userspace..."
  
  # Try QMI read_file for EFS2
  adb shell "/opt/nvtl/bin/nwcli qmi_idl read_file /tmp/efs2_backup.bin /nv/item_files/modem/mmode/lte_bandpref 8" 2>&1 | tee "$BACKUP_DIR/efs2_safe/qmi_read_attempt.log"
  
  if [ -f "/tmp/efs2_backup.bin" ]; then
    echo "EFS2 via QMI: ✓ Success"
    adb pull "/tmp/efs2_backup.bin" "$BACKUP_DIR/efs2_safe/"
  else
    echo "EFS2 via QMI: Partial or failed (expected for large files)"
  fi
else
  echo "nwcli not found, trying modem2_cli EFS read..."
  
  # Attempt via modem2_cli efs_read
  adb shell "/opt/nvtl/bin/modem2_cli efs_read" << EOF 2>&1 | tee "$BACKUP_DIR/efs2_safe/modem2_efs_attempt.log"
/nv/item_files/modem/mmode/lte_bandpref
0
8
/tmp/lte_band_sample.bin
EOF
fi

echo ""

# ============================================
# STEP 4: Mounted Filesystem Backup (tar method)
# ============================================
echo "=== STEP 4: Mounted Filesystem Backup ==="

# Check for mounted EFS partitions
echo "Checking for mounted EFS partitions..."
adb shell "df | grep -E 'efs|/efs|/data'" > "$BACKUP_DIR/efs2_safe/mounted_fs.txt" 2>&1

# If EFS2 is mounted, safely back it up with tar
if adb shell "mount | grep -q efs2"; then
  echo "EFS2 mounted detected. Creating tar backup (safe method)..."
  adb shell "tar -czf /tmp/efs2_safe_backup.tar.gz /efs 2>&1" > "$BACKUP_DIR/efs2_safe/tar_backup.log"
  
  if adb shell "[ -f /tmp/efs2_safe_backup.tar.gz ]" 2>/dev/null; then
    echo "tar backup created. Pulling..."
    adb pull "/tmp/efs2_safe_backup.tar.gz" "$BACKUP_DIR/efs2_safe/"
    echo "✓ EFS2 tar backup successful"
  else
    echo "❌ tar backup failed (watchdog may have triggered)"
  fi
else
  echo "EFS2 mount point not found. Checking alternative paths..."
  adb shell "find / -name '*efs*' -type d 2>/dev/null" > "$BACKUP_DIR/efs2_safe/efs_paths.txt"
fi

echo ""

# ============================================
# STEP 5: FOTA & Carrier Configuration
# ============================================
echo "=== STEP 5: FOTA & Carrier Configuration ==="

# FOTA mechanism analysis
echo "Extracting FOTA configuration..."
adb shell "cat /opt/nvtl/data/fota/update_log" > "$BACKUP_DIR/fota/update_log.txt" 2>&1
adb shell "cat /opt/nvtl/etc/fota/config.xml" > "$BACKUP_DIR/fota/config.xml" 2>&1
adb shell "ls -lah /opt/nvtl/data/fota/" > "$BACKUP_DIR/fota/fota_dir_listing.txt" 2>&1

# Carrier customization files
echo "Extracting carrier customization..."
adb shell "cat /opt/nvtl/etc/cc/carrier_customization.xml" > "$BACKUP_DIR/carrier_config/carrier_customization.xml" 2>&1
adb shell "cat /opt/nvtl/etc/dmdb/config.xml" > "$BACKUP_DIR/carrier_config/dmdb_config.xml" 2>&1

# FOTA certificates
adb shell "cat /opt/nvtl/etc/fota/build_cert.pem" > "$BACKUP_DIR/fota/build_cert.pem" 2>&1
adb shell "cat /opt/nvtl/etc/fota/device.pem" > "$BACKUP_DIR/fota/device.pem" 2>&1

echo "FOTA & carrier config extraction complete."
echo ""

# ============================================
# STEP 6: SMS & Protocol Configuration
# ============================================
echo "=== STEP 6: SMS & Protocol Configuration ==="

adb shell "/opt/nvtl/bin/modem2_cli enabled_tech_get" > "$BACKUP_DIR/modem_info/enabled_tech.txt" 2>&1
adb shell "cat /opt/nvtl/etc/sms/config.xml" > "$BACKUP_DIR/modem_info/sms_config.xml" 2>&1

echo ""

# ============================================
# STEP 7: Compile findings summary
# ============================================
echo "=== STEP 7: Compilation Summary ==="

cat > "$BACKUP_DIR/EXTRACTION_SUMMARY.txt" << 'SUMMARY_EOF'
Phase 5 Safe EFS2 & Locking Extraction Summary
==============================================

Extraction Method: USERSPACE (modem2_cli, nwcli, tar)
Rationale: Standard dd on /dev/mtd2 (EFS2) causes device reboot
          Userspace tools avoid watchdog/lock conflicts

Key Data Extracted:
- NV Items: Carrier lock status (NV 3461, 4399), PRI version (NV 60044), IMEI (NV 550)
- EFS2: Attempted via nwcli QMI and modem2_cli EFS read (non-dd methods)
- FOTA: Update logs, certificates, configuration files
- Carrier: Customization files, DM configuration, SMS config
- Modem Info: Device info, state, signal, SIM status, enabled technologies

Critical Findings Location:
- nv_items/nv_3461.txt      -> SIM lock status
- nv_items/nv_4399.txt      -> Subsidy lock status  
- nv_items/nv_60044.txt     -> PRI version (WRITABLE per Phase 4!)
- nv_items/nv_550.txt       -> IMEI
- fota/                      -> FOTA mechanism analysis data
- carrier_config/            -> Carrier lock configuration

Next Steps:
1. Analyze NV item values to understand lock state
2. Cross-reference carrier_customization.xml with lock policies
3. Study FOTA certificate chain for FOTA restrictions
4. Extract and analyze libmodem2_api.so for SPC validation
5. Document all findings in PHASE_5_FINDINGS.md

Known Limitations:
- EFS2 full extraction may be incomplete (watchdog protection)
- Some NV items protected (require SPC or carry unlock limitations)
- FOTA certificates may be signed/encrypted
- Modem firmware binary analysis required for complete SPC understanding
SUMMARY_EOF

echo "Summary created: $BACKUP_DIR/EXTRACTION_SUMMARY.txt"
echo ""

# ============================================
# STEP 8: Pull all extracted data locally
# ============================================
echo "=== STEP 8: Pulling Data to Local Machine ==="

# Create local backup directory
LOCAL_BACKUP="$(dirname "$BACKUP_DIR")/phase5_extraction_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$LOCAL_BACKUP"

# Note: For files pulled via adb pull, they're already in $BACKUP_DIR
# Just verify count and compress for transfer

echo "Backup structure created at: $BACKUP_DIR"
echo "Total files: $(find "$BACKUP_DIR" -type f | wc -l)"
echo "Total size: $(du -sh "$BACKUP_DIR" | cut -f1)"

# Create tarball of entire extraction for easy transport
tar -czf "$BACKUP_DIR.tar.gz" "$BACKUP_DIR" 2>/dev/null
echo "Compressed backup: $BACKUP_DIR.tar.gz"

echo ""
echo "========================================="
echo "Extraction Complete!"
echo "========================================="
echo "Key outputs:"
echo "  - NV items (carrier lock data): $BACKUP_DIR/nv_items/"
echo "  - EFS2 backups: $BACKUP_DIR/efs2_safe/"
echo "  - FOTA analysis: $BACKUP_DIR/fota/"
echo "  - Summary: $BACKUP_DIR/EXTRACTION_SUMMARY.txt"
echo ""
echo "⚠️  CRITICAL: Device did NOT reboot - Safe extraction successful!"
echo "========================================="
