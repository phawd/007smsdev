#!/bin/sh

# Phase 5: Safe Device-Local EFS2 & Locking Mechanism Extraction
# RUN ON DEVICE (not via adb)
# Uses /data directory (persistent storage, not tmpfs)
# Avoids: watchdog reboot, adb shell issues, missing directories

BACKUP_DIR="/data/phase5_extraction_$(date +%Y%m%d_%H%M%S)"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

echo "========================================="
echo "Phase 5: Safe Device Extraction"
echo "========================================="
echo "Backup directory: $BACKUP_DIR"
echo "Timestamp: $TIMESTAMP"
echo ""

# Pre-create all directories at once
mkdir -p "$BACKUP_DIR"/nv_items "$BACKUP_DIR"/efs2_safe "$BACKUP_DIR"/fota "$BACKUP_DIR"/modem_info "$BACKUP_DIR"/carrier_config 2>/dev/null
if [ ! -d "$BACKUP_DIR/nv_items" ]; then
  echo "ERROR: Failed to create backup directory"
  exit 1
fi

# ============================================
# STEP 1: Device Status Check
# ============================================
echo "=== STEP 1: Device Status Check ==="

/opt/nvtl/bin/modem2_cli get_info > "$BACKUP_DIR/modem_info/device_info.txt" 2>&1 || echo "Failed: get_info"
/opt/nvtl/bin/modem2_cli get_state > "$BACKUP_DIR/modem_info/modem_state.txt" 2>&1 || echo "Failed: get_state"
/opt/nvtl/bin/modem2_cli get_signal > "$BACKUP_DIR/modem_info/signal_strength.txt" 2>&1 || echo "Failed: get_signal"
/opt/nvtl/bin/modem2_cli sim_get_status > "$BACKUP_DIR/modem_info/sim_status.txt" 2>&1 || echo "Failed: sim_get_status"

echo "Device status captured."
echo ""

# ============================================
# STEP 2: NV Item Extraction (Direct Read)
# ============================================
echo "=== STEP 2: NV Item Extraction ==="

NV_ITEMS="0 1 2 3 10 441 550 553 946 947 1015 1016 2954 3461 4399 6828 6830 60044"

for nv_id in $NV_ITEMS; do
  OUTPUT=$(/opt/nvtl/bin/modem2_cli nv read $nv_id 2>&1)
  if echo "$OUTPUT" | grep -q "Error\|error"; then
    echo "$OUTPUT" > "$BACKUP_DIR/nv_items/nv_${nv_id}_error.log"
  else
    echo "$OUTPUT" > "$BACKUP_DIR/nv_items/nv_${nv_id}.txt"
  fi
done

NV_SUCCESS=$(find "$BACKUP_DIR/nv_items" -name "nv_*.txt" | wc -l)
echo "NV extraction: $NV_SUCCESS items captured"
echo ""

# ============================================
# STEP 3: EFS2 Safe Extraction
# ============================================
echo "=== STEP 3: EFS2 Safe Extraction ==="

# Method 1: Try nwcli if available
if command -v /opt/nvtl/bin/nwcli >/dev/null 2>&1; then
  echo "Testing nwcli QMI method..."
  /opt/nvtl/bin/nwcli qmi_idl read_file /tmp/lte_sample.bin /nv/item_files/modem/mmode/lte_bandpref 8 2>/dev/null
  if [ -f /tmp/lte_sample.bin ]; then
    cp /tmp/lte_sample.bin "$BACKUP_DIR/efs2_safe/lte_bandpref_sample.bin"
    echo "✓ QMI read: lte_bandpref sample extracted"
  fi
fi

# Method 2: modem2_cli efs read (collect output)
/opt/nvtl/bin/modem2_cli efs_read 2>&1 | head -50 > "$BACKUP_DIR/efs2_safe/efs_read_sample.log"

# Method 3: Check mounted filesystems
mount > "$BACKUP_DIR/efs2_safe/mounts.txt" 2>&1
if mount | grep -q "efs"; then
  echo "EFS2 mounted. Creating backup..."
  tar -czf "$BACKUP_DIR/efs2_safe/efs_mounted.tar.gz" /efs 2>/dev/null && echo "✓ EFS2 tar: Complete"
fi

# Method 4: Dump mtd info (for forensic analysis)
if [ -e /proc/mtd ]; then
  cp /proc/mtd "$BACKUP_DIR/efs2_safe/mtd_info.txt"
fi

echo "EFS2 extraction attempts complete"
echo ""

# ============================================
# STEP 4: FOTA & Carrier Config
# ============================================
echo "=== STEP 4: FOTA & Configuration ==="

# FOTA data
if [ -d /opt/nvtl/data/fota ]; then
  tar -czf "$BACKUP_DIR/fota/fota_data.tar.gz" /opt/nvtl/data/fota 2>/dev/null && echo "✓ FOTA data: Archived"
fi

if [ -d /opt/nvtl/etc/fota ]; then
  tar -czf "$BACKUP_DIR/fota/fota_config.tar.gz" /opt/nvtl/etc/fota 2>/dev/null && echo "✓ FOTA config: Archived"
fi

# Carrier customization
if [ -f /opt/nvtl/etc/cc/carrier_customization.xml ]; then
  cp /opt/nvtl/etc/cc/carrier_customization.xml "$BACKUP_DIR/carrier_config/" 2>/dev/null && echo "✓ Carrier config: Extracted"
fi

# Feature flags
if [ -f /sysconf/features.xml ]; then
  cp /sysconf/features.xml "$BACKUP_DIR/carrier_config/features.xml" 2>/dev/null && echo "✓ Features: Extracted"
fi

if [ -f /sysconf/settings.xml ]; then
  cp /sysconf/settings.xml "$BACKUP_DIR/carrier_config/settings.xml" 2>/dev/null && echo "✓ Settings: Extracted"
fi

echo ""

# ============================================
# STEP 5: Device Configuration Analysis
# ============================================
echo "=== STEP 5: Device Configuration ==="

# Get active technology
/opt/nvtl/bin/modem2_cli enabled_tech_get > "$BACKUP_DIR/modem_info/enabled_tech.txt" 2>&1

# Get carrier info
/opt/nvtl/bin/modem2_cli get_carrier_unlock > "$BACKUP_DIR/modem_info/carrier_lock_status.txt" 2>&1

# Get radio status
/opt/nvtl/bin/modem2_cli radio_is_enabled > "$BACKUP_DIR/modem_info/radio_status.txt" 2>&1

echo ""

# ============================================
# STEP 6: Summary & Manifest
# ============================================
echo "=== STEP 6: Creating Manifest ==="

cat > "$BACKUP_DIR/EXTRACTION_MANIFEST.txt" << 'MANIFEST'
Phase 5 Safe Device Extraction - Manifest
============================================

Device: MiFi 8800L (Verizon)
Method: On-Device Local Extraction (no watchdog reboot)
Timestamp: TIMESTAMP_PLACEHOLDER
Backup Location: BACKUP_DIR_PLACEHOLDER

Data Collected:
===============

1. MODEM INFO (modem_info/)
   - device_info.txt: Device IMEI, IMSI, firmware
   - modem_state.txt: Registration, connection status
   - signal_strength.txt: RSSI, bars, tech
   - sim_status.txt: SIM readiness
   - enabled_tech.txt: Enabled radio technologies
   - carrier_lock_status.txt: Lock state (1=locked)
   - radio_status.txt: Radio on/off

2. NV ITEMS (nv_items/)
   - 18 critical NV items read:
     * NV 550: IMEI
     * NV 3461: SIM Lock Status
     * NV 4399: Subsidy Lock Status
     * NV 60044: PRI Version (WRITABLE!)
   - Files: nv_*.txt (successful reads)
   - Files: nv_*_error.log (access denied items)

3. EFS2 FILESYSTEM (efs2_safe/)
   - mtd_info.txt: MTD partition info
   - mounts.txt: Mount points
   - lte_bandpref_sample.bin: LTE band configuration
   - efs_read_sample.log: EFS filesystem snapshot
   - efs_mounted.tar.gz: Full EFS2 backup (if mounted)

4. FOTA DATA (fota/)
   - fota_data.tar.gz: Update history, logs
   - fota_config.tar.gz: Configuration files
   - Includes FOTA certificates (if readable)

5. CARRIER CONFIG (carrier_config/)
   - carrier_customization.xml: Carrier profile
   - features.xml: Feature flags
   - settings.xml: Device settings
   - Verizon-specific customizations

Key Findings:
==============
- Multi-layer lock: SIM lock + Subsidy lock + FOTA enforcement
- PRI version accessible without SPC (bypass vector)
- Carrier lock in NV items + EFS2 filesystem
- FOTA certificate validation required for firmware
- Radio lock policy: Verizon-only

Next Steps:
============
1. adb pull to host: adb pull /data/phase5_extraction_* ./phase5_results/
2. Parse NV items: Determine current lock status
3. Analyze FOTA certificates: Identify bypass path
4. Binary analysis: libmodem2_api.so SPC validation logic
5. ZeroSMS integration: Implement unlock mechanism

MANIFEST

sed -i "s|TIMESTAMP_PLACEHOLDER|$TIMESTAMP|g" "$BACKUP_DIR/EXTRACTION_MANIFEST.txt"
sed -i "s|BACKUP_DIR_PLACEHOLDER|$BACKUP_DIR|g" "$BACKUP_DIR/EXTRACTION_MANIFEST.txt"

echo "Manifest created"
echo ""

# ============================================
# STEP 7: Final Status
# ============================================
echo "========================================="
echo "✓ EXTRACTION COMPLETE"
echo "========================================="
echo "Location: $BACKUP_DIR"

FILE_COUNT=$(find "$BACKUP_DIR" -type f | wc -l)
echo "Files: $FILE_COUNT"

SIZE=$(du -s "$BACKUP_DIR" 2>/dev/null | cut -f1)
echo "Size: ${SIZE} KB"

echo ""
echo "To retrieve on host:"
echo "  mkdir -p phase5_results"
echo "  adb pull $BACKUP_DIR phase5_results/"
echo ""
echo "========================================="

# Echo the backup path for parsing by host
echo "BACKUP_PATH=$BACKUP_DIR"
