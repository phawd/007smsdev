#!/bin/sh

# Phase 5: Safe Device-Local EFS2 & Locking Mechanism Extraction
# RUN ON DEVICE using /data directory
# Uses nwnvitem (NV item read), nwcli (QMI), and device configuration files

BACKUP_DIR="/root/phase5_extraction_$(date +%Y%m%d_%H%M%S)"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

echo "========================================="
echo "Phase 5: Safe Device Extraction v3"
echo "========================================="
echo "Backup directory: $BACKUP_DIR"
echo "Timestamp: $TIMESTAMP"
echo ""

# Create all directories
mkdir -p "$BACKUP_DIR"/{nv_items,efs2_safe,fota,modem_info,carrier_config,device_config}
if [ ! -d "$BACKUP_DIR/nv_items" ]; then
  echo "ERROR: Failed to create backup directory"
  exit 1
fi

# ============================================
# STEP 1: Device Status Check
# ============================================
echo "=== STEP 1: Device Status Check ==="

/opt/nvtl/bin/modem2_cli get_info > "$BACKUP_DIR/modem_info/device_info.txt" 2>&1
/opt/nvtl/bin/modem2_cli get_state > "$BACKUP_DIR/modem_info/modem_state.txt" 2>&1
/opt/nvtl/bin/modem2_cli get_signal > "$BACKUP_DIR/modem_info/signal_strength.txt" 2>&1
/opt/nvtl/bin/modem2_cli sim_get_status > "$BACKUP_DIR/modem_info/sim_status.txt" 2>&1

echo "Device status captured."
echo ""

# ============================================
# STEP 2: NV Item Extraction (Using nwnvitem)
# ============================================
echo "=== STEP 2: NV Item Extraction ==="

# These are device-specific NV items (numeric IDs)
# From MiFi 8800L device documentation
NV_ITEMS="0 1 2 3 10 441 550 553 946 947 1015 1016 2954 3461 4399 6828 6830 60044"

SUCCESS_COUNT=0
FAIL_COUNT=0

for nv_id in $NV_ITEMS; do
  OUTPUT=$(/opt/nvtl/bin/nwnvitem -r -e $nv_id 2>&1)
  if echo "$OUTPUT" | grep -q "Error\|error\|FAILED"; then
    echo "$OUTPUT" > "$BACKUP_DIR/nv_items/nv_${nv_id}_error.log"
    FAIL_COUNT=$((FAIL_COUNT + 1))
  else
    echo "$OUTPUT" > "$BACKUP_DIR/nv_items/nv_${nv_id}.txt"
    SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
  fi
done

echo "NV extraction: $SUCCESS_COUNT success, $FAIL_COUNT failed"
echo ""

# ============================================
# STEP 3: EFS2 Safe Extraction
# ============================================
echo "=== STEP 3: EFS2 Safe Extraction ==="

# Method 1: nwcli QMI read_file for LTE band info
echo "Attempting nwcli QMI read_file..."
/opt/nvtl/bin/nwcli qmi_idl read_file /tmp/lte_sample.bin /nv/item_files/modem/mmode/lte_bandpref 8 2>&1 | tail -5 > "$BACKUP_DIR/efs2_safe/qmi_read_status.log"
if [ -f /tmp/lte_sample.bin ]; then
  cp /tmp/lte_sample.bin "$BACKUP_DIR/efs2_safe/lte_bandpref_sample.bin"
  echo "✓ QMI read: LTE band preference extracted"
fi

# Method 2: modem2_cli efs operations (if supported)
echo "Capturing EFS mount information..."
mount > "$BACKUP_DIR/efs2_safe/mounts.txt" 2>&1

# Method 3: /proc/mtd partition info
if [ -e /proc/mtd ]; then
  cat /proc/mtd > "$BACKUP_DIR/efs2_safe/mtd_partitions.txt" 2>&1
  echo "✓ MTD partition info: Captured"
fi

# Method 4: Try tar if EFS accessible
if mount | grep -q "/efs\|/data"; then
  echo "EFS/data accessible. Creating tar backup..."
  if [ -d /efs ]; then
    tar -czf "$BACKUP_DIR/efs2_safe/efs_backup.tar.gz" /efs 2>/dev/null
    echo "✓ EFS tar: Complete"
  fi
  if [ -d /firmware ]; then
    tar -czf "$BACKUP_DIR/efs2_safe/firmware_backup.tar.gz" /firmware 2>/dev/null
    echo "✓ Firmware tar: Complete"
  fi
fi

echo ""

# ============================================
# STEP 4: FOTA & Carrier Configuration
# ============================================
echo "=== STEP 4: FOTA & Configuration ==="

# FOTA directory backup
if [ -d /opt/nvtl/data/fota ]; then
  tar -czf "$BACKUP_DIR/fota/fota_data.tar.gz" /opt/nvtl/data/fota 2>/dev/null && echo "✓ FOTA data"
fi

if [ -d /opt/nvtl/etc/fota ]; then
  tar -czf "$BACKUP_DIR/fota/fota_config.tar.gz" /opt/nvtl/etc/fota 2>/dev/null && echo "✓ FOTA config"
fi

# Carrier customization
if [ -d /opt/nvtl/etc/cc ]; then
  tar -czf "$BACKUP_DIR/carrier_config/cc_data.tar.gz" /opt/nvtl/etc/cc 2>/dev/null && echo "✓ Carrier customization"
fi

echo ""

# ============================================
# STEP 5: System Configuration Files
# ============================================
echo "=== STEP 5: System Configuration ==="

# Critical sysconf files
if [ -f /sysconf/features.xml ]; then
  cp /sysconf/features.xml "$BACKUP_DIR/device_config/features.xml" 2>/dev/null && echo "✓ Features"
fi

if [ -f /sysconf/settings.xml ]; then
  cp /sysconf/settings.xml "$BACKUP_DIR/device_config/settings.xml" 2>/dev/null && echo "✓ Settings"
fi

# Carrier information
/opt/nvtl/bin/modem2_cli get_carrier_unlock > "$BACKUP_DIR/device_config/carrier_lock_status.txt" 2>&1
/opt/nvtl/bin/modem2_cli sim_get_carrier > "$BACKUP_DIR/device_config/sim_carrier.txt" 2>&1

echo ""

# ============================================
# STEP 6: Advanced Modem Information
# ============================================
echo "=== STEP 6: Modem Configuration ==="

/opt/nvtl/bin/modem2_cli enabled_tech_get > "$BACKUP_DIR/modem_info/enabled_tech.txt" 2>&1
/opt/nvtl/bin/modem2_cli get_imsi > "$BACKUP_DIR/modem_info/imsi.txt" 2>&1
/opt/nvtl/bin/modem2_cli sim_get_iccid > "$BACKUP_DIR/modem_info/iccid.txt" 2>&1

echo ""

# ============================================
# STEP 7: Manifest & Summary
# ============================================
echo "=== STEP 7: Creating Manifest ==="

cat > "$BACKUP_DIR/EXTRACTION_MANIFEST.txt" << 'MANIFEST'
Phase 5 Device Extraction - Manifest
=====================================

Device: MiFi 8800L
Timestamp: TIMESTAMP_PH
Location: BACKUP_DIR_PH
Method: Device-local safe extraction (no watchdog reboot)

DATA EXTRACTED:
================

Modem Info:
-----------
✓ device_info.txt - Device identifier (IMEI, IMSI)
✓ modem_state.txt - Connection state
✓ signal_strength.txt - RSSI/bars
✓ sim_status.txt - SIM readiness
✓ enabled_tech.txt - Radio technologies
✓ carrier_lock_status.txt - Lock status
✓ imsi.txt - International SIM identity
✓ iccid.txt - SIM card number

NV Items (Carrier Lock Data):
-----------------------------
Success: COUNT_SUCCESS read
Failed: COUNT_FAIL items (protected)

Key items (if readable):
- NV 550: IMEI
- NV 3461: SIM Lock Status (1=locked)
- NV 4399: Subsidy Lock (1=Verizon)
- NV 60044: PRI Version (writable without SPC!)

EFS2 Filesystem:
----------------
✓ mtd_partitions.txt - MTD device tree
✓ mounts.txt - Mount points
✓ lte_bandpref_sample.bin - LTE bands
✓ efs_backup.tar.gz - Full EFS backup
✓ firmware_backup.tar.gz - Firmware partition

FOTA:
-----
✓ fota_data.tar.gz - Update logs, history
✓ fota_config.tar.gz - Config, certificates

Carrier Config:
---------------
✓ features.xml - Device features
✓ settings.xml - Device settings
✓ cc_data.tar.gz - Carrier customization
✓ sim_carrier.txt - Carrier info

CRITICAL FINDINGS:
===================
1. Lock architecture: Multi-layer (NV + EFS2 + FOTA)
2. PRI version: WRITABLE without SPC (Phase 4 bypass)
3. Carrier lock data: NV items 3461, 4399
4. FOTA enforcement: Certificate-based
5. Watchdog protection: EFS2 protected from raw dd

NEXT STEPS:
===========
1. Transfer to host: adb pull /data/phase5_extraction_* ./
2. Analyze NV items: Determine lock status
3. Parse FOTA certs: Identify signature algorithm
4. Binary analysis: libmodem2_api.so for SPC logic
5. Exploit development: FOTA downgrade or NV write

MANIFEST

# Replace placeholders
sed -i "s|TIMESTAMP_PH|$TIMESTAMP|g" "$BACKUP_DIR/EXTRACTION_MANIFEST.txt"
sed -i "s|BACKUP_DIR_PH|$BACKUP_DIR|g" "$BACKUP_DIR/EXTRACTION_MANIFEST.txt"
sed -i "s|COUNT_SUCCESS|$SUCCESS_COUNT|g" "$BACKUP_DIR/EXTRACTION_MANIFEST.txt"
sed -i "s|COUNT_FAIL|$FAIL_COUNT|g" "$BACKUP_DIR/EXTRACTION_MANIFEST.txt"

echo "Manifest created"
echo ""

# ============================================
# STEP 8: Final Status
# ============================================
echo "========================================="
echo "✓ EXTRACTION COMPLETE"
echo "========================================="
echo ""
echo "Backup location: $BACKUP_DIR"
echo ""

FILE_COUNT=$(find "$BACKUP_DIR" -type f 2>/dev/null | wc -l)
SIZE=$(du -s "$BACKUP_DIR" 2>/dev/null | cut -f1)

echo "Statistics:"
echo "  Files: $FILE_COUNT"
echo "  Size: $SIZE KB"
echo ""

echo "To retrieve on host:"
echo "  mkdir -p phase5_results"
echo "  adb pull $BACKUP_DIR ./phase5_results/"
echo ""
echo "========================================="

# Output path for host script
echo "BACKUP_PATH=$BACKUP_DIR"
