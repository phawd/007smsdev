#!/bin/sh

# Phase 5: Device Extraction - Simplified Direct Execution
# Uses fixed paths to avoid variable expansion issues

TS=$(date +%s)
BACKUP="/root/phase5_extraction_$TS"

echo "========================================="
echo "Phase 5: Safe Device Extraction"
echo "========================================="
echo "Backup directory: $BACKUP"
echo "Timestamp: $TS"
echo ""

# Create directories
mkdir -p "$BACKUP"/nv_items "$BACKUP"/efs2_safe "$BACKUP"/fota "$BACKUP"/modem_info "$BACKUP"/carrier_config "$BACKUP"/device_config

if [ ! -d "$BACKUP/nv_items" ]; then
  echo "ERROR: Failed to create directories"
  exit 1
fi

echo "✓ Directories created"
echo ""

# ============================================
# STEP 1: Device Information
# ============================================
echo "=== Device Information ==="

/opt/nvtl/bin/modem2_cli get_info > "$BACKUP/modem_info/device_info.txt" 2>&1
/opt/nvtl/bin/modem2_cli get_state > "$BACKUP/modem_info/modem_state.txt" 2>&1
/opt/nvtl/bin/modem2_cli get_signal > "$BACKUP/modem_info/signal_strength.txt" 2>&1
/opt/nvtl/bin/modem2_cli sim_get_status > "$BACKUP/modem_info/sim_status.txt" 2>&1

echo "✓ Device info captured"

# ============================================
# STEP 2: NV Items (Carrier Lock Data)
# ============================================
echo "=== NV Items (Carrier Lock Data) ==="

# Key NV items for lock mechanism
ITEMS="550 3461 4399 60044"

for NV_ID in $ITEMS; do
  /opt/nvtl/bin/nwnvitem -r -e $NV_ID > "$BACKUP/nv_items/nv_$NV_ID.txt" 2>&1
done

echo "✓ NV items extracted (550, 3461, 4399, 60044)"

# ============================================
# STEP 3: EFS2 via QMI
# ============================================
echo "=== EFS2 Extraction (QMI) ==="

/opt/nvtl/bin/nwcli qmi_idl read_file /tmp/lte_band.bin /nv/item_files/modem/mmode/lte_bandpref 8 2>&1 > "$BACKUP/efs2_safe/qmi_read.log"

if [ -f /tmp/lte_band.bin ]; then
  cp /tmp/lte_band.bin "$BACKUP/efs2_safe/lte_bandpref.bin"
  echo "✓ LTE band preference extracted via QMI"
else
  echo "✗ QMI read failed (see qmi_read.log)"
fi

# ============================================
# STEP 4: MTD Partition Info
# ============================================
echo "=== Partition Information ==="

cat /proc/mtd > "$BACKUP/efs2_safe/mtd_partitions.txt" 2>&1
mount > "$BACKUP/efs2_safe/mounts.txt" 2>&1

echo "✓ MTD and mount info captured"

# ============================================
# STEP 5: Configuration Files
# ============================================
echo "=== Configuration Files ==="

cp /sysconf/features.xml "$BACKUP/device_config/" 2>/dev/null && echo "✓ Features captured"
cp /sysconf/settings.xml "$BACKUP/device_config/" 2>/dev/null && echo "✓ Settings captured"

# ============================================
# STEP 6: Modem Status
# ============================================
echo "=== Modem Status ==="

/opt/nvtl/bin/modem2_cli get_carrier_unlock > "$BACKUP/device_config/carrier_lock_status.txt" 2>&1
/opt/nvtl/bin/modem2_cli enabled_tech_get > "$BACKUP/modem_info/enabled_tech.txt" 2>&1
/opt/nvtl/bin/modem2_cli get_imsi > "$BACKUP/modem_info/imsi.txt" 2>&1

echo "✓ Modem status captured"

# ============================================
# STEP 7: Archive Everything
# ============================================
echo ""
echo "=== Creating Archive ==="

tar -czf "$BACKUP.tar.gz" "$BACKUP" 2>/dev/null && echo "✓ Tarball created: $BACKUP.tar.gz"

# ============================================
# STEP 8: Final Status
# ============================================
echo ""
echo "========================================="
echo "✓ EXTRACTION COMPLETE"
echo "========================================="
echo ""
echo "Backup directory: $BACKUP"
echo "Backup tarball: $BACKUP.tar.gz"
echo ""

FILE_COUNT=$(find "$BACKUP" -type f 2>/dev/null | wc -l)
SIZE=$(du -s "$BACKUP" 2>/dev/null | cut -f1)

echo "Files extracted: $FILE_COUNT"
echo "Total size: $SIZE KB"
echo ""
echo "To retrieve on host:"
echo "  adb pull $BACKUP.tar.gz ./phase5_extraction.tar.gz"
echo "  OR"
echo "  adb pull $BACKUP ./phase5_results/"
echo ""
echo "========================================="

# Output for host parsing
echo "BACKUP_PATH=$BACKUP"
echo "BACKUP_TARBALL=$BACKUP.tar.gz"
