#!/bin/sh
# Phase 5: Complete filesystem extraction from MiFi 8800L
# Extracts all MTD partitions, firmware, configuration, and lock data

set -e

BACKUP_DIR="${1:-.}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
SESSION_DIR="$BACKUP_DIR/phase5_filesystem_$TIMESTAMP"

echo "========================================="
echo "Phase 5: Filesystem & Firmware Extraction"
echo "========================================="
echo "Backup directory: $SESSION_DIR"
echo "Device: $(getprop ro.build.fingerprint)"
echo "Timestamp: $TIMESTAMP"
echo

mkdir -p "$SESSION_DIR/mtd_partitions"
mkdir -p "$SESSION_DIR/firmware"
mkdir -p "$SESSION_DIR/configuration"
mkdir -p "$SESSION_DIR/carrier_lock_data"
mkdir -p "$SESSION_DIR/fota_info"

# ============================================
# STEP 1: Extract all MTD partitions
# ============================================
echo "=== STEP 1: MTD Partition Extraction ==="

# Get partition map
echo "Modem partition details:"
cat /proc/mtd | grep -E "mtd|modem|efs|boot|recovery|system"

# Extract each MTD partition
for i in {0..12}; do
    MTD_DEV="/dev/mtd$i"
    if [ -e "$MTD_DEV" ]; then
        MTD_NAME=$(cat /proc/mtd | grep "mtd$i:" | awk '{print $4}')
        if [ -n "$MTD_NAME" ]; then
            MTD_SIZE=$(cat /proc/mtd | grep "mtd$i:" | awk '{print $2}')
            echo "Extracting mtd$i ($MTD_NAME, $MTD_SIZE bytes)..."
            
            # Use dd to extract
            dd if="$MTD_DEV" of="$SESSION_DIR/mtd_partitions/mtd${i}_${MTD_NAME}.bin" bs=1024 2>/dev/null
            
            # Get file info
            ls -lh "$SESSION_DIR/mtd_partitions/mtd${i}_${MTD_NAME}.bin"
        fi
    fi
done

echo "MTD extraction complete."
echo

# ============================================
# STEP 2: Extract EFS2 partition (carrier lock data)
# ============================================
echo "=== STEP 2: EFS2 Partition (Carrier Lock Data) ==="

EFS2_DEV="/dev/mtd2"
if [ -e "$EFS2_DEV" ]; then
    echo "Extracting EFS2 (carrier lock storage)..."
    
    # Full extraction
    dd if="$EFS2_DEV" of="$SESSION_DIR/carrier_lock_data/efs2_full.bin" bs=1024 2>/dev/null
    
    # Try to mount for file analysis
    mkdir -p "$SESSION_DIR/carrier_lock_data/efs2_mount"
    mount -t ubifs -o ro "$EFS2_DEV" "$SESSION_DIR/carrier_lock_data/efs2_mount" 2>/dev/null || {
        echo "UBIFS mount failed, trying direct analysis..."
        
        # Extract strings from binary
        strings "$SESSION_DIR/carrier_lock_data/efs2_full.bin" > "$SESSION_DIR/carrier_lock_data/efs2_strings.txt"
        
        # Extract hex dump for analysis
        hexdump -C "$SESSION_DIR/carrier_lock_data/efs2_full.bin" | head -100 > "$SESSION_DIR/carrier_lock_data/efs2_hexdump.txt"
    }
    
    ls -lh "$SESSION_DIR/carrier_lock_data/efs2_full.bin"
fi

echo

# ============================================
# STEP 3: Extract modem firmware and binaries
# ============================================
echo "=== STEP 3: Modem Firmware & Binary Extraction ==="

# Extract modem firmware partition
MTD_MODEM="/dev/mtd8"
if [ -e "$MTD_MODEM" ]; then
    echo "Extracting modem firmware (mtd8)..."
    dd if="$MTD_MODEM" of="$SESSION_DIR/firmware/modem_firmware.bin" bs=1024 2>/dev/null
    ls -lh "$SESSION_DIR/firmware/modem_firmware.bin"
fi

# Extract CLI tools and libraries
echo "Extracting modem CLI tools..."
cp -r /opt/nvtl/bin "$SESSION_DIR/firmware/nvtl_bin" 2>/dev/null || echo "nvtl_bin not found"
cp -r /opt/nvtl/lib "$SESSION_DIR/firmware/nvtl_lib" 2>/dev/null || echo "nvtl_lib not found"

# Extract critical libraries
echo "Extracting modem libraries..."
mkdir -p "$SESSION_DIR/firmware/modem_libraries"
for lib in libmodem2_api.so libmal_qct.so libsms_encoder.so libmal_ims_client_api.so; do
    find /opt -name "$lib" -exec cp {} "$SESSION_DIR/firmware/modem_libraries/" \; 2>/dev/null
done

ls -la "$SESSION_DIR/firmware/modem_libraries/"

echo

# ============================================
# STEP 4: Extract carrier lock configuration files
# ============================================
echo "=== STEP 4: Carrier Lock Configuration ==="

mkdir -p "$SESSION_DIR/configuration/device_config"

# Device configuration files
for file in /policyman/device_config.xml /policyman/carrier_policy.xml /sysconf/settings.xml /sysconf/features.xml; do
    if [ -f "$file" ]; then
        echo "Extracting $file..."
        cp "$file" "$SESSION_DIR/configuration/device_config/" 2>/dev/null || echo "Failed: $file"
    fi
done

# Extract sysconf directory
cp -r /sysconf "$SESSION_DIR/configuration/sysconf" 2>/dev/null || echo "sysconf directory not found"

# Extract OMaDM configuration
cp -r /opt/nvtl/etc/omadm "$SESSION_DIR/configuration/omadm" 2>/dev/null || echo "OMaDM config not found"

echo

# ============================================
# STEP 5: Extract FOTA (Firmware Over-The-Air) information
# ============================================
echo "=== STEP 5: FOTA (Firmware Update) Analysis ==="

mkdir -p "$SESSION_DIR/fota_info"

# FOTA tool locations
for tool in /opt/nvtl/bin/fota* /usr/bin/*fota* /opt/bin/*fota*; do
    if [ -f "$tool" ]; then
        echo "Found FOTA tool: $tool"
        cp "$tool" "$SESSION_DIR/fota_info/" 2>/dev/null
        
        # Get strings from FOTA binary
        strings "$tool" > "$SESSION_DIR/fota_info/$(basename $tool)_strings.txt" 2>/dev/null
    fi
done

# Extract FOTA configuration
for config in /etc/fota* /opt/nvtl/etc/fota* /sysconf/fota*; do
    if [ -f "$config" ]; then
        echo "Extracting FOTA config: $config"
        cp "$config" "$SESSION_DIR/fota_info/" 2>/dev/null
    fi
done

# Try to get FOTA status
echo "FOTA status information:"
if command -v modem2_cli >/dev/null 2>&1; then
    modem2_cli fota_get_status > "$SESSION_DIR/fota_info/fota_status.txt" 2>&1
fi

if command -v fota_cli >/dev/null 2>&1; then
    fota_cli status > "$SESSION_DIR/fota_info/fota_cli_status.txt" 2>&1
    fota_cli help > "$SESSION_DIR/fota_info/fota_cli_help.txt" 2>&1
fi

# Firmware version info
echo "Firmware version information:"
cat /opt/nvtl/etc/version > "$SESSION_DIR/fota_info/firmware_version.txt" 2>/dev/null || echo "No version file found"

echo

# ============================================
# STEP 6: Extract SPC/Lock-Related NV Items
# ============================================
echo "=== STEP 6: SPC and Lock-Related NV Items ==="

mkdir -p "$SESSION_DIR/nv_items"

# Critical NV items for analysis
NV_ITEMS="5 851 4398 60044 550 553 60500 65000"

for nv_id in $NV_ITEMS; do
    echo "Reading NV item $nv_id..."
    nwcli qmi_idl read_nv "$nv_id" 0 > "$SESSION_DIR/nv_items/nv_${nv_id}.txt" 2>&1
done

echo

# ============================================
# STEP 7: Extract binary metadata
# ============================================
echo "=== STEP 7: Binary Metadata Extraction ==="

mkdir -p "$SESSION_DIR/binary_analysis"

# Extract symbol information from modem libraries
for lib in "$SESSION_DIR/firmware/modem_libraries"/*.so; do
    if [ -f "$lib" ]; then
        LIBNAME=$(basename "$lib")
        echo "Analyzing $LIBNAME..."
        
        # Get all symbols
        nm -D "$lib" > "$SESSION_DIR/binary_analysis/${LIBNAME}_symbols.txt" 2>/dev/null || true
        
        # Get strings
        strings "$lib" > "$SESSION_DIR/binary_analysis/${LIBNAME}_strings.txt" 2>/dev/null || true
        
        # Get section info
        readelf -S "$lib" > "$SESSION_DIR/binary_analysis/${LIBNAME}_sections.txt" 2>/dev/null || true
    fi
done

echo

# ============================================
# STEP 8: Generate summary report
# ============================================
echo "=== STEP 8: Generating Summary Report ==="

cat > "$SESSION_DIR/EXTRACTION_SUMMARY.txt" <<EOF
========================================
Phase 5: Filesystem Extraction Summary
========================================

Device: $(getprop ro.build.fingerprint)
Extract Timestamp: $TIMESTAMP
Modem Chipset: $(getprop ro.baseband)
Android/Linux Version: $(getprop ro.build.version.release)

MTD PARTITIONS EXTRACTED
------------------------
$(cat /proc/mtd | grep -E "mtd|sbl|boot|system|modem|efs")

CRITICAL FILES BACKED UP
------------------------
✓ EFS2 partition (carrier lock storage): efs2_full.bin
✓ Modem firmware: modem_firmware.bin  
✓ Modem libraries: nvtl_lib/
✓ Modem CLI tools: nvtl_bin/
✓ Device configuration: configuration/
✓ FOTA information: fota_info/
✓ Binary symbols: binary_analysis/

CARRIER LOCK DATA LOCATIONS
----------------------------
EFS2 Partition (mtd2):
  - Size: $(cat /proc/mtd | grep mtd2 | awk '{print $2}')
  - Contains: SIM lock, carrier lock flags, device NV items
  - Location: efs2_full.bin

NV Items Read:
  - NV 5: Feature code
  - NV 851: SPC code
  - NV 4398: Subsidy lock
  - NV 60044: PRI (Carrier ID)
  - NV 550: IMEI
  - NV 553: SID/NID lock

Configuration Files:
  - /policyman/device_config.xml: Device capabilities
  - /sysconf/settings.xml: Device settings
  - /sysconf/features.xml: Feature flags

FOTA ANALYSIS
-------------
Firmware update mechanism documented in: fota_info/
Key files for analysis:
  - FOTA binary strings
  - FOTA configuration
  - Signature verification approach (TBD)

BINARY ANALYSIS DATA
--------------------
Extracted for offline analysis:
  - Symbol tables (nm -D)
  - String data (strings)
  - Section information (readelf)

All data ready for decompilation and SPC discovery.

Next Steps (Phase 5):
  1. Analyze modem libraries offline with IDA Pro/Ghidra
  2. Search for SPC validation functions
  3. Identify hardcoded SPC codes or bypass conditions
  4. Analyze FOTA signature validation
  5. Map carrier lock persistence mechanism
  6. Document findings for exploitation
EOF

echo "Summary report created."
echo

# ============================================
# STEP 9: Tar and compress backup
# ============================================
echo "=== STEP 9: Creating Compressed Archive ==="

cd "$BACKUP_DIR"
TAR_FILE="phase5_filesystem_${TIMESTAMP}.tar.gz"
echo "Creating archive: $TAR_FILE"
tar -czf "$TAR_FILE" "phase5_filesystem_$TIMESTAMP" 2>&1 | tail -5

echo

# ============================================
# Final report
# ============================================
echo "========================================="
echo "EXTRACTION COMPLETE"
echo "========================================="
echo "Location: $SESSION_DIR"
echo "Archive: $TAR_FILE"
echo "Size: $(du -sh $SESSION_DIR | awk '{print $1}')"
echo
echo "Ready for Phase 5 offline analysis:"
echo "  ✓ Modem libraries extracted"
echo "  ✓ Firmware backed up"
echo "  ✓ Configuration files archived"
echo "  ✓ FOTA mechanism documented"
echo "  ✓ Carrier lock data preserved"
echo "========================================="
