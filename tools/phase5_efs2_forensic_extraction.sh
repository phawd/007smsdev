#!/bin/sh
# Phase 5: Forensic EFS2 Partition Extraction
# Purpose: Extract complete EFS2 data (11.5 MB) for structure analysis
# Method: Small blocksize dd to avoid watchdog reboot
# Device: MiFi 8800L, Firmware: SDx20ALP-1.22.11

OUTPUT_DIR="/root/efs2_forensic_extraction"

# Create output directory
mkdir -p "$OUTPUT_DIR"
cd "$OUTPUT_DIR"

echo "[$(date)] Starting forensic EFS2 extraction..."
echo "[$(date)] Method: dd with 512-byte blocksize"
echo "[$(date)] Output directory: $OUTPUT_DIR"

# Extract EFS2 partition directly using dd with small blocksize
# This avoids watchdog reboot while reading the complete partition
dd if=/dev/mtd2 bs=512 of=efs2_complete.bin 2> dd_output.log

# Check result
if [ -f "efs2_complete.bin" ]; then
    FINAL_SIZE=$(stat -c%s efs2_complete.bin 2>/dev/null || echo "0")
    echo "[$(date)] ✓ EFS2 extraction complete"
    echo "[$(date)] Output size: $FINAL_SIZE bytes"
    
    if [ $FINAL_SIZE -gt 0 ]; then
        # Generate checksums
        md5sum efs2_complete.bin > efs2_complete.bin.md5
        echo "[$(date)] MD5: $(cat efs2_complete.bin.md5)"
        
        # Create metadata
        cat > extraction_metadata.txt << EOFMETA
EFS2 Forensic Extraction Report
Date: $(date)
Device: MiFi 8800L
Method: dd with 512-byte blocksize
Output Size: $FINAL_SIZE bytes
Status: SUCCESS
EOFMETA
        
        echo "[$(date)] ✓ Metadata created"
    fi
else
    echo "[$(date)] ✗ EFS2 extraction FAILED"
fi

# List files and device status
echo ""
echo "=== OUTPUT FILES ==="
ls -lah "$OUTPUT_DIR"

echo ""
echo "[$(date)] Device status:"
/opt/nvtl/bin/modem2_cli get_state

echo "[$(date)] ✓ Extraction complete"
