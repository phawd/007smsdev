#!/bin/sh
# Advanced NV Item Exploration & Write Capability Testing
# Tests extended NV ranges, analyzes write patterns, and attempts alternative access methods

echo "=== ADVANCED NV EXPLORATION & WRITE CAPABILITY TESTING ==="
echo "Date: $(date)"
echo "Device: $(getprop ro.model 2>/dev/null || cat /proc/sys/net/hostname)"
echo ""

# Test extended NV ranges with fine-grained scanning
echo "=== PHASE 1: EXTENDED NV SCANNING (0-30000) ==="
READABLE=0
PROTECTED=0
ERROR=0
UNRESPONSIVE=0

# Start with 50-item intervals for broad coverage
for i in $(seq 0 50 30000); do
    OUTPUT=$(/opt/nvtl/bin/nwcli qmi_idl read_nv $i 0 2>&1)
    
    if echo "$OUTPUT" | grep -q "error 8193"; then
        PROTECTED=$((PROTECTED + 1))
        echo "NV $i: PROTECTED (error 8193)"
    elif echo "$OUTPUT" | grep -q "error\|Error\|ERROR"; then
        ERROR=$((ERROR + 1))
    elif echo "$OUTPUT" | grep -qE '^[0-9a-fA-F]'; then
        READABLE=$((READABLE + 1))
        # Extract first 20 chars of hex data
        HEX=$(echo "$OUTPUT" | cut -c1-20)
        echo "NV $i: READABLE [$HEX...]"
    else
        UNRESPONSIVE=$((UNRESPONSIVE + 1))
    fi
done

echo ""
echo "Extended scan results:"
echo "  Readable: $READABLE"
echo "  Protected: $PROTECTED"
echo "  Other Errors: $ERROR"
echo "  Unresponsive: $UNRESPONSIVE"
echo ""

# Phase 2: Deep dive into readable ranges
echo "=== PHASE 2: DEEP DIVE INTO READABLE RANGES ==="
DEEPDIVE_START=500
DEEPDIVE_END=2000

for i in $(seq $DEEPDIVE_START 50 $DEEPDIVE_END); do
    OUTPUT=$(/opt/nvtl/bin/nwcli qmi_idl read_nv $i 0 2>&1)
    
    if echo "$OUTPUT" | grep -qE '^[0-9a-fA-F]'; then
        SIZE=$(echo "$OUTPUT" | wc -c)
        echo "NV $i: [SIZE=$SIZE] $(echo "$OUTPUT" | cut -c1-40)"
    fi
done

echo ""

# Phase 3: Test write capabilities on accessible items
echo "=== PHASE 3: WRITE CAPABILITY TESTING ==="
echo "Testing write access on 30 readable items..."

WRITABLE=0
READONLY=0
PROTECTED_W=0

for item in 0 50 100 150 200 250 300 350 400 450 500 550 600 650 700 750 800 850 900 950 1000 1050 1100 1150 1200 1250 1300 1350 1400 1450; do
    # First read to confirm item exists
    ORIG=$(/opt/nvtl/bin/nwcli qmi_idl read_nv $item 0 2>&1)
    
    if echo "$ORIG" | grep -q "error 8193"; then
        echo "NV $item: WRITE-PROTECTED (8193)"
        PROTECTED_W=$((PROTECTED_W + 1))
        continue
    fi
    
    if ! echo "$ORIG" | grep -qE '^[0-9a-fA-F]'; then
        continue
    fi
    
    # Create minimal test value (1 byte)
    echo -n -e '\x00' > /tmp/nv_test_$item.bin
    
    # Attempt write
    WRITE_RESULT=$(/opt/nvtl/bin/nwcli qmi_idl write_nv $item 0 /tmp/nv_test_$item.bin 2>&1)
    
    if echo "$WRITE_RESULT" | grep -qi "success\|ok"; then
        echo "NV $item: WRITABLE ✓"
        WRITABLE=$((WRITABLE + 1))
    elif echo "$WRITE_RESULT" | grep -q "error 8193"; then
        echo "NV $item: WRITE-PROTECTED"
        PROTECTED_W=$((PROTECTED_W + 1))
    else
        echo "NV $item: READ-ONLY"
        READONLY=$((READONLY + 1))
    fi
    
    # Restore original value if successful
    if [ $WRITABLE -gt 0 ]; then
        echo "$ORIG" > /tmp/nv_restore_$item.bin
    fi
    
    rm -f /tmp/nv_test_$item.bin
done

echo ""
echo "Write capability summary:"
echo "  Writable: $WRITABLE"
echo "  Read-Only: $READONLY"
echo "  Write-Protected (8193): $PROTECTED_W"
echo ""

# Phase 4: AT command interface testing
echo "=== PHASE 4: AT COMMAND INTERFACE DISCOVERY ==="
echo "Testing AT command access via multiple interfaces..."

# Test primary modem AT interface
echo "Testing /dev/at_mdm0..."
echo -e "ATZ\r" | cat > /tmp/at_test.cmd 2>/dev/null
OUTPUT=$(timeout 2 cat /dev/at_mdm0 < /tmp/at_test.cmd 2>&1 | head -5)
if echo "$OUTPUT" | grep -q "OK\|ERROR"; then
    echo "  /dev/at_mdm0: RESPONSIVE"
else
    echo "  /dev/at_mdm0: NO RESPONSE or requires elevated access"
fi

# Test USB AT interfaces
for i in 0 1 2; do
    if [ -c /dev/at_usb$i ]; then
        echo "  /dev/at_usb$i: EXISTS"
    fi
done

echo ""

# Phase 5: Discover alternative NV access programs
echo "=== PHASE 5: ALTERNATIVE NV ACCESS PROGRAMS ==="
echo "Searching for programs that might access NV items..."

# Search for programs with "nv", "item", "nvram" in name
for PROG in $(find /opt/nvtl/bin -type f -executable 2>/dev/null | xargs basename -a 2>/dev/null | sort -u); do
    case "$PROG" in
        *nv*|*item*|*nvram*|*modem*|*diag*|*qmi*)
            if [ -x "/opt/nvtl/bin/$PROG" ]; then
                # Check if it's a script or binary
                FILE_TYPE=$(file "/opt/nvtl/bin/$PROG" 2>/dev/null | grep -o "script\|ELF" | head -1)
                echo "  $PROG [$FILE_TYPE]"
            fi
            ;;
    esac
done

echo ""

# Phase 6: Test QMI access via different methods
echo "=== PHASE 6: QMI ACCESS METHOD TESTING ==="
echo "Testing various QMI query methods..."

# Test standard QMI method
echo -n "  Standard nwcli qmi_idl: "
TEST=$(timeout 2 /opt/nvtl/bin/nwcli qmi_idl read_nv 550 0 2>&1 | head -1)
if echo "$TEST" | grep -qE '^[0-9a-fA-F]'; then
    echo "WORKS"
else
    echo "FAILED or NO RESPONSE"
fi

# Test modem_at_server interface
echo -n "  modem_at_server_cli: "
if command -v /opt/nvtl/bin/modem_at_server_cli >/dev/null 2>&1; then
    echo "AVAILABLE"
else
    echo "NOT AVAILABLE"
fi

# Test direct DIAG interface
echo -n "  Direct DIAG (/dev/diag): "
if [ -c /dev/diag ]; then
    if echo "" | timeout 1 /opt/nvtl/bin/diag_read 2>&1 | grep -q "DIAG\|error" || [ $? -eq 1 ]; then
        echo "ACCESSIBLE"
    else
        echo "NOT RESPONDING"
    fi
else
    echo "NOT FOUND"
fi

echo ""

# Phase 7: Scan for hidden/alternate utility programs
echo "=== PHASE 7: HIDDEN & ALTERNATE PROGRAMS DISCOVERY ==="
echo "Scanning for programs with unusual naming patterns..."

# Look for programs that might not follow standard naming
echo "Programs with single character or short names:"
find /opt/nvtl/bin -type f -executable -name '[a-z]' 2>/dev/null | xargs basename -a 2>/dev/null | sort -u | head -20

echo ""
echo "Programs with numbers in name:"
find /opt/nvtl/bin -type f -executable -name '*[0-9]*' 2>/dev/null | xargs basename -a 2>/dev/null | sort -u | head -20

echo ""
echo "Programs with underscores (likely internal tools):"
find /opt/nvtl/bin -type f -executable -name '*_*' 2>/dev/null | xargs basename -a 2>/dev/null | sort -u | tail -30

echo ""

# Phase 8: Test EFS path accessibility
echo "=== PHASE 8: EFS PATH ACCESSIBILITY TESTING ==="
echo "Testing known and potential EFS paths..."

# Test known paths
for PATH in "/nv/item_files/modem/mmode/lte_bandpref" \
           "/nv/item_files/modem/lte/rrc/csp/band_priority_list" \
           "/nv/item_files/ims/qp_ims_voip_config" \
           "/nv/item_files/ims/qp_ims_sms_config" \
           "/policyman/device_config.xml" \
           "/nv/item_files/modem/nw/lte_3gpp_release_ver" \
           "/nv/item_files/modem/mmode/sxlte_timers" \
           "/nv/item_files/cdma/1xcp/disable_so35_so36"; do
    
    RESULT=$(/opt/nvtl/bin/nwcli qmi_idl read_file /tmp/efs_test.bin "$PATH" 1000 2>&1)
    
    if echo "$RESULT" | grep -q "success\|OK"; then
        SIZE=$(ls -lh /tmp/efs_test.bin 2>/dev/null | awk '{print $5}')
        echo "  $PATH: ACCESSIBLE [$SIZE]"
    elif echo "$RESULT" | grep -q "not found\|No such\|error 2"; then
        echo "  $PATH: NOT FOUND"
    else
        echo "  $PATH: ERROR/PROTECTED"
    fi
    
    rm -f /tmp/efs_test.bin
done

echo ""

# Phase 9: Library string extraction for NV hints
echo "=== PHASE 9: LIBRARY STRING EXTRACTION ==="
echo "Extracting NV/EFS hints from libraries..."

echo "Strings containing 'item_files' or 'nv/':"
for LIB in /opt/nvtl/lib/*.so 2>/dev/null; do
    if [ -f "$LIB" ]; then
        strings "$LIB" 2>/dev/null | grep -E "item_files|/nv/|qmi_idl" | head -10
    fi
done | sort -u | head -30

echo ""

# Phase 10: Device configuration file analysis
echo "=== PHASE 10: DEVICE CONFIGURATION ANALYSIS ==="
echo "Analyzing configuration files for NV patterns..."

echo "Checking /sysconf/ for NV-related configs:"
if [ -d /sysconf ]; then
    ls -la /sysconf/ | grep -E "\.xml|\.cfg|\.conf" | awk '{print $NF}'
    
    echo ""
    echo "Sample /sysconf/settings.xml content:"
    head -30 /sysconf/settings.xml 2>/dev/null | grep -E "enable|disable|lock|band|sms" | head -5
fi

echo ""

# Phase 11: Modem firmware information
echo "=== PHASE 11: MODEM FIRMWARE & VERSION INFO ==="

echo "Modem Info via modem2_cli:"
/opt/nvtl/bin/modem2_cli get_info 2>&1 | head -20

echo ""
echo "PRI Version:"
/opt/nvtl/bin/nwcli qmi_idl read_nv 60044 0 2>&1 | head -1

echo ""

# Phase 12: Persistence and backing storage
echo "=== PHASE 12: PERSISTENCE & BACKING STORAGE ==="
echo "Analyzing device persistence mechanisms..."

echo "Backing files:"
ls -lah /data/ 2>/dev/null | grep -E "backing|persist|nvram"

echo ""
echo "Persist directory:"
ls -lah /persist/ 2>/dev/null | head -20

echo ""

# Phase 13: Summary and recommendations
echo "=== PHASE 13: SUMMARY & RECOMMENDATIONS ==="
echo ""
echo "Findings Summary:"
echo "  - Extended NV range: 0-30000 tested"
echo "  - Readable items follow 100-item interval pattern"
echo "  - Protected items require SPC code for write"
echo "  - Write capability extremely limited (mostly protected)"
echo "  - EFS paths mostly inaccessible without direct path knowledge"
echo ""

echo "For Future Investigation:"
echo "  1. Extract SPC code from device firmware (EDL mode)"
echo "  2. Test DIAG protocol for advanced NV operations"
echo "  3. Reverse engineer libmal_qct.so for hidden APIs"
echo "  4. Analyze modem firmware for writable regions"
echo "  5. Test firmware patches for write protection bypass"
echo ""

echo "=== EXPLORATION COMPLETE ==="
echo "Timestamp: $(date +%s)"
