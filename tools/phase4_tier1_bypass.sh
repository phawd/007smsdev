#!/bin/sh
# PHASE 4: TIER 1/2 PROTECTION BYPASS INVESTIGATION
# Focus: TIER 1 (locked items) and TIER 2 (read-only) access + alternative vectors
# Methods: SPC code search, firmware analysis, memory access, library exploitation

echo "========================================"
echo "PHASE 4: TIER 1/2 PROTECTION BYPASS"
echo "Started: $(date)"
echo "========================================"
echo ""

# ============================================
# PHASE 1: SPC CODE DISCOVERY
# ============================================
echo "=== PHASE 1: SPC CODE SEARCH ==="
echo "Searching for hardcoded SPC codes in firmware/libraries..."
echo ""

# Check for SPC patterns in memory
echo "Checking running processes for SPC data..."
for pid in $(ps aux | grep -E 'modem|qmi|nv' | grep -v grep | awk '{print $1}'); do
    if [ -f "/proc/$pid/environ" ]; then
        cat "/proc/$pid/environ" 2>/dev/null | tr '\0' '\n' | grep -i spc
    fi
done

echo ""
echo "Checking common SPC locations..."
# Common SPC storage locations
for path in /opt/nvtl/etc /etc /data /persist /sysconf; do
    if [ -d "$path" ]; then
        find "$path" -type f 2>/dev/null | xargs grep -l "SPC\|spc\|000000\|111111" 2>/dev/null | head -10
    fi
done

echo ""
echo "Searching binary strings for SPC patterns..."
strings /opt/nvtl/bin/modem2_cli 2>/dev/null | grep -i "spc\|service.*program" | head -5
strings /opt/nvtl/lib/libmodem2_api.so 2>/dev/null | grep -i "spc\|0x" | grep -E "[0-9]{6}" | head -5

echo ""

# ============================================
# PHASE 2: NV ITEM WRITE VECTOR ANALYSIS
# ============================================
echo "=== PHASE 2: TIER 1/2 WRITE CAPABILITY ==="
echo "Attempting high-numbered NV item writes (likely less protected)..."
echo ""

# Test specific TIER 1/2 items
echo "Testing NV items known to be protected..."

# Try NV 5 (Carrier lock candidate)
echo "NV 5 (potential carrier lock):"
result=$(/opt/nvtl/bin/nwcli qmi_idl write_nv 5 0 "AA BB CC DD" 2>&1)
if echo "$result" | grep -q "success"; then
    echo "  WRITABLE (unexpected!)"
elif echo "$result" | grep -q "8193\|denied"; then
    echo "  PROTECTED (as expected)"
else
    echo "  Result: $result"
fi

# Try NV 550 (IMEI)
echo ""
echo "NV 550 (IMEI):"
result=$(/opt/nvtl/bin/nwcli qmi_idl write_nv 550 0 "AA 11 22 33 44" 2>&1)
if echo "$result" | grep -q "success"; then
    echo "  WRITABLE (unexpected!)"
elif echo "$result" | grep -q "8193\|denied"; then
    echo "  PROTECTED (as expected)"
else
    echo "  Result: $result"
fi

# Extended high-number testing
echo ""
echo "Testing high-numbered items (>60000)..."
for i in 60500 61000 61500 62000 62500 63000 63500 64000 64500 65000 65535; do
    result=$(/opt/nvtl/bin/nwcli qmi_idl read_nv "$i" 0 2>&1)
    if ! echo "$result" | grep -q "Error"; then
        write_result=$(/opt/nvtl/bin/nwcli qmi_idl write_nv "$i" 0 "TEST" 2>&1 | head -1)
        echo "NV $i: READABLE, write: $write_result"
    fi
done

echo ""

# ============================================
# PHASE 3: DIRECT MODEM MEMORY ACCESS
# ============================================
echo "=== PHASE 3: DIRECT MEMORY ACCESS VECTORS ==="
echo "Testing /dev/mem and /dev/kmem for modem state access..."
echo ""

# Check if /dev/mem is accessible
if [ -r /dev/mem ]; then
    echo "/dev/mem: READABLE"
    # Try to read a small chunk
    dd if=/dev/mem bs=1 count=16 2>/dev/null | od -A x -t x1z -v | head -1
else
    echo "/dev/mem: NOT READABLE (protected)"
fi

# Check MTD devices
echo ""
echo "MTD (flash) partition analysis..."
if [ -d /proc/mtd ]; then
    cat /proc/mtd | head -5
    echo "MTD devices found (modem firmware may be modifiable)"
fi

echo ""

# ============================================
# PHASE 4: LIBRARY FUNCTION EXTRACTION
# ============================================
echo "=== PHASE 4: LIBRARY WRITE FUNCTIONS ==="
echo "Extracting symbols from modem libraries..."
echo ""

# Extract symbols from key libraries
echo "libmodem2_api.so symbols (write-related):"
nm -D /opt/nvtl/lib/libmodem2_api.so 2>/dev/null | grep -i "write\|set\|modify\|unlock" | head -10

echo ""
echo "libsms_encoder.so symbols (PDU encoding):"
nm -D /opt/nvtl/lib/libsms_encoder.so 2>/dev/null | grep -i "encode\|sms\|pdu" | head -10

echo ""
echo "Checking for QMI write functions..."
nm -D /opt/nvtl/lib/libmal_qct.so 2>/dev/null | grep -i "write\|send" 2>/dev/null | head -10

echo ""

# ============================================
# PHASE 5: DIAG PROTOCOL INTERFACE
# ============================================
echo "=== PHASE 5: DIAG PROTOCOL ANALYSIS ==="
echo "Analyzing Qualcomm DIAG protocol access..."
echo ""

# Check DIAG device
if [ -c /dev/diag ]; then
    echo "/dev/diag: ACCESSIBLE (Qualcomm diagnostic interface)"
    
    # DIAG uses binary protocol - attempt info query
    echo "DIAG device major:minor: $(ls -l /dev/diag | awk '{print $5,$6}')"
    
    # Try to list DIAG operations via strings in binaries
    echo ""
    echo "DIAG commands available (from diag_read strings):"
    strings /opt/nvtl/bin/diag_read 2>/dev/null | grep -E "^0x[0-9A-F]+" | head -10
else
    echo "/dev/diag: NOT ACCESSIBLE"
fi

echo ""

# ============================================
# PHASE 6: AT COMMAND SERVER EXPLOITATION
# ============================================
echo "=== PHASE 6: AT COMMAND SERVER VECTORS ==="
echo "Analyzing modem_at_server for write capabilities..."
echo ""

# Check AT server
if command -v /opt/nvtl/bin/modem_at_server_cli >/dev/null 2>&1; then
    echo "modem_at_server_cli: AVAILABLE"
    
    # AT commands for NV modification
    echo "Attempting AT-based NV access..."
    
    # List AT commands
    /opt/nvtl/bin/modem_at_server_cli help 2>/dev/null || echo "No help available"
else
    echo "modem_at_server_cli: NOT FOUND"
fi

echo ""

# ============================================
# PHASE 7: EFS WRITE CAPABILITY TESTING
# ============================================
echo "=== PHASE 7: EFS FILE MODIFICATION ==="
echo "Testing EFS write capability on known paths..."
echo ""

# Test write to writable EFS path
echo "Attempting to write to /nv/item_files/modem/mmode/lte_bandpref..."
echo -n -e '\xff\xff\xff\xff\xff\xff\xff\xff' > /tmp/test_band.bin

result=$(/opt/nvtl/bin/nwcli qmi_idl write_file /tmp/test_band.bin /nv/item_files/modem/mmode/lte_bandpref 2>&1)
if echo "$result" | grep -q "success"; then
    echo "  WRITABLE: Band preference modification successful"
    
    # Verify write
    verify=$(/opt/nvtl/bin/nwcli qmi_idl read_file /tmp/verify.bin /nv/item_files/modem/mmode/lte_bandpref 8 2>&1)
    echo "  Verification: $verify"
else
    echo "  PROTECTED or ERROR: $result"
fi

echo ""
echo "Testing device_config.xml write..."
# device_config.xml contains capability flags
echo '<?xml version="1.0"?>
<device_config name="MiFi" target="CHGWLTD" single_sim="0" ss_toggle="0">
  <config primary="C H G W L T D" />
  <feature name="Feature_Hdr" enabled="1" />
  <feature name="Feature_RF_Bands" enabled="1" />
</device_config>' > /tmp/device_config_test.xml

result=$(/opt/nvtl/bin/nwcli qmi_idl write_file /tmp/device_config_test.xml /policyman/device_config.xml 2>&1)
if echo "$result" | grep -q "success"; then
    echo "  WRITABLE: device_config.xml modification successful"
else
    echo "  PROTECTED: $result"
fi

echo ""

# ============================================
# PHASE 8: FIRMWARE FOTA CHAIN ANALYSIS
# ============================================
echo "=== PHASE 8: FOTA FIRMWARE MODIFICATION ==="
echo "Analyzing FOTA firmware update process..."
echo ""

# Check FOTA state
echo "FOTA tools available:"
ls -la /opt/nvtl/bin/fota* 2>/dev/null | awk '{print $NF}' | head -10

echo ""
echo "FOTA configuration:"
if [ -f /sysconf/fota.xml ]; then
    head -20 /sysconf/fota.xml
fi

echo ""
echo "Checking FOTA firmware storage..."
find /tmp /data /persist 2>/dev/null -name "*fota*" -o -name "*firmware*" -o -name "*pri*" 2>/dev/null | head -10

echo ""

# ============================================
# PHASE 9: PROCESS MEMORY ANALYSIS
# ============================================
echo "=== PHASE 9: PROCESS MEMORY INSPECTION ==="
echo "Analyzing running modem processes for exploitable state..."
echo ""

# Find modem processes
echo "Modem processes:"
ps aux | grep -E 'modem|qmi|diag' | grep -v grep | head -5

# Check process memory maps
for pid in $(ps aux | grep modem2d | grep -v grep | awk '{print $1}'); do
    echo ""
    echo "Process $pid memory map:"
    cat /proc/$pid/maps 2>/dev/null | grep -E 'modem|nv|flash' | head -5
done

echo ""

# ============================================
# PHASE 10: LIBRARY DEPENDENCY CHAIN
# ============================================
echo "=== PHASE 10: LIBRARY WRITE CAPABILITY CHAIN ==="
echo "Tracing library dependencies for write operations..."
echo ""

# Main libraries involved in NV writes
echo "Library dependencies:"
ldd /opt/nvtl/bin/modem2_cli 2>/dev/null | grep -E 'qmi|nv|modem'

echo ""
echo "Exported functions in libmodem2_api.so:"
nm -D /opt/nvtl/lib/libmodem2_api.so 2>/dev/null | grep -i "nv\|write" | head -15

echo ""

# ============================================
# PHASE 11: CARRIER CONFIGURATION FILES
# ============================================
echo "=== PHASE 11: CARRIER CONFIG ANALYSIS ==="
echo "Analyzing carrier configuration for lock bypass..."
echo ""

# Check carrier-specific configs
echo "Carrier configuration files:"
find /sysconf /etc /opt/nvtl/etc 2>/dev/null -name "*carrier*" -o -name "*verizon*" -o -name "*lock*" 2>/dev/null | head -10

echo ""
echo "Device settings that might control locks:"
cat /sysconf/settings.xml 2>/dev/null | grep -i "carrier\|lock\|subsidy\|roam" | head -10

echo ""

# ============================================
# PHASE 12: ALTERNATE PROGRAM DISCOVERY
# ============================================
echo "=== PHASE 12: HIDDEN WRITE INTERFACES ==="
echo "Searching for undocumented write/modify programs..."
echo ""

# Look for programs with write capabilities
echo "Programs that might have write access:"
find /opt/nvtl/bin /bin /usr/bin 2>/dev/null -type f -executable | \
    xargs strings 2>/dev/null | grep -E "write_nv|modify|unlock|bypass|set_nv" | sort -u | head -15

echo ""
echo "Checking for shell functions that enable writes..."
grep -r "nwcli.*write\|write_nv\|modify.*nv" /opt/nvtl/bin/*.sh 2>/dev/null | head -10

echo ""

# ============================================
# PHASE 13: KERNEL MODULE ANALYSIS
# ============================================
echo "=== PHASE 13: KERNEL MODULES ==="
echo "Checking loaded kernel modules for modem access..."
echo ""

if [ -f /proc/modules ]; then
    echo "Loaded modules (modem-related):"
    cat /proc/modules | grep -i "modem\|smd\|qmi" | head -10
    
    echo ""
    echo "Module parameters:"
    cat /sys/module/*/parameters/* 2>/dev/null | grep -i "nv\|write\|unlock" | head -10
fi

echo ""

# ============================================
# PHASE 14: FORENSIC SUMMARY
# ============================================
echo "=== PHASE 14: FINDINGS SUMMARY ==="
echo ""
echo "Completed: $(date)"
echo ""
echo "Key investigation results:"
echo "  - SPC code search: Completed"
echo "  - TIER 1/2 write testing: Completed"
echo "  - Memory access vectors: Checked"
echo "  - Library exploitation: Analyzed"
echo "  - DIAG protocol: Assessed"
echo "  - AT command vectors: Evaluated"
echo "  - EFS write capability: Tested"
echo "  - FOTA chain: Examined"
echo "  - Process memory: Inspected"
echo "  - Library chains: Traced"
echo "  - Carrier configs: Analyzed"
echo "  - Hidden interfaces: Searched"
echo "  - Kernel modules: Reviewed"
echo ""
echo "Next steps: Review findings and implement successful exploitation vectors"
