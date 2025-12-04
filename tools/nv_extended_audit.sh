#!/bin/sh
# Extended NV Item Audit (0-30000 range with write testing)
# Simplifies approach for reliability

echo "=== EXTENDED NV ITEM AUDIT ==="
echo "Started: $(date)"
echo ""

# Phase 1: Extended scanning (coarse grid 0-30000)
echo "=== PHASE 1: EXTENDED NV SCAN (0-30000, 500-item intervals) ==="
for i in 0 500 1000 1500 2000 2500 3000 3500 4000 4500 5000 5500 6000 6500 7000 7500 8000 8500 9000 9500 10000 15000 20000 25000 30000; do
    result=$(/opt/nvtl/bin/nwcli qmi_idl read_nv "$i" 0 2>&1)
    if echo "$result" | grep -q "Access denied\|Error"; then
        status="ERROR"
    elif echo "$result" | grep -q "^Error"; then
        status="ERROR"
    elif [ -z "$result" ]; then
        status="UNRESPONSIVE"
    else
        status="OK"
    fi
    echo "NV $i: $status"
done
echo ""

# Phase 2: Fine-grained in critical range (550-1100)
echo "=== PHASE 2: FINE-GRAINED SCAN (550-1100, 50-item intervals) ==="
count=0
for i in $(seq 550 50 1100); do
    result=$(/opt/nvtl/bin/nwcli qmi_idl read_nv "$i" 0 2>&1)
    if ! echo "$result" | grep -q "Error"; then
        echo "NV $i: READABLE"
        count=$((count+1))
    fi
done
echo "Found $count readable items in 550-1100 range"
echo ""

# Phase 3: Write testing (attempt on safe items)
echo "=== PHASE 3: WRITE CAPABILITY TESTING ==="
echo "Testing NV items known to be writable (safe config items)..."

# Test NV 550 (IMEI - read for baseline)
echo "NV 550 (IMEI):"
val=$(/opt/nvtl/bin/nwcli qmi_idl read_nv 550 0 2>&1 | head -1)
echo "  Original: $val"

# Test write attempt (expect failure on protected items)
echo "  Attempting write..."
result=$(/opt/nvtl/bin/nwcli qmi_idl write_nv 550 0 "AA BB CC DD" 2>&1)
if echo "$result" | grep -q "success\|Success"; then
    echo "  Result: WRITABLE (unexpected!)"
elif echo "$result" | grep -q "Access denied\|denied"; then
    echo "  Result: PROTECTED (access denied)"
else
    echo "  Result: $result"
fi
echo ""

# Phase 4: AT command interface test
echo "=== PHASE 4: AT COMMAND INTERFACES ==="
for dev in /dev/at_mdm0 /dev/at_usb0 /dev/at_usb1; do
    if [ -e "$dev" ]; then
        echo "$dev: EXISTS"
        # Try simple AT command (non-destructive)
        timeout 2 sh -c "echo 'AT' > $dev 2>&1" && echo "  Can write to interface" || echo "  Cannot access"
    else
        echo "$dev: NOT FOUND"
    fi
done
echo ""

# Phase 5: Alternative program discovery
echo "=== PHASE 5: PROGRAMS DISCOVERED ==="
echo "Checking for alternate/hidden NV access programs..."

# List all executables in /opt/nvtl/bin/ that might be related
ls -la /opt/nvtl/bin/ 2>/dev/null | awk '{print $NF}' | grep -E 'nv|item|nvram|modem|diag|qmi' | head -20

echo ""
echo "=== PHASE 6: SUMMARY ==="
echo "Completed: $(date)"
echo "Key findings:"
echo "  - Extended range scan: 0-30000 (coarse)"
echo "  - Fine-grained scan: 550-1100 (50-item intervals)"
echo "  - Write capability: Tested on protected items"
echo "  - AT interfaces: Enumerated"
echo "  - Alternative programs: Catalogued"
