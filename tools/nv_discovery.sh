#!/bin/sh
# Comprehensive NV item discovery and write capability testing
# Tests all NV items 0-20000, detects read/write/protected patterns
# Searches filesystem for alternative tools and hidden programs

REPORT="/tmp/nv_discovery_$(date +%s).txt"
BINDIR="/opt/nvtl/bin"
LIBDIR="/opt/nvtl/lib"

echo "=== COMPREHENSIVE NV ITEM DISCOVERY ===" | tee "$REPORT"
echo "Time: $(date)" | tee -a "$REPORT"
echo "Scan range: NV 0-20000" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

# 1. AGGRESSIVE NV SCAN - All items 0-20000
echo "=== PHASE 1: AGGRESSIVE NV ITEM SCAN (0-20000) ===" | tee -a "$REPORT"
echo "$(date '+%H:%M:%S'): Starting NV enumeration..." | tee -a "$REPORT"

READABLE=0
WRITABLE=0
PROTECTED=0
ERRORS=0
UNRESPONSIVE=0

READABLES_FILE="/tmp/readable_nv_items.txt"
PROTECTED_FILE="/tmp/protected_nv_items.txt"
ERRORS_FILE="/tmp/error_nv_items.txt"

> "$READABLES_FILE"
> "$PROTECTED_FILE"
> "$ERRORS_FILE"

# Scan every 100th item first (faster pass)
for NV_ID in $(seq 0 100 20000); do
  RESULT=$($BINDIR/nwcli qmi_idl read_nv $NV_ID 0 2>&1 | head -1)
  
  if echo "$RESULT" | grep -q "^[0-9a-f]"; then
    echo "$NV_ID" >> "$READABLES_FILE"
    READABLE=$((READABLE + 1))
  elif echo "$RESULT" | grep -q "8193"; then
    echo "$NV_ID" >> "$PROTECTED_FILE"
    PROTECTED=$((PROTECTED + 1))
  elif echo "$RESULT" | grep -q "error\|Error\|ERROR"; then
    echo "$NV_ID" >> "$ERRORS_FILE"
    ERRORS=$((ERRORS + 1))
  else
    UNRESPONSIVE=$((UNRESPONSIVE + 1))
  fi
done

echo "$(date '+%H:%M:%S'): Fast pass complete" | tee -a "$REPORT"
echo "  Readable: $READABLE, Protected: $PROTECTED, Errors: $ERRORS, Unresponsive: $UNRESPONSIVE" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

# Now zoom into readable ranges for detailed scan
echo "=== PHASE 2: DETAILED SCAN OF READABLE RANGES ===" | tee -a "$REPORT"

while IFS= read -r BASE_ID; do
  START=$((BASE_ID - 50))
  [ $START -lt 0 ] && START=0
  END=$((BASE_ID + 50))
  
  for NV_ID in $(seq $START 1 $END); do
    RESULT=$($BINDIR/nwcli qmi_idl read_nv $NV_ID 0 2>&1 | head -1)
    
    if echo "$RESULT" | grep -q "^[0-9a-f]"; then
      if ! grep -q "^$NV_ID$" "$READABLES_FILE"; then
        echo "$NV_ID" >> "$READABLES_FILE"
        READABLE=$((READABLE + 1))
      fi
    fi
  done
done < "$PROTECTED_FILE" 2>/dev/null

echo "$(date '+%H:%M:%S'): Detailed pass complete" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

# 3. TEST WRITE CAPABILITY ON READABLE ITEMS
echo "=== PHASE 3: WRITE CAPABILITY TESTING ===" | tee -a "$REPORT"
echo "Testing first 50 readable NV items for write access..." | tee -a "$REPORT"

TEST_COUNT=0
while IFS= read -r NV_ID; do
  if [ $TEST_COUNT -ge 50 ]; then
    break
  fi
  
  # Read current value
  ORIG=$($BINDIR/nwcli qmi_idl read_nv $NV_ID 0 2>&1 | head -1)
  
  # Try to write dummy value
  echo -n -e '\x00' > /tmp/nv_test.bin 2>/dev/null
  WRITE_RESULT=$($BINDIR/nwcli qmi_idl write_nv $NV_ID 0 /tmp/nv_test.bin 2>&1)
  
  if echo "$WRITE_RESULT" | grep -q "success"; then
    echo "  ✓ NV $NV_ID: WRITABLE" | tee -a "$REPORT"
    WRITABLE=$((WRITABLE + 1))
    
    # Restore original
    echo -n "$ORIG" > /tmp/nv_restore.bin 2>/dev/null
    $BINDIR/nwcli qmi_idl write_nv $NV_ID 0 /tmp/nv_restore.bin 2>/dev/null
  elif echo "$WRITE_RESULT" | grep -q "8193\|error"; then
    echo "  ✗ NV $NV_ID: READ-ONLY (error in write)" | tee -a "$REPORT"
  fi
  
  TEST_COUNT=$((TEST_COUNT + 1))
done < "$READABLES_FILE"

echo "" | tee -a "$REPORT"

# 4. LIST ALL DISCOVERED ITEMS
echo "=== DISCOVERED READABLE NV ITEMS ===" | tee -a "$REPORT"
sort -n "$READABLES_FILE" | head -100 | tr '\n' ',' | tee -a "$REPORT"
echo "" | tee -a "$REPORT"
echo "Total readable: $(wc -l < "$READABLES_FILE")" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

# 5. FILESYSTEM EXPLORATION FOR ALTERNATIVE TOOLS
echo "=== PHASE 4: FILESYSTEM EXPLORATION ===" | tee -a "$REPORT"

# Find all executables in /opt/nvtl/bin
echo "=== All /opt/nvtl/bin executables ===" | tee -a "$REPORT"
ls -la /opt/nvtl/bin 2>/dev/null | grep -v '^d' | awk '{print $NF}' | sort | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

# Find programs with "nv", "eeprom", "config" in name
echo "=== Programs related to NV/EEPROM/CONFIG ===" | tee -a "$REPORT"
find / -type f -name "*nv*" -o -name "*eeprom*" -o -name "*config*" 2>/dev/null | grep -E "^/(opt|sbin|usr/sbin|bin|usr/bin)" | head -50 | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

# Find shell scripts that might contain NV operations
echo "=== Shell scripts with QMI/NV operations ===" | tee -a "$REPORT"
grep -r "read_nv\|write_nv\|qmi_idl" /opt/nvtl 2>/dev/null | head -20 | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

# 6. LIBRARY ANALYSIS
echo "=== PHASE 5: LIBRARY ANALYSIS ===" | tee -a "$REPORT"
echo "=== Functions in libmodem2_api.so ===" | tee -a "$REPORT"
strings /opt/nvtl/lib/libmodem2_api.so 2>/dev/null | grep -E "^(nv|nwqmi|qmi|write|read)" | sort | uniq | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

echo "=== Functions in libmal_qct.so ===" | tee -a "$REPORT"
strings /opt/nvtl/lib/libmal_qct.so 2>/dev/null | grep -E "^(nv|nwqmi|qmi|write|read)" | sort | uniq | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

# 7. MODEM2_CLI ADVANCED DISCOVERY
echo "=== PHASE 6: MODEM2_CLI COMMAND DISCOVERY ===" | tee -a "$REPORT"
$BINDIR/modem2_cli help 2>&1 | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

# 8. NV ITEM VALUE PATTERNS
echo "=== PHASE 7: SAMPLE NV ITEM VALUES ===" | tee -a "$REPORT"

head -50 "$READABLES_FILE" | while read NV_ID; do
  RESULT=$($BINDIR/nwcli qmi_idl read_nv $NV_ID 0 2>&1 | head -1)
  VALUE=$(echo "$RESULT" | sed 's/ //g' | cut -c1-32)
  echo "NV $NV_ID: $VALUE" | tee -a "$REPORT"
done

echo "" | tee -a "$REPORT"

# 9. CHECK FOR SPECIAL ACCESS MECHANISMS
echo "=== PHASE 8: SPECIAL ACCESS MECHANISMS ===" | tee -a "$REPORT"

# Check if diag mode is available
if [ -w "/dev/diag" ]; then
  echo "✓ DIAG device writable" | tee -a "$REPORT"
else
  echo "✗ DIAG device not writable" | tee -a "$REPORT"
fi

# Check AT ports
for PORT in /dev/at_mdm0 /dev/at_usb0 /dev/at_usb1; do
  if [ -w "$PORT" ]; then
    echo "✓ $PORT writable" | tee -a "$REPORT"
  else
    echo "✗ $PORT not writable" | tee -a "$REPORT"
  fi
done

echo "" | tee -a "$REPORT"

# 10. ROOT-ONLY PATHS
echo "=== PHASE 9: ROOT-ONLY OPERATIONS ===" | tee -a "$REPORT"
echo "User: $(id)" | tee -a "$REPORT"
echo "Mounted filesystems:" | tee -a "$REPORT"
mount 2>&1 | grep -E "^/dev|^tmpfs" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

# 11. PERSISTENCE PATHS
echo "=== PERSISTENCE PATHS ===" | tee -a "$REPORT"
ls -la /root 2>/dev/null | tee -a "$REPORT"
ls -la /data 2>/dev/null | tee -a "$REPORT"
ls -la /persist 2>/dev/null | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

echo "=== DISCOVERY COMPLETE ===" | tee -a "$REPORT"
echo "Report: $REPORT" | tee -a "$REPORT"
