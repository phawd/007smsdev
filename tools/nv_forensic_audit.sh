#!/bin/sh
# Comprehensive NV/EFS forensic audit for MiFi device
# Usage: adb push nv_forensic_audit.sh /tmp && adb shell sh /tmp/nv_forensic_audit.sh

REPORT="/tmp/nv_forensic_audit_$(date +%s).txt"
BINDIR="/opt/nvtl/bin"

echo "=== NV/EFS FORENSIC AUDIT ===" > "$REPORT"
echo "Date: $(date)" >> "$REPORT"
echo "Device: $(cat /proc/version)" >> "$REPORT"
echo "" >> "$REPORT"

# 1. FULL NV ITEM SCAN (0-10000)
echo "=== SCANNING ALL NV ITEMS (0-10000) ===" >> "$REPORT"
echo "$(date '+%H:%M:%S'): Starting NV item enumeration..."

READABLE=0
PROTECTED=0
ERRORS=0

for NV_ID in 0 1 2 3 4 5 10 50 100 200 300 400 441 500 550 553 600 700 800 900 946 947 1000 1015 1016 1500 2000 2954 3000 3461 3500 4000 4399 4500 5000 6000 6828 6830 7000 8000 9000 10000; do
  RESULT=$($BINDIR/nwcli qmi_idl read_nv $NV_ID 0 2>&1)
  
  if echo "$RESULT" | grep -q "^[0-9a-f]*$"; then
    echo "NV $NV_ID (READABLE): $RESULT" >> "$REPORT"
    READABLE=$((READABLE + 1))
  elif echo "$RESULT" | grep -q "8193"; then
    echo "NV $NV_ID (PROTECTED - 8193)" >> "$REPORT"
    PROTECTED=$((PROTECTED + 1))
  elif echo "$RESULT" | grep -q "error\|Error\|ERROR"; then
    echo "NV $NV_ID (ERROR): $(echo "$RESULT" | head -1)" >> "$REPORT"
    ERRORS=$((ERRORS + 1))
  fi
done

echo "" >> "$REPORT"
echo "NV Scan Summary: Readable=$READABLE Protected=$PROTECTED Errors=$ERRORS" >> "$REPORT"
echo "" >> "$REPORT"

# 2. ALL DEVICE NV ITEMS (nwnvitem)
echo "=== DEVICE NV ITEMS (via nwnvitem) ===" >> "$REPORT"

ITEMS="NW_NV_MAC_ID_I NW_NV_MAC_ID_2_I NW_NV_USB_MAC_ID_I NW_NV_ETHERNET_MAC_ID_I NW_NV_PRI_INFORMATION_I NW_NV_USB_DEFAULT_MODE_I NW_NV_PSM_DEFAULT_MODE_I NW_NV_LINUX_RUN_LEVEL_I NW_NV_LINUX_ROOT_PASSWORD_I NV_AUTO_POWER_I"

for ITEM in $ITEMS; do
  RESULT=$(/opt/nvtl/bin/nwnvitem -r -e "$ITEM" 2>&1)
  if [ $? -eq 0 ]; then
    echo "$ITEM: $RESULT" >> "$REPORT"
  else
    echo "$ITEM: (error)" >> "$REPORT"
  fi
done

echo "" >> "$REPORT"

# 3. EFS FILE SYSTEM AUDIT
echo "=== EFS PATHS FORENSIC SCAN ===" >> "$REPORT"

# Extract all EFS paths from library strings
echo "$(date '+%H:%M:%S'): Extracting EFS paths from libraries..."
EFSPATHS=$(/system/bin/strings /opt/nvtl/lib/libmal_qct.so /opt/nvtl/lib/libmodem2_api.so 2>/dev/null | grep -E "^/nv|^/efs|^/policyman" | sort -u)

echo "Found $(echo "$EFSPATHS" | wc -l) potential EFS paths:" >> "$REPORT"
echo "$EFSPATHS" >> "$REPORT"
echo "" >> "$REPORT"

# Test each path
echo "Testing EFS paths for accessibility:" >> "$REPORT"

for PATH in $EFSPATHS; do
  RESULT=$($BINDIR/nwcli qmi_idl read_file /tmp/efs_test.bin "$PATH" 4096 2>&1)
  if echo "$RESULT" | grep -q "success"; then
    SIZE=$(ls -la /tmp/efs_test.bin 2>/dev/null | awk '{print $5}')
    echo "  ✓ $PATH (readable, size=$SIZE)" >> "$REPORT"
  else
    echo "  ✗ $PATH (error: $(echo "$RESULT" | grep -E "error|Error" | head -1))" >> "$REPORT"
  fi
done

echo "" >> "$REPORT"

# 4. MODEM2_CLI COMMAND ENUMERATION
echo "=== MODEM2_CLI COMMANDS ===" >> "$REPORT"

$BINDIR/modem2_cli help 2>&1 | head -200 >> "$REPORT"

echo "" >> "$REPORT"

# 5. LIBRARY FUNCTION EXTRACTION
echo "=== QUALCOMM LIBRARY FUNCTIONS ===" >> "$REPORT"
echo "libmal_qct.so functions:" >> "$REPORT"
/system/bin/strings /opt/nvtl/lib/libmal_qct.so 2>/dev/null | grep -E "nwqmi|wms|qmi" | head -50 >> "$REPORT"

echo "" >> "$REPORT"
echo "libmodem2_api.so functions:" >> "$REPORT"
/system/bin/strings /opt/nvtl/lib/libmodem2_api.so 2>/dev/null | grep -E "modem|radio|signal|tech" | head -50 >> "$REPORT"

echo "" >> "$REPORT"

# 6. SYSTEM MODEM CONFIGURATION
echo "=== CURRENT MODEM STATE ===" >> "$REPORT"

echo "Info:" >> "$REPORT"
$BINDIR/modem2_cli get_info 2>&1 >> "$REPORT"

echo "" >> "$REPORT"
echo "State:" >> "$REPORT"
$BINDIR/modem2_cli get_state 2>&1 >> "$REPORT"

echo "" >> "$REPORT"
echo "Signal:" >> "$REPORT"
$BINDIR/modem2_cli get_signal 2>&1 >> "$REPORT"

echo "" >> "$REPORT"
echo "Enabled Tech:" >> "$REPORT"
$BINDIR/modem2_cli enabled_tech_get 2>&1 >> "$REPORT"

echo "" >> "$REPORT"

# 7. SMS DATABASE
echo "=== SMS DATABASE STATE ===" >> "$REPORT"

for FOLDER in 0 1 2 3; do
  FOLDER_NAME="Unknown"
  [ $FOLDER -eq 0 ] && FOLDER_NAME="PreInbox"
  [ $FOLDER -eq 1 ] && FOLDER_NAME="Inbox"
  [ $FOLDER -eq 2 ] && FOLDER_NAME="Outbox"
  [ $FOLDER -eq 3 ] && FOLDER_NAME="Sent"
  
  echo "=== $FOLDER_NAME ===" >> "$REPORT"
  $BINDIR/sms_cli get_list $FOLDER 2>&1 | head -50 >> "$REPORT"
  echo "" >> "$REPORT"
done

# 8. USB/AT PORT STATUS
echo "=== USB/AT INTERFACE STATUS ===" >> "$REPORT"

for PORT in /dev/at_mdm0 /dev/at_usb0 /dev/at_usb1 /dev/smd7 /dev/smd8 /dev/smd11 /dev/diag; do
  if [ -e "$PORT" ]; then
    PERM=$(ls -la "$PORT" 2>/dev/null | awk '{print $1, $3, $4}')
    if [ -w "$PORT" ]; then
      echo "  ✓ $PORT (writable) $PERM" >> "$REPORT"
    else
      echo "  - $PORT (readable only) $PERM" >> "$REPORT"
    fi
  else
    echo "  ✗ $PORT (not found)" >> "$REPORT"
  fi
done

echo "" >> "$REPORT"

# 9. CARRIER LOCK STATUS
echo "=== CARRIER LOCK STATUS ===" >> "$REPORT"

$BINDIR/modem2_cli get_carrier_unlock 2>&1 >> "$REPORT"

echo "" >> "$REPORT"

# 10. BAND PREFERENCES
echo "=== LTE BAND STATUS ===" >> "$REPORT"

$BINDIR/modem2_cli lte_band_get_enabled 2>&1 >> "$REPORT"

echo "" >> "$REPORT"

# 11. EFS BAND PREFERENCE VERIFICATION
echo "=== EFS LTE_BANDPREF VERIFICATION ===" >> "$REPORT"

$BINDIR/nwcli qmi_idl read_file /tmp/bandpref_check.bin /nv/item_files/modem/mmode/lte_bandpref 8 2>&1 >> "$REPORT"
/system/bin/od -tx1 /tmp/bandpref_check.bin 2>&1 >> "$REPORT"

echo "" >> "$REPORT"
echo "=== AUDIT COMPLETE ===" >> "$REPORT"
echo "Report saved to: $REPORT" >> "$REPORT"

cat "$REPORT"
