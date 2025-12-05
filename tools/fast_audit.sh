#!/bin/sh
# Fast forensic audit - non-blocking version
# Outputs results directly to stdout

REPORT="/tmp/fast_audit_$(date +%s).txt"

echo "=== FAST NV/QUALCOMM FORENSIC AUDIT ===" | tee "$REPORT"
echo "Time: $(date)" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

# Quick: Sample 30 key NV items
echo "=== NV ITEM SAMPLE (30 items) ===" | tee -a "$REPORT"
for NV_ID in 0 1 5 10 50 100 200 300 400 441 550 553 600 946 947 1000 1015 1016 2954 3000 3461 4000 4399 4500 6000 6828 6830 7000 9000 10000; do
  RESULT=$(/opt/nvtl/bin/nwcli qmi_idl read_nv $NV_ID 0 2>&1 | head -1)
  if echo "$RESULT" | grep -q "^[0-9a-f]"; then
    echo "  NV $NV_ID: $RESULT" | tee -a "$REPORT"
  elif echo "$RESULT" | grep -q "8193"; then
    echo "  NV $NV_ID: PROTECTED" | tee -a "$REPORT"
  else
    echo "  NV $NV_ID: ERROR" | tee -a "$REPORT"
  fi
done

echo "" | tee -a "$REPORT"

# Device NV items
echo "=== DEVICE NV ITEMS ===" | tee -a "$REPORT"
for ITEM in NW_NV_MAC_ID_I NW_NV_USB_MAC_ID_I NW_NV_PRI_INFORMATION_I NW_NV_LINUX_ROOT_PASSWORD_I; do
  RESULT=$(/opt/nvtl/bin/nwnvitem -r -e "$ITEM" 2>&1)
  echo "  $ITEM: $RESULT" | tee -a "$REPORT"
done

echo "" | tee -a "$REPORT"

# Modem state
echo "=== MODEM STATE ===" | tee -a "$REPORT"
/opt/nvtl/bin/modem2_cli get_state 2>&1 | head -20 | tee -a "$REPORT"

echo "" | tee -a "$REPORT"

# Carrier unlock
echo "=== CARRIER LOCK ===" | tee -a "$REPORT"
/opt/nvtl/bin/modem2_cli get_carrier_unlock 2>&1 | tee -a "$REPORT"

echo "" | tee -a "$REPORT"

# SMS Database
echo "=== SMS DATABASE ===" | tee -a "$REPORT"
for FOLDER in 0 1 2 3; do
  NAME="Unknown"
  [ $FOLDER -eq 1 ] && NAME="Inbox"
  [ $FOLDER -eq 3 ] && NAME="Sent"
  COUNT=$(/opt/nvtl/bin/sms_cli get_list $FOLDER 2>&1 | grep "count:\[" | sed 's/.*count:\[\([0-9]*\)\].*/\1/')
  echo "  $NAME ($FOLDER): $COUNT messages" | tee -a "$REPORT"
done

echo "" | tee -a "$REPORT"
echo "Report: $REPORT" | tee -a "$REPORT"
