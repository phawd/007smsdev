#!/bin/sh
# Continuous SMS listener and logger for ZeroSMS testing
# Monitors incoming SMS and logs with detailed metadata
# Usage: adb push sms_listener.sh /tmp && adb shell sh /tmp/sms_listener.sh

LOGFILE="/tmp/sms_listener_$(date +%s).log"
CHECK_INTERVAL=2  # seconds
SESSION_START=$(date '+%H:%M:%S')

echo "=== SMS LISTENER STARTED ===" | tee "$LOGFILE"
echo "Start time: $SESSION_START" | tee -a "$LOGFILE"
echo "Log file: $LOGFILE" | tee -a "$LOGFILE"
echo "Check interval: ${CHECK_INTERVAL}s" | tee -a "$LOGFILE"
echo "" | tee -a "$LOGFILE"

LAST_COUNT=0
TOTAL_RECEIVED=0

while true; do
  CURRENT_TIME=$(date '+%H:%M:%S')
  
  # Check inbox for new messages
  SMS_OUTPUT=$(/opt/nvtl/bin/sms_cli get_list 1 2>&1)
  CURRENT_COUNT=$(echo "$SMS_OUTPUT" | grep "count:\[" | sed 's/.*count:\[\([0-9]*\)\].*/\1/')
  
  if [ -z "$CURRENT_COUNT" ]; then
    CURRENT_COUNT=0
  fi
  
  # If count increased, fetch new messages
  if [ "$CURRENT_COUNT" -gt "$LAST_COUNT" ]; then
    NEW_MSGS=$((CURRENT_COUNT - LAST_COUNT))
    TOTAL_RECEIVED=$((TOTAL_RECEIVED + NEW_MSGS))
    
    echo "[$CURRENT_TIME] ✓ RECEIVED $NEW_MSGS new message(s) (total: $TOTAL_RECEIVED, inbox: $CURRENT_COUNT)" | tee -a "$LOGFILE"
    
    # Extract and log each message
    MSG_ID=1
    while [ $MSG_ID -le $CURRENT_COUNT ]; do
      echo "" | tee -a "$LOGFILE"
      echo "--- Message $MSG_ID ---" | tee -a "$LOGFILE"
      /opt/nvtl/bin/sms_cli read $MSG_ID 2>&1 >> "$LOGFILE"
      MSG_ID=$((MSG_ID + 1))
    done
    
    echo "" | tee -a "$LOGFILE"
  fi
  
  LAST_COUNT=$CURRENT_COUNT
  sleep $CHECK_INTERVAL
done
