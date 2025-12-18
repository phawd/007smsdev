#!/bin/sh
# Automatic Type 0 Silent SMS (PID=0x40) sender for SMS Test testing
# Usage: adb push auto_type0_sms.sh /tmp && adb shell sh /tmp/auto_type0_sms.sh [iterations]

ITERATIONS=${1:-10}
TARGET="+15042147419"
# Type 0 Silent SMS PDU: PID=0x40 (no user display)
# 00 = SMS-SUBMIT
# 11 = no reply path, validity period format
# 00 = message reference 0
# 0B 91 51 40 12 74 14 F9 = destination +15042147419
# 40 = protocol id 0x40 (Type 0 / Silent SMS)
# 00 = data coding scheme 0x00 (default GSM 7-bit)
# 01 = user data length 1
# 30 = message content "0"
PDU="0011000B915140127414F940000130"
PDU_LEN=14
SCADDR="+13123149810"
LOG="/tmp/type0_sms_$$.log"

echo "[$(date '+%H:%M:%S')] Starting Type 0 Silent SMS sender - $ITERATIONS messages to $TARGET" | tee "$LOG"

send_via_port() {
  PORT=$1
  ATTEMPT=$2
  
  if [ -w "$PORT" ] 2>/dev/null; then
    echo "[$(date '+%H:%M:%S')] Attempt $ATTEMPT: Using $PORT" | tee -a "$LOG"
    {
      echo "AT+CMGF=0"
      sleep 0.5
      echo "AT+CSCA=$SCADDR"
      sleep 0.5
      echo "AT+CMGS=$PDU_LEN"
      sleep 0.5
      printf "%s\x1A" "$PDU"
      sleep 2
    } > "$PORT" 2>&1
    RESULT=$?
    if [ $RESULT -eq 0 ]; then
      echo "[$(date '+%H:%M:%S')] Message $ATTEMPT sent successfully to $PORT" | tee -a "$LOG"
      return 0
    fi
  fi
  return 1
}

for i in $(seq 1 $ITERATIONS); do
  SENT=0
  
  # Try each AT port in priority order
  for PORT in /dev/at_usb1 /dev/at_usb0 /dev/at_mdm0 /dev/smd11; do
    if send_via_port "$PORT" "$i"; then
      SENT=1
      break
    fi
  done
  
  if [ $SENT -eq 0 ]; then
    echo "[$(date '+%H:%M:%S')] Message $i: No AT port available" | tee -a "$LOG"
  fi
  
  sleep 1
done

echo "[$(date '+%H:%M:%S')] Complete. Log: $LOG" | tee -a "$LOG"
