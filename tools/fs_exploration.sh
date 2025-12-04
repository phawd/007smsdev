#!/bin/sh
# Deep filesystem exploration for NV/EFS hints, undocumented programs, and capabilities
# Searches entire device for clues about NV item access, configuration, and hidden tools

REPORT="/tmp/fs_exploration_$(date +%s).txt"

echo "=== DEEP FILESYSTEM EXPLORATION ===" | tee "$REPORT"
echo "Time: $(date)" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

# 1. BINARY DISCOVERY
echo "=== PHASE 1: EXECUTABLE DISCOVERY ===" | tee -a "$REPORT"

echo "=== All executables in common paths ===" | tee -a "$REPORT"
for DIR in /bin /sbin /usr/bin /usr/sbin /opt/nvtl/bin; do
  if [ -d "$DIR" ]; then
    echo "=== $DIR ===" | tee -a "$REPORT"
    ls -1 "$DIR" 2>/dev/null | sort | tee -a "$REPORT"
    echo "" | tee -a "$REPORT"
  fi
done

# 2. PROGRAM FINGERPRINTING
echo "=== PHASE 2: PROGRAM FINGERPRINTING ===" | tee -a "$REPORT"

# Find programs containing "qmi" or "modem" strings
echo "=== Programs with modem/QMI functions ===" | tee -a "$REPORT"
for PROG in /opt/nvtl/bin/* /bin/* /sbin/*; do
  if [ -f "$PROG" ] && [ -x "$PROG" ]; then
    if strings "$PROG" 2>/dev/null | grep -q -E "qmi_idl|nwcli|modem2_cli|nv_write|nv_read"; then
      echo "$PROG" | tee -a "$REPORT"
    fi
  fi
done

echo "" | tee -a "$REPORT"

# 3. CONFIGURATION FILE DISCOVERY
echo "=== PHASE 3: CONFIGURATION FILES ===" | tee -a "$REPORT"

echo "=== XML/Config files (potential NV hints) ===" | tee -a "$REPORT"
find /opt/nvtl/etc /sysconf /etc 2>/dev/null -name "*.xml" -o -name "*.conf" -o -name "*.config" | head -50 | tee -a "$REPORT"

echo "" | tee -a "$REPORT"

echo "=== Content of /sysconf/features.xml ===" | tee -a "$REPORT"
cat /sysconf/features.xml 2>/dev/null | tee -a "$REPORT"

echo "" | tee -a "$REPORT"

echo "=== Content of /sysconf/settings.xml ===" | tee -a "$REPORT"
cat /sysconf/settings.xml 2>/dev/null | tee -a "$REPORT"

echo "" | tee -a "$REPORT"

# 4. LIBRARY INVENTORY
echo "=== PHASE 4: LIBRARY ANALYSIS ===" | tee -a "$REPORT"

echo "=== All .so libraries in /opt/nvtl/lib ===" | tee -a "$REPORT"
ls -lh /opt/nvtl/lib/*.so 2>/dev/null | awk '{print $NF, $5}' | tee -a "$REPORT"

echo "" | tee -a "$REPORT"

# 5. STRING EXTRACTION FOR NV PATTERNS
echo "=== PHASE 5: NV/EEPROM PATTERN DISCOVERY ===" | tee -a "$REPORT"

echo "=== Strings containing 'NV', 'EFS', 'NVITEM' ===" | tee -a "$REPORT"
for LIB in /opt/nvtl/lib/libmal_qct.so /opt/nvtl/lib/libmodem2_api.so; do
  strings "$LIB" 2>/dev/null | grep -i "nv\|efs\|nvitem\|eeprom" | head -30
done | sort | uniq | tee -a "$REPORT"

echo "" | tee -a "$REPORT"

# 6. ERROR MESSAGE DISCOVERY
echo "=== PHASE 6: ERROR/DEBUG MESSAGES ===" | tee -a "$REPORT"

echo "=== Error codes in binaries ===" | tee -a "$REPORT"
strings /opt/nvtl/bin/modem2_cli 2>/dev/null | grep -E "error|Error|ERROR|failed|FAILED" | head -30 | tee -a "$REPORT"

echo "" | tee -a "$REPORT"

# 7. INIT SCRIPTS AND STARTUP CLUES
echo "=== PHASE 7: INIT/STARTUP SCRIPTS ===" | tee -a "$REPORT"

echo "=== Init scripts in /etc/init.d ===" | tee -a "$REPORT"
ls -la /etc/init.d 2>/dev/null | tee -a "$REPORT"

echo "" | tee -a "$REPORT"

echo "=== Relevant rcS scripts ===" | tee -a "$REPORT"
find / -name "rcS*" -o -name "rc.local" 2>/dev/null | head -20 | xargs cat 2>/dev/null | grep -E "modem|nv|qmi" | tee -a "$REPORT"

echo "" | tee -a "$REPORT"

# 8. MOUNT AND PARTITION INFO
echo "=== PHASE 8: STORAGE TOPOLOGY ===" | tee -a "$REPORT"

echo "=== MTD partitions ===" | tee -a "$REPORT"
cat /proc/mtd 2>/dev/null | tee -a "$REPORT"

echo "" | tee -a "$REPORT"

echo "=== Mounted filesystems ===" | tee -a "$REPORT"
mount 2>/dev/null | tee -a "$REPORT"

echo "" | tee -a "$REPORT"

# 9. DEVICE NODES
echo "=== PHASE 9: DEVICE NODES ===" | tee -a "$REPORT"

echo "=== Character devices related to modem ===" | tee -a "$REPORT"
ls -la /dev/at* /dev/smd* /dev/tty* /dev/diag* 2>/dev/null | tee -a "$REPORT"

echo "" | tee -a "$REPORT"

# 10. RUNNING PROCESS ANALYSIS
echo "=== PHASE 10: PROCESS ANALYSIS ===" | tee -a "$REPORT"

echo "=== Daemons and services ===" | tee -a "$REPORT"
ps aux 2>/dev/null | grep -E "modem|qmi|nv|sms" | tee -a "$REPORT"

echo "" | tee -a "$REPORT"

echo "=== Network sockets and connections ===" | tee -a "$REPORT"
netstat -tpln 2>/dev/null || ss -tpln 2>/dev/null | head -30 | tee -a "$REPORT"

echo "" | tee -a "$REPORT"

# 11. ENVIRONMENT VARIABLES
echo "=== PHASE 11: ENVIRONMENT CLUES ===" | tee -a "$REPORT"

echo "=== Environment variables ===" | tee -a "$REPORT"
env 2>/dev/null | sort | tee -a "$REPORT"

echo "" | tee -a "$REPORT"

# 12. BOOT LOGS AND DMESG
echo "=== PHASE 12: KERNEL MESSAGES ===" | tee -a "$REPORT"

echo "=== Recent dmesg (modem/QMI related) ===" | tee -a "$REPORT"
dmesg 2>/dev/null | grep -i -E "modem|qmi|smd|diag" | tail -50 | tee -a "$REPORT"

echo "" | tee -a "$REPORT"

# 13. CAPABILITY FLAGS
echo "=== PHASE 13: DEVICE CAPABILITIES ===" | tee -a "$REPORT"

echo "=== /proc/cpuinfo ===" | tee -a "$REPORT"
cat /proc/cpuinfo 2>/dev/null | tee -a "$REPORT"

echo "" | tee -a "$REPORT"

echo "=== /proc/version ===" | tee -a "$REPORT"
cat /proc/version 2>/dev/null | tee -a "$REPORT"

echo "" | tee -a "$REPORT"

# 14. HIDDEN/SYMLINK DETECTION
echo "=== PHASE 14: SYMLINKS AND ALTERNATE PATHS ===" | tee -a "$REPORT"

echo "=== Symlinks in /opt/nvtl/bin ===" | tee -a "$REPORT"
find /opt/nvtl/bin -type l 2>/dev/null | xargs ls -la 2>/dev/null | tee -a "$REPORT"

echo "" | tee -a "$REPORT"

# 15. SUID/CAPABILITY FILES
echo "=== PHASE 15: PRIVILEGE ESCALATION VECTORS ===" | tee -a "$REPORT"

echo "=== SUID binaries ===" | tee -a "$REPORT"
find / -perm -4000 2>/dev/null | head -30 | tee -a "$REPORT"

echo "" | tee -a "$REPORT"

echo "=== EXPLORATION COMPLETE ===" | tee -a "$REPORT"
echo "Report: $REPORT" | tee -a "$REPORT"
