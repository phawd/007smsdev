#!/bin/sh
# Alternate Program Discovery - Find hidden/non-standard named utilities

echo "=== ALTERNATE PROGRAM DISCOVERY ==="
echo "Started: $(date)"
echo ""

# Phase 1: Standard tools in /opt/nvtl/bin/
echo "=== PHASE 1: STANDARD TOOLS ==="
ls -la /opt/nvtl/bin/ 2>/dev/null | grep -v "^total\|^d" | awk '{print $NF}' | sort

echo ""
echo "=== PHASE 2: HIDDEN/ALTERNATE NAMING PATTERNS ==="

# Single character programs
echo "Single-character executables:"
find /opt/nvtl/bin/ /usr/bin/ /bin/ 2>/dev/null -maxdepth 1 -type f -executable | xargs -I {} basename {} | grep -E '^[a-z]$' 2>/dev/null | sort -u || echo "  (none found or errors)"

# Programs with numbers
echo ""
echo "Programs with numbers in name:"
find /opt/nvtl/bin/ /usr/bin/ /bin/ 2>/dev/null -maxdepth 1 -type f -executable | xargs -I {} basename {} | grep '[0-9]' 2>/dev/null | sort -u || echo "  (none found or errors)"

# Programs with underscores
echo ""
echo "Programs with underscores (internal tools):"
find /opt/nvtl/bin/ /usr/bin/ /bin/ 2>/dev/null -maxdepth 1 -type f -executable | xargs -I {} basename {} | grep '_' 2>/dev/null | sort -u || echo "  (none found or errors)"

echo ""
echo "=== PHASE 3: DEVICE FILES THAT MIGHT PROVIDE ACCESS ==="
echo "Modem/AT devices:"
ls -la /dev/at_* /dev/smd* /dev/diag /dev/ttyHS* 2>/dev/null || echo "  (not all devices present)"

echo ""
echo "=== PHASE 4: FIRMWARE & FLASH TOOLS ==="
echo "Looking for firmware update/flash utilities..."
find /opt /usr /bin 2>/dev/null -type f -name '*fota*' -o -name '*flash*' -o -name '*firmware*' 2>/dev/null | head -10 || echo "  (none found in standard locations)"

echo ""
echo "=== PHASE 5: LIBRARY ANALYSIS ==="
echo "Libraries related to NV/QMI/DIAG access:"
find /opt/nvtl/lib* /usr/lib* /lib* 2>/dev/null -type f -name '*.so*' | grep -E 'qmi|nv|diag|sms|modem' 2>/dev/null | head -15 || echo "  (limited library info available)"

echo ""
echo "=== PHASE 6: RUNNING PROCESSES USING MODEM/NV ==="
ps aux 2>/dev/null | head -20

echo ""
echo "=== PHASE 7: IPC MECHANISMS ==="
echo "Unix sockets in system:"
find /tmp /var /run 2>/dev/null -type s 2>/dev/null | head -10 || echo "  (socket info limited)"

echo ""
echo "=== PHASE 8: EFS ACCESSIBILITY TEST ==="
echo "Testing EFS path read capability..."
/opt/nvtl/bin/nwcli qmi_idl read_file /tmp/test_efs.bin /policyman/device_config.xml 1024 2>&1 | head -5 && echo "EFS read: POSSIBLE" || echo "EFS read: PROTECTED"

echo ""
echo "=== PHASE 9: CONFIGURATION FILES ==="
echo "System configuration that might contain NV hints:"
ls -la /sysconf/ 2>/dev/null || echo "  (sysconf directory not found)"
ls -la /etc/ 2>/dev/null | grep -i modem | head -10

echo ""
echo "Completed: $(date)"
