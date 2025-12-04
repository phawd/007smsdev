#!/bin/sh

########################################################################
#
# USAGE:
#   Requires ADB access to a MiFi device (e.g., Inseego MiFi 8800L).
#   Deploy and run with:
#     adb push mifi_explorer.sh /tmp/ && adb shell sh /tmp/mifi_explorer.sh
#
# PREREQUISITES:
#   - ADB installed and device connected
#   - Device must be a MiFi running Linux (MiFiOS2)
#   - Sufficient permissions to run shell scripts via ADB
#
#
mkdir -p "$OUTPUT_DIR"
chmod 700 "$OUTPUT_DIR"
#   Run this script on a MiFi 8800L device (Linux-based) via ADB shell
#   or directly on the device. Example:
#     adb shell 'sh /path/to/mifi_explorer.sh'
#
# Prerequisites:
#   - Device must be a MiFi 8800L (or compatible Linux-based MiFi)
#   - ADB connectivity (if running remotely)
#   - Sufficient privileges (root recommended for full access)
#   - Required binaries: /opt/nvtl/bin/modem2_cli, /opt/nvtl/bin/usb_cli
#
# Output:
#   - All collected information is saved to /tmp/mifi_catalog/catalog.txt
#
# WARNING:
if command -v /opt/nvtl/bin/modem2_cli >/dev/null 2>&1; then
    /opt/nvtl/bin/modem2_cli get_info >> "$OUTPUT_DIR/catalog.txt" 2>&1
    echo "" >> "$OUTPUT_DIR/catalog.txt"
    /opt/nvtl/bin/modem2_cli get_state >> "$OUTPUT_DIR/catalog.txt" 2>&1
    echo "" >> "$OUTPUT_DIR/catalog.txt"
    /opt/nvtl/bin/modem2_cli sim_get_status >> "$OUTPUT_DIR/catalog.txt" 2>&1
    echo "" >> "$OUTPUT_DIR/catalog.txt"
    /opt/nvtl/bin/modem2_cli enabled_tech_get >> "$OUTPUT_DIR/catalog.txt" 2>&1
    echo "" >> "$OUTPUT_DIR/catalog.txt"
else
    echo "modem2_cli not found at /opt/nvtl/bin/modem2_cli. Modem info will not be collected." | tee -a "$OUTPUT_DIR/catalog.txt" >&2
    echo "" >> "$OUTPUT_DIR/catalog.txt"
fi
OUTPUT_DIR="/tmp/mifi_catalog"
mkdir -p "$OUTPUT_DIR"

echo "=== MiFi 8800L Deep Exploration ===" > "$OUTPUT_DIR/catalog.txt"
echo "Date: $(date)" >> "$OUTPUT_DIR/catalog.txt"
echo "" >> "$OUTPUT_DIR/catalog.txt"

# System Info
echo "=== SYSTEM INFO ===" >> "$OUTPUT_DIR/catalog.txt"
cat /proc/cpuinfo >> "$OUTPUT_DIR/catalog.txt" 2>&1
echo "" >> "$OUTPUT_DIR/catalog.txt"
cat /proc/version >> "$OUTPUT_DIR/catalog.txt" 2>&1
echo "" >> "$OUTPUT_DIR/catalog.txt"
cat /proc/meminfo >> "$OUTPUT_DIR/catalog.txt" 2>&1
echo "" >> "$OUTPUT_DIR/catalog.txt"

# Partition layout
echo "=== PARTITIONS ===" >> "$OUTPUT_DIR/catalog.txt"
cat /proc/mtd >> "$OUTPUT_DIR/catalog.txt" 2>&1
echo "" >> "$OUTPUT_DIR/catalog.txt"
df -h >> "$OUTPUT_DIR/catalog.txt" 2>&1
echo "" >> "$OUTPUT_DIR/catalog.txt"
mount >> "$OUTPUT_DIR/catalog.txt" 2>&1
echo "" >> "$OUTPUT_DIR/catalog.txt"

# Modem Info
echo "=== MODEM INFO ===" >> "$OUTPUT_DIR/catalog.txt"
/opt/nvtl/bin/modem2_cli get_info >> "$OUTPUT_DIR/catalog.txt" 2>&1
echo "" >> "$OUTPUT_DIR/catalog.txt"
/opt/nvtl/bin/modem2_cli get_state >> "$OUTPUT_DIR/catalog.txt" 2>&1
echo "" >> "$OUTPUT_DIR/catalog.txt"
/opt/nvtl/bin/modem2_cli sim_get_status >> "$OUTPUT_DIR/catalog.txt" 2>&1
echo "" >> "$OUTPUT_DIR/catalog.txt"
/opt/nvtl/bin/modem2_cli enabled_tech_get >> "$OUTPUT_DIR/catalog.txt" 2>&1
echo "" >> "$OUTPUT_DIR/catalog.txt"

# USB Info
echo "=== USB INFO ===" >> "$OUTPUT_DIR/catalog.txt"
/opt/nvtl/bin/usb_cli get_config >> "$OUTPUT_DIR/catalog.txt" 2>&1
echo "" >> "$OUTPUT_DIR/catalog.txt"
/opt/nvtl/bin/usb_cli get_state >> "$OUTPUT_DIR/catalog.txt" 2>&1
echo "" >> "$OUTPUT_DIR/catalog.txt"

# Network Interfaces
echo "=== NETWORK ===" >> "$OUTPUT_DIR/catalog.txt"
ifconfig >> "$OUTPUT_DIR/catalog.txt" 2>&1
echo "" >> "$OUTPUT_DIR/catalog.txt"
cat /etc/resolv.conf >> "$OUTPUT_DIR/catalog.txt" 2>&1
echo "" >> "$OUTPUT_DIR/catalog.txt"

# Device Nodes
echo "=== DEVICE NODES ===" >> "$OUTPUT_DIR/catalog.txt"
ls -la /dev/at_* /dev/smd* /dev/diag /dev/ttyHS* /dev/ttyHSL* 2>/dev/null >> "$OUTPUT_DIR/catalog.txt"
echo "" >> "$OUTPUT_DIR/catalog.txt"

# Running Processes
echo "=== PROCESSES ===" >> "$OUTPUT_DIR/catalog.txt"
ps aux >> "$OUTPUT_DIR/catalog.txt" 2>&1 || ps >> "$OUTPUT_DIR/catalog.txt" 2>&1
echo "" >> "$OUTPUT_DIR/catalog.txt"

# Open ports
echo "=== NETWORK PORTS ===" >> "$OUTPUT_DIR/catalog.txt"
netstat -tlnp >> "$OUTPUT_DIR/catalog.txt" 2>&1 || netstat -tln >> "$OUTPUT_DIR/catalog.txt" 2>&1
echo "" >> "$OUTPUT_DIR/catalog.txt"

# All executables in /opt/nvtl/bin
echo "=== NVTL BINARIES ===" >> "$OUTPUT_DIR/catalog.txt"
ls -la /opt/nvtl/bin/ >> "$OUTPUT_DIR/catalog.txt" 2>&1
echo "" >> "$OUTPUT_DIR/catalog.txt"

# All shared libraries
echo "=== NVTL LIBRARIES ===" >> "$OUTPUT_DIR/catalog.txt"
ls -la /opt/nvtl/lib/ >> "$OUTPUT_DIR/catalog.txt" 2>&1
echo "" >> "$OUTPUT_DIR/catalog.txt"

# Key config files
echo "=== KEY CONFIGS ===" >> "$OUTPUT_DIR/catalog.txt"
echo "--- /sysconf/features.xml ---" >> "$OUTPUT_DIR/catalog.txt"
cat /sysconf/features.xml >> "$OUTPUT_DIR/catalog.txt" 2>&1
echo "" >> "$OUTPUT_DIR/catalog.txt"

echo "--- /sysconf/settings.xml (truncated) ---" >> "$OUTPUT_DIR/catalog.txt"
head -200 /sysconf/settings.xml >> "$OUTPUT_DIR/catalog.txt" 2>&1
echo "" >> "$OUTPUT_DIR/catalog.txt"

# Web UI apps (hidden APIs)
echo "=== WEB UI APPS ===" >> "$OUTPUT_DIR/catalog.txt"
ls -la /opt/nvtl/webui/apps/ >> "$OUTPUT_DIR/catalog.txt" 2>&1
echo "" >> "$OUTPUT_DIR/catalog.txt"

# Cron jobs
echo "=== CRON JOBS ===" >> "$OUTPUT_DIR/catalog.txt"
cat /var/spool/cron/crontabs/* >> "$OUTPUT_DIR/catalog.txt" 2>&1
echo "" >> "$OUTPUT_DIR/catalog.txt"

# Init scripts
echo "=== INIT SCRIPTS ===" >> "$OUTPUT_DIR/catalog.txt"
ls -la /etc/init.d/ >> "$OUTPUT_DIR/catalog.txt" 2>&1
echo "" >> "$OUTPUT_DIR/catalog.txt"

# Password hashes
echo "=== USERS ===" >> "$OUTPUT_DIR/catalog.txt"
cat /etc/passwd >> "$OUTPUT_DIR/catalog.txt" 2>&1
echo "" >> "$OUTPUT_DIR/catalog.txt"

# Environment
echo "=== ENVIRONMENT ===" >> "$OUTPUT_DIR/catalog.txt"
env >> "$OUTPUT_DIR/catalog.txt" 2>&1
echo "" >> "$OUTPUT_DIR/catalog.txt"

# Kernel modules
echo "=== KERNEL MODULES ===" >> "$OUTPUT_DIR/catalog.txt"
lsmod >> "$OUTPUT_DIR/catalog.txt" 2>&1
echo "" >> "$OUTPUT_DIR/catalog.txt"

# Full file listing of key directories
echo "=== FULL FILE LISTING ===" >> "$OUTPUT_DIR/file_listing.txt"
echo "--- /opt/nvtl/ ---" >> "$OUTPUT_DIR/file_listing.txt"
find /opt/nvtl -type f 2>/dev/null >> "$OUTPUT_DIR/file_listing.txt"
echo "" >> "$OUTPUT_DIR/file_listing.txt"

echo "--- /etc/ ---" >> "$OUTPUT_DIR/file_listing.txt"
find /etc -type f 2>/dev/null >> "$OUTPUT_DIR/file_listing.txt"
echo "" >> "$OUTPUT_DIR/file_listing.txt"

echo "--- /sysconf/ ---" >> "$OUTPUT_DIR/file_listing.txt"
find /sysconf -type f 2>/dev/null >> "$OUTPUT_DIR/file_listing.txt"
echo "" >> "$OUTPUT_DIR/file_listing.txt"

echo "Exploration complete. Output in $OUTPUT_DIR"
echo "Use: adb pull $OUTPUT_DIR to retrieve files"
