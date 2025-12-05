#!/bin/sh
# Alternate Program & Deep Utilities Discovery
# Searches for programs with non-standard names that might provide NV/device access

echo "=== DEEP PROGRAM DISCOVERY & ALTERNATE ACCESS METHODS ==="
echo "Time: $(date)"
echo ""

# Phase 1: Binary analysis for program capabilities
echo "=== PHASE 1: BINARY CAPABILITY ANALYSIS ==="
echo "Scanning for programs with 'read', 'write', 'mem', 'eeprom' capabilities..."
echo ""

for PROG in /opt/nvtl/bin/* /bin/* /sbin/* /usr/bin/* 2>/dev/null; do
    if [ ! -x "$PROG" ]; then
        continue
    fi
    
    NAME=$(basename "$PROG")
    
    # Check if strings contain capability hints
    STRINGS_OUTPUT=$(strings "$PROG" 2>/dev/null | grep -E "read|write|eeprom|nvram|NV|item|memory|persist" | head -3)
    
    if [ ! -z "$STRINGS_OUTPUT" ]; then
        echo "[$NAME]"
        echo "$STRINGS_OUTPUT" | head -2 | sed 's/^/  /'
    fi
done | head -100

echo ""

# Phase 2: Search for programs that operate on /dev/
echo "=== PHASE 2: DEVICE FILE OPERATORS ==="
echo "Programs that interact with device files..."
echo ""

for PROG in /opt/nvtl/bin/* /bin/* /sbin/* 2>/dev/null; do
    if [ ! -x "$PROG" ]; then
        continue
    fi
    
    NAME=$(basename "$PROG")
    
    # Look for /dev patterns in strings
    DEV_REFS=$(strings "$PROG" 2>/dev/null | grep "/dev/" | sort -u)
    
    if [ ! -z "$DEV_REFS" ]; then
        echo "$NAME: $(echo "$DEV_REFS" | wc -l) device references"
        echo "$DEV_REFS" | head -3 | sed 's/^/  /'
    fi
done | head -80

echo ""

# Phase 3: Discover test and debug utilities
echo "=== PHASE 3: TEST & DEBUG UTILITIES ==="
echo "Programs with 'test', 'debug', 'diag' in names or functionality..."
echo ""

find /opt/nvtl/bin -type f -executable \( -name '*test*' -o -name '*debug*' -o -name '*diag*' -o -name 'dump*' \) 2>/dev/null | while read PROG; do
    NAME=$(basename "$PROG")
    
    # Check if it has parameters/help
    HELP=$($PROG -h 2>&1 | head -3)
    or
    HELP=$($PROG --help 2>&1 | head -3)
    or
    HELP=$($PROG help 2>&1 | head -3)
    
    echo "$NAME"
done | head -50

echo ""

# Phase 4: Analyze program dependencies
echo "=== PHASE 4: LIBRARY DEPENDENCY ANALYSIS ==="
echo "Programs using QMI/NV libraries..."
echo ""

for PROG in /opt/nvtl/bin/* 2>/dev/null; do
    if [ ! -x "$PROG" ]; then
        continue
    fi
    
    NAME=$(basename "$PROG")
    
    # Check library dependencies (if ldd available)
    LIBS=$(ldd "$PROG" 2>/dev/null | grep -E "qmi|mal|modem|nvram" | awk '{print $1}')
    
    if [ ! -z "$LIBS" ]; then
        echo "$NAME depends on:"
        echo "$LIBS" | sed 's/^/  /'
    fi
done | head -100

echo ""

# Phase 5: Executable symbols revealing hidden functions
echo "=== PHASE 5: EXECUTABLE SYMBOL EXTRACTION ==="
echo "Extracting symbols from key binaries (first 30 symbols)..."
echo ""

for PROG in /opt/nvtl/bin/nwcli /opt/nvtl/bin/modem2_cli /opt/nvtl/bin/sms_cli 2>/dev/null; do
    if [ -x "$PROG" ]; then
        NAME=$(basename "$PROG")
        echo "[$NAME]"
        nm "$PROG" 2>/dev/null | grep -E "read|write|nv|item|get|set" | head -10 | awk '{print $NF}' | sed 's/^/  /'
        echo ""
    fi
done

# Phase 6: Configuration and data files
echo "=== PHASE 6: CONFIGURATION & DATA FILES ==="
echo "Searching for XML, config, and database files..."
echo ""

echo "XML configurations:"
find /opt/nvtl/etc -name "*.xml" 2>/dev/null | while read FILE; do
    echo "  $(basename $FILE): $(wc -l < $FILE) lines"
    grep -E "nv|item|band|lock|sms|config" "$FILE" | head -2 | sed 's/^/    /'
done

echo ""
echo "Database files:"
find /persist /data -name "*.db" -o -name "*.sqlite" 2>/dev/null | head -20 | sed 's/^/  /'

echo ""

# Phase 7: Shell script analysis
echo "=== PHASE 7: SHELL SCRIPT COMMAND DISCOVERY ==="
echo "Commands used in shell scripts that might reveal functionality..."
echo ""

for SCRIPT in /opt/nvtl/bin/*.sh 2>/dev/null; do
    if [ -f "$SCRIPT" ]; then
        NAME=$(basename "$SCRIPT")
        
        # Extract unique commands
        CMDS=$(grep -oE '\b(read|write|echo|cat|sed|awk|grep|nv|modem|qmi|diag|at|sms|get|set|enable|disable)\b' "$SCRIPT" | sort -u | wc -l)
        
        if [ $CMDS -gt 5 ]; then
            echo "$NAME: $(grep -oE 'read|write|qmi|nv|modem|diag' $SCRIPT | sort | uniq -c | sort -rn | head -3 | awk '{print $NF}' | tr '\n' ',' | sed 's/,$//')"
        fi
    fi
done | head -30

echo ""

# Phase 8: IPC and socket communication
echo "=== PHASE 8: IPC & SOCKET ANALYSIS ==="
echo "Programs using Unix sockets or named pipes for communication..."
echo ""

netstat -l 2>/dev/null | grep -E "unix|socket" | head -20

echo ""
ls -la /tmp/*.socket 2>/dev/null
ls -la /var/run/*.socket 2>/dev/null

echo ""

# Phase 9: Environment and startup analysis
echo "=== PHASE 9: ENVIRONMENT & STARTUP ANALYSIS ==="
echo "Checking startup scripts and environment variables..."
echo ""

echo "Init scripts that might start NV-related services:"
find /etc/init.d -type f 2>/dev/null | xargs grep -l "modem\|nv\|diag\|qmi" 2>/dev/null | while read SCRIPT; do
    echo "  $(basename $SCRIPT)"
    grep -E "start|stop|execute|run" "$SCRIPT" | head -2 | sed 's/^/    /'
done | head -40

echo ""

# Phase 10: Alternative access mechanisms
echo "=== PHASE 10: ALTERNATIVE NV ACCESS MECHANISMS ==="
echo "Testing non-standard access methods..."
echo ""

# Direct memory access
echo "Memory devices:"
ls -la /dev/mem /dev/kmem 2>/dev/null || echo "  Memory devices not accessible"

echo ""
echo "MTD (Memory Technology Devices):"
ls -la /dev/mtd* 2>/dev/null | head -10 || echo "  MTD devices not found"

echo ""
echo "NVRAM devices:"
find /dev -name "*nvram*" -o -name "*eeprom*" 2>/dev/null || echo "  NVRAM devices not found"

echo ""

# Phase 11: Firmware and flash analysis
echo "=== PHASE 11: FIRMWARE & FLASH ANALYSIS ==="
echo "Checking for firmware update and flash tools..."
echo ""

ls -la /opt/nvtl/bin/ | grep -iE "flash|firmware|fota|update|burn|write" | awk '{print $NF}'

echo ""
echo "Modem firmware paths:"
find /firmware /mnt -name "*mbn*" -o -name "*mdt*" -o -name "*elf*" 2>/dev/null | head -20

echo ""

# Phase 12: Process inspection for hidden operations
echo "=== PHASE 12: RUNNING PROCESS INSPECTION ==="
echo "Analyzing current processes for hints..."
echo ""

ps aux | grep -E "modem|nv|diag|qmi|sms" | grep -v grep | awk '{print $11, $12}' | head -20

echo ""

# Phase 13: File descriptor analysis
echo "=== PHASE 13: OPEN FILE DESCRIPTOR ANALYSIS ==="
echo "What files are open by modem-related processes..."
echo ""

for PID in $(ps aux | grep -E "modem|nwcli|diag" | grep -v grep | awk '{print $2}'); do
    echo "Process $PID open files:"
    ls -la /proc/$PID/fd 2>/dev/null | grep -E "/dev/|/sys/|/proc/" | awk '{print $NF}' | head -5 | sed 's/^/  /'
done

echo ""

# Phase 14: Manufacturer-specific extensions
echo "=== PHASE 14: MANUFACTURER-SPECIFIC EXTENSIONS ==="
echo "Searching for Novatel/Inseego proprietary features..."
echo ""

echo "Programs with 'nvtl' or 'mifi' prefix (likely proprietary):"
find /opt -name "*nvtl*" -o -name "*mifi*" 2>/dev/null | head -40 | sed 's/^/  /'

echo ""
echo "Novatel/Inseego command prefixes discovered:"
grep -rh "nwcli\|nvtl\|mifi" /opt/nvtl/bin --include="*.sh" 2>/dev/null | grep -oE '\b[a-z_]+_(cli|cmd|exe)\b' | sort -u | head -20 | sed 's/^/  /'

echo ""

# Phase 15: Comparison with similar devices
echo "=== PHASE 15: DEVICE CLASS ANALYSIS ==="
echo "Identifying Qualcomm chipset specific tools..."
echo ""

echo "Chipset: $(cat /proc/device-tree/model 2>/dev/null || echo 'SDX20 Alpine')"
echo ""

echo "Qualcomm specific programs:"
grep -r "qualcomm\|qcom\|sdx" /opt/nvtl/lib --include="*.so" 2>/dev/null | grep -oE 'lib[a-z_]+\.so' | sort -u | head -20 | sed 's/^/  /'

echo ""

# Phase 16: Write capability via indirect methods
echo "=== PHASE 16: INDIRECT WRITE CAPABILITY TESTING ==="
echo "Testing write access through configuration APIs..."
echo ""

echo "Testing APN modification (indirect NV write):"
APNTEST=$(/opt/nvtl/bin/modem2_cli prof_get_pri_tech 2>&1 | head -1)
if [ ! -z "$APNTEST" ]; then
    echo "  APN profile read: SUCCESS"
fi

echo ""
echo "Testing band preference modification:"
BANDTEST=$(/opt/nvtl/bin/modem2_cli enabled_tech_get 2>&1 | head -1)
if [ ! -z "$BANDTEST" ]; then
    echo "  Band preference read: SUCCESS"
fi

echo ""

echo "=== DISCOVERY COMPLETE ==="
echo "Time: $(date +%s)"
