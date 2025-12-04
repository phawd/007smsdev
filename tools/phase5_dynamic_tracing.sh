#!/bin/sh
# Phase 5: Dynamic Tracing Analysis
# Uses strace and ltrace to trace carrier unlock operations
# Purpose: Identify exact system calls and library functions involved in lock validation

TRACE_DIR="/root/phase5_dynamic_traces_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$TRACE_DIR"

cd "$TRACE_DIR"

echo "========================================="
echo "Phase 5: Dynamic Tracing Analysis"
echo "Using strace and ltrace"
echo "Trace directory: $TRACE_DIR"
echo "========================================="
echo ""

# ============================================
# TRACE 1: Carrier Unlock Status Check
# ============================================
echo "=== TRACE 1: Get Carrier Unlock Status ==="
echo "Tracing: modem2_cli get_carrier_unlock"

strace -f -e trace=file,read,write,ioctl,open,openat -o strace_get_carrier_unlock.log /opt/nvtl/bin/modem2_cli get_carrier_unlock > modem2_cli_get_carrier_unlock_output.txt 2>&1
ltrace -f -e '*' -o ltrace_get_carrier_unlock.log /opt/nvtl/bin/modem2_cli get_carrier_unlock >> modem2_cli_get_carrier_unlock_output.txt 2>&1

echo "✓ Trace complete"
echo ""

# ============================================
# TRACE 2: SPC Code Validation
# ============================================
echo "=== TRACE 2: SPC Code Validation ==="
echo "Tracing: modem2_cli validate_spc_code (attempt with invalid code)"

strace -f -e trace=file,read,write,ioctl,open,openat -o strace_validate_spc.log /opt/nvtl/bin/modem2_cli validate_spc_code 000000 > modem2_cli_validate_spc_output.txt 2>&1
ltrace -f -e '*' -o ltrace_validate_spc.log /opt/nvtl/bin/modem2_cli validate_spc_code 000000 >> modem2_cli_validate_spc_output.txt 2>&1

echo "✓ SPC validation trace complete"
echo ""

# ============================================
# TRACE 3: Carrier Unlock Attempt
# ============================================
echo "=== TRACE 3: Carrier Unlock Attempt ==="
echo "Tracing: modem2_cli carrier_unlock (will fail without valid SPC)"

strace -f -e trace=file,read,write,ioctl,open,openat -o strace_carrier_unlock.log /opt/nvtl/bin/modem2_cli carrier_unlock > modem2_cli_carrier_unlock_output.txt 2>&1
ltrace -f -e '*' -o ltrace_carrier_unlock.log /opt/nvtl/bin/modem2_cli carrier_unlock >> modem2_cli_carrier_unlock_output.txt 2>&1

echo "✓ Carrier unlock trace complete"
echo ""

# ============================================
# TRACE 4: NV Item Read (Lock Status)
# ============================================
echo "=== TRACE 4: NV Item Operations ==="
echo "Tracing: NV item read operations"

strace -f -e trace=file,read,write,ioctl,open,openat -o strace_nv_read.log /opt/nvtl/bin/modem2_cli nv_read 3461 > modem2_cli_nv_read_output.txt 2>&1
ltrace -f -e '*' -o ltrace_nv_read.log /opt/nvtl/bin/modem2_cli nv_read 3461 >> modem2_cli_nv_read_output.txt 2>&1

echo "✓ NV item trace complete"
echo ""

# ============================================
# TRACE 5: Library Function Calls
# ============================================
echo "=== TRACE 5: Library Function Analysis ==="

# Extract all library function calls from ltrace logs
echo "Extracting modem2_cli library calls..." >> ltrace_analysis.txt
echo "==========================================" >> ltrace_analysis.txt

# Analyze ltrace output for carrier/lock related calls
grep -i "carrier\|unlock\|spc\|lock\|validate" ltrace_*.log >> ltrace_analysis.txt 2>&1

echo "✓ Library function analysis complete"
echo ""

# ============================================
# TRACE 6: System Call Analysis
# ============================================
echo "=== TRACE 6: System Call Analysis ==="

# Extract ioctl calls (likely QMI interaction)
echo "Extracting ioctl system calls (QMI protocol)..." >> strace_ioctl_analysis.txt
echo "==========================================" >> strace_ioctl_analysis.txt

grep "ioctl" strace_*.log | grep -v "TIOCGWINSZ" >> strace_ioctl_analysis.txt 2>&1

# Extract file operations
echo "Extracting file operations..." >> strace_file_analysis.txt
echo "==========================================" >> strace_file_analysis.txt

grep -E "open\(|read\(|write\(" strace_*.log | grep -E "/dev/|/proc|smd|mtd" >> strace_file_analysis.txt 2>&1

echo "✓ System call analysis complete"
echo ""

# ============================================
# TRACE 7: EFS2 Access Tracing
# ============================================
echo "=== TRACE 7: EFS2 Access Detection ==="
echo "Checking for any dd or direct MTD access attempts"

# Monitor for MTD device access
strace -f -e trace=open,openat,read,write -o strace_mtd_access.log -p $(pgrep -f modem2d) sleep 5 > /dev/null 2>&1

if [ -f strace_mtd_access.log ]; then
    grep -E "/dev/mtd|/proc/mtd" strace_mtd_access.log >> mtd_access_analysis.txt 2>&1
    echo "✓ MTD access trace captured"
fi

echo ""

# ============================================
# SUMMARY AND KEY FINDINGS
# ============================================
echo "=== TRACE SUMMARY ==="

cat > TRACE_ANALYSIS_SUMMARY.txt << 'SUMMARY_EOF'
=================================================
Dynamic Tracing Analysis Summary
Phase 5 Forensic Investigation
=================================================

Tracing Tools Used:
- strace: System call tracing (protocols, device access, file ops)
- ltrace: Library function call tracing (modem2_api.so, libmal_qct.so)

Trace Files Generated:
1. strace_get_carrier_unlock.log
2. ltrace_get_carrier_unlock.log
3. strace_validate_spc.log
4. ltrace_validate_spc.log
5. strace_carrier_unlock.log
6. ltrace_carrier_unlock.log
7. strace_nv_read.log
8. ltrace_nv_read.log
9. strace_ioctl_analysis.txt (QMI protocol calls)
10. strace_file_analysis.txt (Device/file access)
11. ltrace_analysis.txt (Library function mapping)
12. mtd_access_analysis.txt (MTD partition access)

KEY ANALYSIS POINTS:
====================

1. QMI Protocol Analysis
   - Review strace_ioctl_analysis.txt
   - Look for QMI service IDs and message types
   - Identify lock validation message flow

2. Library Function Calls
   - Review ltrace_analysis.txt
   - Identify:
     - modem2_carrier_unlock function signature
     - modem2_validate_spc_code entry point
     - QMI library call patterns

3. Device Access Patterns
   - Review strace_file_analysis.txt
   - Check for /dev/smd*, /dev/mtd*, /proc/mtd access
   - Identify if direct dd is used (should see reboot risk)

4. NV Item Access Flow
   - strace_nv_read.log shows system calls for NV read
   - ltrace_nv_read.log shows library functions involved
   - Use to understand protection mechanism

EXPLOITATION INSIGHTS:
======================

From Dynamic Analysis, determine:
1. Is SPC validation done in kernel or userspace?
2. What QMI messages are exchanged?
3. Can we intercept/modify validation?
4. What file descriptors are used for lock access?
5. Is modem firmware involved in validation?

NEXT STEPS:
===========
1. Analyze ltrace output for library function names
2. Extract QMI message formats from strace ioctl calls
3. Identify exact SPC validation function call sequence
4. Load libmodem2_api.so in Ghidra and find functions
5. Create direct QMI message fuzzer or SPC bypass

FILES READY FOR GHIDRA ANALYSIS:
================================
- /opt/nvtl/lib/libmodem2_api.so (already extracted)
- /opt/nvtl/lib/libmal_qct.so (already extracted)

Use ltrace output to find function offsets for analysis.
SUMMARY_EOF

echo "✓ Analysis summary created"
echo ""

# ============================================
# FINALIZE
# ============================================
echo "========================================="
echo "✓ DYNAMIC TRACING ANALYSIS COMPLETE"
echo "========================================="
echo "Trace directory: $TRACE_DIR"
echo ""
echo "Key files:"
ls -lh *.log *.txt 2>/dev/null | awk '{print "  " $9 " (" $5 ")"}'
echo ""
echo "Device status:"
/opt/nvtl/bin/modem2_cli get_state
echo ""
echo "Ready for offline analysis and Ghidra work"
echo "========================================="
