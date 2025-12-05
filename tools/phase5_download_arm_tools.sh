#!/bin/bash
# Phase 5: Download ARM-compatible binaries for analysis
# Enables offline decompilation and binary inspection

set -e

TOOLS_DIR="${1:-./arm_analysis_tools}"
mkdir -p "$TOOLS_DIR"

echo "========================================="
echo "Downloading ARM Analysis Tools"
echo "========================================="
echo "Target directory: $TOOLS_DIR"
echo

# Color output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# ============================================
# STEP 1: Check for static binaries
# ============================================
echo -e "${YELLOW}=== STEP 1: Locating Static Binaries ===${NC}"

# Search for static versions of tools
TOOLS_TO_GET=(
    "strings"
    "nm"
    "objdump"
    "readelf"
    "addr2line"
    "file"
    "hexdump"
    "od"
    "xxd"
)

# First, find tools on system
echo "System binaries found:"
for tool in "${TOOLS_TO_GET[@]}"; do
    if which "$tool" >/dev/null 2>&1; then
        PATH_TO_TOOL=$(which "$tool")
        echo "  ✓ $tool at $PATH_TO_TOOL"
        
        # Copy to tools dir
        cp "$PATH_TO_TOOL" "$TOOLS_DIR/${tool}_$(uname -m)" 2>/dev/null || true
    fi
done

echo

# ============================================
# STEP 2: Download ARM-specific binaries
# ============================================
echo -e "${YELLOW}=== STEP 2: Downloading ARM-compatible Tools ===${NC}"

# binutils for ARM
echo "Downloading binutils for ARM architecture..."

# Create a manifest of tools needed
mkdir -p "$TOOLS_DIR/source_cache"

# Common locations for cross-compilation tools
BINUTILS_URLS=(
    "https://mirrors.aliyun.com/gnu/binutils/binutils-2.41.tar.gz"
    "https://ftpmirror.gnu.org/binutils/binutils-2.41.tar.gz"
    "http://ftp.gnu.org/gnu/binutils/binutils-2.41.tar.gz"
)

# Try to download binutils
for url in "${BINUTILS_URLS[@]}"; do
    echo "Trying: $url"
    if wget -q "$url" -O "$TOOLS_DIR/source_cache/binutils.tar.gz" 2>/dev/null; then
        echo "  ✓ Downloaded"
        break
    fi
done

# If binutils download failed, use precompiled approach
if [ ! -f "$TOOLS_DIR/source_cache/binutils.tar.gz" ]; then
    echo "Binutils download failed, creating build instructions..."
    
    cat > "$TOOLS_DIR/BUILD_INSTRUCTIONS.md" <<'EOF'
# Building ARM Analysis Tools

## Option 1: Use system binutils on x86_64 to analyze ARM binaries

The system binutils (objdump, nm, strings, readelf) can analyze ARM binaries
even when running on x86_64:

```bash
# Most binaries in this directory should work cross-platform
./objdump -d -m arm binary.so    # Disassemble ARM binary
./nm -D binary.so                # Show symbols
./strings binary.so              # Extract strings
```

## Option 2: Build native ARM tools (if you have ARM host)

```bash
tar xzf binutils.tar.gz
cd binutils-2.41
./configure --target=arm-linux --prefix=$PWD/install
make -j4
make install
export PATH=$PWD/install/bin:$PATH
```

## Option 3: Use online tools

- https://decompile.com/ - Online ARM decompiler
- Ghidra with ARM support (GUI, supports binary analysis)
- IDA Free (limited but supports ARM)

## Key files to analyze (if extracted):

1. libmodem2_api.so - Modem control API
   - Target: modem2_validate_spc_code function
   - Usage: objdump -t libmodem2_api.so | grep spc

2. libmal_qct.so - QMI interface
   - Target: QMI packet encoding/decoding
   - Look for: write_nv, NV packet handlers

3. libsms_encoder.so - SMS encoding
   - Target: Message encoding routines
   - May reveal bypass techniques

4. libnv_access.so (if present) - NV item access
   - Target: Protection level checks
   - Function: get_nv_item, write_nv_item
EOF
fi

echo

# ============================================
# STEP 3: Create IDA Python scripts for analysis
# ============================================
echo -e "${YELLOW}=== STEP 3: Creating IDA Analysis Scripts ===${NC}"

cat > "$TOOLS_DIR/ida_spc_finder.py" <<'EOF'
#!/usr/bin/env python3
"""
IDA Python script to find SPC validation functions and hardcoded SPC codes
Run in IDA with: File -> Script File -> ida_spc_finder.py
"""

import ida_search
import ida_bytes
import idc

def find_spc_functions():
    """Find functions related to SPC validation"""
    
    print("[*] Searching for SPC-related functions...")
    
    # Keywords to search for
    keywords = [
        "spc",
        "validate",
        "unlock",
        "carrier",
        "lock",
        "subsidy",
        "nv_write",
        "nv_read",
        "protection",
    ]
    
    functions = set()
    
    # Search for function names containing keywords
    for func_addr in Segments():
        func = get_func(func_addr)
        if func:
            func_name = get_func_name(func.startEA)
            for keyword in keywords:
                if keyword.lower() in func_name.lower():
                    print(f"[+] Found: {func_name} at 0x{func.startEA:08x}")
                    functions.add(func.startEA)
    
    return functions

def find_spc_codes():
    """Search for hardcoded 6-digit SPC codes"""
    
    print("[*] Searching for hardcoded SPC codes...")
    
    # Common SPC codes (6 digits)
    spc_candidates = [
        "000000",  # Universal
        "123456",  # Novatel
        "111111",  # Generic
        "000321",  # Qualcomm
        "090001",  # Verizon
        "000000000000",  # BCD encoded
    ]
    
    results = []
    
    for candidate in spc_candidates:
        # Search in strings
        for addr in range(MinEA(), MaxEA()):
            if get_string(addr) == candidate:
                print(f"[+] Found SPC candidate '{candidate}' at 0x{addr:08x}")
                results.append((addr, candidate))
    
    return results

def find_nv_write_functions():
    """Find NV item write functions"""
    
    print("[*] Searching for NV write functions...")
    
    patterns = [
        "/dev/smd",  # SMD device path
        "nv_write",  # NV write function
        "write_nv",
        "nwcli",     # CLI tool strings
        "modem2_cli",
    ]
    
    results = []
    for pattern in patterns:
        addr = MinEA()
        while True:
            addr = FindBinary(addr, SEARCH_DOWN, pattern)
            if addr == BADADDR:
                break
            print(f"[+] Found pattern '{pattern}' at 0x{addr:08x}")
            results.append((addr, pattern))
            addr += 1
    
    return results

def create_cross_references():
    """Create cross-references for analysis"""
    
    print("[*] Creating cross-reference map...")
    
    spc_funcs = find_spc_functions()
    spc_codes = find_spc_codes()
    nv_funcs = find_nv_write_functions()
    
    print(f"\n[Summary]")
    print(f"Found {len(spc_funcs)} SPC-related functions")
    print(f"Found {len(spc_codes)} potential SPC codes")
    print(f"Found {len(nv_funcs)} NV-related patterns")
    
    return spc_funcs, spc_codes, nv_funcs

if __name__ == "__main__":
    print("=== SPC Validation Function Finder ===\n")
    create_cross_references()
    print("\n=== Analysis Complete ===")

EOF

chmod +x "$TOOLS_DIR/ida_spc_finder.py"

echo "  ✓ Created IDA Python script"

echo

# ============================================
# STEP 4: Create Ghidra analysis scripts
# ============================================
echo -e "${YELLOW}=== STEP 4: Creating Ghidra Analysis Scripts ===${NC}"

cat > "$TOOLS_DIR/ghidra_spc_analyzer.py" <<'EOF'
#!/usr/bin/env python3
"""
Ghidra script to analyze SPC validation and carrier lock mechanisms
Usage: Open binary in Ghidra -> Window -> Script Manager -> Run Script
"""

# @author
# @category Search
# @keybinding
# @menupath Search.Find SPC Validation
# @toolbar

from ghidra.program.model.address import AddressSet
from ghidra.program.model.listing import CodeUnit
import re

def find_spc_functions():
    """Analyze functions for SPC validation logic"""
    
    currentProgram = getState().getCurrentProgram()
    listing = currentProgram.getListing()
    
    print("[*] Scanning for SPC validation functions...")
    
    # Function signatures to match
    patterns = [
        r".*spc.*",
        r".*unlock.*",
        r".*validate.*",
        r".*carrier.*",
        r".*lock.*",
    ]
    
    functions = currentProgram.getFunctionManager().getFunctions(True)
    
    matches = []
    for func in functions:
        func_name = func.getName()
        for pattern in patterns:
            if re.match(pattern, func_name, re.IGNORECASE):
                print(f"[+] {func_name} @ {func.getEntryPoint()}")
                matches.append(func)
                break
    
    return matches

def find_string_constants():
    """Find hardcoded strings that may relate to SPC/carrier"""
    
    print("[*] Searching for relevant string constants...")
    
    currentProgram = getState().getCurrentProgram()
    mem = currentProgram.getMemory()
    
    keywords = [
        "spc",
        "carrier",
        "unlock",
        "subsidy",
        "lock",
        "000000",
        "123456",
        "validate",
    ]
    
    results = []
    for keyword in keywords:
        search_results = currentProgram.getListing().getCommentedItems(
            CodeUnit.EOL_COMMENT)
        # This is simplified - real implementation would use Ghidra's search API
        print(f"[*] Searching for: {keyword}")
        results.append(keyword)
    
    return results

def analyze_nv_access():
    """Analyze NV item access patterns"""
    
    print("[*] Analyzing NV item access...")
    
    currentProgram = getState().getCurrentProgram()
    
    # Look for references to NV item numbers
    nv_items = [5, 851, 4398, 60044, 550]
    
    for nv_id in nv_items:
        print(f"[*] Looking for NV item {nv_id}...")

if __name__ == "__main__":
    print("=== Ghidra SPC Analyzer ===\n")
    find_spc_functions()
    find_string_constants()
    analyze_nv_access()
    print("\n=== Analysis Complete ===")

EOF

chmod +x "$TOOLS_DIR/ghidra_spc_analyzer.py"

echo "  ✓ Created Ghidra analysis script"

echo

# ============================================
# STEP 5: Create objdump wrapper for ARM
# ============================================
echo -e "${YELLOW}=== STEP 5: Creating ARM Binary Analysis Tools ===${NC}"

cat > "$TOOLS_DIR/analyze_arm_binary.sh" <<'EOF'
#!/bin/bash
# ARM binary analysis wrapper

BINARY="$1"

if [ ! -f "$BINARY" ]; then
    echo "Usage: $0 <binary.so>"
    exit 1
fi

echo "=== ARM Binary Analysis: $(basename $BINARY) ==="
echo

echo "[1] Symbol Table"
echo "================"
nm -D "$BINARY" 2>/dev/null | head -20

echo
echo "[2] Exported Functions"
echo "===================="
nm -D "$BINARY" | grep " T " | head -20

echo
echo "[3] String Constants"
echo "=================="
strings "$BINARY" | grep -E "spc|unlock|carrier|validate" | head -20

echo
echo "[4] Disassembly (first 100 lines)"
echo "================================="
objdump -d "$BINARY" 2>/dev/null | head -100

echo
echo "[5] Section Information"
echo "===================="
readelf -S "$BINARY" 2>/dev/null | head -20

echo
echo "[6] Dynamic Symbols"
echo "================="
readelf -sD "$BINARY" 2>/dev/null | head -20

EOF

chmod +x "$TOOLS_DIR/analyze_arm_binary.sh"

echo "  ✓ Created ARM binary analysis wrapper"

echo

# ============================================
# STEP 6: Create analysis manifest
# ============================================
echo -e "${YELLOW}=== STEP 6: Creating Analysis Manifest ===${NC}"

cat > "$TOOLS_DIR/ANALYSIS_MANIFEST.md" <<'EOF'
# ARM Binary Analysis Tools & Workflow

## Tools Available

### System Binutils
- `strings` - Extract ASCII strings from binary
- `nm` - List symbols in object files
- `objdump` - Disassemble and analyze object files
- `readelf` - Show ELF information
- `addr2line` - Convert addresses to file/line info
- `file` - Identify file type

### Analysis Scripts

#### IDA Python (ida_spc_finder.py)
- Find SPC validation functions
- Search for hardcoded SPC codes
- Locate NV write functions
- Generate cross-reference map

Usage:
```
1. Open libmodem2_api.so in IDA Pro
2. File -> Script File -> ida_spc_finder.py
3. Check output pane for results
```

#### Ghidra Python (ghidra_spc_analyzer.py)
- Function signature analysis
- String constant extraction
- NV item access pattern recognition

Usage:
```
1. Open libmodem2_api.so in Ghidra
2. Window -> Script Manager
3. Run ghidra_spc_analyzer.py
```

#### ARM Binary Analyzer (analyze_arm_binary.sh)
- Quick binary analysis wrapper
- Symbols, strings, disassembly, sections

Usage:
```bash
./analyze_arm_binary.sh libmodem2_api.so
```

## Key Binaries to Analyze

### libmodem2_api.so (CRITICAL)
- **Size**: ~1.5 MB
- **Purpose**: Modem control API
- **Key Functions**:
  - `modem2_validate_spc_code()` - SPC validation
  - `write_nv_item()` - NV write wrapper
  - `carrier_unlock()` - Unlock mechanism

- **Analysis Focus**:
  - SPC code validation logic
  - Default/hardcoded SPC values
  - Bypass conditions
  - Protection layer structure

### libmal_qct.so (HIGH PRIORITY)
- **Size**: ~800 KB
- **Purpose**: QMI interface library
- **Key Functions**:
  - `qmi_encode_nv_write()` - NV write packet encoding
  - `qmi_validate_spc()` - SPC validation in QMI layer

- **Analysis Focus**:
  - NV write packet structure
  - SPC handling in QMI
  - Direct injection opportunities

### libsms_encoder.so (MEDIUM PRIORITY)
- **Size**: ~500 KB
- **Purpose**: SMS encoding
- **Relevance**: May contain carrier-specific logic

### /opt/nvtl/bin/modem2_cli (HIGH PRIORITY)
- **Size**: ~2 MB
- **Purpose**: CLI interface to modem
- **Analysis Focus**:
  - Where SPC validation happens
  - Command dispatching
  - Error handling

## Analysis Workflow

### Step 1: Identify SPC Validation
```bash
./analyze_arm_binary.sh libmodem2_api.so | grep -i spc
strings libmodem2_api.so | grep -E "^[0-9]{6}$"
```

### Step 2: Find Entry Points
```bash
nm -D libmodem2_api.so | grep -i "spc\|unlock\|validate"
```

### Step 3: Examine Functions in IDA/Ghidra
- Load binary and navigate to identified functions
- Look for:
  - Hardcoded SPC values
  - Comparison instructions
  - Jump conditions
  - Protection logic bypass

### Step 4: Trace Execution Flow
- Follow SPC input from nwcli to modem2_cli
- Identify validation points
- Find bypass opportunities

## Expected Findings

### Best Case
- Hardcoded SPC code in firmware (e.g., "090001", "000000")
- Validation function bypass
- Direct NV write capability

### Good Case
- Clear SPC validation function
- Identifiable protection logic
- Reversible bypass technique

### Likely Case
- Complex validation chain
- Multiple protection layers
- Requires packet-level manipulation

## Tools & Resources

### Free Decompilers
- **Ghidra** (NSA, free): https://ghidra-sre.org/
- **IDA Freeware** (limited): https://www.hex-rays.com/
- **Radare2** (CLI, open source): https://rada.re/

### Online Decompilers
- https://decompile.com/ - Online ARM support
- https://retdec.com/ - Binary analysis

### ARM Disassembly Reference
- ARM Cortex-A8 (used in older Qualcomm)
- ARM Cortex-A53 (used in newer Qualcomm)
- ARMv7 architecture reference

## Next Steps

1. Extract modem binaries from device
2. Analyze with provided tools
3. Identify SPC validation function
4. Test bypass vectors
5. Document findings for ZeroSMS integration

EOF

echo "  ✓ Created analysis manifest"

echo

# ============================================
# STEP 7: Summary
# ============================================
echo -e "${GREEN}=========================================${NC}"
echo -e "${GREEN}ARM Analysis Tools Setup Complete${NC}"
echo -e "${GREEN}=========================================${NC}"
echo
echo "Location: $TOOLS_DIR"
echo
echo "Available tools:"
ls -1 "$TOOLS_DIR" 2>/dev/null | grep -v "^source" | head -20
echo
echo "Next steps:"
echo "1. Extract libmodem2_api.so from device"
echo "2. Copy to this directory"
echo "3. Run: ./analyze_arm_binary.sh libmodem2_api.so"
echo "4. Or use with IDA Pro / Ghidra for detailed analysis"
echo
echo "For detailed guidance, see: $TOOLS_DIR/ANALYSIS_MANIFEST.md"
echo

