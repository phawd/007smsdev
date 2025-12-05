# Phase 5: Binary Analysis Quick Reference Guide

**Purpose:** Quick-start guide for analyzing modem binaries for SPC codes and bypass techniques  
**Target Binaries:** libmodem2_api.so (PRIMARY), libmal_qct.so, libsms_encoder.so  
**Architecture:** ARM 32-bit (ARMv7) / ARM 64-bit (ARMv8)

---

## Extracted Binaries Available

### Location

```
f:\repo\zerosms\mifi_backup\binaries\
├── libmodem2_api.so     (144 KB) ⭐ CRITICAL
├── libmal_qct.so        (307 KB) ⭐ HIGH PRIORITY
├── libsms_encoder.so    (91 KB)
└── modem2_cli           (148 KB)
```

### Binary Sizes & Characteristics

| Binary | Size | Symbols | Type | Purpose |
|--------|------|---------|------|---------|
| libmodem2_api.so | 144 KB | Stripped | Shared lib | Modem API, SPC validation |
| libmal_qct.so | 307 KB | Partial | Shared lib | QMI protocol, NV operations |
| libsms_encoder.so | 91 KB | Partial | Shared lib | SMS/MMS encoding |
| modem2_cli | 148 KB | Partial | Executable | CLI interface to modem |

---

## Analysis Tools & Setup

### Option 1: Ghidra (FREE, Recommended)

**Download:** <https://ghidra-sre.org>  
**Installation:**

```bash
# Windows
Invoke-WebRequest -Uri "https://ghidra-sre.org/ghidra_latest_build.zip" -OutFile ghidra.zip
Expand-Archive ghidra.zip
cd ghidra_*/bin
./ghidraRun.bat
```

**Usage:**

1. File → Import File → Select `libmodem2_api.so`
2. Accept defaults (language auto-detected)
3. Window → Script Manager
4. Create new script → Load `arm_analysis_tools/ghidra_spc_analyzer.py`
5. Run script

### Option 2: IDA Pro (PAID, More Powerful)

**Cost:** $699 (single-use license)  
**Compatibility:** Supports ARM 32/64-bit perfectly  
**Usage:**

1. File → Open → Select `libmodem2_api.so`
2. Choose: ARM Little-Endian (or IDA will auto-detect)
3. Python → Load `arm_analysis_tools/ida_spc_finder.py`
4. Script execution panel → Run

### Option 3: Cutter (FREE, Radare2 GUI)

**Download:** <https://cutter.re>  
**Installation:** Pre-built binaries for Windows/Mac/Linux  
**Usage:**

1. File → Open → Select binary
2. Analysis → Full Analysis
3. Search → Strings (contains "spc", "validate")
4. Look for function cross-references

### Option 4: Online Decompilers (FREE, No Installation)

- **dogbolt.org** - Multi-decompiler comparison
- **decompiler.com** - IDA-like interface
- **Ghidra online** - Browser-based Ghidra

**Process:**

1. Upload binary
2. Auto-analyze
3. Search for "spc", "validate", "090001"

---

## ARM Assembly Quick Reference

### Key Registers (32-bit ARM)

```
R0-R3   Function arguments / return value
R4-R11  Callee-saved registers
R12     Intermediate register
R13     Stack pointer (SP)
R14     Link register (LR)
R15     Program counter (PC)
```

### Key ARM Instructions

```
LDR R0, [R1]        Load register from memory
STR R0, [R1]        Store register to memory
MOV R0, R1          Move value
CMP R0, R1          Compare (sets flags)
BEQ/BNE label       Branch on equal/not equal
BL function         Branch with Link (call)
LDM/STM             Load/Store Multiple
PUSH/POP            Stack operations
```

### Function Prologue/Epilogue

```ARM
; Function prologue (entry)
PUSH {R4-R11, LR}      ; Save callee-saved registers
SUB SP, SP, #0x20      ; Allocate stack space for locals

; Function epilogue (return)
ADD SP, SP, #0x20      ; Deallocate stack
POP {R4-R11, PC}       ; Restore and return
```

### ARM Call Convention (EABI)

```
Function call:     BL function_name
Argument 1:        R0
Argument 2:        R1
Argument 3:        R2
Argument 4:        R3
Additional args:   Stack (SP+0, SP+4, ...)
Return value:      R0 (32-bit) or R0:R1 (64-bit)
```

---

## SPC Validation Function Signature

### Expected Function Characteristics

```c
// Typical SPC validation function signature:
int validate_spc_code(const char *input_spc, int spc_length) {
    // 1. Check length (usually 6 digits)
    if (spc_length != 6) return -1;
    
    // 2. Validate digits (0-9 only)
    for (int i = 0; i < 6; i++) {
        if (input_spc[i] < '0' || input_spc[i] > '9')
            return -1;
    }
    
    // 3. Compare against stored/default SPC
    if (strcmp(input_spc, default_spc) == 0) {
        // 4. Perform unlock operation
        return unlock_carrier();
    }
    
    return -1;  // Failed
}
```

### Strings to Search For

```
"SPC"
"spc code"
"verification failed"
"unlock"
"carrier lock"
"security code"
"090001"        # Verizon default
"000000"        # Common default
"123456"        # Common test value
"subsidy lock"
"permission denied"
"invalid code"
```

### Important Functions to Find

```
- modem2_validate_spc_code()
- nv_item_write()
- nv_item_read()
- carrier_unlock_set()
- carrier_unlock_get()
- qmi_write_nv_item()
- qmi_read_nv_item()
- sms_send_raw_pdu()
- at_command_send()
```

---

## Analysis Workflow

### Step 1: Binary Metadata

```
Questions to answer:
- Is it stripped (no symbols)?
- Architecture: 32-bit or 64-bit?
- Byte order: Little or Big endian?
- Compiler: GCC, LLVM, MSVC?
- Optimization level: -O0, -O2, -Os?
```

**How to find:**

```bash
# Use file command (PowerShell on Windows)
file libmodem2_api.so
# Output: ELF 32-bit LSB shared object, ARM, EABI5

# Use readelf (if available)
readelf -h libmodem2_api.so
```

### Step 2: String Analysis

**Goal:** Find hardcoded SPC codes and related strings

**In Ghidra:**

1. Windows → Defined Strings
2. Filter: Contains "spc" or "090001"
3. Right-click → References → Find references to address
4. Jump to function containing reference

**In IDA:**

1. Strings window (Alt+T)
2. Search for keywords
3. Double-click string
4. View cross-references (X key)

### Step 3: Function Identification

**Goal:** Locate SPC validation function

**Indicators:**

- String references to SPC keywords nearby
- Comparison operations (CMP instructions)
- Branch instructions (BEQ, BNE, BLS)
- Limited parameters (typically 1-2)
- Early return paths (error handling)

**Check these functions first:**

1. Functions containing "validate" in name
2. Functions containing "unlock" in name
3. Functions with calls to strcmp, strncmp
4. Functions referenced by "spc" strings

### Step 4: Control Flow Analysis

**Goal:** Understand validation logic

**Look for:**

- String comparison (strcmp)
- Length checks
- Digit validation loops
- Conditional branches
- Success/failure paths

**Example pattern in ARM:**

```ARM
BL _Z9strcmpPKcS0_    ; Call strcmp
CMP R0, #0             ; Compare result
BEQ success_label      ; Branch if equal
B error_label          ; Branch to error
success_label:
...unlock operations...
```

### Step 5: Bypass Discovery

**Goal:** Identify protection gaps and bypass opportunities

**Questions:**

1. Is SPC validated before NV write?
2. Is userspace validation bypassable?
3. Can we inject QMI packets directly?
4. Are there hidden functions?
5. Is modem firmware re-validating?

---

## Common Bypass Patterns

### Pattern 1: Hardcoded Default SPC

**Indicator:** String "090001" in binary  
**Bypass:** Use the hardcoded SPC to unlock  
**Effort:** Minimal (1 hour)  
**Success Rate:** 70% (varies by device)

### Pattern 2: Userspace Validation Only

**Indicator:** NV write in libmal_qct without modem check  
**Bypass:** QMI packet injection or SMD channel manipulation  
**Effort:** Medium (4-6 hours)  
**Success Rate:** 50%

### Pattern 3: Weak Comparison Logic

**Indicator:** strcmp(input, hardcoded) without return value check  
**Bypass:** Off-by-one buffer overflow or format string  
**Effort:** High (8-12 hours)  
**Success Rate:** 30%

### Pattern 4: NV Item Direct Modification

**Indicator:** EFS2 partition is writable without SPC  
**Bypass:** Directly modify EFS2 carrier lock flags  
**Effort:** Low (1-2 hours)  
**Success Rate:** 90% (if EFS2 is writable)

---

## Analysis Commands Cheat Sheet

### Ghidra Script Manager

```
# View functions
Listing → Functions
Search → Function Names → Contains "spc"

# View strings
Windows → Defined Strings
Filter by name

# View cross-references
Right-click → References → Xrefs to
Navigation → Go to xref address
```

### IDA Keyboard Shortcuts

```
G       Go to address
F5      Decompile (C-like view)
X       Show xrefs to this address
Ctrl+F  Find binary/text
Alt+T   Open Strings window
Ctrl+F  Search in strings
```

### Cutter (Radare2 GUI)

```
Menu → Analysis → Full Analysis
Menu → Search → Strings
Menu → Search → Functions
Right-click → Show references
```

---

## Expected Findings

### Best Case (Complete Success)

```
✅ Found hardcoded SPC: "090001"
✅ SPC stored in string table (not encrypted)
✅ Validation only in userspace (no modem check)
✅ NV items writable from userspace
✅ Can unlock device by:
   - Entering SPC "090001", OR
   - Directly modifying NV item 4398, OR
   - Bypassing validation via SMD channel
```

### Realistic Case (Partial Success)

```
✅ Located modem2_validate_spc_code() function
✅ Identified validation logic
⚠️  No hardcoded SPC found (encrypted or runtime-generated)
⚠️  Validation re-checked in modem firmware
⚠️  NV items protected even in userspace
❌ Cannot get SPC, but can:
   - Bypass userspace validation via direct API calls
   - Potentially modify EFS2 if accessible
   - Test alternative vectors (FOTA, EDL, etc.)
```

### Worst Case (Limited Success)

```
✅ Documented all protection layers
✅ Identified validation functions
✅ Found entry points for exploitation
❌ No SPC code discovered
❌ Modem firmware protects all operations
❌ EFS2 protected by secure partition
✅ But can still:
   - Document findings for responsible disclosure
   - Identify potential future vectors
   - Plan phased exploitation for next device
```

---

## Responsible Disclosure Process

1. **Document all findings** (technical details, proof-of-concept)
2. **Contact manufacturer** (Inseego: <security@inseego.com>)
3. **Provide 90-day patch window** before publication
4. **Allow time for carrier testing** (if applicable)
5. **Publish responsibly** on security research channels

---

## Tools Summary

| Tool | Cost | Ease | ARM Support | Recommendation |
|------|------|------|-------------|-----------------|
| Ghidra | Free | Medium | ⭐⭐⭐ | **BEST** for free |
| IDA Pro | $699 | Easy | ⭐⭐⭐⭐ | **BEST** overall |
| Cutter | Free | Hard | ⭐⭐ | Good backup |
| Online | Free | Easy | ⭐⭐ | Quick preview |
| Radare2 | Free | Hard | ⭐⭐⭐ | Powerful but CLI |

---

## Next Steps

1. ✅ Binaries extracted to `mifi_backup/binaries/`
2. Download Ghidra (free) or Radare2 (free)
3. Open `libmodem2_api.so` in Ghidra
4. Load analysis script: `arm_analysis_tools/ghidra_spc_analyzer.py`
5. Review findings and document in `PHASE_5_SPC_ANALYSIS.md`

---

**Time Estimate:** 2-4 hours for complete binary analysis  
**Effort Level:** Medium-High (requires ARM knowledge)  
**Expected Outcome:** Identification of SPC validation logic and potential bypasses
