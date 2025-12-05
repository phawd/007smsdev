# Ghidra Interactive Analysis - Quick Reference

**Target**: libmal_qct.so carrier unlock mechanism  
**Project**: F:\repo\zerosms\analysis\ghidra_project\MiFi_Unlock_Analysis.gpr

---

## Opening the Project

1. Ghidra should now be open
2. **File → Open Project**
3. Navigate to: `F:\repo\zerosms\analysis\ghidra_project`
4. Select: `MiFi_Unlock_Analysis.gpr`
5. Double-click: `libmal_qct.so` to open in CodeBrowser

---

## Finding the Unlock Function (3 Methods)

### Method 1: Symbol Tree (Visual)

```
Window → Symbol Tree
[Expand] Functions
[Scroll or Search] modem2_modem_carrier_unlock
[Double-click] to jump to function
```

### Method 2: Function Search (Filtered)

```
Search → For Functions... (or press Ctrl+Shift+F)
Function Name: modem2_modem_carrier_unlock
[Search]
[Double-click result]
```

### Method 3: Go To (Fastest)

```
Navigation → Go To... (or press G)
Type: modem2_modem_carrier_unlock
[OK]
```

---

## Understanding the Views

### Left Panel: Listing (Assembly)

- Shows ARM assembly instructions
- Useful for seeing exact operations
- Color coding:
  - Blue = function calls
  - Green = strings
  - Purple = addresses

### Right Panel: Decompiler (C Pseudocode)

- Shows reconstructed C code
- Easiest to understand logic
- May not be perfect, but very close
- **This is where you'll spend most time**

### Bottom Panel: Console/Data

- Shows raw data, strings, etc.

---

## What to Look for in `modem2_modem_carrier_unlock`

### 1. Function Signature

```c
// Expected structure:
int modem2_modem_carrier_unlock(char *nck_code, char *spc_code)
```

### 2. Validation Logic

- [ ] **NCK Validation**: How is the unlock code checked?
  - Direct comparison? `if (strcmp(nck, expected_nck) == 0)`
  - Hash comparison? `if (sha256(nck) == stored_hash)`
  - Algorithm-based? `if (generate_nck(imei) == nck)`

- [ ] **SPC Validation**: 6-digit code check
  - Default is "000000"
  - Look for: `strcmp(spc, "000000")`

### 3. QMI Service Calls

```c
// Look for patterns like:
qmi_client_send_msg_sync(...);
qmi_dms_validate_spc(...);
qmi_dms_carrier_unlock(...);
```

### 4. Lock State Checks

- Strings to search for:
  - "BLOCKED"
  - "PERMANENTLY BLOCKED"
  - "UNBLOCKED"
  - "[1_ALL_BLOCKS]", "[4_ALL_BLOCKS]", "[5_ALL_BLOCKS]"

### 5. Return Codes

```c
// Look for return statements:
return 0;  // Success
return -1; // Error
return QMI_ERR_AUTHENTICATION_FAILED;
```

---

## Useful Ghidra Features

### Rename Variables (for clarity)

```
Right-click variable → Rename Variable (or press L)
Example: var1 → nck_code
```

### View Cross-References

```
Right-click function name → Show References to
See everywhere this function is called
```

### Search for Strings

```
Search → For Strings...
Find: "BLOCKED", "unlock", "carrier"
Double-click results to see usage
```

### View Function Call Graph

```
Select function → Graph → Function Call Graph
Visual representation of function relationships
```

### Export Decompiled Code

```
In Decompiler window:
1. Select all (Ctrl+A)
2. Copy (Ctrl+C)
3. Paste into text editor
4. Save as: F:\repo\zerosms\analysis\modem2_modem_carrier_unlock.c
```

---

## Analysis Checklist

### Phase 1: Initial Exploration

- [ ] Locate `modem2_modem_carrier_unlock` function
- [ ] Read decompiled code in right panel
- [ ] Identify function parameters (NCK? SPC?)
- [ ] Note overall structure (if/else, loops, calls)

### Phase 2: Deep Dive

- [ ] Analyze NCK validation logic
- [ ] Analyze SPC validation logic
- [ ] Identify QMI message structure
- [ ] Find retry limit logic
- [ ] Map error codes

### Phase 3: Related Functions

- [ ] Analyze `modem2_modem_validate_spc`
- [ ] Analyze `modem2_modem_get_carrier_unlock_status`
- [ ] Analyze `nwqmi_dms_validate_spc`
- [ ] Cross-reference with `dsm_modem_get_imei`

### Phase 4: Documentation

- [ ] Export all decompiled functions to .c files
- [ ] Screenshot key logic sections
- [ ] Document algorithm in plain English
- [ ] Note any crypto functions found

---

## Expected Findings

### Scenario A: Direct Comparison (Simple)

```c
int modem2_modem_carrier_unlock(char *nck, char *spc) {
    char *expected_nck = "12345678"; // Hardcoded or from NV
    
    if (strcmp(spc, "000000") != 0) {
        return ERROR_INVALID_SPC;
    }
    
    if (strcmp(nck, expected_nck) == 0) {
        // Unlock device
        set_carrier_lock_status(UNBLOCKED);
        return SUCCESS;
    }
    
    return ERROR_AUTHENTICATION_FAILED;
}
```

### Scenario B: Algorithm-Based (Complex)

```c
int modem2_modem_carrier_unlock(char *nck, char *spc) {
    char imei[16];
    char calculated_nck[9];
    
    // Get IMEI
    dsm_modem_get_imei(imei);
    
    // Validate SPC
    if (!validate_spc(spc)) {
        return ERROR_INVALID_SPC;
    }
    
    // Calculate expected NCK from IMEI
    generate_nck_from_imei(imei, calculated_nck);
    
    // Compare
    if (strcmp(nck, calculated_nck) == 0) {
        set_carrier_lock_status(UNBLOCKED);
        return SUCCESS;
    }
    
    // Decrement attempts
    if (--unlock_attempts <= 0) {
        set_carrier_lock_status(PERMANENTLY_BLOCKED);
    }
    
    return ERROR_AUTHENTICATION_FAILED;
}
```

### Scenario C: Hash-Based (Most Secure)

```c
int modem2_modem_carrier_unlock(char *nck, char *spc) {
    unsigned char hash[32];
    unsigned char stored_hash[32];
    
    // Validate SPC
    if (!validate_spc(spc)) {
        return ERROR_INVALID_SPC;
    }
    
    // Hash the provided NCK
    sha256(nck, strlen(nck), hash);
    
    // Compare with stored hash (from secure NV item)
    get_stored_nck_hash(stored_hash);
    
    if (memcmp(hash, stored_hash, 32) == 0) {
        set_carrier_lock_status(UNBLOCKED);
        return SUCCESS;
    }
    
    return ERROR_AUTHENTICATION_FAILED;
}
```

---

## Key Questions to Answer

1. **How is NCK validated?** (comparison, algorithm, hash)
2. **Where is expected NCK stored?** (NV item, hardcoded, calculated)
3. **What is SPC validation logic?** (default 000000?)
4. **How many unlock attempts allowed?** (retry limit)
5. **What triggers permanent lock?** (exceed attempts)
6. **Can lock be reversed?** (if permanently blocked)
7. **What QMI services are used?** (DMS, UIM?)
8. **Are there alternative unlock methods?** (other functions)

---

## Saving Your Work

### Export Function Decompilation

```
File → Export Program...
Format: C/C++
Select: Current function only
Output: F:\repo\zerosms\analysis\decompiled\modem2_modem_carrier_unlock.c
```

### Take Screenshots

```
Tools → Take Program Snapshot
Or use Windows Snip (Win+Shift+S)
Save to: F:\repo\zerosms\analysis\screenshots\
```

### Save Project

```
File → Save Project (Ctrl+S)
Ghidra auto-saves, but good practice
```

---

## Next Steps After Analysis

Once you understand the algorithm:

1. **Document findings** in markdown
2. **Implement status check** in mifi_controller.py
3. **Test SPC validation** (with default 000000)
4. **Research NCK calculation** (if algorithm-based)
5. **Consider unlock attempt** (only if NCK known and safe)

---

## Tips

- **Take your time**: Reverse engineering requires patience
- **Use comments**: Right-click → Edit Comment to annotate code
- **Follow the logic**: Start from top, trace execution paths
- **Check cross-refs**: See how function is called elsewhere
- **Compare with docs**: Cross-reference with QMI documentation if available

---

## Common Ghidra Shortcuts

```
G       - Go to address/function
L       - Rename variable
;       - Add comment
Ctrl+E  - Edit function signature
Ctrl+F  - Find (in current view)
Ctrl+Shift+F - Search functions
Ctrl+Shift+E - Search memory
```

---

## If You Get Stuck

1. **Search strings**: Look for error messages, they reveal logic
2. **Follow QMI calls**: QMI functions are well-documented online
3. **Check similar functions**: Analyze `validate_spc` first (simpler)
4. **Use call graph**: Visual representation helps understand flow
5. **Take breaks**: Fresh eyes spot patterns better

---

**Good luck with the analysis! Document everything you find.**
