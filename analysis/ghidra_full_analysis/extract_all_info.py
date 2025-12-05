# Comprehensive Ghidra Analysis Script - extract_all_info.py
# @category Analysis
# @author ZeroSMS Research

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
import json

# Initialize decompiler
decompiler = DecompInterface()
decompiler.openProgram(currentProgram)
monitor = ConsoleTaskMonitor()

output = []
output.append("=" * 80)
output.append("GHIDRA COMPREHENSIVE ANALYSIS REPORT")
output.append("=" * 80)
output.append("Binary: " + currentProgram.getName())
output.append("Base Address: " + hex(currentProgram.getImageBase().getOffset()))
output.append("")

# 1. PROGRAM INFO
output.append("\n[*] PROGRAM INFORMATION")
output.append("-" * 80)
output.append("Executable Format: " + currentProgram.getExecutableFormat())
output.append("Executable Path: " + currentProgram.getExecutablePath())
output.append("Compiler: " + str(currentProgram.getCompiler()))
output.append("Language: " + str(currentProgram.getLanguage()))
output.append("")

# 2. MEMORY LAYOUT
output.append("\n[*] MEMORY LAYOUT")
output.append("-" * 80)
for block in currentProgram.getMemory().getBlocks():
    output.append("  [{0}] {1} - {2} ({3} bytes) {4}".format(
        block.getName(),
        block.getStart(),
        block.getEnd(),
        block.getSize(),
        "R" + ("W" if block.isWrite() else "-") + ("X" if block.isExecute() else "-")
    ))
output.append("")

# 3. FUNCTIONS
output.append("\n[*] FUNCTIONS")
output.append("-" * 80)
fm = currentProgram.getFunctionManager()
functions = list(fm.getFunctions(True))
output.append("Total Functions: " + str(len(functions)))
output.append("")

# Group functions by category
imported_funcs = []
exported_funcs = []
internal_funcs = []

for func in functions:
    func_name = func.getName()
    func_addr = func.getEntryPoint()
    func_size = func.getBody().getNumAddresses()
    
    if func.isExternal():
        imported_funcs.append("  {0} @ EXTERNAL:{1}".format(func_name, func_addr))
    elif func.isThunk():
        exported_funcs.append("  {0} @ {1} (thunk)".format(func_name, func_addr))
    else:
        internal_funcs.append("  {0} @ {1} ({2} bytes)".format(func_name, func_addr, func_size))

output.append("Imported Functions ({0}):".format(len(imported_funcs)))
for f in imported_funcs[:50]:  # Limit to first 50
    output.append(f)
if len(imported_funcs) > 50:
    output.append("  ... and {0} more".format(len(imported_funcs) - 50))

output.append("\nExported Functions ({0}):".format(len(exported_funcs)))
for f in exported_funcs[:50]:
    output.append(f)
if len(exported_funcs) > 50:
    output.append("  ... and {0} more".format(len(exported_funcs) - 50))

output.append("\nInternal Functions ({0}):".format(len(internal_funcs)))
for f in internal_funcs[:50]:
    output.append(f)
if len(internal_funcs) > 50:
    output.append("  ... and {0} more".format(len(internal_funcs) - 50))

# 4. STRINGS
output.append("\n\n[*] INTERESTING STRINGS")
output.append("-" * 80)
string_count = 0
interesting_patterns = ["qmi", "nv", "efs", "unlock", "password", "key", "secret", "admin", "root", "config"]

for string in currentProgram.getListing().getDefinedData(True):
    if string.hasStringValue():
        string_val = string.getValue()
        if string_val and len(str(string_val)) > 3:
            string_str = str(string_val).lower()
            for pattern in interesting_patterns:
                if pattern in string_str:
                    output.append("  {0}: \"{1}\"".format(string.getAddress(), string_val))
                    string_count += 1
                    if string_count >= 100:  # Limit output
                        break
                    break
            if string_count >= 100:
                break

output.append("\nTotal interesting strings: " + str(string_count))

# 5. CROSS REFERENCES (for key functions)
output.append("\n\n[*] KEY FUNCTION CROSS-REFERENCES")
output.append("-" * 80)
key_funcs = ["unlock", "qmi", "nv_read", "nv_write", "validate", "check", "verify"]

for func in functions[:200]:  # Check first 200 functions
    func_name = func.getName().lower()
    for key in key_funcs:
        if key in func_name:
            output.append("\n  Function: {0} @ {1}".format(func.getName(), func.getEntryPoint()))
            refs = func.getCallingFunctions(monitor)
            if refs:
                output.append("    Called by:")
                for ref in list(refs)[:10]:  # Limit to 10 refs
                    output.append("      - {0} @ {1}".format(ref.getName(), ref.getEntryPoint()))
            break

# 6. DECOMPILE KEY FUNCTIONS (if requested)
output.append("\n\n[*] DECOMPILED FUNCTIONS (KEY FUNCTIONS ONLY)")
output.append("-" * 80)

key_functions_to_decompile = []
for func in functions:
    func_name = func.getName().lower()
    if any(keyword in func_name for keyword in ["unlock", "carrier", "validate", "spc", "nck", "otksk"]):
        if not func.isExternal() and not func.isThunk():
            key_functions_to_decompile.append(func)

output.append("Found {0} key functions to decompile".format(len(key_functions_to_decompile)))

for func in key_functions_to_decompile[:10]:  # Limit to 10 functions
    output.append("\n" + "=" * 80)
    output.append("FUNCTION: {0}".format(func.getName()))
    output.append("Address: {0}".format(func.getEntryPoint()))
    output.append("Size: {0} bytes".format(func.getBody().getNumAddresses()))
    output.append("-" * 80)
    
    try:
        results = decompiler.decompileFunction(func, 30, monitor)
        if results and results.decompileCompleted():
            decomp = results.getDecompiledFunction()
            if decomp:
                output.append(decomp.getC())
        else:
            output.append("// Decompilation failed or timed out")
    except:
        output.append("// Error during decompilation")

# Output everything
for line in output:
    println(line)

println("\n[+] Analysis complete!")
