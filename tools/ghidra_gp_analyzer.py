# Ghidra Python Script (Jython)
# Analyzes GlobalPlatformPro (gp.jar) for SCP-related logic and key derivation logic
# specifically targeting SCP02/SCP03 and static key generation

from ghidra.program.model.listing import Function
from ghidra.program.model.symbol import SymbolType
from ghidra.util.task import TaskMonitor

print("=== GlobalPlatformPro JAR Analysis ===")
print("Searching for SCP key derivation and crypto functions...")

listing = currentProgram.getListing()
funcs = listing.getFunctions(True)
target_strings = ["derive", "calculate", "master", "static", "aes", "des", "scp02", "scp03", "mac", "enc"]

# Search functions by name
found_funcs = []
for func in funcs:
    name = func.getName().lower()
    if any(s in name for s in target_strings):
        found_funcs.append(func)
        # print("Found suspect function: " + func.getName() + " @ " + func.getEntryPoint().toString())

print("Found " + str(len(found_funcs)) + " potentially interesting functions.")

# Decompile top interesting functions (limit output)
# Note: Decompilation is slow, do only a few highly relevant ones if needed.
# For now, just list them sorted by relevance (simple heuristic)

print("\n--- Top Relevant Functions ---")
for func in found_funcs[:20]: # Limit to first 20 for brevity
    print(func.getName() + " @ " + func.getEntryPoint().toString())

# Search for specific strings in memory (if any)
model = currentProgram.getMemory()
searches = ["default", "404142434445464748494a4b4c4d4e4f"] # Default GP keys
# Note: In JAR analysis, strings are often in constant pool.

print("\nAnalysis complete.")
