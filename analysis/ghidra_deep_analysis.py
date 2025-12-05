#!/usr/bin/env python3
"""
Ghidra Deep Analysis Script for QMI/NV/EFS Layers
Compatible with Jython 2.7 (Ghidra's Python)

This script analyzes binaries to understand:
- QMI service implementations
- NV item read/write mechanisms
- EFS file operations
- Unlock mechanisms
"""

from ghidra.program.model.symbol import SymbolType, SourceType
from ghidra.program.model.listing import CodeUnit
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.data import *
import re


def find_functions_by_pattern(program, pattern):
    """Find all functions matching a regex pattern."""
    matched = []
    symbol_table = program.getSymbolTable()

    for symbol in symbol_table.getAllSymbols(True):
        if symbol.getSymbolType() == SymbolType.FUNCTION:
            name = symbol.getName()
            if re.search(pattern, name, re.IGNORECASE):
                func = program.getFunctionManager().getFunctionAt(
                    symbol.getAddress())
                if func:
                    matched.append((name, func))

    return matched


def decompile_function(program, function, timeout=30):
    """Decompile a function and return C code."""
    if function is None:
        return None

    decompiler = DecompInterface()
    decompiler.openProgram(program)

    results = decompiler.decompileFunction(function, timeout, monitor)
    if results and results.decompileCompleted():
        return results.getDecompiledFunction().getC()
    return None


def find_string_references(program, search_string):
    """Find all references to a string."""
    refs = []
    memory = program.getMemory()

    # Search through all memory blocks
    for block in memory.getBlocks():
        if not block.isInitialized():
            continue

        addr = block.getStart()
        end = block.getEnd()

        while addr.compareTo(end) < 0:
            try:
                data = program.getListing().getDataAt(addr)
                if data and data.hasStringValue():
                    value = data.getValue()
                    if value and search_string.lower() in str(value).lower():
                        refs.append((addr, str(value)))
            except:
                pass
            addr = addr.add(1)

    return refs


def analyze_qmi_functions(program):
    """Analyze QMI-related functions."""
    print("=" * 70)
    print("QMI Layer Analysis")
    print("=" * 70)

    qmi_patterns = [
        "qmi_client.*",
        "qmi_idl.*",
        "qmi_dms.*",
        "qmi_nas.*",
        "qmi_uim.*",
        "qmi_wds.*",
        "qmiservices.*"
    ]

    results = {}

    for pattern in qmi_patterns:
        print("\n[*] Searching for: " + pattern)
        funcs = find_functions_by_pattern(program, pattern)

        if funcs:
            print("    [+] Found " + str(len(funcs)) + " functions")
            results[pattern] = []

            for name, func in funcs[:5]:  # Limit to first 5
                print("        - " + name)
                addr = str(func.getEntryPoint())
                params = func.getParameterCount()

                results[pattern].append({
                    "name": name,
                    "address": addr,
                    "params": params
                })
        else:
            print("    [-] No matches")

    return results


def analyze_nv_functions(program):
    """Analyze NV item read/write functions."""
    print("\n" + "=" * 70)
    print("NV Layer Analysis")
    print("=" * 70)

    nv_patterns = [
        "nv_read.*",
        "nv_write.*",
        "nvtl.*",
        ".*nv_item.*",
        "efs_get.*",
        "efs_put.*",
        "efs_read.*",
        "efs_write.*"
    ]

    results = {}

    for pattern in nv_patterns:
        print("\n[*] Searching for: " + pattern)
        funcs = find_functions_by_pattern(program, pattern)

        if funcs:
            print("    [+] Found " + str(len(funcs)) + " functions")
            results[pattern] = []

            for name, func in funcs[:10]:
                print("        - " + name)
                addr = str(func.getEntryPoint())

                results[pattern].append({
                    "name": name,
                    "address": addr
                })
        else:
            print("    [-] No matches")

    return results


def analyze_unlock_mechanism(program):
    """Deep analysis of unlock mechanisms."""
    print("\n" + "=" * 70)
    print("Unlock Mechanism Analysis")
    print("=" * 70)

    unlock_patterns = [
        ".*unlock.*",
        ".*carrier.*",
        ".*validate_spc.*",
        ".*validate_nck.*",
        ".*lock_status.*",
        ".*imei.*"
    ]

    results = {}

    for pattern in unlock_patterns:
        print("\n[*] Searching for: " + pattern)
        funcs = find_functions_by_pattern(program, pattern)

        if funcs:
            print("    [+] Found " + str(len(funcs)) + " functions")
            results[pattern] = []

            for name, func in funcs:
                addr = str(func.getEntryPoint())
                print("        - " + name + " @ " + addr)

                # Try to decompile key functions
                if "modem2_modem_carrier_unlock" in name:
                    print(
                        "          [*] Decompiling PRIMARY unlock function...")
                    code = decompile_function(program, func)
                    if code:
                        results["PRIMARY_UNLOCK"] = {
                            "name": name,
                            "address": addr,
                            "code": code
                        }
                        print("          [+] Decompiled successfully!")

                results.setdefault(pattern, []).append({
                    "name": name,
                    "address": addr
                })

    return results


def analyze_strings(program):
    """Analyze interesting strings in the binary."""
    print("\n" + "=" * 70)
    print("String Analysis")
    print("=" * 70)

    interesting_strings = [
        "QMI_ERR",
        "BLOCKED",
        "UNLOCK",
        "CARRIER",
        "NV_",
        "/dev/smd",
        "/nv/item_files",
        "authentication",
        "validate",
        "SPC",
        "NCK"
    ]

    results = {}

    for search in interesting_strings:
        print("\n[*] Searching for: '" + search + "'")
        refs = find_string_references(program, search)

        if refs:
            print("    [+] Found " + str(len(refs)) + " occurrences")
            results[search] = []

            for addr, value in refs[:5]:  # Limit output
                print("        @ " + str(addr) + ": " + value[:60])
                results[search].append({
                    "address": str(addr),
                    "value": value
                })
        else:
            print("    [-] Not found")

    return results


def export_results(results, filename):
    """Export results to a file."""
    try:
        output_path = "F:\\repo\\zerosms\\analysis\\decompiled\\" + filename
        with open(output_path, "w") as f:
            f.write("Ghidra Deep Analysis Results\n")
            f.write("=" * 70 + "\n\n")

            for category, data in results.items():
                f.write("\n" + category + "\n")
                f.write("-" * 70 + "\n")
                f.write(str(data) + "\n\n")

        print("\n[+] Results exported to: " + output_path)
        return True
    except Exception as e:
        print("\n[!] Export failed: " + str(e))
        return False


def main():
    """Main analysis routine."""
    program = getCurrentProgram()

    if program is None:
        print("[!] No program loaded")
        return

    prog_name = program.getName()
    print("\n" + "=" * 70)
    print("Ghidra Deep Analysis - " + prog_name)
    print("=" * 70)

    all_results = {}

    # Run all analyses
    print("\n[1/4] Analyzing QMI layer...")
    all_results["QMI_Functions"] = analyze_qmi_functions(program)

    print("\n[2/4] Analyzing NV/EFS layer...")
    all_results["NV_Functions"] = analyze_nv_functions(program)

    print("\n[3/4] Analyzing unlock mechanisms...")
    all_results["Unlock_Functions"] = analyze_unlock_mechanism(program)

    print("\n[4/4] Analyzing strings...")
    all_results["Strings"] = analyze_strings(program)

    # Export results
    output_file = prog_name.replace(
        ".so", "").replace(".", "_") + "_analysis.txt"
    export_results(all_results, output_file)

    # Print summary
    print("\n" + "=" * 70)
    print("Analysis Summary")
    print("=" * 70)

    for category, data in all_results.items():
        if isinstance(data, dict):
            count = sum(len(v) if isinstance(v, list)
                        else 1 for v in data.values())
        else:
            count = len(data) if isinstance(data, list) else 0
        print(category + ": " + str(count) + " items")

    print("\n[+] Analysis complete!")


if __name__ == "__main__":
    main()
