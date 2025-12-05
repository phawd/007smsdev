#!/usr/bin/env python3
"""
Ghidra Headless Analysis Script for libmal_qct.so
Focuses on carrier unlock mechanism

This script is designed to be run with Ghidra's analyzeHeadless tool:
    analyzeHeadless <project_location> <project_name> -import <file> -postScript ghidra_unlock_analysis.py

Target Functions (discovered via string analysis):
    - modem2_modem_carrier_unlock (PRIMARY)
    - modem2_modem_get_carrier_unlock_status
    - modem2_modem_validate_spc
    - modem2_modem_get_spc_validate_limit
    - dsm_modem_get_imei
    - nwqmi_dms_validate_spc
"""

# This is a Ghidra Python script - requires Ghidra API
# For now, this is a template. Actual analysis will be done interactively.

from ghidra.program.model.symbol import SymbolType
from ghidra.program.model.listing import CodeUnit
from ghidra.app.decompiler import DecompInterface
import json


def find_function_by_name(program, name):
    """Find function by name."""
    symbol_table = program.getSymbolTable()
    symbols = symbol_table.getSymbols(name)

    for symbol in symbols:
        if symbol.getSymbolType() == SymbolType.FUNCTION:
            return program.getFunctionManager().getFunctionAt(symbol.getAddress())
    return None


def decompile_function(program, function):
    """Decompile a function and return C code."""
    if function is None:
        return None

    decompiler = DecompInterface()
    decompiler.openProgram(program)

    results = decompiler.decompileFunction(function, 30, monitor)
    if results and results.decompileCompleted():
        return results.getDecompiledFunction().getC()
    return None


def analyze_unlock_functions(program):
    """Analyze all unlock-related functions."""

    target_functions = [
        "modem2_modem_carrier_unlock",
        "modem2_modem_get_carrier_unlock_status",
        "modem2_modem_validate_spc",
        "modem2_modem_get_spc_validate_limit",
        "modem2_modem_unblock_pin",
        "dsm_modem_get_imei",
        "nwqmi_dms_validate_spc",
        "nwqmi_uim_unblock_pin"
    ]

    results = {}

    for func_name in target_functions:
        print(f"[*] Analyzing {func_name}...")
        func = find_function_by_name(program, func_name)

        if func:
            print(f"    [+] Found at {func.getEntryPoint()}")

            # Decompile
            code = decompile_function(program, func)
            if code:
                results[func_name] = {
                    "address": str(func.getEntryPoint()),
                    "code": code,
                    "parameters": func.getParameterCount(),
                    "local_vars": func.getLocalVariables().length
                }
                print(f"    [+] Decompiled successfully")
            else:
                print(f"    [-] Decompilation failed")
        else:
            print(f"    [-] Function not found")

    return results


def main():
    """Main analysis routine."""
    program = getCurrentProgram()

    print("=" * 70)
    print("Ghidra Unlock Analysis - libmal_qct.so")
    print("=" * 70)

    # Analyze all unlock functions
    results = analyze_unlock_functions(program)

    # Save results
    output_file = "/tmp/unlock_analysis_results.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\n[*] Results saved to {output_file}")
    print(f"[*] Analyzed {len(results)} functions")

    # Print summary
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    for func_name, data in results.items():
        print(f"{func_name}:")
        print(f"  Address: {data.get('address', 'N/A')}")
        print(f"  Parameters: {data.get('parameters', 'N/A')}")
        print(f"  Local Variables: {data.get('local_vars', 'N/A')}")
        print()


if __name__ == "__main__":
    main()
