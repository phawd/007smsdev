"""
Ghidra Function Extractor - Extract specific decompiled functions
Run this in Ghidra Script Manager on libmal_qct.so
"""

from ghidra.program.model.symbol import SymbolType
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor


def find_function_by_name(program, name):
    """Find function by exact name."""
    symbol_table = program.getSymbolTable()
    symbols = symbol_table.getSymbols(name)

    for symbol in symbols:
        if symbol.getSymbolType() == SymbolType.FUNCTION:
            return program.getFunctionManager().getFunctionAt(symbol.getAddress())
    return None


def decompile_function(program, function):
    """Decompile function to C pseudocode."""
    if function is None:
        return None

    decompiler = DecompInterface()
    decompiler.openProgram(program)
    monitor = ConsoleTaskMonitor()

    results = decompiler.decompileFunction(function, 30, monitor)
    if results and results.decompileCompleted():
        return results.getDecompiledFunction().getC()
    return None


def main():
    program = getCurrentProgram()

    # Target functions to extract
    target_functions = [
        "modem2_modem_carrier_unlock",
        "modem2_modem_get_carrier_unlock_status",
        "modem2_modem_validate_spc",
        "modem2_modem_get_spc_validate_limit",
        "nwqmi_dms_validate_spc",
        "dsm_modem_get_imei"
    ]

    output_lines = []
    output_lines.append("=" * 80)
    output_lines.append("Ghidra Function Decompilation - libmal_qct.so")
    output_lines.append("=" * 80)
    output_lines.append("")

    for func_name in target_functions:
        print("[*] Extracting: " + func_name)
        func = find_function_by_name(program, func_name)

        if func:
            addr = str(func.getEntryPoint())
            print("    [+] Found at: " + addr)

            output_lines.append("")
            output_lines.append("-" * 80)
            output_lines.append("Function: " + func_name)
            output_lines.append("Address: " + addr)
            output_lines.append("-" * 80)
            output_lines.append("")

            code = decompile_function(program, func)
            if code:
                output_lines.append(code)
                print("    [+] Decompiled (" + str(len(code)) + " chars)")
            else:
                output_lines.append("// Decompilation failed")
                print("    [!] Decompilation failed")
        else:
            print("    [!] Function not found")
            output_lines.append("")
            output_lines.append("-" * 80)
            output_lines.append("Function: " + func_name + " - NOT FOUND")
            output_lines.append("-" * 80)
            output_lines.append("")

    # Write to file
    output_file = "F:\\repo\\zerosms\\analysis\\decompiled\\unlock_functions.c"
    try:
        with open(output_file, "w") as f:
            f.write("\n".join(output_lines))
        print("\n[+] Exported to: " + output_file)
    except Exception as e:
        print("\n[!] Export failed: " + str(e))


if __name__ == "__main__":
    main()
