"""
Ghidra CLI Command Extractor - Extract command handlers from CLI binaries
Run this in Ghidra Script Manager on CLI binaries (sms_cli, gps_cli, wifi_cli, rmnetcli)
"""

from ghidra.program.model.symbol import SymbolType
from ghidra.program.model.listing import CodeUnit
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor


def find_command_handlers(program):
    """Find command handler functions and main dispatch logic."""
    listing = program.getListing()
    symbol_table = program.getSymbolTable()

    handlers = []

    # Search for command-related functions
    patterns = [
        ".*_cmd.*", ".*_command.*", ".*_handler.*",
        ".*process.*", ".*dispatch.*", "main"
    ]

    for pattern in patterns:
        symbols = symbol_table.getSymbolIterator(pattern, True)
        for symbol in symbols:
            if symbol.getSymbolType() == SymbolType.FUNCTION:
                func = program.getFunctionManager().getFunctionAt(symbol.getAddress())
                if func:
                    handlers.append({
                        'name': symbol.getName(),
                        'address': str(func.getEntryPoint()),
                        'function': func
                    })

    return handlers


def find_string_references(program):
    """Find command strings that might indicate available commands."""
    listing = program.getListing()
    memory = program.getMemory()

    command_strings = []

    # Search for strings in .rodata section
    rodata = memory.getBlock(".rodata")
    if rodata:
        addr = rodata.getStart()
        end = rodata.getEnd()

        while addr.compareTo(end) < 0:
            data = listing.getDataAt(addr)
            if data and data.hasStringValue():
                string_val = data.getValue()
                if string_val:
                    s = str(string_val)
                    # Look for command-like strings
                    if any(keyword in s.lower() for keyword in
                           ['usage', 'command', 'option', 'help', '--', 'invalid']):
                        command_strings.append({
                            'address': str(addr),
                            'value': s
                        })
            addr = addr.add(1)

    return command_strings


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


def analyze_qmi_calls(program):
    """Find QMI-related function calls."""
    listing = program.getListing()
    symbol_table = program.getSymbolTable()

    qmi_calls = []

    # Find functions that call QMI services
    qmi_patterns = [
        "qmi_client_send_msg.*",
        "qmi_client_.*",
        "qmi_.*_req",
        "qmi_.*_resp"
    ]

    for pattern in qmi_patterns:
        symbols = symbol_table.getSymbolIterator(pattern, True)
        for symbol in symbols:
            if symbol.getSymbolType() == SymbolType.FUNCTION:
                # Find references to this function
                refs = symbol.getReferences()
                for ref in refs:
                    from_addr = ref.getFromAddress()
                    from_func = program.getFunctionManager().getFunctionContaining(from_addr)
                    if from_func:
                        qmi_calls.append({
                            'caller': from_func.getName(),
                            'caller_addr': str(from_func.getEntryPoint()),
                            'qmi_function': symbol.getName(),
                            'call_site': str(from_addr)
                        })

    return qmi_calls


def main():
    program = getCurrentProgram()
    binary_name = program.getName()

    output_lines = []
    output_lines.append("=" * 80)
    output_lines.append("CLI Binary Analysis - " + binary_name)
    output_lines.append("=" * 80)
    output_lines.append("")

    # 1. Find command handlers
    print("[*] Searching for command handlers...")
    handlers = find_command_handlers(program)

    output_lines.append("")
    output_lines.append("-" * 80)
    output_lines.append("COMMAND HANDLERS (" + str(len(handlers)) + " found)")
    output_lines.append("-" * 80)
    output_lines.append("")

    for handler in handlers:
        output_lines.append("Function: " + handler['name'])
        output_lines.append("Address: " + handler['address'])
        output_lines.append("")

    # 2. Find command strings
    print("[*] Extracting command strings...")
    cmd_strings = find_string_references(program)

    output_lines.append("")
    output_lines.append("-" * 80)
    output_lines.append(
        "COMMAND STRINGS (" + str(len(cmd_strings)) + " found)")
    output_lines.append("-" * 80)
    output_lines.append("")

    for cmd in cmd_strings:
        output_lines.append("@ " + cmd['address'] + ": " + cmd['value'])

    # 3. Find QMI calls
    print("[*] Analyzing QMI function calls...")
    qmi_calls = analyze_qmi_calls(program)

    output_lines.append("")
    output_lines.append("-" * 80)
    output_lines.append(
        "QMI FUNCTION CALLS (" + str(len(qmi_calls)) + " found)")
    output_lines.append("-" * 80)
    output_lines.append("")

    for call in qmi_calls:
        output_lines.append(
            "Caller: " + call['caller'] + " @ " + call['caller_addr'])
        output_lines.append(
            "  Calls: " + call['qmi_function'] + " @ " + call['call_site'])
        output_lines.append("")

    # 4. Decompile main function
    print("[*] Decompiling main function...")
    main_func = program.getFunctionManager().getFunctionsByName("main")
    if main_func:
        main_func = main_func.next()
        output_lines.append("")
        output_lines.append("-" * 80)
        output_lines.append("MAIN FUNCTION DECOMPILATION")
        output_lines.append("-" * 80)
        output_lines.append("")

        code = decompile_function(program, main_func)
        if code:
            output_lines.append(code)
        else:
            output_lines.append("// Decompilation failed")

    # Write output
    output_file = "F:\\repo\\zerosms\\analysis\\decompiled\\" + \
        binary_name + "_cli_analysis.txt"
    try:
        with open(output_file, "w") as f:
            f.write("\n".join(output_lines))
        print("\n[+] Exported to: " + output_file)
    except Exception as e:
        print("\n[!] Export failed: " + str(e))


if __name__ == "__main__":
    main()
