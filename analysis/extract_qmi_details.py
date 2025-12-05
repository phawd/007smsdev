"""
Advanced QMI Service Discovery - Extract QMI service IDs and message types
Run this in Ghidra to discover complete QMI service architecture
"""

from ghidra.program.model.data import DataType
from ghidra.program.model.symbol import SymbolType
from ghidra.util.task import ConsoleTaskMonitor


def find_qmi_service_ids(program):
    """
    Find QMI service ID definitions and constants.
    Common QMI services:
    - DMS (Device Management): 0x02
    - NAS (Network Access): 0x03
    - WDS (Wireless Data): 0x01
    - UIM (User Identity Module): 0x0B
    - PDS (Position Determination): 0x06
    """
    listing = program.getListing()
    memory = program.getMemory()

    service_ids = {}

    # Search for QMI service ID constants in .rodata
    rodata = memory.getBlock(".rodata")
    if rodata:
        addr = rodata.getStart()
        end = rodata.getEnd()

        # Look for byte sequences that match known QMI service IDs
        known_services = {
            0x01: "WDS (Wireless Data Service)",
            0x02: "DMS (Device Management Service)",
            0x03: "NAS (Network Access Service)",
            0x04: "QOS (Quality of Service)",
            0x05: "WMS (Wireless Messaging Service)",
            0x06: "PDS (Position Determination Service)",
            0x07: "AUTH (Authentication Service)",
            0x08: "AT (AT Command Processor)",
            0x09: "VOICE (Voice Service)",
            0x0A: "CAT2 (Card Application Toolkit v2)",
            0x0B: "UIM (User Identity Module)",
            0x0C: "PBM (Phonebook Manager)",
            0x0E: "RMTFS (Remote File System)",
            0x10: "LOC (Location Service)",
            0x11: "SAR (Specific Absorption Rate)",
            0x14: "CSD (Circuit Switched Data)",
            0x17: "TS (Test Service)",
            0x18: "TMD (Thermal Mitigation Device)",
            0x1A: "WDA (Wireless Data Administrative)",
            0xE0: "CAT (Card Application Toolkit)",
            0xE1: "RMS (Remote Management Service)",
            0xE2: "OMA (Open Mobile Alliance)"
        }

        while addr.compareTo(end) < 0:
            try:
                byte_val = memory.getByte(addr) & 0xFF
                if byte_val in known_services:
                    service_ids[str(addr)] = {
                        'id': byte_val,
                        'name': known_services[byte_val]
                    }
            except:
                pass
            addr = addr.add(1)

    return service_ids


def find_qmi_message_ids(program):
    """Find QMI message ID definitions."""
    symbol_table = program.getSymbolTable()

    messages = []

    # Search for message ID constants
    patterns = [
        "QMI_.*_REQ",
        "QMI_.*_RESP",
        "QMI_.*_IND",
        ".*_MSG_ID"
    ]

    for pattern in patterns:
        symbols = symbol_table.getSymbolIterator(pattern, True)
        for symbol in symbols:
            addr = symbol.getAddress()
            messages.append({
                'name': symbol.getName(),
                'address': str(addr),
                'type': symbol.getSymbolType().toString()
            })

    return messages


def find_qmi_data_structures(program):
    """Find QMI request/response structure definitions."""
    data_type_manager = program.getDataTypeManager()

    structures = []

    # Search for QMI-related structure definitions
    all_data_types = data_type_manager.getAllDataTypes()

    for dt in all_data_types:
        name = dt.getName()
        if any(keyword in name.lower() for keyword in
               ['qmi', 'req', 'resp', 'ind', 'msg']):
            structures.append({
                'name': name,
                'size': dt.getLength(),
                'category': dt.getCategoryPath().toString()
            })

    return structures


def find_nv_item_definitions(program):
    """Find NV item ID definitions and constants."""
    listing = program.getListing()
    symbol_table = program.getSymbolTable()
    memory = program.getMemory()

    nv_items = {}

    # Search for NV item constant definitions
    patterns = ["NV_.*", "RFNV_.*", ".*_NV_ITEM"]

    for pattern in patterns:
        symbols = symbol_table.getSymbolIterator(pattern, True)
        for symbol in symbols:
            addr = symbol.getAddress()
            try:
                # Try to read the value at this address
                value = memory.getInt(addr)
                nv_items[symbol.getName()] = {
                    'address': str(addr),
                    'value': hex(value)
                }
            except:
                nv_items[symbol.getName()] = {
                    'address': str(addr),
                    'value': 'unknown'
                }

    return nv_items


def find_efs_paths(program):
    """Find EFS filesystem path strings."""
    listing = program.getListing()
    memory = program.getMemory()

    efs_paths = []

    # Search for EFS path strings
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
                    # Look for EFS paths
                    if s.startswith('/nv/') or s.startswith('/efs/') or 'item_files' in s:
                        efs_paths.append({
                            'address': str(addr),
                            'path': s
                        })
            addr = addr.add(1)

    return efs_paths


def main():
    program = getCurrentProgram()
    binary_name = program.getName()

    output_lines = []
    output_lines.append("=" * 80)
    output_lines.append("Advanced QMI/NV/EFS Analysis - " + binary_name)
    output_lines.append("=" * 80)
    output_lines.append("")

    # 1. QMI Service IDs
    print("[*] Searching for QMI service IDs...")
    service_ids = find_qmi_service_ids(program)

    output_lines.append("")
    output_lines.append("-" * 80)
    output_lines.append(
        "QMI SERVICE IDs (" + str(len(service_ids)) + " found)")
    output_lines.append("-" * 80)
    output_lines.append("")

    for addr, info in sorted(service_ids.items()):
        output_lines.append("@ " + addr + ": Service 0x" +
                            format(info['id'], '02X') + " - " + info['name'])

    # 2. QMI Message IDs
    print("[*] Searching for QMI message IDs...")
    messages = find_qmi_message_ids(program)

    output_lines.append("")
    output_lines.append("-" * 80)
    output_lines.append("QMI MESSAGE IDs (" + str(len(messages)) + " found)")
    output_lines.append("-" * 80)
    output_lines.append("")

    for msg in messages:
        output_lines.append(msg['name'] + " @ " +
                            msg['address'] + " (" + msg['type'] + ")")

    # 3. QMI Data Structures
    print("[*] Analyzing QMI data structures...")
    structures = find_qmi_data_structures(program)

    output_lines.append("")
    output_lines.append("-" * 80)
    output_lines.append(
        "QMI DATA STRUCTURES (" + str(len(structures)) + " found)")
    output_lines.append("-" * 80)
    output_lines.append("")

    for struct in structures:
        output_lines.append(
            struct['name'] + " (size: " + str(struct['size']) + " bytes)")
        output_lines.append("  Category: " + struct['category'])
        output_lines.append("")

    # 4. NV Item Definitions
    print("[*] Searching for NV item definitions...")
    nv_items = find_nv_item_definitions(program)

    output_lines.append("")
    output_lines.append("-" * 80)
    output_lines.append(
        "NV ITEM DEFINITIONS (" + str(len(nv_items)) + " found)")
    output_lines.append("-" * 80)
    output_lines.append("")

    for name, info in sorted(nv_items.items()):
        output_lines.append(
            name + " @ " + info['address'] + " = " + info['value'])

    # 5. EFS Paths
    print("[*] Extracting EFS filesystem paths...")
    efs_paths = find_efs_paths(program)

    output_lines.append("")
    output_lines.append("-" * 80)
    output_lines.append(
        "EFS FILESYSTEM PATHS (" + str(len(efs_paths)) + " found)")
    output_lines.append("-" * 80)
    output_lines.append("")

    for path in efs_paths:
        output_lines.append("@ " + path['address'] + ": " + path['path'])

    # Write output
    output_file = "F:\\repo\\zerosms\\analysis\\decompiled\\" + \
        binary_name + "_qmi_nv_efs_detailed.txt"
    try:
        with open(output_file, "w") as f:
            f.write("\n".join(output_lines))
        print("\n[+] Exported to: " + output_file)
    except Exception as e:
        print("\n[!] Export failed: " + str(e))


if __name__ == "__main__":
    main()
