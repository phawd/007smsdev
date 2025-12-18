#!/usr/bin/env python3
"""
Binary Analysis Tool for MiFi 8800L Binaries
=============================================

Uses Capstone disassembler to analyze ARM binaries from the device.
Extracts function tables, command dispatch logic, and hidden functionality.

Key Analysis Targets:
- nwcli: Fix write_nv parameter bug (writes to wrong NV item)
- modem2_cli: Reverse unlock_carrier for NCK bypass
- libmal_qct.so: Direct QMI NV write functions
- libsms_encoder.so: PDU manipulation for Flash/Silent SMS

Author: SMS Test Project
License: MIT
"""

import sys
import struct
import re
from pathlib import Path
from typing import List, Dict, Tuple, Optional, Any
from dataclasses import dataclass
from capstone import *
from capstone.arm import *

# ============================================================================
# DATA STRUCTURES
# ============================================================================


@dataclass
class Function:
    """Represents a discovered function"""
    address: int
    name: str
    size: int
    instructions: List[Tuple[int, str, str]]  # (addr, mnemonic, op_str)
    xrefs_to: List[int]  # Functions calling this
    xrefs_from: List[int]  # Functions called by this
    is_export: bool = False


@dataclass
class StringRef:
    """String reference found in binary"""
    address: int
    string: str
    refs: List[int]  # Addresses referencing this string


@dataclass
class CommandHandler:
    """Command dispatch table entry"""
    name: str
    handler_addr: int
    description: str = ""

# ============================================================================
# BINARY ANALYZER CLASS
# ============================================================================


class ARMBinaryAnalyzer:
    """Analyze ARM binaries for function discovery and reverse engineering"""

    def __init__(self, binary_path: str, base_addr: int = 0x10000):
        self.binary_path = Path(binary_path)
        self.base_addr = base_addr
        self.data = self.binary_path.read_bytes()
        self.size = len(self.data)

        # Initialize Capstone for ARM
        self.md = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
        self.md.detail = True

        # Analysis results
        self.functions: Dict[int, Function] = {}
        self.strings: Dict[int, StringRef] = {}
        self.command_table: List[CommandHandler] = []

        print(f"[*] Loaded {self.binary_path.name}: {self.size} bytes")

    def find_strings(self, min_length: int = 4) -> Dict[int, str]:
        """Extract ASCII strings from binary"""
        strings = {}
        current = bytearray()
        start_addr = 0

        for i, byte in enumerate(self.data):
            if 0x20 <= byte <= 0x7E:  # Printable ASCII
                if not current:
                    start_addr = i
                current.append(byte)
            else:
                if len(current) >= min_length:
                    addr = self.base_addr + start_addr
                    strings[addr] = current.decode('ascii', errors='ignore')
                current = bytearray()

        print(f"[*] Found {len(strings)} strings")
        return strings

    def find_function_prologues(self) -> List[int]:
        """Find ARM function prologues (push {r4-r11, lr} patterns)"""
        prologues = []

        # Common ARM function prologue patterns
        patterns = [
            b'\x00\x48\x2d\xe9',  # push {r11, lr}
            b'\x00\x40\x2d\xe9',  # push {lr}
            b'\xf0\x4f\x2d\xe9',  # push {r4-r11, lr}
        ]

        for pattern in patterns:
            offset = 0
            while True:
                offset = self.data.find(pattern, offset)
                if offset == -1:
                    break

                # Align to 4-byte boundary
                if offset % 4 == 0:
                    prologues.append(self.base_addr + offset)
                offset += 1

        prologues = sorted(set(prologues))
        print(f"[*] Found {len(prologues)} potential function prologues")
        return prologues

    def disassemble_function(self, start_addr: int, max_size: int = 512) -> Function:
        """Disassemble a function starting at address"""
        offset = start_addr - self.base_addr
        if offset < 0 or offset >= self.size:
            raise ValueError(f"Address 0x{start_addr:x} out of range")

        instructions = []
        func_size = 0
        code = self.data[offset:offset + max_size]

        for insn in self.md.disasm(code, start_addr):
            instructions.append((insn.address, insn.mnemonic, insn.op_str))
            func_size = insn.address - start_addr + insn.size

            # Stop at function epilogue (pop {pc} or bx lr)
            if insn.mnemonic in ['pop', 'bx'] and 'pc' in insn.op_str.lower():
                break
            if insn.mnemonic == 'bx' and 'lr' in insn.op_str:
                break

        func = Function(
            address=start_addr,
            name=f"sub_{start_addr:x}",
            size=func_size,
            instructions=instructions,
            xrefs_to=[],
            xrefs_from=[]
        )

        return func

    def find_command_strings(self) -> Dict[str, int]:
        """Find command name strings (lowercase with underscores)"""
        strings = self.find_strings()
        commands = {}

        # Pattern: lowercase letters, underscores, possibly digits
        cmd_pattern = re.compile(r'^[a-z][a-z0-9_]{2,40}$')

        for addr, string in strings.items():
            if cmd_pattern.match(string):
                commands[string] = addr

        print(f"[*] Found {len(commands)} potential command strings")
        return commands

    def find_dispatch_table(self) -> List[CommandHandler]:
        """Find command dispatch table (array of {name_ptr, handler_ptr})"""
        handlers = []

        # Search for pointer pairs (command name, handler function)
        for i in range(0, self.size - 8, 4):
            try:
                name_ptr = struct.unpack('<I', self.data[i:i+4])[0]
                handler_ptr = struct.unpack('<I', self.data[i+4:i+8])[0]

                # Check if name_ptr points to string in binary
                if self.base_addr <= name_ptr < self.base_addr + self.size:
                    name_offset = name_ptr - self.base_addr
                    if name_offset + 20 < self.size:
                        # Try to read string
                        null_pos = self.data.find(b'\x00', name_offset)
                        if null_pos > name_offset:
                            name = self.data[name_offset:null_pos].decode(
                                'ascii', errors='ignore')

                            # Check if handler_ptr is reasonable function address
                            if self.base_addr <= handler_ptr < self.base_addr + self.size:
                                if re.match(r'^[a-z_][a-z0-9_]+$', name):
                                    handlers.append(
                                        CommandHandler(name, handler_ptr))
            except:
                continue

        print(f"[*] Found {len(handlers)} command dispatch entries")
        return handlers

    def analyze_nwcli_write_nv(self) -> Dict[str, Any]:
        """Specific analysis for nwcli write_nv bug"""
        print("\n[*] Analyzing nwcli write_nv function...")

        # Find "write_nv" string
        strings = self.find_strings()
        write_nv_addr = None
        for addr, s in strings.items():
            if s == "write_nv":
                write_nv_addr = addr
                break

        if not write_nv_addr:
            return {"error": "write_nv string not found"}

        print(f"[+] Found 'write_nv' string at 0x{write_nv_addr:x}")

        # Find cross-references to this string
        # Look for LDR instructions loading this address
        xrefs = self.find_string_xrefs(write_nv_addr)
        print(f"[+] Found {len(xrefs)} references to 'write_nv'")

        # Disassemble each xref to find handler function
        for xref in xrefs[:3]:  # Analyze first 3 xrefs
            print(f"\n[+] Analyzing xref at 0x{xref:x}")
            func = self.disassemble_function(xref & ~1)  # Clear thumb bit

            # Look for NV item ID parameter parsing
            # First 50 instructions
            for addr, mnem, ops in func.instructions[:50]:
                print(f"  0x{addr:08x}: {mnem:8s} {ops}")

        return {"write_nv_addr": write_nv_addr, "xrefs": xrefs}

    def find_string_xrefs(self, string_addr: int, search_range: int = 0x10000) -> List[int]:
        """Find code addresses that reference a string"""
        xrefs = []

        # Convert address to bytes (little-endian)
        addr_bytes = struct.pack('<I', string_addr)

        # Search for this pattern in code
        offset = 0
        while offset < min(self.size, search_range):
            offset = self.data.find(addr_bytes, offset)
            if offset == -1:
                break
            xrefs.append(self.base_addr + offset)
            offset += 1

        return xrefs

    def analyze_unlock_carrier(self) -> Dict[str, Any]:
        """Analyze modem2_cli unlock_carrier function"""
        print("\n[*] Analyzing unlock_carrier function...")

        # Find "unlock_carrier" string
        strings = self.find_strings()
        unlock_addr = None
        for addr, s in strings.items():
            if "unlock_carrier" in s:
                unlock_addr = addr
                break

        if not unlock_addr:
            return {"error": "unlock_carrier string not found"}

        print(f"[+] Found 'unlock_carrier' string at 0x{unlock_addr:x}")

        # Find handler function
        xrefs = self.find_string_xrefs(unlock_addr)
        print(f"[+] Found {len(xrefs)} references")

        results = {
            "unlock_addr": unlock_addr,
            "xrefs": xrefs,
            "handlers": []
        }

        for xref in xrefs[:2]:
            func = self.disassemble_function(xref & ~1)
            results["handlers"].append({
                "addr": func.address,
                "size": func.size,
                "instructions": func.instructions[:30]  # First 30 instructions
            })

        return results

    def export_ghidra_script(self, output_path: str):
        """Export findings as Ghidra Python script"""
        script = f"""# Ghidra Auto-Analysis Script
# Generated by binary_analyzer.py for {self.binary_path.name}

# Command strings found:
"""
        commands = self.find_command_strings()
        for cmd, addr in sorted(commands.items()):
            script += f"createLabel(toAddr(0x{addr:x}), 'cmd_{cmd}', True)\n"

        script += "\n# Function prologues:\n"
        prologues = self.find_function_prologues()
        for i, addr in enumerate(prologues[:50]):  # First 50
            script += f"createFunction(toAddr(0x{addr:x}), 'discovered_func_{i}')\n"

        Path(output_path).write_text(script)
        print(f"[+] Exported Ghidra script to {output_path}")

# ============================================================================
# MAIN ANALYSIS FUNCTIONS
# ============================================================================


def analyze_nwcli(binary_path: str):
    """Analyze nwcli to fix write_nv bug"""
    print("\n" + "="*70)
    print("NWCLI WRITE_NV BUG ANALYSIS")
    print("="*70)

    analyzer = ARMBinaryAnalyzer(binary_path, base_addr=0x10000)

    # Find all commands
    commands = analyzer.find_command_strings()
    print(f"\n[+] Commands in nwcli: {sorted(commands.keys())}")

    # Analyze write_nv specifically
    results = analyzer.analyze_nwcli_write_nv()

    # Export for Ghidra
    analyzer.export_ghidra_script("f:/repo/zerosms/analysis/nwcli_ghidra.py")

    return results


def analyze_modem2_cli(binary_path: str):
    """Analyze modem2_cli to understand unlock_carrier"""
    print("\n" + "="*70)
    print("MODEM2_CLI UNLOCK_CARRIER ANALYSIS")
    print("="*70)

    analyzer = ARMBinaryAnalyzer(binary_path, base_addr=0x10000)

    # Find command dispatch table
    dispatch = analyzer.find_dispatch_table()
    print(f"\n[+] Found {len(dispatch)} command handlers:")
    for cmd in sorted(dispatch, key=lambda x: x.name)[:30]:
        print(f"  {cmd.name:30s} -> 0x{cmd.handler_addr:08x}")

    # Analyze unlock_carrier
    results = analyzer.analyze_unlock_carrier()

    # Export for Ghidra
    analyzer.export_ghidra_script(
        "f:/repo/zerosms/analysis/modem2_cli_ghidra.py")

    return results


def analyze_libmal_qct(binary_path: str):
    """Analyze libmal_qct.so for direct QMI NV write"""
    print("\n" + "="*70)
    print("LIBMAL_QCT.SO QMI NV WRITE ANALYSIS")
    print("="*70)

    analyzer = ARMBinaryAnalyzer(binary_path, base_addr=0)

    # Find nwqmi_nvtl_nv_item_write_cmd function
    strings = analyzer.find_strings()
    target_funcs = []
    for addr, s in strings.items():
        if "nwqmi_nvtl_nv_item_write" in s:
            print(f"[+] Found '{s}' at 0x{addr:x}")
            target_funcs.append((s, addr))

    # Export
    analyzer.export_ghidra_script(
        "f:/repo/zerosms/analysis/libmal_qct_ghidra.py")

    return {"functions": target_funcs}

# ============================================================================
# CLI INTERFACE
# ============================================================================


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="ARM Binary Analyzer for MiFi 8800L")
    parser.add_argument("binary", help="Path to binary file")
    parser.add_argument("--type", choices=["nwcli", "modem2_cli", "libmal", "auto"],
                        default="auto", help="Binary type")
    parser.add_argument("--export-ghidra", action="store_true",
                        help="Export Ghidra analysis script")
    parser.add_argument("--find-commands", action="store_true",
                        help="Find all command strings")
    parser.add_argument("--analyze-function",
                        help="Analyze specific function by name")

    args = parser.parse_args()

    # Auto-detect binary type
    binary_name = Path(args.binary).name.lower()
    if args.type == "auto":
        if "nwcli" in binary_name:
            args.type = "nwcli"
        elif "modem2" in binary_name:
            args.type = "modem2_cli"
        elif "libmal" in binary_name:
            args.type = "libmal"

    # Run appropriate analysis
    if args.type == "nwcli":
        results = analyze_nwcli(args.binary)
    elif args.type == "modem2_cli":
        results = analyze_modem2_cli(args.binary)
    elif args.type == "libmal":
        results = analyze_libmal_qct(args.binary)
    else:
        # Generic analysis
        analyzer = ARMBinaryAnalyzer(args.binary)

        if args.find_commands:
            commands = analyzer.find_command_strings()
            print(f"\nFound {len(commands)} commands:")
            for cmd in sorted(commands.keys()):
                print(f"  {cmd}")

        if args.export_ghidra:
            analyzer.export_ghidra_script(
                args.binary.replace(".so", "_ghidra.py"))

        results = {"commands": list(analyzer.find_command_strings().keys())}

    print("\n[+] Analysis complete!")
    return results


if __name__ == "__main__":
    main()
