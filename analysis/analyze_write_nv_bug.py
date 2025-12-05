#!/usr/bin/env python3
"""
Targeted disassembly of nwcli write_nv bug
=========================================

Finds write_nv function and traces parameter handling to identify
why NV item 550 writes to NV 60044 instead.
"""

import capstone
import struct
import re


def find_string(data, target):
    """Find string in binary and return offset"""
    target_bytes = target.encode('ascii') + b'\x00'
    offset = data.find(target_bytes)
    return offset if offset != -1 else None


def find_word_references(data, word_value, max_refs=10):
    """Find little-endian word references in binary"""
    word_bytes = struct.pack('<I', word_value)
    refs = []
    offset = 0
    while len(refs) < max_refs:
        offset = data.find(word_bytes, offset)
        if offset == -1:
            break
        # Align to 4-byte boundary
        if offset % 4 == 0:
            refs.append(offset)
        offset += 1
    return refs


def disassemble_function(data, start_offset, base_addr=0x10000, max_insns=100):
    """Disassemble function starting at offset"""
    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
    md.detail = True

    instructions = []
    code = data[start_offset:start_offset + max_insns * 4]
    addr = base_addr + start_offset

    for insn in md.disasm(code, addr):
        instructions.append({
            'addr': insn.address,
            'offset': insn.address - base_addr,
            'mnemonic': insn.mnemonic,
            'op_str': insn.op_str,
            'bytes': insn.bytes.hex()
        })

        # Stop at function return
        if insn.mnemonic in ['bx', 'pop'] and 'pc' in insn.op_str.lower():
            break
        if insn.mnemonic == 'bx' and 'lr' in insn.op_str:
            break

    return instructions


def analyze_write_nv_bug():
    """Main analysis function"""
    print("="*70)
    print("NWCLI WRITE_NV BUG ANALYSIS")
    print("="*70)

    # Load binary
    nwcli_path = 'f:/repo/zerosms/binaries/nwcli'
    data = open(nwcli_path, 'rb').read()
    base_addr = 0x10000

    print(f"\n[+] Loaded nwcli: {len(data)} bytes")

    # Find "write_nv" string
    write_nv_offset = find_string(data, "write_nv")
    if not write_nv_offset:
        print("[-] ERROR: write_nv string not found!")
        return

    write_nv_addr = base_addr + write_nv_offset
    print(
        f"[+] Found 'write_nv' string at offset 0x{write_nv_offset:x} (addr 0x{write_nv_addr:x})")

    # Find references to this string address
    print(f"\n[+] Searching for references to 0x{write_nv_addr:x}...")
    refs = find_word_references(data, write_nv_addr, max_refs=20)
    print(f"[+] Found {len(refs)} potential references")

    # Analyze each reference
    for i, ref_offset in enumerate(refs):
        ref_addr = base_addr + ref_offset
        print(f"\n{'='*70}")
        print(
            f"Reference #{i+1}: offset 0x{ref_offset:x}, addr 0x{ref_addr:x}")
        print('='*70)

        # Find function start (scan backward for push {... lr})
        func_start_offset = ref_offset
        for scan_offset in range(ref_offset - 200, ref_offset, 4):
            if scan_offset < 0:
                break
            # Check for PUSH instruction (0xe92d or 0xe52d patterns)
            word = struct.unpack('<I', data[scan_offset:scan_offset+4])[0]
            if (word & 0xffff0000) == 0xe92d0000:  # PUSH {...}
                if word & 0x4000:  # LR bit set
                    func_start_offset = scan_offset
                    break

        func_start_addr = base_addr + func_start_offset
        print(
            f"[+] Likely function start: offset 0x{func_start_offset:x}, addr 0x{func_start_addr:x}")

        # Disassemble function
        instructions = disassemble_function(
            data, func_start_offset, base_addr, max_insns=150)

        print(f"\n[+] Disassembled {len(instructions)} instructions:")
        print()

        # Print with annotations
        for insn in instructions:
            # Highlight interesting instructions
            highlight = ""
            if 'nwqmi' in insn['op_str']:
                highlight = " ← QMI CALL"
            elif any(reg in insn['op_str'] for reg in ['r0', 'r1', 'r2', 'r3']):
                if insn['mnemonic'] in ['mov', 'ldr', 'str']:
                    highlight = " ← PARAMETER"

            print(
                f"  0x{insn['addr']:08x}: {insn['mnemonic']:8s} {insn['op_str']:30s}{highlight}")

            # Stop if we hit another function
            if insn['addr'] > ref_addr + 500:
                print("  ... (truncated)")
                break

    # Additional analysis: Find nwqmi_nvtl_nv_item_write_cmd
    print(f"\n{'='*70}")
    print("SEARCHING FOR QMI WRITE FUNCTION")
    print('='*70)

    qmi_write_offset = find_string(data, "nwqmi_nvtl_nv_item_write_cmd")
    if qmi_write_offset:
        qmi_write_addr = base_addr + qmi_write_offset
        print(
            f"[+] Found 'nwqmi_nvtl_nv_item_write_cmd' at offset 0x{qmi_write_offset:x}")
        print(f"[+] Address: 0x{qmi_write_addr:x}")

        # Find references
        qmi_refs = find_word_references(data, qmi_write_addr, max_refs=10)
        print(f"[+] Found {len(qmi_refs)} references to QMI write function")
        for ref_offset in qmi_refs:
            ref_addr = base_addr + ref_offset
            print(f"  - Offset 0x{ref_offset:x} (addr 0x{ref_addr:x})")

    print(f"\n{'='*70}")
    print("ANALYSIS COMPLETE")
    print('='*70)
    print("\nNext steps:")
    print("1. Identify which function is write_nv handler (look for string comparison)")
    print("2. Trace argv[2] (NV item ID parameter) through function")
    print("3. Find where 550 is transformed to 60044")
    print("4. Check for: array indexing bug, parameter swap, or hardcoded offset")
    print("\nTo fix:")
    print("- If bug is simple offset, patch with LIEF")
    print("- If bug is complex, bypass nwcli and call libmal_qct.so directly")


if __name__ == "__main__":
    analyze_write_nv_bug()
