#!/usr/bin/env python3
"""Quick binary analysis using Capstone"""
import capstone
import struct
import re


def analyze_binary(path, base=0x10000):
    print(f"\n{'='*70}\nAnalyzing: {path}\n{'='*70}")

    data = open(path, 'rb').read()
    print(f"Size: {len(data)} bytes")

    # Find strings
    strings = re.findall(b'[\x20-\x7E]{4,}', data)
    commands = sorted(
        set([s.decode() for s in strings if re.match(b'^[a-z_][a-z0-9_]+$', s)]))
    print(f"\nCommand strings ({len(commands)}):")
    for cmd in commands[:80]:
        print(f"  {cmd}")

    # Disassemble entry point
    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
    print(f"\nFirst 30 instructions at 0x{base:x}:")
    for i in list(md.disasm(data[:200], base))[:30]:
        print(f"0x{i.address:08x}: {i.mnemonic:8s} {i.op_str}")

    # Find "write_nv" or "unlock_carrier"
    targets = [b'write_nv', b'unlock_carrier', b'unlock_carrier_lock']
    for target in targets:
        offset = data.find(target)
        if offset != -1:
            print(f"\nFound '{target.decode()}' at file offset 0x{offset:x}")


# Analyze nwcli
analyze_binary('f:/repo/zerosms/binaries/nwcli', 0x10000)

# Analyze modem2_cli
analyze_binary('f:/repo/zerosms/binaries/modem2_cli', 0x10000)
