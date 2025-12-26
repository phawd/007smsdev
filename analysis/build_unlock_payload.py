#!/usr/bin/env python3
"""Build candidate modem2_carrier_unlock request payload (dry-run).

Produces `unlock_payload.bin` (binary) and prints a hex dump.
"""
from pathlib import Path

OUT = Path(__file__).with_name('unlock_payload.bin')

def build_payload(code_bytes: bytes, total_size: int = 0x68) -> bytes:
    # Candidate struct (inferred):
    # offset 0x00: reserved/flags (4 bytes)
    # offset 0x04: code_length (4 bytes)
    # offset 0x08: code payload (up to total_size-8)
    # rest: zero padding
    if len(code_bytes) > (total_size - 8):
        raise ValueError('code too long')
    payload = bytearray(total_size)
    payload[0:4] = (1).to_bytes(4, 'little')  # Flag
    payload[4:8] = (len(code_bytes)).to_bytes(4, 'little')  # Length
    payload[8:8+len(code_bytes)] = code_bytes  # Payload
    return bytes(payload)

def hexdump(b: bytes, width: int = 16) -> str:
    lines = []
    for i in range(0, len(b), width):
        chunk = b[i:i+width]
        hex_bytes = ' '.joinghidra.program.model.listing.Function(f"{x:02x}" for x in chunk)
        ascii_repr = ''.join((chr(x) if 32 <= x < 127 else '.') for x in chunk)
        lines.append(f"{i:08x}: {hex_bytes:<{width*3}}  {ascii_repr}")
    return '\n'.join(lines)

def main():
    # Use SPC 000000 (6 zeros)
    code = b'000000'
    payload = build_payload(code)
    OUT.write_bytes(payload)
    print(f'Wrote {OUT} ({len(payload)} bytes)')
    print('\nHex dump:')
    print(hexdump(payload))

if __name__ == '__main__':
    main()
