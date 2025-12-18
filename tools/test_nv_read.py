#!/usr/bin/env python3
"""Quick test of NV read functions"""

from mifi_controller import nv_read, nv_read_range

# Test single read
print("=== Testing single NV read (NV 550 - IMEI) ===")
success, msg, data = nv_read(550)
print(f"Success: {success}")
print(f"Message: {msg}")
print(f"Data (hex): {data.hex()[:50]}...")
print()

# Test range read
print("=== Testing NV range read (0-10) ===")
results = nv_read_range(0, 10)
for nv_id, (success, data) in sorted(results.items()):
    status = "OK" if success else "FAIL"
    print(
        f"NV {nv_id:5d}: {status:4s} - {len(data):3d} bytes - {data.hex()[:40]}")
print()

# Test CDMA provisioning items
print("=== Testing CDMA provisioning items (32, 33, 178, 264, 265) ===")
cdma_items = [32, 33, 178, 264, 265]
for nv_id in cdma_items:
    success, msg, data = nv_read(nv_id)
    status = "OK" if success else "FAIL"
    print(
        f"NV {nv_id:5d}: {status:4s} - {len(data):3d} bytes - {data.hex()[:40]}")
