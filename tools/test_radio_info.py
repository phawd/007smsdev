#!/usr/bin/env python3
"""Quick test of radio and network info functions"""

from mifi_controller import (
    radio_is_enabled,
    active_band_get,
    get_voice_signal,
    get_reject_cause_code,
    get_oper_info,
    get_service_info,
)

# Test radio status
print("=== Radio Status ===")
enabled = radio_is_enabled()
print(f"Radio enabled: {enabled}")
print()

# Test active band
print("=== Active Band ===")
band_info = active_band_get()
print(f"Band: {band_info.get('band', 'N/A')}")
print(f"Channel: {band_info.get('channel', 'N/A')}")
print(f"Raw: {band_info['raw'][:100]}...")
print()

# Test voice signal
print("=== Voice Signal ===")
voice_sig = get_voice_signal()
for key, val in voice_sig.items():
    if key != 'raw':
        print(f"{key}: {val}")
print()

# Test operator info
print("=== Operator Info ===")
oper_info = get_oper_info()
print(f"MCC: {oper_info.get('mcc', 'N/A')}")
print(f"MNC: {oper_info.get('mnc', 'N/A')}")
print(f"Name: {oper_info.get('name', 'N/A')}")
print()

# Test service info
print("=== Service Info ===")
service_info = get_service_info()
for key, val in service_info.items():
    if key != 'raw':
        print(f"{key}: {val}")
