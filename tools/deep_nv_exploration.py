#!/usr/bin/env python3
"""
Deep NV Item Exploration

Systematically reads extended NV item ranges to map provisioning data.
Safe read-only operations.
"""

import sys
import os
import time
from mifi_controller import nv_read_range

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def explore_nv_range(start, end, desc):
    """Explore a range of NV items and report findings."""
    print(f"\n{'='*70}")
    print(f"Exploring NV Range {start}-{end}: {desc}")
    print(f"{'='*70}\n")

    results = nv_read_range(start, end)

    non_empty = []
    for nv_id, (success, data) in results.items():
        if success and len(data) > 0:
            # First 16 bytes preview
            non_empty.append((nv_id, len(data), data[:16].hex()))

    print(f"Results: {len(results)} items read, "
          f"{len(non_empty)} contain data\n")

    if non_empty:
        print("Non-empty items:")
        for nv_id, size, preview in non_empty:
            print(f"  NV {nv_id:5d}: {size:4d} bytes - {preview}...")
    else:
        print("  (All items empty or inaccessible)")

    return non_empty


def main():
    """Main exploration routine."""
    print("=" * 70)
    print("DEEP NV EXPLORATION - Extended Range Scan")
    print("=" * 70)
    print()
    print("⚠️  READ-ONLY OPERATIONS - SAFE")
    print()

    # Define ranges to explore with descriptions
    ranges = [
        (100, 150, "Extended Security & Auth"),
        (200, 250, "CDMA Provisioning Extended"),
        (500, 550, "Core Device Identifiers"),
        (600, 650, "Network Selection"),
        (1000, 1050, "Advanced CDMA"),
        (1500, 1550, "LTE Configuration"),
        (2000, 2050, "IMS/VoLTE Settings"),
        (3000, 3050, "Security & Lock"),
        (3450, 3470, "Carrier Lock Region"),
        (4000, 4050, "Advanced Features"),
        (4390, 4410, "Lock Status Region"),
    ]

    all_findings = {}

    for start, end, desc in ranges:
        findings = explore_nv_range(start, end, desc)
        if findings:
            all_findings[f"{start}-{end}"] = findings
        time.sleep(0.5)  # Brief pause between ranges

    # Summary
    print(f"\n{'='*70}")
    print("EXPLORATION SUMMARY")
    print(f"{'='*70}\n")

    total_ranges = len(ranges)
    ranges_with_data = len(all_findings)
    total_items = sum(len(items) for items in all_findings.values())

    print(f"Ranges scanned: {total_ranges}")
    print(f"Ranges with data: {ranges_with_data}")
    print(f"Total non-empty items found: {total_items}")
    print()

    if all_findings:
        print("Detailed findings by range:")
        for range_name, items in all_findings.items():
            print(f"\n  {range_name}:")
            for nv_id, size, preview in items[:5]:  # Show first 5 per range
                print(f"    NV {nv_id}: {size} bytes - {preview}...")
            if len(items) > 5:
                print(f"    ... and {len(items) - 5} more items")

    print(f"\n{'='*70}")
    print("Exploration complete - All data saved above")
    print(f"{'='*70}")


if __name__ == "__main__":
    main()
