#!/usr/bin/env python3
"""
Check for dangerous NV write occurrences in the diffs in this PR branch.

Usage: (in CI) run in repo root and this script will scan the git diff
between the default branch and HEAD for writes to the dangerous NV items
0xEA64 (60004), 0xEAAC (60076), 0xEA62 (60002).
"""

import sys
import subprocess
import re
from pathlib import Path

DANGEROUS_HEX = ["0xEA64", "0xEAAC", "0xEA62"]
DANGEROUS_DEC = [str(int(h, 16)) for h in DANGEROUS_HEX]

PATTERNS = [
    r"write_nv\s*\(",
    r"qmi_idl write_nv",
    r"nwcli .*write_nv",
    r"nwqmi_nvtl_nv_item_write_cmd\(",
    r"nv_write\s*\(",
]


def get_diff_text(base: str = "origin/master") -> str:
    try:
        proc = subprocess.run(["git", "fetch", "--quiet"], check=False)
        diff = subprocess.check_output(
            ["git", "diff", f"{base}...HEAD"], encoding="utf-8", errors="ignore"
        )
    except Exception as e:
        print("Error obtaining git diff:", e)
        sys.exit(2)
    return diff


def scan_diff(diff: str) -> int:
    found = 0
    lines = diff.splitlines()
    for i, line in enumerate(lines, start=1):
        # Check for write pattern and dangerous NV in the same added line
        if not line.startswith("+"):
            continue
        for p in PATTERNS:
            if re.search(p, line):
                # now check if any NV is present in the same line
                low = line.lower()
                if any(h.lower() in low for h in DANGEROUS_HEX) or any(d in low for d in DANGEROUS_DEC):
                    print(f"[DANGEROUS] Found NV write in diff at line {i}: {line}")
                    found += 1
    if found:
        print(f"Found {found} dangerous NV write(s) in PR diff. Block or add DO IT sign-off.")
    return found


def main():
    base = sys.argv[1] if len(sys.argv) > 1 else "origin/master"
    diff = get_diff_text(base)
    count = scan_diff(diff)
    if count > 0:
        sys.exit(1)
    print("No dangerous NV writes found in diff.")


if __name__ == "__main__":
    main()
