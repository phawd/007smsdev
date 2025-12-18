#!/usr/bin/env bash
# tools/update_device_info.sh
# Minimal updater: runs available probe tools and writes a basic device inventory.
set -euo pipefail

OUT=docs/device_inventory.md
echo "# Device Inventory (auto-generated)" > "$OUT"
echo "Generated: $(date -u)" >> "$OUT"
echo >> "$OUT"

if [ -x "tools/qmi_adapter.py" ]; then
  echo "## QMI Backends" >> "$OUT"
  python3 tools/qmi_adapter.py --probe >> "$OUT" 2>&1 || true
  echo >> "$OUT"
fi

if [ -f "tools/zerosms_cli.py" ]; then
  echo "## Probe Output (zerosms_cli)" >> "$OUT"
  python3 tools/zerosms_cli.py probe --deep --include-response 2>> "$OUT" | sed -n '1,200p' >> "$OUT" || true
  echo >> "$OUT"
fi

echo "## Notes" >> "$OUT"
echo "This file is a lightweight inventory intended for quick reference. For full device details use dedicated probes and update docs/PHASE_* notes." >> "$OUT"

echo "Wrote $OUT"
