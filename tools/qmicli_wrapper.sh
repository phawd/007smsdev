#!/usr/bin/env bash
# Simple wrapper: prefer host qmicli, fall back to adb shell qmicli if present
set -euo pipefail

if command -v qmicli >/dev/null 2>&1; then
  qmicli "$@"
  exit $?
fi

if command -v adb >/dev/null 2>&1; then
  # Forward arguments to device-side qmicli if available
  adb shell "qmicli $*"
  exit $?
fi

echo "qmicli not found on host and adb not available. Install libqmi/qmicli or adb." >&2
exit 2
