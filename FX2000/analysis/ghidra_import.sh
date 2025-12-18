#!/bin/bash
set -euo pipefail
BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
INPUT_TAR="$BASE_DIR/for_ghidra.tar"
INPUT_DIR="$BASE_DIR/ghidra_input"
PROJECT_DIR="$BASE_DIR/ghidra_project"
PROJECT_NAME="FX2000_project"
GHIDRA_BIN="${GHIDRA_INSTALL_DIR:-}/support/analyzeHeadless"

mkdir -p "$INPUT_DIR" "$PROJECT_DIR"
if [ -f "$INPUT_TAR" ]; then
  echo "Extracting $INPUT_TAR to $INPUT_DIR"
  tar -xf "$INPUT_TAR" -C "$INPUT_DIR"
fi

# list files to import
echo "Files to import:"
find "$INPUT_DIR" -type f -maxdepth 99 -print | sed -n '1,200p'

if [ ! -d "$INPUT_DIR" ] || [ -z "$(find "$INPUT_DIR" -type f -print -quit)" ]; then
  echo "No files found to import in $INPUT_DIR"
  exit 1
fi

if [ -x "$GHIDRA_BIN" ]; then
  echo "Running Ghidra headless import using $GHIDRA_BIN"
  # analyzeHeadless accepts a project dir and project name
  "$GHIDRA_BIN" "$PROJECT_DIR" "$PROJECT_NAME" -overwrite -import "$INPUT_DIR" || true
  echo "Ghidra headless import finished. Project at: $PROJECT_DIR"
else
  cat <<'EOF'
GHIDRA not available or GHIDRA_INSTALL_DIR not set.
To import into Ghidra GUI:
 1. Open Ghidra, create a new Project (Non-Shared Project).
 2. In the Project window use File -> Import File... and select files from:
    <repo-root>/FX2000/analysis/ghidra_input
 3. For many ELF files, Ghidra will auto-detect ARM and offer analysis options. Use default analyzer options, then run analysis.
Alternatively, set environment variable GHIDRA_INSTALL_DIR to your Ghidra install and re-run this script to attempt headless import.
EOF
fi
