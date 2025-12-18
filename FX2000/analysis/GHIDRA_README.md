GHIDRA Import README

This directory contains a packaged archive for importing the FX2000 binaries into Ghidra for static reverse engineering.

Files:
- for_ghidra.tar : tarball of files pulled from the device under /opt (and other relevant paths) suitable for import.
- ghidra_import.sh : helper script to extract the tar and attempt a headless import using Ghidra's analyzeHeadless if GHIDRA_INSTALL_DIR is set.
- ghidra_project/ : (created by script) will contain the Ghidra project after headless import.

Usage (headless import):
1. Ensure Ghidra is installed and GHIDRA_INSTALL_DIR environment variable points to the Ghidra installation root (the directory that contains "support/analyzeHeadless").
   Example: export GHIDRA_INSTALL_DIR=/opt/ghidra
2. Run: bash ghidra_import.sh

Usage (GUI import):
1. Extract for_ghidra.tar: tar -xf for_ghidra.tar -C ghidra_input
2. Open Ghidra GUI, create a new Non-Shared Project.
3. File -> Import File... -> Select the files under ghidra_input (you can import whole directories).
4. Let Ghidra detect ARM ELF files and run analysis (use default analyzers). For stripped binaries, use related libraries with debug_info first to help symbol resolution.

Tips:
- Prioritize importing non-stripped libraries (those with debug_info) first, such as libs listed in FX2000/analysis/readelf_all.txt.
- For webui app.so modules (C++), enable demangling and C++ analysis options.
- Use Ghidra scripting (Python/Jython) to extract cross-references and strings.

Security:
- The extracted archive contains sensitive material (private keys, device certificates, SMS DB). Analyze on an isolated encrypted host and follow disclosure policies.
