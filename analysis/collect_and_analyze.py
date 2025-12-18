#!/usr/bin/env python3
"""
Collect key device binaries via ADB and run Ghidra headless analysis on them.

This script intentionally only performs read actions (adb pull) and then runs
Ghidra headless. It does NOT write or alter the device.
"""

import subprocess
import os
from pathlib import Path
import sys
import argparse


DEFAULT_FILES = [
    '/opt/nvtl/bin/modem2_cli',
    '/opt/nvtl/bin/nwcli',
    '/opt/nvtl/bin/nwnvitem',
    '/lib/libmal_qct.so',
    '/lib64/libmal_qct.so',
]

GHIDRA_PATH = '/snap/bin/ghidra.analyzeHeadless'


def adb_pull(remote: str, dst: Path) -> bool:
    try:
        dst.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(['adb', 'pull', remote, str(dst)], check=True)
        return True
    except Exception as e:
        print(f"[!] adb pull failed for {remote}: {e}")
        return False


def run_ghidra_on(file_path: Path, output_dir: Path) -> bool:
    if not Path(GHIDRA_PATH).exists():
        print("[!] Ghidra headless not found at", GHIDRA_PATH)
        return False
    proj_dir = output_dir / "ghidra_project"
    proj_dir.mkdir(parents=True, exist_ok=True)
    project_name = f"ghidra_{file_path.name}"
    cmd = [
        GHIDRA_PATH,
        str(proj_dir),
        project_name,
        '-import', str(file_path),
        '-deleteProject',
    ]
    try:
        subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(f"[+] Ghidra analysis completed for {file_path.name}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[!] Ghidra failed for {file_path.name}: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description='Collect device binaries via adb and run Ghidra')
    parser.add_argument('--files', nargs='*', default=DEFAULT_FILES, help='Remote paths to pull')
    parser.add_argument('--out', default='analysis/device_binaries', help='Output directory')
    args = parser.parse_args()

    outdir = Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)

    pulled = []
    for remote in args.files:
        local = outdir / Path(remote).name
        ok = adb_pull(remote, local)
        if ok:
            pulled.append(local)

    if not pulled:
        print('[!] No files pulled, aborting ghidra run')
        sys.exit(0)

    ghidra_out = outdir / 'ghidra_out'
    ghidra_out.mkdir(parents=True, exist_ok=True)
    for f in pulled:
        run_ghidra_on(f, ghidra_out)


if __name__ == '__main__':
    main()
