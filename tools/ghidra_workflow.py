#!/usr/bin/env python3
"""Lightweight Ghidra workflow: normalize or parse summary into functions JSON."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, Any, List

from tools.ghidra_headless_wrapper import run_headless


def normalize_and_write_functions(src: Dict[str, Any], out_path: Path) -> None:
    if isinstance(src, dict) and "binaries" in src and isinstance(src["binaries"], dict):
        mapping = src["binaries"]
    elif isinstance(src, dict):
        mapping = src
    else:
        raise ValueError("Invalid function mapping format")

    out = {"binaries": {}}
    for k, v in mapping.items():
        if not isinstance(v, list):
            continue
        cleaned = []
        for ent in v:
            if not isinstance(ent, dict):
                continue
            rec = {}
            if ent.get("function"):
                rec["function"] = str(ent.get("function"))
            if ent.get("address"):
                rec["address"] = str(ent.get("address"))
            if ent.get("insn_idx") is not None:
                try:
                    rec["insn_idx"] = int(ent.get("insn_idx"))
                except Exception:
                    pass
            if rec:
                cleaned.append(rec)
        if cleaned:
            out["binaries"][k] = cleaned

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, indent=2), encoding="utf-8")


def parse_summary_for_functions(summary_path: Path) -> Dict[str, List[Dict[str, Any]]]:
    s = json.loads(summary_path.read_text(encoding="utf-8"))
    attempts = s.get("attempts", [])
    mapping: Dict[str, List[Dict[str, Any]]] = {}
    import re

    fn_re = re.compile(r"function\s+([A-Za-z0-9_@.$]+)\s+at\s+(0x[0-9a-fA-F]+)")
    any_re = re.compile(r"([A-Za-z0-9_@.$]+)\s+at\s+(0x[0-9a-fA-F]+)")

    for a in attempts:
        binpath = a.get("binary") or "unknown"
        text = (a.get("stderr_snippet") or "") + "\n" + (a.get("stdout_snippet") or "")
        for m in fn_re.finditer(text):
            name, addr = m.group(1), m.group(2)
            mapping.setdefault(binpath, []).append({"function": name, "address": addr})
        if binpath not in mapping:
            for m in any_re.finditer(text):
                name, addr = m.group(1), m.group(2)
                mapping.setdefault(binpath, []).append({"function": name, "address": addr})

    return mapping


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--summary", default="analysis/ghidra_summary.json")
    parser.add_argument("--function-json", default=None)
    parser.add_argument("--output", default="analysis/ghidra_functions.json")
    args = parser.parse_args(argv)

    outp = Path(args.output)
    if args.function_json:
        data = json.loads(Path(args.function_json).read_text(encoding="utf-8"))
        normalize_and_write_functions(data, outp)
        print(f"Wrote normalized functions to {outp}")
        return 0

    sp = Path(args.summary)
    if not sp.exists():
        print("summary not found", sp)
        return 1
    parsed = parse_summary_for_functions(sp)
    normalize_and_write_functions(parsed, outp)
    print(f"Wrote parsed functions to {outp}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
