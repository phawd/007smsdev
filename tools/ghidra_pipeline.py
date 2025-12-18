#!/usr/bin/env python3
"""Ghidra pipeline utilities.
# This script runs the Ghidra headless wrapper over device binaries,
# writes a summary JSON, and then runs `analysis/extract_nv_references.py`
# with the generated mapping to produce an enriched CSV/Markdown report.

#!/usr/bin/env python3
"""Ghidra pipeline utilities.

Normalize function mappings and optionally run the headless wrapper to
produce a canonical `analysis/ghidra_functions.json` mapping used by the
NV extraction step.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Dict, Any, List

from tools.ghidra_headless_wrapper import run_headless


def normalize_and_write_functions(src: Dict[str, Any], out_path: Path) -> None:
    """Normalize a mapping and write to out_path as JSON.

    Accepts either a top-level mapping or a dict with a "binaries" key.
    """
    if isinstance(src, dict) and "binaries" in src and isinstance(
        src["binaries"], dict
    ):
        mapping = src["binaries"]
    elif isinstance(src, dict):
        mapping = src
    else:
        raise ValueError("Invalid function mapping format")

    out: Dict[str, Any] = {"binaries": {}}
    for k, v in mapping.items():
        if not isinstance(v, list):
            continue
        cleaned: List[Dict[str, Any]] = []
        for ent in v:
            if not isinstance(ent, dict):
                continue
            rec: Dict[str, Any] = {}
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


def parse_summary_for_functions(summary: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    """Parse headless summary logs to find 'function <name> at 0xADDR'."""
    import re

    mapping: Dict[str, List[Dict[str, Any]]] = {}
    attempts = summary.get("attempts", [])
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


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run headless wrapper and normalize functions")
    parser.add_argument("--binaries-dir", default="analysis/device_binaries")
    parser.add_argument("--ghidra-path", default=None)
    parser.add_argument("--project-dir", default="analysis/ghidra_projects")
    parser.add_argument("--log-dir", default="analysis/ghidra_logs")
    parser.add_argument("--summary", default="analysis/ghidra_summary.json")
    parser.add_argument("--function-json", default=None)
    parser.add_argument("--output", default="analysis/ghidra_functions.json")
    parser.add_argument("--csv-out", default="analysis/nv_references_with_gh.csv")
    parser.add_argument("--extra-args", nargs="*", default=[])
    args = parser.parse_args(argv)

    outp = Path(args.output)

    if args.function_json:
        data = json.loads(Path(args.function_json).read_text(encoding="utf-8"))
        normalize_and_write_functions(data, outp)
        print(f"Wrote normalized functions to {outp}")
        return 0

    bdir = Path(args.binaries_dir)
    bins = [p for p in bdir.iterdir() if p.is_file()] if bdir.exists() else []
    if not bins:
        print("No binaries found to analyze in", bdir)

    ghpath = args.ghidra_path or "/snap/bin/ghidra.analyzeHeadless"
    summary = run_headless(ghpath, Path(args.project_dir), bins, Path(args.log_dir), args.extra_args)
    out_summary = Path(args.summary)
    out_summary.parent.mkdir(parents=True, exist_ok=True)
    out_summary.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    parsed = parse_summary_for_functions(summary)
    normalize_and_write_functions(parsed, outp)
    print(f"Extracted function mapping written to {outp}")

    script = Path(__file__).resolve().parents[1] / "analysis" / "extract_nv_references.py"
    cmd = ["python3", str(script), "--root", ".", "--csv", args.csv_out, "--ghidra-output", str(outp)]
    proc = subprocess.run(cmd, check=False)
    return proc.returncode


if __name__ == "__main__":
    raise SystemExit(main())
Normalize function mappings and optionally run the headless wrapper to
produce a canonical `analysis/ghidra_functions.json` mapping used by the
NV extraction step.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Dict, Any, List

from tools.ghidra_headless_wrapper import run_headless


def normalize_and_write_functions(src: Dict[str, Any], out_path: Path) -> None:
    """Normalize a mapping and write to out_path as JSON.

    Accepts either a top-level mapping or a dict with a "binaries" key.
    """
    if isinstance(src, dict) and "binaries" in src and isinstance(
        src["binaries"], dict
    ):
        mapping = src["binaries"]
    elif isinstance(src, dict):
        mapping = src
    else:
        raise ValueError("Invalid function mapping format")

    out: Dict[str, Any] = {"binaries": {}}
    for k, v in mapping.items():
        if not isinstance(v, list):
            continue
        cleaned: List[Dict[str, Any]] = []
        for ent in v:
            if not isinstance(ent, dict):
                continue
            rec: Dict[str, Any] = {}
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


def parse_summary_for_functions(summary: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    """Parse headless summary logs to find 'function <name> at 0xADDR'."""
    import re

    mapping: Dict[str, List[Dict[str, Any]]] = {}
    attempts = summary.get("attempts", [])
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


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run headless wrapper and normalize functions")
    parser.add_argument("--binaries-dir", default="analysis/device_binaries")
    parser.add_argument("--ghidra-path", default=None)
    parser.add_argument("--project-dir", default="analysis/ghidra_projects")
    parser.add_argument("--log-dir", default="analysis/ghidra_logs")
    parser.add_argument("--summary", default="analysis/ghidra_summary.json")
    parser.add_argument("--function-json", default=None)
    parser.add_argument("--output", default="analysis/ghidra_functions.json")
    parser.add_argument("--csv-out", default="analysis/nv_references_with_gh.csv")
    parser.add_argument("--extra-args", nargs="*", default=[])
    args = parser.parse_args(argv)

    outp = Path(args.output)

    if args.function_json:
        data = json.loads(Path(args.function_json).read_text(encoding="utf-8"))
        normalize_and_write_functions(data, outp)
        print(f"Wrote normalized functions to {outp}")
        return 0

    bdir = Path(args.binaries_dir)
    bins = [p for p in bdir.iterdir() if p.is_file()] if bdir.exists() else []
    if not bins:
        print("No binaries found to analyze in", bdir)

    ghpath = args.ghidra_path or "/snap/bin/ghidra.analyzeHeadless"
    summary = run_headless(ghpath, Path(args.project_dir), bins, Path(args.log_dir), args.extra_args)
    out_summary = Path(args.summary)
    out_summary.parent.mkdir(parents=True, exist_ok=True)
    out_summary.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    parsed = parse_summary_for_functions(summary)
    normalize_and_write_functions(parsed, outp)
    print(f"Extracted function mapping written to {outp}")

    script = Path(__file__).resolve().parents[1] / "analysis" / "extract_nv_references.py"
    cmd = ["python3", str(script), "--root", ".", "--csv", args.csv_out, "--ghidra-output", str(outp)]
    proc = subprocess.run(cmd, check=False)
    return proc.returncode


if __name__ == "__main__":
    raise SystemExit(main())
#!/usr/bin/env python3
"""Ghidra pipeline utilities.

Normalize function mappings and optionally run the headless wrapper to
produce a canonical `analysis/ghidra_functions.json` mapping used by the
NV extraction step.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Dict, Any, List

from tools.ghidra_headless_wrapper import run_headless


def normalize_and_write_functions(src: Dict[str, Any], out_path: Path) -> None:
    """Normalize a mapping and write to out_path as JSON.

    Accepts either a top-level mapping or a dict with a "binaries" key.
    """
    if isinstance(src, dict) and "binaries" in src and isinstance(
        src["binaries"], dict
    ):
        mapping = src["binaries"]
    elif isinstance(src, dict):
        mapping = src
    else:
        raise ValueError("Invalid function mapping format")

    out: Dict[str, Any] = {"binaries": {}}
    for k, v in mapping.items():
        if not isinstance(v, list):
            continue
        cleaned: List[Dict[str, Any]] = []
        for ent in v:
            if not isinstance(ent, dict):
                continue
            rec: Dict[str, Any] = {}
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


def parse_summary_for_functions(summary: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    """Parse headless summary logs to find 'function <name> at 0xADDR'."""
    import re

    mapping: Dict[str, List[Dict[str, Any]]] = {}
    attempts = summary.get("attempts", [])
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


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run headless wrapper and normalize functions")
    parser.add_argument("--binaries-dir", default="analysis/device_binaries")
    parser.add_argument("--ghidra-path", default=None)
    parser.add_argument("--project-dir", default="analysis/ghidra_projects")
    parser.add_argument("--log-dir", default="analysis/ghidra_logs")
    parser.add_argument("--summary", default="analysis/ghidra_summary.json")
    parser.add_argument("--function-json", default=None)
    parser.add_argument("--output", default="analysis/ghidra_functions.json")
    parser.add_argument("--csv-out", default="analysis/nv_references_with_gh.csv")
    parser.add_argument("--extra-args", nargs="*", default=[])
    args = parser.parse_args(argv)

    outp = Path(args.output)

    if args.function_json:
        data = json.loads(Path(args.function_json).read_text(encoding="utf-8"))
        normalize_and_write_functions(data, outp)
        print(f"Wrote normalized functions to {outp}")
        return 0

    bdir = Path(args.binaries_dir)
    bins = [p for p in bdir.iterdir() if p.is_file()] if bdir.exists() else []
    if not bins:
        print("No binaries found to analyze in", bdir)

    ghpath = args.ghidra_path or "/snap/bin/ghidra.analyzeHeadless"
    summary = run_headless(ghpath, Path(args.project_dir), bins, Path(args.log_dir), args.extra_args)
    out_summary = Path(args.summary)
    out_summary.parent.mkdir(parents=True, exist_ok=True)
    out_summary.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    parsed = parse_summary_for_functions(summary)
    normalize_and_write_functions(parsed, outp)
    print(f"Extracted function mapping written to {outp}")

    script = Path(__file__).resolve().parents[1] / "analysis" / "extract_nv_references.py"
    cmd = ["python3", str(script), "--root", ".", "--csv", args.csv_out, "--ghidra-output", str(outp)]
    proc = subprocess.run(cmd, check=False)
    return proc.returncode


if __name__ == "__main__":
    raise SystemExit(main())
#!/usr/bin/env python3
"""Ghidra pipeline utilities.

Normalize function mappings and optionally run the headless wrapper to
generate a canonical `analysis/ghidra_functions.json` used by the NV
extraction script.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import re
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

    out: Dict[str, Any] = {"binaries": {}}
    for k, v in mapping.items():
        if not isinstance(v, list):
            continue
        cleaned: List[Dict[str, Any]] = []
        for ent in v:
            if not isinstance(ent, dict):
                continue
            rec: Dict[str, Any] = {}
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


def parse_summary_for_functions(summary: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    mapping: Dict[str, List[Dict[str, Any]]] = {}
    attempts = summary.get("attempts", [])
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


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run headless wrapper and normalize functions")
    parser.add_argument("--binaries-dir", default="analysis/device_binaries", help="Directory containing binaries to analyze")
    parser.add_argument("--ghidra-path", default=None, help="Path to analyzeHeadless")
    parser.add_argument("--project-dir", default="analysis/ghidra_projects", help="Ghidra project dir")
    parser.add_argument("--log-dir", default="analysis/ghidra_logs", help="Ghidra logs dir")
    parser.add_argument("--summary", default="analysis/ghidra_summary.json", help="Headless wrapper summary to parse")
    parser.add_argument("--function-json", default=None, help="Precomputed function JSON to normalize")
    parser.add_argument("--output", default="analysis/ghidra_functions.json", help="Normalized functions output")
    parser.add_argument("--csv-out", default="analysis/nv_references_with_gh.csv", help="CSV output file for extractor")
    parser.add_argument("--extra-args", nargs="*", default=[], help="Extra args for ghidra analyzeHeadless")
    args = parser.parse_args(argv)

    outp = Path(args.output)

    if args.function_json:
        data = json.loads(Path(args.function_json).read_text(encoding="utf-8"))
        normalize_and_write_functions(data, outp)
        print(f"Wrote normalized functions to {outp}")
        return 0

    bdir = Path(args.binaries_dir)
    bins = [p for p in bdir.iterdir() if p.is_file()] if bdir.exists() else []
    if not bins:
        print("No binaries found to analyze in", bdir)

    ghpath = args.ghidra_path or "/snap/bin/ghidra.analyzeHeadless"
    summary = run_headless(ghpath, Path(args.project_dir), bins, Path(args.log_dir), args.extra_args)
    out_summary = Path(args.summary)
    out_summary.parent.mkdir(parents=True, exist_ok=True)
    out_summary.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    parsed = parse_summary_for_functions(summary)
    normalize_and_write_functions(parsed, outp)
    print(f"Extracted function mapping written to {outp}")

    script = Path(__file__).resolve().parents[1] / "analysis" / "extract_nv_references.py"
    cmd = [
        "python3",
        str(script),
        "--root",
        ".",
        "--csv",
        args.csv_out,
        "--ghidra-output",
        str(outp),
    ]
    proc = subprocess.run(cmd, check=False)
    return proc.returncode


if __name__ == "__main__":
    raise SystemExit(main())
#!/usr/bin/env python3
"""Ghidra pipeline utilities.

This tool normalizes function mappings produced by a headless Ghidra run and
provides a small orchestration entrypoint to run the headless wrapper and
produce a canonical `analysis/ghidra_functions.json` mapping suitable for the
NV extraction script (`analysis/extract_nv_references.py`).

The canonical output schema is:
  { "binaries": { "<path or basename>": [ {"function": "name", "address": "0x...", "insn_idx": N}, ... ] } }

Usage examples:
  # Normalize a precomputed functions JSON
  python tools/ghidra_pipeline.py --function-json precomputed.json --output analysis/ghidra_functions.json

  # Run headless wrapper over binaries in analysis/device_binaries and then
  # invoke the extractor with the resulting summary
  python tools/ghidra_pipeline.py --binaries-dir analysis/device_binaries --summary analysis/ghidra_summary.json --csv-out analysis/nv_references_with_gh.csv
"""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Dict, Any, List

from tools.ghidra_headless_wrapper import run_headless


def normalize_and_write_functions(src: Dict[str, Any], out_path: Path) -> None:
    # accept either {'binaries': {...}} or direct mapping
    if isinstance(src, dict) and "binaries" in src and isinstance(src["binaries"], dict):
        mapping = src["binaries"]
    elif isinstance(src, dict):
        mapping = src
    else:
        raise ValueError("Invalid function mapping format")

    out: Dict[str, Any] = {"binaries": {}}
    for k, v in mapping.items():
        if not isinstance(v, list):
            continue
        cleaned: List[Dict[str, Any]] = []
        for ent in v:
            if not isinstance(ent, dict):
                continue
            rec: Dict[str, Any] = {}
            if ent.get("function"):
                rec["function"] = str(ent.get("function"))
            if ent.get("address"):
                rec["address"] = str(ent.get("address"))
            if ent.get("insn_idx") is not None:
                try:
                    rec["insn_idx"] = int(ent.get("insn_idx"))
                except Exception:
                    # ignore parse issues
                    pass
            if rec:
                cleaned.append(rec)
        if cleaned:
            out["binaries"][k] = cleaned

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, indent=2), encoding="utf-8")


def parse_summary_for_functions(summary: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    """Best-effort parse of headless summary 'attempts' for lines like:
    'function <name> at 0xADDR' or '<name> at 0xADDR' and return mapping.
    """
    import re

    mapping: Dict[str, List[Dict[str, Any]]] = {}
    attempts = summary.get("attempts", [])
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


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run headless wrapper and normalize functions")
    parser.add_argument("--binaries-dir", default="analysis/device_binaries", help="Directory containing binaries to analyze")
    parser.add_argument("--ghidra-path", default=None, help="Path to analyzeHeadless")
    parser.add_argument("--project-dir", default="analysis/ghidra_projects", help="Ghidra project dir")
    parser.add_argument("--log-dir", default="analysis/ghidra_logs", help="Ghidra logs dir")
    parser.add_argument("--summary", default="analysis/ghidra_summary.json", help="Headless wrapper summary to parse")
    parser.add_argument("--function-json", default=None, help="Precomputed function JSON to normalize")
    parser.add_argument("--output", default="analysis/ghidra_functions.json", help="Normalized functions output")
    parser.add_argument("--csv-out", default="analysis/nv_references_with_gh.csv", help="CSV output file for extractor")
    parser.add_argument("--extra-args", nargs="*", default=[], help="Extra args for ghidra analyzeHeadless")
    args = parser.parse_args(argv)

    outp = Path(args.output)

    # If a precomputed function JSON is provided, use it directly
    if args.function_json:
        data = json.loads(Path(args.function_json).read_text(encoding="utf-8"))
        normalize_and_write_functions(data, outp)
        print(f"Wrote normalized functions to {outp}")
        return 0

    # Otherwise run the headless wrapper over binaries (if any) and parse the summary
    bdir = Path(args.binaries_dir)
    bins = [p for p in bdir.iterdir() if p.is_file()] if bdir.exists() else []

    if not bins:
        print("No binaries found to analyze in", bdir)
    ghpath = args.ghidra_path or "/snap/bin/ghidra.analyzeHeadless"

    summary = run_headless(ghpath, Path(args.project_dir), bins, Path(args.log_dir), args.extra_args)
    out_summary = Path(args.summary)
    out_summary.parent.mkdir(parents=True, exist_ok=True)
    out_summary.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    parsed = parse_summary_for_functions(summary)
    normalize_and_write_functions(parsed, outp)
    print(f"Extracted function mapping written to {outp}")

    # Run the extract script with ghidra output
    script = Path(__file__).resolve().parents[1] / "analysis" / "extract_nv_references.py"
    cmd = [
        "python3",
        str(script),
        "--root",
        ".",
        "--csv",
        args.csv_out,
        "--ghidra-output",
        str(outp),
    ]
    proc = subprocess.run(cmd, check=False)
    return proc.returncode


if __name__ == "__main__":
    raise SystemExit(main())
#!/usr/bin/env python3
"""Pipeline helpers to run headless analysis and produce a normalized functions JSON.

"""
Orchestrate headless analysis and NV extraction.

This module provides a small CLI entrypoint to run the headless wrapper over
device binaries, write a headless summary, then invoke the extraction script
with the produced mapping to generate an enriched CSV/Markdown report.
"""

import argparse
import subprocess
from typing import List

from tools.ghidra_headless_wrapper import run_headless


def run_pipeline(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=("Run Ghidra headless and extract NV references")
    )
    parser.add_argument(
        "--binaries-dir",
        default="analysis/device_binaries",
        help="Directory containing binaries to analyze",
    )
    parser.add_argument("--ghidra-path", default=None, help="Path to analyzeHeadless")
    parser.add_argument(
        "--project-dir", default="analysis/ghidra_projects", help="Ghidra project dir"
    )
    parser.add_argument(
        "--log-dir", default="analysis/ghidra_logs", help="Ghidra logs dir"
    )
    parser.add_argument(
        "--summary",
        default="analysis/ghidra_summary.json",
        help="Output JSON summary",
    )
    parser.add_argument(
        "--csv-out",
        default="analysis/nv_references_with_gh.csv",
        help="CSV output file",
    )
    parser.add_argument(
        "--extra-args",
        nargs="*",
        default=[],
        help="Extra args for ghidra analyzeHeadless",
    )
    args = parser.parse_args(argv)

    bdir = Path(args.binaries_dir)
    bins = [p for p in bdir.iterdir() if p.is_file()] if bdir.exists() else []
    if not bins:
        print("No binaries found to analyze in", bdir)

    proj = Path(args.project_dir)
    logs = Path(args.log_dir)

    ghpath = args.ghidra_path
    if ghpath is None:
        ghpath = "/snap/bin/ghidra.analyzeHeadless"

    summary = run_headless(ghpath, proj, bins, logs, args.extra_args)
    outp = Path(args.summary)
    outp.parent.mkdir(parents=True, exist_ok=True)
    outp.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    # Run the extract script with ghidra output
    script = Path(__file__).resolve().parents[1]
    script = script / "analysis" / "extract_nv_references.py"
    cmd = [
        "python3",
        str(script),
        "--root",
        ".",
        "--csv",
        args.csv_out,
        "--ghidra-output",
        str(outp),
    ]
    proc = subprocess.run(cmd, check=False)
    return proc.returncode


if __name__ == "__main__":
    raise SystemExit(run_pipeline())

    # Otherwise try to parse the summary file if it exists
    summary_path = Path(args.summary)
    if not summary_path.exists():
        print("No headless summary found; nothing to do.")
        return 1

    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    parsed = parse_summary_for_functions(summary)
    # write normalized structure
    normalize_and_write_functions(parsed, outp)
    print(f"Extracted function mapping written to {outp}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
#!/usr/bin/env python3
"""Orchestrate headless analysis and NV extraction.

This script runs the ghidra headless wrapper over device binaries, writes a
summary JSON, and then runs `analysis/extract_nv_references.py` with the
generated mapping to produce an enriched CSV/Markdown report.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import List

from tools.ghidra_headless_wrapper import run_headless


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=("Run Ghidra headless and extract NV references")
    )
    parser.add_argument(
        "--binaries-dir",
        default="analysis/device_binaries",
        help="Directory containing binaries to analyze",
    )
    parser.add_argument(
        "--ghidra-path", default=None, help="Path to analyzeHeadless"
    )
    parser.add_argument(
        "--project-dir",
        default="analysis/ghidra_projects",
        help="Ghidra project dir",
    )
    parser.add_argument(
        "--log-dir", default="analysis/ghidra_logs", help="Ghidra logs dir"
    )
    parser.add_argument(
        "--summary",
        default="analysis/ghidra_summary.json",
        help="Output JSON summary",
    )
    parser.add_argument(
        "--csv-out",
        default="analysis/nv_references_with_gh.csv",
        help="CSV output file",
    )
    parser.add_argument(
        "--extra-args",
        nargs="*",
        default=[],
        help="Extra args for ghidra analyzeHeadless",
    )
    args = parser.parse_args(argv)

    bdir = Path(args.binaries_dir)
    bins = [p for p in bdir.iterdir() if p.is_file()] if bdir.exists() else []
    if not bins:
        print("No binaries found to analyze in", bdir)

    proj = Path(args.project_dir)
    logs = Path(args.log_dir)

    ghpath = args.ghidra_path
    if ghpath is None:
        ghpath = "/snap/bin/ghidra.analyzeHeadless"

    summary = run_headless(ghpath, proj, bins, logs, args.extra_args)
    outp = Path(args.summary)
    outp.parent.mkdir(parents=True, exist_ok=True)
    outp.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    # Run the extract script with ghidra output
    script = Path(__file__).resolve().parents[1]
    script = script / "analysis" / "extract_nv_references.py"
    cmd = [
        "python3",
        str(script),
        "--root",
        ".",
        "--csv",
        args.csv_out,
        "--ghidra-output",
        str(outp),
    ]
    proc = subprocess.run(cmd, check=False)
    return proc.returncode


if __name__ == "__main__":
    raise SystemExit(main())
