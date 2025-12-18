#!/usr/bin/env python3
"""
Extract NV references from the repo (search for hex and decimal NV ids and
parse JSON artifacts to find function calls referencing NV items).

Usage:
  python analysis/extract_nv_references.py [--nv 0xEA64 0xEAAC 0xEA62] [--csv out.csv]

Output: prints a table of NV->(file, function, snippet) and writes CSV if requested.

This tool reads files, tries to parse JSON (for disassembly artifacts) and otherwise
searches text. For JSON, it attempts to extract function names and operand fields.
"""

import argparse
import json
import os
import re
import csv
from pathlib import Path
from typing import List, Tuple, Dict, Any, Optional

# Patterns for the NV items
DEFAULT_HEX = ["0xEA64", "0xEAAC", "0xEA62"]
# Decimal equivalents - compute from hex
HEX_TO_DECIMAL = {h.lower(): str(int(h, 16)) for h in DEFAULT_HEX}

# We'll also search for local filename hints like nv_60004.bin
NV_FILENAME_PATTERNS = [f"nv_{d}.bin" for d in HEX_TO_DECIMAL.values()]

# File types to process as JSON
JSON_EXTS = {".json"}

# Basic text search patterns
HEX_RE = re.compile(r"\b(0x[0-9a-fA-F]{3,6})\b")
DEC_RE = re.compile(r"\b(\d{4,6})\b")
NV_RE_STRINGS = []

for h, d in HEX_TO_DECIMAL.items():
    NV_RE_STRINGS.append(h)
    NV_RE_STRINGS.append(d)

NV_RE_STRINGS = set(s.lower() for s in NV_RE_STRINGS)


def find_in_text(path: Path, nvset: set) -> List[Tuple[int, str]]:
    """Search for NV hex or decimal values in text files and return matches
    as list of (line_number, snippet)"""
    results = []
    try:
        text = path.read_text(errors="ignore")
    except Exception:
        return results

    for i, line in enumerate(text.splitlines(), start=1):
        lo = line.lower()
        # Quick check: see if any nv pattern present
        if any(x in lo for x in nvset):
            results.append((i, line.strip()))
    return results


def traverse_json(obj: Any, nvset: set, path_stack: List[str]) -> List[Dict[str, Any]]:
    """Recursively traverse JSON structure and collect nodes (paths/values) that
    contain the NV patterns."""
    matches = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            new_stack = path_stack + [str(k)]
            matches.extend(traverse_json(v, nvset, new_stack))
    elif isinstance(obj, list):
        for idx, item in enumerate(obj):
            new_stack = path_stack + [f"[{idx}]"]
            matches.extend(traverse_json(item, nvset, new_stack))
    elif isinstance(obj, str):
        lo = obj.lower()
        if any(x in lo for x in nvset):
            matches.append({
                "path": "/".join(path_stack),
                "value": obj,
            })
    else:
        # numbers etc
        try:
            s = str(obj).lower()
            if any(x in s for x in nvset):
                matches.append({
                    "path": "/".join(path_stack),
                    "value": s,
                })
        except Exception:
            pass
    return matches


def search_repo(root: Path, nvset: set) -> List[Dict[str, Any]]:
    """Search repo for NV references; return list of matches with metadata"""
    matches = []
    for file_path in root.rglob("*"):
        if file_path.is_dir():
            continue
        try:
            ext = file_path.suffix.lower()
            if ext in JSON_EXTS:
                # Try parse JSON
                try:
                    obj = json.loads(file_path.read_text(errors="ignore"))
                    json_matches = traverse_json(obj, nvset, [])
                    for m in json_matches:
                        matches.append({
                            "nv": None,
                            "path": str(file_path),
                            "type": "json",
                            "context_path": m.get("path"),
                            "value": m.get("value"),
                        })
                except json.JSONDecodeError:
                    # treat as plain text fallback
                    txt = find_in_text(file_path, nvset)
                    for lineno, line in txt:
                        matches.append({
                            "nv": None,
                            "path": str(file_path),
                            "type": "text",
                            "lineno": lineno,
                            "value": line,
                        })
            else:
                # plain text files; including .c, .h, .md, .txt
                txt = find_in_text(file_path, nvset)
                for lineno, line in txt:
                    matches.append({
                        "nv": None,
                        "path": str(file_path),
                        "type": "text",
                        "lineno": lineno,
                        "value": line,
                    })
        except Exception:
            # ignore permission or read errors
            continue
    return matches


def associate_function(match: Dict[str, Any]) -> Dict[str, Any]:
    """Try heuristic to extract function name or symbol for match by looking
    in the same file for 'name' fields or function signatures around the
    matched line (for text files)."""
    path = Path(match["path"])
    func_name = None
    try:
        text = path.read_text(errors="ignore")
    except Exception:
        text = ""

    if match.get("type") == "json":
        # For JSON disassembly we often have multiple fields: function, operands
        # We'll try to parse the containing JSON file for 'function' fields nearby
        # and fallback to the 'path' from traverse_json.
        try:
            obj = json.loads(path.read_text(errors="ignore"))
            # naive walk: find function entries and instruction operands that contain the NV string
            for entry in traverse_find_function_entries(obj):
                operands = entry.get("operands") or entry.get("instruction") or entry.get("value")
                if operands and isinstance(operands, str):
                    if any(x in operands.lower() for x in NV_RE_STRINGS):
                        func_name = entry.get("function") or entry.get("name")
                    # attempt to extract address, might be in 'address' field
                    if entry.get("address"):
                        match["address"] = entry.get("address")
                    # instruction index: some entries contain 'instructions' as arrays; otherwise parse context_path
                    instrs = entry.get("instructions")
                    if instrs and isinstance(instrs, list):
                        for idx, ins in enumerate(instrs):
                            op = ins.get("operands", "")
                            if isinstance(op, str) and any(x in op.lower() for x in NV_RE_STRINGS):
                                match["instruction_index"] = idx
                                match["address"] = ins.get("address") or match.get("address")
                                break
                    break
            # If we didn't find via function entries, try context path like '.../instructions/[58]/operands'
            if not func_name and match.get("context_path"):
                ctx = match.get("context_path")
                # try to extract function name from context path
                # pattern: target_function_analysis/<func>/instructions/[<index>]/operands
                mfunc = re.search(r"target_function_analysis/([^/]+)/", ctx)
                if mfunc:
                    func_name = mfunc.group(1)
                # try to find an index in the path
                m_idx = re.search(r"/instructions/\[(\d+)\]", ctx)
                if m_idx:
                    match["instruction_index"] = int(m_idx.group(1))
        except Exception:
            pass
    else:
        # For text matches, search upwards for function signature lines (C-like) or 'def ' for Python
        lineno = match.get("lineno")
        if lineno and text:
            lines = text.splitlines()
            # look back up to 40 lines for a likely function header
            for i in range(max(0, lineno - 40), max(0, lineno)):
                l = lines[i].strip()
                if l.endswith("{") and ("(" in l and ")" in l or "def " in l):
                    # crude header
                    func_name = l
                    break
            # look forward too
            for i in range(lineno, min(len(lines), lineno + 20)):
                l = lines[i].strip()
                if l.startswith("def ") or l.endswith("{"):
                    func_name = func_name or l
                    break

    match["function"] = func_name
    return match


def traverse_find_function_entries(obj: Any) -> List[Dict[str, Any]]:
    """Return a list of objects in JSON that look like function entries with operands."""
    results = []
    if isinstance(obj, dict):
        if ("function" in obj or "name" in obj) and ("operands" in obj or "body" in obj):
            results.append(obj)
        for k, v in obj.items():
            results.extend(traverse_find_function_entries(v))
    elif isinstance(obj, list):
        for v in obj:
            results.extend(traverse_find_function_entries(v))
    return results


def main():
    parser = argparse.ArgumentParser(description="Extract NV references and collate them into a table")
    parser.add_argument("--nv", nargs="*", default=DEFAULT_HEX, help="NV items (hex), e.g. 0xEA64")
    parser.add_argument("--csv", default=None, help="CSV output file")
    parser.add_argument(
        "--ghidra-output",
        default=None,
        help=(
            "Optional JSON mapping produced by a headless analysis step."
            " Keys should map binary path or basename to a list of findings"
        ),
    )
    parser.add_argument("--root", default=".", help="Repo root to scan")
    args = parser.parse_args()

    nvset = set(x.lower() for x in args.nv)
    # ensure decimals are included
    for hv in list(nvset):
        if hv.startswith("0x"):
            nvset.add(str(int(hv, 16)))

    root = Path(args.root).resolve()
    print(f"Scanning for NV patterns: {sorted(nvset)} under {root}")

    raw_matches = search_repo(root, nvset)

    # Load optional ghidra outputs which map binaries -> findings
    ghidra_map: Dict[str, List[Dict[str, Any]]] = {}
    if args.ghidra_output:
        try:
            ghtext = Path(args.ghidra_output).read_text(encoding="utf-8")
            ghobj = json.loads(ghtext)
            # accept either {'binaries': {path: [findings]}} or direct mapping
            if isinstance(ghobj, dict) and "binaries" in ghobj and isinstance(
                ghobj["binaries"], dict
            ):
                ghidra_map = ghobj["binaries"]
            elif isinstance(ghobj, dict):
                ghidra_map = ghobj
        except (OSError, json.JSONDecodeError, ValueError):
            print(
                "Warning: failed to parse ghidra output",
                args.ghidra_output,
            )
    rows = []
    for m in raw_matches:
        m = associate_function(m)
        # Try to enrich with ghidra mapping: collect all findings that match
        gh_functions: List[str] = []
        gh_addresses: List[str] = []
        gh_insn_idxs: List[str] = []
        if ghidra_map:
            mfpath = str(m.get("path") or "")
            mbase = Path(mfpath).name
            for k, findings in ghidra_map.items():
                if not isinstance(findings, list):
                    continue
                if k == mfpath or k == mbase or mbase in str(k):
                    for f in findings:
                        if not isinstance(f, dict):
                            continue
                        if f.get("function"):
                            gh_functions.append(str(f.get("function")))
                        if f.get("address"):
                            gh_addresses.append(str(f.get("address")))
                        if f.get("insn_idx") is not None:
                            gh_insn_idxs.append(str(f.get("insn_idx")))
                        # fill primary fields if empty for convenience
                        if not m.get("function") and f.get("function"):
                            m["function"] = f.get("function")
                        if not m.get("address") and f.get("address"):
                            m["address"] = f.get("address")
                        if (
                            not m.get("instruction_index")
                            and f.get("insn_idx") is not None
                        ):
                            m["instruction_index"] = f.get("insn_idx")
                    break
        # annotate the matched NVs by scanning the value field
        val = str(m.get("value") or "").lower()
        nv_found = []
        nv_hex = ""
        nv_dec = ""
        for vp in nvset:
            if vp in val:
                nv_found.append(vp)
                if vp.startswith("0x"):
                    nv_hex = vp
                    nv_dec = str(int(vp, 16))
                elif vp.isdigit():
                    nv_dec = vp
                    nv_hex = hex(int(vp))
        rows.append({
            "nv_found": nv_found,
            "nv_hex": nv_hex,
            "nv_dec": nv_dec,
            "path": m.get("path"),
            "type": m.get("type"),
            "lineno": m.get("lineno"),
            "function": m.get("function"),
            "address": m.get("address"),
            "instruction_index": m.get("instruction_index"),
            "context_path": m.get("context_path"),
            "value": (m.get("value") or "")[:200],
            "gh_functions": gh_functions,
            "gh_addresses": gh_addresses,
            "gh_insn_indices": gh_insn_idxs,
        })

    # Print a basic table
    md_lines = []
    if rows:
        print("\nFound NV references:\n")
        print(
            "NV\tHEX/DEC\tFile\tFunction/Signature\tAddress\tInsnIdx\t"
            "Context/Path\tSnippet"
        )
        print("-" * 120)
        for r in rows:
            nv_str = ",".join(r["nv_found"]) if r["nv_found"] else "?"
            hexdec = f"{r.get('nv_hex')}/{r.get('nv_dec')}"
            parts = [
                nv_str,
                hexdec,
                r["path"],
                r.get("function") or "",
                r.get("address") or "",
                str(r.get("instruction_index") or ""),
                r.get("context_path") or "",
                r.get("value") or "",
            ]
            line = "\t".join(parts)
            print(line)
            md_lines.append({
                "nv": nv_str,
                "hex": r.get('nv_hex') or '',
                "dec": r.get('nv_dec') or '',
                "file": r['path'],
                "function": r.get('function') or '',
                "address": r.get('address') or '',
                "insn_idx": r.get('instruction_index') or '',
                "gh_funcs": ";".join(r.get('gh_functions') or []),
                "gh_addrs": ";".join(r.get('gh_addresses') or []),
                "gh_insns": ";".join(r.get('gh_insn_indices') or []),
                "context": r.get('context_path') or '',
                "snippet": r.get('value') or '',
            })
    else:
        print("No NV matches found.")

    if args.csv:
        csv_path = Path(args.csv)
        if args.csv:
            csv_path = Path(args.csv)
            # Write CSV with explicit UTF-8 encoding and quoting
            with csv_path.open("w", newline="", encoding="utf-8") as csvf:
                writer = csv.DictWriter(
                    csvf,
                    fieldnames=[
                        "nv_found",
                        "nv_hex",
                        "nv_dec",
                        "path",
                        "type",
                        "lineno",
                        "function",
                        "address",
                        "instruction_index",
                        "gh_functions",
                        "gh_addresses",
                        "gh_insn_indices",
                        "context_path",
                        "value",
                    ],
                    quoting=csv.QUOTE_MINIMAL,
                )
                writer.writeheader()
                for r in rows:
                    # normalize fields
                    out = {}
                    for k in writer.fieldnames:
                        v = r.get(k)
                        if v is None:
                            out[k] = ""
                        else:
                            if isinstance(v, list):
                                out[k] = ";".join(str(x) for x in v)
                            else:
                                out[k] = v
                    # ensure nv_found is a comma-separated string
                    out["nv_found"] = ",".join(r.get("nv_found") or [])
                    writer.writerow(out)
            print(f"CSV output written to {csv_path}")
    # Write Markdown table
    md_out = Path("analysis/nv_references.md")
    md_out.parent.mkdir(parents=True, exist_ok=True)
    with md_out.open("w", encoding="utf-8") as md:
        md.write("# NV References Summary\n\n")
        md.write(
                (
                    "| NV | Hex | Dec | File | Line | Function | "
                    "Address | InsnIdx | GhidraFuncs | GhidraAddrs | "
                    "GhidraInsns | Context | Snippet |\n"
                )
        )
        md.write(
            "|--:|--|--|--|--:|--|--|--:|--|--|\n"
        )
        for m in md_lines:
            # sanitize fields for Markdown table
            def esc(s):
                if s is None:
                    return ""
                s = str(s)
                s = s.replace("|", "\\|")
                s = s.replace("\n", " ")
                if len(s) > 120:
                    s = s[:117] + "..."
                return s

            md.write(
                (
                    "|{nv}|{hex}|{dec}|{file}|{line}|{function}|{address}|"
                    "{insn_idx}|{gh_funcs}|{gh_addrs}|"
                    "{gh_insns}|{context}|{snippet}|\n"
                ).format(
                    nv=esc(m.get("nv")),
                    hex=esc(m.get("hex")),
                    dec=esc(m.get("dec")),
                    file=esc(m.get("file")),
                    line=esc(m.get("line", "")),
                    function=esc(m.get("function")),
                    address=esc(m.get("address")),
                    insn_idx=esc(m.get("insn_idx")),
                    gh_funcs=esc(m.get("gh_funcs")),
                    gh_addrs=esc(m.get("gh_addrs")),
                    gh_insns=esc(m.get("gh_insns")),
                    context=esc(m.get("context")),
                    snippet=esc(m.get("snippet")),
                )
            )
        print(f"Markdown summary written to {md_out}")


if __name__ == "__main__":
    main()
