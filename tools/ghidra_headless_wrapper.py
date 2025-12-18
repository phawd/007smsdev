#!/usr/bin/env python3
"""Simple wrapper to invoke Ghidra headless analyzer and collect logs/results.

This script focuses on reliably invoking a headless analyzer binary (by default
`/snap/bin/ghidra.analyzeHeadless`) with conservative options, capturing
stdout/stderr to log files, and producing a small JSON summary that other
tools can ingest. It intentionally does not try to parse Ghidra project files
itself (that is for follow-up work) but records return codes and snippets of
logs for debugging and iterative improvement.

Usage:
  python tools/ghidra_headless_wrapper.py --binaries analysis/device_binaries/* --output analysis/ghidra_summary.json

Notes:
 - If Ghidra is not available at the default path, pass `--ghidra-path`.
 - The wrapper supports retries and conservative fallbacks.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import List, Dict, Any


DEFAULT_GHIDRA = "/snap/bin/ghidra.analyzeHeadless"


def run_headless(
    ghidra_path: str,
    project_dir: Path,
    binaries: List[Path],
    log_dir: Path,
    extra_args: List[str],
) -> Dict[str, Any]:
    results: Dict[str, Any] = {
        "ghidra_path": ghidra_path,
        "project_dir": str(project_dir),
        "binaries": [str(p) for p in binaries],
        "attempts": [],
    }

    # Ensure project and log directories exist
    project_dir.mkdir(parents=True, exist_ok=True)
    log_dir.mkdir(parents=True, exist_ok=True)

    # Basic guard: check that the ghidra binary exists and is executable
    gh = Path(ghidra_path)
    if not gh.exists() or not gh.is_file():
        results["error"] = f"ghidra not found at {ghidra_path}"
        return results

    # Build a conservative command. We use a single project name to avoid
    # collisions across runs.
    proj_name = "zerosms_ghidra_project"

    # prepare base args
    base_cmd = [ghidra_path, str(project_dir), proj_name, "-import"]

    # We will import binaries one by one, capturing per-file logs
    for b in binaries:
        fname = b.name
        stdout_log = log_dir / f"{fname}.stdout.log"
        stderr_log = log_dir / f"{fname}.stderr.log"

        cmd = list(base_cmd) + [str(b)] + extra_args
        attempt: Dict[str, Any] = {"binary": str(b), "cmd": cmd}
        try:
            with stdout_log.open("wb") as out, stderr_log.open("wb") as err:
                proc = subprocess.run(cmd, stdout=out, stderr=err, check=False)
                attempt["returncode"] = proc.returncode
        except (OSError, subprocess.SubprocessError) as e:
            attempt["exception"] = str(e)

        # Collect small snippets for quick debugging
        for p, key in (
            (stdout_log, "stdout_snippet"), (stderr_log, "stderr_snippet")
        ):
            try:
                txt = p.read_text(errors="ignore")
                attempt[key] = txt[-8192:]
            except OSError:
                attempt[key] = ""

        results["attempts"].append(attempt)

        # conservative fallback: if returncode != 0, try a no-analysis import
        if attempt.get("returncode", 1) != 0:
            fallback_cmd = list(base_cmd) + [str(b), "-noanalysis"]
            attempt_fb: Dict[str, Any] = {
                "binary": str(b),
                "cmd": fallback_cmd,
            }
            try:
                fb_stdout = log_dir / f"{fname}.fallback.stdout.log"
                fb_stderr = log_dir / f"{fname}.fallback.stderr.log"
                with fb_stdout.open("wb") as out, fb_stderr.open("wb") as err:
                    proc2 = subprocess.run(
                        fallback_cmd, stdout=out, stderr=err, check=False
                    )
                    attempt_fb["returncode"] = proc2.returncode
            except (OSError, subprocess.SubprocessError) as e:
                attempt_fb["exception"] = str(e)

            # capture fallback snippets
            for p, key in (
                (fb_stdout, "stdout_snippet"), (fb_stderr, "stderr_snippet")
            ):
                try:
                    attempt_fb[key] = p.read_text(errors="ignore")[-8192:]
                except OSError:
                    attempt_fb[key] = ""

            results["attempts"].append(attempt_fb)

    return results


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Wrapper to run Ghidra headless analyze and record logs/results"
        )
    )
    parser.add_argument(
        "--ghidra-path",
        default=DEFAULT_GHIDRA,
        help="Path to analyzeHeadless",
    )
    parser.add_argument(
        "--project-dir",
        default="analysis/ghidra_projects",
        help="Directory to host ghidra project files",
    )
    parser.add_argument(
        "--log-dir",
        default="analysis/ghidra_logs",
        help="Directory to write logs",
    )
    parser.add_argument(
        "--binaries", nargs="+", required=True, help="Binaries to import"
    )
    parser.add_argument(
        "--output",
        default="analysis/ghidra_summary.json",
        help="JSON summary output",
    )
    parser.add_argument(
        "--extra-args",
        nargs="*",
        default=[],
        help="Extra args to pass to analyzeHeadless",
    )
    args = parser.parse_args(argv)

    gh_path = args.ghidra_path
    proj_dir = Path(args.project_dir)
    log_dir = Path(args.log_dir)
    binaries = [Path(x) for x in args.binaries]

    summary = run_headless(
        gh_path, proj_dir, binaries, log_dir, args.extra_args
    )

    outp = Path(args.output)
    outp.parent.mkdir(parents=True, exist_ok=True)
    outp.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    # exit with non-zero if any attempt returned non-zero status
    any_nonzero = any(
        a.get("returncode", 0) != 0 for a in summary.get("attempts", [])
    )
    return 1 if any_nonzero else 0


if __name__ == "__main__":
    raise SystemExit(main())
