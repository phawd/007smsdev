import json
import subprocess
import sys
from pathlib import Path


def test_extract_nv_with_ghidra(tmp_path):
    repo_root = tmp_path / "repo"
    repo_root.mkdir()

    # create a sample file that contains the NV hex
    sf = repo_root / "somefile.c"
    sf.write_text(
        "/* sample */\nint foo() { volatile int x = 0xEA64; return x; }\n"
    )

    # prepare ghidra mapping: map basename to findings
    ghmap = {
        "somefile.c": [
            {"function": "nck_handler", "address": "0x401000", "insn_idx": 5}
        ]
    }
    ghf = repo_root / "ghmap.json"
    ghf.write_text(json.dumps(ghmap))

    out_csv = repo_root / "out.csv"

    script = Path(__file__).resolve().parents[2]
    script = script / "analysis" / "extract_nv_references.py"
    assert script.exists()

    cmd = [
        sys.executable,
        str(script),
        "--root",
        str(repo_root),
        "--csv",
        str(out_csv),
        "--ghidra-output",
        str(ghf),
    ]
    proc = subprocess.run(cmd, cwd=str(repo_root), check=False)
    assert proc.returncode == 0
    assert out_csv.exists()

    # read csv and assert the function/address were applied
    import csv

    with out_csv.open(encoding="utf-8") as f:
        r = csv.DictReader(f)
        rows = list(r)
    assert rows, "Expect at least one row"
    found = False
    for row in rows:
        if row.get("function") == "nck_handler":
            found = True
            assert row.get("address") == "0x401000"
            assert row.get("instruction_index") in ("5", "5.0", "5")
    assert found, "Ghidra function mapping not applied"
