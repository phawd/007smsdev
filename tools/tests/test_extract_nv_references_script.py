import subprocess
import sys


def test_extract_runs_and_creates_csv(tmp_path):
    """Run the extract script and ensure the CSV output exists and contains
    nv_found header.
    """
    out_csv = tmp_path / "nv_refs.csv"
    cmd = [
        sys.executable,
        "analysis/extract_nv_references.py",
        "--nv",
        "0xEA64",
        "0xEAAC",
        "0xEA62",
        "--csv",
        str(out_csv),
        "--root",
        ".",
    ]
    subprocess.run(cmd, check=True)
    assert out_csv.exists()
    text = out_csv.read_text()
    assert "nv_found" in text
