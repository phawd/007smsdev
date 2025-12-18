# Path is not needed directly in this test, keep file lightweight


def test_ghidra_pipeline_merges_findings(monkeypatch, tmp_path):
    # prepare device binaries dir
    bdir = tmp_path / "analysis" / "device_binaries"
    bdir.mkdir(parents=True)
    bin1 = bdir / "libmodem.so"
    bin1.write_bytes(b"")

    # prepare a small repo file referencing NV
    repo_root = tmp_path
    sf = repo_root / "somefile.c"
    sf.write_text("int foo() { return 0xEA64; }\n")

    # fake ghidra summary: binaries -> findings
    fake_summary = {
        "binaries": {
            "libmodem.so": [
                {"function": "modem_nck", "address": "0x1000", "insn_idx": 3},
                {
                    "function": "modem_check",
                    "address": "0x1100",
                    "insn_idx": 12,
                },
            ]
        }
    }

    # monkeypatch the run_headless used by the pipeline
    import tools.ghidra_pipeline as pipeline

    def fake_run_headless(*_args, **_kwargs):
        return fake_summary

    monkeypatch.setattr(pipeline, "run_headless", fake_run_headless)

    # run pipeline main pointing at our temp dirs
    rc = pipeline.main(
        [
            "--binaries-dir",
            str(bdir),
            "--summary",
            str(tmp_path / "analysis" / "gh.json"),
            "--csv-out",
            str(tmp_path / "analysis" / "out.csv"),
        ]
    )
    assert rc == 0

    out_csv = tmp_path / "analysis" / "out.csv"
    assert out_csv.exists()
    import csv

    with out_csv.open(encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    # verify that gh_fields were applied (as semicolon-separated lists)
    assert any("modem_nck" in (r.get("gh_functions") or "") for r in rows)
    assert any("0x1000" in (r.get("gh_addresses") or "") for r in rows)
