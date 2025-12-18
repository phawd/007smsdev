from pathlib import Path
import subprocess

import importlib.util

# Import module by file path to avoid package import issues during test runs
_mod_path = Path(__file__).resolve().parents[1] / "ghidra_headless_wrapper.py"
spec = importlib.util.spec_from_file_location(
    "ghidra_headless_wrapper", str(_mod_path)
)
assert spec and spec.loader
_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(_mod)
run_headless = _mod.run_headless


def test_run_headless_missing_ghidra(tmp_path):
    project_dir = tmp_path / "proj"
    log_dir = tmp_path / "logs"
    binaries = [tmp_path / "bin1"]
    # binary files must exist but can be empty
    for b in binaries:
        b.write_bytes(b"")

    gh = str(tmp_path / "no_such_ghidra")
    res = run_headless(gh, project_dir, binaries, log_dir, [])
    assert "error" in res


def test_run_headless_success(monkeypatch, tmp_path):
    project_dir = tmp_path / "proj"
    log_dir = tmp_path / "logs"
    binaries = [tmp_path / "bin1"]
    for b in binaries:
        b.write_bytes(b"")

    class Dummy:
        def __init__(self, rc=0):
            self.returncode = rc

    def fake_run(cmd, stdout, stderr, check=False):
        # reference unused args to satisfy linters
        _ = cmd
        _ = check
        # write some bytes so the wrapper can read snippets
        stdout.write(b"analyze ok\n")
        stderr.write(b"")
        return Dummy(0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    gh = str(Path("/bin/true"))
    res = run_headless(gh, project_dir, binaries, log_dir, [])
    assert "attempts" in res
    assert res["attempts"][0]["returncode"] == 0


def test_run_headless_fallback(monkeypatch, tmp_path):
    project_dir = tmp_path / "proj"
    log_dir = tmp_path / "logs"
    binaries = [tmp_path / "bin1"]
    for b in binaries:
        b.write_bytes(b"")

    class Dummy:
        def __init__(self, rc=1):
            self.returncode = rc

    calls = {"count": 0}

    def fake_run(cmd, stdout, stderr, check=False):
        _ = cmd
        _ = check
        calls["count"] += 1
        if calls["count"] == 1:
            stdout.write(b"first attempt fail\n")
            stderr.write(b"error")
            return Dummy(1)
        else:
            stdout.write(b"fallback ok\n")
            stderr.write(b"")
            return Dummy(0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    gh = str(Path("/bin/false"))
    res = run_headless(gh, project_dir, binaries, log_dir, [])
    # should have two attempts: initial and fallback
    assert len(res["attempts"]) >= 2
    # check that fallback had returncode 0
    assert any(a.get("returncode") == 0 for a in res["attempts"])
