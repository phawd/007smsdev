from tools import mifi_controller


def test_show_nck_masked(monkeypatch):
    # Return a 12-char ascii NCK from nv_read
    monkeypatch.setattr(
        mifi_controller,
        "nv_read",
        lambda *_: (True, "ok", b"123456789012"),
    )
    ok, msg = mifi_controller.show_nck(
        full=False, from_backup=False, confirm_flag=True
    )
    assert ok
    assert "****9012" in msg or "*" in msg


def test_show_nck_full_requires_confirm(monkeypatch):
    # nv_read returns an NCK
    monkeypatch.setattr(
        mifi_controller,
        "nv_read",
        lambda *_: (True, "ok", b"ABCDEFGHIJKLMNOP"),
    )
    # Simulate a non-confirm (avoid blocking input) by patching the imported
    # zerosms_safety module used inside show_nck via sys.modules
    import sys
    import types
    fake = types.SimpleNamespace(confirm_danger=lambda *a, **k: False)
    sys.modules["zerosms_safety"] = fake
    # confirm_flag False should fail
    ok, msg = mifi_controller.show_nck(
        full=True, from_backup=False, confirm_flag=False
    )
    assert ok is False
    assert "Confirmation required" in msg


def test_show_nck_from_backup(monkeypatch, tmp_path):
    # Simulate backup file
    backup_dir = tmp_path / "backup"
    backup_dir.mkdir()
    nv_file = backup_dir / "nv_60004.bin"
    nv_file.write_bytes(b"BACKUPCODE1234")
    # Monkeypatch find_nck_in_backups to return bytes
    monkeypatch.setattr(
        mifi_controller,
        "find_nck_in_backups",
        lambda *_: nv_file.read_bytes(),
    )
    ok, msg = mifi_controller.show_nck(
        full=False, from_backup=True, confirm_flag=True
    )
    assert ok
    assert "1234" in msg or "*" in msg


def test_pri_override_nv_dry_run(monkeypatch):
    # Monkeypatch confirm_danger to allow the operation
    monkeypatch.setattr(
        mifi_controller,
        "backup_items",
        lambda *_, **__: (True, "tools/backups/testbackup"),
    )
    monkeypatch.setattr(
        mifi_controller,
        "nv_write",
        lambda *_, **__: (True, "ok"),
    )
    monkeypatch.setattr(
        mifi_controller,
        "nv_read",
        lambda *_, **__: (True, "ok", b"1234"),
    )
    ok, msg = mifi_controller.pri_override_nv(
        60004, "0x31323334", confirm_flag=True
    )
    assert ok
    assert "override successful" in msg
