import tools.mifi_controller as mc
from tools.zerosms_safety import confirm_danger


def test_confirm_danger_env_override(monkeypatch):
    monkeypatch.setenv("ZEROSMS_DANGER_DO_IT", "1")
    # confirm_danger will return True when env var set
    assert confirm_danger(allow_flag=True) is True


def test_show_nck_prints_when_confirm(monkeypatch, tmp_path):
    # Monkeypatch nv_read to return known NCK bytes
    def fake_nv_read(item_id, index=0):
        return True, "OK", b"123456"

    monkeypatch.setattr(mc, "nv_read", fake_nv_read)
    ok, msg = mc.show_nck(full=True, confirm_flag=True)
    assert ok
    assert "123456" in msg


def test_show_nck_masks_by_default(monkeypatch):
    def fake_nv_read(item_id, index=0):
        return True, "OK", b"MYSECRET1234"

    monkeypatch.setattr(mc, "nv_read", fake_nv_read)
    ok, msg = mc.show_nck(full=False)
    assert ok
    # Should not contain the full secret
    assert "MYSECRET1234" not in msg
    # Should contain only the last 4 digits (1234)
    assert msg.endswith("1234")


def test_show_nck_full_requires_confirm(monkeypatch):
    def fake_nv_read(item_id, index=0):
        return True, "OK", b"FULLSECRET"

    monkeypatch.setattr(mc, "nv_read", fake_nv_read)
    # Without confirm: full reveal should abort (monkeypatch confirm_danger to avoid prompt)
    import zerosms_safety as zs
    monkeypatch.setattr(zs, "confirm_danger", lambda allow_flag=True: False)
    ok, msg = mc.show_nck(full=True, confirm_flag=False)
    assert not ok

    # With confirm it should reveal
    ok, msg = mc.show_nck(full=True, confirm_flag=True)
    assert ok
    assert "FULLSECRET" in msg


def test_show_nck_from_backup(monkeypatch, tmp_path):
    # Prepare a backup folder and nv_60004.bin
    backup_dir = tmp_path / "backup_test"
    backup_dir.mkdir(parents=True)
    nv_file = backup_dir / "nv_60004.bin"
    nv_file.write_bytes(b"BACKUP_NCK_9999")

    # Monkeypatch the find_nck_in_backups function to search our tmp path
    def fake_find(nv, root=None):
        return nv_file.read_bytes()

    monkeypatch.setattr(mc, "find_nck_in_backups", fake_find)
    ok, msg = mc.show_nck(full=False, from_backup=True)
    assert ok
    assert "9999" in msg



def test_backup_items_creates_files(monkeypatch, tmp_path):
    # Replace nv_read with simulated data
    def fake_nv_read(item_id, index=0):
        return True, "OK", b"AAABBB"

    def fake_efs_read(efs_path, local_tmp=None):
        return True, "OK", b"<xml></xml>"

    monkeypatch.setattr(mc, "nv_read", fake_nv_read)
    monkeypatch.setattr(mc, "efs_read_file", fake_efs_read)

    backup_dir = tmp_path / "backup_test"
    ok, path = mc.backup_items(backup_dir=str(backup_dir))
    assert ok
    assert (backup_dir / "nv_60004.bin").exists()
    assert (backup_dir / "efs_device_config.xml").exists()
    assert path == str(backup_dir)


def test_pri_override_nv_dry_run(monkeypatch, tmp_path):
    # Monkeypatch nv_read and nv_write
    last_written = {}
    def fake_nv_read(item_id, index=0):
        if item_id in last_written:
            return True, "OK", last_written[item_id]
        return True, "OK", b"OLD"

    def fake_nv_write(item_id, index, data):
        last_written[item_id] = data
        return True, "success"

    monkeypatch.setattr(mc, "nv_read", fake_nv_read)
    monkeypatch.setattr(mc, "nv_write", fake_nv_write)

    # Monkeypatch backup to avoid real adb/qmi calls during testing
    monkeypatch.setattr(mc, "backup_items", lambda *a, **k: (True, str(tmp_path)))
    ok, msg = mc.pri_override_nv(60004, "NEWVALUE", confirm_flag=True)
    assert ok
# End of tests
