import sys
from types import SimpleNamespace

# Import the adapter module; tests are lightweight and avoid hardware access
from tools import qmi_adapter as qa


def test_probe_backends_no_raise():
    b = qa.probe_backends()
    assert isinstance(b, list)


def test_get_modem_info_returns_dict():
    info = qa.get_modem_info()
    assert isinstance(info, dict)
    assert 'backend' in info and 'output' in info


def test_read_nv_dry_run():
    args = SimpleNamespace(dry_run=True)
    ok, out = qa.read_nv('0xEA64', args)
    assert ok is True and out == 'dry-run'


def test_write_nv_blocked_and_allowed(monkeypatch):
    args = SimpleNamespace(dry_run=True, danger_do_it=False)
    ok, out = qa.write_nv('0xEA64', 'deadbeef', args)
    assert ok is False and out == 'blocked'

    monkeypatch.setenv('ZEROSMS_DANGER_DO_IT', '1')
    args2 = SimpleNamespace(dry_run=True, danger_do_it=False)
    ok2, out2 = qa.write_nv('0xEA64', 'deadbeef', args2)
    assert ok2 is True and out2 == 'dry-run'
    monkeypatch.delenv('ZEROSMS_DANGER_DO_IT', raising=False)


def test_probe_with_missing_profile_module_does_not_crash():
    profiles = [{'adapter_module': 'nonexistent.module'}]
    b = qa.probe_backends(profiles=profiles)
    assert isinstance(b, list)


def test_profile_adapter_factory(monkeypatch):
    # Create a fake module that provides a get_backend factory
    import types

    mod = types.ModuleType('tools._dummy_adapter')

    class DummyBackend(qa.Backend):
        name = 'dummy'

        def available(self):
            return True

        def run(self, cmd: str):
            return True, 'ok'

        def info(self):
            return True, 'dummy info'

        def read_nv(self, nv_id: str):
            return True, 'dummy nv'

        def write_nv(self, nv_id: str, value: str):
            return True, 'dummy write'

    def get_backend(_profile):
        return DummyBackend()

    mod.get_backend = get_backend
    monkeypatch.setitem(sys.modules, 'tools._dummy_adapter', mod)

    profiles = [{'adapter_module': 'tools._dummy_adapter'}]
    backends = qa.probe_backends(profiles=profiles)
    names = [b.name for b in backends]
    assert 'dummy' in names


def test_example_adapter_selected_by_profile():
    profiles = [{'adapter_module': 'tools.vendor_adapters.example_adapter'}]
    backends = qa.probe_backends(profiles=profiles)
    names = [b.name for b in backends]
    # Example adapter declares name 'example-vendor'
    assert 'example-vendor' in names


def test_example_adapter_read_masked():
    profiles = [{'adapter_module': 'tools.vendor_adapters.example_adapter'}]
    backends = qa.probe_backends(profiles=profiles)
    # find example backend and call read_nv
    ex = next((b for b in backends if b.name == 'example-vendor'), None)
    assert ex is not None
    ok, out = ex.read_nv('0xEA64')
    assert ok is True
    assert 'MASKED' in out


def test_load_device_profiles():
    profiles = qa.load_device_profiles()
    assert isinstance(profiles, list)
    # example.json exists in repository; ensure at least dicts are returned
    assert any(isinstance(p, dict) for p in profiles)
