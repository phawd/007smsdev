#!/usr/bin/env python3
"""tools/qmi_adapter.py

Improved QMI adapter for 007smsdev.

Features added:
- Modular backend classes (Local qmicli, ADB qmicli, libqmi stub)
- Capability detection and `get_modem_info()` helper
- Device profile support (optional JSON files under `tools/device_profiles/`)
- Dry-run and explicit destructive-op guards

Design goals: remain conservative by default, be extensible for new device
adapters, and prefer safe informative output over destructive defaults.
"""

import argparse
import json
import importlib.util
import os
import shutil
import subprocess
from typing import List, Optional, Tuple

DEFAULT_DRY_RUN = True
DEVICE_PROFILE_DIR = os.path.join(os.path.dirname(__file__), 'device_profiles')


def _log(*args, **kwargs):
    print('[qmi_adapter]', *args, **kwargs)


class Backend:
    name = 'base'

    def available(self) -> bool:
        raise NotImplementedError()

    def run(self, cmd: str) -> Tuple[bool, str]:
        raise NotImplementedError()

    def info(self) -> Tuple[bool, str]:
        raise NotImplementedError()

    def read_nv(self, nv_id: str) -> Tuple[bool, str]:
        raise NotImplementedError()

    def write_nv(self, nv_id: str, value: str) -> Tuple[bool, str]:
        raise NotImplementedError()


class QmicliLocalBackend(Backend):
    name = 'qmicli'

    def available(self) -> bool:
        return shutil.which('qmicli') is not None

    def _exec(self, cmd: str) -> Tuple[bool, str]:
        _log('running local:', cmd)
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return p.returncode == 0, p.stdout + p.stderr

    def run(self, cmd: str):
        return self._exec(cmd)

    def info(self):
        # Generic info command; callers should adapt device path if needed
        cmd = 'qmicli --help'
        return self._exec(cmd)

    def read_nv(self, nv_id: str) -> Tuple[bool, str]:
        cmd = "qmicli -d /dev/cdc-wdm0 --dms-get-identifier"  # placeholder
        return self._exec(cmd)

    def write_nv(self, nv_id: str, value: str) -> Tuple[bool, str]:
        cmd = "qmicli -d /dev/cdc-wdm0 --dms-set-identifier='{}'".format(value)
        return self._exec(cmd)


class ADBQmicliBackend(Backend):
    name = 'adb'

    def available(self) -> bool:
        return shutil.which('adb') is not None

    def _exec(self, cmd: str) -> Tuple[bool, str]:
        full = "adb shell '" + cmd.replace("'", "'\\''") + "'"
        _log('running adb:', full)
        p = subprocess.run(full, shell=True, capture_output=True, text=True)
        return p.returncode == 0, p.stdout + p.stderr

    def run(self, cmd: str):
        return self._exec(cmd)

    def info(self):
        # Try calling qmicli on device
        cmd = 'qmicli --help'
        return self._exec(cmd)

    def read_nv(self, nv_id: str) -> Tuple[bool, str]:
        cmd = "qmicli -d /dev/cdc-wdm0 --dms-get-identifier"  # placeholder
        return self._exec(cmd)

    def write_nv(self, nv_id: str, value: str) -> Tuple[bool, str]:
        cmd = "qmicli -d /dev/cdc-wdm0 --dms-set-identifier='{}'".format(value)
        return self._exec(cmd)


class LibqmiBackend(Backend):
    name = 'libqmi_python'

    def available(self) -> bool:
        # Use importlib to detect presence without importing into locals
        return importlib.util.find_spec('libqmi') is not None

    def run(self, cmd: str) -> Tuple[bool, str]:
        # libqmi Python usage is device specific. Provide a stub that
        # indicates libqmi is present and defers to specialized adapters.
        return True, 'libqmi available (use specialized adapter)'

    def info(self) -> Tuple[bool, str]:
        return True, 'libqmi backend (no-op info)'

    def read_nv(self, nv_id: str) -> Tuple[bool, str]:
        return False, 'libqmi read_nv not implemented in generic adapter'

    def write_nv(self, nv_id: str, value: str) -> Tuple[bool, str]:
        return False, 'libqmi write_nv not implemented in generic adapter'


def load_device_profiles(path: Optional[str] = None) -> List[dict]:
    profiles: List[dict] = []
    base = path or DEVICE_PROFILE_DIR
    if not os.path.isdir(base):
        return profiles
    for fn in sorted(os.listdir(base)):
        if not fn.endswith('.json'):
            continue
        try:
            with open(os.path.join(base, fn), 'r') as f:
                profiles.append(json.load(f))
        except Exception as e:
            _log('failed to load profile', fn, e)
    return profiles


def probe_backends(profiles: Optional[List[dict]] = None) -> List[Backend]:
    """Discover available backends.

    If `profiles` are provided, will attempt to import and instantiate
    any adapter modules declared in profiles (key: `adapter_module`).
    This lets device profiles specify specialized backends for new
    or vendor-specific chipsets.
    """
    backends: List[Backend] = []
    for cls in (QmicliLocalBackend, LibqmiBackend, ADBQmicliBackend):
        try:
            b = cls()
            if b.available():
                backends.append(b)
        except Exception as e:
            # ignore backend construction failures but log for visibility
            _log('backend init failed:', getattr(e, 'args', e))

    # Profiles can declare adapter_module which should expose a
    # `get_backend()` factory returning a Backend instance.
    if profiles:
        for p in profiles:
            mod_name = p.get('adapter_module')
            if not mod_name:
                continue
            try:
                mod = importlib.import_module(mod_name)
                factory = getattr(mod, 'get_backend', None)
                if callable(factory):
                    b = factory(p)
                    if isinstance(b, Backend) and b.available():
                        backends.append(b)
            except Exception:
                _log('failed to load adapter', mod_name)
                continue

    return backends


def probe():
    b = probe_backends()
    _log('Detected backends:', [x.name for x in b])
    for be in b:
        ok, out = be.info()
        _log(be.name, 'info ok=', ok)
        _log(out)


def get_modem_info(backends: Optional[List[Backend]] = None,
                   profiles: Optional[List[dict]] = None) -> dict:
    backends = backends or probe_backends(profiles)
    for be in backends:
        ok, out = be.info()
        if ok:
            return {'backend': be.name, 'output': out}
    return {'backend': None, 'output': ''}


def read_nv(
    nv_id: str,
    args,
    profiles: Optional[List[dict]] = None,
) -> Tuple[bool, str]:
    if args.dry_run:
        _log('DRY RUN: read_nv', nv_id)
        return True, 'dry-run'
    backends = probe_backends(profiles)
    for be in backends:
        ok, out = be.read_nv(nv_id)
        if ok:
            return True, out
    return False, 'no backend'


def write_nv(
    nv_id: str,
    value: str,
    args,
    profiles: Optional[List[dict]] = None,
) -> Tuple[bool, str]:
    allow_env = os.getenv('ZEROSMS_DANGER_DO_IT') == '1'
    allow_arg = getattr(args, 'danger_do_it', False)
    allow = allow_env or allow_arg
    if not allow:
        _log(
            'Write NV blocked: set ZEROSMS_DANGER_DO_IT=1 or '
            'pass --danger-do-it'
        )
        return False, 'blocked'
    if args.dry_run:
        _log('DRY RUN: would write NV', nv_id, '=', value)
        return True, 'dry-run'
    backends = probe_backends(profiles)
    for be in backends:
        ok, out = be.write_nv(nv_id, value)
        if ok:
            return True, out
    return False, 'no backend'


def main():
    p = argparse.ArgumentParser(description='QMI adapter (safe defaults)')
    p.add_argument('--probe', action='store_true')
    p.add_argument('--info', action='store_true')
    p.add_argument('--read-nv', help='Read NV item (id hex)')
    p.add_argument('--write-nv', help='Write NV item (id hex)')
    p.add_argument('--value', help='Value for write')
    p.add_argument(
        '--danger-do-it', action='store_true',
        help='Allow destructive ops'
    )
    p.add_argument(
        '--dry-run', dest='dry_run', action='store_true',
        default=DEFAULT_DRY_RUN, help='Show commands only'
    )
    p.add_argument(
        '--no-dry-run', dest='dry_run', action='store_false',
        help='Allow executing commands'
    )
    p.add_argument(
        '--profile-dir',
        help='Directory with device profile JSON files',
        default=DEVICE_PROFILE_DIR,
    )
    args = p.parse_args()

    # Load optional device profiles
    profiles = load_device_profiles(args.profile_dir)
    if profiles:
        _log('Loaded', len(profiles), 'device profiles')

    if args.probe:
        probe()
        return
    if args.info:
        info = get_modem_info()
        _log('Modem info:', info)
        return
    if args.read_nv:
        ok, out = read_nv(args.read_nv, args)
        print('OK:', ok)
        print(out)
        return
    if args.write_nv:
        ok, out = write_nv(args.write_nv, args.value, args)
        print('OK:', ok)
        print(out)
        return
    p.print_help()


if __name__ == '__main__':
    main()

