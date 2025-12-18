"""Example vendor adapter for qmi_adapter.

This is a small, safe example that demonstrates the adapter contract.

It is intentionally conservative: it supports `available()`, `info()`,
`read_nv()` and `write_nv()` but will honor dry-run semantics and avoid
destructive actions unless explicitly allowed by the caller.
"""
from typing import Tuple
import os

from tools.qmi_adapter import Backend


class ExampleBackend(Backend):
    name = 'example-vendor'

    def __init__(self, profile: dict | None = None):
        self.profile = profile or {}

    def available(self) -> bool:
        # Advertise available so tests can exercise it; in real adapters,
        # check for device nodes, vendor IDs, or helper binaries.
        return True

    def run(self, cmd: str) -> Tuple[bool, str]:
        return True, f'example run: {cmd}'

    def info(self) -> Tuple[bool, str]:
        node = self.profile.get('default_device_node', '/dev/cdc-wdm0')
        return True, f'example backend (device_node={node})'

    def read_nv(self, nv_id: str) -> Tuple[bool, str]:
        # Safe read: return masked NCK for the known NCK NV id (tests expect
        # masked output to avoid accidental disclosure in logs)
        if nv_id.lower() in ('0xea64', 'ea64', '60004'):
            return True, '****-MASKED-NCK-****'
        return True, f'example read nv {nv_id}'

    def write_nv(self, nv_id: str, value: str) -> Tuple[bool, str]:
        # Never perform real writes in example adapter; caller should perform
        # safety gating via environment/args in qmi_adapter.
        if os.getenv('ZEROSMS_DANGER_DO_IT') == '1':
            return True, f'example write nv {nv_id} = {value} (simulated)'
        return False, (
            'blocked (example adapter requires '
            'ZEROSMS_DANGER_DO_IT=1)'
        )


def get_backend(profile: dict) -> Backend:
    return ExampleBackend(profile)
