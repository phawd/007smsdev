"""Compatibility wrapper for module imports in tests and tools.

Some tests import mifi_controller as a top-level module. This file
re-exports the package-level module to keep existing import paths working.
"""
from tools.mifi_controller import *  # noqa: F401,F403

__all__ = [name for name in dir() if not name.startswith("_")]
