# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec for geo_grid_explorer.

Build the standalone executable with:
    pyinstaller geo_grid_explorer.spec

Output is placed in dist/geo_grid_explorer/
"""

import os

block_cipher = None

a = Analysis(
    ["tools/geo_grid_explorer.py"],
    pathex=[os.path.abspath("tools")],
    binaries=[],
    datas=[
        ("tools/geo_grid", "geo_grid"),
    ],
    hiddenimports=[
        "numpy",
        "matplotlib",
        "matplotlib.backends.backend_qt5agg",
        "PyQt5",
        "PyQt5.QtCore",
        "PyQt5.QtGui",
        "PyQt5.QtWidgets",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="geo_grid_explorer",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="geo_grid_explorer",
)
