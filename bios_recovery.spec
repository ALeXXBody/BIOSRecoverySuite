# -*- mode: python ; coding: utf-8 -*-

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

import sys

block_cipher = None

IS_WIN = sys.platform == "win32"
IS_MAC = sys.platform == "darwin"
# Linux/darwin builds keep icon and upx off: .ico is meaningless there and upx
# is not part of the CI toolchain off Windows.
exe_icon = "assets/icon.ico" if IS_WIN else ("assets/icon.icns" if IS_MAC else None)

a = Analysis(
    ["bios_recovery/main.py"],
    pathex=[],
    binaries=[],
    datas=[("assets/icon.png", "assets"),
        ("bios_recovery/third_party/mea/MEA.py", "bios_recovery/third_party/mea"),
        ("bios_recovery/third_party/mea/MEA.dat", "bios_recovery/third_party/mea"),
        ("bios_recovery/third_party/mea/Huffman.dat", "bios_recovery/third_party/mea"),
        ("bios_recovery/third_party/mea/FileTable.dat", "bios_recovery/third_party/mea"),
        ("bios_recovery/patches", "bios_recovery/patches")],
    hiddenimports=[
        "bios_recovery.engines.mea_bridge",
        "bios_recovery.third_party.mea",
        "PySide6",
        "cryptography",
        "PySide6.QtCore",
        "PySide6.QtGui",
        "PySide6.QtWidgets",
        # MEA.py is exec'd from a data file at runtime (child mode), so its
        # imports are invisible to PyInstaller's static analysis:
        "colorama",
        "crccheck",
        "pltable",
    ] + collect_submodules("bios_recovery"),
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["PyQt5", "PyQt6"],
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
    name="BIOSRecoverySuite",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=IS_WIN,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=exe_icon,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="BIOSRecoverySuite",
)

if IS_MAC:
    bundle = BUNDLE(coll, name="BIOSRecoverySuite.app", icon="assets/icon.icns")
