# -*- mode: python ; coding: utf-8 -*-

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

block_cipher = None

a = Analysis(
    ["bios_recovery/main.py"],
    pathex=[],
    binaries=[],
    datas=[("assets/icon.png", "assets"),
        ("bios_recovery/third_party/mea/MEA.py", "bios_recovery/third_party/mea"),
        ("bios_recovery/third_party/mea/MEA.dat", "bios_recovery/third_party/mea"),
        ("bios_recovery/third_party/mea/Huffman.dat", "bios_recovery/third_party/mea"),
        ("bios_recovery/third_party/mea/FileTable.dat", "bios_recovery/third_party/mea")],
    hiddenimports=[
        "bios_recovery.engines.mea_bridge",
        "bios_recovery.third_party.mea",
        "PySide6",
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
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon="assets/icon.ico",
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="BIOSRecoverySuite",
)
