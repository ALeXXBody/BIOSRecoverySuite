"""Startup diagnostics: a Qt DLL failure must explain itself, not just
traceback. The regression this covers is real and painful: a stale DLL left
next to the exe shadows the system copy and Qt dies with a bare
"DLL load failed ... The specified procedure could not be found".
"""

import os
import sys

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class _FakeSys:
    """Stand-in for the sys module of a PyInstaller-frozen process."""

    def __init__(self, exe_dir):
        self.frozen = True
        self.executable = os.path.join(exe_dir, "BIOSRecoverySuite.exe")


@pytest.fixture
def frozen_app(tmp_path, monkeypatch):
    """Make bios_recovery.main believe it runs frozen from tmp_path."""
    import bios_recovery.main as main_mod

    (tmp_path / "BIOSRecoverySuite.exe").write_bytes(b"MZ")
    monkeypatch.setattr(main_mod, "sys", _FakeSys(str(tmp_path)))
    return tmp_path


def test_diagnose_lists_stale_dlls(frozen_app, monkeypatch):
    """The message must actually name the offending DLLs in the app folder."""
    import bios_recovery.main as main_mod

    (frozen_app / "icuuc.dll").write_bytes(b"MZ")
    (frozen_app / "Qt6Core.dll").write_bytes(b"MZ")

    msg = main_mod._diagnose_qt_import_failure(ImportError("DLL load failed"))

    assert "icuuc.dll" in msg
    assert "Qt6Core.dll" in msg
    assert "LIKELY CAUSE" in msg
    # must give an actionable remedy
    assert "Uninstall" in msg
    assert str(frozen_app) in msg


def test_diagnose_clean_folder_points_at_windows_version(frozen_app):
    """With a clean folder, the next likely cause is an old Windows build."""
    import bios_recovery.main as main_mod

    msg = main_mod._diagnose_qt_import_failure(ImportError("boom"))

    assert "No obviously stale DLLs" in msg
    assert "winver" in msg


def test_installer_wipes_previous_install():
    """The installer must clear the app folder before unpacking.

    Qt resolves DLLs from the app folder first, so any leftover file from a
    previous build shadows the correct system copy. [InstallDelete] is what
    prevents a stale-DLL startup crash after an in-place upgrade.
    """
    with open(os.path.join(REPO, "installer.iss"), encoding="utf-8") as f:
        iss = f.read()
    assert "[InstallDelete]" in iss, "installer must wipe {app} before install"
    install_delete = iss.split("[InstallDelete]")[1].split("[Files]")[0]
    assert "{app}" in install_delete, "[InstallDelete] must target {app}"


def test_main_returns_nonzero_on_qt_failure(monkeypatch, capsys):
    """A failed Qt import must exit non-zero with the explanation, not a
    traceback."""
    import builtins

    import bios_recovery.main as main_mod

    real_import = builtins.__import__

    def fake_import(name, *a, **k):
        if name.startswith("PySide6"):
            raise ImportError("DLL load failed while importing QtWidgets")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    rc = main_mod.main()
    assert rc == 1
    err = capsys.readouterr().err
    assert "could not start" in err
    assert "Traceback" not in err