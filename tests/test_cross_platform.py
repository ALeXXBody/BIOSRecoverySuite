"""Cross-platform support: the suite runs on Linux and macOS too.

Windows keeps the signed installer + silent self-update; Linux and macOS ship
PyInstaller builds packaged by CI (tarball / .dmg) and the update dialog points
at the releases page instead of pretending to self-install.
"""

import pytest


def test_silent_installer_update_refuses_off_windows(monkeypatch):
    from bios_recovery.utils import updater as up

    with pytest.raises(OSError, match="only supported on Windows"):
        up.apply_installer_update("/nonexistent/setup.exe")


def test_pick_assets_recognises_platform_artifacts():
    """Linux tarball and macOS dmg assets are picked up for the releases page."""
    from bios_recovery.utils.updater import _pick_assets

    assets = _pick_assets(
        [
            {"name": "BIOSRecoverySuite-portable-0.4.32.zip",
             "browser_download_url": "https://example.invalid/portable.zip"},
            {"name": "BIOSRecoverySuite-linux-x64-0.4.32.tar.gz",
             "browser_download_url": "https://example.invalid/linux.tar.gz"},
            {"name": "BIOSRecoverySuite-macos-arm64-0.4.32.dmg",
             "browser_download_url": "https://example.invalid/macos.dmg"},
        ]
    )
    assert assets["portable"] == "https://example.invalid/portable.zip"
    assert assets["linux"] == "https://example.invalid/linux.tar.gz"
    assert assets["macos"] == "https://example.invalid/macos.dmg"
