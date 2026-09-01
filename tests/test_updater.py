"""Tests for the self-update engine (pure logic, no network)."""

from bios_recovery.utils.updater import _parse_tag, is_newer, _pick_assets, ReleaseInfo


def test_parse_tag():
    assert _parse_tag("v1.2.3") == (1, 2, 3)
    assert _parse_tag("1.2.3") == (1, 2, 3)
    assert _parse_tag("v0.9.11") == (0, 9, 11)
    assert _parse_tag("garbage") == ()
    assert _parse_tag("") == ()


def test_is_newer():
    assert is_newer("v1.2.0", "1.1.1")
    assert is_newer("2.0.0", "1.9.9")
    assert not is_newer("v1.1.1", "1.1.1")
    assert not is_newer("v1.1.0", "1.1.1")
    assert not is_newer("bad-tag", "1.1.1")     # unparsable remote -> never update
    assert is_newer("v1.1.1", "0.0.0")


def test_pick_assets_prefers_installer_and_portable():
    assets = [
        {"name": "BIOSRecoverySuite-Setup-1.2.0.exe", "browser_download_url": "https://x/setup.exe"},
        {"name": "BIOSRecoverySuite-v1.2.0-windows-portable.zip", "browser_download_url": "https://x/portable.zip"},
        {"name": "Source code (zip)", "browser_download_url": "https://x/src.zip"},
        {"name": "notes.txt", "browser_download_url": "https://x/notes.txt"},
    ]
    picked = _pick_assets(assets)
    assert picked["installer"] == "https://x/setup.exe"
    assert picked["portable"] == "https://x/portable.zip"


def test_pick_assets_empty():
    assert _pick_assets([]) == {"installer": None, "portable": None}
    assert _pick_assets([{"name": "no-url"}]) == {"installer": None, "portable": None}


def test_release_info_defaults():
    info = ReleaseInfo(version="1.2.0", notes="n", html_url="u")
    assert info.installer_url is None
    assert info.portable_url is None
