"""Tests for the self-update engine (pure logic, no network)."""

import hashlib
import io
import os

import pytest

from bios_recovery.utils import updater as up
from bios_recovery.utils.updater import ReleaseInfo, _parse_tag, _pick_assets, is_newer


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
    assert not is_newer("bad-tag", "1.1.1")  # unparsable remote -> never update
    assert is_newer("v1.1.1", "0.0.0")


def test_pick_assets_prefers_installer_and_portable():
    assets = [
        {
            "name": "BIOSRecoverySuite-Setup-1.2.0.exe",
            "browser_download_url": "https://x/setup.exe",
        },
        {
            "name": "BIOSRecoverySuite-v1.2.0-windows-portable.zip",
            "browser_download_url": "https://x/portable.zip",
        },
        {"name": "Source code (zip)", "browser_download_url": "https://x/src.zip"},
        {"name": "notes.txt", "browser_download_url": "https://x/notes.txt"},
    ]
    picked = _pick_assets(assets)
    assert picked["installer"] == "https://x/setup.exe"
    assert picked["portable"] == "https://x/portable.zip"


def test_pick_assets_empty():
    assert _pick_assets([]) == {"installer": None, "installer_sha256": None, "portable": None}
    assert _pick_assets([{"name": "no-url"}]) == {
        "installer": None,
        "installer_sha256": None,
        "portable": None,
    }


def test_release_info_defaults():
    info = ReleaseInfo(version="1.2.0", notes="n", html_url="u")
    assert info.installer_url is None
    assert info.portable_url is None


def test_tag_with_extra_text_is_rejected():
    assert _parse_tag("v1.2.3/../../x") == ()
    assert _parse_tag("v1.2.3-rc1") == ()
    assert not is_newer("v1.2.3/../x", "1.0.0")


def test_installer_digest_is_taken_from_the_release():
    assets = [
        {
            "name": "BIOSRecoverySuite-Setup-1.2.0.exe",
            "browser_download_url": "https://x/s.exe",
            "digest": "sha256:ABCDEF",
        }
    ]
    assert _pick_assets(assets)["installer_sha256"] == "abcdef"


def test_plain_http_assets_are_ignored():
    assets = [
        {"name": "BIOSRecoverySuite-Setup-1.2.0.exe", "browser_download_url": "http://x/s.exe"}
    ]
    assert _pick_assets(assets)["installer"] is None


def test_verify_fails_closed_without_digest(tmp_path):
    f = tmp_path / "setup.exe"
    f.write_bytes(b"MZ")
    with pytest.raises(up.UpdateIntegrityError, match="publishes no SHA-256"):
        up.verify_sha256(str(f), None)


def test_verify_rejects_wrong_digest(tmp_path):
    f = tmp_path / "setup.exe"
    f.write_bytes(b"MZ")
    with pytest.raises(up.UpdateIntegrityError, match="does not match"):
        up.verify_sha256(str(f), "0" * 64)
    up.verify_sha256(str(f), hashlib.sha256(b"MZ").hexdigest())  # correct digest passes


class _Resp(io.BytesIO):
    def __init__(self, body, length):
        super().__init__(body)
        self._length = length

    def getheader(self, name):
        return str(self._length) if name == "Content-Length" else None

    def geturl(self):
        return "https://example.invalid/setup.exe"

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_truncated_download_is_refused_and_removed(tmp_path, monkeypatch):
    dest = tmp_path / "setup.exe"
    monkeypatch.setattr(up.urllib.request, "urlopen", lambda *a, **k: _Resp(b"MZ" * 10, 100))
    with pytest.raises(up.UpdateIntegrityError, match="ended early"):
        up.download("https://example.invalid/setup.exe", str(dest))
    assert not os.path.exists(dest)


def test_download_refuses_plain_http(tmp_path):
    with pytest.raises(up.UpdateIntegrityError, match="non-HTTPS"):
        up.download("http://example.invalid/setup.exe", str(tmp_path / "x.exe"))
