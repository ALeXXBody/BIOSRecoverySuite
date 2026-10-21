"""ME Analyzer updater: version logic and verified staging (no network)."""

import hashlib
import io
import os
import zipfile

import pytest

from bios_recovery.utils import mea_updater as up
from bios_recovery.third_party.mea import MEA_PATH


class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _zip(entries: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


def test_bundled_version_is_read():
    assert up.extract_version_from_mea_py(MEA_PATH) != ""


def test_newer_release_detected():
    assert up.is_mea_newer("v1.313.0-r380", "v1.312.0")
    assert not up.is_mea_newer("v1.312.0-r378", "v1.312.0-r378")
    assert not up.is_mea_newer("", "v1.312.0")


def test_stage_extracts_only_mea_files(tmp_path, monkeypatch):
    blob = _zip({
        "MEAnalyzer-1/MEA.py": b"title = 'ME Analyzer v9.9.9'\n",
        "MEAnalyzer-1/MEA.dat": b"data",
        "MEAnalyzer-1/../../evil.exe": b"MZ",
        "MEAnalyzer-1/readme.txt": b"hi",
    })
    rel = up.MEAReleaseInfo(tag="v9.9.9", name="", html_url="",
                            zip_url="https://example.invalid/a.zip",
                            zip_sha256=hashlib.sha256(blob).hexdigest())
    monkeypatch.setattr(up.urllib.request, "urlopen", lambda *a, **k: _Resp(blob))
    staged = up.stage_mea_update(rel, str(tmp_path))
    assert sorted(staged) == ["MEA.dat", "MEA.py"]
    assert sorted(os.listdir(tmp_path)) == ["MEA.dat", "MEA.py"]


def test_digest_mismatch_writes_nothing(tmp_path, monkeypatch):
    blob = _zip({"MEA.py": b"x"})
    rel = up.MEAReleaseInfo(tag="v9", name="", html_url="",
                            zip_url="https://example.invalid/a.zip", zip_sha256="0" * 64)
    monkeypatch.setattr(up.urllib.request, "urlopen", lambda *a, **k: _Resp(blob))
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        up.stage_mea_update(rel, str(tmp_path / "stage"))
    assert not (tmp_path / "stage").exists() or os.listdir(tmp_path / "stage") == []


def test_missing_digest_is_refused(tmp_path):
    rel = up.MEAReleaseInfo(tag="v9", name="", html_url="",
                            zip_url="https://example.invalid/a.zip", zip_sha256=None)
    with pytest.raises(ValueError, match="no published SHA-256"):
        up.stage_mea_update(rel, str(tmp_path))


def test_same_release_line_is_not_reported_newer(monkeypatch):
    rel = up.MEAReleaseInfo(tag="v1.312.0-r378", name="", html_url="")
    monkeypatch.setattr(up, "fetch_latest_mea_release", lambda: rel)
    result = up.check_mea_update(MEA_PATH)
    assert result["newer"] is False or result["local_version"] != "1.312.0"
    if result["local_version"] == "1.312.0":
        assert result["status"] == "same version (revision unknown)"
