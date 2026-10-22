"""Regression tests for the user library audit fixes (LB-1 to LB-7)."""

import hashlib
import os

import pytest

from bios_recovery.core import user_library as lib
from bios_recovery.main import _library_cli
from bios_recovery.platforms.intel.me import fit_bridge

POSIX_ONLY = pytest.mark.skipif(os.name == "nt", reason="symlinks and shell tools")


@pytest.fixture(autouse=True)
def isolated_config(tmp_path, monkeypatch):
    monkeypatch.setenv("BIOS_RECOVERY_CONFIG_DIR", str(tmp_path / "cfg"))
    monkeypatch.setenv("BIOS_RECOVERY_DATA_DIR", str(tmp_path / "data"))
    yield


@POSIX_ONLY
def test_scan_survives_dangling_symlink(tmp_path):
    """LB-1: one dangling link is listed as skipped; the scan completes."""
    folder = tmp_path / "tools"
    folder.mkdir()
    (folder / "fit_dangling.exe").symlink_to(tmp_path / "nowhere")
    result = lib.scan([str(folder)])
    assert any("fit_dangling.exe" in note for note in result.skipped)
    assert result.tools == []


@POSIX_ONLY
def test_scan_ignores_dangling_links_it_does_not_need(tmp_path):
    folder = tmp_path / "misc"
    folder.mkdir()
    (folder / "readme.txt").symlink_to(tmp_path / "nowhere")
    assert lib.scan([str(folder)]).skipped == []


def test_second_damaged_config_keeps_first_backup(tmp_path):
    """LB-3: each damaged config gets its own backup name."""
    cfg = lib.config_path()
    os.makedirs(os.path.dirname(cfg), exist_ok=True)
    with open(cfg, "w") as f:
        f.write("{bad-one")
    lib.load_library()
    with open(cfg, "w") as f:
        f.write("{bad-two")
    lib.load_library()
    assert open(cfg + ".damaged").read() == "{bad-one"
    assert open(cfg + ".damaged.1").read() == "{bad-two"


def test_identify_runs_the_bytes_that_were_hashed(tmp_path, monkeypatch):
    """LB-5: the cache key is the hash of the exact bytes that were run."""
    tool = tmp_path / "fit_tool.bin"
    tool.write_bytes(b"\x7fELF-original-bytes")
    seen = {}

    def fake_probe(path, timeout=20):
        with open(path, "rb") as f:
            seen["ran"] = f.read()
        return fit_bridge.ToolProbe(path=path, identified=True, family="FIT", version="1.2.3.4")

    monkeypatch.setattr(fit_bridge, "probe_tool", fake_probe)
    probe = lib.identify_tool(str(tool))
    assert probe.identified
    digest = hashlib.sha256(b"\x7fELF-original-bytes").hexdigest()
    assert seen["ran"] == b"\x7fELF-original-bytes"
    assert lib.load_library().identified[digest] == {"family": "FIT", "version": "1.2.3.4"}


def test_import_keeps_each_copy_and_never_overwrites(tmp_path, monkeypatch):
    """LB-6: two imports of the same name both survive, numbered."""
    src = tmp_path / "fit.bin"
    src.write_bytes(b"\x7fELF-tool")
    monkeypatch.setattr(
        fit_bridge,
        "probe_tool",
        lambda path, timeout=20: fit_bridge.ToolProbe(
            path=path, identified=True, family="FIT", version="1.2.3.4"
        ),
    )
    first = lib.import_files([str(src)], "tools")[0]
    second = lib.import_files([str(src)], "tools")[0]
    assert first.copied_to and second.copied_to
    assert first.copied_to != second.copied_to
    assert os.path.exists(first.copied_to) and os.path.exists(second.copied_to)
    assert not any(n.startswith(".") for n in os.listdir(os.path.dirname(first.copied_to)))


def test_tool_file_name_rejects_path_parts():
    """LB-7: a family, version or platform with separators cannot name a file."""
    assert lib.tool_file_name("FIT", "15.0.35.1951", "Linux") == "FIT_15.0.35.1951_Linux"
    with pytest.raises(ValueError):
        lib.tool_file_name("../../x", "1.2.3.4", "Linux")
    with pytest.raises(ValueError):
        lib.tool_file_name("FIT", "1.2/3", "Linux")


def test_full_spi_image_is_not_listed_as_me_firmware(tmp_path):
    """F-29: a full flash image is not a clean ME donor, even if it contains $FPT."""
    from tests.fixture_builder import build_intel_ifd_image

    folder = tmp_path / "fw"
    folder.mkdir()
    full = bytearray(build_intel_ifd_image())
    full[0x2000:0x2004] = b"$FPT"
    full[0x2004:0x2008] = (2).to_bytes(4, "little")
    (folder / "board.bin").write_bytes(bytes(full))
    standalone = bytearray(b"\xff" * 0x1000)
    standalone[0:4] = b"$FPT"
    standalone[4:8] = (2).to_bytes(4, "little")
    (folder / "me_only.bin").write_bytes(bytes(standalone))

    assert not lib._looks_like_me_image(bytes(full))
    assert lib._looks_like_me_image(bytes(standalone))
    refused = lib.import_files([str(folder / "board.bin")], "firmware")[0]
    assert refused.refused and not refused.copied_to
    kept = lib.import_files([str(folder / "me_only.bin")], "firmware")[0]
    assert kept.copied_to and not kept.refused


def test_library_cli_config_path_is_a_file_returns_2(tmp_path, monkeypatch, capsys):
    """LB-4: an unusable config location is a one-line error, not a traceback."""
    blocker = tmp_path / "not_a_dir"
    blocker.write_text("x")
    monkeypatch.setenv("BIOS_RECOVERY_CONFIG_DIR", str(blocker))
    folder = tmp_path / "tools"
    folder.mkdir()
    assert _library_cli(["add-folder", str(folder)]) == 2
    assert "Error:" in capsys.readouterr().err
