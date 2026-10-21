"""User-chosen folders for Intel tools and ME firmware (nothing is bundled)."""

import os
import shutil
import stat

import pytest

from bios_recovery.core import user_library as lib
from tests.fixture_builder import build_intel_ifd_image

POSIX_ONLY = pytest.mark.skipif(os.name == "nt", reason="uses POSIX shell scripts")


@pytest.fixture(autouse=True)
def isolated_config(tmp_path, monkeypatch):
    monkeypatch.setenv("BIOS_RECOVERY_CONFIG_DIR", str(tmp_path / "cfg"))
    yield


def test_nothing_is_configured_by_default():
    assert lib.load_library().folders == []
    result = lib.scan()
    assert result.folders == [] and result.tools == [] and result.firmware == []


def test_add_list_remove_folder(tmp_path):
    folder = tmp_path / "my_tools"
    folder.mkdir()
    lib.add_folder(str(folder))
    lib.add_folder(str(folder))  # idempotent
    assert lib.load_library().folders == [os.path.abspath(folder)]
    lib.remove_folder(str(folder))
    assert lib.load_library().folders == []


def test_missing_folder_is_refused(tmp_path):
    with pytest.raises(ValueError):
        lib.add_folder(str(tmp_path / "nope"))


def test_scan_finds_firmware_in_user_folder(tmp_path):
    folder = tmp_path / "fw"
    folder.mkdir()
    (folder / "ME_image.bin").write_bytes(build_intel_ifd_image())
    (folder / "notes.txt").write_text("ignore me")
    lib.add_folder(str(folder))
    result = lib.scan()
    assert [os.path.basename(f.path) for f in result.firmware] == ["ME_image.bin"]
    assert result.firmware[0].me_version.startswith("12.")


@POSIX_ONLY
def test_scan_identifies_user_supplied_tool(tmp_path):
    folder = tmp_path / "tools"
    folder.mkdir()
    tool = folder / "mfit"
    tool.write_text("#!/bin/sh\necho 'Intel (R) Modular Flash Image Tool. Version: 16.50.0.1120'\n")
    tool.chmod(tool.stat().st_mode | stat.S_IXUSR)
    lib.add_folder(str(folder))
    result = lib.scan()
    assert [(t.family, t.version) for t in result.tools] == [("MFIT", "16.50.0.1120")]


@POSIX_ONLY
def test_fit_info_uses_library_tool_when_compatible(tmp_path, capsys):
    from bios_recovery.main import _cli_main
    folder = tmp_path / "tools"
    folder.mkdir()
    tool = folder / "fit"
    tool.write_text("#!/bin/sh\necho 'Intel (R) Flash Image Tool. Version: 12.0.45.1509'\n")
    tool.chmod(tool.stat().st_mode | stat.S_IXUSR)
    img = tmp_path / "img.bin"
    img.write_bytes(build_intel_ifd_image())
    lib.add_folder(str(folder))
    rc = _cli_main(["fit-info", str(img)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "tool:         FIT 12.0.45.1509" in out and "compatible:   yes" in out


def test_library_cli_add_list_scan(tmp_path, capsys):
    from bios_recovery.main import _library_cli
    folder = tmp_path / "fw"
    folder.mkdir()
    assert _library_cli(["scan"]) == 0
    assert "no folders added" in capsys.readouterr().out
    assert _library_cli(["add-folder", str(folder)]) == 0
    assert _library_cli(["list"]) == 0
    assert os.path.abspath(folder) in capsys.readouterr().out
    assert _library_cli(["remove-folder", str(folder)]) == 0
    assert _library_cli(["bogus"]) == 2


def test_sub_partitions_and_duplicates_are_not_firmware(tmp_path):
    folder = tmp_path / "fw"
    (folder / "copy").mkdir(parents=True)
    full = build_intel_ifd_image()
    (folder / "full.bin").write_bytes(full)
    (folder / "copy" / "full_copy.bin").write_bytes(full)
    # a sub-partition: manifest-like bytes but no partition table
    (folder / "OEMP.bin").write_bytes(b"\x00" * 0x100 + b"$MN2" + b"\x00" * 0x100)
    lib.add_folder(str(folder))
    names = sorted(os.path.basename(f.path) for f in lib.scan().firmware)
    assert names == ["full.bin"]
