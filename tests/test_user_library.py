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
    monkeypatch.setenv("BIOS_RECOVERY_DATA_DIR", str(tmp_path / "data"))
    yield


def test_nothing_is_configured_by_default():
    cfg = lib.load_library()
    assert cfg.tools_folders == [] and cfg.firmware_folders == []
    result = lib.scan()
    assert result.folders == [] and result.tools == [] and result.firmware == []


def test_add_list_remove_folder(tmp_path):
    folder = tmp_path / "my_tools"
    folder.mkdir()
    lib.add_folder(str(folder), "tools")
    lib.add_folder(str(folder), "tools")  # idempotent
    assert lib.load_library().tools_folders == [os.path.abspath(folder)]
    assert lib.load_library().firmware_folders == []
    lib.add_folder(str(folder), "firmware")
    lib.remove_folder(str(folder), "both")
    cfg = lib.load_library()
    assert cfg.tools_folders == [] and cfg.firmware_folders == []


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
    assert [(t.family, t.identified) for t in lib.scan().tools] == [("unidentified", False)]
    lib.identify_tool(str(tool))
    assert [(t.family, t.version) for t in lib.scan().tools] == [("MFIT", "16.50.0.1120")]


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
    lib.identify_tool(str(tool))
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


@POSIX_ONLY
def test_import_tool_copies_into_app_folder(tmp_path):
    src = tmp_path / "in" / "fit"
    src.parent.mkdir()
    src.write_text("#!/bin/sh\necho 'Intel (R) Flash Image Tool. Version: 15.0.35.1951'\n")
    res = lib.import_files([str(src)], "tools")
    assert res[0].refused == "" and res[0].copied_to.startswith(lib.app_library_dir())
    assert os.access(res[0].copied_to, os.X_OK)
    assert src.exists()  # original untouched
    assert [t.version for t in lib.scan().tools] == ["15.0.35.1951"]


def test_import_refuses_non_tool_and_partial_firmware(tmp_path):
    junk = tmp_path / "junk.bin"
    junk.write_bytes(b"\xff" * 0x1000)
    res = lib.import_files([str(junk)], "tools")
    assert res[0].copied_to == "" and "Flash Image Tool" in res[0].refused
    sub = tmp_path / "OEMP.bin"
    sub.write_bytes(b"\x00" * 0x100 + b"$MN2" + b"\x00" * 0x100)
    res = lib.import_files([str(sub)], "firmware")
    assert res[0].copied_to == "" and "partition table" in res[0].refused


def test_import_firmware_accepts_full_image(tmp_path):
    full = tmp_path / "me_full.bin"
    full.write_bytes(build_intel_ifd_image())
    res = lib.import_files([str(full)], "firmware")
    assert res[0].copied_to.startswith(os.path.join(lib.app_library_dir(), "firmware"))
    assert [f.me_version[:3] for f in lib.scan().firmware] == ["12."]


def test_old_flat_config_is_migrated(tmp_path):
    folder = tmp_path / "old"
    folder.mkdir()
    os.makedirs(lib.config_dir(), exist_ok=True)
    with open(lib.config_path(), "w") as f:
        f.write('{"folders": ["%s"]}' % str(folder))
    cfg = lib.load_library()
    assert cfg.tools_folders == [str(folder)] and cfg.firmware_folders == [str(folder)]


@POSIX_ONLY
def test_tool_with_spaces_in_name_is_found(tmp_path):
    folder = tmp_path / "tools"
    folder.mkdir()
    tool = folder / "fit v15"
    tool.write_text("#!/bin/sh\necho 'Intel (R) Flash Image Tool. Version: 15.40.16.2534'\n")
    tool.chmod(tool.stat().st_mode | stat.S_IXUSR)
    lib.add_folder(str(folder), "tools")
    lib.identify_tool(str(tool))
    assert [t.version for t in lib.scan().tools] == ["15.40.16.2534"]


@POSIX_ONLY
def test_identity_comes_from_content_not_name(tmp_path):
    # Two tools, both called "fit", different banners: the app tells them apart.
    a = tmp_path / "a" / "fit"
    b = tmp_path / "b" / "fit"
    for path, ver in ((a, "15.0.35.1951"), (b, "15.40.16.2534")):
        path.parent.mkdir()
        path.write_text(f"#!/bin/sh\necho 'Intel (R) Flash Image Tool. Version: {ver}'\n")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
    lib.add_folder(str(tmp_path / "a"), "tools")
    lib.add_folder(str(tmp_path / "b"), "tools")
    lib.identify_tool(str(a))
    lib.identify_tool(str(b))
    tools = {t.version: t for t in lib.scan().tools}
    assert tools["15.0.35.1951"].release == "v15.0 r15"
    assert tools["15.40.16.2534"].release == "v15.40 r3"
    assert tools["15.0.35.1951"].platform == "unknown"  # script, not ELF or PE


def test_platform_detected_from_format(tmp_path):
    elf = tmp_path / "x1"
    elf.write_bytes(b"\x7fELF" + b"\x00" * 60)
    pe = tmp_path / "x2.exe"
    pe.write_bytes(b"MZ" + b"\x00" * 60)
    assert lib.file_platform(str(elf)) == "Linux"
    assert lib.file_platform(str(pe)) == "Windows"


def test_import_names_tool_by_its_banner(tmp_path):
    if os.name == "nt":
        pytest.skip("POSIX script")
    src = tmp_path / "fit"
    src.write_text("#!/bin/sh\necho 'Intel (R) Flash Image Tool. Version: 14.1.60.1790'\n")
    res = lib.import_files([str(src)], "tools")
    assert os.path.basename(res[0].copied_to) == "FIT_14.1.60.1790_unknown"


@POSIX_ONLY
def test_scan_never_runs_a_tool(tmp_path):
    marker = tmp_path / "ran.marker"
    folder = tmp_path / "tools"
    folder.mkdir()
    tool = folder / "fit"
    tool.write_text(f"#!/bin/sh\necho ran >> '{marker}'\necho 'Flash Image Tool. Version: 15.0.35.1951'\n")
    tool.chmod(tool.stat().st_mode | stat.S_IXUSR)
    lib.add_folder(str(folder), "tools")
    lib.scan()
    lib.scan()
    assert not marker.exists()


@POSIX_ONLY
def test_identify_runs_once_and_caches_by_hash(tmp_path):
    marker = tmp_path / "runs.marker"
    folder = tmp_path / "tools"
    folder.mkdir()
    tool = folder / "fit"
    tool.write_text(f"#!/bin/sh\necho x >> '{marker}'\necho 'Flash Image Tool. Version: 14.1.60.1790'\n")
    tool.chmod(tool.stat().st_mode | stat.S_IXUSR)
    lib.add_folder(str(folder), "tools")
    assert lib.identify_tool(str(tool)).identified
    lib.scan()
    lib.scan()
    assert marker.read_text().count("x") == 1  # identify ran it once; scans did not
    assert lib.scan().tools[0].identified


def test_identify_refuses_a_non_tool(tmp_path):
    other = tmp_path / "notes"
    other.write_text("hello")
    probe = lib.identify_tool(str(other))
    assert not probe.identified
    assert lib.load_library().identified == {}


def test_damaged_config_is_kept_aside_not_overwritten(tmp_path):
    os.makedirs(lib.config_dir(), exist_ok=True)
    with open(lib.config_path(), "w") as f:
        f.write("{ not json")
    cfg = lib.load_library()
    assert cfg.tools_folders == []
    assert os.path.exists(lib.config_path() + ".damaged")
    assert open(lib.config_path() + ".damaged").read() == "{ not json"
