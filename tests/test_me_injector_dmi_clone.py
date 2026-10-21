"""Tests for the ME/TXE region injector and DMI clone engines."""

import struct

from tests.fixture_builder import build_intel_ifd_image
from bios_recovery.platforms.intel.me.me_injector import MEInjector, detect_me_version_in_blob
from bios_recovery.engines.dmi_clone import DMIClone
from bios_recovery.engines.dmi_extractor import DMIExtractor


def _read(path):
    with open(path, "rb") as f:
        return f.read()


def _make_clean_me(size: int = 0x3FF000, version=(9, 5)) -> bytes:
    blob = bytearray(bytes((i * 13 + 7) & 0xFF for i in range(size)))
    fpt = 0x10
    blob[fpt:fpt + 4] = b"$FPT"
    struct.pack_into("<I", blob, fpt + 4, 2)
    # Real manifest layout: tag at base+0x1C, version u16x4 at base+0x24
    marker = 0x501C
    blob[marker:marker + 4] = b"$MN2"
    ver = version + (0,) * (4 - len(version))
    struct.pack_into("<HHHH", blob, marker + 8, *ver)  # base+0x24 = tag+8
    return bytes(blob)


def test_detect_version_in_blob():
    assert detect_me_version_in_blob(_make_clean_me(version=(9, 1))).startswith("9.1")
    assert detect_me_version_in_blob(b"\x00" * 0x1000) == ""


def test_me_inject_roundtrip(tmp_path):
    src = tmp_path / "bios.bin"
    src.write_bytes(build_intel_ifd_image())

    inj = MEInjector()
    analysis = inj.analyze(str(src))
    assert analysis["found"]
    assert analysis["offset"] == 0x1000
    assert analysis["version"].startswith("12.8")   # from the fixture's CSME 12.8

    clean = tmp_path / "clean_me.bin"
    clean.write_bytes(_make_clean_me(version=(9, 5)))

    out = str(tmp_path / "mefixed.bin")
    report = inj.inject(str(src), str(clean), out)
    assert report["success"], report["message"]
    assert report["new_version"].startswith("9.5")
    assert "9.5" in report["message"] and "12.8" in report["message"]

    fixed = _read(out)
    # descriptor untouched
    assert fixed[:0x1000] == build_intel_ifd_image()[:0x1000]
    # region now carries the new firmware, FF-padded to the region size
    from bios_recovery.platforms.intel.me.me_injector import detect_me_version_in_blob as dv
    region = fixed[0x1000:0x1000 + 0x3FF000]
    assert dv(region).startswith("9.5")
    assert region[-1] == _read(str(clean))[-1]  # equal-size blob, no padding
    # BIOS region untouched
    assert fixed[0x401000:0x401010] == build_intel_ifd_image()[0x401000:0x401010]


def test_me_inject_rejects_oversized_clean(tmp_path):
    src = tmp_path / "bios.bin"
    src.write_bytes(build_intel_ifd_image())
    big = tmp_path / "big.bin"
    big.write_bytes(b"\xFF" * 0x800000)   # larger than the 0x3FF000 ME region
    report = MEInjector().inject(str(src), str(big), str(tmp_path / "out.bin"))
    assert not report["success"]
    assert "larger" in report["message"]


def test_dmi_clone_restores_identity(tmp_path):
    original = build_intel_ifd_image()
    # a genuinely different build: UUID is randomized per build, layout identical
    other_build = build_intel_ifd_image()
    assert original != other_build

    new_path = tmp_path / "new.bin"
    new_path.write_bytes(other_build)
    old_path = tmp_path / "old.bin"
    old_path.write_bytes(original)

    cloner = DMIClone()
    analysis = cloner.analyze(str(old_path), str(new_path))
    assert analysis["old_found"] and analysis["new_found"]

    old_uuid = DMIExtractor().extract_from_bios(str(old_path)).system_uuid
    new_uuid = DMIExtractor().extract_from_bios(str(new_path)).system_uuid
    assert old_uuid != new_uuid, "fixtures should carry different identities"

    out = str(tmp_path / "cloned.bin")
    report = cloner.clone(str(old_path), str(new_path), out)
    assert report["success"], report["message"]

    # DMI identity from the original dump must now be present in the clone
    info = DMIExtractor().extract_from_bios(out)
    assert info.system_manufacturer == "LENOVO"
    assert info.system_serial_number == "PF1ABC123"
    assert info.system_uuid == old_uuid
    assert len(info.structures) >= 5
