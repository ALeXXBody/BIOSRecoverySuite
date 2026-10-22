"""Regression tests: descriptor addressing, truncation refusal, strap read-back, injector guards.

FRBA, FLREG, FPSBA and FMBA are absolute file offsets (coreboot ifdtool find_frba, find_fpsba,
find_fmba; corna/me_cleaner flreg_to_start_end). The descriptor may sit at 0x10.
"""

import os
import struct

from bios_recovery.core.bios_analyzer import BiosAnalyzer
from bios_recovery.platforms.intel.me.me_cleaner import IntelMECleaner
from bios_recovery.platforms.intel.me.me_injector import MEInjector

SIG = b"\x5a\xa5\xf0\x0f"


def _image(fd: int = 0x10, size: int = 0x400000) -> bytearray:
    data = bytearray(b"\xff" * size)
    data[fd : fd + 4] = SIG
    struct.pack_into("<I", data, fd + 0x04, (0x40 >> 4) << 16)  # FLMAP0: FRBA = 0x40
    struct.pack_into("<I", data, 0x44, (0x0002 << 16) | 0x0001)  # BIOS FLREG: pages 1..2
    struct.pack_into("<I", data, 0x48, (0x0005 << 16) | 0x0004)  # ME FLREG: pages 4..5
    data[0x4000:0x4010] = b"\x00" * 0x10  # the ME region is not blank
    return data


def test_truncation_refused_on_full_image(tmp_path):
    src = tmp_path / "full.bin"
    src.write_bytes(bytes(_image()))
    out = tmp_path / "out.bin"
    report = IntelMECleaner().clean(str(src), str(out), truncate=True)
    assert report.status.name == "ERROR"
    assert "Truncation refused" in report.messages[0]
    assert not os.path.exists(out)


def test_hap_bit_is_written_at_absolute_fpsba_and_read_back():
    data = _image()
    struct.pack_into("<I", data, 0x18, (0x3000 >> 4) << 12)  # FLMAP1 at fd+0x08: FPSBA = 0x3000
    before = bytes(data[0x3010:0x3014])
    ok = IntelMECleaner()._set_hap_bit(data, 0x4000, 0x6000, None, 15)
    assert ok is True
    assert struct.unpack_from("<I", data, 0x3000)[0] & (1 << 16)
    assert bytes(data[0x3010:0x3014]) == before  # the old, shifted location is untouched


def test_flmstr2_is_written_at_absolute_fmba_and_read_back():
    from bios_recovery.platforms.intel.me.me_cleaner import MeGeneration

    data = _image()
    struct.pack_into("<I", data, 0x18, 0x00000020)  # FLMAP1 at fd+0x08: FMBA = 0x20 * 16 = 0x200
    before = bytes(data[0x0210:0x0214])
    ok = IntelMECleaner()._lock_me_descriptor(data, MeGeneration.GEN3)
    assert ok is True
    assert struct.unpack_from("<I", data, 0x204)[0] == 0x00400500
    assert bytes(data[0x0210:0x0214]) == before


def test_injector_writes_only_the_declared_me_region(tmp_path):
    img = tmp_path / "full.bin"
    original = bytes(_image())
    img.write_bytes(original)
    clean = tmp_path / "clean_me.bin"
    clean.write_bytes(b"\x24\x4d\x4e\x32" + b"\x11" * 0x800)  # content only; no version needed
    out = tmp_path / "injected.bin"

    result = MEInjector().inject(str(img), str(clean), str(out))
    if result["success"]:
        new = out.read_bytes()
        changed = [i for i in range(len(original)) if original[i] != new[i]]
        assert changed, "the ME region should change"
        assert all(0x4000 <= i < 0x6000 for i in changed), "bytes outside the ME region changed"
    else:
        # Refused by the region check is acceptable; nothing may be written.
        assert not os.path.exists(out)


def test_injector_refuses_empty_clean_image_and_same_path(tmp_path):
    img = tmp_path / "full.bin"
    img.write_bytes(bytes(_image()))
    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")
    out = tmp_path / "out.bin"

    assert MEInjector().inject(str(img), str(empty), str(out))["success"] is False
    assert not os.path.exists(out)

    clean = tmp_path / "clean.bin"
    clean.write_bytes(b"\x11" * 0x100)
    res = MEInjector().inject(str(img), str(clean), str(img))
    assert res["success"] is False and "input file" in res["message"]


def test_analyzer_regions_are_absolute_for_descriptor_at_0x10():
    regions = {r.region_type.name: r for r in BiosAnalyzer()._parse_intel_ifd(bytes(_image()))}
    assert regions["BIOS"].offset == 0x1000
    assert regions["INTEL_ME"].offset == 0x4000
