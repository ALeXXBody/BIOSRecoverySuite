"""CSME 11+ ("CSE LT") engine clean expectations.

On those engines the standard clean is the HAP/AltMeDisable soft-disable and
NOTHING else — the same behaviour me_cleaner documents for CSME 11+. The
formerly misleading "Cleaned Size: 0x0" reporting is fixed: the region size does
not change, and the report names the one byte that was modified.
"""

import pytest


@pytest.fixture()
def cleaner():
    from bios_recovery.platforms.intel.me.me_cleaner import IntelMECleaner

    return IntelMECleaner()


def _lt_with_straps(tmp_path):
    """Standalone LT-style image including a descriptor, so the strap is reachable."""
    import struct

    from tests.test_intel_fix_cleaner import SIG, _fpt, _manifest  # type: ignore

    size = 0x80000
    data = bytearray(b"\xff" * size)
    data[0x10:0x14] = SIG
    struct.pack_into("<I", data, 0x14, 0x00040000)  # FLMAP0: FRBA = 0x40
    struct.pack_into("<I", data, 0x18, 0x00300000)  # FLMAP1: FPSBA = 0x300
    struct.pack_into("<I", data, 0x48, 0x007F0000)  # FLREG2: ME 0x0..0x7FFFF (in image)
    data[0x300:0x304] = b"\x00\x00\x00\x00"  # strap dword with the HAP bit unset
    _fpt(data, 0x0, [(b"NFTP", 0x1000, 0x1000)])
    data[0x4000:0x5000] = b"\x55" * 0x1000
    data[0x2000:0x2004] = b"$CPD"
    _manifest(data, 0x3000, version=(15, 0, 55, 2751))
    data[0x3000:0x3004] = b"$MN2"
    src = str(tmp_path / "in.bin")
    with open(src, "wb") as f:
        f.write(bytes(data))
    return src, data


def test_lt_clean_reports_original_size_and_changed_byte(tmp_path, cleaner):
    src, data = _lt_with_straps(tmp_path)
    out = str(tmp_path / "out.bin")
    _pre = bytes(data)
    report = cleaner.clean(src, out, soft_disable=True)
    assert report.status.name == "SUCCESS"
    assert report.hap_bit_set is True
    # Nothing was removed or truncated: the region keeps its size.
    assert report.cleaned_size == report.original_size
    assert report.partitions_removed == 0
    body = "\n".join(report.messages)
    # The report names the exact strap location and the single changed byte.
    assert "0x302" in body           # FPSBA 0x300 + 2, bit 16 -> byte index 0x302
    assert "bit 16" in body
    with open(out, "rb") as f:
        cleaned = f.read()
    differs = [
        i for i in range(len(cleaned)) if cleaned[i] != data[i]
    ]
    assert len(differs) == 1 and differs[0] == 0x302
    assert (cleaned[0x302] & 0x01) == 0x01  # bit 16 = bit 0 of the third byte


def test_is_cse_lt_engine_detects_lt(tmp_path, cleaner):
    src, _data = _lt_with_straps(tmp_path)
    assert cleaner.is_cse_lt_engine(src) is True
