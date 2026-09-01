"""Unit tests for BIOS Recovery Suite."""

import sys
import os
import struct

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bios_recovery.engines.bios_analyzer import BiosAnalyzer, BiosType


def _make_fake_bios_dump(size=0x1000000):
    """Create a fake but structurally valid Intel flash descriptor image."""
    data = bytearray(0xFF for _ in range(size))

    struct.pack_into("<I", data, 0x00, 0x0FF0A55A)
    struct.pack_into("<I", data, 0x10, 0x00000000)
    struct.pack_into("<I", data, 0x14, 0x00000000)

    FRBA = 0x100
    struct.pack_into("<I", data, 0x10, FRBA << 16)
    data[FRBA + 0x08:FRBA + 0x0C] = struct.pack("<I", (0x100000 >> 12) | ((size >> 12) << 16))
    data[FRBA + 0x10:FRBA + 0x14] = struct.pack("<I", (0x1000 >> 12) | ((0x100000 >> 12) << 16))

    fpt_offset = 0x100000
    data[fpt_offset:fpt_offset + 4] = b"$FPT"
    struct.pack_into("<I", data, fpt_offset + 0x04, 1)
    data[fpt_offset + 0x20:fpt_offset + 0x24] = b"FTPR"
    data[fpt_offset + 0x28:fpt_offset + 0x2C] = struct.pack("<I", 0x1000)
    data[fpt_offset + 0x2C:fpt_offset + 0x30] = struct.pack("<I", 0x100000)

    return bytes(data)


def test_analyzer_detects_intel_ifd():
    data = _make_fake_bios_dump()
    path = "/tmp/test_bios.bin"
    with open(path, "wb") as f:
        f.write(data)

    analyzer = BiosAnalyzer()
    result = analyzer.analyze(path)

    assert result.bios_type == BiosType.INTEL_IFD
    assert result.has_flash_descriptor
    assert result.has_me_region
    assert result.file_size == len(data)
    assert result.md5

    os.unlink(path)


def test_analyzer_unknown_file():
    path = "/tmp/test_random.bin"
    with open(path, "wb") as f:
        f.write(b"\x00" * 0x1000)

    analyzer = BiosAnalyzer()
    result = analyzer.analyze(path)

    assert result.bios_type == BiosType.UNKNOWN
    assert result.issues

    os.unlink(path)


if __name__ == "__main__":
    test_analyzer_detects_intel_ifd()
    test_analyzer_unknown_file()
    print("All tests passed!")
