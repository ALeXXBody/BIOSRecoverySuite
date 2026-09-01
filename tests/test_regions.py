"""Regression tests for the BIOS analysis and region-detection engines."""

import struct

from bios_recovery.engines.bios_analyzer import BiosAnalyzer, BiosType


def test_detects_intel_flash_descriptor(intel_ifd):
    analyzer = BiosAnalyzer()
    result = analyzer.analyze(intel_ifd)

    assert result.bios_type == BiosType.INTEL_IFD
    assert result.has_flash_descriptor
    assert result.has_me_region
    assert result.file_size == 0x1000000
    assert len(result.md5) == 32
    assert len(result.sha256) == 64


def test_region_layout_from_descriptor(intel_ifd):
    analyzer = BiosAnalyzer()
    result = analyzer.analyze(intel_ifd)

    fd = [r for r in result.regions if r.region_type.name == "FLASH_DESCRIPTOR"]
    me = [r for r in result.regions if r.region_type.name == "INTEL_ME"]
    bios = [r for r in result.regions if r.region_type.name == "BIOS"]
    gbe = [r for r in result.regions if r.region_type.name == "GBE"]

    assert fd, "flash descriptor region not found"
    assert fd[0].offset == 0

    assert me, "ME region not found"
    assert me[0].offset == 0x1000
    assert me[0].size == 0x3FF000

    assert bios, "BIOS region not found"
    assert bios[0].offset == 0x401000

    assert gbe, "GbE region not found"
    assert gbe[0].offset == 0x400000


def test_me_version_detected(intel_ifd):
    analyzer = BiosAnalyzer()
    result = analyzer.analyze(intel_ifd)

    assert result.me_version == "12.8"
    assert result.me_type.startswith("CSME")


def test_unknown_file_flagged():
    import tempfile, os
    path = os.path.join(tempfile.mkdtemp(), "random.bin")
    with open(path, "wb") as f:
        f.write(b"\x99" * 0x1000)
    result = BiosAnalyzer().analyze(path)
    assert result.bios_type == BiosType.UNKNOWN
    assert result.issues
    os.unlink(path)


def test_firmware_volume_header_parsed(intel_ifd):
    """Verify the _FVH firmware volume is located with correct size (regression: FvLength is +0x20)."""
    analyzer = BiosAnalyzer()
    result = analyzer.analyze(intel_ifd)

    fvs = [r for r in result.regions if "Firmware Volume" in r.name]
    assert fvs, "no firmware volume detected"
    assert fvs[0].offset == 0x401000
    assert fvs[0].size >= 0x80000


def test_hex_view(intel_ifd):
    data = BiosAnalyzer().get_hex_view(intel_ifd, 0, 16)
    assert data[:4] == b"\x5a\xa5\xf0\x0f"