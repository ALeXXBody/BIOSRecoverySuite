"""Regression tests for the audit batch: refusals that must hold, not guesses."""

import struct

import pytest

from bios_recovery.core.bios_analyzer import BiosAnalyzer
from bios_recovery.manufacturers.common.bios_capsule import (
    APTIO_CAPSULE_GUID_LE,
    APTIO_UNSIGNED_CAPSULE_GUID_LE,
    detect_capsule,
)
from bios_recovery.manufacturers.common.bios_extractor import BiosExtractor, ExtractionMethod
from bios_recovery.platforms.ec.ec_patcher import ECPatcher
from bios_recovery.platforms.intel.me.fit_bridge import ToolProbe, compatible_with_me


def _capsule(rom_offset=0x800, size_delta=0, total=0x2000, guid=APTIO_CAPSULE_GUID_LE):
    data = bytearray(b"\xff" * total)
    data[0:16] = guid
    struct.pack_into("<I", data, 0x10, 0x20)
    struct.pack_into("<I", data, 0x18, total + size_delta)
    struct.pack_into("<H", data, 0x1C, rom_offset)
    struct.pack_into("<H", data, 0x1E, 0x20)
    return bytes(data)


def test_capsule_with_matching_header_is_accepted():
    assert detect_capsule(_capsule()).success


def test_capsule_larger_than_file_is_refused_as_truncated():
    info = detect_capsule(_capsule(size_delta=0x10))
    assert not info.success
    assert any("truncated" in m for m in info.messages)


def test_capsule_with_trailing_bytes_is_accepted_with_a_note():
    info = detect_capsule(_capsule(size_delta=-0x10))
    assert info.success and info.image_end == 0x2000 - 0x10
    assert any("ignored" in m for m in info.messages)


def test_capsule_with_zero_or_oversized_image_offset_is_refused():
    assert not detect_capsule(_capsule(rom_offset=0)).success
    assert not detect_capsule(_capsule(rom_offset=0x3000)).success


def test_unsigned_aptio_capsule_guid_is_accepted():
    assert detect_capsule(_capsule(guid=APTIO_UNSIGNED_CAPSULE_GUID_LE)).success


def test_image_starts_at_rom_image_offset_not_header_size_field():
    data = _capsule(rom_offset=0x400)
    info = detect_capsule(data)
    assert info.success and info.header_size == 0x400
    assert info.image_size == len(data) - 0x400


def test_negative_manual_ec_offset_is_refused_not_ignored():
    data = b"\x00" * 0x10000
    offset, size, err = ECPatcher().resolve_region(data, -0x10, 0x1000)
    assert offset < 0 and "zero or more" in err


def test_manual_ec_offset_without_size_is_refused():
    offset, _size, err = ECPatcher().resolve_region(b"\x00" * 0x10000, 0x100, None)
    assert offset < 0 and err


def test_hex_view_rejects_negative_offset_and_zero_length(tmp_path):
    path = tmp_path / "x.bin"
    path.write_bytes(b"\x00" * 64)
    with pytest.raises(ValueError):
        BiosAnalyzer().get_hex_view(str(path), -1, 16)
    with pytest.raises(ValueError):
        BiosAnalyzer().get_hex_view(str(path), 0, 0)


def test_pfs_detection_needs_a_plausible_header():
    stray = b"hello PFS world" + b"\x00" * 0x100
    assert not BiosExtractor()._has_pfs_header(stray)
    real = bytearray(b"\x00" * 0x200)
    real[0x40:0x44] = b"PFS "
    struct.pack_into("<I", real, 0x44, 0x100)
    assert BiosExtractor()._has_pfs_header(bytes(real))


def test_ambiguous_release_refuses_even_a_matching_tool():
    probe = ToolProbe(path="x", identified=True, family="FIT", version="14.0.11.1002")
    ok, why = compatible_with_me(probe, "14.0.11.1002")
    assert not ok and "ambiguous" in why


def test_hp_detection_needs_a_whole_word():
    assert (
        BiosExtractor()._detect_method(b"Hewlett HP BIOS" + b"\x00" * 0x100, "x.bin")
        == ExtractionMethod.HP_INSIDE
    )
    stray = b"chpcm and hpet tables" + b"\x00" * 0x100
    assert BiosExtractor()._detect_method(stray, "x.bin") != ExtractionMethod.HP_INSIDE


def test_lzma_stream_round_trips_and_only_valid_headers_match(tmp_path):
    import lzma

    from bios_recovery.manufacturers.common.bios_extractor import ExtractionResult

    payload = bytes(range(256)) * 5000 + b"END-OF-PAYLOAD"  # larger than 1 MB
    stream = lzma.compress(payload, format=lzma.FORMAT_ALONE)
    blob = b"\x00" * 0x40 + stream
    ex = BiosExtractor()
    offsets = ex._find_compressed_sections(blob)
    assert 0x40 in offsets
    result = ExtractionResult(success=False)
    ex._try_decompress_lzma(blob, 0x40, str(tmp_path), result)
    assert result.success
    assert (tmp_path / "decompressed_0x40.bin").read_bytes() == payload


def test_lzma_header_with_absurd_dictionary_is_ignored():
    bogus = b"\x00" * 8 + b"\x5d" + (0x12345).to_bytes(4, "little") + b"\x00" * 16
    assert 8 not in BiosExtractor()._find_compressed_sections(bogus)


def test_vendor_tie_is_ambiguous_and_refuses_vendor_tools():
    from bios_recovery.core.traits import classify
    from bios_recovery.core.traits_matrix import tool_matrix

    t = classify(b"\x00" * 64 + b" ASUS " + b" Lenovo " + b"\x00" * 64)
    assert t.vendor == "ambiguous"
    assert not tool_matrix(t)["Lenovo Unlock"].applies


def test_me_family_label_matches_analyzer_rule():
    from bios_recovery.core.traits import me_family_label

    assert me_family_label("15.0.3.1402") == "CSME 15"
    assert me_family_label("11.8.50.3470") == "CSME"
    assert me_family_label("7.1.20.1100") == "ME"
    assert me_family_label("") == ""


def _descriptor(fd_offset: int, frba: int = 0x40) -> bytearray:
    """A flash descriptor with the FRBA table at a real-world offset (0x40 from the descriptor)."""
    data = bytearray(b"\xff" * 0x400000)
    data[fd_offset : fd_offset + 4] = b"\x5a\xa5\xf0\x0f"
    struct.pack_into("<I", data, fd_offset + 0x04, (frba >> 4) << 16)  # FLMAP0: FRBA
    table = fd_offset + frba
    struct.pack_into("<I", data, table + 4, (0x0002 << 16) | 0x0001)  # BIOS: 1..2 pages
    struct.pack_into("<I", data, table + 8, (0x0005 << 16) | 0x0004)  # ME: 4..5 pages
    return data


@pytest.mark.parametrize("fd_offset", [0, 0x10])
def test_descriptor_regions_use_real_frba_layout(fd_offset):
    data = _descriptor(fd_offset)
    regions = {r.region_type.name: r for r in BiosAnalyzer()._parse_intel_ifd(bytes(data))}
    bios = regions["BIOS"]
    assert bios.offset == fd_offset + 0x1000
    assert bios.size == 0x2000
    me = regions["INTEL_ME"]
    assert me.offset == fd_offset + 0x4000
    assert me.size == 0x2000
