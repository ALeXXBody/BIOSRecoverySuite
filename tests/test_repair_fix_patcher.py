"""Regression tests for the UEFI patcher findings in the repair audit (H2, H4, H5, L1, L2,
L6, L7, M1-M4, M8)."""

import os
import struct
import uuid

import pytest

from bios_recovery.platforms.intel import uefi_patcher as uefi_module
from bios_recovery.platforms.intel.uefi_patcher import UEFIPatcher, UEFIPatchError
from tests.fixture_builder import (
    UEFI_PATCH_TARGET_GUID,
    AUTOpatch_BOOTOPTION_GUID,
    AUTOpatch_TRANSLATE_GUID,
    _ffs_header,
    _pad_ffs,
    _section,
)

DXE_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "bios_recovery", "patches", "dxe"
)
NVRAM_VOL = os.path.join(DXE_DIR, "NVRAM_EfiSystemNvDataFvGuid.vol")
GUID_A = "11111111-2222-3333-4444-555555555555"
GUID_B = "66666666-7777-8888-9999-AAAAAAAABBBB"
FFS2 = "8C8CE578-8A3D-4F1C-9935-896185C32DD3"
POLARITY_ONE = 0x0004FEFF  # erase polarity bit set: erased bytes are 0xFF
POLARITY_ZERO = 0x0004EFFF & ~0x800


def _fv(body: bytes, attrs: int = POLARITY_ZERO, fv_len: int = 0x10000, fs_guid: str = FFS2):
    hdr = bytearray(0x48)
    hdr[0x10:0x20] = uuid.UUID(fs_guid).bytes_le
    struct.pack_into("<Q", hdr, 0x20, fv_len)
    hdr[0x28:0x2C] = b"_FVH"
    struct.pack_into("<I", hdr, 0x2C, attrs)
    struct.pack_into("<H", hdr, 0x30, 0x48)
    hdr[0x37] = 0x02
    struct.pack_into("<II", hdr, 0x38, fv_len // 0x1000, 0x1000)
    struct.pack_into("<H", hdr, 0x32, (0x10000 - sum(struct.unpack_from("<36H", hdr))) & 0xFFFF)
    erased = 0xFF if attrs & 0x800 else 0x00
    fv = bytes(hdr) + body
    return fv + bytes([erased]) * (fv_len - len(fv))


def _large_ffs(guid: str, ftype: int, body: bytes, state: int = 0x07) -> bytes:
    """FFS file with FFS_ATTRIB_LARGE_FILE: Size is zero and ExtendedSize holds the length."""
    size = 0x20 + len(body)
    hdr = bytearray(0x20)
    hdr[0:16] = uuid.UUID(guid).bytes_le
    hdr[0x12] = ftype
    hdr[0x13] = 0x01
    struct.pack_into("<Q", hdr, 0x18, size)
    hdr[0x17] = state
    probe = bytearray(hdr)
    probe[0x10] = probe[0x11] = probe[0x17] = 0
    hdr[0x10] = (-sum(probe)) & 0xFF
    hdr[0x11] = 0xAA
    return bytes(hdr) + body


def _write(path, data: bytes) -> str:
    path.write_bytes(data)
    return str(path)


def _file_guids(patcher, image, attrs: int = POLARITY_ZERO) -> list:
    return [f.guid for f in patcher.parse_fv_files(image, 0, len(image), 0x48, attrs, None)]


def _patcher(tmp_path, text: str) -> UEFIPatcher:
    path = tmp_path / "patches.txt"
    path.write_text(text)
    return UEFIPatcher(str(path))


def test_user_interface_section_is_read_as_driver_name(patcher, tmp_path):
    """L1: the UI section type is 0x15; 0x16 is COMPATIBILITY16."""
    name = "LenovoTestDriver".encode("utf-16-le") + b"\x00\x00"
    body = _section(0x15, name)
    image = _fv(_pad_ffs(_ffs_header(GUID_A, 0x07, 0x00, body)))
    path = _write(tmp_path / "ui.bin", image)

    names = {f["guid"]: f["name"] for f in patcher.list_files(path)}
    assert names[GUID_A] == "LenovoTestDriver"


def test_erased_polarity_one_is_zero_gap_not_free(tmp_path):
    """L2: with erase polarity 1 a zero-filled gap is data, not free space, so the walk
    must resync past it and still find the file behind it."""
    p = UEFIPatcher(str(tmp_path / "none.txt"))
    file1 = _pad_ffs(_ffs_header(GUID_A, 0x07, 0x00, _section(0x19, b"one"), state=0xF8))
    file2 = _ffs_header(GUID_B, 0x07, 0x00, _section(0x19, b"two"), state=0xF8)
    body = file1 + b"\x00" * 0x40 + file2
    image = _fv(body, attrs=POLARITY_ONE)
    assert _file_guids(p, image, POLARITY_ONE) == [GUID_A, GUID_B]


def test_large_file_with_zero_size_field_is_parsed(tmp_path):
    """M1: PI says a large file has Size 0 and ExtendedSize (UINT64 at 0x18)."""
    p = UEFIPatcher(str(tmp_path / "none.txt"))
    large = _large_ffs(GUID_A, 0x07, b"LARGE-BODY" * 40)
    follow = _ffs_header(GUID_B, 0x07, 0x00, _section(0x19, b"after"))
    image = _fv(_pad_ffs(large) + follow)

    files = {f.guid: f for f in p.parse_fv_files(image, 0, len(image), 0x48, POLARITY_ZERO, None)}
    assert GUID_A in files and GUID_B in files
    assert files[GUID_A].size == len(large)
    assert files[GUID_A].hdr_size == 0x20


def test_fv_with_bad_header_checksum_is_not_a_volume(tmp_path):
    """M4: the FV header words must sum to zero (PI); the patcher must not patch such a volume."""
    p = UEFIPatcher(str(tmp_path / "none.txt"))
    image = bytearray(_fv(_pad_ffs(_ffs_header(GUID_A, 0x07, 0x00, _section(0x19, b"x")))))
    assert [o for o, *_ in p.find_fvs(bytes(image))] == [0]
    image[0x34] ^= 0x01  # inside the header, not the checksum word
    assert p.find_fvs(bytes(image)) == []


def test_ffs_header_with_unknown_type_is_rejected(tmp_path):
    """M4: a file header with a valid checksum but a type no PI file type uses is not a file."""
    p = UEFIPatcher(str(tmp_path / "none.txt"))
    bogus = _ffs_header(GUID_A, 0x34, 0x00, _section(0x19, b"x"))
    image = _fv(_pad_ffs(bogus))
    assert GUID_A not in _file_guids(p, image)


def test_ffs_header_checksum_is_checked(tmp_path):
    """M4: a file whose header checksum is wrong is not parsed as a file."""
    p = UEFIPatcher(str(tmp_path / "none.txt"))
    bad = bytearray(_ffs_header(GUID_A, 0x07, 0x00, _section(0x19, b"x")))
    bad[0x10] ^= 0xFF
    good = _ffs_header(GUID_B, 0x07, 0x00, _section(0x19, b"y"))
    image = _fv(_pad_ffs(bytes(bad)) + _pad_ffs(good))
    guids = _file_guids(p, image)
    assert GUID_A not in guids
    assert GUID_B in guids


def test_lzma_output_is_bounded(tmp_path, monkeypatch):
    """M2: a section that inflates past the output limit is treated as opaque."""
    import lzma

    monkeypatch.setattr(uefi_module, "MAX_LZMA_OUTPUT", 1 << 20, raising=False)
    payload = lzma.compress(b"\x00" * (4 << 20), format=lzma.FORMAT_ALONE)
    guid_bytes = uefi_module.guid_to_bytes(uefi_module.LZMA_GUID)
    section = _section(0x02, guid_bytes + struct.pack("<HH", 0x18, 0x01) + payload)
    image = _fv(_pad_ffs(_ffs_header(GUID_A, 0x07, 0x00, section)))

    p = UEFIPatcher(str(tmp_path / "none.txt"))
    files = p.parse_fv_files(image, 0, len(image), 0x48, POLARITY_ZERO, None)
    node = files[0].sections[0]
    assert node.kind == "unknown"
    assert node.data is None


def test_compressed_section_children_stay_inside_their_section(tmp_path):
    """M3: children of a type-0 compression section end at the section, not the buffer."""
    p = UEFIPatcher(str(tmp_path / "none.txt"))
    inner = _section(0x19, b"INNER")
    comp = _section(0x01, struct.pack("<I", len(inner)) + b"\x00" + inner)
    sibling = _section(0x19, b"SIBLING")
    buf = comp + b"\x00" * ((-len(comp)) % 4) + sibling
    top = p.parse_sections(buf, 0, None, None)
    assert len(top) == 2
    assert len(top[0].children) == 1


def test_scan_and_apply_count_matches_the_same_way(tmp_path):
    """L7: scan and apply count non-overlapping matches alike."""
    image_path = _write(tmp_path / "raw.bin", b"\xaa" * 3 + b"\x00" * 29)
    p = _patcher(
        tmp_path,
        "#@group demo\n"
        "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF 0 P:aaaa:bbbb\n",
    )
    scanned = p.scan(image_path)["demo"]["matches"]
    applied = p.apply(image_path, str(tmp_path / "out.bin"))["matches_total"]
    assert scanned == applied == 1


def test_apply_refuses_to_overwrite_its_input(tmp_path):
    """H2: apply() must never write the patched image over the input dump."""
    raw = b"\xaa" * 3 + b"\x00" * 29
    image_path = _write(tmp_path / "raw.bin", raw)
    p = _patcher(
        tmp_path,
        "#@group demo\nFFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF 0 P:aaaa:bbbb\n",
    )
    with pytest.raises(UEFIPatchError):
        p.apply(image_path, image_path)
    assert open(image_path, "rb").read() == raw


def test_nvram_replacement_longer_than_its_volume_is_refused(patcher, tmp_path):
    """H4: a replacement one byte-run longer than FvLength would overwrite the next volume."""
    vol = open(NVRAM_VOL, "rb").read()
    image = b"\x00" * 0x100 + vol + b"\x55" * 0x100
    image_path = _write(tmp_path / "img.bin", image)
    long_vol = _write(tmp_path / "long.vol", vol + b"\x55" * 16)
    out = str(tmp_path / "out.bin")

    res = patcher.replace_nvram_volume(image_path, out, long_vol)
    assert not res["success"]
    assert not os.path.exists(out)


def test_replace_ffs_file_refuses_a_non_pe_payload_for_a_driver(
    patcher, uefi_patch_image, tmp_path
):
    """M8: a non-PE, non-TE payload cannot be a DXE driver; it is refused unless raw is allowed."""
    payload = _write(tmp_path / "junk.bin", b"NOT-A-PE-IMAGE" * 8)
    out = str(tmp_path / "out.bin")

    res = patcher.replace_ffs_file(uefi_patch_image, out, UEFI_PATCH_TARGET_GUID, payload)
    assert not res["success"]
    assert "RAW" in res["message"]
    assert not os.path.exists(out)

    res = patcher.replace_ffs_file(
        uefi_patch_image, out, UEFI_PATCH_TARGET_GUID, payload, allow_raw=True
    )
    assert res["success"], res["message"]


def test_replace_ffs_file_refuses_to_overwrite_its_driver(patcher, uefi_patch_image, tmp_path):
    """H2: the driver file is a donor; the output must not replace it."""
    driver = _write(tmp_path / "driver.bin", b"MZ" + b"\x90" * 0x80)
    before = open(driver, "rb").read()
    res = patcher.replace_ffs_file(uefi_patch_image, driver, UEFI_PATCH_TARGET_GUID, driver)
    assert not res["success"]
    assert open(driver, "rb").read() == before


def test_autopatch_fails_when_a_required_step_fails(
    patcher, autopatch_image, tmp_path, monkeypatch
):
    """L6: one failed step (its binary is missing) fails the run, even if another step worked."""
    entries = [
        {
            "key": "good",
            "file": f"{AUTOpatch_BOOTOPTION_GUID}.ffs",
            "target_guid": AUTOpatch_BOOTOPTION_GUID,
        },
        {
            "key": "missing",
            "file": "does-not-exist.ffs",
            "target_guid": AUTOpatch_TRANSLATE_GUID,
        },
    ]
    monkeypatch.setattr(patcher, "load_dxe_replacements", lambda *a, **k: entries)
    out = str(tmp_path / "PATCHED.bin")
    report = patcher.run_autopatch(autopatch_image, out, include_nvram=False)
    assert any(s["ok"] for s in report["steps"])
    assert not report["success"]


def test_autopatch_refuses_same_input_and_output(patcher, autopatch_image):
    """H2: run_autopatch must not copy the input over itself."""
    before = open(autopatch_image, "rb").read()
    report = patcher.run_autopatch(autopatch_image, autopatch_image)
    assert not report["success"]
    assert open(autopatch_image, "rb").read() == before
