"""Regression tests for the repair engine findings in the repair audit (H1, H2, M1, M6, M7,
M9, M10, L9)."""

import os
import struct
import uuid

from bios_recovery.core.bios_repair import BiosRepairEngine, RepairReport
from bios_recovery.engines.bios_capsule import APTIO_CAPSULE_GUID_LE

FV_LEN = 0x20000
NV_BASE = 0x1000000
FFS2 = "8C8CE578-8A3D-4F1C-9935-896185C32DD3"
NVRAM_FS = "8D2BF1FF-75B9-4C89-A7D0-2F9C8BE7E4C8"


def _fv(body: bytes, fs_guid: str = FFS2, length: int = FV_LEN, hdr_len: int = 0x48) -> bytes:
    fv = bytearray(b"\xff" * length)
    fv[0x10:0x20] = uuid.UUID(fs_guid).bytes_le
    struct.pack_into("<Q", fv, 0x20, length)
    fv[0x28:0x2C] = b"_FVH"
    struct.pack_into("<I", fv, 0x2C, 0x0004EFFF & ~0x800)
    struct.pack_into("<H", fv, 0x30, hdr_len)
    struct.pack_into("<H", fv, 0x32, 0)
    words = sum(struct.unpack_from(f"<{hdr_len // 2}H", fv, 0))
    struct.pack_into("<H", fv, 0x32, (-words) & 0xFFFF)
    fv[hdr_len : hdr_len + len(body)] = body
    return bytes(fv)


def _ffs(guid: str, body: bytes, large: bool = False) -> bytes:
    """FFS file with a valid header checksum; large=True uses the 0x20-byte large header."""
    hdr_size = 0x20 if large else 0x18
    size = hdr_size + len(body)
    hdr = bytearray(hdr_size)
    hdr[0:16] = uuid.UUID(guid).bytes_le
    hdr[0x12] = 0x01
    if large:
        hdr[0x13] = 0x01
        struct.pack_into("<Q", hdr, 0x18, size)
    else:
        hdr[0x14] = size & 0xFF
        hdr[0x15] = (size >> 8) & 0xFF
        hdr[0x16] = (size >> 16) & 0xFF
    hdr[0x17] = 0xF8
    probe = bytearray(hdr)
    probe[0x10] = probe[0x11] = probe[0x17] = 0
    hdr[0x10] = (-sum(probe)) & 0xFF
    hdr[0x11] = 0xAA
    return bytes(hdr) + body


def _write(path, data: bytes) -> str:
    path.write_bytes(data)
    return str(path)


def _image(fv: bytes, base: int = NV_BASE, size: int = NV_BASE + FV_LEN) -> bytes:
    img = bytearray(b"\xff" * size)
    img[base : base + len(fv)] = fv
    return bytes(img)


def test_damaged_reason_ignores_nvram_store_volumes():
    """H1: an NVRAM (non-FFS) volume is a variable store, not a file list; it is not damaged."""
    nvram = _fv(b"\x00" * 0x18 + b"VARIABLE-STORE", fs_guid=NVRAM_FS)
    assert BiosRepairEngine._damaged_reason(nvram) == ""


def test_damaged_reason_accepts_large_ffs_files():
    """M1: a large file (Size 0, ExtendedSize at 0x18, 0x20-byte header) is not damage."""
    body = _ffs("11111111-2222-3333-4444-555555555555", b"B" * 0x100, large=True)
    body += _ffs("66666666-7777-8888-9999-AAAAAAAABBBB", b"C" * 0x20)
    assert BiosRepairEngine._damaged_reason(_fv(body)) == ""


def test_damaged_reason_uses_header_length_field():
    """M9: the first FFS file starts at HeaderLength, not at a fixed 0x48."""
    body = _ffs("11111111-2222-3333-4444-555555555555", b"D" * 0x20)
    assert BiosRepairEngine._damaged_reason(_fv(body, hdr_len=0x60)) == ""


def test_graft_never_replaces_an_nvram_volume_from_a_donor(tmp_path):
    """H1: the target NVRAM volume is not FFS; even with a damaged-looking body it is kept."""
    damaged_body = b"\x00" * 0x18 + b"VARIABLE-STORE-WITH-MACHINE-DATA"
    target = _image(_fv(damaged_body, fs_guid=NVRAM_FS))
    donor = _image(_fv(_ffs("11111111-2222-3333-4444-555555555555", b"DONOR")))
    target_path = _write(tmp_path / "target.bin", target)
    donor_path = _write(tmp_path / "donor.bin", donor)

    rep = BiosRepairEngine().auto_graft_from_donor(target_path, donor_path)
    assert not rep.success
    assert not rep.output_path
    assert open(target_path, "rb").read() == target
    assert not any("Grafted" in op for op in rep.operations)


def test_graft_inside_an_unreadable_me_region_is_refused(tmp_path, monkeypatch):
    """L8: when the ME layout cannot be read, volumes inside the descriptor's ME region are
    not grafted."""
    from tests.fixture_builder import build_intel_ifd_image

    base = 0x100000
    damaged = bytearray(_fv(_ffs("11111111-2222-3333-4444-555555555555", b"TARGET")))
    damaged[0x48 + 0x10] ^= 0xFF
    target = bytearray(build_intel_ifd_image())
    target[base : base + FV_LEN] = damaged
    donor = bytearray(build_intel_ifd_image())
    donor[base : base + FV_LEN] = _fv(_ffs("11111111-2222-3333-4444-555555555555", b"DONOR"))
    target_path = _write(tmp_path / "target.bin", bytes(target))
    donor_path = _write(tmp_path / "donor.bin", bytes(donor))

    engine = BiosRepairEngine()
    monkeypatch.setattr(engine.me_cleaner, "get_me_info", lambda path: {"found": False})
    rep = engine.auto_graft_from_donor(target_path, donor_path)
    assert not rep.success
    assert any("ME region" in w for w in rep.warnings)
    assert not any("Grafted" in op for op in rep.operations)


def test_graft_refuses_output_equal_to_donor(tmp_path):
    """H2: the donor file is never overwritten by the graft output."""
    target = _image(_fv(_ffs("11111111-2222-3333-4444-555555555555", b"TARGET")))
    donor = _image(_fv(_ffs("11111111-2222-3333-4444-555555555555", b"DONOR")))
    target_path = _write(tmp_path / "target.bin", target)
    donor_path = _write(tmp_path / "donor.bin", donor)

    rep = BiosRepairEngine().auto_graft_from_donor(target_path, donor_path, donor_path)
    assert not rep.success
    assert open(donor_path, "rb").read() == donor


def test_graft_size_mismatch_does_not_write_over_donor(tmp_path):
    """H2: a size mismatch must not write the target over the donor file."""
    donor = b"\xff" * 0x100000
    donor_path = _write(tmp_path / "donor.bin", donor)
    target_path = _write(tmp_path / "target.bin", b"\xff" * 0x200000)

    rep = BiosRepairEngine().auto_graft_from_donor(target_path, donor_path, donor_path)
    assert not rep.success
    assert open(donor_path, "rb").read() == donor


def test_graft_from_capsule_leaves_no_directory_beside_the_donor(tmp_path):
    """M7: the capsule extraction is a temporary step; the donor's folder stays unchanged."""
    donor_image = _image(_fv(_ffs("11111111-2222-3333-4444-555555555555", b"CAP-DATA")))
    hdr = bytearray(b"\x00" * 0x800)
    hdr[0:16] = APTIO_CAPSULE_GUID_LE
    struct.pack_into("<I", hdr, 0x10, 0x800)
    struct.pack_into("<I", hdr, 0x18, 0x800 + len(donor_image))
    struct.pack_into("<H", hdr, 0x1C, 0x800)
    donor_dir = tmp_path / "donor_side"
    donor_dir.mkdir()
    donor_path = donor_dir / "donor.308"
    donor_path.write_bytes(bytes(hdr) + donor_image)
    target_path = _write(tmp_path / "target.bin", b"\xff" * (NV_BASE + FV_LEN))

    rep = BiosRepairEngine().auto_graft_from_donor(target_path, str(donor_path))
    assert sorted(os.listdir(donor_dir)) == ["donor.308"]
    assert rep.output_path


def test_fix_size_refuses_to_drop_non_erased_data(tmp_path):
    """M6: truncation that discards real data is refused unless explicitly allowed."""
    src = _write(tmp_path / "src.bin", b"\x11" * 16 + b"\x22" * 16)
    out = str(tmp_path / "out.bin")
    engine = BiosRepairEngine()

    rep = engine.fix_size(src, 16, out)
    assert not rep.success
    assert not os.path.exists(out)

    rep = engine.fix_size(src, 16, out, allow_truncate=True)
    assert rep.success
    assert open(out, "rb").read() == b"\x11" * 16
    assert any("non-erased" in w for w in rep.warnings)


def test_fix_size_drops_an_erased_tail_silently(tmp_path):
    """M6: an erased tail carries no data, so truncating it is allowed."""
    src = _write(tmp_path / "src.bin", b"\x11" * 16 + b"\xff" * 16)
    out = str(tmp_path / "out.bin")
    rep = BiosRepairEngine().fix_size(src, 16, out)
    assert rep.success
    assert open(out, "rb").read() == b"\x11" * 16


def test_replace_region_refuses_an_empty_replacement(tmp_path):
    """L9: a zero-byte replacement would erase the region; that needs an explicit flag."""
    src = _write(tmp_path / "src.bin", b"\x11" * 64)
    empty = _write(tmp_path / "empty.bin", b"")
    out = str(tmp_path / "out.bin")
    engine = BiosRepairEngine()

    rep = engine.replace_region(src, out, 0, 32, empty)
    assert not rep.success
    assert not os.path.exists(out)

    rep = engine.replace_region(src, out, 0, 32, empty, allow_erase=True)
    assert rep.success
    assert open(out, "rb").read()[:32] == b"\xff" * 32


def test_fpt_outside_the_me_region_is_not_modified(tmp_path):
    """M10: a $FPT lookalike with no declared ME region is not a partition table to fix."""
    data = bytearray(b"\xff" * 0x1000)
    data[0x100:0x104] = b"$FPT"
    data[0x104:0x108] = struct.pack("<I", 1)
    before = bytes(data)
    report = RepairReport(success=True)

    BiosRepairEngine()._fix_fpt_checksum(data, report)
    assert bytes(data) == before
    assert any("not modified" in w for w in report.warnings)
