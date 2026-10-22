"""Tests for donor-graft auto repair."""

import struct

from bios_recovery.core.bios_repair import BiosRepairEngine
from bios_recovery.engines.bios_capsule import APTIO_CAPSULE_GUID_LE

NV_BASE = 0x1000000
FV_LEN = 0x20000


def _mk_fv(body: bytes) -> bytes:
    """A firmware volume with a valid EFI_FIRMWARE_VOLUME_HEADER.

    The header words sum to zero, as the UEFI spec requires.
    """
    fv = bytearray(b"\xff" * FV_LEN)
    struct.pack_into("<Q", fv, 0x20, FV_LEN)
    fv[0x28:0x2C] = b"_FVH"
    struct.pack_into("<H", fv, 0x30, 0x48)  # HeaderLength
    struct.pack_into("<H", fv, 0x32, 0)  # Checksum placeholder
    words_sum = sum(struct.unpack_from("<36H", fv, 0))  # the 0x48-byte header
    struct.pack_into("<H", fv, 0x32, (-words_sum) & 0xFFFF)
    fv[0x48 : 0x48 + len(body)] = body[: FV_LEN - 0x48]
    return bytes(fv)


def _valid_ffs(blob_len: int, marker: bytes) -> bytes:
    """A minimal FFS file with a self-consistent header checksum."""
    hdr = bytearray(b"\x00" * 0x18)
    hdrlen = 0x18
    isize = hdrlen + blob_len
    hdr[0x10] = 0  # .Header (filled below)
    hdr[0x11] = 0  # .File
    hdr[0x12] = 0x01  # type RAW
    hdr[0x13] = 0x00
    hdr[0x14] = isize & 0xFF
    hdr[0x15] = (isize >> 8) & 0xFF
    hdr[0x16] = (isize >> 16) & 0xFF
    # Header checksum per UEFI spec: State and both checksum bytes are excluded
    hdr_tmp = bytearray(hdr)
    hdr_tmp[0x10] = 0
    hdr_tmp[0x11] = 0
    hdr_tmp[0x17] = 0
    hdr[0x10] = (-sum(hdr_tmp)) & 0xFF
    hdr[0x17] = 0xF0  # state valid
    return bytes(hdr) + marker.ljust(blob_len, b"\x00")[:blob_len]


def test_graft_replaces_damaged_fv(tmp_path):
    # donor: healthy NV FV with valid FFS content
    donor = bytearray(b"\xff" * (NV_BASE + FV_LEN))
    donor[NV_BASE : NV_BASE + FV_LEN] = _mk_fv(_valid_ffs(0x40, b"DONOR-DATA"))
    donor_path = str(tmp_path / "donor.bin")
    open(donor_path, "wb").write(bytes(donor))

    # target: same bounds, but the FV is fully erased + a FF-hole style region
    target = bytearray(b"\xff" * (NV_BASE + FV_LEN))
    target[NV_BASE : NV_BASE + FV_LEN] = b"\xff" * FV_LEN  # erased
    target_path = str(tmp_path / "damaged.bin")
    open(target_path, "wb").write(bytes(target))

    eng = BiosRepairEngine()
    rep = eng.auto_graft_from_donor(target_path, donor_path)
    assert rep.success
    assert rep.output_path
    merged = open(rep.output_path, "rb").read()
    assert b"DONOR-DATA" in merged
    ops = " ".join(rep.operations)
    assert "Grafted" in ops or "Restored erased" in ops


def test_graft_accepts_capsule_donor(tmp_path):
    donor_image = bytearray(b"\xff" * (NV_BASE + FV_LEN))
    donor_image[NV_BASE : NV_BASE + FV_LEN] = _mk_fv(_valid_ffs(0x40, b"CAP-DATA"))
    hdr = bytearray(b"\x00" * 0x800)
    hdr[0:16] = APTIO_CAPSULE_GUID_LE
    struct.pack_into("<I", hdr, 0x10, 0x800)
    struct.pack_into("<I", hdr, 0x18, 0x800 + len(donor_image))
    cap = tmp_path / "donor.308"
    cap.write_bytes(bytes(hdr) + bytes(donor_image))

    target = bytearray(b"\xff" * (NV_BASE + FV_LEN))
    target[NV_BASE : NV_BASE + FV_LEN] = b"\xff" * FV_LEN
    target_path = str(tmp_path / "damaged.bin")
    open(target_path, "wb").write(bytes(target))

    eng = BiosRepairEngine()
    rep = eng.auto_graft_from_donor(target_path, str(cap))
    assert rep.success
    merged = open(rep.output_path, "rb").read()
    assert b"CAP-DATA" in merged


def test_graft_refuses_size_mismatch(tmp_path):
    donor = b"\xff" * 0x100000
    donor_path = str(tmp_path / "donor.bin")
    open(donor_path, "wb").write(donor)

    target_path = str(tmp_path / "damaged.bin")
    open(target_path, "wb").write(b"\xff" * 0x200000)

    eng = BiosRepairEngine()
    rep = eng.auto_graft_from_donor(target_path, donor_path)
    assert not rep.operations or not any("Grafted" in op for op in rep.operations)
    assert any("size mismatch" in w or "refused" in w for w in rep.warnings)


def test_graft_leaves_different_content_alone(tmp_path):
    """Same bounds, both sides internally valid, merely different content:
    must NOT be grafted (different versioned content is not corruption)."""
    donor = bytearray(b"\xff" * (NV_BASE + FV_LEN))
    donor[NV_BASE : NV_BASE + FV_LEN] = _mk_fv(_valid_ffs(0x40, b"NEW-VERSION"))
    donor_path = str(tmp_path / "donor.bin")
    open(donor_path, "wb").write(bytes(donor))

    target = bytearray(b"\xff" * (NV_BASE + FV_LEN))
    target[NV_BASE : NV_BASE + FV_LEN] = _mk_fv(_valid_ffs(0x40, b"OLD-VERSION"))
    target_path = str(tmp_path / "old.bin")
    open(target_path, "wb").write(bytes(target))

    eng = BiosRepairEngine()
    rep = eng.auto_graft_from_donor(target_path, donor_path)
    merged = open(rep.output_path, "rb").read()
    assert b"OLD-VERSION" in merged  # left untouched
    assert not any("Grafted" in op for op in rep.operations)
    assert any("left untouched" in w for w in rep.warnings)
