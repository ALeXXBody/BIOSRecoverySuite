"""Regression tests for the capsule findings in the repair audit (H2, H3, L5)."""

import os
import struct
import uuid

from bios_recovery.manufacturers.common.bios_capsule import (
    APTIO_CAPSULE_GUID_LE,
    detect_capsule,
    extract_flashable_image,
    restore_nvar_from_dump,
)

FFS2 = "8C8CE578-8A3D-4F1C-9935-896185C32DD3"
CAP_A = 0x1070000  # capsule's own NVRAM volume, factory content
CAP_B = 0x1090000  # capsule code volume that a larger dump volume would overlap
MACHINE = 0x1200000  # machine volume: erased in the capsule


def _fv(body: bytes, length: int) -> bytes:
    fv = bytearray(b"\xff" * length)
    fv[0x10:0x20] = uuid.UUID(FFS2).bytes_le
    struct.pack_into("<Q", fv, 0x20, length)
    fv[0x28:0x2C] = b"_FVH"
    struct.pack_into("<I", fv, 0x2C, 0x0004EFFF & ~0x800)
    struct.pack_into("<H", fv, 0x30, 0x48)
    struct.pack_into("<H", fv, 0x32, 0)
    struct.pack_into("<H", fv, 0x32, (-sum(struct.unpack_from("<36H", fv, 0))) & 0xFFFF)
    fv[0x48 : 0x48 + len(body)] = body
    return bytes(fv)


def _capsule(image: bytes, rom_offset: int = 0x800) -> bytes:
    hdr = bytearray(b"\x00" * rom_offset)
    hdr[0:16] = APTIO_CAPSULE_GUID_LE
    struct.pack_into("<I", hdr, 0x10, 0x20)
    struct.pack_into("<I", hdr, 0x18, rom_offset + len(image))
    struct.pack_into("<H", hdr, 0x1C, rom_offset)
    struct.pack_into("<H", hdr, 0x1E, 0x20)
    return bytes(hdr) + image


def test_extract_refuses_to_overwrite_the_capsule(tmp_path):
    """H2: the flashable image must not replace the capsule it came from."""
    image = b"\xab" * 0x4000 + b"\xff" * 0x1000
    cap = tmp_path / "update.308"
    cap.write_bytes(_capsule(image))
    before = cap.read_bytes()

    info = extract_flashable_image(str(cap), output_path=str(cap))
    assert not info.success
    assert cap.read_bytes() == before


def test_empty_capsule_image_is_not_success(tmp_path):
    """L5: a capsule whose image is zero bytes long has no flash image to extract."""
    info = detect_capsule(_capsule(b""))
    assert not info.success


def test_restore_does_not_overwrite_a_capsule_volume_with_other_bounds(tmp_path):
    """H3: a dump volume must not overwrite a capsule volume that sits in its range."""
    cap_image = bytearray(b"\xff" * 0x1300000)
    cap_image[CAP_A : CAP_A + 0x20000] = _fv(b"factory", 0x20000)
    cap_image[CAP_B : CAP_B + 0x20000] = _fv(b"CAPSULE-CODE", 0x20000)
    dump = bytearray(b"\xff" * 0x1300000)
    dump[CAP_A : CAP_A + 0x40000] = _fv(b"machine", 0x40000)  # overlaps CAP_B
    dump[MACHINE : MACHINE + 0x20000] = _fv(b"MFG-SERIAL", 0x20000)

    cap_path = tmp_path / "capsule.bin"
    cap_path.write_bytes(bytes(cap_image))
    dump_path = tmp_path / "dump.bin"
    dump_path.write_bytes(bytes(dump))
    out = tmp_path / "merged.bin"

    res = restore_nvar_from_dump(str(cap_path), str(dump_path), str(out))
    assert res.success
    merged = out.read_bytes()
    assert merged[CAP_B : CAP_B + 0x20000] == bytes(cap_image[CAP_B : CAP_B + 0x20000])
    assert b"MFG-SERIAL" in merged
    joined = " ".join(res.messages)
    assert f"Skipped FV @0x{CAP_A:x}" in joined
    assert "capsule omitted it" not in joined


def test_restore_writes_nothing_when_nothing_changes(tmp_path):
    """Output only when bytes change: a dump that matches the capsule restores nothing."""
    cap_image = bytearray(b"\xff" * 0x1300000)
    cap_image[CAP_A : CAP_A + 0x20000] = _fv(b"factory", 0x20000)
    cap_path = tmp_path / "capsule.bin"
    cap_path.write_bytes(bytes(cap_image))
    dump_path = tmp_path / "dump.bin"
    dump_path.write_bytes(bytes(cap_image))
    out = tmp_path / "merged.bin"

    res = restore_nvar_from_dump(str(cap_path), str(dump_path), str(out))
    assert not res.success
    assert not os.path.exists(out)
