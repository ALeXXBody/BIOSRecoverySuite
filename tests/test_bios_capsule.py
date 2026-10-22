"""Tests for AMI Aptio capsule extraction and NVRAM restore."""

import struct

from bios_recovery.manufacturers.common.bios_capsule import (
    APTIO_CAPSULE_GUID_LE,
    detect_capsule,
    extract_flashable_image,
    restore_nvar_from_dump,
)

NV_BASE = 0x1000000
MFG_BASE = 0x1020000
FV_LEN = 0x20000


def _nvar_record(nm, payload):
    """Minimal NVAR record: 'NVAR' | u16 size | state | attr | nameLen | name | payload."""
    body = bytes([0xFF, 0x83, len(nm)]) + nm + payload
    total = 4 + 2 + len(body)
    return b"NVAR" + struct.pack("<H", total) + body


def _mk_fv(body):
    """0x20000 FV with a valid _FVH header; `body` placed after the header."""
    fv = bytearray(b"\xff" * FV_LEN)
    struct.pack_into("<Q", fv, 0x20, FV_LEN)
    fv[0x28:0x2C] = b"_FVH"
    struct.pack_into("<H", fv, 0x30, 0x48)
    struct.pack_into("<H", fv, 0x32, 0)
    struct.pack_into("<H", fv, 0x32, (-sum(struct.unpack_from("<36H", fv, 0))) & 0xFFFF)
    blob = bytes(body)
    fv[0x48:0x48 + len(blob)] = blob[:FV_LEN - 0x48]
    return bytes(fv)


def _mk_capsule(image, hdr_hash=b"\x00" * 32):
    hdr = bytearray(b"\x00" * 0x800)
    hdr[0:16] = APTIO_CAPSULE_GUID_LE
    struct.pack_into("<I", hdr, 0x10, 0x800)
    struct.pack_into("<I", hdr, 0x18, 0x800 + len(image))
    struct.pack_into("<32s", hdr, 0x28, hdr_hash)
    return bytes(hdr) + image


def _write(path, blob):
    path.write_bytes(blob)
    return str(path)


def test_detect_and_extract(tmp_path):
    image = b"\xab" * 0x4000 + b"\xff" * 0x1000
    cap_path = tmp_path / "test.308"
    cap_path.write_bytes(_mk_capsule(image))

    info = detect_capsule(_mk_capsule(image))
    assert info.success
    assert info.header_size == 0x800
    assert info.image_size == len(image)

    out = extract_flashable_image(str(cap_path))
    assert out.success
    assert open(out.output_path, "rb").read() == image


def test_detect_rejects_non_capsule(tmp_path):
    cap = bytearray(_mk_capsule(b"\xff" * 0x4000))
    cap[0x04] = 0xFF  # corrupt the GUID
    assert not detect_capsule(bytes(cap)).success


def test_restore_nvar_restores_dump_region(tmp_path):
    """Merge semantics: NV/machine FVs come from the dump; capsule code stays."""
    factory_rec = _nvar_record(b"Setup", b"\x01" * 8)
    cap_image = bytearray(b"\xff" * 0x2000000)
    cap_image[NV_BASE:NV_BASE + FV_LEN] = _mk_fv(factory_rec)
    cap_path = tmp_path / "test.308"
    cap_path.write_bytes(_mk_capsule(bytes(cap_image)))
    out = extract_flashable_image(str(cap_path))
    assert out.success

    machine_rec = _nvar_record(b"Setup", b"\x42" * 8) + b"SERIAL-BLOB" + b"\xff" * 0x100
    mfg_blob = b"MFG0\x00T6N0CV09125124A" + b"\xff" * 0x40
    dump = bytearray(b"\xff" * 0x2000000)
    dump[NV_BASE:NV_BASE + FV_LEN] = _mk_fv(machine_rec)
    dump[MFG_BASE:MFG_BASE + FV_LEN] = _mk_fv(mfg_blob)

    res = restore_nvar_from_dump(
        out.output_path, _write(tmp_path / "dump.bin", bytes(dump)),
        str(tmp_path / "merged.bin"),
    )
    assert res.success

    merged = open(res.output_path, "rb").read()
    # machine NVRAM value survives, factory value gone
    assert b"\x42" * 8 in merged
    assert b"SERIAL-BLOB" in merged
    assert b"MFG0\x00T6N0CV09125124A" in merged
    assert merged.count(b"\x01" * 8) == 0
    # capsule code area untouched (before the FVs)
    assert merged[:0x2000] == bytes(cap_image[:0x2000])
    # messages mention both restored FVs
    joined = " ".join(res.messages)
    assert "0x1000000" in joined
    assert "0x1020000" in joined
