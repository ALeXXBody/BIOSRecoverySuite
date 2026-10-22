"""Identity audit fixes for DMI clone: bounded writes, validated tables, refused junk."""

import os
import struct

from bios_recovery.core.dmi_clone import DMIClone
from bios_recovery.engines.dmi_extractor import DMIExtractor
from tests.fixture_builder import build_intel_ifd_image, make_smbios_eps, make_smbios_structures


def _small_table() -> bytes:
    """A valid but much shorter table: Type 0, Type 1, end-of-table."""
    t0 = bytearray(0x12)
    t0[0:2] = bytes([0, 0x12])
    t0[4:9] = bytes([1, 2, 0, 0, 0])
    s0 = b"Vendor Co\x00Version 1\x00\x00"
    t1 = bytearray(0x19)
    t1[0:2] = bytes([1, 0x19])
    t1[4:8] = bytes([1, 2, 0, 3])
    s1 = b"Maker\x00Model\x00SN0001\x00\x00"
    eot = bytes([127, 4, 0, 0]) + b"\x00\x00"
    return bytes(t0) + s0 + bytes(t1) + s1 + eot


def _image_with_table(table: bytes, size: int = 0x10000) -> bytes:
    image = bytearray(b"\xff" * size)
    eps_at = 0x40
    table_at = 0x1000
    image[eps_at : eps_at + 0x1F] = make_smbios_eps(table_at, len(table), 2)
    image[table_at : table_at + len(table)] = table
    return bytes(image)


def _write(tmp_path, name, blob):
    p = tmp_path / name
    p.write_bytes(blob)
    return str(p)


def test_shorter_new_table_is_not_overrun(tmp_path):
    small = _small_table()
    big = make_smbios_structures()[0]
    assert len(big) > len(small)
    old = _write(tmp_path, "old.bin", _image_with_table(big))
    new_blob = bytearray(_image_with_table(small))
    tail = 0x1000 + len(small)
    new_blob[tail : tail + 0x200] = b"\xaa" * 0x200  # sentinel after the new table
    new = _write(tmp_path, "new.bin", bytes(new_blob))
    out = str(tmp_path / "out.bin")

    report = DMIClone().clone(old, new, out)

    assert not report["success"]
    assert "does not fit" in report["message"]
    assert not os.path.exists(out)


def test_junk_smbios_anchor_in_old_image_is_not_a_table(tmp_path):
    junk = bytearray(b"\xff" * 0x20000)
    junk[0x100:0x104] = b"_SM_"
    struct.pack_into("<H", junk, 0x100 + 0x16, 0x1000)
    struct.pack_into("<I", junk, 0x100 + 0x18, 0x2000)
    junk[0x2000:0x2010] = b"\x00\x20" + b"\x00" * 14
    old = _write(tmp_path, "old.bin", bytes(junk))
    new_blob = build_intel_ifd_image()
    new = _write(tmp_path, "new.bin", new_blob)
    out = str(tmp_path / "out.bin")

    report = DMIClone().clone(old, new, out)

    assert not report["success"]
    assert not os.path.exists(out)


def test_clone_into_same_layout_keeps_size_and_identity(tmp_path):
    old_path = _write(tmp_path, "old.bin", build_intel_ifd_image())
    new_path = _write(tmp_path, "new.bin", build_intel_ifd_image())
    out = str(tmp_path / "out.bin")

    report = DMIClone().clone(old_path, new_path, out)

    assert report["success"], report["message"]
    assert len(open(out, "rb").read()) == len(open(new_path, "rb").read())
    old_info = DMIExtractor().extract_from_bios(old_path)
    assert DMIExtractor().extract_from_bios(out).system_uuid == old_info.system_uuid


def test_clone_refuses_output_equal_to_new_image(tmp_path):
    old_path = _write(tmp_path, "old.bin", build_intel_ifd_image())
    new_blob = build_intel_ifd_image()
    new_path = _write(tmp_path, "new.bin", new_blob)

    report = DMIClone().clone(old_path, new_path, new_path)

    assert not report["success"]
    assert open(new_path, "rb").read() == new_blob


def test_nvram_identity_clone_reports_the_bytes_it_changed(tmp_path):
    def nvar(data: bytes) -> bytes:
        body = b"MFG0\x00" + data
        total = 0x0B + len(body)
        head = b"NVAR" + struct.pack("<H", total) + b"\xff\xff\xff\x83\xff"
        return head + body

    old = nvar(b"X510UA SERIAL-0001")
    new_blob = b"\xff" * 0x40 + nvar(b"X510UA SERIAL-9999") + b"\xff" * 0x40
    new_path = _write(tmp_path, "new.bin", new_blob)
    old_path = _write(tmp_path, "old.bin", b"\xff" * 0x40 + old + b"\xff" * 0x40)
    out = str(tmp_path / "out.bin")

    report = DMIClone().clone(old_path, new_path, out)

    assert report["success"], report["message"]
    changed = sum(1 for a, b in zip(new_blob, open(out, "rb").read()) if a != b)
    assert report["bytes"] == changed > 0
