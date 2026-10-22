"""Tests for the DMI editor (fixed-size identity edits) and the CLI mode."""

import struct

from bios_recovery.core.dmi_editor import DMIEditor

UUID = "2c4a6b8d0011223344556677889aaabb"
SERIAL = "AS3FYGD3jB"
BASEBOARD = "MT1234ABC"


def _smbios_fixture():
    """Deterministic fixture: EPS @0x0000, structure table @0x0100, FF fill elsewhere."""
    t1 = (
        bytes([1, 0x1B])
        + struct.pack("<H", 0x0300)  # type/length/handle
        + bytes([1, 2, 3, 4])  # manufacturer/product/version/serial refs
        + bytes.fromhex(UUID)  # UUID at +0x08
        + bytes([0, 5, 6])
    )  # wakeup, SKU ref, family ref
    pool1 = b"ASUS\0Vivobook\0V1\0" + SERIAL.encode() + b"\0\0"
    t2 = bytes([2, 0x08, 0x0301 % 256, 0x03]) + bytes([1, 2, 3, 3])
    pool2 = b"ASUS\0Go15\0" + BASEBOARD.encode() + b"\0\0"
    assert len(t1) == 0x1B and len(t2) == 0x08
    table = t1 + pool1 + t2 + pool2

    eps = bytearray(0x1F)
    eps[0:4] = b"_SM_"
    struct.pack_into("<H", eps, 0x16, len(table))
    struct.pack_into("<I", eps, 0x18, 0x0100)
    # (fixture does not require a valid EPS checksum)

    blob = bytearray(b"\xff" * 0x2000)
    blob[0 : len(eps)] = eps
    blob[0x0100 : 0x0100 + len(table)] = table
    return bytes(blob), len(table)


def test_dmi_info_reports_identity(tmp_path):
    blob, _ = _smbios_fixture()
    p = tmp_path / "dump.bin"
    p.write_bytes(blob)
    info = DMIEditor().info(str(p))
    assert info["found"]
    assert info["serials"]["system"] == SERIAL
    assert info["serials"]["baseboard"] == BASEBOARD
    assert info["uuid"] == UUID
    assert info["mac"] is None  # no Intel descriptor in this layout


def test_equal_length_serial_swap(tmp_path):
    blob, tlen = _smbios_fixture()
    p = tmp_path / "dump.bin"
    p.write_bytes(blob)

    new_serial = "AS3ZZZD9kB"  # same length as SERIAL
    assert len(new_serial) == len(SERIAL)
    rep = DMIEditor().set_identity(str(p), serial=new_serial)

    assert rep.success, rep.message
    out = open(rep.output_path, "rb").read()
    assert new_serial.encode() in out
    assert SERIAL.encode() not in out
    # nothing moved: same total size, EPS + baseboard intact
    assert len(out) == len(blob)
    assert out[:0x1F] == blob[:0x1F]
    info = DMIEditor().info(rep.output_path)
    assert info["serials"]["system"] == new_serial
    assert info["serials"]["baseboard"] == BASEBOARD


def test_unequal_length_serial_refused(tmp_path):
    blob, _ = _smbios_fixture()
    p = tmp_path / "dump.bin"
    p.write_bytes(blob)
    rep = DMIEditor().set_identity(str(p), serial="SHORT")

    assert any("refused" in w for w in rep.warnings)
    out = open(rep.output_path, "rb").read() if rep.success else blob
    assert SERIAL.encode() in out  # untouched


def test_uuid_fixed_write(tmp_path):
    blob, _ = _smbios_fixture()
    p = tmp_path / "dump.bin"
    p.write_bytes(blob)
    new_uuid = "00000000-1111-2222-3333-444455556666"
    rep = DMIEditor().set_identity(str(p), uuid=new_uuid)

    assert rep.success, rep.message
    info = DMIEditor().info(rep.output_path)
    assert info["uuid"] == "00000000111122223333444455556666"


def test_mac_refused_without_descriptor(tmp_path):
    blob, _ = _smbios_fixture()
    p = tmp_path / "dump.bin"
    p.write_bytes(blob)
    rep = DMIEditor().set_identity(str(p), mac="AA:BB:CC:DD:EE:FF")

    assert any("refused" in w for w in rep.warnings)
