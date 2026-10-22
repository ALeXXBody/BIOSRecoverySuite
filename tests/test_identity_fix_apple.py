"""Identity audit fixes for Apple Fsys handling: donor validation and refusals."""

import binascii
import os
import struct
import tempfile

from bios_recovery.manufacturers.apple.apple_efi import (
    fix_fsys_checksum,
    parse_fsys_store,
    replace_fsys_store,
    set_serial_number,
)
from tests.test_apple_ec import SERIAL, _mk_fsys


def _image(store: bytes) -> bytes:
    blob = bytearray(b"\xff" * 0x100000)
    blob[0x20000 : 0x20000 + len(store)] = store
    return bytes(blob)


def _write(blob: bytes, name="dump.bin") -> str:
    p = os.path.join(tempfile.mkdtemp(), name)
    with open(p, "wb") as f:
        f.write(blob)
    return p


def test_all_zero_donor_store_is_refused():
    target = _write(_image(_mk_fsys(SERIAL.encode())))
    donor = _write(b"\x00" * 0x800, "donor.bin")
    before = open(target, "rb").read()
    out = os.path.join(os.path.dirname(target), "out.bin")

    rep = replace_fsys_store(target, donor, out)

    assert not rep.success
    assert not os.path.exists(out)
    assert open(target, "rb").read() == before


def test_donor_with_bad_crc_is_refused():
    good = bytearray(_mk_fsys(b"C02Y9876PQRS"))
    good[0x100] ^= 0xFF  # body changed, CRC no longer matches
    target = _write(_image(_mk_fsys(SERIAL.encode())))
    donor = _write(bytes(good), "donor.bin")
    out = os.path.join(os.path.dirname(target), "out.bin")

    rep = replace_fsys_store(target, donor, out)

    assert not rep.success
    assert not os.path.exists(out)


def test_valid_donor_is_transplanted():
    target = _write(_image(_mk_fsys(SERIAL.encode())))
    donor = _write(_mk_fsys(b"C02Y9876PQRS"), "donor.bin")
    out = os.path.join(os.path.dirname(target), "out.bin")

    rep = replace_fsys_store(target, donor, out)

    assert rep.success, rep.message
    assert parse_fsys_store(open(out, "rb").read()).serial == "C02Y9876PQRS"


def _mk_fsys_u16(serial: bytes) -> bytes:
    """Same store as _mk_fsys, but the ssn entry uses the UINT16 DataLength layout."""
    blob = bytearray(_mk_fsys(serial))
    blob[0x10 : 0x10 + 5 + 2 + len(serial)] = b"\x03ssn" + struct.pack("<H", len(serial)) + serial
    blob[0x800 - 4 :] = b"\x00" * 4
    crc = binascii.crc32(bytes(blob[: 0x800 - 4])) & 0xFFFFFFFF
    blob[0x800 - 4 :] = crc.to_bytes(4, "little")
    return bytes(blob)


def test_serial_write_u8_layout_reads_back():
    target = _write(_image(_mk_fsys(SERIAL.encode())))
    out = os.path.join(os.path.dirname(target), "out.bin")

    rep = set_serial_number(target, "C02X4321ZYXW", out)

    assert rep.success, rep.message
    fixed = parse_fsys_store(open(out, "rb").read())
    assert fixed.serial == "C02X4321ZYXW"
    assert fixed.serial_layout == "u8"
    assert fixed.checksum_valid is True


def test_serial_write_u16_layout_keeps_length_field():
    store = _mk_fsys_u16(SERIAL.encode())
    target = _write(_image(store))
    out = os.path.join(os.path.dirname(target), "out.bin")
    assert parse_fsys_store(open(target, "rb").read()).serial_layout == "u16"

    rep = set_serial_number(target, "C02X4321ZYXW", out)

    assert rep.success, rep.message
    before = _image(store)
    after = open(out, "rb").read()
    fixed = parse_fsys_store(after)
    assert fixed.serial == "C02X4321ZYXW"
    assert fixed.serial_layout == "u16"
    assert fixed.checksum_valid is True
    # the two length bytes are untouched, so the entry is not corrupted
    length_at = 0x20000 + 0x10 + len(b"\x03ssn")
    assert after[length_at : length_at + 2] == before[length_at : length_at + 2]


def test_serial_write_refused_when_layout_is_unreadable():
    target = _write(_image(_mk_fsys(b"\x01\x02" + SERIAL.encode()[2:])))
    before = open(target, "rb").read()
    out = os.path.join(os.path.dirname(target), "out.bin")

    rep = set_serial_number(target, "C02X4321ZYXW", out)

    assert not rep.success
    assert "unreadable" in rep.message
    assert not os.path.exists(out)
    assert open(target, "rb").read() == before


def test_output_equal_to_input_is_refused_for_checksum_fix():
    blob = bytearray(_image(_mk_fsys(SERIAL.encode())))
    blob[0x20000 + 0x800 - 4 : 0x20000 + 0x800] = b"\x00\x00\x00\x00"  # break the CRC
    target = _write(bytes(blob))

    rep = fix_fsys_checksum(target, target)

    assert not rep.success
    assert open(target, "rb").read() == bytes(blob)
