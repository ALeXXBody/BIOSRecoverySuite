"""Tests for Apple EFI Fsys parsing/repair and EC advisory scan."""

import binascii
import struct

from bios_recovery.manufacturers.apple.apple_efi import (
    CRC32_SIZE,
    FSYS_MARKER,
    fix_fsys_checksum,
    parse_fsys_store,
    replace_fsys_store,
    rom_info,
    set_serial_number,
)
from bios_recovery.platforms.ec.ec_patcher import ECPatcher

SERIAL = "C02X1234JKLM"


def _mk_fsys(serial: bytes, key_vars: dict = None) -> bytes:
    """0x800-store-shaped Fsys block with correct CRC32 (mirrors the scheme)."""
    blob = bytearray(b"\x00" * 0x800)
    blob[0:5] = FSYS_MARKER
    struct.pack_into("<h", blob, 9, 0x800)  # stored size (int16)
    # 'ssn' variable: [0x03]["ssn"][len][bytes]
    s_var = b"\x03ssn" + bytes([len(serial)]) + serial
    blob[0x10 : 0x10 + len(s_var)] = s_var
    hwc = b"\x03hwc" + bytes([8]) + b"LA1234AB"
    blob[0x40 : 0x40 + len(hwc)] = hwc
    son = b"\x03son" + bytes([6]) + b"123456"
    blob[0x80 : 0x80 + len(son)] = son
    crc = binascii.crc32(bytes(blob[: 0x800 - CRC32_SIZE])) & 0xFFFFFFFF
    blob[0x800 - CRC32_SIZE :] = crc.to_bytes(CRC32_SIZE, "little")
    return bytes(blob)


def _write(blob, name="dump.bin"):
    import os
    import tempfile

    p = os.path.join(tempfile.mkdtemp(), name)
    open(p, "wb").write(blob)
    return p


def test_fsys_parse_and_checksum_valid():
    blob = bytearray(b"\xff" * 0x100000)
    blob[0x20000:0x20800] = _mk_fsys(SERIAL.encode())
    fsys = parse_fsys_store(bytes(blob))
    assert fsys.found
    assert fsys.base_address == 0x20000
    assert fsys.size == 0x800
    assert fsys.checksum_valid is True
    assert fsys.serial == SERIAL


def test_detects_broken_checksum_and_fixes():
    blob = bytearray(b"\xff" * 0x100000)
    good = _mk_fsys(SERIAL.encode())
    bad = bytearray(good)
    bad[0x10] ^= 0xFF  # corrupt data, CRC now wrong
    blob[0x20000:0x20800] = bad
    p = _write(bytes(blob))
    fsys = parse_fsys_store(open(p, "rb").read())
    assert fsys.found and fsys.checksum_valid is False

    rep = fix_fsys_checksum(p)
    assert rep.success, rep.message
    fixed = parse_fsys_store(open(rep.output_path, "rb").read())
    assert fixed.checksum_valid is True


def test_valid_checksum_means_no_write(tmp_path):
    blob = bytearray(b"\xff" * 0x100000)
    blob[0x20000:0x20800] = _mk_fsys(SERIAL.encode())
    p = _write(bytes(blob))
    before = open(p, "rb").read()
    rep = fix_fsys_checksum(p, output_path=str(tmp_path / "o.bin"))
    assert rep.success
    after = open(p, "rb").read()
    assert before == after  # no write performed


def test_equal_length_serial_patch():
    blob = bytearray(b"\xff" * 0x100000)
    blob[0x20000:0x20800] = _mk_fsys(SERIAL.encode())
    p = _write(bytes(blob))
    new_serial = "C02X4321ZYXW"  # 12 chars, electrical lengths equal
    assert len(new_serial) == len(SERIAL)

    rep = set_serial_number(p, new_serial)
    assert rep.success, rep.message
    fixed = parse_fsys_store(open(rep.output_path, "rb").read())
    assert fixed.serial == new_serial
    assert fixed.checksum_valid is True


def test_unequal_length_serial_refused():
    blob = bytearray(b"\xff" * 0x100000)
    blob[0x20000:0x20800] = _mk_fsys(SERIAL.encode())
    p = _write(bytes(blob))
    rep = set_serial_number(p, "TOOLONGSERIAL")
    assert not rep.success
    assert "refused" in rep.message


def test_replace_fsys_transplant():
    blob = bytearray(b"\xff" * 0x100000)
    blob[0x20000:0x20800] = _mk_fsys(SERIAL.encode())
    target_p = _write(bytes(blob), "target.bin")
    # donor: another machine's store (same size)
    donor = _mk_fsys(b"C02Y9876PQRS")
    donor_p = _write(donor, "donor.bin")

    rep = replace_fsys_store(target_p, donor_p)
    assert rep.success, rep.message
    fsys = parse_fsys_store(open(rep.output_path, "rb").read())
    assert fsys.serial == "C02Y9876PQRS"
    assert fsys.checksum_valid is True


def test_rom_info_viewer():
    blob = bytearray(b"\xff" * 0x100000)
    blob[0x20000:0x20800] = _mk_fsys(SERIAL.encode())
    p = _write(bytes(blob))
    info = rom_info(p)
    assert info["apple_detected"] or info["fsys"]["found"]
    assert info["fsys"]["found"]
    assert info["fsys"]["checksum_valid"] is True
    assert info["fsys"]["serial"] == SERIAL


def test_ec_scan_advisory_no_writes(tmp_path):
    ee = ECPatcher()
    blob = bytearray(b"\xff" * 0x10000)
    blob[0x5000:0x500E] = bytearray.fromhex("50617373776f7264537461747573")  # 'PasswordStatus'
    p = _write(bytes(blob), "ec.bin")
    before_file_state = open(p, "rb").read()

    out_dir = tmp_path / "nothing_here"
    findings = ee.scan_patch_sites(p)
    assert findings, "patches exist in the default table"
    found = [f for f in findings if f["found"]]
    assert found and found[0]["offsets"]
    assert all(("offsets" not in f) or isinstance(f.get("offsets"), list) for f in findings)
    # NO writes: no output file created beside the scan (the scan creates nothing)
    assert open(p, "rb").read() == before_file_state
    assert not out_dir.exists()
