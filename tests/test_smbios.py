"""SMBIOS table location: entry points, scanning, and the false positives that must be rejected."""

import struct

from bios_recovery.core.smbios import find_table
from bios_recovery.engines.dmi_extractor import DMIExtractor
from tests.fixture_builder import make_smbios_structures


def _entry_2x(table_len: int, table_addr: int) -> bytes:
    eps = bytearray(0x1F)
    eps[0:4] = b"_SM_"
    eps[5] = 0x1F
    eps[0x10:0x15] = b"_DMI_"
    struct.pack_into("<H", eps, 0x16, table_len)
    struct.pack_into("<I", eps, 0x18, table_addr)
    eps[0x15] = (0x100 - sum(eps[0x10:0x1F]) % 0x100) % 0x100
    eps[4] = (0x100 - sum(eps) % 0x100) % 0x100
    return bytes(eps)


def _entry_3x(table_len: int, table_addr: int) -> bytes:
    eps = bytearray(0x18)
    eps[0:5] = b"_SM3_"
    eps[6] = 0x18
    struct.pack_into("<I", eps, 0x0C, table_len)
    struct.pack_into("<Q", eps, 0x10, table_addr)
    eps[5] = (0x100 - sum(eps) % 0x100) % 0x100
    return bytes(eps)


def test_entry_point_with_table_at_its_address(tmp_path):
    table, _ = make_smbios_structures()
    image = bytearray(b"\xff" * 0x4000)
    image[0x40 : 0x40 + 0x1F] = _entry_2x(len(table), 0x1000)
    image[0x1000 : 0x1000 + len(table)] = table
    anchor, start, length = find_table(bytes(image))
    assert (anchor, start, length) == (0x40, 0x1000, len(table))


def test_entry_point_with_table_directly_after_it(tmp_path):
    table, _ = make_smbios_structures()
    image = bytearray(b"\xff" * 0x4000)
    image[0x40 : 0x40 + 0x1F] = _entry_2x(len(table), 0xDEAD0000)  # runtime address
    image[0x40 + 0x1F : 0x40 + 0x1F + len(table)] = table
    anchor, start, length = find_table(bytes(image))
    assert start == 0x40 + 0x1F and length == len(table)


def test_smbios_3_entry_point(tmp_path):
    table, _ = make_smbios_structures()
    image = bytearray(b"\xff" * 0x4000)
    image[0x80 : 0x80 + 0x18] = _entry_3x(len(table), 0x2000)
    image[0x2000 : 0x2000 + len(table)] = table
    anchor, start, length = find_table(bytes(image))
    assert (anchor, start) == (0x80, 0x2000)


def test_table_without_entry_point_is_found_by_scanning(tmp_path):
    # Real tables end with an end-of-table structure (type 127) and hold more than
    # five structures; the scan needs that many to accept a chain.
    table = make_smbios_structures()[0] + bytes([127, 4, 0, 0]) + b"\x00\x00"
    image = bytearray(b"\xff" * 0x8000)
    image[0x3456 : 0x3456 + len(table)] = table
    anchor, start, length = find_table(bytes(image))
    assert start == 0x3456 and anchor == start


def test_random_anchor_text_is_not_a_table():
    image = b"junk _SM_ junk _DMI_" + b"\x00" * 0x100 + b"{\"x\": 1}" + b"\xff" * 0x1000
    assert find_table(image) is None


def test_extractor_returns_nothing_for_an_image_without_a_table():
    assert DMIExtractor().extract_from_dump_bytes(b"\xff" * 0x10000) is None


def test_extractor_reads_identity_from_a_located_table(tmp_path):
    table, _ = make_smbios_structures()
    image = bytearray(b"\xff" * 0x4000)
    image[0x40 : 0x40 + 0x1F] = _entry_2x(len(table), 0x1000)
    image[0x1000 : 0x1000 + len(table)] = table
    path = tmp_path / "dump.bin"
    path.write_bytes(bytes(image))
    info = DMIExtractor().extract_from_bios(str(path))
    assert info is not None
    assert info.bios_vendor == "American Megatrends Inc."
    assert info.system_manufacturer == "LENOVO"
    assert info.system_serial_number == "PF1ABC123"
