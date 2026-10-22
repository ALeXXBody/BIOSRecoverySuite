"""Identity audit fixes for SMBIOS location: entry point checksums and exact table length."""

import struct

from bios_recovery.core.smbios import find_table
from tests.fixture_builder import make_smbios_structures
from tests.test_smbios import _entry_2x, _entry_3x


def _image_2x(table: bytes) -> bytearray:
    image = bytearray(b"\xff" * 0x4000)
    image[0x40 : 0x40 + 0x1F] = _entry_2x(len(table), 0x1000)
    image[0x1000 : 0x1000 + len(table)] = table
    return image


def test_valid_entry_point_is_found():
    table, _ = make_smbios_structures()
    assert find_table(bytes(_image_2x(table))) == (0x40, 0x1000, len(table))


def test_entry_point_checksum_is_checked():
    table, _ = make_smbios_structures()
    image = _image_2x(table)
    image[0x40 + 4] ^= 0x01  # corrupt the entry point checksum
    assert find_table(bytes(image)) is None


def test_intermediate_anchor_checksum_is_checked():
    table, _ = make_smbios_structures()
    image = _image_2x(table)
    image[0x40 + 0x15] ^= 0x01  # corrupt the intermediate checksum
    assert find_table(bytes(image)) is None


def test_3x_entry_point_checksum_is_checked():
    table, _ = make_smbios_structures()
    image = bytearray(b"\xff" * 0x4000)
    image[0x80 : 0x80 + 0x18] = _entry_3x(len(table), 0x2000)
    image[0x2000 : 0x2000 + len(table)] = table
    assert find_table(bytes(image)) is not None
    image[0x80 + 5] ^= 0x01
    assert find_table(bytes(image)) is None


def test_truncated_table_is_refused_not_shortened():
    table, _ = make_smbios_structures()
    broken = bytearray(table)
    broken[-1] = 0x01  # the last string set is no longer well formed
    image = _image_2x(bytes(broken))
    assert find_table(bytes(image)) is None


def test_table_shorter_than_declared_is_refused():
    table, _ = make_smbios_structures()
    image = _image_2x(table)
    struct.pack_into("<H", image, 0x40 + 0x16, len(table) + 0x10)  # declares more bytes
    assert find_table(bytes(image)) is None


def test_scanned_table_without_end_of_table_is_not_accepted():
    # six structures: enough for the old scanner, but no end-of-table structure
    table = make_smbios_structures()[0] + bytes([32, 4, 0, 0]) + b"\x00\x00"
    image = bytearray(b"\xff" * 0x8000)
    image[0x3456 : 0x3456 + len(table)] = table
    assert find_table(bytes(image)) is None


def test_scanned_table_with_end_of_table_is_accepted():
    table = make_smbios_structures()[0] + bytes([127, 4, 0, 0]) + b"\x00\x00"
    image = bytearray(b"\xff" * 0x8000)
    image[0x3456 : 0x3456 + len(table)] = table
    assert find_table(bytes(image)) == (0x3456, 0x3456, len(table))
