"""Identity audit fixes for DMI extraction: index-resolved strings and dmidecode UUID rules."""

import struct
from dataclasses import fields

from bios_recovery.core.dmi_extractor import DMIExtractor, DMIInfo


def _table(*structs: bytes) -> bytes:
    return b"".join(structs)


def _strings(*items: bytes) -> bytes:
    return b"".join(s + b"\x00" for s in items) + b"\x00"


def _type1(serial_idx: int, uuid: bytes, strings: bytes) -> bytes:
    fixed = bytearray(0x19)
    fixed[0:4] = bytes([1, 0x19, 1, 0])
    fixed[4:8] = bytes([1, 2, 3, serial_idx])
    fixed[8:24] = uuid
    return bytes(fixed) + strings


def _eot() -> bytes:
    return bytes([127, 4, 0, 0]) + b"\x00\x00"


def test_system_serial_comes_from_its_index_byte():
    # string 3 is the version, string 4 is the serial: the index byte says so
    strings = _strings(b"LENOVO", b"20HQ", b"VER1", b"SN123456")
    table = _table(_type1(4, bytes(16), strings), _eot())
    info = DMIExtractor()._parse_smbios(table)
    assert info.system_serial_number == "SN123456"
    assert info.system_manufacturer == "LENOVO"


def test_index_zero_means_no_string_and_past_the_end_is_marked():
    strings = _strings(b"ACME", b"Box")
    fixed = bytearray(0x19)
    fixed[0:4] = bytes([1, 0x19, 1, 0])
    fixed[4:8] = bytes([0, 9, 0, 1])  # manufacturer none, product bad, serial = "ACME"
    table = _table(bytes(fixed) + strings, _eot())
    info = DMIExtractor()._parse_smbios(table)
    assert info.system_manufacturer == ""
    assert info.system_product_name == "<bad index>"
    assert info.system_serial_number == "ACME"


def test_uuid_all_ff_is_not_present_and_all_zero_is_not_settable():
    ex = DMIExtractor()
    assert ex._format_uuid(b"\xff" * 16) == "Not Present"
    assert ex._format_uuid(b"\x00" * 16) == "Not Settable"


def test_uuid_is_big_endian_before_smbios_2_6():
    ex = DMIExtractor()
    raw = bytes(range(16))
    assert ex._format_uuid(raw, 0x0205) == "00010203-0405-0607-0809-0A0B0C0D0E0F"
    assert ex._format_uuid(raw, 0x0206) == "03020100-0504-0706-0809-0A0B0C0D0E0F"
    assert ex._format_uuid(raw) == "03020100-0504-0706-0809-0A0B0C0D0E0F"


def test_processor_socket_is_a_declared_field():
    assert "processor_socket" in {f.name for f in fields(DMIInfo)}
    fixed = bytearray(0x30)
    fixed[0:4] = bytes([4, 0x30, 1, 0])
    fixed[4] = 1  # socket designation -> string 1
    fixed[7] = 2  # manufacturer -> string 2
    fixed[0x20] = 3  # serial -> string 3
    table = _table(bytes(fixed) + _strings(b"U3E1", b"Intel", b"SN-CPU"), _eot())
    info = DMIExtractor()._parse_smbios(table)
    assert info.processor_socket == "U3E1"
    assert info.processor_manufacturer == "Intel"
    assert info.processor_serial == "SN-CPU"


def test_memory_device_fields_use_their_own_index_bytes():
    fixed = bytearray(0x1B)
    fixed[0:4] = bytes([17, 0x1B, 1, 0])
    fixed[0x10] = 1  # device locator
    fixed[0x17] = 3  # manufacturer
    fixed[0x18] = 4  # serial
    strings = _strings(b"DIMM0", b"Micron", b"A1B2", b"SX0123")
    table = _table(bytes(fixed) + strings, _eot())
    info = DMIExtractor()._parse_smbios(table)
    dev = info.memory_devices[0]
    assert dev["device_locator"] == "DIMM0"
    assert dev["manufacturer"] == "A1B2"
    assert dev["serial_number"] == "SX0123"


def test_bios_release_date_is_read_from_offset_0x08():
    fixed = bytearray(0x12)
    fixed[0:4] = bytes([0, 0x12, 1, 0])
    fixed[4:9] = bytes([1, 2, 0, 0, 3])
    strings = _strings(b"AMI", b"5.26", b"03/15/2020")
    info = DMIExtractor()._parse_smbios(_table(bytes(fixed) + strings, _eot()))
    assert info.bios_vendor == "AMI"
    assert info.bios_version == "5.26"
    assert info.bios_release_date == "03/15/2020"


def test_uuid_read_with_version_from_entry_point(tmp_path):
    uuid = bytes(range(16))
    table = _table(_type1(1, uuid, _strings(b"LENOVO", b"Box")), _eot())
    image = bytearray(b"\xff" * 0x4000)
    eps = bytearray(0x1F)
    eps[0:4] = b"_SM_"
    eps[5] = 0x1F
    eps[6] = 2
    eps[7] = 5  # SMBIOS 2.5: UUID bytes are not swapped
    eps[0x10:0x15] = b"_DMI_"
    struct.pack_into("<H", eps, 0x16, len(table))
    struct.pack_into("<I", eps, 0x18, 0x1000)
    eps[0x15] = (0x100 - sum(eps[0x10:0x1F]) % 0x100) % 0x100
    eps[4] = (0x100 - sum(eps) % 0x100) % 0x100
    image[0x40 : 0x40 + 0x1F] = eps
    image[0x1000 : 0x1000 + len(table)] = table
    info = DMIExtractor().extract_from_dump_bytes(bytes(image))
    assert info.system_uuid == "00010203-0405-0607-0809-0A0B0C0D0E0F"
