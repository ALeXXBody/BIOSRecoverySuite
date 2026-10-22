"""DMI/SMBIOS extraction and editing engine."""

import re
import struct
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class DMIField:
    name: str
    value: str
    offset: int = 0
    size: int = 0


@dataclass
class DMIStructure:
    type_id: int
    type_name: str
    handle: int
    length: int
    fields: list[DMIField] = field(default_factory=list)
    raw_data: bytes = b""


@dataclass
class DMIInfo:
    bios_vendor: str = ""
    bios_version: str = ""
    bios_release_date: str = ""
    system_manufacturer: str = ""
    system_product_name: str = ""
    system_serial_number: str = ""
    system_uuid: str = ""
    board_manufacturer: str = ""
    board_product_name: str = ""
    board_serial_number: str = ""
    board_asset_tag: str = ""
    chassis_manufacturer: str = ""
    chassis_serial_number: str = ""
    chassis_asset_tag: str = ""
    processor_family: str = ""
    processor_socket: str = ""
    processor_manufacturer: str = ""
    processor_version: str = ""
    processor_serial: str = ""
    processor_asset_tag: str = ""
    memory_devices: list[dict] = field(default_factory=list)
    structures: list[DMIStructure] = field(default_factory=list)
    raw_smbios: bytes = b""


class DMIExtractor:
    """Extracts and parses DMI/SMBIOS data from BIOS images."""

    SMBIOS_SIGNATURES = [b"_SM_", b"_DMI_"]
    SMBIOS_ENTRY_SIZE = 32

    SMBIOS_TYPES = {
        0: "BIOS Information",
        1: "System Information",
        2: "Baseboard Information",
        3: "Chassis Information",
        4: "Processor Information",
        7: "Cache Information",
        9: "System Slots",
        11: "OEM Strings",
        16: "Physical Memory Array",
        17: "Memory Device",
        32: "System Boot Information",
        38: "IPMI Device",
        43: "TPM Device",
    }

    def extract_from_bios(self, file_path: str) -> Optional[DMIInfo]:
        """DMI identity from an image, or None when no valid SMBIOS table is in it."""
        with open(file_path, "rb") as f:
            data = f.read()
        return self.extract_from_dump_bytes(data)

    def extract_from_dump_bytes(self, data: bytes) -> Optional[DMIInfo]:
        from bios_recovery.core.smbios import find_table

        found = find_table(data)
        if found is None:
            return None
        anchor, start, length = found
        version = _smbios_version(data, anchor, start)
        return self._parse_smbios(data[start : start + length], version)

    def _parse_smbios(self, data: bytes, version: Optional[int] = None) -> DMIInfo:
        info = DMIInfo(raw_smbios=data)
        offset = 0

        while offset < len(data) - 1:
            if offset + 4 > len(data):
                break

            struct_type = data[offset]
            struct_length = data[offset + 1]

            if struct_length < 4 or offset + struct_length > len(data):
                break

            handle = struct.unpack_from("<H", data, offset + 2)[0]
            struct_data = data[offset : offset + struct_length]

            dmi_struct = DMIStructure(
                type_id=struct_type,
                type_name=self.SMBIOS_TYPES.get(struct_type, f"Type {struct_type}"),
                handle=handle,
                length=struct_length,
                raw_data=struct_data,
            )

            string_pool_start = offset + struct_length
            strings = self._extract_strings(data, string_pool_start)

            if struct_type == 0:
                self._parse_bios_info(struct_data, strings, info)
            elif struct_type == 1:
                self._parse_system_info(struct_data, strings, info, version)
            elif struct_type == 2:
                self._parse_baseboard_info(struct_data, strings, info)
            elif struct_type == 3:
                self._parse_chassis_info(struct_data, strings, info)
            elif struct_type == 4:
                self._parse_processor_info(struct_data, strings, info)
            elif struct_type == 17:
                self._parse_memory_device(struct_data, strings, info)

            info.structures.append(dmi_struct)
            offset = string_pool_start
            while offset < len(data) - 1:
                if data[offset] == 0x00 and data[offset + 1] == 0x00:
                    offset += 2
                    break
                offset += 1

        return info

    def _extract_strings(self, data: bytes, start: int) -> list[str]:
        strings = []
        current = b""
        for i in range(start, min(start + 0x1000, len(data))):
            if data[i] == 0x00:
                if current:
                    strings.append(current.decode("ascii", errors="replace"))
                    current = b""
                else:
                    break
            else:
                current += bytes([data[i]])
        return strings

    @staticmethod
    def _field(data: bytes, strings: list[str], offset: int) -> str:
        """The string named by the index byte at offset (0 means none, past the end is bad)."""
        if offset >= len(data):
            return ""
        idx = data[offset]
        if idx == 0:
            return ""
        if idx > len(strings):
            return "<bad index>"
        return strings[idx - 1]

    def _parse_bios_info(self, data: bytes, strings: list[str], info: DMIInfo) -> None:
        if len(data) >= 0x12:
            info.bios_vendor = self._field(data, strings, 0x04)
            info.bios_version = self._field(data, strings, 0x05)
            info.bios_release_date = self._field(data, strings, 0x08)

    def _parse_system_info(
        self,
        data: bytes,
        strings: list[str],
        info: DMIInfo,
        version: Optional[int] = None,
    ) -> None:
        info.system_manufacturer = self._field(data, strings, 0x04)
        info.system_product_name = self._field(data, strings, 0x05)
        info.system_serial_number = self._field(data, strings, 0x07)
        if len(data) >= 0x19:
            info.system_uuid = self._format_uuid(data[8:24], version)

    def _parse_baseboard_info(self, data: bytes, strings: list[str], info: DMIInfo) -> None:
        info.board_manufacturer = self._field(data, strings, 0x04)
        info.board_product_name = self._field(data, strings, 0x05)
        info.board_serial_number = self._field(data, strings, 0x07)
        info.board_asset_tag = self._field(data, strings, 0x08)

    def _parse_chassis_info(self, data: bytes, strings: list[str], info: DMIInfo) -> None:
        info.chassis_manufacturer = self._field(data, strings, 0x04)
        info.chassis_serial_number = self._field(data, strings, 0x07)
        info.chassis_asset_tag = self._field(data, strings, 0x08)

    def _parse_processor_info(self, data: bytes, strings: list[str], info: DMIInfo) -> None:
        info.processor_socket = self._field(data, strings, 0x04)
        info.processor_manufacturer = self._field(data, strings, 0x07)
        info.processor_version = self._field(data, strings, 0x10)
        info.processor_serial = self._field(data, strings, 0x20)
        info.processor_asset_tag = self._field(data, strings, 0x21)

    def _parse_memory_device(self, data: bytes, strings: list[str], info: DMIInfo) -> None:
        mem_device = {
            "device_locator": self._field(data, strings, 0x10),
            "bank_locator": self._field(data, strings, 0x11),
            "manufacturer": self._field(data, strings, 0x17),
            "serial_number": self._field(data, strings, 0x18),
            "asset_tag": self._field(data, strings, 0x19),
            "part_number": self._field(data, strings, 0x1A),
        }
        info.memory_devices.append(mem_device)

    def _format_uuid(self, uuid_bytes: bytes, version: Optional[int] = None) -> str:
        """UUID text as dmidecode prints it. Before SMBIOS 2.6 the bytes are not swapped."""
        if len(uuid_bytes) < 16:
            return ""
        if uuid_bytes == b"\xff" * 16:
            return "Not Present"
        if uuid_bytes == b"\x00" * 16:
            return "Not Settable"
        b = uuid_bytes
        if version is not None and version < 0x0206:
            ordered = b
        else:
            ordered = bytes([b[3], b[2], b[1], b[0], b[5], b[4], b[7], b[6]]) + b[8:16]
        h = ordered.hex().upper()
        return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"

    def search_dmi_in_image(self, file_path: str, pattern: str = "") -> list[dict]:
        with open(file_path, "rb") as f:
            data = f.read()

        results = []
        ascii_pattern = pattern.encode("ascii", errors="ignore")

        if ascii_pattern:
            offset = 0
            while True:
                idx = data.find(ascii_pattern, offset)
                if idx < 0:
                    break
                context_start = max(0, idx - 16)
                context_end = min(len(data), idx + len(ascii_pattern) + 16)
                results.append(
                    {
                        "offset": f"{idx:#x}",
                        "context": data[context_start:context_end].hex(),
                        "matched": data[idx : idx + len(ascii_pattern)].decode(
                            "ascii", errors="replace"
                        ),
                    }
                )
                offset = idx + 1

        return results


def _smbios_version(data: bytes, anchor: int, start: int) -> Optional[int]:
    """SMBIOS version (0xMMmm) from the entry point, or None when the table was scanned."""
    if anchor == start:
        return None
    if data[anchor : anchor + 5] == b"_SM3_":
        return (data[anchor + 7] << 8) | data[anchor + 8]
    return (data[anchor + 6] << 8) | data[anchor + 7]


def _printable_text(blob: bytes, limit: int = 160) -> str:
    """Readable runs of a variable's data, joined; the raw bytes are not shown."""
    runs = [m.group().decode("ascii") for m in re.finditer(rb"[\x20-\x7e]{3,}", blob)]
    text = " | ".join(runs)
    return text[:limit] + ("..." if len(text) > limit else "")


def nvram_identity(data: bytes) -> list:
    """The identity variables (MFG0, _DMI) of an AMI image: copies, size and readable text."""
    from bios_recovery.core.nvar import IDENTITY_NAMES, identity_copies

    copies = identity_copies(data)
    out = []
    for name in IDENTITY_NAMES:
        found = copies.get(name)
        if found:
            live = found[-1]
            out.append(
                {
                    "name": name,
                    "copies": len(found),
                    "size": live.total,
                    "text": _printable_text(live.data),
                }
            )
    return out


def read_identity_file(path: str) -> tuple:
    """(SMBIOS info or None, NVRAM identity list) for an image. Read-only."""
    with open(path, "rb") as f:
        data = f.read()
    return DMIExtractor().extract_from_dump_bytes(data), nvram_identity(data)
