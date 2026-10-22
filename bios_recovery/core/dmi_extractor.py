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
        _anchor, start, length = found
        return self._parse_smbios(data[start : start + length])

    def _parse_smbios(self, data: bytes) -> DMIInfo:
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
                self._parse_system_info(struct_data, strings, info)
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

    def _parse_bios_info(self, data: bytes, strings: list[str], info: DMIInfo) -> None:
        if len(data) >= 0x12:
            info.bios_vendor = strings[0] if len(strings) > 0 else ""
            info.bios_version = strings[1] if len(strings) > 1 else ""
            info.bios_release_date = strings[2] if len(strings) > 2 else ""

    def _parse_system_info(self, data: bytes, strings: list[str], info: DMIInfo) -> None:
        if len(data) >= 0x19:
            info.system_manufacturer = strings[0] if len(strings) > 0 else ""
            info.system_product_name = strings[1] if len(strings) > 1 else ""
            info.system_serial_number = strings[2] if len(strings) > 2 else ""
            if len(data) >= 0x19:
                uuid_bytes = data[8:24]
                info.system_uuid = self._format_uuid(uuid_bytes)

    def _parse_baseboard_info(self, data: bytes, strings: list[str], info: DMIInfo) -> None:
        if len(data) >= 0x08:
            info.board_manufacturer = strings[0] if len(strings) > 0 else ""
            info.board_product_name = strings[1] if len(strings) > 1 else ""
            info.board_serial_number = strings[3] if len(strings) > 3 else ""
            info.board_asset_tag = strings[4] if len(strings) > 4 else ""

    def _parse_chassis_info(self, data: bytes, strings: list[str], info: DMIInfo) -> None:
        if len(data) >= 0x09:
            info.chassis_manufacturer = strings[0] if len(strings) > 0 else ""
            info.chassis_serial_number = strings[2] if len(strings) > 2 else ""
            info.chassis_asset_tag = strings[3] if len(strings) > 3 else ""

    def _parse_processor_info(self, data: bytes, strings: list[str], info: DMIInfo) -> None:
        if len(data) >= 0x20:
            info.processor_socket = strings[0] if len(strings) > 0 else ""
            info.processor_manufacturer = strings[1] if len(strings) > 1 else ""
            info.processor_version = strings[2] if len(strings) > 2 else ""
            info.processor_serial = strings[3] if len(strings) > 3 else ""
            info.processor_asset_tag = strings[4] if len(strings) > 4 else ""

    def _parse_memory_device(self, data: bytes, strings: list[str], info: DMIInfo) -> None:
        mem_device = {
            "device_locator": strings[0] if len(strings) > 0 else "",
            "bank_locator": strings[1] if len(strings) > 1 else "",
            "manufacturer": strings[2] if len(strings) > 2 else "",
            "serial_number": strings[3] if len(strings) > 3 else "",
            "asset_tag": strings[4] if len(strings) > 4 else "",
            "part_number": strings[5] if len(strings) > 5 else "",
        }
        info.memory_devices.append(mem_device)

    def _format_uuid(self, uuid_bytes: bytes) -> str:
        if len(uuid_bytes) < 16:
            return ""
        return (
            f"{uuid_bytes[3]:02X}{uuid_bytes[2]:02X}{uuid_bytes[1]:02X}{uuid_bytes[0]:02X}-"
            f"{uuid_bytes[5]:02X}{uuid_bytes[4]:02X}-"
            f"{uuid_bytes[7]:02X}{uuid_bytes[6]:02X}-"
            f"{uuid_bytes[8]:02X}{uuid_bytes[9]:02X}-"
            f"{uuid_bytes[10]:02X}{uuid_bytes[11]:02X}{uuid_bytes[12]:02X}"
            f"{uuid_bytes[13]:02X}{uuid_bytes[14]:02X}{uuid_bytes[15]:02X}"
        )

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
