"""BIOS password removal engine - supports multiple manufacturers."""

import os
import struct
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional

from bios_recovery.core.nvar import ATTR_VALID, NVAR, is_valid, iter_records
from bios_recovery.core.safety import SameFileError, ensure_distinct


class PasswordType(Enum):
    UNKNOWN = auto()
    AMI_SETUP_PASSWORD = auto()
    PHOENIX_PASSWORD = auto()
    AWARD_PASSWORD = auto()
    DELL_ADMIN_PASSWORD = auto()
    DELL_HDD_PASSWORD = auto()
    HP_PASSWORD = auto()
    LENOVO_PASSWORD = auto()
    TOSHIBA_PASSWORD = auto()
    SAMSUNG_PASSWORD = auto()
    SONY_PASSWORD = auto()
    INSYDE_PASSWORD = auto()
    EFI_PASSWORD = auto()
    UEFI_PASSWORD = auto()


class PasswordRemovalResult(Enum):
    SUCCESS = auto()
    NOT_FOUND = auto()
    UNSUPPORTED = auto()
    PARTIAL = auto()
    ERROR = auto()


@dataclass
class PasswordRemovalReport:
    status: PasswordRemovalResult
    password_type: PasswordType = PasswordType.UNKNOWN
    original_offset: int = 0
    output_path: str = ""
    messages: list[str] = field(default_factory=list)
    found_passwords: list[dict] = field(default_factory=list)


class PasswordRemover:
    """Removes/clears BIOS passwords from firmware images."""

    AMI_PASSWORD_GUIDS = [
        bytes.fromhex("08813F6041F64E8EB33AF4C0D6C1B2E7"),
        bytes.fromhex("A04A3EFADF404D75B3A0C1C4C3D5C1C4"),
        bytes.fromhex("E586008D50A44E26A77B4B2F7A9E5B0A"),
    ]

    # NVRAM variable names that hold an AMI password. Only these are cleared. "Setup" is the
    # BIOS settings store and "Password" is not verified, so they are reported but not written.
    AMI_CLEARABLE_VAR_NAMES = ("AMITSESetup", "SVP")
    AMI_REPORT_ONLY_VAR_NAMES = ("Setup", "Password")

    KNOWN_PASSWORD_PATTERNS = {
        PasswordType.AMI_SETUP_PASSWORD: [
            b"AMITSESetup",
            b"AMITSE",
            b"A\x00M\x00I\x00T\x00S\x00E\x00S\x00e\x00t\x00u\x00p\x00",
        ],
        PasswordType.PHOENIX_PASSWORD: [b"Phoenix", b"phoenix"],
        PasswordType.LENOVO_PASSWORD: [b"cE!"],
        PasswordType.DELL_ADMIN_PASSWORD: [b"8FC8", b"BF97", b"CF1B"],
        PasswordType.HP_PASSWORD: [b"Admin", b"admin"],
    }

    def remove_passwords(
        self,
        input_path: str,
        output_path: Optional[str] = None,
        password_types: Optional[list[PasswordType]] = None,
    ) -> PasswordRemovalReport:
        if not os.path.exists(input_path):
            return PasswordRemovalReport(
                status=PasswordRemovalResult.ERROR,
                messages=[f"File not found: {input_path}"],
            )

        if output_path is None:
            output_path = input_path.rsplit(".", 1)[0] + "_nopass.bin"

        try:
            ensure_distinct(input_path, output_path)
        except SameFileError as exc:
            return PasswordRemovalReport(
                status=PasswordRemovalResult.ERROR,
                messages=[str(exc)],
            )

        with open(input_path, "rb") as f:
            original = f.read()
        data = bytearray(original)

        report = PasswordRemovalReport(status=PasswordRemovalResult.NOT_FOUND)

        self._find_ami_passwords(data, report)
        self._find_uefi_passwords(data, report)
        self._find_lenovo_passwords(data, report)
        self._find_dell_passwords(data, report)
        self._find_hp_passwords(data, report)

        for pw in report.found_passwords:
            pw.setdefault("clearable", False)

        self._clear_passwords(data, report)

        if bytes(data) == original:
            report.messages.append("Nothing was written: no change to the image")
            return report

        with open(output_path, "wb") as f:
            f.write(data)

        report.output_path = output_path
        return report

    def _find_ami_passwords(self, data: bytearray, report: PasswordRemovalReport) -> None:
        names = self.AMI_CLEARABLE_VAR_NAMES + self.AMI_REPORT_ONLY_VAR_NAMES
        for rec in iter_records(bytes(data)):
            if rec.name not in names or not is_valid(rec):
                continue
            report.found_passwords.append(
                {
                    "type": PasswordType.AMI_SETUP_PASSWORD,
                    "name": rec.name,
                    "offset": rec.offset,
                    "size": rec.total,
                    "clearable": rec.name in self.AMI_CLEARABLE_VAR_NAMES,
                }
            )
            report.messages.append(f"Found AMI variable {rec.name} at {rec.offset:#x}")

    def _find_uefi_passwords(self, data: bytearray, report: PasswordRemovalReport) -> None:
        uefi_var_header = b"\x34\x00\x00\x00"
        offset = 0
        while True:
            idx = data.find(uefi_var_header, offset)
            if idx < 0:
                break
            if idx + 4 <= len(data):
                var_size = struct.unpack_from("<I", data, idx)[0]
                if 0x10 <= var_size <= 0x10000:
                    report.found_passwords.append(
                        {
                            "type": PasswordType.UEFI_PASSWORD,
                            "name": "UEFI Variable",
                            "offset": idx,
                            "size": var_size,
                        }
                    )
            offset = idx + 4

    def _find_lenovo_passwords(self, data: bytearray, report: PasswordRemovalReport) -> None:
        ce_pattern = b"cE!"
        offset = 0
        while True:
            idx = data.find(ce_pattern, offset)
            if idx < 0:
                break
            report.found_passwords.append(
                {
                    "type": PasswordType.LENOVO_PASSWORD,
                    "name": "cE! security variable",
                    "offset": idx,
                    "size": 8,
                }
            )
            report.messages.append(f"Found Lenovo security variable at {idx:#x}")
            offset = idx + 1

    def _find_dell_passwords(self, data: bytearray, report: PasswordRemovalReport) -> None:
        for pattern in [b"8FC8", b"BF97", b"CF1B", b"1F66", b"E7A8"]:
            offset = 0
            while True:
                idx = data.find(pattern, offset)
                if idx < 0:
                    break
                report.found_passwords.append(
                    {
                        "type": PasswordType.DELL_ADMIN_PASSWORD,
                        "name": f"Dell {pattern.decode()} password marker",
                        "offset": idx,
                        "size": len(pattern),
                    }
                )
                report.messages.append(f"Found Dell password marker at {idx:#x}")
                offset = idx + 1

    def _find_hp_passwords(self, data: bytearray, report: PasswordRemovalReport) -> None:
        hp_password_markers = [
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",
        ]
        max_matches = 40
        min_separation = 0x1000
        last_match = -min_separation
        found = 0
        for marker in hp_password_markers:
            offset = 0
            while found < max_matches:
                idx = data.find(marker, offset)
                if idx < 0:
                    break
                if idx - last_match >= min_separation:
                    report.found_passwords.append(
                        {
                            "type": PasswordType.HP_PASSWORD,
                            "name": "HP password region",
                            "offset": idx,
                            "size": len(marker),
                        }
                    )
                    found += 1
                    last_match = idx
                offset = idx + 1

    def _clear_passwords(self, data: bytearray, report: PasswordRemovalReport) -> None:
        """Mark each verified password record invalid, the way NVRAM marks a superseded record.

        The record's bytes are left intact, so the store stays well formed. Entries that were
        not verified as a password store are never written.
        """
        cleared = 0
        unverified = 0
        for pw in report.found_passwords:
            if not pw.get("clearable"):
                unverified += 1
                continue
            attr_pos = pw["offset"] + 9
            if data[pw["offset"] : pw["offset"] + 4] != NVAR or not data[attr_pos] & ATTR_VALID:
                continue
            data[attr_pos] &= ~ATTR_VALID & 0xFF
            cleared += 1
            report.messages.append(f"Cleared {pw['name']} at {pw['offset']:#x}")

        if cleared:
            report.status = PasswordRemovalResult.SUCCESS
        elif report.found_passwords:
            report.status = PasswordRemovalResult.PARTIAL
        else:
            report.status = PasswordRemovalResult.NOT_FOUND
            report.messages.append("No recognizable password structures found")
        if unverified:
            report.messages.append(
                f"{unverified} candidate(s) not verified as a password store; left unchanged"
            )

    def generate_dell_master_password(self, service_tag: str, suffix: str) -> list[str]:
        passwords = []
        suffixes = [suffix] if suffix else ["595B", "D35B", "2A7B", "A95B", "1D3B", "6FF1", "1F66"]

        for s in suffixes:
            tag = service_tag.upper()
            full = tag + s
            try:
                val = int(full, 36)
                hash_val = val & 0xFFFFFFFF
                password = f"{hash_val % 100000000:08d}"
                passwords.append(password)
            except ValueError:
                pass

        return passwords

    def generate_hp_master_password(self, code: str) -> str:
        try:
            val = int(code)
            return f"{(val * 3 + 7) % 100000000:08d}"
        except ValueError:
            return ""

    def generate_insyde_master_password(self, code: str) -> str:
        try:
            val = int(code)
            result = ""
            for _ in range(8):
                result = str(val % 10) + result
                val //= 10
            return result
        except ValueError:
            return ""

    def find_password_in_dump(self, file_path: str) -> list[dict]:
        with open(file_path, "rb") as f:
            data = f.read()

        found = []

        for pattern_name, patterns in self.KNOWN_PASSWORD_PATTERNS.items():
            for pattern in patterns:
                offset = 0
                while True:
                    idx = data.find(pattern, offset)
                    if idx < 0:
                        break
                    found.append(
                        {
                            "type": pattern_name.name,
                            "pattern": pattern.hex(),
                            "offset": f"{idx:#x}",
                            "context": data[max(0, idx - 8) : idx + len(pattern) + 8].hex(),
                        }
                    )
                    offset = idx + 1

        return found
