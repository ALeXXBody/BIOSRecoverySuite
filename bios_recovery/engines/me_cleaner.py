"""Intel ME/TXE/CSME cleaning engine - strips and neuters management firmware."""

import struct
import os
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional


class MeGeneration(Enum):
    GEN1 = auto()
    GEN2 = auto()
    GEN3 = auto()
    UNKNOWN = auto()


class MeCleanResult(Enum):
    SUCCESS = auto()
    ALREADY_CLEAN = auto()
    NO_ME_REGION = auto()
    UNSUPPORTED_VERSION = auto()
    ERROR = auto()


@dataclass
class MeCleanReport:
    status: MeCleanResult
    me_version: str = ""
    me_type: str = ""
    generation: MeGeneration = MeGeneration.UNKNOWN
    original_size: int = 0
    cleaned_size: int = 0
    partitions_removed: int = 0
    modules_removed: int = 0
    hap_bit_set: bool = False
    soft_disable: bool = False
    output_path: str = ""
    messages: list[str] = field(default_factory=list)


class IntelMECleaner:
    """Cleans Intel ME/TXE/CSME firmware regions in BIOS images."""

    FPT_SIGNATURE = b"$FPT"
    FPT_ENTRY_SIZE = 0x20
    ME_ANALIGHTIC_WORKAROUND_ME7 = 7
    MAX_SUPPORTED_ME_VERSION = 19

    PARTITION_TABLE_ENTRIES = {
        b"FTPR": "FTPR (Factory Partition Recovery)",
        b"ROMB": "ROMB (ROM Boot)",
        b"LOCL": "LOCL (Local update)",
        b"EFFS": "EFFS (Embedded File System)",
        b"NFTP": "NFTP (Non-FTP)",
        b"FTCS": "FTCS (FTCS)",
        b"SMIP": "SMIP (SMIP)",
        b"LOCM": "LOCM (LOCM)",
        b"ISHC": "ISHC (ISHC)",
        b"WCOD": "WCOD (WCOD)",
        b"LOCL": "LOCL (LOCL)",
        b"WCOD": "WCOD (WCOD)",
    }

    def clean(
        self,
        input_path: str,
        output_path: Optional[str] = None,
        soft_disable: bool = True,
        relocate: bool = False,
        truncate: bool = False,
        remove_modules: bool = True,
        descriptor_lock: bool = False,
    ) -> MeCleanReport:
        if not os.path.exists(input_path):
            return MeCleanReport(
                status=MeCleanResult.ERROR,
                messages=[f"File not found: {input_path}"],
            )

        with open(input_path, "rb") as f:
            data = bytearray(f.read())

        me_start, me_end, me_gen = self._find_me_region(data)
        if me_start < 0:
            return MeCleanReport(
                status=MeCleanResult.NO_ME_REGION,
                messages=["No Intel ME region found in the image"],
            )

        me_version = self._get_me_version(data, me_start, me_end)
        me_type = self._get_me_type(me_version)
        original_size = me_end - me_start

        if self._is_already_clean(data, me_start, me_end):
            return MeCleanReport(
                status=MeCleanResult.ALREADY_CLEAN,
                me_version=me_version,
                me_type=me_type,
                generation=me_gen,
                original_size=original_size,
                cleaned_size=original_size,
                messages=["ME region appears to be already cleaned"],
            )

        try:
            me_version_major = int(me_version.split(".")[0]) if me_version else 0
        except (ValueError, IndexError):
            me_version_major = 0

        if me_version_major > self.MAX_SUPPORTED_ME_VERSION:
            return MeCleanReport(
                status=MeCleanResult.UNSUPPORTED_VERSION,
                me_version=me_version,
                me_type=me_type,
                generation=me_gen,
                messages=[f"ME version {me_version} not yet supported for cleaning"],
            )

        report = MeCleanReport(
            status=MeCleanResult.SUCCESS,
            me_version=me_version,
            me_type=me_type,
            generation=me_gen,
            original_size=original_size,
        )

        fpt_offset = self._find_fpt(data, me_start, me_end)
        if fpt_offset < 0:
            report.status = MeCleanResult.ERROR
            report.messages.append("Cannot find FPT (Firmware Partition Table)")
            return report

        entries = self._parse_fpt_entries(data, fpt_offset, me_start, me_end)
        if not entries:
            report.status = MeCleanResult.ERROR
            report.messages.append("No valid FPT entries found")
            return report

        ftpr_entry = None
        for name, offset, size in entries:
            if name == b"FTPR":
                ftpr_entry = (name, offset, size)
                break

        if ftpr_entry is None:
            report.status = MeCleanResult.ERROR
            report.messages.append("No FTPR partition found - cannot safely clean ME")
            return report

        partitions_removed = 0
        if remove_modules and me_gen in (MeGeneration.GEN2, MeGeneration.GEN3):
            partitions_removed = self._remove_non_essential_partitions(
                data, fpt_offset, entries, ftpr_entry
            )

        if soft_disable:
            self._set_hap_bit(data, me_start, me_end, me_gen, me_version_major)
            report.hap_bit_set = True
            report.soft_disable = True
            report.messages.append("HAP/AltMeDisable bit set for soft disable")

        if descriptor_lock:
            self._lock_me_descriptor(data, me_gen)
            report.messages.append("ME descriptor write access removed")

        if truncate and me_gen in (MeGeneration.GEN2, MeGeneration.GEN3):
            self._truncate_me(data, me_start, ftpr_entry)
            report.cleaned_size = len(data) - me_start
            report.messages.append(f"ME region truncated from {original_size:#x} to {report.cleaned_size:#x}")

        report.partitions_removed = partitions_removed
        report.messages.append(f"Removed {partitions_removed} non-essential partitions")
        report.messages.append(f"ME version: {me_version} ({me_type})")

        if output_path is None:
            output_path = input_path.rsplit(".", 1)[0] + "_cleaned.bin"

        with open(output_path, "wb") as f:
            f.write(data)

        report.output_path = output_path
        return report

    def _find_me_region(self, data: bytes) -> tuple[int, int, MeGeneration]:
        if data[:4] == b"$FPT" or data[0x10:0x14] == b"$FPT":
            me_start = 0x10 if data[0x10:0x14] == b"$FPT" else 0
            return me_start, len(data), MeGeneration.UNKNOWN

        if data[:4] != b"\x5a\xa5\xf0\x0f" and data[0x10:0x14] != b"\x5a\xa5\xf0\x0f":
            return -1, -1, MeGeneration.UNKNOWN

        fd_offset = 0 if data[:4] == b"\x5a\xa5\xf0\x0f" else 0x10
        flmap0 = struct.unpack_from("<I", data, fd_offset + 0x10)[0]
        frba = ((flmap0 >> 16) & 0xFF) << 4
        frba_abs = fd_offset + frba

        if frba_abs + 0x30 > len(data):
            return -1, -1, MeGeneration.UNKNOWN

        me_flreg = struct.unpack_from("<I", data, frba_abs + 0x10)[0]
        me_base = (me_flreg & 0x7FFF) << 12
        me_limit = ((me_flreg >> 16) & 0x7FFF) << 12 | 0xFFF

        if me_base >= me_limit or me_limit > len(data):
            return -1, -1, MeGeneration.UNKNOWN

        gen = self._detect_generation(data, me_base, me_limit)
        return me_base, me_limit + 1, gen

    def _detect_generation(self, data: bytes, me_start: int, me_end: int) -> MeGeneration:
        fpt_off = self._find_fpt(data, me_start, me_end)
        if fpt_off < 0:
            return MeGeneration.UNKNOWN

        try:
            entries = struct.unpack_from("<I", data, fpt_off + 0x04)[0]
        except struct.error:
            return MeGeneration.UNKNOWN

        if entries <= 0 or entries > 16:
            return MeGeneration.UNKNOWN

        for i in range(min(entries, 16)):
            entry_off = fpt_off + 0x20 + i * 0x20
            if entry_off + 0x20 > len(data):
                break
            entry_name = data[entry_off:entry_off + 4]
            if entry_name == b"FTPR":
                return MeGeneration.GEN3
            if entry_name == b"CODE":
                return MeGeneration.GEN2
            if entry_name == b"BRIN":
                return MeGeneration.GEN1
        return MeGeneration.GEN2

    def _find_fpt(self, data: bytes, start: int, end: int) -> int:
        for offset in range(start, min(end, start + 0x100), 0x10):
            if data[offset:offset + 4] == self.FPT_SIGNATURE:
                return offset
        return -1

    def _parse_fpt_entries(
        self, data: bytes, fpt_offset: int, me_start: int, me_end: int
    ) -> list[tuple[bytes, int, int]]:
        entries = []
        try:
            num_entries = struct.unpack_from("<I", data, fpt_offset + 0x04)[0]
        except struct.error:
            return entries

        for i in range(min(num_entries, 32)):
            entry_off = fpt_offset + 0x20 + i * 0x20
            if entry_off + 0x20 > len(data):
                break
            name = data[entry_off:entry_off + 4]
            offset, size = struct.unpack_from("<II", data, entry_off + 0x08)
            abs_offset = me_start + offset
            if abs_offset + size <= me_end:
                entries.append((name, abs_offset, size))
        return entries

    def _remove_non_essential_partitions(
        self,
        data: bytearray,
        fpt_offset: int,
        entries: list[tuple[bytes, int, int]],
        ftpr_entry: tuple,
    ) -> int:
        removed = 0
        for name, offset, size in entries:
            if name == b"FTPR" or name == b"EFFS":
                continue
            if name == b"FTPR":
                continue
            for i in range(min(offset, offset + size)):
                if offset + i < len(data):
                    data[offset + i] = 0xFF
            removed += 1
        return removed

    def _set_hap_bit(
        self,
        data: bytearray,
        me_start: int,
        me_end: int,
        gen: MeGeneration,
        me_version: int,
    ) -> None:
        fd_offset = self._find_fd_in_data(data)
        if fd_offset < 0:
            return

        try:
            flmap1 = struct.unpack_from("<I", data, fd_offset + 0x14)[0]
            fpsba = ((flmap1 >> 16) & 0xFF) << 4
            fpsba_abs = fd_offset + fpsba
        except struct.error:
            return

        if me_version >= 11:
            if fpsba_abs + 0x100 <= len(data):
                try:
                    pchstrp0 = struct.unpack_from("<I", data, fpsba_abs)[0]
                    pchstrp0 |= (1 << 16)
                    struct.pack_into("<I", data, fpsba_abs, pchstrp0)
                except struct.error:
                    pass
        else:
            if fpsba_abs + 0x30 <= len(data):
                try:
                    pchstrp10 = struct.unpack_from("<I", data, fpsba_abs + 0x28)[0]
                    pchstrp10 |= (1 << 7)
                    struct.pack_into("<I", data, fpsba_abs + 0x28, pchstrp10)
                except struct.error:
                    pass

    def _find_fd_in_data(self, data: bytes) -> int:
        if data[:4] == b"\x5a\xa5\xf0\x0f":
            return 0
        if len(data) >= 0x14 and data[0x10:0x14] == b"\x5a\xa5\xf0\x0f":
            return 0x10
        return -1

    def _lock_me_descriptor(self, data: bytearray, gen: MeGeneration) -> None:
        fd_offset = self._find_fd_in_data(data)
        if fd_offset < 0:
            return

        try:
            flmap1 = struct.unpack_from("<I", data, fd_offset + 0x14)[0]
            fmba = (flmap1 & 0xFF) << 4
            fmba_abs = fd_offset + fmba
        except struct.error:
            return

        if fmba_abs + 0x0C <= len(data):
            if gen == MeGeneration.GEN3:
                struct.pack_into("<I", data, fmba_abs + 0x04, 0x00400500)
            else:
                try:
                    flmstr2 = struct.unpack_from("<I", data, fmba_abs + 0x04)[0]
                    flmstr2 = (flmstr2 | 0x04040000) & 0x0404FFFF
                    struct.pack_into("<I", data, fmba_abs + 0x04, flmstr2)
                except struct.error:
                    pass

    def _truncate_me(
        self, data: bytearray, me_start: int, ftpr_entry: tuple
    ) -> None:
        _, _, size = ftpr_entry
        truncate_at = me_start + size + 0x1000
        truncate_at = (truncate_at // 0x1000) * 0x1000
        if truncate_at < len(data):
            del data[truncate_at:]

    def _is_already_clean(self, data: bytes, me_start: int, me_end: int) -> bool:
        fpt_off = self._find_fpt(data, me_start, me_end)
        if fpt_off < 0:
            return True

        non_ff_count = 0
        check_end = min(me_end, me_start + 0x10000)
        for i in range(me_start + 0x20, check_end):
            if data[i] != 0xFF:
                non_ff_count += 1
        return non_ff_count < 0x100

    def _get_me_version(self, data: bytes, me_start: int, me_end: int) -> str:
        search_end = min(me_end, me_start + 0x10000)
        for pattern in [b"$MN2", b"$FPT"]:
            idx = data.find(pattern, me_start, search_end)
            if idx >= 0 and idx + 0x14 <= len(data):
                try:
                    major, minor = struct.unpack_from("<HH", data, idx + 0x04)
                    if 0 < major < 100 and 0 <= minor < 100:
                        return f"{major}.{minor}"
                except struct.error:
                    pass
        return ""

    def _get_me_type(self, version: str) -> str:
        if not version:
            return "Unknown"
        try:
            major = int(version.split(".")[0])
        except (ValueError, IndexError):
            return "Unknown"
        if major <= 5:
            return "ME (Legacy)"
        elif major <= 10:
            return "ME"
        elif major <= 12:
            return "CSME"
        else:
            return f"CSME {major}"

    def get_me_info(self, file_path: str) -> dict:
        with open(file_path, "rb") as f:
            data = f.read()

        me_start, me_end, gen = self._find_me_region(data)
        if me_start < 0:
            return {"found": False}

        version = self._get_me_version(data, me_start, me_end)
        fpt_off = self._find_fpt(data, me_start, me_end)
        entries = self._parse_fpt_entries(data, fpt_off, me_start, me_end) if fpt_off >= 0 else []

        return {
            "found": True,
            "version": version,
            "type": self._get_me_type(version),
            "generation": gen.name,
            "offset": f"{me_start:#x}",
            "size": f"{me_end - me_start:#x}",
            "partitions": [
                {"name": n.decode("ascii", errors="replace"), "offset": f"{o:#x}", "size": f"{s:#x}"}
                for n, o, s in entries
            ],
        }
