"""Intel ME/TXE/CSME cleaning engine - strips and neuters management firmware."""

import os
import struct
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional

from bios_recovery.core.me_manifest import engine_is_txe, engine_version
from bios_recovery.core.safety import SameFileError, ensure_distinct


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
    FPT_HEADER_VERSION = 0x20
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
    }

    def clean(
        self,
        input_path: str,
        output_path: Optional[str] = None,
        soft_disable: bool = True,
        truncate: bool = False,
        remove_modules: bool = True,
        descriptor_lock: bool = False,
    ) -> MeCleanReport:
        if not os.path.isfile(input_path):
            return MeCleanReport(
                status=MeCleanResult.ERROR,
                messages=[f"File not found: {input_path}"],
            )
        try:
            ensure_distinct(input_path, output_path)
        except SameFileError as exc:
            return MeCleanReport(status=MeCleanResult.ERROR, messages=[str(exc)])

        with open(input_path, "rb") as f:
            data = bytearray(f.read())
        original_len = len(data)

        fd = self._find_fd_in_data(data)
        declared = self._declared_me_span(data, fd) if fd >= 0 else None
        if declared is not None and declared[1] > len(data):
            return MeCleanReport(
                status=MeCleanResult.ERROR,
                messages=[
                    f"ME region declared by the flash descriptor ends at {declared[1]:#x}, past "
                    f"the end of the {len(data):#x}-byte image (truncated dump?); refusing to "
                    "modify a partial region"
                ],
            )

        me_start, me_end, me_gen = self._find_me_region(data)
        if me_start < 0:
            return MeCleanReport(
                status=MeCleanResult.NO_ME_REGION,
                messages=["No Intel ME region found in the image"],
            )

        if truncate and self._find_fd_in_data(data) >= 0:
            # Cutting a full flash image drops every region after the ME region, including
            # the BIOS. Truncation is only meaningful for a standalone ME image.
            return MeCleanReport(
                status=MeCleanResult.ERROR,
                messages=[
                    "Truncation refused: this is a full flash image with a flash descriptor, "
                    "and cutting it would remove the BIOS region. Truncation applies only to "
                    "standalone ME images."
                ],
            )

        # The manifest may sit in the 4 KB block just before the partition base (CSME 15 layouts).
        me_version = self._get_me_version(data, max(0, me_start - 0x1000), me_end)
        if not me_version:
            # Same reader the analyzer uses, so the two tools cannot disagree on the version.
            from bios_recovery.core.bios_analyzer import BiosAnalyzer

            me_version = BiosAnalyzer().analyze(input_path).me_version
        me_type = self._get_me_type(me_version, data[me_start:me_end])
        original_size = me_end - me_start

        if not me_version:
            return MeCleanReport(
                status=MeCleanResult.UNSUPPORTED_VERSION,
                me_type=me_type,
                generation=me_gen,
                messages=["ME version could not be read; refusing to modify this region"],
            )

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
        entries = (
            self._parse_fpt_entries(data, fpt_offset, me_start, me_end) if fpt_offset >= 0 else []
        )

        ftpr_entry = None
        for name, offset, size in entries:
            if name == b"FTPR":
                ftpr_entry = (name, offset, size)
                break

        if ftpr_entry is None:
            # CSME 11+ "CSE LT" layouts (Comet Lake / Tiger Lake+) use a $CPD
            # manifest structure instead of an FPT-listed FTPR. Partition-level
            # cleaning is not meaningful there; HAP soft-disable still applies.
            exp_end = min(me_end, len(data))
            # The $CPD manifest of a CSE LT layout may sit in the block before the partition base.
            if b"$CPD" in data[max(0, me_start - 0x1000) : exp_end]:
                if soft_disable:
                    if self._set_hap_bit(data, me_start, me_end, me_gen, me_version_major):
                        report.hap_bit_set = True
                        report.soft_disable = True
                        report.messages.append(
                            "CSME 11+ 'CSE LT' layout detected (engine manifest in $CPD, "
                            "not listed in FPT): partition cleaning is not applicable. "
                            "HAP/AltMeDisable bit set instead."
                        )
                    else:
                        report.messages.append(
                            "CSME 11+ 'CSE LT' layout detected: the HAP/AltMeDisable bit could "
                            "not be set (strap register not reachable); nothing soft-disabled"
                        )
                else:
                    report.status = MeCleanResult.ERROR
                    report.messages.append(
                        "CSE LT layout cannot be partition-cleaned; no action taken"
                    )
                    return report
            else:
                report.status = MeCleanResult.ERROR
                if not entries:
                    report.messages.append("No valid FPT entries found")
                else:
                    report.messages.append("No FTPR partition found - cannot safely clean ME")
                return report
        else:
            partitions_removed = 0
            if remove_modules and me_gen in (MeGeneration.GEN2, MeGeneration.GEN3):
                if data[fpt_offset + 0x08] != self.FPT_HEADER_VERSION:
                    report.messages.append(
                        f"Partition removal skipped: FPT header version "
                        f"{data[fpt_offset + 0x08]:#x} is not supported, so the partition "
                        "table cannot be updated safely"
                    )
                else:
                    partitions_removed = self._remove_non_essential_partitions(
                        data, fpt_offset, entries, ftpr_entry, me_start
                    )
            report.partitions_removed = partitions_removed
            report.messages.append(f"Removed {partitions_removed} non-essential partitions")

        if soft_disable and ftpr_entry is not None:
            if self._set_hap_bit(data, me_start, me_end, me_gen, me_version_major):
                report.hap_bit_set = True
                report.soft_disable = True
                report.messages.append("HAP/AltMeDisable bit set for soft disable (read back)")
            else:
                report.messages.append(
                    "HAP/AltMeDisable bit could not be set (flash descriptor not reachable); "
                    "no soft disable applied"
                )

        if descriptor_lock:
            if self._lock_me_descriptor(data, me_gen):
                report.messages.append("ME descriptor write access removed (read back)")
            else:
                report.messages.append(
                    "ME descriptor lock could not be applied (flash descriptor not reachable)"
                )

        if truncate and me_gen in (MeGeneration.GEN2, MeGeneration.GEN3) and ftpr_entry is not None:
            self._truncate_me(data, me_start, entries, ftpr_entry)
            report.cleaned_size = len(data) - me_start
            report.messages.append(
                f"ME region truncated from {original_size:#x} to {report.cleaned_size:#x}"
            )
        elif truncate:
            report.messages.append("Truncation skipped: no FTPR partition to bound the region")

        report.partitions_removed = report.partitions_removed or 0
        report.messages.append(f"ME version: {me_version} ({me_type})")

        if fd >= 0 and len(data) != original_len:
            return MeCleanReport(
                status=MeCleanResult.ERROR,
                messages=["A full flash image changed size; nothing written"],
            )

        if output_path is None:
            output_path = input_path.rsplit(".", 1)[0] + "_cleaned.bin"

        with open(output_path, "wb") as f:
            f.write(data)

        report.output_path = output_path
        return report

    def _find_me_region(self, data: bytes) -> tuple[int, int, MeGeneration]:
        N = len(data)
        # (a) Standalone ME/TXE region image: $FPT at 0x00 or 0x10. The region base is 0 in
        # both cases; a table at 0x10 is a header offset inside the region (me_cleaner).
        if data[:4] == b"$FPT" or data[0x10:0x14] == b"$FPT":
            gen = self._detect_generation(data, 0, N)  # whole file is the region
            return 0, N, gen

        # (b) Standalone ME/TXE update image ($MN2/$MAN near the start)
        update_tags = (b"$MN2", b"$MAN")
        head = data[:0x40]
        if any(t in head for t in update_tags):
            return 0, N, MeGeneration.UNKNOWN

        # (c) Full flash image with descriptor: read ME FLREG properly
        fd = self._find_fd_in_data(data)
        if fd >= 0:
            result = self._me_region_from_flreg(data, fd)
            if result is not None:
                return result

        # (d) Descriptor present but FLREG unusable: fall back to the FPT scan
        fpt = self._scan_fpt_first(data)
        if fpt >= 0:
            me_start = max(0, fpt & ~0xFFF)
            me_end = self._partition_extent(data, fpt, me_start)
            if me_end > me_start:
                gen = self._detect_generation(data, me_start, me_end)
                return me_start, me_end, gen

        # (e) No descriptor at all, but a valid FPT somewhere (raw ME region dump)
        return -1, -1, MeGeneration.UNKNOWN

    def _declared_me_span(self, data: bytes, fd: int) -> Optional[tuple[int, int]]:
        """(start, end) of the ME region from the descriptor's FLREG2, end not clamped to the file.

        FLMAP0 (fd+0x04) gives FRBA in 16-byte units from the start of the image (ifdtool
        find_frba); the FLREG table is at FRBA and ME is its third entry (FRBA+8). Base and
        limit are 4 KB pages from the start of the image.
        """
        N = len(data)
        if fd + 0x08 > N:
            return None
        flmap0 = struct.unpack_from("<I", data, fd + 0x04)[0]
        frba_abs = ((flmap0 >> 16) & 0xFF) * 0x10
        if frba_abs + 0x0C > N:
            return None
        me_flreg = struct.unpack_from("<I", data, frba_abs + 0x08)[0]
        base = me_flreg & 0x7FFF
        limit = (me_flreg >> 16) & 0x7FFF
        if limit == 0 or base > limit:
            return None
        return base * 0x1000, (limit + 1) * 0x1000

    def _me_region_from_flreg(
        self, data: bytes, fd: int
    ) -> Optional[tuple[int, int, MeGeneration]]:
        """ME region from the descriptor's FLREG2 entry, clamped to the image."""
        span = self._declared_me_span(data, fd)
        if span is None:
            return None
        me_start, me_end = span[0], min(span[1], len(data))
        if me_start >= me_end:
            return None
        if not self._has_region_content(data, me_start, me_end):
            return None
        gen = self._detect_generation(data, me_start, me_end)
        return me_start, me_end, gen

    @staticmethod
    def _has_region_content(data: bytes, start: int, end: int) -> bool:
        """Reject decoded regions that are entirely padding (0xFF)."""
        probe_end = min(end, start + 0x1000)
        return any(b != 0xFF for b in data[start:probe_end])

    def _find_fpt(self, data: bytes, start: int, end: int) -> int:
        """Scan the [start, end) region for the first structurally valid $FPT."""
        N = min(end, len(data))
        pos = max(start, 0)
        if pos + 0x24 > N:
            return -1
        while pos + 0x24 <= N:
            if data[pos : pos + 4] == self.FPT_SIGNATURE:
                count = struct.unpack_from("<I", data, pos + 0x04)[0]
                if 1 <= count <= 64 and pos + 0x20 + count * 0x20 <= N:
                    return pos
                pos += 4
            else:
                nxt = data.find(self.FPT_SIGNATURE, pos + 4, N)
                pos = nxt if nxt >= 0 else N
        return -1

    def _scan_fpt_first(self, data: bytes) -> int:
        """Locate the first structurally valid $FPT header anywhere in the image."""
        N = len(data)
        pos = 0
        while pos + 0x24 <= N:
            if data[pos : pos + 4] == self.FPT_SIGNATURE:
                count = struct.unpack_from("<I", data, pos + 0x04)[0]
                if 1 <= count <= 64 and pos + 0x20 + count * 0x20 <= N:
                    return pos
                pos += 4
            else:
                nxt = data.find(self.FPT_SIGNATURE, pos + 4)
                pos = nxt if nxt >= 0 else N
        return -1

    def _partition_extent(self, data: bytes, fpt_off: int, base: int) -> int:
        """End of the ME region: the furthest end of any partition the table lists.

        Partition offsets are relative to the ME base (the 4 KB boundary at or below
        the table). Falls back to the table's own end when no partition is usable.
        """
        end = 0
        n = (
            min(struct.unpack_from("<I", data, fpt_off + 0x04)[0], 32)
            if fpt_off + 8 <= len(data)
            else 0
        )
        for i in range(n):
            e = fpt_off + 0x20 + i * 0x20
            if e + 0x10 > len(data):
                break
            off, size = struct.unpack_from("<II", data, e + 0x08)
            if off in (0, 0xFFFFFFFF) or size in (0, 0xFFFFFFFF):
                continue
            end = max(end, base + off + size)
        if end and end <= len(data):
            return end
        return self._fpt_region_end(data, fpt_off, base)

    def _fpt_region_end(self, data: bytes, fpt_off: int, base: int) -> int:
        """Best-effort end of the region that owns the FPT at fpt_off (same base as above)."""
        entries = struct.unpack_from("<I", data, fpt_off + 0x04)[0]
        end = fpt_off + 0x20 + entries * 0x20
        for i in range(min(entries, 64)):
            off = fpt_off + 0x20 + i * 0x20
            name, offset, size = data[off : off + 4], *struct.unpack_from("<II", data, off + 0x08)
            if name == b"FTPR" and size != 0xFFFFFFFF:
                rel_end = base + offset + size
                end = max(end, min(rel_end, len(data)))
        return end

    def _detect_generation(self, data: bytes, me_start: int, me_end: int) -> MeGeneration:
        exp_end = min(me_end, me_start + 0x100000)
        region = data[me_start:exp_end]
        # Modern CSME 11+ (CSE LT) puts a $CPD code-partition directory in the region:
        # gen1 uses $MAN manifests / BRIN partitions, gen2 (ME 6..9.x) uses $MN2 only.
        if b"$CPD" in region:
            return MeGeneration.GEN3
        fpt_off = self._find_fpt(data, me_start, me_end)
        if fpt_off >= 0:
            try:
                entries = struct.unpack_from("<I", data, fpt_off + 0x04)[0]
            except struct.error:
                return MeGeneration.UNKNOWN

            if entries <= 0 or entries > 64:
                return MeGeneration.UNKNOWN

            count = min(entries, 32)
            for i in range(count):
                entry_off = fpt_off + 0x20 + i * 0x20
                if entry_off + 0x20 > len(data):
                    break
                entry_name = data[entry_off : entry_off + 4]
                entry_off_v, _ = struct.unpack_from("<II", data, entry_off + 0x08)
                if entry_name in (b"CODE", b"BRIN"):
                    return MeGeneration.GEN1
                if entry_name == b"NFTP":
                    return MeGeneration.GEN2
                if entry_name == b"FTPR":
                    abs_off = me_start + entry_off_v
                    if abs_off + 4 <= len(data):
                        tag = data[abs_off : abs_off + 4]
                        if tag == b"$CPD":
                            return MeGeneration.GEN3
                        if tag == b"$MN2":
                            return MeGeneration.GEN2
                        if tag == b"$MAN":
                            return MeGeneration.GEN1
        if b"$MN2" in region or b"$MAN" in region:
            return MeGeneration.GEN2
        return MeGeneration.UNKNOWN

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
            name = bytes(data[entry_off : entry_off + 4])
            offset, size = struct.unpack_from("<II", data, entry_off + 0x08)
            # Zero offset or size means no data (me_cleaner skips these too); offset 0 would
            # otherwise erase the partition table itself.
            if offset == 0 or size == 0:
                continue
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
        me_start: int = 0,
    ) -> int:
        """Erase the removable partitions and drop their table entries. Returns the count."""
        removed = []
        ftpr_name, ftpr_off, ftpr_size = ftpr_entry
        ftpr_end = ftpr_off + ftpr_size
        table_count = min(struct.unpack_from("<I", data, fpt_offset + 0x04)[0], 64)
        table_end = fpt_offset + self.FPT_ENTRY_SIZE * (table_count + 1)
        for name, offset, size in entries:
            if name in (b"FTPR", b"EFFS"):
                continue
            # A partition that overlaps FTPR is never touched.
            if offset < ftpr_end and offset + size > ftpr_off:
                continue
            # Nor is anything that overlaps the partition table itself.
            if offset < table_end:
                continue
            end = min(offset + size, len(data))
            data[offset:end] = b"\xff" * (end - offset)
            removed.append((name, offset, size))
        self._drop_fpt_entries(data, fpt_offset, me_start, removed)
        return len(removed)

    def _drop_fpt_entries(
        self,
        data: bytearray,
        fpt_offset: int,
        me_start: int,
        erased: list[tuple[bytes, int, int]],
    ) -> None:
        """Remove the table entries of erased partitions, then fix the count and header checksum.

        Entries stay in their original order. The checksum is the two's complement of the
        header sum with the checksum byte (fpt+0x0B) zeroed (me_cleaner; MEAnalyzer FPT_Header).
        """
        if not erased:
            return
        count = min(struct.unpack_from("<I", data, fpt_offset + 0x04)[0], 64)
        table = fpt_offset + self.FPT_ENTRY_SIZE
        records = [bytes(data[table + i * 0x20 : table + (i + 1) * 0x20]) for i in range(count)]
        gone = set(erased)
        kept = []
        for rec in records:
            name = rec[0:4]
            offset, size = struct.unpack_from("<II", rec, 0x08)
            if (name, me_start + offset, size) not in gone:
                kept.append(rec)
        data[table : table + count * 0x20] = b"".join(kept) + b"\xff" * ((count - len(kept)) * 0x20)
        struct.pack_into("<I", data, fpt_offset + 0x04, len(kept))
        header = bytearray(data[fpt_offset : fpt_offset + self.FPT_ENTRY_SIZE])
        header[0x0B] = 0
        data[fpt_offset + 0x0B] = (0x100 - sum(header)) & 0xFF

    def _set_hap_bit(
        self,
        data: bytearray,
        me_start: int,
        me_end: int,
        gen: MeGeneration,
        me_version: int,
    ) -> bool:
        """Set the HAP (ME 11+) or AltMeDisable (older) strap bit. Returns True only if the
        bit reads back set after the write."""
        fd_offset = self._find_fd_in_data(data)
        if fd_offset < 0:
            return False

        flmap1 = self._read_flmap1(data, fd_offset)
        if flmap1 is None:
            return False
        fpsba_abs = ((flmap1 >> 16) & 0xFF) << 4  # absolute file offset (ifdtool find_fpsba)

        if me_version >= 11:
            off, bit = fpsba_abs, 1 << 16
        else:
            off, bit = fpsba_abs + 0x28, 1 << 7
        if off + 4 > len(data):
            return False
        value = struct.unpack_from("<I", data, off)[0] | bit
        struct.pack_into("<I", data, off, value)
        return bool(struct.unpack_from("<I", data, off)[0] & bit)

    def _read_flmap1(self, data: bytes, fd_offset: int) -> Optional[int]:
        """FLMAP1 at fd+0x08 (ifdtool struct fdbar; me_cleaner reads it there). No fallback:
        an unset or unreadable FLMAP1 means the strap and master offsets are unknown."""
        if fd_offset + 0x0C > len(data):
            return None
        v = struct.unpack_from("<I", data, fd_offset + 0x08)[0]
        return None if v in (0, 0xFFFFFFFF) else v

    def _find_fd_in_data(self, data: bytes) -> int:
        if data[:4] == b"\x5a\xa5\xf0\x0f":
            return 0
        if len(data) >= 0x14 and data[0x10:0x14] == b"\x5a\xa5\xf0\x0f":
            return 0x10
        return -1

    def _lock_me_descriptor(self, data: bytearray, gen: MeGeneration) -> bool:
        """Write the ME master (FLMSTR2) entry. Returns True only if it reads back as written."""
        fd_offset = self._find_fd_in_data(data)
        if fd_offset < 0:
            return False

        flmap1 = self._read_flmap1(data, fd_offset)
        if flmap1 is None:
            return False
        fmba_abs = (flmap1 & 0xFF) * 0x10  # absolute file offset (ifdtool find_fmba)

        off = fmba_abs + 0x04  # FLMSTR2
        if off + 4 > len(data):
            return False
        if gen == MeGeneration.GEN3:
            expected = 0x00400500
        else:
            current = struct.unpack_from("<I", data, off)[0]
            expected = (current | 0x04040000) & 0x0404FFFF
        struct.pack_into("<I", data, off, expected)
        return struct.unpack_from("<I", data, off)[0] == expected

    def _truncate_me(
        self, data: bytearray, me_start: int, entries: list, ftpr_entry: tuple
    ) -> None:
        """Cut the image after the last partition that is kept (FTPR and EFFS)."""
        kept = [ftpr_entry] + [e for e in entries if e[0] == b"EFFS"]
        end = max(off + size for _name, off, size in kept)
        truncate_at = -(-end // 0x1000) * 0x1000
        if me_start < truncate_at < len(data):
            del data[truncate_at:]

    def _is_already_clean(self, data: bytes, me_start: int, me_end: int) -> bool:
        fpt_off = self._find_fpt(data, me_start, me_end)
        if fpt_off < 0:
            # Without a partition table, only an erased region counts as clean.
            region = bytes(data[me_start:me_end])
            return region.count(0xFF) == len(region)

        non_ff_count = 0
        check_end = min(me_end, me_start + 0x10000)
        for i in range(me_start + 0x20, check_end):
            if data[i] != 0xFF:
                non_ff_count += 1
        return non_ff_count < 0x100

    def _get_me_version(self, data: bytes, me_start: int, me_end: int) -> str:
        """Engine version: the most common valid `$MN2`/`$MAN` manifest version in the region.

        Manifest layout (gen1-3): tag at manifest+0x1C, version fields (u16 major,
        minor, hotfix, build) at manifest+0x24 — i.e. tag+0x08. Auxiliary modules carry
        their own manifests, so the first match is not necessarily the engine.
        """
        # Manifests of auxiliary modules sit past the table, so the window is wider than the region.
        exp_end = min(me_start + 0x1000000, len(data))
        return engine_version(bytes(data[me_start:exp_end]))

    def _get_me_type(self, version: str, region: bytes = b"") -> str:
        if not version:
            return "Unknown"
        if engine_is_txe(region):
            return "TXE"
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
        if not os.path.isfile(file_path):
            return {"found": False, "reason": f"Not a file: {file_path}"}
        with open(file_path, "rb") as f:
            data = f.read()

        me_start, me_end, gen = self._find_me_region(data)
        if me_start < 0:
            info = {"found": False}
            if self._looks_encrypted(data):
                info["reason"] = (
                    "This image appears to be fully encrypted (high-entropy data, "
                    "no firmware structure at all). This is typical of encrypted "
                    "vendor payloads such as Dell/HP update packages. ME analysis "
                    "is not possible on it; use a raw SPI flash dump instead."
                )
            return info

        version = self._get_me_version(data, me_start, me_end)
        fpt_off = self._find_fpt(data, me_start, me_end)
        entries = self._parse_fpt_entries(data, fpt_off, me_start, me_end) if fpt_off >= 0 else []

        return {
            "found": True,
            "version": version,
            "type": self._get_me_type(version, data[me_start:me_end]),
            "generation": gen.name,
            "offset": f"{me_start:#x}",
            "size": f"{me_end - me_start:#x}",
            "partitions": [
                {
                    "name": n.decode("ascii", errors="replace"),
                    "offset": f"{o:#x}",
                    "size": f"{s:#x}",
                }
                for n, o, s in entries
            ],
        }

    @staticmethod
    def _looks_encrypted(data: bytes, min_size: int = 0x40000) -> bool:
        """Heuristic: detect images that are almost entirely high-entropy cipher text.

        Real SPI dumps always contain plaintext structure somewhere (descriptor
        magic, FV headers, plaintext strings). Encrypted vendor payloads (e.g.
        Dell/HP BIOS update payloads) are uniformly random-looking.
        """
        if len(data) < min_size:
            return False
        import math
        from collections import Counter

        def entropy(block: bytes) -> float:
            c = Counter(block)
            n = len(block)
            return -sum((v / n) * math.log2(v / n) for v in c.values())

        samples = [
            data[o : o + 0x10000]
            for o in range(0, min(len(data), 0x2000000), max(1, len(data) // 8))
        ][:8]
        samples = [s for s in samples if s]
        if not samples:
            return False
        high = sum(1 for s in samples if entropy(s) > 7.9)
        return high == len(samples)
