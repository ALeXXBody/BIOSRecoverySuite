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
        entries = self._parse_fpt_entries(data, fpt_offset, me_start, me_end) if fpt_offset >= 0 else []

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
            if b"$CPD" in data[me_start:exp_end]:
                if soft_disable:
                    self._set_hap_bit(data, me_start, me_end, me_gen, me_version_major)
                    report.hap_bit_set = True
                    report.soft_disable = True
                    report.messages.append(
                        "CSME 11+ 'CSE LT' layout detected (engine manifest in $CPD, "
                        "not listed in FPT): partition cleaning is not applicable. "
                        "HAP/AltMeDisable bit set instead."
                    )
                else:
                    report.status = MeCleanResult.ERROR
                    report.messages.append(
                        "CSE LT layout cannot be partition-cleaned; no action taken"
                    )
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
                partitions_removed = self._remove_non_essential_partitions(
                    data, fpt_offset, entries, ftpr_entry
                )
            report.partitions_removed = partitions_removed
            report.messages.append(f"Removed {partitions_removed} non-essential partitions")

        if soft_disable and ftpr_entry is not None:
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

        report.partitions_removed = report.partitions_removed or 0
        report.messages.append(f"ME version: {me_version} ({me_type})")

        if output_path is None:
            output_path = input_path.rsplit(".", 1)[0] + "_cleaned.bin"

        with open(output_path, "wb") as f:
            f.write(data)

        report.output_path = output_path
        return report

    def _find_me_region(self, data: bytes) -> tuple[int, int, MeGeneration]:
        N = len(data)
        # (a) Standalone ME/TXE region image: $FPT at 0x00 or 0x10
        if data[0x10:0x14] == b"$FPT":
            me_start = 0x10
            gen = self._detect_generation(data, me_start, N)  # whole file is the region
            return me_start, N, gen
        if data[:4] == b"$FPT":
            gen = self._detect_generation(data, 0, N)
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
            result = self._me_region_from_legacy_flmap(data, fd)
            if result is not None:
                return result

        # (d) Descriptor present but FLREG unusable: fall back to the FPT scan
        fpt = self._scan_fpt_first(data)
        if fpt >= 0:
            me_start = max(0, fpt - 0x10)
            me_end = self._fpt_region_end(data, fpt)
            if me_end > me_start:
                gen = self._detect_generation(data, me_start, me_end)
                return me_start, me_end, gen

        # (e) No descriptor at all, but a valid FPT somewhere (raw ME region dump)
        return -1, -1, MeGeneration.UNKNOWN

    def _me_region_from_flreg(self, data: bytes, fd: int) -> Optional[tuple[int, int, MeGeneration]]:
        """Modern 0x5AA5F00F descriptor: FLREG table at fd+0x30, ME FLREG at fd+0x38.

        Layout per Intel PCH spec / MEAnalyzer: FLREG base = region start in 4KB pages
        relative to the descriptor magic; limit = (region_end_page - 1) in the same units.
        """
        N = len(data)
        if fd + 0x3C > N:
            return None
        me_flreg = struct.unpack_from("<I", data, fd + 0x38)[0]
        base = me_flreg & 0x7FFF
        limit = (me_flreg >> 16) & 0x7FFF
        if limit == 0 or base > limit:
            return None
        me_start = fd + base * 0x1000
        me_end = min(fd + (limit + 1) * 0x1000, N)
        if me_start >= me_end:
            return None
        if not self._has_region_content(data, me_start, me_end):
            return None
        gen = self._detect_generation(data, me_start, me_end)
        return me_start, me_end, gen

    def _me_region_from_legacy_flmap(
        self, data: bytes, fd: int
    ) -> Optional[tuple[int, int, MeGeneration]]:
        """Legacy/alternate descriptor layout (FLMAP0 at fd+0x10, ME FLREG at frba+0x10)."""
        N = len(data)
        if fd + 0x14 > N:
            return None
        flmap0 = struct.unpack_from("<I", data, fd + 0x10)[0]
        if flmap0 in (0, 0xFFFFFFFF):
            return None
        frba_abs = fd + ((flmap0 >> 16) & 0xFF) * 0x10
        if frba_abs + 0x14 > N:
            return None
        me_flreg = struct.unpack_from("<I", data, frba_abs + 0x10)[0]
        base = me_flreg & 0x7FFF
        limit = (me_flreg >> 16) & 0x7FFF
        if limit == 0 or base > limit:
            return None
        me_start = fd + base * 0x1000
        me_end = min(fd + (limit + 1) * 0x1000, N)
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
            if data[pos:pos + 4] == self.FPT_SIGNATURE:
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
            if data[pos:pos + 4] == self.FPT_SIGNATURE:
                count = struct.unpack_from("<I", data, pos + 0x04)[0]
                if 1 <= count <= 64 and pos + 0x20 + count * 0x20 <= N:
                    return pos
                pos += 4
            else:
                nxt = data.find(self.FPT_SIGNATURE, pos + 4)
                pos = nxt if nxt >= 0 else N
        return -1

    def _fpt_region_end(self, data: bytes, fpt_off: int) -> int:
        """Best-effort end of the region that owns the FPT at fpt_off."""
        entries = struct.unpack_from("<I", data, fpt_off + 0x04)[0]
        end = fpt_off + 0x20 + entries * 0x20
        for i in range(min(entries, 64)):
            off = fpt_off + 0x20 + i * 0x20
            name, offset, size = data[off:off + 4], *struct.unpack_from("<II", data, off + 0x08)
            if name == b"FTPR" and size != 0xFFFFFFFF:
                rel_end = fpt_off - 0x10 + offset + size
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
                entry_name = data[entry_off:entry_off + 4]
                entry_off_v, _ = struct.unpack_from("<II", data, entry_off + 0x08)
                if entry_name in (b"CODE", b"NFTP", b"BRIN"):
                    return MeGeneration.GEN2 if entry_name != b"BRIN" else MeGeneration.GEN1
                if entry_name == b"FTPR":
                    abs_off = me_start + entry_off_v
                    if abs_off + 4 <= len(data):
                        tag = data[abs_off:abs_off + 4]
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

        flmap1 = self._read_flmap1(data, fd_offset)
        if flmap1 is None:
            return
        fpsba = (flmap1 >> 12) & 0xFF0
        fpsba_abs = fd_offset + fpsba

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

    def _read_flmap1(self, data: bytes, fd_offset: int) -> Optional[int]:
        """FLMAP1 is at fd+0x08 on real images (magic at 0x00 or 0x10).

        Older synthetic layouts stored it at fd+0x14; accept that as fallback.
        """
        n = len(data)
        for off in (0x08, 0x14):
            if fd_offset + off + 4 <= n:
                v = struct.unpack_from("<I", data, fd_offset + off)[0]
                if v not in (0, 0xFFFFFFFF):
                    return v
        return None

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

        flmap1 = self._read_flmap1(data, fd_offset)
        if flmap1 is None:
            return
        fmba = (flmap1 & 0xFF) * 0x10
        fmba_abs = fd_offset + fmba

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
        """Read the ME version from a `$MN2`/`$MAN` partition manifest.

        Manifest layout (gen1-3): tag at manifest+0x1C, version fields (u16 major,
        minor, hotfix, build) at manifest+0x24 — i.e. tag+0x08.
        """
        n = len(data)
        exp_end = min(me_end, me_start + 0x1000000)
        for tag in (b"$MN2", b"$MAN"):
            pos = me_start
            while pos < exp_end:
                idx = data.find(tag, pos, exp_end)
                if idx < 0:
                    break
                base = idx - 0x1C
                if base >= 0 and base + 0x2C <= n:
                    major, minor, hotfix, build = struct.unpack_from(
                        "<HHHH", data, base + 0x24
                    )
                    if 0 < major < 100 and minor < 200 and build < 100000:
                        return f"{major}.{minor}.{hotfix}.{build}"
                pos = idx + 4
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
            "type": self._get_me_type(version),
            "generation": gen.name,
            "offset": f"{me_start:#x}",
            "size": f"{me_end - me_start:#x}",
            "partitions": [
                {"name": n.decode("ascii", errors="replace"), "offset": f"{o:#x}", "size": f"{s:#x}"}
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
            data[o:o + 0x10000]
            for o in range(0, min(len(data), 0x2000000), max(1, len(data) // 8))
        ][:8]
        samples = [s for s in samples if s]
        if not samples:
            return False
        high = sum(1 for s in samples if entropy(s) > 7.9)
        return high == len(samples)
