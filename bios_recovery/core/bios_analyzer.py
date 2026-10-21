"""BIOS file analysis engine - parses and analyzes BIOS/UEFI firmware images."""

import struct
import hashlib
import os
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional


class BiosType(Enum):
    UNKNOWN = auto()
    INTEL_IFD = auto()
    AMI_APTIO = auto()
    PHOENIX = auto()
    AWARD = auto()
    INSYDE = auto()
    DELL_PFS = auto()
    APPLE_EFI = auto()
    COREBOOT = auto()
    AMI_CAPSULE = auto()
    UEFI_FV = auto()


class RegionType(Enum):
    UNKNOWN = auto()
    FLASH_DESCRIPTOR = auto()
    BIOS = auto()
    INTEL_ME = auto()
    TXE = auto()
    GBE = auto()
    PLATFORM_DATA = auto()
    EC = auto()
    NVRAM = auto()
    FIRMWARE_VOLUME = auto()


@dataclass
class RegionInfo:
    region_type: RegionType
    offset: int
    size: int
    name: str = ""
    version: str = ""
    details: dict = field(default_factory=dict)


@dataclass
class BiosAnalysisResult:
    file_path: str
    file_size: int
    md5: str
    sha256: str
    bios_type: BiosType
    regions: list[RegionInfo] = field(default_factory=list)
    me_version: str = ""
    me_type: str = ""
    board_vendor: str = ""
    board_name: str = ""
    bios_version: str = ""
    issues: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    raw_info: dict = field(default_factory=dict)

    @property
    def has_me_region(self) -> bool:
        return any(r.region_type in (RegionType.INTEL_ME, RegionType.TXE) for r in self.regions)

    @property
    def has_flash_descriptor(self) -> bool:
        return any(r.region_type == RegionType.FLASH_DESCRIPTOR for r in self.regions)

    @property
    def total_regions(self) -> int:
        return len(self.regions)


class BiosAnalyzer:
    """Analyzes BIOS/UEFI firmware images to detect type, regions, and issues."""

    FD_SIGNATURE = 0x0FF0A55A
    FPT_SIGNATURE = b"$FPT"
    FV_SIGNATURE = b"_FVH"
    DELL_PFS_SIGNATURE = b"PFS"
    AMI_APTIO_SIGNATURE = b"_AMI"

    def analyze(self, file_path: str) -> BiosAnalysisResult:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        with open(file_path, "rb") as f:
            data = f.read()

        file_size = len(data)
        md5 = hashlib.md5(data).hexdigest()
        sha256 = hashlib.sha256(data).hexdigest()

        bios_type = self._detect_type(data)
        regions = self._find_regions(data, bios_type)
        me_version = self._get_me_version(data, regions)
        me_type = self._get_me_type(data, regions)
        issues = self._find_issues(data, regions, bios_type)
        warnings = self._find_warnings(data, regions, bios_type)

        return BiosAnalysisResult(
            file_path=file_path,
            file_size=file_size,
            md5=md5,
            sha256=sha256,
            bios_type=bios_type,
            regions=regions,
            me_version=me_version,
            me_type=me_type,
            issues=issues,
            warnings=warnings,
        )

    def _detect_type(self, data: bytes) -> BiosType:
        if len(data) < 0x10:
            return BiosType.UNKNOWN

        if data[:4] == b"\x5a\xa5\xf0\x0f":
            return BiosType.INTEL_IFD
        if data[0x10:0x14] == b"\x5a\xa5\xf0\x0f":
            return BiosType.INTEL_IFD

        if self.DELL_PFS_SIGNATURE in data[:0x100]:
            return BiosType.DELL_PFS
        if self.AMI_APTIO_SIGNATURE in data[:0x200]:
            return BiosType.AMI_APTIO

        # AMI Aptio capsule (vendor BIOS update): GUID at offset 0
        from bios_recovery.manufacturers.common.bios_capsule import APTIO_CAPSULE_GUID_LE
        if data[:16] == APTIO_CAPSULE_GUID_LE:
            from bios_recovery.manufacturers.common.bios_capsule import detect_capsule
            if detect_capsule(data).success:
                return BiosType.AMI_CAPSULE

        if self.FPT_SIGNATURE in data[:0x20]:
            return BiosType.INTEL_IFD
        if self.FV_SIGNATURE in data[:0x100]:
            return BiosType.AMI_APTIO

        heuristic = self._heuristic_detect(data)
        if heuristic != BiosType.UNKNOWN:
            return heuristic

        # Vendor header not found, but the image still carries UEFI firmware
        # volumes (e.g. a full-SPI dump whose volumes start past the first
        # 0x100 bytes). Report the format rather than calling it unknown.
        volumes: list[RegionInfo] = []
        self._search_firmware_volumes(data, volumes)
        if volumes:
            return BiosType.UEFI_FV
        return BiosType.UNKNOWN

    def _heuristic_detect(self, data: bytes) -> BiosType:
        signatures = {
            b"Phoenix": BiosType.PHOENIX,
            b"AWARD": BiosType.AWARD,
            b"Insyde": BiosType.INSYDE,
            b"coreboot": BiosType.COREBOOT,
            b"APPLE": BiosType.APPLE_EFI,
        }
        for sig, btype in signatures.items():
            if sig in data[:0x1000]:
                return btype

        if b"Intel(R) Management Engine" in data:
            return BiosType.INTEL_IFD
        if b"BIOS" in data[:0x100]:
            return BiosType.AMI_APTIO

        return BiosType.UNKNOWN

    def _find_regions(self, data: bytes, bios_type: BiosType) -> list[RegionInfo]:
        if bios_type == BiosType.INTEL_IFD:
            regions = self._parse_intel_ifd(data)
            self._search_firmware_volumes(data, regions)
            self._add_derived_bios(regions)
            self._search_me_region(data, regions)
            return regions
        regions = []
        self._search_firmware_volumes(data, regions)
        self._add_derived_bios(regions)
        self._search_me_region(data, regions)
        return regions

    def _parse_intel_ifd(self, data: bytes) -> list[RegionInfo]:
        regions = []
        fd_offset = self._find_fd_offset(data)
        if fd_offset < 0:
            return regions

        regions.append(RegionInfo(
            region_type=RegionType.FLASH_DESCRIPTOR,
            offset=fd_offset,
            size=0x1000,
            name="Flash Descriptor",
        ))

        if fd_offset + 0x20 > len(data):
            return regions

        # FLMAP0 is the second dword of the descriptor (FLVALSIG is the first);
        # FRBA is bits 23:16 in 16-byte units, relative to the descriptor start.
        flmap0 = struct.unpack_from("<I", data, fd_offset + 0x04)[0]
        frba = ((flmap0 >> 16) & 0xFF) << 4
        frba_abs = fd_offset + frba

        if frba_abs + 0x14 > len(data):
            return regions

        region_defs = [
            (1, RegionType.BIOS, "BIOS"),
            (2, RegionType.INTEL_ME, "Intel ME"),
            (3, RegionType.GBE, "GbE"),
            (4, RegionType.PLATFORM_DATA, "Platform Data"),
        ]

        for idx, rtype, name in region_defs:
            off = frba_abs + idx * 4
            if off + 4 > len(data):
                break
            flreg = struct.unpack_from("<I", data, off)[0]
            base = (flreg & 0x7FFF) << 12
            limit = ((flreg >> 16) & 0x7FFF) << 12 | 0xFFF
            if base < limit and limit < len(data):
                regions.append(RegionInfo(
                    region_type=rtype,
                    offset=base,
                    size=limit - base + 1,
                    name=name,
                ))

        return regions

    def _find_fd_offset(self, data: bytes) -> int:
        if data[:4] == b"\x5a\xa5\xf0\x0f":
            return 0
        if len(data) >= 0x14 and data[0x10:0x14] == b"\x5a\xa5\xf0\x0f":
            return 0x10

        for offset in range(0, min(len(data), 0x10000), 0x10):
            if data[offset:offset + 4] == b"\x5a\xa5\xf0\x0f":
                return offset
        return -1

    def _search_firmware_volumes(self, data: bytes, regions: list[RegionInfo]) -> None:
        """Add one FIRMWARE_VOLUME region per validated top-level volume.

        A match counts only if the header checksum verifies and the volume lies
        inside the image. Matches nested in an already accepted volume are
        skipped, so stray "_FVH" bytes inside a volume are not reported.
        """
        accepted: list[tuple[int, int]] = []
        pos = 0
        while True:
            idx = data.find(self.FV_SIGNATURE, pos)
            if idx < 0:
                break
            pos = idx + len(self.FV_SIGNATURE)
            fv_start = idx - 0x28
            if fv_start < 0 or any(lo <= fv_start < hi for lo, hi in accepted):
                continue
            fv_len = self._valid_fv_length(data, fv_start)
            if not fv_len:
                continue
            accepted.append((fv_start, fv_start + fv_len))
            regions.append(RegionInfo(
                region_type=RegionType.FIRMWARE_VOLUME,
                offset=fv_start,
                size=fv_len,
                name=f"Firmware Volume @0x{fv_start:X}",
            ))

    @staticmethod
    def _valid_fv_length(data: bytes, fv_start: int) -> int:
        """Return the FvLength of a well-formed EFI_FIRMWARE_VOLUME_HEADER, else 0."""
        if fv_start + 0x48 > len(data):
            return 0
        fv_len = struct.unpack_from("<Q", data, fv_start + 0x20)[0]
        hdr_len = struct.unpack_from("<H", data, fv_start + 0x30)[0]
        if fv_len == 0 or hdr_len < 0x48 or hdr_len > fv_len:
            return 0
        if fv_start + fv_len > len(data) or fv_start + hdr_len > len(data):
            return 0
        words = struct.unpack_from(f"<{hdr_len // 2}H", data, fv_start)
        if sum(words) & 0xFFFF:
            return 0
        return fv_len

    @staticmethod
    def _add_derived_bios(regions: list[RegionInfo]) -> None:
        """If the descriptor does not advertise a BIOS region, span the volumes instead."""
        if any(r.region_type == RegionType.BIOS for r in regions):
            return
        volumes = [r for r in regions if r.region_type == RegionType.FIRMWARE_VOLUME]
        if not volumes:
            return
        start = min(r.offset for r in volumes)
        end = max(r.offset + r.size for r in volumes)
        regions.append(RegionInfo(
            region_type=RegionType.BIOS,
            offset=start,
            size=end - start,
            name="BIOS (span of firmware volumes)",
        ))

    def _search_me_region(self, data: bytes, regions: list[RegionInfo]) -> None:
        fpt_pos = data.find(self.FPT_SIGNATURE)
        if fpt_pos >= 0:
            has_me = any(r.region_type == RegionType.INTEL_ME for r in regions)
            if not has_me:
                regions.append(RegionInfo(
                    region_type=RegionType.INTEL_ME,
                    offset=fpt_pos,
                    size=len(data) - fpt_pos,
                    name="Intel ME (detected by FPT)",
                ))

    def _get_me_version(self, data: bytes, regions: list[RegionInfo]) -> str:
        me_regions = [r for r in regions if r.region_type in (RegionType.INTEL_ME, RegionType.TXE)]
        if not me_regions:
            return ""

        for me_r in me_regions:
            fpt_pos = data.find(self.FPT_SIGNATURE, me_r.offset)
            if fpt_pos < 0:
                continue

            if fpt_pos + 0x20 > len(data):
                continue

            entries = struct.unpack_from("<I", data, fpt_pos + 0x04)[0]
            if fpt_pos + 0x20 + entries * 0x20 > len(data):
                continue

            for i in range(entries):
                entry_off = fpt_pos + 0x20 + i * 0x20
                entry_name = data[entry_off:entry_off + 4]
                if entry_name in (b"FTPR", b"$MN2", b"ME  "):
                    version = self._decode_me_version(data, me_r)
                    if version:
                        return version
        return self._manifest_me_version(data)

    @staticmethod
    def _manifest_me_version(data: bytes) -> str:
        """Most common version among the ME/CSME manifests in the image (FPT not decodable)."""
        from collections import Counter
        from bios_recovery.core.me_manifest import iter_manifest_versions
        versions = Counter(v for v, _base in iter_manifest_versions(data))
        return versions.most_common(1)[0][0] if versions else ""

    def _decode_me_version(self, data: bytes, me_region: RegionInfo) -> str:
        from bios_recovery.utils.me_manifest import detect_me_version_best

        search_end = min(me_region.offset + me_region.size, len(data))
        region = data[me_region.offset:search_end]
        return detect_me_version_best(region)

    def _get_me_type(self, data: bytes, regions: list[RegionInfo]) -> str:
        version = self._get_me_version(data, regions)
        if not version:
            return ""
        try:
            major = int(version.split(".")[0])
        except (ValueError, IndexError):
            return ""
        if major <= 5:
            return "ME (Legacy)"
        elif major <= 10:
            return "ME"
        elif major <= 12:
            return "CSME"
        return f"CSME {major}"

    def _find_issues(self, data: bytes, regions: list[RegionInfo], bios_type: BiosType) -> list[str]:
        issues = []
        if not regions:
            issues.append("No recognizable firmware regions found")

        fd_region = [r for r in regions if r.region_type == RegionType.FLASH_DESCRIPTOR]
        if fd_region and fd_region[0].offset not in (0, 0x10):
            issues.append(f"Flash Descriptor at unusual offset 0x{fd_region[0].offset:X}")

        me_regions = [r for r in regions if r.region_type == RegionType.INTEL_ME]
        for me_r in me_regions:
            if me_r.size < 0x10000:
                issues.append(f"Intel ME region suspiciously small ({me_r.size:#x} bytes)")

        if len(data) % 0x1000 != 0 and not self._padding_after_chip(data):
            issues.append(f"File size ({len(data)} bytes) not aligned to 4KB boundary")

        fpt_headers = self._fpt_headers(data)
        if len(fpt_headers) > 1:
            issues.append(
                f"Conflicting FPT headers found ({len(fpt_headers)} different) - possible dual-ME or corruption")

        if bios_type == BiosType.UNKNOWN:
            issues.append("Could not identify BIOS type - file may be corrupt or unsupported format")

        return issues

    @staticmethod
    def _padding_after_chip(data: bytes) -> int:
        """Length of 0xFF padding past the largest power-of-two chip size, else 0.

        Dumpers that over-read add a few erased bytes after the real chip image.
        Anything other than 0xFF beyond that size is not padding.
        """
        if not data:
            return 0
        chip = 1 << (len(data).bit_length() - 1)
        tail = data[chip:]
        if tail and not tail.strip(b"\xff"):
            return len(tail)
        return 0

    def _fpt_positions(self, data: bytes) -> list[int]:
        """Offsets of FPT headers with a plausible entry count.

        "$FPT" also occurs by chance in other data; a real partition table has
        a small entry count (a few to a few dozen), random matches do not.
        """
        positions = []
        pos = data.find(self.FPT_SIGNATURE)
        while pos >= 0:
            if pos + 8 <= len(data):
                entries = struct.unpack_from("<I", data, pos + 4)[0]
                if 0 < entries <= 0x80:
                    positions.append(pos)
            pos = data.find(self.FPT_SIGNATURE, pos + 1)
        return positions

    def _fpt_headers(self, data: bytes) -> set[bytes]:
        """Distinct FPT header blocks in the image (identical copies count once)."""
        return {bytes(data[p:p + 0x20]) for p in self._fpt_positions(data)}

    def _find_warnings(self, data: bytes, regions: list[RegionInfo], bios_type: BiosType) -> list[str]:
        warnings = []
        padding = self._padding_after_chip(data)
        if padding and len(data) % 0x1000:
            chip = len(data) - padding
            warnings.append(
                f"{padding} bytes past the 0x{chip:X} chip image are 0xFF padding (dumper over-read); not an error")
        copies = len(self._fpt_positions(data))
        if copies > 1 and len(self._fpt_headers(data)) == 1:
            warnings.append(f"FPT header appears {copies} times with identical content (duplicate copy)")
        if len(data) < 0x10000:
            warnings.append("File is smaller than 64KB - may be an incomplete dump")
        fd_region = [r for r in regions if r.region_type == RegionType.FLASH_DESCRIPTOR]
        if fd_region and fd_region[0].offset == 0x10:
            warnings.append("Flash Descriptor at 0x10: a 16-byte header precedes the chip image (not an error)")

        if len(data) > 0x2000000:
            warnings.append(f"File is {len(data) / 0x100000:.1f} MB - unusually large for a BIOS image")

        non_standard = [r for r in regions if r.region_type == RegionType.UNKNOWN]
        if non_standard:
            warnings.append(f"{len(non_standard)} unrecognized region(s) found")

        return warnings

    def get_hex_view(self, file_path: str, offset: int = 0, length: int = 256) -> bytes:
        with open(file_path, "rb") as f:
            f.seek(offset)
            return f.read(length)
