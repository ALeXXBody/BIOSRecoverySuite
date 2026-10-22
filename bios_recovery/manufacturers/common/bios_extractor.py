"""BIOS extraction engine - extracts BIOS firmware from vendor executables."""

import os
import re
import struct
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional


class ExtractionMethod(Enum):
    AUTO = auto()
    DELL_PFS = auto()
    HP_INSIDE = auto()
    LENOVO_FL1 = auto()
    LENOVO_EXE = auto()
    ASUS_EXE = auto()
    ACER_EXE = auto()
    TOSHIBA_EXE = auto()
    TOSHIBA_COM = auto()
    SAMSUNG_EXE = auto()
    SONY_VAIO = auto()
    AMI_CAPSULE = auto()
    UNIVERSAL = auto()


@dataclass
class ExtractionResult:
    success: bool
    method_used: str = ""
    output_dir: str = ""
    files: list[dict] = field(default_factory=list)
    messages: list[str] = field(default_factory=list)
    bios_region_offset: int = 0
    bios_region_size: int = 0
    me_region_offset: int = 0
    me_region_size: int = 0
    ec_offset: int = 0
    ec_size: int = 0


class BiosExtractor:
    """Extracts BIOS firmware images from vendor executables and packages."""

    VENDOR_SIGNATURES = {
        b"Dell": "dell",
        b"Phoenix": "phoenix",
        b"Insyde": "insyde",
        b"AMI": "ami",
        b"Award": "award",
        b"Lenovo": "lenovo",
        b"ASUS": "asus",
        b"Acer": "acer",
        b"Toshiba": "toshiba",
        b"Samsung": "samsung",
        b"Sony": "sony",
        b"Fujitsu": "fujitsu",
        b"Panasonic": "panasonic",
    }

    FPT_SIGNATURE = b"$FPT"
    FV_SIGNATURE = b"_FVH"
    DELL_PFS_SIGNATURE = b"PFS"
    INTEL_FD_SIGNATURE = b"\x5a\xa5\xf0\x0f"
    LZMA_SIGNATURE = b"\x5d\x00\x00"
    PE_SIGNATURE = b"MZ"
    CAB_SIGNATURE = b"MSCF"

    def extract(
        self,
        input_path: str,
        output_dir: Optional[str] = None,
        method: ExtractionMethod = ExtractionMethod.AUTO,
    ) -> ExtractionResult:
        if not os.path.exists(input_path):
            return ExtractionResult(
                success=False,
                messages=[f"File not found: {input_path}"],
            )

        with open(input_path, "rb") as f:
            data = f.read()

        if output_dir is None:
            output_dir = input_path.rsplit(".", 1)[0] + "_extracted"
        os.makedirs(output_dir, exist_ok=True)

        if method == ExtractionMethod.AUTO:
            method = self._detect_method(data, input_path)

        handlers = {
            ExtractionMethod.DELL_PFS: self._extract_dell_pfs,
            ExtractionMethod.HP_INSIDE: self._extract_hp,
            ExtractionMethod.LENOVO_FL1: self._extract_lenovo,
            ExtractionMethod.LENOVO_EXE: self._extract_lenovo_exe,
            ExtractionMethod.ASUS_EXE: self._extract_asus,
            ExtractionMethod.ACER_EXE: self._extract_acer,
            ExtractionMethod.TOSHIBA_EXE: self._extract_toshiba,
            ExtractionMethod.SAMSUNG_EXE: self._extract_samsung,
            ExtractionMethod.SONY_VAIO: self._extract_sony,
            ExtractionMethod.AMI_CAPSULE: self._extract_ami_capsule,
            ExtractionMethod.UNIVERSAL: self._extract_universal,
        }

        handler = handlers.get(method, self._extract_universal)
        result = handler(data, output_dir, input_path)
        result.method_used = method.name

        if not result.files:
            result.messages.append("No firmware components found in the file")

        return result

    def _detect_method(self, data: bytes, file_path: str) -> ExtractionMethod:
        from bios_recovery.manufacturers.common.bios_capsule import is_aptio_capsule_guid

        # AMI Aptio vendor capsule (e.g. ASUS .308/.CAP updates): detect by GUID,
        # before any brand-keyword guess (which would miscategorize it).
        if is_aptio_capsule_guid(data):
            from bios_recovery.manufacturers.common.bios_capsule import detect_capsule

            if detect_capsule(data).success:
                return ExtractionMethod.AMI_CAPSULE

        if self._has_pfs_header(data):
            return ExtractionMethod.DELL_PFS

        if re.search(rb"\bHP\b|\bInsyde\b", data[:0x1000]):
            return ExtractionMethod.HP_INSIDE

        if b"Lenovo" in data[:0x1000] or b"FL1" in data[:0x1000]:
            if data[:2] == self.PE_SIGNATURE:
                return ExtractionMethod.LENOVO_EXE
            return ExtractionMethod.LENOVO_FL1

        if b"ASUS" in data[:0x1000]:
            return ExtractionMethod.ASUS_EXE

        if b"Acer" in data[:0x1000] or b"BIOS" in data[:0x200]:
            return ExtractionMethod.ACER_EXE

        if b"Toshiba" in data[:0x1000]:
            return ExtractionMethod.TOSHIBA_EXE

        if b"Samsung" in data[:0x1000]:
            return ExtractionMethod.SAMSUNG_EXE

        if b"Sony" in data[:0x1000] or b"VAIO" in data[:0x1000]:
            return ExtractionMethod.SONY_VAIO

        if self.FPT_SIGNATURE in data[:0x100]:
            return ExtractionMethod.UNIVERSAL
        if self.FV_SIGNATURE in data[:0x200]:
            return ExtractionMethod.UNIVERSAL
        if self.INTEL_FD_SIGNATURE in data[:0x20]:
            return ExtractionMethod.UNIVERSAL

        if data[:2] == self.PE_SIGNATURE:
            return self._detect_pe_method(data)

        return ExtractionMethod.UNIVERSAL

    def _detect_pe_method(self, data: bytes) -> ExtractionMethod:
        ascii_strings = self._extract_ascii_strings(data[:0x10000])
        text = " ".join(ascii_strings)

        if "dell" in text.lower():
            return ExtractionMethod.DELL_PFS
        if "lenovo" in text.lower():
            return ExtractionMethod.LENOVO_EXE
        if re.search(r"\b(hp|insyde)\b", text, re.IGNORECASE):
            return ExtractionMethod.HP_INSIDE
        if "asus" in text.lower():
            return ExtractionMethod.ASUS_EXE
        return ExtractionMethod.UNIVERSAL

    def _has_pfs_header(self, data: bytes) -> bool:
        """A PFS signature whose size field fits inside the file, not any stray 'PFS' text."""
        idx = data.find(self.DELL_PFS_SIGNATURE, 0, 0x1000)
        if idx < 0 or idx + 0x08 > len(data):
            return False
        size = struct.unpack_from("<I", data, idx + 0x04)[0]
        return 0x10 <= size and idx + size <= len(data)

    def _extract_dell_pfs(
        self, data: bytes, output_dir: str, original_path: str
    ) -> ExtractionResult:
        result = ExtractionResult(success=False)
        pfs_offset = 0

        while True:
            idx = data.find(self.DELL_PFS_SIGNATURE, pfs_offset)
            if idx < 0:
                break

            if idx + 0x10 <= len(data):
                try:
                    pfs_size = struct.unpack_from("<I", data, idx + 0x04)[0]
                    if 0 < pfs_size <= len(data) and idx + pfs_size <= len(data):
                        output_file = os.path.join(output_dir, f"pfs_segment_{idx:#x}.bin")
                        with open(output_file, "wb") as f:
                            f.write(data[idx : idx + pfs_size])
                        result.files.append(
                            {
                                "name": os.path.basename(output_file),
                                "size": pfs_size,
                                "offset": f"{idx:#x}",
                                "type": "PFS Segment",
                            }
                        )
                        result.success = True
                except struct.error:
                    pass

            pfs_offset = idx + 4

        if not result.files:
            result.messages.append("Found PFS signature but could not parse segments")

        return result

    def _extract_hp(self, data: bytes, output_dir: str, original_path: str) -> ExtractionResult:
        result = ExtractionResult(success=False)

        bios_regions = self._find_bios_regions(data)
        for i, (offset, size) in enumerate(bios_regions):
            output_file = os.path.join(output_dir, f"bios_region_{i:#x}.bin")
            with open(output_file, "wb") as f:
                f.write(data[offset : offset + size])
            result.files.append(
                {
                    "name": os.path.basename(output_file),
                    "size": size,
                    "offset": f"{offset:#x}",
                    "type": "BIOS Region",
                }
            )
            result.success = True

        me_regions = self._find_me_regions(data)
        for i, (offset, size) in enumerate(me_regions):
            output_file = os.path.join(output_dir, f"me_region_{i:#x}.bin")
            with open(output_file, "wb") as f:
                f.write(data[offset : offset + size])
            result.files.append(
                {
                    "name": os.path.basename(output_file),
                    "size": size,
                    "offset": f"{offset:#x}",
                    "type": "ME Region",
                }
            )
            result.success = True

        if not result.files:
            for offset in self._find_compressed_sections(data):
                self._try_decompress_lzma(data, offset, output_dir, result)

        return result

    def _extract_lenovo(self, data: bytes, output_dir: str, original_path: str) -> ExtractionResult:
        result = ExtractionResult(success=False)

        fl1_offset = data.find(b"FL1")
        if fl1_offset >= 0:
            result.messages.append(f"Found FL1 header at {fl1_offset:#x}")

        bios_regions = self._find_bios_regions(data)
        for i, (offset, size) in enumerate(bios_regions):
            output_file = os.path.join(output_dir, f"bios_region_{i:#x}.bin")
            with open(output_file, "wb") as f:
                f.write(data[offset : offset + size])
            result.files.append(
                {
                    "name": os.path.basename(output_file),
                    "size": size,
                    "offset": f"{offset:#x}",
                    "type": "BIOS Region",
                }
            )
            result.success = True

        return result

    def _extract_lenovo_exe(
        self, data: bytes, output_dir: str, original_path: str
    ) -> ExtractionResult:
        result = self._extract_lenovo(data, output_dir, original_path)
        if not result.success:
            result = self._extract_universal(data, output_dir, original_path)
        return result

    def _extract_asus(self, data: bytes, output_dir: str, original_path: str) -> ExtractionResult:
        return self._extract_universal(data, output_dir, original_path)

    def _extract_acer(self, data: bytes, output_dir: str, original_path: str) -> ExtractionResult:
        return self._extract_universal(data, output_dir, original_path)

    def _extract_toshiba(
        self, data: bytes, output_dir: str, original_path: str
    ) -> ExtractionResult:
        result = ExtractionResult(success=False)
        com_offset = data.find(b".COM")
        if com_offset >= 0:
            result.messages.append(f"Found Toshiba COM reference at {com_offset:#x}")

        bios_regions = self._find_bios_regions(data)
        for i, (offset, size) in enumerate(bios_regions):
            output_file = os.path.join(output_dir, f"bios_region_{i:#x}.bin")
            with open(output_file, "wb") as f:
                f.write(data[offset : offset + size])
            result.files.append(
                {
                    "name": os.path.basename(output_file),
                    "size": size,
                    "offset": f"{offset:#x}",
                    "type": "BIOS Region",
                }
            )
            result.success = True

        return result

    def _extract_samsung(
        self, data: bytes, output_dir: str, original_path: str
    ) -> ExtractionResult:
        return self._extract_universal(data, output_dir, original_path)

    def _extract_sony(self, data: bytes, output_dir: str, original_path: str) -> ExtractionResult:
        result = ExtractionResult(success=False)

        cab_offset = data.find(self.CAB_SIGNATURE)
        if cab_offset >= 0:
            result.messages.append(f"Found CAB archive at {cab_offset:#x}")

        bios_regions = self._find_bios_regions(data)
        for i, (offset, size) in enumerate(bios_regions):
            output_file = os.path.join(output_dir, f"bios_region_{i:#x}.bin")
            with open(output_file, "wb") as f:
                f.write(data[offset : offset + size])
            result.files.append(
                {
                    "name": os.path.basename(output_file),
                    "size": size,
                    "offset": f"{offset:#x}",
                    "type": "BIOS Region",
                }
            )
            result.success = True

        return result

    def _extract_ami_capsule(
        self, data: bytes, output_dir: str, original_path: str
    ) -> ExtractionResult:
        """Extract the flash image from an AMI Aptio vendor capsule (ASUS .308/.CAP)."""
        from bios_recovery.manufacturers.common.bios_capsule import detect_capsule

        result = ExtractionResult(success=False)
        info = detect_capsule(data)
        if not info.success:
            result.messages.extend(info.messages)
            return result

        image = data[info.header_size : info.image_end]
        output_file = os.path.join(output_dir, "flashable.bin")
        with open(output_file, "wb") as f:
            f.write(image)

        result.files.append(
            {
                "name": os.path.basename(output_file),
                "size": len(image),
                "offset": f"{info.header_size:#x}",
                "type": "Flash Image (capsule payload)",
            }
        )
        result.messages.append(
            f"AMI Aptio capsule: header {info.header_size:#x}, image {len(image):#x} bytes"
        )
        result.messages.append(
            "Write this image to the SPI chip (whole 32MB) with an external programmer, "
            "or flash it back via the programmer once verified."
        )
        result.success = True
        return result

    def _extract_universal(
        self, data: bytes, output_dir: str, original_path: str
    ) -> ExtractionResult:
        result = ExtractionResult(success=False)

        bios_regions = self._find_bios_regions(data)
        for i, (offset, size) in enumerate(bios_regions):
            output_file = os.path.join(output_dir, f"bios_region_{i:#x}.bin")
            with open(output_file, "wb") as f:
                f.write(data[offset : offset + size])
            result.files.append(
                {
                    "name": os.path.basename(output_file),
                    "size": size,
                    "offset": f"{offset:#x}",
                    "type": "BIOS Region",
                }
            )
            result.success = True

        me_regions = self._find_me_regions(data)
        for i, (offset, size) in enumerate(me_regions):
            output_file = os.path.join(output_dir, f"me_region_{i:#x}.bin")
            with open(output_file, "wb") as f:
                f.write(data[offset : offset + size])
            result.files.append(
                {
                    "name": os.path.basename(output_file),
                    "size": size,
                    "offset": f"{offset:#x}",
                    "type": "ME Region",
                }
            )
            result.success = True

        if not result.files:
            fv_regions = self._find_firmware_volumes(data)
            for i, (offset, size) in enumerate(fv_regions):
                output_file = os.path.join(output_dir, f"firmware_volume_{i:#x}.bin")
                with open(output_file, "wb") as f:
                    f.write(data[offset : offset + size])
                result.files.append(
                    {
                        "name": os.path.basename(output_file),
                        "size": size,
                        "offset": f"{offset:#x}",
                        "type": "Firmware Volume",
                    }
                )
                result.success = True

        return result

    def _find_bios_regions(self, data: bytes) -> list[tuple[int, int]]:
        from bios_recovery.core.bios_analyzer import BiosAnalyzer, RegionType

        analyzer = BiosAnalyzer()
        regions = analyzer._parse_intel_ifd(data) if self._find_intel_fd(data) >= 0 else []
        analyzer._search_firmware_volumes(data, regions)
        analyzer._add_derived_bios(regions)
        return [(r.offset, r.size) for r in regions if r.region_type == RegionType.BIOS]

    def _find_me_regions(self, data: bytes) -> list[tuple[int, int]]:
        from bios_recovery.core.bios_analyzer import BiosAnalyzer, RegionType

        if self._find_intel_fd(data) < 0:
            return []
        regions = BiosAnalyzer()._parse_intel_ifd(data)
        return [(r.offset, r.size) for r in regions if r.region_type == RegionType.INTEL_ME]

    def _find_firmware_volumes(self, data: bytes) -> list[tuple[int, int]]:
        from bios_recovery.core.bios_analyzer import BiosAnalyzer, RegionInfo

        found: list = []
        BiosAnalyzer()._search_firmware_volumes(bytes(data), found)
        return [(r.offset, r.size) for r in found if isinstance(r, RegionInfo)]

    def _find_intel_fd(self, data: bytes) -> int:
        if data[:4] == self.INTEL_FD_SIGNATURE:
            return 0
        if len(data) >= 0x14 and data[0x10:0x14] == self.INTEL_FD_SIGNATURE:
            return 0x10
        return -1

    MAX_LZMA_OUTPUT = 64 * 1024 * 1024

    @staticmethod
    def _valid_lzma_dictionary(size: int) -> bool:
        """LZMA dictionary sizes are 2^n, or 2^n + 2^(n-1), between 4 KB and 64 MB."""
        if not 0x1000 <= size <= 0x4000000:
            return False
        if size & (size - 1) == 0:
            return True
        return size % 3 == 0 and (size // 3) & (size // 3 - 1) == 0

    def _find_compressed_sections(self, data: bytes) -> list[int]:
        offsets = []
        idx = 0
        while True:
            idx = data.find(self.LZMA_SIGNATURE, idx)
            if idx < 0:
                break
            if idx + 5 <= len(data) and self._valid_lzma_dictionary(
                struct.unpack_from("<I", data, idx + 1)[0]
            ):
                offsets.append(idx)
            idx += 1
        return offsets

    def _try_decompress_lzma(
        self, data: bytes, offset: int, output_dir: str, result: ExtractionResult
    ) -> None:
        """Decode one LZMA stream. The stream must end cleanly within MAX_LZMA_OUTPUT."""
        import lzma

        decomp = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE)
        try:
            decompressed = decomp.decompress(data[offset:], max_length=self.MAX_LZMA_OUTPUT)
        except lzma.LZMAError:
            return
        if not decomp.eof or not decompressed:
            return
        output_file = os.path.join(output_dir, f"decompressed_{offset:#x}.bin")
        with open(output_file, "wb") as f:
            f.write(decompressed)
        result.files.append(
            {
                "name": os.path.basename(output_file),
                "size": len(decompressed),
                "offset": f"{offset:#x}",
                "type": "Decompressed",
            }
        )
        result.success = True

    def _extract_ascii_strings(self, data: bytes, min_length: int = 4) -> list[str]:
        strings = []
        current = b""
        for byte in data:
            if 0x20 <= byte <= 0x7E:
                current += bytes([byte])
            else:
                if len(current) >= min_length:
                    try:
                        strings.append(current.decode("ascii"))
                    except UnicodeDecodeError:
                        pass
                current = b""
        return strings
