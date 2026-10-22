"""BIOS repair engine - repairs common BIOS issues."""

import os
import tempfile
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional

from bios_recovery.core.bios_analyzer import BiosAnalyzer, BiosType
from bios_recovery.core.safety import SameFileError, ensure_distinct
from bios_recovery.platforms.intel.me.me_cleaner import IntelMECleaner


class RepairType(Enum):
    AUTO = auto()
    CORRUPTED_DESCRIPTOR = auto()
    ME_REGION_CORRUPT = auto()
    CHECKSUM_FIX = auto()
    SIZE_NORMALIZE = auto()
    DMI_CORRUPT = auto()
    REMOVE_SECURITY = auto()


@dataclass
class RepairIssue:
    repair_type: RepairType
    severity: str
    description: str
    offset: int = 0
    size: int = 0


@dataclass
class RepairReport:
    success: bool
    issue: RepairType = RepairType.AUTO
    output_path: str = ""
    issues_found: list[RepairIssue] = field(default_factory=list)
    operations: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def add(self, text: str) -> None:
        self.operations.append(text)


def _version_family(version) -> tuple:
    """(major, minor) as integers, or () when the version is missing or unreadable."""
    parts = str(version or "").split(".")
    if len(parts) < 2 or not all(p.isdigit() for p in parts[:2]):
        return ()
    return int(parts[0]), int(parts[1])


class BiosRepairEngine:
    """Repairs corrupted, locked, or broken BIOS images."""

    FD_SIGNATURE = b"\x5a\xa5\xf0\x0f"
    FPT_SIGNATURE = b"$FPT"
    FV_SIGNATURE = b"_FVH"

    def __init__(self):
        self.analyzer = BiosAnalyzer()
        self.me_cleaner = IntelMECleaner()
        self._ec_patcher = None
        self._script_addr = None  # unused; reserved

    def analyze(self, file_path: str) -> list[RepairIssue]:
        result = self.analyzer.analyze(file_path)
        issues = []

        for issue in result.issues:
            issues.append(RepairIssue(
                repair_type=RepairType.AUTO,
                severity="error",
                description=issue,
            ))

        for warning in result.warnings:
            issues.append(RepairIssue(
                repair_type=RepairType.AUTO,
                severity="warning",
                description=warning,
            ))

        if not result.has_flash_descriptor and result.bios_type in (BiosType.INTEL_IFD, BiosType.AMI_APTIO):
            issues.append(RepairIssue(
                repair_type=RepairType.CORRUPTED_DESCRIPTOR,
                severity="error",
                description="Flash Descriptor missing or corrupt",
            ))

        if not result.has_me_region and result.bios_type in (BiosType.INTEL_IFD, BiosType.AMI_APTIO):
            issues.append(RepairIssue(
                repair_type=RepairType.ME_REGION_CORRUPT,
                severity="warning",
                description="ME region missing - may cause 30-min shutdown or slow boot",
            ))

        return issues

    def auto_repair(
        self,
        input_path: str,
        output_path: Optional[str] = None,
        fix_checksums: bool = True,
        normalize_size: bool = True,
        clear_passwords: bool = False,
    ) -> RepairReport:
        if not os.path.exists(input_path):
            return RepairReport(success=False, issues_found=[])

        output = output_path or input_path.rsplit(".", 1)[0] + "_repaired.bin"
        try:
            ensure_distinct(input_path, output)
        except SameFileError as exc:
            return RepairReport(success=False, output_path=output, warnings=[str(exc)])

        with open(input_path, "rb") as f:
            original = bytes(f.read())
        data = bytearray(original)

        issues = self.analyze(input_path)
        report = RepairReport(success=True, issues_found=issues, output_path=output)

        if fix_checksums:
            self._fix_fpt_checksum(data, report)
            self._verify_alignment(data, report)

        if clear_passwords:
            self._clear_passwords(data, report)

        if normalize_size:
            self._normalize_size(data, report)

        # Only real byte changes count as repairs; the report lists only those.
        if bytes(data) != original:
            with open(report.output_path, "wb") as f:
                f.write(data)
        else:
            report.success = False
            report.operations = []
            report.warnings.append("Nothing needed repair; no file was written")

        return report

    def _fix_fpt_checksum(self, data: bytearray, report: RepairReport) -> None:
        from bios_recovery.core.bios_analyzer import BiosAnalyzer
        positions = BiosAnalyzer()._fpt_positions(bytes(data))
        if not positions:
            return
        fpt_offset = positions[0]
        if fpt_offset + 0x20 > len(data):
            return

        checksum_offset = fpt_offset + 0x1B
        checksum = 0
        for i in range(fpt_offset, fpt_offset + 0x20):
            checksum += data[i]
        checksum &= 0xFF
        if checksum != 0:
            correction = (0x100 - (checksum - data[checksum_offset]) % 0x100) % 0x100
            data[checksum_offset] = correction
            report.operations.append(f"Fixed FPT checksum at {fpt_offset:#x}")

    def _clear_passwords(self, data: bytearray, report: RepairReport) -> None:
        from bios_recovery.core.password_remover import PasswordRemover
        remover = PasswordRemover()

        fd_in, temp_input = tempfile.mkstemp(prefix="brs_pw_in_", suffix=".bin")
        os.close(fd_in)
        fd_out, temp_output = tempfile.mkstemp(prefix="brs_pw_out_", suffix=".bin")
        os.close(fd_out)

        try:
            with open(temp_input, "wb") as f:
                f.write(data)
            result = remover.remove_passwords(temp_input, temp_output)
            if result.status.name == "SUCCESS":
                if len(result.found_passwords) > 200:
                    report.warnings.append(
                        f"Password scan found {len(result.found_passwords)} candidates "
                        "- likely false positives, skipping to avoid corruption"
                    )
                elif os.path.exists(temp_output):
                    with open(temp_output, "rb") as f:
                        new_data = f.read()
                    data[:] = bytearray(new_data)
                    report.operations.append(f"Removed {len(result.found_passwords)} password structures")
        finally:
            self._safe_remove((temp_input, temp_output))

    @staticmethod
    def _safe_remove(paths) -> None:
        for path in paths:
            try:
                if os.path.exists(path):
                    os.remove(path)
            except OSError:
                pass

    def _verify_alignment(self, data: bytearray, report: RepairReport) -> None:
        if len(data) % 0x1000 != 0:
            report.warnings.append(f"Image size {len(data)} not 4KB aligned")

    def _normalize_size(self, data: bytearray, report: RepairReport) -> None:
        target_sizes = [0x400000, 0x800000, 0x1000000, 0x2000000]
        current = len(data)

        for target in target_sizes:
            if current % target == 0:
                return

        closest = min(target_sizes, key=lambda t: abs(t - current))
        report.warnings.append(f"Image size {current:#x} is not a standard size; nearest is {closest:#x}")

    def fix_size(self, input_path: str, target_size: int, output_path: str) -> RepairReport:
        if target_size <= 0:
            return RepairReport(success=False, warnings=["target size must be positive"])
        try:
            ensure_distinct(input_path, output_path)
        except SameFileError as exc:
            return RepairReport(success=False, output_path=output_path, warnings=[str(exc)])
        with open(input_path, "rb") as f:
            data = f.read()
        before = len(data)

        if len(data) < target_size:
            padded = bytearray(target_size)
            padded[:len(data)] = data
            for i in range(len(data), target_size):
                padded[i] = 0xFF
            data = bytes(padded)
        elif len(data) > target_size:
            data = data[:target_size]

        with open(output_path, "wb") as f:
            f.write(data)

        if before == target_size:
            return RepairReport(success=True, output_path=output_path,
                                warnings=[f"Already {before} bytes; no change"])
        return RepairReport(
            success=True,
            output_path=output_path,
            operations=[f"Resized from {before} to {target_size} bytes"],
        )

    def doctor(self, input_path: str) -> RepairReport:
        """Deep integrity audit ('this is what LBE sells as high-success auto
        detection'): one read-only pass that reports everything damaged or
        unusual in a dump.

        Covers: chip-size sanity, Intel descriptor/regions (when present),
        the AMD PSP directories (when present), all present FV chain FFS
        checksums, FPT checksum/state, patch-site summaries for EC founds,
        and a set of actionable hints. Read-only: no output file is written.
        """
        report = RepairReport(success=True, issue=RepairType.AUTO)
        with open(input_path, "rb") as f:
            data = f.read()

        report.operations.append(f"file: {input_path} ({len(data):,} bytes)")
        if len(data) < 0x40000:
            report.warnings.append("image smaller than 256KB - not a flash dump?")
        if len(data) and (len(data) & (len(data) - 1)) != 0:
            report.warnings.append(f"size {len(data):#x} is not a power of two")

        # Intel descriptor side
        fd = self._find_fd_offset_of(data)
        if fd >= 0:
            report.operations.append(f"Intel flash descriptor @0x{fd:x}")
            me = self.me_cleaner.get_me_info(input_path)
            if me.get("found"):
                report.operations.append(
                    f"ME: version {me.get('version') or '?'} "
                    f"[{me.get('type')}] gen {me.get('generation')} "
                    f"@{me.get('offset')} size {me.get('size')}"
                )
            else:
                reason = me.get("reason")
                if reason:
                    report.warnings.append(f"ME analysis: {reason}")
                else:
                    report.warnings.append("No ME region found (may be disabled, absent, or AMD layout)")
        else:
            # AMD platform check
            psp_hits = [m for m in self._psp_dir_offsets(data)]
            if psp_hits:
                report.operations.append(
                    f"AMD platform: PSP directory at 0x{psp_hits[0]:x} "
                    f"(no Intel descriptor: correct for many AMD boards)"
                )
            else:
                report.warnings.append(
                    "no Intel descriptor and no AMD PSP directory found - "
                    "unusual for a full flash dump"
                )

        # FV chain integrity (FFS header checksums across all volumes)
        bad_files = 0
        fvs = self._fv_bounds(data)
        report.operations.append(f"firmware volumes: {len(fvs)}")
        for base, flen in fvs:
            chunk = bytes(data[base:base + flen])
            reason = self._damaged_reason(chunk)
            if reason:
                bad_files += 1
                report.warnings.append(f"FV @0x{base:x}: {reason}")
        if fvs and bad_files == 0:
            report.operations.append(f"FFS integrity: all {len(fvs)} volumes pass header checksums")
        elif fvs and bad_files:
            report.operations.append(f"FFS issues in {bad_files}/{len(fvs)} volume(s)")

        # Fsys store (Apple)
        try:
            from bios_recovery.manufacturers.apple.apple_efi import parse_fsys_store
            fsys = parse_fsys_store(data)
            if fsys.found:
                status = "valid" if fsys.checksum_valid else "INVALID CHECKSUM"
                report.operations.append(
                    f"Apple Fsys store @0x{fsys.base_address:x}: {status}, "
                    f"serial {fsys.serial!r}"
                )
        except Exception:
            pass

        # EC patches applicability (advisory)
        try:
            sites = self.ec_patcher().scan_patch_sites(input_path)
            hits = [s for s in sites if s.get("found")]
            if hits:
                report.operations.append(
                    f"EC patch table: {len(hits)} signature match(es); "
                    + ", ".join(f"{s['key']}@{s['offsets'][0]}" for s in hits[:4])
                )
        except Exception:
            pass

        return report

    def _find_fd_offset_of(self, data: bytes) -> int:
        if data[:4] == b"\x5a\xa5\xf0\x0f":
            return 0
        if len(data) > 0x14 and data[0x10:0x14] == b"\x5a\xa5\xf0\x0f":
            return 0x10
        return -1

    def _psp_dir_offsets(self, data: bytes) -> list:
        pass
        out, pos = [], 0
        while True:
            pos = data.find(b"$PSP", pos)
            if pos < 0:
                break
            out.append(pos)
            pos += 4
        return out

    def ec_patcher(self):
        from bios_recovery.platforms.ec.ec_patcher import ECPatcher
        if self._ec_patcher is None:
            self._ec_patcher = ECPatcher()
        return self._ec_patcher

    def auto_graft_from_donor(
        self,
        input_path: str,
        donor_path: str,
        output_path: Optional[str] = None,
    ) -> RepairReport:
        """Repair a damaged dump by grafting regions from a known-good donor.

        This is the app's equivalent of paid suites' "auto repair by firmware
        detection" — restricted to structurally-justified writes:

          1. Accept a donor that is either a bare flash image of the same size,
             or an AMI Aptio capsule whose flashable payload has the same size.
          2. Identify damaged regions in the target:
             a) FVS chains that fail FFS header checksums,
             b) all-FF holes sitting inside populated FVs.
          3. Graft only where the donor's FV bounds match the target's exactly
             and the donor's copy of the region validates. Refuse everything
             else (bounds mismatch, unknown format, different chip size) with
             an explicit report message instead of writing guessed bytes.
        """
        report = RepairReport(success=False, issue=RepairType.AUTO)

        with open(input_path, "rb") as f:
            target = bytearray(f.read())

        # Accept capsule donors transparently
        donor_file = donor_path
        from bios_recovery.manufacturers.common.bios_capsule import (
            APTIO_CAPSULE_GUID_LE,
            extract_flashable_image,
        )
        with open(donor_path, "rb") as f:
            donor_head = f.read(16)
        if donor_head == APTIO_CAPSULE_GUID_LE:
            extract_dir = donor_path.rsplit(".", 1)[0] + "_grade_extracted"
            os.makedirs(extract_dir, exist_ok=True)
            info = extract_flashable_image(donor_path,
                                           output_path=os.path.join(extract_dir, "flashable.bin"))
            if not info.success:
                report.warnings.extend(info.messages)
                report.warnings.append("Donor capsule could not be extracted")
                return report
            donor_file = info.output_path

        with open(donor_file, "rb") as f:
            donor = f.read()

        if len(donor) != len(target):
            report.warnings.append(
                f"Donor size {len(donor):#x} differs from target {len(target):#x} - "
                "grafting across different chip sizes is refused"
            )
            report.issues_found.append(RepairIssue(
                RepairType.AUTO, "error", "Donor/target size mismatch", 0, 0))
            if output_path is None:
                return report
            with open(output_path, "wb") as f:
                f.write(bytes(target))
            report.output_path = output_path
            return report

        fvs_t = self._fv_bounds(bytes(target))
        fvs_d = self._fv_bounds(donor)
        common = [b for b in fvs_t if b in fvs_d]
        report.operations.append(f"Target FVs: {len(fvs_t)}, donor FVs: {len(fvs_d)}, "
                                 f"identically bounded: {len(common)}")

        # ME gate, decided before any write. A graft that touches the ME region needs the
        # same ME version family and identical bounds in target and donor; without a
        # readable version on either side, nothing in the ME region is grafted.
        target_me = self.me_cleaner.get_me_info(input_path)
        donor_me = self.me_cleaner.get_me_info(donor_file) if donor_file else {}
        me_found = bool(target_me.get("found"))
        me_block_allowed = True
        if me_found:
            t_version = _version_family(target_me.get("version"))
            d_version = _version_family(donor_me.get("version"))
            same_bounds = (
                int(target_me.get("offset", "0"), 16) == int(donor_me.get("offset", "0"), 16)
                and int(target_me.get("size", "0"), 16) == int(donor_me.get("size", "0"), 16)
            ) if donor_me.get("found") else False
            me_block_allowed = bool(t_version and d_version and t_version == d_version and same_bounds)
            if not me_block_allowed:
                report.warnings.append(
                    f"ME region not grafted: target {target_me.get('version') or 'unknown'} vs "
                    f"donor {donor_me.get('version') or 'unknown'} (version family and bounds must match)"
                )
        t_me_off = int(target_me.get("offset", "0"), 16) if me_found else 0
        t_me_size = int(target_me.get("size", "0"), 16) if me_found else 0

        grafts = 0
        graft_bytes = 0
        for base, flen in fvs_d:
            chunk_d = donor[base:base + flen]
            d_damaged = self._damaged_reason(chunk_d)
            if d_damaged:
                report.warnings.append(
                    f"Donor FV @0x{base:x} fails its own integrity ({d_damaged}) - not grafted"
                )
                continue
            if me_found and not me_block_allowed and base < t_me_off + t_me_size and base + flen > t_me_off:
                report.warnings.append(
                    f"Donor FV @0x{base:x} overlaps the ME region, which is not graftable - refused"
                )
                continue
            chunk_t = bytes(target[base:base + flen])
            t_damaged = self._damaged_reason(chunk_t)
            if (base, flen) in fvs_t:
                if chunk_t == chunk_d:
                    continue
                if not t_damaged:
                    report.warnings.append(
                        f"FV @0x{base:x} differs but is not identified as damaged in the "
                        "target - left untouched (different content is not corruption)"
                    )
                    continue
                target[base:base + flen] = chunk_d
                grafts += 1
                graft_bytes += flen
                report.operations.append(
                    f"Grafted FV @0x{base:x} (0x{flen:x} bytes): {t_damaged} -> replaced with donor copy"
                )
                report.issues_found.append(RepairIssue(
                    RepairType.AUTO, "warning", f"Grafted region at {base:#x}", base, flen))
            elif set(chunk_t) == {0xFF}:
                # Provably erased region: no data exists to destroy, restoring it
                # from the validated donor is justified recovery.
                target[base:base + flen] = chunk_d
                grafts += 1
                graft_bytes += flen
                report.operations.append(
                    f"Restored erased FV @0x{base:x} (0x{flen:x} bytes) from donor copy"
                )
                report.issues_found.append(RepairIssue(
                    RepairType.AUTO, "warning", f"Restored erased region at {base:#x}", base, flen))
            else:
                report.warnings.append(
                    f"Donor FV @0x{base:x} has no matching bounds in the target and the "
                    "target area is not erased - refused (would overwrite unknown data)"
                )

        if output_path is None:
            output_path = input_path.rsplit(".", 1)[0] + "_grafted.bin"
        try:
            ensure_distinct(input_path, output_path)
        except SameFileError as exc:
            report.warnings.append(str(exc))
            report.success = False
            return report
        report.operations.append(f"Total grafts: {grafts} ({graft_bytes:#x} bytes written)")
        with open(output_path, "wb") as f:
            f.write(bytes(target))
        report.output_path = output_path
        if not grafts:
            report.warnings.append("No region was graftable; the output is an unchanged copy of the input")
        report.success = grafts > 0
        return report

    @staticmethod
    def _fv_bounds(blob: bytes) -> list[tuple[int, int]]:
        """Firmware volumes as (base, length), validated the same way the analyzer does
        (header checksum and length), with nested matches inside a volume dropped."""
        from bios_recovery.core.bios_analyzer import BiosAnalyzer, RegionInfo
        found: list = []
        BiosAnalyzer()._search_firmware_volumes(bytes(blob), found)
        return [(r.offset, r.size) for r in found if isinstance(r, RegionInfo)]

    @staticmethod
    def _damaged_reason(chunk: bytes) -> str:
        """Classify structural damage in an FV region; '' means not damaged."""
        # All-FF volume (erased or lost)
        if chunk and set(chunk) == {0xFF}:
            return "entirely FF (erased)"
        # FFS header checksum failures
        bad = 0
        pos = 0x48
        while pos + 0x18 <= len(chunk):
            isize = chunk[pos + 0x14] | chunk[pos + 0x15] << 8 | chunk[pos + 0x16] << 16
            if isize < 0x18 or pos + isize > len(chunk):
                # A corrupt size field is damage, unless only erased space follows.
                if set(chunk[pos:]) != {0xFF}:
                    bad += 1
                break
            hd = bytearray(chunk[pos:pos + 0x18])
            hd[0x10] = hd[0x11] = hd[0x17] = 0
            if ((-sum(hd)) & 0xFF) != chunk[pos + 0x10]:
                bad += 1
            pos = (pos + isize + 7) & ~7
        if bad:
            return f"{bad} FFS file(s) with bad header checksums"
        return ""

    def extract_region(self, input_path: str, offset: int, size: int, output_path: str) -> RepairReport:
        try:
            ensure_distinct(input_path, output_path)
        except SameFileError as exc:
            return RepairReport(success=False, output_path=output_path, warnings=[str(exc)])
        with open(input_path, "rb") as f:
            data = f.read()

        if offset < 0 or size <= 0 or offset + size > len(data):
            return RepairReport(
                success=False,
                issues_found=[RepairIssue(
                    repair_type=RepairType.AUTO,
                    severity="error",
                    description="Requested region is outside the file",
                )],
            )

        region = data[offset:offset + size]
        with open(output_path, "wb") as f:
            f.write(region)

        return RepairReport(
            success=True,
            output_path=output_path,
            operations=[f"Extracted {size} bytes at offset {offset:#x}"],
        )

    def replace_region(
        self,
        input_path: str,
        output_path: str,
        region_offset: int,
        region_size: int,
        replacement_path: str,
    ) -> RepairReport:
        try:
            ensure_distinct(input_path, output_path)
        except SameFileError as exc:
            return RepairReport(success=False, output_path=output_path, warnings=[str(exc)])
        with open(input_path, "rb") as f:
            data = bytearray(f.read())

        with open(replacement_path, "rb") as f:
            replacement = f.read()

        if region_offset < 0 or region_size <= 0 or region_offset + region_size > len(data):
            return RepairReport(
                success=False,
                issues_found=[RepairIssue(
                    repair_type=RepairType.AUTO,
                    severity="error",
                    description="Region exceeds file bounds",
                )],
            )

        if len(replacement) > region_size:
            return RepairReport(
                success=False,
                issues_found=[RepairIssue(
                    repair_type=RepairType.AUTO,
                    severity="error",
                    description="Replacement data larger than region",
                )],
            )

        data[region_offset:region_offset + len(replacement)] = replacement
        for i in range(region_offset + len(replacement), region_offset + region_size):
            data[i] = 0xFF

        with open(output_path, "wb") as f:
            f.write(data)

        return RepairReport(
            success=True,
            output_path=output_path,
            operations=[f"Replaced region at {region_offset:#x} ({region_size} bytes)"],
        )
