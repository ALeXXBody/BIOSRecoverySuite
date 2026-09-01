"""BIOS repair engine - repairs common BIOS issues."""

import struct
import os
import hashlib
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional

from bios_recovery.engines.bios_analyzer import BiosAnalyzer, BiosType
from bios_recovery.engines.me_cleaner import IntelMECleaner


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


class BiosRepairEngine:
    """Repairs corrupted, locked, or broken BIOS images."""

    FD_SIGNATURE = b"\x5a\xa5\xf0\x0f"
    FPT_SIGNATURE = b"$FPT"
    FV_SIGNATURE = b"_FVH"

    def __init__(self):
        self.analyzer = BiosAnalyzer()
        self.me_cleaner = IntelMECleaner()

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
        clear_me: bool = True,
        fix_checksums: bool = True,
        normalize_size: bool = True,
        remove_security: bool = True,
    ) -> RepairReport:
        if not os.path.exists(input_path):
            return RepairReport(success=False, issues_found=[])

        with open(input_path, "rb") as f:
            data = bytearray(f.read())

        issues = self.analyze(input_path)
        report = RepairReport(
            success=True,
            issues_found=issues,
            output_path=output_path or input_path.rsplit(".", 1)[0] + "_repaired.bin",
        )

        if fix_checksums:
            self._fix_fpt_checksum(data, report)
            self._verify_alignment(data, report)

        if clear_me:
            self._clear_me_region(data, report)

        if remove_security:
            self._clear_security(data, report)

        if normalize_size:
            self._normalize_size(data, report)

        if report.operations:
            with open(report.output_path, "wb") as f:
                f.write(data)
        else:
            report.success = False
            report.warnings.append("No repair operations were applicable")

        return report

    def _fix_fpt_checksum(self, data: bytearray, report: RepairReport) -> None:
        fpt_offset = data.find(self.FPT_SIGNATURE)
        if fpt_offset < 0 or fpt_offset + 0x20 > len(data):
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

    def _clear_me_region(self, data: bytearray, report: RepairReport) -> None:
        temp_input = "_temp_me_input.bin"
        temp_output = "_temp_me_output.bin"

        try:
            with open(temp_input, "wb") as f:
                f.write(data)
            clean_result = self.me_cleaner.clean(temp_input, temp_output, soft_disable=True)
            if clean_result.status.name in ("SUCCESS", "ALREADY_CLEAN") and os.path.exists(temp_output):
                with open(temp_output, "rb") as f:
                    new_data = f.read()
                if len(new_data) >= len(data):
                    data[:] = bytearray(new_data)
                    report.operations.append(f"ME cleaned (version {clean_result.me_version})")
            elif clean_result.status.name == "NO_ME_REGION":
                report.warnings.append("No ME region found to clean")
            else:
                report.warnings.append(f"ME cleaning skipped: {clean_result.status.name}")
        finally:
            for temp in (temp_input, temp_output):
                if os.path.exists(temp):
                    os.remove(temp)

    def _clear_security(self, data: bytearray, report: RepairReport) -> None:
        from bios_recovery.engines.password_remover import PasswordRemover
        remover = PasswordRemover()

        temp_input = "_temp_pw_input.bin"
        temp_output = "_temp_pw_output.bin"

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
            for temp in (temp_input, temp_output):
                if os.path.exists(temp):
                    os.remove(temp)

    def _verify_alignment(self, data: bytearray, report: RepairReport) -> None:
        if len(data) % 0x1000 != 0:
            report.warnings.append(f"Image size {len(data)} not 4KB aligned")
        else:
            report.operations.append("Image size is 4KB aligned")

    def _normalize_size(self, data: bytearray, report: RepairReport) -> None:
        target_sizes = [0x400000, 0x800000, 0x1000000, 0x2000000]
        current = len(data)

        for target in target_sizes:
            if current % target == 0:
                report.operations.append(f"Image size {current:#x} is valid ({target >> 20} MB)")
                return

        closest = min(target_sizes, key=lambda t: abs(t - current))
        report.warnings.append(f"Image size {current:#x} is not a standard size; nearest is {closest:#x}")

    def fix_size(self, input_path: str, target_size: int, output_path: str) -> RepairReport:
        with open(input_path, "rb") as f:
            data = f.read()

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

        return RepairReport(
            success=True,
            output_path=output_path,
            operations=[f"Resized from {len(data)} to {target_size} bytes"],
        )

    def extract_region(self, input_path: str, offset: int, size: int, output_path: str) -> RepairReport:
        with open(input_path, "rb") as f:
            data = f.read()

        if offset + size > len(data):
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
        with open(input_path, "rb") as f:
            data = bytearray(f.read())

        with open(replacement_path, "rb") as f:
            replacement = f.read()

        if region_offset + region_size > len(data):
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
