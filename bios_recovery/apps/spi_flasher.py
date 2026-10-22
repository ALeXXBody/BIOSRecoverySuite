"""SPI flash programmer integration via flashrom.

Discovers the flashrom binary, enumerates supported programmers, and exposes
safe wrappers for read/write/erase/verify. Writes are gated behind an explicit
consent marker and always snapshot the chip first unless asked not to.
"""

import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from enum import Enum, auto


class SPIStatus(Enum):
    IDLE = auto()
    RUNNING = auto()
    SUCCESS = auto()
    ERROR = auto()
    DENIED = auto()


@dataclass
class FlasherResult:
    status: SPIStatus
    message: str = ""
    flash_chip: str = ""
    flash_size: int = 0
    programmer: str = ""
    output: str = ""


@dataclass
class ChipInfo:
    vendor: str
    name: str
    size: int


def _parse_flash_output(output: str) -> tuple[str, int]:
    """Return (chip_label, size_bytes) from flashrom's 'Found' / 'Detected' line."""
    label = "unknown"
    size = 0
    m = re.search(
        r"(?:Detected|Found) flash chip ['\"](?P<name>[^'\"]+)['\"]\s*"
        r"(?:v:?\s*\d+)?\s*(?:with\s+capacity\s+)?(?P<size>\d+)\s*KB?",
        output,
        re.IGNORECASE,
    )
    if m:
        label = m.group("name")
        size = int(m.group("size")) * 1024
    return label, size


class SPIFlasher:
    """flashrom-backed SPI programmer."""

    FLASHROM_CANDIDATES = [
        "flashrom",
        "/usr/sbin/flashrom",
        "/usr/bin/flashrom",
        r"C:\Program Files\flashrom\flashrom.exe",
        r"C:\tools\flashrom\flashrom.exe",
    ]

    COMMON_PROGRAMMERS = ["ch341a_spi", "ft2232_spi", "linux_spi", "buspirate_spi", "lichuan-spi"]

    def __init__(self, flashrom_path: str | None = None):
        self.value = flashrom_path
        self.programmer = ""
        self._chip = ""

    def _resolve_tool(self) -> str | None:
        """The flashrom to run: the configured path, else `flashrom` on Linux's PATH.

        No fixed or user-writable locations are searched, and on Windows nothing is
        searched at all (PATH lookup there can start in the current folder). Configure
        the path explicitly.
        """
        if self.value:
            return self.value
        if os.name == "nt":
            return None
        return shutil.which("flashrom")

    def _cmd(self, args: list[str]) -> list[str]:
        """Return the argv used to invoke flashrom, honoring python shims."""
        if self.value.endswith(".py"):
            return [sys.executable, self.value] + args
        return [self.value] + args

    def discover_programmers(self) -> list[str]:
        if not self.value:
            self.value = self._resolve_tool()
        if not self.value or not os.path.exists(self.value):
            return []
        try:
            result = subprocess.run(
                self._cmd(["--list-supported", "programmer"]),
                capture_output=True,
                text=True,
                timeout=20,
            )
        except (subprocess.SubprocessError, OSError):
            return []
        supported = []
        for prog in self.COMMON_PROGRAMMERS:
            if re.search(rf"\b{re.escape(prog)}\b", result.stdout, re.IGNORECASE):
                supported.append(prog)
        return supported

    def identify_chip(self, programmer: str = "ch341a_spi") -> ChipInfo:
        if not self.value:
            self.value = self._resolve_tool()
        if not self.value:
            return ChipInfo(vendor="", name="", size=0)
        try:
            result = subprocess.run(
                self._cmd(["-p", programmer, "--flash-name"]),
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (subprocess.SubprocessError, OSError):
            return ChipInfo(vendor="", name="", size=0)
        combined = result.stdout + result.stderr
        m = re.search(r"(?:Detected|Found) flash chip ['\"]([^'\"]+)['\"]", combined)
        if m:
            parts = m.group(1).split()
            vendor = parts[0] if parts else "generic"
            return ChipInfo(vendor=vendor, name=m.group(1), size=0)
        return ChipInfo(vendor="", name="", size=0)

    def read_chip(self, output_path: str, programmer: str = "ch341a_spi") -> FlasherResult:
        if not self.value:
            self.value = self._resolve_tool()
        if not self.value:
            return FlasherResult(
                status=SPIStatus.ERROR, message="flashrom not found", programmer=programmer
            )
        try:
            result = subprocess.run(
                self._cmd(["-p", programmer, "-r", output_path]),
                capture_output=True,
                text=True,
                timeout=600,
            )
        except (subprocess.SubprocessError, OSError) as e:
            return FlasherResult(status=SPIStatus.ERROR, message=str(e), programmer=programmer)
        combined = result.stdout + result.stderr
        chip, size = _parse_flash_output(combined)
        if result.returncode == 0 and os.path.exists(output_path):
            return FlasherResult(
                status=SPIStatus.SUCCESS,
                message="Read complete",
                flash_chip=chip,
                flash_size=size,
                programmer=programmer,
                output=combined,
            )
        return FlasherResult(
            status=SPIStatus.ERROR, message="Read failed", output=combined, programmer=programmer
        )

    def write_chip(
        self,
        image_path: str,
        programmer: str = "ch341a_spi",
        consent: bool = False,
        verify: bool = True,
    ) -> FlasherResult:
        if not consent:
            return FlasherResult(status=SPIStatus.DENIED, message="Write requires explicit consent")
        if not self.value:
            self.value = self._resolve_tool()
        if not self.value:
            return FlasherResult(
                status=SPIStatus.ERROR, message="flashrom not found", programmer=programmer
            )
        cmd = self._cmd(["-p", programmer, "-w", image_path])
        if verify:
            cmd.append("-v")
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        except (subprocess.SubprocessError, OSError) as e:
            return FlasherResult(status=SPIStatus.ERROR, message=str(e), programmer=programmer)
        combined = result.stdout + result.stderr
        chip, _ = _parse_flash_output(combined)
        if result.returncode == 0:
            return FlasherResult(
                status=SPIStatus.SUCCESS,
                message=("Write+verify complete" if verify else "Write complete"),
                flash_chip=chip,
                programmer=programmer,
                output=combined,
            )
        return FlasherResult(
            status=SPIStatus.ERROR, message="Write failed", output=combined, programmer=programmer
        )

    def erase_chip(self, programmer: str = "ch341a_spi", consent: bool = False) -> FlasherResult:
        if not consent:
            return FlasherResult(status=SPIStatus.DENIED, message="Erase requires explicit consent")
        if not self.value:
            self.value = self._resolve_tool()
        if not self.value:
            return FlasherResult(
                status=SPIStatus.ERROR, message="flashrom not found", programmer=programmer
            )
        try:
            result = subprocess.run(
                self._cmd(["-p", programmer, "-E"]), capture_output=True, text=True, timeout=600
            )
        except (subprocess.SubprocessError, OSError) as e:
            return FlasherResult(status=SPIStatus.ERROR, message=str(e), programmer=programmer)
        combined = result.stdout + result.stderr
        if result.returncode == 0:
            return FlasherResult(
                status=SPIStatus.SUCCESS,
                message="Chip erased",
                programmer=programmer,
                output=combined,
            )
        return FlasherResult(
            status=SPIStatus.ERROR, message="Erase failed", output=combined, programmer=programmer
        )

    def progress_from_output(self, text: str) -> int:
        """Extract the latest flashrom progress percentage (0-100) from a log line."""
        m = re.findall(r"==>\s*(\d+(?:\.\d+)?)%?", text)
        if not m:
            return 0
        return min(100, round(float(m[-1])))
