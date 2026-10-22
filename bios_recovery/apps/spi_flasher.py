"""SPI flash programmer integration via flashrom.

Discovers the flashrom binary, enumerates supported programmers, and exposes
safe wrappers for read/write/erase/verify. Writes are gated behind an explicit
consent marker, check the image file first, and back up the chip before
writing unless asked not to. A failed backup stops the write.
"""

import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from enum import Enum, auto

_PROBE_RE = re.compile(
    r'(?:Found|Assuming) (?P<vendor>.+?) flash chip "(?P<name>[^"]+)" \((?P<size>\d+) kB'
)
_FLASH_NAME_RE = re.compile(r'vendor="([^"]*)" name="([^"]*)"')


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
    backup_path: str = ""


@dataclass
class ChipInfo:
    vendor: str
    name: str
    size: int


def _parse_flash_output(output: str) -> tuple[str, int]:
    """Return (chip_name, size_bytes) from flashrom's probe line, or ("unknown", 0)."""
    m = _PROBE_RE.search(output)
    if m:
        return m.group("name"), int(m.group("size")) * 1024
    return "unknown", 0


def _unique_backup_path(image_path: str) -> str:
    """`<image>_prewrite_backup.bin`, numbered when taken so an earlier backup survives."""
    base = os.path.splitext(image_path)[0] + "_prewrite_backup"
    candidate, n = base + ".bin", 1
    while os.path.exists(candidate):
        candidate = f"{base}_{n}.bin"
        n += 1
    return candidate


def _remove_quietly(path: str) -> None:
    try:
        os.remove(path)
    except OSError:
        pass


class SPIFlasher:
    """flashrom-backed SPI programmer."""

    COMMON_PROGRAMMERS = ["ch341a_spi", "ft2232_spi", "linux_spi", "buspirate_spi"]

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

    @staticmethod
    def _tool_exists(path: str) -> bool:
        if os.path.dirname(path):
            return os.path.isfile(path)
        return shutil.which(path) is not None

    def _cmd(self, args: list[str]) -> list[str]:
        """Return the argv used to invoke flashrom, honoring python shims."""
        if self.value.endswith(".py"):
            return [sys.executable, self.value] + args
        return [self.value] + args

    def _run(self, args: list[str], timeout: int | None):
        return subprocess.run(
            self._cmd(args),
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
        )

    def discover_programmers(self) -> list[str]:
        if not self.value:
            self.value = self._resolve_tool()
        if not self.value or not self._tool_exists(self.value):
            return []
        try:
            result = self._run(["--list-supported"], timeout=20)
        except (subprocess.SubprocessError, OSError, ValueError):
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
            result = self._run(["-p", programmer, "--flash-name"], timeout=30)
        except (subprocess.SubprocessError, OSError, ValueError):
            return ChipInfo(vendor="", name="", size=0)
        combined = result.stdout + result.stderr
        m = _FLASH_NAME_RE.search(combined)
        if not m or not m.group(2):
            return ChipInfo(vendor="", name="", size=0)
        _name, size = _parse_flash_output(combined)
        return ChipInfo(vendor=m.group(1), name=m.group(2), size=size)

    def read_chip(self, output_path: str, programmer: str = "ch341a_spi") -> FlasherResult:
        if not self.value:
            self.value = self._resolve_tool()
        if not self.value:
            return FlasherResult(
                status=SPIStatus.ERROR, message="flashrom not found", programmer=programmer
            )
        # flashrom writes a partial image as it goes; it only takes the real name on success.
        partial = output_path + ".partial"
        try:
            result = self._run(["-p", programmer, "-r", partial], timeout=600)
        except (subprocess.SubprocessError, OSError, ValueError) as e:
            _remove_quietly(partial)
            return FlasherResult(status=SPIStatus.ERROR, message=str(e), programmer=programmer)
        combined = result.stdout + result.stderr
        chip, size = _parse_flash_output(combined)
        if result.returncode == 0 and os.path.exists(partial):
            try:
                os.replace(partial, output_path)
            except OSError as e:
                _remove_quietly(partial)
                return FlasherResult(
                    status=SPIStatus.ERROR,
                    message=f"Read finished but could not be saved: {e.strerror or e}",
                    output=combined,
                    programmer=programmer,
                )
            return FlasherResult(
                status=SPIStatus.SUCCESS,
                message="Read complete",
                flash_chip=chip,
                flash_size=size,
                programmer=programmer,
                output=combined,
            )
        _remove_quietly(partial)
        return FlasherResult(
            status=SPIStatus.ERROR, message="Read failed", output=combined, programmer=programmer
        )

    def write_chip(
        self,
        image_path: str,
        programmer: str = "ch341a_spi",
        consent: bool = False,
        verify: bool = True,
        backup: bool = True,
        backup_path: str | None = None,
    ) -> FlasherResult:
        """Write ``image_path`` to the chip.

        With ``backup`` (the default) the chip is read to ``backup_path`` (or a new
        `<image>_prewrite_backup*.bin` name) first, and nothing is written if that
        read fails. flashrom verifies after writing unless ``verify`` is False.
        """
        if not consent:
            return FlasherResult(status=SPIStatus.DENIED, message="Write requires explicit consent")
        if not self.value:
            self.value = self._resolve_tool()
        if not self.value:
            return FlasherResult(
                status=SPIStatus.ERROR, message="flashrom not found", programmer=programmer
            )
        if not os.path.isfile(image_path):
            return FlasherResult(
                status=SPIStatus.ERROR,
                message=f"Image file not found or not a regular file: {image_path}",
                programmer=programmer,
            )
        if os.path.getsize(image_path) == 0:
            return FlasherResult(
                status=SPIStatus.ERROR,
                message="Image is empty; nothing was written.",
                programmer=programmer,
            )
        image_size = os.path.getsize(image_path)

        saved = ""
        if backup:
            saved = backup_path or _unique_backup_path(image_path)
            taken = self.read_chip(saved, programmer)
            if taken.status != SPIStatus.SUCCESS:
                return FlasherResult(
                    status=SPIStatus.ERROR,
                    message=f"Backup failed, nothing was written: {taken.message}",
                    output=taken.output,
                    programmer=programmer,
                )
            chip_size = taken.flash_size
        else:
            chip_size = self.identify_chip(programmer).size
        if chip_size <= 0:
            return FlasherResult(
                status=SPIStatus.ERROR,
                message="Could not read the chip size, so nothing was written.",
                programmer=programmer,
                backup_path=saved,
            )
        if image_size != chip_size:
            return FlasherResult(
                status=SPIStatus.ERROR,
                message=(
                    f"Image is {image_size} bytes and the chip is {chip_size} bytes. "
                    "Nothing was written."
                ),
                programmer=programmer,
                backup_path=saved,
            )

        args = ["-p", programmer, "-w", image_path]
        if not verify:
            args.append("-n")
        try:
            result = self._run(args, timeout=None)
        except (subprocess.SubprocessError, OSError, ValueError) as e:
            return FlasherResult(
                status=SPIStatus.ERROR,
                message=self._unknown_state(f"Write did not finish ({e})", saved),
                programmer=programmer,
                backup_path=saved,
            )
        combined = result.stdout + result.stderr
        chip, _ = _parse_flash_output(combined)
        if result.returncode == 0:
            return FlasherResult(
                status=SPIStatus.SUCCESS,
                message=("Write+verify complete" if verify else "Write complete (not verified)"),
                flash_chip=chip,
                programmer=programmer,
                output=combined,
                backup_path=saved,
            )
        return FlasherResult(
            status=SPIStatus.ERROR,
            message=self._unknown_state("Write failed", saved),
            output=combined,
            programmer=programmer,
            backup_path=saved,
        )

    @staticmethod
    def _unknown_state(what: str, backup: str) -> str:
        restore = f"restore {backup}" if backup else "restore a backup"
        return f"{what}. The chip state is unknown; {restore} before trying again."

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
            result = self._run(["-p", programmer, "-E"], timeout=None)
        except (subprocess.SubprocessError, OSError, ValueError) as e:
            return FlasherResult(
                status=SPIStatus.ERROR,
                message=self._unknown_state(f"Erase did not finish ({e})", ""),
                programmer=programmer,
            )
        combined = result.stdout + result.stderr
        if result.returncode == 0:
            return FlasherResult(
                status=SPIStatus.SUCCESS,
                message="Chip erased",
                programmer=programmer,
                output=combined,
            )
        return FlasherResult(
            status=SPIStatus.ERROR,
            message=self._unknown_state("Erase failed", ""),
            output=combined,
            programmer=programmer,
        )

    def progress_from_output(self, text: str) -> int:
        """Extract the latest flashrom progress percentage (0-100) from a log line."""
        m = re.findall(r"==>\s*(\d+(?:\.\d+)?)%?", text)
        if not m:
            return 0
        return min(100, round(float(m[-1])))
