"""Regression tests for the flashrom wrapper audit fixes (SP-1 to SP-10).

No test starts flashrom. subprocess.run is replaced by a recorder, so these
check the argv, the timeouts and the output parsing only.
"""

import os
import subprocess

import pytest

from bios_recovery.apps import spi_flasher
from bios_recovery.apps.spi_flasher import (
    ChipInfo,
    FlasherResult,
    SPIFlasher,
    SPIStatus,
    _parse_flash_output,
)

PROBE = 'Found Winbond flash chip "W25Q128.V" (16384 kB, SPI) on linux_spi.'
MB16 = 16 * 1024 * 1024


@pytest.fixture
def tool(tmp_path):
    path = tmp_path / "flashrom"
    path.write_text("#!/bin/sh\n")
    return str(path)


class Recorder:
    """Stands in for subprocess.run. Records every call; never executes anything."""

    def __init__(self, stdout="", stderr="", returncode=0, on_call=None):
        self.calls = []
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode
        self.on_call = on_call

    def __call__(self, cmd, **kwargs):
        self.calls.append((list(cmd), kwargs))
        if self.on_call:
            self.on_call(cmd)
        return subprocess.CompletedProcess(cmd, self.returncode, self.stdout, self.stderr)

    def argvs(self):
        return [cmd for cmd, _ in self.calls]


def _write_partial(cmd):
    if "-r" not in cmd:
        return
    out = cmd[cmd.index("-r") + 1]
    with open(out, "wb") as f:
        f.write(b"\xff" * 4096)


def test_parse_real_probe_line():
    """SP-2: flashrom's real probe line gives the chip name and size."""
    assert _parse_flash_output(PROBE + "\n") == ("W25Q128.V", MB16)
    assert _parse_flash_output('Assuming Foo flash chip "X1" (512 kB, SPI) on x.') == (
        "X1",
        512 * 1024,
    )
    assert _parse_flash_output("nothing useful") == ("unknown", 0)


def test_identify_chip_parses_flash_name_output(monkeypatch, tool):
    """SP-2: --flash-name prints vendor="..." name="..." on stdout."""
    rec = Recorder(stdout='vendor="Winbond" name="W25Q128.V"\n', stderr=PROBE + "\n")
    monkeypatch.setattr(spi_flasher.subprocess, "run", rec)
    chip = SPIFlasher(tool).identify_chip("ch341a_spi")
    assert chip == ChipInfo(vendor="Winbond", name="W25Q128.V", size=MB16)


def test_read_reports_real_chip_and_size(monkeypatch, tool, tmp_path):
    """SP-2: a successful read reports the chip and size, not 'unknown' and 0."""
    rec = Recorder(stderr=PROBE + "\n", on_call=_write_partial)
    monkeypatch.setattr(spi_flasher.subprocess, "run", rec)
    out = tmp_path / "dump.bin"
    result = SPIFlasher(tool).read_chip(str(out), "ch341a_spi")
    assert result.status == SPIStatus.SUCCESS
    assert (result.flash_chip, result.flash_size) == ("W25Q128.V", MB16)
    assert out.exists()
    assert not (tmp_path / "dump.bin.partial").exists()


def test_write_with_verify_does_not_pass_v(monkeypatch, tool, tmp_path):
    """SP-1: -v with -w is two operations; flashrom auto-verifies after -w."""
    image = tmp_path / "img.bin"
    image.write_bytes(b"\xab" * MB16)
    rec = Recorder(
        stdout='vendor="Winbond" name="W25Q128.V"\n',
        stderr=PROBE + "\n",
    )
    monkeypatch.setattr(spi_flasher.subprocess, "run", rec)
    result = SPIFlasher(tool).write_chip(
        str(image), "ch341a_spi", consent=True, verify=True, backup=False
    )
    assert result.status == SPIStatus.SUCCESS, result.message
    write = [argv for argv in rec.argvs() if "-w" in argv]
    assert len(write) == 1
    assert "-v" not in write[0] and "-n" not in write[0]


def test_write_without_verify_passes_noverify(monkeypatch, tool, tmp_path):
    """SP-8: verify=False passes -n, which is the flag that turns auto-verify off."""
    image = tmp_path / "img.bin"
    image.write_bytes(b"\xab" * MB16)
    rec = Recorder(stdout='vendor="Winbond" name="W25Q128.V"\n', stderr=PROBE + "\n")
    monkeypatch.setattr(spi_flasher.subprocess, "run", rec)
    result = SPIFlasher(tool).write_chip(
        str(image), "ch341a_spi", consent=True, verify=False, backup=False
    )
    assert result.status == SPIStatus.SUCCESS, result.message
    assert "Write complete (not verified)" == result.message
    write = [argv for argv in rec.argvs() if "-w" in argv]
    assert write[0][-1] == "-n" and "-v" not in write[0]


def test_write_takes_backup_first_and_stops_when_backup_fails(monkeypatch, tool, tmp_path):
    """SP-4: no -w runs unless the backup read succeeded."""
    image = tmp_path / "img.bin"
    image.write_bytes(b"\xab" * 4096)
    rec = Recorder(returncode=1)
    monkeypatch.setattr(spi_flasher.subprocess, "run", rec)
    result = SPIFlasher(tool).write_chip(str(image), "ch341a_spi", consent=True)
    assert result.status == SPIStatus.ERROR
    assert "Backup failed" in result.message
    assert all("-w" not in argv for argv in rec.argvs())


def test_write_backup_default_name_is_not_overwritten(monkeypatch, tool, tmp_path):
    """SP-4: an earlier backup is kept; the new one gets a numbered name."""
    image = tmp_path / "img.bin"
    image.write_bytes(b"\xab" * MB16)
    earlier = tmp_path / "img_prewrite_backup.bin"
    earlier.write_bytes(b"EARLIER")
    rec = Recorder(stderr=PROBE + "\n", on_call=_write_partial)
    monkeypatch.setattr(spi_flasher.subprocess, "run", rec)
    result = SPIFlasher(tool).write_chip(str(image), "ch341a_spi", consent=True)
    assert result.status == SPIStatus.SUCCESS
    assert earlier.read_bytes() == b"EARLIER"
    assert result.backup_path == str(tmp_path / "img_prewrite_backup_1.bin")
    assert (tmp_path / "img_prewrite_backup_1.bin").exists()


def test_write_refuses_missing_or_empty_image_without_running_tool(monkeypatch, tool, tmp_path):
    """SP-5: a missing or empty image is refused before flashrom is called."""
    rec = Recorder()
    monkeypatch.setattr(spi_flasher.subprocess, "run", rec)
    flasher = SPIFlasher(tool)
    missing = flasher.write_chip(str(tmp_path / "none.bin"), consent=True)
    assert missing.status == SPIStatus.ERROR
    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")
    blank = flasher.write_chip(str(empty), consent=True)
    assert blank.status == SPIStatus.ERROR
    assert rec.calls == []


def test_write_refuses_when_image_size_differs_from_chip(monkeypatch, tool, tmp_path):
    """SP-5: a size mismatch is refused after the chip size is known, and -w is not run."""
    image = tmp_path / "img.bin"
    image.write_bytes(b"\xab" * 4096)
    rec = Recorder(stdout='vendor="Winbond" name="W25Q128.V"\n', stderr=PROBE + "\n")
    monkeypatch.setattr(spi_flasher.subprocess, "run", rec)
    result = SPIFlasher(tool).write_chip(
        str(image), "ch341a_spi", consent=True, backup=False
    )
    assert result.status == SPIStatus.ERROR
    assert "4096 bytes" in result.message and "Nothing was written" in result.message
    assert all("-w" not in argv for argv in rec.argvs())


def test_discover_uses_list_supported_without_extra_word(monkeypatch, tool):
    """SP-3: 'programmer' after --list-supported is an error in flashrom."""
    rec = Recorder(stdout="Supported programmers:\n\tch341a_spi\n\tlinux_spi\n")
    monkeypatch.setattr(spi_flasher.subprocess, "run", rec)
    found = SPIFlasher(tool).discover_programmers()
    assert rec.argvs() == [[tool, "--list-supported"]]
    assert found == ["ch341a_spi", "linux_spi"]


def test_discover_accepts_bare_name_on_path(monkeypatch, tmp_path):
    """SP-3: a bare 'flashrom' found on PATH is used, not checked in the current folder."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    exe = bindir / "flashrom"
    exe.write_text("#!/bin/sh\n")
    exe.chmod(0o755)
    monkeypatch.setenv("PATH", str(bindir))
    rec = Recorder(stdout="\tch341a_spi\n")
    monkeypatch.setattr(spi_flasher.subprocess, "run", rec)
    assert SPIFlasher("flashrom").discover_programmers() == ["ch341a_spi"]


def test_lichuan_is_not_offered_as_a_programmer(monkeypatch, tool):
    """SP-3/SP-9: lichuan-spi is not a flashrom programmer name."""
    rec = Recorder(stdout="lichuan-spi\nch341a_spi\n")
    monkeypatch.setattr(spi_flasher.subprocess, "run", rec)
    assert SPIFlasher(tool).discover_programmers() == ["ch341a_spi"]


def test_read_failure_leaves_no_partial_file(monkeypatch, tool, tmp_path):
    """SP-10: a failed read must not leave a truncated file under the backup name."""
    out = tmp_path / "dump.bin"
    rec = Recorder(returncode=1, on_call=_write_partial)
    monkeypatch.setattr(spi_flasher.subprocess, "run", rec)
    result = SPIFlasher(tool).read_chip(str(out), "ch341a_spi")
    assert result.status == SPIStatus.ERROR
    assert not out.exists()
    assert not (tmp_path / "dump.bin.partial").exists()


def test_write_and_erase_have_no_timeout(monkeypatch, tool, tmp_path):
    """SP-6: a write or erase is never killed by a timer."""
    image = tmp_path / "img.bin"
    image.write_bytes(b"\xab" * MB16)
    rec = Recorder(stdout='vendor="Winbond" name="W25Q128.V"\n', stderr=PROBE + "\n")
    monkeypatch.setattr(spi_flasher.subprocess, "run", rec)
    flasher = SPIFlasher(tool)
    flasher.write_chip(str(image), consent=True, backup=False)
    flasher.erase_chip(consent=True)
    writes = [kw["timeout"] for cmd, kw in rec.calls if "-w" in cmd or "-E" in cmd]
    assert writes == [None, None]


def test_failed_write_says_chip_state_is_unknown(monkeypatch, tool, tmp_path):
    """SP-6: after a failed or interrupted write the user is told to restore the backup."""
    image = tmp_path / "img.bin"
    image.write_bytes(b"\xab" * MB16)
    rec = Recorder(
        returncode=1, stdout='vendor="Winbond" name="W25Q128.V"\n', stderr=PROBE + "\n"
    )
    monkeypatch.setattr(spi_flasher.subprocess, "run", rec)
    result = SPIFlasher(tool).write_chip(str(image), consent=True, backup=False)
    assert result.status == SPIStatus.ERROR
    assert "chip state is unknown" in result.message


def test_tool_output_is_decoded_with_replacement(monkeypatch, tool):
    """SP-7: non-UTF-8 tool output must not raise UnicodeDecodeError."""
    rec = Recorder(stdout="")
    monkeypatch.setattr(spi_flasher.subprocess, "run", rec)
    SPIFlasher(tool).identify_chip()
    assert rec.calls[0][1]["errors"] == "replace"


def test_verified_write_end_to_end_with_test_double(tmp_path, monkeypatch):
    """SP-1: the repo's flashrom test double rejects -w with -v; the default write works."""
    fake = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fake_flashrom.py")
    image = tmp_path / "img.bin"
    image.write_bytes(b"\xab" * MB16)
    chip = tmp_path / "chip.bin"
    monkeypatch.setenv("FAKE_FLASH_IMAGE", str(chip))
    flasher = SPIFlasher(flashrom_path=fake)
    result = flasher.write_chip(str(image), "ch341a_spi", consent=True, verify=True)
    assert result.status == SPIStatus.SUCCESS, result.message
    assert result.backup_path and os.path.exists(result.backup_path)


def test_fake_double_rejects_two_operations(tmp_path):
    """The test double follows flashrom's single-operation rule."""
    import subprocess as sp
    import sys

    fake = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fake_flashrom.py")
    image = tmp_path / "img.bin"
    image.write_bytes(b"\xab" * 16)
    proc = sp.run(
        [sys.executable, fake, "-p", "ch341a_spi", "-w", str(image), "-v"],
        capture_output=True,
        text=True,
        env={**os.environ, "FAKE_FLASH_IMAGE": ""},
    )
    assert proc.returncode == 1
    assert "More than one operation" in proc.stderr


def test_flasher_result_defaults():
    assert FlasherResult(status=SPIStatus.IDLE).backup_path == ""
