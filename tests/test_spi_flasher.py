"""Regression tests for SPI flasher integration (using the fake flashrom shim)."""

import os

import pytest

from bios_recovery.engines.spi_flasher import SPIFlasher, ChipInfo, SPIStatus


FAKE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fake_flashrom.py")


@pytest.fixture
def flasher(tmp_path):
    image = os.environ.get("FAKE_FLASH_IMAGE")
    if image:
        os.environ.pop("FAKE_FLASH_IMAGE")
    return SPIFlasher(flashrom_path=FAKE)


def test_discover_programmers(flasher):
    programmers = flasher.discover_programmers()
    assert "ch341a_spi" in programmers
    assert "ft2232_spi" in programmers


def test_identify_chip(flasher):
    chip = flasher.identify_chip("ch341a_spi")
    assert isinstance(chip, ChipInfo)
    assert "W25Q128" in chip.name


def test_read_chip(flasher, tmp_path):
    out = str(tmp_path / "dump.bin")
    result = flasher.read_chip(out, "ch341a_spi")
    assert result.status == SPIStatus.SUCCESS
    assert os.path.exists(out)
    assert os.path.getsize(out) == 16 * 1024 * 1024


def test_write_requires_consent(flasher, tmp_path):
    image = str(tmp_path / "img.bin")
    with open(image, "wb") as f:
        f.write(b"\xAB" * 4096)
    result = flasher.write_chip(image, "ch341a_spi", consent=False)
    assert result.status == SPIStatus.DENIED


def test_write_with_consent(flasher, tmp_path):
    image = str(tmp_path / "img.bin")
    with open(image, "wb") as f:
        f.write(b"\xAB" * 4096)
    result = flasher.write_chip(image, "ch341a_spi", consent=True, verify=True)
    assert result.status == SPIStatus.SUCCESS


def test_erase_requires_consent(flasher):
    result = flasher.erase_chip("ch341a_spi", consent=False)
    assert result.status == SPIStatus.DENIED


def test_erase_with_consent(flasher):
    result = flasher.erase_chip("ch341a_spi", consent=True)
    assert result.status == SPIStatus.SUCCESS


def test_progress_parsing(flasher):
    assert flasher.progress_from_output("==> 12.34%") == 12
    assert flasher.progress_from_output("==> 100% done") == 100
    assert flasher.progress_from_output("nothing") == 0


def test_missing_flashrom_graceful(tmp_path):
    # An unresolvable flashrom path yields a graceful ERROR/DENIED result, not a crash.
    flasher = SPIFlasher(flashrom_path=str(tmp_path / "does_not_exist_flashrom"))
    resp = flasher.write_chip(str(tmp_path / "x.bin"), consent=True)
    assert resp.status in (SPIStatus.DENIED, SPIStatus.ERROR)
    read = flasher.read_chip(str(tmp_path / "x.bin"))
    assert read.status in (SPIStatus.DENIED, SPIStatus.ERROR)