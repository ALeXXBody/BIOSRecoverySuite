"""Regression tests for the vendor BIOS package extractor."""

from bios_recovery.manufacturers.common.bios_extractor import BiosExtractor
from bios_recovery.manufacturers.common.bios_extractor import ExtractionMethod


def test_dell_pfs_extraction(dell_pfs, tmp_path):
    extractor = BiosExtractor()
    result = extractor.extract(dell_pfs, str(tmp_path / "out"))

    assert result.success
    assert len(result.files) >= 1
    assert any("PFS Segment" == f["type"] for f in result.files)


def test_universal_extraction_finds_fv(intel_ifd, tmp_path):
    extractor = BiosExtractor()
    result = extractor.extract(intel_ifd, str(tmp_path / "out"), ExtractionMethod.UNIVERSAL)

    assert result.success, result.messages
    types = {f["type"] for f in result.files}
    assert "ME Region" in types or "BIOS Region" in types or "Firmware Volume" in types


def test_auto_method_detection(intel_ifd, tmp_path):
    extractor = BiosExtractor()
    result = extractor.extract(intel_ifd, str(tmp_path / "out"))
    assert result.success


def test_method_enum_complete():
    """Every vendor extraction method mapped in GUI must exist in the enum."""
    for name in ["AUTO", "DELL_PFS", "HP_INSIDE", "LENOVO_FL1", "LENOVO_EXE",
                 "ASUS_EXE", "ACER_EXE", "TOSHIBA_EXE", "SAMSUNG_EXE",
                 "SONY_VAIO", "UNIVERSAL"]:
        assert ExtractionMethod[name], f"missing enum member {name}"