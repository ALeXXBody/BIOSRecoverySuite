"""Regression tests for DMI extraction and password removal."""

from bios_recovery.engines.dmi_extractor import DMIExtractor
from bios_recovery.core.password_remover import PasswordRemover


def test_dmi_extraction_from_dump(intel_ifd):
    info = DMIExtractor().extract_from_bios(intel_ifd)

    assert info is not None
    assert info.bios_vendor == "American Megatrends Inc."
    assert info.bios_version == "5.26"
    assert info.system_manufacturer == "LENOVO"
    assert info.system_product_name == "20HQCTO1WW"
    assert info.system_serial_number == "PF1ABC123"
    assert info.board_manufacturer == "LENOVO"
    assert info.chassis_manufacturer == "LENOVO"
    assert info.memory_devices, "at least one memory device expected"
    assert len(info.structures) >= 5


def test_dmi_uuid_parsed(intel_ifd):
    info = DMIExtractor().extract_from_bios(intel_ifd)
    assert len(info.system_uuid) == 36, info.system_uuid
    parts = info.system_uuid.split("-")
    assert len(parts) == 5


def test_password_scan_finds_ami_variable(intel_ifd):
    found = PasswordRemover().find_password_in_dump(intel_ifd)
    types = {f["type"] for f in found}
    assert "AMI_SETUP_PASSWORD" in types


def test_password_removal_clears_variables(intel_ifd, tmp_path):
    out = str(tmp_path / "nopass.bin")
    remover = PasswordRemover()
    report = remover.remove_passwords(intel_ifd, out)

    assert report.status.name == "SUCCESS"
    with open(out, "rb") as f:
        data = f.read()
    target = b"A\x00M\x00I\x00T\x00S\x00E\x00S\x00e\x00t\x00u\x00p\x00"
    assert target not in data, "password variable should be zeroed"

    # Re-scan the cleared image: it must no longer report the AMI variable.
    found_after = PasswordRemover().find_password_in_dump(out)
    assert "AMI_SETUP_PASSWORD" not in {f["type"] for f in found_after}


def test_dell_master_password_generation():
    pw = PasswordRemover()
    passwords = pw.generate_dell_master_password("ABC1234", "595B")
    assert passwords, "should generate at least one password"
    for p in passwords:
        assert len(p) == 8
        assert p.isdigit()


def test_hp_master_password_generation():
    pw = PasswordRemover()
    assert int(pw.generate_hp_master_password("12345")) == 37042


def test_insyde_master_password_generation():
    pw = PasswordRemover()
    assert len(pw.generate_insyde_master_password("12345678")) == 8