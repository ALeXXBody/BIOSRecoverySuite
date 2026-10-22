"""Regression tests for DMI extraction and password removal."""

import os

from bios_recovery.core.nvar import is_valid, iter_records
from bios_recovery.core.password_remover import PasswordRemover
from bios_recovery.engines.dmi_extractor import DMIExtractor


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
    with open(intel_ifd, "rb") as f:
        before = f.read()
    with open(out, "rb") as f:
        after = f.read()

    assert len(after) == len(before)
    changed = [i for i in range(len(before)) if before[i] != after[i]]
    assert changed, "the password record should be marked invalid"
    records = [r for r in iter_records(after) if r.name == "AMITSESetup"]
    assert records and not any(is_valid(r) for r in records)
    assert all(r.name for r in iter_records(after)), "other records must still parse"


def test_password_removal_does_not_write_unverified_markers(tmp_path):
    src = tmp_path / "markers.bin"
    src.write_bytes(b"\x00" * 0x2000 + b"cE!" + b"\x00" * 0x2000)
    out = str(tmp_path / "nopass.bin")

    report = PasswordRemover().remove_passwords(str(src), out)

    assert report.status.name == "PARTIAL"
    assert not os.path.exists(out)
    assert src.read_bytes() == b"\x00" * 0x2000 + b"cE!" + b"\x00" * 0x2000


def test_password_removal_refuses_output_equal_to_input(intel_ifd):
    with open(intel_ifd, "rb") as f:
        before = f.read()
    report = PasswordRemover().remove_passwords(intel_ifd, intel_ifd)
    assert report.status.name == "ERROR"
    with open(intel_ifd, "rb") as f:
        assert f.read() == before


def test_dell_master_password_is_refused():
    # no published Dell algorithm is implemented, so no guessed password is returned
    assert PasswordRemover().generate_dell_master_password("1234567", "595B") == ["46rg65ky"]
    assert PasswordRemover().generate_dell_master_password("ABC1234", "NOPE") == []


def test_hp_master_password_is_refused():
    assert PasswordRemover().generate_hp_master_password("12345") == ""
    assert PasswordRemover().generate_hp_master_password("A7AF422F") == "49163252"


def test_insyde_master_password_generation():
    pw = PasswordRemover()
    assert len(pw.generate_insyde_master_password("12345678")) == 8
