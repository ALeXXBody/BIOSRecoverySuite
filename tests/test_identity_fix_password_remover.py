"""Identity audit fixes for password removal and the generators it exposes."""

import os

from bios_recovery.core.password_remover import PasswordRemover, PasswordType
from bios_recovery.utils.master_passwords import insyde_8dec


def test_password_types_limits_what_is_written(intel_ifd, tmp_path):
    out = str(tmp_path / "nopass.bin")
    report = PasswordRemover().remove_passwords(
        intel_ifd, out, password_types=[PasswordType.HP_PASSWORD]
    )

    assert report.status.name != "SUCCESS"
    assert not os.path.exists(out)


def test_password_types_still_clears_the_requested_ami_record(intel_ifd, tmp_path):
    out = str(tmp_path / "nopass.bin")
    report = PasswordRemover().remove_passwords(
        intel_ifd, out, password_types=[PasswordType.AMI_SETUP_PASSWORD]
    )

    assert report.status.name == "SUCCESS"
    assert os.path.exists(out)


def test_byte_patterns_are_reported_but_never_zeroed(tmp_path):
    # zero runs, 0xFF runs, Dell and UEFI-looking markers: none is a verified password store
    image = bytearray(b"\x00" * 0x3000 + b"\xff" * 0x3000)
    image[0x100:0x104] = b"\x34\x00\x00\x00"
    image[0x200:0x204] = b"8FC8"
    src = tmp_path / "patterns.bin"
    src.write_bytes(bytes(image))
    out = str(tmp_path / "nopass.bin")

    report = PasswordRemover().remove_passwords(str(src), out)

    assert report.status.name in ("PARTIAL", "NOT_FOUND")
    assert not os.path.exists(out)
    assert src.read_bytes() == bytes(image)


def test_insyde_generator_is_the_insyde_algorithm_not_identity():
    assert PasswordRemover().generate_insyde_master_password("12345678") == insyde_8dec("12345678")
    assert PasswordRemover().generate_insyde_master_password("12345678") != "12345678"


def test_insyde_generator_refuses_short_input():
    assert PasswordRemover().generate_insyde_master_password("123") == ""


def test_find_password_in_dump_marks_generic_words_low_confidence(tmp_path):
    src = tmp_path / "text.bin"
    src.write_bytes(b"\x00" * 16 + b"Admin" + b"\x00" * 16 + b"AMITSESetup" + b"\x00" * 16)
    found = PasswordRemover().find_password_in_dump(str(src))
    by_type = {f["type"]: f for f in found}
    assert by_type["HP_PASSWORD"]["confidence"] == "low"
    assert by_type["AMI_SETUP_PASSWORD"]["confidence"] == "normal"
