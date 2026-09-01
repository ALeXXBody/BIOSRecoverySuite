"""Regression tests for the EC firmware analysis and patch engine."""

import os

from bios_recovery.engines.ec_patcher import ECPatcher, ECController, ECStatus


def test_ec_found_in_top_of_dump(ec_dump):
    patcher = ECPatcher()
    with open(ec_dump, "rb") as f:
        data = f.read()
    analysis = patcher.analyze_ec(data)

    assert analysis.found
    assert analysis.offset >= 0
    assert analysis.size >= 0x10000
    assert len(analysis.raw) > 0
    assert analysis.controller == ECController.ITE


def test_ec_controller_detection(ec_firmware):
    patcher = ECPatcher()
    analysis = patcher.analyze_ec(open(ec_firmware, "rb").read())
    assert analysis.controller == ECController.ITE
    assert "IT8587E" in analysis.raw[:0x20].decode("latin1")


def test_password_flags_scanned(ec_dump):
    patcher = ECPatcher()
    analysis = patcher.analyze_ec(open(ec_dump, "rb").read())
    names = {f["name"] for f in analysis.password_flags}
    assert "PasswordStatus" in names
    assert "UnLock" in names


def test_kbc_config_detected(ec_dump):
    analysis = ECPatcher().analyze_ec(open(ec_dump, "rb").read())
    assert analysis.has_kbc_config


def test_checksum_valid(ec_firmware):
    analysis = ECPatcher().analyze_ec(open(ec_firmware, "rb").read())
    assert analysis.checksum_valid is True


def test_extract_ec_from_dump(ec_dump, tmp_path):
    out = str(tmp_path / "ec.bin")
    result = ECPatcher().extract_ec(ec_dump, out)
    assert result.status == ECStatus.SUCCESS
    assert os.path.exists(out)
    assert os.path.getsize(out) >= 0x10000


def test_patch_registry_loaded():
    patcher = ECPatcher()
    patches = patcher.list_patches()
    assert any(p.vendor.lower() == "lenovo" for p in patches)


def test_unverified_patch_refused(ec_firmware, tmp_path):
    patcher = ECPatcher()
    result = patcher.apply_patch(ec_firmware, "lenovo_t430_e147_gen3_disable_unlock_flag",
                                 require_verified=True)
    assert result.status == ECStatus.UNVERIFIED


def test_unverified_patch_forced(ec_firmware, tmp_path):
    out = str(tmp_path / "patched.bin")
    patcher = ECPatcher()
    result = patcher.apply_patch(
        ec_firmware,
        "lenovo_t430_e147_gen3_disable_unlock_flag",
        output_path=out,
        require_verified=False,
    )
    assert result.status == ECStatus.SUCCESS
    assert result.offset >= 0
    assert os.path.exists(out)
    with open(out, "rb") as f:
        patched = f.read()
    assert b"UnLock" not in patched


def test_missing_signature_reports_pattern_missing(intel_ifd, tmp_path):
    patcher = ECPatcher()
    result = patcher.apply_patch(
        intel_ifd,
        "lenovo_t430_e147_gen3_disable_unlock_flag",
        require_verified=False,
    )
    # An Intel flash-descriptor dump carries no EC 'UnLock' marker
    assert result.status == ECStatus.PATTERN_MISSING