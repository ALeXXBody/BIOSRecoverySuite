"""Supervisor-password storage diagnosis for ThinkPad generations.

The suite must say *where* the supervisor password hash lives:
in-dump (patchable via cE! backdoor or the badcaps autopatch targets), or in the
EC EEPROM (8th-gen-and-newer ThinkPads, whose hash is not in the SPI dump at all).
"""

from bios_recovery.platforms.intel.uefi_patcher import UEFIPatcher

TAMPER_FB = bytes.fromhex("4C4E564242534543FB")
CE_GUID = UEFIPatcher.CE_BACKDOOR_GUID
AUTO_G1 = UEFIPatcher.AUTOPATCH_TARGET_GUIDS[0]
# No run of 10 zeros/FFs anywhere, so the HP scanner stays quiet
QUIET_PAD = b"\x55\xff\x33\xcc" * 64


def _write(tmp_path, blob, name="img.bin"):
    p = tmp_path / name
    p.write_bytes(blob)
    return str(p)


def _pad(prefix: bytes, after: bytes = QUIET_PAD) -> bytes:
    return prefix + after


def test_diagnosis_ec_eeprom_for_tamper_marker_dump(tmp_path):
    img = _write(tmp_path, _pad(TAMPER_FB))
    d = UEFIPatcher().diagnose_svp_storage(img)
    assert d["location"] == "ec_eeprom"
    assert "EC EEPROM" in d["message"]
    assert "Config Information Update Utility" in d["message"]


def test_diagnosis_backdoor_dump(tmp_path):
    import uuid

    blob = uuid.UUID(CE_GUID).bytes_le + b"cE!" + b"\xff" * 64
    img = _write(tmp_path, blob)
    d = UEFIPatcher().diagnose_svp_storage(img)
    assert d["location"] == "in_dump_backdoor"


def test_diagnosis_autopatch_targets(tmp_path):
    import uuid

    blob = TAMPER_FB + uuid.UUID(AUTO_G1).bytes_le + b"\xff" * 64
    img = _write(tmp_path, blob)
    d = UEFIPatcher().diagnose_svp_storage(img)
    assert d["location"] == "in_dump_autopatch"


def test_diagnosis_unknown_image(tmp_path):
    img = _write(tmp_path, QUIET_PAD)
    d = UEFIPatcher().diagnose_svp_storage(img)
    assert d["location"] == "unknown"


def test_password_remover_lenovo_message(tmp_path):
    from bios_recovery.core.password_remover import (
        PasswordRemovalResult,
        PasswordRemover,
    )

    img = _write(tmp_path, _pad(TAMPER_FB), name="lenovo.bin")
    out = str(tmp_path / "lenovo_out.bin")
    rep = PasswordRemover().remove_passwords(img, out)
    assert rep.status == PasswordRemovalResult.NOT_FOUND
    assert any("EC EEPROM" in m for m in rep.messages)


def test_password_remover_generic_image_message(tmp_path):
    from bios_recovery.core.password_remover import PasswordRemover

    img = _write(tmp_path, QUIET_PAD, name="generic.bin")
    out = str(tmp_path / "generic_out.bin")
    rep = PasswordRemover().remove_passwords(img, out)
    assert any("No recognizable password structures" in m for m in rep.messages)
