"""Writers refuse an output path that is their input and leave the input untouched (audit F-05)."""

import pytest


@pytest.fixture
def image(tmp_path):
    path = tmp_path / "dump.bin"
    path.write_bytes(b"\xff" * 0x20000)
    return path


def _unchanged(path, before):
    return path.read_bytes() == before


def test_password_remover_refuses_same_path(image):
    from bios_recovery.core.password_remover import PasswordRemovalResult, PasswordRemover

    before = image.read_bytes()
    rep = PasswordRemover().remove_passwords(str(image), str(image))
    assert rep.status == PasswordRemovalResult.ERROR
    assert _unchanged(image, before)


def test_dmi_editor_refuses_same_path(image):
    from bios_recovery.core.dmi_editor import DMIEditor

    before = image.read_bytes()
    rep = DMIEditor().set_identity(str(image), str(image), serial="ABC123")
    assert not rep.success
    assert _unchanged(image, before)


def test_hp_unlocker_refuses_same_path(image):
    from bios_recovery.manufacturers.hp.hp_unlocker import HPUnlocker

    before = image.read_bytes()
    report = HPUnlocker().unlock(str(image), str(image))
    assert not report["success"]
    assert _unchanged(image, before)


def test_me_cleaner_refuses_same_path(image):
    from bios_recovery.platforms.intel.me.me_cleaner import IntelMECleaner, MeCleanResult

    before = image.read_bytes()
    rep = IntelMECleaner().clean(str(image), str(image))
    assert rep.status == MeCleanResult.ERROR
    assert _unchanged(image, before)


def test_uefi_patcher_refuses_same_path(image):
    from bios_recovery.platforms.intel.uefi_patcher import UEFIPatcher, UEFIPatchError

    before = image.read_bytes()
    with pytest.raises(UEFIPatchError):
        UEFIPatcher().apply(str(image), str(image))
    assert _unchanged(image, before)
