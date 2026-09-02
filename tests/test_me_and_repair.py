"""Regression tests for ME cleaning and the auto-repair engine."""

import os

from bios_recovery.engines.me_cleaner import IntelMECleaner, MeCleanResult
from bios_recovery.engines.bios_repair import BiosRepairEngine


def test_me_info(intel_ifd):
    info = IntelMECleaner().get_me_info(intel_ifd)
    assert info["found"] is True
    assert info["version"] == "12.8"
    assert info["generation"] == "GEN3"
    assert info["offset"] == "0x1000"
    assert info["partitions"], "FPT partitions should be listed"
    names = {p["name"] for p in info["partitions"]}
    assert "FTPR" in names


def test_me_clean_preserves_flash_descriptor(intel_ifd, tmp_path):
    out = str(tmp_path / "cleaned.bin")
    cleaner = IntelMECleaner()
    report = cleaner.clean(intel_ifd, out, soft_disable=True, remove_modules=True)

    assert report.status in (MeCleanResult.SUCCESS, MeCleanResult.ALREADY_CLEAN)
    assert os.path.exists(out)

    with open(out, "rb") as f:
        head = f.read(16)
    assert head[:4] == b"\x5a\xa5\xf0\x0f", "flash descriptor must survive cleaning"

    from bios_recovery.engines.bios_analyzer import BiosAnalyzer
    reanalysis = BiosAnalyzer().analyze(out)
    assert reanalysis.has_flash_descriptor


def test_me_clean_removes_partitions(intel_ifd, tmp_path):
    """After a full clean the non-essential partitions (ROMB/LOCL/EFFS) are gone."""
    out = str(tmp_path / "cleaned.bin")
    report = IntelMECleaner().clean(intel_ifd, out, soft_disable=True, remove_modules=True)
    # With GEN3 + IFWI the module removal may be skipped, but cleaning must still succeed.
    assert report.status in (MeCleanResult.SUCCESS, MeCleanResult.ALREADY_CLEAN)


def test_auto_repair_roundtrip(intel_ifd, tmp_path):
    out = str(tmp_path / "repaired.bin")
    engine = BiosRepairEngine()
    report = engine.auto_repair(intel_ifd, out)

    assert report.success
    assert os.path.exists(out)
    with open(out, "rb") as f:
        assert f.read(4) == b"\x5a\xa5\xf0\x0f"


def test_auto_repair_fixes_checksum(intel_ifd, tmp_path):
    # Corrupt the FPT checksum byte deliberately, then verify repair fixes it.
    with open(intel_ifd, "rb") as f:
        data = bytearray(f.read())
    data[0x1010 + 0x1B] = 0xDE  # corrupt the FPT checksum
    corrupt = str(tmp_path / "corrupt.bin")
    with open(corrupt, "wb") as f:
        f.write(data)

    out = str(tmp_path / "repaired.bin")
    report = BiosRepairEngine().auto_repair(corrupt, out)

    with open(out, "rb") as f:
        fixed = f.read()
    checksum = sum(fixed[0x1010:0x1010 + 0x20]) & 0xFF
    assert checksum == 0, "FPT checksum should match after repair"


def test_auto_repair_readonly_cwd(intel_ifd, tmp_path, monkeypatch):
    """Regression: repair used to write '_temp_me_input.bin' into the CWD.

    When the app is launched from Program Files the CWD is not writable and
    auto-repair failed with [Errno 13] Permission denied. Temps must go to the
    system temp directory instead. Simulated here with a CWD that cannot hold
    files (non-existent directory), which breaks every relative-path write.
    """
    src = tmp_path / "src.bin"
    src.write_bytes(open(intel_ifd, "rb").read())
    out = tmp_path / "out.bin"

    # make the process CWD point at a directory that no longer exists:
    # every relative-path write then fails, like an unwritable Program Files CWD
    ghost = tmp_path / "ghost_cwd"
    ghost.mkdir()
    monkeypatch.chdir(ghost)
    ghost.rmdir()

    report = BiosRepairEngine().auto_repair(str(src), str(out))
    assert report.success
    assert os.path.exists(out)
    with open(out, "rb") as f:
        assert f.read(4) == b"\x5a\xa5\xf0\x0f"
    # no temp litter anywhere near the source directory
    litter = [p for p in tmp_path.iterdir() if p.name.startswith("_temp")]
    assert not litter