"""File System State (RGN / EXTR / Dirty EXTR) wiring in ME Analyzer's field set.

The user-visible contract: the ME Cleaner report always names the File System
State, maps it to the analyzer's documented forms — Unconfigured (RGN),
Configured (EXTR), Initialized (Dirty EXTR) — and carries the corresponding
advice so the operator knows what a flashed region will do at first POST.
"""



def test_engine_fields_maps_file_system_states():
    from bios_recovery.platforms.intel.me.me_details import engine_fields

    for raw, expected in (
        ("Unconfigured", "Unconfigured (RGN)"),
        ("Configured", "Configured (EXTR)"),
        ("Initialized", "Initialized (Dirty EXTR)"),
    ):
        fields = engine_fields({"File System State": raw})
        assert ("File System State", expected) in fields, (raw, fields)


def test_unreadable_state_falls_back_to_unconfigured_wording(monkeypatch, tmp_path):
    import bios_recovery.platforms.intel.me.me_details as details
    from bios_recovery.platforms.intel.me.me_cleaner import IntelMECleaner

    monkeypatch.setattr(
        details, "engine_details", lambda p: {"found": False}, raising=False
    )
    value = IntelMECleaner()._read_file_system_state(str(tmp_path / "missing.bin"))
    assert value == ""
def test_state_unconfigured_is_the_bad_donor_state(monkeypatch, tmp_path):
    """RGN = stock/unconfigured. NOT flashable as-is; not a donor."""
    from bios_recovery.platforms.intel.me import me_cleaner as mod
    from bios_recovery.platforms.intel.me.me_cleaner import IntelMECleaner, MeCleanResult

    fake = {"found": True,
            "engines": [("CSME", {"File System State": "Unconfigured"})]}
    monkeypatch.setattr(
        "bios_recovery.platforms.intel.me.me_details.engine_details", lambda p: fake
    )
    monkeypatch.setattr(
        IntelMECleaner, "_get_me_version", lambda self, d, s, e: "15.0.55.2751", raising=False
    )
    monkeypatch.setattr(
        IntelMECleaner,
        "_find_me_region",
        lambda self, data: (0x0, len(data), mod.MeGeneration.GEN3),
    )
    monkeypatch.setattr(IntelMECleaner, "_is_already_clean", lambda self, d, s, e: False)
    monkeypatch.setattr(IntelMECleaner, "_read_flmap1", lambda self, data, fd: None)

    src = tmp_path / "image.bin"
    src.write_bytes(b"$CPD" + b"\x00" * (0x2000 - 4) + bytes.fromhex("f88f"))
    out = tmp_path / "out.bin"

    report = IntelMECleaner().clean(str(src), str(out), soft_disable=True)
    lines = "\n".join(report.messages)
    assert report.file_system_state == "Unconfigured"
    assert "File System State: Unconfigured (RGN)" in lines
    assert "Never flash RGN without first configuring it" in lines
    assert "Intel Flash Image Tool (FIT)" in lines
    assert "via Intel Flash Image Tool" in lines
    assert report.status == MeCleanResult.SUCCESS


def test_state_configured_is_the_good_donor_state(monkeypatch, tmp_path):
    """EXTR-A: OEM-configured via FIT, not bound to any machine — correct donor."""
    from bios_recovery.platforms.intel.me import me_cleaner as mod
    from bios_recovery.platforms.intel.me.me_cleaner import IntelMECleaner, MeCleanResult

    fake = {"found": True, "engines": [("CSME", {"File System State": "Configured"})]}
    monkeypatch.setattr(
        "bios_recovery.platforms.intel.me.me_details.engine_details", lambda p: fake
    )
    monkeypatch.setattr(
        IntelMECleaner, "_get_me_version", lambda self, d, s, e: "15.0.55.2751", raising=False
    )
    monkeypatch.setattr(
        IntelMECleaner,
        "_find_me_region",
        lambda self, data: (0x0, len(data), mod.MeGeneration.GEN3),
    )
    monkeypatch.setattr(IntelMECleaner, "_is_already_clean", lambda self, d, s, e: False)
    monkeypatch.setattr(IntelMECleaner, "_read_flmap1", lambda self, data, fd: None)

    src = tmp_path / "image.bin"
    src.write_bytes(b"$CPD" + b"\x00" * (0x2000 - 4) + bytes.fromhex("f88f"))
    out = tmp_path / "out.bin"

    report = IntelMECleaner().clean(str(src), str(out), soft_disable=True)
    lines = "\n".join(report.messages)
    assert "File System State: Configured (EXTR)" in lines
    assert "donor state you want" in lines
    assert "NOT bound to any machine's" in lines
    assert report.status == MeCleanResult.SUCCESS


def test_state_initialized_dirty_has_fit_roundtrip_guidance(monkeypatch, tmp_path):
    """Dirty EXTR: donor came from a machine that ran; FIT round-trip is the fix."""
    from bios_recovery.platforms.intel.me import me_cleaner as mod
    from bios_recovery.platforms.intel.me.me_cleaner import IntelMECleaner, MeCleanResult

    fake = {"found": True,
            "engines": [("CSME", {"File System State": "Initialized"})]}
    monkeypatch.setattr(
        "bios_recovery.platforms.intel.me.me_details.engine_details", lambda p: fake
    )
    monkeypatch.setattr(
        IntelMECleaner, "_get_me_version", lambda self, d, s, e: "15.0.55.2751", raising=False
    )
    monkeypatch.setattr(
        IntelMECleaner,
        "_find_me_region",
        lambda self, data: (0x0, len(data), mod.MeGeneration.GEN3),
    )
    monkeypatch.setattr(IntelMECleaner, "_is_already_clean", lambda self, d, s, e: False)
    monkeypatch.setattr(IntelMECleaner, "_read_flmap1", lambda self, data, fd: None)

    src = tmp_path / "image.bin"
    src.write_bytes(b"$CPD" + b"\x00" * (0x2000 - 4) + bytes.fromhex("f88f"))
    out = tmp_path / "out.bin"

    report = IntelMECleaner().clean(str(src), str(out), soft_disable=True)
    lines = "\n".join(report.messages)
    assert "File System State: Initialized (Dirty EXTR)" in lines
    assert "second-boot problems" in lines
    assert "Intel Flash Image Tool round-trip" in lines
    assert "second-boot problems and sleep failures" in lines
    assert "not raw byte edits and not the HAP bit" in lines
    assert report.status == MeCleanResult.SUCCESS


def test_state_empty_is_reported_not_guessed(monkeypatch, tmp_path):
    """CSME <= 10 (or analyzer failure): say the state simply isn't reported."""
    from bios_recovery.platforms.intel.me import me_cleaner as mod
    from bios_recovery.platforms.intel.me.me_cleaner import IntelMECleaner

    monkeypatch.setattr(
        "bios_recovery.platforms.intel.me.me_details.engine_details",
        lambda p: {"found": False},
    )
    monkeypatch.setattr(
        IntelMECleaner, "_get_me_version", lambda self, d, s, e: "9.1.37.1002", raising=False
    )
    monkeypatch.setattr(
        IntelMECleaner,
        "_find_me_region",
        lambda self, data: (0x0, len(data), mod.MeGeneration.GEN2),
    )
    monkeypatch.setattr(IntelMECleaner, "_is_already_clean", lambda self, d, s, e: False)
    monkeypatch.setattr(IntelMECleaner, "_read_flmap1", lambda self, data, fd: None)

    src = tmp_path / "image.bin"
    src.write_bytes(b"$FPT" + b"\x00" * (0x2000 - 4))
    out = tmp_path / "out.bin"

    report = IntelMECleaner().clean(str(src), str(out), soft_disable=True)
    lines = "\n".join(report.messages)
    assert "File System State not reported" in lines
    assert "Initialized (Dirty EXTR) by default" in lines
