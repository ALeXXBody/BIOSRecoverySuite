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


def test_unreadable_state_reports_a_reason_not_a_state(monkeypatch, tmp_path):
    """When the analyzer cannot read the image, the helper must return ("", reason)."""
    import bios_recovery.platforms.intel.me.me_details as details
    from bios_recovery.platforms.intel.me.me_cleaner import IntelMECleaner

    monkeypatch.setattr(
        details,
        "engine_details",
        lambda p: {"found": False, "reason": "no engine detail"},
        raising=False,
    )
    state, reason = IntelMECleaner()._read_file_system_state(str(tmp_path / "missing.bin"))
    assert state == ""
    assert reason == "no engine detail"


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


def test_state_empty_failure_path_reports_analyzer_reason(monkeypatch, tmp_path):
    """A crashed/unreadable analyzer must be reported, never mapped to a state."""
    from bios_recovery.platforms.intel.me import me_cleaner as mod
    from bios_recovery.platforms.intel.me.me_cleaner import IntelMECleaner

    monkeypatch.setattr(
        "bios_recovery.platforms.intel.me.me_details.engine_details",
        lambda p: {"found": False, "reason": "analyzer crashed"},
        raising=False,
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
    monkeypatch.setattr(IntelMECleaner, "_read_flmap1", lambda self, data, fd: 0x18)

    src = tmp_path / "image.bin"
    src.write_bytes(b"$CPD" + b"\x00" * (0x2000 - 4) + bytes.fromhex("f88f"))
    out = tmp_path / "out.bin"

    report = IntelMECleaner().clean(str(src), str(out), soft_disable=True)
    lines = "\n".join(report.messages)
    assert "could not be read" in lines
    assert "Unconfigured (RGN)" not in lines, "a crashed analyzer must not be labeled RGN"


def test_state_empty_reports_csme10_wording(monkeypatch, tmp_path):
    """CSME <= 10: ME Analyzer does not print the field; the report says so."""
    from bios_recovery.platforms.intel.me import me_cleaner as mod
    from bios_recovery.platforms.intel.me.me_cleaner import IntelMECleaner

    monkeypatch.setattr(
        "bios_recovery.platforms.intel.me.me_details.engine_details",
        lambda p: {"found": True, "engines": [("ME", {})]},
        raising=False,
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
