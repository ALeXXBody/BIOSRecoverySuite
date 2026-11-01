"""EC firmware version detection.

The point of this feature: a ThinkPad EC dump whose version token differs from
the platform's expectations is the failure class where a donor chip pair keeps
a machine from booting until the EC update capsule re-baselines it. Verifying
the version *before* flashing is the whole reason this reader exists.
"""


from bios_recovery.platforms.ec.ec_version import scan_ec_firmware_version


def test_real_style_thinkpad_tokens():
    for token in (b"N2IHT39W", b"R16ET35W", b"N2RET26W"):
        ec = bytearray(b"\xff" * 0x1000)
        ec[0x600:0x608] = token
        res = scan_ec_firmware_version(bytes(ec))
        assert res.version == token.decode()
        assert res.offset == 0x600


def test_rightmost_token_is_the_reported_one():
    ec = bytearray(b"\xff" * 0x400)
    ec[0x100:0x108] = b"N2IHT39W"
    ec[0x200:0x208] = b"R16ET35W"
    res = scan_ec_firmware_version(bytes(ec))
    assert res.version == "R16ET35W"
    assert res.offset == 0x200


def test_embedded_token_is_not_double_reported():
    # a token glued inside a longer alphanumeric run must not match
    ec = bytearray(b"\xff" * 0x200)
    ec[0x80:0x90] = b"XXN2IHT39WYY"
    res = scan_ec_firmware_version(bytes(ec))
    assert res.version == ""


def test_blank_region_reports_not_found_with_note():
    res = scan_ec_firmware_version(b"\xff" * 0x800)
    assert res.version == ""
    assert res.offset == -1
    assert "not found" in res.note or "No " in res.note


def test_empty_input_is_not_a_hit():
    assert scan_ec_firmware_version(b"").version == ""


def test_nan_tokens_do_not_partial_match():
    # engineered look-alikes inside device strings are left out on purpose:
    # only the strict ThinkPad shape and position qualify
    ec = bytearray(b"\xff" * 0x300)
    ec[0x40:0x50] = b"MEC1724N-L0P"  # chip name, not a firmware version
    res = scan_ec_firmware_version(bytes(ec))
    assert res.version == ""


def test_analyze_ec_carries_the_version_into_the_analysis():
    """analyze_ec wires the version into its report (so the GUI can show it)."""
    import sys

    sys.path.insert(0, "tests")
    from test_ec_patcher import _lenovo_15ahp9_style_dump

    from bios_recovery.platforms.ec.ec_patcher import ECPatcher

    data, _ = _lenovo_15ahp9_style_dump()
    # plant one version token inside the located EC region
    patcher = ECPatcher()
    start, size = patcher.find_ec_region(data)
    end = start + size
    assert end > start
    work = bytearray(data)
    work[start + 0x2000 : start + 0x2008] = b"N2IHT39W"
    result = patcher.analyze_ec(bytes(work))
    assert result.ec_version == "N2IHT39W"
