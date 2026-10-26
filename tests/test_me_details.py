"""ME detail lines: the analyzer report reduced to one line per field."""

import pytest

from bios_recovery.platforms.intel.me import me_details
from bios_recovery.platforms.intel.me.mea_bridge import MEAResult


def _engine(**overrides):
    entry = {
        "Family": "CSE ME",
        "Version": "16.1.25.1991",
        "Release": "Production",
        "Type": "Extracted",
        "SKU": "Consumer H",
        "Chipset": "Unknown",
        "TCB Security Version Number": "1",
        "ARB Security Version Number": "4",
        "Version Control Number": "14",
        "Production Ready": "Yes",
        "OEM Configuration": "Yes",
        "FWUpdate Support": "No",
        "Date": "2022-08-29",
        "File System State": "Initialized",
        "Size": "0x3DA000",
        "Flash Image Tool": "16.1.25.1991",
        "MEA Database Name": "16.1.25.1991_CON_H_X_PRD_EXTR",
    }
    entry.update(overrides)
    return entry


def _report():
    """The shape ME Analyzer writes: sections per firmware, plus Messages."""
    return {
        "image.bin": {
            "Management Engine": [_engine()],
            "Power Management Controller": [
                {"Family": "PMC", "Version": "160.2.00.1039", "Type": "Independent"}
            ],
            "USB Type C Physical": [
                {"Family": "PHY", "Version": "13.57.211.7252", "Type": "Independent"}
            ],
            "Messages": ["Error: Unsupported Intel Engine"],
        }
    }


def test_only_engine_entries_are_kept():
    entries = me_details.engine_entries(_report())

    assert [name for name, _entry in entries] == ["Management Engine"]
    assert entries[0][1]["Family"] == "CSE ME"


def test_fields_are_the_full_analyzer_set_in_order():
    entry = me_details.engine_entries(_report())[0][1]

    labels = [label for label, _value in me_details.engine_fields(entry)]

    assert labels == [
        "Family",
        "Version",
        "Release",
        "Type",
        "SKU",
        "Chipset",
        "TCB SVN",
        "ARB SVN",
        "VCN",
        "Production Ready",
        "OEM Configuration",
        "FWUpdate Support",
        "Date",
        "File System State",
        "Size",
        "Flash Image Tool",
        "MEA Database Name",
    ]


def test_unknown_values_are_left_out_instead_of_guessed():
    entry = _engine(Chipset=None, SKU="NaN", Date="")

    labels = [label for label, _value in me_details.engine_fields(entry)]

    assert "Chipset" not in labels and "SKU" not in labels and "Date" not in labels
    assert "Version" in labels


def test_na_is_kept_because_it_is_a_real_answer():
    entry = _engine(**{"Flash Image Tool": "N/A"})

    lines = me_details.format_engines([("Management Engine", entry)])

    assert "Flash Image Tool: N/A" in lines


def test_one_engine_has_no_heading():
    lines = me_details.format_engines([("Management Engine", _engine())])

    assert lines[0] == "Family: CSE ME"
    assert "MEA Database Name: 16.1.25.1991_CON_H_X_PRD_EXTR" in lines


def test_two_engines_are_labelled_and_not_split_by_a_trailing_blank():
    lines = me_details.format_engines(
        [("Management Engine", _engine()), ("Management Engine", _engine(Version="1.2.3.4"))]
    )

    assert lines[0] == "Engine 1 (Management Engine):"
    assert "  Version: 16.1.25.1991" in lines
    assert "Engine 2 (Management Engine):" in lines
    assert "  Version: 1.2.3.4" in lines
    assert lines[-1] != ""


def test_details_from_the_analyzer_report(monkeypatch):
    monkeypatch.setattr(
        "bios_recovery.platforms.intel.me.mea_bridge.run_mea_analyzer",
        lambda path: MEAResult(success=True, json_data=_report()),
    )

    details = me_details.engine_details("image.bin")

    assert details["found"] is True
    assert "Family: CSE ME" in details["lines"]
    assert "MEA Database Name: 16.1.25.1991_CON_H_X_PRD_EXTR" in details["lines"]


def test_an_unreadable_image_says_so_in_one_line(monkeypatch):
    monkeypatch.setattr(
        "bios_recovery.platforms.intel.me.mea_bridge.run_mea_analyzer",
        lambda path: MEAResult(success=False, error="No JSON output (return code 1)"),
    )

    details = me_details.engine_details("image.bin")

    assert details["found"] is False
    assert details["reason"] == "This image has no engine data ME Analyzer could read."


def test_a_missing_analyzer_dependency_is_reported_as_a_suite_problem(monkeypatch):
    monkeypatch.setattr(
        "bios_recovery.platforms.intel.me.mea_bridge.run_mea_analyzer",
        lambda path: MEAResult(
            success=False,
            error="No JSON output",
            stdout=(
                'Error: Dependency "crccheck" is missing!\n'
                '       Install via "pip3 install crccheck"'
            ),
        ),
    )

    details = me_details.engine_details("image.bin")

    assert details["reason"] == "The bundled ME Analyzer is incomplete; reinstall the suite."


def test_a_timeout_keeps_the_timeout_wording(monkeypatch):
    monkeypatch.setattr(
        "bios_recovery.platforms.intel.me.mea_bridge.run_mea_analyzer",
        lambda path: MEAResult(success=False, error="ME Analyzer timed out (300s)"),
    )

    details = me_details.engine_details("image.bin")

    assert details["reason"] == "ME Analyzer timed out on this image."


def test_a_report_without_an_engine_is_not_found(monkeypatch):
    report = {"image.bin": {"Power Management Controller": [{"Family": "PMC"}], "Messages": []}}
    monkeypatch.setattr(
        "bios_recovery.platforms.intel.me.mea_bridge.run_mea_analyzer",
        lambda path: MEAResult(success=True, json_data=report),
    )

    details = me_details.engine_details("image.bin")

    assert details["found"] is False


@pytest.mark.parametrize("bad", [Exception("boom")])
def test_a_broken_analyzer_does_not_raise(monkeypatch, bad):
    def boom(path):
        raise bad

    monkeypatch.setattr("bios_recovery.platforms.intel.me.mea_bridge.run_mea_analyzer", boom)

    details = me_details.engine_details("image.bin")

    assert details["found"] is False
    assert "could not run" in details["reason"]
