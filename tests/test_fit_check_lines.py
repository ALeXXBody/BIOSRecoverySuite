"""The "Tools for this image" output is exactly three lines when a match exists.

The user's contract, verbatim:
    Image: Lenovo P14s U2201 good.bin
    ME:    15.0.55.2751 - needs FIT 15.0

    Matching tool: FIT 15.0.35.1951 (Windows)
Anything the library holds beyond the matching tool is not part of the answer
and is not printed.
"""

from bios_recovery.platforms.intel.me.fit_check import FitCheck, ToolRow


def _row(family, version, platform="Windows", compatible=True):
    return ToolRow(
        family=family,
        version=version,
        platform=platform,
        release="",
        path="/x",
        compatible=compatible,
        reason="",
    )


def _check_with(rows):
    return FitCheck(
        image="Lenovo P14s U2201 good.bin",
        me_version="15.0.55.2751",
        release="v15.0",
        confidence="normal",
        note="",
        tools=rows,
    )


def test_exact_contract_with_a_match():
    rows = [_row("FIT", "15.0.35.1951")] + [
        _row("FIT", f"11.8.{i}.1", compatible=False) for i in range(9)
    ]
    lines = _check_with(rows).lines()
    assert lines == [
        "Image: Lenovo P14s U2201 good.bin",
        "ME:    15.0.55.2751 - needs FIT 15.0",
        "",
        "Matching tool: FIT 15.0.35.1951 (Windows)",
    ]


def test_identical_entries_do_not_duplicate_the_matching_line():
    rows = [
        _row("FIT", "15.0.35.1951"),
        _row("FIT", "15.0.35.1951"),
    ]
    assert _check_with(rows).lines().count("Matching tool: FIT 15.0.35.1951 (Windows)") == 1


def test_no_match_says_what_to_add_and_nothing_else():
    text = "\n".join(_check_with([_row("FIT", "", platform="Linux", compatible=False)]).lines())
    assert "Add the CSME 15.0 System Tools folder in Settings." in text
    assert "Matching tool: none" in text
    # nothing else about the library contents
    assert "not identified" not in text


def test_empty_library_message_stays():
    lines = _check_with([]).lines()
    assert lines[-1] == "No Intel tools found. Add the CSME 15.0 System Tools folder in Settings."
