"""The "Tools for this image" output must not bury the answer.

The feature answers one question — "which Intel tool does this image need, and
do I own it?" — so the report keeps: the image, the needed tool, the matching
tool, a summarised incompatible list, and an aggregated unidentified count.
A library holding dozens of FIT builds used to produce a wall of noise rows.
"""

from bios_recovery.platforms.intel.me.fit_check import FitCheck, ToolRow


def _row(family, version, platform="Windows", path="/x", compatible=True, reason=""):
    return ToolRow(
        family=family,
        version=version,
        platform=platform,
        release=reason,
        path=path,
        compatible=compatible,
        reason=reason,
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


def test_matches_first_and_keeps_the_report_short():
    rows = [_row("FIT", "15.0.35.1951", compatible=True)] + [
        _row("FIT", f"11.8.{i}.1", compatible=False) for i in range(9)
    ]
    lines = _check_with(rows).lines()
    text = "\n".join(lines)
    assert "Matching tool: FIT 15.0.35.1951 (Windows)" in text
    # Only a handful of incompatible rows are named; the rest are collapsed.
    assert "(+3 more)" in text
    assert lines[0] == "Image: Lenovo P14s U2201 good.bin"


def test_duplicate_library_entries_do_not_repeat():
    rows = [
        _row("FIT", "15.0.35.1951", compatible=True),
        _row("FIT", "15.0.35.1951", compatible=True),
        _row("FIT", "13.30.0.1065", compatible=False),
        _row("FIT", "13.30.0.1065", compatible=False),
    ]
    text = "\n".join(_check_with(rows).lines())
    assert text.count("FIT 15.0.35.1951") == 1
    assert text.count("FIT 13.30.0.1065") == 1


def test_unidentified_entries_are_summarized_not_listed():
    rows = [
        _row("FIT", "", platform="Linux", compatible=False),
        _row("FIT", "", platform="Linux", compatible=False),
        _row("unidentified", "", platform="unknown", compatible=False),
    ]
    text = "\n".join(_check_with(rows).lines())
    assert "Unidentified library entries (ignored): 3" in text
    assert "(not identified)" not in text


def test_clean_high_needs_message_only_mentions_what_is_missing():
    ffc = _check_with([])
    lines = ffc.lines()
    assert ("No Intel tools found. Add the CSME 15.0 System Tools folder in "
            "Settings.") in "\n".join(lines)
