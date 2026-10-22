"""Flash Image Tool support: ME-to-release mapping, binary identification, CLI."""

import os
import stat

import pytest

from bios_recovery.platforms.intel.me.fit_bridge import (
    ToolProbe,
    compatible_with_me,
    probe_tool,
)
from bios_recovery.platforms.intel.me.fit_versions import tool_for_me_version

POSIX_ONLY = pytest.mark.skipif(os.name == "nt", reason="uses POSIX shell scripts")


@pytest.mark.parametrize(
    "me, release, confidence",
    [
        ("15.0.3.1402", "v15.0 r15", "listed"),
        ("15.40.1.1000", "v15.40 r3", "listed"),
        ("16.1.25.2091", "v16.1 r0", "inferred"),
        ("14.0.20.1234", "v14.0.20 r20", "listed"),
        ("14.5.0.1", "v14.5 r7", "listed"),
        ("12.0.45.1509", "v12 r38", "listed"),
        ("11.8.50.3470", "v11 r46", "listed"),
        ("9.5.14.1724", "v9.5 r6", "inferred"),
        ("13.0.21.1319", "v13.0 r7", "listed"),
    ],
)
def test_me_version_maps_to_release(me, release, confidence):
    m = tool_for_me_version(me)
    assert m.release == release
    assert m.confidence == confidence


def test_ambiguous_range_is_flagged_not_guessed():
    m = tool_for_me_version("14.0.11.1002")
    assert m.confidence == "ambiguous"


def test_ambiguous_range_refuses_compatibility():
    from bios_recovery.platforms.intel.me.fit_bridge import ToolProbe, compatible_with_me

    probe = ToolProbe(path="x", identified=True, family="FIT", version="14.0.11.1002")
    ok, why = compatible_with_me(probe, "14.0.11.1002")
    assert not ok and "ambiguous" in why


def test_unknown_or_missing_version():
    assert tool_for_me_version("").release is None
    assert tool_for_me_version("garbage").release is None


def test_compatibility_requires_same_release_line():
    probe = ToolProbe(path="x", identified=True, family="MFIT", version="16.1.25.2053")
    assert compatible_with_me(probe, "16.1.25.2091")[0] is True
    ok, why = compatible_with_me(probe, "15.0.3.1402")
    assert ok is False and "belongs to" in why


def test_unidentified_tool_is_never_compatible():
    assert compatible_with_me(ToolProbe(path="x"), "16.1.1.1")[0] is False


@POSIX_ONLY
def test_probe_identifies_linux_mfit(tmp_path):
    tool = tmp_path / "mfit"
    tool.write_text("#!/bin/sh\necho 'Modular Flash Image Tool (LINUX64): 16.1.25.2053'\n")
    tool.chmod(tool.stat().st_mode | stat.S_IXUSR)
    probe = probe_tool(str(tool))
    assert probe.identified and probe.family == "MFIT"
    assert probe.version == "16.1.25.2053" and probe.platform == "LINUX64"


@POSIX_ONLY
def test_probe_refuses_other_programs(tmp_path):
    tool = tmp_path / "other"
    tool.write_text("#!/bin/sh\necho 'hello world'\n")
    tool.chmod(tool.stat().st_mode | stat.S_IXUSR)
    probe = probe_tool(str(tool))
    assert not probe.identified and "not a Flash Image Tool" in probe.error


@POSIX_ONLY
def test_probe_times_out(tmp_path):
    tool = tmp_path / "slow"
    tool.write_text("#!/bin/sh\nsleep 5\n")
    tool.chmod(tool.stat().st_mode | stat.S_IXUSR)
    probe = probe_tool(str(tool), timeout=1)
    assert not probe.identified and "within" in probe.error


def test_probe_refuses_missing_and_non_executable(tmp_path):
    assert "not a file" in probe_tool(str(tmp_path / "nope")).error
    plain = tmp_path / "plain"
    plain.write_text("x")
    if os.name != "nt":
        plain.chmod(0o644)
        assert "not executable" in probe_tool(str(plain)).error


def test_cli_fit_info_reports_release(intel_ifd, capsys):
    from bios_recovery.main import _cli_main

    rc = _cli_main(["fit-info", intel_ifd])
    out = capsys.readouterr().out
    assert rc == 0
    assert "tool release: v12 r38" in out


@POSIX_ONLY
def test_cli_fit_info_checks_supplied_tool(intel_ifd, tmp_path, capsys):
    from bios_recovery.main import _cli_main

    tool = tmp_path / "mfit"
    tool.write_text("#!/bin/sh\necho 'Modular Flash Image Tool (LINUX64): 16.1.25.2053'\n")
    tool.chmod(tool.stat().st_mode | stat.S_IXUSR)
    rc = _cli_main(["fit-info", intel_ifd, "--tool", str(tool)])
    out = capsys.readouterr().out
    assert rc == 4
    assert "compatible:   no" in out


@POSIX_ONLY
def test_probe_uses_help_flag_not_bare_run(tmp_path):
    # A bare run of the real Linux tool opens a window and waits; "-h" prints and exits.
    tool = tmp_path / "fit"
    tool.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = "-h" ]; then '
        "echo 'Intel (R) Flash Image Tool. Version: 15.40.16.2534'; exit 0; fi\n"
        "sleep 30\n"
    )
    tool.chmod(tool.stat().st_mode | stat.S_IXUSR)
    probe = probe_tool(str(tool), timeout=5)
    assert probe.identified and probe.family == "FIT" and probe.version == "15.40.16.2534"


@POSIX_ONLY
def test_fit_from_other_release_line_is_refused(tmp_path):
    tool = tmp_path / "fit"
    tool.write_text("#!/bin/sh\necho 'Intel (R) Flash Image Tool. Version: 15.40.16.2534'\n")
    tool.chmod(tool.stat().st_mode | stat.S_IXUSR)
    probe = probe_tool(str(tool))
    ok, why = compatible_with_me(probe, "15.0.3.1402")
    assert ok is False and "v15.40 r3" in why


@pytest.mark.parametrize(
    "me, release",
    [
        ("16.50.0.1120", "v16.50"),
        ("16.1.25.2053", "v16.1 r0"),
    ],
)
def test_csme_16_50_is_its_own_line(me, release):
    assert tool_for_me_version(me).release == release


def test_mfit_16_50_is_refused_for_16_1_image():
    probe = ToolProbe(path="x", identified=True, family="MFIT", version="16.50.0.1120")
    ok, why = compatible_with_me(probe, "16.1.25.1865")
    assert ok is False and "v16.50" in why
