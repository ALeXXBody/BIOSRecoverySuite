"""Regression tests for the MEA bridge, FIT probe, injector file checks (M1, L1, L7, L8, 4.7).

MEA and the Flash Image Tool are never run here: subprocess.run is replaced, or a fake tool
script is written into pytest's temporary directory.
"""

import os

import pytest

import bios_recovery.platforms.intel.me.mea_bridge as mea_bridge
from bios_recovery.platforms.intel.me.fit_bridge import (
    ToolProbe,
    compatible_with_me,
    probe_tool,
)
from bios_recovery.platforms.intel.me.me_injector import MEInjector

POSIX_ONLY = pytest.mark.skipif(os.name == "nt", reason="uses POSIX shell scripts")


class _Done:
    returncode = 0
    stdout = "File does not contain Intel Engine/Graphics/Independent Firmware"
    stderr = ""


def test_mea_exit_zero_without_json_is_not_success(tmp_path, monkeypatch):
    monkeypatch.setattr(mea_bridge, "ensure_data_files", lambda: True)
    monkeypatch.setattr(mea_bridge.subprocess, "run", lambda args, **kw: _Done())
    image = tmp_path / "random.bin"
    image.write_bytes(os.urandom(4096))
    result = mea_bridge.run_mea_analyzer(str(image), output_dir=str(tmp_path / "out"))
    assert result.success is False
    assert result.error


def test_mea_gets_an_absolute_input_path(tmp_path, monkeypatch):
    seen = {}

    def fake_run(args, **kw):
        seen["args"] = args
        return _Done()

    monkeypatch.setattr(mea_bridge, "ensure_data_files", lambda: True)
    monkeypatch.setattr(mea_bridge.subprocess, "run", fake_run)
    monkeypatch.chdir(tmp_path)
    (tmp_path / "-dump.bin").write_bytes(b"\x00" * 16)
    mea_bridge.run_mea_analyzer("-dump.bin", output_dir=str(tmp_path / "out"))
    assert os.path.abspath("-dump.bin") in seen["args"]


@POSIX_ONLY
def test_fit_version_comes_from_the_tool_line_not_a_copyright_year(tmp_path):
    tool = tmp_path / "fit"
    tool.write_text(
        "#!/bin/sh\n"
        "echo 'Copyright 2016.11.22.1'\n"
        "echo 'Intel(R) Flash Image Tool v16.1.25.2053 (LINUX64)'\n"
    )
    tool.chmod(0o755)
    probe = probe_tool(str(tool))
    assert probe.identified is True
    assert probe.version == "16.1.25.2053"
    assert probe.platform == "LINUX64"


def test_inferred_release_is_named_in_the_compatibility_reason():
    probe = ToolProbe(path="x", identified=True, family="MFIT", version="16.1.25.2053")
    ok, why = compatible_with_me(probe, "16.1.25.2091")
    assert ok is True
    assert "inferred" in why


def test_injector_refuses_a_directory_instead_of_raising(tmp_path):
    clean = tmp_path / "clean.bin"
    clean.write_bytes(b"\x24\x4d\x4e\x32" + b"\x11" * 0x100)
    result = MEInjector().inject(str(tmp_path), str(clean), str(tmp_path / "out.bin"))
    assert result["success"] is False
    assert MEInjector().analyze(str(tmp_path))["found"] is False
