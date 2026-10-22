"""remove-passwords reports a refused write as a failure and never touches its input (F-05)."""

import pytest

from bios_recovery import main as cli


@pytest.fixture
def image(tmp_path):
    path = tmp_path / "dump.bin"
    path.write_bytes(b"\xff" * 0x20000)
    return path


def test_same_path_output_exits_nonzero_and_leaves_input_alone(image, capsys):
    before = image.read_bytes()
    rc = cli._cli_main(["remove-passwords", str(image), "-o", str(image)])
    assert rc != 0
    assert image.read_bytes() == before
    assert "out:" not in capsys.readouterr().out


def test_successful_run_without_changes_reports_no_output(image, tmp_path, capsys):
    out = tmp_path / "clean.bin"
    rc = cli._cli_main(["remove-passwords", str(image), "-o", str(out)])
    assert rc != 0
    assert not out.exists()
    assert "out:" not in capsys.readouterr().out
