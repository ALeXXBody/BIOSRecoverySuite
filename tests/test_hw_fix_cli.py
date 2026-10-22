"""Regression tests for the EC CLI audit fixes (MN-1, MN-2, EC-12, EC-13)."""

import random

import pytest

from bios_recovery.main import _cli_main

EC_OFF = 0x100000
EC_SIZE = 0x40000


def _dump() -> bytes:
    data = bytearray(b"\xff") * 0x400000
    rng = random.Random(7)
    ec = bytearray(rng.getrandbits(8) for _ in range(EC_SIZE))
    ec[:8] = b"\x12\x34\x56\x78\x9a\xbc\xde\xf0"
    ec[0x100:0x109] = b"IT8218VG "
    ec[0x200:0x206] = b"ITE8\x02\x00"
    data[EC_OFF : EC_OFF + EC_SIZE] = ec
    return bytes(data)


@pytest.fixture
def dump(tmp_path):
    path = tmp_path / "a.b" / "dump"
    path.parent.mkdir()
    path.write_bytes(_dump())
    return path


def test_ec_extract_directory_input_is_an_error(tmp_path, capsys):
    """MN-1: a directory is refused with a message, not a traceback."""
    assert _cli_main(["ec-extract", str(tmp_path), "--force"]) == 2
    assert "not a file" in capsys.readouterr().err


def test_ec_scan_directory_input_is_an_error(tmp_path, capsys):
    """MN-1: ec-scan on a directory is refused the same way."""
    assert _cli_main(["ec-scan", str(tmp_path), "--force"]) == 2
    assert "not a file" in capsys.readouterr().err


def test_ec_extract_refuses_existing_output_without_overwrite(dump, tmp_path, capsys):
    """MN-2: -o never replaces an existing file unless --overwrite is given."""
    keep = tmp_path / "keep_ec.bin"
    keep.write_bytes(b"PRECIOUS")
    assert _cli_main(["ec-extract", str(dump), "-o", str(keep), "--force"]) == 1
    assert keep.read_bytes() == b"PRECIOUS"
    assert "already exists" in capsys.readouterr().out
    assert _cli_main(["ec-extract", str(dump), "-o", str(keep), "--force", "--overwrite"]) == 0
    assert keep.read_bytes() == _dump()[EC_OFF : EC_OFF + EC_SIZE]


def test_ec_extract_manual_offset_and_size(dump, tmp_path):
    """EC-13: the CLI can choose the region, as the GUI can."""
    out = tmp_path / "manual.bin"
    rc = _cli_main(
        [
            "ec-extract",
            str(dump),
            "-o",
            str(out),
            "--offset",
            str(EC_OFF),
            "--size",
            str(EC_SIZE),
            "--force",
        ]
    )
    assert rc == 0
    assert out.read_bytes() == _dump()[EC_OFF : EC_OFF + EC_SIZE]


def test_ec_extract_default_output_keeps_folder_for_extensionless_input(dump):
    """EC-12: the default output is next to the input, even without an extension."""
    rc = _cli_main(["ec-extract", str(dump), "--force"])
    assert rc == 0
    assert (dump.parent / "dump_ec.bin").exists()
    assert not (dump.parent.parent / "a_ec.bin").exists()


def test_ec_extract_rejects_bad_offset_text(dump, capsys):
    with pytest.raises(SystemExit) as exc:
        _cli_main(["ec-extract", str(dump), "--offset", "zzz", "--force"])
    assert exc.value.code == 2
