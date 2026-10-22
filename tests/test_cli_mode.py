"""CLI-mode smoke tests (`bios-recovery <command> ...`)."""

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bios_recovery.main import _cli_main

UUID = "2c4a6b8d0011223344556677889aaabb"
SERIAL = "AS3FYGD3jB"


def _fixture_with_smbios():
    t1 = (
        bytes([1, 0x1B])
        + struct.pack("<H", 0x0300)
        + bytes([1, 2, 3, 4])
        + bytes.fromhex(UUID)
        + bytes([0, 5, 6])
    )
    pool1 = b"ASUS\0Vivobook\0V1\0" + SERIAL.encode() + b"\0\0"
    t2 = bytes([2, 0x08, 0x01, 0x03]) + bytes([1, 2, 3, 3])
    pool2 = b"ASUS\0Go15\0MT1234ABC\0\0"
    table = t1 + pool1 + t2 + pool2
    eps = bytearray(0x1F)
    eps[0:4] = b"_SM_"
    struct.pack_into("<H", eps, 0x16, len(table))
    struct.pack_into("<I", eps, 0x18, 0x0100)
    blob = bytearray(b"\xff" * 0x2000)
    blob[0 : len(eps)] = eps
    blob[0x0100 : 0x0100 + len(table)] = table
    return bytes(blob)


def test_cli_dmi(capsys, tmp_path):
    p = tmp_path / "dump.bin"
    p.write_bytes(_fixture_with_smbios())
    rc = _cli_main(["dmi", str(p)])
    out = capsys.readouterr().out
    assert rc == 0
    assert SERIAL in out
    assert "AA:" not in out or "n/a" in out


def test_cli_set_dmi_and_verify(capsys, tmp_path):
    p = tmp_path / "dump.bin"
    p.write_bytes(_fixture_with_smbios())
    rc = _cli_main(["set-dmi", str(p), "--serial", "AS3ZZZD9kB"])
    out = capsys.readouterr().out
    assert rc == 0
    # apply against the produced edit file
    edited = [line.split()[-1] for line in out.splitlines() if line.startswith("out:")]
    assert edited and os.path.exists(edited[0])
    rc2 = _cli_main(["dmi", edited[0]])
    out2 = capsys.readouterr().out
    assert rc2 == 0
    assert "AS3ZZZD9kB" in out2


def test_cli_analyze_unknown(capsys, tmp_path):
    p = tmp_path / "empty.ff"
    p.write_bytes(b"\xff" * 0x1000)
    rc = _cli_main(["analyze", str(p)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "type:" in out


def test_cli_missing_file(capsys, tmp_path):
    rc = _cli_main(["analyze", str(tmp_path / "nothere.bin")])
    assert rc == 2


def test_cli_refuses_intel_tool_on_amd_image(tmp_path, capsys):
    from bios_recovery.main import _cli_main

    img = tmp_path / "amd.bin"
    img.write_bytes(b"\xff" * 0x800 + b"$PSP" + b"\xff" * 0x800)
    rc = _cli_main(["me-clean", str(img), "-o", str(tmp_path / "out.bin")])
    assert rc == 3
    assert "does not apply" in capsys.readouterr().err
    assert not (tmp_path / "out.bin").exists()


def test_cli_force_runs_inapplicable_tool(tmp_path, capsys):
    from bios_recovery.main import _cli_main

    img = tmp_path / "amd.bin"
    img.write_bytes(b"\xff" * 0x800 + b"$PSP" + b"\xff" * 0x800)
    rc = _cli_main(["me-clean", str(img), "-o", str(tmp_path / "out.bin"), "--force"])
    assert rc != 3
    assert "does not apply" not in capsys.readouterr().err
