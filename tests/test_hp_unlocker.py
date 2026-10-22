"""Tests for the HP unlocker engine (schorschii / RC-unlocker mechanism)."""

import os
import struct

from bios_recovery.engines.hp_unlocker import HPUnlocker

BIOS_USER = b"B\x00i\x00o\x00s\x00U\x00s\x00e\x00r\x00\x00\x00"


def _write(tmp_path, data: bytes):
    p = tmp_path / "hp.bin"
    p.write_bytes(data)
    return str(p)


def _read(path):
    with open(path, "rb") as f:
        return f.read()


def _vss_entry(data_len, name_size=len(BIOS_USER), payload=b"\x00"):
    # EDK2 VARIABLE_HEADER: StartId, State, Reserved, Attributes, NameSize, DataSize, VendorGuid
    header = b"\xaa\x55" + bytes([0x3F, 0x00]) + struct.pack("<I", 0x7)
    header += struct.pack("<II", name_size, data_len) + bytes(16)
    return header + BIOS_USER + (payload * data_len)[:data_len]


def test_new_style_usercred_unlock(tmp_path):
    # modern HP UEFI: UTF-16LE 'UserCred' followed by a credential block
    cred = bytearray(0x64)
    cred[:] = b"\x77" * 0x64
    data = (
        b"\xaa" * 0x1000 + b"U\x00s\x00e\x00r\x00C\x00r\x00e\x00d" + bytes(cred) + b"\xbb" * 0x100
    )
    src = _write(tmp_path, data)

    u = HPUnlocker()
    analysis = u.analyze(src)
    assert analysis["style"] == "new"
    assert analysis["usercred_offset"] == 0x1000

    out = str(tmp_path / "hp_unlocked.bin")
    report = u.unlock(src, out)
    assert report["success"] and report["style"] == "new"

    after = _read(out)
    base = 0x1000 + 16
    for j in range(100):
        expected = 0xFF if 10 <= j < 14 else 0x00
        assert after[base + j] == expected, f"byte {j} wrong"
    # untouched surroundings
    assert after[:0x1000] == data[:0x1000]
    assert after[base + 100 :] == data[base + 100 :]


def test_old_style_vss_biosuser_unlock(tmp_path):
    # legacy HP: $VSS entries named 'BiosUser', each with its own DataSize
    first = _vss_entry(0x40, payload=b"\x5a")
    second = _vss_entry(0x20, payload=b"\x6b")
    data = b"\x11" * 0x200 + first + b"\x22" * 0x30 + second + b"\x33" * 0x100
    src = _write(tmp_path, data)

    u = HPUnlocker()
    analysis = u.analyze(src)
    assert analysis["style"] == "old"
    assert analysis["vss_entries"] == 2

    out = str(tmp_path / "hp_unlocked.bin")
    report = u.unlock(src, out)
    assert report["success"] and report["cleared"] == 2

    after = _read(out)
    first_data = 0x200 + 32 + len(BIOS_USER)
    second_data = first_data + 0x40 + 0x30 + 32 + len(BIOS_USER)
    assert after[: first_data] == data[: first_data]
    assert after[first_data : first_data + 0x40] == b"\xff" * 0x40
    assert after[first_data + 0x40 : second_data] == data[first_data + 0x40 : second_data]
    assert after[second_data : second_data + 0x20] == b"\xff" * 0x20
    assert after[second_data + 0x20 :] == data[second_data + 0x20 :]


def test_vss_wipe_is_bounded_by_data_size(tmp_path):
    # a later AA 55 must not widen the wipe: only DataSize bytes change
    entry = _vss_entry(0x10, payload=b"\x42")
    tail = b"\xaa\x55" + b"\x99" * 0x2000
    data = entry + tail
    src = _write(tmp_path, data)
    out = str(tmp_path / "hp_unlocked.bin")

    report = HPUnlocker().unlock(src, out)
    assert report["success"]
    after = _read(out)
    start = 32 + len(BIOS_USER)
    assert after[start : start + 0x10] == b"\xff" * 0x10
    assert after[start + 0x10 :] == data[start + 0x10 :]


def test_vss_entry_with_wrong_name_size_is_not_wiped(tmp_path):
    data = _vss_entry(0x10, name_size=0x40, payload=b"\x42")
    src = _write(tmp_path, data)
    out = str(tmp_path / "hp_unlocked.bin")

    report = HPUnlocker().unlock(src, out)
    assert not report["success"]
    assert report["cleared"] == 0
    assert not os.path.exists(out)


def test_unlock_no_match_reports_failure(tmp_path):
    src = _write(tmp_path, b"\x00" * 0x1000)
    out = str(tmp_path / "x.bin")
    report = HPUnlocker().unlock(src, out)
    assert not report["success"]
    assert not os.path.exists(out)
    assert "correct HP BIOS image" in report["messages"][0]


def test_unlock_refuses_output_equal_to_input(tmp_path):
    src = _write(tmp_path, _vss_entry(0x10, payload=b"\x42"))
    report = HPUnlocker().unlock(src, src)
    assert not report["success"]
    assert "input file" in report["messages"][0]
    assert _read(src) == _vss_entry(0x10, payload=b"\x42")
