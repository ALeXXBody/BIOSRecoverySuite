"""Identity audit fixes for the HP unlocker: $VSS is checked before UserCred, as the reference."""

import struct

from bios_recovery.manufacturers.hp.hp_unlocker import HPUnlocker

BIOS_USER = b"B\x00i\x00o\x00s\x00U\x00s\x00e\x00r\x00\x00\x00"
USER_CRED = b"U\x00s\x00e\x00r\x00C\x00r\x00e\x00d"


def _vss_entry(data_len, payload=b"\x42"):
    header = b"\xaa\x55" + bytes([0x3F, 0x00]) + struct.pack("<I", 0x7)
    header += struct.pack("<II", len(BIOS_USER), data_len) + bytes(16)
    return header + BIOS_USER + (payload * data_len)[:data_len]


def test_vss_biosuser_is_cleared_when_usercred_is_also_present(tmp_path):
    cred = b"\x77" * 0x64
    entry = _vss_entry(0x10)
    data = b"\x11" * 0x100 + USER_CRED + cred + b"\x22" * 0x40 + entry + b"\x33" * 0x40
    src = tmp_path / "hp.bin"
    src.write_bytes(data)
    out = str(tmp_path / "out.bin")

    report = HPUnlocker().unlock(str(src), out)

    assert report["success"]
    assert report["style"] == "old"
    assert report["cleared"] == 1
    after = open(out, "rb").read()
    assert after[0x100 + len(USER_CRED) : 0x100 + len(USER_CRED) + 0x64] == cred


def test_vss_wipe_stays_within_data_size_across_a_long_gap(tmp_path):
    entry = _vss_entry(0x10)
    data = entry + b"\xaa\x55" + b"\x99" * 0x180000
    src = tmp_path / "hp.bin"
    src.write_bytes(data)
    out = str(tmp_path / "out.bin")

    report = HPUnlocker().unlock(str(src), out)

    assert report["success"]
    after = open(out, "rb").read()
    start = 32 + len(BIOS_USER)
    assert after[start : start + 0x10] == b"\xff" * 0x10
    assert after[start + 0x10 :] == data[start + 0x10 :]
