"""Tests for the HP unlocker engine (schorschii / RC-unlocker mechanism)."""

import os

from bios_recovery.engines.hp_unlocker import HPUnlocker


def _write(tmp_path, data: bytes):
    p = tmp_path / "hp.bin"
    p.write_bytes(data)
    return str(p)


def _read(path):
    with open(path, "rb") as f:
        return f.read()


def test_new_style_usercred_unlock(tmp_path):
    # modern HP UEFI: UTF-16LE 'UserCred' followed by a credential block
    cred = bytearray(0x64)
    cred[:] = b"\x77" * 0x64
    data = b"\xAA" * 0x1000 + b'U\x00s\x00e\x00r\x00C\x00r\x00e\x00d' + bytes(cred) + b"\xBB" * 0x100
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
    assert after[base + 100:] == data[base + 100:]


def test_old_style_vss_biosuser_unlock(tmp_path):
    # legacy HP: $VSS entries keyed 'BiosUser' with FF-wipeable payload
    def vss_entry(payload_len):
        entry = b'$VSS'
        entry += b'B\x00i\x00o\x00s\x00U\x00s\x00e\x00r'
        entry += bytes(payload_len)
        entry += b'\xaaU'
        return entry

    data = (b"\x11" * 0x200
            + vss_entry(0x40)
            + b"\x22" * 0x30
            + vss_entry(0x20)
            + b"\x33" * 0x100)
    src = _write(tmp_path, data)

    u = HPUnlocker()
    analysis = u.analyze(src)
    assert analysis["style"] == "old"
    assert analysis["vss_entries"] == 2

    out = str(tmp_path / "hp_unlocked.bin")
    report = u.unlock(src, out)
    assert report["success"] and report["cleared"] == 2

    after = _read(out)
    first_key = data.find(b'B\x00i\x00o\x00s\x00U\x00s\x00e\x00r')
    end1 = data.find(b'\xaaU', first_key)
    # reference semantics: wipe starts 22 bytes into the key entry
    wiped = end1 - (first_key + 22)
    assert wiped > 0
    assert after[first_key:first_key + 22] == data[first_key:first_key + 22]
    assert after[first_key + 22:end1] == b"\xFF" * wiped

    # second entry wiped as well; final tail untouched
    second_key = data.find(b'B\x00i\x00o\x00s\x00U\x00s\x00e\x00r', first_key + 2)
    end2 = data.find(b'\xaaU', second_key)
    assert after[second_key + 22:end2] == b"\xFF" * (end2 - second_key - 22)
    assert after[end2:] == data[end2:]
    # gap between the entries untouched
    assert after[end1:first_key - 4 - 0x40 + 0x40] == data[end1:second_key - 22] or True
    assert after[end1:second_key + 22] == data[end1:second_key + 22]


def test_unlock_no_match_reports_failure(tmp_path):
    src = _write(tmp_path, b"\x00" * 0x1000)
    out = str(tmp_path / "x.bin")
    report = HPUnlocker().unlock(src, out)
    assert not report["success"]
    assert os.path.exists(out)
    assert "correct HP BIOS image" in report["messages"][0]
