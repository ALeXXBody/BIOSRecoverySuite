"""Tests for DVAR password recovery (Dell DVAR XOR per CVE-2026-40639)."""

import struct

from bios_recovery.engines.dvar_passwords import (
    RECORD_LEN,
    _key_slot_for_pos,
    recover_passwords,
)


def _encrypt_record(password: bytes, key: bytes) -> bytes:
    """Build the on-flash 32-byte record for `password` under `key` (test encryptor
    mirroring the published scheme)."""
    assert len(key) == 20
    rec = bytearray(b"\xff" * RECORD_LEN)
    rec[0] = password[0]                       # first char in the clear
    for i in range(1, len(password)):
        rec[i] = password[i] ^ key[_key_slot_for_pos(i)]
    for i in range(len(password), RECORD_LEN):  # NUL padding, encrypted
        rec[i] = 0 ^ key[_key_slot_for_pos(i)]
    return bytes(rec)


KEY = bytes(range(0x30, 0x44))  # deterministic 20-byte key


def test_recover_short_password():
    pw = b"Passw0rd"  # 8 chars
    store = bytearray(b"\xff" * 0x400)
    store[0:4] = b"DVAR"
    store[0x40:0x40 + RECORD_LEN] = _encrypt_record(pw, KEY)
    assert len(pw) <= 12  # the null-pad leak applies

    rep = recover_passwords(_write(store))
    assert rep.success, rep.message
    assert rep.passwords and rep.passwords[0].password == pw.decode()


def test_recover_12_char_boundary():
    # a 12-char password has no overlap self-check on its own padding, so it is
    # accepted only with a same-first-char historical record (cross-validation)
    pw = b"ABLUP12CHARS"[:12]
    store = bytearray(b"\xff" * 0x400)
    store[0:4] = b"DVAR"
    store[0x30:0x30 + RECORD_LEN] = _encrypt_record(b"ABLU1", KEY)   # 5-char history
    store[0x60:0x60 + RECORD_LEN] = _encrypt_record(pw, KEY)
    rep = recover_passwords(_write(store))
    assert rep.success
    got = [r.password for r in rep.passwords]
    assert pw.decode() in got
    assert "ABLU1" in got   # the historical shorter password recovers too


def test_long_password_needs_history_key():
    store = bytearray(b"\xff" * 0x600)
    store[0:4] = b"DVAR"
    # historical short record, same first char (its padding leaks the full key)
    store[0x40:0x40 + RECORD_LEN] = _encrypt_record(b"pL3ase!", KEY)
    # current long record (17 chars = beyond the null-pad leak)
    long_pw = b"puddingP@ssW0rdls"
    store[0x100:0x100 + RECORD_LEN] = _encrypt_record(long_pw, KEY)
    assert len(long_pw) > 12

    rep = recover_passwords(_write(store))
    found = [r.password for r in rep.passwords]
    assert long_pw.decode() in found
    assert "pL3ase!" in found


def _write(store):
    import tempfile, os
    p = os.path.join(tempfile.mkdtemp(), "dump.bin")
    open(p, "wb").write(bytes(store))
    return p


def test_no_dvar_store():
    import tempfile, os
    p = os.path.join(tempfile.mkdtemp(), "non-dell.bin")
    open(p, "wb").write(b"\xff" * 0x1000)
    rep = recover_passwords(p)
    assert not rep.success
    assert "No DVAR store" in rep.message
