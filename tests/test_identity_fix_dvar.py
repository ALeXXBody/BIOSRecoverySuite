"""Identity audit fixes for DVAR recovery: unverified candidates and short-buffer safety."""

import os
import tempfile

from bios_recovery.manufacturers.dell.dvar_passwords import (
    RECORD_LEN,
    recover_passwords,
    try_recover_record,
)
from tests.test_dvar_passwords import KEY, _encrypt_record


def _write(store: bytearray) -> str:
    p = os.path.join(tempfile.mkdtemp(), "dump.bin")
    with open(p, "wb") as f:
        f.write(bytes(store))
    return p


def test_full_length_record_reusing_a_historical_key_is_unverified():
    long_pw = b"p" + b"X" * (RECORD_LEN - 1)  # fills all 32 bytes: no NUL tail to check
    store = bytearray(b"\xff" * 0x600)
    store[0:4] = b"DVAR"
    store[0x40 : 0x40 + RECORD_LEN] = _encrypt_record(b"pL3ase!", KEY)
    store[0x100 : 0x100 + RECORD_LEN] = _encrypt_record(long_pw, KEY)

    rep = recover_passwords(_write(store))

    assert long_pw.decode() not in [r.password for r in rep.passwords]
    assert long_pw.decode() in [r.password for r in rep.unverified]
    assert "pL3ase!" in [r.password for r in rep.passwords]


def test_derived_key_password_repeated_at_two_offsets_is_unverified():
    long_pw = b"puddingP@ssW0rdls"  # 17 chars: found through the historical key, NUL-tailed
    store = bytearray(b"\xff" * 0x600)
    store[0:4] = b"DVAR"
    store[0x40 : 0x40 + RECORD_LEN] = _encrypt_record(b"pL3ase!", KEY)
    store[0x100 : 0x100 + RECORD_LEN] = _encrypt_record(long_pw, KEY)
    store[0x200 : 0x200 + RECORD_LEN] = _encrypt_record(long_pw, KEY)

    rep = recover_passwords(_write(store))

    assert long_pw.decode() not in [r.password for r in rep.passwords]
    assert {r.record_offset for r in rep.unverified} >= {0x100, 0x200}


def test_self_checked_password_repeated_at_two_offsets_is_still_recovered():
    store = bytearray(b"\xff" * 0x400)
    store[0:4] = b"DVAR"
    store[0x40 : 0x40 + RECORD_LEN] = _encrypt_record(b"Passw0rd", KEY)
    store[0x100 : 0x100 + RECORD_LEN] = _encrypt_record(b"Passw0rd", KEY)

    rep = recover_passwords(_write(store))

    assert [r.password for r in rep.passwords] == ["Passw0rd", "Passw0rd"]
    assert not rep.unverified


def test_short_buffer_is_rejected_without_an_exception():
    assert try_recover_record(b"A" * 10) is None
    assert try_recover_record(b"") is None


def test_single_recovered_password_is_still_reported():
    store = bytearray(b"\xff" * 0x400)
    store[0:4] = b"DVAR"
    store[0x40 : 0x40 + RECORD_LEN] = _encrypt_record(b"Passw0rd", KEY)

    rep = recover_passwords(_write(store))

    assert rep.success
    assert [r.password for r in rep.passwords] == ["Passw0rd"]
