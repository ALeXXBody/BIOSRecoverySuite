"""Tests for the dogbert master password generators (ports + properties)."""

from bios_recovery.utils import master_passwords as mp


def test_fsi_hex_output():
    pw = mp.fsi_hex("DEADBEEF")
    assert len(pw) == 8
    assert pw.isdigit()
    # deterministic
    assert pw == mp.fsi_hex("DEADBEEF")
    # 5x4 hex form uses only the last block
    assert mp.fsi_hex("AAAA-BBBB-CCCC-DEAD-BEEF") == pw


def test_fsi_6x4dec_output():
    pw = mp.fsi_6x4dec("1234-4321-1234-4321-1234")
    assert len(pw) == 8
    assert all(c in "0123456789abcdefghijklmnopqrstuvwxyz" for c in pw)
    assert pw == mp.fsi_6x4dec("12344321123443211234")


def test_insyde_8dec_output():
    pw = mp.insyde_8dec("03133610")
    assert len(pw) == 8
    assert pw.isdigit()
    assert pw == mp.insyde_8dec("03133610")


def test_sony_4x4_output():
    pw = mp.sony_4x4("73KR-3FP9-PVKH-K29R")
    assert len(pw) == 8
    assert all(c in "47592836" for c in pw)


def test_hp_mini_output():
    pw = mp.hp_mini("CNU1234ABC")
    assert len(pw) >= 10
    assert pw == pw.lower()
    # table difference is only 'x' -> unused serials give a single password
    assert " OR " not in pw


def test_asus_date_output():
    pw = mp.asus_date("2013-12-31")
    assert len(pw) == 8
    assert pw == mp.asus_date("20131231")
    assert all(c in "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ" for c in pw)


def test_phoenix_5dec_recovers_hash():
    """Whatever password the brute force returns, its buggy-CRC16 must equal
    the input hash - the defining property of the algorithm."""
    for hash_val in (0x3133, 0x2345, 0x0042):
        results = mp.phoenix_5dec(str(hash_val))
        generic = results["Phoenix generic"]
        assert generic, f"no password found for {hash_val}"
        # encode ASCII back to keyboard scancodes
        rev = {v: k for k, v in mp.KEYBOARD_DICT.items()}
        encoded = [rev[c] for c in generic]
        assert mp.bad_crc16(encoded, 0) == hash_val


def test_phoenix_hp_variant_recovers_hash():
    results = mp.phoenix_5dec(str(0x1234))
    hp = results["HP/Compaq Phoenix"]
    assert hp
    rev = {v: k for k, v in mp.KEYBOARD_DICT.items()}
    assert mp.bad_crc16([rev[c] for c in hp], salt=17232) == 0x1234


def test_dispatcher():
    out = mp.generate("fsi_hex", "DEADBEEF")
    assert out and out[0][0] == "password"
    out = mp.generate("samsung", "07088120410C0000")
    labels = [name for name, _ in out]
    assert labels == ["key 1", "key 2"]
    out = mp.generate("phoenix_5dec", "12345")
    assert len(out) == 7
