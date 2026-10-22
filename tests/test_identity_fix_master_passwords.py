"""Identity audit fixes for the master password generators (dogbert reference parity)."""

import random
import struct

import pytest

from bios_recovery.utils import master_passwords as mp

_OTP = "9DPK7V2F3RT6HX8J"
_PWD = "47592836"


def _reference_sony(code: str) -> str:
    """Transcription of dogbert pwgen-sony-4x4.py (decodeHash prepends each byte)."""
    code = code.replace("-", "").replace(" ", "").upper()
    s = ""
    for c in range(len(code) // 2):
        s = chr(_OTP.find(code[2 * c]) * 16 + _OTP.find(code[2 * c + 1])) + s
    c_val = struct.unpack("<Q", s.encode("latin-1"))[0]
    p, q, e = 2795287379, 3544934711, 41
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    dp, dq = d % (p - 1), d % (q - 1)
    qinv = pow(q, -1, p)
    m1 = pow(c_val, dp, p)
    m2 = pow(c_val, dq, q)
    h = (qinv * (m1 - m2 + p)) % p if m1 < m2 else (qinv * (m1 - m2)) % p
    m = m2 + h * q
    n = struct.unpack("<I", struct.pack("<Q", m)[0:4])[0]
    return "".join(_PWD[(n >> (21 - i * 3)) & 7] for i in range(8))


def test_sony_reference_example_matches_dogbert():
    # dogbert pwgen-sony-4x4.py example code; the value is the reference transcription's output
    assert mp.sony_4x4("73KR-3FP9-PVKH-K29R") == "32799624"


def test_sony_matches_reference_on_random_codes():
    rng = random.Random(1)
    for _ in range(100):
        code = "".join(rng.choice(_OTP) for _ in range(16))
        assert mp.sony_4x4(code) == _reference_sony(code), code


def test_samsung_scancode_text_uses_reference_names_and_stops_at_nul():
    assert mp.samsung_scancode_to_text([39, 51, 53]) == ";./"
    assert mp.samsung_scancode_to_text([30, 0, 31]) == "a"
    assert mp.samsung_scancode_to_text([54, 30]) == "<RSHIFT>a"
    assert mp.samsung_scancode_to_text([200]) == "<U-0xc8/200>"


@pytest.mark.parametrize(
    "call",
    [
        lambda: mp.hp_mini("ab-c!"),
        lambda: mp.sony_4x4("XYZ"),
        lambda: mp.asus_date("2013/1"),
        lambda: mp.samsung("zz"),
        lambda: mp.insyde_8dec("123"),
        lambda: mp.phoenix_5dec("12x45"),
    ],
)
def test_malformed_input_raises_value_error(call):
    with pytest.raises(ValueError):
        call()


def test_phoenix_search_stops_at_its_time_budget():
    results = mp.phoenix_5dec("12345", budget_s=-1.0)
    assert results["Phoenix generic"] == "not found within time limit"
    assert all(v == "not found within time limit" for v in results.values())
