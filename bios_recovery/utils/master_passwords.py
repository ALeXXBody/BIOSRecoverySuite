"""Master password generators for laptop BIOS password recovery.

Faithful Python-3 ports of the reverse-engineered algorithms published by
dogbert (https://github.com/dogbert/bios-pwgen, dogber1.blogspot.com) and the
pwgen-for-bios project. The ported functions are derived from GPL-2+ sources:
this module is therefore distributed under GPL-2+.

Vendors / formats covered:
  * Phoenix generic, HP/Compaq, Fujitsu-Siemens  - 5 decimal digits (brute)
  * Fujitsu-Siemens                              - 8 hex digits, 5x4 hex
  * Fujitsu-Siemens                              - 6x4 decimal digits
  * Insyde H2O (Acer/HP/Lenovo)                  - 8 decimal digits
  * Samsung                                      - 12/18 hex digits
  * Sony                                         - 4x4 hex OTP
  * HP/Compaq Mini netbooks                      - 10 character serial
  * HP AMI                                       - 8 hex digits
  * ASUS                                         - system date (Alt+R)
"""

import struct
import time
import zlib

# --------------------------------------------------------------------- #
#  shared building blocks (from dogbert's scripts)                       #
# --------------------------------------------------------------------- #

KEYBOARD_DICT = {
    2: "1",
    3: "2",
    4: "3",
    5: "4",
    6: "5",
    7: "6",
    8: "7",
    9: "8",
    10: "9",
    11: "0",
    16: "q",
    17: "w",
    18: "e",
    19: "r",
    20: "t",
    21: "y",
    22: "u",
    23: "i",
    24: "o",
    25: "p",
    30: "a",
    31: "s",
    32: "d",
    33: "f",
    34: "g",
    35: "h",
    36: "j",
    37: "k",
    38: "l",
    44: "z",
    45: "x",
    46: "c",
    47: "v",
    48: "b",
    49: "n",
    50: "m",
}

KEYBOARD_SCANCODE_DICT = {
    2: "1",
    3: "2",
    4: "3",
    5: "4",
    6: "5",
    7: "6",
    8: "7",
    9: "8",
    10: "9",
    11: "0",
    16: "q",
    17: "w",
    18: "e",
    19: "r",
    20: "t",
    21: "y",
    22: "u",
    23: "i",
    24: "o",
    25: "p",
    30: "a",
    31: "s",
    32: "d",
    33: "f",
    34: "g",
    35: "h",
    36: "j",
    37: "k",
    38: "l",
    39: ";",
    44: "z",
    45: "x",
    46: "c",
    47: "v",
    48: "b",
    49: "n",
    50: "m",
    51: ".",
    52: ",",
    53: "/",
}


def keyboard_enc_to_ascii(in_key) -> str:
    return "".join(KEYBOARD_DICT[c] for c in in_key if c in KEYBOARD_DICT)


# dogbert pwgen-samsung.py keyboardDict. Markers name keys with no printable character.
_SAMSUNG_SCANCODE_NAMES = {
    54: "<RSHIFT>",
    55: "<NUMPAD/*>",
    59: "<F1>",
    60: "<F2>",
    61: "<F3>",
    62: "<F4>",
    63: "<F5>",
    64: "<F6>",
    65: "<F7>",
    66: "<F8>",
    67: "<F9>",
    68: "<F9>",
    87: "<F11>",
    88: "<F12>",
    71: "<NUMPAD7/HOME>",
    72: "<NUMPAD8/UP>",
    73: "<NUMPAD9/PGUP>",
    74: "<NUMPAD->",
    75: "<NUMPAD4/LEFT>",
    76: "<NUMPAD5>",
    77: "<NUMPAD6/RIGHT>",
    78: "<NUMPAD+>",
    79: "<NUMPAD1/END>",
    80: "<NUMPAD2/DOWN>",
    81: "<NUMPAD3/PGDN>",
    82: "<NUMPAD0/INS>",
    83: "<NUMPAD./DEL>",
    84: "<NUMPAD/DELIMITER>",
    156: "<NUMPAD/ENTER>",
    92: "<KP4/Left>",
    1: "<ESCAPE>",
    0xC7: "<HOME>",
    174: "<VOLDOWN>",
    212: "<CAMERA>",
    226: "<LAlt>",
    227: "<LGUI>",
}
SAMSUNG_SCANCODE_DICT = {**KEYBOARD_SCANCODE_DICT, **_SAMSUNG_SCANCODE_NAMES}


def samsung_scancode_to_text(in_key) -> str:
    """dogbert keyboardEncToAscii: stops at the first NUL, names unknown keys by scancode."""
    out = ""
    for c in in_key:
        if c == 0:
            return out
        out += SAMSUNG_SCANCODE_DICT.get(c, "<U-0x%02x/%d>" % (c, c))
    return out


def bad_crc16(pwd, salt: int = 0) -> int:
    """Phoenix's buggy CRC-16 (both top MSBs always zero, polynomial 0x2001)."""
    h = salt
    for c in pwd:
        h ^= c
        for _ in range(8):
            if h & 1:
                h = (h >> 1) ^ 0x2001
            else:
                h = h >> 1
    return h


def generate_crc16_table() -> list:
    table = []
    for i in range(256):
        crc = i << 8
        for _ in range(8):
            crc = (crc << 1) ^ 0x1021 if crc & 0x8000 else (crc << 1)
        table.append(crc & 0xFFFF)
    return table


# --------------------------------------------------------------------- #
#  Phoenix / FSI / HP / Compaq  -  5 decimal digits                      #
# --------------------------------------------------------------------- #


PHOENIX_SEARCH_BUDGET_S = 15.0


def _brute_force_deterministic(
    hash_val: int,
    salt: int = 0,
    digits_only: bool = False,
    chars_only: bool = True,
    min_len: int = 3,
    max_len: int = 8,
    deadline: float = None,
) -> str:
    """Deterministic DFS variant of dogbert's randomized brute force.

    Returns a keyboard-encoded password whose buggy-CRC16 equals hash_val, or "" when the
    whole keyspace up to max_len has no match. Raises TimeoutError past deadline
    (a time.monotonic() value)."""
    if digits_only:
        # dogbert pwgen-5dec.py digitsOnly slices keys [0:9], which leaves out '0'. The '0'
        # key is kept here: every candidate is checked against the hash, so it adds no false hits.
        keys = [k for k in KEYBOARD_DICT if KEYBOARD_DICT[k].isdigit()][:10]
    elif chars_only:
        keys = [k for k in KEYBOARD_DICT if KEYBOARD_DICT[k].isalpha()]
    else:
        keys = list(KEYBOARD_DICT)
    if hash_val > 0x3FFF:
        return "invalid hash code"

    from itertools import product

    for length in range(min_len, max_len + 1):
        for n, combo in enumerate(product(keys, repeat=length)):
            if deadline is not None and n & 0xFFFF == 0 and time.monotonic() > deadline:
                raise TimeoutError("phoenix search time limit reached")
            if bad_crc16(combo, salt) == hash_val:
                return keyboard_enc_to_ascii(combo)
    return ""


def phoenix_5dec(code: str, budget_s: float = PHOENIX_SEARCH_BUDGET_S) -> dict:
    """5-decimal-digit hashes: Phoenix generic, HP/Compaq, FSI variants.

    The seven searches share one time budget. A search that runs out of time reports
    "not found within time limit" rather than a password.
    """
    code = (code or "").strip().replace("[", "").replace("]", "")
    try:
        h = int(code)
    except ValueError:
        raise ValueError("Phoenix hash must be a decimal number, e.g. 12345") from None
    deadline = time.monotonic() + budget_s

    def search(value: int, **kwargs) -> str:
        try:
            return _brute_force_deterministic(value, deadline=deadline, **kwargs)
        except TimeoutError:
            return "not found within time limit"

    return {
        "Phoenix generic": search(h, salt=0),
        "HP/Compaq Phoenix": search(h, salt=17232),
        "FSI Phoenix (generic)": search(h, salt=65, digits_only=True, min_len=3, max_len=7),
        "FSI Phoenix (L model)": search(
            h + 1, salt=ord("L"), digits_only=True, min_len=3, max_len=7
        ),
        "FSI Phoenix (P model)": search(
            h + 1, salt=ord("P"), digits_only=True, min_len=3, max_len=7
        ),
        "FSI Phoenix (S model)": search(
            h + 1, salt=ord("S"), digits_only=True, min_len=3, max_len=7
        ),
        "FSI Phoenix (X model)": search(
            h + 1, salt=ord("X"), digits_only=True, min_len=3, max_len=7
        ),
    }


# --------------------------------------------------------------------- #
#  Fujitsu-Siemens  -  8 hex digits and 5x4 hex digits                   #
# --------------------------------------------------------------------- #


def _fsi_hash_to_string(h: int) -> str:
    return (
        chr(ord("0") + ((h >> 12) % 16) % 10)
        + chr(ord("0") + ((h >> 8) % 16) % 10)
        + chr(ord("0") + ((h >> 4) % 16) % 10)
        + chr(ord("0") + ((h >> 0) % 16) % 10)
    )


def _fsi_calculate_hash(word: str, table) -> int:
    h = 0
    for c in word:
        d = table[(ord(c) ^ (h >> 8)) % 256]
        h = ((h << 8) ^ d) & 0xFFFF
    return h


def fsi_hex(code: str) -> str:
    """8-hex-digit hash (or 5x4 hex: AAAA-BBBB-CCCC-DEAD-BEEF)."""
    code = (code or "").strip().replace("-", "").upper()
    if len(code) == 20:
        code = code[12:20]
    table = generate_crc16_table()
    return _fsi_hash_to_string(_fsi_calculate_hash(code[0:4], table)) + _fsi_hash_to_string(
        _fsi_calculate_hash(code[4:8], table)
    )


# --------------------------------------------------------------------- #
#  Fujitsu-Siemens  -  6x4 decimal digits                                #
# --------------------------------------------------------------------- #


def fsi_6x4dec(code: str) -> str:
    """6x4-decimal hash (entered after 3hqgo3 / jqw534 / 0qww294e)."""
    code = (code or "").strip().replace("-", "").replace(" ", "")
    code = code[4:]
    numbers = (int(code[0:5]), int(code[5:10]), int(code[10:15]), int(code[15:20]))
    data = []
    for n in numbers:
        data.append(n % 256)
        data.append(n // 256)

    data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7] = (
        (data[3] & 0xF0) | (data[0] & 0x0F),
        (data[2] & 0xF0) | (data[1] & 0x0F),
        (data[5] & 0xF0) | (data[6] & 0x0F),
        (data[4] & 0xF0) | (data[7] & 0x0F),
        (data[7] & 0xF0) | (data[4] & 0x0F),
        (data[6] & 0xF0) | (data[5] & 0x0F),
        (data[1] & 0xF0) | (data[2] & 0x0F),
        (data[0] & 0xF0) | (data[3] & 0x0F),
    )

    xor_key = "<7#&9?>s"
    for i in range(8):
        data[i] ^= ord(xor_key[i])

    rots = [1, 7, 2, 8, 3, 6, 4, 5]
    for i in range(8):
        r = rots[i]
        data[i] = ((data[i] << r) & 0xFF) | (data[i] >> (8 - r))

    def byte_to_char(b: int) -> str:
        return chr(ord("a") + b - 10) if b > 9 else chr(ord("0") + b)

    return "".join(byte_to_char(x % 36) for x in data)


# --------------------------------------------------------------------- #
#  Insyde H2O (Acer, HP, Lenovo)  -  8 decimal digits                    #
# --------------------------------------------------------------------- #


def insyde_8dec(in_hash: str) -> str:
    in_hash = (in_hash or "").strip().replace("-", "")
    if len(in_hash) < 8:
        raise ValueError("Insyde hash must be 8 characters")
    salt = "Iou|hj&Z"
    pwd = ""
    for i in range(8):
        b = ord(salt[i]) ^ ord(in_hash[i])
        a = b
        a = (a * 0x66666667) >> 32
        a = (a >> 2) | (a & 0xC0)
        if a & 0x80000000:
            a += 1
        a *= 10
        pwd += str(b - a)
    return pwd


# --------------------------------------------------------------------- #
#  Samsung  -  12/18 hex digits                                          #
# --------------------------------------------------------------------- #

_SAMSUNG_ROT1 = [
    7,
    1,
    5,
    3,
    0,
    6,
    2,
    5,
    2,
    3,
    0,
    6,
    1,
    7,
    6,
    1,
    5,
    2,
    7,
    1,
    0,
    3,
    7,
    6,
    1,
    0,
    5,
    2,
    1,
    5,
    7,
    3,
    2,
    0,
    6,
]
_SAMSUNG_ROT2 = [
    1,
    6,
    2,
    5,
    7,
    3,
    0,
    7,
    1,
    6,
    2,
    5,
    0,
    3,
    0,
    6,
    5,
    1,
    1,
    7,
    2,
    5,
    2,
    3,
    7,
    6,
    2,
    1,
    3,
    7,
    6,
    5,
    0,
    1,
    7,
]


def _samsung_decrypt(hash_bytes, key: int, matrix) -> list:
    out = []
    for i in range(len(hash_bytes)):
        try:
            r = matrix[7 * key + i]
            out.append(((hash_bytes[i] << r) & 0xFF) | (hash_bytes[i] >> (8 - r)))
        except IndexError:
            break
    return out


def samsung(code: str) -> list[dict]:
    """12/18-hex-digit hash -> candidate passwords for key 1 and key 2."""
    code = (code or "").strip().replace("-", "").replace(" ", "").upper()
    if len(code) < 4 or not all(c in "0123456789ABCDEF" for c in code):
        raise ValueError("Samsung hash must be 12 or 18 hexadecimal digits")
    hash_bytes = [int(code[2 * i] + code[2 * i + 1], 16) for i in range(1, len(code) // 2)]
    key = int(code[0:2], 16) % 5
    out = []
    for name, matrix in (("key 1", _SAMSUNG_ROT1), ("key 2", _SAMSUNG_ROT2)):
        dec = _samsung_decrypt(hash_bytes, key, matrix)
        out.append(
            {
                "label": name,
                "hex": "".join("%02x" % x for x in dec),
                "ascii": "".join(chr(x) if 32 <= x < 127 else "" for x in dec),
                "scancode": samsung_scancode_to_text(dec),
            }
        )
    return out


# --------------------------------------------------------------------- #
#  Sony  -  4x4 hexadecimal OTP                                          #
# --------------------------------------------------------------------- #


def sony_4x4(code: str) -> str:
    code = (code or "").replace("-", "").replace(" ", "").upper()
    otp_chars = "9DPK7V2F3RT6HX8J"
    pwd_chars = "47592836"
    if len(code) != 16 or any(c not in otp_chars for c in code):
        raise ValueError("Sony code must be 16 characters from 9DPK7V2F3RT6HX8J")

    # dogbert decodeHash prepends each decoded byte, so code byte c lands at byte 7-c
    dec = 0
    for c in range(8):
        dec |= (otp_chars.find(code[2 * c]) * 16 + otp_chars.find(code[2 * c + 1])) << (
            8 * (7 - c)
        )

    p, q = 2795287379, 3544934711
    e = 41
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)

    c_val = dec
    dp, dq = d % (p - 1), d % (q - 1)
    qinv = pow(q, -1, p)
    m1 = pow(c_val, dp, p)
    m2 = pow(c_val, dq, q)
    if m1 < m2:
        h = (qinv * (m1 - m2 + p)) % p
    else:
        h = (qinv * (m1 - m2)) % p
    m = m2 + h * q
    raw = struct.pack("<Q", m)

    num = struct.unpack("<I", raw[0:4])[0]
    return "".join(pwd_chars[(num >> (21 - i * 3)) & 0x7] for i in range(8))


# --------------------------------------------------------------------- #
#  HP / Compaq Mini netbooks  -  10 character serial                     #
# --------------------------------------------------------------------- #

_HP_MINI_TABLE1 = {
    "1": "3",
    "0": "1",
    "3": "F",
    "2": "7",
    "5": "Q",
    "4": "V",
    "7": "X",
    "6": "G",
    "9": "O",
    "8": "U",
    "a": "C",
    "c": "E",
    "b": "P",
    "e": "M",
    "d": "T",
    "g": "H",
    "f": "8",
    "i": "Y",
    "h": "Z",
    "k": "S",
    "j": "W",
    "m": "4",
    "l": "K",
    "o": "J",
    "n": "9",
    "q": "5",
    "p": "2",
    "s": "N",
    "r": "B",
    "u": "L",
    "t": "A",
    "w": "D",
    "v": "6",
    "y": "I",
    "x": "4",
    "z": "0",
}
_HP_MINI_TABLE2 = dict(_HP_MINI_TABLE1)
_HP_MINI_TABLE2["x"] = "R"


_HP_AMI_SALT = bytes(
    [
        0xB9,
        0xED,
        0xF5,
        0x69,
        0x9D,
        0x16,
        0x49,
        0xF9,
        0x8C,
        0x5F,
        0x7C,
        0xB3,
        0x68,
        0x3C,
        0xD4,
        0xA7,
    ]
)


def hp_ami(code: str) -> str:
    """HP AMI master password from an 8-digit hex code (pwgen-for-bios hpami).

    Refuses anything that is not 8 hex digits rather than returning a guess.
    """
    text = (code or "").strip()
    if len(text) != 8 or any(c not in "0123456789abcdefABCDEF" for c in text):
        raise ValueError("HP AMI code must be 8 hex digits")
    value = int(text, 16)
    inner = bytes(b ^ 0x36 for b in _HP_AMI_SALT) + value.to_bytes(4, "little")
    mixed = zlib.crc32(inner) & 0xFFFFFFFF
    outer = bytes(b ^ 0x5C for b in _HP_AMI_SALT) + mixed.to_bytes(4, "little")
    return f"{zlib.crc32(outer) & 0xFFFFFFFF:08x}"


def hp_mini(code: str) -> str:
    code = (code or "").strip()
    if not code or any(c.lower() not in _HP_MINI_TABLE1 for c in code):
        raise ValueError("HP Mini serial must use only letters and digits")
    pw1 = "".join(_HP_MINI_TABLE1[c.lower()] for c in code)
    pw2 = "".join(_HP_MINI_TABLE2[c.lower()] for c in code)
    if pw1 == pw2:
        return pw1.lower()
    return pw1.lower() + " OR " + pw2.lower()


# --------------------------------------------------------------------- #
#  ASUS  -  system date (shown after Alt+R on a wrong password)          #
# --------------------------------------------------------------------- #


def _asus_shuffle1(a1: int, a2: int) -> int:
    v3 = 2
    for _ in range(a2):
        v4 = v3
        v5 = a1
        while v5 > 0:
            if v5 < v4:
                v5, v4 = v4, v5
            v5 %= v4
        if v4 != 1:
            v3 += 1
            if v3 < a1:
                continue
    return v3


def _asus_shuffle2(a1: int, a2: int, a3: int) -> int:
    if a1 >= a3:
        a1 %= a3
    result = a1
    if a2 != 1:
        for _ in range(a2 - 1):
            result = a1 * result % a3
    return result


def _asus_init_table(i1: int = 11, i2: int = 19, i3: int = 6) -> list:
    table = [""] * 32
    table[0] = chr(i1 + ord("0"))
    table[1] = chr(i2 + ord("0"))
    table[2] = chr(i3 + ord("0"))
    table[3:7] = ["6", "7", "8", "9"]
    chksum = sum(ord(table[i]) for i in range(7))
    for i in range(7, 32):
        chksum = 33676 * chksum + 12345
        table[i] = chr(((chksum >> 16) & 0x7FFF) % 43 + ord("0"))
    v3 = i1 * i2
    v4 = _asus_shuffle1((i1 - 1) * (i2 - 1), i3)
    for i in range(32):
        table[i] = chr(_asus_shuffle2(ord(table[i]) - ord("0"), v4, v3))
    return table


def asus_date(date_str: str) -> str:
    date_str = (date_str or "").strip().replace("/", "-").replace(".", "-")
    digits = date_str.replace("-", "")
    if len(digits) != 8 or not digits.isdigit():
        raise ValueError("ASUS date must be YYYY-MM-DD")
    date = int(digits, 16)
    chksum = date
    table = _asus_init_table()
    password = ""
    for _ in range(8):
        chksum = 33676 * chksum + 12345
        index = (chksum >> 16) & 31
        pwd_c = ord(table[index]) % 36
        password += chr(pwd_c + ord("7")) if pwd_c > 9 else chr(pwd_c + ord("0"))
    return password


# --------------------------------------------------------------------- #
#  dispatcher                                                            #
# --------------------------------------------------------------------- #

def _dell_code(code: str) -> list[str]:
    from bios_recovery.utils.dell_passwords import dell_from_code

    return dell_from_code(code)


GENERATORS = {
    "phoenix_5dec": ("Phoenix / HP / Compaq / FSI (5 decimal digits)", phoenix_5dec),
    "fsi_hex": ("Fujitsu-Siemens (8 hex digits or 5x4 hex)", fsi_hex),
    "fsi_6x4dec": ("Fujitsu-Siemens (6x4 decimal digits)", fsi_6x4dec),
    "insyde_8dec": ("Insyde H2O - Acer/HP/Lenovo (8 decimal digits)", insyde_8dec),
    "samsung": ("Samsung (12/18 hex digits)", samsung),
    "sony_4x4": ("Sony (4x4 hexadecimal OTP)", sony_4x4),
    "hp_mini": ("HP/Compaq Mini (10 char serial)", hp_mini),
    "hp_ami": ("HP AMI (8 hex digits)", hp_ami),
    "dell": ("Dell (1234567-595B, or an 11-character HDD serial)", _dell_code),
    "asus_date": ("ASUS (system date, e.g. 2013-12-31)", asus_date),
}


def generate(generator_key: str, code: str):
    """Run a generator; returns a list of (label, password) tuples."""
    _, fn = GENERATORS[generator_key]
    result = fn(code)
    if isinstance(result, dict):
        return list(result.items())
    if isinstance(result, str):
        return [("password", result)]
    if isinstance(result, list) and result and isinstance(result[0], str):
        labelled = []
        for i, item in enumerate(result):
            name = f"password {i + 1}" if len(result) > 1 else "password"
            labelled.append((name, item))
        return labelled
    if isinstance(result, list) and not result:
        raise ValueError("no password for this input")
    if isinstance(result, list):  # samsung: list of dicts
        return [
            (
                item["label"],
                " / ".join(filter(None, [item["ascii"], item["scancode"], item["hex"]])),
            )
            for item in result
        ]
    return [("password", str(result))]
