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
  * ASUS                                         - system date (Alt+R)
"""

import struct

# --------------------------------------------------------------------- #
#  shared building blocks (from dogbert's scripts)                       #
# --------------------------------------------------------------------- #

KEYBOARD_DICT = {
    2: '1', 3: '2', 4: '3', 5: '4', 6: '5', 7: '6', 8: '7', 9: '8', 10: '9', 11: '0',
    16: 'q', 17: 'w', 18: 'e', 19: 'r', 20: 't', 21: 'y', 22: 'u', 23: 'i', 24: 'o', 25: 'p',
    30: 'a', 31: 's', 32: 'd', 33: 'f', 34: 'g', 35: 'h', 36: 'j', 37: 'k', 38: 'l',
    44: 'z', 45: 'x', 46: 'c', 47: 'v', 48: 'b', 49: 'n', 50: 'm',
}

KEYBOARD_SCANCODE_DICT = {
    2: '1', 3: '2', 4: '3', 5: '4', 6: '5', 7: '6', 8: '7', 9: '8', 10: '9', 11: '0',
    16: 'q', 17: 'w', 18: 'e', 19: 'r', 20: 't', 21: 'y', 22: 'u', 23: 'i', 24: 'o', 25: 'p',
    30: 'a', 31: 's', 32: 'd', 33: 'f', 34: 'g', 35: 'h', 36: 'j', 37: 'k', 38: 'l', 39: ';',
    44: 'z', 45: 'x', 46: 'c', 47: 'v', 48: 'b', 49: 'n', 50: 'm', 51: '.', 52: ',', 53: '/',
}


def keyboard_enc_to_ascii(in_key) -> str:
    return "".join(KEYBOARD_DICT[c] for c in in_key if c in KEYBOARD_DICT)


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

def _brute_force_deterministic(hash_val: int, salt: int = 0,
                               digits_only: bool = False,
                               chars_only: bool = True,
                               min_len: int = 3, max_len: int = 8) -> str:
    """Deterministic DFS variant of dogbert's randomized brute force.

    Returns a keyboard-encoded password whose buggy-CRC16 equals hash_val."""
    if digits_only:
        keys = [k for k in KEYBOARD_DICT if KEYBOARD_DICT[k].isdigit()][:10]
    elif chars_only:
        keys = [k for k in KEYBOARD_DICT if KEYBOARD_DICT[k].isalpha()]
    else:
        keys = list(KEYBOARD_DICT)
    if hash_val > 0x3FFF:
        return "invalid hash code"

    from itertools import product
    for length in range(min_len, max_len + 1):
        for combo in product(keys, repeat=length):
            # incremental check is unnecessary: product yields quickly enough
            if bad_crc16(combo, salt) == hash_val:
                return keyboard_enc_to_ascii(combo)
    return ""


def phoenix_5dec(code: str) -> dict:
    """5-decimal-digit hashes: Phoenix generic, HP/Compaq, FSI variants."""
    code = (code or "").strip().replace("[", "").replace("]", "")
    h = int(code)
    return {
        "Phoenix generic": _brute_force_deterministic(h, 0),
        "HP/Compaq Phoenix": _brute_force_deterministic(h, salt=17232),
        "FSI Phoenix (generic)": _brute_force_deterministic(
            h, salt=65, digits_only=True, min_len=3, max_len=7),
        "FSI Phoenix (L model)": _brute_force_deterministic(
            h + 1, salt=ord('L'), digits_only=True, min_len=3, max_len=7),
        "FSI Phoenix (P model)": _brute_force_deterministic(
            h + 1, salt=ord('P'), digits_only=True, min_len=3, max_len=7),
        "FSI Phoenix (S model)": _brute_force_deterministic(
            h + 1, salt=ord('S'), digits_only=True, min_len=3, max_len=7),
        "FSI Phoenix (X model)": _brute_force_deterministic(
            h + 1, salt=ord('X'), digits_only=True, min_len=3, max_len=7),
    }


# --------------------------------------------------------------------- #
#  Fujitsu-Siemens  -  8 hex digits and 5x4 hex digits                   #
# --------------------------------------------------------------------- #

def _fsi_hash_to_string(h: int) -> str:
    return (chr(ord('0') + ((h >> 12) % 16) % 10)
            + chr(ord('0') + ((h >> 8) % 16) % 10)
            + chr(ord('0') + ((h >> 4) % 16) % 10)
            + chr(ord('0') + ((h >> 0) % 16) % 10))


def _fsi_calculate_hash(word: str, table) -> int:
    h = 0
    for c in word:
        d = table[(ord(c) ^ (h >> 8)) % 256]
        h = ((h << 8) ^ d) & 0xFFFF
    return h


def fsi_hex(code: str) -> str:
    """8-hex-digit hash (or 5x4 hex: AAAA-BBBB-CCCC-DEAD-BEEF)."""
    code = (code or "").strip().replace('-', '').upper()
    if len(code) == 20:
        code = code[12:20]
    table = generate_crc16_table()
    return (_fsi_hash_to_string(_fsi_calculate_hash(code[0:4], table))
            + _fsi_hash_to_string(_fsi_calculate_hash(code[4:8], table)))


# --------------------------------------------------------------------- #
#  Fujitsu-Siemens  -  6x4 decimal digits                                #
# --------------------------------------------------------------------- #

def fsi_6x4dec(code: str) -> str:
    """6x4-decimal hash (entered after 3hqgo3 / jqw534 / 0qww294e)."""
    code = (code or "").strip().replace('-', '').replace(' ', '')
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
        return chr(ord('a') + b - 10) if b > 9 else chr(ord('0') + b)

    return "".join(byte_to_char(x % 36) for x in data)


# --------------------------------------------------------------------- #
#  Insyde H2O (Acer, HP, Lenovo)  -  8 decimal digits                    #
# --------------------------------------------------------------------- #

def insyde_8dec(in_hash: str) -> str:
    in_hash = (in_hash or "").strip().replace('-', '')
    salt = 'Iou|hj&Z'
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

_SAMSUNG_ROT1 = [7, 1, 5, 3, 0, 6, 2, 5, 2, 3, 0, 6, 1, 7, 6, 1,
                 5, 2, 7, 1, 0, 3, 7, 6, 1, 0, 5, 2, 1, 5, 7, 3, 2, 0, 6]
_SAMSUNG_ROT2 = [1, 6, 2, 5, 7, 3, 0, 7, 1, 6, 2, 5, 0, 3, 0, 6,
                 5, 1, 1, 7, 2, 5, 2, 3, 7, 6, 2, 1, 3, 7, 6, 5, 0, 1, 7]


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
    code = (code or "").strip().replace('-', '').replace(' ', '').upper()
    hash_bytes = [int(code[2 * i] + code[2 * i + 1], 16)
                  for i in range(1, len(code) // 2)]
    key = int(code[0:2], 16) % 5
    out = []
    for name, matrix in (("key 1", _SAMSUNG_ROT1), ("key 2", _SAMSUNG_ROT2)):
        dec = _samsung_decrypt(hash_bytes, key, matrix)
        out.append({
            "label": name,
            "hex": "".join("%02x" % x for x in dec),
            "ascii": "".join(chr(x) if 32 <= x < 127 else "" for x in dec),
            "scancode": keyboard_enc_to_ascii(dec),
        })
    return out


# --------------------------------------------------------------------- #
#  Sony  -  4x4 hexadecimal OTP                                          #
# --------------------------------------------------------------------- #

def sony_4x4(code: str) -> str:
    code = (code or "").replace('-', '').replace(' ', '').upper()
    otp_chars = "9DPK7V2F3RT6HX8J"
    pwd_chars = "47592836"

    # decodeHash: bytes are prepended, little-endian style
    dec = 0
    for c in range(len(code) // 2):
        dec = ((otp_chars.find(code[2 * c]) * 16
                + otp_chars.find(code[2 * c + 1])) << (8 * c)) | dec
    b = dec.to_bytes(8, "little")

    p, q = 2795287379, 3544934711
    e = 41
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)

    c_val = struct.unpack("<Q", b)[0]
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

_HP_MINI_TABLE1 = {'1': '3', '0': '1', '3': 'F', '2': '7', '5': 'Q', '4': 'V',
                   '7': 'X', '6': 'G', '9': 'O', '8': 'U', 'a': 'C', 'c': 'E',
                   'b': 'P', 'e': 'M', 'd': 'T', 'g': 'H', 'f': '8', 'i': 'Y',
                   'h': 'Z', 'k': 'S', 'j': 'W', 'm': '4', 'l': 'K', 'o': 'J',
                   'n': '9', 'q': '5', 'p': '2', 's': 'N', 'r': 'B', 'u': 'L',
                   't': 'A', 'w': 'D', 'v': '6', 'y': 'I', 'x': '4', 'z': '0'}
_HP_MINI_TABLE2 = dict(_HP_MINI_TABLE1)
_HP_MINI_TABLE2['x'] = 'R'


def hp_mini(code: str) -> str:
    code = (code or "").strip()
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
    table = [''] * 32
    table[0] = chr(i1 + ord('0'))
    table[1] = chr(i2 + ord('0'))
    table[2] = chr(i3 + ord('0'))
    table[3:7] = ["6", "7", "8", "9"]
    chksum = sum(ord(table[i]) for i in range(7))
    for i in range(7, 32):
        chksum = 33676 * chksum + 12345
        table[i] = chr(((chksum >> 16) & 0x7FFF) % 43 + ord('0'))
    v3 = i1 * i2
    v4 = _asus_shuffle1((i1 - 1) * (i2 - 1), i3)
    for i in range(32):
        table[i] = chr(_asus_shuffle2(ord(table[i]) - ord('0'), v4, v3))
    return table


def asus_date(date_str: str) -> str:
    date_str = (date_str or "").strip().replace('/', '-').replace('.', '-')
    date = int(date_str.replace('-', ''), 16)
    chksum = date
    table = _asus_init_table()
    password = ""
    for _ in range(8):
        chksum = 33676 * chksum + 12345
        index = (chksum >> 16) & 31
        pwd_c = ord(table[index]) % 36
        password += chr(pwd_c + ord('7')) if pwd_c > 9 else chr(pwd_c + ord('0'))
    return password


# --------------------------------------------------------------------- #
#  dispatcher                                                            #
# --------------------------------------------------------------------- #

GENERATORS = {
    "phoenix_5dec": ("Phoenix / HP / Compaq / FSI (5 decimal digits)", phoenix_5dec),
    "fsi_hex": ("Fujitsu-Siemens (8 hex digits or 5x4 hex)", fsi_hex),
    "fsi_6x4dec": ("Fujitsu-Siemens (6x4 decimal digits)", fsi_6x4dec),
    "insyde_8dec": ("Insyde H2O - Acer/HP/Lenovo (8 decimal digits)", insyde_8dec),
    "samsung": ("Samsung (12/18 hex digits)", samsung),
    "sony_4x4": ("Sony (4x4 hexadecimal OTP)", sony_4x4),
    "hp_mini": ("HP/Compaq Mini (10 char serial)", hp_mini),
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
    if isinstance(result, list):     # samsung: list of dicts
        return [(item["label"],
                 " / ".join(filter(None, [item["ascii"], item["scancode"], item["hex"]])))
                for item in result]
    return [("password", str(result))]
