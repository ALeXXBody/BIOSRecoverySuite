"""Dell BIOS master passwords, matching pwgen-for-bios (bacher09) and dogbert's dell.c.

The service-tag and HDD-serial forms are the ones that project publishes and tests.
A code it does not recognise returns no password, rather than a guess.
Derived from GPL-2+ sources, so this module is GPL-2+ as well.
"""

from __future__ import annotations

import hashlib

_MD5 = [
    0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE,
    0xF57C0FAF, 0x4787C62A, 0xA8304613, 0xFD469501,
    0x698098D8, 0x8B44F7AF, 0xFFFF5BB1, 0x895CD7BE,
    0x6B901122, 0xFD987193, 0xA679438E, 0x49B40821,
    0xF61E2562, 0xC040B340, 0x265E5A51, 0xE9B6C7AA,
    0xD62F105D, 0x02441453, 0xD8A1E681, 0xE7D3FBC8,
    0x21E1CDE6, 0xC33707D6, 0xF4D50D87, 0x455A14ED,
    0xA9E3E905, 0xFCEFA3F8, 0x676F02D9, 0x8D2A4C8A,
    0xFFFA3942, 0x8771F681, 0x6D9D6122, 0xFDE5380C,
    0xA4BEEA44, 0x4BDECFA9, 0xF6BB4B60, 0xBEBFBC70,
    0x289B7EC6, 0xEAA127FA, 0xD4EF3085, 0x4881D05,
    0xD9D4D039, 0xE6DB99E5, 0x1FA27CF8, 0xC4AC5665,
    0xF4292244, 0x432AFF97, 0xAB9423A7, 0xFC93A039,
    0x655B59C3, 0x8F0CCC92, 0xFFEFF47D, 0x85845DD1,
    0x6FA87E4F, 0xFE2CE6E0, 0xA3014314, 0x4E0811A1,
    0xF7537E82, 0xBD3AF235, 0x2AD7D2BB, 0xEB86D391,
]
_MD5_2 = [
    0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE,
    0xF57C0FAF, 0x4787C62A, 0xA8304613, 0xFD469501,
    0x698098D8, 0x8B44F7AF, 0xFFFF5BB1, 0x895CD7BE,
    0x6B901122, 0xFD987193, 0xA679438E, 0x49B40821,
    0xF61E2562, 0xC040B340, 0x265E5A51, 0xE9B6C7AA,
    0xD62F105D, 0x02441453, 0xD8A1E681, 0xE7D3FBC8,
    0x21E1CDE6, 0xC33707D6, 0xF4D50D87, 0x455A14ED,
    0xA9E3E905, 0xFCEFA3F8, 0x676F02D9, 0x8D2A4C8A,
    0xD9D4D039, 0xE6DB99E5, 0x1FA27CF8, 0xC4AC5665,
    0x289B7EC6, 0xEAA127FA, 0xD4EF3085, 0x04881D05,
    0xA4BEEA44, 0x4BDECFA9, 0xF6BB4B60, 0xBEBFBC70,
    0xFFFA3942, 0x8771F681, 0x6D9D6122, 0xFDE5380C,
    0xF7537E82, 0xBD3AF235, 0x2AD7D2BB, 0xEB86D391,
    0x6FA87E4F, 0xFE2CE6E0, 0xA3014314, 0x4E0811A1,
    0x655B59C3, 0x8F0CCC92, 0xFFEFF47D, 0x85845DD1,
    0xF4292244, 0x432AFF97, 0xAB9423A7, 0xFC93A039,
]
_ROT = ((7, 12, 17, 22), (5, 9, 14, 20), (4, 11, 16, 23), (6, 10, 15, 21))
_INIT = [0x67452301, 0xEFCDAB89 - 0x100000000, 0x98BADCFE - 0x100000000, 0x10325476]
_SCAN = "\0\x1b1234567890-=\x08\tqwertyuiop[]\r\xffasdfghjkl;'`\xff\\zxcvbnm,./"
_ENCSCANS = [
    0x05, 0x10, 0x13, 0x09, 0x32, 0x03, 0x25, 0x11, 0x1F, 0x17, 0x06, 0x15,
    0x30, 0x19, 0x26, 0x22, 0x0A, 0x02, 0x2C, 0x2F, 0x16, 0x14, 0x07, 0x18,
    0x24, 0x23, 0x31, 0x20, 0x1E, 0x08, 0x2D, 0x21, 0x04, 0x0B, 0x12, 0x2E,
]
_ASCII = "012345679abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0"
_TABLES = {
    "2A7B": _ASCII,
    "1F5A": _ASCII,
    "1D3B": "0BfIUG1kuPvc8A9Nl5DLZYSno7Ka6HMgqsJWm65yCQR94b21OTp7VFX2z0jihE33d4xtrew0",
    "1F66": "0ewr3d4xtUG1ku0BfIp7VFb21OTSno7KDLZYqsJWa6HMgCQR94m65y9Nl5Pvc8AjihE3X2z0",
    "6FF1": "08rptBxfbGVMz38IiSoeb360MKcLf4QtBCbWVzmH5wmZUcRR5DZG2xNCEv1nFtzsZB2bw1X0",
    "BF97": "0Q2drGk99rkQFMxN[Z5y3DGr16h638myIL2rzz2pzcU7JWLJ1EGnqRN4seZPRM2aBXIjbkGZ",
}
_TAGS = ("595B", "D35B", "2A7B", "A95B", "1D3B", "6FF1", "1F66", "1F5A", "BF97", "E7A8")
_E7A8_TABLE = "Q92G0drk9y63r5DG1hLqJGW1EnRk[QxrFMNZ328I6myLr4MsPNeZR2z72czpzUJBGXbaIjkZ"


def _i32(n: int) -> int:
    n &= 0xFFFFFFFF
    return n - 0x100000000 if n >= 0x80000000 else n


def _xor(a: int, b: int) -> int:
    return _i32(_i32(a) ^ _i32(b))


def _and(a: int, b: int) -> int:
    return _i32(_i32(a) & _i32(b))


def _or(a: int, b: int) -> int:
    return _i32(_i32(a) | _i32(b))


def _not(a: int) -> int:
    return _i32(~_i32(a))


def _rol(x: int, bits: int) -> int:
    """The rotate pwgen-for-bios uses: a truncating divide, then a JS signed shift."""
    bits &= 31
    xu = x & 0xFFFFFFFF
    divided = int(xu / (2 ** (32 - bits)))
    shifted = _i32(_i32(xu) << bits)
    return _i32(divided | (shifted & 0xFFFFFFFF))


def _f2(a, b, c):
    return _xor(_and(_xor(c, b), a), c)


def _f3(a, b, c):
    return _xor(_and(_xor(a, b), c), b)


def _f4(a, b, c):
    return _xor(_xor(b, a), c)


def _f5(a, b, c):
    return _xor(_or(a, _not(c)), b)


def _f2n(a, b, c):
    return _f2(a, b, _not(c))


def _f4n(a, b, c):
    return _f4(a, _not(b), c)


def _f5n(a, b, c):
    return _f5(_not(a), b, c)


class _Encoder:
    f_sub = True
    f2, f3, f4, f5 = staticmethod(_f2n), staticmethod(_f3), staticmethod(_f4n), staticmethod(_f5n)
    table = _MD5
    rounds = 1
    prefix = None

    def __init__(self, block):
        self.block = block
        self.data = self._initial()
        self.A, self.B, self.C, self.D = self.data

    def _initial(self):
        return list(_INIT)

    def _mix(self, func, key1, key2):
        temp = func(self.B, self.C, self.D)
        total = self.table[key2] + self.block[key1]
        mixed = _i32(temp - total) if self.f_sub else _i32(temp + total)
        return _i32(self.A + mixed)

    def _step(self, t, row, col):
        self.A, self.D, self.C = self.D, self.C, self.B
        self.B = _i32(_rol(t, _ROT[row][col]) + self.B)

    def _one_pass(self, index_of):
        for i in range(64):
            kind, key1, key2 = index_of(i)
            func = (self.f2, self.f3, self.f4, self.f5)[kind]
            self._step(self._mix(func, key1, key2), i >> 4, i & 3)
        self._store(self.A, self.B, self.C, self.D)

    def _store(self, a, b, c, d):
        self.data[0] = _i32(self.data[0] + a)
        self.data[1] = _i32(self.data[1] + b)
        self.data[2] = _i32(self.data[2] + c)
        self.data[3] = _i32(self.data[3] + d)

    def _standard(self, i):
        band = i >> 4
        if band == 0:
            return 0, i & 15, i
        if band == 1:
            return 1, (i * 5 + 1) & 15, i
        if band == 2:
            return 2, (i * 3 + 5) & 15, i
        return 3, (i * 7) & 15, i

    def encode(self):
        for _ in range(self.rounds):
            self._before_pass()
            self._one_pass(self._standard)
        return [n & 0xFFFFFFFF for n in self.data]

    def _before_pass(self):
        return None


class _D35B(_Encoder):
    f_sub = False
    f2, f4, f5 = staticmethod(_f2), staticmethod(_f4), staticmethod(_f5)


class _1D3B(_Encoder):
    rounds = 21

    def _before_pass(self):
        j = self._seen
        self.A = _or(self.A, 0x97)
        self.B = _xor(self.B, 0x8)
        self.C = _or(self.C, 0x60606161 - j)
        self.D = _xor(self.D, 0x50501010 + j)
        self._seen += 1

    def encode(self):
        self._seen = 0
        return super().encode()


class _1F66(_Encoder):
    table = _MD5_2

    def encode(self):
        for j in range(17):
            self.A = _or(self.A, 0x100097)
            self.B = _xor(self.B, 0xA0008)
            self.C = _or(self.C, 0x60606161 - j)
            self.D = _xor(self.D, 0x50501010 + j)
            self._one_pass(self._first)
        for j in range(21):
            self.A = _or(self.A, 0x97)
            self.B = _xor(self.B, 0x8)
            self.C = _or(self.C, 0x50501010 - j)
            self.D = _xor(self.D, 0x60606161 + j)
            self._one_pass(self._second)
        return [n & 0xFFFFFFFF for n in self.data]

    def _first(self, i):
        band = i >> 4
        if band == 0:
            return 0, i & 15, i + 16
        if band == 1:
            return 1, (i * 5 + 1) & 15, i + 32
        if band == 2:
            return 2, (i * 3 + 5) & 15, i - 2 * (i & 12) + 12
        return 3, (i * 7) & 15, 2 * (i & 3) - (i & 15) + 12

    def _second(self, i):
        band = i >> 4
        if band == 0:
            return 2, (i * 3 + 5) & 15, 2 * (i & 3) - i + 44
        if band == 1:
            return 3, (i * 7) & 15, 2 * (i & 3) - i + 76
        if band == 2:
            return 0, i & 15, i & 15
        return 1, (i * 5 + 1) & 15, i - 32

    def _step(self, t, row, col):
        if getattr(self, "_alt_rot", False):
            row = (row + 2) & 3
        super()._step(t, row, col)

    def _one_pass(self, index_of):
        self._alt_rot = getattr(index_of, "__func__", None) is self._second.__func__
        super()._one_pass(index_of)


class _6FF1(_1F66):
    def encode(self):
        for j in range(self._outer()):
            self.A = _or(self.A, 0xA08097)
            self.B = _xor(self.B, 0xA010908)
            self.C = _or(self.C, 0x60606161 - j)
            self.D = _xor(self.D, 0x50501010 + j)
            self._one_pass(self._first6)
        for j in range(17):
            self.A = _or(self.A, 0x100097)
            self.B = _xor(self.B, 0xA0008)
            self.C = _or(self.C, 0x50501010 - j)
            self.D = _xor(self.D, 0x60606161 + j)
            self._one_pass(self._second6)
        return [n & 0xFFFFFFFF for n in self.data]

    def _outer(self):
        return 23

    def _first6(self, i):
        k = (i & 15) - ((i & 12) << 1) + 12
        band = i >> 4
        if band == 0:
            return 0, i & 15, i + 32
        if band == 1:
            return 1, (i * 5 + 1) & 15, i & 15
        if band == 2:
            return 2, (i * 3 + 5) & 15, k + 16
        return 3, (i * 7) & 15, k + 48

    def _second6(self, i):
        k = (i & 15) - ((i & 12) << 1) + 12
        band = i >> 4
        if band == 0:
            return 2, ((i & 15) * 3 + 5) & 15, k + 16
        if band == 1:
            return 3, ((i & 3) * 7 + (i & 12) + 4) & 15, (i & 15) + 32
        if band == 2:
            return 0, k & 15, k
        return 1, ((i & 15) * 5 + 1) & 15, (i & 15) + 48

    def _one_pass(self, index_of):
        self._alt_rot = getattr(index_of, "__func__", None) is self._second6.__func__
        _Encoder._one_pass(self, index_of)


class _BF97(_6FF1):
    def _outer(self):
        return 31


class _1F5A(_Encoder):
    table = _MD5_2

    def _mix(self, func, key1, key2):
        temp = func(self.C, self.A, self.D)
        total = self.table[key2] + self.block[key1]
        mixed = _i32(temp - total) if self.f_sub else _i32(temp + total)
        return _i32(self.B + mixed)

    def _step(self, t, row, col):
        self.B, self.D, self.A = self.D, self.A, self.C
        self.C = _i32(_rol(t, _ROT[row][col]) + self.C)

    def _store(self, a, b, c, d):
        self.data[0] = _i32(self.data[0] + b)
        self.data[1] = _i32(self.data[1] + c)
        self.data[2] = _i32(self.data[2] + a)
        self.data[3] = _i32(self.data[3] + d)

    def encode(self):
        for _ in range(5):
            self._one_pass(self._indexes)
        return [n & 0xFFFFFFFF for n in self.data]

    def _indexes(self, i):
        k = 12 + (i & 3) - (i & 12)
        band = i >> 4
        if band == 0:
            return 0, i & 15, i
        if band == 1:
            return 1, (i * 5 + 1) & 15, i
        if band == 2:
            return 2, (i * 3 + 5) & 15, k + 0x20
        return 3, (i * 7) & 15, k + 0x30


_ENCODERS = {
    "595B": _Encoder,
    "2A7B": _Encoder,
    "A95B": _Encoder,
    "D35B": _D35B,
    "1D3B": _1D3B,
    "1F66": _1F66,
    "6FF1": _6FF1,
    "1F5A": _1F5A,
    "BF97": _BF97,
}


def _bytes_to_ints(raw: list[int]) -> list[int]:
    out = []
    for i in range(16):
        chunk = raw[i * 4 : i * 4 + 4]
        word = 0
        for shift, value in enumerate(chunk):
            word |= value << (8 * shift)
        out.append(_i32(word))
    return out


def _ints_to_bytes(words: list[int]) -> list[int]:
    out = []
    for word in words:
        value = word & 0xFFFFFFFF
        out.extend((value & 0xFF, (value >> 8) & 0xFF, (value >> 16) & 0xFF, (value >> 24) & 0xFF))
    return out


def _suffix(serial: list[int], tag: str, hdd: bool) -> list[int]:
    a1 = [1, 10, 9, 8] if hdd else [1, 2, 3, 4]
    a2 = [8, 9, 10] if hdd else [4, 3, 2]
    suffix = [
        serial[a1[3]],
        (serial[a1[3]] >> 5) | (((serial[a1[2]] >> 5) | (serial[a1[2]] << 3)) & 0xF1),
        serial[a1[2]] >> 2,
        (serial[a1[2]] >> 7) | (serial[a1[1]] << 1),
        (serial[a1[1]] >> 4) | (serial[a1[0]] << 4),
        serial[1] >> 1,
        (serial[1] >> 6) | (serial[0] << 2),
        serial[0] >> 3,
    ]
    suffix = [n & 0xFF for n in suffix]
    table = [ord(c) for c in _TABLES[tag]] if tag in _TABLES else _ENCSCANS
    for i, value in enumerate(suffix):
        mixed = 0xAA
        if value & 1:
            mixed ^= serial[a2[0]]
        if value & 2:
            mixed ^= serial[a2[1]]
        if value & 4:
            mixed ^= serial[a2[2]]
        if value & 8:
            mixed ^= serial[1]
        if value & 16:
            mixed ^= serial[0]
        suffix[i] = table[mixed % len(table)]
    return suffix


def _result(raw: list[int], tag: str) -> str:
    table = _TABLES.get(tag)
    if table:
        return "".join(table[b % len(table)] for b in raw[:16])
    start = raw[0] % 9
    out = []
    for i, byte in enumerate(raw[:16]):
        if start <= i and len(out) < 8:
            out.append(_SCAN[_ENCSCANS[byte % len(_ENCSCANS)]])
    return "".join(out)


class _E7A8(_Encoder):
    """The E7A8 block step from pwgen-for-bios. SHA-256 is applied to its output."""

    table = _MD5_2
    loops = (17, 13, 12, 8)
    params = (
        0x50501010, 0xA010908, 0xA08097, 0x60606161,
        0x60606161, 0xA0008, 0x100097, 0x50501010,
    )

    def _initial(self):
        return [0, 0, 0, 0]

    def _shortcut(self, func, j, md5_index, rot_index, indexes):
        for i in range(4):
            mixed = self._mix(func, (j + indexes[i]) & 7, i + md5_index)
            self.A, self.D, self.C = self.D, self.C, self.B
            self.B = _i32(_rol(mixed, _ROT[rot_index][i]) + self.B)

    def _body(self, p, base):
        self.A = _or(self.A, self.params[base])
        self.B = _xor(self.B, self.params[base + 1])
        self.C = _or(self.C, self.params[base + 2] - p)
        self.D = _xor(self.D, self.params[base + 3] + p)

    def encode(self):
        width, inner = self.loops[2], self.loops[3]
        for p in range(self.loops[0]):
            self._body(p, 0)
            for j in range(0, width, 4):
                self._shortcut(self.f2, j, j + 32, 0, (0, 1, 2, 3))
            for j in range(0, width, 4):
                self._shortcut(self.f3, j, j, 1, (1, -2, -1, 0))
            j = inner
            while j > 3:
                self._shortcut(self.f4, j, j + 16, 2, (-3, -4, -1, 2))
                j -= 4
            j = inner
            while j > 3:
                self._shortcut(self.f5, j, j + 48, 3, (2, 3, 2, -3))
                j -= 4
            self._store(self.A, self.B, self.C, self.D)
        for p in range(self.loops[1]):
            self._body(p, 4)
            j = inner
            while j > 3:
                self._shortcut(self.f4, j, j + 16, 2, (-3, -4, -1, 2))
                j -= 4
            for j in range(0, width, 4):
                self._shortcut(self.f5, j, j + 32, 3, (2, 3, 2, -3))
            j = inner
            while j > 0:
                self._shortcut(self.f2, j, j, 0, (0, 1, 2, 3))
                j -= 4
            for j in range(0, width, 4):
                self._shortcut(self.f3, j, j + 48, 1, (1, -2, 3, 0))
            self._store(self.A, self.B, self.C, self.D)
        return [n & 0xFFFFFFFF for n in self.data]


class _E7A8B(_E7A8):
    loops = (17, 13, 12, 16)

    def __init__(self, block):
        extra = [
            0xA0008 ^ 0x6D2F93A5,
            0xA08097 ^ 0x6D2F93A5,
            0xA010908 ^ 0x6D2F93A5,
            0x60606161 ^ 0x6D2F93A5,
        ]
        self.table = list(_MD5_2) + extra
        super().__init__(block)


def _e7a8_passwords(serial: str, suffix: str) -> list[str]:
    raw = [ord(c) for c in serial + suffix]
    words = _bytes_to_ints(raw)
    out = []
    for klass in (_E7A8, _E7A8B):
        digest = hashlib.sha256(bytes(_ints_to_bytes(klass(words).encode()))).digest()
        width = len(_E7A8_TABLE)
        text = "".join(_E7A8_TABLE[(digest[i + 16] + digest[i]) % width] for i in range(16))
        if text:
            out.append(text)
    return out


def dell_password(serial: str, suffix: str, hdd: bool = False) -> list[str]:
    """Passwords for one Dell code, or [] when the suffix or the length is not recognised."""
    serial = (serial or "").strip().upper()
    suffix = (suffix or "").strip().upper()
    if suffix not in _TAGS:
        return []
    if hdd and len(serial) != 11 or not hdd and len(serial) != 7:
        return []
    if suffix == "E7A8":
        return _e7a8_passwords(serial, suffix)
    body = serial[3:] + "\0\0\0" + "595B" if suffix == "A95B" and hdd else serial + (
        "595B" if suffix == "A95B" else suffix
    )
    raw = [ord(c) for c in body]
    raw.extend(_suffix(raw, suffix, hdd))
    # The published code writes the padding byte at index 23, not at the end.
    raw.extend([0] * (23 - len(raw)))
    raw.append(0x80)
    words = _bytes_to_ints(raw)
    words[14] = _i32(23 << 3)
    encoded = _ENCODERS[suffix](words).encode()
    text = _result(_ints_to_bytes(encoded), suffix)
    return [text] if text else []


def dell_from_code(code: str) -> list[str]:
    """Accept the same forms the other project does: ``1234567-595B`` or ``1234567890A-595B``."""
    text = (code or "").strip().upper()
    if len(text) == 11 and "-" not in text:
        return [_hdd_old(text)] if _hdd_old(text) else []
    if len(text) == 12 and text[7] == "-":
        return dell_password(text[:7], text[8:], hdd=False)
    if len(text) == 16 and text[11] == "-":
        return dell_password(text[:11], text[12:], hdd=True)
    return []


def _hdd_old(serial: str) -> str:
    raw = [ord(c) for c in serial]
    out = [49, 49, 49, 49, 49, raw[1] >> 1, (raw[1] >> 6) | (raw[0] << 2), raw[0] >> 3]
    for i, value in enumerate(out):
        mixed = 0xAA
        if value & 8:
            mixed ^= raw[1]
        if value & 16:
            mixed ^= raw[0]
        out[i] = _ENCSCANS[mixed % len(_ENCSCANS)]
    return "".join(_SCAN[c] for c in out)


