"""Dell Latitude 3540 master password, matching pwgen-for-bios.

The input is 16 hex digits and a 7-character tag, with or without a hyphen:
``5F3988D5E0ACE4BF-7QH8602``. A result that is not 8 hex digits is refused.
Derived from GPL-2+ sources, so this module is GPL-2+ as well.
"""

from __future__ import annotations

_IP = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7,
]
_FP = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25,
]
_PC1 = [
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4,
]
_PC2 = [
    14, 17, 11, 24, 1, 5, 3, 28,
    15, 6, 21, 10, 23, 19, 12, 4,
    26, 8, 16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40,
    51, 45, 33, 48, 44, 49, 39, 56,
    34, 53, 46, 42, 50, 36, 29, 32,
]
_EXPANSION = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1,
]
_POST = [
    16, 7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2, 8, 24, 14,
    32, 27, 3, 9,
    19, 13, 30, 6,
    22, 11, 4, 25,
]
_SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
_SBOX = [
    14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
    0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
    4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
    15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
    15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
    3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
    0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
    13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9,
    10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
    13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
    13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
    1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,
    7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
    13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
    10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
    3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14,
    2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
    14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
    4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
    11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3,
    12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
    10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
    9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
    4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13,
    4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
    13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
    1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
    6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12,
    13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
    1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
    7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
    2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11,
]
_MASTER = b"23AAFFAD"


def _byte_bit(data: bytes, index: int) -> int:
    return (data[index >> 3] >> (7 - (index & 7))) & 1


def _shift28(part: int, count: int) -> int:
    return ((part >> count) | (part << (28 - count))) & 0x0FFFFFFF


def _func(data: int, subkey2: int, subkey1: int) -> int:
    part1 = part2 = 0
    for i, source in enumerate(_EXPANSION):
        bit = (data >> (source - 1)) & 1
        if i < 32:
            part1 |= bit << i
        else:
            part2 |= bit << (i - 32)
    part2 ^= subkey2
    part1 ^= subkey1

    def ebit(index: int) -> int:
        if index < 32:
            return (part1 >> index) & 1
        return (part2 >> (index - 32)) & 1

    temp = 0
    for level, i in enumerate(range(0, 48, 6)):
        row = (ebit(i) << 1) | ebit(i + 5)
        col = (ebit(i + 1) << 3) | (ebit(i + 2) << 2) | (ebit(i + 3) << 1) | ebit(i + 4)
        temp = (temp << 4) | _SBOX[(level << 6) | (row << 4) | col]
    output = 0
    for i, source in enumerate(_POST):
        output |= ((temp >> (32 - source)) & 1) << i
    return output


class _DES:
    def __init__(self, key: bytes):
        if len(key) != 8:
            raise ValueError("DES key should be 8 bytes long")
        self._subkeys = self._subkeys_for(key)

    @staticmethod
    def _subkeys_for(key: bytes) -> list[int]:
        left = right = 0
        for i, source in enumerate(_PC1):
            bit = _byte_bit(key, source - 1)
            if i < 28:
                left |= bit << i
            else:
                right |= bit << (i - 28)
        subkeys = []
        for count in _SHIFTS:
            left = _shift28(left, count)
            right = _shift28(right, count)
            part1 = part2 = 0
            for i, source in enumerate(_PC2):
                index = source - 1
                bit = (left >> index) & 1 if index < 28 else (right >> (index - 28)) & 1
                if i < 32:
                    part1 |= bit << i
                else:
                    part2 |= bit << (i - 32)
            subkeys.extend((part2, part1))
        return subkeys

    def encrypt_block(self, block: bytes) -> bytes:
        return self._crypt(block, True)

    def decrypt_block(self, block: bytes) -> bytes:
        return self._crypt(block, False)

    def _crypt(self, block: bytes, encrypt: bool) -> bytes:
        if len(block) != 8:
            raise ValueError("Input should be 8 bytes long")
        left = right = 0
        for i, source in enumerate(_IP):
            bit = _byte_bit(block, source - 1)
            if i < 32:
                left |= bit << i
            else:
                right |= bit << (i - 32)
        rounds = range(16) if encrypt else range(15, -1, -1)
        for round_ in rounds:
            mixed = _func(right, self._subkeys[round_ << 1], self._subkeys[(round_ << 1) | 1])
            left, right = right, left ^ mixed
        output = bytearray(8)
        for i, source in enumerate(_FP):
            index = source - 1
            bit = (right >> index) & 1 if index < 32 else (left >> (index - 32)) & 1
            output[i >> 3] |= bit << (7 - (i & 7))
        return bytes(output)


def latitude3540(code: str) -> list[str]:
    """Password for a Latitude 3540 code, or [] if it is not that form or does not decode."""
    text = (code or "").strip().replace("-", "")
    if len(text) != 23:
        return []
    digest, tag = text[:16], text[16:]
    if any(c not in "0123456789abcdefABCDEF" for c in digest):
        return []
    if any(not (c.isdigit() or ("A" <= c <= "Z") or ("a" <= c <= "z")) for c in tag):
        return []
    block2 = bytes(int(digest[i : i + 2], 16) for i in range(0, 16, 2))
    block1 = bytes([ord(tag[-1])]) + b"\x00" * 7
    key2 = _DES(_MASTER).encrypt_block(block1)
    decoded = _DES(key2).decrypt_block(block2)
    try:
        password = decoded.decode("ascii")
    except UnicodeDecodeError:
        return []
    if len(password) == 8 and all(c in "0123456789abcdefABCDEF" for c in password):
        return [password]
    return []
