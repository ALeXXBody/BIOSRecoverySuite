"""Find the SMBIOS structure table in a firmware image.

DMI extract, edit and clone all use this module, so they agree on where the table is.

A table is found in one of two ways:

1. An entry point (_SM_ for SMBIOS 2.x, _SM3_ for 3.x) whose table validates. The table
   is taken at the address the entry gives when that address is inside the image, and
   otherwise directly after the entry point, which is the layout many firmwares use.
2. No usable entry point: a chain of structures that validates, found by scanning. This
   is how images keep the table without an entry point.

A table validates only when its structures are well formed (lengths fit, each string
set is printable ASCII ending in the spec's double NUL) and it contains a System
Information structure (type 1). Random bytes that happen to contain "_SM_" or "_DMI_"
do not pass.
"""

from __future__ import annotations

import re
import struct
from typing import Iterator, Optional

END_OF_TABLE = 127
SCAN_MIN_STRUCTURES = 6
ENTRY_MIN_STRUCTURES = 2


def _string_set_end(data: bytes, start: int, end: int) -> Optional[int]:
    """Position just past the string set at start, or None if it is malformed."""
    pos = start
    if pos + 1 < end and data[pos] == 0 and data[pos + 1] == 0:
        return pos + 2
    while True:
        while pos < end and data[pos] != 0:
            if not 0x20 <= data[pos] <= 0x7E:
                return None
            pos += 1
        if pos >= end:
            return None
        pos += 1  # the NUL that ends this string
        if pos < end and data[pos] == 0:
            return pos + 1
        if pos >= end:
            return None


def walk(data: bytes, start: int, end: int) -> Iterator[tuple[int, int, int, int]]:
    """Yield (offset, type, length, next_offset) for each well-formed structure.

    Stops at the first malformed structure or at end-of-table.
    """
    pos = start
    while pos + 4 <= end:
        stype = data[pos]
        slen = data[pos + 1]
        if slen < 4 or pos + slen > end:
            return
        nxt = _string_set_end(data, pos + slen, end)
        if nxt is None:
            return
        yield pos, stype, slen, nxt
        if stype == END_OF_TABLE:
            return
        pos = nxt


def _first_string(data: bytes, start: int, slen: int, end: int) -> bytes:
    """The first string of the structure at start (its vendor or manufacturer field)."""
    pos = start + slen
    stop = pos
    while stop < end and data[stop] != 0:
        stop += 1
    return bytes(data[pos:stop])


def _plausible_first_string(text: bytes) -> bool:
    """Vendor names are at least three printable characters and contain a letter."""
    return len(text) >= 3 and any(chr(c).isalpha() for c in text)


def _validate(data: bytes, start: int, end: int, min_structures: int) -> Optional[int]:
    """End offset of the table if [start, end) validates, else None."""
    kinds = []
    last = start
    first_text = None
    for off, stype, slen, nxt in walk(data, start, end):
        if first_text is None:
            first_text = _first_string(data, off, slen, end)
        kinds.append(stype)
        last = nxt
    if len(kinds) < min_structures or 1 not in kinds or kinds[0] not in (0, 1):
        return None
    if not _plausible_first_string(first_text or b""):
        return None
    return last


def _entry_candidates(data: bytes):
    """(entry_offset, table_start, table_length) for every SMBIOS entry point."""
    for m in re.finditer(rb"_SM_", data):
        i = m.start()
        if i + 0x1F > len(data):
            continue
        entry_len = data[i + 5]
        table_len = struct.unpack_from("<H", data, i + 0x16)[0]
        table_addr = struct.unpack_from("<I", data, i + 0x18)[0]
        yield i, table_addr, table_len
        if entry_len >= 0x1F:
            yield i, i + entry_len, table_len
    for m in re.finditer(rb"_SM3_", data):
        i = m.start()
        if i + 0x18 > len(data):
            continue
        entry_len = data[i + 6]
        table_len = struct.unpack_from("<I", data, i + 0x0C)[0]
        table_addr = struct.unpack_from("<Q", data, i + 0x10)[0] & 0xFFFFFFFF
        yield i, table_addr, table_len
        if entry_len >= 0x18:
            yield i, i + entry_len, table_len


def find_table(data: bytes) -> Optional[tuple[int, int, int]]:
    """(anchor_offset, table_start, table_length) of the SMBIOS table, or None.

    anchor_offset is the entry point's offset, or the table start when found by scanning.
    """
    for anchor, start, length in _entry_candidates(data):
        if length <= 0 or start <= 0 or start + length > len(data):
            continue
        end = _validate(data, start, start + length, ENTRY_MIN_STRUCTURES)
        if end is not None:
            return anchor, start, end - start

    for m in re.finditer(rb"(?=\x00[\x12-\x40])", data):
        start = m.start()
        end = _validate(data, start, len(data), SCAN_MIN_STRUCTURES)
        if end is not None:
            return start, start, end - start
    return None
