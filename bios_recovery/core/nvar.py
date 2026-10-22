"""AMI NVRAM variable records (NVAR) and the machine identity they carry.

Record layout (as used by uefi-firmware-parser, and matching AMI dumps):

  0x00  'NVAR'
  0x04  TotalSize    u16, bytes of the whole record
  0x06  Reserved     3 bytes
  0x09  Attributes   u8   bit 0x04 = GUID present, 0x08 = data-only, 0x02 = ASCII name
  0x0A  (GUID, 16 bytes, when attribute 0x04 is set; otherwise one byte of padding)
        Name         NUL-terminated (ASCII, or UTF-16LE when 0x02 is clear)
        Data         the rest of the record

Identity carry-over copies the records that hold the machine's own data (MFG0, _DMI)
from an old dump into a new image. It does that only when every identity record of the
old dump has a counterpart of exactly the same size in the new image. Otherwise nothing
is written.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional

NVAR = b"NVAR"
ATTR_GUID = 0x04
ATTR_ASCII_NAME = 0x02
ATTR_VALID = 0x80
HEADER_SIZE = 0x0A
MIN_TOTAL = 0x0B + 2

IDENTITY_NAMES = ("MFG0", "_DMI")


@dataclass(frozen=True)
class NvarRecord:
    offset: int
    total: int
    name: str
    attributes: int
    data: bytes

    @property
    def end(self) -> int:
        return self.offset + self.total


def _parse_at(data: bytes, pos: int) -> Optional[NvarRecord]:
    if data[pos : pos + 4] != NVAR or pos + MIN_TOTAL > len(data):
        return None
    total = struct.unpack_from("<H", data, pos + 4)[0]
    if total < MIN_TOTAL or pos + total > len(data):
        return None
    attrs = data[pos + 9]
    rec = data[pos : pos + total]
    off = HEADER_SIZE + (16 if attrs & ATTR_GUID else 1)
    if off >= total:
        return None
    if attrs & ATTR_ASCII_NAME:
        end = rec.find(b"\x00", off)
        if end < 0:
            return None
        raw = rec[off:end]
        if not raw or not all(0x20 <= c < 0x7F for c in raw):
            return None
        name = raw.decode("ascii")
        data_start = end + 1
    else:
        end = off
        while end + 1 < total and not (rec[end] == 0 and rec[end + 1] == 0):
            end += 2
        raw = rec[off:end]
        try:
            name = raw.decode("utf-16-le")
        except UnicodeDecodeError:
            return None
        if not name or not name.isprintable():
            return None
        data_start = end + 2
    return NvarRecord(pos, total, name, attrs, bytes(rec[data_start:]))


def iter_records(data: bytes) -> list[NvarRecord]:
    """Every well-formed NVAR record in the image, in file order."""
    out: list[NvarRecord] = []
    pos = data.find(NVAR)
    while pos >= 0:
        rec = _parse_at(data, pos)
        if rec is not None:
            out.append(rec)
            pos = data.find(NVAR, rec.end)
        else:
            pos = data.find(NVAR, pos + 1)
    return out


def is_valid(rec: NvarRecord) -> bool:
    """A record superseded by a later write has its valid bit cleared."""
    return bool(rec.attributes & ATTR_VALID)


def identity_copies(data: bytes) -> dict[str, list[NvarRecord]]:
    """Valid, non-blank copies of each identity variable, in file order."""
    out: dict[str, list[NvarRecord]] = {}
    for rec in iter_records(data):
        if rec.name in IDENTITY_NAMES and is_valid(rec) and rec.data and set(rec.data) != {0xFF}:
            out.setdefault(rec.name, []).append(rec)
    return out


@dataclass
class CarryReport:
    success: bool = False
    copied: list = None
    messages: list = None
    refused: str = ""

    def __post_init__(self):
        if self.copied is None:
            self.copied = []
        if self.messages is None:
            self.messages = []


def carry_identity(old: bytes, new: bytearray) -> CarryReport:
    """Copy the identity variables from old into new, all or nothing.

    The live old copy (the last valid one) is written over every valid copy of the same
    name in the new image, so the firmware cannot read a stale copy. Refused when a name
    is missing in the new image or any copy there has a different size. The new image is
    changed only on success.
    """
    report = CarryReport()
    old_copies = identity_copies(old)
    new_copies = identity_copies(bytes(new))

    if not old_copies:
        report.refused = "no identity variables (MFG0, _DMI) with data in the old dump"
        return report
    extra = sorted(set(new_copies) - set(old_copies))
    if extra:
        report.refused = (
            f"the new image has {', '.join(extra)} which the old dump lacks; keeping it would mix "
            "two identities, so nothing written"
        )
        return report
    plan = {}
    for name, copies in old_copies.items():
        src = copies[-1]
        targets = new_copies.get(name, [])
        if not targets:
            report.refused = f"{name} has no valid copy in the new image; nothing written"
            return report
        if any(t.total != src.total for t in targets):
            report.refused = (
                f"{name} is {src.total:#x} bytes in the old dump but differs in the new image; "
                "nothing written"
            )
            return report
        plan[name] = (src, targets)

    for name, (src, targets) in plan.items():
        payload = bytes(old[src.offset : src.end])
        for t in targets:
            new[t.offset : t.end] = payload
        report.copied.append(name)
        report.messages.append(
            f"{name}: {src.total:#x} bytes written to {len(targets)} copy/copies in the new image"
        )

    after = identity_copies(bytes(new))
    for name, (src, _targets) in plan.items():
        payload = bytes(old[src.offset : src.end])
        if any(bytes(new[t.offset : t.end]) != payload for t in after.get(name, [])):
            raise RuntimeError(f"{name} did not verify after the copy")

    report.success = True
    return report
