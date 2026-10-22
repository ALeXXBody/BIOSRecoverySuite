"""AMI NVRAM variable records (NVAR) and the machine identity they carry.

Record layout (as used by uefi-firmware-parser, and matching AMI dumps):

  0x00  'NVAR'
  0x04  TotalSize    u16, bytes of the whole record
  0x06  Next         24-bit offset of the next record (UEFITool NVAR_ENTRY_HEADER)
  0x09  Attributes   u8   bit 0x80 = valid, 0x08 = data-only, 0x04 = GUID present,
                          0x02 = ASCII name
  0x0A  (GUID, 16 bytes, when attribute 0x04 is set; otherwise one byte of padding)
        Name         NUL-terminated (ASCII, or UTF-16LE when 0x02 is clear); absent when
                     the data-only attribute 0x08 is set
        Data         the rest of the record

Identity carry-over copies the records that hold the machine's own data (MFG0, _DMI)
from an old dump into a new image. It does that only when every identity record of the
old dump has a counterpart of exactly the same size in the new image, and when the
board model in MFG0 matches. Otherwise nothing is written.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass
from typing import Optional

NVAR = b"NVAR"
ATTR_GUID = 0x04
ATTR_ASCII_NAME = 0x02
ATTR_VALID = 0x80
HEADER_SIZE = 0x0A
MIN_TOTAL = 0x0B + 2

ATTR_DATA_ONLY = 0x08
IDENTITY_NAMES = ("MFG0", "_DMI")
_MODEL_TOKEN = re.compile(rb"(?<![A-Za-z0-9])[A-Z]{1,4}[0-9]{2,4}[A-Z]{1,4}(?![A-Za-z0-9])")


@dataclass(frozen=True)
class NvarRecord:
    offset: int
    total: int
    name: Optional[str]
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
    if attrs & ATTR_DATA_ONLY:
        return NvarRecord(pos, total, None, attrs, bytes(rec[off:]))
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


def _all_identity_records(data: bytes) -> list[NvarRecord]:
    """Non-blank identity records whether or not they are valid."""
    return [r for r in iter_records(data) if _non_blank_identity(r)]


def is_valid(rec: NvarRecord) -> bool:
    """A record superseded by a later write has its valid bit cleared."""
    return bool(rec.attributes & ATTR_VALID)


def _non_blank_identity(rec: NvarRecord) -> bool:
    return rec.name in IDENTITY_NAMES and bool(rec.data) and set(rec.data) != {0xFF}


def identity_copies(data: bytes) -> dict[str, list[NvarRecord]]:
    """Valid, non-blank copies of each identity variable, in file order."""
    out: dict[str, list[NvarRecord]] = {}
    for rec in iter_records(data):
        if _non_blank_identity(rec) and is_valid(rec):
            out.setdefault(rec.name, []).append(rec)
    return out


def model_tokens(mfg0: bytes) -> frozenset:
    """Board model identifiers in an MFG0 payload, e.g. X510UA or TUF516PE."""
    return frozenset(m.group().decode("ascii") for m in _MODEL_TOKEN.finditer(mfg0))


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


def carry_identity(old: bytes, new: bytearray, force: bool = False) -> CarryReport:
    """Copy the identity variables from old into new, all or nothing.

    The live old copy (the last valid one) is written over every valid copy of the same
    name in the new image, so the firmware cannot read a stale copy. Superseded copies of
    the same size get the old data too, with their header left as it is. Refused when a
    name is missing in the new image, any valid copy there has a different size, or the
    MFG0 board model does not match (unless force is set). The new image is changed only
    on success.
    """
    report = CarryReport()
    old_copies = identity_copies(old)
    new_copies = identity_copies(bytes(new))

    if not old_copies:
        report.refused = "no identity variables (MFG0, _DMI) with data in the old dump"
        return report
    if not force:
        old_mfg0 = old_copies.get("MFG0")
        new_mfg0 = new_copies.get("MFG0")
        if not old_mfg0 or not new_mfg0:
            report.refused = "MFG0 is missing in one image, so the board model cannot be checked"
            return report
        if model_tokens(old_mfg0[-1].data) != model_tokens(new_mfg0[-1].data):
            report.refused = (
                "MFG0 board model differs between the old dump and the new image "
                "(the identity belongs to another board); nothing written"
            )
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
        superseded = [
            r
            for r in _all_identity_records(bytes(new))
            if r.name == name and not is_valid(r) and len(r.data) == len(src.data)
        ]
        plan[name] = (src, targets, superseded)

    for name, (src, targets, superseded) in plan.items():
        payload = bytes(old[src.offset : src.end])
        for t in targets:
            new[t.offset : t.end] = payload
        for r in superseded:
            new[r.end - len(r.data) : r.end] = src.data
        report.copied.append(name)
        report.messages.append(
            f"{name}: {src.total:#x} bytes written to {len(targets)} copy/copies in the new image"
            + (f", {len(superseded)} superseded data block(s) updated" if superseded else "")
        )

    after = identity_copies(bytes(new))
    fresh = _all_identity_records(bytes(new))
    for name, (src, _targets, superseded) in plan.items():
        payload = bytes(old[src.offset : src.end])
        if any(bytes(new[t.offset : t.end]) != payload for t in after.get(name, [])):
            raise RuntimeError(f"{name} did not verify after the copy")
        for r in superseded:
            current = next(x for x in fresh if x.offset == r.offset)
            if current.data != src.data:
                raise RuntimeError(f"{name} superseded copy did not verify after the copy")

    report.success = True
    return report
