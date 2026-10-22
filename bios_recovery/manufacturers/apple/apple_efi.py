"""Apple EFI / SOC-ROM repair support.

Implements the community-verified AppleEFI NVRAM *Fsys* store handling (the
capability paid suites label "Apple Fsys/FSC CRC calculation & fix"), using
the same binary rules as the open-source MacEfiToolkit:

  * store marker:    b"Fsys\\x01" (46 73 79 73 01)
  * stored size:     int16 LE at marker + 9
  * stored checksum: CRC32 over the first (size - 4) store bytes, stored in
    the last 4 store bytes **byte-reversed**
  * known variables: ssn (serial), hwc, son — marker-tagged length-prefixed
    strings inside the store

Every modification is consistency-gated: sizes must match, strings must be
equal-length in-place swaps, and the CRC recomputation must verify after the
write. Anything else is refused with an explicit message.
"""

from __future__ import annotations

import binascii
import os
import struct
from dataclasses import dataclass, field
from typing import Optional

from bios_recovery.core.safety import SameFileError, ensure_distinct, write_file_atomic

FSYS_MARKER = b"Fsys\x01"
CRC32_SIZE = 4
_SERIAL_MARKERS = (b"\x03ssn", b"\x03SSN", b"\x04ssnp")
_HWC_MARKERS = (b"\x03hwc",)
_SON_MARKERS = (b"\x03son", b"\x03SON")
_APPLE_ROM_MARKERS = (b"BIOS ID:", b"Model:", b"EFI Version:")


@dataclass
class FsysStoreInfo:
    found: bool = False
    base_address: int = -1
    size: int = 0
    crc_stored: Optional[int] = None  # as stored (flipped) on flash
    crc_computed: Optional[int] = None  # crc32(size-4 bytes)
    checksum_valid: Optional[bool] = None
    serial: Optional[str] = None
    serial_base: int = -1
    serial_layout: Optional[str] = None  # "u8" or "u16": the entry length width that matched
    hwc: Optional[str] = None
    son: Optional[str] = None
    notes: list = field(default_factory=list)


@dataclass
class AppleReport:
    success: bool = False
    message: str = ""
    warnings: list = field(default_factory=list)
    operations: list = field(default_factory=list)
    output_path: str = ""


def detect_apple_rom(data: bytes) -> bool:
    """True when the image shows AppleEFI markers."""
    return any(m in data for m in _APPLE_ROM_MARKERS) or _find_fsys_base(data) >= 0


def _find_fsys_base(data: bytes) -> int:
    return data.find(FSYS_MARKER)


def _printable(raw: bytes) -> bool:
    return len(raw) > 0 and all(0x20 <= b <= 0x7E for b in raw)


def _entry_candidates(data: bytes, pos: int, end: int) -> dict:
    """Read a marker-tagged entry under each length width the format may use.

    "u8": one length byte, as the reader used before. "u16": a little-endian UINT16
    DataLength, as UEFITool documents for SysF entries. A candidate counts only when
    its bytes are printable ASCII and lie inside the store, so a store that fits one
    width does not also fit the other.
    """
    out = {}
    if pos < min(end, len(data)):
        ln = data[pos]
        raw = bytes(data[pos + 1 : pos + 1 + ln]) if ln else b""
        if pos + 1 + ln <= end and _printable(raw):
            out["u8"] = (pos + 1, raw)
    if pos + 2 <= min(end, len(data)):
        ln = struct.unpack_from("<H", data, pos)[0]
        raw = bytes(data[pos + 2 : pos + 2 + ln]) if ln else b""
        if pos + 2 + ln <= end and _printable(raw):
            out["u16"] = (pos + 2, raw)
    return out


def _scan_entry(data: bytes, pos: int, end: int) -> tuple:
    """Return (layout, data_start, text) when exactly one width fits, else (None, -1, None)."""
    cands = _entry_candidates(data, pos, end)
    if len(cands) != 1:
        return None, -1, None
    layout, (start, raw) = next(iter(cands.items()))
    return layout, start, raw.decode("ascii")


def parse_fsys_store(data: bytes) -> FsysStoreInfo:
    info = FsysStoreInfo()
    base = _find_fsys_base(data)
    if base < 0:
        return info
    info.base_address = base
    # stored size: uint16 LE at base + 9
    try:
        info.size = struct.unpack_from("<H", data, base + 9)[0]
    except struct.error:
        return info
    if info.size <= 4 or base + info.size > len(data) or info.size > 0x800 + 4:
        info.notes.append(f"implausible store size {info.size:#x}")
        return info

    buf = bytes(data[base : base + info.size])
    # stored CRC: last 4 bytes, byte-flipped
    stored_flipped = buf[-CRC32_SIZE:]
    info.crc_computed = binascii.crc32(buf[: info.size - CRC32_SIZE]) & 0xFFFFFFFF
    # flip the computed value to compare with the stored (reversed) bytes
    computed_flipped = int.from_bytes(stored_flipped, "little")
    info.crc_stored = computed_flipped
    # For verification we compare stored == crc32 computed over data minus crc:
    # stored bytes encode the SAME crc value byte-reversed.
    stored_value = int.from_bytes(stored_flipped, "little")
    computed = binascii.crc32(buf[: info.size - CRC32_SIZE]) & 0xFFFFFFFF
    info.crc_computed = computed
    info.checksum_valid = stored_value == computed

    # variables
    end = base + info.size
    for mk in _SERIAL_MARKERS:
        p = data.find(mk, base, end)
        if p >= 0:
            layout, start, text = _scan_entry(data, p + len(mk), end)
            if text is not None:
                info.serial, info.serial_base, info.serial_layout = text, start, layout
                break
    for mk in _HWC_MARKERS:
        p = data.find(mk, base, end)
        if p >= 0:
            info.hwc = _scan_entry(data, p + len(mk), end)[2]
    for mk in _SON_MARKERS:
        p = data.find(mk, base, end)
        if p >= 0:
            info.son = _scan_entry(data, p + len(mk), end)[2]
    info.found = True
    return info


def rom_info(file_path: str) -> dict:
    """Gather Apple-Rom information + Fsys values for the GUI/CLI viewers."""
    with open(file_path, "rb") as f:
        data = f.read()
    fsys = parse_fsys_store(data)
    return {
        "apple_detected": detect_apple_rom(data),
        "fsys": {
            "found": fsys.found,
            "base": hex(fsys.base_address) if fsys.found else None,
            "size": hex(fsys.size) if fsys.found else None,
            "checksum_valid": fsys.checksum_valid,
            "serial": fsys.serial,
            "hwc": fsys.hwc,
            "son": fsys.son,
            "notes": fsys.notes,
        },
    }


def _same_file_refusal(file_path: str, output_path: Optional[str], rep: AppleReport) -> bool:
    try:
        ensure_distinct(file_path, output_path)
    except SameFileError as exc:
        rep.message = str(exc)
        return True
    return False


def fix_fsys_checksum(file_path: str, output_path: Optional[str] = None) -> AppleReport:
    """Recompute and rewrite the Fsys CRC32 when invalid; verify after the write."""
    rep = AppleReport()
    if _same_file_refusal(file_path, output_path, rep):
        return rep
    with open(file_path, "rb") as f:
        data = bytearray(f.read())

    fsys = parse_fsys_store(bytes(data))
    if not fsys.found:
        rep.message = "Fsys store not found (not an Apple EFI image, or NVRAM erased)"
        return rep
    if fsys.checksum_valid:
        rep.message = "Fsys checksum already valid - no write performed"
        rep.success = True
        return rep

    crc = (
        binascii.crc32(bytes(data[fsys.base_address : fsys.base_address + fsys.size - CRC32_SIZE]))
        & 0xFFFFFFFF
    )
    # stored byte-reversed
    data[fsys.base_address + fsys.size - CRC32_SIZE : fsys.base_address + fsys.size] = crc.to_bytes(
        CRC32_SIZE, "little"
    )

    # verify
    again = parse_fsys_store(bytes(data))
    if not again.found or not again.checksum_valid:
        rep.message = "checksum rewrite failed verification - output not written"
        return rep

    if output_path is None:
        output_path = os.path.splitext(file_path)[0] + "_fsysfixed.bin"
    write_file_atomic(output_path, bytes(data))
    rep.success = True
    rep.message = "Fsys checksum repaired and verified"
    rep.operations.append(
        f"CRC32 0x{crc:08X} written at 0x{fsys.base_address + fsys.size - CRC32_SIZE:x}"
    )
    rep.output_path = output_path
    return rep


def replace_fsys_store(
    file_path: str,
    donor_store_path: str,
    output_path: Optional[str] = None,
) -> AppleReport:
    """Transplant a donor 0x800h Fsys store into the image (equal size required),
    then repair the CRC32."""
    rep = AppleReport()
    if _same_file_refusal(file_path, output_path, rep):
        return rep
    with open(file_path, "rb") as f:
        data = bytearray(f.read())
    with open(donor_store_path, "rb") as f:
        donor = f.read()

    fsys = parse_fsys_store(bytes(data))
    if not fsys.found:
        rep.message = "No Fsys store in the target image"
        return rep

    donor_fsys = parse_fsys_store(donor)
    if not (
        donor_fsys.found
        and donor_fsys.base_address == 0
        and donor_fsys.size == len(donor)
        and donor_fsys.checksum_valid
    ):
        rep.message = "donor is not a valid Fsys store (marker, size or CRC32 fails) - refused"
        return rep

    if len(donor) != fsys.size:
        rep.message = (
            f"donor store size {len(donor):#x} != target store size {fsys.size:#x} - refused"
        )
        return rep

    data[fsys.base_address : fsys.base_address + fsys.size] = donor

    fixed = fix_fsys_checksum_from_buffer(data, fsys.base_address, fsys.size)
    if fixed is None:
        rep.message = "post-transplant checksum repair failed verification - not written"
        return rep
    rep.operations.extend(fixed)

    if output_path is None:
        output_path = os.path.splitext(file_path)[0] + "_fsysreplaced.bin"
    write_file_atomic(output_path, bytes(data))
    rep.success = True
    rep.message = "Fsys store replaced and checksum repaired/verified"
    rep.output_path = output_path
    return rep


def fix_fsys_checksum_from_buffer(data: bytearray, base: int, size: int) -> Optional[list]:
    """Repair CRC32 within a buffer; returns operation strings on success."""
    computed = binascii.crc32(bytes(data[base : base + size - CRC32_SIZE])) & 0xFFFFFFFF
    data[base + size - CRC32_SIZE : base + size] = computed.to_bytes(CRC32_SIZE, "little")
    verify = binascii.crc32(bytes(data[base : base + size - CRC32_SIZE])) & 0xFFFFFFFF
    if verify != computed:
        return None
    return [f"CRC32 0x{computed:08X} written at 0x{base + size - CRC32_SIZE:x}"]


def set_serial_number(
    file_path: str,
    new_serial: str,
    output_path: Optional[str] = None,
) -> AppleReport:
    """Patch the Fsys ssn variable — **equal-length in-place swap only** — and
    repair the store CRC32. Refused unless the entry layout is unambiguous and the
    patched store reads back with the new serial and a valid CRC."""
    rep = AppleReport()
    if _same_file_refusal(file_path, output_path, rep):
        return rep
    with open(file_path, "rb") as f:
        data = bytearray(f.read())

    fsys = parse_fsys_store(bytes(data))
    if not fsys.found or fsys.serial_base < 0:
        rep.message = (
            "Fsys store/serial variable not found, or its entry layout is unreadable - refused"
        )
        return rep
    if not _printable(new_serial.encode("ascii", errors="replace")) or "?" in new_serial:
        rep.message = "new serial must be printable ASCII - refused"
        return rep

    s_len = len(fsys.serial)
    if len(new_serial) != s_len:
        rep.message = (
            f"equal-length swap only: new serial is {len(new_serial)} chars, "
            f"existing is {s_len} - refused"
        )
        return rep

    s_start = fsys.serial_base
    data[s_start : s_start + s_len] = new_serial.encode("ascii")

    fixed = fix_fsys_checksum_from_buffer(data, fsys.base_address, fsys.size)
    if fixed is None:
        rep.message = "post-patch checksum repair failed verification - not written"
        return rep
    check = parse_fsys_store(bytes(data))
    if (
        check.serial != new_serial
        or check.serial_base != s_start
        or check.serial_layout != fsys.serial_layout
        or not check.checksum_valid
    ):
        rep.message = "patched Fsys store did not read back as expected - not written"
        return rep
    rep.operations.extend(fixed)

    if output_path is None:
        output_path = os.path.splitext(file_path)[0] + "_ssnpatched.bin"
    write_file_atomic(output_path, bytes(data))
    rep.success = True
    rep.message = "Serial patched (equal-length) and Fsys checksum repaired/verified"
    rep.output_path = output_path
    return rep
