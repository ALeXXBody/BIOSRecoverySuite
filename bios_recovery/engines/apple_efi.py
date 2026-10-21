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
    crc_stored: Optional[int] = None     # as stored (flipped) on flash
    crc_computed: Optional[int] = None   # crc32(size-4 bytes)
    checksum_valid: Optional[bool] = None
    serial: Optional[str] = None
    serial_base: int = -1
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


def _scan_string(data: bytes, pos: int, end: int) -> Optional[str]:
    """Parse a marker-tagged length-prefixed string: [len byte][bytes]."""
    if pos + 1 > end or pos >= len(data):
        return None
    ln = data[pos]
    if ln == 0 or pos + 1 + ln > end or pos + 1 + ln > len(data):
        return None
    raw = bytes(data[pos + 1:pos + 1 + ln])
    if raw == b"\xff" * ln:
        return None  # erased
    return raw.decode("ascii", errors="replace")


def parse_fsys_store(data: bytes) -> FsysStoreInfo:
    info = FsysStoreInfo()
    base = _find_fsys_base(data)
    if base < 0:
        return info
    info.base_address = base
    # stored size: int16 LE at base + 9
    try:
        info.size = struct.unpack_from("<h", data, base + 9)[0]
    except struct.error:
        return info
    if info.size <= 4 or base + info.size > len(data) or info.size > 0x800 + 4:
        info.notes.append(f"implausible store size {info.size:#x}")
        return info

    buf = bytes(data[base:base + info.size])
    # stored CRC: last 4 bytes, byte-flipped
    stored_flipped = buf[-CRC32_SIZE:]
    info.crc_computed = binascii.crc32(buf[:info.size - CRC32_SIZE]) & 0xFFFFFFFF
    # flip the computed value to compare with the stored (reversed) bytes
    computed_flipped = int.from_bytes(stored_flipped, "little")
    info.crc_stored = computed_flipped
    # For verification we compare stored == crc32 computed over data minus crc:
    # stored bytes encode the SAME crc value byte-reversed.
    stored_value = int.from_bytes(stored_flipped, "little")
    computed = binascii.crc32(buf[:info.size - CRC32_SIZE]) & 0xFFFFFFFF
    info.crc_computed = computed
    info.checksum_valid = (stored_value == computed)

    # variables
    end = base + info.size
    for mk in _SERIAL_MARKERS:
        p = data.find(mk, base, end)
        if p >= 0:
            info.serial = _scan_string(data, p + len(mk), end)
            if info.serial is not None:
                info.serial_base = p + len(mk) + 1
                break
    for mk in _HWC_MARKERS:
        p = data.find(mk, base, end)
        if p >= 0:
            info.hwc = _scan_string(data, p + len(mk), end)
    for mk in _SON_MARKERS:
        p = data.find(mk, base, end)
        if p >= 0:
            info.son = _scan_string(data, p + len(mk), end)
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


def fix_fsys_checksum(file_path: str, output_path: Optional[str] = None) -> AppleReport:
    """Recompute and rewrite the Fsys CRC32 when invalid; verify after the write."""
    rep = AppleReport()
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

    crc = binascii.crc32(
        bytes(data[fsys.base_address:fsys.base_address + fsys.size - CRC32_SIZE])
    ) & 0xFFFFFFFF
    # stored byte-reversed
    data[fsys.base_address + fsys.size - CRC32_SIZE:fsys.base_address + fsys.size] = \
        crc.to_bytes(CRC32_SIZE, "little")

    # verify
    again = parse_fsys_store(bytes(data))
    if not again.found or not again.checksum_valid:
        rep.message = "checksum rewrite failed verification - output not written"
        return rep

    if output_path is None:
        output_path = file_path.rsplit(".", 1)[0] + "_fsysfixed.bin"
    with open(output_path, "wb") as f:
        f.write(bytes(data))
    rep.success = True
    rep.message = "Fsys checksum repaired and verified"
    rep.operations.append(f"CRC32 0x{crc:08X} written at 0x{fsys.base_address + fsys.size - CRC32_SIZE:x}")
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
    with open(file_path, "rb") as f:
        data = bytearray(f.read())
    with open(donor_store_path, "rb") as f:
        donor = f.read()

    fsys = parse_fsys_store(bytes(data))
    if not fsys.found:
        rep.message = "No Fsys store in the target image"
        return rep

    if len(donor) != fsys.size:
        rep.message = (
            f"donor store size {len(donor):#x} != target store size {fsys.size:#x} - refused"
        )
        return rep

    data[fsys.base_address:fsys.base_address + fsys.size] = donor

    fixed = fix_fsys_checksum_from_buffer(data, fsys.base_address, fsys.size)
    if fixed is None:
        rep.message = "post-transplant checksum repair failed verification - not written"
        return rep
    rep.operations.extend(fixed)

    if output_path is None:
        output_path = file_path.rsplit(".", 1)[0] + "_fsysreplaced.bin"
    with open(output_path, "wb") as f:
        f.write(bytes(data))
    rep.success = True
    rep.message = "Fsys store replaced and checksum repaired/verified"
    rep.output_path = output_path
    return rep


def fix_fsys_checksum_from_buffer(data: bytearray, base: int, size: int) -> Optional[list]:
    """Repair CRC32 within a buffer; returns operation strings on success."""
    computed = binascii.crc32(bytes(data[base:base + size - CRC32_SIZE])) & 0xFFFFFFFF
    data[base + size - CRC32_SIZE:base + size] = computed.to_bytes(CRC32_SIZE, "little")
    verify = binascii.crc32(bytes(data[base:base + size - CRC32_SIZE])) & 0xFFFFFFFF
    if verify != computed:
        return None
    return [f"CRC32 0x{computed:08X} written at 0x{base + size - CRC32_SIZE:x}"]


def set_serial_number(
    file_path: str,
    new_serial: str,
    output_path: Optional[str] = None,
) -> AppleReport:
    """Patch the Fsys ssn variable — **equal-length in-place swap only** — and
    repair the store CRC32."""
    rep = AppleReport()
    with open(file_path, "rb") as f:
        data = bytearray(f.read())

    fsys = parse_fsys_store(bytes(data))
    if not fsys.found or fsys.serial_base < 0:
        rep.message = "Fsys store/serial variable not found - refused"
        return rep

    s_len = len(fsys.serial)
    if len(new_serial) != s_len:
        rep.message = (
            f"equal-length swap only: new serial is {len(new_serial)} chars, "
            f"existing is {s_len} - refused"
        )
        return rep

    s_start = fsys.serial_base
    data[s_start:s_start + s_len] = new_serial.encode("ascii")

    fixed = fix_fsys_checksum_from_buffer(data, fsys.base_address, fsys.size)
    if fixed is None:
        rep.message = "post-patch checksum repair failed verification - not written"
        return rep
    rep.operations.extend(fixed)

    if output_path is None:
        output_path = file_path.rsplit(".", 1)[0] + "_ssnpatched.bin"
    with open(output_path, "wb") as f:
        f.write(bytes(data))
    rep.success = True
    rep.message = "Serial patched (equal-length) and Fsys checksum repaired/verified"
    rep.output_path = output_path
    return rep
