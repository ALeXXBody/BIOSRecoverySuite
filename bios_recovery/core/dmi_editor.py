"""Structured SN/MAC/UUID editor for flashed dumps.

Edits are limited to fixed-size, spec-defined fields so that no layout
adjustment — and therefore no unjustified byte movement — is required:

  * SMBIOS Type 1 UUID (16 bytes at structure offset 0x08, per spec)
  * SMBIOS Type 1 / Type 2 serial strings — **equal-length in-place swaps only**
    (string-pool indices and all downstream structures stay untouched)
  * LAN MAC address — inside an Intel flash descriptor's GbE region (6 bytes
    at the region base), written only when the descriptor layout validates

Anything that does not fit those constraints is refused with an explicit
message instead of being force-patched.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Optional

from bios_recovery.core.bios_analyzer import decode_flreg


def _locate_smbios(data: bytes):
    """(anchor, table_start, table_len) of the SMBIOS table, or None. See core.smbios."""
    from bios_recovery.core.smbios import find_table

    return find_table(data)


@dataclass
class DMIEditReport:
    success: bool = False
    message: str = ""
    operations: list = field(default_factory=list)
    warnings: list = field(default_factory=list)
    output_path: str = ""


def _smbios_structures(data: bytes, table_addr: int, table_len: int):
    """Walk a SMBIOS structure table.

    Yields (abs_off, type_id, struct_len, strings) where strings is a list of
    absolute (offset, length) pairs into the image — the string-pool entries
    referenced by that structure.

    SMBIOS layout rules (spec):
      structure = fixed part (length = struct_len) followed by a string set,
      in which every referenced string is printable ASCII terminated by one
      NUL, and the whole set is terminated by one *extra* NUL (i.e. the
      terminator is two consecutive NUL bytes when at least one string
      exists, or two NULs immediately when none does).
    """
    pos = table_addr
    end = table_addr + table_len
    while pos + 4 <= end:
        stype = data[pos]
        slen = data[pos + 1]
        if slen < 4 or pos + slen > end:
            break
        strings = []
        scan = pos + slen
        consecutive_nuls = 0
        print_pool_ended = False
        while scan < end and consecutive_nuls < 2 and not print_pool_ended:
            b = data[scan]
            if b == 0x00:
                consecutive_nuls += 1
                scan += 1
                continue
            if b < 0x20 or b > 0x7E:
                # non-printable: not a valid SMBIOS string -> string set ended
                print_pool_ended = True
                break
            consecutive_nuls = 0
            start = scan
            while scan < end and 0x20 <= data[scan] <= 0x7E:
                scan += 1
            strings.append((start, scan - start))
            scan += 1  # consume this string's terminating NUL
        # `scan` now points past the string set (terminators or first non-printable)
        yield (pos, stype, slen, strings)
        pos = scan


class DMIEditor:
    """Applies fixed-size identity edits to a flashed BIOS image."""

    def info(self, file_path: str) -> dict:
        """Report current serial/UUID/MAC values."""
        with open(file_path, "rb") as f:
            data = f.read()
        eps = _locate_smbios(data)
        if not eps:
            return {"found": False, "message": "no valid SMBIOS table found"}

        _, table_addr, table_len = eps
        out = {
            "found": True,
            "eps_offset": eps[0],
            "table_addr": table_addr,
            "table_len": table_len,
            "serials": {},
            "uuid": None,
            "mac": self._read_mac(data),
        }
        for off, stype, slen, strings in _smbios_structures(data, table_addr, table_len):
            if stype == 1 and len(data) >= off + 0x1B:
                serial_idx = data[off + 0x07]  # Type 1 SerialNumber per spec
                out["uuid"] = data[off + 0x08 : off + 0x18].hex()
                if 1 <= serial_idx <= len(strings):
                    s = strings[serial_idx - 1]
                    out["serials"]["system"] = data[s[0] : s[0] + s[1]].decode(
                        "ascii", errors="replace"
                    )
            if stype == 2 and len(data) >= off + 0x08:
                serial_idx = data[off + 0x07]
                if 1 <= serial_idx <= len(strings):
                    s = strings[serial_idx - 1]
                    out["serials"]["baseboard"] = data[s[0] : s[0] + s[1]].decode(
                        "ascii", errors="replace"
                    )
        return out

    @staticmethod
    def _find_fd(data: bytes):
        """Descriptor offset (0 or 0x10) or None."""
        if data[:4] == b"\x5a\xa5\xf0\x0f":
            return 0
        if len(data) > 0x14 and data[0x10:0x14] == b"\x5a\xa5\xf0\x0f":
            return 0x10
        return None

    def _read_mac(self, data: bytes):
        """Read the LAN MAC only when a validated Intel descriptor GbE region exists."""
        fd = self._find_fd(data)
        if fd is None:
            return None  # AMD-layout boards: no descriptor/GbE region
        try:
            flreg3 = struct.unpack_from("<I", data, fd + 0x4C)[0]
        except struct.error:
            return None
        gb_base, gb_limit = decode_flreg(flreg3)
        if gb_base == 0 or gb_base > gb_limit or gb_limit > len(data):
            return None
        mac = data[gb_base : gb_base + 6]
        if mac == b"\xff" * 6 or mac == b"\x00" * 6:
            return None
        return ":".join(f"{b:02X}" for b in mac)

    def set_identity(
        self,
        file_path: str,
        output_path: Optional[str] = None,
        serial: Optional[str] = None,
        uuid: Optional[str] = None,
        mac: Optional[str] = None,
    ) -> DMIEditReport:
        """Apply identity edits. Refuses unequal-length serial swaps."""
        report = DMIEditReport()
        with open(file_path, "rb") as f:
            data = bytearray(f.read())
        eps = _locate_smbios(bytes(data))
        if not eps:
            report.message = "no valid SMBIOS table found - edit refused"
            return report
        _, table_addr, table_len = eps
        structures = list(_smbios_structures(bytes(data), table_addr, table_len))

        if serial is not None:
            new = serial.encode("ascii")
            targets = []
            for off, stype, slen, strings in structures:
                if stype == 1 and len(data) >= off + 0x1B:
                    idx = data[off + 0x07]  # Type 1 SerialNumber per spec
                    if 1 <= idx <= len(strings):
                        targets.append(strings[idx - 1])
                if stype == 2 and len(data) >= off + 0x08:
                    idx = data[off + 0x07]
                    if 1 <= idx <= len(strings):
                        targets.append(strings[idx - 1])
            if not targets:
                report.warnings.append("no serial string referenced by Type 1/2 - skipped")
            for s_off, s_len in targets:
                if len(new) != s_len:
                    report.warnings.append(
                        f"serial swap refused @0x{s_off:x}: length differs "
                        f"({len(new)} != {s_len}); equal-length in-place swaps only"
                    )
                    continue
                data[s_off : s_off + s_len] = new
                report.operations.append(
                    f"serial replaced @0x{s_off:x} (equal-length swap, {s_len} bytes)"
                )

        if uuid is not None:
            hexs = uuid.replace("-", "")
            if len(hexs) != 32:
                report.message = "uuid must be 32 hex chars (8-4-4-4-12) - refused"
                return report
            done = 0
            for off, stype, slen, _ in structures:
                if stype == 1:
                    data[off + 0x08 : off + 0x18] = bytes.fromhex(hexs)
                    done += 1
                    report.operations.append(f"Type-1 UUID written @0x{off + 8:x}")
            if not done:
                report.warnings.append("no SMBIOS Type 1 structure - uuid skipped")

        if mac is not None:
            fd = self._find_fd(bytes(data))
            if fd is None:
                report.warnings.append(
                    "board has no Intel descriptor (AMD layout): NIC keeps its MAC "
                    "in its own storage - MAC edit refused"
                )
            else:
                raw = mac.replace(":", "").replace("-", "")
                flreg3 = struct.unpack_from("<I", data, fd + 0x4C)[0]
                gb_base, gb_limit = decode_flreg(flreg3)
                if not (gb_base and gb_base <= gb_limit and gb_limit <= len(data)):
                    report.warnings.append("descriptor has no valid GbE region - MAC skipped")
                else:
                    data[gb_base : gb_base + 6] = bytes.fromhex(raw)
                    report.operations.append(f"MAC written to GbE region @0x{gb_base:x}")

        if not report.operations and not report.warnings:
            report.message = "nothing to edit"
            return report

        if output_path is None:
            output_path = file_path.rsplit(".", 1)[0] + "_edited.bin"
        with open(output_path, "wb") as f:
            f.write(bytes(data))
        report.success = True
        report.output_path = output_path
        return report
