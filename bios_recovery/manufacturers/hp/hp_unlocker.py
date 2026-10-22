"""HP BIOS unlock engine - removes admin passwords from HP UEFI/BIOS dumps.

Ports the public HPUnlocker.py approach (schorschii's gist; same mechanism the
IndiaFix/badcaps "HP Unlocker" / "RC Unlocker" drag-drop tools use):

* Modern HP UEFI images: locate the UTF-16LE ``UserCred`` structure and reset
  its 100-byte credential block (0x00 with the 4 flag bytes at +26..+29 = 0xFF).
* Legacy HP BIOS images: find each ``$VSS`` variable named ``BiosUser`` and wipe
  its data with 0xFF. The entry is read with the EDK2 ``VARIABLE_HEADER`` layout
  (MdeModulePkg/Include/Guid/VariableFormat.h), and only its own ``DataSize`` bytes
  are touched.

Always flash back the original dump afterwards unless instructed otherwise.
"""

from __future__ import annotations

import struct

from bios_recovery.core.safety import SameFileError, ensure_distinct

_USER_CRED = b"U\x00s\x00e\x00r\x00C\x00r\x00e\x00d"
_VSS_HEADER_SIZE = 32
_VSS_START_ID = b"\xaa\x55"  # VARIABLE_DATA 0x55AA, little-endian
_VSS_KEY = b"B\x00i\x00o\x00s\x00U\x00s\x00e\x00r\x00\x00\x00"  # "BiosUser" + NUL, UCS-2


def _vss_entries(data: bytes | bytearray) -> list[tuple[int, int]]:
    """Validated ``BiosUser`` variables as (data_offset, data_size).

    The name must sit directly after a 32-byte VARIABLE_HEADER whose StartId is 0x55AA and
    whose NameSize equals the name's length including its NUL. With ALIGNMENT 1 (IA-32 and
    x64) the data follows the name with no padding. Entries that fail any check are skipped.
    """
    out: list[tuple[int, int]] = []
    pos = data.find(_VSS_KEY)
    while pos >= 0:
        hdr = pos - _VSS_HEADER_SIZE
        if hdr >= 0 and data[hdr : hdr + 2] == _VSS_START_ID and pos + len(_VSS_KEY) <= len(data):
            name_size, data_size = struct.unpack_from("<II", data, hdr + 8)
            data_start = pos + len(_VSS_KEY)
            if name_size == len(_VSS_KEY) and 0 < data_size <= len(data) - data_start:
                out.append((data_start, data_size))
        pos = data.find(_VSS_KEY, pos + 1)
    return out


class HPUnlocker:
    """Detects and clears HP BIOS password storage inside a firmware dump."""

    def analyze(self, image_path: str) -> dict:
        with open(image_path, "rb") as f:
            data = f.read()
        out = {
            "style": None,
            "usercred_offset": None,
            "vss_entries": 0,
            "vss_offsets": [],
        }
        cred = data.find(_USER_CRED)
        if cred >= 0:
            out["usercred_offset"] = cred
        entries = _vss_entries(data)
        out["vss_entries"] = len(entries)
        out["vss_offsets"] = [start for start, _ in entries]
        if out["vss_entries"]:
            out["style"] = "old"
        elif cred >= 0:
            out["style"] = "new"
        return out

    def unlock(self, image_path: str, output_path: str) -> dict:
        """Clear HP admin password storage. Returns a report dict."""
        report = {
            "success": False,
            "style": None,
            "cleared": 0,
            "output_path": "",
            "messages": [],
        }
        try:
            ensure_distinct(image_path, output_path)
        except SameFileError as exc:
            report["messages"].append(f"ERROR: {exc}")
            return report

        with open(image_path, "rb") as f:
            original = f.read()
        data = bytearray(original)

        # $VSS is checked first, as in the public reference; UserCred is the fallback.
        entries = _vss_entries(original)
        loc = data.find(_USER_CRED)
        if entries:
            report["style"] = "old"
            for start, size in entries:
                data[start : start + size] = b"\xff" * size
            report["cleared"] = len(entries)
            report["success"] = True
            report["messages"].append(f"Cleared {report['cleared']} $VSS/BiosUser entr(ies)")
        elif loc >= 0:
            report["style"] = "new"
            # credential block: 100 bytes after the structure header;
            # flag bytes 10..13 of the block are set to 0xFF, rest to 0x00
            for j in range(100):
                pos = loc + 16 + j
                if pos < len(data):
                    data[pos] = 0xFF if 10 <= j < 14 else 0x00
            report["cleared"] = 1
            report["success"] = True
            report["messages"].append(f"UserCred credential block cleared at 0x{loc:X}")
        else:
            report["style"] = "old"
            report["messages"].append(
                "ERROR: unable to find HP BIOS password - is this a correct HP BIOS image?"
            )

        if bytes(data) == original:
            report["messages"].append("Nothing was written: the image was already clear")
            return report

        with open(output_path, "wb") as f:
            f.write(bytes(data))
        report["output_path"] = output_path
        return report
