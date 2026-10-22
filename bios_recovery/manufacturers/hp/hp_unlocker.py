"""HP BIOS unlock engine - removes admin passwords from HP UEFI/BIOS dumps.

Ports the public HPUnlocker.py approach (schorschii's gist; same mechanism the
IndiaFix/badcaps "HP Unlocker" / "RC Unlocker" drag-drop tools use):

* Modern HP UEFI images: locate the UTF-16LE ``UserCred`` structure and reset
  its 100-byte credential block (0x00 with the 4 flag bytes at +26..+29 = 0xFF).
* Legacy HP BIOS images: walk every ``$VSS`` variable entry keyed
  ``BiosUser`` (UTF-16LE) and wipe its value region with 0xFF up to the
  ``AA 55`` terminator.

Always flash back the original dump afterwards unless instructed otherwise.
"""

_USER_CRED = b"U\x00s\x00e\x00r\x00C\x00r\x00e\x00d"
_VSS_MAGIC = b"$VSS"
_VSS_KEY = b"B\x00i\x00o\x00s\x00U\x00s\x00e\x00r"
_VSS_END = b"\xaaU"


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
            out["style"] = "new"
            out["usercred_offset"] = cred
            return out
        key = data.find(_VSS_KEY)
        while key >= 0:
            out["vss_entries"] += 1
            out["vss_offsets"].append(key)
            key = data.find(_VSS_KEY, key + 2)
        if out["vss_entries"]:
            out["style"] = "old"
        return out

    def unlock(self, image_path: str, output_path: str) -> dict:
        """Clear HP admin password storage. Returns a report dict."""
        with open(image_path, "rb") as f:
            data = bytearray(f.read())

        report = {
            "success": False,
            "style": None,
            "cleared": 0,
            "output_path": output_path,
            "messages": [],
        }

        loc = data.find(_USER_CRED)
        if loc >= 0:
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
            search_from = 0
            while True:
                loc_start = data.find(_VSS_KEY, search_from + 2)
                if loc_start < 0:
                    break
                end_marker = data.find(_VSS_END, loc_start)
                loc_len = end_marker - loc_start - 22 if end_marker >= 0 else -1
                if loc_len > 0:
                    for i in range(loc_len):
                        pos = loc_start + 22 + i
                        if pos < len(data):
                            data[pos] = 0xFF
                    report["cleared"] += 1
                search_from = loc_start
            if report["cleared"]:
                report["success"] = True
                report["messages"].append(f"Cleared {report['cleared']} $VSS/BiosUser entr(ies)")
            else:
                report["messages"].append(
                    "ERROR: unable to find HP BIOS password - is this a correct HP BIOS image?"
                )

        with open(output_path, "wb") as f:
            f.write(bytes(data))
        return report
