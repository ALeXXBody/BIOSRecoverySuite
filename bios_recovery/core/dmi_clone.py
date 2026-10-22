"""DMI clone - transfers system identity (serials, UUID, MACs) between dumps.

The classic IndiaFix/All-in-One-BIOS-Edit workflow: you flash a clean/new BIOS
dump for a machine but must carry over the original DMI/SMBIOS data (serial
number, UUID, product name) or the machine loses its identity.

This engine locates the validated SMBIOS entry point and table (core.smbios) in both
images and copies the old entry point and table over the new ones. Both must have the
same layout (the entry point at the same offset from its table), and the old block must
fit inside the new validated span. Nothing is written unless the result validates again.
AMI images without an SMBIOS table fall back to the NVRAM identity variables (core.nvar).
"""

from bios_recovery.core.safety import SameFileError, ensure_distinct, write_file_atomic
from bios_recovery.core.smbios import find_table

_SM3_ANCHOR = b"_SM3_"
_SM2_ENTRY_LEN = 0x1F
_SM3_ENTRY_LEN = 0x18


def _entry_span(data: bytes, anchor: int, start: int) -> int:
    if anchor == start:
        return 0
    return _SM3_ENTRY_LEN if data[anchor : anchor + 5] == _SM3_ANCHOR else _SM2_ENTRY_LEN


def _block(data: bytes, located) -> tuple[int, int]:
    """(lo, hi) of the entry point and table together."""
    anchor, start, length = located
    lo = min(anchor, start)
    hi = max(anchor + _entry_span(data, anchor, start), start + length)
    return lo, hi


def _read(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


class DMIClone:
    def analyze(self, old_path: str, new_path: str) -> dict:
        old = _read(old_path)
        new = _read(new_path)
        o = find_table(old)
        n = find_table(new)
        ob = _block(old, o) if o else None
        nb = _block(new, n) if n else None

        def describe(found, span):
            if not found:
                return None
            return {"eps": found[0], "start": span[0], "end": span[1], "size": span[1] - span[0]}

        return {
            "old_found": o is not None,
            "new_found": n is not None,
            "old": describe(o, ob),
            "new": describe(n, nb),
        }

    def _clone_nvram_identity(self, old: bytes, new: bytearray, output_path: str) -> dict:
        """AMI images keep the machine identity in NVRAM variables, not in an SMBIOS table.

        The identity variables (MFG0, _DMI) are carried over only when every one of them
        fits exactly in the new image; otherwise nothing is written.
        """
        from bios_recovery.core.nvar import carry_identity

        before = bytes(new)
        data = bytearray(new)
        rep = carry_identity(old, data)
        if not rep.success:
            return {"success": False, "message": f"Identity not carried: {rep.refused}"}
        changed = sum(1 for a, b in zip(before, data) if a != b)
        write_file_atomic(output_path, bytes(data))
        return {
            "success": True,
            "message": "Identity variables carried over: " + "; ".join(rep.messages),
            "output_path": output_path,
            "bytes": changed,
        }

    def clone(self, old_path: str, new_path: str, output_path: str) -> dict:
        """Copy the DMI identity block from old dump into the new dump."""
        try:
            ensure_distinct(new_path, output_path)
        except SameFileError as exc:
            return {"success": False, "message": str(exc)}
        old = _read(old_path)
        new = _read(new_path)

        o = find_table(old)
        n = find_table(new)
        if not o or not n:
            return self._clone_nvram_identity(old, bytearray(new), output_path)

        if o[0] - o[1] != n[0] - n[1]:
            return {
                "success": False,
                "message": "DMI layout differs: the entry point sits at a different offset "
                "from its table in the two dumps - nothing written",
            }
        o_lo, o_hi = _block(old, o)
        n_lo, n_hi = _block(new, n)
        block = old[o_lo:o_hi]
        if len(block) > n_hi - n_lo:
            return {
                "success": False,
                "message": f"DMI block from old dump ({len(block)} bytes) does not fit the "
                f"new dump's validated SMBIOS span ({n_hi - n_lo} bytes) - nothing written",
            }

        out = bytearray(new)
        out[n_lo : n_lo + len(block)] = block
        if find_table(bytes(out)) != (n[0], n[1], o[2]):
            return {
                "success": False,
                "message": "cloned SMBIOS table does not validate - nothing written",
            }
        write_file_atomic(output_path, bytes(out))

        return {
            "success": True,
            "message": f"DMI identity block ({len(block)} bytes) cloned "
            f"from 0x{o_lo:X} (old) to 0x{n_lo:X} (new)",
            "output_path": output_path,
            "bytes": len(block),
        }
