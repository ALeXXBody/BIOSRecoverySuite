"""DMI clone - transfers system identity (serials, UUID, MACs) between dumps.

The classic IndiaFix/All-in-One-BIOS-Edit workflow: you flash a clean/new BIOS
dump for a machine but must carry over the original DMI/SMBIOS data (serial
number, UUID, product name) or the machine loses its identity.

This engine locates the SMBIOS entry point (``_SM_``) and its table in both
images and copies the whole identity block from the old dump into the new one
at the same offsets (the two dumps must share the same DMI area layout, which
holds for same-model BIOS updates).
"""

import struct


def _locate_smbios(data: bytes):
    """Return (eps_offset, block_start, block_end) covering EPS + table."""
    idx = 0
    while True:
        idx = data.find(b"_SM_", idx)
        if idx < 0:
            return None
        if idx + 0x1F > len(data):
            idx += 4
            continue
        table_len = struct.unpack_from("<H", data, idx + 0x16)[0]
        table_addr = struct.unpack_from("<I", data, idx + 0x18)[0]
        if 0 < table_addr < len(data) and 0 < table_len and table_addr + table_len <= len(data):
            start = min(idx, table_addr)
            end = max(idx + 0x1F, table_addr + table_len)
            return (idx, start, end)
        idx += 4


class DMIClone:
    def analyze(self, old_path: str, new_path: str) -> dict:
        old = open(old_path, "rb").read()
        new = open(new_path, "rb").read()
        o = _locate_smbios(old)
        n = _locate_smbios(new)
        return {
            "old_found": o is not None,
            "new_found": n is not None,
            "old": {"eps": o[0], "start": o[1], "end": o[2], "size": o[2] - o[1]} if o else None,
            "new": {"eps": n[0], "start": n[1], "end": n[2], "size": n[2] - n[1]} if n else None,
        }

    def _clone_nvram_identity(self, old: bytes, new: bytearray, output_path: str) -> dict:
        """AMI images keep the machine identity in NVRAM variables, not in an SMBIOS table.

        The identity variables (MFG0, _DMI) are carried over only when every one of them
        fits exactly in the new image; otherwise nothing is written.
        """
        from bios_recovery.core.nvar import carry_identity

        data = bytearray(new)
        rep = carry_identity(old, data)
        if not rep.success:
            return {"success": False, "message": f"Identity not carried: {rep.refused}"}
        with open(output_path, "wb") as f:
            f.write(bytes(data))
        return {
            "success": True,
            "message": "Identity variables carried over: " + "; ".join(rep.messages),
            "output_path": output_path,
            "bytes": 0,
        }

    def clone(self, old_path: str, new_path: str, output_path: str) -> dict:
        """Copy the DMI identity block from old dump into the new dump."""
        old = open(old_path, "rb").read()
        new = bytearray(open(new_path, "rb").read())

        o = _locate_smbios(old)
        n = _locate_smbios(new)
        if not o or not n:
            return self._clone_nvram_identity(old, new, output_path)

        block = old[o[1] : o[2]]
        if n[1] + len(block) > len(new):
            return {"success": False, "message": "DMI block from old dump does not fit in new dump"}

        new[n[1] : n[1] + len(block)] = block
        with open(output_path, "wb") as f:
            f.write(bytes(new))

        return {
            "success": True,
            "message": f"DMI identity block ({len(block)} bytes) cloned "
            f"from 0x{o[1]:X} (old) to 0x{n[1]:X} (new)",
            "output_path": output_path,
            "bytes": len(block),
        }
