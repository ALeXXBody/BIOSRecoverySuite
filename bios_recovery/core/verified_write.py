"""Write an output file only after its bytes read back identical."""

from __future__ import annotations

from bios_recovery.core.safety import write_file_atomic


def write_verified(path: str, data: bytes) -> None:
    """Atomically write data to path, then read it back and compare.

    Raises OSError when the file on disk differs from data, so a caller never
    reports success for an output that was not written as intended.
    """
    write_file_atomic(path, data)
    with open(path, "rb") as f:
        if f.read() != bytes(data):
            raise OSError(f"read-back check failed for {path}; output does not match")
