"""Shared safety checks for every operation that writes a file."""

from __future__ import annotations

import os
import stat
import tempfile


class SameFileError(ValueError):
    """Raised when an output path would overwrite the input file."""


def ensure_distinct(input_path: str, output_path: str | None) -> None:
    """Refuse to write an output over the input, or over any other file the input shares.

    Compares resolved real paths, so symlinks and relative paths cannot bypass the check.
    """
    if not output_path:
        return
    if os.path.realpath(input_path) == os.path.realpath(output_path):
        raise SameFileError(
            f"output path is the input file ({input_path}); choose a different output path"
        )
    if os.path.exists(output_path) and os.path.exists(input_path):
        try:
            if os.path.samefile(input_path, output_path):
                raise SameFileError(
                    f"output path is the input file ({input_path}); choose a different output path"
                )
        except OSError:
            pass


def write_file_atomic(path: str, data: bytes) -> None:
    """Replace ``path`` with ``data``: a synced temporary file in the same folder, then rename.

    A failed write leaves the previous file (or no file) in place, never a partial one.
    """
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(prefix=".", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        mode = stat.S_IMODE(os.stat(path).st_mode) if os.path.exists(path) else 0o644
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise
