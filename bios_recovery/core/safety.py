"""Shared safety checks for every operation that writes a file."""

from __future__ import annotations

import os


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
