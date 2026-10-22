"""Output-path helpers shared by every page that writes a file."""

from __future__ import annotations

import os

from PySide6.QtWidgets import QMessageBox


def derived_path(path: str, suffix: str) -> str:
    """Output beside the input: suffix replaces the final extension only."""
    root, _ext = os.path.splitext(path)
    return root + suffix


def unique_path(path: str) -> str:
    """path itself if free, otherwise path_1, path_2, ... so no existing file is replaced."""
    root, ext = os.path.splitext(path)
    candidate = path
    n = 1
    while os.path.exists(candidate):
        candidate = f"{root}_{n}{ext}"
        n += 1
    return candidate


def confirm_overwrite(parent, path: str) -> bool:
    """Ask before replacing an existing file. The default button is No."""
    if not os.path.exists(path):
        return True
    answer = QMessageBox.question(
        parent,
        "Overwrite?",
        f"{path} already exists. Replace it?",
        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        QMessageBox.StandardButton.No,
    )
    return answer == QMessageBox.StandardButton.Yes
