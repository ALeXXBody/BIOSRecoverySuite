"""Rebuild Check page: which of the user's tools fit an image, and verify a rebuilt image.

Nothing here writes a firmware image. Tool and firmware folders come from Settings.
"""

from __future__ import annotations

from PySide6.QtWidgets import (
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from bios_recovery.core.rebuild_verify import describe, verify_rebuild
from bios_recovery.platforms.intel.me.fit_check import check_image


def _run_inline(task, on_done):
    on_done(task())


class RebuildCheckPage(QWidget):
    def __init__(self, parent=None, run_task=None):
        super().__init__(parent)
        self._run_task = run_task or _run_inline
        self._build()

    def _path_row(self, edit: QLineEdit, label: str, on_browse):
        row = QHBoxLayout()
        row.addWidget(QLabel(label))
        row.addWidget(edit, 1)
        browse = QPushButton("Browse…")
        browse.clicked.connect(on_browse)
        row.addWidget(browse)
        return row

    def _build(self):
        root = QVBoxLayout(self)
        title = QLabel("Rebuild Check")
        title.setStyleSheet("font-weight: bold; font-size: 14px;")
        root.addWidget(title)
        note = QLabel(
            "Checks which of your Intel tools fit an image's ME firmware, and verifies a "
            "rebuilt image region by region. Only ME-region changes are accepted. "
            "Nothing is written."
        )
        note.setWordWrap(True)
        note.setStyleSheet("color: #AAA;")
        root.addWidget(note)

        self.image_edit = QLineEdit()
        root.addLayout(self._path_row(self.image_edit, "Image:", self._browse_image))
        self.check_button = QPushButton("Check tools for this image")
        self.check_button.clicked.connect(lambda: self.check_image(self.image_edit.text()))
        root.addWidget(self.check_button)
        self.check_output = QPlainTextEdit()
        self.check_output.setReadOnly(True)
        self.check_output.setMinimumHeight(160)
        root.addWidget(self.check_output)

        verify_box = QGroupBox("Verify a rebuilt image against the original")
        vlayout = QVBoxLayout(verify_box)
        self.original_edit = QLineEdit()
        self.candidate_edit = QLineEdit()
        vlayout.addLayout(self._path_row(self.original_edit, "Original:", self._browse_original))
        vlayout.addLayout(self._path_row(self.candidate_edit, "Rebuilt:", self._browse_candidate))
        self.verify_button = QPushButton("Verify")
        self.verify_button.clicked.connect(
            lambda: self.verify(self.original_edit.text(), self.candidate_edit.text())
        )
        vlayout.addWidget(self.verify_button)
        self.verify_output = QPlainTextEdit()
        self.verify_output.setReadOnly(True)
        self.verify_output.setMinimumHeight(160)
        vlayout.addWidget(self.verify_output)
        root.addWidget(verify_box, 1)

    # -- actions (testable without dialogs) -------------------------------------
    def check_image(self, path: str, on_done=None):
        if not path:
            self.check_output.setPlainText("Choose an image first.")
            return
        self.check_button.setEnabled(False)
        self.check_output.setPlainText("Checking…")

        def finished(report):
            self.check_button.setEnabled(True)
            self.check_output.setPlainText("\n".join(report.lines()))
            if on_done:
                on_done(report)

        self._run_task(lambda: check_image(path), finished)

    def verify(self, original: str, candidate: str, on_done=None):
        if not original or not candidate:
            self.verify_output.setPlainText("Choose both the original and the rebuilt image.")
            return
        self.verify_button.setEnabled(False)
        self.verify_output.setPlainText("Verifying…")

        def finished(result):
            self.verify_button.setEnabled(True)
            self.verify_output.setPlainText("\n".join(describe(result)))
            if on_done:
                on_done(result)

        self._run_task(lambda: verify_rebuild(original, candidate), finished)

    # -- dialogs ----------------------------------------------------------------
    def _browse_image(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Choose image", "", "Firmware (*.bin *.rom *.fd);;All files (*)"
        )
        if path:
            self.image_edit.setText(path)

    def _browse_original(self):
        path, _ = QFileDialog.getOpenFileName(self, "Choose original image", "", "All files (*)")
        if path:
            self.original_edit.setText(path)

    def _browse_candidate(self):
        path, _ = QFileDialog.getOpenFileName(self, "Choose rebuilt image", "", "All files (*)")
        if path:
            self.candidate_edit.setText(path)
