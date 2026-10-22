"""Embedded Controller firmware analysis and patching tab."""


from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from bios_recovery.gui.outputs import confirm_overwrite, derived_path
from bios_recovery.platforms.ec.ec_patcher import ECPatcher, ECStatus


def _run_inline(task, on_done, button=None):
    on_done(task())


class ECTab(QWidget):
    """Analyze, extract and (carefully) patch EC firmware."""

    def __init__(self, parent=None, run_task=None):
        super().__init__(parent)
        self._run_task = run_task or _run_inline
        self.patcher = ECPatcher()
        self.current_dump = None
        self.last_extracted = None
        self._build()

    def _build(self):
        layout = QVBoxLayout(self)

        layout.addWidget(QLabel("Works on the file loaded in the header (File > Open)."))

        analyze_btn = QPushButton("Analyze EC Firmware")
        analyze_btn.clicked.connect(self.analyze)
        layout.addWidget(analyze_btn)

        # ---- manual region override -------------------------------------
        # Auto-detection is a heuristic. When it cannot find (or mis-sizes) the
        # EC region, the user must be able to pin the exact offset and size --
        # flashing the wrong bytes to the chip is unrecoverable.
        override_group = QGroupBox("Manual region override (if auto-detect is wrong)")
        override_layout = QVBoxLayout(override_group)

        self.override_check = QCheckBox("Use manual chip size instead of auto-detect")
        override_layout.addWidget(self.override_check)

        hint = QLabel(
            "Leave the offset BLANK to take the selected size ending at the "
            "detected end of the EC region (recommended -- the chip size is "
            "known, the exact offset is the uncertain part).\n"
            "Fill in the offset to force an exact position instead."
        )
        hint.setWordWrap(True)
        hint.setStyleSheet("color: #888;")
        override_layout.addWidget(hint)

        size_row = QHBoxLayout()
        size_row.addWidget(QLabel("Offset:"))
        self.override_offset = QLineEdit()
        self.override_offset.setPlaceholderText("blank = auto-anchor at region end")
        size_row.addWidget(self.override_offset, 1)
        size_row.addWidget(QLabel("Size:"))
        self.override_size = QComboBox()
        self.override_size.addItems(
            [
                "0x20000 (128 KB)",
                "0x40000 (256 KB)",
                "0x80000 (512 KB)",
            ]
        )
        self.override_size.setCurrentIndex(1)
        size_row.addWidget(self.override_size)
        override_layout.addLayout(size_row)
        layout.addWidget(override_group)

        self.analysis_text = QPlainTextEdit()
        self.analysis_text.setReadOnly(True)
        self.analysis_text.setMaximumHeight(200)
        layout.addWidget(self.analysis_text)

        extract_row = QHBoxLayout()
        self.extract_btn = QPushButton("Extract EC Region")
        self.extract_btn.clicked.connect(self.extract_ec)
        extract_row.addWidget(self.extract_btn)
        extract_row.addWidget(QLabel("Save to:"))
        self.extract_path = QLineEdit()
        self.extract_path.setPlaceholderText("ec_firmware.bin")
        extract_row.addWidget(self.extract_path, 1)
        extract_browse = QPushButton("Browse...")
        extract_browse.clicked.connect(self.browse_extract)
        extract_row.addWidget(extract_browse)
        layout.addLayout(extract_row)

        patch_group = QGroupBox("Patch Registry")
        patch_layout = QVBoxLayout(patch_group)

        patch_row = QHBoxLayout()
        self.patch_combo = QComboBox()
        self.patch_combo.currentIndexChanged.connect(self._patch_desc_changed)
        patch_row.addWidget(self.patch_combo, 1)
        self.patch_apply_btn = QPushButton("Apply Patch")
        self.patch_apply_btn.clicked.connect(self.apply_patch)
        patch_row.addWidget(self.patch_apply_btn)
        patch_layout.addLayout(patch_row)

        self.patch_desc = QLabel("")
        self.patch_desc.setWordWrap(True)
        patch_layout.addWidget(self.patch_desc)

        self.verified_label = QLabel("")
        patch_layout.addWidget(self.verified_label)

        patch_layout.addWidget(
            QLabel("Only 'verified' patches are applied unless you explicitly accept the risk.")
        )
        layout.addWidget(patch_group)

        self.patches_table = QTableWidget(0, 4)
        self.patches_table.setHorizontalHeaderLabels(["Key", "Vendor", "Generation", "Verified"])
        layout.addWidget(self.patches_table, 1)

        self.log_text = QPlainTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setMaximumHeight(140)
        layout.addWidget(self.log_text)

        # Everything must exist before the registry is loaded into the widgets.
        self._reload_patch_list()

    def _reload_patch_list(self):
        self._patches = self.patcher.list_patches()
        self.patch_combo.clear()
        for p in self._patches:
            label = f"[{'OK' if p.verified else '??'}] {p.key}"
            self.patch_combo.addItem(label, p.key)
        self._populate_table()

    def _populate_table(self):
        self.patches_table.setRowCount(0)
        for i, p in enumerate(self._patches):
            self.patches_table.insertRow(i)
            self.patches_table.setItem(i, 0, QTableWidgetItem(p.key))
            self.patches_table.setItem(i, 1, QTableWidgetItem(p.vendor))
            self.patches_table.setItem(i, 2, QTableWidgetItem(p.generation))
            self.patches_table.setItem(i, 3, QTableWidgetItem("Yes" if p.verified else "No"))

    def _patch_desc_changed(self, _index):
        key = self.patch_combo.currentData()
        for p in self._patches:
            if p.key == key:
                self.patch_desc.setText(p.description)
                self.verified_label.setText(
                    "Verified: "
                    + ("Yes" if p.verified else "NO - unverified, apply at your own risk")
                )
                return
        self.patch_desc.setText("")
        self.verified_label.setText("")

    def set_file(self, path: str):
        """Called by the window when a file is loaded; the EC tab never picks its own."""
        self.current_dump = path
        self._log(f"Loaded {path}")

    def browse_extract(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Save EC firmware", "ec_firmware.bin", "Binary (*.bin)"
        )
        if path:
            self.extract_path.setText(path)

    def _log(self, text: str):
        self.log_text.appendPlainText(text)

    def _override_region(self):
        """Return (offset, size) from the manual controls, or (None, None).

        Three cases:
          * box unchecked              -> (None, None), use auto-detection.
          * box checked, offset blank  -> (None, size): END-ANCHORED. The engine
            places the region as the last ``size`` bytes before the detected end
            of the EC region. This is the mode to use when the detected SIZE is
            wrong but the chip capacity is known -- e.g. a 256KB IT8218VG that
            the heuristics keep reporting as 128KB.
          * box checked, offset filled -> (offset, size), used verbatim.

        A typed offset that is not hex raises ValueError. It never falls back to
        auto-detection: the user asked for a specific region.
        """
        if not self.override_check.isChecked():
            return None, None
        size_text = self.override_size.currentText().split()[0]
        size = int(size_text, 16)
        raw = self.override_offset.text().strip()
        if not raw:
            return None, size
        try:
            offset = int(raw, 16)
        except ValueError:
            raise ValueError(
                f"'{raw}' is not a valid hex offset. Example: 1FC0000\n\n"
                "Leave the offset blank to anchor the region at its detected "
                "end using the selected chip size."
            ) from None
        return offset, size

    def _region_or_warn(self):
        """(offset, size) from the manual controls, or None after telling the user why not."""
        try:
            return self._override_region()
        except ValueError as exc:
            QMessageBox.warning(self, "Bad offset", str(exc))
            return None

    def analyze(self):
        if not self.current_dump:
            QMessageBox.warning(self, "No File", "Open a BIOS/SPI dump first.")
            return
        region = self._region_or_warn()
        if region is None:
            return
        off_override, size_override = region
        path = self.current_dump

        def task():
            with open(path, "rb") as f:
                return self.patcher.analyze_ec(f.read(), off_override, size_override)

        self._run_task(
            task,
            lambda analysis: self._analysis_done(analysis, off_override, size_override),
        )

    def _analysis_done(self, analysis, off_override, size_override):
        if not analysis.found:
            self.analysis_text.setPlainText(
                "No EC firmware found at that region. Tried known controller "
                "signatures (ITE, Nuvoton, MEC, ENE).\n\n"
                "If this board keeps the EC firmware on a separate chip, or the "
                "region is stored unusually, enable the manual override below and "
                "set the offset/size yourself (0x40000 = 256KB, e.g. for IT8218VG-256)."
            )
            self._log("EC not found.")
            return
        checksum = (
            "valid"
            if analysis.checksum_valid
            else ("invalid/trailing" if analysis.checksum_valid is False else "n/a")
        )
        lines = [
            "EC firmware found",
            f"  Offset: 0x{analysis.offset:X}",
            f"  Size:   0x{analysis.size:X} ({analysis.size:,} bytes)",
            f"  Controller: {analysis.controller_name}",
            f"  Magic: {analysis.magic}",
            f"  KBC_CONFIG markers: {'yes' if analysis.has_kbc_config else 'no'}",
            f"  XOR checksum: {checksum}",
            f"  Password/security flags found: {len(analysis.password_flags)}",
        ]
        for flag in analysis.password_flags[:40]:
            lines.append(f"    [{flag['name']}] at 0x{flag['offset_in_image']:X}")
        if off_override is not None or size_override is not None:
            lines.append("")
            lines.append("  (manual chip size active -- verify before flashing)")
            if off_override is None:
                lines.append(f"  (size 0x{size_override:X} anchored at the detected end)")
        self.analysis_text.setPlainText("\n".join(lines))
        self.last_extracted = analysis
        self._log(f"Analyzed EC at 0x{analysis.offset:X} ({analysis.size:,} bytes).")

    def extract_ec(self):
        if not self.current_dump:
            QMessageBox.warning(self, "No File", "Open a BIOS/SPI dump first.")
            return
        out = self.extract_path.text().strip()
        if not out:
            out = derived_path(self.current_dump, "_ec.bin")
            self.extract_path.setText(out)
        if not confirm_overwrite(self, out):
            return
        region = self._region_or_warn()
        if region is None:
            return
        off_override, size_override = region
        path = self.current_dump
        manual = off_override is not None or size_override is not None
        self._run_task(
            lambda: self.patcher.extract_ec(
                path, out, off_override, size_override, overwrite=True
            ),
            lambda result: self._extract_done(result, manual),
        )

    def _extract_done(self, result, manual):
        self._log(result.message)
        if result.status == ECStatus.SUCCESS:
            if manual:
                QMessageBox.information(
                    self,
                    "Extract",
                    result.message + "\n\nExtracted using a MANUAL chip size -- "
                    "double-check this is the right region before flashing.",
                )
            else:
                QMessageBox.information(self, "Extract", result.message)
        else:
            QMessageBox.warning(self, "Extract failed", result.message)

    def apply_patch(self):
        if not self.current_dump:
            QMessageBox.warning(self, "No File", "Open a BIOS/SPI dump first.")
            return
        key = self.patch_combo.currentData()
        if not key:
            return
        patch = self.patcher.get_patch(key)
        if not patch:
            return

        require_verified = True
        if not patch.verified:
            accept, _ = QInputDialog.getText(
                self,
                "Unverified Patch",
                "This patch is NOT hardware-verified.\n"
                "Type 'I understand' to force-apply it to your dump:",
            )
            if not accept or accept.strip().lower() != "i understand":
                QMessageBox.information(self, "Cancelled", "Unverified patch not applied.")
                return
            require_verified = False

        output = derived_path(self.current_dump, "_ecpatched.bin")
        if not confirm_overwrite(self, output):
            return
        path = self.current_dump
        self._run_task(
            lambda: self.patcher.apply_patch(
                path,
                key,
                output_path=output,
                require_verified=require_verified,
                overwrite=True,
            ),
            self._patch_done,
        )

    def _patch_done(self, result):
        self._log(result.message)
        if result.status == ECStatus.SUCCESS:
            QMessageBox.information(
                self, "Applied", f"{result.message}\n\nOutput saved to: {result.output_path}"
            )
        elif result.status != ECStatus.UNVERIFIED:
            QMessageBox.warning(self, "Patch Not Applied", result.message)
