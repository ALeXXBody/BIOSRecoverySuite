"""SPI flash programmer tab - flashrom / CH341A based."""

import os

from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from bios_recovery.apps.spi_flasher import SPIFlasher, SPIStatus


class SPITab(QWidget):
    """Read / write / erase SPI flash chips through flashrom."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.flasher = SPIFlasher()
        self.parent_window = parent
        self.current_image = None
        self._build()

    def _build(self):
        layout = QVBoxLayout(self)

        prog_row = QHBoxLayout()
        prog_row.addWidget(QLabel("Programmer:"))
        self.prog_combo = QComboBox()
        self.prog_combo.addItems(["ch341a_spi", "ft2232_spi", "linux_spi", "buspirate_spi"])
        prog_row.addWidget(self.prog_combo, 1)

        self.refresh_btn = QPushButton("Detect Programmers")
        self.refresh_btn.clicked.connect(self.detect_programmers)
        prog_row.addWidget(self.refresh_btn)
        layout.addLayout(prog_row)

        chip_row = QHBoxLayout()
        chip_row.addWidget(QLabel("Chip:"))
        self.chip_label = QLabel("Unknown")
        self.chip_label.setStyleSheet("color: #999;")
        chip_row.addWidget(self.chip_label, 1)
        self.identify_btn = QPushButton("Identify Chip")
        self.identify_btn.clicked.connect(self.identify_chip)
        chip_row.addWidget(self.identify_btn)
        layout.addLayout(chip_row)

        read_group = QGroupBox("Read Backup")
        read_layout = QVBoxLayout(read_group)
        read_row = QHBoxLayout()
        read_row.addWidget(QLabel("Save dump to:"))
        self.read_path = QLineEdit()
        self.read_path.setPlaceholderText("Path for the full chip read (..._dump.bin)")
        read_row.addWidget(self.read_path, 1)
        read_browse = QPushButton("Browse...")
        read_browse.clicked.connect(self._browse_save)
        read_row.addWidget(read_browse)
        read_layout.addLayout(read_row)
        self.read_btn = QPushButton("Read Chip (Backup)")
        self.read_btn.clicked.connect(self.read_chip)
        read_layout.addWidget(self.read_btn)
        layout.addWidget(read_group)

        write_group = QGroupBox("Write Image (DANGER - requires consent)")
        write_layout = QVBoxLayout(write_group)
        write_row = QHBoxLayout()
        write_row.addWidget(QLabel("Image:"))
        self.write_path = QLineEdit()
        self.write_path.setPlaceholderText("Path to the BIOS image to write")
        write_row.addWidget(self.write_path, 1)
        write_browse = QPushButton("Browse...")
        write_browse.clicked.connect(self._browse_open)
        write_row.addWidget(write_browse)
        write_layout.addLayout(write_row)

        self.write_auto_backup = QCheckBox("Read full backup first (recommended)")
        self.write_auto_backup.setChecked(True)
        write_layout.addWidget(self.write_auto_backup)

        self.write_verify = QCheckBox("Verify after writing")
        self.write_verify.setChecked(True)
        write_layout.addWidget(self.write_verify)

        self.write_consent = QCheckBox("I understand this can brick the board - allow write")
        write_layout.addWidget(self.write_consent)

        self.write_btn = QPushButton("Write Chip")
        self.write_btn.clicked.connect(self.write_chip)
        write_layout.addWidget(self.write_btn)
        layout.addWidget(write_group)

        erase_row = QHBoxLayout()
        self.erase_consent = QCheckBox("I understand erasing destroys the chip contents")
        self.erase_consent.setChecked(False)
        erase_row.addWidget(self.erase_consent, 1)
        self.erase_btn = QPushButton("Erase Chip")
        self.erase_btn.clicked.connect(self.erase_chip)
        erase_row.addWidget(self.erase_btn)
        layout.addLayout(erase_row)

        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        layout.addWidget(self.progress)

        self.log_text = QPlainTextEdit()
        self.log_text.setReadOnly(True)
        layout.addWidget(self.log_text, 1)

    def _current_programmer(self) -> str:
        return self.prog_combo.currentText()

    def _browse_save(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save chip dump", "chip_dump.bin", "Binary (*.bin)")
        if path:
            self.read_path.setText(path)

    def _browse_open(self):
        path, _ = QFileDialog.getOpenFileName(self, "Open BIOS image", "", "Binary (*.bin *.rom);;All Files (*)")
        if path:
            self.write_path.setText(path)

    def _log(self, text: str):
        self.log_text.appendPlainText(text)

    def detect_programmers(self):
        self.refresh_btn.setEnabled(False)
        try:
            programmers = self.flasher.discover_programmers()
        except Exception as e:
            self._log(f"Programming detection failed: {e}")
            return
        finally:
            self.refresh_btn.setEnabled(True)
        if not programmers:
            self._log("No supported programmers found. Install flashrom and/or a CH341A driver.")
            return
        current = self._current_programmer()
        self.prog_combo.blockSignals(True)
        self.prog_combo.clear()
        self.prog_combo.addItems(programmers)
        if current in programmers:
            self.prog_combo.setCurrentText(current)
        self.prog_combo.blockSignals(False)
        self._log("Detected programmers: " + ", ".join(programmers))

    def identify_chip(self):
        self.identify_btn.setEnabled(False)
        try:
            chip = self.flasher.identify_chip(self._current_programmer())
        except Exception as e:
            self._log(f"Identify failed: {e}")
            return
        finally:
            self.identify_btn.setEnabled(True)
        self.chip_label.setText(chip.name or "Unknown")
        self._log(f"Identified chip: {chip.name or 'none'}")

    def read_chip(self):
        path = self.read_path.text().strip()
        if not path:
            QMessageBox.warning(self, "No Destination", "Set the path to save the chip dump.")
            return
        self.read_btn.setEnabled(False)
        self.progress.setValue(0)
        self._log(f"Reading chip via {self._current_programmer()} ...")
        try:
            result = self.flasher.read_chip(path, self._current_programmer())
        finally:
            self.read_btn.setEnabled(True)
        self.progress.setValue(100)
        self._log(result.message)
        if result.output:
            self._log(result.output.strip())
        if result.status == SPIStatus.SUCCESS:
            self.current_image = path
            self._log(f"Backup saved to {path} ({result.flash_size:,} bytes)")

    def write_chip(self):
        if not self.write_consent.isChecked():
            QMessageBox.warning(self, "Consent Required", "Check the write consent box first.")
            return
        image = self.write_path.text().strip()
        if not image:
            QMessageBox.warning(self, "No Image", "Select the BIOS image to write.")
            return
        if not os.path.exists(image):
            QMessageBox.warning(self, "Missing Image", "Image file not found.")
            return

        if self.write_auto_backup.isChecked():
            backup = image.rsplit(".", 1)[0] + "_prewrite_backup.bin"
            self._log(f"Taking automatic backup to {backup} ...")
            result = self.flasher.read_chip(backup, self._current_programmer())
            if result.status != SPIStatus.SUCCESS:
                QMessageBox.critical(self, "Backup Failed", f"Could not create backup: {result.message}")
                return
            self._log("Backup complete.")

        yes = QMessageBox.question(
            self,
            "Final Confirmation",
            f"Write {os.path.basename(image)} to the chip?\n\n"
            "This is irreversible. A wrong image can permanently brick the motherboard.",
        )
        if yes != QMessageBox.StandardButton.Yes:
            return

        self.write_btn.setEnabled(False)
        self.progress.setValue(0)
        self._log(f"Writing image via {self._current_programmer()} ...")
        try:
            result = self.flasher.write_chip(image, self._current_programmer(),
                                             consent=True, verify=self.write_verify.isChecked())
        finally:
            self.write_btn.setEnabled(True)
        self.progress.setValue(100)
        self._log(result.message)
        if result.output:
            self._log(result.output.strip())

    def erase_chip(self):
        if not self.erase_consent.isChecked():
            QMessageBox.warning(self, "Consent Required", "Check the erase consent box first.")
            return
        yes = QMessageBox.question(
            self,
            "Confirm Erase",
            "Erase the entire SPI chip? This destroys all contents including the BIOS.",
        )
        if yes != QMessageBox.StandardButton.Yes:
            return
        self.erase_btn.setEnabled(False)
        self._log(f"Erasing chip via {self._current_programmer()} ...")
        try:
            result = self.flasher.erase_chip(self._current_programmer(), consent=True)
        finally:
            self.erase_btn.setEnabled(True)
        self._log(result.message)
        if result.output:
            self._log(result.output.strip())
