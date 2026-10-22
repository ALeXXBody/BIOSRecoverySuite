"""Flash & Hex page: SPI programmer (flashrom / CH341A) and a hex view of the image.

One image field serves both: the write source and the hex view. A completed backup
read becomes that image, so its contents can be viewed without a browse step.
Results of every action go to one output pane.
"""

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
from bios_recovery.gui.workers import Job


class SPITab(QWidget):
    """Read / write / erase SPI flash chips through flashrom."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.flasher = SPIFlasher()
        self._jobs = {}
        self._job_seq = 0
        self.parent_window = parent
        self.current_image = None
        self._build()

    def _build(self):
        layout = QVBoxLayout(self)

        image_row = QHBoxLayout()
        image_row.addWidget(QLabel("Image:"))
        self.image_edit = QLineEdit()
        self.image_edit.setPlaceholderText("BIOS image to write, or to view in hex")
        image_row.addWidget(self.image_edit, 1)
        image_browse = QPushButton("Browse...")
        image_browse.clicked.connect(self._browse_open)
        image_row.addWidget(image_browse)
        layout.addLayout(image_row)

        hex_row = QHBoxLayout()
        hex_row.addWidget(QLabel("Hex view  Offset:"))
        self.hex_offset = QLineEdit("0x0")
        self.hex_offset.setMaximumWidth(120)
        hex_row.addWidget(self.hex_offset)
        hex_row.addWidget(QLabel("Length:"))
        self.hex_length = QLineEdit("256")
        self.hex_length.setMaximumWidth(120)
        hex_row.addWidget(self.hex_length)
        self.hex_btn = QPushButton("View Image in Hex")
        self.hex_btn.clicked.connect(self.view_hex)
        hex_row.addWidget(self.hex_btn)
        hex_row.addStretch(1)
        layout.addLayout(hex_row)

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

    def set_image(self, path: str) -> None:
        """Make path the image used for writing and for the hex view."""
        self.image_edit.setText(path)

    def view_hex(self):
        path = self.image_edit.text().strip()
        if not path or not os.path.exists(path):
            QMessageBox.warning(self, "No Image", "Choose an image first.")
            return
        try:
            offset = int(self.hex_offset.text().strip(), 16)
            length = int(self.hex_length.text().strip())
        except ValueError:
            QMessageBox.warning(self, "Invalid Range", "Offset and length must be numbers.")
            return
        if offset < 0 or length <= 0:
            QMessageBox.warning(
                self, "Invalid Range", "Offset must be zero or more, and length at least 1."
            )
            return
        from bios_recovery.core.bios_analyzer import BiosAnalyzer

        data = BiosAnalyzer().get_hex_view(path, offset, min(length, 0x10000))
        lines = [f"Hex view: {os.path.basename(path)} @ {offset:#x}, {len(data)} bytes"]
        for i in range(0, len(data), 16):
            chunk = data[i : i + 16]
            hex_str = " ".join(f"{b:02X}" for b in chunk)
            ascii_str = "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in chunk)
            lines.append(f"{offset + i:08X}  {hex_str:<48}  {ascii_str}")
        self._log("\n".join(lines))

    def _current_programmer(self) -> str:
        return self.prog_combo.currentText()

    def _browse_save(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Save chip dump", "chip_dump.bin", "Binary (*.bin)"
        )
        if path:
            self.read_path.setText(path)

    def _browse_open(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Open BIOS image", "", "Binary (*.bin *.rom);;All Files (*)"
        )
        if path:
            self.image_edit.setText(path)

    def _log(self, text: str):
        self.log_text.appendPlainText(text)

    def _start_job(self, button, task, on_result):
        """Run a flashrom operation off the UI thread; the button is disabled while it runs."""
        button.setEnabled(False)
        self._job_seq += 1
        token = self._job_seq
        self._jobs[token] = (button, on_result)
        job = Job(token, task)
        job.done.connect(self._job_done)
        job.failed.connect(self._job_failed)
        job.start()
        return job

    def _job_done(self, token, result):
        button, on_result = self._jobs.pop(token)
        button.setEnabled(True)
        on_result(result)

    def _job_failed(self, token, message):
        button, _ = self._jobs.pop(token)
        button.setEnabled(True)
        self._log(f"Operation failed: {message}")

    def detect_programmers(self):
        def on_result(programmers):
            if not programmers:
                self._log(
                    "No supported programmers found. Install flashrom and/or a CH341A driver."
                )
                return
            current = self._current_programmer()
            self.prog_combo.blockSignals(True)
            self.prog_combo.clear()
            self.prog_combo.addItems(programmers)
            if current in programmers:
                self.prog_combo.setCurrentText(current)
            self.prog_combo.blockSignals(False)
            self._log("Detected programmers: " + ", ".join(programmers))

        self._start_job(self.refresh_btn, self.flasher.discover_programmers, on_result)

    def identify_chip(self):
        def on_result(chip):
            self.chip_label.setText(chip.name or "Unknown")
            self._log(f"Identified chip: {chip.name or 'none'}")

        self._start_job(
            self.identify_btn,
            lambda: self.flasher.identify_chip(self._current_programmer()),
            on_result,
        )

    def read_chip(self):
        path = self.read_path.text().strip()
        if not path:
            QMessageBox.warning(self, "No Destination", "Set the path to save the chip dump.")
            return
        self.progress.setValue(0)
        self._log(f"Reading chip via {self._current_programmer()} ...")

        def on_result(result):
            self.progress.setValue(100)
            self._log(result.message)
            if result.output:
                self._log(result.output.strip())
            if result.status == SPIStatus.SUCCESS:
                self.current_image = path
                self.set_image(path)
                self._log(f"Backup saved to {path} ({result.flash_size:,} bytes)")

        self._start_job(
            self.read_btn,
            lambda: self.flasher.read_chip(path, self._current_programmer()),
            on_result,
        )

    def write_chip(self):
        if not self.write_consent.isChecked():
            QMessageBox.warning(self, "Consent Required", "Check the write consent box first.")
            return
        image = self.image_edit.text().strip()
        if not image:
            QMessageBox.warning(self, "No Image", "Select the BIOS image to write.")
            return
        if not os.path.exists(image):
            QMessageBox.warning(self, "Missing Image", "Image file not found.")
            return

        if self.write_auto_backup.isChecked():
            backup = image.rsplit(".", 1)[0] + "_prewrite_backup.bin"
            self._log(f"Taking automatic backup to {backup} ...")

            def after_backup(result):
                if result.status != SPIStatus.SUCCESS:
                    QMessageBox.critical(
                        self, "Backup Failed", f"Could not create backup: {result.message}"
                    )
                    return
                self._log("Backup complete.")
                self._confirm_and_write(image)

            self._start_job(
                self.write_btn,
                lambda: self.flasher.read_chip(backup, self._current_programmer()),
                after_backup,
            )
            return
        self._confirm_and_write(image)

    def _confirm_and_write(self, image: str):
        yes = QMessageBox.question(
            self,
            "Final Confirmation",
            f"Write {os.path.basename(image)} to the chip?\n\n"
            "This is irreversible. A wrong image can permanently brick the motherboard.",
        )
        if yes != QMessageBox.StandardButton.Yes:
            return

        self.progress.setValue(0)
        self._log(f"Writing image via {self._current_programmer()} ...")

        def on_result(result):
            self.progress.setValue(100)
            self._log(result.message)
            if result.output:
                self._log(result.output.strip())

        verify = self.write_verify.isChecked()
        self._start_job(
            self.write_btn,
            lambda: self.flasher.write_chip(
                image, self._current_programmer(), consent=True, verify=verify
            ),
            on_result,
        )

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
        self._log(f"Erasing chip via {self._current_programmer()} ...")

        def on_result(result):
            self._log(result.message)
            if result.output:
                self._log(result.output.strip())

        self._start_job(
            self.erase_btn,
            lambda: self.flasher.erase_chip(self._current_programmer(), consent=True),
            on_result,
        )
