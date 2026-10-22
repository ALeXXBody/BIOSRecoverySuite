"""Lenovo unlock tab: UEFIPatch pattern patches + DXE driver replacement.

Implements the community-proven workflow for supervisor-password removal and
advanced-menu/whitelist unlocking on Lenovo machines:

  * dry-run scan of the UEFIPatch-format registry (digmorepaka & co.)
  * targeted pattern patching (advanced menu, WLAN/WWAN whitelist, tamper fix)
  * DXE driver replacement from the derived/autopatch registry (badcaps flow)
"""

import os

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
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

from bios_recovery.platforms.intel.uefi_patcher import UEFIPatcher, UEFIPatchError


class LenovoTab(QWidget):
    """Apply community Lenovo unlock patches to a firmware dump."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.patcher = UEFIPatcher()
        self.current_dump = None
        self._scan_results = {}
        self._dxe_entries = []
        self._build()
        self._reload_dxe_registry()

    def _build(self):
        layout = QVBoxLayout(self)

        file_row = QHBoxLayout()
        file_row.addWidget(QLabel("BIOS dump:"))
        self.file_edit = QLineEdit()
        self.file_edit.setReadOnly(True)
        file_row.addWidget(self.file_edit, 1)
        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self.browse)
        file_row.addWidget(browse_btn)
        layout.addLayout(file_row)

        # ---- detection -----------------------------------------------
        self.detect_btn = QPushButton("Detect Lenovo Features")
        self.detect_btn.clicked.connect(self.run_detect)
        layout.addWidget(self.detect_btn)

        self.detect_text = QPlainTextEdit()
        self.detect_text.setReadOnly(True)
        self.detect_text.setMaximumHeight(130)
        layout.addWidget(self.detect_text)

        # ---- pattern patch groups ------------------------------------
        pattern_group = QGroupBox("UEFIPatch Groups (dry-run scan first)")
        pg_layout = QVBoxLayout(pattern_group)

        scan_row = QHBoxLayout()
        self.scan_btn = QPushButton("Scan (Dry Run)")
        self.scan_btn.clicked.connect(self.run_scan)
        scan_row.addWidget(self.scan_btn)
        scan_row.addStretch(1)
        pg_layout.addLayout(scan_row)

        self.groups_table = QTableWidget(0, 5)
        self.groups_table.setHorizontalHeaderLabels(
            ["Apply", "Group", "Matches", "Models", "Description"]
        )
        self.groups_table.setColumnWidth(0, 50)
        self.groups_table.setColumnWidth(2, 70)
        pg_layout.addWidget(self.groups_table)

        apply_row = QHBoxLayout()
        self.apply_btn = QPushButton("Apply Selected Pattern Patches")
        self.apply_btn.clicked.connect(self.apply_patches)
        apply_row.addWidget(self.apply_btn)
        apply_row.addStretch(1)
        pg_layout.addLayout(apply_row)

        pg_layout.addWidget(
            QLabel(
                "Patches apply only where their byte patterns are found. "
                "Verify your dump against a second read before flashing."
            )
        )
        layout.addWidget(pattern_group)

        # ---- DXE driver replacement ----------------------------------
        dxe_group = QGroupBox("DXE Driver Replacement (autopatch binaries)")
        dxe_layout = QVBoxLayout(dxe_group)

        self.dxe_table = QTableWidget(0, 5)
        self.dxe_table.setHorizontalHeaderLabels(
            ["Apply", "Key", "Target GUID", "Verified", "Binary"]
        )
        dxe_layout.addWidget(self.dxe_table)

        dxe_btn_row = QHBoxLayout()
        self.dxe_apply_btn = QPushButton("Apply Selected DXE Replacements")
        self.dxe_apply_btn.clicked.connect(self.apply_dxe)
        dxe_btn_row.addWidget(self.dxe_apply_btn)

        self.derive_btn = QPushButton("Derive From Pair (original + patched)...")
        self.derive_btn.clicked.connect(self.derive_from_pair)
        dxe_btn_row.addWidget(self.derive_btn)
        dxe_btn_row.addStretch(1)
        dxe_layout.addLayout(dxe_btn_row)

        self.dxe_consent = QCheckBox(
            "I understand driver replacement modifies critical firmware code"
        )
        dxe_layout.addWidget(self.dxe_consent)

        autopatch_row = QHBoxLayout()
        self.autopatch_btn = QPushButton("Run Full Autopatch (drivers + NVRAM clean)")
        self.autopatch_btn.clicked.connect(self.run_full_autopatch)
        autopatch_row.addWidget(self.autopatch_btn)
        autopatch_row.addStretch(1)
        dxe_layout.addLayout(autopatch_row)
        layout.addWidget(dxe_group)

        self.log_text = QPlainTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setMaximumHeight(140)
        layout.addWidget(self.log_text)

    # ------------------------------------------------------------------

    def set_file(self, path: str):
        self.current_dump = path
        self.file_edit.setText(path)
        self._clear_scan()
        self._log(f"Loaded {path}")

    def _clear_scan(self):
        """Results belong to one file. A new file, or a failed scan, must not leave old ones."""
        self._scan_results = {}
        self.groups_table.setRowCount(0)

    def browse(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Open BIOS dump", "", "Binary (*.bin *.rom *.fd *.dump);;All Files (*)"
        )
        if path:
            self.set_file(path)

    def _log(self, text: str):
        self.log_text.appendPlainText(text)

    def _require_file(self) -> bool:
        if not self.current_dump or not os.path.exists(self.current_dump):
            QMessageBox.warning(self, "No File", "Open a BIOS dump first.")
            return False
        return True

    # ---- detection -----------------------------------------------------

    def run_detect(self):
        if not self._require_file():
            return
        try:
            det = self.patcher.detect_lenovo(self.current_dump)
        except Exception as e:
            self._log(f"detection failed: {e}")
            return
        lines = []
        lines.append(f"Lenovo firmware detected: {'YES' if det['is_lenovo'] else 'no'}")
        ce = det["ce_backdoor"]
        if ce["guid_hits"] or ce["string_hits"]:
            lines.append(
                f"cE! runtime backdoor: {len(ce['guid_hits'])} GUID hit(s), "
                f"{len(ce['string_hits'])} string hit(s) -> the H2O runtime "
                "unlocker method applies to this machine"
            )
        if det["tamper_marker"] is not None:
            lines.append(
                f"LNVBBSEC tamper flag present at 0x{det['tamper_marker']:X} "
                "(tamper-fix patch group is relevant)"
            )
        elif det["tamper_already_patched"]:
            lines.append("LNVBBSEC tamper flag: already patched (FF)")
        for d in det["drivers"]:
            lines.append(
                f"driver: {d['name']} (ascii x{d['ascii_hits']}, utf16 x{d['utf16_hits']})"
            )
        self.detect_text.setPlainText("\n".join(lines) or "No Lenovo markers found.")

    # ---- pattern patches -------------------------------------------------

    def run_scan(self):
        if not self._require_file():
            return
        self._clear_scan()
        self.scan_btn.setEnabled(False)
        try:
            self._scan_results = self.patcher.scan(self.current_dump)
        except Exception as e:
            self._log(f"scan failed: {e}")
            return
        finally:
            self.scan_btn.setEnabled(True)
        for i, g in enumerate(self.patcher.groups):
            self.groups_table.insertRow(i)
            chk = QTableWidgetItem()
            chk.setFlags(chk.flags() | Qt.ItemIsUserCheckable)
            chk.setCheckState(
                Qt.Checked if self._scan_results[g["key"]]["matches"] else Qt.Unchecked
            )
            self.groups_table.setItem(i, 0, chk)
            self.groups_table.setItem(i, 1, QTableWidgetItem(g["key"]))
            self.groups_table.setItem(
                i, 2, QTableWidgetItem(str(self._scan_results[g["key"]]["matches"]))
            )
            self.groups_table.setItem(i, 3, QTableWidgetItem(g["models"]))
            self.groups_table.setItem(i, 4, QTableWidgetItem(g["desc"]))
        total = sum(r["matches"] for r in self._scan_results.values())
        self._log(
            f"Scan complete: {total} pattern match(es) across {len(self._scan_results)} groups."
        )

    def _selected_groups(self):
        sel = []
        for i in range(self.groups_table.rowCount()):
            item = self.groups_table.item(i, 0)
            if item and item.checkState() == Qt.Checked:
                sel.append(self.groups_table.item(i, 1).text())
        return sel

    def apply_patches(self):
        if not self._require_file():
            return
        sel = self._selected_groups()
        if not sel:
            QMessageBox.information(
                self, "Nothing Selected", "Tick at least one patch group (run a scan first)."
            )
            return
        out = self.current_dump.rsplit(".", 1)[0] + "_patched.bin"
        try:
            report = self.patcher.apply(self.current_dump, out, group_keys=sel)
        except UEFIPatchError as e:
            QMessageBox.critical(self, "Patch Failed", str(e))
            return
        self._log(f"Applied {report['matches_total']} patch(es) -> {out}")
        for msg in report["messages"]:
            self._log(f"  {msg}")
        QMessageBox.information(
            self,
            "Patches Applied",
            f"{report['matches_total']} pattern patch(es) applied.\n\nOutput: {out}\n\n"
            "Remember: flash the patched image, boot, clear the password/settings,\n"
            "then flash the ORIGINAL image back (autopatch flow).",
        )

    # ---- DXE driver replacement -------------------------------------------

    def _reload_dxe_registry(self):
        self._dxe_entries = self.patcher.load_dxe_replacements()
        self.dxe_table.setRowCount(0)
        patches_dir = os.path.dirname(self.patcher.patches_path)
        for i, e in enumerate(self._dxe_entries):
            self.dxe_table.insertRow(i)
            chk = QTableWidgetItem()
            chk.setFlags(chk.flags() | Qt.ItemIsUserCheckable)
            chk.setCheckState(Qt.Unchecked)
            self.dxe_table.setItem(i, 0, chk)
            bin_path = os.path.join(patches_dir, e["file"])
            missing = "" if os.path.exists(bin_path) else "  [binary missing]"
            self.dxe_table.setItem(i, 1, QTableWidgetItem(e["key"] + missing))
            self.dxe_table.setItem(i, 2, QTableWidgetItem(e["target_guid"]))
            self.dxe_table.setItem(i, 3, QTableWidgetItem("Yes" if e["verified"] else "No"))
            self.dxe_table.setItem(i, 4, QTableWidgetItem(e["file"]))

    def _selected_dxe(self):
        sel = []
        for i in range(self.dxe_table.rowCount()):
            item = self.dxe_table.item(i, 0)
            if item and item.checkState() == Qt.Checked:
                sel.append(self._dxe_entries[i])
        return sel

    def apply_dxe(self):
        if not self._require_file():
            return
        if not self.dxe_consent.isChecked():
            QMessageBox.warning(
                self, "Consent Required", "Tick the consent box before replacing drivers."
            )
            return
        sel = self._selected_dxe()
        if not sel:
            QMessageBox.information(
                self, "Nothing Selected", "Tick at least one driver replacement."
            )
            return
        patches_dir = os.path.dirname(self.patcher.patches_path)
        work = self.current_dump
        applied = 0
        for e in sel:
            bin_path = os.path.join(patches_dir, e["file"])
            if not os.path.exists(bin_path):
                self._log(f"skip {e['key']}: binary missing ({e['file']})")
                continue
            out = work.rsplit(".", 1)[0] + "_dxe.bin"
            res = self.patcher.replace_ffs_file(work, out, e["target_guid"], bin_path)
            if res["success"]:
                self._log(
                    f"{e['key']}: replaced {e['target_guid']} "
                    f"({res['old_size']} -> {res['new_size']} bytes)"
                )
                work = out
                applied += 1
            else:
                self._log(f"{e['key']} FAILED: {res['message']}")
        if applied:
            QMessageBox.information(
                self, "Drivers Replaced", f"{applied} replacement(s) applied.\nOutput: {work}"
            )
        else:
            QMessageBox.warning(self, "Nothing Applied", "No replacements were applied.")

    def run_full_autopatch(self):
        if not self._require_file():
            return
        if not self.dxe_consent.isChecked():
            QMessageBox.warning(
                self, "Consent Required", "Tick the consent box before running the autopatch."
            )
            return
        out = self.current_dump.rsplit(".", 1)[0] + "_autopatched.bin"
        try:
            report = self.patcher.run_autopatch(self.current_dump, out)
        except Exception as e:
            QMessageBox.critical(self, "Autopatch Failed", str(e))
            return
        for s in report["steps"]:
            tag = "OK " if s["ok"] else ("SKIP" if s.get("skipped") else "FAIL")
            self._log(f"[{tag}] {s['step']}: {s['message']}")
        QMessageBox.information(
            self,
            "Autopatch Complete",
            "Patched image written to:\n" + out + "\n\n[ HOW TO USE THE PATCH ]\n"
            "1. Flash the PATCHED image\n"
            "2. Boot and enter BIOS settings (ENTER/F1)\n"
            "3. Enter any character when asked for Supervisor Password\n"
            "4. Press Enter when it shows Hardware ID\n"
            "5. Press Space twice when asked\n"
            "6. Power off\n"
            "7. Flash the ORIGINAL image back\n"
            "8. Reset BIOS settings to factory default\n\n"
            "You may need to hold the anti-tamper switch (tape) while booting,\n"
            "and remove the disk if it is locked.",
        )

    def derive_from_pair(self):
        orig, _ = QFileDialog.getOpenFileName(
            self, "Original (unpatched) dump", "", "Binary (*.bin);;All Files (*)"
        )
        if not orig:
            return
        patched, _ = QFileDialog.getOpenFileName(
            self, "Autopatched dump", "", "Binary (*.bin);;All Files (*)"
        )
        if not patched:
            return
        outdir = QFileDialog.getExistingDirectory(self, "Where to store extracted drivers")
        if not outdir:
            return
        try:
            derived = self.patcher.derive_replacements(orig, patched, outdir)
        except Exception as e:
            QMessageBox.critical(self, "Derive Failed", str(e))
            return
        if not derived:
            QMessageBox.information(
                self, "No Differences", "No replaced files found between the two dumps."
            )
            return
        entries = self._dxe_entries + derived
        self.patcher.save_dxe_replacements(entries)
        self._reload_dxe_registry()
        self._log(f"Derived {len(derived)} replacement(s) from the dump pair -> {outdir}")
