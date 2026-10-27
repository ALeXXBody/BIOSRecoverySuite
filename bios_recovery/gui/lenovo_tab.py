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
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from bios_recovery.gui.outputs import confirm_overwrite, derived_path
from bios_recovery.platforms.intel.uefi_patcher import UEFIPatcher, UEFIPatchError


def _run_inline(task, on_done, button=None):
    on_done(task())


class LenovoTab(QWidget):
    """Apply community Lenovo unlock patches to a firmware dump."""

    def __init__(self, parent=None, run_task=None):
        super().__init__(parent)
        self._run_task = run_task or _run_inline
        self.patcher = UEFIPatcher()
        self.current_dump = None
        self._scan_results = {}
        self._dxe_entries = []
        self._build()
        self._reload_dxe_registry()

    def _build(self):
        layout = QVBoxLayout(self)

        layout.addWidget(QLabel("Works on the file loaded in the header (File > Open)."))

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
        self._clear_scan()
        self._log(f"Loaded {path}")

    def _clear_scan(self):
        """Results belong to one file. A new file, or a failed scan, must not leave old ones."""
        self._scan_results = {}
        self.groups_table.setRowCount(0)

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

        def task():
            det = self.patcher.detect_lenovo(self.current_dump)
            try:
                diag = self.patcher.diagnose_svp_storage(self.current_dump)
            except Exception as e:  # diagnosis must never break detection
                diag = {"location": "unknown", "message": f"diagnosis failed: {e}"}
            return det, diag

        self._run_task(task, self._detect_done, button=self.detect_btn)

    def _detect_done(self, result):
        det, diag = result
        lines = []
        lines.append(f"Lenovo firmware detected: {'YES' if det['is_lenovo'] else 'no'}")
        ce = det["ce_backdoor"]
        if ce["guid_hits"] or ce["string_hits"]:
            lines.append(
                f"cE! runtime backdoor: {len(ce['guid_hits'])} GUID hit(s), "
                f"{len(ce['string_hits'])} string hit(s) -> the H2O runtime "
                "unlocker method applies to this machine"
            )
        else:
            lines.append(f"Supervisor password storage: {diag['message']}")
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
        self._run_task(
            lambda: self.patcher.scan(self.current_dump),
            self._scan_done,
            button=self.scan_btn,
        )

    def _scan_done(self, results):
        self._scan_results = results
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
        out = derived_path(self.current_dump, "_patched.bin")
        if not confirm_overwrite(self, out):
            return
        path = self.current_dump

        def task():
            try:
                return self.patcher.apply(path, out, group_keys=sel)
            except UEFIPatchError as e:
                return {"error": str(e)}

        self._run_task(task, self._patches_done, button=self.apply_btn)

    def _patches_done(self, report):
        if "error" in report:
            QMessageBox.critical(self, "Patch Failed", report["error"])
            return
        if not report.get("output_path"):
            self._log("Nothing written: no pattern patch changed the image.")
            for msg in report["messages"]:
                self._log(f"  {msg}")
            QMessageBox.warning(
                self,
                "Nothing Applied",
                "No pattern patch changed the image, so no file was written.",
            )
            return
        out = report["output_path"]
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
        for i, e in enumerate(self._dxe_entries):
            self.dxe_table.insertRow(i)
            chk = QTableWidgetItem()
            chk.setFlags(chk.flags() | Qt.ItemIsUserCheckable)
            chk.setCheckState(Qt.Unchecked)
            self.dxe_table.setItem(i, 0, chk)
            bin_path = self.patcher.dxe_binary_path(e["file"])
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
        out = derived_path(self.current_dump, "_dxe.bin")
        if not confirm_overwrite(self, out):
            return
        path = self.current_dump

        def task():
            return self._apply_dxe_chain(path, out, sel)

        self._run_task(task, self._dxe_done, button=self.dxe_apply_btn)

    def _apply_dxe_chain(self, path, out, sel):
        """Replace each selected driver in turn. Each step reads the previous result."""
        work = path
        applied = []
        log = []
        for e in sel:
            bin_path = self.patcher.dxe_binary_path(e["file"])
            if not os.path.exists(bin_path):
                log.append(f"skip {e['key']}: binary missing ({e['file']})")
                continue
            nxt = out + ".tmp"
            res = self.patcher.replace_ffs_file(work, nxt, e["target_guid"], bin_path)
            if res["success"]:
                os.replace(nxt, out)
                log.append(
                    f"{e['key']}: replaced {e['target_guid']} "
                    f"({res['old_size']} -> {res['new_size']} bytes)"
                )
                work = out
                applied.append(e["key"])
            else:
                log.append(f"{e['key']} FAILED: {res['message']}")
        return {"applied": applied, "output": out if applied else "", "log": log}

    def _dxe_done(self, result):
        for line in result["log"]:
            self._log(line)
        if result["output"]:
            QMessageBox.information(
                self,
                "Drivers Replaced",
                f"{len(result['applied'])} replacement(s) applied.\nOutput: {result['output']}",
            )
        else:
            QMessageBox.warning(
                self, "Nothing Applied", "No replacements were applied; no file was written."
            )

    def run_full_autopatch(self):
        if not self._require_file():
            return
        if not self.dxe_consent.isChecked():
            QMessageBox.warning(
                self, "Consent Required", "Tick the consent box before running the autopatch."
            )
            return
        out = derived_path(self.current_dump, "_autopatched.bin")
        if not confirm_overwrite(self, out):
            return
        path = self.current_dump

        def task():
            try:
                return self.patcher.run_autopatch(path, out)
            except Exception as e:
                return {"error": str(e)}

        self._run_task(task, self._autopatch_done, button=self.autopatch_btn)

    def _autopatch_done(self, report):
        if "error" in report:
            QMessageBox.critical(self, "Autopatch Failed", report["error"])
            return
        for s in report["steps"]:
            tag = "OK " if s["ok"] else ("SKIP" if s.get("skipped") else "FAIL")
            self._log(f"[{tag}] {s['step']}: {s['message']}")
        if not report.get("output_path"):
            QMessageBox.warning(
                self,
                "Autopatch Not Applied",
                "No step changed the image, so no patched file was written.",
            )
            return
        if not report["success"]:
            QMessageBox.warning(
                self,
                "Autopatch Partly Applied",
                "Some steps failed or were skipped. The patched file below contains only the "
                "steps that succeeded; see the log.\n\n" + report["output_path"],
            )
            return
        QMessageBox.information(
            self,
            "Autopatch Complete",
            "Patched image written to:\n" + report["output_path"] + "\n\n[ HOW TO USE THE PATCH ]\n"
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
        # The loaded file is the original; only the autopatched output is picked.
        orig = self.current_dump
        if not orig:
            QMessageBox.warning(self, "No Original", "Open the original dump first (File > Open).")
            return
        patched, _ = QFileDialog.getOpenFileName(
            self, "Autopatched dump", "", "Binary (*.bin);;All Files (*)"
        )
        if not patched:
            return
        outdir = QFileDialog.getExistingDirectory(self, "Where to store extracted drivers")
        if not outdir:
            return
        self._run_task(
            lambda: self.patcher.derive_replacements(orig, patched, outdir),
            self._derive_done,
            button=self.derive_btn,
        )

    def _derive_done(self, derived):
        if not derived:
            QMessageBox.information(
                self, "No Differences", "No replaced files found between the two dumps."
            )
            return
        try:
            added = self.patcher.add_user_dxe_replacements(derived)
        except OSError as e:
            QMessageBox.critical(
                self,
                "Derive: registry not saved",
                f"The drivers were extracted, but the registry could not be saved:\n{e}",
            )
            return
        self._reload_dxe_registry()
        self._log(
            f"Derived {len(derived)} replacement(s) from the dump pair; "
            f"{len(added)} new registry entr{'y' if len(added) == 1 else 'ies'} saved."
        )
