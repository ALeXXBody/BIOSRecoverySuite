"""Settings page: the user's own Intel tool and ME firmware folders.

The app ships no Intel tools or ME firmware. The user points the app at folders
where they keep their own copies (subfolders are searched), or imports files
into the app's own library folder. Scanning runs in the background.
"""

from __future__ import annotations

import os

from PySide6.QtWidgets import (
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QListWidget,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from bios_recovery.core import user_library as lib

DISCLAIMER = (
    "BIOS Recovery Suite does not include Intel tools or ME firmware, and it never "
    "downloads them. Add the folders where you keep your own copies; subfolders are "
    "searched. Files stay where they are unless you import them."
)


def _run_inline(task, on_done, button=None):
    on_done(task())


class SettingsPage(QWidget):
    def __init__(self, parent=None, run_task=None):
        super().__init__(parent)
        self._run_task = run_task or _run_inline
        self._build()
        self.refresh_folders()

    # -- layout ----------------------------------------------------------------
    def _build(self):
        root = QVBoxLayout(self)
        title = QLabel("Settings: Intel tools and ME firmware")
        title.setStyleSheet("font-weight: bold; font-size: 14px;")
        root.addWidget(title)
        note = QLabel(DISCLAIMER)
        note.setWordWrap(True)
        note.setStyleSheet("color: #AAA;")
        root.addWidget(note)

        self.tools_list = QListWidget()
        self.firmware_list = QListWidget()
        root.addWidget(
            self._folder_group(
                "Intel tools folders (Flash Image Tool / MFIT)",
                "tools",
                self.tools_list,
                "Import tool files…",
            )
        )
        root.addWidget(
            self._folder_group(
                "ME firmware folders", "firmware", self.firmware_list, "Import firmware files…"
            )
        )

        scan_box = QGroupBox("Scan")
        scan_layout = QVBoxLayout(scan_box)
        row = QHBoxLayout()
        self.scan_button = QPushButton("Scan folders")
        self.scan_button.clicked.connect(lambda: self.start_scan())
        row.addWidget(self.scan_button)
        self.identify_button = QPushButton("Identify selected tool (runs it once)")
        self.identify_button.setToolTip(
            "Scanning only lists files. Identifying runs the selected tool once with -h, "
            "so only do this for tools you trust."
        )
        self.identify_button.clicked.connect(self.identify_selected)
        row.addWidget(self.identify_button)
        self.scan_status = QLabel("Not scanned yet.")
        row.addWidget(self.scan_status, 1)
        scan_layout.addLayout(row)

        self.tools_table = self._table(["Tool", "Version", "Platform", "Release line", "Path"])
        self.tools_table.itemSelectionChanged.connect(self._update_identify_state)
        self.firmware_table = self._table(["ME version", "Size", "Path"])
        scan_layout.addWidget(QLabel("Tools found"))
        scan_layout.addWidget(self.tools_table)
        scan_layout.addWidget(QLabel("ME firmware found"))
        scan_layout.addWidget(self.firmware_table)
        root.addWidget(scan_box, 1)

    def _folder_group(self, title, kind, listwidget, import_label):
        box = QGroupBox(title)
        layout = QVBoxLayout(box)
        layout.addWidget(listwidget)
        row = QHBoxLayout()
        add = QPushButton("Add folder…")
        add.clicked.connect(lambda: self._choose_folder(kind))
        remove = QPushButton("Remove selected")
        remove.clicked.connect(lambda: self._remove_selected(kind, listwidget))
        imp = QPushButton(import_label)
        imp.clicked.connect(lambda: self._choose_files(kind))
        for b in (add, remove, imp):
            row.addWidget(b)
        row.addStretch(1)
        layout.addLayout(row)
        return box

    def _table(self, headers):
        table = QTableWidget(0, len(headers))
        table.setMinimumHeight(170)
        table.setHorizontalHeaderLabels(headers)
        table.horizontalHeader().setSectionResizeMode(len(headers) - 1, QHeaderView.Stretch)
        table.setEditTriggers(QTableWidget.NoEditTriggers)
        return table

    # -- actions (testable without dialogs) -------------------------------------
    def refresh_folders(self):
        cfg = lib.load_library()
        self.tools_list.clear()
        self.tools_list.addItems(cfg.tools_folders or ["(none added)"])
        self.firmware_list.clear()
        self.firmware_list.addItems(cfg.firmware_folders or ["(none added)"])

    def add_folder(self, kind: str, path: str):
        lib.add_folder(path, kind)
        self.refresh_folders()

    def remove_folder(self, kind: str, path: str):
        lib.remove_folder(path, kind)
        self.refresh_folders()

    def import_files(self, kind: str, paths: list):
        results = lib.import_files(paths, kind)
        self.refresh_folders()
        return results

    def start_scan(self, on_done=None):
        self.scan_status.setText("Scanning…")

        def finished(result):
            self._show_result(result)
            if on_done:
                on_done(result)

        self._run_task(lib.scan, finished, button=self.scan_button)

    def _show_result(self, result):
        self.tools_table.setRowCount(0)
        for t in result.tools:
            self._add_row(
                self.tools_table, [t.family, t.version or "-", t.platform, t.release, t.path]
            )
        self._update_identify_state()
        self.firmware_table.setRowCount(0)
        for f in result.firmware:
            self._add_row(self.firmware_table, [f.me_version, f"{f.size:,} bytes", f.path])
        if not result.folders:
            self.scan_status.setText("No folders yet. Add one above.")
        else:
            self.scan_status.setText(
                f"{len(result.tools)} tool(s), {len(result.firmware)} firmware image(s) "
                f"in {len(result.folders)} folder(s)."
            )

    def _selected_tool_path(self):
        rows = self.tools_table.selectionModel().selectedRows()
        if not rows:
            return None
        item = self.tools_table.item(rows[0].row(), 4)
        return item.text() if item else None

    def _update_identify_state(self):
        path = self._selected_tool_path()
        family = None
        if path:
            family = self.tools_table.item(
                self.tools_table.selectionModel().selectedRows()[0].row(), 0
            ).text()
        self.identify_button.setEnabled(bool(path) and family == "unidentified")

    def identify_selected(self, on_done=None):
        path = self._selected_tool_path()
        if not path:
            return
        self.scan_status.setText("Identifying (running the tool once)...")

        def finished(probe):
            if probe.identified:
                self.scan_status.setText(f"Identified: {probe.family} {probe.version}")
            else:
                self.scan_status.setText(f"Not identified: {probe.error}")
            if on_done:
                on_done(probe)
            self.start_scan()

        self._run_task(lambda: lib.identify_tool(path), finished, button=self.identify_button)

    @staticmethod
    def _add_row(table, values):
        row = table.rowCount()
        table.insertRow(row)
        for col, value in enumerate(values):
            table.setItem(row, col, QTableWidgetItem(str(value)))

    # -- dialogs ----------------------------------------------------------------
    def _choose_folder(self, kind):
        folder = QFileDialog.getExistingDirectory(self, "Choose folder")
        if folder:
            try:
                self.add_folder(kind, folder)
            except ValueError as exc:
                self.scan_status.setText(str(exc))

    def _remove_selected(self, kind, listwidget):
        item = listwidget.currentItem()
        if item is None or item.text() == "(none added)":
            return
        self.remove_folder(kind, item.text())

    def _choose_files(self, kind):
        paths, _ = QFileDialog.getOpenFileNames(self, "Choose files to import", "", "All files (*)")
        if not paths:
            return
        self._run_task(lambda: lib.import_files(paths, kind), self._import_done)

    def _import_done(self, results):
        self.refresh_folders()
        refused = [f"{os.path.basename(r.source)}: {r.refused}" for r in results if r.refused]
        copied = [r for r in results if r.copied_to]
        self.scan_status.setText(
            f"Imported {len(copied)} file(s)."
            + (" Refused: " + "; ".join(refused) if refused else "")
        )
