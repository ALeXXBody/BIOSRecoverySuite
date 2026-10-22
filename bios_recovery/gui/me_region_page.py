"""ME Region page: inspect, clean, repair and verify the Intel ME region.

One image serves every action: the file loaded in the window. Each action appends a
headed section to one output pane, so the results of inspecting, cleaning, injecting
and verifying can be compared without switching pages.

Nothing here writes over the loaded file. Cleaning, injecting and verifying write or
read separate files, and the engines refuse an output path that is the input.
"""

from __future__ import annotations

import os
from typing import Callable, Optional

from PySide6.QtWidgets import (
    QCheckBox,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from bios_recovery.core.rebuild_verify import describe, verify_rebuild
from bios_recovery.gui.outputs import confirm_overwrite, derived_path
from bios_recovery.platforms.intel.me.fit_check import check_image as check_tools
from bios_recovery.platforms.intel.me.me_cleaner import IntelMECleaner
from bios_recovery.platforms.intel.me.me_injector import MEInjector


def _run_inline(task, on_done, button=None):
    on_done(task())


class MERegionPage(QWidget):
    def __init__(
        self,
        image_provider: Callable[[], Optional[str]],
        run_task: Optional[Callable] = None,
        parent=None,
    ):
        super().__init__(parent)
        self._image = image_provider
        self._run_task = run_task or _run_inline
        self.cleaner = IntelMECleaner()
        self.injector = MEInjector()
        self._build()

    # -- layout -----------------------------------------------------------------
    def _build(self):
        root = QVBoxLayout(self)

        inspect_row = QHBoxLayout()
        self.info_btn = QPushButton("Show ME Info")
        self.info_btn.clicked.connect(self.show_info)
        inspect_row.addWidget(self.info_btn)
        self.check_btn = QPushButton("Check Tools For This Image")
        self.check_btn.clicked.connect(self.check_tools)
        inspect_row.addWidget(self.check_btn)
        root.addLayout(inspect_row)

        clean_group = QGroupBox("Clean ME region")
        clean_layout = QVBoxLayout(clean_group)
        options = QHBoxLayout()
        self.soft_disable = QCheckBox("Set HAP/AltMeDisable bit (soft disable)")
        self.soft_disable.setChecked(True)
        self.remove_modules = QCheckBox("Remove non-essential modules")
        self.remove_modules.setChecked(True)
        self.lock_descriptor = QCheckBox("Lock descriptor (remove ME write access)")
        self.truncate = QCheckBox("Truncate empty ME space")
        for box in (self.soft_disable, self.remove_modules, self.lock_descriptor, self.truncate):
            options.addWidget(box)
        clean_layout.addLayout(options)
        self.clean_btn = QPushButton("Clean ME Region (writes a _cleaned file)")
        self.clean_btn.clicked.connect(self.clean)
        clean_layout.addWidget(self.clean_btn)
        root.addWidget(clean_group)

        repair_group = QGroupBox("Repair: inject a clean ME of the same version")
        repair_layout = QVBoxLayout(repair_group)
        repair_layout.addWidget(
            QLabel(
                "Uses the clean ME image for this ME version from your library. If there is "
                "none, you are asked to choose one, and it is added to the library."
            )
        )
        self.inject_btn = QPushButton("Inject Clean ME (writes a _mefixed file)")
        self.inject_btn.clicked.connect(self.inject)
        repair_layout.addWidget(self.inject_btn)
        root.addWidget(repair_group)

        verify_group = QGroupBox("Verify a rebuilt image against the loaded image")
        verify_layout = QVBoxLayout(verify_group)
        verify_row = QHBoxLayout()
        self.rebuilt_edit = QLineEdit()
        self.rebuilt_edit.setPlaceholderText("Path to the rebuilt image")
        verify_row.addWidget(self.rebuilt_edit, 1)
        browse_rebuilt = QPushButton("Browse...")
        browse_rebuilt.clicked.connect(self._browse_rebuilt)
        verify_row.addWidget(browse_rebuilt)
        verify_layout.addLayout(verify_row)
        self.verify_btn = QPushButton("Verify")
        self.verify_btn.clicked.connect(self.verify)
        verify_layout.addWidget(self.verify_btn)
        root.addWidget(verify_group)

        output_head = QHBoxLayout()
        output_head.addWidget(QLabel("Results"))
        output_head.addStretch(1)
        clear_btn = QPushButton("Clear")
        clear_btn.clicked.connect(lambda: self.output.clear())
        output_head.addWidget(clear_btn)
        root.addLayout(output_head)
        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        self.output.setMinimumHeight(180)
        root.addWidget(self.output, 1)

    # -- shared state -----------------------------------------------------------
    def _current(self) -> Optional[str]:
        path = self._image()
        if not path:
            self._report("No image", ["Open a BIOS file first (File > Open)."])
            return None
        return path

    def _report(self, title: str, lines) -> None:
        self.output.appendPlainText(f"== {title} ==")
        self.output.appendPlainText("\n".join(lines))
        self.output.appendPlainText("")

    def _for_image(self, path: str, lines) -> list:
        """A result that finished after another image was loaded says so, and names its image."""
        if self._image() == path:
            return list(lines)
        return [f"(for {os.path.basename(path)}; a different image is loaded now)", *lines]

    # -- actions ----------------------------------------------------------------
    def show_info(self):
        path = self._current()
        if not path:
            return

        def done(info):
            self._report("ME info", self._for_image(path, _format_me_info(info)))

        self._run_task(lambda: self.cleaner.get_me_info(path), done, button=self.info_btn)

    def check_tools(self):
        path = self._current()
        if not path:
            return
        self._run_task(
            lambda: check_tools(path),
            lambda report: self._report(
                "Tools for this image", self._for_image(path, report.lines())
            ),
            button=self.check_btn,
        )

    def clean(self):
        path = self._current()
        if not path:
            return
        output = derived_path(path, "_cleaned.bin")
        if not confirm_overwrite(self, output):
            return
        options = (
            self.soft_disable.isChecked(),
            self.truncate.isChecked(),
            self.remove_modules.isChecked(),
            self.lock_descriptor.isChecked(),
        )

        def done(report):
            self._report("Clean ME", self._for_image(path, _format_clean(report)))

        self._run_task(
            lambda: self.cleaner.clean(path, output, *options),
            done,
            button=self.clean_btn,
        )

    def inject(self):
        path = self._current()
        if not path:
            return
        self._run_task(
            lambda: _library_lookup(path),
            lambda info: self._choose_clean_me(path, info),
            button=self.inject_btn,
        )

    def _choose_clean_me(self, path: str, info: dict):
        version = info["version"]
        if not version:
            self._report("Inject clean ME", ["No ME version could be read from the loaded image."])
            return
        if info["matches"]:
            source = info["matches"][0]
            if len(info["matches"]) == 1:
                answer = QMessageBox.question(
                    self,
                    "Inject clean ME",
                    f"Use this library image for ME {version}?\n{source}",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No,
                )
                if answer != QMessageBox.StandardButton.Yes:
                    self._report("Inject clean ME", ["Cancelled; nothing done."])
                    return
            if len(info["matches"]) > 1:
                names = [f"{os.path.basename(m)}  ({m})" for m in info["matches"]]
                choice, ok = QInputDialog.getItem(
                    self,
                    "Choose clean ME",
                    f"{len(names)} library images match ME {version}. Use which one?",
                    names,
                    0,
                    False,
                )
                if not ok:
                    self._report("Inject clean ME", ["Cancelled; nothing done."])
                    return
                source = info["matches"][names.index(choice)]
            self._inject_from(path, source, f"from the library: {source}")
            return
        chosen, _ = QFileDialog.getOpenFileName(
            self,
            f"No clean ME {version} in the library - choose one (it will be added)",
            "",
            "Binary (*.bin);;All Files (*)",
        )
        if not chosen:
            self._report(
                "Inject clean ME", [f"No clean ME {version} in the library; nothing done."]
            )
            return
        from bios_recovery.core import user_library as lib

        result = lib.import_files([chosen], "firmware")[0]
        if result.refused:
            self._report("Inject clean ME", [f"Not added to the library: {result.refused}."])
            return
        with open(result.copied_to, "rb") as f:
            added = lib.dominant_me_version(f.read())
        if added != version:
            self._report(
                "Inject clean ME",
                [
                    f"Added to the library as {os.path.basename(result.copied_to)} (ME {added}), "
                    f"but the loaded image is ME {version}. Nothing was injected."
                ],
            )
            return
        self._inject_from(path, result.copied_to, "added to the library and used")

    def _inject_from(self, path: str, source: str, note: str):
        output = derived_path(path, "_mefixed.bin")
        if not confirm_overwrite(self, output):
            return

        def done(result):
            if result["success"]:
                self._report(
                    "Inject clean ME",
                    self._for_image(path, [result["message"], f"Source: {note}"]),
                )
            else:
                QMessageBox.warning(self, "Inject Failed", result["message"])

        self._run_task(
            lambda: self.injector.inject(path, source, output),
            done,
            button=self.inject_btn,
        )

    def verify(self, rebuilt: Optional[str] = None, on_done=None):
        path = self._current()
        if not path:
            return
        candidate = (rebuilt if rebuilt is not None else self.rebuilt_edit.text()).strip()
        if not candidate:
            self._report("Verify", ["Choose the rebuilt image first."])
            return

        def done(result):
            self._report("Verify", self._for_image(path, describe(result)))
            if on_done:
                on_done(result)

        self._run_task(lambda: verify_rebuild(path, candidate), done, button=self.verify_btn)

    # -- dialogs ----------------------------------------------------------------
    def _browse_rebuilt(self):
        path, _ = QFileDialog.getOpenFileName(self, "Choose rebuilt image", "", "All files (*)")
        if path:
            self.rebuilt_edit.setText(path)


def _library_lookup(path: str) -> dict:
    """Read the loaded image's ME version and find library images that match it."""
    from bios_recovery.core import user_library as lib

    with open(path, "rb") as f:
        version = lib.dominant_me_version(f.read())
    return {"version": version, "matches": lib.firmware_for_version(version)}


def _format_me_info(info) -> list:
    if not info.get("found"):
        return [info.get("reason") or "No Intel ME region found in this image."]
    lines = [
        f"ME Version: {info.get('version', 'Unknown')}",
        f"ME Type: {info.get('type', 'Unknown')}",
        f"Generation: {info.get('generation', 'Unknown')}",
        f"Offset: {info.get('offset', '0x0')}",
        f"Size: {info.get('size', '0x0')}",
        "",
        "Partitions:",
    ]
    for p in info.get("partitions", []):
        lines.append(f"  {p['name']}: offset {p['offset']}, size {p['size']}")
    return lines


def _format_clean(report) -> list:
    lines = [
        f"Status: {report.status.name}",
        f"ME Version: {report.me_version}",
        f"ME Type: {report.me_type}",
        f"Original Size: {report.original_size:#x}",
        f"Cleaned Size: {report.cleaned_size:#x}",
        f"Partitions Removed: {report.partitions_removed}",
        f"HAP Bit Set: {report.hap_bit_set}",
        f"Output: {report.output_path}",
    ]
    lines.extend(f"  - {msg}" for msg in report.messages)
    return lines
