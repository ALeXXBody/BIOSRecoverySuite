"""Main application window for BIOS Recovery Suite."""

import os
import sys
import threading
from typing import Optional

from PySide6.QtWidgets import (
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QTabWidget,
    QFrame,
    QGridLayout,
    QToolButton,
    QPushButton,
    QLabel,
    QFileDialog,
    QMessageBox,
    QProgressBar,
    QTextEdit,
    QStatusBar,
    QLineEdit,
    QComboBox,
    QCheckBox,
    QTableWidget,
    QTableWidgetItem,
    QGroupBox,
    QListWidget,
    QListWidgetItem,
    QPlainTextEdit,
    QSplitter,
    QToolBar,
)
from PySide6.QtCore import Qt, QThread, Signal, QObject, QTimer
from PySide6.QtGui import QIcon

from bios_recovery.core.bios_analyzer import BiosAnalyzer, BiosType
from bios_recovery.platforms.intel.me.me_cleaner import IntelMECleaner
from bios_recovery.core.dmi_extractor import DMIExtractor
from bios_recovery.core.password_remover import PasswordRemover
from bios_recovery.core.bios_repair import BiosRepairEngine
from bios_recovery.manufacturers.common.bios_extractor import BiosExtractor
from bios_recovery.manufacturers.hp.hp_unlocker import HPUnlocker
from bios_recovery.platforms.intel.me.me_injector import MEInjector
from bios_recovery.core.dmi_clone import DMIClone
from bios_recovery.utils import master_passwords
from bios_recovery.manufacturers.profiles import ManufacturerProfiles, Manufacturer
from bios_recovery.gui.sidebar_tabs import SidebarTabs
from bios_recovery.gui.spi_tab import SPITab
from bios_recovery.gui.ec_tab import ECTab
from bios_recovery.gui.lenovo_tab import LenovoTab
from bios_recovery.gui.update_dialog import UpdateDialog, CheckWorker
from bios_recovery import __version__
from bios_recovery.platforms.intel.me import mea_bridge


class WorkerThread(QThread):
    """Runs a task in a background thread."""
    finished = Signal(object)
    error = Signal(str)
    progress = Signal(int, str)

    def __init__(self, task, *args, **kwargs):
        super().__init__()
        self.task = task
        self.args = args
        self.kwargs = kwargs

    def run(self):
        try:
            result = self.task(*self.args, **self.kwargs)
            self.finished.emit(result)
        except Exception as e:
            self.error.emit(str(e))


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("BIOS Recovery Suite")
        self.resize(1200, 800)
        self.setMinimumSize(900, 600)

        self.bios_analyzer = BiosAnalyzer()
        self.me_cleaner = IntelMECleaner()
        self.dmi_extractor = DMIExtractor()
        self.password_remover = PasswordRemover()
        self.repair_engine = BiosRepairEngine()
        self.bios_extractor = BiosExtractor()
        self.hp_unlocker = HPUnlocker()
        self.me_injector = MEInjector()
        self.dmi_clone = DMIClone()
        self.manufacturer_profiles = ManufacturerProfiles()

        self.current_file = None
        self.current_bios_info = None
        self._threads = []

        self._build_ui()
        self.setWindowIcon(self._app_icon())
        self.statusBar().showMessage("Ready - Open a BIOS file to begin")
        QTimer.singleShot(3000, self._auto_update_check)

    def _app_icon(self) -> QIcon:
        candidates = []
        if getattr(sys, "frozen", False):
            base = getattr(sys, "_MEIPASS", os.path.dirname(sys.executable))
            candidates.append(os.path.join(base, "assets", "icon.png"))
            candidates.append(os.path.join(os.path.dirname(sys.executable), "assets", "icon.png"))
        else:
            root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            candidates.append(os.path.join(root, "assets", "icon.png"))
        for c in candidates:
            if os.path.exists(c):
                return QIcon(c)
        return QIcon()

    def _auto_update_check(self):
        """Quiet startup check - only surfaces a dialog when an update exists."""
        self._update_worker = CheckWorker()
        self._update_worker.found.connect(self._show_update_dialog)
        self._update_worker.start()

    def _show_update_dialog(self, release):
        self._update_dialog = UpdateDialog(self)
        self._update_dialog.present_release(release)
        self._update_dialog.show()
        self._update_dialog.raise_()

    def check_for_updates(self):
        self._update_dialog = UpdateDialog(self)
        self._update_dialog.exec()

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)

        header = QHBoxLayout()
        self.open_btn = QPushButton("Open BIOS File")
        self.open_btn.clicked.connect(self.open_file)
        header.addWidget(self.open_btn)

        self.file_label = QLabel("No file loaded")
        self.file_label.setStyleSheet("color: #AAA;")
        header.addWidget(self.file_label, 1)

        self.platform_badge = QLabel("")
        self.platform_badge.setStyleSheet(
            "background: #313244; color: #CDD6F4; padding: 3px 10px; "
            "border-radius: 4px; font-weight: bold;"
        )
        self.platform_badge.setVisible(False)
        header.addWidget(self.platform_badge)

        self.analyze_btn = QPushButton("Analyze")
        self.analyze_btn.clicked.connect(self.run_analysis)
        header.addWidget(self.analyze_btn)
        layout.addLayout(header)

        self.tabs = SidebarTabs()
        layout.addWidget(self.tabs, 1)

        self.main_tab = self._build_main_tab()
        self.repair_tab = self._build_repair_tab()
        self.me_tab = self._build_me_tab()
        self.dmi_tab = self._build_dmi_tab()
        self.password_tab = self._build_password_tab()
        self.extract_tab = self._build_extract_tab()
        self.hex_tab = self._build_hex_tab()
        self.spi_tab = SPITab(self)
        self.ec_tab = ECTab(self)
        self.lenovo_tab = LenovoTab(self)

        self.tabs.addTab(self.main_tab, "Overview")
        self.tabs.addTab(self.repair_tab, "Repair")
        self.tabs.addTab(self.ec_tab, "EC Patching")
        self.tabs.addTab(self.me_tab, "ME Cleaner")
        self.tabs.addTab(self.dmi_tab, "DMI")
        self.tabs.addTab(self.password_tab, "Security")
        self.tabs.addTab(self.extract_tab, "Extract")
        self.tabs.addTab(self.spi_tab, "SPI Flasher")
        self.tabs.addTab(self.hex_tab, "Hex Viewer")
        self.tabs.addTab(self.lenovo_tab, "Lenovo Unlock")

        self._build_menubar()

    def _build_menubar(self):
        menubar = self.menuBar()
        file_menu = menubar.addMenu("&File")
        file_menu.addAction("&Open BIOS File...", self.open_file)
        file_menu.addSeparator()
        file_menu.addAction("E&xit", self.close)

        tool_menu = menubar.addMenu("&Tools")
        tool_menu.addAction("Run &Analysis", self.run_analysis)
        tool_menu.addAction("&Repair BIOS", lambda: self.tabs.setCurrentWidget(self.repair_tab))
        tool_menu.addAction("&Clean ME", lambda: self.tabs.setCurrentWidget(self.me_tab))
        tool_menu.addAction("&Extract DMI", lambda: self.tabs.setCurrentWidget(self.dmi_tab))
        tool_menu.addAction("Remove &Passwords", lambda: self.tabs.setCurrentWidget(self.password_tab))
        tool_menu.addAction("SPI &Flasher", lambda: self.tabs.setCurrentWidget(self.spi_tab))
        tool_menu.addAction("&EC Patching", lambda: self.tabs.setCurrentWidget(self.ec_tab))
        tool_menu.addAction("&Lenovo Unlock", lambda: self.tabs.setCurrentWidget(self.lenovo_tab))
        tool_menu.addAction("&ME Analyzer", self.run_mea_analysis)

        help_menu = menubar.addMenu("&Help")
        help_menu.addAction("&Check for Updates...", self.check_for_updates)
        help_menu.addAction("&About", self.show_about)

    def _build_main_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)

        self.info_text = QPlainTextEdit()
        self.info_text.setReadOnly(True)
        self.info_text.setMaximumHeight(200)

        cards = QGridLayout()
        cards.setSpacing(8)
        self._cards = {}
        for col, title in enumerate(("File", "Platform", "Firmware", "Issues")):
            frame = QFrame()
            frame.setObjectName("overviewCard")
            frame.setStyleSheet(
                "QFrame#overviewCard { background: #252537; border: 1px solid #313244; border-radius: 8px; }"
                " QFrame#overviewCard QLabel { background: transparent; }"
            )
            card_layout = QVBoxLayout(frame)
            card_layout.setContentsMargins(12, 8, 12, 8)
            heading = QLabel(title.upper())
            heading.setStyleSheet("color: #7F849C; font-size: 11px; font-weight: bold;")
            body = QLabel("—")
            body.setTextFormat(Qt.RichText)
            body.setWordWrap(True)
            body.setStyleSheet("font-size: 14px;")
            card_layout.addWidget(heading)
            card_layout.addWidget(body)
            card_layout.addStretch(1)
            cards.addWidget(frame, 0, col)
            self._cards[title] = body
        layout.addLayout(cards)

        caps_layout = QHBoxLayout()
        self.capsule_btn = QPushButton("Capsule → Flashable Image")
        self.capsule_btn.setToolTip(
            "Strip the Aptio capsule header (.CAP/.308/.217) and write the bare "
            "flash image, ready to burn to the SPI chip with an external programmer."
        )
        self.capsule_btn.clicked.connect(self.build_flashable_image)
        caps_layout.addWidget(self.capsule_btn)
        self.capsule_merge_btn = QPushButton("Merge Dump onto Capsule")
        self.capsule_merge_btn.setToolTip(
            "Build a flashable image from the capsule and restore machine NVRAM "
            "records (serials etc.) from a saved dump."
        )
        self.capsule_merge_btn.clicked.connect(self.build_flashable_merged)
        caps_layout.addWidget(self.capsule_merge_btn)
        caps_layout.addStretch(1)
        layout.addLayout(caps_layout)

        regions_group = QGroupBox("Detected Regions")
        regions_layout = QVBoxLayout(regions_group)
        self.regions_table = QTableWidget(0, 4)
        self.regions_table.setHorizontalHeaderLabels(["Region", "Type", "Offset", "Size"])
        self.regions_table.horizontalHeader().setStretchLastSection(True)
        regions_layout.addWidget(self.regions_table)
        layout.addWidget(regions_group, 1)

        self.main_status = QLabel("")
        layout.addWidget(self.main_status)

        layout.addWidget(self._collapsible("Full report", self.info_text))
        layout.addWidget(self._collapsible("Platform classification", self._build_platform_tab()))

        return widget

    def _collapsible(self, title, content):
        box = QWidget()
        box_layout = QVBoxLayout(box)
        box_layout.setContentsMargins(0, 0, 0, 0)
        toggle = QToolButton()
        toggle.setText(f"▸ {title}")
        toggle.setCheckable(True)
        toggle.setStyleSheet("QToolButton { color: #7F849C; font-weight: bold; padding: 4px 0; border: none; }")
        content.setVisible(False)

        def on_toggled(checked):
            toggle.setText(f"{'▾' if checked else '▸'} {title}")
            content.setVisible(checked)

        toggle.toggled.connect(on_toggled)
        box_layout.addWidget(toggle)
        box_layout.addWidget(content)
        return box

    def _update_overview_cards(self, result, traits):
        size_mb = result.file_size / 0x100000
        self._cards["File"].setText(
            f"<span style='color:#7F849C;font-size:11px'>Size</span><br>"
            f"<b>{size_mb:.2f} MB</b><br>"
            f"<span style='color:#7F849C;font-size:11px'>SHA256</span><br>"
            f"<b>{(result.sha256 or '')[:16]}…</b>"
        )
        self._cards["Platform"].setText(
            f"<span style='color:#7F849C;font-size:11px'>Architecture</span><br>"
            f"<b>{traits.architecture.upper()}</b><br>"
            f"<span style='color:#7F849C;font-size:11px'>Vendor</span><br>"
            f"<b>{traits.vendor}</b>"
        )
        if result.me_version:
            me = result.me_version
        elif result.has_me_region:
            me = "present (version unknown)"
        else:
            me = "not present"
        self._cards["Firmware"].setText(
            f"<span style='color:#7F849C;font-size:11px'>Regions</span><br>"
            f"<b>{sum(1 for r in result.regions if r.region_type.name == 'FIRMWARE_VOLUME')} firmware volumes</b><br>"
            f"<span style='color:#7F849C;font-size:11px'>ME</span><br>"
            f"<b>{me}</b>"
        )
        issues = result.issues or []
        first = issues[0] if issues else "none"
        self._cards["Issues"].setText(
            f"<span style='color:#7F849C;font-size:11px'>Open</span><br>"
            f"<b>{len(issues)}</b> — {first}"
        )

    def _build_platform_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)

        header = QLabel("Platform Classification (Traits Matrix)")
        header.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(header)

        desc = QLabel(
            "The app classifies the loaded image once on load, then both the GUI "
            "and the CLI consult the same tool matrix. Tools that don't apply are "
            "greyed out with an explicit reason — no more offering Intel ME tools "
            "on an AMD machine."
        )
        desc.setWordWrap(True)
        desc.setStyleSheet("color: #AAA;")
        layout.addWidget(desc)

        self.platform_info = QPlainTextEdit()
        self.platform_info.setReadOnly(True)
        self.platform_info.setMaximumHeight(120)
        layout.addWidget(self.platform_info)

        self.traits_table = QTableWidget(0, 3)
        self.traits_table.setHorizontalHeaderLabels(["Tool", "Applies?", "Reason"])
        self.traits_table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.traits_table, 1)

        return widget

    def _build_repair_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)

        file_row = QHBoxLayout()
        file_row.addWidget(QLabel("File:"))
        self.repair_file = QLineEdit()
        self.repair_file.setReadOnly(True)
        file_row.addWidget(self.repair_file, 1)
        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self.open_file)
        file_row.addWidget(browse_btn)
        layout.addLayout(file_row)

        options_group = QGroupBox("Repair Options")
        options_layout = QVBoxLayout(options_group)
        me_hint = QLabel("ME region cleaning is done on the ME Cleaner page, with its own options.")
        me_hint.setStyleSheet("color: #7F849C;")
        options_layout.addWidget(me_hint)
        self.repair_checksum_ck = QCheckBox("Fix FPT Checksum")
        self.repair_checksum_ck.setChecked(True)
        self.repair_size_ck = QCheckBox("Verify Size Alignment")
        self.repair_size_ck.setChecked(True)
        self.repair_password_ck = QCheckBox("Also clear BIOS password structures")
        self.repair_password_ck.setChecked(True)
        options_layout.addWidget(self.repair_checksum_ck)
        options_layout.addWidget(self.repair_size_ck)
        options_layout.addWidget(self.repair_password_ck)
        layout.addWidget(options_group)

        self.repair_btn = QPushButton("Run Auto Repair")
        self.repair_btn.clicked.connect(self.run_repair)
        layout.addWidget(self.repair_btn)

        graft_row = QHBoxLayout()
        self.graft_btn = QPushButton("Auto Graft from Donor...")
        self.graft_btn.setToolTip(
            "Repair a damaged dump by copying structurally-verified regions from a "
            "known-good donor (a capsule .308/.CAP or another dump). Only validated "
            "matching-bound regions are written; everything else is refused."
        )
        self.graft_btn.clicked.connect(self.run_graft)
        graft_row.addWidget(self.graft_btn)
        graft_row.addStretch(1)
        layout.addLayout(graft_row)

        self.repair_text = QPlainTextEdit()
        self.repair_text.setReadOnly(True)
        layout.addWidget(self.repair_text, 1)

        return widget

    def _build_me_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)

        file_row = QHBoxLayout()
        file_row.addWidget(QLabel("File:"))
        self.me_file = QLineEdit()
        self.me_file.setReadOnly(True)
        file_row.addWidget(self.me_file, 1)
        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self.open_file)
        file_row.addWidget(browse_btn)
        layout.addLayout(file_row)

        me_options = QGroupBox("ME Cleaning Options")
        me_options_layout = QVBoxLayout(me_options)
        self.me_soft_disable = QCheckBox("Set HAP/AltMeDisable bit (soft disable)")
        self.me_soft_disable.setChecked(True)
        self.me_relocate = QCheckBox("Relocate FTPR partition")
        self.me_remove_modules = QCheckBox("Remove non-essential modules")
        self.me_remove_modules.setChecked(True)
        self.me_lock_descriptor = QCheckBox("Lock descriptor (remove ME write access)")
        self.me_truncate = QCheckBox("Truncate empty ME space")
        me_options_layout.addWidget(self.me_soft_disable)
        me_options_layout.addWidget(self.me_relocate)
        me_options_layout.addWidget(self.me_remove_modules)
        me_options_layout.addWidget(self.me_lock_descriptor)
        me_options_layout.addWidget(self.me_truncate)
        layout.addWidget(me_options)

        self.me_info_btn = QPushButton("Show ME Info")
        self.me_info_btn.clicked.connect(self.show_me_info)
        layout.addWidget(self.me_info_btn)

        self.me_clean_btn = QPushButton("Clean ME Region")
        self.me_clean_btn.clicked.connect(self.clean_me)
        layout.addWidget(self.me_clean_btn)

        inject_group = QGroupBox("Inject Clean ME/TXE Region (repair corrupted ME)")
        inject_layout = QVBoxLayout(inject_group)
        inject_layout.addWidget(QLabel(
            "Replaces the whole ME region with a clean firmware image of the\n"
            "same version (drag the clean .bin from your ME repository)."))
        inject_row = QHBoxLayout()
        self.me_clean_file = QLineEdit()
        self.me_clean_file.setPlaceholderText("Path to clean ME region image (.bin)")
        inject_row.addWidget(self.me_clean_file, 1)
        me_browse = QPushButton("Browse...")
        me_browse.clicked.connect(self.browse_clean_me)
        inject_row.addWidget(me_browse)
        inject_layout.addLayout(inject_row)
        self.me_inject_btn = QPushButton("Inject Clean ME")
        self.me_inject_btn.clicked.connect(self.inject_me)
        inject_layout.addWidget(self.me_inject_btn)
        layout.addWidget(inject_group)

        self.me_text = QPlainTextEdit()
        self.me_text.setReadOnly(True)
        layout.addWidget(self.me_text, 1)

        return widget

    def browse_clean_me(self):
        path, _ = QFileDialog.getOpenFileName(self, "Open clean ME image", "",
                                              "Binary (*.bin);;All Files (*)")
        if path:
            self.me_clean_file.setText(path)

    def inject_me(self):
        if not self.current_file:
            return
        clean_path = self.me_clean_file.text().strip()
        if not clean_path or not os.path.exists(clean_path):
            QMessageBox.warning(self, "No Clean Image", "Select a clean ME region image first.")
            return
        self.me_inject_btn.setEnabled(False)
        try:
            result = self.me_injector.inject(self.current_file, clean_path,
                                             self.current_file.rsplit(".", 1)[0] + "_mefixed.bin")
        finally:
            self.me_inject_btn.setEnabled(True)
        if result["success"]:
            self.me_text.setPlainText(result["message"])
            self.statusBar().showMessage("ME region injected")
        else:
            QMessageBox.warning(self, "Inject Failed", result["message"])

    def _build_dmi_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)

        file_row = QHBoxLayout()
        file_row.addWidget(QLabel("File:"))
        self.dmi_file = QLineEdit()
        self.dmi_file.setReadOnly(True)
        file_row.addWidget(self.dmi_file, 1)
        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self.open_file)
        file_row.addWidget(browse_btn)
        layout.addLayout(file_row)

        self.dmi_extract_btn = QPushButton("Extract DMI / SMBIOS Data")
        self.dmi_extract_btn.clicked.connect(self.extract_dmi)
        layout.addWidget(self.dmi_extract_btn)

        edit_group = QGroupBox("Edit Identity (fixed-size structured edits)")
        edit_layout = QVBoxLayout(edit_group)
        edit_row = QHBoxLayout()
        edit_row.addWidget(QLabel("Serial:"))
        self.dmi_edit_serial = QLineEdit()
        self.dmi_edit_serial.setPlaceholderText("new serial — equal-length swap only")
        edit_row.addWidget(self.dmi_edit_serial, 1)
        edit_row.addWidget(QLabel("UUID:"))
        self.dmi_edit_uuid = QLineEdit()
        self.dmi_edit_uuid.setPlaceholderText("8-4-4-4-12")
        edit_row.addWidget(self.dmi_edit_uuid, 1)
        edit_row.addWidget(QLabel("MAC:"))
        self.dmi_edit_mac = QLineEdit()
        self.dmi_edit_mac.setPlaceholderText("AA:BB:CC:DD:EE:FF (Intel GbE only)")
        edit_row.addWidget(self.dmi_edit_mac, 1)
        edit_layout.addLayout(edit_row)
        self.dmi_apply_btn = QPushButton("Apply Edits")
        self.dmi_apply_btn.clicked.connect(self.apply_dmi_edits)
        edit_layout.addWidget(self.dmi_apply_btn)
        layout.addWidget(edit_group)

        clone_group = QGroupBox("Clone DMI Identity (old dump -> new dump)")
        clone_layout = QVBoxLayout(clone_group)
        clone_layout.addWidget(QLabel(
            "Carries serials/UUID/MAC data from the original dump into a clean\n"
            "BIOS image so the machine keeps its identity after a reflash."))
        clone_row = QHBoxLayout()
        clone_row.addWidget(QLabel("Old dump:"))
        self.clone_old_edit = QLineEdit()
        self.clone_old_edit.setReadOnly(True)
        clone_row.addWidget(self.clone_old_edit, 1)
        clone_layout.addLayout(clone_row)

        new_row = QHBoxLayout()
        new_row.addWidget(QLabel("New dump:"))
        self.clone_new_edit = QLineEdit()
        self.clone_new_edit.setPlaceholderText("Clean/new BIOS image to receive the identity")
        new_row.addWidget(self.clone_new_edit, 1)
        new_browse = QPushButton("Browse...")
        new_browse.clicked.connect(self.browse_clone_new)
        new_row.addWidget(new_browse)
        clone_layout.addLayout(new_row)

        self.dmi_clone_btn = QPushButton("Clone DMI Into New Dump")
        self.dmi_clone_btn.clicked.connect(self.clone_dmi)
        clone_layout.addWidget(self.dmi_clone_btn)
        layout.addWidget(clone_group)

        self.dmi_text = QPlainTextEdit()
        self.dmi_text.setReadOnly(True)
        layout.addWidget(self.dmi_text, 1)

        return widget

    def browse_clone_new(self):
        path, _ = QFileDialog.getOpenFileName(self, "Open new/clean BIOS dump", "",
                                              "Binary (*.bin *.rom *.fd);;All Files (*)")
        if path:
            self.clone_new_edit.setText(path)

    def clone_dmi(self):
        old_path = self.clone_old_edit.text().strip() or self.current_file
        new_path = self.clone_new_edit.text().strip()
        if not old_path or not os.path.exists(old_path):
            QMessageBox.warning(self, "No Old Dump", "Load the original dump first.")
            return
        if not new_path or not os.path.exists(new_path):
            QMessageBox.warning(self, "No New Dump", "Select the new/clean BIOS image.")
            return
        self.dmi_clone_btn.setEnabled(False)
        try:
            result = self.dmi_clone.clone(old_path, new_path,
                                          new_path.rsplit(".", 1)[0] + "_dmiclone.bin")
        finally:
            self.dmi_clone_btn.setEnabled(True)
        if result["success"]:
            self.dmi_text.setPlainText(result["message"])
            self.statusBar().showMessage("DMI identity cloned")
        else:
            QMessageBox.warning(self, "Clone Failed", result["message"])

    def _build_password_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)

        file_row = QHBoxLayout()
        file_row.addWidget(QLabel("File:"))
        self.password_file = QLineEdit()
        self.password_file.setReadOnly(True)
        file_row.addWidget(self.password_file, 1)
        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self.open_file)
        file_row.addWidget(browse_btn)
        layout.addLayout(file_row)

        self.scan_btn = QPushButton("Scan for Password Structures")
        self.scan_btn.clicked.connect(self.scan_passwords)
        layout.addWidget(self.scan_btn)

        self.remove_btn = QPushButton("Clear All BIOS Passwords (writes new file)")
        self.remove_btn.clicked.connect(self.remove_passwords)
        layout.addWidget(self.remove_btn)
        self.dvar_btn = QPushButton("Recover Stored Passwords (Dell DVAR)")
        self.dvar_btn.setToolTip(
            "Reads BIOS passwords from Dell's DVAR XOR store (CVE-2026-40639). "
            "Passwords of <= 12 chars recover from the null-padding key leak; "
            "longer ones need a shorter historical record with the same first "
            "character. Offline; newer SIVB-vault platforms are not recoverable."
        )
        self.dvar_btn.clicked.connect(self.recover_dvar_passwords)
        layout.addWidget(self.dvar_btn)

        self.apple_btn = QPushButton("Apple Fsys: Fix CRC + Show Info")
        self.apple_btn.setToolTip(
            "Detects an Apple EFIROM's Fsys store, reports the serial/HWC/SON, "
            "and repairs the Fsys CRC32 only when it is invalid (no-op otherwise)."
        )
        self.apple_btn.clicked.connect(self.run_apple_fsys)
        layout.addWidget(self.apple_btn)

        hp_group = QGroupBox("HP Unlock (ProBook / EliteBook / ZBook dumps)")
        hp_layout = QVBoxLayout(hp_group)
        hp_layout.addWidget(QLabel(
            "Clears the HP admin password storage inside the dump\n"
            "(UserCred block on modern UEFI, $VSS/BiosUser entries on legacy BIOSes)."))
        self.hp_unlock_btn = QPushButton("Unlock HP Dump")
        self.hp_unlock_btn.clicked.connect(self.hp_unlock)
        hp_layout.addWidget(self.hp_unlock_btn)
        layout.addWidget(hp_group)

        layout.addWidget(self._build_passgen_tab())

        self.password_text = QPlainTextEdit()
        self.password_text.setReadOnly(True)
        layout.addWidget(self.password_text, 1)

        return widget

    def _build_extract_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)

        file_row = QHBoxLayout()
        file_row.addWidget(QLabel("Source EXE/File:"))
        self.extract_file = QLineEdit()
        self.extract_file.setReadOnly(True)
        file_row.addWidget(self.extract_file, 1)
        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self.open_file)
        file_row.addWidget(browse_btn)
        layout.addLayout(file_row)

        method_row = QHBoxLayout()
        method_row.addWidget(QLabel("Method:"))
        self.extract_method = QComboBox()
        self.extract_method.addItems([
            "Auto Detect",
            "Dell PFS",
            "HP / Insyde",
            "Lenovo FL1",
            "Lenovo EXE",
            "ASUS",
            "Acer",
            "Toshiba",
            "Samsung",
            "Sony VAIO",
            "Universal",
        ])
        method_row.addWidget(self.extract_method, 1)
        layout.addLayout(method_row)

        self.extract_btn = QPushButton("Extract BIOS Components")
        self.extract_btn.clicked.connect(self.extract_bios)
        layout.addWidget(self.extract_btn)

        self.extract_text = QPlainTextEdit()
        self.extract_text.setReadOnly(True)
        layout.addWidget(self.extract_text, 1)

        return widget

    def _build_hex_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)

        controls = QHBoxLayout()
        controls.addWidget(QLabel("Offset (hex):"))
        self.hex_offset = QLineEdit("0x0")
        controls.addWidget(self.hex_offset)
        controls.addWidget(QLabel("Length:"))
        self.hex_length = QLineEdit("256")
        controls.addWidget(self.hex_length)
        self.hex_btn = QPushButton("View")
        self.hex_btn.clicked.connect(self.view_hex)
        controls.addWidget(self.hex_btn)
        controls.addStretch(1)
        layout.addLayout(controls)

        self.hex_text = QPlainTextEdit()
        self.hex_text.setReadOnly(True)
        self.hex_text.setFont("Courier New" if hasattr(self.hex_text, "setFont") else None)
        layout.addWidget(self.hex_text, 1)

        return widget

    def _build_passgen_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)

        brand_group = QGroupBox("Master Password Generator (dogbert algorithms)")
        brand_layout = QVBoxLayout(brand_group)

        row1 = QHBoxLayout()
        row1.addWidget(QLabel("BIOS type:"))
        self.gen_generator = QComboBox()
        self._gen_keys = list(master_passwords.GENERATORS.keys())
        for key in self._gen_keys:
            label, _fn = master_passwords.GENERATORS[key]
            self.gen_generator.addItem(label, key)
        self.gen_generator.setCurrentIndex(0)
        row1.addWidget(self.gen_generator, 1)
        brand_layout.addLayout(row1)

        hint = QLabel("Input: the hash/serial shown after 3 wrong passwords "
                      "(or the system date for ASUS).")
        hint.setWordWrap(True)
        brand_layout.addWidget(hint)

        row2 = QHBoxLayout()
        row2.addWidget(QLabel("Input:"))
        self.gen_input = QLineEdit()
        self.gen_input.setPlaceholderText("e.g. 12345 / 03133610 / CNU1234ABC / 2013-12-31")
        row2.addWidget(self.gen_input, 1)
        brand_layout.addLayout(row2)

        self.generate_btn = QPushButton("Generate Password")
        self.generate_btn.clicked.connect(self.generate_passwords)
        brand_layout.addWidget(self.generate_btn)

        layout.addWidget(brand_group)

        self.gen_text = QPlainTextEdit()
        self.gen_text.setReadOnly(True)
        self.gen_text.setMaximumHeight(110)
        layout.addWidget(self.gen_text)

        return widget

    def open_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Open BIOS File",
            "",
            "BIOS Files (*.bin *.rom *.fd *.wph *.exe *.cap *.fl1 *.pfs *.hdr *.dmi *.dump);;All Files (*)",
        )
        if path:
            self.current_file = path
            self.file_label.setText(os.path.basename(path))
            self.repair_file.setText(path)
            self.me_file.setText(path)
            self.dmi_file.setText(path)
            self.password_file.setText(path)
            self.extract_file.setText(path)
            self.ec_tab.current_dump = path
            self.ec_tab.ec_file.setText(path)
            self.lenovo_tab.set_file(path)
            self.clone_old_edit.setText(path)
            self.statusBar().showMessage(f"Loaded: {path}")
            self.run_analysis()

    def _run_in_thread(self, task, on_done, *args):
        thread = WorkerThread(task, *args)
        thread.finished.connect(on_done)
        thread.error.connect(lambda e: self._show_error(e))
        self._threads.append(thread)
        thread.start()
        # prune finished workers so the list does not grow unboundedly
        self._threads = [t for t in self._threads if t.isRunning() or t is thread]
        return thread

    def _show_error(self, error: str):
        QMessageBox.critical(self, "Error", error)

    def run_analysis(self):
        if not self.current_file:
            return
        if hasattr(self, "analyze_btn"):
            self.analyze_btn.setEnabled(False)
        self._run_in_thread(self.bios_analyzer.analyze, self._analysis_done, self.current_file)

    def _analysis_done(self, result):
        self.current_bios_info = result
        self.info_text.setPlainText(self._format_bios_info(result))
        self._populate_regions(result)
        self.main_status.setText(
            f"Type: {result.bios_type.name} | Regions: {result.total_regions} | "
            f"ME: {result.me_version} {result.me_type} | Issues: {len(result.issues)}"
        )
        # Platform-traits gating (architecture/vendor → which tools apply)
        from bios_recovery.core.traits import classify
        traits = classify(self._read_current_file_bytes())
        self._apply_traits(traits)
        self._update_overview_cards(result, traits)
        if hasattr(self, "analyze_btn"):
            self.analyze_btn.setEnabled(True)
        self.tabs.setCurrentWidget(self.main_tab)

    def _read_current_file_bytes(self):
        if self.current_file and os.path.exists(self.current_file):
            with open(self.current_file, "rb") as f:
                return f.read()
        return b""

    def _apply_traits(self, traits):
        """Grey-out platform/vendor-bound tabs with an explicit reason in the tooltip."""
        from bios_recovery.core.traits import ARCH_AMD, ARCH_INTEL, ARCH_APPLE_INTEL
        from bios_recovery.core.traits_matrix import tool_matrix

        rules = {
            "ME Cleaner": (
                traits.architecture in (ARCH_INTEL, ARCH_APPLE_INTEL),
                "Not applicable: AMD platform (no Intel ME)" if traits.architecture == ARCH_AMD
                else "Not applicable on this platform type",
            ),
            "Lenovo Unlock": (
                traits.vendor == "lenovo",
                "Not applicable: manufacturer-specific tool (Lenovo)",
            ),
            "EC Patching": (True, ""),
        }
        self.platform_badge.setText(f"{traits.architecture.upper()} · {traits.vendor}")
        self.platform_badge.setVisible(True)
        for idx in range(self.tabs.count()):
            title = self.tabs.tabText(idx)
            rule = rules.get(title)
            if rule is None:
                self.tabs.setTabToolTip(idx, "")
                continue
            applies, reason = rule
            self.tabs.setTabEnabled(idx, applies)
            self.tabs.setTabToolTip(idx, "" if applies else reason)

        # Populate the Platform tab table + info panel
        matrix = tool_matrix(traits)
        if hasattr(self, "traits_table"):
            self.traits_table.setRowCount(0)
            for i, (tool, row) in enumerate(matrix.items()):
                self.traits_table.insertRow(i)
                self.traits_table.setItem(i, 0, QTableWidgetItem(tool))
                self.traits_table.setItem(i, 1, QTableWidgetItem("Yes" if row.applies else "No"))
                self.traits_table.setItem(i, 2, QTableWidgetItem(row.reason))
            self.traits_table.resizeColumnsToContents()

        if hasattr(self, "platform_info"):
            lines = [
                f"Architecture: {traits.architecture}",
                f"Vendor: {traits.vendor}",
            ]
            if traits.me_family:
                lines.append(f"ME family: {traits.me_family} (version {traits.me_version or '?'})")
            if traits.evidence:
                for vendor, evs in traits.evidence.items():
                    lines.append(f"  evidence[{vendor}]: {', '.join(evs[:3])}")
            self.platform_info.setPlainText("\n".join(lines))

        # Overview panel: show the classification (the traits matrix)
        lines = ["", "=== Platform Classification ===",
                 f"  Architecture: {traits.architecture}",
                 f"  Vendor: {traits.vendor}",
                 ]
        if traits.me_family:
            lines.append(f"  ME family: {traits.me_family} (version {traits.me_version or '?'})")
        for init_idx, title in (("ME Cleaner", "ME Cleaner"), ("Lenovo Unlock", "Lenovo Unlock")):
            applies, reason = rules.get(title, (True, ""))
            lines.append(f"  tool[{title}]: {'available' if applies else 'disabled — ' + reason}")
        cur = self.info_text.toPlainText()
        self.info_text.setPlainText(cur + "\n" + "\n".join(lines))

    def _format_bios_info(self, result) -> str:
        lines = [
            f"File: {result.file_path}",
            f"Size: {result.file_size:,} bytes ({result.file_size / 0x100000:.2f} MB)",
            f"MD5: {result.md5}",
            f"SHA256: {result.sha256}",
            f"BIOS Type: {result.bios_type.name}",
            f"ME Version: {result.me_version or 'N/A'}",
            f"ME Type: {result.me_type or 'N/A'}",
            f"Flash Descriptor: {'Yes' if result.has_flash_descriptor else 'No'}",
            f"ME Region: {'Yes' if result.has_me_region else 'No'}",
        ]
        if result.issues:
            lines.append("")
            lines.append("ISSUES:")
            for issue in result.issues:
                lines.append(f"  - {issue}")
        if result.warnings:
            lines.append("")
            lines.append("WARNINGS:")
            for warn in result.warnings:
                lines.append(f"  - {warn}")
        return "\n".join(lines)

    def _populate_regions(self, result):
        self.regions_table.setRowCount(0)
        for i, region in enumerate(result.regions):
            self.regions_table.insertRow(i)
            self.regions_table.setItem(i, 0, QTableWidgetItem(region.name))
            self.regions_table.setItem(i, 1, QTableWidgetItem(region.region_type.name))
            self.regions_table.setItem(i, 2, QTableWidgetItem(f"0x{region.offset:X}"))
            self.regions_table.setItem(i, 3, QTableWidgetItem(f"0x{region.size:X} ({region.size:,} bytes)"))

    def run_repair(self):
        if not self.current_file:
            return
        self.repair_btn.setEnabled(False)
        output = self.current_file.rsplit(".", 1)[0] + "_repaired.bin"
        self._run_in_thread(
            self.repair_engine.auto_repair,
            self._repair_done,
            self.current_file,
            output,
            self.repair_checksum_ck.isChecked(),
            self.repair_size_ck.isChecked(),
            self.repair_password_ck.isChecked(),
        )

    def _repair_done(self, report):
        self.repair_btn.setEnabled(True)
        lines = []
        lines.append(f"Repair {'Success' if report.success else 'Failed'}")
        lines.append(f"Output: {report.output_path}")
        for op in report.operations:
            lines.append(f"  + {op}")
        for warn in report.warnings:
            lines.append(f"  ! {warn}")
        for issue in report.issues_found:
            lines.append(f"  # [{issue.severity}] {issue.description}")
        self.repair_text.setPlainText("\n".join(lines))

    def run_graft(self):
        from bios_recovery.core.bios_repair import BiosRepairEngine

        if not self.current_file:
            QMessageBox.warning(self, "No File", "Open the damaged dump first.")
            return
        donor, _ = QFileDialog.getOpenFileName(
            self,
            "Select donor capsule or dump (known-good)",
            "",
            "Capsule/Dump (*.308 *.cap *.bin);;All Files (*)",
        )
        if not donor:
            return
        self.graft_btn.setEnabled(False)
        engine = BiosRepairEngine()
        self._run_in_thread(engine.auto_graft_from_donor, self._graft_done,
                            self.current_file, donor)

    def _graft_done(self, report):
        self.graft_btn.setEnabled(True)
        lines = [f"Graft {'Success' if report.success else 'Failed'}",
                 f"Output: {report.output_path}"]
        for op in report.operations:
            lines.append(f"  + {op}")
        for warn in report.warnings:
            lines.append(f"  ! {warn}")
        for issue in report.issues_found:
            lines.append(f"  # [{issue.severity}] {issue.description}")
        self.repair_text.setPlainText("\n".join(lines))
        self.statusBar().showMessage(f"Graft complete: {report.output_path}")

    def build_flashable_image(self):
        from bios_recovery.manufacturers.common.bios_capsule import extract_flashable_image

        if not self.current_file:
            QMessageBox.warning(self, "No File", "Open a capsule update (.CAP/.308/.217) first.")
            return
        self.capsule_btn.setEnabled(False)
        self._run_in_thread(
            extract_flashable_image,
            self._flashable_done,
            self.current_file,
        )

    def _flashable_done(self, info):
        self.capsule_btn.setEnabled(True)
        if not info.success:
            QMessageBox.warning(self, "Capsule Error", " ".join(info.messages) or "Unknown error")
            self.statusBar().showMessage("Capsule extraction failed")
            return
        lines = [
            "Capsule → flashable image",
            f"Header size: {info.header_size:#x}",
            f"Image size: {info.image_size:#x}",
            f"Image SHA-256: {info.image_sha256}",
            f"Output: {info.output_path}",
        ]
        lines.extend(info.messages)
        self.info_text.setPlainText("\n".join(lines))
        self.statusBar().showMessage(f"Flashable image written: {info.output_path}")

    def build_flashable_merged(self):
        from bios_recovery.manufacturers.common.bios_capsule import extract_flashable_image, restore_nvar_from_dump

        if not self.current_file:
            QMessageBox.warning(self, "No File", "Open a capsule update (.CAP/.308/.217) first.")
            return
        dump_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Your Dump (for machine NVRAM)",
            "",
            "BIOS Dumps (*.bin);;All Files (*)",
        )
        if not dump_path:
            return
        self.capsule_merge_btn.setEnabled(False)

        def task():
            base = extract_flashable_image(self.current_file,
                                           output_path=self.current_file.rsplit(".", 1)[0] + "_flashable_merged_base.bin")
            if not base.success:
                return base
            merged = base.output_path
            out = self.current_file.rsplit(".", 1)[0] + "_flashable_merged.bin"
            return restore_nvar_from_dump(merged, dump_path, out)

        self._run_in_thread(task, self._flashable_merge_done)

    def _flashable_merge_done(self, info):
        self.capsule_merge_btn.setEnabled(True)
        if not info.success:
            QMessageBox.warning(self, "Merge Error", " ".join(info.messages) or "Unknown error")
            self.statusBar().showMessage("Capsule merge failed")
            return
        lines = [
            "Capsule merged with dump NVRAM",
            f"Image size: {info.image_size:#x}",
            f"Output: {info.output_path}",
        ]
        lines.extend(info.messages)
        self.info_text.setPlainText("\n".join(lines))
        self.statusBar().showMessage(f"Merged image written: {info.output_path}")

    def show_me_info(self):
        if not self.current_file:
            return
        info = self.me_cleaner.get_me_info(self.current_file)
        if not info.get("found"):
            reason = info.get("reason")
            if reason:
                self.me_text.setPlainText(reason)
            else:
                self.me_text.setPlainText("No Intel ME region found in this image.")
            return
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
        self.me_text.setPlainText("\n".join(lines))

    def clean_me(self):
        if not self.current_file:
            return
        self.me_clean_btn.setEnabled(False)
        output = self.current_file.rsplit(".", 1)[0] + "_cleaned.bin"
        self._run_in_thread(
            self.me_cleaner.clean,
            self._me_clean_done,
            self.current_file,
            output,
            self.me_soft_disable.isChecked(),
            self.me_relocate.isChecked(),
            self.me_truncate.isChecked(),
            self.me_remove_modules.isChecked(),
            self.me_lock_descriptor.isChecked(),
        )

    def _me_clean_done(self, report):
        self.me_clean_btn.setEnabled(True)
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
        for msg in report.messages:
            lines.append(f"  - {msg}")
        self.me_text.setPlainText("\n".join(lines))

    def hp_unlock(self):
        if not self.current_file:
            return
        self.hp_unlock_btn.setEnabled(False)
        try:
            report = self.hp_unlocker.unlock(self.current_file,
                                             self.current_file.rsplit(".", 1)[0] + "_unlocked.bin")
        finally:
            self.hp_unlock_btn.setEnabled(True)
        lines = [f"Style: {report['style'] or 'unknown'}",
                 f"Success: {report['success']}",
                 f"Output: {report['output_path']}"]
        lines.extend(f"  - {m}" for m in report["messages"])
        self.password_text.setPlainText("\n".join(lines))
        if not report["success"]:
            QMessageBox.warning(self, "HP Unlock", "\n".join(report["messages"]))
        else:
            self.statusBar().showMessage("HP dump unlocked")

    def extract_dmi(self):
        if not self.current_file:
            return
        self.dmi_extract_btn.setEnabled(False)
        self._run_in_thread(self.dmi_extractor.extract_from_bios, self._dmi_done, self.current_file)

    def _dmi_done(self, info):
        self.dmi_extract_btn.setEnabled(True)
        if info is None:
            self.dmi_text.setPlainText("No SMBIOS data found in this image.")
            return
        lines = [
            "=== BIOS Information ===",
            f"  Vendor: {info.bios_vendor}",
            f"  Version: {info.bios_version}",
            f"  Release Date: {info.bios_release_date}",
            "",
            "=== System Information ===",
            f"  Manufacturer: {info.system_manufacturer}",
            f"  Product Name: {info.system_product_name}",
            f"  Serial Number: {info.system_serial_number}",
            f"  UUID: {info.system_uuid}",
            "",
            "=== Baseboard Information ===",
            f"  Manufacturer: {info.board_manufacturer}",
            f"  Product Name: {info.board_product_name}",
            f"  Serial Number: {info.board_serial_number}",
            "",
            "=== Chassis Information ===",
            f"  Manufacturer: {info.chassis_manufacturer}",
            f"  Serial Number: {info.chassis_serial_number}",
            "",
            "=== Processor ===",
            f"  Manufacturer: {info.processor_manufacturer}",
            f"  Version: {info.processor_version}",
            f"  Serial: {info.processor_serial}",
            "",
            f"=== Memory Devices: {len(info.memory_devices)} ===",
        ]
        for mem in info.memory_devices:
            lines.append(f"  {mem.get('device_locator', '')}: {mem.get('manufacturer', '')} {mem.get('part_number', '')} SN:{mem.get('serial_number', '')}")
        lines.append("")
        lines.append(f"Total structures: {len(info.structures)}")
        lines.extend(self._dmi_editor_summary())
        self.dmi_text.setPlainText("\n".join(lines))

    def _dmi_editor_summary(self):
        if not self.current_file:
            return []
        from bios_recovery.core.dmi_editor import DMIEditor

        try:
            info = DMIEditor().info(self.current_file)
        except Exception:
            return []
        if not info.get("found"):
            return []
        s = info.get("serials", {})
        return [
            "",
            "=== Editor (current fixed-size values) ===",
            f"  System serial: {s.get('system')}",
            f"  Baseboard serial: {s.get('baseboard')}",
            f"  UUID: {info.get('uuid')}",
            f"  MAC: {info.get('mac') or 'n/a (no descriptor GbE region)'}",
            "  Serial edits: equal-length in-place swap only; UUID/GBE-MAC: fixed-size writes.",
        ]

    def apply_dmi_edits(self):
        from bios_recovery.core.dmi_editor import DMIEditor

        if not self.current_file:
            QMessageBox.warning(self, "No File", "Open a flashed BIOS dump first.")
            return
        serial = self.dmi_edit_serial.text().strip() or None
        uuid = self.dmi_edit_uuid.text().strip() or None
        mac = self.dmi_edit_mac.text().strip() or None
        if not (serial or uuid or mac):
            QMessageBox.information(self, "Nothing to Edit",
                                    "Fill in a serial, UUID or MAC first.")
            return
        self.dmi_apply_btn.setEnabled(False)
        editor = DMIEditor()
        self._run_in_thread(editor.set_identity, self._dmi_edit_done,
                            self.current_file, None, serial, uuid, mac)

    def _dmi_edit_done(self, rep):
        self.dmi_apply_btn.setEnabled(True)
        lines = [f"Edit {'Success' if rep.success else 'Failed'}",
                 f"Output: {rep.output_path}"]
        for op in rep.operations:
            lines.append(f"  + {op}")
        for warn in rep.warnings:
            lines.append(f"  ! {warn}")
        if rep.message:
            lines.append(f"  # {rep.message}")
        self.dmi_text.setPlainText("\n".join(lines))
        self.statusBar().showMessage(f"Identity edit written: {rep.output_path}")

    def run_apple_fsys(self):
        from bios_recovery.manufacturers.apple.apple_efi import fix_fsys_checksum, rom_info

        if not self.current_file:
            QMessageBox.warning(self, "No File", "Open a flashed BIOS dump first.")
            return
        self.apple_btn.setEnabled(False)
        self._run_in_thread(_apple_fsys_task, self._apple_fsys_done, self.current_file)

    def _apple_fsys_done(self, rep):
        self.apple_btn.setEnabled(True)
        lines = [f"{'Success' if rep.success else 'Failed'}: {rep.message}"]
        for op in rep.operations:
            lines.append(f"  + {op}")
        for warn in rep.warnings:
            lines.append(f"  ! {warn}")
        self.password_text.setPlainText("\n".join(lines))
        self.statusBar().showMessage("Apple Fsys handling complete")

    def recover_dvar_passwords(self):
        from bios_recovery.manufacturers.dell.dvar_passwords import recover_passwords

        if not self.current_file:
            QMessageBox.warning(self, "No File", "Open a flashed BIOS dump first.")
            return
        self.dvar_btn.setEnabled(False)
        self._run_in_thread(recover_passwords, self._dvar_recovery_done, self.current_file)

    def _dvar_recovery_done(self, rep):
        self.dvar_btn.setEnabled(True)
        lines = [f"Recovery {'Success' if rep.success else 'Failed'}", rep.message]
        for pw in rep.passwords:
            lines.append(f"  @0x{pw.record_offset:x}: {pw.password!r} "
                         f"(len {pw.length}, via {pw.recovered_from})")
        for n in rep.notes:
            lines.append(f"  {n}")
        self.password_text.setPlainText("\n".join(lines))
        self.statusBar().showMessage("DVAR password recovery complete")

    def scan_passwords(self):
        if not self.current_file:
            return
        self.scan_btn.setEnabled(False)
        self._run_in_thread(self.password_remover.find_password_in_dump, self._password_scan_done, self.current_file)

    def _password_scan_done(self, found):
        self.scan_btn.setEnabled(True)
        if not found:
            self.password_text.setPlainText("No password structures found.")
            return
        lines = [f"Found {len(found)} potential password structures:"]
        for item in found:
            lines.append(f"  Type: {item['type']}")
            lines.append(f"    Offset: {item['offset']}")
            lines.append(f"    Pattern: {item['pattern']}")
            lines.append(f"    Context: {item['context']}")
        self.password_text.setPlainText("\n".join(lines))

    def remove_passwords(self):
        if not self.current_file:
            return
        self.remove_btn.setEnabled(False)
        output = self.current_file.rsplit(".", 1)[0] + "_nopass.bin"
        self._run_in_thread(self.password_remover.remove_passwords, self._password_remove_done, self.current_file, output)

    def _password_remove_done(self, report):
        self.remove_btn.setEnabled(True)
        lines = [
            f"Status: {report.status.name}",
            f"Output: {report.output_path}",
            f"Found Structures: {len(report.found_passwords)}",
        ]
        for msg in report.messages:
            lines.append(f"  - {msg}")
        for pw in report.found_passwords:
            lines.append(f"  Found: {pw['name']} at {pw['offset']:#x}")
        self.password_text.setPlainText("\n".join(lines))

    def extract_bios(self):
        if not self.current_file:
            return
        self.extract_btn.setEnabled(False)

        method_map = {
            0: "AUTO",
            1: "DELL_PFS",
            2: "HP_INSIDE",
            3: "LENOVO_FL1",
            4: "LENOVO_EXE",
            5: "ASUS_EXE",
            6: "ACER_EXE",
            7: "TOSHIBA_EXE",
            8: "SAMSUNG_EXE",
            9: "SONY_VAIO",
            10: "UNIVERSAL",
        }
        method_name = method_map.get(self.extract_method.currentIndex(), "AUTO")

        from bios_recovery.manufacturers.common.bios_extractor import ExtractionMethod
        method = ExtractionMethod[method_name]

        self._run_in_thread(self.bios_extractor.extract, self._extract_done, self.current_file, None, method)

    def _extract_done(self, result):
        self.extract_btn.setEnabled(True)
        lines = [
            f"Success: {result.success}",
            f"Method: {result.method_used}",
            f"Output Dir: {result.output_dir}",
        ]
        for msg in result.messages:
            lines.append(f"  - {msg}")
        for f in result.files:
            lines.append(f"  {f['type']}: {f['name']} ({f['size']:,} bytes @ {f['offset']})")
        self.extract_text.setPlainText("\n".join(lines))

    def view_hex(self):
        if not self.current_file:
            return
        try:
            offset = int(self.hex_offset.text().strip(), 16)
            length = int(self.hex_length.text().strip())
        except ValueError:
            self._show_error("Invalid offset or length")
            return
        data = self.bios_analyzer.get_hex_view(self.current_file, offset, min(length, 0x10000))
        lines = []
        for i in range(0, len(data), 16):
            chunk = data[i:i + 16]
            hex_str = " ".join(f"{b:02X}" for b in chunk)
            ascii_str = "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in chunk)
            lines.append(f"{offset + i:08X}  {hex_str:<48}  {ascii_str}")
        self.hex_text.setPlainText("\n".join(lines))

    def generate_passwords(self):
        key = self.gen_generator.currentData()
        user_input = self.gen_input.text().strip()
        if not user_input:
            QMessageBox.warning(self, "Input Required", "Please enter the hash, serial or date.")
            return
        label, _fn = master_passwords.GENERATORS[key]
        lines = [f"{label}", f"Input: {user_input}", ""]
        try:
            results = master_passwords.generate(key, user_input)
        except Exception as e:
            self.gen_text.setPlainText(f"Could not generate a password:\n{e}")
            return
        for name, pwd in results:
            lines.append(f"{name:<28}: {pwd}")
        lines.append("")
        lines.append("Passwords are encoded for US QWERTY keyboard layout.")
        self.gen_text.setPlainText("\n".join(lines))


    def run_mea_analysis(self):
        if not self.current_file:
            QMessageBox.warning(self, "No File", "Open a BIOS file first.")
            return
        self.statusBar().showMessage("Running ME Analyzer...")
        try:
            res = mea_bridge.run_mea_analyzer(self.current_file)
        except Exception as e:
            QMessageBox.critical(self, "ME Analyzer Error", str(e))
            self.statusBar().showMessage("ME Analyzer failed")
            return
        lines = ["ME Analyzer Result:"]
        if res.success:
            lines.append("Success")
        else:
            lines.append(f"Failed: {res.error}")
        if res.messages:
            lines.append("")
            lines.extend(res.messages)
        if res.stdout:
            lines.append("")
            lines.append(res.stdout[-1000:])
        self.info_text.setPlainText("\n".join(lines))
        self.statusBar().showMessage("ME Analyzer completed")


    def show_about(self):
        QMessageBox.about(
            self,
            "About BIOS Recovery Suite",
            f"BIOS Recovery Suite v{__version__}\n\n"
            "Professional BIOS repair, analysis, ME cleaning,\n"
            "DMI extraction, and password removal tool.\n\n"
            "Supports all major BIOS manufacturers.\n\n"
            "⚠️ DISCLAIMER: BIOS modification carries risk of bricking.\n"
            "Always create backups before flashing.",
        )

def _apple_fsys_task(file_path):
    from bios_recovery.manufacturers.apple.apple_efi import fix_fsys_checksum, rom_info
    info = rom_info(file_path)
    rep = fix_fsys_checksum(file_path)
    rep.notes = [f"rom_info: {info}"]
    return rep
