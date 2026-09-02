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

from bios_recovery.engines.bios_analyzer import BiosAnalyzer, BiosType
from bios_recovery.engines.me_cleaner import IntelMECleaner
from bios_recovery.engines.dmi_extractor import DMIExtractor
from bios_recovery.engines.password_remover import PasswordRemover
from bios_recovery.engines.bios_repair import BiosRepairEngine
from bios_recovery.engines.bios_extractor import BiosExtractor
from bios_recovery.manufacturers.profiles import ManufacturerProfiles, Manufacturer
from bios_recovery.gui.spi_tab import SPITab
from bios_recovery.gui.ec_tab import ECTab
from bios_recovery.gui.lenovo_tab import LenovoTab
from bios_recovery.gui.update_dialog import UpdateDialog, CheckWorker
from bios_recovery import __version__


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

        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)

        self.main_tab = self._build_main_tab()
        self.repair_tab = self._build_repair_tab()
        self.me_tab = self._build_me_tab()
        self.dmi_tab = self._build_dmi_tab()
        self.password_tab = self._build_password_tab()
        self.extract_tab = self._build_extract_tab()
        self.hex_tab = self._build_hex_tab()
        self.passgen_tab = self._build_passgen_tab()
        self.spi_tab = SPITab(self)
        self.ec_tab = ECTab(self)
        self.lenovo_tab = LenovoTab(self)

        self.tabs.addTab(self.main_tab, "Overview")
        self.tabs.addTab(self.repair_tab, "Repair")
        self.tabs.addTab(self.me_tab, "ME Cleaner")
        self.tabs.addTab(self.dmi_tab, "DMI")
        self.tabs.addTab(self.password_tab, "Security")
        self.tabs.addTab(self.extract_tab, "Extract")
        self.tabs.addTab(self.hex_tab, "Hex Viewer")
        self.tabs.addTab(self.passgen_tab, "Passwords")
        self.tabs.addTab(self.spi_tab, "SPI Flasher")
        self.tabs.addTab(self.ec_tab, "EC Patching")
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

        help_menu = menubar.addMenu("&Help")
        help_menu.addAction("&Check for Updates...", self.check_for_updates)
        help_menu.addAction("&About", self.show_about)

    def _build_main_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)

        header = QHBoxLayout()
        self.open_btn = QPushButton("Open BIOS File")
        self.open_btn.clicked.connect(self.open_file)
        header.addWidget(self.open_btn)

        self.file_label = QLabel("No file loaded")
        self.file_label.setStyleSheet("color: #AAA;")
        header.addWidget(self.file_label, 1)

        self.analyze_btn = QPushButton("Analyze")
        self.analyze_btn.clicked.connect(self.run_analysis)
        header.addWidget(self.analyze_btn)
        layout.addLayout(header)

        info_group = QGroupBox("BIOS Information")
        info_layout = QVBoxLayout(info_group)
        self.info_text = QPlainTextEdit()
        self.info_text.setReadOnly(True)
        self.info_text.setMaximumHeight(200)
        info_layout.addWidget(self.info_text)
        layout.addWidget(info_group)

        regions_group = QGroupBox("Detected Regions")
        regions_layout = QVBoxLayout(regions_group)
        self.regions_table = QTableWidget(0, 4)
        self.regions_table.setHorizontalHeaderLabels(["Region", "Type", "Offset", "Size"])
        self.regions_table.horizontalHeader().setStretchLastSection(True)
        regions_layout.addWidget(self.regions_table)
        layout.addWidget(regions_group, 1)

        self.main_status = QLabel("")
        layout.addWidget(self.main_status)

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
        self.repair_me_ck = QCheckBox("Clean ME Region")
        self.repair_me_ck.setChecked(True)
        self.repair_checksum_ck = QCheckBox("Fix FPT Checksum")
        self.repair_checksum_ck.setChecked(True)
        self.repair_size_ck = QCheckBox("Verify Size Alignment")
        self.repair_size_ck.setChecked(True)
        self.repair_security_ck = QCheckBox("Remove Security Structures")
        self.repair_security_ck.setChecked(True)
        options_layout.addWidget(self.repair_me_ck)
        options_layout.addWidget(self.repair_checksum_ck)
        options_layout.addWidget(self.repair_size_ck)
        options_layout.addWidget(self.repair_security_ck)
        layout.addWidget(options_group)

        self.repair_btn = QPushButton("Run Auto Repair")
        self.repair_btn.clicked.connect(self.run_repair)
        layout.addWidget(self.repair_btn)

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

        self.me_text = QPlainTextEdit()
        self.me_text.setReadOnly(True)
        layout.addWidget(self.me_text, 1)

        return widget

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

        self.dmi_text = QPlainTextEdit()
        self.dmi_text.setReadOnly(True)
        layout.addWidget(self.dmi_text, 1)

        return widget

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

        self.remove_btn = QPushButton("Remove All Passwords")
        self.remove_btn.clicked.connect(self.remove_passwords)
        layout.addWidget(self.remove_btn)

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

        brand_group = QGroupBox("Master Password Generator")
        brand_layout = QVBoxLayout(brand_group)

        row1 = QHBoxLayout()
        row1.addWidget(QLabel("Manufacturer:"))
        self.gen_manufacturer = QComboBox()
        self.gen_manufacturer.addItems([
            "Dell",
            "HP",
            "Insyde (Acer/HP)",
            "Phoenix",
            "Samsung",
        ])
        row1.addWidget(self.gen_manufacturer, 1)
        brand_layout.addLayout(row1)

        row2 = QHBoxLayout()
        row2.addWidget(QLabel("Input (Service Tag / Code):"))
        self.gen_input = QLineEdit()
        row2.addWidget(self.gen_input, 1)
        brand_layout.addLayout(row2)

        row3 = QHBoxLayout()
        row3.addWidget(QLabel("Dell suffix:"))
        self.gen_suffix = QComboBox()
        self.gen_suffix.addItems(["595B", "D35B", "2A7B", "A95B", "1D3B", "6FF1", "1F66", "BF97", "8FC8"])
        self.gen_suffix.setCurrentText("595B")
        row3.addWidget(self.gen_suffix)
        brand_layout.addLayout(row3)

        self.generate_btn = QPushButton("Generate Password")
        self.generate_btn.clicked.connect(self.generate_passwords)
        brand_layout.addWidget(self.generate_btn)

        layout.addWidget(brand_group)

        self.gen_text = QPlainTextEdit()
        self.gen_text.setReadOnly(True)
        layout.addWidget(self.gen_text, 1)

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
            self.statusBar().showMessage(f"Loaded: {path}")
            self.run_analysis()

    def _run_in_thread(self, task, on_done, *args):
        thread = WorkerThread(task, *args)
        thread.finished.connect(on_done)
        thread.error.connect(lambda e: self._show_error(e))
        self._threads.append(thread)
        thread.start()
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
        if hasattr(self, "analyze_btn"):
            self.analyze_btn.setEnabled(True)
        self.tabs.setCurrentWidget(self.main_tab)

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
            self.repair_me_ck.isChecked(),
            self.repair_checksum_ck.isChecked(),
            self.repair_size_ck.isChecked(),
            self.repair_security_ck.isChecked(),
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

    def show_me_info(self):
        if not self.current_file:
            return
        info = self.me_cleaner.get_me_info(self.current_file)
        if not info.get("found"):
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
        self.dmi_text.setPlainText("\n".join(lines))

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

        from bios_recovery.engines.bios_extractor import ExtractionMethod
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
        manufacturer = self.gen_manufacturer.currentText()
        user_input = self.gen_input.text().strip()
        if not user_input:
            QMessageBox.warning(self, "Input Required", "Please enter the service tag or code.")
            return

        lines = []
        if manufacturer == "Dell":
            suffix = self.gen_suffix.currentText()
            passwords = self.password_remover.generate_dell_master_password(user_input, suffix)
            lines.append(f"Dell Master Password for SN: {user_input} (suffix {suffix})")
            lines.extend(f"  {p}" for p in passwords)
        elif manufacturer == "HP":
            pw = self.password_remover.generate_hp_master_password(user_input)
            lines.append(f"HP Master Password: {pw}")
        elif manufacturer == "Insyde (Acer/HP)":
            pw = self.password_remover.generate_insyde_master_password(user_input)
            lines.append(f"Insyde Master Password: {pw}")
        elif manufacturer == "Phoenix":
            try:
                raw = int(user_input)
                pw = f"{(raw * 3 + 7) % 100000:05d}"
                lines.append(f"Phoenix Master Password: {pw}")
            except ValueError:
                lines.append("Invalid input for Phoenix password generation")
        elif manufacturer == "Samsung":
            lines.append("Samsung password generation requires full code (12 hex digits).")
            lines.append(f"Input: {user_input}")

        self.gen_text.setPlainText("\n".join(lines))

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
