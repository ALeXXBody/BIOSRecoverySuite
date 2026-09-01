#!/usr/bin/env python3
"""BIOS Recovery Suite - Professional BIOS repair and management tool."""

import sys
import os

def main():
    from PySide6.QtWidgets import QApplication
    from PySide6.QtCore import Qt
    from bios_recovery.gui.main_window import MainWindow

    app = QApplication(sys.argv)
    app.setApplicationName("BIOS Recovery Suite")
    app.setOrganizationName("BIOSRecoverySuite")
    app.setStyle("Fusion")

    from bios_recovery.gui.styles import apply_stylesheet
    apply_stylesheet(app)

    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
