#!/usr/bin/env python3
"""BIOS Recovery Suite - Professional BIOS repair and management tool."""

import sys
import os

def _app_dir():
    """Directory the running exe lives in (the folder Qt loads DLLs from)."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return None


def _diagnose_qt_import_failure(exc):
    """Explain a Qt DLL load failure instead of dumping a raw traceback.

    The overwhelmingly common cause is a stale DLL sitting next to the exe:
    Windows resolves DLLs from the app folder BEFORE the system folder, so one
    leftover icu*.dll / Qt6*.dll from an older build shadows the correct one.
    """
    lines = [
        "",
        "=" * 72,
        "BIOS Recovery Suite could not start: Qt failed to load.",
        "",
        f"Error: {exc}",
        "",
    ]

    app_dir = _app_dir()
    if app_dir:
        suspects = []
        try:
            for name in sorted(os.listdir(app_dir)):
                low = name.lower()
                if low.endswith(".dll") and (
                    low.startswith("icu") or low.startswith("qt6")
                ):
                    suspects.append(name)
        except OSError:
            pass
        if suspects:
            lines += [
                "LIKELY CAUSE - stale DLLs in the program folder:",
                *[f"    {s}" for s in suspects],
                "",
                "Windows loads DLLs from the app folder before the system folder,",
                "so these shadow the correct system copies. Fix:",
                "",
                "  1. Uninstall 'BIOS Recovery Suite' (Control Panel > Programs).",
                "  2. DELETE the leftover folder:",
                f"     {app_dir}",
                "  3. Download a fresh installer and install into a clean folder.",
            ]
        else:
            lines += [
                "No obviously stale DLLs were found in the program folder.",
                "Next most likely cause: this Windows build is too old for the",
                "Qt version this app needs (Qt 6 requires Windows 10 1809 or",
                "newer). Run 'winver' to check.",
            ]
    else:
        lines.append("Running from source, not a packaged build.")

    lines += [
        "",
        "If the folder was already clean, install the Microsoft Visual C++",
        "redistributable (x64) from https://aka.ms/vs/17/release/vc_redist.x64.exe",
        "=" * 72,
        "",
    ]
    return "\n".join(lines)


def main():
    try:
        from PySide6.QtWidgets import QApplication
        from PySide6.QtCore import Qt
    except ImportError as exc:
        sys.stderr.write(_diagnose_qt_import_failure(exc))
        sys.stderr.flush()
        return 1

    from bios_recovery.gui.main_window import MainWindow

    app = QApplication(sys.argv)
    app.setApplicationName("BIOS Recovery Suite")
    app.setOrganizationName("BIOSRecoverySuite")
    app.setStyle("Fusion")

    from bios_recovery.gui.styles import apply_stylesheet
    apply_stylesheet(app)

    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main() or 0)
