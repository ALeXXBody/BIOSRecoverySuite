"""Check-for-updates dialog with download + silent installer hand-off."""

import os
import sys
import webbrowser

from PySide6.QtCore import QThread, Signal
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
)

from bios_recovery import __version__
from bios_recovery.gui.workers import track
from bios_recovery.utils import updater


class CheckWorker(QThread):
    """Fetches the latest release info from GitHub."""

    found = Signal(object)  # ReleaseInfo
    not_found = Signal()  # API reachable, no newer version
    failed = Signal(str)  # API unreachable / parse error

    def __init__(self):
        super().__init__()
        track(self)

    def run(self):
        try:
            info = updater.fetch_latest_release()
            newer = updater.is_newer(info.version, __version__)
        except Exception as e:
            self.failed.emit(str(e))
            return
        if newer:
            self.found.emit(info)
        else:
            self.not_found.emit()


class DownloadWorker(QThread):
    """Downloads the installer asset, reporting progress."""

    progress = Signal(int)
    done = Signal(str)
    failed = Signal(str)

    def __init__(self, url: str, dest: str, sha256, signature_url=None):
        super().__init__()
        self.url = url
        self.dest = dest
        self.sha256 = sha256
        self.signature_url = signature_url
        track(self)

    def run(self):
        sig_dest = self.dest + ".sig"
        try:
            updater.download(self.url, self.dest, progress_cb=lambda p: self.progress.emit(p))
            updater.verify_sha256(self.dest, self.sha256)
            if self.signature_url:
                updater.download(self.signature_url, sig_dest)
                updater.verify_signature(self.dest, sig_dest)
            self.done.emit(self.dest)
        except Exception as e:
            # Never leave an unverified installer where it could be run later.
            for p in (self.dest, sig_dest):
                if os.path.exists(p):
                    os.remove(p)
            self.failed.emit(str(e))


class UpdateDialog(QDialog):
    """Shows update status, release notes, and performs the update."""

    def __init__(self, parent=None, auto_silent=False, auto_check=True):
        super().__init__(parent)
        self.setWindowTitle("Software Update")
        self.setMinimumWidth(520)
        self.release = None
        self._worker = None
        self._downloader = None
        self._auto_silent = auto_silent
        self._build()
        # The startup check already fetched the release it shows, so it must not
        # send a second request.
        if auto_check:
            self.check()

    def _build(self):
        layout = QVBoxLayout(self)

        self.status_label = QLabel("Checking for updates...")
        self.status_label.setStyleSheet("font-weight: bold;")
        layout.addWidget(self.status_label)

        self.notes_text = QPlainTextEdit()
        self.notes_text.setReadOnly(True)
        self.notes_text.setVisible(False)
        self.notes_text.setMaximumHeight(220)
        layout.addWidget(self.notes_text)

        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setVisible(False)
        layout.addWidget(self.progress)

        buttons = QHBoxLayout()
        buttons.addStretch(1)

        self.install_btn = QPushButton("Download && Install")
        self.install_btn.clicked.connect(self._start_download)
        self.install_btn.setVisible(False)
        buttons.addWidget(self.install_btn)

        self.page_btn = QPushButton("Open Releases Page")
        self.page_btn.clicked.connect(lambda: webbrowser.open(updater.RELEASES_PAGE))
        buttons.addWidget(self.page_btn)

        self.close_btn = QPushButton("Close")
        self.close_btn.clicked.connect(self.reject)
        buttons.addWidget(self.close_btn)

        layout.addLayout(buttons)

    # ---- check phase -----------------------------------------------------

    def present_release(self, release):
        """Populate the dialog with an already-fetched release (no re-check)."""
        self.release = release
        self._on_update_found(release)

    def check(self):
        self.status_label.setText("Checking for updates...")
        self.install_btn.setVisible(False)
        self._worker = CheckWorker()
        self._worker.found.connect(self._on_update_found)
        self._worker.not_found.connect(self._on_up_to_date)
        self._worker.failed.connect(self._on_check_failed)
        self._worker.start()

    def _on_update_found(self, release):
        self.release = release
        self.status_label.setText(
            f"A new version is available: v{release.version} (you have v{__version__})"
        )
        if release.notes:
            self.notes_text.setPlainText(release.notes)
            self.notes_text.setVisible(True)
        can_install = (
            sys.platform == "win32"
            and bool(release.installer_url)
            and getattr(sys, "frozen", False)
        )
        self.install_btn.setVisible(can_install)
        if not can_install:
            lines = []
            if sys.platform == "darwin" and release.macos_url:
                lines.append(f"macOS build: {release.macos_url}")
            elif sys.platform.startswith("linux") and release.linux_url:
                lines.append(f"Linux build: {release.linux_url}")
            if lines:
                lines.append("Grab it from the releases page (button below) — this app "
                             "does not self-update on this platform.")
                self.status_label.setText(
                    f"New version available: v{release.version} — download it manually."
                )
            if release.notes:
                self.notes_text.setPlainText(release.notes)
                self.notes_text.setVisible(True)
                if lines:
                    self.notes_text.appendPlainText("\n" + "\n".join(lines))
        if self._auto_silent and can_install:
            self._start_download()

    def _on_up_to_date(self):
        self.status_label.setText(f"You are up to date (v{__version__}).")

    def _on_check_failed(self, error: str):
        if self.release is not None:
            # A release is already shown; a failed check must not replace it.
            self.notes_text.setVisible(True)
            self.notes_text.appendPlainText(f"\nThe update check could not be repeated:\n{error}")
            return
        self.status_label.setText("Could not check for updates.")
        self.notes_text.setVisible(True)
        self.notes_text.setPlainText(
            f"The update server could not be reached:\n{error}\n\n"
            "If this repository is private, the public API cannot see its releases.\n"
            "Use the button below to open the releases page in your browser instead."
        )

    # ---- download / install phase ---------------------------------------

    def _start_download(self):
        if not self.release or not self.release.installer_url:
            return
        self.install_btn.setEnabled(False)
        self.progress.setVisible(True)
        self.progress.setValue(0)
        self.status_label.setText(f"Downloading v{self.release.version}...")

        dest = updater.default_installer_destination(self.release.version)
        self._downloader = DownloadWorker(
            self.release.installer_url,
            dest,
            self.release.installer_sha256,
            signature_url=self.release.signature_url,
        )
        self._downloader.progress.connect(self.progress.setValue)
        self._downloader.done.connect(self._on_download_done)
        self._downloader.failed.connect(self._on_download_failed)
        self._downloader.start()

    def _on_download_done(self, path: str):
        self.progress.setValue(100)
        self.status_label.setText("Download complete. Starting the installer...")
        try:
            updater.apply_installer_update(path)
        except OSError as e:
            QMessageBox.warning(
                self,
                "Update",
                f"Could not start the installer automatically:\n{e}\n\n"
                f"The installer was saved to:\n{path}",
            )
            return
        # Hand off to the installer: quit this instance so files can be replaced.
        app = QApplication.instance()
        if app:
            app.quit()

    def _on_download_failed(self, error: str):
        self.progress.setVisible(False)
        self.install_btn.setEnabled(True)
        self.status_label.setText("Download failed.")
        QMessageBox.warning(
            self,
            "Update",
            f"Download failed:\n{error}\n\n"
            f"You can download the installer manually from the releases page.",
        )
