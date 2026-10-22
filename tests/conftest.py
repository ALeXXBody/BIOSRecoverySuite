import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.fixture_builder import write_fixtures

os.environ.setdefault("BIOS_RECOVERY_NO_UPDATE_CHECK", "1")


@pytest.fixture(scope="session")
def fixtures(tmp_path_factory):
    return write_fixtures(str(tmp_path_factory.mktemp("fixtures")))


@pytest.fixture(scope="session")
def intel_ifd(fixtures):
    return fixtures["intel_ifd.bin"]


@pytest.fixture(scope="session")
def dell_pfs(fixtures):
    return fixtures["dell_pfs.bin"]


@pytest.fixture(scope="session")
def ec_firmware(fixtures):
    return fixtures["ec_firmware.bin"]


@pytest.fixture(scope="session")
def ec_dump(fixtures):
    return fixtures["ec_dump.bin"]


@pytest.fixture(scope="session")
def uefi_patch_image(fixtures):
    return fixtures["uefi_patch.bin"]


@pytest.fixture(scope="session")
def patcher():
    from bios_recovery.engines.uefi_patcher import UEFIPatcher

    return UEFIPatcher()


@pytest.fixture(scope="session")
def autopatch_image(fixtures):
    return fixtures["autopatch.bin"]


@pytest.fixture(autouse=True)
def _no_leftover_workers():
    """Each test's background jobs finish, and their results are delivered, inside that test.

    A result that lands during a later test could reach a window from an earlier one.
    """
    yield
    try:
        from PySide6.QtWidgets import QApplication

        from bios_recovery.gui.workers import wait_for_workers

        wait_for_workers()
        if QApplication.instance() is not None:
            QApplication.processEvents()
    except ImportError:
        pass


@pytest.fixture(scope="session", autouse=True)
def _qt_teardown():
    """Close windows and wait for workers before the interpreter tears Qt down."""
    yield
    try:
        from PySide6.QtWidgets import QApplication

        from bios_recovery.gui.workers import wait_for_workers

        wait_for_workers()
        app = QApplication.instance()
        if app is not None:
            for widget in app.topLevelWidgets():
                widget.close()
                widget.deleteLater()
            app.processEvents()
    except ImportError:
        pass
