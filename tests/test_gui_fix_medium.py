"""Regression tests for GUI, CLI and updater findings from the GUI audit (F-06 to F-33)."""

import io
import os
import types

import pytest

from tests.fixture_builder import build_intel_ifd_image
from tests.test_gui_exercise import qapp  # noqa: F401


def _intel_image(tmp_path):
    path = tmp_path / "intel.bin"
    path.write_bytes(build_intel_ifd_image())
    return path


# ---- F-06: the dialog shown after a startup check makes no second request -----------


def test_update_dialog_from_startup_does_not_check_again(qapp, monkeypatch):  # noqa: F811
    from bios_recovery.gui import update_dialog as ud
    from bios_recovery.utils.updater import ReleaseInfo

    requests = []
    monkeypatch.setattr(ud, "CheckWorker", lambda: requests.append(1))
    dialog = ud.UpdateDialog(None, auto_check=False)
    dialog.present_release(ReleaseInfo(version="9.9.9", notes="notes", html_url="u"))
    assert requests == []


def test_failed_recheck_keeps_the_release_on_screen(qapp, monkeypatch):  # noqa: F811
    from bios_recovery.gui import update_dialog as ud
    from bios_recovery.utils.updater import ReleaseInfo

    monkeypatch.setattr(ud, "CheckWorker", lambda: None)
    dialog = ud.UpdateDialog(None, auto_check=False)
    dialog.present_release(ReleaseInfo(version="9.9.9", notes="release notes", html_url="u"))
    shown = dialog.status_label.text()
    dialog._on_check_failed("network down")
    assert dialog.release is not None
    assert dialog.status_label.text() == shown
    assert "release notes" in dialog.notes_text.toPlainText()
    assert "network down" in dialog.notes_text.toPlainText()


# ---- F-07: an invalid manual offset stops the action; it never falls back ------------


def test_bad_manual_offset_does_not_run_auto_detection(qapp, tmp_path, monkeypatch):  # noqa: F811
    from PySide6.QtWidgets import QMessageBox

    from bios_recovery.gui.ec_tab import ECTab

    monkeypatch.setattr(QMessageBox, "warning", lambda *a, **k: None)
    tab = ECTab()
    dump = tmp_path / "dump.bin"
    dump.write_bytes(b"\xff" * 0x100000)
    tab.current_dump = str(dump)
    tab.override_check.setChecked(True)
    tab.override_offset.setText("ZZZ")
    calls = []
    monkeypatch.setattr(tab.patcher, "analyze_ec", lambda *a, **k: calls.append(a))
    tab.analyze()
    assert calls == []


# ---- F-08 / F-17: DVAR, Apple and ME Analyzer follow the tool matrix ------------------


def test_tool_buttons_follow_the_traits_matrix(qapp, tmp_path):  # noqa: F811
    from bios_recovery.core.traits import classify
    from bios_recovery.core.traits_matrix import tool_matrix
    from bios_recovery.gui.main_window import MainWindow

    traits = classify(_intel_image(tmp_path).read_bytes())
    matrix = tool_matrix(traits)
    dvar = matrix["Dell DVAR Recovery"]
    assert dvar.applies is False
    win = MainWindow()
    win._apply_traits(traits)
    assert not win.dvar_btn.isEnabled()
    assert dvar.reason in win.dvar_btn.toolTip()
    assert win.apple_btn.isEnabled() == matrix["Apple Fsys Tools"].applies
    assert win._mea_action.isEnabled() == matrix["ME Cleaner"].applies


# ---- F-12: shipped DXE binaries resolve; derived entries are stored with a usable path -


def test_shipped_dxe_entries_find_their_binaries(qapp):  # noqa: F811
    from bios_recovery.gui.lenovo_tab import LenovoTab

    tab = LenovoTab()
    labels = [tab.dxe_table.item(i, 1).text() for i in range(tab.dxe_table.rowCount())]
    assert labels
    assert not any("binary missing" in label for label in labels)


def test_derived_entries_are_saved_outside_the_program_folder(tmp_path, monkeypatch):
    from bios_recovery.platforms.intel.uefi_patcher import UEFIPatcher

    config = tmp_path / "config"
    monkeypatch.setenv("BIOS_RECOVERY_CONFIG_DIR", str(config))
    binary = tmp_path / "derived" / "x.ffs"
    binary.parent.mkdir()
    binary.write_bytes(b"ffs")
    patcher = UEFIPatcher()
    entry = {
        "key": "derived_test",
        "file": str(binary),
        "target_guid": "00000000-0000-0000-0000-000000000001",
        "description": "",
        "verified": False,
        "source": "",
    }
    added = patcher.add_user_dxe_replacements([entry])
    assert [e["key"] for e in added] == ["derived_test"]
    assert (config / "dxe_replacements.json").exists()
    loaded = {e["key"]: e for e in UEFIPatcher().load_dxe_replacements()}
    assert loaded["derived_test"]["file"] == str(binary)
    assert patcher.dxe_binary_path(str(binary)) == str(binary)
    assert patcher.add_user_dxe_replacements([entry]) == []


def test_derive_records_absolute_binary_paths(tmp_path):
    from bios_recovery.platforms.intel.uefi_patcher import UEFIPatcher
    from tests.fixture_builder import build_uefi_patch_image

    original = tmp_path / "orig.bin"
    original.write_bytes(build_uefi_patch_image())
    patched = tmp_path / "patched.bin"
    UEFIPatcher().apply(str(original), str(patched))
    derived = UEFIPatcher().derive_replacements(
        str(original), str(patched), str(tmp_path / "drv")
    )
    assert derived
    assert all(os.path.isabs(d["file"]) and os.path.isfile(d["file"]) for d in derived)


# ---- F-14 / F-25 / F-26: output names and overwrite prompts --------------------------


def test_output_names_keep_the_directory_of_a_dotted_path():
    from bios_recovery.gui.outputs import derived_path

    assert derived_path("/data/v1.2/dump", "_repaired.bin") == "/data/v1.2/dump_repaired.bin"
    assert derived_path("/data/dump.bin", "_repaired.bin") == "/data/dump_repaired.bin"


def test_unique_path_never_returns_an_existing_file(tmp_path):
    from bios_recovery.gui.outputs import unique_path

    (tmp_path / "chip_prewrite_backup.bin").write_bytes(b"1")
    assert unique_path(str(tmp_path / "chip_prewrite_backup.bin")) == str(
        tmp_path / "chip_prewrite_backup_1.bin"
    )


def test_overwrite_prompt_defaults_to_no(qapp, tmp_path, monkeypatch):  # noqa: F811
    from PySide6.QtWidgets import QMessageBox

    from bios_recovery.gui.outputs import confirm_overwrite

    seen = {}

    def fake(*args, **kwargs):
        seen["default"] = args[-1]
        return QMessageBox.StandardButton.No

    monkeypatch.setattr(QMessageBox, "question", fake)
    target = tmp_path / "out.bin"
    target.write_bytes(b"1")
    assert confirm_overwrite(None, str(target)) is False
    assert seen["default"] == QMessageBox.StandardButton.No


def test_chip_write_confirmation_defaults_to_no(qapp, tmp_path, monkeypatch):  # noqa: F811
    from PySide6.QtWidgets import QMessageBox

    from bios_recovery.gui.spi_tab import SPITab

    seen = {}

    def fake(*args, **kwargs):
        seen["default"] = args[-1]
        return QMessageBox.StandardButton.No

    monkeypatch.setattr(QMessageBox, "question", fake)
    image = tmp_path / "bios.bin"
    image.write_bytes(b"\xff" * 16)
    SPITab()._confirm_and_write(str(image))
    assert seen["default"] == QMessageBox.StandardButton.No


# ---- F-22 / F-24 / repair-report notes: messages say what happened ---------------------


def test_result_for_a_previous_image_is_labelled(qapp, tmp_path):  # noqa: F811
    from bios_recovery.gui.me_region_page import MERegionPage

    current = tmp_path / "new.bin"
    page = MERegionPage(image_provider=lambda: str(current))
    lines = page._for_image(str(tmp_path / "old.bin"), ["result"])
    assert "old.bin" in lines[0]
    assert page._for_image(str(current), ["result"]) == ["result"]


def _report(**kw):
    base = {
        "success": False,
        "output_path": "",
        "operations": [],
        "warnings": [],
        "issues_found": [],
        "message": "",
    }
    base.update(kw)
    return types.SimpleNamespace(**base)


def test_graft_with_nothing_grafted_shows_no_output_path(qapp, tmp_path):  # noqa: F811
    from bios_recovery.gui.main_window import MainWindow

    win = MainWindow()
    win._graft_done(_report(warnings=["No region was graftable; no output written"]))
    text = win.repair_text.toPlainText()
    assert "Output:" not in text
    assert "Graft Failed" in text
    assert "no file" in win.statusBar().currentMessage()


def test_repair_that_changed_nothing_reports_no_file(qapp):  # noqa: F811
    from bios_recovery.gui.main_window import MainWindow

    win = MainWindow()
    win._repair_done(_report(output_path="/tmp/x_repaired.bin"))
    text = win.repair_text.toPlainText()
    assert "Output:" not in text
    assert "no file was written" in text


def test_refused_identity_edit_is_not_reported_as_written(qapp):  # noqa: F811
    from bios_recovery.gui.main_window import MainWindow

    win = MainWindow()
    win._dmi_edit_done(_report(output_path="/tmp/x_edited.bin", message="refused"))
    assert "Identity edit written" not in win.statusBar().currentMessage()
    assert "Output:" not in win.dmi_text.toPlainText()


def test_apple_fsys_result_names_the_written_file(qapp):  # noqa: F811
    from bios_recovery.gui.main_window import MainWindow

    win = MainWindow()
    win._apple_fsys_done(
        _report(success=True, message="repaired", output_path="/tmp/rom_fsysfixed.bin")
    )
    assert "Output: /tmp/rom_fsysfixed.bin" in win.password_text.toPlainText()


# ---- F-09 / F-19: command line -------------------------------------------------------


def test_unknown_flag_is_refused_without_starting_the_gui(monkeypatch, capsys):
    from bios_recovery import main as cli

    monkeypatch.setattr(cli.sys, "argv", ["bios-recovery", "--bogus-flag"])
    assert cli.main() == 2
    assert "unknown option" in capsys.readouterr().err


def test_help_lists_exit_code_3():
    from bios_recovery import main as cli

    assert "3 refused" in cli._CLI_HELP


# ---- F-20 / F-16: updater ------------------------------------------------------------


class _Resp(io.BytesIO):
    def __init__(self, body, final_url):
        super().__init__(body)
        self._final_url = final_url

    def geturl(self):
        return self._final_url

    def getheader(self, name):
        return None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_download_refuses_a_redirect_to_plain_http(tmp_path, monkeypatch):
    from bios_recovery.utils import updater as up

    dest = tmp_path / "setup.exe"
    monkeypatch.setattr(
        up.urllib.request,
        "urlopen",
        lambda *a, **k: _Resp(b"MZ", "http://example.invalid/setup.exe"),
    )
    with pytest.raises(up.UpdateIntegrityError, match="non-HTTPS"):
        up.download("https://example.invalid/setup.exe", str(dest))
    assert not dest.exists()


def test_installer_that_exits_at_once_is_reported_as_not_started(tmp_path, monkeypatch):
    from bios_recovery.utils import updater as up

    installer = tmp_path / "setup.exe"
    installer.write_bytes(b"MZ")

    class _Proc:
        def wait(self, timeout=None):
            return 1

    monkeypatch.setattr(up.subprocess, "Popen", lambda *a, **k: _Proc())
    monkeypatch.setattr(up, "sys", types.SimpleNamespace(platform="win32"))
    with pytest.raises(OSError, match="did not start"):
        up.apply_installer_update(str(installer))
