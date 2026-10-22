"""Patch registries must ship with the app and a missing one must be reported (audit F-02)."""

import os
import re

from bios_recovery.platforms.ec.ec_patcher import ECPatcher
from bios_recovery.platforms.intel.uefi_patcher import UEFIPatcher

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_default_registries_are_found_from_the_source_tree():
    assert ECPatcher().load_error is None
    assert UEFIPatcher().load_error is None


def test_missing_registry_is_reported_not_silently_empty(tmp_path):
    assert "not found" in ECPatcher(str(tmp_path / "missing.json")).load_error
    assert "not found" in UEFIPatcher(str(tmp_path / "missing.txt")).load_error


def test_spec_bundles_the_patch_folder():
    with open(os.path.join(ROOT, "bios_recovery.spec"), encoding="utf-8") as f:
        spec = f.read()
    assert re.search(r'\("bios_recovery/patches",\s*"bios_recovery/patches"\)', spec)


def test_pyproject_uses_the_public_build_backend_and_ships_patches():
    with open(os.path.join(ROOT, "pyproject.toml"), encoding="utf-8") as f:
        text = f.read()
    assert 'build-backend = "setuptools.build_meta"' in text
    assert "patches/*.json" in text
