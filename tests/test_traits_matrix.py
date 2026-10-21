"""Tests for traits classification and the GUI tool-availability matrix."""

import sys

from bios_recovery.core.traits import ARCH_AMD, ARCH_INTEL, classify
from bios_recovery.core.traits_matrix import tool_matrix


def test_classify_amd_asus_dump():
    import os
    p = '/home/truenas_admin/drop/E1504FAFAS_flashable.bin'
    if not os.path.exists(p):
        import pytest
        pytest.skip("real dump not present")
    t = classify(open(p, 'rb').read())
    assert t.architecture == ARCH_AMD
    assert t.vendor == "asus"


def test_classify_intel_dell_dump():
    import os
    p = '/home/truenas_admin/drop/outimage.bin'
    if not os.path.exists(p):
        import pytest
        pytest.skip("real dump not present")
    t = classify(open(p, 'rb').read())
    assert t.architecture == ARCH_INTEL
    assert t.vendor == "dell"
    assert t.me_family.startswith("CSME")


def test_matrix_gates_intel_tools_off_amd():
    t = classify(b"$PSP\x00" + b"A" * 200)
    row = tool_matrix(t)["ME Cleaner"]
    assert not row.applies
    assert "AMD" in row.reason or "not applicable" in row.reason.lower()


def test_matrix_not_applicable_for_lenovo_tab_on_generic():
    t = classify(b"\x00" * 64)
    row = tool_matrix(t)["Lenovo Unlock"]
    assert not row.applies
