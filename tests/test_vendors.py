"""Vendor recognition from BIOS brand markers (one synthetic image per vendor)."""

import pytest

from bios_recovery.core.traits import _VENDOR_MARKERS, classify


@pytest.mark.parametrize(
    "vendor, marker",
    [(v, m) for v, markers in _VENDOR_MARKERS.items() for m in markers],
)
def test_each_marker_identifies_its_vendor(vendor, marker):
    data = b"\xFF" * 0x1000 + b"\x00" * 0x40 + marker + b"\x00" * 0x40
    assert classify(data).vendor == vendor


def test_msi_and_razer_are_recognised():
    msi = b"\xFF" * 0x800 + b"MICRO-STAR INTERNATIONAL CO., LTD" + b"\xFF" * 0x800
    razer = b"\xFF" * 0x800 + b"Razer Blade" + b"\xFF" * 0x800
    assert classify(msi).vendor == "msi"
    assert classify(razer).vendor == "razer"


def test_unbranded_image_stays_generic():
    assert classify(b"\xFF" * 0x4000).vendor == "generic"


def test_msi_notebook_identity_string():
    data = b"\xFF" * 0x800 + b"MSI_NBMEGABOOKWINDOWS" + b"\xFF" * 0x800
    assert classify(data).vendor == "msi"


def test_secure_boot_certificate_names_are_not_a_vendor():
    # Microsoft's UEFI CA names appear in almost every modern image.
    data = b"\xFF" * 0x800 + b"Microsoft Corporation UEFI CA 2011" + b"\xFF" * 0x800
    assert classify(data).vendor == "generic"


def test_t2_marker_not_matched_inside_efi_variable_names():
    from bios_recovery.core.traits import ARCH_APPLE_T2
    data = b"\xFF" * 0x800 + b"UefiBootPathSecurity FastEfiBootOption" + b"\xFF" * 0x800
    assert classify(data).architecture != ARCH_APPLE_T2


def test_t2_marker_matches_as_a_word():
    from bios_recovery.core.traits import ARCH_APPLE_T2
    data = b"\xFF" * 0x800 + b"iBoot stage 2" + b"\xFF" * 0x800
    assert classify(data).architecture == ARCH_APPLE_T2
