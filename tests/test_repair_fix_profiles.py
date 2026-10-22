"""Regression tests for manufacturer detection false positives (L3)."""

import random

from bios_recovery.manufacturers.profiles import Manufacturer, ManufacturerProfiles


def test_random_bytes_are_not_detected_as_a_manufacturer():
    """L3: two-letter tokens such as HP occur in random data; they must not identify a vendor."""
    profiles = ManufacturerProfiles()
    rng = random.Random(7)
    for _ in range(40):
        blob = bytes(rng.randrange(256) for _ in range(8192))
        assert profiles.detect_manufacturer(blob) is Manufacturer.UNKNOWN


def test_a_short_token_alone_is_not_enough():
    profiles = ManufacturerProfiles()
    assert profiles.detect_manufacturer(b"\x00\x01HP\x02\x00") is Manufacturer.UNKNOWN


def test_vendor_strings_are_still_detected():
    profiles = ManufacturerProfiles()
    assert profiles.detect_manufacturer(b"\x00LENOVO ThinkPad T450\x00") is Manufacturer.LENOVO
    assert profiles.detect_manufacturer(b"\x00Dell Inc.\x00") is Manufacturer.DELL
    assert profiles.detect_manufacturer(b"\x00Hewlett-Packard\x00\x00HP\x00") is Manufacturer.HP
