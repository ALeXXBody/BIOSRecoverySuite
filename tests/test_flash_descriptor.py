"""FLREG decoding: base is bits 14:0 and limit bits 30:16, both in 4 KB pages.

The 15-bit page field addresses 128 MB. Narrower fields would mis-place regions on
images larger than 32 MB, so the width is pinned by these tests.
"""

from bios_recovery.core.bios_analyzer import decode_flreg


def test_base_and_limit_fields():
    value = (0x1F << 16) | 0x10          # base page 0x10, limit page 0x1F (inclusive)
    assert decode_flreg(value) == (0x10 << 12, (0x1F << 12) | 0xFFF)


def test_regions_above_32_mb_are_decoded():
    # limit page 0x3FFF (128 MB boundary less one page) must not wrap
    value = (0x3FFF << 16) | 0x4000
    base, limit = decode_flreg(value)
    assert base == 0x4000 << 12
    assert limit == (0x3FFF << 12) | 0xFFF


def test_bits_outside_the_fields_do_not_leak_into_the_addresses():
    clean = (0x1F << 16) | 0x10
    dirty = clean | (1 << 15) | (1 << 31)
    assert decode_flreg(dirty) == decode_flreg(clean)


def test_unused_region_has_limit_below_base():
    base, limit = decode_flreg(0x00007FFF)  # base page 0x7FFF, limit page 0
    assert limit < base
