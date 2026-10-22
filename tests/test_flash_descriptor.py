"""FLREG decoding: base is bits 12:0 and limit bits 28:16, both in 4 KB pages."""

from bios_recovery.core.bios_analyzer import decode_flreg


def test_base_and_limit_fields():
    # base page 0x10, limit page 0x1F (inclusive)
    value = (0x1F << 16) | 0x10
    assert decode_flreg(value) == (0x10 << 12, (0x1F << 12) | 0xFFF)


def test_bits_outside_the_fields_do_not_leak_into_the_addresses():
    # bits 13-15 (below the limit field) and 29-31 (above it) must not change the result
    clean = (0x1F << 16) | 0x10
    dirty = clean | (0x7 << 13) | (0x7 << 29)
    assert decode_flreg(dirty) == decode_flreg(clean)


def test_unused_region_has_limit_below_base():
    base, limit = decode_flreg(0x00001FFF)  # base page 0x1FFF, limit page 0
    assert limit < base  # ifdtool treats such a region as unused
