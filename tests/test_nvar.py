"""AMI NVAR identity carry-over: parsing, live copies, and the all-or-nothing rule."""

import struct

from bios_recovery.core.nvar import carry_identity, iter_records


def _nvar(name: bytes, data: bytes, valid: bool = True) -> bytes:
    attr = 0x03 | (0x80 if valid else 0x00)  # ASCII name, runtime; valid bit
    body = name + b"\x00" + data
    total = 0x0B + len(body)
    head = b"NVAR" + struct.pack("<H", total) + b"\xff\xff\xff" + bytes([attr]) + b"\xff"
    return head + body


def _image(*records: bytes, pad: int = 0x40) -> bytearray:
    return bytearray(b"\xff" * pad + b"".join(records) + b"\xff" * pad)


def test_parses_name_and_data():
    img = _image(_nvar(b"MFG0", b"SERIAL123"))
    recs = iter_records(bytes(img))
    assert [(r.name, r.data) for r in recs] == [("MFG0", b"SERIAL123")]


def test_carries_identity_into_a_same_sized_image():
    old = bytes(_image(_nvar(b"MFG0", b"OLD-SERIAL-01")))
    new = _image(_nvar(b"MFG0", b"NEW-SERIAL-99"))
    rep = carry_identity(old, new)
    assert rep.success and rep.copied == ["MFG0"]
    assert [r.data for r in iter_records(bytes(new))] == [b"OLD-SERIAL-01"]


def test_superseded_copies_are_ignored_and_all_valid_copies_are_written():
    old = bytes(_image(_nvar(b"MFG0", b"STALE", valid=False), _nvar(b"MFG0", b"LIVE-VALUE")))
    new = _image(_nvar(b"MFG0", b"aaaaaaaaaa"), _nvar(b"MFG0", b"bbbbbbbbbb"))
    rep = carry_identity(old, new)
    assert rep.success
    assert [r.data for r in iter_records(bytes(new))] == [b"LIVE-VALUE", b"LIVE-VALUE"]


def test_refuses_when_the_new_image_has_a_different_size():
    old = bytes(_image(_nvar(b"MFG0", b"0123456789")))
    new = _image(_nvar(b"MFG0", b"short"))
    before = bytes(new)
    rep = carry_identity(old, new)
    assert not rep.success and "differs" in rep.refused
    assert bytes(new) == before  # nothing written


def test_refuses_when_one_identity_variable_is_missing_in_the_new_image():
    old = bytes(_image(_nvar(b"MFG0", b"ABCDEFGHIJ"), _nvar(b"_DMI", b"XYZ")))
    new = _image(_nvar(b"MFG0", b"0123456789"))
    before = bytes(new)
    rep = carry_identity(old, new)
    assert not rep.success and "_DMI" in rep.refused
    assert bytes(new) == before


def test_refuses_blank_identity_in_the_old_dump():
    old = bytes(_image(_nvar(b"MFG0", b"\xff" * 10)))
    new = _image(_nvar(b"MFG0", b"0123456789"))
    assert not carry_identity(old, new).success


def test_refuses_when_the_new_image_has_an_identity_variable_the_old_lacks():
    old = bytes(_image(_nvar(b"MFG0", b"0123456789")))
    new = _image(_nvar(b"MFG0", b"aaaaaaaaaa"), _nvar(b"_DMI", b"bbbbbbbbbb"))
    before = bytes(new)
    rep = carry_identity(old, new)
    assert not rep.success and "_DMI" in rep.refused
    assert bytes(new) == before


def test_identity_listing_shows_readable_text_not_raw_bytes():
    from bios_recovery.core.dmi_extractor import nvram_identity

    img = bytes(_image(_nvar(b"MFG0", b"\x01\x02SERIAL-XYZ\x00\xff")))
    items = nvram_identity(img)
    assert [(i["name"], i["copies"]) for i in items] == [("MFG0", 1)]
    assert "SERIAL-XYZ" in items[0]["text"]
