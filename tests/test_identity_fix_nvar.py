"""Identity audit fixes for NVAR carry-over: model check, DATA_ONLY records, superseded copies."""

import struct

from bios_recovery.core.nvar import carry_identity, identity_copies, iter_records


def _rec(name: bytes, data: bytes, attrs: int = 0x82) -> bytes:
    """ASCII-named record with a valid bit by default (0x80 valid, 0x02 ASCII name)."""
    body = name + b"\x00" + data
    total = 0x0B + len(body)
    head = b"NVAR" + struct.pack("<H", total) + b"\xff\xff\xff" + bytes([attrs]) + b"\xff"
    return head + body


def _image(*records: bytes) -> bytearray:
    return bytearray(b"\xff" * 0x40 + b"".join(records) + b"\xff" * 0x40)


def test_identity_from_another_board_model_is_refused():
    old = bytes(_image(_rec(b"MFG0", b"X510UA SN00000000001")))
    new = _image(_rec(b"MFG0", b"FX80GE SN00000000002"))
    before = bytes(new)

    rep = carry_identity(old, new)

    assert not rep.success
    assert "model" in rep.refused
    assert bytes(new) == before


def test_identity_from_the_same_board_model_is_carried():
    old = bytes(_image(_rec(b"MFG0", b"X510UA SN00000000001")))
    new = _image(_rec(b"MFG0", b"X510UA SN00000000002"))

    rep = carry_identity(old, new)

    assert rep.success, rep.refused
    assert [r.data for r in iter_records(bytes(new))] == [b"X510UA SN00000000001"]


def test_model_check_can_be_overridden_explicitly():
    old = bytes(_image(_rec(b"MFG0", b"X510UA SN00000000001")))
    new = _image(_rec(b"MFG0", b"FX80GE SN00000000002"))

    assert carry_identity(old, new, force=True).success


def test_data_only_record_is_not_taken_for_an_identity_variable():
    # attribute 0x08: the payload has no name, so MFG0 text inside it is just data
    payload = b"MFG0\x00X510UA SN0000000003"
    total = 0x0B + len(payload)
    head = b"NVAR" + struct.pack("<H", total) + b"\xff\xff\xff" + bytes([0x88]) + b"\xff"
    data_only = head + payload
    image = bytes(_image(data_only))

    recs = iter_records(image)
    assert recs and recs[0].name is None
    assert "MFG0" not in identity_copies(image)


def test_superseded_identity_copy_of_the_same_size_gets_the_live_data():
    old = bytes(_image(_rec(b"MFG0", b"OLD-SERIAL-01")))
    new = _image(
        _rec(b"MFG0", b"NEW-SERIAL-99"),
        _rec(b"MFG0", b"STALE-NEW-009", attrs=0x02),  # superseded (valid bit clear)
    )

    rep = carry_identity(old, new)

    assert rep.success, rep.refused
    stale = [r for r in iter_records(bytes(new)) if r.attributes & 0x80 == 0]
    assert len(stale) == 1
    assert stale[0].data == b"OLD-SERIAL-01"
    assert stale[0].attributes == 0x02
