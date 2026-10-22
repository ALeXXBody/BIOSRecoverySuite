"""Rebuild gate: accept only ME-region changes, refuse everything else."""

import pytest

from bios_recovery.core.bios_analyzer import BiosAnalyzer
from bios_recovery.core.rebuild_verify import changed_spans, verify_rebuild
from tests.fixture_builder import build_intel_ifd_image


@pytest.fixture
def ifd(tmp_path):
    src = tmp_path / "src.bin"
    src.write_bytes(build_intel_ifd_image())
    return src


def _edit(tmp_path, src, edits, name="cand.bin"):
    """Flip the given bytes so every edit really changes the image."""
    data = bytearray(src.read_bytes())
    for off, _val in edits:
        data[off] ^= 0x5A
    out = tmp_path / name
    out.write_bytes(bytes(data))
    return str(out)


def _me_offset(src):
    """An offset inside the ME region the descriptor declares (the fixture declares one)."""
    me = [
        r
        for r in BiosAnalyzer().analyze(str(src)).regions
        if r.region_type.name == "INTEL_ME" and "FPT" not in r.name
    ]
    assert me, "fixture declares an ME region"
    return me[0].offset + 0x2000


def test_identical_image_is_refused(tmp_path, ifd):
    r = verify_rebuild(str(ifd), str(ifd))
    assert not r.accepted and "no bytes changed" in r.reasons


def test_me_only_change_is_accepted(tmp_path, ifd):
    cand = _edit(tmp_path, ifd, [(_me_offset(ifd), 0xA5)])
    r = verify_rebuild(str(ifd), cand)
    assert r.accepted, r.reasons
    assert r.changed_bytes == 1


def test_bios_change_is_refused(tmp_path, ifd):
    cand = _edit(tmp_path, ifd, [(0x402000, 0x5A)])
    r = verify_rebuild(str(ifd), cand)
    assert not r.accepted
    assert any(s.kind == "bios" for s in r.refused_spans)


def test_descriptor_change_is_refused(tmp_path, ifd):
    cand = _edit(tmp_path, ifd, [(0x20, 0x77)])
    r = verify_rebuild(str(ifd), cand)
    assert not r.accepted
    assert any(s.kind == "descriptor" for s in r.refused_spans)


def test_size_change_is_refused(tmp_path, ifd):
    data = ifd.read_bytes()
    out = tmp_path / "short.bin"
    out.write_bytes(data[:-16])
    r = verify_rebuild(str(ifd), str(out))
    assert not r.accepted and any("size" in x for x in r.reasons)


def test_boot_guard_manifest_adds_warning(tmp_path, ifd):
    data = bytearray(ifd.read_bytes())
    data[0x500000:0x500008] = b"__ACBP__\x00"
    ifd.write_bytes(bytes(data))
    cand = _edit(tmp_path, ifd, [(_me_offset(ifd), 0xA5)])
    r = verify_rebuild(str(ifd), cand)
    assert r.accepted and r.boot_guard_tags == ["__ACBP__"]
    assert any("Boot Guard" in x for x in r.reasons)


def test_spans_merge_across_small_gaps():
    a = bytes(100)
    b = bytearray(a)
    b[10] = 1
    b[14] = 1
    b[90] = 1
    assert changed_spans(a, bytes(b), merge_gap=16) == [(10, 15), (90, 91)]


def test_cli_verify_rebuild_exit_codes(tmp_path, ifd, capsys):
    from bios_recovery.main import _verify_rebuild_cli

    cand = _edit(tmp_path, ifd, [(_me_offset(ifd), 0)])
    assert _verify_rebuild_cli([str(ifd), cand]) == 0
    bad = _edit(tmp_path, ifd, [(0x402000, 0)], name="bad.bin")
    assert _verify_rebuild_cli([str(ifd), bad]) == 3
    assert "REFUSE" in capsys.readouterr().out


def test_bpdt_header_block_is_me_layer(tmp_path):
    # A BPDT header block (0xAA 0x55 0 0, 13 entries, major 2) in the ME area is ME data.
    import struct as _s

    data = bytearray(b"\xff" * 0x10000)
    data[0x2000:0x2004] = b"\xaa\x55\x00\x00"
    _s.pack_into("<HH", data, 0x2004, 13, 0x0201)
    src = tmp_path / "bpdt.bin"
    src.write_bytes(bytes(data))
    cand = bytearray(data)
    cand[0x2010] ^= 0x5A
    out = tmp_path / "bpdt_cand.bin"
    out.write_bytes(bytes(cand))
    r = verify_rebuild(str(src), str(out))
    assert r.accepted, r.reasons
    assert r.spans[0].kind == "me"


def test_run_across_unclaimed_gap_is_refused(tmp_path):
    # Two ME (BPDT) blocks with an unclaimed gap between them. A rewrite that starts in
    # one block and ends in the other must not be accepted just because its first and last
    # bytes are in ME space.
    import struct as _s

    data = bytearray(b"\xff" * 0x10000)
    for off in (0x1000, 0x3000):
        data[off : off + 4] = b"\xaa\x55\x00\x00"
        _s.pack_into("<HH", data, off + 4, 13, 0x0201)
    data[0x2000:0x3000] = b"\x00" * 0x1000
    src = tmp_path / "gap.bin"
    src.write_bytes(bytes(data))
    cand = bytearray(data)
    for i in range(0x1FF0, 0x3010):
        cand[i] ^= 0x5A
    out = tmp_path / "gap_cand.bin"
    out.write_bytes(bytes(cand))
    r = verify_rebuild(str(src), str(out))
    assert not r.accepted
    assert any(s.kind == "unclaimed" for s in r.refused_spans)
