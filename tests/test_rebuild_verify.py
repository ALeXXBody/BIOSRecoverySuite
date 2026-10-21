"""Rebuild gate: accept only ME-region changes, refuse everything else."""

import pytest

from bios_recovery.core.rebuild_verify import verify_rebuild, changed_spans
from bios_recovery.core.bios_analyzer import BiosAnalyzer
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
    me = [r for r in BiosAnalyzer().analyze(str(src)).regions
          if r.region_type.name == "INTEL_ME" and "FPT" not in r.name]
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
