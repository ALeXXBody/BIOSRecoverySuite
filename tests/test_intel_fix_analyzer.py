"""Regression tests for the analyzer, rebuild gate and manifest findings (C1, M4, M5, M9, L2, L10).

Synthetic images only. The descriptor signature sits at 0x10, as on the real dumps; FRBA is 0x40
and all FLREG values are absolute (ifdtool find_frba, me_cleaner flreg_to_start_end).
"""

import hashlib
import struct

from bios_recovery.core import me_manifest
from bios_recovery.core.bios_analyzer import BiosAnalyzer, RegionInfo, RegionType
from bios_recovery.core.me_manifest import iter_manifest_versions
from bios_recovery.core.rebuild_verify import verify_rebuild
from bios_recovery.core.traits import ARCH_INTEL, classify

SIG = b"\x5a\xa5\xf0\x0f"


def _fd_image(size=0x400000):
    data = bytearray(b"\xff" * size)
    data[0x10:0x14] = SIG
    struct.pack_into("<I", data, 0x14, 0x00040000)  # FLMAP0: FRBA = 0x40
    struct.pack_into("<I", data, 0x18, 0x00000000)  # FLMAP1
    struct.pack_into("<I", data, 0x44, 0xFFFFFFFF)  # BIOS FLREG: unused
    struct.pack_into("<I", data, 0x48, 0x03FF0001)  # ME FLREG: 0x1000..0x3FFFFF
    data[0x1000:0x2000] = b"\x55" * 0x1000
    return data


def _manifest_at(data, base, version, key=b"\x00" * 0x104):
    data[base + 0x1C : base + 0x20] = b"$MN2"
    struct.pack_into("<HHHH", data, base + 0x24, *version)
    data[base + 0x80 : base + 0x80 + 0x104] = key


def test_descriptor_region_is_at_offset_zero_with_signature_recorded(tmp_path):
    path = tmp_path / "dump.bin"
    path.write_bytes(bytes(_fd_image()))
    result = BiosAnalyzer().analyze(str(path))
    fd = [r for r in result.regions if r.region_type == RegionType.FLASH_DESCRIPTOR]
    assert fd and fd[0].offset == 0 and fd[0].size == 0x1000
    assert fd[0].details["signature_offset"] == 0x10
    assert not any("unusual offset" in i for i in result.issues)


def test_gate_classifies_me_bytes_past_0x1000_as_me(tmp_path):
    original = _fd_image()
    candidate = bytearray(original)
    candidate[0x1005] ^= 0xFF
    a = tmp_path / "orig.bin"
    b = tmp_path / "cand.bin"
    a.write_bytes(bytes(original))
    b.write_bytes(bytes(candidate))
    result = verify_rebuild(str(a), str(b))
    assert result.accepted is True
    assert [s.kind for s in result.spans] == ["me"]


def test_gate_refuses_a_descriptor_change_at_0x0005(tmp_path):
    original = _fd_image()
    candidate = bytearray(original)
    candidate[0x0005] ^= 0xFF
    a = tmp_path / "orig.bin"
    b = tmp_path / "cand.bin"
    a.write_bytes(bytes(original))
    b.write_bytes(bytes(candidate))
    result = verify_rebuild(str(a), str(b))
    assert result.accepted is False
    assert [s.kind for s in result.spans] == ["descriptor"]


def test_txe_key_gives_txe_label_in_analyzer(monkeypatch):
    key = bytes((i * 7) & 0xFF for i in range(0x104))
    data = bytearray(b"\x00" * 0x400)
    _manifest_at(data, 0x0, (1, 1, 0, 1089), key)
    monkeypatch.setattr(
        me_manifest,
        "TXE_PUBKEY_MD5",
        frozenset({hashlib.md5(key).hexdigest()}),
    )
    regions = [RegionInfo(RegionType.INTEL_ME, 0, len(data), "Intel ME")]
    analyzer = BiosAnalyzer()
    assert analyzer._get_me_type(bytes(data), regions) == "TXE"


def test_unknown_key_keeps_version_based_label():
    data = bytearray(b"\x00" * 0x400)
    _manifest_at(data, 0x0, (1, 1, 0, 1089))
    regions = [RegionInfo(RegionType.INTEL_ME, 0, len(data), "Intel ME")]
    assert BiosAnalyzer()._get_me_type(bytes(data), regions) == "ME (Legacy)"


def test_txe_key_gives_txe_family_in_traits(monkeypatch):
    key = bytes((i * 7) & 0xFF for i in range(0x104))
    data = bytearray(b"\x00" * 0x400)
    _manifest_at(data, 0x0, (1, 1, 0, 1089), key)
    monkeypatch.setattr(
        me_manifest,
        "TXE_PUBKEY_MD5",
        frozenset({hashlib.md5(key).hexdigest()}),
    )
    traits = classify(bytes(data))
    assert traits.architecture == ARCH_INTEL
    assert traits.me_family == "TXE"


def test_version_is_the_most_common_manifest_not_the_largest():
    data = bytearray(b"\x00" * 0x400)
    _manifest_at(data, 0x000, (9, 0, 0, 1000))
    _manifest_at(data, 0x100, (9, 0, 0, 1000))
    _manifest_at(data, 0x200, (9, 0, 0, 2000))
    region = RegionInfo(RegionType.INTEL_ME, 0, len(data), "Intel ME")
    assert BiosAnalyzer()._decode_me_version(bytes(data), region) == "9.0.0.1000"


def test_manifest_cap_is_per_tag():
    blob = bytearray(b"$MN2" * 2100)
    tail = len(blob)
    blob += b"\x00" * 0x200
    _manifest_at(blob, tail, (11, 0, 0, 1))
    blob[tail + 0x1C : tail + 0x20] = b"$MAN"
    assert ("11.0.0.1", tail) in iter_manifest_versions(bytes(blob))
