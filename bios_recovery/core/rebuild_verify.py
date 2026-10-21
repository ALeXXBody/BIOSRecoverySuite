"""Read-only gate for a rebuilt flash image, checked region by region.

A rebuilt image (from Intel's FIT or MFIT, or any other tool) is accepted only
if every changed byte lies in a region the policy allows. The default policy
allows the Intel ME region and nothing else. Changes to the BIOS, the flash
descriptor, other descriptor regions, or unclaimed gaps are refused.

Boot Guard manifests in the image are reported because a change outside the ME
region can stop a Boot Guard board from starting, even when the tool reports
success. The gate never writes to any file.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

import struct
from typing import Optional

from bios_recovery.core.bios_analyzer import BiosAnalyzer, RegionInfo, RegionType

BOOT_GUARD_TAGS = (b"__ACBP__", b"__KEYM__", b"__IBBM__")
MAX_SPANS_REPORTED = 20

# Region kinds from the analyzer, mapped to what a rebuild may change.
_KIND = {
    RegionType.INTEL_ME: "me",
    RegionType.TXE: "me",
    RegionType.FLASH_DESCRIPTOR: "descriptor",
    RegionType.BIOS: "bios",
    RegionType.FIRMWARE_VOLUME: "bios",
    RegionType.PLATFORM_DATA: "other",
    RegionType.GBE: "other",
}


@dataclass
class ChangedSpan:
    start: int
    end: int
    kind: str           # "me" | "descriptor" | "bios" | "other" | "unclaimed" | "mixed"
    region: str

    @property
    def size(self) -> int:
        return self.end - self.start


@dataclass
class VerifyResult:
    original_size: int
    candidate_size: int
    changed_bytes: int = 0
    spans: list = field(default_factory=list)
    refused_spans: list = field(default_factory=list)
    boot_guard_tags: list = field(default_factory=list)
    reasons: list = field(default_factory=list)
    accepted: bool = False

    def summary(self) -> str:
        if self.accepted:
            verdict = "ACCEPT (region check only; this does not test that the board boots)"
        else:
            verdict = "REFUSE"
        return f"{verdict}: {self.changed_bytes} bytes changed in {len(self.spans)} spans"


def changed_spans(a: bytes, b: bytes, merge_gap: int = 16) -> list[tuple[int, int]]:
    """(start, end) runs where the two images differ, merged across small gaps."""
    spans: list[list[int]] = []
    n = min(len(a), len(b))
    i = 0
    while i < n:
        if a[i] == b[i]:
            i += 1
            continue
        start = i
        while i < n and a[i] != b[i]:
            i += 1
        if spans and start - spans[-1][1] <= merge_gap:
            spans[-1][1] = i
        else:
            spans.append([start, i])
    if len(a) != len(b):
        spans.append([n, max(len(a), len(b))])
    return [(s, e) for s, e in spans]


def me_bounds_from_fpt(data: bytes, analyzer: BiosAnalyzer) -> Optional[tuple[int, int]]:
    """ME region bounds from its own partition table, when the descriptor does not declare them.

    Regions are 4 KB aligned, so the ME region starts at the 4 KB boundary at or below
    the FPT header. The region ends at the furthest partition end. Partitions outside
    the image, or a table with no usable entry, give no bounds.
    """
    positions = analyzer._fpt_positions(data)
    for pos in positions:
        base = pos & ~0xFFF
        if base < 0 or pos + 0x20 > len(data):
            continue
        entries = struct.unpack_from("<I", data, pos + 4)[0]
        end = 0
        for i in range(entries):
            off = pos + 0x20 + i * 0x20
            if off + 0x10 > len(data):
                break
            part_off, part_len = struct.unpack_from("<II", data, off + 8)
            if part_off in (0, 0xFFFFFFFF) or part_len in (0, 0xFFFFFFFF):
                continue
            end = max(end, base + part_off + part_len)
        if end and end <= len(data):
            return base, end
    return None


def bpdt_blocks(data: bytes, bios_spans: list) -> list[tuple[int, int]]:
    """4 KB boot-partition descriptor table headers that belong to the ME (IFWI) layer.

    A BPDT header is 0x55AA (as 0xAA 0x55 0x00 0x00), a descriptor count of 1 to 32, and
    a major version of 1 or 2. Blocks overlapping a BIOS or firmware-volume span are
    excluded; they are firmware, not ME layout.
    """
    found = []
    for off in range(0, len(data) - 8, 0x1000):
        if data[off:off + 4] != b"\xaa\x55\x00\x00":
            continue
        count = struct.unpack_from("<H", data, off + 4)[0]
        major = data[off + 6]
        if not (1 <= count <= 32 and major in (1, 2)):
            continue
        if any(lo < off + 0x1000 and hi > off for lo, hi in bios_spans):
            continue
        found.append((off, 0x1000))
    return found


def _kind_at(offset: int, regions) -> tuple[str, str]:
    for r in regions:
        if r.offset <= offset < r.offset + r.size:
            return _KIND.get(r.region_type, "other"), r.name or r.region_type.name
    return "unclaimed", "unclaimed"


def verify_rebuild(original_path: str, candidate_path: str,
                   allow: tuple = ("me",)) -> VerifyResult:
    with open(original_path, "rb") as f:
        a = f.read()
    with open(candidate_path, "rb") as f:
        b = f.read()

    analyzer = BiosAnalyzer()
    analysis = analyzer.analyze(original_path)
    # The descriptor's ME entry is often unused on real dumps; the analyzer's fallback
    # ME region runs to end of file and would claim the BIOS. Use the partition table.
    regions = [r for r in analysis.regions if r.region_type != RegionType.INTEL_ME]
    declared = [r for r in analysis.regions if r.region_type == RegionType.INTEL_ME
                and "FPT" not in (r.name or "")]
    regions.extend(declared)
    fpt_bounds = me_bounds_from_fpt(a, analyzer)
    if fpt_bounds and not declared:
        regions.append(RegionInfo(RegionType.INTEL_ME, fpt_bounds[0],
                                  fpt_bounds[1] - fpt_bounds[0], "ME (partition table bounds)"))
    bios_spans = [(r.offset, r.offset + r.size) for r in analysis.regions
                  if r.region_type in (RegionType.BIOS, RegionType.FIRMWARE_VOLUME)]
    for off, size in bpdt_blocks(a, bios_spans):
        regions.append(RegionInfo(RegionType.INTEL_ME, off, size, "ME BPDT header block"))
    analysis.regions = regions
    result = VerifyResult(original_size=len(a), candidate_size=len(b))
    result.boot_guard_tags = [t.decode() for t in BOOT_GUARD_TAGS if t in a]

    if len(a) != len(b):
        result.reasons.append(f"size changed: {len(a):#x} -> {len(b):#x}")

    for start, end in changed_spans(a, b):
        kind, region = _kind_at(start, analysis.regions)
        last_kind, last_region = _kind_at(end - 1, analysis.regions)
        if last_kind != kind:
            kind, region = "mixed", f"{region} / {last_region}"
        span = ChangedSpan(start, end, kind, region)
        result.spans.append(span)
        result.changed_bytes += span.size
        if kind not in allow:
            result.refused_spans.append(span)

    if result.refused_spans:
        kinds = sorted({s.kind for s in result.refused_spans})
        result.reasons.append(
            f"{len(result.refused_spans)} span(s) in refused region(s): {', '.join(kinds)}")
    if len(a) != len(b):
        result.reasons.append("refusing: candidate has a different size")

    if result.changed_bytes == 0:
        result.reasons.append("no bytes changed")

    result.accepted = (not result.refused_spans and len(a) == len(b)
                       and result.changed_bytes > 0)
    if result.accepted and result.boot_guard_tags:
        result.reasons.append(
            "Boot Guard manifests present: even ME-only changes can stop some boards from "
            "booting. Keep the original image and a hardware programmer for recovery.")
    return result


def describe(result: VerifyResult) -> list[str]:
    lines = [result.summary()]
    for s in result.spans[:MAX_SPANS_REPORTED]:
        lines.append(f"  0x{s.start:08X}-0x{s.end:08X} {s.size:>8} bytes  {s.kind:<10} {s.region}")
    if len(result.spans) > MAX_SPANS_REPORTED:
        lines.append(f"  ... {len(result.spans) - MAX_SPANS_REPORTED} more spans")
    lines.extend(f"  ! {r}" for r in result.reasons)
    return lines
