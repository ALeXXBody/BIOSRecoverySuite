"""Shared Intel ME manifest version parsing.

Layout (generations 1-3): a partition manifest starts at `base`; its tag
(`$MN2` gen2/gen3, `$MAN` gen1) is stored at base+0x1C, and the firmware
version fields (u16 major, minor, hotfix, build) live at base+0x24 — i.e.
tag_offset + 0x08. This is valid for ME 2.x through CSME 14+ (verified
against MEAnalyzer and me_cleaner on real dumps).
"""

from __future__ import annotations

import struct

MANIFEST_TAGS = (b"$MN2", b"$MAN")
_TAG_OFFSET = 0x1C
_VERSION_OFFSET = 0x24


def iter_manifest_versions(blob: bytes) -> list[tuple[str, int]]:
    """Return [(version_str, manifest_base_off), ...] for every sane manifest.

    Manifests with a zero major version (uninitialized module copies) are skipped.
    """
    out: list[tuple[str, int]] = []
    n = len(blob)
    seen = 0
    for tag in MANIFEST_TAGS:
        pos = 0
        while True:
            idx = blob.find(tag, pos)
            if idx < 0 or seen > 2000:
                break
            seen += 1
            base = idx - _TAG_OFFSET
            if base >= 0 and base + _VERSION_OFFSET + 8 <= n:
                major, minor, hotfix, build = struct.unpack_from(
                    "<HHHH", blob, base + _VERSION_OFFSET
                )
                if 0 < major < 100 and minor < 200 and build < 0x20000:
                    out.append((f"{major}.{minor}.{hotfix}.{build}", base))
            pos = idx + 1
    return out


def detect_me_version_in_blob(blob: bytes) -> str:
    """Best-effort full version string (maj.min.hot.bld) inside a blob/region."""
    versions = iter_manifest_versions(blob)
    if not versions:
        return ""
    return versions[0][0]


def detect_me_version_best(blob: bytes) -> str:
    """Highest version found (used to pick the main engine manifest)."""
    versions = iter_manifest_versions(blob)
    if not versions:
        return ""

    def key(v: str) -> tuple[float, ...]:
        try:
            return tuple(int(p) for p in v.split("."))
        except ValueError:
            return (0.0,)

    return max(versions, key=lambda t: key(t[0]))[0]
